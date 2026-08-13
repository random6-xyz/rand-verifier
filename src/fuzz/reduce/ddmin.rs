// ── ddmin core with oracle cache and budget (v0.8, #78) ─────────────────────

//! Zeller's delta debugging over instruction deletion: repeatedly try
//! removing chunks of the program (halving granularity down to single
//! instructions) and keep every removal that preserves the reduction
//! invariant. The oracle check is the expensive step (mini + concrete,
//! optionally the kernel), so two mechanisms bound the cost:
//!
//! - **cache** — the same byte string is never evaluated twice (a
//!   hash-keyed map shared across all passes of a reduction run);
//! - **budget** — a cap on oracle checks; hitting it stops ddmin and
//!   returns the best program found so far (documented, not an error).
//!
//! Deterministic: fixed iteration order (index-ascending chunks), no
//! randomness. The core is deletion-only; the CFG/operand passes plug
//! in as additional oracle-guided transforms (#79/#80) reusing the same
//! cache and budget.

use std::collections::HashMap;

use crate::fuzz::reduce::fixup::delete_insns;

/// Oracle-evaluation cache + budget, shared across all reduction passes
/// of one run.
pub struct OracleCache {
    results: HashMap<Vec<u8>, bool>,
    max_checks: usize,
    /// Oracle evaluations performed (cache misses).
    pub checks: usize,
    /// Cache hits (evaluations avoided).
    pub hits: usize,
}

impl OracleCache {
    /// `max_checks == 0` means "unlimited" (tests and tiny programs).
    pub fn new(max_checks: usize) -> Self {
        Self {
            results: HashMap::new(),
            max_checks,
            checks: 0,
            hits: 0,
        }
    }

    /// Whether the oracle-check budget is exhausted.
    pub fn budget_exhausted(&self) -> bool {
        self.max_checks > 0 && self.checks >= self.max_checks
    }

    /// Evaluate `bytes` through the oracle, memoized. Returns `None`
    /// when the budget is exhausted — the caller stops and keeps the
    /// best program found so far.
    pub fn check(&mut self, bytes: &[u8], oracle: &mut impl FnMut(&[u8]) -> bool) -> Option<bool> {
        if let Some(&result) = self.results.get(bytes) {
            self.hits += 1;
            return Some(result);
        }
        if self.budget_exhausted() {
            return None;
        }
        self.checks += 1;
        let result = oracle(bytes);
        self.results.insert(bytes.to_vec(), result);
        Some(result)
    }
}

/// Zeller's ddmin over instruction indices: try removing chunks at
/// granularity `ceil(len / n)` for n = 2, 4, 8, … down to single
/// instructions; keep every removal the oracle accepts. Returns the
/// smallest program found (1-minimal with respect to single-insn
/// deletion when the budget allows).
///
/// The input must satisfy the oracle (the caller's baseline was
/// replay-validated); if it does not, `None` is returned defensively.
pub fn ddmin(
    bytes: &[u8],
    cache: &mut OracleCache,
    oracle: &mut impl FnMut(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let len = bytes.len() / 8;
    if len < 2 {
        return Some(bytes.to_vec());
    }
    // the invariant must hold on the input — one cached check
    match cache.check(bytes, oracle) {
        Some(true) => {}
        Some(false) => return None,
        None => return Some(bytes.to_vec()), // budget exhausted immediately
    }

    let mut keep: Vec<u32> = (0..len as u32).collect();
    let mut best = bytes.to_vec();
    let mut n = 2usize;

    while keep.len() >= 2 && !cache.budget_exhausted() {
        let granularity = keep.len().div_ceil(n);
        let mut reduced = false;
        for chunk in 0..n {
            // candidate = keep minus chunk `chunk` (index-ascending)
            let candidate: Vec<u32> = keep
                .iter()
                .enumerate()
                .filter(|(i, _)| i / granularity != chunk)
                .map(|(_, &idx)| idx)
                .collect();
            if candidate.len() == keep.len() {
                continue; // empty chunk (len not a multiple of n)
            }
            let removed: Vec<u32> = (0..len as u32).filter(|i| !candidate.contains(i)).collect();
            let Some(candidate_bytes) = delete_insns(bytes, &removed) else {
                continue; // the deletion breaks a jump — not preservable
            };
            match cache.check(&candidate_bytes, oracle) {
                Some(true) => {
                    keep = candidate;
                    best = candidate_bytes;
                    reduced = true;
                    break;
                }
                Some(false) => {}
                None => return Some(best), // budget exhausted
            }
        }
        if reduced {
            // the bound is updated after the loop: equivalent to the
            // classic `n = max(n-1, 2)` on success
            n = n.saturating_sub(1).max(2);
            continue;
        }
        if n >= keep.len() {
            break; // 1-minimal with respect to single-insn deletion
        }
        n = (n * 2).min(keep.len());
    }
    Some(best)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::BpfVerifierEnv;
    use crate::error::Verdict;
    use crate::testutil::{insn_bytes, prog_bytes};

    /// The oracle of the tests: the program must still be rejected for
    /// the *uninitialized r4* read (not any other reason) — a
    /// reason-preserving invariant like the reducer's.
    fn r4_uninit_oracle(bytes: &[u8]) -> bool {
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(bytes).unwrap();
        match env.verify().unwrap() {
            Verdict::Safe => false,
            Verdict::Unsafe(failure) => failure.message.contains("register r4 is uninitialized"),
        }
    }

    /// A padded program whose minimal core is `[r4 -= r0; exit]`
    /// (removing either instruction changes the failure reason).
    fn padded_program(pad: usize) -> Vec<u8> {
        let mut insns: Vec<[u8; 8]> = Vec::new();
        for i in 0..pad {
            insns.push(insn_bytes(0xb7, 1, 0, 0, i as i32 + 1)); // r1 = i+1
        }
        insns.push(insn_bytes(0x1f, 4, 0, 0, 0)); // r4 -= r0 (uninit)
        insns.push(insn_bytes(0xb7, 0, 0, 0, 1)); // r0 = 1
        insns.push(insn_bytes(0x95, 0, 0, 0, 0)); // exit
        prog_bytes(&insns)
    }

    #[test]
    fn ddmin_reduces_to_known_minimal_core() {
        let bytes = padded_program(20);
        let mut cache = OracleCache::new(0); // unlimited
        let mut oracle = r4_uninit_oracle;
        let out = ddmin(&bytes, &mut cache, &mut oracle).unwrap();
        // exactly [r4 -= r0; exit] — 1-minimal
        assert_eq!(out.len(), 16, "{:?}", out);
        assert!(oracle(&out));
        // the minimal core still fails for the r4 read
        assert!(r4_uninit_oracle(&out));
        // and no single instruction can be removed
        for i in 0..(out.len() / 8) {
            let removed = delete_insns(&out, &[i as u32]).unwrap();
            assert!(!r4_uninit_oracle(&removed), "insn {i} should be essential");
        }
    }

    #[test]
    fn ddmin_padding_variants() {
        // padding before, interleaved and with duplicates — all must
        // collapse to the same minimal core
        for pad in [0usize, 1, 5, 32] {
            let bytes = padded_program(pad);
            let mut cache = OracleCache::new(0);
            let mut oracle = r4_uninit_oracle;
            let out = ddmin(&bytes, &mut cache, &mut oracle).unwrap();
            assert_eq!(out.len(), 16, "pad {pad}");
        }
    }

    #[test]
    fn ddmin_cache_avoids_re_evaluation() {
        // identical padding instructions produce duplicate byte
        // streams under deletion — the cache must absorb them
        let bytes = padded_program(40);
        let mut cache = OracleCache::new(0);
        let mut oracle = r4_uninit_oracle;
        let out = ddmin(&bytes, &mut cache, &mut oracle).unwrap();
        assert_eq!(out.len(), 16);
        assert!(
            cache.hits > 0,
            "expected cache hits, checks={} hits={}",
            cache.checks,
            cache.hits
        );
        // and the cache size equals the miss count
        assert_eq!(cache.results.len(), cache.checks);
    }

    #[test]
    fn ddmin_budget_stops_and_returns_best_so_far() {
        // a tiny budget must stop the search and return a program that
        // still satisfies the oracle (the original, if nothing was
        // tried yet)
        let bytes = padded_program(10);
        let mut cache = OracleCache::new(3);
        let mut oracle = r4_uninit_oracle;
        let out = ddmin(&bytes, &mut cache, &mut oracle).unwrap();
        assert!(r4_uninit_oracle(&out), "best-so-far must stay valid");
        assert!(cache.budget_exhausted());
        assert_eq!(cache.checks, 3);
    }

    #[test]
    fn ddmin_rejects_input_without_the_property() {
        // an accepted program does not satisfy the r4-uninit oracle —
        // ddmin refuses to reduce it instead of deleting blindly
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)]);
        let mut cache = OracleCache::new(0);
        let mut oracle = r4_uninit_oracle;
        assert!(ddmin(&bytes, &mut cache, &mut oracle).is_none());
    }

    #[test]
    fn ddmin_single_insn_program_unchanged() {
        let bytes = prog_bytes(&[insn_bytes(0x95, 0, 0, 0, 0)]);
        let mut cache = OracleCache::new(0);
        let mut oracle = r4_uninit_oracle;
        assert_eq!(ddmin(&bytes, &mut cache, &mut oracle).unwrap(), bytes);
    }

    #[test]
    fn ddmin_is_deterministic() {
        let bytes = padded_program(25);
        let mut cache_a = OracleCache::new(0);
        let mut cache_b = OracleCache::new(0);
        let mut oracle_a = r4_uninit_oracle;
        let mut oracle_b = r4_uninit_oracle;
        let a = ddmin(&bytes, &mut cache_a, &mut oracle_a).unwrap();
        let b = ddmin(&bytes, &mut cache_b, &mut oracle_b).unwrap();
        assert_eq!(a, b);
        assert_eq!(cache_a.checks, cache_b.checks);
    }

    #[test]
    fn cache_hits_counted() {
        let mut cache = OracleCache::new(100);
        let mut oracle = r4_uninit_oracle;
        let bytes = padded_program(2);
        assert_eq!(cache.check(&bytes, &mut oracle), Some(true));
        assert_eq!(cache.check(&bytes, &mut oracle), Some(true));
        assert_eq!(cache.checks, 1);
        assert_eq!(cache.hits, 1);
    }
}
