// ── Novelty scheduling (#140) ────────────────────────────────────────────────

//! Uniform seed selection re-finds the same programs: the 2026-10 campaign
//! produced 391 labels that collapsed to 53 unique programs (7.4x
//! duplication). This module turns a program into a **signature** and gives
//! each signature an energy that decays with use, so the mutation pool
//! drifts toward programs whose verifier response or structure is new.
//!
//! The signature is deliberately cheap and deterministic:
//!
//! - the classification label,
//! - the normalized mini and kernel messages (literals collapse to `#`),
//! - an FNV-1a hash over the opcode-family sequence.
//!
//! Two programs with the same rule violation but different shapes stay
//! separate; the same shape reached through different literals collapses.

use std::collections::BTreeMap;

use crate::fuzz::insn_lib::opcode_family;
use crate::insn::BpfInsn;

/// Normalize a verifier message into a clusterable form: embedded hex and
/// decimal literals become `#` (they vary per program, the rule does not),
/// while register names (`R6`) keep their number.
pub fn normalize_message(message: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for token in message.split_whitespace() {
        let mut norm = String::new();
        let mut chars = token.chars().peekable();
        let mut prev: Option<char> = None;
        while let Some(c) = chars.next() {
            let starts_number =
                c.is_ascii_digit() && prev.is_none_or(|p| !p.is_ascii_alphanumeric() && p != '_');
            if starts_number {
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_hexdigit() || d == 'x' || d == 'X' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                if norm.ends_with('-') || norm.ends_with('+') {
                    norm.pop();
                }
                norm.push('#');
                prev = Some('#');
            } else {
                norm.push(c);
                prev = Some(c);
            }
        }
        let norm = norm.trim_matches(|c: char| c == ',' || c == '.' || c == ';' || c == ':');
        if norm.is_empty() {
            continue;
        }
        if prev_space {
            out.push(' ');
        }
        out.push_str(norm);
        prev_space = true;
    }
    out.truncate(120);
    out
}

/// FNV-1a over the opcode-family sequence: deterministic across processes
/// (std's DefaultHasher is randomly keyed).
pub fn shape_hash(insns: &[BpfInsn]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for insn in insns {
        for byte in opcode_family(insn).bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One program's novelty signature.
pub fn signature(
    finding: &str,
    mini_reason: Option<&str>,
    kernel_message: Option<&str>,
    insns: &[BpfInsn],
) -> String {
    format!(
        "{}|{}|{}|{:016x}",
        finding,
        normalize_message(mini_reason.unwrap_or("")),
        normalize_message(kernel_message.unwrap_or("")),
        shape_hash(insns),
    )
}

/// A coarser signature for **scheduling**: the exact opcode sequence is
/// too specific (every mutant inserts/deletes something, so everything
/// looks novel). The scheduler keys on the verifier response plus coarse
/// structure: the sorted opcode-family set, a branch-count bucket and a
/// length bucket.
pub fn feature_signature(
    finding: &str,
    mini_reason: Option<&str>,
    kernel_message: Option<&str>,
    insns: &[BpfInsn],
) -> String {
    let mut families: Vec<&'static str> = insns.iter().map(opcode_family).collect();
    families.sort_unstable();
    families.dedup();
    let branches = insns
        .iter()
        .filter(|insn| insn.is_conditional_branch())
        .count()
        .min(8);
    let len_bucket = (insns.len() / 8).min(15);
    format!(
        "{}|{}|{}|{}|{}b|{}l",
        finding,
        normalize_message(mini_reason.unwrap_or("")),
        normalize_message(kernel_message.unwrap_or("")),
        families.join(","),
        branches,
        len_bucket,
    )
}

/// Use counts per signature: the scheduler's memory.
#[derive(Default)]
pub struct NoveltyMap {
    uses: BTreeMap<String, u64>,
    novel: usize,
}

impl NoveltyMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one program. Returns true when the signature is new.
    pub fn observe(&mut self, signature: &str) -> bool {
        let uses = self.uses.entry(signature.to_string()).or_insert(0);
        let is_new = *uses == 0;
        *uses += 1;
        if is_new {
            self.novel += 1;
        }
        is_new
    }

    /// Selection weight: `1 / (1 + uses)`. An unseen signature weighs 1.0,
    /// a used one decays — the classic "energy" used by novelty search.
    pub fn energy(&self, signature: &str) -> f64 {
        1.0 / (1.0 + self.uses.get(signature).copied().unwrap_or(0) as f64)
    }

    /// Count a seed pick, so [`Self::energy`] decays the seeds a
    /// campaign keeps choosing (the promotion counter alone saturates
    /// after the first promotion and makes every weight equal).
    pub fn note_pick(&mut self, signature: &str) {
        *self.uses.entry(signature.to_string()).or_insert(0) += 1;
    }

    pub fn uses(&self, signature: &str) -> u64 {
        self.uses.get(signature).copied().unwrap_or(0)
    }

    pub fn unique(&self) -> usize {
        self.uses.len()
    }

    pub fn novel_events(&self) -> usize {
        self.novel
    }
}

/// Weighted index pick: `weights` must be non-empty, finite and >= 0;
/// an all-zero vector falls back to uniform selection.
pub(crate) fn pick_index(rng: &mut crate::fuzz::prng::SplitMix64, weights: &[f64]) -> usize {
    if weights.is_empty() {
        return 0;
    }
    let total: f64 = weights.iter().filter(|w| w.is_finite() && **w > 0.0).sum();
    if total <= 0.0 {
        return rng.below(weights.len() as u64) as usize;
    }
    let mut point = (rng.unit() * total).min(total - f64::EPSILON);
    for (index, weight) in weights.iter().enumerate() {
        if !weight.is_finite() || *weight <= 0.0 {
            continue;
        }
        if point < *weight {
            return index;
        }
        point -= *weight;
    }
    weights.len() - 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::decode_program;

    fn prog(fill: u8) -> Vec<BpfInsn> {
        decode_program(&[0xb7, 0, 0, 0, fill, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn signature_is_deterministic_and_shape_sensitive() {
        let a = signature("agree", Some("r2 off=-8"), None, &prog(1));
        let b = signature("agree", Some("r2 off=-16"), None, &prog(2));
        assert_eq!(a, b, "literals must collapse");
        let c = signature("agree", Some("r2 off=-8"), None, &[]);
        assert_ne!(a, c, "a different shape must differ");
        let d = signature("agree", Some("r3 off=-8"), None, &prog(1));
        assert_ne!(a, d, "register names stay");
    }

    #[test]
    fn energy_decays_with_use() {
        let mut map = NoveltyMap::new();
        assert_eq!(map.energy("s"), 1.0);
        assert!(map.observe("s"));
        assert!(!map.observe("s"));
        assert!((map.energy("s") - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(map.unique(), 1);
        assert_eq!(map.novel_events(), 1);
        assert_eq!(map.uses("s"), 2);
    }

    #[test]
    fn weighted_pick_respects_zero_weights() {
        use crate::fuzz::prng::SplitMix64;
        let mut rng = SplitMix64::new(7);
        for _ in 0..100 {
            assert_eq!(pick_index(&mut rng, &[0.0, 1.0, 0.0]), 1);
        }
        // all-zero weights fall back to uniform, never out of range
        for _ in 0..100 {
            let i = pick_index(&mut rng, &[0.0, 0.0]);
            assert!(i < 2);
        }
    }
}
