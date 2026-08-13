// ── Deterministic PRNG for the fuzzer (v0.7, #66) ───────────────────────────

//! SplitMix64 — a small deterministic PRNG, implemented in-house to
//! keep the dependency list at {anyhow, libc} (FUZZ_PLAN §8). The seed
//! fully determines the output stream.

/// SplitMix64: 64-bit state, a well-known fast generator (public domain
/// algorithm by Sebastiano Vigna). Not cryptographically secure — the
/// fuzzer only needs deterministic, well-distributed values.
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next pseudo-random u64.
    pub(crate) fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform value in `0..n` (modulo bias is acceptable for fuzzing).
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0, "below(0) is undefined");
        self.next() % n
    }

    /// A uniformly picked element of `slice` (must be non-empty).
    pub(crate) fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.below(slice.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix64_deterministic() {
        let mut a = SplitMix64::new(7);
        let mut b = SplitMix64::new(7);
        for _ in 0..1000 {
            assert_eq!(a.next(), b.next());
        }
    }

    #[test]
    fn splitmix64_differs_for_different_seeds() {
        let mut a = SplitMix64::new(1);
        let mut b = SplitMix64::new(2);
        let mut any_diff = false;
        for _ in 0..64 {
            if a.next() != b.next() {
                any_diff = true;
                break;
            }
        }
        assert!(any_diff, "different seeds produced identical streams");
    }

    #[test]
    fn below_stays_in_range() {
        let mut rng = SplitMix64::new(99);
        for _ in 0..10_000 {
            let v = rng.below(17);
            assert!(v < 17);
        }
    }
}
