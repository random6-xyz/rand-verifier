// ── Tracked number abstraction (tnum) (v0.3 Mini) ────────────────────────────

/// A tracked number: `value` holds the known bits and `mask` the unknown
/// ones (a 1 in `mask` means the bit may be either 0 or 1).
///
/// This is the simplified counterpart of the kernel's `struct tnum`
/// (tnum_var_off); it is not wired into RegState yet — that happens in
/// Meso, alongside the min/max ranges the kernel keeps next to it.
#[allow(dead_code)] // wired into RegState in Meso
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tnum {
    pub(crate) value: u64,
    pub(crate) mask: u64,
}

#[allow(dead_code)] // wired into RegState in Meso
impl Tnum {
    /// A fully known constant.
    pub(crate) fn constant(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// A fully unknown value (every bit may be anything).
    pub(crate) fn unknown() -> Self {
        Self {
            value: 0,
            mask: u64::MAX,
        }
    }

    /// Whether every bit is known.
    pub(crate) fn is_constant(&self) -> bool {
        self.mask == 0
    }

    /// Whether no bit is known.
    pub(crate) fn is_unknown(&self) -> bool {
        self.mask == u64::MAX
    }

    /// The bits that are known to be 1.
    pub(crate) fn known_ones(&self) -> u64 {
        self.value & !self.mask
    }

    /// Addition with carry, following the kernel's tnum_add(): the
    /// possible carry chain is folded into the mask.
    pub(crate) fn add(self, other: Tnum) -> Self {
        // kernel: sm = a.mask + b.mask; sv = a.value + b.value;
        // sigma = sm + sv; chi = sigma ^ sv; mu = chi | a.mask | b.mask
        let sm = self.mask.wrapping_add(other.mask);
        let sv = self.value.wrapping_add(other.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Self {
            value: sv & !mu,
            mask: mu,
        }
    }

    /// Bitwise AND: a bit is known 1 only if both operands are known 1
    /// there; it is unknown if either operand could be 0 there.
    pub(crate) fn and(self, other: Tnum) -> Self {
        let alpha = self.value | self.mask; // possible 1s of self
        let beta = other.value | other.mask; // possible 1s of other
        let value = self.value & other.value;
        let mask = (alpha & beta) ^ value;
        Self { value, mask }
    }

    /// Bitwise OR: a bit is known 1 if either operand is known 1 there,
    /// and known 0 if both operands are known 0.
    pub(crate) fn or(self, other: Tnum) -> Self {
        let known_one = self.known_ones() | other.known_ones();
        let known_zero = (!self.value & !self.mask) & (!other.value & !other.mask);
        Self {
            value: known_one,
            mask: !(known_one | known_zero),
        }
    }

    /// The values common to both abstractions (kernel's tnum_intersect).
    pub(crate) fn intersect(self, other: Tnum) -> Self {
        let v = self.value | other.value;
        let mu = self.mask & other.mask;
        Self {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Does `self` contain every value of `other` (a partial order)?
    /// A bit known in `self` must be known with the same value in
    /// `other`; unknown bits of `self` may be refined in `other`.
    pub(crate) fn subsumes(self, other: Tnum) -> bool {
        (other.mask & !self.mask) == 0 && (other.value & !self.mask) == (self.value & !self.mask)
    }
}

impl std::fmt::Display for Tnum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TNUM({:#x},{:#x})", self.value, self.mask)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnum_constants() {
        assert_eq!(Tnum::constant(5), Tnum { value: 5, mask: 0 });
        assert_eq!(Tnum::unknown().mask, u64::MAX);
        assert!(Tnum::constant(5).is_constant());
        assert!(!Tnum::unknown().is_constant());
        assert!(Tnum::unknown().is_unknown());
        assert!(!Tnum::constant(5).is_unknown());
        assert_eq!(Tnum::constant(0b1010).known_ones(), 0b1010);
        assert_eq!(Tnum::unknown().known_ones(), 0);
        // value bits under the mask are not known ones
        assert_eq!(
            Tnum {
                value: 0b001,
                mask: 0b010
            }
            .known_ones(),
            0b001
        );
    }

    #[test]
    fn tnum_add() {
        // constants add exactly
        assert_eq!(Tnum::constant(1).add(Tnum::constant(2)), Tnum::constant(3));
        assert_eq!(
            Tnum::constant(5).add(Tnum::constant(-3i64 as u64)),
            Tnum::constant(2)
        );
        // unknown + anything = unknown
        assert_eq!(Tnum::unknown().add(Tnum::constant(0)), Tnum::unknown());
        // bit0 known 1, bit1 unknown (value 1 or 3) + const 2 → bit0 is
        // always 1, bits 1..2 unknown (carry from the unknown bit)
        let a = Tnum {
            value: 0b001,
            mask: 0b010,
        };
        assert_eq!(
            a.add(Tnum::constant(0b010)),
            Tnum {
                value: 0b001,
                mask: 0b110
            }
        );
    }

    #[test]
    fn tnum_and_or() {
        // a = {101, 111} (bit1 unknown)
        let a = Tnum {
            value: 0b101,
            mask: 0b010,
        };
        let b = Tnum::constant(0b001);
        // AND: only bit0 can be 1 in both → const 001
        assert_eq!(a.and(b), Tnum::constant(0b001));
        // OR: bit0 known 1, bit1 unknown, bit2 known 1 → {101, 111}
        assert_eq!(
            a.or(b),
            Tnum {
                value: 0b101,
                mask: 0b010
            }
        );
    }

    #[test]
    fn tnum_intersect() {
        // {1, 3} ∩ {1} = {1}
        let a = Tnum {
            value: 0b001,
            mask: 0b010,
        };
        assert_eq!(a.intersect(Tnum::constant(0b001)), Tnum::constant(0b001));
        // {1, 3} ∩ {0, 1} = {1}
        let b = Tnum {
            value: 0b000,
            mask: 0b001,
        };
        assert_eq!(a.intersect(b), Tnum::constant(0b001));
        // intersecting with unknown keeps the value
        assert_eq!(a.intersect(Tnum::unknown()), a);
    }

    #[test]
    fn tnum_subsumes() {
        // a wider abstraction contains narrower ones
        let wide = Tnum {
            value: 0b100,
            mask: 0b011,
        }; // {100, 101, 110, 111}
        assert!(wide.subsumes(Tnum::constant(0b101)));
        assert!(wide.subsumes(Tnum {
            value: 0b110,
            mask: 0b001,
        }));
        assert!(!Tnum::constant(0b101).subsumes(wide));
        // constants subsume only themselves
        assert!(Tnum::constant(7).subsumes(Tnum::constant(7)));
        assert!(!Tnum::constant(7).subsumes(Tnum::constant(6)));
        // unknown subsumes everything
        assert!(Tnum::unknown().subsumes(Tnum::constant(0)));
        assert!(Tnum::unknown().subsumes(Tnum::unknown()));
    }

    #[test]
    fn tnum_display() {
        assert_eq!(Tnum::constant(5).to_string(), "TNUM(0x5,0x0)");
        assert_eq!(Tnum::unknown().to_string(), "TNUM(0x0,0xffffffffffffffff)");
    }

    // ── VerifierState (v0.2) ─────────────────────────────────────────────────
}
