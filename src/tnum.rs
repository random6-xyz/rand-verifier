// ── Tracked number abstraction (tnum) (v0.3 Mini) ────────────────────────────

/// A tracked number: `value` holds the known bits and `mask` the unknown
/// ones (a 1 in `mask` means the bit may be either 0 or 1).
///
/// This is the simplified counterpart of the kernel's `struct tnum`
/// (tnum_var_off), wired into [`crate::state::ScalarBounds`] (Meso #42)
/// next to the min/max ranges the kernel keeps beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tnum {
    pub(crate) value: u64,
    pub(crate) mask: u64,
}

impl Tnum {
    /// A fully known constant.
    pub(crate) const fn constant(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// A fully unknown value (every bit may be anything).
    pub(crate) const fn unknown() -> Self {
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
    #[allow(dead_code)] // used by tests
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

    /// Subtraction, following the kernel's tnum_sub() (kernel/bpf/
    /// tnum.c): the difference spans `[dv - b.mask, dv + a.mask]` and
    /// the mask covers the bits that vary across that span plus both
    /// input masks. (The add-symmetric carry-folding form was unsound:
    /// `a = {0}, b = {0,1}` yields `0 - 1 = -1` outside the result —
    /// found by the SMT soundness harness, issue #116.)
    pub(crate) fn sub(self, other: Tnum) -> Self {
        let dv = self.value.wrapping_sub(other.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(other.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | other.mask;
        Self {
            value: dv & !mu,
            mask: mu,
        }
    }

    /// Multiplication, following the kernel's tnum_mul()
    /// (kernel/bpf/tnum.c, upstreamed 2025-01 as "Provably sound,
    /// faster, and more precise algorithm for tnum_mul"): long
    /// multiplication over the bits of `a`; when the LSB of `a` is
    /// uncertain the accumulator takes the union of both partial
    /// products (LSB 0 and LSB 1).
    #[cfg(feature = "smt")]
    pub(crate) fn mul(self, other: Tnum) -> Self {
        let mut acc = Tnum::constant(0);
        let mut a = self;
        let mut b = other;
        while a.value != 0 || a.mask != 0 {
            if a.value & 1 != 0 {
                acc = acc.add(b);
            } else if a.mask & 1 != 0 {
                acc = acc.union(acc.add(b));
            }
            a = a.rshift(1);
            b = b.lshift(1);
        }
        acc
    }

    /// Bitwise XOR: a bit is known 1 if the operands differ there and
    /// both are known; it is unknown if either operand could differ.
    pub(crate) fn xor(self, other: Tnum) -> Self {
        let value = self.value ^ other.value;
        let mask = self.mask | other.mask;
        Self {
            value: value & !mask,
            mask,
        }
    }

    /// Shift left: the kernel shifts both fields (bits shifted out of
    /// the u64 vanish — they are determined).
    pub(crate) fn lshift(self, k: u32) -> Self {
        Self {
            value: self.value.checked_shl(k).unwrap_or(0),
            mask: self.mask.checked_shl(k).unwrap_or(0),
        }
    }

    /// Logical shift right, kernel tnum_rshift.
    pub(crate) fn rshift(self, k: u32) -> Self {
        Self {
            value: self.value.checked_shr(k).unwrap_or(0),
            mask: self.mask.checked_shr(k).unwrap_or(0),
        }
    }

    /// Arithmetic shift right, kernel tnum_arshift: the mask is shifted
    /// with sign extension, like the value.
    pub(crate) fn arshift(self, k: u32) -> Self {
        let v = (self.value as i64).checked_shr(k);
        let m = (self.mask as i64).checked_shr(k);
        Self {
            value: v
                .map(|x| x as u64)
                .unwrap_or_else(|| if (self.value as i64) < 0 { u64::MAX } else { 0 }),
            mask: m
                .map(|x| x as u64)
                .unwrap_or_else(|| if (self.mask as i64) < 0 { u64::MAX } else { 0 }),
        }
    }

    /// Truncate to the low 32 bits (kernel tnum_subreg): the result of
    /// an ALU32 operation.
    pub(crate) fn subreg(self) -> Self {
        Self {
            value: self.value as u32 as u64,
            mask: self.mask as u32 as u64,
        }
    }

    /// The smallest tnum covering a u64 interval [min, max] (kernel
    /// tnum_range): bits above the highest differing bit are fixed,
    /// the rest are unknown.
    pub(crate) fn from_range(min: u64, max: u64) -> Self {
        let chi = min ^ max;
        if chi == 0 {
            return Self::constant(min);
        }
        let bits = 64 - chi.leading_zeros();
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        Self {
            value: min & !mask,
            mask,
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

    /// The union of two abstractions (kernel tnum_union,
    /// kernel/bpf/tnum.c): the smallest tnum containing both member
    /// sets — a bit is known only when both agree on it with the same
    /// value. (`value | value; mask | mask` is NOT the union: it
    /// drops members — e.g. `union({0}, {1})` would return `{1}` —
    /// found by the SMT soundness harness, issue #116.)
    #[cfg(feature = "smt")]
    pub(crate) fn union(self, other: Tnum) -> Self {
        let v = self.value & other.value;
        let mu = (self.value ^ other.value) | self.mask | other.mask;
        Self {
            value: v & !mu,
            mask: mu,
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
    fn tnum_sub() {
        // constants subtract exactly
        assert_eq!(Tnum::constant(10).sub(Tnum::constant(3)), Tnum::constant(7));
        // {0, 1} - 1 = {u64::MAX, 0}: every bit unknown
        let a = Tnum { value: 0, mask: 1 };
        assert_eq!(a.sub(Tnum::constant(1)), Tnum::unknown());
    }

    #[test]
    fn tnum_xor() {
        // a = {101, 111} (bit1 unknown) ^ 001 → {100, 110}
        let a = Tnum {
            value: 0b101,
            mask: 0b010,
        };
        assert_eq!(
            a.xor(Tnum::constant(0b001)),
            Tnum {
                value: 0b100,
                mask: 0b010
            }
        );
        // unknown ^ constant = unknown
        assert_eq!(Tnum::unknown().xor(Tnum::constant(5)), Tnum::unknown());
    }

    #[test]
    fn tnum_shifts() {
        // 1 << 4 = 16; unknown bits shift along
        let a = Tnum {
            value: 0b001,
            mask: 0b010,
        };
        assert_eq!(
            a.lshift(2),
            Tnum {
                value: 0b100,
                mask: 0b1000
            }
        );
        assert_eq!(Tnum::constant(16).rshift(4), Tnum::constant(1));
        // arithmetic shift sign-extends the mask
        assert_eq!(
            Tnum::constant(-8i64 as u64).arshift(1),
            Tnum::constant(-4i64 as u64)
        );
        // shifts >= 64 yield zero
        assert_eq!(Tnum::constant(5).lshift(64), Tnum::constant(0));
        assert_eq!(Tnum::constant(5).rshift(64), Tnum::constant(0));
    }

    #[test]
    fn tnum_subreg() {
        // truncation to 32 bits: the high bits become determined zero
        let a = Tnum {
            value: 0x1_0000_0001,
            mask: 0xFFFF_FFFF_0000_0000,
        };
        assert_eq!(a.subreg(), Tnum::constant(1));
        assert_eq!(
            Tnum::unknown().subreg(),
            Tnum {
                value: 0,
                mask: 0xFFFF_FFFF,
            }
        );
    }

    #[test]
    fn tnum_from_range() {
        // [0, 100]: bits 0..6 unknown, bit 7+ known zero
        let t = Tnum::from_range(0, 100);
        assert_eq!(t.value, 0);
        assert_eq!(t.mask, 0x7F);
        // a constant range is exact
        assert_eq!(Tnum::from_range(42, 42), Tnum::constant(42));
        // [0, u64::MAX] is fully unknown
        assert_eq!(Tnum::from_range(0, u64::MAX), Tnum::unknown());
        // [0x100, 0x1FF] → bits 8+ fixed, low 8 unknown
        let t = Tnum::from_range(0x100, 0x1FF);
        assert_eq!(t.value, 0x100);
        assert_eq!(t.mask, 0xFF);
    }

    #[test]
    fn tnum_display() {
        assert_eq!(Tnum::constant(5).to_string(), "TNUM(0x5,0x0)");
        assert_eq!(Tnum::unknown().to_string(), "TNUM(0x0,0xffffffffffffffff)");
    }

    // ── VerifierState (v0.2) ─────────────────────────────────────────────────
}
