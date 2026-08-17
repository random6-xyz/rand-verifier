// ── SMT encoding of the tnum operators (issue #115) ─────────────────────────

//! The tracked-number (tnum) operators of src/tnum.rs encoded as
//! bitvector formulas. Each `encode_*` is the direct formula
//! translation of the Rust implementation; the tests cross-check the
//! encodings against the Rust functions on concrete inputs.

use z3::ast::BV;
use z3::ast::Bool;

pub(crate) use super::SymTnum;

/// The width of a full tnum (64-bit).
pub const TNUM_WIDTH: u32 = 64;

/// The concrete values of a tnum: the known bits (mask == 0) must
/// equal the value's bits — `(x & !mask) == (value & !mask)`. The
/// `!mask` form is robust to unnormalized tnums (the kernel keeps
/// `value` free of mask bits, but the harness enumerates raw pairs).
pub(crate) fn concretize(t: &SymTnum, x: &BV) -> Bool {
    let known = t.mask.bvnot();
    x.bvand(&known).eq(t.value.bvand(&known))
}

/// Encodes `Tnum::add` (kernel tnum_add: the carry chain folds into
/// the mask).
pub(crate) fn encode_add(a: &SymTnum, b: &SymTnum) -> SymTnum {
    let sm = a.mask.bvadd(&b.mask);
    let sv = a.value.bvadd(&b.value);
    let sigma = sm.bvadd(&sv);
    let chi = sigma.bvxor(&sv);
    let mu = chi.bvor(&a.mask).bvor(&b.mask);
    SymTnum {
        value: sv.bvand(mu.bvnot()),
        mask: mu,
    }
}

/// Encodes `Tnum::sub` (the kernel formula: the difference spans
/// `[dv - b.mask, dv + a.mask]`).
pub(crate) fn encode_sub(a: &SymTnum, b: &SymTnum) -> SymTnum {
    let dv = a.value.bvsub(&b.value);
    let alpha = dv.bvadd(&a.mask);
    let beta = dv.bvsub(&b.mask);
    let chi = alpha.bvxor(&beta);
    let mu = chi.bvor(&a.mask).bvor(&b.mask);
    SymTnum {
        value: dv.bvand(mu.bvnot()),
        mask: mu,
    }
}

/// Encodes `Tnum::xor`.
pub(crate) fn encode_xor(a: &SymTnum, b: &SymTnum) -> SymTnum {
    let value = a.value.bvxor(&b.value);
    let mask = a.mask.bvor(&b.mask);
    SymTnum {
        value: value.bvand(mask.bvnot()),
        mask,
    }
}

/// Encodes `Tnum::and`.
pub(crate) fn encode_and(a: &SymTnum, b: &SymTnum) -> SymTnum {
    let alpha = a.value.bvor(&a.mask); // possible 1s of a
    let beta = b.value.bvor(&b.mask); // possible 1s of b
    let value = a.value.bvand(&b.value);
    let mask = alpha.bvand(&beta).bvxor(&value);
    SymTnum { value, mask }
}

/// Encodes `Tnum::or`.
pub(crate) fn encode_or(a: &SymTnum, b: &SymTnum) -> SymTnum {
    let known_one = a
        .value
        .bvand(a.mask.bvnot())
        .bvor(b.value.bvand(b.mask.bvnot()));
    let known_zero = a
        .value
        .bvnot()
        .bvand(a.mask.bvnot())
        .bvand(b.value.bvnot())
        .bvand(b.mask.bvnot());
    let mask = known_one.bvor(&known_zero).bvnot();
    SymTnum {
        value: known_one,
        mask,
    }
}

/// Encodes `Tnum::lshift` for a symbolic shift amount (the Rust side
/// requires a constant amount; the encoding keeps the amount symbolic
/// and the soundness harness constrains it).
pub(crate) fn encode_lshift(a: &SymTnum, k: &BV) -> SymTnum {
    SymTnum {
        value: a.value.bvshl(k),
        mask: a.mask.bvshl(k),
    }
}

/// Encodes `Tnum::rshift`.
pub(crate) fn encode_rshift(a: &SymTnum, k: &BV) -> SymTnum {
    SymTnum {
        value: a.value.bvlshr(k),
        mask: a.mask.bvlshr(k),
    }
}

/// Encodes `Tnum::arshift` (the mask is shifted with sign extension).
pub(crate) fn encode_arshift(a: &SymTnum, k: &BV) -> SymTnum {
    SymTnum {
        value: a.value.bvashr(k),
        mask: a.mask.bvashr(k),
    }
}

#[cfg(test)]
/// Encodes `Tnum::subreg` (truncation to 32 bits): the high bits
/// become determined zero.
pub(crate) fn encode_subreg(a: &SymTnum) -> SymTnum {
    SymTnum {
        value: a.value.extract(31, 0).zero_ext(32),
        mask: a.mask.extract(31, 0).zero_ext(32),
    }
}

#[cfg(test)]
/// Encodes `Tnum::from_range`: the smallest tnum covering `[lo, hi]`
/// — bits above the highest differing bit are fixed, the rest
/// unknown.
pub(crate) fn encode_from_range(lo: &BV, hi: &BV) -> SymTnum {
    // chi = lo ^ hi; the highest set bit of chi separates the fixed
    // prefix. The mask covers the low (bit_width - leading_zeros)
    // bits of chi.
    let chi = lo.bvxor(hi);
    // width = 64 - clz(chi) — compute via a loop over bit positions:
    // mask = sum over i of (chi >> i == 0 ? 0 : 1<<i - 1) ... simpler:
    // the mask is (1 << n) - 1 where n = position of the highest set
    // bit + 1. Encode by iterating candidate n with ite chains.
    let one = BV::from_u64(1, TNUM_WIDTH);
    let zero = BV::from_u64(0, TNUM_WIDTH);
    // mask_n = (1 << n) - 1 for n in 1..=64, chosen by whether
    // chi < (1 << n) (i.e. the highest set bit is below n); chi == 0
    // (a constant interval) yields mask 0.
    let mut mask = BV::from_u64(u64::MAX, TNUM_WIDTH);
    for n in (1..=64u32).rev() {
        let shift = BV::from_u64(n as u64, TNUM_WIDTH);
        let below = if n == 64 {
            Bool::from_bool(true)
        } else {
            chi.bvult(one.bvshl(&shift))
        };
        let m_n = one.bvshl(&shift).bvsub(&one); // (1<<64)-1 = MAX in 64 bits
        mask = Bool::ite(&below, &m_n, &mask);
    }
    let is_const = chi.eq(&zero);
    mask = Bool::ite(&is_const, &zero, &mask);
    SymTnum {
        value: lo.bvand(mask.bvnot()),
        mask,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tnum::Tnum;
    use z3::{Config, SatResult, Solver, with_z3_config};

    /// Evaluate an encoded operator against the Rust implementation on
    /// one concrete input pair.
    fn check_pair(
        rust_op: fn(Tnum, Tnum) -> Tnum,
        encode: fn(&SymTnum, &SymTnum) -> SymTnum,
        a: Tnum,
        b: Tnum,
    ) -> bool {
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let solver = Solver::new();
            let sa = SymTnum {
                value: BV::from_u64(a.value, TNUM_WIDTH),
                mask: BV::from_u64(a.mask, TNUM_WIDTH),
            };
            let sb = SymTnum {
                value: BV::from_u64(b.value, TNUM_WIDTH),
                mask: BV::from_u64(b.mask, TNUM_WIDTH),
            };
            let out = encode(&sa, &sb);
            let expected = rust_op(a, b);
            // the encoding must reproduce the Rust value/mask exactly
            solver.assert(out.value.eq(BV::from_u64(expected.value, TNUM_WIDTH)));
            solver.assert(out.mask.eq(BV::from_u64(expected.mask, TNUM_WIDTH)));
            solver.check() == SatResult::Sat
        })
    }

    fn t(v: u64, m: u64) -> Tnum {
        Tnum { value: v, mask: m }
    }

    #[test]
    fn tnum_encodings_match_rust() {
        let cases = [
            t(0, 0),
            t(0x1234, 0),
            t(0, u64::MAX),
            t(0x0101, 0x1010),
            t(0xFFFF_FFFF_0000_0000, 0x0000_0000_FFFF_FFFF),
            t(0x8000_0000_0000_0000, 0x7FFF_FFFF_FFFF_FFFF),
        ];
        for a in cases {
            for b in cases {
                assert!(check_pair(Tnum::add, encode_add, a, b), "add {a} {b}");
                assert!(check_pair(Tnum::sub, encode_sub, a, b), "sub {a} {b}");
                assert!(check_pair(Tnum::xor, encode_xor, a, b), "xor {a} {b}");
                assert!(check_pair(Tnum::and, encode_and, a, b), "and {a} {b}");
                assert!(check_pair(Tnum::or, encode_or, a, b), "or {a} {b}");
            }
        }
    }

    #[test]
    fn tnum_shift_encodings_match_rust() {
        for k in [0u32, 1, 7, 31, 32, 63] {
            let a = t(0xFFFF_FFFF_0000_0001, 0x0000_0000_FFFF_FFFE);
            let cfg = Config::new();
            with_z3_config(&cfg, || {
                let sa = SymTnum {
                    value: BV::from_u64(a.value, TNUM_WIDTH),
                    mask: BV::from_u64(a.mask, TNUM_WIDTH),
                };
                let kk = BV::from_u64(k as u64, TNUM_WIDTH);
                for (rust, enc) in [
                    (a.lshift(k), encode_lshift(&sa, &kk)),
                    (a.rshift(k), encode_rshift(&sa, &kk)),
                    (a.arshift(k), encode_arshift(&sa, &kk)),
                ] {
                    let s = Solver::new();
                    s.assert(enc.value.eq(BV::from_u64(rust.value, TNUM_WIDTH)));
                    s.assert(enc.mask.eq(BV::from_u64(rust.mask, TNUM_WIDTH)));
                    assert_eq!(s.check(), SatResult::Sat, "shift {k}");
                }
            });
        }
    }

    #[test]
    fn tnum_subreg_and_range_encode() {
        // subreg: high bits cleared
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let a = t(0xFFFF_FFFF_0000_0001, 0x0000_0000_FFFF_FFFE);
            let sa = SymTnum {
                value: BV::from_u64(a.value, TNUM_WIDTH),
                mask: BV::from_u64(a.mask, TNUM_WIDTH),
            };
            let out = encode_subreg(&sa);
            let subreg = a.subreg();
            let s = Solver::new();
            s.assert(out.value.eq(BV::from_u64(subreg.value, TNUM_WIDTH)));
            s.assert(out.mask.eq(BV::from_u64(subreg.mask, TNUM_WIDTH)));
            assert_eq!(s.check(), SatResult::Sat);
        });
        // from_range: the known prefix above the highest differing bit
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let lo = BV::from_u64(0x100, TNUM_WIDTH);
            let hi = BV::from_u64(0x1FF, TNUM_WIDTH);
            let out = encode_from_range(&lo, &hi);
            let s = Solver::new();
            s.assert(out.value.eq(BV::from_u64(0x100, TNUM_WIDTH)));
            s.assert(out.mask.eq(BV::from_u64(0xFF, TNUM_WIDTH)));
            assert_eq!(s.check(), SatResult::Sat);
        });
        // from_range constant
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let lo = BV::from_u64(42, TNUM_WIDTH);
            let hi = BV::from_u64(42, TNUM_WIDTH);
            let out = encode_from_range(&lo, &hi);
            let s = Solver::new();
            s.assert(out.mask.eq(BV::from_u64(0, TNUM_WIDTH)));
            assert_eq!(s.check(), SatResult::Sat);
        });
    }
}
