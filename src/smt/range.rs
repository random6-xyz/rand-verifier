// ── SMT encoding of the range operators (issue #115) ────────────────────────

//! The scalar-range operators of src/exec.rs / src/spec/value.rs
//! encoded as bitvector formulas: wrapping u64 interval arithmetic
//! (add/sub/mul), the ALU32 truncate-and-zero-extend path, and the
//! signed/unsigned comparisons used by branch refinement. The
//! encodings are the formula translations of the Rust interval
//! functions; the tests cross-check them on concrete inputs and the
//! soundness harness (issue #116) checks containment symbolically.

use z3::ast::{BV, Bool};

pub(crate) use super::SymRange;

/// 64-bit width of scalar ranges.
pub const RANGE_WIDTH: u32 = 64;

/// The full u64 range.
pub(crate) fn full_range() -> (BV, BV) {
    (
        BV::from_u64(0, RANGE_WIDTH),
        BV::from_u64(u64::MAX, RANGE_WIDTH),
    )
}

/// `x ∈ [lo, hi]` (unsigned).
pub(crate) fn in_range(x: &BV, r: &SymRange) -> Bool {
    Bool::and(&[&x.bvuge(&r.lo), &x.bvule(&r.hi)])
}

/// Encodes `rng_add` (src/spec/value.rs): the pointwise image of two
/// u64 intervals under wrapping addition, a single interval when the
/// 65-bit sum spans one 2^64 block, the full range otherwise.
pub(crate) fn encode_uadd(a: &SymRange, b: &SymRange) -> (BV, BV) {
    let lo = a.lo.zero_ext(1).bvadd(b.lo.zero_ext(1));
    let hi = a.hi.zero_ext(1).bvadd(b.hi.zero_ext(1));
    let same_block = lo.extract(64, 64).eq(hi.extract(64, 64));
    let out_lo = Bool::ite(&same_block, &lo.extract(63, 0), &BV::from_u64(0, 64));
    let out_hi = Bool::ite(&same_block, &hi.extract(63, 0), &BV::from_u64(u64::MAX, 64));
    (out_lo, out_hi)
}

/// Encodes `rng_sub` (src/spec/value.rs): `[a0,a1] ⊟ [b0,b1] =
/// [a0-b1, a1-b0]` modulo 2^64, a single interval iff the span is
/// below 2^64 and the folded interval does not wrap.
pub(crate) fn encode_usub(a: &SymRange, b: &SymRange) -> (BV, BV) {
    let dlo = a.lo.bvsub(&b.hi); // folded lower bound (64-bit wrap)
    // span = (a1-a0) + (b1-b0), 65 bits
    let span =
        a.hi.bvsub(&a.lo)
            .zero_ext(1)
            .bvadd(b.hi.bvsub(&b.lo).zero_ext(1));
    let span_ok = span.extract(64, 64).eq(BV::from_u64(0, 1));
    // folded_lo + span < 2^64
    let fold_ok = dlo
        .zero_ext(1)
        .bvadd(&span)
        .extract(64, 64)
        .eq(BV::from_u64(0, 1));
    let ok = Bool::and(&[&span_ok, &fold_ok]);
    let dhi = dlo.bvadd(span.extract(63, 0));
    let (fl, fh) = full_range();
    (Bool::ite(&ok, &dlo, &fl), Bool::ite(&ok, &dhi, &fh))
}

/// Encodes `rng_mul` (src/spec/value.rs): exact for constant pairs,
/// the full range otherwise.
pub(crate) fn encode_umul(a: &SymRange, b: &SymRange) -> (BV, BV) {
    let a_const = a.lo.eq(&a.hi);
    let b_const = b.lo.eq(&b.hi);
    let both_const = Bool::and(&[&a_const, &b_const]);
    let prod = a.lo.bvmul(&b.lo);
    let (fl, fh) = full_range();
    (
        Bool::ite(&both_const, &prod, &fl),
        Bool::ite(&both_const, &prod, &fh),
    )
}

/// Encodes `rng_or` (src/spec/value.rs): `[max(a0, b0), MAX]`.
pub(crate) fn encode_uor(a: &SymRange, b: &SymRange) -> (BV, BV) {
    let lo = Bool::ite(&a.lo.bvugt(&b.lo), &a.lo, &b.lo);
    (lo, BV::from_u64(u64::MAX, 64))
}

/// Encodes `rng_xor` (src/spec/value.rs): `[0, MAX]`.
pub(crate) fn encode_uxor(_a: &SymRange, _b: &SymRange) -> (BV, BV) {
    (BV::from_u64(0, 64), BV::from_u64(u64::MAX, 64))
}

#[cfg(test)]
/// Encodes `rng_and` (src/spec/value.rs): `[0, min(a1, b1)]`.
pub(crate) fn encode_uand(a: &SymRange, b: &SymRange) -> (BV, BV) {
    (
        BV::from_u64(0, 64),
        Bool::ite(&a.hi.bvult(&b.hi), &a.hi, &b.hi),
    )
}

#[cfg(test)]
/// The ALU32 path: truncate the operand range to 32 bits
/// (`range32`), compute, zero-extend the result. Sign-extension
/// (MEMSX loads) uses `sign_ext`.
pub(crate) fn truncate32(lo: &BV, hi: &BV) -> (BV, BV) {
    // the image of [lo,hi] under x ↦ x & 0xffff_ffff: single 32-bit
    // interval iff lo and hi share the top 32 bits
    let same_block = lo.extract(63, 32).eq(hi.extract(63, 32));
    let lo32 = lo.extract(31, 0);
    let hi32 = hi.extract(31, 0);
    let out_lo = Bool::ite(&same_block, &lo32, &BV::from_u64(0, 32));
    let out_hi = Bool::ite(&same_block, &hi32, &BV::from_u64(u32::MAX as u64, 32));
    (out_lo, out_hi)
}

#[cfg(test)]
/// Zero-extend a 32-bit result into 64 bits.
pub(crate) fn zero_extend32(v: &BV) -> BV {
    v.zero_ext(32)
}

#[cfg(test)]
/// Sign-extend a 32-bit result into 64 bits (ALU32 with the sign bit
/// — the kernel zero-extends ALU32 results; MEMSX loads sign-extend).
pub(crate) fn sign_extend32(v: &BV) -> BV {
    v.sign_ext(32)
}

/// The signed interpretation of a range: `[lo, hi]` as i64 — the
/// comparison encodings use the z3 signed operators directly on the
/// bitvectors (two's complement), so no re-interpretation is needed.
/// One comparison of a range against a range — the branch-refinement
/// surface (issue #115): equality, unsigned and signed families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeCmp {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

#[cfg(test)]
/// The SMT encoding of one comparison: `x CMP y` for concrete
/// members `x ∈ a`, `y ∈ b` — the satisfiability of the formula for
/// members is what the soundness harness checks against the
/// refinement (a refinement must never make a feasible outcome
/// unsatisfiable, nor an infeasible one satisfiable).
pub(crate) fn encode_cmp(cmp: RangeCmp, x: &BV, y: &BV) -> Bool {
    match cmp {
        RangeCmp::Eq => x.eq(y),
        RangeCmp::Ne => x.eq(y).not(),
        RangeCmp::Ult => x.bvult(y),
        RangeCmp::Ule => x.bvule(y),
        RangeCmp::Ugt => x.bvugt(y),
        RangeCmp::Uge => x.bvuge(y),
        RangeCmp::Slt => x.bvslt(y),
        RangeCmp::Sle => x.bvsle(y),
        RangeCmp::Sgt => x.bvsgt(y),
        RangeCmp::Sge => x.bvsge(y),
    }
}

#[cfg(test)]
/// The Rust comparison verdict of one scalar pair (mirrors the
/// refinement direction: `dst CMP src`).
pub(crate) fn rust_cmp(cmp: RangeCmp, dst: u64, src: u64) -> bool {
    match cmp {
        RangeCmp::Eq => dst == src,
        RangeCmp::Ne => dst != src,
        RangeCmp::Ult => dst < src,
        RangeCmp::Ule => dst <= src,
        RangeCmp::Ugt => dst > src,
        RangeCmp::Uge => dst >= src,
        RangeCmp::Slt => (dst as i64) < (src as i64),
        RangeCmp::Sle => (dst as i64) <= (src as i64),
        RangeCmp::Sgt => (dst as i64) > (src as i64),
        RangeCmp::Sge => (dst as i64) >= (src as i64),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::value::{rng_add, rng_and, rng_mul, rng_sub};
    use z3::{Config, SatResult, Solver, with_z3_config};

    fn sym(lo: u64, hi: u64) -> SymRange {
        SymRange {
            lo: BV::from_u64(lo, RANGE_WIDTH),
            hi: BV::from_u64(hi, RANGE_WIDTH),
        }
    }

    /// Assert the encoding equals the Rust result on one input pair.
    fn check_binop(
        rust: crate::smt::verify::RangeFnAlias,
        encode: fn(&SymRange, &SymRange) -> (BV, BV),
        a: (u64, u64),
        b: (u64, u64),
    ) -> bool {
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let s = Solver::new();
            let (lo, hi) = encode(&sym(a.0, a.1), &sym(b.0, b.1));
            let (rlo, rhi) = rust(a, b);
            s.assert(lo.eq(BV::from_u64(rlo, RANGE_WIDTH)));
            s.assert(hi.eq(BV::from_u64(rhi, RANGE_WIDTH)));
            s.check() == SatResult::Sat
        })
    }

    #[test]
    fn range_encodings_match_rust() {
        let cases: [(u64, u64); 6] = [
            (0, 0),
            (5, 5),
            (0, 100),
            (u64::MAX - 2, u64::MAX),
            (0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF),
            (0x0000_0000_0000_0001, 0x0000_0001_0000_0000),
        ];
        for a in cases {
            for b in cases {
                assert!(check_binop(rng_add, encode_uadd, a, b), "add {a:?} {b:?}");
                assert!(check_binop(rng_sub, encode_usub, a, b), "sub {a:?} {b:?}");
                assert!(check_binop(rng_mul, encode_umul, a, b), "mul {a:?} {b:?}");
                assert!(check_binop(rng_and, encode_uand, a, b), "and {a:?} {b:?}");
            }
        }
    }

    /// The comparison encodings match the Rust semantics on concrete
    /// pairs (including sign-bit cases).
    #[test]
    fn comparison_encodings_match_rust() {
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let pairs = [
                (0u64, 0u64),
                (1, 2),
                (2, 1),
                (u64::MAX, 1),
                (1, u64::MAX),
                (0x8000_0000_0000_0000, 1),
                (1, 0x8000_0000_0000_0000),
                (0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFE),
            ];
            for (d, s) in pairs {
                for cmp in [
                    RangeCmp::Eq,
                    RangeCmp::Ne,
                    RangeCmp::Ult,
                    RangeCmp::Ule,
                    RangeCmp::Ugt,
                    RangeCmp::Uge,
                    RangeCmp::Slt,
                    RangeCmp::Sle,
                    RangeCmp::Sgt,
                    RangeCmp::Sge,
                ] {
                    let solver = Solver::new();
                    let x = BV::from_u64(d, RANGE_WIDTH);
                    let y = BV::from_u64(s, RANGE_WIDTH);
                    let expected = rust_cmp(cmp, d, s);
                    if expected {
                        solver.assert(encode_cmp(cmp, &x, &y));
                    } else {
                        solver.assert(encode_cmp(cmp, &x, &y).not());
                    }
                    assert_eq!(solver.check(), SatResult::Sat, "{cmp:?} {d:#x} {s:#x}");
                }
            }
        });
    }

    /// The ALU32 sign-extension path (MEMSX loads): a 32-bit value
    /// with the sign bit set sign-extends to all-ones in the high
    /// half; zero-extension clears it.
    #[test]
    fn alu32_sign_extension_encoding() {
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            let v = BV::from_u64(0x8000_0000, 32);
            let z = zero_extend32(&v);
            let s = sign_extend32(&v);
            let solver = Solver::new();
            solver.assert(z.eq(BV::from_u64(0x0000_0000_8000_0000, 64)));
            solver.assert(s.eq(BV::from_u64(0xFFFF_FFFF_8000_0000, 64)));
            assert_eq!(solver.check(), SatResult::Sat);
        });
    }

    #[test]
    fn alu32_truncation_encoding() {
        let cfg = Config::new();
        with_z3_config(&cfg, || {
            // [0x1_0000_0001, 0x1_0000_0003] → [1, 3]
            let (lo, hi) = truncate32(
                &BV::from_u64(0x1_0000_0001, 64),
                &BV::from_u64(0x1_0000_0003, 64),
            );
            let s = Solver::new();
            s.assert(lo.eq(BV::from_u64(1, 32)));
            s.assert(hi.eq(BV::from_u64(3, 32)));
            assert_eq!(s.check(), SatResult::Sat);
            // a range spanning two 32-bit blocks widens
            let (lo, hi) = truncate32(&BV::from_u64(0, 64), &BV::from_u64(u64::MAX, 64));
            let s = Solver::new();
            s.assert(lo.eq(BV::from_u64(0, 32)));
            s.assert(hi.eq(BV::from_u64(u32::MAX as u64, 32)));
            assert_eq!(s.check(), SatResult::Sat);
        });
    }
}
