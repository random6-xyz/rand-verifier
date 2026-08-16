// ── SMT translation of tnum/range operators (issue #115) ────────────────────

//! Agni-style (CAV '23) verification of the abstract operators: every
//! operator in scope gets a faithful bitvector encoding plus
//! soundness checks. The encodings translate the Rust implementations
//! (src/tnum.rs, src/exec.rs) into SMT bitvector formulas; the
//! soundness harness (issue #116) checks `op(γ(a), γ(b)) ⊆ γ(g(a,b))`
//! both exhaustively on small bit-widths and symbolically on 64 bits.
//!
//! A shared symbolic value context keeps the encodings uniform:
//! [`Sym`] wraps a z3 BV of a fixed width with a unique name prefix
//! for solver-time readability.

pub mod range;
pub mod tnum;
pub mod verify;

use z3::ast::BV;

/// A symbolic bitvector value with a width and a name prefix.
#[derive(Clone)]
pub struct Sym {
    pub name: String,
    pub bv: BV,
    pub width: u32,
}

impl Sym {
    /// A fresh symbolic constant of `width` bits.
    pub fn fresh(prefix: &str, width: u32) -> Self {
        Self {
            name: prefix.to_string(),
            bv: BV::fresh_const(prefix, width),
            width,
        }
    }

    /// A constant.
    pub fn const_u64(v: u64, width: u32) -> Self {
        Self {
            name: format!("0x{v:x}"),
            bv: BV::from_u64(v, width),
            width,
        }
    }
}

/// The tristate value of a tnum: `value` (known bits) and `mask`
/// (unknown bits) as symbolic bitvectors.
#[derive(Clone)]
pub(crate) struct SymTnum {
    pub value: BV,
    pub mask: BV,
}

/// The symbolic range `[lo, hi]` of a scalar.
#[derive(Clone)]
pub(crate) struct SymRange {
    pub lo: BV,
    pub hi: BV,
}
