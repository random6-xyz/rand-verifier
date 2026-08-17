// ── ProgSpec: the independent safety-spec oracle (issue #112) ────────────────

//! The safety specification that becomes the fourth oracle axis
//! (issue #113): a SpecCheck-style (SOSP '25 Veritas) independent
//! verifier covering scalar ranges, stack access safety, pointer
//! arithmetic and helper-call contracts.
//!
//! The spec is deliberately NOT a clone of mini:
//! - one wrapping u64 interval per scalar (mini: four ranges + tnum)
//! - a visited-set loop handler (mini: kernel-style checkpoints)
//! - its own dynamic types and helper table
//!
//! [`verify_spec`] returns [`SpecVerdict`]; the verdict report and the
//! divergence audit against mini live in docs/spec-oracle-design.md.
//!
//! Since issue #113 the fuzz oracle (src/fuzz/oracle.rs) consumes
//! `verify_spec` as the fourth verdict axis; remaining item-level
//! `#[allow(dead_code)]` carries a reason where an item is only used
//! by tests or a later issue.

pub(crate) mod helper;
pub(crate) mod runner;
pub(crate) mod state;
pub(crate) mod value;

/// The interval arithmetic shared with the SMT tooling (issues
/// #115-#117): sound wrapping-u64 interval operators.
pub use value::{rng_add, rng_and, rng_mul, rng_or, rng_sub, rng_xor};

pub use runner::{SpecFailure, SpecVerdict, verify_spec};
