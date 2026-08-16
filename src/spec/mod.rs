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
//! `dead_code` is allowed until issue #113 wires the spec into the
//! fuzz oracle as the fourth axis (the corpus tests are the only
//! consumers today).

#![allow(dead_code)]

pub(crate) mod helper;
pub(crate) mod runner;
pub(crate) mod state;
pub(crate) mod value;
