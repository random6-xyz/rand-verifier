// ── Failure reducer (v0.8, #75–#84) ──────────────────────────────────────────

//! Automatic testcase minimization: shrink fuzzer findings down to a
//! human-analyzable minimal reproducer (PLAN Phase 5). The reduction
//! invariant is the v0.7 oracle itself — a candidate must re-classify
//! to the same finding (#76); deletion is always offset-fixed (#77);
//! the search is ddmin with a shared cache and budget (#78) over CFG
//! and operand passes (#79/#80), driven by a fixpoint driver (#81) and
//! a CLI (#82).

pub mod replay;

pub use replay::{
    Baseline, FindingSpec, Invariant, ReduceError, Sides, evaluate_bytes, invariant_for,
    is_kernel_dependent, load_and_replay, load_finding, replay_check,
};
