// ── Fuzz infrastructure (v0.7, #63) ─────────────────────────────────────────

pub mod generator;
pub mod idiom;
pub mod insn_lib;
pub mod mutator;
pub mod oracle;
pub(crate) mod prng;
pub mod qemu;
pub mod reduce;
pub mod triage;

#[cfg(test)]
mod regression;
