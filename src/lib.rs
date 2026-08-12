//! rand-verifier — a learning reimplementation of the Linux eBPF verifier.
//!
//! The crate is organized around the milestone structure of the project:
//!
//! - [`insn`] — instruction representation and decoding
//! - [`state`] — abstract register/stack state (micro pass)
//! - [`exec`] — abstract instruction execution and branch expansion
//! - [`cfg`] — control flow graph checks (nano pass)
//! - [`concrete`] — concrete execution state model (v0.5)
//! - [`mini`] — path-sensitive exploration (mini pass)
//! - [`helper`] — helper function prototypes and argument validation
//! - [`tnum`] — tracked number abstraction (not wired into `RegState` yet)
//! - [`trace`] — execution trace rendering
//! - [`error`] — verification error types and the final verdict
//! - [`env`] — program loading and the full verification pipeline

pub mod cfg;
pub mod concrete;
pub mod env;
pub mod error;
pub mod exec;
pub mod helper;
pub mod insn;
pub mod mini;
pub mod state;
pub mod tnum;
pub mod trace;

#[cfg(test)]
mod testutil;
