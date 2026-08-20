//! rand-verifier — a learning reimplementation of the Linux eBPF verifier.
//!
//! The crate is organized around the milestone structure of the project:
//!
//! - [`insn`] — instruction representation and decoding
//! - [`klog`] — kernel verifier log parsing and reason categories (#59)
//! - [`krun`] — kernel-side program loading via the raw bpf() syscall (#59)
//! - [`diff`] — differential verdict comparison between the two verifiers (#60)
//! - [`state`] — abstract register/stack state (micro pass)
//! - [`exec`] — abstract instruction execution and branch expansion
//! - [`cfg`] — control flow graph checks (nano pass)
//! - [`concrete`] — concrete execution state model (v0.5)
//! - [`liveness`] — static liveness analysis (#97)
//! - [`state_eq`] — kernel-style state equality (#97)
//! - [`mini`] — path-sensitive exploration (mini pass)
//! - [`helper`] — helper function prototypes and argument validation
//! - [`tnum`] — tracked number abstraction (wired into the [`state`]
//!   scalar bounds, intersected with the range on every narrowing)
//! - [`trace`] — execution trace rendering
//! - [`error`] — verification error types and the final verdict
//! - [`env`] — program loading and the full verification pipeline
//! - [`fuzz`] — fuzz infrastructure (v0.7): instruction builders and value pools

pub mod cfg;
pub mod concrete;
pub mod diff;
pub mod env;
pub mod error;
pub mod exec;
pub mod fuzz;
pub mod helper;
pub mod insn;
pub mod klog;
pub mod krun;
pub mod liveness;
pub mod mini;
#[cfg(feature = "smt")]
pub mod smt;
pub mod spec;
pub mod state;
pub mod state_eq;
pub mod tnum;
pub mod trace;

#[cfg(test)]
mod testutil;
