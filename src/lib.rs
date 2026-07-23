//! # rand-verifier
//!
//! A Rust reimplementation of the Linux kernel eBPF verifier, built for learning.
//!
//! The project is structured in three milestones:
//!
//! - **Nano** — Structural verification (CFG correctness)
//! - **Micro** — Abstract state interpretation (registers, stack, scalars)
//! - **Mini** — Path-sensitive verification (branch exploration, state pruning)
//!
//! ## Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`instruction`] | eBPF instruction and register types |
//! | [`decoder`] | Bytecode → instruction decoding |
//! | [`program`] | Program container and instruction indexing |
//! | [`cfg`] | Control-flow graph construction |
//! | [`error`] | Decode and verification error types |
//! | [`verifier`] | Verifier implementations (nano, micro, mini) |

pub mod cfg;
pub mod decoder;
pub mod error;
pub mod instruction;
pub mod program;
pub mod verifier;
