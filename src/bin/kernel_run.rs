//! kernel-runner: load an eBPF program into the real Linux kernel
//! verifier via the raw `bpf()` syscall — no libbpf dependency
//! (issue #59).
//!
//! Usage:
//!
//! ```sh
//! kernel_run <program-file>   # verify one program
//! kernel_run --all            # verify every tests/programs corpus program
//! ```
//!
//! Loading is privileged on most systems
//! (`kernel.unprivileged_bpf_disabled = 2`): run as root / with CAP_BPF,
//! e.g. `sudo target/debug/kernel_run --all`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use rand_verifier::insn::{disassemble, parse_insn};
use rand_verifier::klog::ReasonCategory;
use rand_verifier::krun::{KernelOutcome, drop_cap_perfmon, load_with_kernel};

/// Print the disassembly of a program (decode errors are shown inline —
/// the kernel would reject them as "unknown opcode").
fn print_program(insns: &[u8]) {
    for (i, chunk) in insns.chunks_exact(8).enumerate() {
        match parse_insn(chunk) {
            Ok(insn) => println!("{:4}: {}", i, disassemble(&insn)),
            Err(e) => println!("{:4}: <{}>", i, e),
        }
    }
}

fn category_name(category: ReasonCategory) -> &'static str {
    match category {
        ReasonCategory::UninitRead => "UninitRead",
        ReasonCategory::StackBounds => "StackBounds",
        ReasonCategory::StackAlign => "StackAlign",
        ReasonCategory::PointerArith => "PointerArith",
        ReasonCategory::HelperArgs => "HelperArgs",
        ReasonCategory::CfgJump => "CfgJump",
        ReasonCategory::Loop => "Loop",
        ReasonCategory::Unreachable => "Unreachable",
        ReasonCategory::ExitR0 => "ExitR0",
        ReasonCategory::Complexity => "Complexity",
        ReasonCategory::Other => "Other",
    }
}

/// Load one program and print the outcome: ACCEPT / REJECT (+ reason
/// category) / privileged-load failure.
fn run_program(path: &Path, verbose: bool) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("{}: cannot read: {}", path.display(), e);
            return;
        }
    };

    if verbose {
        print_program(&data);
    }

    match load_with_kernel(&data) {
        KernelOutcome::Accept => println!("{}: ACCEPT", path.display()),
        KernelOutcome::Reject {
            insn_idx,
            message,
            category,
        } => {
            println!(
                "{}: REJECT at insn {}: {} [{}]",
                path.display(),
                insn_idx,
                message,
                category_name(category)
            );
        }
        KernelOutcome::Privilege => println!(
            "{}: EPERM — the bpf() syscall is not permitted (run as root / with CAP_BPF, or enable unprivileged BPF)",
            path.display()
        ),
        KernelOutcome::NoErrorLine { errno } => println!(
            "{}: REJECT errno {} (no error line in the verifier log)",
            path.display(),
            errno
        ),
        KernelOutcome::InvalidProgram => println!(
            "{}: not a valid program (empty or not a multiple of 8 bytes)",
            path.display()
        ),
    }
}

/// All corpus programs, accept first then reject (the #60 diff input).
fn corpus_programs() -> Vec<PathBuf> {
    let mut programs = Vec::new();
    for sub in ["accept", "reject"] {
        let dir = Path::new("tests/programs").join(sub);
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_none())
            .collect();
        entries.sort();
        programs.extend(entries);
    }
    programs
}

fn usage() -> ! {
    eprintln!(
        "Usage: kernel_run <program-file> | kernel_run --all | kernel_run --strict --all\n\
         Loads an eBPF program into the kernel verifier via the raw bpf() syscall.\n\
         Requires root / CAP_BPF on systems with unprivileged BPF disabled.\n\
         --strict drops CAP_PERFMON so the verifier applies its strict rules\n\
         (uninit-stack reads and pointer leaks are rejected)."
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let strict = args.iter().any(|a| a == "--strict");
    if strict {
        drop_cap_perfmon();
        eprintln!("strict mode: CAP_PERFMON dropped");
    }
    match args.iter().find(|a| *a != "--strict").map(String::as_str) {
        Some("--all") => {
            for path in corpus_programs() {
                run_program(&path, false);
            }
        }
        Some(path) => run_program(Path::new(path), true),
        None => usage(),
    }
}
