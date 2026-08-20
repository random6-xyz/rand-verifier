//! qemu guest agent: verify raw eBPF programs through the real kernel
//! verifier inside the bpf-next guest and print a single machine-
//! readable line per program, matching the format the host-side fuzz
//! campaign parses (`src/fuzz/qemu.rs::parse_agent_verdict`):
//!
//! ```text
//! ACCEPT
//! REJECT <reason text> errno=<n>
//! ```
//!
//! Usage (invoked by the guest init loop / run.sh):
//!
//! ```sh
//! /sbin/agent [--strict] <program-file>...
//! ```
//!
//! No `.maps` sidecar travels over the 9p share, so the agent resolves
//! every map fd referenced by ldimm64 pseudo instructions against a
//! default ARRAY map (4-byte key, 8-byte value, 1 entry) and creates
//! real kernel maps for them before the load — the guest-side analog of
//! `load_with_kernel_maps` with a synthetic registry.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

use rand_verifier::env::{MapInfo, MapType};
use rand_verifier::krun::{KernelOutcome, drop_privileged_caps, load_with_kernel_maps_level};

/// Collect the map fds referenced by ldimm64 pseudo instructions from
/// raw program bytes (mirror of the private `krun::referenced_map_fds`).
fn referenced_map_fds(insns: &[u8]) -> Vec<u32> {
    let mut fds = Vec::new();
    let mut i = 0usize;
    while i + 16 <= insns.len() {
        if insns[i] == 0x18 {
            let pseudo = (insns[i + 1] >> 4) & 0x0F;
            if pseudo == 1 || pseudo == 2 {
                // BPF_PSEUDO_MAP_FD / BPF_PSEUDO_MAP_VALUE
                let fd =
                    u32::from_le_bytes([insns[i + 4], insns[i + 5], insns[i + 6], insns[i + 7]]);
                if !fds.contains(&fd) {
                    fds.push(fd);
                }
            }
            i += 16;
        } else {
            i += 8;
        }
    }
    fds
}

/// Synthetic map registry: every referenced fd maps to the ARRAY
/// default (key 4, value 8, max_entries 1) — the same shape the
/// fuzzer's generated programs expect (mini's default test map).
fn default_maps(insns: &[u8]) -> HashMap<u32, MapInfo> {
    let mut maps = HashMap::new();
    for fd in referenced_map_fds(insns) {
        maps.insert(
            fd,
            MapInfo {
                map_type: MapType::Array,
                key_size: 4,
                value_size: 8,
                max_entries: 1,
            },
        );
    }
    maps
}

fn run_program_bytes(data: &[u8]) {
    let maps = default_maps(data);
    // AGENT_LOG=1 → full verifier log (level 2) kept for diagnostics; a
    // subset is printed to stderr (captured into the out file by run.sh)
    let log_level = if std::env::var_os("AGENT_LOG").is_some() {
        2
    } else {
        1
    };
    let (outcome, log) = load_with_kernel_maps_level(data, &maps, log_level);
    match outcome {
        KernelOutcome::Accept => println!("ACCEPT"),
        KernelOutcome::Reject { message, .. } => println!("REJECT {message} errno=0"),
        KernelOutcome::Privilege => println!("REJECT not-privileged errno=1"),
        KernelOutcome::NoErrorLine { errno } => println!("REJECT no-error-line errno={errno}"),
        KernelOutcome::InvalidProgram => println!("REJECT invalid-program errno=0"),
    }
    if log_level >= 2 {
        eprintln!("AGENT_LOG: log len {} bytes", log.len());
        eprintln!("--- log head ---");
        eprintln!("{}", log.lines().take(30).collect::<Vec<_>>().join("\n"));
        eprintln!("--- log tail ---");
        eprintln!(
            "{}",
            log.lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    // NB: do NOT print anything to stderr here — the guest run.sh
    // redirects stderr into the same out file, and the host parser
    // (src/fuzz/qemu.rs::parse_agent_verdict) keys off the first line,
    // which must be exactly `ACCEPT` or `REJECT ...`.
    let strict = rest.contains(&"--strict");
    let files: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| *a != "--strict" && *a != "--")
        .collect();
    if files.is_empty() {
        eprintln!("usage: agent [--strict] <program-file>...");
        process::exit(2);
    }
    // Read every program file FIRST, while we still have full root
    // privileges: the 9p share can surface host-owned files that the
    // (dropped-privilege) agent cannot open afterwards. Dropping caps
    // is only safe once the bytes are in memory.
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for f in &files {
        match fs::read(f) {
            Ok(d) => payloads.push(d),
            Err(e) => {
                eprintln!(
                    "cannot-read detail: path={f} errno={}",
                    e.raw_os_error().unwrap_or(-1)
                );
                println!("REJECT cannot-read job file errno=2");
                return;
            }
        }
    }
    if strict {
        let _ = drop_privileged_caps();
    }
    for data in payloads {
        run_program_bytes(&data);
    }
}
