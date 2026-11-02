//! qemu guest agent: verify raw eBPF programs through the real kernel
//! verifier inside the bpf-next guest and print a single machine-
//! readable line per program, matching the format the host-side fuzz
//! campaign parses (`src/fuzz/qemu.rs::parse_agent_verdict`):
//!
//! ```text
//! ACCEPT
//! REJECT <reason text> insn_idx=<n> errno=<n>
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
use rand_verifier::krun::{
    CapMode, KernelOutcome, drop_caps, load_with_kernel_maps_level, referenced_map_fds,
};

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

fn format_kernel_verdict(outcome: &KernelOutcome) -> String {
    match outcome {
        KernelOutcome::Accept => "ACCEPT".to_string(),
        KernelOutcome::Reject {
            message, insn_idx, ..
        } => format!("REJECT {message} insn_idx={insn_idx} errno=0"),
        KernelOutcome::Privilege => "REJECT not-privileged errno=1".to_string(),
        KernelOutcome::NoErrorLine { errno } => format!("REJECT no-error-line errno={errno}"),
        KernelOutcome::InvalidProgram => "REJECT invalid-program errno=0".to_string(),
    }
}

fn run_program_bytes(data: &[u8]) {
    let maps = default_maps(data);
    // Full verifier log (level 2) is the default since #142: level 1
    // drops the first error line on errno=28 programs (K-2), which made
    // a plain bounded loop look like "no-error-line errno=28".
    // AGENT_LOG=0 opts back into level 1 for throughput runs.
    let log_level = match std::env::var("AGENT_LOG").ok().as_deref() {
        Some("0") => 1,
        _ => 2,
    };
    let (outcome, log) = load_with_kernel_maps_level(data, &maps, log_level);
    // a 4 MiB buffer still runs out on pathological state dumps: retry
    // once with the error-only log so the verdict is never lost
    let (outcome, log) = match outcome {
        KernelOutcome::NoErrorLine { errno: 28 } if log_level > 1 => {
            let (outcome, log) = load_with_kernel_maps_level(data, &maps, 1);
            (outcome, log)
        }
        other => (other, log),
    };
    println!("{}", format_kernel_verdict(&outcome));
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
    // capability axis (#143): --caps <priv|cap-bpf|cap-bpf-perfmon|unpriv>;
    // --strict stays as the cap-bpf alias
    let mut caps = if rest.contains(&"--strict") {
        CapMode::CapBpf
    } else {
        CapMode::Priv
    };
    let mut skip_next = false;
    for (i, arg) in rest.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if *arg == "--caps" {
            let Some(value) = rest.get(i + 1) else {
                eprintln!("--caps needs a value");
                process::exit(2);
            };
            match CapMode::parse(value) {
                Some(mode) => caps = mode,
                None => {
                    eprintln!("unknown --caps value {value}");
                    process::exit(2);
                }
            }
            skip_next = true;
        }
    }
    let files: Vec<&str> = rest
        .iter()
        .copied()
        .enumerate()
        .filter(|(i, a)| {
            *a != "--strict" && *a != "--" && *a != "--caps" && !(*i > 0 && rest[i - 1] == "--caps")
        })
        .map(|(_, a)| a)
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
    if caps != CapMode::Priv && drop_caps(caps).is_err() {
        // A failed capability drop must never fall back to a privileged
        // kernel verdict. The host classifies this as infrastructure skip.
        for _ in &payloads {
            println!("REJECT not-privileged errno=1");
        }
        return;
    }
    for data in payloads {
        run_program_bytes(&data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_verifier::klog::ReasonCategory;

    #[test]
    fn rejection_output_preserves_instruction_index() {
        let outcome = KernelOutcome::Reject {
            insn_idx: 7,
            message: "invalid mem access".into(),
            category: ReasonCategory::PointerArith,
        };
        assert_eq!(
            format_kernel_verdict(&outcome),
            "REJECT invalid mem access insn_idx=7 errno=0"
        );
    }

    #[test]
    fn capability_mode_parsing_rejects_unknown_values() {
        assert_eq!(CapMode::parse("--strict"), None);
        assert_eq!(CapMode::parse("cap-bpf"), Some(CapMode::CapBpf));
        assert_eq!(CapMode::parse("unpriv"), Some(CapMode::Unpriv));
    }
}
