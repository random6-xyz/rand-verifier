//! drift — corpus verdict and state-count drift monitoring against the
//! kernel (issue #102).
//!
//! Records a snapshot of every corpus program's mini verdict and
//! checkpoint count plus the kernel's verdict and its processed-insn /
//! state counts (parsed from the verifier log), then compares two
//! snapshots and reports regressions: verdict flips in either
//! direction, and state-count changes beyond a threshold.
//!
//! Usage:
//!   drift --record <out.json>          # run mini + kernel on the corpus
//!   drift --compare <base.json> --new <new.json> [--verbose]
//!
//! The kernel side needs the bpf() syscall (root / CAP_BPF); the
//! record mode must run privileged (the CI diff job does).

use std::collections::HashMap;
use std::path::Path;

use rand_verifier::mini::{VerifierLimits, verify_mini_with_limits};

/// One program's drift record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DriftRecord {
    mini: Option<MiniSide>,
    kernel: Option<KernelSide>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MiniSide {
    verdict: String,
    /// The mini's stored checkpoint count (the kernel's total_states
    /// analog, #97).
    states: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct KernelSide {
    verdict: String,
    /// processed N insns — parsed from the verifier summary.
    insns: Option<u64>,
    total_states: Option<u64>,
    peak_states: Option<u64>,
}

type Snapshot = HashMap<String, DriftRecord>;

fn parse_kernel_summary(log: &str) -> (u64, u64, u64) {
    // "processed 204 insns (limit 1000000) max_states_per_insn 4
    //  total_states 6 peak_states 6 mark_read 0"
    let mut insns = 0u64;
    let mut total = 0u64;
    let mut peak = 0u64;
    for line in log.lines() {
        let mut it = line.split_whitespace();
        while let Some(w) = it.next() {
            match w {
                "processed" => {
                    if let Some(n) = it.next().and_then(|n| n.parse().ok()) {
                        insns = n;
                    }
                }
                "total_states" => {
                    if let Some(n) = it.next().and_then(|n| n.parse().ok()) {
                        total = n;
                    }
                }
                "peak_states" => {
                    if let Some(n) = it.next().and_then(|n| n.parse().ok()) {
                        peak = n;
                    }
                }
                _ => {}
            }
        }
    }
    (insns, total, peak)
}

fn mini_side(program: &[rand_verifier::insn::BpfInsn]) -> MiniSide {
    let subprogs = match rand_verifier::cfg::add_subprog(program) {
        Ok(s) => s,
        Err(f) => {
            return MiniSide {
                verdict: format!("REJECT({})", f.message),
                states: 0,
            };
        }
    };
    let loop_heads = match rand_verifier::cfg::check_cfg(program, &subprogs) {
        Ok(h) => h,
        Err(f) => {
            return MiniSide {
                verdict: format!("REJECT({})", f.message),
                states: 0,
            };
        }
    };
    match verify_mini_with_limits(program, &loop_heads, &VerifierLimits::default()) {
        Ok(states) => MiniSide {
            verdict: "ACCEPT".to_string(),
            states,
        },
        Err(f) => MiniSide {
            verdict: format!("REJECT({})", f.message),
            states: 0,
        },
    }
}

fn run_program(path: &Path) -> DriftRecord {
    let data = std::fs::read(path).unwrap_or_default();
    let insns = rand_verifier::insn::decode_program(&data).unwrap_or_default();
    let mini = mini_side(&insns);
    let maps = rand_verifier::env::parse_maps_sidecar(path.to_str().unwrap());
    let (outcome, log) = rand_verifier::krun::load_with_kernel_maps_level(&data, &maps, 1);
    let kernel = match outcome {
        rand_verifier::krun::KernelOutcome::Accept => {
            let (insns, total, peak) = parse_kernel_summary(&log);
            KernelSide {
                verdict: "ACCEPT".to_string(),
                insns: Some(insns),
                total_states: Some(total),
                peak_states: Some(peak),
            }
        }
        rand_verifier::krun::KernelOutcome::Reject { category, .. } => KernelSide {
            verdict: format!("REJECT({:?})", category),
            insns: None,
            total_states: None,
            peak_states: None,
        },
        other => KernelSide {
            verdict: format!("SKIP({:?})", other),
            insns: None,
            total_states: None,
            peak_states: None,
        },
    };
    DriftRecord {
        mini: Some(mini),
        kernel: Some(kernel),
    }
}

fn record_corpus() -> Snapshot {
    let mut snap = Snapshot::new();
    for sub in ["accept", "reject"] {
        let dir = Path::new("tests/programs").join(sub);
        let mut paths: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_none())
            .collect();
        paths.sort();
        for path in paths {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            snap.insert(name, run_program(&path));
        }
    }
    snap
}

/// Compare two snapshots and report regressions. Returns the number of
/// verdict regressions (exit code material).
fn compare(base: &Snapshot, new: &Snapshot, verbose: bool) -> usize {
    let mut regressions = 0usize;
    let mut names: Vec<&String> = base.keys().chain(new.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let b = base.get(name);
        let n = new.get(name);
        let verdict_flip = match (b, n) {
            (Some(b), Some(n)) => {
                let bv = (
                    b.mini.as_ref().map(|m| &m.verdict),
                    b.kernel.as_ref().map(|k| &k.verdict),
                );
                let nv = (
                    n.mini.as_ref().map(|m| &m.verdict),
                    n.kernel.as_ref().map(|k| &k.verdict),
                );
                bv != nv
            }
            _ => b.is_some() != n.is_some(),
        };
        if verdict_flip {
            regressions += 1;
            println!(
                "DRIFT VERDICT {name}: {:?} → {:?}",
                b.map(|r| r.kernel.as_ref().map(|k| &k.verdict)),
                n.map(|r| r.kernel.as_ref().map(|k| &k.verdict))
            );
        }
        if let (Some(b), Some(n)) = (b, n) {
            if let (Some(bk), Some(nk)) = (b.kernel.as_ref(), n.kernel.as_ref()) {
                if let (Some(bi), Some(ni)) = (bk.insns, nk.insns) {
                    let rel = (ni as i64 - bi as i64).unsigned_abs();
                    if bi > 0 && rel * 100 / bi > 10 {
                        println!("DRIFT INSNS {name}: {bi} → {ni} ({}%)", rel * 100 / bi);
                    }
                }
                if let (Some(bs), Some(ns)) = (bk.total_states, nk.total_states)
                    && bs != ns
                {
                    println!("DRIFT STATES {name}: {bs} → {ns}");
                }
            }
            if let (Some(bm), Some(nm)) = (b.mini.as_ref(), n.mini.as_ref())
                && bm.states != nm.states
            {
                println!("DRIFT MINI-STATES {name}: {} → {}", bm.states, nm.states);
            }
        }
    }
    if verbose {
        for (name, r) in new {
            if let Some(k) = r.kernel.as_ref() {
                println!(
                    "{:<38} mini={} ({} states) kernel={} ({} insns, {} states)",
                    name,
                    r.mini.as_ref().map(|m| m.verdict.as_str()).unwrap_or("-"),
                    r.mini.as_ref().map(|m| m.states).unwrap_or(0),
                    k.verdict,
                    k.insns.unwrap_or(0),
                    k.total_states.unwrap_or(0),
                );
            }
        }
    }
    regressions
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--record") {
        let out = args
            .iter()
            .position(|a| a == "--record")
            .and_then(|i| args.get(i + 1))
            .expect("usage: drift --record <out.json>");
        let snap = record_corpus();
        let json = serde_json::to_string_pretty(&snap).unwrap();
        std::fs::write(out, json).expect("cannot write the snapshot");
        eprintln!("drift snapshot written to {out} ({} programs)", snap.len());
        return;
    }
    if args.iter().any(|a| a == "--compare") {
        let base_path = args
            .iter()
            .position(|a| a == "--compare")
            .and_then(|i| args.get(i + 1))
            .expect("usage: drift --compare <base.json> --new <new.json>");
        let new_path = args
            .iter()
            .position(|a| a == "--new")
            .and_then(|i| args.get(i + 1))
            .expect("usage: drift --compare <base.json> --new <new.json>");
        let verbose = args.iter().any(|a| a == "--verbose");
        let base: Snapshot =
            serde_json::from_str(&std::fs::read_to_string(base_path).unwrap()).unwrap();
        let new: Snapshot =
            serde_json::from_str(&std::fs::read_to_string(new_path).unwrap()).unwrap();
        let regressions = compare(&base, &new, verbose);
        if regressions > 0 {
            eprintln!("{regressions} verdict regression(s) — the corpus drifted");
            std::process::exit(1);
        }
        eprintln!("drift comparison clean");
        return;
    }
    eprintln!(
        "usage: drift --record <out.json> | drift --compare <base.json> --new <new.json> [--verbose]"
    );
    std::process::exit(2);
}
