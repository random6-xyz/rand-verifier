//! replay — replay a labelled verifier corpus across the kernel, mini and
//! the independent spec (#139).
//!
//! The corpus is the (legacy) verifier selftests extracted by
//! `tools/selftest_corpus.py`: every case carries the kernel's expected
//! verdict (`.result`), optionally the unprivileged expectation
//! (`.result_unpriv`) and the prog type. The replay compares:
//!
//! - **kernel**: the selftest expectation, or a recorded kernel column
//!   (`--kernel-column`, produced against the pinned bpf-next image),
//! - **mini**: rand-verifier's abstract verifier,
//! - **spec**: the independent safety spec (accept / reject / inconclusive),
//! - **concrete**: the witness interpreter (via the mini pipeline).
//!
//! Each case is classified exactly like a campaign program (`oracle::classify_env`),
//! so whitelists, surface gaps and the precision/soundness matrix stay in
//! lockstep with the fuzzer.
//!
//! Usage:
//!
//! ```sh
//! cargo run --release --bin replay -- \
//!     --manifest lab/selftest-corpus/manifest.jsonl \
//!     --programs lab/selftest-corpus/programs \
//!     --json /tmp/replay.json
//!
//! cargo run --release --bin replay -- \
//!     --manifest ... --programs ... \
//!     --baseline tools/replay-baseline.json --gate
//! ```

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use rand_verifier::diff::SideVerdict;
use rand_verifier::env::{BpfVerifierEnv, MapInfo};
use rand_verifier::error::Verdict;
use rand_verifier::fuzz::oracle::{Finding, SurfaceGapKind, classify_env, surface_gap_kind};
use rand_verifier::klog::ReasonCategory;
use rand_verifier::krun::referenced_map_fds;
use rand_verifier::prog_type::ProgType;
use rand_verifier::spec::{SpecVerdict, verify_spec_with};

#[derive(serde::Deserialize)]
struct Row {
    id: String,
    name: String,
    file: String,
    expected: String,
    #[serde(default)]
    errstr: Option<String>,
    #[serde(default)]
    result_unpriv: Option<String>,
    #[serde(default)]
    prog_type: Option<String>,
}

#[derive(serde::Deserialize)]
struct KernelColumnRow {
    id: String,
    verdict: String,
    #[serde(default)]
    message: Option<String>,
}

struct Args {
    manifest: PathBuf,
    programs: PathBuf,
    kernel_column: Option<PathBuf>,
    baseline: Option<PathBuf>,
    json_out: Option<PathBuf>,
    gate: bool,
    write_baseline: bool,
    strict: bool,
    only_file: Option<String>,
    quiet: bool,
}

fn main() {
    let args = parse_args();
    let rows = read_manifest(&args.manifest);
    let column = args.kernel_column.as_ref().map(|p| read_kernel_column(p));

    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut agreement: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut per_file: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut cases = Vec::new();
    let mut findings = BTreeSet::new();
    let mut surface: BTreeMap<String, usize> = BTreeMap::new();

    for row in &rows {
        if let Some(only) = &args.only_file
            && !row.file.contains(only.as_str())
        {
            continue;
        }
        let path = args.programs.join(format!("{}.bin", row.id));
        let Ok(bytes) = fs::read(&path) else {
            *counts.entry("missing").or_insert(0) += 1;
            continue;
        };
        let entry = per_file.entry(row.file.clone()).or_insert((0, 0));
        entry.0 += 1;

        let prog_type = prog_type_of(row);
        if let Some(kind) = unsupported_prog_type(prog_type) {
            *counts.entry(Finding::SurfaceGap.name()).or_insert(0) += 1;
            *surface.entry(kind.name().to_string()).or_insert(0) += 1;
            cases.push(serde_json::json!({
                "id": row.id,
                "name": row.name,
                "file": row.file,
                "expected": row.expected,
                "prog_type": row.prog_type,
                "finding": Finding::SurfaceGap.name(),
                "surface_gap": kind.name(),
            }));
            continue;
        }

        let mut env = BpfVerifierEnv::new();
        env.set_prog_type(prog_type);
        register_default_maps(&mut env, &bytes);
        if let Err(err) = env.setup_prog_bytes(&bytes) {
            let message = format!("{err:#}");
            let kind = surface_gap_kind(&message).unwrap_or(SurfaceGapKind::Other);
            *counts.entry(Finding::SurfaceGap.name()).or_insert(0) += 1;
            *surface.entry(kind.name().to_string()).or_insert(0) += 1;
            cases.push(serde_json::json!({
                "id": row.id,
                "name": row.name,
                "file": row.file,
                "expected": row.expected,
                "prog_type": row.prog_type,
                "mini": "SKIPPED",
                "spec": "SKIPPED",
                "finding": Finding::SurfaceGap.name(),
                "surface_gap": kind.name(),
                "detail": message,
            }));
            continue;
        }

        let mini = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| env.verify()));
        let (mini_side, mini_reason) = match mini {
            Ok(Ok(Verdict::Safe)) => (SideVerdict::Accept, None),
            Ok(Ok(Verdict::Unsafe(failure))) => (
                SideVerdict::Reject {
                    category: rand_verifier::diff::categorize_mini_reason(&failure),
                },
                Some(failure.message),
            ),
            Ok(Err(err)) => {
                *counts.entry("mini-error").or_insert(0) += 1;
                cases.push(serde_json::json!({
                    "id": row.id,
                    "name": row.name,
                    "file": row.file,
                    "finding": "mini-error",
                    "detail": format!("{err:#}"),
                }));
                continue;
            }
            Err(_) => {
                *counts.entry("mini-panic").or_insert(0) += 1;
                cases.push(serde_json::json!({
                    "id": row.id,
                    "name": row.name,
                    "file": row.file,
                    "finding": "mini-panic",
                }));
                continue;
            }
        };

        let (kernel_side, kernel_reason) = match &column {
            Some(column) => match column.get(&row.id) {
                Some((verdict, message)) => {
                    (verdict_of(verdict, message.as_deref()), message.clone())
                }
                // a column that does not cover this case falls back to the
                // expectation (recorded columns may be filtered)
                None => (
                    verdict_of(&row.expected, row.errstr.as_deref()),
                    row.errstr.clone(),
                ),
            },
            None => (
                verdict_of(&row.expected, row.errstr.as_deref()),
                row.errstr.clone(),
            ),
        };

        // raw two-axis agreement (independent of the oracle precedence):
        // this is the number that moves when a model learns a surface.
        let kernel_accepts = matches!(kernel_side, SideVerdict::Accept);
        let mini_accepts = matches!(mini_side, SideVerdict::Accept);
        let agreement_label = match (mini_accepts, kernel_accepts) {
            (true, true) => "agree-accept",
            (false, false) => "agree-reject",
            (false, true) => "rv-overstrict",
            (true, false) => "rv-unsound",
        };
        *agreement.entry(agreement_label).or_insert(0) += 1;

        let spec_verdict = verify_spec_with(env.program_insns(), env.maps(), prog_type);
        let (spec_label, spec_reason) = match &spec_verdict {
            SpecVerdict::Accept => ("ACCEPT", None),
            SpecVerdict::Reject(f) => ("REJECT", Some(f.message.clone())),
            SpecVerdict::Inconclusive => ("INCONCLUSIVE", None),
        };
        let finding = classify_env(
            &env,
            &row.name,
            &mini_side,
            mini_reason.as_deref(),
            &kernel_side,
            kernel_reason.as_deref(),
            args.strict,
        );
        *counts.entry(finding.name()).or_insert(0) += 1;
        if finding.is_finding() {
            findings.insert(row.id.clone());
            entry.1 += 1;
        }
        cases.push(serde_json::json!({
            "id": row.id,
            "name": row.name,
            "file": row.file,
            "expected": row.expected,
            "prog_type": row.prog_type,
            "errstr": row.errstr,
            "result_unpriv": row.result_unpriv,
            "kernel": side_name(&kernel_side),
            "kernel_reason": kernel_reason,
            "mini": side_name(&mini_side),
            "mini_reason": mini_reason,
            "concrete": env.concrete_report_text(),
            "spec": spec_label,
            "spec_reason": spec_reason,
            "finding": finding.name(),
        }));
    }

    print_summary(&agreement, &counts, &per_file, &surface, args.quiet);

    if let Some(path) = &args.json_out {
        let report = serde_json::json!({
            "generated_by": "replay",
            "kernel_source": if column.is_some() { "column" } else { "expected" },
            "strict": args.strict,
            "cases": cases,
            "summary": {
                "agreement": agreement,
                "classification": counts,
                "surface_gaps": surface,
                "findings": findings.iter().collect::<Vec<_>>(),
                "per_file": per_file.iter().map(|(file, (n, bad))| serde_json::json!({
                    "file": file, "cases": n, "findings": bad,
                })).collect::<Vec<_>>(),
            },
        });
        let text = serde_json::to_string_pretty(&report).expect("serialize report");
        fs::write(path, text + "\n").expect("write report");
        println!("\nwrote {}", path.display());
    }

    if args.write_baseline {
        write_baseline(&args, &findings, &counts);
    }

    if args.gate {
        let baseline = args
            .baseline
            .as_ref()
            .map(|p| read_baseline(p))
            .unwrap_or_default();
        let new = new_findings(&findings, &baseline);
        if new.is_empty() {
            println!(
                "\ngate: no new findings ({} baseline findings)",
                baseline.len()
            );
        } else {
            eprintln!("\ngate: {} new finding(s):", new.len());
            for id in new.iter().take(40) {
                eprintln!("  {id}");
            }
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().skip(1).collect();
    let value = |flag: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };
    let has = |flag: &str| argv.iter().any(|a| a == flag);
    let manifest = value("--manifest").unwrap_or_else(|| usage());
    let programs = value("--programs").unwrap_or_else(|| usage());
    Args {
        manifest: PathBuf::from(manifest),
        programs: PathBuf::from(programs),
        kernel_column: value("--kernel-column").map(PathBuf::from),
        baseline: value("--baseline").map(PathBuf::from),
        json_out: value("--json").map(PathBuf::from),
        gate: has("--gate"),
        write_baseline: has("--write-baseline"),
        strict: has("--strict"),
        only_file: value("--only-file"),
        quiet: has("--quiet"),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: replay --manifest <jsonl> --programs <dir>\n\
         \x20             [--kernel-column <jsonl>] [--baseline <json>] [--json <out>]\n\
         \x20             [--gate] [--write-baseline] [--strict] [--only-file <substr>] [--quiet]"
    );
    std::process::exit(2)
}

fn read_manifest(path: &Path) -> Vec<Row> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read manifest {}: {e}", path.display());
        std::process::exit(2)
    });
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("manifest row"))
        .collect()
}

fn read_kernel_column(path: &Path) -> HashMap<String, (String, Option<String>)> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read kernel column {}: {e}", path.display());
        std::process::exit(2)
    });
    let mut out = HashMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let row: KernelColumnRow =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("kernel column row: {e}"));
        out.insert(row.id, (row.verdict, row.message));
    }
    out
}

fn read_baseline(path: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read baseline {}: {e}", path.display());
        std::process::exit(2)
    });
    let value: serde_json::Value = serde_json::from_str(&text).expect("baseline json");
    value
        .get("allowed_findings")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn write_baseline(args: &Args, findings: &BTreeSet<String>, counts: &BTreeMap<&str, usize>) {
    let path = args
        .baseline
        .clone()
        .unwrap_or_else(|| PathBuf::from("tools/replay-baseline.json"));
    let body = serde_json::json!({
        "kernel_source": if args.kernel_column.is_some() { "column" } else { "expected" },
        "strict": args.strict,
        "counts": counts,
        "allowed_findings": findings.iter().collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&body).expect("serialize baseline");
    fs::write(&path, text + "\n").expect("write baseline");
    println!(
        "\nwrote baseline {} ({} findings)",
        path.display(),
        findings.len()
    );
}

/// The kernel selftest harness assigns map fds at load time; mirror it by
/// registering the default ARRAY map for every referenced fd (the guest
/// agent does the same, so the kernel column and the models agree).
fn register_default_maps(env: &mut BpfVerifierEnv, bytes: &[u8]) {
    for fd in referenced_map_fds(bytes) {
        env.register_map(fd, MapInfo::array_default());
    }
}

fn verdict_of(verdict: &str, message: Option<&str>) -> SideVerdict {
    if verdict.eq_ignore_ascii_case("ACCEPT") {
        SideVerdict::Accept
    } else {
        SideVerdict::Reject {
            category: message
                .map(rand_verifier::klog::categorize_reason)
                .unwrap_or(ReasonCategory::Other),
        }
    }
}

fn side_name(side: &SideVerdict) -> &'static str {
    match side {
        SideVerdict::Accept => "ACCEPT",
        SideVerdict::Reject { .. } => "REJECT",
        SideVerdict::Skipped => "SKIPPED",
    }
}

/// The program type of a corpus row: a missing field means the loader's
/// default (`BPF_PROG_TYPE_SOCKET_FILTER`).
fn prog_type_of(row: &Row) -> ProgType {
    row.prog_type
        .as_deref()
        .and_then(ProgType::parse)
        .unwrap_or_default()
}

/// Prog types without a context model are a surface gap, not a model
/// disagreement (#131, #135).
fn unsupported_prog_type(prog_type: ProgType) -> Option<SurfaceGapKind> {
    if prog_type.ctx_model().is_none() {
        Some(SurfaceGapKind::UnmodeledProgType)
    } else {
        None
    }
}

fn print_summary(
    agreement: &BTreeMap<&str, usize>,
    counts: &BTreeMap<&str, usize>,
    per_file: &BTreeMap<String, (usize, usize)>,
    surface: &BTreeMap<String, usize>,
    quiet: bool,
) {
    if quiet {
        return;
    }
    println!("agreement             count");
    let mut raw_total = 0;
    for (key, value) in agreement {
        println!("{key:<22}{value:>6}");
        raw_total += value;
    }
    println!("{:<22}{raw_total:>6}", "total");

    println!("\nclassification        count");
    let mut total = 0;
    for (key, value) in counts {
        println!("{key:<22}{value:>6}");
        total += value;
    }
    println!("{:<22}{total:>6}", "total");

    if !surface.is_empty() {
        println!("\nsurface gap            count");
        for (key, value) in surface {
            println!("{key:<22}{value:>6}");
        }
    }

    println!("\nfile                                  n  findings");
    for (file, (n, bad)) in per_file {
        if *bad > 0 {
            println!("{file:<36}{n:>4}{bad:>10}");
        }
    }
}

/// Findings not covered by the committed baseline — the gate's failure set.
/// Shrinking the set (a model learns a surface) is allowed; growing it is not.
fn new_findings(findings: &BTreeSet<String>, baseline: &BTreeSet<String>) -> Vec<String> {
    findings.difference(baseline).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn gate_allows_shrinking_and_rejects_growth() {
        let findings = set(&["a", "b"]);
        assert!(new_findings(&findings, &set(&["a", "b", "c"])).is_empty());
        let new = new_findings(&findings, &set(&["a"]));
        assert_eq!(new.len(), 1);
        assert_eq!(new[0], "b");
    }

    #[test]
    fn kernel_verdict_mapping_uses_the_message_category() {
        assert!(matches!(verdict_of("ACCEPT", None), SideVerdict::Accept));
        assert!(matches!(
            verdict_of("REJECT", Some("invalid read from stack off -8")),
            SideVerdict::Reject {
                category: ReasonCategory::UninitRead
            }
        ));
        assert!(matches!(
            verdict_of("REJECT", None),
            SideVerdict::Reject {
                category: ReasonCategory::Other
            }
        ));
    }
}
