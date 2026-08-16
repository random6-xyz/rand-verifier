//! reduce: automatically minimize a fuzzer finding down to a
//! human-analyzable minimal reproducer (v0.8, #81/#82).
//!
//! ```sh
//! reduce <finding-dir|group-dir>              # one finding or triage group
//! reduce --all-groups fuzz-out/               # every triage group under a root
//! reduce <dir> --kernel                       # kernel-backed (root/CAP_BPF)
//! reduce <dir> --strict --kernel              # unprivileged-equivalent kernel rules
//! reduce <dir> --budget 500 --out-dir out/    # oracle-check budget + output root
//! ```
//!
//! The reduction invariant is the v0.7 oracle: the reduced program
//! must re-classify to the same finding (kernel reason category
//! included for kernel-reject findings; verdict flips keep the flip
//! direction). Kernel-dependent findings (precision/soundness
//! candidates, rv gaps) require `--kernel`; rv-soundness bugs and
//! verdict flips reduce unprivileged. The final re-check is mandatory.
//!
//! Exit codes: 0 = reduced, classification preserved; 1 = final
//! re-check failed (reducer bug) or a finding could not be processed;
//! 2 = kernel required but unavailable; 3 = usage error.
//! `--tolerate-findings` forces 0.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use rand_verifier::fuzz::reduce::{ReduceConfig, ReduceError, reduce_finding};
use rand_verifier::krun::drop_privileged_caps;

struct Args {
    target: Option<PathBuf>,
    all_groups: Option<PathBuf>,
    out_dir: PathBuf,
    strict: bool,
    kernel: bool,
    budget: usize,
    tolerate_findings: bool,
    qemu_dir: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: reduce <finding-dir|group-dir> [--all-groups <root>] [--kernel] [--strict]\n\
         \x20           [--budget <n>] [--out-dir <dir>] [--tolerate-findings]"
    );
    process::exit(3);
}

fn parse_args() -> Args {
    let mut args = Args {
        target: None,
        all_groups: None,
        out_dir: PathBuf::from("fuzz-out"),
        strict: false,
        kernel: false,
        budget: 0,
        tolerate_findings: false,
        qemu_dir: None,
    };
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next().unwrap_or_else(|| {
                eprintln!("missing value for {arg}");
                usage();
            })
        };
        match arg.as_str() {
            "--all-groups" => args.all_groups = Some(value().into()),
            "--out-dir" => args.out_dir = value().into(),
            "--budget" => args.budget = value().parse().unwrap_or_else(|_| usage()),
            "--kernel" => args.kernel = true,
            "--strict" => args.strict = true,
            "--qemu-dir" => args.qemu_dir = Some(value().into()),
            "--tolerate-findings" => args.tolerate_findings = true,
            "--help" | "-h" => usage(),
            other if other.starts_with('-') => {
                eprintln!("unknown argument: {other}");
                usage();
            }
            other => {
                if args.target.is_some() {
                    eprintln!("unexpected extra argument: {other}");
                    usage();
                }
                args.target = Some(other.into());
            }
        }
    }
    if args.target.is_none() && args.all_groups.is_none() {
        eprintln!("missing <finding-dir|group-dir>");
        usage();
    }
    if args.target.is_some() && args.all_groups.is_some() {
        eprintln!("--all-groups cannot be combined with a finding directory");
        usage();
    }
    args
}

/// The finding directories to reduce: the single target, or every
/// triage group under `<root>/groups/*/`.
fn finding_dirs(args: &Args) -> anyhow::Result<Vec<PathBuf>> {
    if let Some(target) = &args.target {
        let meta = target.join("meta.json");
        if !meta.is_file() {
            anyhow::bail!(
                "{}: not a finding directory (no meta.json)",
                target.display()
            );
        }
        return Ok(vec![target.clone()]);
    }
    let root = args.all_groups.as_ref().unwrap();
    let groups = root.join("groups");
    let mut dirs = Vec::new();
    if groups.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(&groups)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.join("meta.json").is_file())
            .collect();
        entries.sort();
        dirs.extend(entries);
    }
    if dirs.is_empty() {
        anyhow::bail!("no triage groups found under {}", groups.display());
    }
    Ok(dirs)
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    if args.strict && !args.kernel {
        eprintln!("note: --strict only affects the kernel side; ignored without --kernel");
    }
    if args.kernel && args.strict && args.qemu_dir.is_none() {
        // unprivileged-equivalent kernel rules, like diff/fuzz --strict
        // (qemu guests handle strict via the share marker)
        if let Err(msg) = drop_privileged_caps() {
            eprintln!("{msg}");
            process::exit(2);
        }
    }

    let dirs = finding_dirs(&args)?;
    let config = ReduceConfig {
        budget: args.budget,
        kernel: args.kernel,
        strict: args.strict,
        qemu_dir: args.qemu_dir,
    };

    let mut failed = 0usize;
    for dir in &dirs {
        match reduce_finding(dir, &args.out_dir, &config) {
            Ok(report) => {
                println!(
                    "reduced {} ({}): {} insns -> {} insns",
                    report.name, report.label, report.original_insns, report.final_insns
                );
                for (pass, count) in &report.timeline {
                    println!("  {pass}: {count}");
                }
                println!(
                    "  final re-check: mini {} kernel {} — preserved",
                    report.final_mini, report.final_kernel
                );
                println!(
                    "  artifacts: {}/reduced/{}/",
                    args.out_dir.display(),
                    dir.file_name().unwrap_or_default().to_string_lossy()
                );
            }
            Err(e) => {
                eprintln!("{}: {e}", dir.display());
                match e {
                    ReduceError::KernelRequired(_) => process::exit(2),
                    _ => failed += 1,
                }
            }
        }
    }

    if failed > 0 && !args.tolerate_findings {
        eprintln!("{failed} finding(s) failed — use --tolerate-findings to exit 0");
        process::exit(1);
    }
    Ok(())
}
