//! fuzz: run a fuzz campaign — generate programs, verify them through
//! rand-verifier (mini + concrete), consult the kernel when privileged,
//! classify with the oracle, and persist findings (issue #69).
//!
//! ```sh
//! fuzz --seed 42 --iters 1000 --out-dir out/   # mini + concrete only
//! fuzz --seed 1 --iters 100 --kernel --strict  # + kernel (root/CAP_BPF)
//! ```
//!
//! Determinism: with a fixed `--seed` the rand-verifier side (program
//! bytes, mini/concrete verdicts, classifications, finding files) is
//! byte-reproducible. The kernel outcome is host-dependent; it is
//! recorded separately (`kernel.log` is not part of the determinism
//! guarantee).
//!
//! Exit code: 1 when a non-whitelisted finding appears
//! (precision/soundness candidate, rand-verifier gap/bug); 0 otherwise
//! (`--tolerate-findings` forces 0). The kernel side needs root /
//! CAP_BPF (run with sudo on hosts with unprivileged BPF disabled).

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use rand_verifier::diff::{SideVerdict, categorize_mini_reason};
use rand_verifier::env::BpfVerifierEnv;
use rand_verifier::error::Verdict;
use rand_verifier::fuzz::generator::{GenConfig, Generator};
use rand_verifier::fuzz::insn_lib::{self, opcode_family};
use rand_verifier::fuzz::oracle::{Finding, classify_env};
use rand_verifier::krun::{KernelOutcome, drop_privileged_caps, load_with_kernel};

/// Share of idiom-template programs in a generation campaign — the
/// milestone's stress semantics get reliable coverage (#67).
const IDIOM_RATIO_PERCENT: u64 = 30;

struct Args {
    seed: u64,
    iters: usize,
    min_len: usize,
    max_len: usize,
    out_dir: PathBuf,
    strict: bool,
    kernel: bool,
    tolerate_findings: bool,
    mode: String,
}

fn usage() -> ! {
    eprintln!(
        "usage: fuzz --seed <u64> [--iters <n>] [--min-len <n>] [--max-len <n>]\n\
         \x20            [--out-dir <dir>] [--strict] [--kernel] [--tolerate-findings]\n\
         \x20            [--mode generation|mutation]"
    );
    process::exit(2);
}

fn parse_args() -> Args {
    let mut args = Args {
        seed: 0,
        iters: 100,
        min_len: 1,
        max_len: 100,
        out_dir: PathBuf::from("fuzz-out"),
        strict: false,
        kernel: false,
        tolerate_findings: false,
        mode: "generation".to_string(),
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
            "--seed" => args.seed = value().parse().unwrap_or_else(|_| usage()),
            "--iters" => args.iters = value().parse().unwrap_or_else(|_| usage()),
            "--min-len" => args.min_len = value().parse().unwrap_or_else(|_| usage()),
            "--max-len" => args.max_len = value().parse().unwrap_or_else(|_| usage()),
            "--out-dir" => args.out_dir = value().into(),
            "--mode" => args.mode = value(),
            "--strict" => args.strict = true,
            "--kernel" => args.kernel = true,
            "--tolerate-findings" => args.tolerate_findings = true,
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }
    args
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    if args.mode != "generation" {
        anyhow::bail!(
            "--mode {} is not implemented yet (mutation lands with #71)",
            args.mode
        );
    }
    if args.strict && !args.kernel {
        eprintln!("note: --strict only affects the kernel side; ignored without --kernel");
    }
    if args.kernel && args.strict {
        // unprivileged-equivalent kernel rules, like diff --strict
        if let Err(msg) = drop_privileged_caps() {
            eprintln!("{msg}");
            process::exit(2);
        }
    }

    let cfg = GenConfig {
        min_len: args.min_len,
        max_len: args.max_len,
    };
    let findings_dir = args.out_dir.join("findings");
    fs::create_dir_all(&findings_dir)?;

    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut coverage: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut findings: Vec<(String, String)> = Vec::new(); // (name, dir)

    for i in 0..args.iters {
        let name = format!("seed-{}-{}", args.seed, i);
        // one generator per program: the per-program seed fully
        // determines the program and every rand-verifier verdict
        let mut generator = Generator::new(args.seed.wrapping_add(i as u64));
        let insns = generator.gen_mixed_program(&cfg, IDIOM_RATIO_PERCENT);
        for insn in &insns {
            *coverage.entry(opcode_family(insn)).or_insert(0) += 1;
        }
        let bytes: Vec<u8> = insns.iter().flat_map(insn_lib::encode).collect();

        // rand-verifier side (mini + concrete)
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes)?;
        let (mini, mini_reason) = match env.verify()? {
            Verdict::Safe => (SideVerdict::Accept, None),
            Verdict::Unsafe(failure) => (
                SideVerdict::Reject {
                    category: categorize_mini_reason(&failure),
                },
                Some(failure.message),
            ),
        };

        // kernel side (optional)
        let (kernel, kernel_message) = if args.kernel {
            kernel_side_of(&load_with_kernel(&bytes))
        } else {
            (SideVerdict::Skipped, None)
        };

        let finding = classify_env(&env, &name, &mini, &kernel, args.strict);
        *counts.entry(finding.name()).or_insert(0) += 1;
        if finding.is_finding() {
            let dir = findings_dir.join(format!("{}-{}", finding.name(), name));
            save_finding(
                &dir,
                &env,
                &ProgramResult {
                    name: &name,
                    finding,
                    mini,
                    mini_reason,
                    kernel,
                    kernel_message,
                    bytes: &bytes,
                },
            )?;
            findings.push((name, dir.display().to_string()));
        }
    }

    write_summary(&args, &counts, &coverage, &findings)?;

    println!("campaign done: seed {} iters {}", args.seed, args.iters);
    for (k, v) in &counts {
        println!("  {k}: {v}");
    }
    if !findings.is_empty() {
        println!("findings saved under {}", findings_dir.display());
        for (name, dir) in &findings {
            println!("  {name} → {dir}");
        }
    }

    if !findings.is_empty() && !args.tolerate_findings {
        eprintln!(
            "{} finding(s) — use --tolerate-findings to exit 0",
            findings.len()
        );
        process::exit(1);
    }
    Ok(())
}

/// The kernel side of one load, with the message for the finding
/// artifact (same mapping as the diff harness).
fn kernel_side_of(outcome: &KernelOutcome) -> (SideVerdict, Option<String>) {
    match outcome {
        KernelOutcome::Accept => (SideVerdict::Accept, None),
        KernelOutcome::Reject {
            message, category, ..
        } => (
            SideVerdict::Reject {
                category: *category,
            },
            Some(message.clone()),
        ),
        KernelOutcome::Privilege => (SideVerdict::Skipped, Some("EPERM (privilege)".into())),
        KernelOutcome::NoErrorLine { errno } => (
            SideVerdict::Skipped,
            Some(format!("errno {errno} (no log line)")),
        ),
        KernelOutcome::InvalidProgram => (SideVerdict::Skipped, Some("invalid program".into())),
    }
}

/// Everything the runner knows about one finding — the inputs of the
/// persisted artifact.
struct ProgramResult<'a> {
    name: &'a str,
    finding: Finding,
    mini: SideVerdict,
    mini_reason: Option<String>,
    kernel: SideVerdict,
    kernel_message: Option<String>,
    bytes: &'a [u8],
}

/// Persist one finding: program bytes (replayable via kernel_run),
/// decoded dump, mini verdict, concrete report, kernel log line, and a
/// meta.json with the full classification. All files except
/// `kernel.log` are deterministic for a fixed seed.
fn save_finding(dir: &Path, env: &BpfVerifierEnv, result: &ProgramResult) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("prog.bin"), result.bytes)?;

    let mut dump = String::new();
    for (idx, chunk) in result.bytes.chunks_exact(8).enumerate() {
        match rand_verifier::insn::parse_insn(chunk) {
            Ok(insn) => dump.push_str(&format!("{idx:4}: {insn:?}\n")),
            Err(e) => dump.push_str(&format!("{idx:4}: decode error: {e}\n")),
        }
    }
    fs::write(dir.join("prog.dump"), dump)?;

    let mut mini_txt = format!("mini: {}\n", result.mini.name());
    if let Some(reason) = &result.mini_reason {
        mini_txt.push_str(&format!("reason: {reason}\n"));
    }
    fs::write(dir.join("mini.txt"), mini_txt)?;

    if let Some(report) = env.concrete_report_text() {
        fs::write(dir.join("concrete.txt"), report)?;
    }

    if let Some(msg) = &result.kernel_message {
        fs::write(dir.join("kernel.log"), format!("{msg}\n"))?;
    }

    fs::write(
        dir.join("meta.json"),
        meta_json(result.name, &result.finding, &result.mini, &result.kernel),
    )?;
    Ok(())
}

/// The per-finding meta.json (deterministic for a fixed seed).
fn meta_json(name: &str, finding: &Finding, mini: &SideVerdict, kernel: &SideVerdict) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"name\": \"{}\",\n", json_escape(name)));
    s.push_str(&format!("  \"finding\": \"{}\",\n", finding.name()));
    s.push_str(&format!("  \"mini\": \"{}\",\n", side_json(mini)));
    s.push_str(&format!("  \"kernel\": \"{}\"\n", side_json(kernel)));
    s.push_str("}\n");
    s
}

/// One side as a compact JSON string, e.g. `REJECT(StackBounds)`.
fn side_json(side: &SideVerdict) -> String {
    match side {
        SideVerdict::Accept => "ACCEPT".to_string(),
        SideVerdict::Reject { category } => {
            format!("REJECT({:?})", category)
        }
        SideVerdict::Skipped => "SKIPPED".to_string(),
    }
}

/// The campaign summary (schema: see #69 / the PR).
///
/// ```json
/// { "seed": 42, "mode": "generation", "iters": 1000,
///   "counts": { "agree": 980, "precision-candidate": 2, ... },
///   "opcode_coverage": { "alu64": 512, ... },
///   "findings": [ { "name": "seed-42-7", "finding": "precision-candidate",
///                   "dir": "out/findings/..." } ] }
/// ```
fn write_summary(
    args: &Args,
    counts: &BTreeMap<&'static str, usize>,
    coverage: &BTreeMap<&'static str, usize>,
    findings: &[(String, String)],
) -> anyhow::Result<()> {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"seed\": {},\n", args.seed));
    s.push_str(&format!("  \"mode\": \"{}\",\n", args.mode));
    s.push_str(&format!("  \"iters\": {},\n", args.iters));
    s.push_str("  \"counts\": {\n");
    push_map(&mut s, counts, "    ");
    s.push_str("  },\n  \"opcode_coverage\": {\n");
    push_map(&mut s, coverage, "    ");
    s.push_str("  },\n  \"findings\": [\n");
    for (i, (name, dir)) in findings.iter().enumerate() {
        let comma = if i + 1 == findings.len() { "" } else { "," };
        s.push_str(&format!(
            "    {{\"name\": \"{}\", \"dir\": \"{}\"}}{}\n",
            json_escape(name),
            json_escape(dir),
            comma
        ));
    }
    s.push_str("  ]\n}\n");
    fs::write(args.out_dir.join("summary.json"), s)?;
    Ok(())
}

fn push_map(s: &mut String, map: &BTreeMap<&'static str, usize>, indent: &str) {
    for (i, (k, v)) in map.iter().enumerate() {
        let comma = if i + 1 == map.len() { "" } else { "," };
        s.push_str(&format!("{indent}\"{k}\": {v}{comma}\n"));
    }
}

/// Minimal JSON string escaping for the summary files.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}
