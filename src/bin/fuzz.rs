//! fuzz: run a fuzz campaign — generate or mutate programs, verify
//! them through rand-verifier (mini + concrete), consult the kernel
//! when privileged, classify with the oracle, and persist findings
//! (issues #69, #71).
//!
//! ```sh
//! fuzz --seed 42 --iters 1000 --out-dir out/          # generation
//! fuzz --seed 1 --iters 100 --mode mutation           # seed-based mutation
//! fuzz --seed 1 --iters 100 --kernel --strict         # + kernel (root/CAP_BPF)
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

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use rand_verifier::diff::{
    FingerprintInput, SideVerdict, categorize_mini_reason, suppressed_fingerprint,
};
use rand_verifier::env::BpfVerifierEnv;
use rand_verifier::error::Verdict;
use rand_verifier::fuzz::generator::{GenConfig, Generator};
use rand_verifier::fuzz::insn_lib::{self, opcode_family};
use rand_verifier::fuzz::mutator::Mutator;
use rand_verifier::fuzz::oracle::{
    Finding, SurfaceGapKind, classify_env_with_gap, first_violation_pc, surface_gap_kind,
};
use rand_verifier::fuzz::prng::mix_seed;
use rand_verifier::fuzz::qemu::QemuBatch;
use rand_verifier::fuzz::triage::{Candidate, Divergence, Group, group};
use rand_verifier::insn::BpfInsn;
use rand_verifier::klog::ReasonCategory;
use rand_verifier::krun::{KernelOutcome, drop_privileged_caps, load_with_kernel};

/// Share of idiom-template programs in a generation campaign — the
/// milestone's stress semantics get reliable coverage (#67).
const IDIOM_RATIO_PERCENT: u64 = 30;
/// Mutation-mode pool size cap: the corpus plus the most recent
/// campaign programs.
const POOL_CAP: usize = 200;
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
    mutate_ratio: u64,
    /// Extra seed directories for mutation mode (raw bytecode files).
    corpus_dirs: Vec<PathBuf>,
    /// Generation mode: save every generated program here as `.bin`.
    save_corpus: Option<PathBuf>,
    /// Kernel column via the qemu guest agent (9p share dir).
    qemu_dir: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: fuzz --seed <u64> [--iters <n>] [--min-len <n>] [--max-len <n>]\n\
         \x20            [--out-dir <dir>] [--strict] [--kernel] [--tolerate-findings]\n\
         \x20            [--mode generation|mutation] [--mutate-ratio <0-100>]\n\
         \x20            [--corpus-dir <dir>]... [--save-corpus <dir>] [--qemu-dir <dir>]"
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
        mutate_ratio: 80,
        corpus_dirs: Vec::new(),
        save_corpus: None,
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
            "--seed" => args.seed = value().parse().unwrap_or_else(|_| usage()),
            "--iters" => args.iters = value().parse().unwrap_or_else(|_| usage()),
            "--min-len" => args.min_len = value().parse().unwrap_or_else(|_| usage()),
            "--max-len" => args.max_len = value().parse().unwrap_or_else(|_| usage()),
            "--out-dir" => args.out_dir = value().into(),
            "--mode" => args.mode = value(),
            "--mutate-ratio" => args.mutate_ratio = value().parse().unwrap_or_else(|_| usage()),
            "--corpus-dir" => args.corpus_dirs.push(value().into()),
            "--save-corpus" => args.save_corpus = Some(value().into()),
            "--qemu-dir" => args.qemu_dir = Some(value().into()),
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
    if args.mutate_ratio > 100 {
        eprintln!("--mutate-ratio must be 0-100");
        usage();
    }
    args
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    if args.mode != "generation" && args.mode != "mutation" {
        anyhow::bail!("unknown --mode {} (generation|mutation)", args.mode);
    }
    if args.strict && !args.kernel {
        eprintln!("note: --strict only affects the kernel side; ignored without --kernel");
    }
    if args.kernel && args.strict && args.qemu_dir.is_none() {
        // unprivileged-equivalent kernel rules, like diff --strict.
        // The host-side cap drop only applies to direct host loads: a
        // qemu guest handles strict via the share marker (the guest
        // agent drops its own caps), and the host user may not hold
        // CAP_SETPCAP at all.
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
    let mut surface_gaps: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut suppressed: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut kpi = Kpi::new();
    let mut coverage: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut findings: Vec<(String, String)> = Vec::new(); // (name, dir)
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut mutations = MutStats::default();
    let mut flips: Vec<(String, String, String)> = Vec::new(); // (name, before, after)
    let mut qemu = args
        .qemu_dir
        .as_ref()
        .map(|d| QemuBatch::new(d.clone(), args.strict));

    if args.mode == "mutation" {
        run_mutation_campaign(
            &args,
            &cfg,
            &findings_dir,
            &mut counts,
            &mut surface_gaps,
            &mut suppressed,
            &mut kpi,
            &mut coverage,
            &mut findings,
            &mut candidates,
            &mut mutations,
            &mut flips,
            qemu.as_mut(),
        )?;
    } else {
        let total = args.iters.max(1);
        let report_every = (total / 10).max(1);
        for i in 0..args.iters {
            let name = format!("seed-{}-{}", args.seed, i);
            // one generator per program: the per-program seed fully
            // determines the program and every rand-verifier verdict
            let mut generator = Generator::new(mix_seed(args.seed, i as u64));
            let insns = generator.gen_mixed_program(&cfg, IDIOM_RATIO_PERCENT);
            // optional corpus persistence: every generated program
            // becomes a future mutation seed (raw bytecode, .bin)
            if let Some(save_dir) = &args.save_corpus {
                fs::create_dir_all(save_dir)?;
                let bytes: Vec<u8> = insns.iter().flat_map(insn_lib::encode).collect();
                fs::write(save_dir.join(format!("gen-{}-{}.bin", args.seed, i)), bytes)?;
            }
            let out = run_program(&args, &name, &insns, qemu.as_mut())?;
            handle_outcome(
                &mut counts,
                &mut surface_gaps,
                &mut suppressed,
                &mut kpi,
                &mut coverage,
                &mut findings,
                &mut candidates,
                &findings_dir,
                out,
            )?;
            if (i + 1) % report_every == 0 || i + 1 == total {
                let done = i + 1;
                let pct = done * 100 / total;
                println!(
                    "  progress: {done}/{total} ({pct}%) agree={} skip={} findings={}",
                    counts.get("agree").copied().unwrap_or(0),
                    counts.get("skipped").copied().unwrap_or(0),
                    findings.len(),
                );
            }
        }
    }

    // dedup into groups: one representative per root cause (#70)
    let groups = group(candidates);
    let groups_dir = args.out_dir.join("groups");
    if !groups.is_empty() {
        fs::create_dir_all(&groups_dir)?;
        for (i, g) in groups.iter().enumerate() {
            let gdir = groups_dir.join(format!("{}-{:03}", g.priority, i));
            let src = findings_dir.join(format!("{}-{}", g.key.finding.name(), g.representative));
            copy_dir(&src, &gdir)?;
            fs::write(gdir.join("group.json"), group_json(g, &gdir))?;
        }
    }

    // flush the qemu batch tail so every kernel verdict is in, then report
    // the retry count in the same summary (#142)
    if let Some(qemu) = qemu.as_mut() {
        qemu.flush()?;
    }
    let batch_retries = qemu.as_ref().map(|q| q.retries()).unwrap_or(0);

    write_summary(
        &args,
        &counts,
        &surface_gaps,
        &suppressed,
        &kpi,
        &coverage,
        &findings,
        &groups,
        &groups_dir,
        &mutations,
        &flips,
        batch_retries,
    )?;

    println!(
        "campaign done: seed {} iters {} mode {}",
        args.seed, args.iters, args.mode
    );
    for (k, v) in &counts {
        println!("  {k}: {v}");
    }
    if args.mode == "mutation" {
        println!(
            "  mutations: {} total, {} valid, {} invalid ({:.1}% valid)",
            mutations.total,
            mutations.valid,
            mutations.invalid,
            mutations.validity_rate() * 100.0
        );
        for (name, before, after) in &flips {
            println!("  verdict flip: {name} {before} → {after}");
        }
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

/// The mutation campaign (#71): seed programs from the corpus plus the
/// campaign pool, mutate, verify, track verdict flips.
#[allow(clippy::too_many_arguments)]
fn run_mutation_campaign(
    args: &Args,
    cfg: &GenConfig,
    findings_dir: &Path,
    counts: &mut BTreeMap<&'static str, usize>,
    surface_gaps: &mut BTreeMap<&'static str, usize>,
    suppressed: &mut BTreeMap<&'static str, usize>,
    kpi: &mut Kpi,
    coverage: &mut BTreeMap<&'static str, usize>,
    findings: &mut Vec<(String, String)>,
    candidates: &mut Vec<Candidate>,
    mutations: &mut MutStats,
    flips: &mut Vec<(String, String, String)>,
    mut qemu: Option<&mut QemuBatch>,
) -> anyhow::Result<()> {
    let corpus = load_corpus_seeds(args)?;
    let corpus_len = corpus.len();
    let mut pool: Vec<(String, Vec<BpfInsn>, &'static str)> = corpus;

    for i in 0..args.iters {
        let name = format!("mseed-{}-{}", args.seed, i);
        let mut mutator = Mutator::new(mix_seed(args.seed, i as u64));

        let (insns, seed_verdict) = if mutator.chance(args.mutate_ratio) {
            mutations.total += 1;
            let (_, seed_insns, seed_v) = mutator.pick(&pool);
            let other_seed = mutator.pick(&pool);
            let seed_insns = seed_insns.clone();
            let seed_v = *seed_v;
            match mutator.try_mutate(&seed_insns, Some(&other_seed.1)) {
                None => {
                    mutations.invalid += 1;
                    continue;
                }
                Some(insns) => {
                    mutations.valid += 1;
                    (insns, Some(seed_v))
                }
            }
        } else {
            let mut generator = Generator::new(mix_seed(args.seed, i as u64));
            (generator.gen_mixed_program(cfg, IDIOM_RATIO_PERCENT), None)
        };

        let out = run_program(args, &name, &insns, qemu.as_deref_mut())?;

        // a verdict flip is high-value: it exposes a boundary in the
        // verifier's reasoning — persisted separately from findings
        if let Some(before) = seed_verdict {
            let after = out.mini.name();
            if before != after
                && let Some(env) = &out.env
            {
                let dir = findings_dir.join(format!("verdict-flip-{}", name));
                save_finding(
                    &dir,
                    env,
                    &ProgramResult {
                        label: "verdict-flip",
                        name: &out.name,
                        finding: out.finding,
                        mini: out.mini.clone(),
                        mini_reason: out.mini_reason.clone(),
                        kernel: out.kernel.clone(),
                        kernel_message: out.kernel_message.clone(),
                        bytes: &out.bytes,
                    },
                )?;
                flips.push((name.clone(), before.to_string(), after.to_string()));
            }
        }

        // the pool grows with campaign programs; only the campaign
        // tail is drained — the corpus seeds stay in the pool for the
        // whole campaign (AGENTS.md: seed >= 1000 must be exercised)
        pool.push((name.clone(), out.insns.clone(), out.mini.name()));
        if pool.len() > corpus_len + POOL_CAP {
            pool.drain(corpus_len..pool.len() - POOL_CAP);
        }

        handle_outcome(
            counts,
            surface_gaps,
            suppressed,
            kpi,
            coverage,
            findings,
            candidates,
            findings_dir,
            out,
        )?;

        let done = i + 1;
        let pct = done * 100 / args.iters.max(1);
        if done % ((args.iters / 10).max(1)) == 0 || done == args.iters {
            println!(
                "  progress: {done}/{} ({pct}%) agree={} skip={} flip={} findings={} mut={}/{}",
                args.iters,
                counts.get("agree").copied().unwrap_or(0),
                counts.get("skipped").copied().unwrap_or(0),
                flips.len(),
                findings.len(),
                mutations.valid,
                mutations.total,
            );
        }
    }
    Ok(())
}

/// The corpus fixtures as decoded mutation seeds, with their known
/// mini verdicts ("ACCEPT" / "REJECT").
fn load_corpus_seeds(args: &Args) -> anyhow::Result<Vec<(String, Vec<BpfInsn>, &'static str)>> {
    let mut seeds = Vec::new();
    for (dir, verdict) in [
        ("tests/programs/accept", "ACCEPT"),
        ("tests/programs/reject", "REJECT"),
    ] {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let bytes = fs::read(&path)?;
            // skip decode-invalid fixtures (e.g. ldimm64_bad_pseudo):
            // there is no instruction stream to mutate from
            let Ok(insns) = rand_verifier::insn::decode_program(&bytes) else {
                continue;
            };
            seeds.push((
                path.file_stem().unwrap().to_string_lossy().into_owned(),
                insns,
                verdict,
            ));
        }
    }
    // extra corpus directories: verdicts are computed with mini here
    for dir in &args.corpus_dirs {
        if !dir.is_dir() {
            anyhow::bail!("corpus dir not found: {}", dir.display());
        }
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }
            // accept `.bin` files only in extra dirs (meta files are
            // skipped by the extension check)
            let ext = path.extension();
            if ext.is_none() || ext.unwrap() != "bin" {
                continue;
            }
            let bytes = fs::read(&path)?;
            let Ok(insns) = rand_verifier::insn::decode_program(&bytes) else {
                continue;
            };
            let mut env = BpfVerifierEnv::new();
            env.setup_prog_bytes(&bytes)?;
            let verdict =
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| env.verify())) {
                    Ok(Ok(v)) => v,
                    // a model crash on a seed is recorded via the campaign
                    // stream itself; here the seed is skipped so the
                    // campaign can start (the mutated copies will re-trigger
                    // the path through run_program's catcher)
                    _ => continue,
                };
            let verdict = match verdict {
                Verdict::Safe => "ACCEPT",
                Verdict::Unsafe(_) => "REJECT",
            };
            seeds.push((
                path.file_stem().unwrap().to_string_lossy().into_owned(),
                insns,
                verdict,
            ));
        }
    }
    Ok(seeds)
}

/// Campaign KPI (#141): the numbers that expose saturation, as opposed to
/// the label count. A cluster is one root cause: the finding class plus the
/// normalized verifier messages plus a structural hash of the program.
struct Kpi {
    started: Instant,
    clusters: BTreeSet<String>,
    first_new_cluster_ms: Option<u128>,
}

impl Kpi {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            clusters: BTreeSet::new(),
            first_new_cluster_ms: None,
        }
    }

    fn observe(&mut self, out: &Outcome) {
        if !out.finding.is_finding() {
            return;
        }
        let is_new = self.clusters.insert(cluster_key(out));
        if is_new && self.first_new_cluster_ms.is_none() {
            self.first_new_cluster_ms = Some(self.started.elapsed().as_millis());
        }
    }
}

/// Normalize a verifier message into a clusterable form: embedded hex and
/// decimal literals become `#` (they vary per program, the rule does not),
/// while register names (`R6`) keep their number.
fn normalize_message(message: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for token in message.split_whitespace() {
        let mut norm = String::new();
        let mut chars = token.chars().peekable();
        let mut prev: Option<char> = None;
        while let Some(c) = chars.next() {
            let starts_number =
                c.is_ascii_digit() && prev.is_none_or(|p| !p.is_ascii_alphanumeric() && p != '_');
            if starts_number {
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_hexdigit() || d == 'x' || d == 'X' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                if norm.ends_with('-') || norm.ends_with('+') {
                    norm.pop();
                }
                norm.push('#');
                prev = Some('#');
            } else {
                norm.push(c);
                prev = Some(c);
            }
        }
        let norm = norm.trim_matches(|c: char| c == ',' || c == '.' || c == ';' || c == ':');
        if norm.is_empty() {
            continue;
        }
        if prev_space {
            out.push(' ');
        }
        out.push_str(norm);
        prev_space = true;
    }
    out.truncate(120);
    out
}

/// FNV-1a over the opcode-family sequence: deterministic across processes
/// (std's DefaultHasher is randomly keyed).
fn shape_hash(insns: &[BpfInsn]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for insn in insns {
        for byte in opcode_family(insn).bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn cluster_key(out: &Outcome) -> String {
    format!(
        "{}|{}|{}|{:016x}",
        out.finding.name(),
        normalize_message(out.mini_reason.as_deref().unwrap_or("")),
        normalize_message(out.kernel_message.as_deref().unwrap_or("")),
        shape_hash(&out.insns),
    )
}

/// Mutation statistics for the summary.
#[derive(Default)]
struct MutStats {
    total: usize,
    valid: usize,
    invalid: usize,
}

impl MutStats {
    fn validity_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.valid as f64 / self.total as f64
        }
    }
}

/// Everything the runner knows about one processed program.
struct Outcome {
    name: String,
    bytes: Vec<u8>,
    insns: Vec<BpfInsn>,
    /// `None` when the program could not even be loaded (decode error or
    /// an unregistered map fd): a surface gap, not a finding (#131).
    env: Option<BpfVerifierEnv>,
    mini: SideVerdict,
    mini_reason: Option<String>,
    mini_insn: Option<u32>,
    kernel: SideVerdict,
    kernel_message: Option<String>,
    kernel_insn: Option<u32>,
    finding: Finding,
    surface_gap: Option<SurfaceGapKind>,
}

/// One program through the whole pipeline: verify (mini + concrete),
/// optional kernel load, oracle classification. A panic inside the
/// mini/concrete side is caught and recorded as an `rv-panic` finding:
/// a model crash is a real bug, but it must not kill a whole
/// multi-hour campaign (the kernel verdict for the same program is
/// still asked and stored).
fn run_program(
    args: &Args,
    name: &str,
    insns: &[BpfInsn],
    qemu: Option<&mut QemuBatch>,
) -> anyhow::Result<Outcome> {
    let bytes: Vec<u8> = insns.iter().flat_map(insn_lib::encode).collect();

    // rand-verifier side (mini + concrete)
    let mut env = BpfVerifierEnv::new();
    if let Err(err) = env.setup_prog_bytes(&bytes) {
        // decode errors and unregistered map fds mean "the model cannot
        // judge this program", never "the kernel is wrong" (#131)
        let message = format!("{err:#}");
        let kind = surface_gap_kind(&message).unwrap_or(SurfaceGapKind::Other);
        return Ok(Outcome {
            name: name.to_string(),
            bytes,
            insns: insns.to_vec(),
            env: None,
            mini: SideVerdict::Skipped,
            mini_reason: Some(message),
            mini_insn: None,
            kernel: SideVerdict::Skipped,
            kernel_message: None,
            kernel_insn: None,
            finding: Finding::SurfaceGap,
            surface_gap: Some(kind),
        });
    }
    let (mini, mini_reason, mini_insn, panic_msg) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| env.verify())) {
            Ok(Ok(Verdict::Safe)) => (SideVerdict::Accept, None, None, None),
            Ok(Ok(Verdict::Unsafe(failure))) => {
                let category = categorize_mini_reason(&failure);
                let insn = failure.insn_idx();
                (
                    SideVerdict::Reject { category },
                    Some(failure.message),
                    Some(insn),
                    None,
                )
            }
            Ok(Err(e)) => return Err(e),
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(|s| s.as_str()))
                    .unwrap_or("<non-string panic>")
                    .to_string();
                (
                    SideVerdict::Skipped,
                    Some(format!("mini panicked: {msg}")),
                    None,
                    Some(msg),
                )
            }
        };

    // kernel side: qemu guest agent (preferred) or host kernel
    let (kernel, kernel_message, kernel_insn) = if let Some(qemu) = qemu {
        qemu.ask(name, &bytes)?
    } else if args.kernel {
        kernel_side_of(&load_with_kernel(&bytes))
    } else {
        (SideVerdict::Skipped, None, None)
    };

    let (finding, surface_gap) = if panic_msg.is_some() {
        (Finding::RvPanic, None)
    } else {
        classify_env_with_gap(
            &env,
            name,
            &mini,
            mini_reason.as_deref(),
            &kernel,
            kernel_message.as_deref(),
            args.strict,
        )
    };
    Ok(Outcome {
        name: name.to_string(),
        bytes,
        insns: insns.to_vec(),
        env: Some(env),
        mini,
        mini_reason,
        mini_insn,
        kernel,
        kernel_message,
        kernel_insn,
        finding,
        surface_gap,
    })
}

/// Count, record coverage, and persist a finding (plus its triage
/// candidate) — shared by both campaign modes.
#[allow(clippy::too_many_arguments)]
fn handle_outcome(
    counts: &mut BTreeMap<&'static str, usize>,
    surface_gaps: &mut BTreeMap<&'static str, usize>,
    suppressed: &mut BTreeMap<&'static str, usize>,
    kpi: &mut Kpi,
    coverage: &mut BTreeMap<&'static str, usize>,
    findings: &mut Vec<(String, String)>,
    candidates: &mut Vec<Candidate>,
    findings_dir: &Path,
    out: Outcome,
) -> anyhow::Result<()> {
    for insn in &out.insns {
        *coverage.entry(opcode_family(insn)).or_insert(0) += 1;
    }
    *counts.entry(out.finding.name()).or_insert(0) += 1;
    kpi.observe(&out);
    if out.finding == Finding::Whitelisted {
        let input = FingerprintInput {
            name: &out.name,
            mini: &out.mini,
            kernel: &out.kernel,
            mini_reason: out.mini_reason.as_deref(),
        };
        if let Some(fingerprint) = suppressed_fingerprint(&input) {
            *suppressed.entry(fingerprint.id).or_insert(0) += 1;
        }
    }
    if let Some(gap) = out.surface_gap {
        *surface_gaps.entry(gap.name()).or_insert(0) += 1;
    }
    if out.finding.is_finding() {
        let dir = findings_dir.join(format!("{}-{}", out.finding.name(), out.name));
        let env = out.env.as_ref().expect("finding outcomes carry an env");
        save_finding(
            &dir,
            env,
            &ProgramResult {
                label: out.finding.name(),
                name: &out.name,
                finding: out.finding,
                mini: out.mini.clone(),
                mini_reason: out.mini_reason.clone(),
                kernel: out.kernel.clone(),
                kernel_message: out.kernel_message.clone(),
                bytes: &out.bytes,
            },
        )?;
        findings.push((out.name.clone(), dir.display().to_string()));
        // triage input: the divergence signature (#70)
        candidates.push(Candidate {
            name: out.name.clone(),
            finding: out.finding,
            mini: out.mini.clone(),
            kernel: out.kernel.clone(),
            divergence: Divergence {
                mini_insn: out.mini_insn,
                kernel_insn: out.kernel_insn,
                concrete_pc: out.env.as_ref().and_then(first_violation_pc),
            },
        });
    }
    Ok(())
}

/// The kernel side of one load, with the message and reject index for
/// the finding artifact (same mapping as the diff harness).
fn kernel_side_of(outcome: &KernelOutcome) -> (SideVerdict, Option<String>, Option<u32>) {
    match outcome {
        KernelOutcome::Accept => (SideVerdict::Accept, None, None),
        KernelOutcome::Reject {
            message,
            category,
            insn_idx,
            ..
        } => (
            SideVerdict::Reject {
                category: *category,
            },
            Some(message.clone()),
            Some(*insn_idx),
        ),
        KernelOutcome::Privilege => (SideVerdict::Skipped, Some("EPERM (privilege)".into()), None),
        KernelOutcome::NoErrorLine { errno } => (
            SideVerdict::Skipped,
            Some(format!("errno {errno} (no log line)")),
            None,
        ),
        KernelOutcome::InvalidProgram => {
            (SideVerdict::Skipped, Some("invalid program".into()), None)
        }
    }
}

/// Everything the runner knows about one finding — the inputs of the
/// persisted artifact.
struct ProgramResult<'a> {
    /// The classification label: a finding name or "verdict-flip".
    label: &'a str,
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
    match rand_verifier::insn::decode_program(result.bytes) {
        Ok(decoded) => {
            for (idx, insn) in decoded.iter().enumerate() {
                dump.push_str(&format!("{idx:4}: {insn:?}\n"));
            }
        }
        Err((idx, e)) => dump.push_str(&format!("{idx:4}: decode error: {e}\n")),
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

    let spec = rand_verifier::fuzz::oracle::spec_side(&rand_verifier::spec::verify_spec(
        env.program_insns(),
        env.maps(),
    ));
    fs::write(
        dir.join("meta.json"),
        meta_json(
            result.label,
            result.name,
            &result.finding,
            &result.mini,
            &result.kernel,
            &spec,
        ),
    )?;
    Ok(())
}

/// The per-finding meta.json (deterministic for a fixed seed).
fn meta_json(
    label: &str,
    name: &str,
    finding: &Finding,
    mini: &SideVerdict,
    kernel: &SideVerdict,
    spec: &rand_verifier::fuzz::oracle::SpecSide,
) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"label\": \"{}\",\n", json_escape(label)));
    s.push_str(&format!("  \"name\": \"{}\",\n", json_escape(name)));
    s.push_str(&format!("  \"finding\": \"{}\",\n", finding.name()));
    s.push_str(&format!("  \"mini\": \"{}\",\n", side_json(mini)));
    s.push_str(&format!("  \"kernel\": \"{}\",\n", side_json(kernel)));
    s.push_str(&format!(
        "  \"spec\": \"{}\"\n",
        match spec {
            rand_verifier::fuzz::oracle::SpecSide::Accept => "ACCEPT",
            rand_verifier::fuzz::oracle::SpecSide::Reject => "REJECT",
            rand_verifier::fuzz::oracle::SpecSide::Inconclusive => "INCONCLUSIVE",
        }
    ));
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

/// Copy the artifact files of one finding into a group directory
/// (existing files only — kernel.log is optional).
fn copy_dir(src: &Path, dst: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dst)?;
    for name in [
        "prog.bin",
        "prog.dump",
        "mini.txt",
        "concrete.txt",
        "kernel.log",
        "meta.json",
    ] {
        let from = src.join(name);
        if from.is_file() {
            fs::copy(&from, dst.join(name))?;
        }
    }
    Ok(())
}

/// The per-group group.json (deterministic).
fn group_json(g: &Group, dir: &Path) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"finding\": \"{}\",\n", g.key.finding.name()));
    s.push_str(&format!(
        "  \"mini_category\": {},\n",
        opt_category(g.key.mini_category)
    ));
    s.push_str(&format!(
        "  \"kernel_category\": {},\n",
        opt_category(g.key.kernel_category)
    ));
    s.push_str(&format!("  \"div_insn\": {},\n", opt_u32(g.key.div_insn)));
    s.push_str(&format!(
        "  \"concrete_pc\": {},\n",
        opt_u32(g.key.concrete_pc)
    ));
    s.push_str(&format!("  \"count\": {},\n", g.count));
    s.push_str(&format!("  \"priority\": {},\n", g.priority));
    s.push_str(&format!(
        "  \"representative\": \"{}\",\n",
        json_escape(&g.representative)
    ));
    s.push_str(&format!(
        "  \"dir\": \"{}\"\n",
        json_escape(&dir.display().to_string())
    ));
    s.push_str("}\n");
    s
}

fn opt_category(c: Option<ReasonCategory>) -> String {
    match c {
        Some(c) => format!("\"{:?}\"", c),
        None => "null".to_string(),
    }
}

fn opt_u32(v: Option<u32>) -> String {
    match v {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    }
}

/// The campaign summary (schema: see #69/#71 / the PR).
///
/// ```json
/// { "seed": 42, "mode": "generation", "iters": 1000,
///   "counts": { "agree": 980, "precision-candidate": 2, ... },
///   "opcode_coverage": { "alu64": 512, ... },
///   "findings": [ { "name": "seed-42-7", "finding": "precision-candidate",
///                   "dir": "out/findings/..." } ],
///   "groups": [ { "finding": "precision-candidate", "count": 2,
///                  "priority": 1, "representative": "seed-42-7",
///                  "dir": "out/groups/1-000" } ],
///   "mutations": { "total": N, "valid": M, "invalid": K,
///                  "validity_rate": 0.xx },
///   "verdict_flips": [ { "name": "...", "before": "ACCEPT",
///                        "after": "REJECT" } ] }
/// ```
#[allow(clippy::too_many_arguments)]
fn write_summary(
    args: &Args,
    counts: &BTreeMap<&'static str, usize>,
    surface_gaps: &BTreeMap<&'static str, usize>,
    suppressed: &BTreeMap<&'static str, usize>,
    kpi: &Kpi,
    coverage: &BTreeMap<&'static str, usize>,
    findings: &[(String, String)],
    groups: &[Group],
    groups_dir: &Path,
    mutations: &MutStats,
    flips: &[(String, String, String)],
    batch_retries: usize,
) -> anyhow::Result<()> {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"seed\": {},\n", args.seed));
    s.push_str(&format!("  \"mode\": \"{}\",\n", args.mode));
    s.push_str(&format!("  \"iters\": {},\n", args.iters));
    s.push_str(&format!("  \"batch_retries\": {batch_retries},\n"));
    s.push_str("  \"counts\": {\n");
    push_map(&mut s, counts, "    ");
    s.push_str("  },\n  \"surface_gaps\": {\n");
    push_map(&mut s, surface_gaps, "    ");
    s.push_str("  },\n  \"suppressed\": {\n");
    push_map(&mut s, suppressed, "    ");
    let findings_total = findings.len();
    let unique_clusters = kpi.clusters.len();
    let duplicate_ratio = if unique_clusters == 0 {
        0.0
    } else {
        findings_total as f64 / unique_clusters as f64
    };
    let per_10k = if args.iters == 0 {
        0.0
    } else {
        unique_clusters as f64 * 10_000.0 / args.iters as f64
    };
    let surface_total: usize = surface_gaps.values().sum();
    let surface_rate = if args.iters == 0 {
        0.0
    } else {
        surface_total as f64 / args.iters as f64
    };
    s.push_str("  },\n  \"kpi\": {\n");
    s.push_str(&format!("    \"findings_total\": {findings_total},\n"));
    s.push_str(&format!("    \"unique_clusters\": {unique_clusters},\n"));
    s.push_str(&format!("    \"duplicate_ratio\": {duplicate_ratio:.3},\n"));
    s.push_str(&format!("    \"unique_clusters_per_10k\": {per_10k:.3},\n"));
    s.push_str(&format!("    \"surface_gap_rate\": {surface_rate:.3},\n"));
    match kpi.first_new_cluster_ms {
        Some(ms) => s.push_str(&format!("    \"time_to_first_new_cluster_ms\": {ms}\n")),
        None => s.push_str("    \"time_to_first_new_cluster_ms\": null\n"),
    }
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
    s.push_str("  ],\n  \"groups\": [\n");
    for (i, g) in groups.iter().enumerate() {
        let comma = if i + 1 == groups.len() { "" } else { "," };
        let gdir = groups_dir.join(format!("{}-{:03}", g.priority, i));
        s.push_str(&format!(
            "    {{\"finding\": \"{}\", \"count\": {}, \"priority\": {}, \"representative\": \"{}\", \"dir\": \"{}\"}}{}\n",
            g.key.finding.name(),
            g.count,
            g.priority,
            json_escape(&g.representative),
            json_escape(&gdir.display().to_string()),
            comma
        ));
    }
    s.push_str("  ],\n  \"mutations\": {\n");
    s.push_str(&format!("    \"total\": {},\n", mutations.total));
    s.push_str(&format!("    \"valid\": {},\n", mutations.valid));
    s.push_str(&format!("    \"invalid\": {},\n", mutations.invalid));
    s.push_str(&format!(
        "    \"validity_rate\": {:.3}\n",
        mutations.validity_rate()
    ));
    s.push_str("  },\n  \"verdict_flips\": [\n");
    for (i, (name, before, after)) in flips.iter().enumerate() {
        let comma = if i + 1 == flips.len() { "" } else { "," };
        s.push_str(&format!(
            "    {{\"name\": \"{}\", \"before\": \"{}\", \"after\": \"{}\"}}{}\n",
            json_escape(name),
            before,
            after,
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

#[cfg(test)]
mod kpi_tests {
    use super::*;
    use rand_verifier::insn::decode_program;

    #[test]
    fn normalize_collapses_literals_and_keeps_registers() {
        assert_eq!(
            normalize_message("invalid stack off=-8 size=8"),
            "invalid stack off=# size=#"
        );
        assert_eq!(
            normalize_message("R6 invalid mem access 'scalar'"),
            "R6 invalid mem access 'scalar'"
        );
        assert_eq!(normalize_message("ptr 0xffffffff"), "ptr #");
        assert_eq!(normalize_message(""), "");
    }

    #[test]
    fn shape_hash_is_deterministic_and_program_specific() {
        let a = decode_program(&[0xb7, 0, 0, 0, 42, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let b = decode_program(&[0xb7, 0, 0, 0, 42, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let c = decode_program(&[0xb7, 0, 0, 0, 7, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        // same opcode families -> same structural hash (the value differs)
        assert_eq!(shape_hash(&a), shape_hash(&b));
        assert_eq!(shape_hash(&a), shape_hash(&c));
        assert_ne!(shape_hash(&a), shape_hash(&a[..1]));
    }
}
