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
use rand_verifier::fuzz::mutator::Mutator;
use rand_verifier::fuzz::oracle::{Finding, classify_env, first_violation_pc};
use rand_verifier::fuzz::triage::{Candidate, Divergence, Group, group};
use rand_verifier::insn::BpfInsn;
use rand_verifier::klog::{ReasonCategory, categorize_reason};
use rand_verifier::krun::{KernelOutcome, drop_privileged_caps, load_with_kernel};

/// Share of idiom-template programs in a generation campaign — the
/// milestone's stress semantics get reliable coverage (#67).
const IDIOM_RATIO_PERCENT: u64 = 30;
/// Mutation-mode pool size cap: the corpus plus the most recent
/// campaign programs.
const POOL_CAP: usize = 200;
/// qemu batch size: programs sent to the guest per round-trip.
const QEMU_BATCH: usize = 100;

/// The script the guest runs for one batch: verify every job file,
/// write `out/<name>.out`. Completion is detected by state, not by a
/// marker file: the host polls until `job/` is empty and every
/// expected result exists in `out/`. (A shared batch-done marker
/// races badly over the 9p share: the guest's stale dentry cache can
/// make its touch fail with ENOENT or hide the host's deletions,
/// stalling the host for its full 60s/300s wait.)
const QEMU_RUN_SCRIPT: &str = r###"#!/bin/sh
STRICT=""
[ -f /mnt/host/strict ] && STRICT="--strict"
for f in /mnt/host/job/*.bin; do
    [ -e "$f" ] || continue
    b=$(basename "$f" .bin)
    /sbin/agent "$f" $STRICT > "/mnt/host/out/$b.out" 2>&1
    rm -f "$f"
done
"###;

/// Batch kernel-verdict queries to the qemu guest via the 9p share:
/// the guest's init loop picks up `job/<name>.bin`, runs the agent,
/// and writes the verdict to `out/<name>.out`. The host polls until
/// every result is back (or times out), then classifies.
struct QemuBatch {
    tx: std::sync::mpsc::Sender<QemuJob>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// One kernel query: program bytes + a channel the worker replies on.
type QemuJob = (
    String,
    Vec<u8>,
    std::sync::mpsc::Sender<Result<(SideVerdict, Option<String>), String>>,
);

impl QemuBatch {
    fn new(dir: PathBuf, strict: bool) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_dir = dir.clone();
        let handle = std::thread::spawn(move || qemu_worker(worker_dir, strict, rx));
        Self {
            tx,
            handle: Some(handle),
        }
    }

    /// Queue one program and block until the guest kernel verdict is
    /// back. The worker batches queries and flushes them to the guest
    /// every `QEMU_BATCH` jobs or ~30ms, whichever comes first.
    fn ask(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> anyhow::Result<(SideVerdict, Option<String>, Option<u32>)> {
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx.send((name.to_string(), bytes.to_vec(), rtx))?;
        match rrx.recv()? {
            Ok((v, m)) => Ok((v, m, None)),
            Err(e) => Ok((SideVerdict::Skipped, Some(e), None)),
        }
    }

    /// Flush any remaining tail batch (campaign end).
    fn flush(&mut self) -> anyhow::Result<()> {
        let (rtx, rrx) = std::sync::mpsc::channel();
        self.tx.send(("__flush__".into(), Vec::new(), rtx))?;
        rrx.recv()?.map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

impl Drop for QemuBatch {
    fn drop(&mut self) {
        // disconnect the channel so the worker drains and exits: send the
        // flush signal, then drop our sender so the worker's recv_timeout
        // loop sees the disconnect and terminates (without dropping the
        // sender first, join() hangs forever — the channel stays open).
        let _ = self
            .tx
            .send(("__flush__".into(), Vec::new(), std::sync::mpsc::channel().0));
        drop(std::mem::replace(
            &mut self.tx,
            std::sync::mpsc::channel().0,
        ));
        let _ = self.handle.take().map(|h| h.join());
    }
}
/// Worker thread: collect queries, flush them to the guest in batches,
/// and deliver every verdict to its query channel.
fn qemu_worker(dir: PathBuf, strict: bool, rx: std::sync::mpsc::Receiver<QemuJob>) {
    let mut pending: Vec<QemuJob> = Vec::new();
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(30)) {
            Ok((name, bytes, resp)) => {
                if name == "__flush__" {
                    flush_batch(&dir, strict, &mut pending);
                    let _ = resp.send(Ok((SideVerdict::Accept, None)));
                } else {
                    pending.push((name, bytes, resp));
                    if pending.len() >= QEMU_BATCH {
                        flush_batch(&dir, strict, &mut pending);
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !pending.is_empty() {
                    flush_batch(&dir, strict, &mut pending);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                flush_batch(&dir, strict, &mut pending);
                break;
            }
        }
    }
}

/// Send one batch to the guest and deliver the parsed verdicts.
///
/// Completion protocol (markerless, race-free over the 9p share):
/// the host waits until `job/` is empty (the guest consumed the
/// previous batch), clears stale results, writes the new batch, and
/// polls until every job has its `out/<name>.out` and `job/` is
/// empty again. No batch-done marker exists, so host and guest never
/// churn the same file.
fn flush_batch(dir: &Path, strict: bool, pending: &mut Vec<QemuJob>) {
    if pending.is_empty() {
        return;
    }
    let job = dir.join("job");
    let out = dir.join("out");
    if fs::create_dir_all(&job).is_err() || fs::create_dir_all(&out).is_err() {
        fail_all(pending, "qemu: cannot create share dirs");
        return;
    }
    // strict mode is signalled to the guest via a marker file
    let strict_marker = dir.join("strict");
    if strict {
        let _ = fs::write(&strict_marker, b"1");
    } else {
        let _ = fs::remove_file(&strict_marker);
    }

    // wait until the guest consumed the previous batch (job/ empty),
    // then clear stale results
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while job_has_files(&job) {
        if std::time::Instant::now() > deadline {
            eprintln!("qemu: previous batch never consumed; clearing job dir");
            clear_dir(&job);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    clear_dir(&out);

    // write the batch + the run script
    let mut ok = true;
    for (name, bytes, _) in pending.iter() {
        if fs::write(job.join(format!("{name}.bin")), bytes).is_err() {
            ok = false;
            break;
        }
    }
    if ok {
        ok = fs::write(dir.join("run.sh"), QEMU_RUN_SCRIPT).is_ok();
    }
    if !ok {
        fail_all(pending, "qemu: cannot write batch");
        return;
    }
    // poll until every job has its result and the guest consumed the
    // whole batch: the job file disappears only after the agent
    // finished writing its out file, so both conditions together mean
    // the result is complete
    let want = pending.len();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while pending.iter().any(|(name, _, _)| {
        job.join(format!("{name}.bin")).exists()
            || !out.join(format!("{name}.out")).is_file()
    }) {
        if std::time::Instant::now() > deadline {
            eprintln!("qemu: timeout waiting for {want} results; marking rest skipped");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // parse the results and reply
    for (name, _, resp) in pending.drain(..) {
        let p = out.join(format!("{name}.out"));
        // the guest may still be writing the last file: retry a few
        // times before giving up
        let mut parsed = None;
        for _ in 0..10 {
            let text = fs::read_to_string(&p).unwrap_or_default();
            if text.trim().is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            parsed = parse_agent_verdict(&text);
            break;
        }
        let first_line = fs::read_to_string(&p)
            .ok()
            .and_then(|s| s.lines().next().map(|l| l.to_string()))
            .unwrap_or_else(|| "<no file>".into());
        let _ = fs::remove_file(&p);
        match parsed {
            Some((v, m)) => {
                let _ = resp.send(Ok((v, m)));
            }
            None => {
                eprintln!("qemu: parse failure for {name}: {first_line:?}");
                let _ = resp.send(Err("qemu: parse/read failure".into()));
            }
        }
    }
}

fn job_has_files(job: &Path) -> bool {
    fs::read_dir(job)
        .map(|it| it.flatten().next().is_some())
        .unwrap_or(false)
}

fn clear_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let _ = fs::remove_file(e.path());
        }
    }
}

fn fail_all(pending: &mut Vec<QemuJob>, why: &str) {
    for (name, _, resp) in pending.drain(..) {
        eprintln!("qemu: {why} for {name}");
        let _ = resp.send(Err(why.into()));
    }
}

/// Parse one agent output file: `ACCEPT` or `REJECT <reason> errno=<n>`.
fn parse_agent_verdict(text: &str) -> Option<(SideVerdict, Option<String>)> {
    let first = text.lines().find(|l| !l.trim().is_empty())?;
    if first.trim() == "ACCEPT" {
        return Some((SideVerdict::Accept, None));
    }
    let rest = first.trim();
    if let Some(reason) = rest.strip_prefix("REJECT ") {
        // strip the trailing "errno=<n>"
        let reason = reason
            .rsplit_once(" errno=")
            .map(|(r, _)| r)
            .unwrap_or(reason);
        let category = categorize_reason(reason);
        return Some((SideVerdict::Reject { category }, Some(reason.to_string())));
    }
    None
}

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
            &mut coverage,
            &mut findings,
            &mut candidates,
            &mut mutations,
            &mut flips,
            qemu.as_mut(),
        )?;
    } else {
        for i in 0..args.iters {
            let name = format!("seed-{}-{}", args.seed, i);
            // one generator per program: the per-program seed fully
            // determines the program and every rand-verifier verdict
            let mut generator = Generator::new(args.seed.wrapping_add(i as u64));
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
                &mut coverage,
                &mut findings,
                &mut candidates,
                &findings_dir,
                out,
            )?;
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

    write_summary(
        &args,
        &counts,
        &coverage,
        &findings,
        &groups,
        &groups_dir,
        &mutations,
        &flips,
    )?;

    // flush the qemu batch tail so every kernel verdict is in
    if let Some(qemu) = qemu.as_mut() {
        qemu.flush()?;
    }

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
        let mut mutator = Mutator::new(args.seed.wrapping_add(i as u64));

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
            let mut generator = Generator::new(args.seed.wrapping_add(i as u64));
            (generator.gen_mixed_program(cfg, IDIOM_RATIO_PERCENT), None)
        };

        let out = run_program(args, &name, &insns, qemu.as_deref_mut())?;

        // a verdict flip is high-value: it exposes a boundary in the
        // verifier's reasoning — persisted separately from findings
        if let Some(before) = seed_verdict {
            let after = out.mini.name();
            if before != after {
                let dir = findings_dir.join(format!("verdict-flip-{}", name));
                save_finding(
                    &dir,
                    &out.env,
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

        handle_outcome(counts, coverage, findings, candidates, findings_dir, out)?;
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
            let verdict = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                env.verify()
            })) {
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
    env: BpfVerifierEnv,
    mini: SideVerdict,
    mini_reason: Option<String>,
    mini_insn: Option<u32>,
    kernel: SideVerdict,
    kernel_message: Option<String>,
    kernel_insn: Option<u32>,
    finding: Finding,
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
    env.setup_prog_bytes(&bytes)?;
    let (mini, mini_reason, mini_insn, panic_msg) = match std::panic::catch_unwind(
        std::panic::AssertUnwindSafe(|| env.verify()),
    ) {
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

    let finding = if panic_msg.is_some() {
        Finding::RvPanic
    } else {
        classify_env(
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
        env,
        mini,
        mini_reason,
        mini_insn,
        kernel,
        kernel_message,
        kernel_insn,
        finding,
    })
}

/// Count, record coverage, and persist a finding (plus its triage
/// candidate) — shared by both campaign modes.
#[allow(clippy::too_many_arguments)]
fn handle_outcome(
    counts: &mut BTreeMap<&'static str, usize>,
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
    if out.finding.is_finding() {
        let dir = findings_dir.join(format!("{}-{}", out.finding.name(), out.name));
        save_finding(
            &dir,
            &out.env,
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
                concrete_pc: first_violation_pc(&out.env),
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

    fs::write(
        dir.join("meta.json"),
        meta_json(
            result.label,
            result.name,
            &result.finding,
            &result.mini,
            &result.kernel,
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
) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"label\": \"{}\",\n", json_escape(label)));
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
    coverage: &BTreeMap<&'static str, usize>,
    findings: &[(String, String)],
    groups: &[Group],
    groups_dir: &Path,
    mutations: &MutStats,
    flips: &[(String, String, String)],
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
