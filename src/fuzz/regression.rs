// ── Fuzzer regression tests (v0.7, #72) ─────────────────────────────────────

//! Integration-level fuzz regression tests: the pipeline from
//! generation to classification, pinned by fixed seeds. Every kernel
//! column is injected as a [`SideVerdict`] — no bpf() syscall — so the
//! suite is green on unprivileged hosts (kernel columns are "skipped,
//! not failed", following the v0.6 diff test pattern).

use std::collections::HashSet;

use crate::diff::{SideVerdict, categorize_mini_reason};
use crate::env::BpfVerifierEnv;
use crate::error::Verdict;
use crate::fuzz::generator::{GenConfig, Generator};
use crate::fuzz::insn_lib;
use crate::fuzz::oracle::{ConcreteSide, Finding, classify_env, concrete_side};

/// One program through generation → verify, with the mini and concrete
/// sides extracted for classification.
struct Case {
    bytes: Vec<u8>,
    env: BpfVerifierEnv,
    verdict: Verdict,
    mini: SideVerdict,
    mini_reason: Option<String>,
    concrete: ConcreteSide,
}

fn run_case(seed: u64) -> Case {
    let mut g = Generator::new(seed);
    // the campaign's mixed mode: 30% idiom templates (#69)
    let insns = g.gen_mixed_program(&GenConfig::default(), 30);
    let bytes: Vec<u8> = insns.iter().flat_map(insn_lib::encode).collect();
    let mut env = BpfVerifierEnv::new();
    env.setup_prog_bytes(&bytes).unwrap();
    let verdict = env.verify().unwrap();
    let (mini, mini_reason) = match &verdict {
        Verdict::Safe => (SideVerdict::Accept, None),
        Verdict::Unsafe(f) => (
            SideVerdict::Reject {
                category: categorize_mini_reason(f),
            },
            Some(f.message.clone()),
        ),
    };
    let concrete = concrete_side(env.concrete_report.as_ref().expect("concrete report"));
    Case {
        bytes,
        env,
        verdict,
        mini,
        mini_reason,
        concrete,
    }
}

fn same_verdict(a: &Verdict, b: &Verdict) -> bool {
    match (a, b) {
        (Verdict::Safe, Verdict::Safe) => true,
        (Verdict::Unsafe(x), Verdict::Unsafe(y)) => {
            x.insn_idx() == y.insn_idx() && x.message == y.message
        }
        _ => false,
    }
}

/// The classification invariants over a fixed-seed campaign and the
/// corpus:
/// 1. a mini-ACCEPT program with an UNSAFE concrete side is a model
///    bug (`RvSoundnessBug`) — it must surface in the report channel,
///    never silently;
/// 2. a program the kernel accepts (concretely safe) that mini rejects
///    is a rand-verifier gap — never a kernel soundness finding;
/// 3. nothing panics and everything decodes.
#[test]
fn campaign_invariants() {
    let kernel_accept = SideVerdict::Accept;
    let kernel_skipped = SideVerdict::Skipped;
    let mut model_bugs = 0;
    for seed in 0..200u64 {
        let case = run_case(seed);

        // invariant 1: a model bug is always the loud classification
        if case.mini == SideVerdict::Accept && case.concrete == ConcreteSide::Unsafe {
            let f = classify_env(
                &case.env,
                &format!("seed-{seed}"),
                &case.mini,
                case.mini_reason.as_deref(),
                &kernel_skipped,
                None,
                false,
            );
            assert_eq!(f, Finding::RvSoundnessBug, "seed {seed}: model bug hidden");
            model_bugs += 1;
        }
    }

    // invariant 2 over the corpus: every reject fixture that executes
    // concretely must classify as a rand-verifier gap (or a
    // name-whitelisted design difference) when the kernel accepts —
    // never a kernel soundness finding. Generated programs always pass
    // the nano checks, so concrete-safe rejects only exist in the
    // corpus (e.g. unreachable, invalid_helper_argument).
    let dir = std::path::Path::new("tests/programs/reject");
    let mut gap_fixtures = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes).unwrap();
        let verdict = env.verify().unwrap();
        if let Verdict::Unsafe(failure) = &verdict {
            let mini = SideVerdict::Reject {
                category: categorize_mini_reason(failure),
            };
            // decode-error rejects have no concrete run
            let Some(report) = env.concrete_report.as_ref() else {
                continue;
            };
            let concrete = concrete_side(report);
            if concrete == ConcreteSide::Safe {
                let name = path.file_stem().unwrap().to_string_lossy().into_owned();
                let f = classify_env(&env, &name, &mini, None, &kernel_accept, None, false);
                // with the spec axis (#113) a fixture the spec also
                // rejects is a kernel-unsound candidate under the
                // hypothetical kernel-accept — the spec independently
                // flags the program, so mini's rejection is no longer
                // just a model gap
                assert!(
                    f == Finding::RvPrecisionGap
                        || f == Finding::Whitelisted
                        || f == Finding::KernelUnsoundCandidate,
                    "{name}: {f:?}"
                );
                gap_fixtures += 1;
            }
        }
    }
    assert!(
        gap_fixtures > 0,
        "no concretely-executing reject fixtures found"
    );
    eprintln!("model bugs surfaced: {model_bugs}, gap fixtures: {gap_fixtures}");
}

/// The whole pipeline is deterministic: same seed → identical program
/// bytes, verdict, and concrete report.
#[test]
fn campaign_deterministic_stream() {
    for seed in 0..20u64 {
        let a = run_case(seed);
        let b = run_case(seed);
        assert_eq!(a.bytes, b.bytes, "seed {seed}: program bytes");
        assert!(same_verdict(&a.verdict, &b.verdict), "seed {seed}: verdict");
        assert_eq!(
            a.env.concrete_report_text(),
            b.env.concrete_report_text(),
            "seed {seed}: concrete report"
        );
    }
}

/// The mixed campaign mode (30% idioms) covers every supported opcode
/// family over a fixed seed set.
#[test]
fn campaign_opcode_coverage() {
    let mut seen = HashSet::new();
    for seed in 0..500u64 {
        let mut g = Generator::new(seed);
        let insns = g.gen_mixed_program(&GenConfig::default(), 30);
        for insn in &insns {
            seen.insert(insn_lib::opcode_family(insn));
        }
    }
    for family in [
        "alu64",
        "alu32",
        "cmp_eq",
        "cmp_unsigned",
        "cmp_signed",
        "stack",
        "helper",
        "jmp",
        "exit",
    ] {
        assert!(seen.contains(family), "family '{family}' never generated");
    }
}

/// A saved finding reproduces its classification through the pipeline:
/// the persisted bytes reload into the same verdict and the same
/// finding (kernel column injected as ACCEPT so precision/soundness
/// candidates appear without privilege).
#[test]
fn campaign_finding_replay() {
    let kernel_accept = SideVerdict::Accept;
    let mut replayed = 0;
    for seed in 0..200u64 {
        let case = run_case(seed);
        let name = format!("seed-{seed}");
        let f = classify_env(
            &case.env,
            &name,
            &case.mini,
            case.mini_reason.as_deref(),
            &kernel_accept,
            None,
            false,
        );
        if !f.is_finding() {
            continue;
        }
        // persist the finding bytes exactly like the runner does
        let path = std::env::temp_dir().join(format!(
            "rand_verifier_fuzz_replay_{}_{}.bpf",
            seed,
            std::process::id()
        ));
        std::fs::write(&path, &case.bytes).unwrap();

        // replay through the pipeline
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).ok();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes).unwrap();
        let verdict = env.verify().unwrap();
        assert!(
            same_verdict(&case.verdict, &verdict),
            "seed {seed}: verdict changed on replay"
        );
        let mini = match &verdict {
            Verdict::Safe => SideVerdict::Accept,
            Verdict::Unsafe(f) => SideVerdict::Reject {
                category: categorize_mini_reason(f),
            },
        };
        let f2 = classify_env(&env, &name, &mini, None, &kernel_accept, None, false);
        assert_eq!(f, f2, "seed {seed}: classification changed on replay");
        replayed += 1;
    }
    assert!(replayed > 0, "no findings in the fixed-seed campaign");
    eprintln!("findings replayed: {replayed}");
}

/// Explicit smoke: N seeds × M iterations of generation + verification
/// never panic and every program decodes (pinned by this test).
#[test]
fn campaign_smoke_no_panic() {
    for seed in 0..100u64 {
        for _ in 0..3 {
            let case = run_case(seed);
            assert_eq!(case.bytes.len() % 8, 0);
        }
    }
}
