//! Reducer regression tests (v0.8, #83): pinned fixtures from real
//! v0.7 findings, CLI exit-code contracts, and determinism — all
//! unprivileged (kernel columns skipped, not failed).
//!
//! Fixtures under `tests/data/reduce/`:
//! - `verdict-flip-mseed-5-3` — a real mutation-mode flip (kernel-
//!   independent; reduces unprivileged).
//!
//! The former kernel-dependent fixture (`rv-precision-gap-mseed-5-99`)
//! was absorbed into the accept corpus as `computed_pointer_no_access`
//! once #87 moved pointer validation to access time — there is no
//! kernel-dependent finding left to pin.

use std::path::PathBuf;
use std::process::Command;

use rand_verifier::error::Verdict;
use rand_verifier::fuzz::reduce::{ReduceConfig, evaluate_bytes, reduce_finding};

const VERDICT_FLIP: &str = "tests/data/reduce/verdict-flip-mseed-5-3";

fn reduce_bin() -> &'static str {
    env!("CARGO_BIN_EXE_reduce")
}

/// A unique scratch directory per test (parallel-safe).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rv-reduce-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── CLI exit-code contract (#82) ───────────────────────────────────────────

#[test]
fn cli_usage_error_exits_3() {
    // no arguments
    let out = Command::new(reduce_bin()).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "no args must exit 3");
    // unknown flag
    let out = Command::new(reduce_bin())
        .args(["--nope", VERDICT_FLIP])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "unknown flag must exit 3");
    // a finding dir plus --all-groups is contradictory
    let out = Command::new(reduce_bin())
        .args([VERDICT_FLIP, "--all-groups", "tests/data/reduce"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn cli_success_reduces_fixture_exit_0() {
    let out_dir = scratch("ok");
    let out = Command::new(reduce_bin())
        .args([VERDICT_FLIP, "--out-dir"])
        .arg(&out_dir)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // the artifact exists and is a valid instruction stream
    let prog = out_dir.join("reduced/verdict-flip-mseed-5-3/prog.bin");
    assert!(prog.is_file(), "missing {prog:?}");
    let bytes = std::fs::read(&prog).unwrap();
    assert!(bytes.len().is_multiple_of(8) && !bytes.is_empty());
    let json = std::fs::read_to_string(out_dir.join("reduced/verdict-flip-mseed-5-3/reduce.json"))
        .unwrap();
    assert!(json.contains("\"final_insns\""), "{json}");
    // the reduced program still exhibits the flip (mini REJECT)
    let sides = evaluate_bytes(&bytes, false, false, None).unwrap();
    assert_eq!(sides.mini.name(), "REJECT");
    assert!(
        bytes.len() < 64,
        "the fixture must shrink ({} bytes)",
        bytes.len()
    );
}

#[test]
fn cli_reduces_all_groups() {
    // build a groups root with one copied group
    let root = scratch("groups");
    let groups = root.join("groups");
    std::fs::create_dir_all(&groups).unwrap();
    let src = PathBuf::from(VERDICT_FLIP);
    let dst = groups.join("0-000");
    std::fs::create_dir_all(&dst).unwrap();
    for f in ["prog.bin", "meta.json", "mini.txt"] {
        std::fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    let out = Command::new(reduce_bin())
        .args(["--all-groups"])
        .arg(&root)
        .args(["--out-dir"])
        .arg(scratch("grp-out"))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── library-level invariants on the fixtures ────────────────────────────────

#[test]
fn fixture_verdict_flip_reduces_and_preserves() {
    let out_dir = scratch("lib");
    let report = reduce_finding(
        PathBuf::from(VERDICT_FLIP).as_path(),
        &out_dir,
        &ReduceConfig {
            budget: 0,
            kernel: false,
            strict: false,
            qemu_dir: None,
        },
    )
    .unwrap();
    assert_eq!(report.label, "verdict-flip");
    assert!(report.final_insns < report.original_insns);
    assert_eq!(report.final_mini, "REJECT");
    // the timeline is monotonic non-increasing
    let counts: Vec<usize> = report.timeline.iter().map(|(_, c)| *c).collect();
    assert!(counts.windows(2).all(|w| w[0] >= w[1]), "{counts:?}");
}

// ── determinism ─────────────────────────────────────────────────────────────

#[test]
fn fixture_reduction_is_deterministic() {
    let out_a = scratch("det-a");
    let out_b = scratch("det-b");
    for out in [&out_a, &out_b] {
        let status = Command::new(reduce_bin())
            .args([VERDICT_FLIP, "--out-dir"])
            .arg(out)
            .status()
            .unwrap();
        assert!(status.success());
    }
    let a = std::fs::read(out_a.join("reduced/verdict-flip-mseed-5-3/prog.bin")).unwrap();
    let b = std::fs::read(out_b.join("reduced/verdict-flip-mseed-5-3/prog.bin")).unwrap();
    assert_eq!(a, b, "same fixture must reduce byte-identically");
}

// ── replay of the fixtures through the pipeline ─────────────────────────────

#[test]
fn fixture_replay_matches_meta() {
    // the mini side recorded in meta.json must reproduce — the
    // fixtures stay meaningful across verifier changes (#76 contract)
    let dir = VERDICT_FLIP;
    let bytes = std::fs::read(format!("{dir}/prog.bin")).unwrap();
    let mut env = rand_verifier::env::BpfVerifierEnv::new();
    env.setup_prog_bytes(&bytes).unwrap();
    match env.verify().unwrap() {
        Verdict::Safe => panic!("{dir}: fixture must reject"),
        Verdict::Unsafe(failure) => {
            let category = rand_verifier::diff::categorize_mini_reason(&failure);
            let meta = std::fs::read_to_string(format!("{dir}/meta.json")).unwrap();
            // the recorded mini line, e.g. "mini": "REJECT(UninitRead)"
            let recorded = meta
                .lines()
                .find(|l| l.contains("\"mini\""))
                .unwrap_or_else(|| panic!("{dir}: meta.json without a mini line"));
            assert!(
                recorded.contains(&format!("{category:?}")),
                "{dir}: mini {category:?} not in {recorded}"
            );
        }
    }
}
