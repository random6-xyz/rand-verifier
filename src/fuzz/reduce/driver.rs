// ── Reducer driver and report (v0.8, #81) ───────────────────────────────────

//! The driver composes the pieces: replay + invariant (#76), deletion
//! fixup (#77), ddmin with cache/budget (#78), CFG passes (#79) and
//! operand minimization (#80) into one working reducer.
//!
//! Pass order per cycle: CFG (dead code → slice → branch
//! simplification) → ddmin → operand minimization; cycles repeat until
//! a full cycle makes no progress (fixpoint). Every candidate is
//! validated by the oracle — the invariant preserved through the
//! pipeline (with the kernel column when the finding needs it).
//!
//! The final re-check is mandatory: the reduced program is evaluated
//! once more and must still exhibit the finding. A failure is a
//! reducer bug and surfaces as a hard error, never a silent success.
//! Artifacts land in `<out-dir>/reduced/<finding>/`: `prog.bin`,
//! `prog.dump` (replayable via kernel_run) and `reduce.json` with the
//! per-pass size timeline, oracle stats, and the re-confirmed
//! classification.

use std::fs;
use std::path::Path;

use crate::fuzz::reduce::ddmin::{OracleCache, ddmin};
use crate::fuzz::reduce::operand::operand_candidates;
use crate::fuzz::reduce::passes::{dead_code, failure_anchor, simplify_dead_side, slice_to_anchor};
use crate::fuzz::reduce::replay::{Baseline, ReduceError, Sides, evaluate_bytes, load_and_replay};
use crate::insn::parse_insn;

/// The reducer configuration.
#[derive(Debug, Clone)]
pub struct ReduceConfig {
    /// Max oracle checks (`0` = unlimited).
    pub budget: usize,
    /// Consult the kernel for every evaluation (required for
    /// kernel-dependent findings — enforced at replay).
    pub kernel: bool,
    /// Strict mode: the kernel ran with unprivileged-equivalent rules.
    pub strict: bool,
    /// Kernel verdicts via a qemu guest's 9p share instead of a host
    /// bpf() syscall (issue #114: no host privileges needed).
    pub qemu_dir: Option<std::path::PathBuf>,
}

/// One timeline entry: the pass that produced the program and the
/// instruction count after it.
pub type TimelineEntry = (String, usize);

/// The result of one reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReduceReport {
    pub name: String,
    pub label: String,
    pub original_insns: usize,
    pub final_insns: usize,
    pub timeline: Vec<TimelineEntry>,
    pub checks: usize,
    pub hits: usize,
    pub budget: usize,
    pub final_mini: String,
    pub final_kernel: String,
}

/// Reduce one finding directory into `<out-dir>/reduced/<finding>/`.
/// The classification must survive every step (oracle) and the final
/// re-check; both are hard contracts.
pub fn reduce_finding(
    dir: &Path,
    out_dir: &Path,
    config: &ReduceConfig,
) -> Result<ReduceReport, ReduceError> {
    let mut qemu = config
        .qemu_dir
        .clone()
        .map(|d| crate::fuzz::qemu::QemuBatch::new(d, config.strict));
    let baseline = load_and_replay(dir, config.kernel, config.strict, qemu.as_mut())?;
    let original = read_prog(dir)?;

    // the oracle: the candidate must re-classify to the finding
    let mut oracle = |bytes: &[u8]| -> bool {
        match evaluate_bytes(bytes, config.kernel, config.strict, qemu.as_mut()) {
            Ok(sides) => baseline
                .invariant
                .preserves(&baseline.spec.name, &sides, config.strict),
            Err(_) => false, // pipeline failure / kernel refused — reject
        }
    };

    let mut cache = OracleCache::new(config.budget);
    let mut current = original.clone();
    let mut timeline: Vec<TimelineEntry> = vec![("start".to_string(), insn_count(&original))];

    // a full cycle makes no progress → fixpoint
    loop {
        let mut progress = false;

        // 1. CFG passes: dead code → slice → branch simplification
        let anchor = failure_anchor(&current);
        let cfg_candidates = [
            dead_code(&current),
            slice_to_anchor(&current, anchor),
            dead_code(&current).and_then(|d| slice_to_anchor(&d, anchor)),
        ]
        .into_iter()
        .flatten()
        .chain(simplify_dead_side(&current));
        for candidate in cfg_candidates {
            if let Some(next) = apply(&current, candidate, &mut cache, &mut oracle) {
                current = next;
                timeline.push(("cfg".to_string(), insn_count(&current)));
                progress = true;
                break;
            }
        }

        // 2. ddmin: chunk → single-insn deletion
        if let Some(reduced) = ddmin(&current, &mut cache, &mut oracle)
            && reduced != current
        {
            current = reduced;
            timeline.push(("ddmin".to_string(), insn_count(&current)));
            progress = true;
        }

        // 3. operand minimization (one change per candidate)
        for (_, candidate) in operand_candidates(&current) {
            if let Some(next) = apply(&current, candidate, &mut cache, &mut oracle) {
                current = next;
                timeline.push(("operand".to_string(), insn_count(&current)));
                progress = true;
                break;
            }
        }

        if !progress {
            break;
        }
    }

    // mandatory final re-check: the reduced program must still exhibit
    // the finding — anything else is a reducer bug
    let final_sides = evaluate_bytes(&current, config.kernel, config.strict, qemu.as_mut())?;
    if !baseline
        .invariant
        .preserves(&baseline.spec.name, &final_sides, config.strict)
    {
        return Err(ReduceError::FinalCheckFailed {
            expected: label_of(&baseline, &final_sides),
            actual: side_summary(&final_sides),
        });
    }

    write_artifacts(
        dir, out_dir, &baseline, &original, &current, &timeline, &cache, config,
    )?;

    Ok(ReduceReport {
        name: baseline.spec.name.clone(),
        label: baseline.spec.label.clone(),
        original_insns: insn_count(&original),
        final_insns: insn_count(&current),
        timeline,
        checks: cache.checks,
        hits: cache.hits,
        budget: config.budget,
        final_mini: final_sides.mini.name().to_string(),
        final_kernel: final_sides.kernel.name().to_string(),
    })
}

/// Try one candidate: must differ from the current program, decode via
/// the fixup (implicit in the caller), and pass the oracle.
fn apply(
    current: &[u8],
    candidate: Vec<u8>,
    cache: &mut OracleCache,
    oracle: &mut impl FnMut(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    if candidate == current {
        return None;
    }
    match cache.check(&candidate, oracle) {
        Some(true) => Some(candidate),
        _ => None,
    }
}

fn read_prog(dir: &Path) -> Result<Vec<u8>, ReduceError> {
    let path = dir.join("prog.bin");
    fs::read(&path).map_err(|e| ReduceError::InvalidFinding(format!("{}: {e}", path.display())))
}

fn insn_count(bytes: &[u8]) -> usize {
    bytes.len() / 8
}

/// A human-readable label of the expected finding (for the final-check
/// error) — the classification name for oracle findings, the flip
/// direction for verdict flips.
fn label_of(baseline: &Baseline, sides: &Sides) -> String {
    match &baseline.invariant {
        crate::fuzz::reduce::replay::Invariant::Classification { finding, .. } => {
            finding.name().to_string()
        }
        crate::fuzz::reduce::replay::Invariant::VerdictFlip { .. } => {
            format!("verdict-flip {}", sides.mini.name())
        }
    }
}

fn side_summary(sides: &Sides) -> String {
    format!(
        "mini {} kernel {} concrete {:?}",
        sides.mini.name(),
        sides.kernel.name(),
        sides.concrete
    )
}

/// The reduced artifacts: prog.bin + prog.dump + reduce.json.
#[allow(clippy::too_many_arguments)]
fn write_artifacts(
    dir: &Path,
    out_dir: &Path,
    baseline: &Baseline,
    original: &[u8],
    reduced: &[u8],
    timeline: &[TimelineEntry],
    cache: &OracleCache,
    config: &ReduceConfig,
) -> Result<(), ReduceError> {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| baseline.spec.name.clone());
    let target = out_dir.join("reduced").join(&name);
    fs::create_dir_all(&target)
        .map_err(|e| ReduceError::Pipeline(format!("{}: {e}", target.display())))?;

    fs::write(target.join("prog.bin"), reduced)
        .map_err(|e| ReduceError::Pipeline(e.to_string()))?;

    let mut dump = String::new();
    for (idx, chunk) in reduced.as_chunks::<8>().0.iter().enumerate() {
        match parse_insn(chunk) {
            Ok(insn) => dump.push_str(&format!("{idx:4}: {insn:?}\n")),
            Err(e) => dump.push_str(&format!("{idx:4}: decode error: {e}\n")),
        }
    }
    fs::write(target.join("prog.dump"), dump).map_err(|e| ReduceError::Pipeline(e.to_string()))?;

    fs::write(
        target.join("reduce.json"),
        reduce_json(baseline, original, reduced, timeline, cache, config),
    )
    .map_err(|e| ReduceError::Pipeline(e.to_string()))?;
    Ok(())
}

/// The per-reduction reduce.json (hand-rolled, dependency-free).
fn reduce_json(
    baseline: &Baseline,
    original: &[u8],
    reduced: &[u8],
    timeline: &[TimelineEntry],
    cache: &OracleCache,
    config: &ReduceConfig,
) -> String {
    let mut s = String::from("{\n");
    s.push_str(&format!("  \"finding\": \"{}\",\n", baseline.spec.label));
    s.push_str(&format!(
        "  \"name\": \"{}\",\n",
        json_escape(&baseline.spec.name)
    ));
    s.push_str(&format!(
        "  \"original_insns\": {},\n",
        insn_count(original)
    ));
    s.push_str(&format!("  \"final_insns\": {},\n", insn_count(reduced)));
    s.push_str("  \"timeline\": [\n");
    for (i, (pass, count)) in timeline.iter().enumerate() {
        let comma = if i + 1 == timeline.len() { "" } else { "," };
        s.push_str(&format!(
            "    {{\"pass\": \"{pass}\", \"insns\": {count}}}{comma}\n"
        ));
    }
    s.push_str("  ],\n");
    s.push_str(&format!("  \"checks\": {},\n", cache.checks));
    s.push_str(&format!("  \"hits\": {},\n", cache.hits));
    s.push_str(&format!("  \"budget\": {},\n", config.budget));
    s.push_str(&format!("  \"strict\": {},\n", config.strict));
    s.push_str(
        "  \"determinism_note\": \"kernel outcomes are host-dependent; the rand-verifier side is deterministic\"\n",
    );
    s.push_str("}\n");
    s
}

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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::reduce::replay::ReduceError;
    use crate::testutil::{insn_bytes, prog_bytes};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A padded program whose failure is the uninit r4 read.
    fn padded(extra: usize) -> Vec<u8> {
        let mut insns: Vec<[u8; 8]> = Vec::new();
        for i in 0..extra {
            insns.push(insn_bytes(0xb7, 1, 0, 0, i as i32 + 1));
        }
        insns.push(insn_bytes(0x1f, 4, 0, 0, 0)); // r4 -= r0 (uninit)
        insns.push(insn_bytes(0xb7, 0, 0, 0, 1)); // r0 = 1
        insns.push(insn_bytes(0x95, 0, 0, 0, 0)); // exit
        prog_bytes(&insns)
    }

    fn make_finding(dir: &Path, meta: &str, bytes: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("prog.bin"), bytes).unwrap();
        std::fs::write(dir.join("meta.json"), meta).unwrap();
    }

    const FLIP_META: &str = r#"{
  "label": "verdict-flip",
  "name": "pad-1",
  "finding": "agree",
  "mini": "REJECT(UninitRead)",
  "kernel": "SKIPPED"
}"#;

    #[test]
    fn reduce_synthetic_finding_to_minimal() {
        let bytes = padded(20);
        let _guard = TempDir::new("rv-reduce-81-in");
        let dir = _guard.path().join("pad-1");
        make_finding(&dir, FLIP_META, &bytes);
        let out = TempDir::new("rv-reduce-81-out");
        let report = reduce_finding(
            &dir,
            out.path(),
            &ReduceConfig {
                budget: 0,
                kernel: false,
                strict: false,
                qemu_dir: None,
            },
        )
        .unwrap();

        // the padded 23-insn program collapses to the single failing
        // instruction (the verdict-flip invariant only demands REJECT)
        assert_eq!(report.final_insns, 1, "{:?}", report.timeline);
        assert_eq!(report.original_insns, 23);
        assert_eq!(report.final_mini, "REJECT");
        // timeline is monotonic non-increasing
        let counts: Vec<usize> = report.timeline.iter().map(|(_, c)| *c).collect();
        assert!(counts.windows(2).all(|w| w[0] >= w[1]), "{counts:?}");

        // artifacts written
        let target = out.path().join("reduced").join("pad-1");
        assert!(target.join("prog.bin").is_file());
        assert!(target.join("prog.dump").is_file());
        let json = std::fs::read_to_string(target.join("reduce.json")).unwrap();
        assert!(json.contains("\"final_insns\": 1"), "{json}");
        assert!(json.contains("\"checks\""));
    }

    #[test]
    fn reduce_rejects_kernel_dependent_findings_without_kernel() {
        let bytes = padded(5);
        let _guard = TempDir::new("rv-reduce-81-k");
        let dir = _guard.path().join("mseed-5-99");
        let meta = r#"{
  "label": "rv-precision-gap",
  "name": "mseed-5-99",
  "finding": "rv-precision-gap",
  "mini": "REJECT(StackBounds)",
  "kernel": "ACCEPT"
}"#;
        make_finding(&dir, meta, &bytes);
        let out = TempDir::new("rv-reduce-81-out");
        let err = reduce_finding(
            &dir,
            out.path(),
            &ReduceConfig {
                budget: 0,
                kernel: false,
                strict: false,
                qemu_dir: None,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ReduceError::KernelRequired(_)), "{err:?}");
    }

    #[test]
    fn reduce_deterministic() {
        let bytes = padded(12);
        let _guard_a = TempDir::new("rv-reduce-81-d");
        let _guard_b = TempDir::new("rv-reduce-81-d");
        let dir_a = _guard_a.path().join("pad-1");
        let dir_b = _guard_b.path().join("pad-1");
        make_finding(&dir_a, FLIP_META, &bytes);
        make_finding(&dir_b, FLIP_META, &bytes);
        let out_a = TempDir::new("rv-reduce-81-out");
        let out_b = TempDir::new("rv-reduce-81-out");
        let report_a = reduce_finding(
            &dir_a,
            out_a.path(),
            &ReduceConfig {
                budget: 0,
                kernel: false,
                strict: false,
                qemu_dir: None,
            },
        )
        .unwrap();
        let report_b = reduce_finding(
            &dir_b,
            out_b.path(),
            &ReduceConfig {
                budget: 0,
                kernel: false,
                strict: false,
                qemu_dir: None,
            },
        )
        .unwrap();
        assert_eq!(report_a.timeline, report_b.timeline);
        assert_eq!(report_a.checks, report_b.checks);
        let a = std::fs::read(out_a.path().join("reduced/pad-1/prog.bin")).unwrap();
        let b = std::fs::read(out_b.path().join("reduced/pad-1/prog.bin")).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn reduce_budget_returns_best_so_far() {
        let bytes = padded(30);
        let _guard = TempDir::new("rv-reduce-81-b");
        let dir = _guard.path().join("pad-1");
        make_finding(&dir, FLIP_META, &bytes);
        let out = TempDir::new("rv-reduce-81-out");
        let report = reduce_finding(
            &dir,
            out.path(),
            &ReduceConfig {
                budget: 3,
                kernel: false,
                strict: false,
                qemu_dir: None,
            },
        )
        .unwrap();
        // budget respected, final re-check still passes, and the
        // search stopped with a strictly smaller program
        assert_eq!(report.checks, 3);
        assert!(report.final_insns < report.original_insns);
        assert_eq!(report.final_mini, "REJECT");
    }
}
