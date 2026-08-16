// ── Failure reducer: finding replay and the reduction invariant (v0.8, #76) ─

//! The reducer consumes v0.7 findings. This module turns a saved finding
//! directory back into a reproducible classification and defines the
//! reduction invariant — the predicate every candidate program must
//! preserve. The oracle is the v0.7 classifier itself (`oracle::classify`):
//! a candidate that no longer exhibits the finding is rolled back.
//!
//! Two concepts:
//!
//! - **Replay** — re-derive the three verdict sides (mini + concrete +
//!   kernel) from the saved `prog.bin` and check them against the
//!   recorded `meta.json`. Replay is strict: a mismatch is reported
//!   loudly (stale finding / changed verifier / different host kernel),
//!   never silently accepted.
//! - **Invariant** — per-finding-class preservation predicate. The
//!   classification must stay the same; kernel-reject-based findings
//!   additionally keep the kernel reason category; verdict-flip findings
//!   keep the recorded flip direction (the program's own mini verdict).

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::diff::{SideVerdict, categorize_mini_reason, kernel_side};
use crate::env::BpfVerifierEnv;
use crate::error::Verdict;
use crate::fuzz::oracle::{ConcreteSide, Finding, OracleInput, classify, concrete_side};
use crate::klog::ReasonCategory;
use crate::krun::load_with_kernel;

/// Errors of the reduce pipeline — replay, invariant, and (later)
/// passes and the driver. Everything is a hard, reportable condition:
/// the reducer never silently accepts a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReduceError {
    /// The finding's classification depends on the kernel column, but
    /// the kernel side is unavailable (not requested, or the host
    /// cannot produce a kernel verdict — EPERM / no log line).
    KernelRequired(String),
    /// Replay mismatch: the re-derived sides differ from the recorded
    /// finding (verifier drift, tampered meta.json, host-dependent
    /// kernel outcome).
    ReplayMismatch { expected: String, actual: String },
    /// The mandatory final re-check failed: the reduced program no
    /// longer exhibits the finding — a reducer bug, always surfaced.
    FinalCheckFailed { expected: String, actual: String },
    /// The finding directory does not have the expected layout
    /// (missing prog.bin / meta.json, unparsable fields).
    InvalidFinding(String),
    /// The pipeline itself failed (I/O, decode-level load error).
    Pipeline(String),
}

impl std::fmt::Display for ReduceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReduceError::KernelRequired(msg) => write!(f, "kernel column required: {msg}"),
            ReduceError::ReplayMismatch { expected, actual } => {
                write!(
                    f,
                    "replay mismatch: expected {expected}, re-derived {actual}"
                )
            }
            ReduceError::FinalCheckFailed { expected, actual } => write!(
                f,
                "final re-check failed (reducer bug): expected {expected}, got {actual}"
            ),
            ReduceError::InvalidFinding(msg) => write!(f, "invalid finding: {msg}"),
            ReduceError::Pipeline(msg) => write!(f, "pipeline error: {msg}"),
        }
    }
}

impl std::error::Error for ReduceError {}

/// The recorded classification of one finding, parsed from `meta.json`
/// (the v0.7 fuzzer's hand-rolled JSON schema, #69).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSpec {
    /// The program name (fuzzer id or corpus stem).
    pub name: String,
    /// The classification label: a finding name or `"verdict-flip"`.
    pub label: String,
    /// The parsed oracle classification; `None` for verdict-flip
    /// entries (their meta.json `finding` field holds the *program's*
    /// oracle class, e.g. `agree` — not the flip).
    pub finding: Option<Finding>,
    /// The recorded rand-verifier side.
    pub mini: SideVerdict,
    /// The recorded kernel side.
    pub kernel: SideVerdict,
    /// The recorded spec side (#113): the independent safety spec's
    /// verdict, preserved through reduction.
    pub spec: crate::fuzz::oracle::SpecSide,
    /// Whether meta.json carried a "spec" field — old finding dirs
    /// (pre-#113) default to Inconclusive and are NOT re-checked.
    pub spec_recorded: bool,
}

/// The three verdict sides of one program, re-derived from the
/// pipeline — the shared input of the replay check and the reduction
/// oracle (the oracle consumed by ddmin/passes in #78/#79).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sides {
    pub mini: SideVerdict,
    /// The mini failure message — needed by the oracle's
    /// privileged-uninit-stack whitelisting (#73 empirical).
    pub mini_reason: Option<String>,
    pub concrete: ConcreteSide,
    pub kernel: SideVerdict,
    /// The spec side (#113): the independent safety spec's verdict on
    /// the program.
    pub spec: crate::fuzz::oracle::SpecSide,
}

/// The replay baseline: the recorded spec validated against the
/// re-derived sides of the original program, plus the invariant that
/// every candidate must preserve.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub spec: FindingSpec,
    pub sides: Sides,
    pub invariant: Invariant,
}

/// The reduction invariant: what a candidate program must preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invariant {
    /// The oracle classification must stay `finding`; when the kernel
    /// side rejects, its reason category must stay `kernel_category`
    /// too (a changed rejection reason means the root cause moved).
    Classification {
        finding: Finding,
        kernel_category: Option<ReasonCategory>,
    },
    /// A verdict-flip finding: the mini verdict must stay `after`
    /// (the recorded flip direction — the program's own verdict).
    VerdictFlip { after: &'static str },
}

impl Invariant {
    /// Whether candidate sides still exhibit the finding.
    pub fn preserves(&self, name: &str, sides: &Sides, strict: bool) -> bool {
        match self {
            Invariant::VerdictFlip { after } => sides.mini.name() == *after,
            Invariant::Classification {
                finding,
                kernel_category,
            } => {
                let candidate = classify(&OracleInput {
                    name,
                    mini: &sides.mini,
                    mini_reason: sides.mini_reason.as_deref(),
                    concrete: sides.concrete,
                    kernel: &sides.kernel,
                    kernel_reason: None,
                    strict,
                    spec: sides.spec,
                });
                if candidate != *finding {
                    return false;
                }
                if let Some(expected) = kernel_category {
                    return matches!(
                        &sides.kernel,
                        SideVerdict::Reject { category } if category == expected
                    );
                }
                true
            }
        }
    }
}

/// Whether the finding's classification depends on the kernel column.
/// Kernel-independent findings (rv-soundness-bug, verdict flips) reduce
/// unprivileged with mini + concrete only.
pub fn is_kernel_dependent(label: &str) -> bool {
    matches!(
        label,
        "precision-candidate"
            | "soundness-candidate"
            | "rv-precision-gap"
            | "kernel-unsound-candidate"
            | "kernel-overstrict-candidate"
            | "whitelisted"
    )
}

/// Load a finding directory: `meta.json` (recorded classification) and
/// `prog.bin` (replayable bytes). Both must exist; the schema is the
/// v0.7 fuzzer's hand-rolled JSON (no serde — dependency-free, §8 of
/// the v0.7 plan).
pub fn load_finding(dir: &Path) -> Result<(FindingSpec, Vec<u8>), ReduceError> {
    let meta_path = dir.join("meta.json");
    let text = fs::read_to_string(&meta_path)
        .map_err(|e| ReduceError::InvalidFinding(format!("{}: {e}", meta_path.display())))?;

    let name = meta_value(&text, "name")
        .ok_or_else(|| ReduceError::InvalidFinding("meta.json: missing \"name\"".into()))?;
    let label = meta_value(&text, "label")
        .ok_or_else(|| ReduceError::InvalidFinding("meta.json: missing \"label\"".into()))?;
    let mini = parse_side(
        &meta_value(&text, "mini")
            .ok_or_else(|| ReduceError::InvalidFinding("meta.json: missing \"mini\"".into()))?,
    )
    .ok_or_else(|| ReduceError::InvalidFinding("meta.json: unparsable \"mini\"".into()))?;
    let kernel = parse_side(
        &meta_value(&text, "kernel")
            .ok_or_else(|| ReduceError::InvalidFinding("meta.json: missing \"kernel\"".into()))?,
    )
    .ok_or_else(|| ReduceError::InvalidFinding("meta.json: unparsable \"kernel\"".into()))?;
    let spec_raw = meta_value(&text, "spec");
    let spec = parse_spec_side(spec_raw.as_deref());
    let spec_recorded = spec_raw.is_some();

    let finding = if is_kernel_dependent(&label) || label == "rv-soundness-bug" {
        Some(parse_finding(&label).ok_or_else(|| {
            ReduceError::InvalidFinding(format!("meta.json: unknown finding label {label:?}"))
        })?)
    } else {
        None
    };

    let prog = dir.join("prog.bin");
    let bytes = fs::read(&prog)
        .map_err(|e| ReduceError::InvalidFinding(format!("{}: {e}", prog.display())))?;
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(ReduceError::InvalidFinding(format!(
            "{}: not a multiple-of-8 instruction stream",
            prog.display()
        )));
    }

    Ok((
        FindingSpec {
            name,
            label,
            finding,
            mini,
            kernel,
            spec,
            spec_recorded,
        },
        bytes,
    ))
}

/// Run one program through the pipeline and collect the three sides.
/// `kernel: false` skips the kernel column (`Skipped`). When the kernel
/// was requested but the host cannot produce a verdict (EPERM, no log
/// line), the program cannot be classified — an error, never a silent
/// `Skipped` (the reducer must not reduce blind).
/// Unique job names for qemu queries: the guest writes one out file
/// per name, so every evaluation gets a fresh name.
static QEMU_SEQ: AtomicU64 = AtomicU64::new(0);

fn qemu_name() -> String {
    format!("rv-{}", QEMU_SEQ.fetch_add(1, Ordering::Relaxed))
}

pub fn evaluate_bytes(
    bytes: &[u8],
    kernel: bool,
    _strict: bool,
    qemu: Option<&mut crate::fuzz::qemu::QemuBatch>,
) -> Result<Sides, ReduceError> {
    let mut env = BpfVerifierEnv::new();
    env.setup_prog_bytes(bytes)
        .map_err(|e| ReduceError::Pipeline(e.to_string()))?;
    let verdict = env
        .verify()
        .map_err(|e| ReduceError::Pipeline(e.to_string()))?;
    let (mini, mini_reason) = match verdict {
        Verdict::Safe => (SideVerdict::Accept, None),
        Verdict::Unsafe(failure) => (
            SideVerdict::Reject {
                category: categorize_mini_reason(&failure),
            },
            Some(failure.message),
        ),
    };
    let concrete = env
        .concrete_report
        .as_ref()
        .map(concrete_side)
        .unwrap_or(ConcreteSide::Inconclusive);
    let kernel = if kernel {
        match qemu {
            Some(q) => {
                q.ask(&qemu_name(), bytes)
                    .map_err(|e| ReduceError::KernelRequired(format!("qemu verdict failed: {e}")))?
                    .0
            }
            None => {
                let outcome = load_with_kernel(bytes);
                match kernel_side(&outcome) {
                    SideVerdict::Skipped => {
                        return Err(ReduceError::KernelRequired(format!(
                            "kernel load produced no verdict ({})",
                            kernel_skip_reason(&outcome)
                        )));
                    }
                    side => side,
                }
            }
        }
    } else {
        SideVerdict::Skipped
    };
    let spec =
        crate::fuzz::oracle::spec_side(&crate::spec::verify_spec(env.program_insns(), &env.maps));
    Ok(Sides {
        mini,
        mini_reason,
        concrete,
        kernel,
        spec,
    })
}

/// Why the kernel side was skipped — guidance for the KernelRequired
/// error (the `KernelOutcome` debug is not part of the public API here).
fn kernel_skip_reason(outcome: &crate::krun::KernelOutcome) -> &'static str {
    match outcome {
        crate::krun::KernelOutcome::Privilege => "EPERM — need root / CAP_BPF (sudo or CI runner)",
        crate::krun::KernelOutcome::NoErrorLine { .. } => "errno without a log line",
        crate::krun::KernelOutcome::InvalidProgram => "invalid program",
        crate::krun::KernelOutcome::Accept | crate::krun::KernelOutcome::Reject { .. } => {
            unreachable!("kernel_side mapped Accept/Reject to a verdict")
        }
    }
}

/// Replay validation: the re-derived sides must reproduce the recorded
/// finding. Kernel-dependent findings require a kernel verdict.
/// Strict by design — a mismatch is a hard error, never a warning.
pub fn replay_check(spec: &FindingSpec, sides: &Sides, strict: bool) -> Result<(), ReduceError> {
    if is_kernel_dependent(&spec.label) && matches!(sides.kernel, SideVerdict::Skipped) {
        return Err(ReduceError::KernelRequired(format!(
            "{} depends on the kernel column — run the reducer with --kernel (privileged)",
            spec.label
        )));
    }
    if sides.mini != spec.mini {
        return Err(ReduceError::ReplayMismatch {
            expected: side_str(&spec.mini),
            actual: side_str(&sides.mini),
        });
    }
    // the spec verdict (#113) is re-derived too — a recorded spec
    // side that no longer reproduces is stale (changed verifier /
    // changed spec surface). Old finding dirs without the field are
    // not re-checked.
    if spec.spec_recorded && sides.spec != spec.spec {
        return Err(ReduceError::ReplayMismatch {
            expected: format!("spec {:?}", spec.spec),
            actual: format!("spec {:?}", sides.spec),
        });
    }
    // verdict-flip: the mini verdict IS the flip direction — equality
    // was checked above; classification findings additionally re-derive
    // the oracle class (covers kernel drift: a recorded precision
    // candidate whose kernel now accepts re-classifies and fails here)
    if let Some(finding) = spec.finding {
        let actual = classify(&OracleInput {
            name: &spec.name,
            mini: &sides.mini,
            mini_reason: sides.mini_reason.as_deref(),
            concrete: sides.concrete,
            kernel: &sides.kernel,
            kernel_reason: None,
            strict,
            spec: sides.spec,
        });
        if actual != finding {
            return Err(ReduceError::ReplayMismatch {
                expected: finding.name().to_string(),
                actual: actual.name().to_string(),
            });
        }
    }
    Ok(())
}

/// Build the invariant for a loaded finding spec.
pub fn invariant_for(spec: &FindingSpec) -> Result<Invariant, ReduceError> {
    match spec.label.as_str() {
        "verdict-flip" => match spec.mini.name() {
            "ACCEPT" | "REJECT" => Ok(Invariant::VerdictFlip {
                after: spec.mini.name(),
            }),
            _ => Err(ReduceError::InvalidFinding(
                "verdict-flip without a mini verdict".into(),
            )),
        },
        label => {
            let finding = parse_finding(label).ok_or_else(|| {
                ReduceError::InvalidFinding(format!("unknown finding label {label:?}"))
            })?;
            let kernel_category = match &spec.kernel {
                SideVerdict::Reject { category } => Some(*category),
                _ => None,
            };
            Ok(Invariant::Classification {
                finding,
                kernel_category,
            })
        }
    }
}

/// Load a finding directory and validate it against the pipeline: the
/// baseline every reduction starts from. `kernel` must be true for
/// kernel-dependent findings (enforced here).
pub fn load_and_replay(
    dir: &Path,
    kernel: bool,
    strict: bool,
    qemu: Option<&mut crate::fuzz::qemu::QemuBatch>,
) -> Result<Baseline, ReduceError> {
    let (spec, bytes) = load_finding(dir)?;
    let sides = evaluate_bytes(&bytes, kernel, strict, qemu)?;
    replay_check(&spec, &sides, strict)?;
    let invariant = invariant_for(&spec)?;
    Ok(Baseline {
        spec,
        sides,
        invariant,
    })
}

// ── meta.json parsing (hand-rolled, dependency-free) ────────────────────────

/// Extract the string value of `"key": "value"` from the fuzzer's
/// hand-rolled JSON. Returns `None` when the key is absent or malformed.
fn meta_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut rest = text;
    while let Some(pos) = rest.find(&needle) {
        let after = rest[pos + needle.len()..].trim_start();
        if let Some(after) = after.strip_prefix(':') {
            let after = after.trim_start();
            if let Some(after) = after.strip_prefix('"') {
                return after.find('"').map(|end| after[..end].to_string());
            }
            return None;
        }
        rest = &rest[pos + needle.len()..];
    }
    None
}

/// Parse the compact side encoding of meta.json: `ACCEPT`, `SKIPPED`,
/// or `REJECT(CategoryName)`.
fn parse_spec_side(s: Option<&str>) -> crate::fuzz::oracle::SpecSide {
    match s {
        Some("ACCEPT") => crate::fuzz::oracle::SpecSide::Accept,
        Some("REJECT") => crate::fuzz::oracle::SpecSide::Reject,
        _ => crate::fuzz::oracle::SpecSide::Inconclusive,
    }
}

fn parse_side(s: &str) -> Option<SideVerdict> {
    match s {
        "ACCEPT" => Some(SideVerdict::Accept),
        "SKIPPED" => Some(SideVerdict::Skipped),
        s if s.starts_with("REJECT(") && s.ends_with(')') => {
            parse_category(&s[7..s.len() - 1]).map(|category| SideVerdict::Reject { category })
        }
        _ => None,
    }
}

/// Parse a `ReasonCategory` from its debug name (the meta.json form).
fn parse_category(s: &str) -> Option<ReasonCategory> {
    use ReasonCategory::*;
    match s {
        "UninitRead" => Some(UninitRead),
        "StackBounds" => Some(StackBounds),
        "StackAlign" => Some(StackAlign),
        "PointerArith" => Some(PointerArith),
        "HelperArgs" => Some(HelperArgs),
        "CfgJump" => Some(CfgJump),
        "Loop" => Some(Loop),
        "Unreachable" => Some(Unreachable),
        "ExitR0" => Some(ExitR0),
        "Complexity" => Some(Complexity),
        "Other" => Some(Other),
        _ => None,
    }
}

/// Parse a finding label into the oracle classification.
fn parse_finding(label: &str) -> Option<Finding> {
    [
        Finding::PrecisionCandidate,
        Finding::KernelUnsoundCandidate,
        Finding::KernelOverstrictCandidate,
        Finding::SoundnessCandidate,
        Finding::RvPrecisionGap,
        Finding::RvSoundnessBug,
        Finding::Agree,
        Finding::Whitelisted,
        Finding::Inconclusive,
        Finding::Skipped,
    ]
    .into_iter()
    .find(|f| f.name() == label)
}

/// The compact side encoding, for error messages and reports.
fn side_str(side: &SideVerdict) -> String {
    match side {
        SideVerdict::Accept => "ACCEPT".to_string(),
        SideVerdict::Skipped => "SKIPPED".to_string(),
        SideVerdict::Reject { category } => format!("REJECT({:?})", category),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{insn_bytes, prog_bytes};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A minimal self-cleaning temp directory (no external deps — the
    /// project keeps the dependency list at {anyhow, libc}).
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

    // the recorded meta.json of a real v0.7 verdict-flip finding
    // (fuzz-out/findings/verdict-flip-mseed-5-3)
    const FLIP_META: &str = r#"{
  "label": "verdict-flip",
  "name": "mseed-5-3",
  "finding": "agree",
  "mini": "REJECT(UninitRead)",
  "kernel": "REJECT(UninitRead)"
}"#;

    fn reject(category: ReasonCategory) -> SideVerdict {
        SideVerdict::Reject { category }
    }

    fn sides_of(mini: SideVerdict, concrete: ConcreteSide, kernel: SideVerdict) -> Sides {
        Sides {
            mini,
            mini_reason: None,
            concrete,
            kernel,
            spec: crate::fuzz::oracle::SpecSide::Inconclusive,
        }
    }

    // ── meta.json parsing ───────────────────────────────────────────────────

    #[test]
    fn meta_value_extracts_keys() {
        assert_eq!(meta_value(FLIP_META, "label"), Some("verdict-flip".into()));
        assert_eq!(meta_value(FLIP_META, "name"), Some("mseed-5-3".into()));
        assert_eq!(meta_value(FLIP_META, "finding"), Some("agree".into()));
        assert_eq!(
            meta_value(FLIP_META, "mini"),
            Some("REJECT(UninitRead)".into())
        );
        assert_eq!(
            meta_value(FLIP_META, "kernel"),
            Some("REJECT(UninitRead)".into())
        );
        assert_eq!(meta_value(FLIP_META, "missing"), None);
    }

    #[test]
    fn parse_spec_side_strings() {
        use crate::fuzz::oracle::SpecSide;
        assert_eq!(parse_spec_side(Some("ACCEPT")), SpecSide::Accept);
        assert_eq!(parse_spec_side(Some("REJECT")), SpecSide::Reject);
        assert_eq!(
            parse_spec_side(Some("INCONCLUSIVE")),
            SpecSide::Inconclusive
        );
        // old finding dirs (no "spec" key) default to Inconclusive —
        // the classic three-axis semantics
        assert_eq!(parse_spec_side(None), SpecSide::Inconclusive);
        assert_eq!(parse_spec_side(Some("bogus")), SpecSide::Inconclusive);
    }

    /// The spec-backed classes reduce with the spec verdict preserved:
    /// a kernel-unsound candidate whose spec verdict flips to Accept
    /// during reduction must not silently change class.
    #[test]
    fn invariant_preserves_spec_verdict() {
        use crate::fuzz::oracle::{Finding, SpecSide};
        use crate::klog::ReasonCategory;
        let u = ReasonCategory::UninitRead;
        let spec = FindingSpec {
            name: "seed-1".into(),
            label: "kernel-unsound-candidate".into(),
            finding: Some(Finding::KernelUnsoundCandidate),
            mini: SideVerdict::Reject { category: u },
            kernel: SideVerdict::Accept,
            spec: SpecSide::Reject,
            spec_recorded: true,
        };
        let invariant = Invariant::Classification {
            finding: Finding::KernelUnsoundCandidate,
            kernel_category: None,
        };
        // the original sides preserve the class
        let sides = Sides {
            mini: SideVerdict::Reject { category: u },
            mini_reason: None,
            concrete: ConcreteSide::Safe,
            kernel: SideVerdict::Accept,
            spec: SpecSide::Reject,
        };
        assert!(invariant.preserves(&spec.name, &sides, false));
        // a reduction that flips the spec verdict to Accept changes the
        // classification (kernel-unsound needs spec REJECT) — the
        // invariant must reject the candidate
        let flipped = Sides {
            spec: SpecSide::Accept,
            ..sides.clone()
        };
        assert!(!invariant.preserves(&spec.name, &flipped, false));
        // the kernel column is mandatory for these classes
        assert!(is_kernel_dependent("kernel-unsound-candidate"));
        assert!(is_kernel_dependent("kernel-overstrict-candidate"));
    }

    #[test]
    fn parse_side_strings() {
        assert_eq!(parse_side("ACCEPT"), Some(SideVerdict::Accept));
        assert_eq!(parse_side("SKIPPED"), Some(SideVerdict::Skipped));
        assert_eq!(
            parse_side("REJECT(StackBounds)"),
            Some(reject(ReasonCategory::StackBounds))
        );
        assert_eq!(
            parse_side("REJECT(UninitRead)"),
            Some(reject(ReasonCategory::UninitRead))
        );
        assert_eq!(parse_side("REJECT(Unknown)"), None);
        assert_eq!(parse_side("REJECT"), None);
        assert_eq!(parse_side(""), None);
    }

    #[test]
    fn parse_finding_labels() {
        assert_eq!(
            parse_finding("precision-candidate"),
            Some(Finding::PrecisionCandidate)
        );
        assert_eq!(
            parse_finding("rv-precision-gap"),
            Some(Finding::RvPrecisionGap)
        );
        assert_eq!(parse_finding("verdict-flip"), None);
        assert_eq!(parse_finding("nonsense"), None);
    }

    // ── kernel dependency ───────────────────────────────────────────────────

    #[test]
    fn kernel_dependency_per_class() {
        assert!(is_kernel_dependent("precision-candidate"));
        assert!(is_kernel_dependent("soundness-candidate"));
        assert!(is_kernel_dependent("rv-precision-gap"));
        assert!(is_kernel_dependent("kernel-unsound-candidate"));
        assert!(is_kernel_dependent("kernel-overstrict-candidate"));
        assert!(is_kernel_dependent("whitelisted"));
        assert!(!is_kernel_dependent("rv-soundness-bug"));
        assert!(!is_kernel_dependent("verdict-flip"));
        assert!(!is_kernel_dependent("agree"));
    }

    // ── invariant preserves ─────────────────────────────────────────────────

    #[test]
    fn invariant_classification_passes_and_fails() {
        let inv = Invariant::Classification {
            finding: Finding::PrecisionCandidate,
            kernel_category: Some(ReasonCategory::StackBounds),
        };
        // the same finding (mini accepts, kernel rejects) passes
        assert!(inv.preserves(
            "seed-0-1",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Safe,
                reject(ReasonCategory::StackBounds)
            ),
            false
        ));
        // a changed kernel category fails — the root cause moved
        assert!(!inv.preserves(
            "seed-0-1",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Safe,
                reject(ReasonCategory::PointerArith)
            ),
            false
        ));
        // kernel now accepts — the finding is gone
        assert!(!inv.preserves(
            "seed-0-1",
            &sides_of(SideVerdict::Accept, ConcreteSide::Safe, SideVerdict::Accept),
            false
        ));
        // concrete now unsafe — no longer a precision candidate
        assert!(!inv.preserves(
            "seed-0-1",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Unsafe,
                reject(ReasonCategory::StackBounds)
            ),
            false
        ));
        // kernel skipped (unprivileged) — the reducer must not reduce blind
        assert!(!inv.preserves(
            "seed-0-1",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Safe,
                SideVerdict::Skipped
            ),
            false
        ));
    }

    #[test]
    fn invariant_rv_gap_and_soundness_bug() {
        // rv-precision-gap: mini REJECT + kernel ACCEPT, concrete SAFE
        let inv = Invariant::Classification {
            finding: Finding::RvPrecisionGap,
            kernel_category: None,
        };
        assert!(inv.preserves(
            "mseed-5-99",
            &sides_of(
                reject(ReasonCategory::StackBounds),
                ConcreteSide::Safe,
                SideVerdict::Accept
            ),
            false
        ));
        // kernel REJECT now — re-classifies to precision candidate
        assert!(!inv.preserves(
            "mseed-5-99",
            &sides_of(
                reject(ReasonCategory::StackBounds),
                ConcreteSide::Safe,
                reject(ReasonCategory::UninitRead)
            ),
            false
        ));
        // rv-soundness-bug: kernel column irrelevant
        let inv = Invariant::Classification {
            finding: Finding::RvSoundnessBug,
            kernel_category: None,
        };
        assert!(inv.preserves(
            "seed-0-0",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Unsafe,
                SideVerdict::Skipped
            ),
            false
        ));
        // mini now rejects too — the model bug is gone
        assert!(!inv.preserves(
            "seed-0-0",
            &sides_of(
                reject(ReasonCategory::UninitRead),
                ConcreteSide::Unsafe,
                SideVerdict::Skipped
            ),
            false
        ));
    }

    #[test]
    fn invariant_verdict_flip() {
        let inv = Invariant::VerdictFlip { after: "REJECT" };
        // the flip direction preserved
        assert!(inv.preserves(
            "mseed-5-3",
            &sides_of(
                reject(ReasonCategory::UninitRead),
                ConcreteSide::Unsafe,
                SideVerdict::Skipped
            ),
            false
        ));
        // flipped back — the finding is gone
        assert!(!inv.preserves(
            "mseed-5-3",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Safe,
                SideVerdict::Skipped
            ),
            false
        ));
    }

    #[test]
    fn invariant_strict_mode_whitelists() {
        // strict mode: the `!root` kernel rules (PointerArith,
        // Complexity) are design behaviour, not findings
        let inv = Invariant::Classification {
            finding: Finding::Whitelisted,
            kernel_category: None,
        };
        assert!(inv.preserves(
            "seed-1-3",
            &sides_of(
                reject(ReasonCategory::UninitRead),
                ConcreteSide::Safe,
                reject(ReasonCategory::PointerArith)
            ),
            true
        ));
        // default mode: a mini-accepting precision candidate is NOT
        // whitelisted (the strict `!root` rules only apply in strict)
        assert!(!inv.preserves(
            "seed-1-3",
            &sides_of(
                SideVerdict::Accept,
                ConcreteSide::Safe,
                reject(ReasonCategory::PointerArith)
            ),
            false
        ));
    }

    // ── replay (real programs) ──────────────────────────────────────────────

    /// Build a finding dir in a temp location: prog.bin + meta.json.
    fn temp_finding(meta: &str, insns: &[[u8; 8]]) -> (std::path::PathBuf, TempDir) {
        let dir = TempDir::new("rv-reduce-76");
        std::fs::write(dir.path().join("prog.bin"), prog_bytes(insns)).unwrap();
        std::fs::write(dir.path().join("meta.json"), meta).unwrap();
        (dir.path().to_path_buf(), dir)
    }

    #[test]
    fn replay_verdict_flip_unprivileged() {
        // the mseed-5-3 shape: r4 is uninitialized at the SubReg (mini
        // REJECT(UninitRead)) — replay must reproduce the flip verdict
        let insns = [
            insn_bytes(0xb7, 1, 0, 0, 5), // r1 = 5
            insn_bytes(0xb7, 2, 0, 0, 7), // r2 = 7
            insn_bytes(0x5d, 1, 2, 2, 0), // if r1 != r2 goto +2
            insn_bytes(0xb7, 0, 0, 0, 0), // r0 = 0
            insn_bytes(0x95, 0, 0, 0, 0), // exit
            insn_bytes(0x1f, 4, 0, 0, 0), // r4 -= r0  ← uninit r4
            insn_bytes(0xb7, 0, 0, 0, 1), // r0 = 1
            insn_bytes(0x95, 0, 0, 0, 0), // exit
        ];
        let (dir, _guard) = temp_finding(FLIP_META, &insns);
        let baseline = load_and_replay(&dir, false, false, None).unwrap();
        assert_eq!(baseline.spec.label, "verdict-flip");
        assert_eq!(baseline.spec.finding, None);
        assert_eq!(baseline.sides.mini.name(), "REJECT");
        assert!(
            baseline
                .invariant
                .preserves(&baseline.spec.name, &baseline.sides, false)
        );
    }

    #[test]
    fn replay_kernel_dependent_without_kernel_refused() {
        // a kernel-dependent finding (rv-precision-gap) cannot be
        // replayed unprivileged — the reducer must refuse, not guess
        let meta = r#"{
  "label": "rv-precision-gap",
  "name": "mseed-5-99",
  "finding": "rv-precision-gap",
  "mini": "REJECT(StackBounds)",
  "kernel": "ACCEPT"
}"#;
        // the mseed-5-99 shape: pointer arithmetic that mini rejects at
        // arithmetic time (StackBounds) — the exact program is not
        // needed for the refusal path
        let insns = [
            insn_bytes(0xb7, 6, 0, 0, 8), // r6 = 8
            insn_bytes(0xb7, 1, 0, 0, 1), // r1 = 1
            insn_bytes(0x0f, 1, 6, 0, 0), // r1 += r6  (pointer-ish arith)
            insn_bytes(0xb7, 0, 0, 0, 0), // r0 = 0
            insn_bytes(0x95, 0, 0, 0, 0), // exit
        ];
        let (dir, _guard) = temp_finding(meta, &insns);
        let err = load_and_replay(&dir, false, false, None).unwrap_err();
        assert!(matches!(err, ReduceError::KernelRequired(_)), "{err:?}");
    }

    #[test]
    fn replay_mismatch_is_loud() {
        // tampered meta.json: the recorded mini side is ACCEPT, but the
        // program rejects — replay must fail loudly
        let meta = r#"{
  "label": "verdict-flip",
  "name": "mseed-5-x",
  "finding": "agree",
  "mini": "ACCEPT",
  "kernel": "SKIPPED"
}"#;
        let insns = [
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x1f, 4, 0, 0, 0), // r4 -= r0 — uninit r4
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (dir, _guard) = temp_finding(meta, &insns);
        let err = load_and_replay(&dir, false, false, None).unwrap_err();
        assert!(
            matches!(
                err,
                ReduceError::ReplayMismatch {
                    ref expected,
                    ref actual
                } if expected == "ACCEPT" && actual == "REJECT(UninitRead)"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn load_finding_rejects_bad_layout() {
        // missing meta.json
        let dir = TempDir::new("rv-reduce-76-empty");
        let err = load_finding(dir.path()).unwrap_err();
        assert!(matches!(err, ReduceError::InvalidFinding(_)), "{err:?}");
        // malformed side encoding
        let meta =
            r#"{"label": "verdict-flip", "name": "x", "mini": "REJECT(Nope)", "kernel": "ACCEPT"}"#;
        let (dir, _guard) = temp_finding(
            meta,
            &[insn_bytes(0xb7, 0, 0, 0, 1), insn_bytes(0x95, 0, 0, 0, 0)],
        );
        let err = load_finding(&dir).unwrap_err();
        assert!(matches!(err, ReduceError::InvalidFinding(_)), "{err:?}");
    }
}
