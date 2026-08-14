// ── Fuzzer oracle: mini + concrete + kernel classification (v0.7, #68) ──────

//! Turns one program's three verdict sources into exactly one bucket of
//! the classification matrix (FUZZ_PLAN §3). Concrete is the truth
//! axis; mini additionally finds rand-verifier's own bugs; the kernel
//! side (when available) finds kernel precision/soundness candidates.
//! The v0.6 diff whitelist is reused, never forked.

use crate::concrete::{ConcreteReport, ConcreteVerdict};
use crate::diff::{SideVerdict, whitelisted};
use crate::env::BpfVerifierEnv;
use crate::klog::ReasonCategory;

/// The concrete side of one program — the oracle's truth axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcreteSide {
    /// The concrete run executed the program safely.
    Safe,
    /// The concrete run failed, or the abstract states failed to cover
    /// it (accepted programs).
    Unsafe,
    /// The concrete run hit an exploration budget — non-finding.
    Inconclusive,
}

/// Read the concrete side from a verification report.
pub(crate) fn concrete_side(report: &ConcreteReport) -> ConcreteSide {
    match report.verdict {
        ConcreteVerdict::Safe => ConcreteSide::Safe,
        ConcreteVerdict::Unsafe => ConcreteSide::Unsafe,
        ConcreteVerdict::Inconclusive => ConcreteSide::Inconclusive,
    }
}

/// The classification of one program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Finding {
    /// 🎯 Kernel REJECT + concrete SAFE (non-whitelisted) — the v0.7
    /// target: the kernel rejects a concretely safe program.
    PrecisionCandidate,
    /// 🚨 Kernel ACCEPT + concrete UNSAFE — the v1.0 target: the kernel
    /// accepts a concretely unsafe program. Saved separately.
    SoundnessCandidate,
    /// mini REJECT + kernel ACCEPT (concrete SAFE) — rand-verifier is
    /// more conservative than the kernel (our side).
    RvPrecisionGap,
    /// mini ACCEPT + concrete UNSAFE — a rand-verifier model bug. Must
    /// surface loudly (report channel), never silently.
    RvSoundnessBug,
    /// All sides agree — discard.
    Agree,
    /// A known design difference (diff whitelist, same-reason reject,
    /// strict-mode `!root` rules) — discard with a note.
    Whitelisted,
    /// Concrete inconclusive (loop budget) — non-finding.
    Inconclusive,
    /// The kernel side could not produce a verdict (privilege).
    Skipped,
}

impl Finding {
    pub fn name(&self) -> &'static str {
        match self {
            Finding::PrecisionCandidate => "precision-candidate",
            Finding::SoundnessCandidate => "soundness-candidate",
            Finding::RvPrecisionGap => "rv-precision-gap",
            Finding::RvSoundnessBug => "rv-soundness-bug",
            Finding::Agree => "agree",
            Finding::Whitelisted => "whitelisted",
            Finding::Inconclusive => "inconclusive",
            Finding::Skipped => "skipped",
        }
    }

    /// Whether this classification is a stored finding (vs discarded).
    pub fn is_finding(&self) -> bool {
        matches!(
            self,
            Finding::PrecisionCandidate
                | Finding::SoundnessCandidate
                | Finding::RvPrecisionGap
                | Finding::RvSoundnessBug
        )
    }
}

/// The three verdict sources plus the context needed for whitelisting.
pub struct OracleInput<'a> {
    /// Program name (corpus fixture stem or a fuzzer-generated id) —
    /// used by the name-based diff whitelist.
    pub name: &'a str,
    /// The rand-verifier side (`diff::mini_side`).
    pub mini: &'a SideVerdict,
    /// The mini failure message, when mini rejected — needed to
    /// distinguish uninit-stack from uninit-register rejects (the
    /// category alone is too coarse; privileged loads allow uninit
    /// stack reads by design, #73 empirical).
    pub mini_reason: Option<&'a str>,
    /// The concrete side.
    pub concrete: ConcreteSide,
    /// The kernel side (`diff::kernel_side`), `Skipped` when the kernel
    /// was not consulted (unprivileged runs).
    pub kernel: &'a SideVerdict,
    /// Strict mode: the kernel ran with unprivileged-equivalent rules
    /// (v0.6 `--strict`), so `!root` rejections (R10 pointer comparison
    /// prohibited, insn limits) are design behaviour, not findings.
    pub strict: bool,
}

/// Classify one program into exactly one [`Finding`]. The rules are
/// unambiguous (FUZZ_PLAN §3); precedence: model bugs > soundness >
/// precision > gaps > discard.
pub fn classify(input: &OracleInput) -> Finding {
    let OracleInput {
        name,
        mini,
        mini_reason,
        concrete,
        kernel,
        strict,
    } = input;
    match concrete {
        ConcreteSide::Inconclusive => Finding::Inconclusive,
        ConcreteSide::Unsafe => match mini {
            SideVerdict::Accept => Finding::RvSoundnessBug,
            SideVerdict::Reject { .. } => match kernel {
                // v0.6 kernel-accepts fixtures are design behaviour
                // (e.g. stack_write_before_read under privilege)
                SideVerdict::Accept => {
                    if whitelisted(name, mini, kernel, *mini_reason).is_some()
                        || crate::diff::privileged_stack_leniency(mini, *mini_reason)
                    {
                        Finding::Whitelisted
                    } else {
                        Finding::SoundnessCandidate
                    }
                }
                _ => Finding::Agree,
            },
            SideVerdict::Skipped => Finding::Agree,
        },
        ConcreteSide::Safe => match kernel {
            SideVerdict::Skipped => Finding::Skipped,
            SideVerdict::Accept => match mini {
                SideVerdict::Reject { .. } => {
                    if whitelisted(name, mini, kernel, *mini_reason).is_some() {
                        Finding::Whitelisted
                    } else {
                        Finding::RvPrecisionGap
                    }
                }
                _ => Finding::Agree,
            },
            SideVerdict::Reject { category } => {
                // name-based diff whitelist (kernel-accepts fixtures)
                if whitelisted(name, mini, kernel, *mini_reason).is_some() {
                    return Finding::Whitelisted;
                }
                // strict mode: unprivileged-equivalent kernel rules are
                // design behaviour (v0.6 --strict empirical run:
                // "R10 pointer comparison prohibited" → PointerArith,
                // insn limits → Complexity)
                if *strict
                    && matches!(
                        category,
                        ReasonCategory::PointerArith | ReasonCategory::Complexity
                    )
                {
                    return Finding::Whitelisted;
                }
                // both sides reject for the same reason — an intended
                // agreement, not a kernel precision candidate
                if let SideVerdict::Reject { category: mini_cat } = mini
                    && mini_cat == category
                {
                    return Finding::Whitelisted;
                }
                Finding::PrecisionCandidate
            }
        },
    }
}

/// Privileged loads allow uninit stack reads by design
/// Privileged-load stack leniency, shared with the diff whitelist
/// (#90): mini rejects uninitialized stack reads and indirect reads
/// over spilled pointers that the kernel accepts under privilege
/// (allow_uninit_stack / allow_ptr_leaks; CAP_SYS_ADMIN superset rule,
/// kernel/bpf/token.c). Applied by category so it covers fuzzer-
/// generated programs (found empirically as mseed-5-19 in the first
/// kernel-backed campaign, #73). Uninit *register* reads stay
/// soundness candidates — the kernel rejects those too.
pub use crate::diff::privileged_stack_leniency as is_privileged_uninit_stack;

/// Classify a verified program from its environment — the binary-
/// facing wrapper for the campaign runner (#69): reads the concrete
/// report produced by the last [`BpfVerifierEnv::verify`] call. A
/// program that failed at decode time has no concrete report — it is
/// treated as Inconclusive (a non-finding; both sides reject decode
/// errors anyway).
pub fn classify_env(
    env: &BpfVerifierEnv,
    name: &str,
    mini: &SideVerdict,
    mini_reason: Option<&str>,
    kernel: &SideVerdict,
    strict: bool,
) -> Finding {
    let concrete = env
        .concrete_report
        .as_ref()
        .map(concrete_side)
        .unwrap_or(ConcreteSide::Inconclusive);
    classify(&OracleInput {
        name,
        mini,
        mini_reason,
        concrete,
        kernel,
        strict,
    })
}

/// The first coverage-violation pc of the last verification, if any —
/// the concrete divergence point for triage (#70).
pub fn first_violation_pc(env: &BpfVerifierEnv) -> Option<u32> {
    env.concrete_report
        .as_ref()
        .and_then(|r| r.violations.first())
        .map(|v| v.pc)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::BpfVerifierEnv;
    use crate::error::Verdict;
    use crate::testutil::insn_bytes;

    fn acc() -> SideVerdict {
        SideVerdict::Accept
    }
    fn rej(c: ReasonCategory) -> SideVerdict {
        SideVerdict::Reject { category: c }
    }
    fn skip() -> SideVerdict {
        SideVerdict::Skipped
    }
    fn classify_with(
        mini: SideVerdict,
        concrete: ConcreteSide,
        kernel: SideVerdict,
        name: &str,
        strict: bool,
    ) -> Finding {
        classify(&OracleInput {
            name,
            mini: &mini,
            mini_reason: None,
            concrete,
            kernel: &kernel,
            strict,
        })
    }

    /// Every row of the classification matrix plus the precedence
    /// conflicts.
    #[test]
    fn classify_matrix_all_rows() {
        let u = ReasonCategory::UninitRead;
        let s = ReasonCategory::StackBounds;

        // agree: everything accepts
        assert_eq!(
            classify_with(acc(), ConcreteSide::Safe, acc(), "p", false),
            Finding::Agree
        );
        // agree: everything rejects (concrete also fails)
        assert_eq!(
            classify_with(rej(u), ConcreteSide::Unsafe, rej(u), "p", false),
            Finding::Agree
        );
        // rv precision gap: mini rejects what the kernel accepts
        assert_eq!(
            classify_with(rej(s), ConcreteSide::Safe, acc(), "p", false),
            Finding::RvPrecisionGap
        );
        // precision candidate: kernel rejects a concretely safe program
        // with a different reason than mini
        assert_eq!(
            classify_with(rej(u), ConcreteSide::Safe, rej(s), "p", false),
            Finding::PrecisionCandidate
        );
        // same-reason reject: intended agreement, not a finding
        assert_eq!(
            classify_with(rej(u), ConcreteSide::Safe, rej(u), "p", false),
            Finding::Whitelisted
        );
        // soundness candidate: kernel accepts a concretely unsafe program
        assert_eq!(
            classify_with(rej(u), ConcreteSide::Unsafe, acc(), "p", false),
            Finding::SoundnessCandidate
        );
        // rv soundness bug: mini accepts a concretely unsafe program
        assert_eq!(
            classify_with(acc(), ConcreteSide::Unsafe, rej(u), "p", false),
            Finding::RvSoundnessBug
        );
        assert_eq!(
            classify_with(acc(), ConcreteSide::Unsafe, acc(), "p", false),
            Finding::RvSoundnessBug
        );
        // inconclusive concrete → non-finding
        assert_eq!(
            classify_with(rej(u), ConcreteSide::Inconclusive, acc(), "p", false),
            Finding::Inconclusive
        );
        // kernel skipped (unprivileged run)
        assert_eq!(
            classify_with(acc(), ConcreteSide::Safe, skip(), "p", false),
            Finding::Skipped
        );
        // the model bug still surfaces without the kernel
        assert_eq!(
            classify_with(acc(), ConcreteSide::Unsafe, skip(), "p", false),
            Finding::RvSoundnessBug
        );
    }

    /// The diff whitelist (name-based) and the strict-mode `!root`
    /// rules never count as findings.
    #[test]
    fn whitelist_name_and_strict() {
        let u = ReasonCategory::UninitRead;
        // v0.6 kernel-accepts fixtures are whitelisted by name
        assert_eq!(
            classify_with(
                rej(ReasonCategory::Complexity),
                ConcreteSide::Safe,
                acc(),
                "complexity_limit",
                false
            ),
            Finding::Whitelisted
        );
        assert_eq!(
            classify_with(
                rej(u),
                ConcreteSide::Unsafe,
                acc(),
                "stack_write_before_read",
                false
            ),
            Finding::Whitelisted
        );
        // the same pair under a fuzzer-generated name is a finding
        assert_eq!(
            classify_with(
                rej(ReasonCategory::Complexity),
                ConcreteSide::Safe,
                acc(),
                "seed-1-3",
                false
            ),
            Finding::RvPrecisionGap
        );
        // strict mode whitelists the !root kernel rules even when mini
        // rejects for a different reason...
        assert_eq!(
            classify_with(
                rej(u),
                ConcreteSide::Safe,
                rej(ReasonCategory::PointerArith),
                "seed-1-3",
                true
            ),
            Finding::Whitelisted
        );
        // ...but they are precision candidates in the default mode
        assert_eq!(
            classify_with(
                rej(u),
                ConcreteSide::Safe,
                rej(ReasonCategory::PointerArith),
                "seed-1-3",
                false
            ),
            Finding::PrecisionCandidate
        );
    }

    /// Every corpus fixture classifies consistently with the v0.6
    /// privileged diff run (match / match-reject / kernel-accepts-
    /// whitelisted): no fixture produces a finding. The kernel verdict
    /// is injected from the v0.6 empirical table so the test runs
    /// unprivileged too.
    #[test]
    fn corpus_reproduction_v06() {
        // remaining kernel-accepts reject fixtures (the computed-offset
        // and pointer-arith fixtures moved to accept in #87)
        let kernel_accepts = ["complexity_limit", "stack_write_before_read"];
        for dir in ["tests/programs/accept", "tests/programs/reject"] {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if !path.is_file() || path.extension().is_some() {
                    continue;
                }
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                let bytes = std::fs::read(&path).unwrap();

                let mut env = BpfVerifierEnv::new();
                env.setup_prog_bytes(&bytes).unwrap();
                let verdict = env.verify().unwrap();
                let mini = match &verdict {
                    Verdict::Safe => acc(),
                    Verdict::Unsafe(failure) => rej(crate::diff::categorize_mini_reason(failure)),
                };
                let concrete = match env.concrete_report.as_ref() {
                    Some(report) => concrete_side(report),
                    // decode-error rejects have no concrete run
                    None => continue,
                };

                // kernel verdict from the v0.6 privileged run: all
                // accept fixtures accepted; the five kernel-accepts
                // reject fixtures accepted; the remaining reject
                // fixtures rejected (with mini's own category — the
                // v0.6 run compared reason categories separately)
                let kernel = if dir.ends_with("accept") || kernel_accepts.contains(&name.as_str()) {
                    acc()
                } else {
                    match &mini {
                        SideVerdict::Reject { category } => rej(*category),
                        _ => skip(),
                    }
                };

                let finding = classify(&OracleInput {
                    name: &name,
                    mini: &mini,
                    mini_reason: None,
                    concrete,
                    kernel: &kernel,
                    strict: false,
                });
                match dir {
                    "tests/programs/accept" => assert_eq!(finding, Finding::Agree, "{name}"),
                    _ => {
                        if kernel_accepts.contains(&name.as_str()) {
                            assert_eq!(finding, Finding::Whitelisted, "{name}");
                        } else {
                            assert!(!finding.is_finding(), "{name}: {finding:?}");
                        }
                    }
                }
            }
        }
    }

    /// The structured concrete verdict is set correctly by the
    /// pipeline: clean accept, reject-that-also-fails, reject-that-
    /// executes (precision candidate), and the inconclusive loop.
    #[test]
    fn concrete_side_detection() {
        // clean accept: mov r0, 42; exit
        let insns = [insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Safe));
        assert_eq!(
            concrete_side(env.concrete_report.as_ref().unwrap()),
            ConcreteSide::Safe
        );

        // reject that also fails concretely: r0 = 1; r0 += r2 (uninit); exit
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x0f, 0, 2, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        assert_eq!(
            concrete_side(env.concrete_report.as_ref().unwrap()),
            ConcreteSide::Unsafe
        );

        // reject that executes concretely (nano: unreachable insn)
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x05, 0, 0, 1, 0), // jmp +1
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        assert_eq!(
            concrete_side(env.concrete_report.as_ref().unwrap()),
            ConcreteSide::Safe
        );

        // inconclusive: never-converging loop
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x07, 0, 0, 0, 1),  // r0 += 1
            insn_bytes(0x05, 0, 0, -2, 0), // jmp -2
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        assert_eq!(
            concrete_side(env.concrete_report.as_ref().unwrap()),
            ConcreteSide::Inconclusive
        );
    }

    fn verify_bytes(insns: &[[u8; 8]]) -> (Verdict, BpfVerifierEnv) {
        let bytes: Vec<u8> = insns.iter().flatten().copied().collect();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes).unwrap();
        let verdict = env.verify().unwrap();
        (verdict, env)
    }

    /// The env-facing wrapper reads the pipeline's concrete report and
    /// classifies — the campaign runner's entry point (#69).
    #[test]
    fn classify_env_wrapper() {
        // clean accept + kernel skipped (unprivileged run)
        let insns = [insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Safe));
        let finding = classify_env(&env, "seed-0-0", &acc(), None, &skip(), false);
        assert_eq!(finding, Finding::Skipped);

        // reject-that-executes + kernel reject with a different reason
        // → precision candidate (the v0.7 target path)
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x05, 0, 0, 1, 0), // jmp +1
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let mini = rej(ReasonCategory::Unreachable);
        let kernel = rej(ReasonCategory::UninitRead);
        let finding = classify_env(&env, "seed-0-1", &mini, None, &kernel, false);
        assert_eq!(finding, Finding::PrecisionCandidate);

        // decode-error program: no concrete report → inconclusive
        // (non-finding; both sides reject decode errors anyway)
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0xef, 0, 0, 0, 0), // unknown opcode
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let finding = classify_env(
            &env,
            "seed-0-2",
            &rej(ReasonCategory::Other),
            None,
            &rej(ReasonCategory::Other),
            false,
        );
        assert_eq!(finding, Finding::Inconclusive);
    }

    /// The privileged uninit-stack design difference whitelists by
    /// category (empirical: mseed-5-19 in the first kernel-backed
    /// campaign, #73) — the fuzzer-side counterpart of the v0.6
    /// `stack_write_before_read` whitelist. Uninit *register* reads
    /// stay soundness candidates.
    #[test]
    fn whitelist_privileged_uninit_stack() {
        // r2 = 10; r0 = *(u64 *)(r10 - 8); exit — the mseed-5-19 shape
        let insns = [
            insn_bytes(0xb7, 2, 0, 0, 10),
            insn_bytes(0x79, 0, 10, -8, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_bytes(&insns);
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let mini = rej(ReasonCategory::UninitRead);

        // stack-slot uninit + kernel accept = privileged design
        // behaviour (allow_uninit_stack)
        let reason = "stack slot at offset -8 is uninitialized (write before read)";
        let finding = classify_env(&env, "mseed-5-19", &mini, Some(reason), &acc(), false);
        assert_eq!(finding, Finding::Whitelisted);

        // register uninit + kernel accept stays a soundness candidate
        // (the kernel rejects those — an accept would be a real bug)
        let reason = "register r2 is uninitialized";
        let finding = classify_env(&env, "mseed-x", &mini, Some(reason), &acc(), false);
        assert_eq!(finding, Finding::SoundnessCandidate);
    }
}
