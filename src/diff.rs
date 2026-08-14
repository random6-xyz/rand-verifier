// ── Differential comparison: rand-verifier vs the kernel (issue #60) ────────

use crate::error::VerificationFailure;
use crate::klog::ReasonCategory;
use crate::krun::KernelOutcome;

/// Map a rand-verifier failure message to the shared reason category,
/// so the diff harness can compare the reasons of the two verifiers on
/// the same program. The patterns are the actual `VerificationFailure`
/// messages of the mini pass; decode-level rejections (unknown opcode,
/// reserved fields, invalid register) map to `Other`, like their kernel
/// counterparts.
pub fn categorize_mini_reason(failure: &VerificationFailure) -> ReasonCategory {
    let msg = &failure.message;
    if msg.contains("unreachable instruction") {
        ReasonCategory::Unreachable
    } else if msg.contains("crosses subprogram boundary")
        || msg.contains("falls through out of subprogram")
        || msg.contains("does not end with exit")
        || msg.contains("pc out of program range")
    {
        ReasonCategory::CfgJump
    } else if msg.contains("uninitialized") {
        // "register rN is uninitialized", "stack slot ... is uninitialized",
        // "r0 is uninitialized at exit" — the kernel says "R0 !read_ok"
        ReasonCategory::UninitRead
    } else if msg.contains("aligned") {
        // "stack access ... is not 8-byte aligned",
        // "stack pointer ... alignment is not provable"
        ReasonCategory::StackAlign
    } else if msg.contains("arithmetic")
        || msg.contains("invalid comparison")
        || msg.contains("comparing pointers")
        || msg.contains("non-stack pointer")
        || msg.contains("through a scalar")
    {
        // "... pointer arithmetic ...", "stack access through a
        // non-stack pointer / a scalar ..." — the kernel says
        // "invalid mem access"
        ReasonCategory::PointerArith
    } else if msg.contains("indirect read") {
        // "invalid indirect read from stack ... spilled ..." — the
        // kernel rejects variable-offset reads over spilled registers
        ReasonCategory::UninitRead
    } else if msg.contains("stack access") || msg.contains("stack pointer") {
        // "stack access at r10 ... exceeds/points away",
        // "stack access at r6+0 with base offsets ...",
        // "stack pointer ... may leave/are out of the frame"
        ReasonCategory::StackBounds
    } else if msg.contains("helper") || msg.contains("expected") {
        ReasonCategory::HelperArgs
    } else if msg.contains("back-edge") || msg.contains("complexity limit") {
        // mini's loop budget is its complexity mechanism — the kernel
        // rejects non-converging loops with "BPF program is too large"
        ReasonCategory::Complexity
    } else {
        // decode rejections ("unknown opcode", "reserved fields",
        // "invalid register"), shift-amount errors, ...
        ReasonCategory::Other
    }
}

/// The verdict of one side (rand-verifier or the kernel) on one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideVerdict {
    Accept,
    Reject {
        category: ReasonCategory,
    },
    /// The side could not produce a verdict (privilege, invalid input).
    Skipped,
}

impl SideVerdict {
    pub fn name(&self) -> &'static str {
        match self {
            SideVerdict::Accept => "ACCEPT",
            SideVerdict::Reject { .. } => "REJECT",
            SideVerdict::Skipped => "SKIPPED",
        }
    }
}

/// The rand-verifier side of one program: `None` for an accepted
/// program.
pub fn mini_side(failure: Option<&VerificationFailure>) -> SideVerdict {
    match failure {
        None => SideVerdict::Accept,
        Some(failure) => SideVerdict::Reject {
            category: categorize_mini_reason(failure),
        },
    }
}

/// The kernel side of one program.
pub fn kernel_side(outcome: &KernelOutcome) -> SideVerdict {
    match outcome {
        KernelOutcome::Accept => SideVerdict::Accept,
        KernelOutcome::Reject { category, .. } => SideVerdict::Reject {
            category: *category,
        },
        KernelOutcome::Privilege
        | KernelOutcome::NoErrorLine { .. }
        | KernelOutcome::InvalidProgram => SideVerdict::Skipped,
    }
}

/// The verdict-matrix class of one program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffClass {
    /// Both verifiers accept.
    Match,
    /// Both verifiers reject (reasons are compared separately).
    MatchReject,
    /// The kernel is stricter: rand-verifier accepts, the kernel rejects.
    KernelStricter,
    /// 🎯 The kernel accepts what rand-verifier rejects — a precision
    /// candidate for manual analysis (Phase 6 entry point).
    KernelAccepts,
    /// One side could not produce a verdict.
    Skipped,
}

impl DiffClass {
    pub fn name(&self) -> &'static str {
        match self {
            DiffClass::Match => "match",
            DiffClass::MatchReject => "match-reject",
            DiffClass::KernelStricter => "kernel-stricter",
            DiffClass::KernelAccepts => "kernel-accepts",
            DiffClass::Skipped => "skipped",
        }
    }
}

/// Classify the verdict pair in the verdict matrix.
pub fn classify(mini: &SideVerdict, kernel: &SideVerdict) -> DiffClass {
    match (mini, kernel) {
        (SideVerdict::Accept, SideVerdict::Accept) => DiffClass::Match,
        (SideVerdict::Reject { .. }, SideVerdict::Reject { .. }) => DiffClass::MatchReject,
        (SideVerdict::Accept, SideVerdict::Reject { .. }) => DiffClass::KernelStricter,
        (SideVerdict::Reject { .. }, SideVerdict::Accept) => DiffClass::KernelAccepts,
        _ => DiffClass::Skipped,
    }
}

/// Known semantic differences (docs/DIFFERENTIAL_PLAN.md §6) that do
/// not count as findings. `name` is the corpus program name (file
/// stem). Returns the reason when the pair is expected.
pub fn whitelisted(name: &str, mini: &SideVerdict, kernel: &SideVerdict) -> Option<&'static str> {
    match (mini, kernel) {
        (SideVerdict::Reject { .. }, SideVerdict::Accept) => match name {
            // mini's state budget is 1024 vs the kernel's much larger
            // limits — an intentional design limit, not a bug
            "complexity_limit" => {
                Some("mini max_states=1024 vs kernel state limits — intentional (§6)")
            }
            // the kernel validates pointer alignment/bounds at access
            // time only; these computed pointers are never dereferenced
            "computed_offset_misaligned" => Some(
                "mini requires provable 8-byte alignment at pointer arithmetic (#45); the kernel validates at access time — r6 is never dereferenced",
            ),
            "computed_offset_out_of_frame" => Some(
                "mini requires in-frame offsets at pointer arithmetic (#45); the kernel validates at access time — r6 is never dereferenced",
            ),
            // the kernel explicitly allows scalar += pointer (dst
            // inherits the pointer state); mini only implements
            // immediate offsets (#20)
            "pointer_reg_arith" => Some(
                "mini does not implement register-offset pointer arithmetic (#20); the kernel allows scalar += pointer by design",
            ),
            // privileged load: allow_uninit_stack is
            // bpf_token_capable(CAP_PERFMON), and bpf_ns_capable treats
            // CAP_SYS_ADMIN as a superset of every BPF capability
            // (kernel/bpf/token.c) — uninit stack reads are allowed for
            // privileged loaders by design
            "stack_write_before_read" => Some(
                "privileged load: CAP_SYS_ADMIN implies allow_uninit_stack (bpf_ns_capable superset) — uninit stack reads allowed for privileged loaders by design",
            ),
            _ => None,
        },
        _ => None,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VerificationFailure;

    fn fail(message: &str) -> VerificationFailure {
        VerificationFailure::new(0, message.to_string())
    }

    #[test]
    fn mini_categories_from_actual_messages() {
        // every failure kind of the mini pass (the exact message
        // formats from src/exec.rs, src/cfg.rs, src/mini.rs)
        let cases = [
            ("register r2 is uninitialized", ReasonCategory::UninitRead),
            (
                "stack slot at offset -8 is uninitialized (write before read)",
                ReasonCategory::UninitRead,
            ),
            (
                "stack access at r10-520 exceeds the 512 byte frame",
                ReasonCategory::StackBounds,
            ),
            (
                "stack access at r10+8 points away from the frame (valid: r10-512..r10-8)",
                ReasonCategory::StackBounds,
            ),
            (
                "stack access at r6+0 with base offsets -8..240 exceeds the 512 byte frame",
                ReasonCategory::StackBounds,
            ),
            (
                "stack access through a non-stack pointer r1 is not supported",
                ReasonCategory::PointerArith,
            ),
            (
                "stack access through a scalar r2 is not supported",
                ReasonCategory::PointerArith,
            ),
            (
                "invalid indirect read from stack at r6+0: spilled PTR_CTX at offset -8",
                ReasonCategory::UninitRead,
            ),
            (
                "stack access at r10-4 is not 8-byte aligned",
                ReasonCategory::StackAlign,
            ),
            (
                "stack pointer r5 alignment is not provable (computed offsets must be 8-byte aligned)",
                ReasonCategory::StackAlign,
            ),
            (
                "arithmetic on context pointer r1 is not allowed",
                ReasonCategory::PointerArith,
            ),
            (
                "arithmetic on stack pointer r10 is not allowed (only ADD supports stack pointer arithmetic)",
                ReasonCategory::PointerArith,
            ),
            (
                "register-offset pointer arithmetic on r0 is not supported yet (only immediate offsets)",
                ReasonCategory::PointerArith,
            ),
            (
                "invalid comparison of r1 with r2 (different types)",
                ReasonCategory::PointerArith,
            ),
            (
                "comparing pointers r1 s> r2 is not allowed",
                ReasonCategory::PointerArith,
            ),
            ("unknown helper 99", ReasonCategory::HelperArgs),
            (
                "helper arg 1: r1 has type PTR_CTX, expected PtrToMap",
                ReasonCategory::HelperArgs,
            ),
            (
                "jump target 100 crosses subprogram boundary [0, 3)",
                ReasonCategory::CfgJump,
            ),
            (
                "branch target 5 crosses subprogram boundary [0, 3)",
                ReasonCategory::CfgJump,
            ),
            (
                "falls through out of subprogram [0, 3)",
                ReasonCategory::CfgJump,
            ),
            (
                "subprogram [0..2) does not end with exit",
                ReasonCategory::CfgJump,
            ),
            (
                "internal error: pc out of program range",
                ReasonCategory::CfgJump,
            ),
            ("unreachable instruction", ReasonCategory::Unreachable),
            (
                "back-edge exceeds max loops (256) — the loop does not converge",
                ReasonCategory::Complexity,
            ),
            ("r0 is uninitialized at exit", ReasonCategory::UninitRead),
            (
                "verification complexity limit exceeded (max_states 1024)",
                ReasonCategory::Complexity,
            ),
            (
                "verification complexity limit exceeded (max_steps 100000)",
                ReasonCategory::Complexity,
            ),
            // decode-level rejections stay Other, like their kernel side
            ("unknown opcode 0xef", ReasonCategory::Other),
            ("BPF_JMP uses reserved fields", ReasonCategory::Other),
            ("R11 is invalid", ReasonCategory::Other),
            ("invalid shift amount 64", ReasonCategory::Other),
        ];
        for (message, expected) in cases {
            assert_eq!(
                categorize_mini_reason(&fail(message)),
                expected,
                "message: {}",
                message
            );
        }
    }

    #[test]
    fn classify_verdict_matrix() {
        let acc = SideVerdict::Accept;
        let rej = SideVerdict::Reject {
            category: ReasonCategory::UninitRead,
        };
        let skip = SideVerdict::Skipped;

        assert_eq!(classify(&acc, &acc), DiffClass::Match);
        assert_eq!(classify(&rej, &rej), DiffClass::MatchReject);
        assert_eq!(classify(&acc, &rej), DiffClass::KernelStricter);
        assert_eq!(classify(&rej, &acc), DiffClass::KernelAccepts);
        assert_eq!(classify(&skip, &acc), DiffClass::Skipped);
        assert_eq!(classify(&acc, &skip), DiffClass::Skipped);
        assert_eq!(classify(&skip, &skip), DiffClass::Skipped);
    }

    #[test]
    fn whitelist_complexity_limit() {
        let rej = SideVerdict::Reject {
            category: ReasonCategory::Complexity,
        };
        let acc = SideVerdict::Accept;
        // the documented mini-limit difference is whitelisted
        assert!(whitelisted("complexity_limit", &rej, &acc).is_some());
        // documented mini-precision gaps (empirical, v0.6 first run)
        assert!(whitelisted("computed_offset_misaligned", &rej, &acc).is_some());
        assert!(whitelisted("computed_offset_out_of_frame", &rej, &acc).is_some());
        assert!(whitelisted("pointer_reg_arith", &rej, &acc).is_some());
        // privileged loads allow uninit stack reads by design
        // (allow_uninit_stack, CAP_SYS_ADMIN superset)
        assert!(whitelisted("stack_write_before_read", &rej, &acc).is_some());
        // the same pair under another name is a finding
        assert!(whitelisted("bounded_loop", &rej, &acc).is_none());
        // and the whitelist never applies to other pairs
        assert!(whitelisted("complexity_limit", &acc, &rej).is_none());
    }

    #[test]
    fn reject_corpus_categorizes() {
        // every reject fixture's failure must map to a reason category;
        // `invalid_shift` ("invalid shift amount 64") is the one
        // documented Other — the kernel's "invalid shift 64" maps to
        // Other too, so the diff pair stays consistent
        let dir = std::path::Path::new("tests/programs/reject");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let mut env = crate::env::BpfVerifierEnv::new();
            env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
            match env.verify().unwrap() {
                crate::error::Verdict::Safe => panic!("reject program accepted: {:?}", path),
                crate::error::Verdict::Unsafe(failure) => {
                    let category = categorize_mini_reason(&failure);
                    let shift_other =
                        category == ReasonCategory::Other && failure.message.contains("shift");
                    assert!(
                        shift_other || category != ReasonCategory::Other,
                        "{:?}: {} → {:?}",
                        path,
                        failure.message,
                        category
                    );
                    count += 1;
                }
            }
        }
        assert!(count > 0, "no reject programs found");
    }
}
