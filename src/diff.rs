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
        || msg.contains("map value")
        || msg.contains("math between")
        || msg.contains("out of bounds")
        || msg.contains("pointer offset")
    {
        // "... pointer arithmetic ...", "stack access through a
        // non-stack pointer / a scalar ...", "invalid access to map
        // value ...", "math between ... pointer and ... is not
        // allowed", "value ... makes ... pointer be out of bounds",
        // "... pointer offset ... is not allowed" (the kernel's
        // check_reg_sane_offset_* family)
        ReasonCategory::PointerArith
    } else if msg.contains("indirect read") {
        // "invalid indirect read from stack ... spilled ..." — the
        // kernel rejects variable-offset reads over spilled registers
        ReasonCategory::UninitRead
    } else if msg.contains("invalid size of register fill")
        || msg.contains("corrupt spilled pointer")
    {
        // the kernel's -EACCES fill/spill corruption family (#100)
        ReasonCategory::UninitRead
    } else if msg.contains("stack access") || msg.contains("stack pointer") {
        // "stack access at r10 ... exceeds/points away",
        // "stack access at r6+0 with base offsets ...",
        // "stack pointer ... may leave/are out of the frame"
        ReasonCategory::StackBounds
    } else if msg.contains("not a scalar") {
        // "r0 is not a scalar value at exit" — the kernel's
        // check_return_code rejects a non-scalar R0 at exit
        // ("R0 leaks addr as return value" / "R0 is not a known value")
        ReasonCategory::ExitR0
    } else if msg.contains("helper") || msg.contains("expected") {
        ReasonCategory::HelperArgs
    } else if msg.contains("back-edge") || msg.contains("complexity limit") {
        // mini's loop budget is its complexity mechanism — the kernel
        // rejects non-converging loops with "BPF program is too large"
        ReasonCategory::Complexity
    } else if msg.contains("kfunc") {
        // "unknown kfunc", "calling kernel function ... is not
        // allowed" (kernel check_kfunc_call, #101)
        ReasonCategory::Ref
    } else if msg.contains("dynptr") {
        // "Expected an initialized dynptr as arg #N", "dynptr read out
        // of bounds" (kernel check_func_arg for ARG_PTR_TO_DYNPTR,
        // #101)
        ReasonCategory::Ref
    } else if msg.contains("reference") || msg.contains("Unreleased") {
        // "Unreleased reference id=N", "release of unacquired
        // reference" (kernel check_reference_leak, #101)
        ReasonCategory::Ref
    } else if msg.contains("infinite loop") {
        // kernel/bpf/states.c: "infinite loop detected at insn N"
        ReasonCategory::Loop
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
///
/// Besides the name-based entries, a category rule covers the whole
/// privileged-leniency family ([`privileged_stack_leniency`]) so
/// fuzzer-generated and corpus programs are treated alike.
///
/// The computed-offset / pointer-arith entries were removed in v0.8.1
/// (#90): #87 moved bounds/alignment validation to access time like the
/// kernel, so those fixtures moved to the accept corpus and the pairs
/// no longer occur.
pub fn whitelisted(
    name: &str,
    mini: &SideVerdict,
    kernel: &SideVerdict,
    mini_reason: Option<&str>,
) -> Option<&'static str> {
    match (mini, kernel) {
        (SideVerdict::Reject { .. }, SideVerdict::Accept) => {
            // mini's exploration budget (max_states 1024 / max_steps)
            // vs the kernel's much larger limits — an intentional
            // design limit; category-applied so fuzzer-generated
            // complexity programs are whitelisted like the corpus
            // fixture (the kernel accepts what mini rejects here)
            if matches!(
                mini,
                SideVerdict::Reject {
                    category: ReasonCategory::Complexity
                }
            ) {
                return Some(
                    "mini's exploration budget (max_states 1024 / max_steps) vs the kernel's much larger limits — intentional design limit (§6)",
                );
            }
            // privileged loads allow uninit stack reads
            // (allow_uninit_stack) and indirect reads over spilled
            // pointers (allow_ptr_leaks) by design — the same family as
            // stack_write_before_read, applied by category so it also
            // covers fuzzer-generated programs
            if privileged_stack_leniency(mini, mini_reason) {
                return Some(
                    "privileged load leniency: uninit stack reads (allow_uninit_stack) and indirect reads over spilled pointers (allow_ptr_leaks) are allowed for privileged loaders (CAP_SYS_ADMIN superset, kernel/bpf/token.c)",
                );
            }
            // privileged loads allow pointer values in R0 at exit: the
            // exit-time check ("R0 leaks addr as return value") is
            // gated on is_pointer_value(), which returns false when
            // allow_ptr_leaks is set (kernel/bpf/verifier.c) —
            // returning a pointer from a program is allowed for
            // privileged loaders by design; strict mode
            // (unprivileged-equivalent) rejects it, which the mini
            // mirrors ("r0 is not a scalar value at exit"). Same
            // privileged-leniency family as the stack rule above;
            // category-applied so fuzzer-generated programs are
            // whitelisted like the corpus fixture (m5, PR #92).
            if matches!(
                mini,
                SideVerdict::Reject {
                    category: ReasonCategory::ExitR0
                }
            ) && mini_reason.is_some_and(|r| r.contains("at exit"))
            {
                return Some(
                    "privileged load leniency: pointer return in R0 allowed for privileged loaders (allow_ptr_leaks gates the exit-time R0 check); strict mode rejects it",
                );
            }
            match name {
                // privileged load: allow_uninit_stack is
                // bpf_token_capable(CAP_PERFMON), and bpf_ns_capable treats
                // CAP_SYS_ADMIN as a superset of every BPF capability
                // (kernel/bpf/token.c: ns_capable(ns, cap) || (cap !=
                // CAP_SYS_ADMIN && ns_capable(ns, CAP_SYS_ADMIN))) — uninit
                // stack reads are allowed for privileged loaders by design.
                // The category rule above covers the same family for
                // programs without a mini reason (fuzzer seeds); this name
                // entry keeps the corpus fixture stable.
                "stack_write_before_read" => Some(
                    "privileged load: CAP_SYS_ADMIN implies allow_uninit_stack (bpf_ns_capable superset) — uninit stack reads allowed for privileged loaders by design",
                ),
                // the same family for the narrow-read fixture (#100)
                "narrow_read_uninit" => Some(
                    "privileged load: CAP_SYS_ADMIN implies allow_uninit_stack (bpf_ns_capable superset) — uninit stack reads allowed for privileged loaders by design",
                ),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Privileged-load stack leniency (#90): mini rejects uninitialized
/// stack reads ("stack slot ... is uninitialized") and indirect reads
/// over spilled pointers ("invalid indirect read from stack") that the
/// kernel accepts when the loader is privileged — `allow_uninit_stack`
/// and `allow_ptr_leaks` are gated on `bpf_token_capable` / the
/// CAP_SYS_ADMIN superset rule (kernel/bpf/token.c:14), so unprivileged
/// (--strict) loads reject the same programs. Uninit *register* reads
/// are NOT lenient — the kernel rejects those too.
pub fn privileged_stack_leniency(mini: &SideVerdict, mini_reason: Option<&str>) -> bool {
    matches!(
        mini,
        SideVerdict::Reject {
            category: ReasonCategory::UninitRead
        }
    ) && mini_reason.is_some_and(|r| r.contains("stack slot") || r.contains("indirect read"))
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
                "invalid access to map value r0+0, value_size=8 (base offsets 8..8)",
                ReasonCategory::PointerArith,
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
            ("r0 is not a scalar value at exit", ReasonCategory::ExitR0),
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
    fn categorize_mini_exit_r0_pointer() {
        // the mini rejects a pointer in R0 at exit (mseed-99399-57) —
        // same ExitR0 category as the kernel's "R0 leaks addr as
        // return value" / "R0 is not a known value"
        let failure = VerificationFailure::new(3, "r0 is not a scalar value at exit");
        assert_eq!(categorize_mini_reason(&failure), ReasonCategory::ExitR0);
    }

    #[test]
    fn whitelist_complexity_limit() {
        let rej = SideVerdict::Reject {
            category: ReasonCategory::Complexity,
        };
        let acc = SideVerdict::Accept;
        // mini's exploration budget (max_states 1024 / max_steps) vs
        // the kernel's much larger limits is whitelisted — by category,
        // so fuzzer-generated complexity programs are treated alike
        // (the complexity_limit corpus fixture itself moved to accept
        // in #97: kernel-style dead-slot pruning explores it within
        // the limits, like the privileged kernel)
        assert!(whitelisted("complexity_limit", &rej, &acc, None).is_some());
        assert!(whitelisted("seed-1-3", &rej, &acc, None).is_some());
        // other categories under any name stay findings
        let uninit = SideVerdict::Reject {
            category: ReasonCategory::UninitRead,
        };
        assert!(whitelisted("anything", &uninit, &acc, None).is_none());
        // and the whitelist never applies to other pairs
        assert!(whitelisted("complexity_limit", &acc, &rej, None).is_none());
    }

    #[test]
    fn whitelist_privileged_stack_leniency() {
        // the category rule covers the whole privileged-leniency
        // family (#90): uninit stack reads and indirect reads over
        // spilled pointers that the kernel accepts under privilege
        let uninit = SideVerdict::Reject {
            category: ReasonCategory::UninitRead,
        };
        let acc = SideVerdict::Accept;
        for reason in [
            "stack slot at offset -8 is uninitialized (write before read)",
            "invalid indirect read from stack at r6+0: spilled PTR_CTX at offset -8",
        ] {
            assert!(
                whitelisted("anything", &uninit, &acc, Some(reason)).is_some(),
                "{reason}"
            );
        }
        // uninit *register* reads stay findings (the kernel rejects
        // those too — a kernel accept would be a real bug)
        assert!(
            whitelisted(
                "anything",
                &uninit,
                &acc,
                Some("register r2 is uninitialized")
            )
            .is_none()
        );
        // and the rule never applies to other pairs
        assert!(
            whitelisted(
                "anything",
                &uninit,
                &SideVerdict::Reject {
                    category: ReasonCategory::UninitRead
                },
                Some("stack slot at offset -8 is uninitialized (write before read)")
            )
            .is_none()
        );
        // the computed-offset / pointer-arith entries were removed in
        // v0.8.1 (#90): the fixtures moved to the accept corpus after
        // #87 moved validation to access time
        assert!(whitelisted("computed_offset_misaligned", &uninit, &acc, None).is_none());
        assert!(whitelisted("computed_offset_out_of_frame", &uninit, &acc, None).is_none());
        assert!(whitelisted("pointer_reg_arith", &uninit, &acc, None).is_none());
    }

    #[test]
    fn whitelist_privileged_pointer_return() {
        // the mini mirrors the strict (unprivileged-equivalent) rule:
        // R0 must be a scalar at exit. The privileged kernel accepts
        // pointer returns (allow_ptr_leaks gates the exit-time check),
        // so the pair is a design difference, whitelisted by category
        // (m5 mseed-99399-57 shape; pointer_reg_arith corpus fixture)
        let exit = SideVerdict::Reject {
            category: ReasonCategory::ExitR0,
        };
        let acc = SideVerdict::Accept;
        assert!(
            whitelisted(
                "pointer_reg_arith",
                &exit,
                &acc,
                Some("r0 is not a scalar value at exit")
            )
            .is_some()
        );
        // category-applied: fuzzer-generated names are treated alike
        assert!(
            whitelisted(
                "seed-1-7",
                &exit,
                &acc,
                Some("r0 is not a scalar value at exit")
            )
            .is_some()
        );
        // other categories under any name stay findings
        let uninit = SideVerdict::Reject {
            category: ReasonCategory::UninitRead,
        };
        assert!(
            whitelisted(
                "pointer_reg_arith",
                &uninit,
                &acc,
                Some("r0 is not a scalar value at exit")
            )
            .is_none()
        );
        // and the rule never applies to other pairs
        assert!(
            whitelisted(
                "pointer_reg_arith",
                &exit,
                &SideVerdict::Reject {
                    category: ReasonCategory::ExitR0
                },
                Some("r0 is not a scalar value at exit")
            )
            .is_none()
        );
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
                    // decode-level rejections (unknown opcode, reserved
                    // fields, unsupported instructions) stay Other, like
                    // their kernel-side "unknown opcode" family
                    let decode_other = category == ReasonCategory::Other
                        && (failure.message.contains("shift")
                            || failure.message.contains("unsupported instruction"));
                    assert!(
                        decode_other || category != ReasonCategory::Other,
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
