// ── Kernel verifier log parsing (issue #59) ─────────────────────────────────

/// The normalized reason category of a kernel verifier rejection.
///
/// The categories mirror the rand-verifier failure kinds so the diff
/// harness (#60) can compare the reasons of the two verifiers on the
/// same program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReasonCategory {
    /// Reading a register or stack slot before it was initialized
    /// ("R%d !read_ok", "invalid read from stack off ...").
    UninitRead,
    /// Stack access outside the frame ("invalid%s stack %s off=...").
    StackBounds,
    /// Stack access that is not 8-byte aligned ("misaligned ...access...").
    StackAlign,
    /// Pointer arithmetic, pointer leaks and invalid memory accesses
    /// ("... pointer arithmetic ... prohibited", "... invalid mem access ...",
    /// "R%d leaks addr ...", "R%d stack pointer arithmetic goes out of range").
    PointerArith,
    /// Helper call problems: unknown helper, wrong argument types
    /// ("invalid func ...#%d", "R%d type=... expected=...", "arg#...").
    HelperArgs,
    /// CFG violations: jump targets, subprogram boundaries
    /// ("jump out of range from insn ...", "last insn is not an exit").
    CfgJump,
    /// Loop-related rejections ("back-edge from insn ..." — unprivileged
    /// loads only; privileged loads accept back edges).
    Loop,
    /// Unreachable instructions ("unreachable insn %d").
    Unreachable,
    /// Exit-time R0 problems ("R0 not a scalar value", "cannot return
    /// stack pointer to the caller", "R0 leaks addr as return value").
    ExitR0,
    /// Exploration complexity limits ("The sequence of %d jumps is too
    /// complex.", "BPF program is too large. Processed %d insn").
    Complexity,
    /// Reference tracking problems ("Unreleased reference id=...",
    /// "release of unacquired reference", #101).
    Ref,
    /// Anything not matched yet — the raw message is kept for manual
    /// analysis and the diff whitelist (#60).
    Other,
}

/// Map a kernel verifier error message to its reason category.
///
/// The patterns are the `verbose()` formats of `kernel/bpf/verifier.c`,
/// `kernel/bpf/cfg.c` and `kernel/bpf/syscall.c` (checked against
/// upstream master). Order matters — the more specific patterns come
/// first.
pub fn categorize_reason(message: &str) -> ReasonCategory {
    let msg = message.trim();
    if msg.contains("Unreleased reference") || msg.contains("release of unacquired reference") {
        ReasonCategory::Ref
    } else if msg.contains("misaligned") {
        ReasonCategory::StackAlign
    } else if msg.contains("stack") && msg.contains("off=") && msg.contains("invalid") {
        // "invalid read/write to stack R10 off=N size=N" — out of bounds
        ReasonCategory::StackBounds
    } else if msg.contains("!read_ok") || msg.contains("invalid read from stack") {
        // "R2 !read_ok", "invalid read from stack R10 off -8+0 size 8"
        ReasonCategory::UninitRead
    } else if msg.contains("unreachable insn") {
        ReasonCategory::Unreachable
    } else if msg.contains("jump out of range")
        || msg.contains("jump into the middle")
        || msg.contains("indirect jump out of range")
        || msg.contains("last insn is not an exit")
        || msg.contains("call to invalid destination")
    {
        ReasonCategory::CfgJump
    } else if msg.contains("back-edge") || msg.contains("infinite loop detected") {
        ReasonCategory::Loop
    } else if msg.contains("leaks addr as return")
        || msg.contains("R0 ") // "R0 not a scalar value", "R0 leaks addr ..."
        || msg.contains("cannot return")
        || msg.contains("not a scalar")
    {
        ReasonCategory::ExitR0
    } else if msg.contains("pointer arithmetic")
        || msg.contains("pointer comparison")
        || msg.contains("invalid mem access")
        || msg.contains("leaks addr")
        || msg.contains("leaking pointer")
        || msg.contains("subtraction from stack pointer")
        || msg.contains("frame pointer is read only")
        || msg.contains("unbounded min value")
        || msg.contains("math between")
        || msg.contains("out of bounds")
        || msg.contains("pointer offset")
    {
        // "... pointer arithmetic ... prohibited", "R%d invalid mem
        // access", "math between fp pointer and N is not allowed",
        // "value N makes fp pointer be out of bounds", "fp pointer
        // offset N is not allowed" (adjust_ptr_min_max_vals /
        // check_reg_sane_offset_* family)
        ReasonCategory::PointerArith
    } else if msg.contains("variable stack access") {
        // "... variable stack access prohibited for !root"
        ReasonCategory::StackBounds
    } else if msg.contains("invalid func")
        || msg.contains("unknown func")
        || msg.contains("helper")
        || msg.contains("arg#")
        || msg.contains("expected")
        || msg.contains("Possibly NULL pointer")
    {
        ReasonCategory::HelperArgs
    } else if msg.contains("too complex")
        || msg.contains("BPF program is too large")
        || msg.contains("iteration limit")
    {
        ReasonCategory::Complexity
    } else {
        ReasonCategory::Other
    }
}

/// Extract the error `(insn_idx, message)` from a kernel verifier log —
/// `None` when the log contains no error (the program was accepted, or
/// the log was truncated).
///
/// Kernel log layout at `log_level = 1`:
///
/// ```text
/// 0: (b7) r0 = 1                  ← instruction traces ("N: (op) ...")
/// 1: (85) call unknown#99
/// invalid func unknown#99          ← the error block, printed right
///                                    after the insn that caused it
/// processed 2 insns (limit ...)   ← summary (printed for accepts too)
/// ```
///
/// The error block is everything between the last trace and the
/// summary; it can span several lines (e.g. the helper-argument
/// message "R1 type=ctx expected=" + "map_ptr"). State transitions
/// ("from X to Y: ...", log_level 2) are filtered out.
///
/// CFG-stage errors (jump out of range, unreachable insn, last insn is
/// not an exit) are detected before any instruction is traced — the log
/// holds only the error and the summary. In that case the whole log is
/// the error block and the insn index is read from the "insn N" inside
/// the message.
pub fn parse_verifier_log(log: &str) -> Option<(u32, String)> {
    let lines: Vec<&str> = log.lines().collect();
    let is_summary = |t: &str| {
        t.is_empty()
            || t.starts_with("processed ")
            || t.starts_with("verification time ")
            || t.starts_with("stack depth ")
            || t.starts_with("insns processed ")
    };
    let is_trace = |t: &str| {
        let (num, rest) = t.trim().split_once(':').unwrap_or(("", ""));
        rest.trim_start().starts_with('(') && num.parse::<u32>().is_ok()
    };
    // the last insn trace line ("N: (op) ...")
    let last_trace = lines.iter().rposition(|l| is_trace(l.trim()));
    // everything between the last trace and the summary is the error;
    // without traces (CFG-stage errors) the whole log minus the summary
    // is the error
    let error_lines = match last_trace {
        Some(pos) => &lines[pos + 1..],
        None => &lines[..],
    };
    let message: String = error_lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            !is_summary(t) && !is_trace(t) && !t.starts_with("from ")
        })
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" ");
    if message.is_empty() {
        return None;
    }
    let insn_idx = match last_trace {
        Some(pos) => lines[pos]
            .trim()
            .split_once(':')
            .and_then(|(num, _)| num.parse::<u32>().ok())
            .unwrap_or(0),
        // CFG-stage errors embed the insn index in the message
        None => message
            .split_whitespace()
            .zip(message.split_whitespace().skip(1))
            .find(|(w, _)| *w == "insn")
            .and_then(|(_, next)| next.trim_end_matches(',').parse::<u32>().ok())
            .unwrap_or(0),
    };
    Some((insn_idx, message))
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Sample logs modeled on the kernel's actual output formats
    // (verifier.c / cfg.c / syscall.c message strings).

    #[test]
    fn categorize_unknown_helper() {
        assert_eq!(
            categorize_reason("invalid func unknown#99"),
            ReasonCategory::HelperArgs
        );
        assert_eq!(
            categorize_reason("program of this type cannot use helper bpf_get_prandom_u32#7"),
            ReasonCategory::HelperArgs
        );
    }

    #[test]
    fn categorize_uninit_read() {
        assert_eq!(categorize_reason("R2 !read_ok"), ReasonCategory::UninitRead);
        assert_eq!(
            categorize_reason("invalid read from stack off -8+0 size 8"),
            ReasonCategory::UninitRead
        );
    }

    #[test]
    fn categorize_stack() {
        assert_eq!(
            categorize_reason("invalid stack off=-520 size=8"),
            ReasonCategory::StackBounds
        );
        assert_eq!(
            categorize_reason("invalid write to stack R10 off=-520 size=8"),
            ReasonCategory::StackBounds
        );
        assert_eq!(
            categorize_reason("invalid read from stack R10 off=8 size=8"),
            ReasonCategory::StackBounds
        );
        assert_eq!(
            categorize_reason("misaligned stack access off 0+-4 size 8"),
            ReasonCategory::StackAlign
        );
        // the uninitialized-slot form carries the offset as "off -8+0"
        // (no '='): bounds are fine, the slot was never written
        assert_eq!(
            categorize_reason("invalid read from stack R10 off -8+0 size 8"),
            ReasonCategory::UninitRead
        );
    }

    #[test]
    fn categorize_pointer() {
        assert_eq!(
            categorize_reason("R1 pointer arithmetic on ctx prohibited"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("R1 stack pointer arithmetic goes out of range, prohibited for null"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("R2 invalid mem access 'map_value'"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("leaking pointer from stack off -8"),
            ReasonCategory::PointerArith
        );
    }

    #[test]
    fn categorize_helper_args() {
        assert_eq!(
            categorize_reason("R1 type=ctx expected=map_ptr"),
            ReasonCategory::HelperArgs
        );
        assert_eq!(
            categorize_reason("arg#0 expected pointer to map, got ctx"),
            ReasonCategory::HelperArgs
        );
    }

    #[test]
    fn categorize_cfg_and_unreachable() {
        assert_eq!(
            categorize_reason("jump out of range from insn 1 to 101"),
            ReasonCategory::CfgJump
        );
        assert_eq!(
            categorize_reason("last insn is not an exit or jmp"),
            ReasonCategory::CfgJump
        );
        assert_eq!(
            categorize_reason("unreachable insn 2"),
            ReasonCategory::Unreachable
        );
    }

    #[test]
    fn categorize_loop_and_complexity() {
        assert_eq!(
            categorize_reason("back-edge from insn 1 to 0"),
            ReasonCategory::Loop
        );
        assert_eq!(
            categorize_reason(
                "infinite loop detected at insn 0 cur state: R10=fp0 old state: R10=fp0"
            ),
            ReasonCategory::Loop
        );
        assert_eq!(
            categorize_reason("The sequence of 2049 jumps is too complex."),
            ReasonCategory::Complexity
        );
        assert_eq!(
            categorize_reason("BPF program is too large. Processed 1000001 insn"),
            ReasonCategory::Complexity
        );
    }

    #[test]
    fn categorize_privileged_messages() {
        // messages observed on privileged loads (bpf-next, 2026-08)
        assert_eq!(
            categorize_reason("frame pointer is read only"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason(
                "math between fp pointer and register with unbounded min value is not allowed"
            ),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("math between fp pointer and 2147483647 is not allowed"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("value -9223372035854775808 makes fp pointer be out of bounds"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("fp pointer offset 2147483648 is not allowed"),
            ReasonCategory::PointerArith
        );
        assert_eq!(
            categorize_reason("R1 32-bit pointer arithmetic prohibited"),
            ReasonCategory::PointerArith
        );
    }

    #[test]
    fn categorize_exit_r0() {
        assert_eq!(
            categorize_reason("R0 not a scalar value"),
            ReasonCategory::ExitR0
        );
        assert_eq!(
            categorize_reason("cannot return stack pointer to the caller"),
            ReasonCategory::ExitR0
        );
        assert_eq!(
            categorize_reason("R0 leaks addr as return value"),
            ReasonCategory::ExitR0
        );
        // leaks into memory are pointer problems, not exit problems
        assert_eq!(
            categorize_reason("R3 leaks addr into mem"),
            ReasonCategory::PointerArith
        );
    }

    #[test]
    fn parse_accept_log_returns_none() {
        // an accepted program's log ends with the summary line only
        let log = "\
0: (b7) r0 = 1
1: (95) exit
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        assert_eq!(parse_verifier_log(log), None);
    }

    #[test]
    fn parse_reject_log_unknown_helper() {
        let log = "\
0: (85) call unknown#99
invalid func unknown#99
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error line");
        assert_eq!(insn_idx, 0);
        assert_eq!(message, "invalid func unknown#99");
    }

    #[test]
    fn parse_reject_log_uninit() {
        let log = "\
0: (b7) r0 = 1
1: (bf) r2 = r0
2: (95) exit
R2 !read_ok
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error line");
        assert_eq!(insn_idx, 2);
        assert_eq!(message, "R2 !read_ok");
        assert_eq!(categorize_reason(&message), ReasonCategory::UninitRead);
    }

    #[test]
    fn parse_reject_log_unreachable() {
        // the error mentions its own insn index; the trace scan finds
        // the last traced insn, which is the same one here
        let log = "\
0: (b7) r0 = 1
1: (05) goto pc+0
2: (95) exit
unreachable insn 2
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error line");
        assert_eq!(insn_idx, 2);
        assert_eq!(message, "unreachable insn 2");
    }

    #[test]
    fn parse_reject_log_with_state_dumps() {
        // log_level 2 adds "N: R..." register dumps and "from X to Y:"
        // state transitions before the failing trace — the error block
        // is still identified by the last trace line
        let log = "\
0: R1=ctx() R10=fp0
0: (b7) r0 = 1
1: R0=scalar() R10=fp0
from 1 to 2: R0=scalar() R10=fp0
1: (79) r0 = *(u64 *)(r10 -8)
invalid read from stack off -8+0 size 8
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 1
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error line");
        assert_eq!(insn_idx, 1);
        assert_eq!(message, "invalid read from stack off -8+0 size 8");
    }

    #[test]
    fn parse_reject_log_multiline_error() {
        // the helper-argument message is printed in two parts:
        // "R1 type=ctx expected=" + "map_ptr"
        let log = "\
0: (85) call map_lookup_elem#1
R1 type=ctx expected=
map_ptr
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error block");
        assert_eq!(insn_idx, 0);
        assert!(message.contains("R1 type=ctx expected="), "{}", message);
        assert!(message.contains("map_ptr"), "{}", message);
        assert_eq!(categorize_reason(&message), ReasonCategory::HelperArgs);
    }

    #[test]
    fn parse_cfg_stage_error_without_traces() {
        // CFG-stage errors are detected before any instruction is
        // traced — the log has no "N: (op) ..." lines at all
        let log = "\
unreachable insn 2
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error");
        assert_eq!(insn_idx, 2);
        assert_eq!(message, "unreachable insn 2");

        let log = "\
jump out of range from insn 1 to 101
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (insn_idx, message) = parse_verifier_log(log).expect("error");
        assert_eq!(insn_idx, 1);
        assert_eq!(categorize_reason(&message), ReasonCategory::CfgJump);

        let log = "\
last insn is not an exit or jmp
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
        let (_, message) = parse_verifier_log(log).expect("error");
        assert_eq!(categorize_reason(&message), ReasonCategory::CfgJump);
    }

    #[test]
    fn parse_empty_log_returns_none() {
        assert_eq!(parse_verifier_log(""), None);
        assert_eq!(
            parse_verifier_log("processed 1 insns (limit 1000000)"),
            None
        );
    }
}
