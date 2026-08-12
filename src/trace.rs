// ── Execution trace rendering (v0.2 Micro) ──────────────────────────────────

use crate::error::VerificationFailure;
use crate::exec::step;
use crate::insn::{BpfInsn, disassemble};
use crate::state::{RegState, VerifierState};

/// Render one trace entry for a step: the disassembled instruction
/// followed by the interesting registers.
///
/// The first step shows the entry-relevant state (R0, the exit-value
/// register, plus every initialized register); later steps show only the
/// registers whose state changed, mirroring the #21 example.
pub(crate) fn trace_step(
    pc: u32,
    insn: &BpfInsn,
    before: &VerifierState,
    after: &VerifierState,
) -> String {
    let mut out = format!("{}: {}\n", pc, disassemble(insn));
    if pc == 0 {
        // R0 is the exit value — always shown at the start
        out.push_str(&format!("  R0 = {}\n", after.regs[0]));
        for (i, reg) in after.regs.iter().enumerate().skip(1) {
            if *reg != RegState::Uninit {
                out.push_str(&format!("  R{} = {}\n", i, reg));
            }
        }
    } else {
        for (i, (before, after)) in before.regs.iter().zip(&after.regs).enumerate() {
            if before != after {
                out.push_str(&format!("  R{} = {}\n", i, after));
            }
        }
    }
    out
}

/// Execute a straight-line program and render the execution trace.
///
/// Micro-stage trace renderer: steps through every instruction in order
/// and stops at the first control-flow instruction, which step() cannot
/// execute (control flow is expanded by the worklist driver).
#[allow(dead_code)] // used by tests; CLI wiring is a separate feature
pub(crate) fn run_trace(program: &[BpfInsn]) -> Result<String, VerificationFailure> {
    let mut out = String::new();
    let mut state = VerifierState::initial();
    for (pc, insn) in program.iter().enumerate() {
        // exit ends the trace (no state change); control flow is not
        // part of the straight-line subset
        if matches!(
            insn,
            BpfInsn::Exit | BpfInsn::Jmp { .. } | BpfInsn::Jeq { .. } | BpfInsn::Jgt { .. }
        ) {
            if matches!(insn, BpfInsn::Exit) {
                out.push_str(&trace_step(pc as u32, insn, &state, &state));
                out.push('\n');
            } else {
                return Err(VerificationFailure::new(
                    pc as u32,
                    "control flow is not traced (straight-line subset)",
                ));
            }
            break;
        }
        let next = step(pc as u32, &state, insn)?;
        out.push_str(&trace_step(pc as u32, insn, &state, &next));
        out.push('\n');
        state = next;
    }
    Ok(out)
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::step;
    use crate::insn::*;
    use crate::state::*;

    #[test]
    fn trace_step_issue_example() {
        // issue example: the first step shows the entry-relevant state
        // (R0 plus every initialized register)…
        let state = VerifierState::initial();
        let after = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let trace = trace_step(0, &BpfInsn::MovImm { dst: 2, imm: 10 }, &state, &after);
        assert_eq!(
            trace,
            "0: r2 = 10\n  R0 = UNINIT\n  R1 = PTR_CTX\n  R2 = SCALAR(10..10)\n  R10 = PTR_STACK(0)\n"
        );
        // …later steps show only the changed register
        let after2 = step(1, &after, &BpfInsn::AddImm { dst: 2, imm: 5 }).unwrap();
        let trace = trace_step(1, &BpfInsn::AddImm { dst: 2, imm: 5 }, &after, &after2);
        assert_eq!(trace, "1: r2 += 5\n  R2 = SCALAR(15..15)\n");
    }

    #[test]
    fn run_trace_straight_line() {
        let program = vec![
            BpfInsn::MovImm { dst: 2, imm: 10 },
            BpfInsn::AddImm { dst: 2, imm: 5 },
            BpfInsn::Exit,
        ];
        let trace = run_trace(&program).unwrap();
        assert_eq!(
            trace,
            "0: r2 = 10\n  R0 = UNINIT\n  R1 = PTR_CTX\n  R2 = SCALAR(10..10)\n  R10 = PTR_STACK(0)\n\n\
         1: r2 += 5\n  R2 = SCALAR(15..15)\n\n\
         2: exit\n\n"
        );
    }

    #[test]
    fn run_trace_stops_on_unsupported() {
        // control flow is not part of the straight-line subset → the trace stops
        let program = vec![BpfInsn::Jmp { offset: 0 }, BpfInsn::Exit];
        let err = run_trace(&program).unwrap_err();
        assert_eq!(err.insn_idx, 0);
        assert!(err.message.contains("control flow"));
    }

    #[test]
    fn run_trace_full_sequence() {
        // registers, stack, and pointers all visible in one trace
        let program = vec![
            BpfInsn::MovImm { dst: 2, imm: 10 },
            BpfInsn::StStack { src: 2, offset: -8 },
            BpfInsn::LdStack { dst: 0, offset: -8 },
            BpfInsn::AddImm { dst: 10, imm: -8 },
            BpfInsn::Exit,
        ];
        let trace = run_trace(&program).unwrap();
        assert!(trace.contains("1: [r10-8] = r2\n"));
        // the spilled scalar range survives the round-trip (#30)
        assert!(trace.contains("2: r0 = [r10-8]\n  R0 = SCALAR(10..10)\n"));
        assert!(trace.contains("3: r10 += -8\n  R10 = PTR_STACK(-8)\n"));
    }

    // ── Branch refinement (v0.2) ─────────────────────────────────────────────
}
