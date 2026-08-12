// ── Abstract instruction execution and branch expansion ─────────────────────

use crate::error::VerificationFailure;
use crate::helper::{check_helper_args, helper_prototype};
use crate::insn::BpfInsn;
use crate::state::{
    RegState, STACK_SIZE, StackSlot, VerifierState, check_reg, read_reg, read_scalar,
    stack_slot_index,
};

/// Symbolically execute a single instruction, producing the next state.
///
/// Instead of tracking concrete u64 values, registers are updated by
/// abstract rules: an immediate move produces a constant scalar range,
/// a register move copies the source's abstract state, and `exit`
/// terminates the path without changing the state.
///
/// Instructions that expand to a single successor are executed here;
/// control flow (Jmp/Jeq/Jgt) and exit are expanded by `successors()`
/// and never reach this function in the verification pipeline, calls
/// are validated as helper invocations (#28), and register-offset
/// pointer arithmetic is rejected (#20).
pub(crate) fn step(
    pc: u32,
    state: &VerifierState,
    insn: &BpfInsn,
) -> Result<VerifierState, VerificationFailure> {
    match insn {
        // rX = imm → constant scalar
        BpfInsn::MovImm { dst, imm } => {
            check_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar {
                min: *imm as i64,
                max: *imm as i64,
            };
            Ok(next)
        }
        // rX = rY → copy the source's abstract state;
        // the source must have been written before it is read (#14)
        BpfInsn::MovReg { dst, src } => {
            check_reg(pc, *dst)?;
            let src_state = read_reg(pc, state, *src)?;
            let mut next = *state;
            next.regs[*dst as usize] = src_state;
            Ok(next)
        }
        // terminal and control flow are expanded by successors();
        // reaching them here is a driver bug
        BpfInsn::Exit | BpfInsn::Jmp { .. } | BpfInsn::Jeq { .. } | BpfInsn::Jgt { .. } => {
            unreachable!("exit and control flow are expanded by successors(), not step()")
        }
        // rX += imm → shift a scalar range, or a stack pointer offset:
        // pointer + immediate is the only allowed pointer arithmetic (#20)
        BpfInsn::AddImm { dst, imm } => {
            check_reg(pc, *dst)?;
            let dst_state = read_reg(pc, state, *dst)?;
            match dst_state {
                RegState::Scalar { min, max } => {
                    let mut next = *state;
                    next.regs[*dst as usize] = RegState::Scalar {
                        min: min.wrapping_add(*imm as i64),
                        max: max.wrapping_add(*imm as i64),
                    };
                    Ok(next)
                }
                // PtrToStack + Scalar => PtrToStack at the shifted offset;
                // the pointer must stay within the frame (cf. #19)
                RegState::PtrToStack { offset } => {
                    let new_offset = offset.wrapping_add(*imm);
                    if !(-(STACK_SIZE as i32)..=0).contains(&new_offset) {
                        return Err(VerificationFailure::new(
                            pc,
                            format!(
                                "stack pointer r{} offset {} is out of the {} byte frame",
                                dst, new_offset, STACK_SIZE
                            ),
                        ));
                    }
                    let mut next = *state;
                    next.regs[*dst as usize] = RegState::PtrToStack { offset: new_offset };
                    Ok(next)
                }
                RegState::PtrToCtx => Err(VerificationFailure::new(
                    pc,
                    format!("arithmetic on context pointer r{} is not allowed", dst),
                )),
                RegState::PtrToMap => Err(VerificationFailure::new(
                    pc,
                    format!("arithmetic on map pointer r{} is not allowed", dst),
                )),
                RegState::PtrToMapValue => Err(VerificationFailure::new(
                    pc,
                    format!(
                        "arithmetic on map value pointer r{} is not supported yet",
                        dst
                    ),
                )),
                RegState::PtrToMapValueOrNull => Err(VerificationFailure::new(
                    pc,
                    format!(
                        "arithmetic on nullable pointer r{} is not allowed (check for NULL first)",
                        dst
                    ),
                )),
                RegState::Uninit => unreachable!("read_reg rejects uninitialized registers"),
            }
        }
        // rX += rY → add the two scalar ranges; exact constants propagate
        // because a constant is a range with min == max
        BpfInsn::AddReg { dst, src } => {
            check_reg(pc, *dst)?;
            let (dmin, dmax) = read_scalar(pc, state, *dst)?;
            let (smin, smax) = read_scalar(pc, state, *src)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar {
                min: dmin.wrapping_add(smin),
                max: dmax.wrapping_add(smax),
            };
            Ok(next)
        }
        // r10[offset] = rY → spill the source's full abstract state,
        // including pointers and scalar ranges (#30)
        BpfInsn::StStack { src, offset } => {
            let slot = stack_slot_index(pc, *offset as i32)?;
            let src_state = read_reg(pc, state, *src)?;
            let mut next = *state;
            next.stack.slots[slot] = StackSlot::Spilled(src_state);
            Ok(next)
        }
        // rX = r10[offset] → load a stack slot; a slot must have been
        // written before it is read (write-before-read, #18). The full
        // spilled register state is restored, pointers included (#30).
        BpfInsn::LdStack { dst, offset } => {
            check_reg(pc, *dst)?;
            let slot = stack_slot_index(pc, *offset as i32)?;
            let spilled = match state.stack.slots[slot] {
                StackSlot::Uninit => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "stack slot at offset {} is uninitialized (write before read)",
                            offset
                        ),
                    ));
                }
                StackSlot::Spilled(spilled) => spilled,
            };
            let mut next = *state;
            next.regs[*dst as usize] = spilled;
            Ok(next)
        }
        // helper call: validate R1..R5 against the helper prototype, then
        // apply the eBPF calling convention (#28/#29): R1..R5 are
        // clobbered by the call (kernel's check_helper_call resets them
        // to NOT_INIT), R6..R9 are preserved, and R0 gets the return type
        BpfInsn::Call { imm } => {
            // helper ids are encoded as negative immediates (kernel
            // convention); positive immediates are BPF-to-BPF calls
            let helper = helper_prototype(-*imm)
                .ok_or_else(|| VerificationFailure::new(pc, format!("unknown helper {}", imm)))?;
            check_helper_args(pc, helper, state)?;
            let mut next = *state;
            // argument registers are scratch — invalidated by the call
            for reg in 1..=5 {
                next.regs[reg] = RegState::Uninit;
            }
            next.regs[0] = helper.return_type;
            Ok(next)
        }
    }
}

// ── Branch refinement (v0.2 Micro) ───────────────────────────────────────────

/// A scalar value range [min, max].
pub(crate) type ScalarRange = (i64, i64);

/// Both operands of a comparison refined for one branch side: (dst, src).
type RefinedPair = (ScalarRange, ScalarRange);

/// Refinement result of a comparison: (true branch, false branch).
type RefinedBranches = (RefinedPair, RefinedPair);

/// Refine two scalar ranges on the `dst > src` comparison.
///
/// Both operands are narrowed (cf. the kernel's adjust_scalar_min_max_vals):
///
/// - true branch:  dst >= src.min + 1, src <= dst.max - 1
/// - false branch: dst <= src.max,     src >= dst.min
///
/// A refined range with min > max means the branch is infeasible.
/// Comparisons are interpreted as signed (the kernel splits JGT/JSGT by
/// signedness; our subset has a single `Jgt`).
pub(crate) fn refine_gt(dst: ScalarRange, src: ScalarRange) -> RefinedBranches {
    // true: dst > src
    let true_dst = (dst.0.max(src.0.wrapping_add(1)), dst.1);
    let true_src = (src.0, src.1.min(dst.1.wrapping_sub(1)));
    // false: dst <= src
    let false_dst = (dst.0, dst.1.min(src.1));
    let false_src = (src.0.max(dst.0), src.1);
    ((true_dst, true_src), (false_dst, false_src))
}

/// Refine two scalar ranges on the `dst == src` comparison.
///
/// - true branch: both operands take the intersection of the two ranges
///   (min > max means the branch is infeasible)
/// - false branch: a single interval cannot represent the complement of
///   another interval, so no safe narrowing is possible — both are kept
pub(crate) fn refine_eq(dst: ScalarRange, src: ScalarRange) -> RefinedBranches {
    let inter = (dst.0.max(src.0), dst.1.min(src.1));
    ((inter, inter), (dst, src))
}

// ── Worklist path exploration (v0.3 Mini) ────────────────────────────────────

/// One pending state in the path exploration: an instruction index and
/// the verifier state carried to it (cf. the kernel's verifier stack).
pub(crate) struct WorkItem {
    pub(crate) pc: u32,
    pub(crate) state: VerifierState,
}

/// The conditional comparisons in the mini subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CondOp {
    Eq,
    Gt,
}

/// PC-relative branch target: the offset is relative to the next insn.
pub(crate) fn branch_target(pc: u32, offset: i16) -> u32 {
    (pc as i32 + 1 + offset as i32) as u32
}

/// Static verdict of a comparison over two scalar ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchVerdict {
    /// The condition holds for every concrete value in the ranges.
    AlwaysTaken,
    /// The condition fails for every concrete value in the ranges.
    AlwaysNotTaken,
    /// Both outcomes are possible.
    Unknown,
}

/// Decide whether a conditional branch is statically always taken,
/// never taken, or unknown for the given scalar ranges (cf. the
/// kernel's is_branch_taken()).
pub(crate) fn is_branch_taken(op: CondOp, dst: ScalarRange, src: ScalarRange) -> BranchVerdict {
    match op {
        // dst > src: always true iff dst.min > src.max,
        // always false iff dst.max <= src.min
        CondOp::Gt => {
            if dst.0 > src.1 {
                BranchVerdict::AlwaysTaken
            } else if dst.1 <= src.0 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        // dst == src: always true iff both are the same constant,
        // always false iff the ranges are disjoint
        CondOp::Eq => {
            if dst.0 == dst.1 && src.0 == src.1 && dst.0 == src.0 {
                BranchVerdict::AlwaysTaken
            } else if dst.1 < src.0 || dst.0 > src.1 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
    }
}

/// Expand the instruction at `pc` into its successor (pc, state) pairs.
///
/// Control flow is expanded here, not in `step()` (which is single-state):
/// exit terminates the path, Jmp follows only its target, Jeq/Jgt fork
/// into both branches with scalar range refinement (#16), and everything
/// else falls through via `step()`.
pub(crate) fn successors(
    pc: u32,
    insn: &BpfInsn,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    match insn {
        BpfInsn::Exit => Ok(vec![]),
        BpfInsn::Jmp { offset } => Ok(vec![(branch_target(pc, *offset), *state)]),
        BpfInsn::Jeq { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Eq, state)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Gt, state)
        }
        // everything else falls through via step() (this includes
        // helper calls, which step() validates — #28)
        _ => {
            let next = step(pc, state, insn)?;
            Ok(vec![(pc + 1, next)])
        }
    }
}

/// Fork a conditional branch into taken and fall-through successors.
///
/// Scalar operands are refined on both sides via #16 (like the kernel's
/// check_cond_jmp_op / regs_refine_cond_op); a branch that the static
/// verdict (#24) rules out is not explored at all, mirroring the
/// kernel's is_branch_taken(). A nullable pointer compared to the
/// constant 0 is a NULL check (#27): the taken branch turns it into the
/// scalar 0 (kernel style) and the fall-through refines it to a valid
/// map value pointer (mark_ptr_not_null_reg). Pointers of the same type
/// may be compared for equality without refinement; `>` on pointers and
/// mixed-type comparisons are rejected, mirroring the kernel.
pub(crate) fn cond_branch(
    pc: u32,
    dst: u8,
    src: u8,
    offset: i16,
    op: CondOp,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    let dst_state = read_reg(pc, state, dst)?;
    let src_state = read_reg(pc, state, src)?;
    let taken_pc = branch_target(pc, offset);
    let fall_pc = pc + 1;

    let out = match (dst_state, src_state) {
        (
            RegState::Scalar {
                min: dmin,
                max: dmax,
            },
            RegState::Scalar {
                min: smin,
                max: smax,
            },
        ) => {
            let verdict = is_branch_taken(op, (dmin, dmax), (smin, smax));
            let ((t_dst, t_src), (f_dst, f_src)) = match op {
                CondOp::Eq => refine_eq((dmin, dmax), (smin, smax)),
                CondOp::Gt => refine_gt((dmin, dmax), (smin, smax)),
            };
            let mut out = Vec::with_capacity(2);
            // a statically impossible branch is never explored
            if !matches!(verdict, BranchVerdict::AlwaysNotTaken) {
                let mut taken = *state;
                taken.regs[dst as usize] = RegState::Scalar {
                    min: t_dst.0,
                    max: t_dst.1,
                };
                taken.regs[src as usize] = RegState::Scalar {
                    min: t_src.0,
                    max: t_src.1,
                };
                out.push((taken_pc, taken));
            }
            if !matches!(verdict, BranchVerdict::AlwaysTaken) {
                let mut fall = *state;
                fall.regs[dst as usize] = RegState::Scalar {
                    min: f_dst.0,
                    max: f_dst.1,
                };
                fall.regs[src as usize] = RegState::Scalar {
                    min: f_src.0,
                    max: f_src.1,
                };
                out.push((fall_pc, fall));
            }
            out
        }
        // NULL check: a nullable pointer compared to the constant 0
        (RegState::PtrToMapValueOrNull, RegState::Scalar { min: 0, max: 0 })
        | (RegState::Scalar { min: 0, max: 0 }, RegState::PtrToMapValueOrNull) => {
            let ptr_reg = if matches!(dst_state, RegState::PtrToMapValueOrNull) {
                dst
            } else {
                src
            };
            // taken (== 0): the pointer becomes the constant 0 (kernel
            // style — NULL is a scalar zero, not a pointer type)
            let mut taken = *state;
            taken.regs[ptr_reg as usize] = RegState::Scalar { min: 0, max: 0 };
            // fall (!= 0): refined to a valid map value pointer
            let mut not_null = *state;
            not_null.regs[ptr_reg as usize] = RegState::PtrToMapValue;
            vec![(taken_pc, taken), (fall_pc, not_null)]
        }
        // a non-null map value pointer compared to 0: both branches are
        // kept without refinement (simplified — the kernel marks the
        // taken branch infeasible)
        (RegState::PtrToMapValue, RegState::Scalar { min: 0, max: 0 })
        | (RegState::Scalar { min: 0, max: 0 }, RegState::PtrToMapValue) => {
            vec![(taken_pc, *state), (fall_pc, *state)]
        }
        // pointers of the same type: equality is allowed without
        // refinement; `>` on pointers is not
        (RegState::PtrToStack { .. }, RegState::PtrToStack { .. })
        | (RegState::PtrToCtx, RegState::PtrToCtx)
        | (RegState::PtrToMap, RegState::PtrToMap)
        | (RegState::PtrToMapValue, RegState::PtrToMapValue)
        | (RegState::PtrToMapValueOrNull, RegState::PtrToMapValueOrNull) => match op {
            CondOp::Eq => vec![(taken_pc, *state), (fall_pc, *state)],
            CondOp::Gt => {
                return Err(VerificationFailure::new(
                    pc,
                    format!("comparing pointers r{} > r{} is not allowed", dst, src),
                ));
            }
        },
        // read_reg rejects uninitialized registers before we get here
        (RegState::Uninit, _) | (_, RegState::Uninit) => {
            unreachable!("read_reg rejects uninitialized registers")
        }
        // scalar vs pointer, or pointers of different types
        _ => {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "invalid comparison of r{} with r{} (different types)",
                    dst, src
                ),
            ));
        }
    };

    Ok(out)
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::*;
    use crate::state::*;
    use crate::testutil::*;

    #[test]
    fn step_mov_imm_issue_example() {
        // Before: R2 = Uninit;  r2 = 10;  After: R2 = Scalar(10..10)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        assert_eq!(next.regs[2], RegState::Scalar { min: 10, max: 10 });
        // other registers untouched
        assert_eq!(next.regs[1], RegState::PtrToCtx);
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }

    #[test]
    fn step_mov_imm_overwrites() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 20 }).unwrap();
        assert_eq!(next.regs[2], RegState::Scalar { min: 20, max: 20 });
    }

    #[test]
    fn step_mov_imm_negative() {
        // i32 imm is sign-extended into the i64 scalar range
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: -7 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar { min: -7, max: -7 });
    }

    #[test]
    fn step_mov_reg_copies_scalar() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::MovReg { dst: 3, src: 2 }).unwrap();
        assert_eq!(next.regs[3], RegState::Scalar { min: 10, max: 10 });
    }

    #[test]
    fn step_mov_reg_copies_pointers() {
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::MovReg { dst: 4, src: 1 }).unwrap();
        assert_eq!(next.regs[4], RegState::PtrToCtx);
        let next = step(0, &state, &BpfInsn::MovReg { dst: 5, src: 10 }).unwrap();
        assert_eq!(next.regs[5], RegState::PtrToStack { offset: 0 });
    }

    #[test]
    fn step_mov_reg_uninit_rejected() {
        // issue example: r0 = r2 with R2 uninitialized → REJECT
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::MovReg { dst: 0, src: 2 }).unwrap_err();
        assert!(err.message.contains("r2"));
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_mov_reg_self_copy_uninit_rejected() {
        // r2 = r2 with R2 uninitialized is still a read → REJECT
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::MovReg { dst: 2, src: 2 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_mov_reg_uninit_after_write_ok() {
        // r2 = 10 then r0 = r2 → the read is allowed once written
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::MovReg { dst: 0, src: 2 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar { min: 10, max: 10 });
    }

    #[test]
    fn successors_exit_terminates_path() {
        let state = VerifierState::initial();
        let insn = parse(opcode::EXIT, 0, 0, 0, 0);
        // exit is expanded by successors() — no successors, path ends
        let nexts = successors(0, &insn, &state).unwrap();
        assert!(nexts.is_empty());
    }

    #[test]
    fn step_invalid_register_rejected() {
        let state = VerifierState::initial();
        // dst 11 is out of range (valid: r0..r10)
        let err = step(0, &state, &BpfInsn::MovImm { dst: 11, imm: 1 }).unwrap_err();
        assert!(err.message.contains("invalid register r11"));
        // src 12 is out of range
        let err = step(0, &state, &BpfInsn::MovReg { dst: 0, src: 12 }).unwrap_err();
        assert!(err.message.contains("invalid register r12"));
    }

    #[test]
    fn step_is_pure() {
        // the input state is not mutated
        let state = VerifierState::initial();
        let _ = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        assert_eq!(state.regs[2], RegState::Uninit);
    }

    #[test]
    fn step_add_imm_issue_example() {
        // issue example: r1 = 10; r1 += 20 → R1 = Scalar(30..30)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 20 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 30, max: 30 });
    }

    #[test]
    fn step_add_imm_negative() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: -3 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 7, max: 7 });
    }

    #[test]
    fn step_add_reg_constants() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 5 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 15, max: 15 });
        // the source register is unchanged
        assert_eq!(next.regs[2], RegState::Scalar { min: 5, max: 5 });
    }

    #[test]
    fn step_add_reg_self() {
        // r1 += r1 doubles the value
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 1 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 20, max: 20 });
    }

    #[test]
    fn step_add_imm_range() {
        // range shift, a preview of #16: [0, 100] + 10 → [10, 110]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 0, max: 100 };
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 10, max: 110 });
    }

    #[test]
    fn step_add_reg_ranges() {
        // [0, 100] + [5, 5] → [5, 105]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 0, max: 100 };
        state.regs[2] = RegState::Scalar { min: 5, max: 5 };
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar { min: 5, max: 105 });
    }

    #[test]
    fn step_add_uninit_rejected() {
        // r0 += 1 with R0 uninitialized → #14 error
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::AddImm { dst: 0, imm: 1 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
        // r0 += r2 with R2 uninitialized → #14 error
        let err = step(0, &state, &BpfInsn::AddReg { dst: 0, src: 2 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_add_ptr_rejected() {
        // r1 += 10 with R1 = PtrToCtx → arithmetic on a context pointer is rejected
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap_err();
        assert!(err.message.contains("context pointer"));
        // r0 += r10 with R10 = PtrToStack → register-offset pointer arithmetic is rejected
        let state = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: 1 }).unwrap();
        let err = step(0, &state, &BpfInsn::AddReg { dst: 0, src: 10 }).unwrap_err();
        assert!(err.message.contains("register-offset"));
        // r10 += r1 with R1 = PtrToCtx → a pointer destination is rejected too
        let err = step(0, &state, &BpfInsn::AddReg { dst: 10, src: 1 }).unwrap_err();
        assert!(err.message.contains("register-offset"));
    }

    // ── Pointer arithmetic (v0.2) ────────────────────────────────────────────

    #[test]
    fn step_add_imm_ptr_stack() {
        // r10 += -8 → PtrToStack(-8): the frame pointer moves down one slot
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: -8 });
    }

    #[test]
    fn step_add_imm_ptr_stack_chain() {
        // r10 += -8; r10 += -8 → offset -16
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: -16 });
    }

    #[test]
    fn step_add_imm_ptr_stack_copied_reg() {
        // r5 = r10; r5 += -16 → a copied stack pointer moves independently
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovReg { dst: 5, src: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 5, imm: -16 }).unwrap();
        assert_eq!(next.regs[5], RegState::PtrToStack { offset: -16 });
        // the frame pointer itself is untouched
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }

    #[test]
    fn step_add_imm_ptr_stack_out_of_frame() {
        // r10 += 8 → offset 8 points above the frame → REJECT
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: 8 }).unwrap_err();
        assert!(err.message.contains("out of the"));
        // r10 += -520 → offset -520 exceeds the frame → REJECT
        let err = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -520 }).unwrap_err();
        assert!(err.message.contains("out of the"));
    }

    #[test]
    fn step_add_imm_ptr_stack_bounds_edges() {
        // offset -512 is the last valid slot; one step past it → REJECT
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -512 }).unwrap();
        assert_eq!(state.regs[10], RegState::PtrToStack { offset: -512 });
        let err = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -1 }).unwrap_err();
        assert!(err.message.contains("out of the"));
    }

    #[test]
    fn step_add_imm_ptr_stack_zero() {
        // adding 0 keeps the pointer (no-op)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: 0 }).unwrap();
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }

    // ── Trace (v0.2) ─────────────────────────────────────────────────────────

    #[test]
    fn refine_gt_issue_example() {
        // issue example: R1 = [0, 100]; if R1 > 50
        // true: R1 = [51, 100], false: R1 = [0, 50]
        let ((true_dst, true_src), (false_dst, false_src)) = refine_gt((0, 100), (50, 50));
        assert_eq!(true_dst, (51, 100));
        assert_eq!(true_src, (50, 50));
        assert_eq!(false_dst, (0, 50));
        assert_eq!(false_src, (50, 50));
    }

    #[test]
    fn refine_gt_both_ranges() {
        // dst = [0, 100], src = [20, 200]: on the true branch both operands
        // narrow (dst >= src.min + 1, src <= dst.max - 1)
        let ((true_dst, true_src), (false_dst, false_src)) = refine_gt((0, 100), (20, 200));
        assert_eq!(true_dst, (21, 100));
        assert_eq!(true_src, (20, 99));
        // the false branch adds no constraint here (dst <= 200, src >= 0
        // are already implied by the ranges)
        assert_eq!(false_dst, (0, 100));
        assert_eq!(false_src, (20, 200));
    }

    #[test]
    fn refine_gt_self() {
        // r1 > r1 with r1 = [0, 100]: both sides of the comparison are
        // refined, so the true branch narrows to the empty range
        let ((true_dst, true_src), (false_dst, false_src)) = refine_gt((0, 100), (0, 100));
        assert_eq!(true_dst, (1, 100));
        assert_eq!(true_src, (0, 99));
        assert_eq!(false_dst, (0, 100));
        assert_eq!(false_src, (0, 100));
    }

    #[test]
    fn refine_gt_infeasible_true_branch() {
        // dst = [0, 100] vs src = [100, 100]: dst > 100 is impossible,
        // so the true branch narrows to an empty range (min > max)
        let ((true_dst, _), _) = refine_gt((0, 100), (100, 100));
        assert!(true_dst.0 > true_dst.1);
    }

    #[test]
    fn refine_eq_intersection() {
        // dst = [0, 100], src = [40, 60]: equality means both must be in [40, 60]
        let ((true_dst, true_src), (false_dst, false_src)) = refine_eq((0, 100), (40, 60));
        assert_eq!(true_dst, (40, 60));
        assert_eq!(true_src, (40, 60));
        // false branch keeps both ranges (no safe single-interval narrowing)
        assert_eq!(false_dst, (0, 100));
        assert_eq!(false_src, (40, 60));
    }

    #[test]
    fn refine_eq_disjoint() {
        // disjoint ranges: equality is impossible → true branch is empty
        let ((true_dst, true_src), _) = refine_eq((0, 10), (20, 30));
        assert!(true_dst.0 > true_dst.1);
        assert!(true_src.0 > true_src.1);
    }

    #[test]
    fn refine_eq_constants() {
        // two constants: r1 = 5, r2 = 5 → true branch keeps 5..5
        let ((true_dst, _), _) = refine_eq((5, 5), (5, 5));
        assert_eq!(true_dst, (5, 5));
    }

    #[test]
    fn refine_gt_extremes() {
        // wrapping at i64 extremes stays sound (never panics)
        let ((true_dst, true_src), _) = refine_gt((i64::MIN, i64::MAX), (0, 0));
        assert_eq!(true_dst, (1, i64::MAX));
        // src.max = 0 is already below dst.max - 1, so src stays [0, 0]
        assert_eq!(true_src, (0, 0));
        // src.min + 1 wraps to i64::MIN; dst is kept soundly (the branch is
        // actually infeasible, but over-approximation is allowed)
        let ((true_dst, _), _) = refine_gt((0, i64::MAX), (i64::MAX, i64::MAX));
        assert_eq!(true_dst.0, 0);
        // dst.max - 1 wraps when dst.max = i64::MIN; dst stays [MIN, MIN] so
        // the true branch narrows to an empty range (dst > src is impossible)
        let ((true_dst, _), _) = refine_gt((i64::MIN, i64::MIN), (i64::MIN, i64::MIN));
        assert!(true_dst.0 > true_dst.1);
    }

    // ── add_subprog / register_subprog ───────────────────────────────────────

    #[test]
    fn successors_jgt_refines_issue_example() {
        // issue #16 example wired through the driver: R1 = [0, 100]; if R1 > 50
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 0, max: 100 };
        state.regs[2] = RegState::Scalar { min: 50, max: 50 };

        let nexts = successors(
            0,
            &BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);

        // taken: pc = 0 + 1 + 1 = 2, R1 = [51, 100]
        let (taken_pc, taken) = &nexts[0];
        assert_eq!(*taken_pc, 2);
        assert_eq!(taken.regs[1], RegState::Scalar { min: 51, max: 100 });
        // fall: pc = 1, R1 = [0, 50]
        let (fall_pc, fall) = &nexts[1];
        assert_eq!(*fall_pc, 1);
        assert_eq!(fall.regs[1], RegState::Scalar { min: 0, max: 50 });
    }

    #[test]
    fn successors_jeq_pointer_equality_allowed() {
        // comparing a context pointer with itself: two successors, no refinement
        let state = VerifierState::initial();
        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 1,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        assert_eq!(nexts[0].1, state);
        assert_eq!(nexts[1].1, state);
    }

    #[test]
    fn successors_jgt_pointer_rejected() {
        // > on stack pointers is not allowed
        let state = VerifierState::initial();
        let err = successors(
            0,
            &BpfInsn::Jgt {
                dst: 10,
                src: 10,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("comparing pointers"));
    }

    #[test]
    fn successors_mixed_types_rejected() {
        // context pointer vs stack pointer comparison is invalid
        let state = VerifierState::initial();
        let err = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 10,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("different types"));
    }

    #[test]
    fn successors_uninit_operand_rejected() {
        // r2 is uninitialized at entry → #14 error
        let state = VerifierState::initial();
        let err = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn is_branch_taken_gt() {
        // always true: dst.min > src.max
        assert!(matches!(
            is_branch_taken(CondOp::Gt, (30, 40), (10, 20)),
            BranchVerdict::AlwaysTaken
        ));
        // always false: dst.max <= src.min (boundary included)
        assert!(matches!(
            is_branch_taken(CondOp::Gt, (10, 20), (20, 30)),
            BranchVerdict::AlwaysNotTaken
        ));
        // overlapping ranges → unknown
        assert!(matches!(
            is_branch_taken(CondOp::Gt, (0, 100), (50, 50)),
            BranchVerdict::Unknown
        ));
    }

    #[test]
    fn is_branch_taken_eq() {
        // both the same constant → always taken
        assert!(matches!(
            is_branch_taken(CondOp::Eq, (5, 5), (5, 5)),
            BranchVerdict::AlwaysTaken
        ));
        // disjoint ranges → never taken
        assert!(matches!(
            is_branch_taken(CondOp::Eq, (0, 10), (20, 30)),
            BranchVerdict::AlwaysNotTaken
        ));
        // overlapping ranges → unknown
        assert!(matches!(
            is_branch_taken(CondOp::Eq, (0, 100), (40, 60)),
            BranchVerdict::Unknown
        ));
        // a non-constant range is never 'always taken'
        assert!(matches!(
            is_branch_taken(CondOp::Eq, (5, 7), (5, 5)),
            BranchVerdict::Unknown
        ));
    }

    #[test]
    fn successors_jgt_always_taken() {
        // dst = [30, 40] > src = [10, 20] is always true → only taken
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 30, max: 40 };
        state.regs[2] = RegState::Scalar { min: 10, max: 20 };
        let nexts = successors(
            0,
            &BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 2);
    }

    #[test]
    fn successors_jgt_never_taken() {
        // dst = [10, 20] > src = [30, 40] is always false → only fall-through
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 10, max: 20 };
        state.regs[2] = RegState::Scalar { min: 30, max: 40 };
        let nexts = successors(
            0,
            &BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 1);
    }

    #[test]
    fn successors_jeq_always_taken() {
        // r1 == r2 with both constant 5 → only the taken successor
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar { min: 5, max: 5 };
        state.regs[2] = RegState::Scalar { min: 5, max: 5 };
        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 2);
    }

    #[test]
    fn successors_null_check_issue_example() {
        // issue example: r0 = PtrToMapValueOrNull; if r0 == 0 (via r1 = 0)
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        state.regs[1] = RegState::Scalar { min: 0, max: 0 };

        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 0,
                src: 1,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);

        // taken (r0 == 0): the pointer becomes the constant 0 (kernel style)
        let (taken_pc, taken) = &nexts[0];
        assert_eq!(*taken_pc, 2);
        assert_eq!(taken.regs[0], RegState::Scalar { min: 0, max: 0 });
        // fall (r0 != 0): refined to a valid map value pointer
        let (fall_pc, fall) = &nexts[1];
        assert_eq!(*fall_pc, 1);
        assert_eq!(fall.regs[0], RegState::PtrToMapValue);
    }

    #[test]
    fn successors_null_check_reversed_operands() {
        // the constant 0 may also be the dst register: if r1 == r0 with r1 = 0
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        state.regs[1] = RegState::Scalar { min: 0, max: 0 };
        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 0,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        assert_eq!(nexts[0].1.regs[0], RegState::Scalar { min: 0, max: 0 });
        assert_eq!(nexts[1].1.regs[0], RegState::PtrToMapValue);
    }

    #[test]
    fn successors_null_check_nonzero_scalar_rejected() {
        // only the constant 0 enables a NULL check; other scalars keep the
        // different-types rejection
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        state.regs[1] = RegState::Scalar { min: 8, max: 8 };
        let err = successors(
            0,
            &BpfInsn::Jeq {
                dst: 0,
                src: 1,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("different types"));
    }

    #[test]
    fn successors_map_value_vs_zero_both_branches() {
        // a non-null map value pointer compared to 0 keeps both branches
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue;
        state.regs[1] = RegState::Scalar { min: 0, max: 0 };
        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 0,
                src: 1,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        assert_eq!(nexts[0].1, state);
        assert_eq!(nexts[1].1, state);
    }

    #[test]
    fn successors_same_type_map_pointers() {
        // equality is allowed without refinement, > is not
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue;
        let nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 0,
                src: 0,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        assert_eq!(nexts[0].1, state);

        let err = successors(
            0,
            &BpfInsn::Jgt {
                dst: 0,
                src: 0,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("comparing pointers"));
    }

    #[test]
    fn step_add_imm_nullable_ptr_rejected() {
        // arithmetic on a nullable pointer is rejected until the NULL check
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        let err = step(0, &state, &BpfInsn::AddImm { dst: 0, imm: 8 }).unwrap_err();
        assert!(err.message.contains("NULL"));
    }

    #[test]
    fn step_add_imm_map_value_ptr_rejected() {
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue;
        let err = step(0, &state, &BpfInsn::AddImm { dst: 0, imm: 8 }).unwrap_err();
        assert!(err.message.contains("map value pointer"));
    }

    // ── Helpers (v0.3) ──────────────────────────────────────────────────────

    #[test]
    fn step_call_map_lookup_ok() {
        // R1 = map pointer, R2 = key pointer → after the call R0 is the
        // nullable map value pointer (#27's producer) and the argument
        // registers are clobbered (#29)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        state.regs[2] = RegState::PtrToStack { offset: -8 };
        let next = step(0, &state, &BpfInsn::Call { imm: -1 }).unwrap();
        assert_eq!(next.regs[0], RegState::PtrToMapValueOrNull);
        assert_eq!(next.regs[1], RegState::Uninit);
        assert_eq!(next.regs[2], RegState::Uninit);
    }

    #[test]
    fn step_call_prandom() {
        // no arguments → R0 becomes an unknown scalar (full range)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::Call { imm: -7 }).unwrap();
        assert_eq!(
            next.regs[0],
            RegState::Scalar {
                min: i64::MIN,
                max: i64::MAX
            }
        );
    }

    #[test]
    fn step_call_map_update_ok() {
        // map_update(map, key, value, flags): all four args validated,
        // returns 0 on success
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        state.regs[2] = RegState::PtrToStack { offset: -8 };
        state.regs[3] = RegState::PtrToStack { offset: -16 };
        state.regs[4] = RegState::Scalar { min: 0, max: 0 };
        let next = step(0, &state, &BpfInsn::Call { imm: -2 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar { min: 0, max: 0 });
    }

    #[test]
    fn step_call_map_update_missing_value() {
        // R3 (the value pointer) is uninitialized → #14 error
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        state.regs[2] = RegState::PtrToStack { offset: -8 };
        let err = step(0, &state, &BpfInsn::Call { imm: -2 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_call_arg_mismatch() {
        // R1 is the context pointer, not a map pointer → rejected
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::Call { imm: -1 }).unwrap_err();
        assert!(err.message.contains("expected PtrToMap"));
        assert!(err.message.contains("r1 has type PTR_CTX"));
    }

    #[test]
    fn step_call_unknown_helper() {
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::Call { imm: -99 }).unwrap_err();
        assert!(err.message.contains("unknown helper -99"));
    }

    #[test]
    fn step_call_uninit_arg() {
        // R2 (the key pointer) is uninitialized → #14 error
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        let err = step(0, &state, &BpfInsn::Call { imm: -1 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_call_clobbers_r1_to_r5_preserves_r6_to_r9() {
        // the eBPF calling convention: R1..R5 are scratch, R6..R9 callee-saved
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        state.regs[2] = RegState::PtrToStack { offset: -8 };
        state.regs[3] = RegState::Scalar { min: 1, max: 1 };
        state.regs[4] = RegState::Scalar { min: 2, max: 2 };
        state.regs[5] = RegState::Scalar { min: 3, max: 3 };
        state.regs[6] = RegState::Scalar { min: 10, max: 10 };
        state.regs[7] = RegState::Scalar { min: 11, max: 11 };
        state.regs[8] = RegState::Scalar { min: 12, max: 12 };
        state.regs[9] = RegState::Scalar { min: 13, max: 13 };

        let next = step(0, &state, &BpfInsn::Call { imm: -1 }).unwrap();
        // R0 = return type, R1..R5 invalidated
        assert_eq!(next.regs[0], RegState::PtrToMapValueOrNull);
        for reg in 1..=5 {
            assert_eq!(next.regs[reg], RegState::Uninit, "r{}", reg);
        }
        // R6..R9 and the frame pointer are preserved
        for (reg, val) in [(6, 10), (7, 11), (8, 12), (9, 13)] {
            assert_eq!(
                next.regs[reg],
                RegState::Scalar { min: val, max: val },
                "r{}",
                reg
            );
        }
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }
}
