// ── Concrete execution state model (v0.5 Concrete, #49) ─────────────────────

//! Concrete counterpart of the abstract [`VerifierState`]: the same program
//! executed with real values, so the abstract state can be checked to
//! always cover the concrete results (Phase 2).
//!
//! The containment test mirrors [`crate::mini::reg_subsumes`] (abstract ⊇
//! abstract) with the direction reversed: does the abstract state contain
//! this actual value? Since #50 the concrete side is type-aware — a scalar
//! holding the same bits as a stack address is not a stack pointer.

use std::collections::HashMap;

use crate::exec::{AluOp, AluWidth, CondOp, alu_const32, alu_const64, branch_target};
use crate::helper::{ArgType, HelperPrototype, helper_prototype};
use crate::insn::{BpfInsn, disassemble};
use crate::state::{
    ALIGN_UNKNOWN, NUM_REGS, RegState, STACK_SIZE, STACK_SLOT_SIZE, STACK_SLOTS, ScalarBounds,
    StackSlot, VerifierState,
};
use crate::tnum::Tnum;

/// Fixed virtual address of the stack frame base (R10), arbitrary but
/// disjoint from every other address class. The 512-byte frame spans
/// `STACK_BASE - 512 .. STACK_BASE`.
pub(crate) const STACK_BASE: u64 = 0x1000;

/// Fixed virtual address of the program context (R1 at entry).
pub(crate) const CTX_BASE: u64 = 0x2000;

/// A concrete register value, with the pointer-ness the abstract side
/// tracks as a type. The kind is preserved by register moves and stack
/// spill/fill, so pointer arithmetic is rejected like the abstract
/// rejects it (#20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConcreteValue {
    Scalar(u64),
    /// Pointer into the stack frame: `value = STACK_BASE + offset`, the
    /// concrete counterpart of `RegState::PtrToStack`.
    StackPtr(u64),
    /// The context pointer, the concrete counterpart of `RegState::PtrToCtx`.
    CtxPtr(u64),
}

/// Concrete register/stack state: `None` = uninitialized, mirroring the
/// abstract `RegState::Uninit` / `StackSlot::Uninit` slots 1:1.
///
/// `Option<ConcreteValue>` keeps the correspondence exact: a concrete
/// value where the abstract side is uninitialized is an immediate
/// coverage violation (#52), so no value is ever invented for an
/// uninitialized register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConcreteState {
    pub(crate) regs: [Option<ConcreteValue>; NUM_REGS],
    /// One slot per 8-byte cell of the 512-byte frame, like the abstract
    /// `StackState`.
    pub(crate) stack: [Option<ConcreteValue>; STACK_SLOTS],
}

impl ConcreteState {
    /// Initial state at program entry, mirroring the abstract
    /// `initial_reg_state()`: R1 = context pointer, R10 = frame pointer,
    /// everything else (registers and stack) uninitialized. Argument
    /// seeds arrive with helper-call modeling (#51), not at entry.
    pub(crate) fn initial() -> Self {
        let mut regs = [None; NUM_REGS];
        regs[1] = Some(ConcreteValue::CtxPtr(CTX_BASE));
        regs[10] = Some(ConcreteValue::StackPtr(STACK_BASE));
        Self {
            regs,
            stack: [None; STACK_SLOTS],
        }
    }
}

/// A concrete execution failure, mirroring the abstract REJECT reasons
/// one-to-one (the concrete counterpart of [`crate::error::VerificationFailure`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConcreteFailure {
    /// Reading a register that was never written (#14).
    UninitializedRead { pc: u32, reg: u8 },
    /// Writing to a register number outside r0..r10.
    InvalidRegister { pc: u32, reg: u8 },
    /// Stack access outside the frame: `offset >= 0` or `< -512` (#19).
    StackOutOfFrame { pc: u32, offset: i32 },
    /// Stack access that is not 8-byte aligned (#19).
    MisalignedStackAccess { pc: u32, offset: i32 },
    /// Reading a stack slot before it was written (#18).
    UninitializedStackRead { pc: u32, offset: i32 },
    /// Arithmetic on a pointer-typed register (#20).
    PointerArithmetic { pc: u32, reg: u8 },
    /// Stack pointer arithmetic that leaves the frame (#19).
    StackPointerOutOfFrame { pc: u32, reg: u8 },
    /// A shift amount outside the accepted range (mirrors the abstract
    /// 0..64 check for both widths, `check_shift_amount`).
    InvalidShiftAmount { pc: u32, amount: u64 },
    /// An unknown helper id (mirrors the abstract "unknown helper").
    UnknownHelper { pc: u32, imm: i32 },
    /// A helper argument that does not match the prototype (mirrors
    /// `check_helper_args`, #28).
    HelperArgMismatch { pc: u32, arg: u8 },
    /// A comparison the abstract rejects: pointer ordering or mixed
    /// pointer/scalar types (mirrors `cond_branch`).
    InvalidComparison { pc: u32, dst: u8, src: u8 },
    /// An immediate-form comparison the abstract rejects: a pointer
    /// compared to an immediate (mirrors `cond_branch_imm`).
    InvalidComparisonImm { pc: u32, dst: u8 },
    /// A helper whose abstract return type has no concrete counterpart
    /// yet (pointer returns). Unreachable for the current corpus —
    /// map_lookup fixtures fail at argument validation.
    UnsupportedHelperReturn { pc: u32, imm: i32 },
    /// A jump target outside the program (defensive: the structural
    /// pass rejects invalid targets before this driver runs).
    InternalError { pc: u32 },
}

impl std::fmt::Display for ConcreteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UninitializedRead { pc, reg } => {
                write!(f, "at insn {}: register r{} is uninitialized", pc, reg)
            }
            Self::InvalidRegister { pc, reg } => {
                write!(f, "at insn {}: invalid register r{}", pc, reg)
            }
            Self::StackOutOfFrame { pc, offset } => write!(
                f,
                "at insn {}: stack access at r10{:+} is out of the frame",
                pc, offset
            ),
            Self::MisalignedStackAccess { pc, offset } => write!(
                f,
                "at insn {}: stack access at r10{:+} is not 8-byte aligned",
                pc, offset
            ),
            Self::UninitializedStackRead { pc, offset } => write!(
                f,
                "at insn {}: stack slot at r10{:+} is uninitialized (write before read)",
                pc, offset
            ),
            Self::PointerArithmetic { pc, reg } => {
                write!(f, "at insn {}: arithmetic on pointer r{}", pc, reg)
            }
            Self::StackPointerOutOfFrame { pc, reg } => {
                write!(f, "at insn {}: stack pointer r{} left the frame", pc, reg)
            }
            Self::InvalidShiftAmount { pc, amount } => {
                write!(f, "at insn {}: invalid shift amount {}", pc, amount)
            }
            Self::UnknownHelper { pc, imm } => write!(f, "at insn {}: unknown helper {}", pc, imm),
            Self::HelperArgMismatch { pc, arg } => {
                write!(
                    f,
                    "at insn {}: helper argument r{} has the wrong type",
                    pc, arg
                )
            }
            Self::InvalidComparison { pc, dst, src } => {
                write!(
                    f,
                    "at insn {}: invalid comparison of r{} and r{}",
                    pc, dst, src
                )
            }
            Self::InvalidComparisonImm { pc, dst } => {
                write!(
                    f,
                    "at insn {}: invalid comparison of r{} with an immediate",
                    pc, dst
                )
            }
            Self::UnsupportedHelperReturn { pc, imm } => {
                write!(
                    f,
                    "at insn {}: helper {} return type has no concrete model",
                    pc, imm
                )
            }
            Self::InternalError { pc } => write!(f, "at insn {}: internal error", pc),
        }
    }
}

/// Does the tnum admit the value? The known bits (`!mask`) must match;
/// the unknown bits (`mask`) may be anything (kernel tnum semantics).
fn tnum_contains(t: Tnum, value: u64) -> bool {
    (value & !t.mask) == (t.value & !t.mask)
}

/// The value-level part of `abstract_covers` for scalars: both
/// interpretations plus the tnum must admit the value. The 32-bit views
/// are derived from the 64-bit ones by the sync (#41), so re-checking
/// them is redundant.
fn scalar_covers(bounds: ScalarBounds, value: u64) -> bool {
    (bounds.smin..=bounds.smax).contains(&(value as i64))
        && (bounds.umin..=bounds.umax).contains(&value)
        && tnum_contains(bounds.tnum, value)
}

/// The value-level part of `abstract_covers` for stack pointers: the
/// offset must fall inside the tracked range and match `align_off`
/// (mod 8, #45).
fn stack_ptr_covers(min_offset: i32, max_offset: i32, align_off: u8, value: u64) -> bool {
    let offset = value.wrapping_sub(STACK_BASE) as i64;
    (min_offset as i64..=max_offset as i64).contains(&offset)
        && (align_off == ALIGN_UNKNOWN || offset.rem_euclid(8) as u8 == align_off)
}

/// Does the abstract register state contain the concrete value?
///
/// The reverse direction of `reg_subsumes`: the abstract side must be at
/// least as broad as the actual value, never narrower. Type-aware since
/// #50: only matching kinds are compared — scalar bits are not a pointer
/// and a pointer value is not a scalar.
pub(crate) fn abstract_covers(reg: RegState, value: ConcreteValue) -> bool {
    match (reg, value) {
        // a concrete value where the abstract side is uninitialized can
        // never be covered — the abstract side must be initialized too
        (RegState::Uninit, _) => false,
        (RegState::Scalar(bounds), ConcreteValue::Scalar(v)) => scalar_covers(bounds, v),
        (
            RegState::PtrToStack {
                min_offset,
                max_offset,
                align_off,
            },
            ConcreteValue::StackPtr(v),
        ) => stack_ptr_covers(min_offset, max_offset, align_off, v),
        (RegState::PtrToCtx, ConcreteValue::CtxPtr(v)) => v == CTX_BASE,
        // type mismatches are never covered
        (RegState::Scalar(_), _)
        | (RegState::PtrToStack { .. }, _)
        | (RegState::PtrToCtx, _)
        | (RegState::PtrToMap, _)
        | (RegState::PtrToMapValue, _)
        | (RegState::PtrToMapValueOrNull, _) => false,
    }
}

/// Does the abstract state cover the whole concrete state — every
/// register and every stack slot?
///
/// Slot-level granularity mirrors the abstract stack (`StackState`):
/// an uninitialized slot pairs with `None`, a spilled register with
/// `Some(value)` plus `abstract_covers` on the spilled state.
pub(crate) fn state_covers(abstract_state: &VerifierState, concrete: &ConcreteState) -> bool {
    abstract_state
        .regs
        .iter()
        .zip(&concrete.regs)
        .all(|(abstract_reg, value)| match value {
            None => matches!(abstract_reg, RegState::Uninit),
            Some(value) => abstract_covers(*abstract_reg, *value),
        })
        && abstract_state
            .stack
            .slots
            .iter()
            .zip(&concrete.stack)
            .all(|(abstract_slot, value)| match (abstract_slot, value) {
                (StackSlot::Uninit, None) => true,
                (StackSlot::Spilled(reg), Some(value)) => abstract_covers(*reg, *value),
                _ => false,
            })
}

// ── Concrete instruction execution (#50) ────────────────────────────────────

/// Validate a register number used as a write destination.
fn check_concrete_reg(pc: u32, reg: u8) -> Result<(), ConcreteFailure> {
    if reg as usize >= NUM_REGS {
        Err(ConcreteFailure::InvalidRegister { pc, reg })
    } else {
        Ok(())
    }
}

/// Read a register's concrete value; the register must have been written
/// before it is read (#14).
fn read_concrete_reg(
    pc: u32,
    state: &ConcreteState,
    reg: u8,
) -> Result<ConcreteValue, ConcreteFailure> {
    check_concrete_reg(pc, reg)?;
    match state.regs[reg as usize] {
        None => Err(ConcreteFailure::UninitializedRead { pc, reg }),
        Some(value) => Ok(value),
    }
}

/// Map an r10-relative stack offset to a slot index, mirroring the
/// abstract `stack_slot_index` checks (#19): offsets must point into the
/// frame (r10-512..r10-8) and be 8-byte aligned.
fn concrete_stack_slot(pc: u32, offset: i32) -> Result<usize, ConcreteFailure> {
    if offset >= 0 || offset < -(STACK_SIZE as i32) {
        return Err(ConcreteFailure::StackOutOfFrame { pc, offset });
    }
    if offset % (STACK_SLOT_SIZE as i32) != 0 {
        return Err(ConcreteFailure::MisalignedStackAccess { pc, offset });
    }
    Ok(((-offset) as usize - 8) / STACK_SLOT_SIZE)
}

/// The exact bit-level ALU result for a width: delegates to the same
/// helpers the abstract side uses for constants, so both sides share
/// one operation definition.
fn alu_value(op: AluOp, width: AluWidth, a: u64, b: u64) -> u64 {
    match width {
        AluWidth::W64 => alu_const64(op, a, b),
        AluWidth::W32 => alu_const32(op, a, b),
    }
}

/// The frame-validity check shared by both pointer-ADD paths: the new
/// offset must stay within `r10-512..=r10` (mirrors the abstract
/// `add_scalar_to_stack_ptr` frame check). Overflowing the addition
/// means the offset is certainly out of the frame.
fn stack_ptr_offset_ok(offset: i64) -> bool {
    (-(STACK_SIZE as i64)..=0).contains(&offset)
}

/// Execute an ALU operation with an immediate operand.
///
/// Mirrors the abstract `alu_imm`: shifts require an amount in 0..64 for
/// both widths; a stack pointer accepts only ADD (which must stay in the
/// frame); every other pointer rejects arithmetic (#20).
fn concrete_alu_imm(
    pc: u32,
    state: &ConcreteState,
    dst: u8,
    imm: i32,
    op: AluOp,
    width: AluWidth,
) -> Result<ConcreteState, ConcreteFailure> {
    check_concrete_reg(pc, dst)?;
    // shifts require an amount below the width (mirror of the abstract
    // alu_imm check — kernel: "< 64 range, for 32-bit < 32 range")
    let bitness: i32 = match width {
        AluWidth::W64 => 64,
        AluWidth::W32 => 32,
    };
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && !(0..bitness).contains(&imm) {
        return Err(ConcreteFailure::InvalidShiftAmount {
            pc,
            amount: imm as i64 as u64,
        });
    }
    let dst_value = read_concrete_reg(pc, state, dst)?;
    match dst_value {
        ConcreteValue::Scalar(d) => {
            let result = alu_value(op, width, d, imm as i64 as u64);
            let mut next = *state;
            next.regs[dst as usize] = Some(ConcreteValue::Scalar(result));
            Ok(next)
        }
        // stack pointer + immediate: only ADD is allowed (#20), and the
        // result must stay within the frame (#19)
        ConcreteValue::StackPtr(v) => {
            if op != AluOp::Add || width != AluWidth::W64 {
                return Err(ConcreteFailure::PointerArithmetic { pc, reg: dst });
            }
            let offset = v as i64 - STACK_BASE as i64 + imm as i64;
            if !stack_ptr_offset_ok(offset) {
                return Err(ConcreteFailure::StackPointerOutOfFrame { pc, reg: dst });
            }
            let mut next = *state;
            next.regs[dst as usize] =
                Some(ConcreteValue::StackPtr((STACK_BASE as i64 + offset) as u64));
            Ok(next)
        }
        ConcreteValue::CtxPtr(_) => Err(ConcreteFailure::PointerArithmetic { pc, reg: dst }),
    }
}

/// Execute an ALU operation with a register operand.
///
/// Mirrors the abstract `alu_reg`: both operands must be scalars, except
/// that a stack pointer plus a scalar ADD is allowed when the computed
/// offset provably stays in the frame (#45). Concrete offsets are exact,
/// so the abstract #45 provable-alignment condition (a range-only
/// requirement) is trivially satisfied here.
fn concrete_alu_reg(
    pc: u32,
    state: &ConcreteState,
    dst: u8,
    src: u8,
    op: AluOp,
    width: AluWidth,
) -> Result<ConcreteState, ConcreteFailure> {
    check_concrete_reg(pc, dst)?;
    let dst_value = read_concrete_reg(pc, state, dst)?;
    let src_value = read_concrete_reg(pc, state, src)?;
    match (dst_value, src_value) {
        (ConcreteValue::Scalar(d), ConcreteValue::Scalar(s)) => {
            // shifts require an amount below the width (mirror of the
            // abstract check_shift_amount, which collapses to
            // s >= bitness for a single value)
            let bitness = match width {
                AluWidth::W64 => 64,
                AluWidth::W32 => 32,
            };
            if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && s >= bitness as u64 {
                return Err(ConcreteFailure::InvalidShiftAmount { pc, amount: s });
            }
            let result = alu_value(op, width, d, s);
            let mut next = *state;
            next.regs[dst as usize] = Some(ConcreteValue::Scalar(result));
            Ok(next)
        }
        // computed stack pointer arithmetic (#45): only ADD, and the
        // result must stay within the frame
        (ConcreteValue::StackPtr(v), ConcreteValue::Scalar(s)) => {
            if op != AluOp::Add || width != AluWidth::W64 {
                return Err(ConcreteFailure::PointerArithmetic { pc, reg: dst });
            }
            let offset = match (v as i64)
                .checked_sub(STACK_BASE as i64)
                .and_then(|o| o.checked_add(s as i64))
            {
                Some(offset) => offset,
                None => return Err(ConcreteFailure::StackPointerOutOfFrame { pc, reg: dst }),
            };
            if !stack_ptr_offset_ok(offset) {
                return Err(ConcreteFailure::StackPointerOutOfFrame { pc, reg: dst });
            }
            let mut next = *state;
            next.regs[dst as usize] =
                Some(ConcreteValue::StackPtr((STACK_BASE as i64 + offset) as u64));
            Ok(next)
        }
        // every other combination is pointer arithmetic (#20)
        _ => Err(ConcreteFailure::PointerArithmetic { pc, reg: dst }),
    }
}

/// Execute a single instruction on the concrete state, producing the
/// next state — the concrete counterpart of the abstract `step()`.
///
/// Control flow (jumps, compares, exit) and helper calls are expanded by
/// the path explorer (#51) and never reach this function, mirroring the
/// abstract `step()`/`successors()` split.
#[allow(dead_code)] // used by the path explorer (#51); used by tests
pub(crate) fn concrete_step(
    pc: u32,
    state: &ConcreteState,
    insn: &BpfInsn,
) -> Result<ConcreteState, ConcreteFailure> {
    match insn {
        // rX = imm → the sign-extended constant (both interpretations
        // carry the same bits, #40)
        BpfInsn::MovImm { dst, imm } => {
            check_concrete_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = Some(ConcreteValue::Scalar(*imm as i64 as u64));
            Ok(next)
        }
        // rX = rY → copy the value and its pointer kind; the source must
        // have been written before it is read (#14)
        BpfInsn::MovReg { dst, src } => {
            check_concrete_reg(pc, *dst)?;
            let value = read_concrete_reg(pc, state, *src)?;
            let mut next = *state;
            next.regs[*dst as usize] = Some(value);
            Ok(next)
        }
        // terminal, control flow and helper calls are expanded by the
        // path explorer (#51); reaching them here is a driver bug
        BpfInsn::Exit
        | BpfInsn::Jmp { .. }
        | BpfInsn::Jeq { .. }
        | BpfInsn::Jne { .. }
        | BpfInsn::Jgt { .. }
        | BpfInsn::Jge { .. }
        | BpfInsn::Jlt { .. }
        | BpfInsn::Jle { .. }
        | BpfInsn::Jsgt { .. }
        | BpfInsn::Jsge { .. }
        | BpfInsn::Jslt { .. }
        | BpfInsn::Jsle { .. }
        | BpfInsn::JeqImm { .. }
        | BpfInsn::JneImm { .. }
        | BpfInsn::JgtImm { .. }
        | BpfInsn::JgeImm { .. }
        | BpfInsn::JltImm { .. }
        | BpfInsn::JleImm { .. }
        | BpfInsn::JsgtImm { .. }
        | BpfInsn::JsgeImm { .. }
        | BpfInsn::JsltImm { .. }
        | BpfInsn::JsleImm { .. }
        | BpfInsn::Call { .. } => {
            unreachable!(
                "exit, control flow and calls are expanded by the explorer (#51), not concrete_step()"
            )
        }
        // ALU64
        BpfInsn::AddImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Add, AluWidth::W64)
        }
        BpfInsn::AddReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Add, AluWidth::W64)
        }
        BpfInsn::SubImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Sub, AluWidth::W64)
        }
        BpfInsn::SubReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Sub, AluWidth::W64)
        }
        BpfInsn::AndImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::And, AluWidth::W64)
        }
        BpfInsn::AndReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::And, AluWidth::W64)
        }
        BpfInsn::OrImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Or, AluWidth::W64)
        }
        BpfInsn::OrReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Or, AluWidth::W64)
        }
        BpfInsn::XorImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Xor, AluWidth::W64)
        }
        BpfInsn::XorReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Xor, AluWidth::W64)
        }
        BpfInsn::LshImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Lsh, AluWidth::W64)
        }
        BpfInsn::LshReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Lsh, AluWidth::W64)
        }
        BpfInsn::RshImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Rsh, AluWidth::W64)
        }
        BpfInsn::RshReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Rsh, AluWidth::W64)
        }
        BpfInsn::ArshImm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Arsh, AluWidth::W64)
        }
        BpfInsn::ArshReg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Arsh, AluWidth::W64)
        }
        // ALU32 (#39): the same operations, truncating and zero-extending
        BpfInsn::Add32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Add, AluWidth::W32)
        }
        BpfInsn::Add32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Add, AluWidth::W32)
        }
        BpfInsn::Sub32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Sub, AluWidth::W32)
        }
        BpfInsn::Sub32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Sub, AluWidth::W32)
        }
        BpfInsn::And32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::And, AluWidth::W32)
        }
        BpfInsn::And32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::And, AluWidth::W32)
        }
        BpfInsn::Or32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Or, AluWidth::W32)
        }
        BpfInsn::Or32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Or, AluWidth::W32)
        }
        BpfInsn::Xor32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Xor, AluWidth::W32)
        }
        BpfInsn::Xor32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Xor, AluWidth::W32)
        }
        BpfInsn::Lsh32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Lsh, AluWidth::W32)
        }
        BpfInsn::Lsh32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Lsh, AluWidth::W32)
        }
        BpfInsn::Rsh32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Rsh, AluWidth::W32)
        }
        BpfInsn::Rsh32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Rsh, AluWidth::W32)
        }
        BpfInsn::Arsh32Imm { dst, imm } => {
            concrete_alu_imm(pc, state, *dst, *imm, AluOp::Arsh, AluWidth::W32)
        }
        BpfInsn::Arsh32Reg { dst, src } => {
            concrete_alu_reg(pc, state, *dst, *src, AluOp::Arsh, AluWidth::W32)
        }
        // r10[offset] = rY → spill the value and its pointer kind (#30)
        BpfInsn::StStack { src, offset } => {
            let slot = concrete_stack_slot(pc, *offset as i32)?;
            let value = read_concrete_reg(pc, state, *src)?;
            let mut next = *state;
            next.stack[slot] = Some(value);
            Ok(next)
        }
        // rX = r10[offset] → load a stack slot; a slot must have been
        // written before it is read (write-before-read, #18). The value
        // and its pointer kind are restored (#30).
        BpfInsn::LdStack { dst, offset } => {
            check_concrete_reg(pc, *dst)?;
            let slot = concrete_stack_slot(pc, *offset as i32)?;
            let value = match state.stack[slot] {
                None => {
                    return Err(ConcreteFailure::UninitializedStackRead {
                        pc,
                        offset: *offset as i32,
                    });
                }
                Some(value) => value,
            };
            let mut next = *state;
            next.regs[*dst as usize] = Some(value);
            Ok(next)
        }
    }
}

// ── Concrete path exploration (#51) ────────────────────────────────────────

/// Exploration bounds, mirroring `VerifierLimits` (#32/#46). Exceeding
/// any of them marks the run inconclusive — concrete exploration cannot
/// prove non-termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConcreteLimits {
    /// Maximum number of distinct (pc, state) pairs analyzed.
    pub(crate) max_states: usize,
    /// Maximum number of worklist steps (states popped).
    pub(crate) max_steps: usize,
    /// Maximum number of distinct re-visits of one loop head: a head
    /// that keeps producing new states is not converging. Mirrors the
    /// abstract loop budget, so accepted programs terminate before it.
    pub(crate) max_loop_iterations: usize,
}

impl Default for ConcreteLimits {
    fn default() -> Self {
        Self {
            max_states: 1024,
            max_steps: 100_000,
            max_loop_iterations: 256,
        }
    }
}

/// The state at a reached `exit` (the exit pc plus the full state,
/// including `R0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConcreteOutcome {
    pub(crate) pc: u32,
    pub(crate) state: ConcreteState,
}

/// The result of a concrete exploration: every distinct visited state
/// (in visit order, for the coverage checker #52) plus the exit
/// outcomes. `inconclusive` means an exploration budget was hit — the
/// run proves nothing (non-terminating loop candidate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConcreteRun {
    pub(crate) visited: Vec<(u32, ConcreteState)>,
    pub(crate) outcomes: Vec<ConcreteOutcome>,
    pub(crate) inconclusive: bool,
}

/// Explore a program with the default limits. `loop_heads` are the
/// targets of back edges from the structural pass (like `verify_mini`).
pub(crate) fn run_concrete(
    program: &[BpfInsn],
    loop_heads: &[u32],
) -> Result<ConcreteRun, ConcreteFailure> {
    run_concrete_with_limits(program, loop_heads, &ConcreteLimits::default())
}

/// `run_concrete` with explicit exploration limits.
///
/// Mirrors `verify_mini_with_limits`: a worklist of `(pc, state)` pairs,
/// processed LIFO. Concrete states are exact, so deduplication is state
/// equality (the abstract side uses subsumption); a deterministic loop
/// converges by reaching its exit, and a loop that never converges hits
/// the loop-head budget → inconclusive.
pub(crate) fn run_concrete_with_limits(
    program: &[BpfInsn],
    loop_heads: &[u32],
    limits: &ConcreteLimits,
) -> Result<ConcreteRun, ConcreteFailure> {
    let mut worklist = vec![(0u32, ConcreteState::initial())];
    // states already visited at each pc, for exact-state deduplication
    let mut visited: HashMap<u32, Vec<ConcreteState>> = HashMap::new();
    // visit order of the distinct states — the input of #52
    let mut visited_order: Vec<(u32, ConcreteState)> = Vec::new();
    // distinct re-visits per loop head (#46): exceeding the budget means
    // the loop never converges → inconclusive (concrete cannot prove
    // non-termination, so this is not a REJECT)
    let mut loop_iters: HashMap<u32, usize> = HashMap::new();
    let mut outcomes: Vec<ConcreteOutcome> = Vec::new();
    let mut steps = 0usize;
    let mut explored = 0usize;

    while let Some((pc, state)) = worklist.pop() {
        // worklist bound: every pop counts, even skipped ones
        steps += 1;
        if steps > limits.max_steps {
            return Ok(ConcreteRun {
                visited: visited_order,
                outcomes,
                inconclusive: true,
            });
        }

        // skip states already visited at this pc (exact equality)
        let seen = visited.entry(pc).or_default();
        if seen.contains(&state) {
            continue;
        }
        seen.push(state);
        visited_order.push((pc, state));

        // loop-head budget: a head that keeps producing new states is
        // not converging
        if loop_heads.contains(&pc) {
            let iters = loop_iters.entry(pc).or_insert(0);
            *iters += 1;
            if *iters > limits.max_loop_iterations {
                return Ok(ConcreteRun {
                    visited: visited_order,
                    outcomes,
                    inconclusive: true,
                });
            }
        }
        explored += 1;
        if explored > limits.max_states {
            return Ok(ConcreteRun {
                visited: visited_order,
                outcomes,
                inconclusive: true,
            });
        }

        let insn = program
            .get(pc as usize)
            .ok_or(ConcreteFailure::InternalError { pc })?;

        // a path ends at exit; R0 must hold a valid value there (mirror
        // of the abstract "r0 is uninitialized at exit")
        if matches!(insn, BpfInsn::Exit) {
            read_concrete_reg(pc, &state, 0)
                .map_err(|_| ConcreteFailure::UninitializedRead { pc, reg: 0 })?;
            // deduplicate identical exit states (e.g. converging seeds)
            if !outcomes.iter().any(|o| o.state == state) {
                outcomes.push(ConcreteOutcome { pc, state });
            }
            continue;
        }

        for (next_pc, next_state) in concrete_successors(pc, insn, &state)? {
            worklist.push((next_pc, next_state));
        }
    }
    Ok(ConcreteRun {
        visited: visited_order,
        outcomes,
        inconclusive: false,
    })
}

/// Expand the successors of one instruction, mirroring the abstract
/// `successors()`: terminal, jumps and compares are expanded here;
/// everything else falls through via `concrete_step`.
fn concrete_successors(
    pc: u32,
    insn: &BpfInsn,
    state: &ConcreteState,
) -> Result<Vec<(u32, ConcreteState)>, ConcreteFailure> {
    match insn {
        BpfInsn::Exit => Ok(vec![]),
        BpfInsn::Jmp { offset } => Ok(vec![(branch_target(pc, *offset), *state)]),
        BpfInsn::Jeq { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Eq, state)
        }
        BpfInsn::Jne { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Ne, state)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Ugt, state)
        }
        BpfInsn::Jge { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Uge, state)
        }
        BpfInsn::Jlt { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Ult, state)
        }
        BpfInsn::Jle { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Ule, state)
        }
        BpfInsn::Jsgt { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Sgt, state)
        }
        BpfInsn::Jsge { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Sge, state)
        }
        BpfInsn::Jslt { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Slt, state)
        }
        BpfInsn::Jsle { dst, src, offset } => {
            concrete_cond(pc, *dst, *src, *offset, CondOp::Sle, state)
        }
        BpfInsn::JeqImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Eq, state)
        }
        BpfInsn::JneImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Ne, state)
        }
        BpfInsn::JgtImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Ugt, state)
        }
        BpfInsn::JgeImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Uge, state)
        }
        BpfInsn::JltImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Ult, state)
        }
        BpfInsn::JleImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Ule, state)
        }
        BpfInsn::JsgtImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Sgt, state)
        }
        BpfInsn::JsgeImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Sge, state)
        }
        BpfInsn::JsltImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Slt, state)
        }
        BpfInsn::JsleImm { dst, imm, offset } => {
            concrete_cond_imm(pc, *dst, *imm, *offset, CondOp::Sle, state)
        }
        BpfInsn::Call { imm } => concrete_call(pc, *imm, state),
        // everything else falls through via concrete_step()
        _ => Ok(vec![(pc + 1, concrete_step(pc, state, insn)?)]),
    }
}

/// Evaluate a conditional branch on the exact concrete values.
///
/// Deterministic: exactly one successor is produced, the taken or the
/// fall-through side. Same-kind pointers may be compared for equality
/// only; pointer ordering and mixed-type comparisons are rejected,
/// mirroring the abstract `cond_branch`.
fn concrete_cond(
    pc: u32,
    dst: u8,
    src: u8,
    offset: i16,
    op: CondOp,
    state: &ConcreteState,
) -> Result<Vec<(u32, ConcreteState)>, ConcreteFailure> {
    let dst_value = read_concrete_reg(pc, state, dst)?;
    let src_value = read_concrete_reg(pc, state, src)?;
    let taken = match (dst_value, src_value) {
        (ConcreteValue::Scalar(d), ConcreteValue::Scalar(s)) => match op {
            CondOp::Eq => d == s,
            CondOp::Ne => d != s,
            CondOp::Ugt => d > s,
            CondOp::Uge => d >= s,
            CondOp::Ult => d < s,
            CondOp::Ule => d <= s,
            CondOp::Sgt => (d as i64) > (s as i64),
            CondOp::Sge => (d as i64) >= (s as i64),
            CondOp::Slt => (d as i64) < (s as i64),
            CondOp::Sle => (d as i64) <= (s as i64),
        },
        // same-kind pointers: equality comparisons only
        (ConcreteValue::StackPtr(d), ConcreteValue::StackPtr(s))
        | (ConcreteValue::CtxPtr(d), ConcreteValue::CtxPtr(s)) => match op {
            CondOp::Eq => d == s,
            CondOp::Ne => d != s,
            _ => return Err(ConcreteFailure::InvalidComparison { pc, dst, src }),
        },
        // mixed pointer/scalar types are never comparable
        _ => return Err(ConcreteFailure::InvalidComparison { pc, dst, src }),
    };
    let next_pc = if taken {
        branch_target(pc, offset)
    } else {
        pc + 1
    };
    Ok(vec![(next_pc, *state)])
}

/// Evaluate an immediate-form conditional branch (`BPF_J*_K`, #57) on
/// the exact concrete values: deterministic, exactly one successor.
/// The immediate is sign-extended to 64 bits, like the kernel's imm32
/// materialization of the constant source register.
fn concrete_cond_imm(
    pc: u32,
    dst: u8,
    imm: i32,
    offset: i16,
    op: CondOp,
    state: &ConcreteState,
) -> Result<Vec<(u32, ConcreteState)>, ConcreteFailure> {
    let dst_value = read_concrete_reg(pc, state, dst)?;
    let s = imm as i64 as u64;
    let taken = match dst_value {
        ConcreteValue::Scalar(d) => match op {
            CondOp::Eq => d == s,
            CondOp::Ne => d != s,
            CondOp::Ugt => d > s,
            CondOp::Uge => d >= s,
            CondOp::Ult => d < s,
            CondOp::Ule => d <= s,
            CondOp::Sgt => (d as i64) > (imm as i64),
            CondOp::Sge => (d as i64) >= (imm as i64),
            CondOp::Slt => (d as i64) < (imm as i64),
            CondOp::Sle => (d as i64) <= (imm as i64),
        },
        // a pointer compared to an immediate is never comparable
        // (mirror of the abstract cond_branch_impl)
        _ => return Err(ConcreteFailure::InvalidComparisonImm { pc, dst }),
    };
    let next_pc = if taken {
        branch_target(pc, offset)
    } else {
        pc + 1
    };
    Ok(vec![(next_pc, *state)])
}

/// Model a helper call: validate the arguments, clobber R1..R5, and
/// fork over the return seeds (the concrete counterpart of the abstract
/// return range).
fn concrete_call(
    pc: u32,
    imm: i32,
    state: &ConcreteState,
) -> Result<Vec<(u32, ConcreteState)>, ConcreteFailure> {
    // the immediate is the helper id (kernel convention); BPF-to-BPF
    // calls are rejected at decode time (issue #56)
    let helper = helper_prototype(imm).ok_or(ConcreteFailure::UnknownHelper { pc, imm })?;
    check_concrete_helper_args(pc, helper, state)?;
    // argument registers are scratch — invalidated by the call (mirror
    // of the abstract step() Call)
    let mut base = *state;
    for reg in 1..=5 {
        base.regs[reg] = None;
    }
    let seeds = helper_return_seeds(pc, imm, helper.return_type)?;
    Ok(seeds
        .into_iter()
        .map(|seed| {
            let mut next = base;
            next.regs[0] = Some(seed);
            (pc + 1, next)
        })
        .collect())
}

/// Validate R1..R5 against the helper's argument types, mirroring
/// `check_helper_args` (#28) on the concrete kinds. `PtrToMap` has no
/// concrete counterpart yet, so no actual kind can match it.
fn check_concrete_helper_args(
    pc: u32,
    helper: &HelperPrototype,
    state: &ConcreteState,
) -> Result<(), ConcreteFailure> {
    for (i, expected) in helper.args.iter().enumerate() {
        let reg = (i + 1) as u8; // R1..R5
        let actual = read_concrete_reg(pc, state, reg)?;
        let ok = matches!(
            (expected, actual),
            (ArgType::PtrToStack, ConcreteValue::StackPtr(_))
                | (ArgType::Scalar, ConcreteValue::Scalar(_))
        );
        if !ok {
            return Err(ConcreteFailure::HelperArgMismatch { pc, arg: reg });
        }
    }
    Ok(())
}

/// The return seeds for a helper call, derived from the abstract return
/// type: a constant return gets exactly the constant, an unknown scalar
/// gets the default boundary seeds (always covered by the abstract full
/// range). Seed selection for narrow scalar ranges is a follow-up.
fn helper_return_seeds(
    pc: u32,
    imm: i32,
    return_type: RegState,
) -> Result<Vec<ConcreteValue>, ConcreteFailure> {
    match return_type {
        RegState::Scalar(bounds) if bounds.is_constant() => {
            Ok(vec![ConcreteValue::Scalar(bounds.smin as u64)])
        }
        RegState::Scalar(_) => Ok(vec![0, 1, u64::MAX]
            .into_iter()
            .map(ConcreteValue::Scalar)
            .collect()),
        // pointer returns have no concrete address class yet; reaching
        // this is a model gap, not a fake value
        _ => Err(ConcreteFailure::UnsupportedHelperReturn { pc, imm }),
    }
}

/// The concrete-side report of the last verification (v0.5, #53): what
/// the concrete interpreter found next to the verdict. The verdict
/// itself is unchanged — an unsoundness is a verifier/model bug, not a
/// program failure, so it is reported instead of flipping ACCEPT/REJECT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConcreteReport {
    /// Coverage violations on accepted programs (#52): `NotCovered` is
    /// unsoundness, `AbstractMissedPc` a precision candidate.
    pub(crate) violations: Vec<CoverageViolation>,
    /// The concrete run hit an exploration budget (non-termination
    /// candidate). Only reachable on rejected programs — accepted
    /// programs terminate within the concrete budget (mirrors the
    /// abstract loop budget).
    pub(crate) inconclusive: bool,
    /// The concrete interpreter failed although the abstract verifier
    /// accepted the program — a model discrepancy.
    pub(crate) unexpected_failure: Option<ConcreteFailure>,
    /// Rejected programs: informational cross-check of the concrete
    /// run ("also fails" / "precision candidate" / "inconclusive").
    pub(crate) reject_note: Option<String>,
}

// ── Abstract↔concrete coverage checker (#52) ────────────────────────────────

/// The classification of a coverage violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoverageKind {
    /// The concrete execution reached a pc the abstract exploration
    /// never visited: the abstract missed a reachable path — a
    /// precision candidate (warning, not a soundness failure).
    AbstractMissedPc,
    /// The abstract visited the pc, but no abstract state there covers
    /// the concrete state: the abstract under-approximates the actual
    /// execution — unsoundness.
    NotCovered,
}

/// One abstract↔concrete mismatch found by [`check_coverage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoverageViolation {
    pub(crate) pc: u32,
    pub(crate) kind: CoverageKind,
    /// The concrete state the abstract side fails to cover.
    pub(crate) concrete: ConcreteState,
    /// The abstract states analyzed at this pc (empty for
    /// `AbstractMissedPc`).
    pub(crate) abstract_states: Vec<VerifierState>,
}

/// Check that every concrete visited state is covered by at least one
/// abstract state at the same pc — the Phase 2 soundness question.
///
/// Exit states are part of `run.visited` (#51), so the R0-at-exit rule
/// is checked through the same path. On an inconclusive run the
/// violations found in the explored prefix are still real; the pipeline
/// (#53) treats the inconclusive flag itself as a warning.
pub(crate) fn check_coverage(
    abstract_states: &HashMap<u32, Vec<VerifierState>>,
    run: &ConcreteRun,
) -> Vec<CoverageViolation> {
    let mut violations = Vec::new();
    for (pc, concrete) in &run.visited {
        match abstract_states.get(pc) {
            None => violations.push(CoverageViolation {
                pc: *pc,
                kind: CoverageKind::AbstractMissedPc,
                concrete: *concrete,
                abstract_states: Vec::new(),
            }),
            Some(candidates) => {
                if !candidates
                    .iter()
                    .any(|abstract_state| state_covers(abstract_state, concrete))
                {
                    violations.push(CoverageViolation {
                        pc: *pc,
                        kind: CoverageKind::NotCovered,
                        concrete: *concrete,
                        abstract_states: candidates.clone(),
                    });
                }
            }
        }
    }
    violations
}

/// Render one concrete value in the trace style.
fn render_concrete_value(value: &ConcreteValue) -> String {
    match value {
        ConcreteValue::Scalar(v) => format!("Scalar({})", v),
        ConcreteValue::StackPtr(v) => format!("StackPtr({:#x})", v),
        ConcreteValue::CtxPtr(v) => format!("CtxPtr({:#x})", v),
    }
}

/// Render the initialized registers and stack slots of a concrete state.
fn render_concrete_state(state: &ConcreteState) -> String {
    let mut out = String::new();
    for (i, reg) in state.regs.iter().enumerate() {
        if let Some(value) = reg {
            out.push_str(&format!("    R{} = {}\n", i, render_concrete_value(value)));
        }
    }
    for (i, slot) in state.stack.iter().enumerate() {
        if let Some(value) = slot {
            out.push_str(&format!(
                "    [r10-{}] = {}\n",
                (i + 1) * 8,
                render_concrete_value(value)
            ));
        }
    }
    out
}

/// Render a coverage report in the trace style: pc, disassembled
/// instruction, concrete values, and the candidate abstract states.
pub(crate) fn render_coverage_report(
    violations: &[CoverageViolation],
    program: &[BpfInsn],
) -> String {
    let mut out = String::new();
    for violation in violations {
        let insn = program
            .get(violation.pc as usize)
            .map(disassemble)
            .unwrap_or_else(|| "<out of range>".to_string());
        let kind = match violation.kind {
            CoverageKind::AbstractMissedPc => {
                "ABSTRACT MISSED PC (precision candidate — the abstract never explored this pc)"
            }
            CoverageKind::NotCovered => {
                "NOT COVERED (unsound — no abstract state at this pc contains the concrete state)"
            }
        };
        out.push_str(&format!(
            "coverage violation at insn {} [{}]\n  {}: {}\n",
            violation.pc, kind, violation.pc, insn
        ));
        out.push_str("  concrete:\n");
        out.push_str(&render_concrete_state(&violation.concrete));
        if !violation.abstract_states.is_empty() {
            out.push_str("  abstract candidates:\n");
            for abstract_state in &violation.abstract_states {
                for (i, reg) in abstract_state.regs.iter().enumerate() {
                    if *reg != RegState::Uninit {
                        out.push_str(&format!("    R{} = {}\n", i, reg));
                    }
                }
            }
        }
        out.push('\n');
    }
    out
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ScalarBounds;

    // ── concrete state model (#49) ──────────────────────────────────────

    #[test]
    fn initial_mirrors_abstract() {
        let state = ConcreteState::initial();
        // R1 = context, R10 = frame pointer, everything else uninitialized
        assert_eq!(state.regs[1], Some(ConcreteValue::CtxPtr(CTX_BASE)));
        assert_eq!(state.regs[10], Some(ConcreteValue::StackPtr(STACK_BASE)));
        assert!(state.regs[0..1].iter().all(|r| r.is_none()));
        assert!(state.regs[2..=9].iter().all(|r| r.is_none()));
        assert!(state.stack.iter().all(|s| s.is_none()));
    }

    #[test]
    fn scalar_constant_covers_exact() {
        let reg = RegState::Scalar(ScalarBounds::constant(42));
        assert!(abstract_covers(reg, ConcreteValue::Scalar(42)));
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(43)));
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(41)));
    }

    #[test]
    fn scalar_range_boundaries() {
        // signed range -10..=10: both interpretations cover it, tnum unknown
        let reg = RegState::Scalar(ScalarBounds::from_signed(-10, 10));
        assert!(abstract_covers(reg, ConcreteValue::Scalar(10)));
        assert!(abstract_covers(reg, ConcreteValue::Scalar(0)));
        assert!(abstract_covers(
            reg,
            ConcreteValue::Scalar(10_u64.wrapping_neg())
        )); // -10
        // just outside the signed range
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(11)));
        assert!(!abstract_covers(
            reg,
            ConcreteValue::Scalar(11_u64.wrapping_neg())
        )); // -11
    }

    #[test]
    fn scalar_unsigned_signed_split() {
        // a range straddling zero has no single u64 interval: the
        // unsigned side is the full range, so only the signed side
        // discriminates (and both sides must pass — #40)
        let reg = RegState::Scalar(ScalarBounds::from_signed(-10, 10));
        // u64::MAX = -1 signed: inside the signed range and unsigned range
        assert!(abstract_covers(reg, ConcreteValue::Scalar(u64::MAX)));
        // 11: unsigned pass, signed fail → not covered
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(11)));
    }

    #[test]
    fn scalar_tnum_bit_mismatch() {
        // wide range with a constant tnum: only the tnum discriminates
        let mut bounds = ScalarBounds::from_signed(0, 15);
        bounds.tnum = Tnum::constant(0b1010);
        let reg = RegState::Scalar(bounds);
        assert!(abstract_covers(reg, ConcreteValue::Scalar(0b1010)));
        // same range, wrong known bit
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(0b1110)));
    }

    #[test]
    fn ptr_stack_offset_and_range() {
        // exact offset 0: only the frame base itself
        let reg = RegState::PtrToStack {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
        };
        assert!(abstract_covers(reg, ConcreteValue::StackPtr(STACK_BASE)));
        assert!(!abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 8)
        ));

        // computed offset range -16..=-8 (#45): boundary values only
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        assert!(abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 16)
        ));
        assert!(abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 8)
        ));
        assert!(!abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 7)
        ));
        assert!(!abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 17)
        ));
    }

    #[test]
    fn ptr_stack_alignment() {
        // offset in range but misaligned: align_off = 0 rejects mod-8 ≠ 0
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        assert!(abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 16)
        ));
        assert!(!abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 15)
        ));

        // unknown alignment accepts any offset in range (#45)
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: ALIGN_UNKNOWN,
        };
        assert!(abstract_covers(
            reg,
            ConcreteValue::StackPtr(STACK_BASE - 15)
        ));
    }

    #[test]
    fn ptr_ctx_exact_address() {
        assert!(abstract_covers(
            RegState::PtrToCtx,
            ConcreteValue::CtxPtr(CTX_BASE)
        ));
        assert!(!abstract_covers(
            RegState::PtrToCtx,
            ConcreteValue::CtxPtr(CTX_BASE + 1)
        ));
        assert!(!abstract_covers(
            RegState::PtrToCtx,
            ConcreteValue::CtxPtr(STACK_BASE)
        ));
    }

    #[test]
    fn uninit_never_covers_value() {
        for value in [
            ConcreteValue::Scalar(0),
            ConcreteValue::StackPtr(0),
            ConcreteValue::CtxPtr(0),
        ] {
            assert!(!abstract_covers(RegState::Uninit, value));
        }
    }

    #[test]
    fn map_ptr_family_not_covered() {
        // no concrete address class exists for map pointers yet
        for reg in [
            RegState::PtrToMap,
            RegState::PtrToMapValue,
            RegState::PtrToMapValueOrNull,
        ] {
            for value in [
                ConcreteValue::Scalar(0),
                ConcreteValue::StackPtr(0),
                ConcreteValue::CtxPtr(0),
            ] {
                assert!(!abstract_covers(reg, value));
            }
        }
    }

    #[test]
    fn scalar_bits_do_not_cover_pointer() {
        // the same bits as a stack address are not a stack pointer
        let reg = RegState::PtrToStack {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
        };
        assert!(!abstract_covers(reg, ConcreteValue::Scalar(STACK_BASE)));
        assert!(!abstract_covers(
            RegState::PtrToCtx,
            ConcreteValue::Scalar(CTX_BASE)
        ));
    }

    #[test]
    fn pointer_kind_does_not_cover_scalar() {
        // a pointer value is not a scalar, whatever its bits
        let reg = RegState::Scalar(ScalarBounds::constant(STACK_BASE as i64));
        assert!(!abstract_covers(reg, ConcreteValue::StackPtr(STACK_BASE)));
    }

    #[test]
    fn state_covers_initial_pair() {
        // the abstract initial state covers the concrete initial state
        assert!(state_covers(
            &VerifierState::initial(),
            &ConcreteState::initial()
        ));
    }

    #[test]
    fn state_covers_register_mismatch() {
        // concrete R0 = 0 where the abstract side is uninitialized
        let mut concrete = ConcreteState::initial();
        concrete.regs[0] = Some(ConcreteValue::Scalar(0));
        assert!(!state_covers(&VerifierState::initial(), &concrete));
    }

    #[test]
    fn state_covers_kind_mismatch() {
        // abstract PtrToStack vs concrete scalar with the same bits
        let mut abstract_state = VerifierState::initial();
        abstract_state.regs[0] = RegState::PtrToStack {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
        };
        let mut concrete = ConcreteState::initial();
        concrete.regs[0] = Some(ConcreteValue::Scalar(STACK_BASE));
        assert!(!state_covers(&abstract_state, &concrete));
        // the proper stack pointer kind is covered
        concrete.regs[0] = Some(ConcreteValue::StackPtr(STACK_BASE));
        assert!(state_covers(&abstract_state, &concrete));
    }

    #[test]
    fn state_covers_stack_roundtrip() {
        // abstract: slot 0 spilled with the constant 42 (a stack
        // store/load round-trip, #30); concrete: the same slot holds 42
        let mut abstract_state = VerifierState::initial();
        abstract_state.stack.slots[0] =
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(42)));
        let mut concrete = ConcreteState::initial();
        concrete.stack[0] = Some(ConcreteValue::Scalar(42));

        assert!(state_covers(&abstract_state, &concrete));

        // wrong value in the slot
        concrete.stack[0] = Some(ConcreteValue::Scalar(43));
        assert!(!state_covers(&abstract_state, &concrete));

        // abstract spilled but concrete uninitialized
        concrete.stack[0] = None;
        assert!(!state_covers(&abstract_state, &concrete));

        // abstract uninitialized but concrete holds a value
        let abstract_state = VerifierState::initial();
        concrete.stack[0] = Some(ConcreteValue::Scalar(42));
        assert!(!state_covers(&abstract_state, &concrete));
    }

    // ── concrete instruction execution (#50) ────────────────────────────

    /// Run a straight-line program from the initial state and return the
    /// final state, failing on any ConcreteFailure.
    fn run(program: &[BpfInsn]) -> ConcreteState {
        let mut state = ConcreteState::initial();
        for (pc, insn) in program.iter().enumerate() {
            state = concrete_step(pc as u32, &state, insn).expect("concrete step failed");
        }
        state
    }

    #[test]
    fn mov_imm_constant() {
        let state = run(&[BpfInsn::MovImm { dst: 2, imm: 42 }]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(42)));
        // negative immediates sign-extend to 64 bits (#40)
        let state = run(&[BpfInsn::MovImm { dst: 2, imm: -1 }]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(u64::MAX)));
    }

    #[test]
    fn mov_reg_copies_value_and_kind() {
        // scalar copy
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 42 },
            BpfInsn::MovReg { dst: 3, src: 2 },
        ]);
        assert_eq!(state.regs[3], Some(ConcreteValue::Scalar(42)));
        // pointer kind copy (ctx)
        let state = run(&[BpfInsn::MovReg { dst: 2, src: 1 }]);
        assert_eq!(state.regs[2], Some(ConcreteValue::CtxPtr(CTX_BASE)));
        // pointer kind copy (stack)
        let state = run(&[BpfInsn::MovReg { dst: 2, src: 10 }]);
        assert_eq!(state.regs[2], Some(ConcreteValue::StackPtr(STACK_BASE)));
    }

    #[test]
    fn mov_reg_uninit_rejected() {
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::MovReg { dst: 2, src: 3 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::UninitializedRead { pc: 0, reg: 3 });
    }

    #[test]
    fn alu64_constants_all_ops() {
        let cases: &[(&str, Vec<BpfInsn>, u64)] = &[
            (
                "add",
                vec![
                    BpfInsn::MovImm { dst: 2, imm: 10 },
                    BpfInsn::AddImm { dst: 2, imm: 5 },
                ],
                15,
            ),
            (
                "sub",
                vec![
                    BpfInsn::MovImm { dst: 2, imm: 10 },
                    BpfInsn::SubImm { dst: 2, imm: 3 },
                ],
                7,
            ),
            (
                "and",
                vec![
                    BpfInsn::MovImm {
                        dst: 2,
                        imm: 0b1100,
                    },
                    BpfInsn::AndImm {
                        dst: 2,
                        imm: 0b1010,
                    },
                ],
                0b1000,
            ),
            (
                "or",
                vec![
                    BpfInsn::MovImm {
                        dst: 2,
                        imm: 0b1100,
                    },
                    BpfInsn::OrImm {
                        dst: 2,
                        imm: 0b1010,
                    },
                ],
                0b1110,
            ),
            (
                "xor",
                vec![
                    BpfInsn::MovImm {
                        dst: 2,
                        imm: 0b1100,
                    },
                    BpfInsn::XorImm {
                        dst: 2,
                        imm: 0b1010,
                    },
                ],
                0b0110,
            ),
            (
                "lsh",
                vec![
                    BpfInsn::MovImm {
                        dst: 2,
                        imm: 0xFFFF,
                    },
                    BpfInsn::LshImm { dst: 2, imm: 4 },
                ],
                0xFFFF0,
            ),
            (
                "rsh",
                vec![
                    BpfInsn::MovImm {
                        dst: 2,
                        imm: 0xFFFF0,
                    },
                    BpfInsn::RshImm { dst: 2, imm: 4 },
                ],
                0xFFFF,
            ),
            (
                "arsh",
                vec![
                    BpfInsn::MovImm { dst: 2, imm: -8 },
                    BpfInsn::ArshImm { dst: 2, imm: 1 },
                ],
                0xFFFF_FFFF_FFFF_FFFC, // -4
            ),
            (
                "add_reg",
                vec![
                    BpfInsn::MovImm { dst: 2, imm: 10 },
                    BpfInsn::MovImm { dst: 3, imm: 5 },
                    BpfInsn::AddReg { dst: 2, src: 3 },
                ],
                15,
            ),
            (
                "arsh_reg",
                vec![
                    BpfInsn::MovImm { dst: 2, imm: -8 },
                    BpfInsn::MovImm { dst: 3, imm: 2 },
                    BpfInsn::ArshReg { dst: 2, src: 3 },
                ],
                0xFFFF_FFFF_FFFF_FFFE, // -2
            ),
        ];
        for (name, program, expected) in cases {
            assert_eq!(
                run(program).regs[2],
                Some(ConcreteValue::Scalar(*expected)),
                "op {}: result mismatch",
                name
            );
        }
    }

    #[test]
    fn alu64_overflow_wraps() {
        // u64::MAX + 1 wraps to 0
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: -1 },
            BpfInsn::AddImm { dst: 2, imm: 1 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(0)));
        // 0 - 1 wraps to u64::MAX
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 0 },
            BpfInsn::SubImm { dst: 2, imm: 1 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(u64::MAX)));
    }

    #[test]
    fn alu32_truncate_zero_extend() {
        // 0x1_0000_0001 truncated to 32 bits is 1; +1 = 2, zero-extended
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::LshImm { dst: 2, imm: 32 },
            BpfInsn::AddImm { dst: 2, imm: 1 }, // r2 = 0x1_0000_0001
            BpfInsn::Add32Imm { dst: 2, imm: 1 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(2)));
        // 0xFFFF_FFFF + 1 (32-bit) wraps to 0
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: -1 },
            BpfInsn::Add32Imm { dst: 2, imm: 1 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(0)));
    }

    #[test]
    fn alu32_imm_shift_large_rejected() {
        // kernel parity (review fix): ALU32 shifts require an amount
        // below 32, while ALU64 accepts the same amount (0..64)
        let err = concrete_step(
            1,
            &ConcreteState::initial(),
            &BpfInsn::Lsh32Imm { dst: 2, imm: 40 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidShiftAmount { pc: 1, amount: 40 }
        );
        // the same amount is valid for ALU64
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::LshImm { dst: 2, imm: 40 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(1 << 40)));
    }

    #[test]
    fn alu32_reg_shift_large_rejected() {
        // ALU32 register shifts also require an amount below 32
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 40 },
        ]);
        let err = concrete_step(2, &state, &BpfInsn::Lsh32Reg { dst: 2, src: 3 }).unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidShiftAmount { pc: 2, amount: 40 }
        );
    }

    #[test]
    fn alu_imm_shift_invalid() {
        let err = concrete_step(
            1,
            &ConcreteState::initial(),
            &BpfInsn::LshImm { dst: 2, imm: 64 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidShiftAmount { pc: 1, amount: 64 }
        );
        let err = concrete_step(
            1,
            &ConcreteState::initial(),
            &BpfInsn::LshImm { dst: 2, imm: -1 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidShiftAmount {
                pc: 1,
                amount: u64::MAX
            }
        );
    }

    #[test]
    fn alu_reg_shift_invalid_amount() {
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 64 },
        ]);
        let err = concrete_step(2, &state, &BpfInsn::LshReg { dst: 2, src: 3 }).unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidShiftAmount { pc: 2, amount: 64 }
        );
    }

    #[test]
    fn alu_uninit_operand_rejected() {
        // destination uninitialized
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::AddImm { dst: 2, imm: 1 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::UninitializedRead { pc: 0, reg: 2 });
        // source uninitialized
        let state = run(&[BpfInsn::MovImm { dst: 2, imm: 1 }]);
        let err = concrete_step(1, &state, &BpfInsn::AddReg { dst: 2, src: 3 }).unwrap_err();
        assert_eq!(err, ConcreteFailure::UninitializedRead { pc: 1, reg: 3 });
    }

    #[test]
    fn alu_on_pointer_rejected() {
        // SUB on a stack pointer is not allowed (only ADD, #20)
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::SubImm { dst: 10, imm: 8 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::PointerArithmetic { pc: 0, reg: 10 });
        // immediate arithmetic on the context pointer
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::AddImm { dst: 1, imm: 8 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::PointerArithmetic { pc: 0, reg: 1 });
        // register arithmetic on the context pointer
        let state = run(&[BpfInsn::MovImm { dst: 2, imm: 8 }]);
        let err = concrete_step(1, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap_err();
        assert_eq!(err, ConcreteFailure::PointerArithmetic { pc: 1, reg: 1 });
        // stack pointer + stack pointer
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::AddReg { dst: 10, src: 10 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::PointerArithmetic { pc: 0, reg: 10 });
    }

    #[test]
    fn stack_ptr_add_imm_ok() {
        let state = run(&[BpfInsn::AddImm { dst: 10, imm: -8 }]);
        assert_eq!(
            state.regs[10],
            Some(ConcreteValue::StackPtr(STACK_BASE - 8))
        );
    }

    #[test]
    fn stack_ptr_add_imm_out_of_frame() {
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::AddImm { dst: 10, imm: 100 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::StackPointerOutOfFrame { pc: 0, reg: 10 }
        );
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::AddImm { dst: 10, imm: -520 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::StackPointerOutOfFrame { pc: 0, reg: 10 }
        );
    }

    #[test]
    fn stack_ptr_add_reg_computed() {
        // computed pointer arithmetic (#45): in-frame scalar ADD
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: -8 },
            BpfInsn::AddReg { dst: 10, src: 2 },
        ]);
        assert_eq!(
            state.regs[10],
            Some(ConcreteValue::StackPtr(STACK_BASE - 8))
        );
        // out-of-frame scalar ADD
        let state = run(&[BpfInsn::MovImm { dst: 2, imm: 8 }]);
        let err = concrete_step(1, &state, &BpfInsn::AddReg { dst: 10, src: 2 }).unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::StackPointerOutOfFrame { pc: 1, reg: 10 }
        );
    }

    #[test]
    fn stack_roundtrip_preserves_kind() {
        // scalar round-trip
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 42 },
            BpfInsn::StStack { src: 2, offset: -8 },
            BpfInsn::LdStack { dst: 0, offset: -8 },
        ]);
        assert_eq!(state.regs[0], Some(ConcreteValue::Scalar(42)));
        // pointer round-trip: the kind survives spill/fill (#30)
        let state = run(&[
            BpfInsn::AddImm { dst: 10, imm: -8 },
            BpfInsn::StStack {
                src: 10,
                offset: -16,
            },
            BpfInsn::LdStack {
                dst: 0,
                offset: -16,
            },
        ]);
        assert_eq!(state.regs[0], Some(ConcreteValue::StackPtr(STACK_BASE - 8)));
    }

    #[test]
    fn stack_uninit_read_rejected() {
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::LdStack { dst: 0, offset: -8 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::UninitializedStackRead { pc: 0, offset: -8 }
        );
        // spilling an uninitialized register is also a read (#14)
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::StStack { src: 3, offset: -8 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::UninitializedRead { pc: 0, reg: 3 });
    }

    #[test]
    fn stack_offset_checks() {
        // offset pointing away from the frame
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::StStack { src: 1, offset: 0 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::StackOutOfFrame { pc: 0, offset: 0 });
        // offset beyond the frame
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::StStack {
                src: 1,
                offset: -520,
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::StackOutOfFrame {
                pc: 0,
                offset: -520
            }
        );
        // misaligned offset
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::StStack { src: 1, offset: -7 },
        )
        .unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::MisalignedStackAccess { pc: 0, offset: -7 }
        );
    }

    #[test]
    fn invalid_register_rejected() {
        let err = concrete_step(
            0,
            &ConcreteState::initial(),
            &BpfInsn::MovImm { dst: 11, imm: 1 },
        )
        .unwrap_err();
        assert_eq!(err, ConcreteFailure::InvalidRegister { pc: 0, reg: 11 });
    }

    // ── concrete path exploration (#51) ──────────────────────────────────

    #[test]
    fn run_straight_line_outcome() {
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        assert!(!run.inconclusive);
        assert_eq!(run.outcomes.len(), 1);
        assert_eq!(run.outcomes[0].pc, 1);
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(42))
        );
        assert_eq!(run.visited.len(), 2); // pc 0 and pc 1 (exit)
    }

    #[test]
    fn run_deterministic_branch_taken() {
        // r0 = 5 > r1 = 3 → taken, skipping r0 = 0
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 5 },
            BpfInsn::MovImm { dst: 1, imm: 3 },
            BpfInsn::Jgt {
                dst: 0,
                src: 1,
                offset: 1,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert_eq!(run.outcomes.len(), 1);
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(5))
        );
    }

    #[test]
    fn run_deterministic_branch_fall() {
        // r0 = 2 is not > r1 = 3 → fall-through executes r0 = 0
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 2 },
            BpfInsn::MovImm { dst: 1, imm: 3 },
            BpfInsn::Jgt {
                dst: 0,
                src: 1,
                offset: 1,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert_eq!(run.outcomes.len(), 1);
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(0))
        );
    }

    #[test]
    fn run_branch_only_visits_taken_side() {
        // taken jump skips pc 3 and pc 4 — they must not appear in visited
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 5 },
            BpfInsn::MovImm { dst: 1, imm: 3 },
            BpfInsn::Jgt {
                dst: 0,
                src: 1,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 0, imm: 9 },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(5))
        );
        assert!(!run.visited.iter().any(|(pc, _)| *pc == 3));
        assert!(!run.visited.iter().any(|(pc, _)| *pc == 4));
    }

    #[test]
    fn run_bounded_loop_terminates() {
        // #46-style loop: r0 accumulates 100 iterations
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::MovImm { dst: 2, imm: 100 },
            BpfInsn::AddImm { dst: 0, imm: 1 }, // pc 3 = loop head
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -3,
            },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[3]).unwrap();
        assert!(!run.inconclusive);
        assert_eq!(run.outcomes.len(), 1);
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(100))
        );
    }

    #[test]
    fn run_non_terminating_loop_inconclusive() {
        // r0 += 1; goto -2 — the state at the loop head changes forever
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::AddImm { dst: 0, imm: 1 },
            BpfInsn::Jmp { offset: -2 },
        ];
        let run = run_concrete(&program, &[1]).unwrap();
        assert!(run.inconclusive);
    }

    #[test]
    fn run_helper_seed_fork() {
        // get_prandom_u32 (7): unknown scalar → default seeds
        let program = vec![BpfInsn::Call { imm: 7 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        assert!(!run.inconclusive);
        let mut r0s: Vec<Option<ConcreteValue>> =
            run.outcomes.iter().map(|o| o.state.regs[0]).collect();
        r0s.sort_by_key(|r| match r {
            Some(ConcreteValue::Scalar(v)) => *v,
            _ => u64::MAX,
        });
        assert_eq!(r0s.len(), 3);
        assert_eq!(r0s[0], Some(ConcreteValue::Scalar(0)));
        assert_eq!(r0s[1], Some(ConcreteValue::Scalar(1)));
        assert_eq!(r0s[2], Some(ConcreteValue::Scalar(u64::MAX)));
    }

    #[test]
    fn run_helper_call_clobbers_args() {
        let program = vec![
            BpfInsn::MovImm { dst: 2, imm: 5 },
            BpfInsn::Call { imm: 7 },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        // after the call, R1..R5 are clobbered and R0 holds a seed
        let call_successor = run
            .visited
            .iter()
            .find(|(pc, _)| *pc == 2)
            .expect("call successor visited");
        assert_eq!(call_successor.1.regs[2], None);
        assert!(matches!(
            call_successor.1.regs[0],
            Some(ConcreteValue::Scalar(_))
        ));
    }

    #[test]
    fn run_unknown_helper() {
        let program = vec![BpfInsn::Call { imm: 999 }];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(err, ConcreteFailure::UnknownHelper { pc: 0, imm: 999 });
    }

    #[test]
    fn run_helper_arg_mismatch() {
        // map_lookup (1) expects R1 = PtrToMap, but R1 is the context
        // pointer at entry (mirror of the invalid_helper_argument fixture)
        let program = vec![BpfInsn::Call { imm: 1 }];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(err, ConcreteFailure::HelperArgMismatch { pc: 0, arg: 1 });
    }

    // ── Immediate compares (BPF_J*_K, #57) ───────────────────────────────────

    #[test]
    fn run_imm_compare_deterministic() {
        // a concrete immediate compare takes exactly one successor:
        // r1 = 5; jeq r1, 5, +1 → taken (the fall-through is never
        // explored)
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::JeqImm {
                dst: 1,
                imm: 5,
                offset: 1,
            },
            BpfInsn::Exit, // fall-through (never reached)
            BpfInsn::Exit, // taken target
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert!(!run.inconclusive);
        assert!(
            run.visited.iter().all(|(pc, _)| *pc != 3),
            "the fall-through must not be explored"
        );
        assert_eq!(run.outcomes.len(), 1);
    }

    #[test]
    fn run_jsgt_imm_negative_sign_extends() {
        // the imm sign-extends to 64 bits like the kernel:
        // r1 = 0; jsgt r1, -1 → 0 > -1 signed → taken
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::JsgtImm {
                dst: 1,
                imm: -1,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert!(!run.inconclusive);
        assert!(
            run.visited.iter().all(|(pc, _)| *pc != 3),
            "the fall-through must not be explored"
        );
    }

    #[test]
    fn run_imm_compare_pointer_rejected() {
        // a pointer compared to an immediate fails concretely too
        // (r1 = CtxPtr at entry, mirror of the abstract rejection)
        let program = vec![BpfInsn::JeqImm {
            dst: 1,
            imm: 0,
            offset: 1,
        }];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(err, ConcreteFailure::InvalidComparisonImm { pc: 0, dst: 1 });
    }

    #[test]
    fn run_pointer_ordering_rejected() {
        // ordering on same-kind pointers (r10 vs r10)
        let program = vec![BpfInsn::Jgt {
            dst: 10,
            src: 10,
            offset: 1,
        }];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidComparison {
                pc: 0,
                dst: 10,
                src: 10
            }
        );
        // mixed pointer/scalar comparison
        let program = vec![
            BpfInsn::MovImm { dst: 2, imm: 5 },
            BpfInsn::Jgt {
                dst: 10,
                src: 2,
                offset: 1,
            },
        ];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(
            err,
            ConcreteFailure::InvalidComparison {
                pc: 1,
                dst: 10,
                src: 2
            }
        );
    }

    #[test]
    fn run_pointer_equality_ok() {
        // r10 == r10 → taken, skipping r0 = 0
        let program = vec![
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 1,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        let run = run_concrete(&program, &[]).unwrap();
        assert_eq!(
            run.outcomes[0].state.regs[0],
            Some(ConcreteValue::Scalar(1))
        );
    }

    #[test]
    fn run_exit_with_uninit_r0() {
        let program = vec![BpfInsn::Exit];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(err, ConcreteFailure::UninitializedRead { pc: 0, reg: 0 });
    }

    #[test]
    fn run_jump_out_of_program_is_internal_error() {
        // defensive: the structural pass rejects this before the driver
        let program = vec![BpfInsn::Jmp { offset: 100 }, BpfInsn::Exit];
        let err = run_concrete(&program, &[]).unwrap_err();
        assert_eq!(err, ConcreteFailure::InternalError { pc: 101 });
    }

    // ── abstract↔concrete coverage checker (#52) ─────────────────────────

    /// The abstract states for `[r0 = 42, exit]`: initial at pc 0, a
    /// state with `r0 = 42` at pc 1.
    fn abstract_states_for_constant_program(r0_at_exit: i64) -> HashMap<u32, Vec<VerifierState>> {
        let mut abstract_states: HashMap<u32, Vec<VerifierState>> = HashMap::new();
        abstract_states.insert(0, vec![VerifierState::initial()]);
        let mut at_exit = VerifierState::initial();
        at_exit.regs[0] = RegState::Scalar(ScalarBounds::constant(r0_at_exit));
        abstract_states.insert(1, vec![at_exit]);
        abstract_states
    }

    #[test]
    fn check_coverage_clean_run() {
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        let abstract_states = abstract_states_for_constant_program(42);
        assert_eq!(check_coverage(&abstract_states, &run), vec![]);
    }

    #[test]
    fn check_coverage_detects_unsound() {
        // the abstract state at pc 1 covers only 41, not the concrete 42
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        let abstract_states = abstract_states_for_constant_program(41);
        let violations = check_coverage(&abstract_states, &run);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].pc, 1);
        assert_eq!(violations[0].kind, CoverageKind::NotCovered);
        assert_eq!(violations[0].abstract_states.len(), 1);
    }

    #[test]
    fn check_coverage_detects_missing_pc() {
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        // pc 1 (exit) is missing from the abstract side
        let mut abstract_states: HashMap<u32, Vec<VerifierState>> = HashMap::new();
        abstract_states.insert(0, vec![VerifierState::initial()]);
        let violations = check_coverage(&abstract_states, &run);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].pc, 1);
        assert_eq!(violations[0].kind, CoverageKind::AbstractMissedPc);
        assert!(violations[0].abstract_states.is_empty());
    }

    #[test]
    fn check_coverage_initial_mismatch() {
        // abstract pc 0 has R0 initialized, concrete initial R0 is None
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        let mut abstract_states = abstract_states_for_constant_program(42);
        let mut wrong_initial = VerifierState::initial();
        wrong_initial.regs[0] = RegState::Scalar(ScalarBounds::constant(0));
        abstract_states.insert(0, vec![wrong_initial]);
        let violations = check_coverage(&abstract_states, &run);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].pc, 0);
        assert_eq!(violations[0].kind, CoverageKind::NotCovered);
    }

    #[test]
    fn check_coverage_end_to_end_accept() {
        // a branched program with a helper call: the abstract pass and
        // the concrete run must agree (no violations)
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Call { imm: 7 }, // r0 = prandom (unknown scalar)
            BpfInsn::MovImm { dst: 1, imm: 10 },
            BpfInsn::Jgt {
                dst: 0,
                src: 1,
                offset: 0,
            },
            BpfInsn::Exit,
        ];
        let (_, abstract_states) =
            crate::mini::verify_mini_with_states(&program, &[], &Default::default()).unwrap();
        let run = run_concrete(&program, &[]).unwrap();
        assert!(!run.inconclusive);
        assert_eq!(check_coverage(&abstract_states, &run), vec![]);
    }

    #[test]
    fn render_report_readable() {
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();
        let abstract_states = abstract_states_for_constant_program(41);
        let violations = check_coverage(&abstract_states, &run);
        let report = render_coverage_report(&violations, &program);
        assert!(report.contains("coverage violation at insn 1"));
        assert!(report.contains("NOT COVERED"));
        assert!(report.contains("1: exit")); // disassembled instruction
        assert!(report.contains("Scalar(42)")); // concrete value
        assert!(report.contains("SCALAR(s:41..41")); // abstract candidate
    }

    #[test]
    fn render_report_distinguishes_kinds() {
        // an unsoundness and a precision case must render differently
        let program = [BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let run = run_concrete(&program, &[]).unwrap();

        let unsound_states = abstract_states_for_constant_program(41);
        let unsound = check_coverage(&unsound_states, &run);
        assert_eq!(unsound.len(), 1);
        let report = render_coverage_report(&unsound, &program);
        assert!(report.contains("NOT COVERED"));
        assert!(!report.contains("ABSTRACT MISSED PC"));

        // precision case: the abstract never visited pc 1
        let mut missing: HashMap<u32, Vec<VerifierState>> = HashMap::new();
        missing.insert(0, vec![VerifierState::initial()]);
        let precision = check_coverage(&missing, &run);
        assert_eq!(precision.len(), 1);
        assert_eq!(precision[0].kind, CoverageKind::AbstractMissedPc);
        let report = render_coverage_report(&precision, &program);
        assert!(report.contains("ABSTRACT MISSED PC"));
        assert!(!report.contains("NOT COVERED"));
    }
}
