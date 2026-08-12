// ── Concrete execution state model (v0.5 Concrete, #49) ─────────────────────

//! Concrete counterpart of the abstract [`VerifierState`]: the same program
//! executed with real values, so the abstract state can be checked to
//! always cover the concrete results (Phase 2).
//!
//! The containment test mirrors [`crate::mini::reg_subsumes`] (abstract ⊇
//! abstract) with the direction reversed: does the abstract state contain
//! this actual value? Since #50 the concrete side is type-aware — a scalar
//! holding the same bits as a stack address is not a stack pointer.

use crate::exec::{AluOp, AluWidth, alu_const32, alu_const64};
use crate::insn::BpfInsn;
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
    #[allow(dead_code)] // constructed by the interpreter (#50); used by tests
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
#[allow(dead_code)] // used by the coverage checker (#52); used by tests
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
    // shifts require a provable amount in 0..64 (mirror of the abstract
    // alu_imm check, which applies to both widths)
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && !(0..64).contains(&imm) {
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
            // shifts require an amount in 0..64: the abstract
            // check_shift_amount rejects smin < 0 or umax >= 64, which
            // collapses to s >= 64 for a single value
            if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && s >= 64 {
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
    fn alu32_imm_shift_large_accepted() {
        // the abstract accepts ALU32 immediate shifts up to 63 (the
        // 0..64 check applies to both widths); a shift by 40 of a 32-bit
        // value is 0 (checked shift semantics)
        let state = run(&[
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::Lsh32Imm { dst: 2, imm: 40 },
        ]);
        assert_eq!(state.regs[2], Some(ConcreteValue::Scalar(0)));
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
}
