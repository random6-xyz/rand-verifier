// ── Abstract instruction execution and branch expansion ─────────────────────

use crate::error::VerificationFailure;
use crate::helper::{check_helper_args, helper_prototype};
use crate::insn::BpfInsn;
use crate::state::{
    RegState, STACK_SIZE, ScalarBounds, StackSlot, VerifierState, check_reg, read_reg, read_scalar,
    stack_slot_index,
};

/// ALU operations of the custom opcode space (Meso #39).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AluOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Lsh,
    Rsh,
    Arsh,
}

/// ALU width: ALU64 (full 64-bit) or ALU32 (truncating, zero-extended).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AluWidth {
    W64,
    W32,
}

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
        // rX = imm → constant scalar (both interpretations carry the
        // same bits: -1 is -1 signed and u64::MAX unsigned, #40)
        BpfInsn::MovImm { dst, imm } => {
            check_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar(ScalarBounds::constant(*imm as i64));
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
        | BpfInsn::Jsle { .. } => {
            unreachable!("exit and control flow are expanded by successors(), not step()")
        }
        // ALU64: rX += imm (pointer + immediate stays the only pointer
        // arithmetic, #20)
        BpfInsn::AddImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Add, AluWidth::W64),
        BpfInsn::AddReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Add, AluWidth::W64),
        BpfInsn::SubImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Sub, AluWidth::W64),
        BpfInsn::SubReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Sub, AluWidth::W64),
        BpfInsn::AndImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::And, AluWidth::W64),
        BpfInsn::AndReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::And, AluWidth::W64),
        BpfInsn::OrImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Or, AluWidth::W64),
        BpfInsn::OrReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Or, AluWidth::W64),
        BpfInsn::XorImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Xor, AluWidth::W64),
        BpfInsn::XorReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Xor, AluWidth::W64),
        BpfInsn::LshImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Lsh, AluWidth::W64),
        BpfInsn::LshReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Lsh, AluWidth::W64),
        BpfInsn::RshImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Rsh, AluWidth::W64),
        BpfInsn::RshReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Rsh, AluWidth::W64),
        BpfInsn::ArshImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Arsh, AluWidth::W64),
        BpfInsn::ArshReg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Arsh, AluWidth::W64),
        // ALU32 (#39): the same operations, truncating and zero-extending
        BpfInsn::Add32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Add, AluWidth::W32),
        BpfInsn::Add32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Add, AluWidth::W32),
        BpfInsn::Sub32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Sub, AluWidth::W32),
        BpfInsn::Sub32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Sub, AluWidth::W32),
        BpfInsn::And32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::And, AluWidth::W32),
        BpfInsn::And32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::And, AluWidth::W32),
        BpfInsn::Or32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Or, AluWidth::W32),
        BpfInsn::Or32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Or, AluWidth::W32),
        BpfInsn::Xor32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Xor, AluWidth::W32),
        BpfInsn::Xor32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Xor, AluWidth::W32),
        BpfInsn::Lsh32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Lsh, AluWidth::W32),
        BpfInsn::Lsh32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Lsh, AluWidth::W32),
        BpfInsn::Rsh32Imm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Rsh, AluWidth::W32),
        BpfInsn::Rsh32Reg { dst, src } => alu_reg(pc, state, *dst, *src, AluOp::Rsh, AluWidth::W32),
        BpfInsn::Arsh32Imm { dst, imm } => {
            alu_imm(pc, state, *dst, *imm, AluOp::Arsh, AluWidth::W32)
        }
        BpfInsn::Arsh32Reg { dst, src } => {
            alu_reg(pc, state, *dst, *src, AluOp::Arsh, AluWidth::W32)
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

// ── ALU helpers (Meso #39) ──────────────────────────────────────────────────

/// Execute an ALU operation with an immediate operand.
///
/// Scalar destinations get the (possibly over-approximated) result range;
/// stack pointers only support `rX += imm` (#20), and every other pointer
/// type rejects arithmetic (mirroring the kernel's check_alu_op).
fn alu_imm(
    pc: u32,
    state: &VerifierState,
    dst: u8,
    imm: i32,
    op: AluOp,
    width: AluWidth,
) -> Result<VerifierState, VerificationFailure> {
    check_reg(pc, dst)?;
    // shifts require a provable amount in 0..64 (kernel check_alu_op)
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && !(0..64).contains(&imm) {
        return Err(VerificationFailure::new(
            pc,
            format!("invalid shift amount {}", imm),
        ));
    }
    let dst_state = read_reg(pc, state, dst)?;
    match dst_state {
        RegState::Scalar(d) => {
            let next_bounds = apply_alu(op, width, d, ScalarBounds::constant(imm as i64));
            let mut next = *state;
            next.regs[dst as usize] = RegState::Scalar(next_bounds);
            Ok(next)
        }
        // PtrToStack + imm => PtrToStack at the shifted offset;
        // the pointer must stay within the frame (cf. #19). Only ADD is
        // allowed on stack pointers — like the kernel's check_alu_op.
        RegState::PtrToStack { offset } => {
            if op != AluOp::Add || width != AluWidth::W64 {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "arithmetic on stack pointer r{} is not allowed (only ADD supports stack pointer arithmetic)",
                        dst
                    ),
                ));
            }
            let new_offset = offset.wrapping_add(imm);
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
            next.regs[dst as usize] = RegState::PtrToStack { offset: new_offset };
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

/// Execute an ALU operation with a register operand.
///
/// Both operands must be scalars; register-offset pointer arithmetic is
/// not supported yet (only immediate offsets, #20) — the real bounds and
/// alignment checks for `PtrToStack + ScalarRange` land in #45.
fn alu_reg(
    pc: u32,
    state: &VerifierState,
    dst: u8,
    src: u8,
    op: AluOp,
    width: AluWidth,
) -> Result<VerifierState, VerificationFailure> {
    check_reg(pc, dst)?;
    let dst_state = read_reg(pc, state, dst)?;
    let d = match dst_state {
        RegState::Scalar(bounds) => bounds,
        _ => {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "register-offset pointer arithmetic on r{} is not supported yet (only immediate offsets)",
                    dst
                ),
            ));
        }
    };
    let s = read_scalar(pc, state, src)?;
    // shifts require a provable amount in 0..64 (kernel check_alu_op)
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) {
        check_shift_amount(pc, s)?;
    }
    let next_bounds = apply_alu(op, width, d, s);
    let mut next = *state;
    next.regs[dst as usize] = RegState::Scalar(next_bounds);
    Ok(next)
}

/// Apply an ALU operation to scalar bounds: both interpretations are
/// updated (#40). Exact constants propagate bit-exactly; ranges get a
/// sound per-family over-approximation; ALU32 truncates to 32 bits and
/// zero-extends (the result always lies in `[0, 0xFFFFFFFF]`). The result
/// is re-synced (kernel reg_bounds_sync) so the two interpretations stay
/// consistent.
fn apply_alu(op: AluOp, width: AluWidth, d: ScalarBounds, s: ScalarBounds) -> ScalarBounds {
    // exact constants propagate bit-exactly in both interpretations
    if d.is_constant() && s.is_constant() {
        let bits = match width {
            AluWidth::W64 => alu_const64(op, d.smin as u64, s.smin as u64),
            AluWidth::W32 => alu_const32(op, d.smin as u64, s.smin as u64),
        };
        return ScalarBounds::constant(bits as i64);
    }
    match width {
        AluWidth::W64 => {
            let (sm, sx) = alu64_signed(op, d.signed(), s.signed());
            // the shift amount is validated on the signed family; the
            // unsigned family uses the same amount range
            let amount = if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) {
                (s.smin as u64, s.smax as u64)
            } else {
                s.unsigned()
            };
            let (um, ux) = alu64_unsigned(op, d.unsigned(), amount);
            ScalarBounds {
                smin: sm,
                smax: sx,
                umin: um,
                umax: ux,
                s32_min: i32::MIN,
                s32_max: i32::MAX,
                u32_min: 0,
                u32_max: u32::MAX,
            }
            .synced()
        }
        // ALU32 with a non-constant operand: compute the result range in
        // 32-bit space (truncating operands), then zero-extend it into
        // the 64-bit ranges — the high 32 bits become known zero (#41).
        // The sync derives the 32-bit sub-ranges from the result.
        AluWidth::W32 => {
            let (rmin, rmax) = alu32_range(op, (d.u32_min, d.u32_max), (s.u32_min, s.u32_max));
            ScalarBounds {
                smin: rmin as i64,
                smax: rmax as i64,
                umin: rmin as u64,
                umax: rmax as u64,
                s32_min: i32::MIN,
                s32_max: i32::MAX,
                u32_min: 0,
                u32_max: u32::MAX,
            }
            .synced()
        }
    }
}

/// ALU32 range arithmetic in 32-bit space (truncating, wrap-aware).
/// The shift amount range is validated by the caller.
fn alu32_range(op: AluOp, d: (u32, u32), s: (u32, u32)) -> (u32, u32) {
    match op {
        // the sum interval [d.0 + s.0, d.1 + s.1] mod 2^32 is a single
        // interval iff it fits in one 32-bit window
        AluOp::Add => interval_mod(d.0 as i64 + s.0 as i64, d.1 as i64 + s.1 as i64),
        // x - y ranges over [d.0 - s.1, d.1 - s.0]
        AluOp::Sub => interval_mod(d.0 as i64 - s.1 as i64, d.1 as i64 - s.0 as i64),
        AluOp::And => (0, d.1.min(s.1)),
        AluOp::Or => (d.0.max(s.0), u32::MAX),
        AluOp::Xor => (0, u32::MAX),
        AluOp::Lsh | AluOp::Rsh | AluOp::Arsh => shift32_range(op, d, s),
    }
}

/// Map an integer interval [lo, hi] into [0, 2^32): a single interval
/// iff it is narrower than 2^32 and does not cross a multiple of 2^32.
fn interval_mod(lo: i64, hi: i64) -> (u32, u32) {
    if hi - lo < 0x1_0000_0000 && lo.rem_euclid(0x1_0000_0000) <= hi.rem_euclid(0x1_0000_0000) {
        (
            lo.rem_euclid(0x1_0000_0000) as u32,
            hi.rem_euclid(0x1_0000_0000) as u32,
        )
    } else {
        (0, u32::MAX)
    }
}

/// 32-bit shift ranges; the amount is validated in 0..64 by the caller.
fn shift32_range(op: AluOp, d: (u32, u32), s: (u32, u32)) -> (u32, u32) {
    if s.0 != s.1 {
        // unknown amount: coarse but sound
        return match op {
            AluOp::Lsh => (0, u32::MAX),
            AluOp::Rsh => (0, d.1),
            AluOp::Arsh => (0, u32::MAX),
            _ => unreachable!(),
        };
    }
    let k = s.0;
    match op {
        AluOp::Lsh => {
            if k >= 32 {
                (0, 0)
            } else if d.1 < 1u32 << (32 - k) {
                (d.0 << k, d.1 << k)
            } else {
                // the shift can overflow the 32-bit window
                (0, u32::MAX)
            }
        }
        AluOp::Rsh => {
            if k >= 32 {
                (0, 0)
            } else {
                (d.0 >> k, d.1 >> k)
            }
        }
        AluOp::Arsh => {
            if k >= 32 {
                // sign fill: the whole range becomes one sign
                if (d.0 as i32) < 0 {
                    (u32::MAX, u32::MAX)
                } else {
                    (0, 0)
                }
            } else {
                ((d.0 as i32 >> k) as u32, (d.1 as i32 >> k) as u32)
            }
        }
        _ => unreachable!(),
    }
}

/// Exact 64-bit ALU on constant bits (wrapping is exact bit arithmetic).
/// Shift amounts are validated by the caller.
fn alu_const64(op: AluOp, a: u64, b: u64) -> u64 {
    match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::And => a & b,
        AluOp::Or => a | b,
        AluOp::Xor => a ^ b,
        AluOp::Lsh => a.wrapping_shl(b as u32),
        AluOp::Rsh => a.wrapping_shr(b as u32),
        AluOp::Arsh => ((a as i64) >> b) as u64,
    }
}

/// Exact 32-bit ALU on constant bits: truncate, compute, zero-extend.
fn alu_const32(op: AluOp, a: u64, b: u64) -> u64 {
    let a = a as u32;
    let b = b as u32;
    let r = match op {
        AluOp::Add => a.wrapping_add(b),
        AluOp::Sub => a.wrapping_sub(b),
        AluOp::And => a & b,
        AluOp::Or => a | b,
        AluOp::Xor => a ^ b,
        AluOp::Lsh => a.checked_shl(b).unwrap_or(0),
        AluOp::Rsh => a.checked_shr(b).unwrap_or(0),
        AluOp::Arsh => (a as i32)
            .checked_shr(b)
            .unwrap_or(if (a as i32) < 0 { -1 } else { 0 }) as u32,
    };
    r as u64
}

/// Validate a shift amount: the kernel rejects shifts that are not provably
/// in `0..64` (check_alu_op's "invalid shift"). Both interpretations are
/// consulted so a diverged state cannot smuggle an invalid amount.
fn check_shift_amount(pc: u32, s: ScalarBounds) -> Result<(), VerificationFailure> {
    if s.smin < 0 || s.smax >= 64 || s.umax >= 64 {
        return Err(VerificationFailure::new(
            pc,
            format!("invalid shift amount range [{}, {}]", s.smin, s.smax),
        ));
    }
    Ok(())
}

/// 64-bit signed-family range arithmetic (#39, the signed view of #40).
///
/// Constants propagate exactly; ranges get a sound over-approximation
/// where an exact interval is not easy to derive. Overflow handling
/// lands in #43. Shift amounts are validated by the caller.
fn alu64_signed(op: AluOp, d: (i64, i64), s: (i64, i64)) -> (i64, i64) {
    let (dmin, dmax) = d;
    let (smin, smax) = s;
    // constants propagate exactly (wrapping is exact bit arithmetic)
    if dmin == dmax && smin == smax {
        let bits = alu_const64(op, dmin as u64, smin as u64);
        return (bits as i64, bits as i64);
    }
    match op {
        AluOp::Add => (dmin.wrapping_add(smin), dmax.wrapping_add(smax)),
        AluOp::Sub => (dmin.wrapping_sub(smax), dmax.wrapping_sub(smin)),
        // AND of non-negative ranges stays in [0, min(max1, max2)];
        // with a possible negative operand the sign bits make the result
        // unbounded (e.g. -1 & x)
        AluOp::And => {
            if dmin >= 0 && smin >= 0 {
                (0, dmax.min(smax))
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        // OR of non-negative ranges is at least the larger lower bound
        // and never negative; the upper bits are unknown
        AluOp::Or => {
            if dmin >= 0 && smin >= 0 {
                (dmin.max(smin), i64::MAX)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Xor => {
            if dmin >= 0 && smin >= 0 {
                (0, i64::MAX)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Lsh | AluOp::Rsh | AluOp::Arsh => shift64_range(op, dmin, dmax, smin, smax),
    }
}

/// 64-bit unsigned-family range arithmetic (the u64 view, #40). The
/// shift amount range is passed in by the caller (validated on the
/// signed family).
fn alu64_unsigned(op: AluOp, d: (u64, u64), s: (u64, u64)) -> (u64, u64) {
    let (dmin, dmax) = d;
    let (smin, smax) = s;
    match op {
        AluOp::Add => (dmin.wrapping_add(smin), dmax.wrapping_add(smax)),
        AluOp::Sub => (dmin.wrapping_sub(smax), dmax.wrapping_sub(smin)),
        // u64 values are never negative: AND clears bits, OR sets them,
        // XOR is unbounded below the mask
        AluOp::And => (0, dmax.min(smax)),
        AluOp::Or => (dmin.max(smin), u64::MAX),
        AluOp::Xor => (0, u64::MAX),
        AluOp::Lsh => {
            if smin == smax && dmax <= (u64::MAX >> smin as u32) {
                (dmin << smin as u32, dmax << smin as u32)
            } else {
                (0, u64::MAX)
            }
        }
        AluOp::Rsh => {
            if smin == smax {
                (dmin >> smin as u32, dmax >> smin as u32)
            } else {
                (0, dmax)
            }
        }
        // arithmetic shift on the unsigned view is unbounded
        AluOp::Arsh => (0, u64::MAX),
    }
}

/// Shift a range by a constant shift amount (validated in `0..64`).
fn shift64_by_const(op: AluOp, dmin: i64, dmax: i64, k: u32) -> (i64, i64) {
    match op {
        // logical shift: the u64 view is monotone; a result that crosses
        // the sign bit cannot be represented as one i64 interval
        AluOp::Lsh => {
            if dmin < 0 {
                return (i64::MIN, i64::MAX);
            }
            let lo = (dmin as u64) << k;
            let hi = (dmax as u64) << k;
            if lo >= 1 << 63 || hi < 1 << 63 {
                (lo as i64, hi as i64)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Rsh => {
            if dmin < 0 {
                (i64::MIN, i64::MAX)
            } else {
                (((dmin as u64) >> k) as i64, ((dmax as u64) >> k) as i64)
            }
        }
        // arithmetic shift is monotone on i64 for a fixed k
        AluOp::Arsh => (dmin >> k, dmax >> k),
        _ => unreachable!("shift64_by_const only handles shifts"),
    }
}

/// Shift a range by a validated shift range: coarse but sound.
fn shift64_range(op: AluOp, dmin: i64, dmax: i64, smin: i64, smax: i64) -> (i64, i64) {
    if smin == smax {
        return shift64_by_const(op, dmin, dmax, smin as u32);
    }
    match op {
        // some shift amount in [smin, smax] applies; only the extremes
        // that hold for every amount are usable
        AluOp::Lsh => {
            if dmin >= 0 {
                (0, i64::MAX)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Rsh => {
            if dmin >= 0 {
                (0, dmax)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Arsh => (dmin >> 63, dmax),
        _ => unreachable!("shift64_range only handles shifts"),
    }
}

// ── Branch refinement (v0.2 Micro, dual ranges in Meso #40) ────────────────

/// Minimal numeric operations for the refinement equations, shared by
/// the i64 (signed) and u64 (unsigned) interval families.
trait WrapInt: Copy + Ord {
    const MIN: Self;
    const MAX: Self;
    const ONE: Self;
    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;
}

impl WrapInt for i64 {
    const MIN: Self = i64::MIN;
    const MAX: Self = i64::MAX;
    const ONE: Self = 1;
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

impl WrapInt for u64 {
    const MIN: Self = u64::MIN;
    const MAX: Self = u64::MAX;
    const ONE: Self = 1;
    fn wrapping_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrapping_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
}

/// Ordered comparison shape without signedness (the kernel equations are
/// shared by both interval families).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OrdOp {
    Gt,
    Ge,
    Lt,
    Le,
}

/// Both operands of a comparison refined for one branch side: (dst, src).
type RefinedPair = (ScalarBounds, ScalarBounds);

/// Refinement result of a comparison: (true branch, false branch).
type RefinedBranches = (RefinedPair, RefinedPair);

/// Refined intervals of one interval family: (true, false) × (dst, src).
type RefinedFamily<T> = (((T, T), (T, T)), ((T, T), (T, T)));

/// The kernel's refinement equations (reg_set_min_max / inv) for one
/// ordered comparison on one interval family.
fn refine_ordered<T: WrapInt>(op: OrdOp, dst: (T, T), src: (T, T)) -> RefinedFamily<T> {
    match op {
        // true: dst > src → dst >= src.min + 1, src <= dst.max - 1
        // false: dst <= src → dst <= src.max, src >= dst.min
        OrdOp::Gt => {
            let true_dst = (dst.0.max(src.0.wrapping_add(T::ONE)), dst.1);
            let true_src = (src.0, src.1.min(dst.1.wrapping_sub(T::ONE)));
            let false_dst = (dst.0, dst.1.min(src.1));
            let false_src = (src.0.max(dst.0), src.1);
            ((true_dst, true_src), (false_dst, false_src))
        }
        // true: dst >= src → dst >= src.min, src <= dst.max
        // false: dst < src → dst <= src.min - 1, src >= dst.min + 1
        OrdOp::Ge => {
            let true_dst = (dst.0.max(src.0), dst.1);
            let true_src = (src.0, src.1.min(dst.1));
            let false_dst = (dst.0, dst.1.min(src.0.wrapping_sub(T::ONE)));
            let false_src = (src.0.max(dst.0.wrapping_add(T::ONE)), src.1);
            ((true_dst, true_src), (false_dst, false_src))
        }
        // true: dst < src → dst <= src.max - 1, src >= dst.min + 1
        // false: dst >= src → dst >= src.min, src <= dst.max
        OrdOp::Lt => {
            let true_dst = (dst.0, dst.1.min(src.1.wrapping_sub(T::ONE)));
            let true_src = (src.0.max(dst.0.wrapping_add(T::ONE)), src.1);
            let false_dst = (dst.0.max(src.0), dst.1);
            let false_src = (src.0, src.1.min(dst.1));
            ((true_dst, true_src), (false_dst, false_src))
        }
        // true: dst <= src → dst <= src.max, src >= dst.min
        // false: dst > src → dst >= src.min + 1, src <= dst.max - 1
        OrdOp::Le => {
            let true_dst = (dst.0, dst.1.min(src.1));
            let true_src = (src.0.max(dst.0), src.1);
            let false_dst = (dst.0.max(src.0.wrapping_add(T::ONE)), dst.1);
            let false_src = (src.0, src.1.min(dst.1.wrapping_sub(T::ONE)));
            ((true_dst, true_src), (false_dst, false_src))
        }
    }
}

/// Refine two scalar bounds for both branch sides of `dst OP src`.
///
/// The opcode family decides which interval family is narrowed (kernel
/// regs_refine_cond_op): unsigned compares narrow `umin`/`umax`, signed
/// compares narrow `smin`/`smax`; equality and inequality narrow both.
/// Every refined state is re-synced so the interpretations stay
/// consistent (kernel reg_bounds_sync). A refined range with min > max
/// means the branch is infeasible.
pub(crate) fn refine_cmp(op: CondOp, dst: ScalarBounds, src: ScalarBounds) -> RefinedBranches {
    match op {
        CondOp::Eq => refine_eq(dst, src),
        CondOp::Ne => refine_ne(dst, src),
        _ => {
            let ord = op.ord().expect("ordered comparison");
            if op.is_signed() {
                let ((td, ts), (fd, fs)) = refine_ordered(ord, dst.signed(), src.signed());
                (
                    (with_signed(dst, td).synced(), with_signed(src, ts).synced()),
                    (with_signed(dst, fd).synced(), with_signed(src, fs).synced()),
                )
            } else {
                let ((td, ts), (fd, fs)) = refine_ordered(ord, dst.unsigned(), src.unsigned());
                (
                    (
                        with_unsigned(dst, td).synced(),
                        with_unsigned(src, ts).synced(),
                    ),
                    (
                        with_unsigned(dst, fd).synced(),
                        with_unsigned(src, fs).synced(),
                    ),
                )
            }
        }
    }
}

fn with_signed(b: ScalarBounds, r: (i64, i64)) -> ScalarBounds {
    let mut b = b;
    b.smin = r.0;
    b.smax = r.1;
    b
}

fn with_unsigned(b: ScalarBounds, r: (u64, u64)) -> ScalarBounds {
    let mut b = b;
    b.umin = r.0;
    b.umax = r.1;
    b
}

/// Refine two scalar bounds on the `dst == src` comparison.
///
/// - true branch: both operands take the intersection of the two bounds
///   per interval family (min > max means the branch is infeasible)
/// - false branch: a single interval cannot represent the complement of
///   another interval, so no safe narrowing is possible — both are kept
pub(crate) fn refine_eq(dst: ScalarBounds, src: ScalarBounds) -> RefinedBranches {
    let inter = ScalarBounds {
        smin: dst.smin.max(src.smin),
        smax: dst.smax.min(src.smax),
        umin: dst.umin.max(src.umin),
        umax: dst.umax.min(src.umax),
        s32_min: i32::MIN,
        s32_max: i32::MAX,
        u32_min: 0,
        u32_max: u32::MAX,
    }
    .synced();
    ((inter, inter), (dst, src))
}

/// Narrow `a` by excluding `b`'s values, when the complement is still a
/// single interval. `None` means no narrowing is representable.
fn exclude_interval<T: WrapInt>(a: (T, T), b: (T, T)) -> Option<(T, T)> {
    // b covers everything of a → the branch is infeasible (empty range)
    if b.0 <= a.0 && b.1 >= a.1 {
        return Some((T::MAX, T::MIN));
    }
    // b sits at the low end of a → a ∈ [b.1 + 1, a.1]
    if b.0 <= a.0 {
        return Some((b.1.wrapping_add(T::ONE), a.1));
    }
    // b sits at the high end of a → a ∈ [a.0, b.0 - 1]
    if b.1 >= a.1 {
        return Some((a.0, b.0.wrapping_sub(T::ONE)));
    }
    // b is strictly inside a → the complement is two intervals
    None
}

/// Narrow every interval family of `a` by excluding `b`'s values where
/// a single interval still represents the complement.
fn exclude_bounds(a: ScalarBounds, b: ScalarBounds) -> ScalarBounds {
    let s = exclude_interval(a.signed(), b.signed()).unwrap_or(a.signed());
    let u = exclude_interval(a.unsigned(), b.unsigned()).unwrap_or(a.unsigned());
    ScalarBounds {
        smin: s.0,
        smax: s.1,
        umin: u.0,
        umax: u.1,
        s32_min: i32::MIN,
        s32_max: i32::MAX,
        u32_min: 0,
        u32_max: u32::MAX,
    }
}

/// Refine two scalar bounds on the `dst != src` comparison.
///
/// - true branch: each operand excludes the other's bounds, where a
///   single interval still represents the complement
/// - false branch: both operands take the intersection (equality)
pub(crate) fn refine_ne(dst: ScalarBounds, src: ScalarBounds) -> RefinedBranches {
    let inter = ScalarBounds {
        smin: dst.smin.max(src.smin),
        smax: dst.smax.min(src.smax),
        umin: dst.umin.max(src.umin),
        umax: dst.umax.min(src.umax),
        s32_min: i32::MIN,
        s32_max: i32::MAX,
        u32_min: 0,
        u32_max: u32::MAX,
    }
    .synced();
    (
        (
            exclude_bounds(dst, src).synced(),
            exclude_bounds(src, dst).synced(),
        ),
        (inter, inter),
    )
}

/// The conditional comparisons of the mini/meso subset.
///
/// The unsigned family (JGT/JGE/JLT/JLE) compares values as u64, the
/// signed family (JSGT/JSGE/JSLT/JSLE) as i64; equality is the same in
/// both interpretations. The pre-#39 single `Jgt` was interpreted as
/// signed — the split into distinct opcodes happened in #39.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CondOp {
    Eq,
    Ne,
    /// Unsigned comparisons (JGT/JGE/JLT/JLE).
    Ugt,
    Uge,
    Ult,
    Ule,
    /// Signed comparisons (JSGT/JSGE/JSLT/JSLE).
    Sgt,
    Sge,
    Slt,
    Sle,
}

impl CondOp {
    /// The operator symbol used in error messages.
    pub(crate) fn symbol(self) -> &'static str {
        match self {
            CondOp::Eq => "==",
            CondOp::Ne => "!=",
            CondOp::Ugt | CondOp::Sgt => ">",
            CondOp::Uge | CondOp::Sge => ">=",
            CondOp::Ult | CondOp::Slt => "<",
            CondOp::Ule | CondOp::Sle => "<=",
        }
    }

    /// The ordered comparison shape, or `None` for equality/inequality.
    pub(crate) fn ord(self) -> Option<OrdOp> {
        match self {
            CondOp::Ugt | CondOp::Sgt => Some(OrdOp::Gt),
            CondOp::Uge | CondOp::Sge => Some(OrdOp::Ge),
            CondOp::Ult | CondOp::Slt => Some(OrdOp::Lt),
            CondOp::Ule | CondOp::Sle => Some(OrdOp::Le),
            CondOp::Eq | CondOp::Ne => None,
        }
    }

    /// Whether this opcode belongs to the signed family (JSGT/JSGE/…).
    pub(crate) fn is_signed(self) -> bool {
        matches!(self, CondOp::Sgt | CondOp::Sge | CondOp::Slt | CondOp::Sle)
    }
}

// ── Worklist path exploration (v0.3 Mini) ────────────────────────────────────

/// One pending state in the path exploration: an instruction index and
/// the verifier state carried to it (cf. the kernel's verifier stack).
pub(crate) struct WorkItem {
    pub(crate) pc: u32,
    pub(crate) state: VerifierState,
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

/// The static verdict for one ordered comparison on one interval family
/// (sound for any `Ord` type).
fn ordered_verdict<T: Ord>(op: OrdOp, dst: (T, T), src: (T, T)) -> BranchVerdict {
    match op {
        OrdOp::Gt => {
            if dst.0 > src.1 {
                BranchVerdict::AlwaysTaken
            } else if dst.1 <= src.0 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        OrdOp::Ge => {
            if dst.0 >= src.1 {
                BranchVerdict::AlwaysTaken
            } else if dst.1 < src.0 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        OrdOp::Lt => {
            if dst.1 < src.0 {
                BranchVerdict::AlwaysTaken
            } else if dst.0 >= src.1 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        OrdOp::Le => {
            if dst.1 <= src.0 {
                BranchVerdict::AlwaysTaken
            } else if dst.0 > src.1 {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
    }
}

/// Whether two ranges of one interval family are disjoint.
fn ranges_disjoint<T: Ord>(a: (T, T), b: (T, T)) -> bool {
    a.1 < b.0 || a.0 > b.1
}

/// Decide whether a conditional branch is statically always taken,
/// never taken, or unknown for the given scalar bounds (cf. the
/// kernel's is_branch_taken()).
///
/// Ordered comparisons decide on the opcode's interval family: the
/// unsigned family (JGT/JGE/JLT/JLE) on `umin`/`umax`, the signed
/// family (JSGT/JSGE/JSLT/JSLE) on `smin`/`smax`. Equality needs both
/// families: it always holds only for the same constant, and can never
/// hold when either family pair is disjoint (sound because a scalar's
/// value set is contained in both of its intervals; synced states keep
/// this precise).
pub(crate) fn is_branch_taken(op: CondOp, dst: ScalarBounds, src: ScalarBounds) -> BranchVerdict {
    match op {
        // dst == src: always true iff both are the same constant in both
        // interpretations, always false iff either family is disjoint
        CondOp::Eq => {
            if dst.is_constant()
                && src.is_constant()
                && dst.smin == src.smin
                && dst.umin == src.umin
            {
                BranchVerdict::AlwaysTaken
            } else if ranges_disjoint(dst.signed(), src.signed())
                || ranges_disjoint(dst.unsigned(), src.unsigned())
            {
                BranchVerdict::AlwaysNotTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        // dst != src: the dual of equality
        CondOp::Ne => {
            if dst.is_constant()
                && src.is_constant()
                && dst.smin == src.smin
                && dst.umin == src.umin
            {
                BranchVerdict::AlwaysNotTaken
            } else if ranges_disjoint(dst.signed(), src.signed())
                || ranges_disjoint(dst.unsigned(), src.unsigned())
            {
                BranchVerdict::AlwaysTaken
            } else {
                BranchVerdict::Unknown
            }
        }
        _ => {
            let ord = op.ord().expect("ordered comparison");
            if op.is_signed() {
                ordered_verdict(ord, dst.signed(), src.signed())
            } else {
                ordered_verdict(ord, dst.unsigned(), src.unsigned())
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
        BpfInsn::Jne { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Ne, state)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Ugt, state)
        }
        BpfInsn::Jge { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Uge, state)
        }
        BpfInsn::Jlt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Ult, state)
        }
        BpfInsn::Jle { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Ule, state)
        }
        BpfInsn::Jsgt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Sgt, state)
        }
        BpfInsn::Jsge { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Sge, state)
        }
        BpfInsn::Jslt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Slt, state)
        }
        BpfInsn::Jsle { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Sle, state)
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
        (RegState::Scalar(d), RegState::Scalar(s)) => {
            let verdict = is_branch_taken(op, d, s);
            let ((t_dst, t_src), (f_dst, f_src)) = refine_cmp(op, d, s);
            let mut out = Vec::with_capacity(2);
            // a statically impossible branch is never explored
            if !matches!(verdict, BranchVerdict::AlwaysNotTaken) {
                let mut taken = *state;
                taken.regs[dst as usize] = RegState::Scalar(t_dst);
                taken.regs[src as usize] = RegState::Scalar(t_src);
                out.push((taken_pc, taken));
            }
            if !matches!(verdict, BranchVerdict::AlwaysTaken) {
                let mut fall = *state;
                fall.regs[dst as usize] = RegState::Scalar(f_dst);
                fall.regs[src as usize] = RegState::Scalar(f_src);
                out.push((fall_pc, fall));
            }
            out
        }
        // NULL check: a nullable pointer compared to the constant 0. For
        // `== 0` the taken branch becomes the scalar 0 and the fall-through
        // a valid map value pointer; for `!= 0` the roles are swapped.
        (RegState::PtrToMapValueOrNull, RegState::Scalar(s))
        | (RegState::Scalar(s), RegState::PtrToMapValueOrNull)
            if s.is_zero() =>
        {
            match op {
                CondOp::Eq | CondOp::Ne => {
                    let ptr_reg = if matches!(dst_state, RegState::PtrToMapValueOrNull) {
                        dst
                    } else {
                        src
                    };
                    let (null_side, valid_side) = match op {
                        // == 0: taken is NULL, fall is the valid pointer
                        CondOp::Eq => (taken_pc, fall_pc),
                        // != 0: taken is the valid pointer, fall is NULL
                        CondOp::Ne => (fall_pc, taken_pc),
                        _ => unreachable!(),
                    };
                    let mut null_state = *state;
                    null_state.regs[ptr_reg as usize] = RegState::Scalar(ScalarBounds::constant(0));
                    let mut valid = *state;
                    valid.regs[ptr_reg as usize] = RegState::PtrToMapValue;
                    vec![(null_side, null_state), (valid_side, valid)]
                }
                _ => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "invalid comparison of r{} with r{} (different types)",
                            dst, src
                        ),
                    ));
                }
            }
        }
        // a non-null map value pointer compared to 0: equality and
        // inequality are kept without refinement (simplified — the kernel
        // marks the taken branch of == 0 infeasible)
        (RegState::PtrToMapValue, RegState::Scalar(s))
        | (RegState::Scalar(s), RegState::PtrToMapValue)
            if s.is_zero() =>
        {
            match op {
                CondOp::Eq | CondOp::Ne => vec![(taken_pc, *state), (fall_pc, *state)],
                _ => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "invalid comparison of r{} with r{} (different types)",
                            dst, src
                        ),
                    ));
                }
            }
        }
        // pointers of the same type: equality and inequality are allowed
        // without refinement; ordered comparisons on pointers are not
        (RegState::PtrToStack { .. }, RegState::PtrToStack { .. })
        | (RegState::PtrToCtx, RegState::PtrToCtx)
        | (RegState::PtrToMap, RegState::PtrToMap)
        | (RegState::PtrToMapValue, RegState::PtrToMapValue)
        | (RegState::PtrToMapValueOrNull, RegState::PtrToMapValueOrNull) => match op {
            CondOp::Eq | CondOp::Ne => vec![(taken_pc, *state), (fall_pc, *state)],
            _ => {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "comparing pointers r{} {} r{} is not allowed",
                        dst,
                        op.symbol(),
                        src
                    ),
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
        assert_eq!(next.regs[2], RegState::Scalar(ScalarBounds::constant(10)));
        // other registers untouched
        assert_eq!(next.regs[1], RegState::PtrToCtx);
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }

    #[test]
    fn step_mov_imm_overwrites() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 20 }).unwrap();
        assert_eq!(next.regs[2], RegState::Scalar(ScalarBounds::constant(20)));
    }

    #[test]
    fn step_mov_imm_negative() {
        // i32 imm is sign-extended into the i64 scalar range
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: -7 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(-7)));
    }

    #[test]
    fn step_mov_reg_copies_scalar() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::MovReg { dst: 3, src: 2 }).unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::constant(10)));
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
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(10)));
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
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(30)));
    }

    #[test]
    fn step_add_imm_negative() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: -3 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(7)));
    }

    #[test]
    fn step_add_reg_constants() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 5 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(15)));
        // the source register is unchanged
        assert_eq!(next.regs[2], RegState::Scalar(ScalarBounds::constant(5)));
    }

    #[test]
    fn step_add_reg_self() {
        // r1 += r1 doubles the value
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 1 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(20)));
    }

    #[test]
    fn step_add_imm_range() {
        // range shift, a preview of #16: [0, 100] + 10 → [10, 110]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
        assert_eq!(
            next.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(10, 110))
        );
    }

    #[test]
    fn step_add_reg_ranges() {
        // [0, 100] + [5, 5] → [5, 105]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(5));
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(
            next.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(5, 105))
        );
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

    // ── ALU extension (Meso #39) ─────────────────────────────────────────────

    #[test]
    fn step_alu_dual_ranges_propagate() {
        // r1 = -1; r1 += -1 → -2 in both interpretations (u64 wraps too)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: -1 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: -1 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (-2, -2));
        assert_eq!(b.unsigned(), (u64::MAX - 1, u64::MAX - 1));
    }

    #[test]
    fn step_alu_sync_after_mixed_ops() {
        // a signed-range operand keeps both families consistent: prandom
        // then JSLE 100 refines smax and the sync narrows umax too
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::unknown());
        let next = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 100 }).unwrap();
        let next = step(0, &next, &BpfInsn::SubReg { dst: 1, src: 2 }).unwrap();
        // [MIN, MAX] - 100 → [MIN, MAX] with wrapped edges synced back
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(
            b.signed(),
            (i64::MIN.wrapping_sub(100), i64::MAX.wrapping_sub(100))
        );
    }

    #[test]
    fn step_sub_imm_issue_example() {
        // r1 = 10; r1 -= 3 → R1 = Scalar(7..7)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::SubImm { dst: 1, imm: 3 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(7)));
    }

    #[test]
    fn step_sub_reg_negative_result() {
        // 10 - 20 = -10, wrapped arithmetic is exact bit arithmetic
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 20 }).unwrap();
        let next = step(0, &state, &BpfInsn::SubReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(-10)));
    }

    #[test]
    fn step_and_or_xor_imm() {
        // 12 & 10 = 8, 12 | 3 = 15, 12 ^ 10 = 6
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 12 }).unwrap();
        let next = step(0, &state, &BpfInsn::AndImm { dst: 1, imm: 10 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(8)));
        let next = step(0, &next, &BpfInsn::OrImm { dst: 1, imm: 3 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(11)));
        let next = step(0, &next, &BpfInsn::XorImm { dst: 1, imm: 12 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(7)));
    }

    #[test]
    fn step_and_reg_tnum_like_precision() {
        // r2 = [0, 100]; r2 &= 1 → the result is bounded by the AND mask
        let mut state = VerifierState::initial();
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        let next = step(0, &state, &BpfInsn::AndImm { dst: 2, imm: 1 }).unwrap();
        assert_eq!(
            next.regs[2],
            RegState::Scalar(ScalarBounds::from_signed(0, 1))
        );
    }

    #[test]
    fn step_shifts_imm() {
        // 1 << 4 = 16, >> 2 = 4, s>> 1 = 2
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 1 }).unwrap();
        let next = step(0, &state, &BpfInsn::LshImm { dst: 1, imm: 4 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(16)));
        let next = step(0, &next, &BpfInsn::RshImm { dst: 1, imm: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(4)));
        let next = step(0, &next, &BpfInsn::ArshImm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(2)));
        // arithmetic shift sign-extends: -8 s>> 1 = -4
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::ArshImm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(-4)));
    }

    #[test]
    fn step_shift_reg() {
        // r1 = 1; r2 = 4; r1 <<= r2 → 16
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 1 }).unwrap();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 4 }).unwrap();
        let next = step(0, &state, &BpfInsn::LshReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(16)));
    }

    #[test]
    fn step_shift_imm_out_of_range_rejected() {
        // shifts by >= 64 or negative amounts are invalid (kernel check_alu_op)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 1 }).unwrap();
        for imm in [64, 100, -1] {
            let err = step(0, &state, &BpfInsn::LshImm { dst: 1, imm }).unwrap_err();
            assert!(err.message.contains("invalid shift"), "imm {}", imm);
        }
        // a register shift amount that may exceed 63 is rejected too
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 64 }).unwrap();
        let err = step(0, &state, &BpfInsn::LshReg { dst: 1, src: 2 }).unwrap_err();
        assert!(err.message.contains("invalid shift"));
    }

    #[test]
    fn step_alu32_constants_truncate_and_zero_extend() {
        // w1 = 0x1_0000_0001 (via two adds) then w1 += 0 → trunc32 = 1
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::MovImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::AddImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 3 }).unwrap();
        assert_eq!(
            state.regs[1],
            RegState::Scalar(ScalarBounds::constant(0x1_0000_0001))
        );
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0 }).unwrap();
        // the high 32 bits are zero-extended away
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(1)));
    }

    #[test]
    fn step_alu32_overflow_wraps_to_zero() {
        // w1 = 0xFFFFFFFF; w1 += 1 → 0x1_0000_0000 trunc32 → 0
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: -1 }).unwrap();
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(0)));
    }

    #[test]
    fn step_alu32_range_zero_extended() {
        // a non-constant ALU32 result is zero-extended: [0, 0xFFFFFFFF]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(-100, 100));
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 5 }).unwrap();
        assert_eq!(
            next.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(0, 0xFFFF_FFFF))
        );
    }

    #[test]
    fn step_alu32_vs_alu64_divergence() {
        // r1 = 0x1_0000_0001 (built via adds): ALU64 keeps the high bits,
        // ALU32 truncates them away and zero-extends
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::MovImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::AddImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 3 }).unwrap();
        // ALU64: r1 += 1 → 0x1_0000_0002
        let w64 = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(
            w64.regs[1],
            RegState::Scalar(ScalarBounds::constant(0x1_0000_0002))
        );
        // ALU32: w1 += 1 → trunc32(0x1_0000_0001) + 1 = 2
        let w32 = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(w32.regs[1], RegState::Scalar(ScalarBounds::constant(2)));
    }

    #[test]
    fn step_alu32_known_zero_high_bits() {
        // an ALU32 result always lies in [0, 0xFFFFFFFF]: the high 32
        // bits are known zero (#41)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::unknown());
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 5 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0, 0xFFFF_FFFF));
        assert_eq!(b.unsigned(), (0, 0xFFFF_FFFF));
        // and the 32-bit sub-ranges carry the same bits
        assert_eq!((b.u32_min, b.u32_max), (0, u32::MAX));
    }

    #[test]
    fn step_alu32_tracks_32_bit_ranges() {
        // a "negative" 32-bit constant zero-extends: 0x80000000 as u64 is
        // positive, while its s32 view is negative (i32 truncation)
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::MovImm {
                dst: 1,
                imm: -0x8000_0000,
            },
        )
        .unwrap();
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0x8000_0000, 0x8000_0000));
        assert_eq!(b.s32_min, -0x8000_0000);
        assert_eq!(b.u32_min, 0x8000_0000);
        // a 64-bit constant outside 32 bits truncates into the 32-bit view
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::MovImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::AddImm {
                dst: 1,
                imm: 0x7FFF_FFFF,
            },
        )
        .unwrap();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 3 }).unwrap();
        let RegState::Scalar(b) = state.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0x1_0000_0001, 0x1_0000_0001));
        assert_eq!(b.u32_min, 1);
        assert_eq!(b.u32_max, 1);
        assert_eq!(b.s32_min, 1);
        assert_eq!(b.s32_max, 1);
    }

    #[test]
    fn step_alu32_range_wrap() {
        // w1: [0xFFFFFFF0, 0xFFFFFFFF] += 0x10 wraps to [0, 0xF]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0xFFFF_FFF0,
            smax: 0xFFFF_FFFF,
            umin: 0xFFFF_FFF0,
            umax: 0xFFFF_FFFF,
            s32_min: -0x10,
            s32_max: -1,
            u32_min: 0xFFFF_FFF0,
            u32_max: 0xFFFF_FFFF,
        });
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0x10 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0, 0xF));
        assert_eq!(b.unsigned(), (0, 0xF));
        // a range crossing the 32-bit boundary widens to the full range
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0xFFFF_FFF0,
            smax: 0x1_0000_0010,
            umin: 0xFFFF_FFF0,
            umax: 0x1_0000_0010,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
        });
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0, 0xFFFF_FFFF));
    }

    #[test]
    fn step_alu32_range_addition_exact() {
        // [0, 10] + [5, 5] in 32-bit space stays exact
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 10));
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 5 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (5, 15));
        assert_eq!((b.u32_min, b.u32_max), (5, 15));
    }

    #[test]
    fn step_alu32_pointer_rejected() {
        // 32-bit arithmetic on a context pointer is rejected
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 1 }).unwrap_err();
        assert!(err.message.contains("context pointer"));
    }

    #[test]
    fn step_sub_on_stack_pointer_rejected() {
        // only ADD supports stack pointer arithmetic (kernel check_alu_op)
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::SubImm { dst: 10, imm: 8 }).unwrap_err();
        assert!(err.message.contains("stack pointer"));
        assert!(err.message.contains("only ADD"));
        // ... and ADD32 on the frame pointer is rejected too
        let err = step(0, &state, &BpfInsn::Add32Imm { dst: 10, imm: 1 }).unwrap_err();
        assert!(err.message.contains("stack pointer"));
    }

    #[test]
    fn step_alu_uninit_rejected() {
        // every new ALU op reads the destination first (#14)
        let state = VerifierState::initial();
        for insn in [
            BpfInsn::SubImm { dst: 0, imm: 1 },
            BpfInsn::AndReg { dst: 0, src: 1 },
            BpfInsn::Xor32Imm { dst: 0, imm: 1 },
            BpfInsn::LshImm { dst: 0, imm: 1 },
        ] {
            let err = step(0, &state, &insn).unwrap_err();
            assert!(err.message.contains("uninitialized"));
        }
    }

    #[test]
    fn step_alu_reg_pointer_src_rejected() {
        // register-offset arithmetic stays rejected for every new op
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: 1 }).unwrap();
        let err = step(0, &state, &BpfInsn::SubReg { dst: 0, src: 10 }).unwrap_err();
        assert!(err.message.contains("register-offset"));
    }

    // ── New compare opcodes (Meso #39) ───────────────────────────────────────

    #[test]
    fn successors_jne_issue_example() {
        // r1 = 5 != r2 = 7 is always true: only the taken branch
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(5));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(7));
        let nexts = successors(
            0,
            &BpfInsn::Jne {
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
    fn successors_jne_refines_equality_side() {
        // r1 = [0, 100] != 42: the fall-through (== 42) keeps both in [42, 42]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(42));
        let nexts = successors(
            0,
            &BpfInsn::Jne {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        // taken: r1 = [0, 100] (complement not representable)
        assert_eq!(
            nexts[0].1.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(0, 100))
        );
        // fall: equality narrows to the constant
        assert_eq!(
            nexts[1].1.regs[1],
            RegState::Scalar(ScalarBounds::constant(42))
        );
    }

    #[test]
    fn successors_jsgt_vs_jgt_negative_constants() {
        // r1 = -1: signed says never taken, unsigned says always taken
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(-1));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(0));
        let nexts = successors(
            0,
            &BpfInsn::Jsgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 1); // fall-through only
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
        assert_eq!(nexts[0].0, 2); // taken only
    }

    #[test]
    fn successors_unsigned_refines_on_non_negative() {
        // JGE: r1 = [0, 100] >= 50 → taken r1 = [50, 100], fall r1 = [0, 49]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(50));
        let nexts = successors(
            0,
            &BpfInsn::Jge {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        assert_eq!(
            nexts[0].1.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(50, 100))
        );
        assert_eq!(
            nexts[1].1.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(0, 49))
        );
    }

    #[test]
    fn successors_signed_lt_negative_refines() {
        // JSLT: r1 = [-10, -1] < 0 is always true → only taken
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(-10, -1));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(0));
        let nexts = successors(
            0,
            &BpfInsn::Jslt {
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
    fn successors_jne_null_check() {
        // r0 != 0 on a nullable pointer: taken is the valid pointer,
        // fall-through is NULL (scalar 0)
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(0));
        let nexts = successors(
            0,
            &BpfInsn::Jne {
                dst: 0,
                src: 1,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        // fall (r0 == 0): the constant 0 comes first
        let (null_pc, null) = &nexts[0];
        assert_eq!(*null_pc, 1);
        assert_eq!(null.regs[0], RegState::Scalar(ScalarBounds::constant(0)));
        // taken (r0 != 0): a valid map value pointer
        let (valid_pc, valid) = &nexts[1];
        assert_eq!(*valid_pc, 2);
        assert_eq!(valid.regs[0], RegState::PtrToMapValue);
    }

    #[test]
    fn successors_ordered_pointer_compare_rejected() {
        // every ordered comparison on pointers is rejected
        let state = VerifierState::initial();
        for insn in [
            BpfInsn::Jsgt {
                dst: 10,
                src: 10,
                offset: 1,
            },
            BpfInsn::Jle {
                dst: 1,
                src: 1,
                offset: 1,
            },
        ] {
            let err = successors(0, &insn, &state).unwrap_err();
            assert!(err.message.contains("comparing pointers"), "{:?}", insn);
        }
        // equality and inequality on same-type pointers stay allowed
        for insn in [
            BpfInsn::Jne {
                dst: 1,
                src: 1,
                offset: 1,
            },
            BpfInsn::Jeq {
                dst: 1,
                src: 1,
                offset: 1,
            },
        ] {
            let nexts = successors(0, &insn, &state).unwrap();
            assert_eq!(nexts.len(), 2, "{:?}", insn);
        }
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
        // issue example: R1 = [0, 100]; if R1 > 50 (signed)
        // true: R1 = [51, 100], false: R1 = [0, 50]
        let ((true_dst, true_src), (false_dst, false_src)) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(50, 50),
        );
        assert_eq!(true_dst.signed(), (51, 100));
        assert_eq!(true_src.signed(), (50, 50));
        assert_eq!(false_dst.signed(), (0, 50));
        assert_eq!(false_src.signed(), (50, 50));
    }

    #[test]
    fn refine_gt_unsigned_matches_signed_on_non_negative() {
        // on non-negative ranges the unsigned and signed views coincide,
        // and the sync keeps both interpretations identical afterwards
        let signed = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(50, 50),
        );
        let unsigned = refine_cmp(
            CondOp::Ugt,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(50, 50),
        );
        assert_eq!(signed, unsigned);
        let ((true_dst, _), _) = unsigned;
        assert_eq!(true_dst.unsigned(), (51, 100));
        assert_eq!(true_dst.signed(), (51, 100));
    }

    #[test]
    fn refine_unsigned_narrows_unsigned_family_only() {
        // JLE 10 refines umax; the sync propagates the narrowing into the
        // signed range too (kernel reg_bounds_sync), so both families agree
        let dst = ScalarBounds::from_signed(0, 100);
        let ((taken, _), (fall, _)) = refine_cmp(CondOp::Ule, dst, ScalarBounds::constant(10));
        assert_eq!(taken.unsigned(), (0, 10));
        assert_eq!(taken.signed(), (0, 10));
        assert_eq!(fall.unsigned(), (11, 100));
        assert_eq!(fall.signed(), (11, 100));
        // and JSLE 10 refines the signed family first, then syncs
        let ((taken, _), _) = refine_cmp(CondOp::Sle, dst, ScalarBounds::constant(10));
        assert_eq!(taken.signed(), (0, 10));
        assert_eq!(taken.unsigned(), (0, 10));
    }

    #[test]
    fn refine_signed_negative_constant_keeps_both_interpretations() {
        // r1 = -1: signed -1..-1, unsigned u64::MAX..u64::MAX; JSGT 0 can
        // never be taken, so the taken side narrows to the empty range
        let r1 = ScalarBounds::constant(-1);
        let ((true_dst, _), _) = refine_cmp(CondOp::Sgt, r1, ScalarBounds::constant(0));
        assert!(true_dst.smin > true_dst.smax);
        // JGT 0 (unsigned) is always taken: the fall side is empty
        let (_, (false_dst, _)) = refine_cmp(CondOp::Ugt, r1, ScalarBounds::constant(0));
        assert!(false_dst.umin > false_dst.umax);
    }

    #[test]
    fn refine_gt_both_ranges() {
        // dst = [0, 100], src = [20, 200]: on the true branch both operands
        // narrow (dst >= src.min + 1, src <= dst.max - 1)
        let ((true_dst, true_src), (false_dst, false_src)) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(20, 200),
        );
        assert_eq!(true_dst.signed(), (21, 100));
        assert_eq!(true_src.signed(), (20, 99));
        // the false branch adds no constraint here (dst <= 200, src >= 0
        // are already implied by the ranges)
        assert_eq!(false_dst.signed(), (0, 100));
        assert_eq!(false_src.signed(), (20, 200));
    }

    #[test]
    fn refine_gt_self() {
        // r1 > r1 with r1 = [0, 100]: both sides of the comparison are
        // refined, so the true branch narrows to the empty range
        let r = ScalarBounds::from_signed(0, 100);
        let ((true_dst, true_src), (false_dst, false_src)) = refine_cmp(CondOp::Sgt, r, r);
        assert_eq!(true_dst.signed(), (1, 100));
        assert_eq!(true_src.signed(), (0, 99));
        assert_eq!(false_dst.signed(), (0, 100));
        assert_eq!(false_src.signed(), (0, 100));
    }

    #[test]
    fn refine_gt_infeasible_true_branch() {
        // dst = [0, 100] vs src = [100, 100]: dst > 100 is impossible,
        // so the true branch narrows to an empty range (min > max)
        let ((true_dst, _), _) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::constant(100),
        );
        assert!(true_dst.smin > true_dst.smax);
    }

    #[test]
    fn refine_eq_intersection() {
        // dst = [0, 100], src = [40, 60]: equality means both must be in [40, 60]
        let ((true_dst, true_src), (false_dst, false_src)) = refine_eq(
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(40, 60),
        );
        assert_eq!(true_dst.signed(), (40, 60));
        assert_eq!(true_src.signed(), (40, 60));
        // false branch keeps both ranges (no safe single-interval narrowing)
        assert_eq!(false_dst.signed(), (0, 100));
        assert_eq!(false_src.signed(), (40, 60));
    }

    #[test]
    fn refine_eq_disjoint() {
        // disjoint ranges: equality is impossible → true branch is empty
        let ((true_dst, true_src), _) = refine_eq(
            ScalarBounds::from_signed(0, 10),
            ScalarBounds::from_signed(20, 30),
        );
        assert!(true_dst.smin > true_dst.smax);
        assert!(true_src.smin > true_src.smax);
    }

    #[test]
    fn refine_eq_constants() {
        // two constants: r1 = 5, r2 = 5 → true branch keeps 5..5
        let ((true_dst, _), _) = refine_eq(ScalarBounds::constant(5), ScalarBounds::constant(5));
        assert_eq!(true_dst.signed(), (5, 5));
    }

    #[test]
    fn refine_gt_extremes() {
        // wrapping at i64 extremes stays sound (never panics)
        let ((true_dst, true_src), _) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::unknown(),
            ScalarBounds::constant(0),
        );
        assert_eq!(true_dst.signed(), (1, i64::MAX));
        // src.max = 0 is already below dst.max - 1, so src stays [0, 0]
        assert_eq!(true_src.signed(), (0, 0));
        // src.min + 1 wraps to i64::MIN; dst is kept soundly (the branch is
        // actually infeasible, but over-approximation is allowed)
        let ((true_dst, _), _) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::from_signed(0, i64::MAX),
            ScalarBounds::constant(i64::MAX),
        );
        assert_eq!(true_dst.smin, 0);
        // dst.max - 1 wraps when dst.max = i64::MIN; dst stays [MIN, MIN] so
        // the true branch narrows to an empty range (dst > src is impossible)
        let ((true_dst, _), _) = refine_cmp(
            CondOp::Sgt,
            ScalarBounds::constant(i64::MIN),
            ScalarBounds::constant(i64::MIN),
        );
        assert!(true_dst.smin > true_dst.smax);
    }

    #[test]
    fn refine_ne_issue_example() {
        // r1 = 5, r2 = 5: r1 != r2 is impossible → taken branch is empty;
        // the fall-through keeps the intersection
        let ((true_dst, true_src), (false_dst, false_src)) =
            refine_ne(ScalarBounds::constant(5), ScalarBounds::constant(5));
        assert!(true_dst.smin > true_dst.smax);
        assert!(true_src.smin > true_src.smax);
        assert_eq!(false_dst.signed(), (5, 5));
        assert_eq!(false_src.signed(), (5, 5));
    }

    #[test]
    fn refine_ne_excludes_endpoint_constant() {
        // r1 = [0, 100] != 42: the complement is two intervals, so no
        // narrowing; r1 = [0, 42] != 42 → taken side excludes 42
        let ((true_dst, _), _) = refine_ne(
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::constant(42),
        );
        assert_eq!(true_dst.signed(), (0, 100));
        let ((true_dst, _), _) =
            refine_ne(ScalarBounds::from_signed(0, 42), ScalarBounds::constant(42));
        assert_eq!(true_dst.signed(), (0, 41));
        let ((true_dst, _), _) = refine_ne(
            ScalarBounds::from_signed(42, 100),
            ScalarBounds::constant(42),
        );
        assert_eq!(true_dst.signed(), (43, 100));
        // a range that covers the whole operand range → infeasible
        let ((true_dst, _), _) =
            refine_ne(ScalarBounds::constant(5), ScalarBounds::from_signed(0, 100));
        assert!(true_dst.smin > true_dst.smax);
    }

    #[test]
    fn refine_signed_variants() {
        // dst = [0, 100], src = [40, 60]: the true branch of each comparison
        let dst = ScalarBounds::from_signed(0, 100);
        let src = ScalarBounds::from_signed(40, 60);
        let ((sgt_true, _), _) = refine_cmp(CondOp::Sgt, dst, src);
        assert_eq!(sgt_true.signed(), (41, 100));
        let ((sge_true, _), _) = refine_cmp(CondOp::Sge, dst, src);
        assert_eq!(sge_true.signed(), (40, 100));
        let ((slt_true, _), _) = refine_cmp(CondOp::Slt, dst, src);
        assert_eq!(slt_true.signed(), (0, 59));
        let ((sle_true, _), _) = refine_cmp(CondOp::Sle, dst, src);
        assert_eq!(sle_true.signed(), (0, 60));
        // and the false branches are the exact complements
        let (_, (sgt_false, _)) = refine_cmp(CondOp::Sgt, dst, src);
        assert_eq!(sgt_false.signed(), (0, 60));
        let (_, (sge_false, _)) = refine_cmp(CondOp::Sge, dst, src);
        assert_eq!(sge_false.signed(), (0, 39));
        let (_, (slt_false, _)) = refine_cmp(CondOp::Slt, dst, src);
        assert_eq!(slt_false.signed(), (40, 100));
        let (_, (sle_false, _)) = refine_cmp(CondOp::Sle, dst, src);
        assert_eq!(sle_false.signed(), (41, 100));
    }

    #[test]
    fn refine_unsigned_variants_u64_view() {
        // r1 = -1 (u64::MAX): unsigned compares see the u64 view
        let r1 = ScalarBounds::constant(-1);
        let ((true_dst, _), _) = refine_cmp(CondOp::Ugt, r1, ScalarBounds::constant(0));
        // u64::MAX > 0: no narrowing, the range is unchanged
        assert_eq!(true_dst.unsigned(), (u64::MAX, u64::MAX));
        // JLE 0 (unsigned): r1 <= 0 is false (MAX > 0) → taken side is empty
        let ((true_dst, _), _) = refine_cmp(CondOp::Ule, r1, ScalarBounds::constant(0));
        assert!(true_dst.umin > true_dst.umax);
        // JSLT 0 (signed): -1 < 0 always → taken side is unchanged
        let ((true_dst, _), _) = refine_cmp(CondOp::Slt, r1, ScalarBounds::constant(0));
        assert_eq!(true_dst.signed(), (-1, -1));
    }

    #[test]
    fn refine_sync_keeps_interpretations_consistent() {
        // after a signed-only refinement the unsigned range is synced:
        // JSLE 10 on [0, 100] narrows smax to 10 and umax to 10 too
        let ((taken, _), _) = refine_cmp(
            CondOp::Sle,
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::constant(10),
        );
        assert_eq!(taken.signed(), (0, 10));
        assert_eq!(taken.unsigned(), (0, 10));
        // a refinement that pushes smin >= 0 syncs umax down to smax
        let r = ScalarBounds::from_signed(-5, 100);
        let ((taken, _), _) = refine_cmp(CondOp::Sge, r, ScalarBounds::constant(0));
        assert_eq!(taken.signed(), (0, 100));
        assert_eq!(taken.unsigned(), (0, 100));
    }

    #[test]
    fn successors_jgt_refines_issue_example() {
        // issue #16 example wired through the driver: R1 = [0, 100]; if R1 > 50
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(50));

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
        assert_eq!(
            taken.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(51, 100))
        );
        // fall: pc = 1, R1 = [0, 50]
        let (fall_pc, fall) = &nexts[1];
        assert_eq!(*fall_pc, 1);
        assert_eq!(
            fall.regs[1],
            RegState::Scalar(ScalarBounds::from_signed(0, 50))
        );
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
            is_branch_taken(
                CondOp::Sgt,
                ScalarBounds::from_signed(30, 40),
                ScalarBounds::from_signed(10, 20)
            ),
            BranchVerdict::AlwaysTaken
        ));
        // always false: dst.max <= src.min (boundary included)
        assert!(matches!(
            is_branch_taken(
                CondOp::Sgt,
                ScalarBounds::from_signed(10, 20),
                ScalarBounds::from_signed(20, 30)
            ),
            BranchVerdict::AlwaysNotTaken
        ));
        // overlapping ranges → unknown
        assert!(matches!(
            is_branch_taken(
                CondOp::Sgt,
                ScalarBounds::from_signed(0, 100),
                ScalarBounds::constant(50)
            ),
            BranchVerdict::Unknown
        ));
        // the unsigned family behaves identically on non-negative ranges
        assert!(matches!(
            is_branch_taken(
                CondOp::Ugt,
                ScalarBounds::from_signed(30, 40),
                ScalarBounds::from_signed(10, 20)
            ),
            BranchVerdict::AlwaysTaken
        ));
    }

    #[test]
    fn is_branch_taken_signed_vs_unsigned_negative() {
        // r1 = -1: signed says -1 > 0 is false (never taken),
        // unsigned says u64::MAX > 0 is true (always taken)
        assert!(matches!(
            is_branch_taken(
                CondOp::Sgt,
                ScalarBounds::constant(-1),
                ScalarBounds::constant(0)
            ),
            BranchVerdict::AlwaysNotTaken
        ));
        assert!(matches!(
            is_branch_taken(
                CondOp::Ugt,
                ScalarBounds::constant(-1),
                ScalarBounds::constant(0)
            ),
            BranchVerdict::AlwaysTaken
        ));
        // a straddling signed range keeps a full unsigned view: JGT 0 is
        // still always taken there
        let straddle = ScalarBounds::from_signed(-10, 10);
        assert!(matches!(
            is_branch_taken(CondOp::Ugt, straddle, ScalarBounds::constant(0)),
            BranchVerdict::Unknown
        ));
        assert!(matches!(
            is_branch_taken(CondOp::Slt, straddle, ScalarBounds::constant(0)),
            BranchVerdict::Unknown
        ));
        assert!(matches!(
            is_branch_taken(
                CondOp::Sle,
                ScalarBounds::from_signed(-10, -1),
                ScalarBounds::constant(0)
            ),
            BranchVerdict::AlwaysTaken
        ));
    }

    #[test]
    fn is_branch_taken_ne() {
        // both the same constant → never taken
        assert!(matches!(
            is_branch_taken(
                CondOp::Ne,
                ScalarBounds::constant(5),
                ScalarBounds::constant(5)
            ),
            BranchVerdict::AlwaysNotTaken
        ));
        // disjoint ranges → always taken
        assert!(matches!(
            is_branch_taken(
                CondOp::Ne,
                ScalarBounds::from_signed(0, 10),
                ScalarBounds::from_signed(20, 30)
            ),
            BranchVerdict::AlwaysTaken
        ));
        // overlapping ranges → unknown
        assert!(matches!(
            is_branch_taken(
                CondOp::Ne,
                ScalarBounds::from_signed(0, 100),
                ScalarBounds::from_signed(40, 60)
            ),
            BranchVerdict::Unknown
        ));
    }

    #[test]
    fn is_branch_taken_all_variants() {
        // dst = [30, 40] vs src = [10, 20]: every "greater" form is taken
        for op in [CondOp::Sgt, CondOp::Ugt, CondOp::Sge, CondOp::Uge] {
            assert!(
                matches!(
                    is_branch_taken(
                        op,
                        ScalarBounds::from_signed(30, 40),
                        ScalarBounds::from_signed(10, 20)
                    ),
                    BranchVerdict::AlwaysTaken
                ),
                "{:?}",
                op
            );
        }
        for op in [CondOp::Slt, CondOp::Ult, CondOp::Sle, CondOp::Ule] {
            assert!(
                matches!(
                    is_branch_taken(
                        op,
                        ScalarBounds::from_signed(30, 40),
                        ScalarBounds::from_signed(10, 20)
                    ),
                    BranchVerdict::AlwaysNotTaken
                ),
                "{:?}",
                op
            );
        }
    }

    #[test]
    fn is_branch_taken_eq() {
        // both the same constant → always taken
        assert!(matches!(
            is_branch_taken(
                CondOp::Eq,
                ScalarBounds::constant(5),
                ScalarBounds::constant(5)
            ),
            BranchVerdict::AlwaysTaken
        ));
        // disjoint ranges (in either family) → never taken
        assert!(matches!(
            is_branch_taken(
                CondOp::Eq,
                ScalarBounds::from_signed(0, 10),
                ScalarBounds::from_signed(20, 30)
            ),
            BranchVerdict::AlwaysNotTaken
        ));
        // overlapping ranges → unknown
        assert!(matches!(
            is_branch_taken(
                CondOp::Eq,
                ScalarBounds::from_signed(0, 100),
                ScalarBounds::from_signed(40, 60)
            ),
            BranchVerdict::Unknown
        ));
        // a non-constant range is never 'always taken'
        assert!(matches!(
            is_branch_taken(
                CondOp::Eq,
                ScalarBounds::from_signed(5, 7),
                ScalarBounds::constant(5)
            ),
            BranchVerdict::Unknown
        ));
    }

    #[test]
    fn is_branch_taken_eq_disjoint_unsigned_family() {
        // signed ranges overlap but the unsigned views are disjoint
        // (e.g. -1 vs 0): equality can never hold → pruned
        assert!(matches!(
            is_branch_taken(
                CondOp::Eq,
                ScalarBounds::constant(-1),
                ScalarBounds::constant(0)
            ),
            BranchVerdict::AlwaysNotTaken
        ));
        // and vice versa: a state refined only in the signed family may
        // still be decided by the unsigned family
        let mut dst = ScalarBounds::from_signed(0, 100);
        dst.umin = 50; // unsigned [50, 100]
        let mut src = ScalarBounds::from_signed(0, 100);
        src.umax = 49; // unsigned [0, 49]
        assert!(matches!(
            is_branch_taken(CondOp::Eq, dst, src),
            BranchVerdict::AlwaysNotTaken
        ));
    }

    #[test]
    fn successors_jgt_always_taken() {
        // dst = [30, 40] > src = [10, 20] is always true → only taken
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(30, 40));
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
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
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(30, 40));
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
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(5));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(5));
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
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(0));

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
        assert_eq!(taken.regs[0], RegState::Scalar(ScalarBounds::constant(0)));
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
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(0));
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
        assert_eq!(
            nexts[0].1.regs[0],
            RegState::Scalar(ScalarBounds::constant(0))
        );
        assert_eq!(nexts[1].1.regs[0], RegState::PtrToMapValue);
    }

    #[test]
    fn successors_null_check_nonzero_scalar_rejected() {
        // only the constant 0 enables a NULL check; other scalars keep the
        // different-types rejection
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(8));
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
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(0));
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
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn step_call_map_update_ok() {
        // map_update(map, key, value, flags): all four args validated,
        // returns 0 on success
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap;
        state.regs[2] = RegState::PtrToStack { offset: -8 };
        state.regs[3] = RegState::PtrToStack { offset: -16 };
        state.regs[4] = RegState::Scalar(ScalarBounds::constant(0));
        let next = step(0, &state, &BpfInsn::Call { imm: -2 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(0)));
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
        state.regs[3] = RegState::Scalar(ScalarBounds::constant(1));
        state.regs[4] = RegState::Scalar(ScalarBounds::constant(2));
        state.regs[5] = RegState::Scalar(ScalarBounds::constant(3));
        state.regs[6] = RegState::Scalar(ScalarBounds::constant(10));
        state.regs[7] = RegState::Scalar(ScalarBounds::constant(11));
        state.regs[8] = RegState::Scalar(ScalarBounds::constant(12));
        state.regs[9] = RegState::Scalar(ScalarBounds::constant(13));

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
                RegState::Scalar(ScalarBounds::constant(val)),
                "r{}",
                reg
            );
        }
        assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
    }
}
