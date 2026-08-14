// ── Abstract instruction execution and branch expansion ─────────────────────

use crate::error::VerificationFailure;
use crate::helper::{check_helper_args, helper_prototype};
use crate::insn::BpfInsn;
use crate::state::{
    ALIGN_UNKNOWN, RegState, STACK_SIZE, STACK_SLOT_SIZE, ScalarBounds, StackSlot, VerifierState,
    check_reg, read_reg, read_scalar,
};
use crate::tnum::Tnum;

/// ALU operations of the supported eBPF subset (Meso #39).
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
        | BpfInsn::JsleImm { .. } => {
            unreachable!("exit and control flow are expanded by successors(), not step()")
        }
        // ALU64: rX += imm (pointer + immediate stays the only pointer
        // arithmetic, #20)
        BpfInsn::AddImm { dst, imm } => alu_imm(pc, state, *dst, *imm, AluOp::Add, AluWidth::W64),
        // ldimm64 (#89): a plain 64-bit constant. The map-fd forms and
        // the second-slot marker are handled below.
        BpfInsn::LdImm64 { dst, imm } => {
            check_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar(ScalarBounds::constant(*imm as i64));
            Ok(next)
        }
        // BPF_PSEUDO_MAP_FD → CONST_PTR_TO_MAP with the map metadata
        // resolved at load time (#89).
        BpfInsn::LdMapFd {
            dst,
            key_size,
            value_size,
            ..
        } => {
            check_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::PtrToMap {
                key_size: *key_size,
                value_size: *value_size,
            };
            Ok(next)
        }
        // BPF_PSEUDO_MAP_VALUE → a pointer into the map value at the
        // fixed offset (kernel check_ld_imm64) (#89).
        BpfInsn::LdMapValue {
            dst,
            offset,
            value_size,
            ..
        } => {
            check_reg(pc, *dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::PtrToMapValue {
                min_offset: *offset as i32,
                max_offset: *offset as i32,
                align_off: (*offset % 8) as u8,
                value_size: *value_size,
            };
            Ok(next)
        }
        // the second slot of an ldimm64 is transparent — it never
        // carries state (jumps into it are rejected by the CFG checks)
        BpfInsn::LdImm64Second { .. } => Ok(*state),
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
        // [base + off] = rY → spill the source's full abstract state,
        // including pointers and scalar ranges (#30). The base must be
        // a stack pointer; bounds and alignment are validated at access
        // time (#87, kernel check_mem_access →
        // check_stack_access_within_bounds). A variable-offset store
        // only initializes the covered slots — the spill info is
        // destroyed (kernel: "Variable offset writes destroy any spilled
        // pointers in range").
        BpfInsn::StMem { src, base, offset } => {
            let base_state = read_reg(pc, state, *base)?;
            match base_state {
                RegState::PtrToStack { .. } => {
                    let slots = stack_access_range(pc, *base, state, *offset)?;
                    let src_state = read_reg(pc, state, *src)?;
                    let mut next = *state;
                    if slots.0 == slots.1 {
                        // exact base: the full spilled state is preserved (#30)
                        next.stack.slots[slots.0] = StackSlot::Spilled(src_state);
                    } else {
                        for slot in slots.0..=slots.1 {
                            next.stack.slots[slot] = StackSlot::Initialized;
                        }
                    }
                    Ok(next)
                }
                // stores into map values leave no abstract state — the
                // concrete engine tracks the bytes (#89)
                RegState::PtrToMapValue { .. } => {
                    map_value_access_check(pc, *base, base_state, *offset)?;
                    Ok(*state)
                }
                _ => Err(non_stack_base_error(pc, *base, "store")),
            }
        }
        // rX = [base + off] → load a stack slot; a slot must have been
        // written before it is read (write-before-read, #18). The full
        // spilled register state is restored, pointers included (#30).
        // A variable-offset load requires every covered slot to be
        // initialized and rejects ranges holding spilled pointers
        // (kernel: "invalid indirect read from stack"); the result is
        // an unknown scalar.
        BpfInsn::LdMem { dst, base, offset } => {
            check_reg(pc, *dst)?;
            let base_state = read_reg(pc, state, *base)?;
            match base_state {
                RegState::PtrToStack { .. } => {
                    let slots = stack_access_range(pc, *base, state, *offset)?;
                    let mut next = *state;
                    if slots.0 == slots.1 {
                        let spilled = match next.stack.slots[slots.0] {
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
                            StackSlot::Initialized => RegState::Scalar(ScalarBounds::unknown()),
                        };
                        next.regs[*dst as usize] = spilled;
                    } else {
                        for slot in slots.0..=slots.1 {
                            match next.stack.slots[slot] {
                                StackSlot::Uninit => {
                                    return Err(VerificationFailure::new(
                                        pc,
                                        format!(
                                            "stack slot at offset {} is uninitialized (write before read)",
                                            slot_offset(slot)
                                        ),
                                    ));
                                }
                                StackSlot::Initialized => {}
                                StackSlot::Spilled(spilled) => {
                                    if !matches!(spilled, RegState::Scalar(_)) {
                                        return Err(VerificationFailure::new(
                                            pc,
                                            format!(
                                                "invalid indirect read from stack at r{}{:+}: spilled {} at offset {}",
                                                base,
                                                offset,
                                                spilled,
                                                slot_offset(slot)
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                        next.regs[*dst as usize] = RegState::Scalar(ScalarBounds::unknown());
                    }
                    Ok(next)
                }
                // loads from map values yield an unknown scalar (the
                // bytes are tracked by the concrete engine, #89)
                RegState::PtrToMapValue { .. } => {
                    map_value_access_check(pc, *base, base_state, *offset)?;
                    let mut next = *state;
                    next.regs[*dst as usize] = RegState::Scalar(ScalarBounds::unknown());
                    Ok(next)
                }
                _ => Err(non_stack_base_error(pc, *base, "load")),
            }
        }
        // helper call: validate R1..R5 against the helper prototype, then
        // apply the eBPF calling convention (#28/#29): R1..R5 are
        // clobbered by the call (kernel's check_helper_call resets them
        // to NOT_INIT), R6..R9 are preserved, and R0 gets the return type
        BpfInsn::Call { imm } => {
            // the immediate is the helper id (kernel convention,
            // BPF_JMP|BPF_CALL); BPF-to-BPF calls are rejected at
            // decode time (issue #56)
            let helper = helper_prototype(*imm)
                .ok_or_else(|| VerificationFailure::new(pc, format!("unknown helper {}", imm)))?;
            // map helpers have a dynamic contract (key/value sizes from
            // the map metadata, #89); the generic table covers the rest
            if matches!(*imm, 1 | 2) {
                check_map_helper_args(pc, *imm, state)?;
            } else {
                check_helper_args(pc, helper, state)?;
            }
            let mut next = *state;
            // argument registers are scratch — invalidated by the call
            for reg in 1..=5 {
                next.regs[reg] = RegState::Uninit;
            }
            next.regs[0] = helper.return_type;
            // map_lookup's return depends on the map's value size: fill
            // it from R1's PtrToMap metadata before the clobber (kernel
            // check_helper_call builds the return from the map, #89)
            if *imm == 1
                && let RegState::PtrToMap { value_size, .. } = state.regs[1]
            {
                next.regs[0] = RegState::PtrToMapValueOrNull { value_size };
            }
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
    // shifts require an amount below the width (kernel check_alu_op:
    // "< 64 range, for 32-bit < 32 range")
    let bitness: i32 = match width {
        AluWidth::W64 => 64,
        AluWidth::W32 => 32,
    };
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) && !(0..bitness).contains(&imm) {
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
        // PtrToStack + imm => PtrToStack at the shifted offset; only
        // ADD is allowed on stack pointers — like the kernel's
        // check_alu_op. The offset interval is widened unconditionally:
        // frame bounds and alignment are validated at access time
        // (#87, kernel adjust_ptr_min_max_vals — no arithmetic-time
        // bounds check for privileged loads).
        RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } => {
            if op != AluOp::Add || width != AluWidth::W64 {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "arithmetic on stack pointer r{} is not allowed (only ADD supports stack pointer arithmetic)",
                        dst
                    ),
                ));
            }
            // saturating add keeps the interval inside i32; anything
            // beyond is far out of the 512-byte frame and rejected by
            // any later access
            let new_min = min_offset.saturating_add(imm);
            let new_max = max_offset.saturating_add(imm);
            let mut next = *state;
            next.regs[dst as usize] = RegState::PtrToStack {
                min_offset: new_min,
                max_offset: new_max,
                align_off: (align_off as i32 + imm.rem_euclid(8)).rem_euclid(8) as u8,
            };
            Ok(next)
        }
        // the kernel allows context pointer ADD/SUB with a sane known
        // offset (adjust_ptr_min_max_vals, PTR_TO_CTX — used for ctx
        // field access); the offset is not tracked (no ctx loads yet)
        RegState::PtrToCtx => {
            if !matches!(op, AluOp::Add | AluOp::Sub) || width != AluWidth::W64 {
                return Err(VerificationFailure::new(
                    pc,
                    format!("arithmetic on context pointer r{} is not allowed", dst),
                ));
            }
            check_sane_addend(pc, "ctx", ScalarBounds::constant(imm as i64))?;
            Ok(*state)
        }
        RegState::PtrToMap { .. } => Err(VerificationFailure::new(
            pc,
            format!("arithmetic on map pointer r{} is not allowed", dst),
        )),
        // map value pointers support ADD (immediate) like stack
        // pointers: the offset interval widens, bounds are validated at
        // access time (#89)
        RegState::PtrToMapValue {
            min_offset,
            max_offset,
            align_off,
            value_size,
        } => {
            if op != AluOp::Add || width != AluWidth::W64 {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "arithmetic on map value pointer r{} is not allowed (only ADD supports map value pointer arithmetic)",
                        dst
                    ),
                ));
            }
            let mut next = *state;
            next.regs[dst as usize] = RegState::PtrToMapValue {
                min_offset: min_offset.saturating_add(imm),
                max_offset: max_offset.saturating_add(imm),
                align_off: (align_off as i32 + imm.rem_euclid(8)).rem_euclid(8) as u8,
                value_size,
            };
            Ok(next)
        }
        RegState::PtrToMapValueOrNull { .. } => Err(VerificationFailure::new(
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
/// Scalar operands get the (possibly over-approximated) result range;
/// `PtrToStack + ScalarRange` widens the pointer's offset interval, and
/// `Scalar + PtrToStack` (ADD only) makes the destination inherit the
/// pointer state — both mirror the kernel's adjust_ptr_min_max_vals
/// (no arithmetic-time bounds check, #87).
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
    // computed stack pointer arithmetic: PtrToStack + ScalarRange is
    // accepted when the result provably stays in the frame and the
    // alignment of the computed offset is provable (#45)
    if let RegState::PtrToStack {
        min_offset,
        max_offset,
        align_off,
    } = dst_state
    {
        if op != AluOp::Add || width != AluWidth::W64 {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "arithmetic on stack pointer r{} is not allowed (only ADD supports stack pointer arithmetic)",
                    dst
                ),
            ));
        }
        let s = read_scalar(pc, state, src)?;
        return add_scalar_to_stack_ptr(pc, dst, min_offset, max_offset, align_off, s, state);
    }
    // context pointer arithmetic (register form): the kernel allows
    // ctx ADD/SUB with a sane scalar (adjust_ptr_min_max_vals,
    // PTR_TO_CTX); the offset is not tracked (no ctx loads yet)
    if let RegState::PtrToCtx = dst_state {
        if !matches!(op, AluOp::Add | AluOp::Sub) || width != AluWidth::W64 {
            return Err(VerificationFailure::new(
                pc,
                format!("arithmetic on context pointer r{} is not allowed", dst),
            ));
        }
        let s = read_scalar(pc, state, src)?;
        check_sane_addend(pc, "ctx", s)?;
        return Ok(*state);
    }
    // map value pointer arithmetic: PtrToMapValue + ScalarRange widens
    // the offset interval; bounds are validated at access time (#89)
    if let RegState::PtrToMapValue {
        min_offset,
        max_offset,
        align_off,
        value_size,
    } = dst_state
    {
        if op != AluOp::Add || width != AluWidth::W64 {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "arithmetic on map value pointer r{} is not allowed (only ADD supports map value pointer arithmetic)",
                    dst
                ),
            ));
        }
        let s = read_scalar(pc, state, src)?;
        return add_scalar_to_map_value_ptr(
            pc,
            dst,
            RegState::PtrToMapValue {
                min_offset,
                max_offset,
                align_off,
                value_size,
            },
            s,
            state,
        );
    }
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
    // scalar += stack pointer / map value pointer: the destination
    // inherits the complete pointer state and shifts by the scalar
    // range (kernel adjust_ptr_min_max_vals: "dst_reg inherits the
    // complete pointer register state") — #87/#89
    if op == AluOp::Add && width == AluWidth::W64 {
        if let RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } = read_reg(pc, state, src)?
        {
            check_sane_addend(pc, "stack", d)?;
            return add_scalar_to_stack_ptr(pc, dst, min_offset, max_offset, align_off, d, state);
        }
        if let RegState::PtrToMapValue { .. } = read_reg(pc, state, src)? {
            return add_scalar_to_map_value_ptr(pc, dst, read_reg(pc, state, src)?, d, state);
        }
        if let RegState::PtrToCtx = read_reg(pc, state, src)? {
            check_sane_addend(pc, "ctx", d)?;
            let mut next = *state;
            next.regs[dst as usize] = RegState::PtrToCtx;
            return Ok(next);
        }
    }
    let s = read_scalar(pc, state, src)?;
    // shifts require a provable amount below the width (kernel
    // check_alu_op: "< 64 range, for 32-bit < 32 range")
    if matches!(op, AluOp::Lsh | AluOp::Rsh | AluOp::Arsh) {
        check_shift_amount(pc, s, width)?;
    }
    let next_bounds = apply_alu(op, width, d, s);
    let mut next = *state;
    next.regs[dst as usize] = RegState::Scalar(next_bounds);
    Ok(next)
}

/// The base-register error for a memory access whose base is neither a
/// stack pointer nor a map value pointer (#89).
fn non_stack_base_error(pc: u32, reg: u8, kind: &str) -> VerificationFailure {
    VerificationFailure::new(
        pc,
        format!(
            "{kind} through a non-stack pointer r{} is not supported",
            reg
        ),
    )
}

/// The access-time checks for a map-value access `[base + off]` (#89):
/// every possible concrete offset must lie within `[0, value_size)` and
/// be 8-byte aligned (kernel `check_map_access`).
fn map_value_access_check(
    pc: u32,
    base: u8,
    ptr: RegState,
    off: i16,
) -> Result<(), VerificationFailure> {
    let RegState::PtrToMapValue {
        min_offset,
        max_offset,
        align_off,
        value_size,
    } = ptr
    else {
        unreachable!("the caller matched PtrToMapValue")
    };
    let min_off = min_offset as i64 + off as i64;
    let max_off = max_offset as i64 + off as i64 + STACK_SLOT_SIZE as i64;
    // alignment: every possible concrete offset must be 8-byte aligned
    if align_off == ALIGN_UNKNOWN {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "map value pointer r{} alignment is not provable (computed offsets must be 8-byte aligned)",
                base
            ),
        ));
    }
    if (align_off as i32 + off.rem_euclid(8) as i32).rem_euclid(8) != 0 {
        return Err(VerificationFailure::new(
            pc,
            format!("stack access at r{}{:+} is not 8-byte aligned", base, off),
        ));
    }
    // bounds: the whole access range must lie within the value
    if min_off < 0 || max_off > value_size as i64 {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "invalid access to map value r{}{:+}, value_size={} (base offsets {}..{})",
                base, off, value_size, min_offset, max_offset
            ),
        ));
    }
    Ok(())
}

/// The map-helper argument contract (#89): R1 = CONST_PTR_TO_MAP (a
/// map fd loaded with ldimm64), R2 = key buffer, and for
/// `map_update_elem` R3 = value buffer, R4 = flags scalar (kernel:
/// ARG_PTR_TO_MAP_KEY / ARG_PTR_TO_MAP_VALUE).
fn check_map_helper_args(
    pc: u32,
    imm: i32,
    state: &VerifierState,
) -> Result<(), VerificationFailure> {
    let RegState::PtrToMap {
        key_size,
        value_size,
    } = state.regs[1]
    else {
        return Err(VerificationFailure::new(
            pc,
            "helper arg 1: r1 must be a map pointer (load a map fd with ldimm64 first)",
        ));
    };
    check_map_buffer(pc, state, 2, key_size, "key")?;
    if imm == 2 {
        check_map_buffer(pc, state, 3, value_size, "value")?;
        if !matches!(state.regs[4], RegState::Scalar(_)) {
            return Err(VerificationFailure::new(
                pc,
                "helper arg 4: r4 must be a scalar (flags)",
            ));
        }
    }
    Ok(())
}

/// R{reg} must be an exact stack pointer whose `[off, off + size)`
/// buffer is in-frame and initialized (readable). Mirrors the kernel's
/// ARG_PTR_TO_MAP_KEY/VALUE checks; variable-offset buffers are not
/// supported yet.
fn check_map_buffer(
    pc: u32,
    state: &VerifierState,
    reg: u8,
    size: u32,
    what: &str,
) -> Result<(), VerificationFailure> {
    let RegState::PtrToStack {
        min_offset,
        max_offset,
        align_off,
    } = state.regs[reg as usize]
    else {
        if matches!(state.regs[reg as usize], RegState::Uninit) {
            return Err(VerificationFailure::new(
                pc,
                format!("register r{} is uninitialized", reg),
            ));
        }
        return Err(VerificationFailure::new(
            pc,
            format!(
                "helper arg {}: r{} must be a stack pointer holding the map {} buffer",
                reg + 1,
                reg,
                what
            ),
        ));
    };
    if min_offset != max_offset || align_off == ALIGN_UNKNOWN {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "helper arg {}: r{} must have an exact offset to hold the map {} buffer",
                reg + 1,
                reg,
                what
            ),
        ));
    }
    let off = min_offset as i64;
    let size = size as i64;
    if off < -(STACK_SIZE as i64) || off + size > 0 {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "helper arg {}: r{}{:+} map {} buffer exceeds the 512 byte frame",
                reg + 1,
                reg,
                min_offset,
                what
            ),
        ));
    }
    // the covered slots must be initialized; spilled pointers are not
    // readable as buffer bytes (kernel: "invalid indirect read from
    // stack")
    let low = (-(off + size) / STACK_SLOT_SIZE as i64) as usize;
    let high = ((-off - 1) / STACK_SLOT_SIZE as i64) as usize;
    for slot in low..=high {
        match state.stack.slots[slot] {
            StackSlot::Uninit => {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "stack slot at offset {} is uninitialized (write before read)",
                        slot_offset(slot)
                    ),
                ));
            }
            StackSlot::Initialized => {}
            StackSlot::Spilled(spilled) => {
                if !matches!(spilled, RegState::Scalar(_)) {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "invalid indirect read from stack at r{}: spilled {} at offset {}",
                            reg,
                            spilled,
                            slot_offset(slot)
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The access-time checks for `[base + off]` (#87): every possible
/// concrete offset (the base's interval plus the fixed offset) must
/// stay within the 512-byte frame and be 8-byte aligned; the covered
/// slot range (inclusive) is returned. Mirrors the kernel's
/// `check_stack_access_within_bounds` + alignment requirement.
fn stack_access_range(
    pc: u32,
    base: u8,
    state: &VerifierState,
    off: i16,
) -> Result<(usize, usize), VerificationFailure> {
    let RegState::PtrToStack {
        min_offset,
        max_offset,
        align_off,
    } = state.regs[base as usize]
    else {
        unreachable!("read_stack_ptr checked the base")
    };
    let off64 = off as i64;
    let min_off = min_offset as i64 + off64;
    let max_off = max_offset as i64 + off64 + STACK_SLOT_SIZE as i64;
    // alignment: every possible concrete offset must be 8-byte aligned
    if align_off == ALIGN_UNKNOWN {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "stack pointer r{} alignment is not provable (computed offsets must be 8-byte aligned)",
                base
            ),
        ));
    }
    if (align_off as i32 + off.rem_euclid(8) as i32).rem_euclid(8) != 0 {
        return Err(VerificationFailure::new(
            pc,
            format!("stack access at r{}{:+} is not 8-byte aligned", base, off),
        ));
    }
    // bounds: the whole access range must lie within [-512, 0)
    if min_off >= 0 {
        if base == 10 && min_offset == 0 && max_offset == 0 {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "stack access at r10{:+} points away from the frame (valid: r10-512..r10-8)",
                    off
                ),
            ));
        }
        return Err(VerificationFailure::new(
            pc,
            format!(
                "stack access at r{}{:+} with base offsets {}..{} exceeds the 512 byte frame",
                base, off, min_offset, max_offset
            ),
        ));
    }
    if min_off < -(STACK_SIZE as i64) || max_off > 0 {
        if base == 10 && min_offset == 0 && max_offset == 0 {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "stack access at r10{:+} exceeds the {} byte frame",
                    off, STACK_SIZE
                ),
            ));
        }
        return Err(VerificationFailure::new(
            pc,
            format!(
                "stack access at r{}{:+} with base offsets {}..{} exceeds the 512 byte frame",
                base, off, min_offset, max_offset
            ),
        ));
    }
    // slot range: the access [min_off, max_off) with 8-aligned endpoints
    // covers slots (lowest) ..= (highest); slot(o) = (-o - 1) / 8
    let low = (-max_off / STACK_SLOT_SIZE as i64) as usize;
    let high = ((-min_off - 1) / STACK_SLOT_SIZE as i64) as usize;
    Ok((low, high))
}

/// The r10-relative offset of a stack slot index.
fn slot_offset(slot: usize) -> i32 {
    -(((slot + 1) * STACK_SLOT_SIZE) as i32)
}

/// `PtrToStack + ScalarRange` (#87): the offset interval is widened by
/// the scalar's signed range (saturated to i32) and the alignment is
/// tracked when the scalar's tnum determines the low three bits. Frame
/// bounds and alignment are validated at access time, mirroring the
/// kernel's adjust_ptr_min_max_vals (no arithmetic-time checks for
/// privileged loads).
/// The kernel's arithmetic-time pointer sanity bound
/// (kernel/bpf/verifier.c: BPF_MAX_VAR_OFF = 1 << 28): scalar addends
/// and pointer offsets beyond it are rejected at arithmetic time by
/// check_reg_sane_offset_scalar / check_reg_sane_offset_ptr — distinct
/// from the 512-byte frame checks that happen at access time (#87).
pub(crate) const BPF_MAX_VAR_OFF: i64 = 1 << 28;

/// The kernel's arithmetic-time sanity checks on a scalar addend
/// (check_reg_sane_offset_scalar): an unbounded minimum or an offset
/// beyond BPF_MAX_VAR_OFF is rejected at arithmetic time.
fn check_sane_addend(pc: u32, ptr_kind: &str, s: ScalarBounds) -> Result<(), VerificationFailure> {
    if s.is_constant() {
        let v = s.smin;
        if v >= BPF_MAX_VAR_OFF || v <= -BPF_MAX_VAR_OFF {
            return Err(VerificationFailure::new(
                pc,
                format!("math between {} pointer and {} is not allowed", ptr_kind, v),
            ));
        }
        return Ok(());
    }
    if s.smin == i64::MIN {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "math between {} pointer and register with unbounded min value is not allowed",
                ptr_kind
            ),
        ));
    }
    if s.smin >= BPF_MAX_VAR_OFF || s.smin <= -BPF_MAX_VAR_OFF {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "value {} makes {} pointer be out of bounds",
                s.smin, ptr_kind
            ),
        ));
    }
    Ok(())
}

/// The kernel's arithmetic-time sanity check on the resulting pointer
/// offset (check_reg_sane_offset_ptr).
fn check_sane_result_offset(
    pc: u32,
    ptr_kind: &str,
    min_offset: i64,
) -> Result<(), VerificationFailure> {
    if min_offset >= BPF_MAX_VAR_OFF || min_offset <= -BPF_MAX_VAR_OFF {
        return Err(VerificationFailure::new(
            pc,
            format!("{} pointer offset {} is not allowed", ptr_kind, min_offset),
        ));
    }
    Ok(())
}

fn add_scalar_to_stack_ptr(
    pc: u32,
    dst: u8,
    min_offset: i32,
    max_offset: i32,
    align_off: u8,
    s: ScalarBounds,
    state: &VerifierState,
) -> Result<VerifierState, VerificationFailure> {
    // arithmetic-time sanity (kernel check_reg_sane_offset_scalar /
    // check_reg_sane_offset_ptr): the addend and the result must stay
    // within BPF_MAX_VAR_OFF — the 512-byte frame check itself stays at
    // access time (#87)
    check_sane_addend(pc, "stack", s)?;
    let new_min64 = (min_offset as i64).saturating_add(s.smin);
    let new_max64 = (max_offset as i64).saturating_add(s.smax);
    check_sane_result_offset(pc, "stack", new_min64)?;
    let new_min = clamp_offset(new_min64);
    let new_max = clamp_offset(new_max64);
    // alignment: the low three bits of the scalar's tnum, when known
    let new_align = if s.tnum.mask & 7 == 0 {
        (align_off as i32 + (s.tnum.value & 7) as i32).rem_euclid(8) as u8
    } else {
        ALIGN_UNKNOWN
    };
    let mut next = *state;
    next.regs[dst as usize] = RegState::PtrToStack {
        min_offset: new_min,
        max_offset: new_max,
        align_off: new_align,
    };
    Ok(next)
}

/// Clamp an i64 offset into the i32 interval representation. Anything
/// beyond i32 range is far out of the 512-byte frame either way, so the
/// access-time bounds check still rejects it.
fn clamp_offset(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// `PtrToMapValue + ScalarRange` (#89): the offset interval is widened
/// (saturated to i32) and the alignment tracked; bounds are validated
/// against `value_size` at access time (kernel check_map_access).
fn add_scalar_to_map_value_ptr(
    pc: u32,
    dst: u8,
    ptr: RegState,
    s: ScalarBounds,
    state: &VerifierState,
) -> Result<VerifierState, VerificationFailure> {
    let RegState::PtrToMapValue {
        min_offset,
        max_offset,
        align_off,
        value_size,
    } = ptr
    else {
        unreachable!("the caller matched PtrToMapValue")
    };
    // arithmetic-time sanity (kernel check_reg_sane_offset_scalar /
    // check_reg_sane_offset_ptr) — value_size bounds stay at access time
    check_sane_addend(pc, "map_value", s)?;
    let new_min64 = (min_offset as i64).saturating_add(s.smin);
    let new_max64 = (max_offset as i64).saturating_add(s.smax);
    check_sane_result_offset(pc, "map_value", new_min64)?;
    let new_min = clamp_offset(new_min64);
    let new_max = clamp_offset(new_max64);
    let new_align = if s.tnum.mask & 7 == 0 {
        (align_off as i32 + (s.tnum.value & 7) as i32).rem_euclid(8) as u8
    } else {
        ALIGN_UNKNOWN
    };
    let mut next = *state;
    next.regs[dst as usize] = RegState::PtrToMapValue {
        min_offset: new_min,
        max_offset: new_max,
        align_off: new_align,
        value_size,
    };
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
                tnum: alu_tnum(op, d.tnum, s.tnum, s.smin, s.smax),
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
                tnum: alu_tnum(op, d.tnum, s.tnum, s.smin, s.smax).subreg(),
            }
            .synced()
        }
    }
}

/// The tnum result of an ALU operation (kernel tnum_*).
///
/// For shifts the amount must be a constant — with a variable amount
/// every bit of the result may be anything (sound over-approximation).
/// The 32-bit path truncates the result with `subreg`.
fn alu_tnum(op: AluOp, d: Tnum, s: Tnum, amount_min: i64, amount_max: i64) -> Tnum {
    match op {
        AluOp::Add => d.add(s),
        AluOp::Sub => d.sub(s),
        AluOp::And => d.and(s),
        AluOp::Or => d.or(s),
        AluOp::Xor => d.xor(s),
        AluOp::Lsh | AluOp::Rsh | AluOp::Arsh => {
            if amount_min != amount_max {
                Tnum::unknown()
            } else {
                match op {
                    AluOp::Lsh => d.lshift(amount_min as u32),
                    AluOp::Rsh => d.rshift(amount_min as u32),
                    AluOp::Arsh => d.arshift(amount_min as u32),
                    _ => unreachable!(),
                }
            }
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

/// 32-bit shift ranges; the amount is validated below 32 by the caller.
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
/// Shift amounts are validated by the caller. Shared with the concrete
/// interpreter (#50) so both sides use the same bit-level operation.
pub(crate) fn alu_const64(op: AluOp, a: u64, b: u64) -> u64 {
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
/// Shared with the concrete interpreter (#50).
pub(crate) fn alu_const32(op: AluOp, a: u64, b: u64) -> u64 {
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

/// Validate a shift amount: the kernel rejects shifts that are not
/// provably below the width (check_alu_op's "invalid shift": "< 64
/// range, for 32-bit < 32 range"). Both interpretations are consulted
/// so a diverged state cannot smuggle an invalid amount.
fn check_shift_amount(
    pc: u32,
    s: ScalarBounds,
    width: AluWidth,
) -> Result<(), VerificationFailure> {
    let bitness: i64 = match width {
        AluWidth::W64 => 64,
        AluWidth::W32 => 32,
    };
    if s.smin < 0 || s.smax >= bitness || s.umax >= bitness as u64 {
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
        // overflow falls back to the full range (kernel
        // signed_add_overflows / signed_sub_overflows, #43): a wrapped
        // interval would not contain the true results
        AluOp::Add => {
            if let (Some(lo), Some(hi)) = (dmin.checked_add(smin), dmax.checked_add(smax)) {
                (lo, hi)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
        AluOp::Sub => {
            if let (Some(lo), Some(hi)) = (dmin.checked_sub(smax), dmax.checked_sub(smin)) {
                (lo, hi)
            } else {
                (i64::MIN, i64::MAX)
            }
        }
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
        // overflow falls back to the full range (kernel
        // unsigned_add_overflows / unsigned_sub_overflows, #43)
        AluOp::Add => {
            if let (Some(lo), Some(hi)) = (dmin.checked_add(smin), dmax.checked_add(smax)) {
                (lo, hi)
            } else {
                (0, u64::MAX)
            }
        }
        AluOp::Sub => {
            if let (Some(lo), Some(hi)) = (dmin.checked_sub(smax), dmax.checked_sub(smin)) {
                (lo, hi)
            } else {
                (0, u64::MAX)
            }
        }
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
            if k == 0 {
                return (dmin, dmax);
            }
            // x << k mod 2^64 is monotone within one block of size
            // 2^(64-k); a range spanning a block boundary can wrap
            // multiple times and must widen to the full range (#43)
            if (dmin as u64) >> (64 - k) != (dmax as u64) >> (64 - k) {
                return (i64::MIN, i64::MAX);
            }
            let lo = (dmin as u64) << k;
            let hi = (dmax as u64) << k;
            // a result crossing the sign bit has no i64 interval view
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
        // equality narrows the tnum to the common values (kernel
        // tnum_intersect in regs_refine_cond_op)
        tnum: dst.tnum.intersect(src.tnum),
    }
    .synced();
    // the fall-through (dst != src) excludes the other operand's values
    // where a single interval still represents the complement — e.g.
    // r1 = [0, 42] == 42 → fall r1 = [0, 41] (#44)
    (
        (inter, inter),
        (
            exclude_bounds(dst, src).synced(),
            exclude_bounds(src, dst).synced(),
        ),
    )
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
///
/// This is only sound when `b` is a constant: with a non-constant
/// operand, for every value of `a` there exists a differing value of
/// `b` (the inequality constraint never forces `a` to a smaller set).
fn exclude_bounds(a: ScalarBounds, b: ScalarBounds) -> ScalarBounds {
    if !b.is_constant() {
        return a;
    }
    let s = exclude_interval(a.signed(), (b.smin, b.smin)).unwrap_or(a.signed());
    let u = exclude_interval(a.unsigned(), (b.umin, b.umin)).unwrap_or(a.unsigned());
    ScalarBounds {
        smin: s.0,
        smax: s.1,
        umin: u.0,
        umax: u.1,
        s32_min: i32::MIN,
        s32_max: i32::MAX,
        u32_min: 0,
        u32_max: u32::MAX,
        // inequality cannot narrow the tnum: the complement of a tnum
        // is not representable — keep the sound over-approximation
        tnum: a.tnum,
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
        tnum: dst.tnum.intersect(src.tnum),
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
        BpfInsn::JeqImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Eq, state)
        }
        BpfInsn::JneImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Ne, state)
        }
        BpfInsn::JgtImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Ugt, state)
        }
        BpfInsn::JgeImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Uge, state)
        }
        BpfInsn::JltImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Ult, state)
        }
        BpfInsn::JleImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Ule, state)
        }
        BpfInsn::JsgtImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Sgt, state)
        }
        BpfInsn::JsgeImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Sge, state)
        }
        BpfInsn::JsltImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Slt, state)
        }
        BpfInsn::JsleImm { dst, imm, offset } => {
            cond_branch_imm(pc, *dst, *imm, *offset, CondOp::Sle, state)
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
    let src_state = read_reg(pc, state, src)?;
    cond_branch_impl(pc, dst, Some(src), src_state, offset, op, state)
}

/// Immediate-form conditional branch (`BPF_J*_K`, #57). The kernel
/// folds the immediate into a constant source register
/// (check_cond_jmp_op), so the imm is materialized as a sign-extended
/// constant scalar (imm32 → 64-bit, like the kernel) and the shared
/// refinement path is reused — the constant-only exclusion (#44), the
/// static verdicts and the NULL check (`imm == 0`) apply automatically.
pub(crate) fn cond_branch_imm(
    pc: u32,
    dst: u8,
    imm: i32,
    offset: i16,
    op: CondOp,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    let src_state = RegState::Scalar(ScalarBounds::constant(imm as i64));
    cond_branch_impl(pc, dst, None, src_state, offset, op, state)
}

/// The shared refinement for both compare forms: fork the branch into
/// taken and fall-through successors.
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
///
/// `src_reg` names the register holding the source operand — `None` for
/// the immediate form, where the refined source value has no register
/// to be written to.
fn cond_branch_impl(
    pc: u32,
    dst: u8,
    src_reg: Option<u8>,
    src_state: RegState,
    offset: i16,
    op: CondOp,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    let dst_state = read_reg(pc, state, dst)?;
    let taken_pc = branch_target(pc, offset);
    let fall_pc = pc + 1;
    let src_name = match src_reg {
        Some(r) => format!("r{}", r),
        None => "imm".to_string(),
    };

    let out = match (dst_state, src_state) {
        (RegState::Scalar(d), RegState::Scalar(s)) => {
            let verdict = is_branch_taken(op, d, s);
            let ((t_dst, t_src), (f_dst, f_src)) = refine_cmp(op, d, s);
            let mut out = Vec::with_capacity(2);
            // a statically impossible branch is never explored
            if !matches!(verdict, BranchVerdict::AlwaysNotTaken) {
                let mut taken = *state;
                taken.regs[dst as usize] = RegState::Scalar(t_dst);
                if let Some(src_reg) = src_reg {
                    taken.regs[src_reg as usize] = RegState::Scalar(t_src);
                }
                out.push((taken_pc, taken));
            }
            if !matches!(verdict, BranchVerdict::AlwaysTaken) {
                let mut fall = *state;
                fall.regs[dst as usize] = RegState::Scalar(f_dst);
                if let Some(src_reg) = src_reg {
                    fall.regs[src_reg as usize] = RegState::Scalar(f_src);
                }
                out.push((fall_pc, fall));
            }
            out
        }
        // NULL check: a nullable pointer compared to the constant 0. For
        // `== 0` the taken branch becomes the scalar 0 and the fall-through
        // a valid map value pointer; for `!= 0` the roles are swapped.
        // The map's value size is propagated into the refined pointer (#89).
        (RegState::PtrToMapValueOrNull { value_size }, RegState::Scalar(s))
        | (RegState::Scalar(s), RegState::PtrToMapValueOrNull { value_size })
            if s.is_zero() =>
        {
            match op {
                CondOp::Eq | CondOp::Ne => {
                    let ptr_reg = if matches!(dst_state, RegState::PtrToMapValueOrNull { .. }) {
                        dst
                    } else {
                        // only the reg-reg form can have the pointer in
                        // the source position — an immediate is never a
                        // pointer
                        src_reg.expect("a nullable pointer is never an immediate")
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
                    valid.regs[ptr_reg as usize] = RegState::PtrToMapValue {
                        min_offset: 0,
                        max_offset: 0,
                        align_off: 0,
                        value_size,
                    };
                    vec![(null_side, null_state), (valid_side, valid)]
                }
                _ => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "invalid comparison of r{} with {} (different types)",
                            dst, src_name
                        ),
                    ));
                }
            }
        }
        // a non-null map value pointer compared to 0: equality and
        // inequality are kept without refinement (simplified — the kernel
        // marks the taken branch of == 0 infeasible)
        (RegState::PtrToMapValue { .. }, RegState::Scalar(s))
        | (RegState::Scalar(s), RegState::PtrToMapValue { .. })
            if s.is_zero() =>
        {
            match op {
                CondOp::Eq | CondOp::Ne => vec![(taken_pc, *state), (fall_pc, *state)],
                _ => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "invalid comparison of r{} with {} (different types)",
                            dst, src_name
                        ),
                    ));
                }
            }
        }
        // pointers of the same type: equality and inequality are allowed
        // without refinement; ordered comparisons on pointers are not
        (RegState::PtrToStack { .. }, RegState::PtrToStack { .. })
        | (RegState::PtrToCtx, RegState::PtrToCtx)
        | (RegState::PtrToMap { .. }, RegState::PtrToMap { .. })
        | (RegState::PtrToMapValue { .. }, RegState::PtrToMapValue { .. })
        | (RegState::PtrToMapValueOrNull { .. }, RegState::PtrToMapValueOrNull { .. }) => {
            match op {
                CondOp::Eq | CondOp::Ne => vec![(taken_pc, *state), (fall_pc, *state)],
                _ => {
                    return Err(VerificationFailure::new(
                        pc,
                        format!(
                            "comparing pointers r{} {} {} is not allowed",
                            dst,
                            op.symbol(),
                            src_name
                        ),
                    ));
                }
            }
        }
        // read_reg rejects uninitialized registers before we get here
        (RegState::Uninit, _) | (_, RegState::Uninit) => {
            unreachable!("read_reg rejects uninitialized registers")
        }
        // scalar vs pointer, or pointers of different types
        _ => {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "invalid comparison of r{} with {} (different types)",
                    dst, src_name
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
        assert_eq!(next.regs[10], ptr_stack(0));
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
        assert_eq!(next.regs[5], ptr_stack(0));
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
        // the kernel allows ctx ADD/SUB with a sane offset (#90,
        // adjust_ptr_min_max_vals PTR_TO_CTX); other ops stay rejected
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
        assert_eq!(next.regs[1], RegState::PtrToCtx);
        let err = step(0, &state, &BpfInsn::XorImm { dst: 1, imm: 10 }).unwrap_err();
        assert!(err.message.contains("context pointer"));
        // an insane offset is rejected (kernel check_reg_sane_offset_*)
        let err = step(
            0,
            &state,
            &BpfInsn::AddImm {
                dst: 1,
                imm: 1 << 29,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("not allowed"), "{}", err.message);
        // r10 += r1 with R1 = PtrToCtx → a pointer destination with a
        // non-scalar source is rejected
        let state = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: 1 }).unwrap();
        let err = step(0, &state, &BpfInsn::AddReg { dst: 10, src: 1 }).unwrap_err();
        assert!(err.message.contains("register-offset"));
    }

    #[test]
    fn step_add_scalar_plus_ptr_inherits_pointer_state() {
        // r0 = 1; r0 += r10 → the destination inherits the stack pointer
        // state shifted by the scalar (#87; kernel adjust_ptr_min_max_vals:
        // "dst_reg inherits the complete pointer register state")
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 0, imm: 1 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddReg { dst: 0, src: 10 }).unwrap();
        assert_eq!(next.regs[0], ptr_stack(1));
        // the source pointer is untouched
        assert_eq!(next.regs[10], ptr_stack(0));
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
    fn step_alu_overflow_falls_back_to_full_range() {
        // [MIN, MAX] - 100 overflows the signed range: the result is the
        // full range, never a wrapped min > max state (#43)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::unknown());
        let next = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 100 }).unwrap();
        let next = step(0, &next, &BpfInsn::SubReg { dst: 1, src: 2 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (i64::MIN, i64::MAX));
        assert_eq!(b.unsigned(), (0, u64::MAX));
    }

    #[test]
    fn step_add_overflow_issue_example() {
        // issue example: [MAX-5, MAX] + 10 must never produce an empty
        // (min > max) range. The signed family overflows and falls back
        // to the full range, but the unsigned family did not overflow —
        // the sync then recovers the exact wrapped interval (kernel
        // __reg64_deduce_bounds, "negative" unsigned view).
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(i64::MAX - 5, i64::MAX));
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert!(b.smin <= b.smax);
        // (MAX-5..MAX) + 10 mod 2^64 = (MIN+4..MIN+9) — exact
        assert_eq!(b.signed(), (i64::MIN + 4, i64::MIN + 9));
        assert_eq!(b.unsigned(), (i64::MAX as u64 + 5, i64::MAX as u64 + 10));
    }

    #[test]
    fn step_add_overflow_unsigned_only() {
        // [MAX-5, MAX] + 10 as u64 overflows; the signed view of the same
        // state is negative and does not overflow
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: -10,
            smax: -1,
            umin: u64::MAX - 9,
            umax: u64::MAX,
            s32_min: -10,
            s32_max: -1,
            u32_min: u32::MAX - 9,
            u32_max: u32::MAX,
            tnum: Tnum::unknown(),
        });
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        // signed: [-10, -1] + 10 = [0, 9]
        assert_eq!(b.signed(), (0, 9));
        // unsigned: MAX-9..MAX + 10 wraps; the full-range fallback is
        // intersected with the signed view by the sync → [0, 9] exact
        assert_eq!(b.unsigned(), (0, 9));
    }

    #[test]
    fn step_sub_overflow_falls_back() {
        // [MIN, MIN + 5] - 10 overflows the signed family: never an empty
        // range; the unsigned view (which did not overflow) recovers the
        // exact wrapped interval through the sync
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(i64::MIN, i64::MIN + 5));
        let next = step(0, &state, &BpfInsn::SubImm { dst: 1, imm: 10 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert!(b.smin <= b.smax && b.umin <= b.umax);
        // MIN - 10 mod 2^64 = 2^63 - 10, which is positive in the signed
        // view — the sync recovers the exact interval from the unsigned
        // family (which did not overflow)
        assert_eq!(
            b.signed(),
            (((1u64 << 63) - 10) as i64, ((1u64 << 63) - 5) as i64)
        );
        assert_eq!(b.unsigned(), ((1u64 << 63) - 10, (1u64 << 63) - 5));
    }

    #[test]
    fn step_add_non_overflowing_unchanged() {
        // no behavior change for non-overflowing arithmetic
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 20 }).unwrap();
        assert_eq!(next.regs[1], RegState::Scalar(ScalarBounds::constant(30)));
        // build the i64::MAX constant: 0x80000000 << 32 - 1
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
        let state = step(0, &state, &BpfInsn::LshImm { dst: 1, imm: 32 }).unwrap();
        let state = step(0, &state, &BpfInsn::SubImm { dst: 1, imm: 1 }).unwrap();
        let RegState::Scalar(b) = state.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (i64::MAX, i64::MAX));
        // a constant that wraps stays exact (wrapping is the eBPF ALU
        // semantics: i64::MAX + 1 == i64::MIN)
        let next = step(0, &state, &BpfInsn::AddImm { dst: 1, imm: 1 }).unwrap();
        assert_eq!(
            next.regs[1],
            RegState::Scalar(ScalarBounds::constant(i64::MIN))
        );
    }

    #[test]
    fn alu_matrix_keeps_range_invariant() {
        // the min <= max invariant holds across an ALU test matrix (#43):
        // no operation may produce an empty (wrapped) range
        let cases: [(AluOp, AluWidth, i64, i64, i64, i64); 12] = [
            // (op, width, dmin, dmax, smin, smax)
            (AluOp::Add, AluWidth::W64, i64::MIN, i64::MAX, 1, 1),
            (AluOp::Add, AluWidth::W64, i64::MAX - 5, i64::MAX, 10, 10),
            (AluOp::Sub, AluWidth::W64, i64::MIN, i64::MIN + 5, 10, 10),
            (AluOp::Sub, AluWidth::W64, i64::MIN, i64::MAX, -1, -1),
            (AluOp::And, AluWidth::W64, i64::MIN, i64::MAX, 1, 1),
            (AluOp::Or, AluWidth::W64, i64::MIN, i64::MAX, 8, 8),
            (AluOp::Xor, AluWidth::W64, -100, 100, -50, 50),
            (AluOp::Lsh, AluWidth::W64, 1, i64::MAX, 1, 1),
            (AluOp::Lsh, AluWidth::W64, 1 << 61, i64::MAX, 2, 2),
            (AluOp::Rsh, AluWidth::W64, i64::MIN, i64::MAX, 1, 1),
            (AluOp::Arsh, AluWidth::W64, i64::MIN, i64::MAX, 1, 1),
            (AluOp::Add, AluWidth::W32, i64::MIN, i64::MAX, 1, 1),
        ];
        for (op, width, dmin, dmax, smin, smax) in cases {
            let mut state = VerifierState::initial();
            state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(dmin, dmax));
            state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(smin, smax));
            let result = apply_alu(
                op,
                width,
                as_scalar(state.regs[1]),
                as_scalar(state.regs[2]),
            );
            assert!(
                result.smin <= result.smax && result.umin <= result.umax,
                "{:?} {:?} on [{}, {}] x [{}, {}] → {:?}",
                op,
                width,
                dmin,
                dmax,
                smin,
                smax,
                result
            );
            assert!(
                result.s32_min <= result.s32_max && result.u32_min <= result.u32_max,
                "32-bit invariant {:?} {:?} on [{}, {}] x [{}, {}] → {:?}",
                op,
                width,
                dmin,
                dmax,
                smin,
                smax,
                result
            );
        }
    }

    #[test]
    fn step_alu_shift_block_boundary_sound() {
        // a range spanning a 2^(64-k) block boundary wraps multiple
        // times: the range must widen instead of claiming [MIN, -4]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(1i64 << 61, i64::MAX));
        let next = step(0, &state, &BpfInsn::LshImm { dst: 1, imm: 2 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        // the true results include 0, so a narrow wrapped interval would
        // be unsound — the full range is the only sound answer
        assert_eq!(b.signed(), (i64::MIN, i64::MAX));
        // within one block the shift stays exact
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(1 << 60, (1 << 60) + 3));
        let next = step(0, &state, &BpfInsn::LshImm { dst: 1, imm: 2 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (1 << 62, (1 << 62) + 12));
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
    fn step_alu_tnum_bitwise_issue_example() {
        // issue example: r1 = 0b1xx (values {1, 3}); r1 &= 1 yields a
        // constant 1 in the tnum
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 1,
            smax: 3,
            umin: 1,
            umax: 3,
            s32_min: 1,
            s32_max: 3,
            u32_min: 1,
            u32_max: 3,
            tnum: Tnum {
                value: 0b001,
                mask: 0b010,
            },
        });
        let next = step(0, &state, &BpfInsn::AndImm { dst: 1, imm: 1 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert!(b.tnum.is_constant());
        assert_eq!(b.tnum.value, 1);
    }

    #[test]
    fn step_alu_tnum_or_keeps_known_bits() {
        // r1 = {0, 1} (bit0 unknown); r1 |= 0b100 keeps bit2 known
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 1,
            umin: 0,
            umax: 1,
            s32_min: 0,
            s32_max: 1,
            u32_min: 0,
            u32_max: 1,
            tnum: Tnum {
                value: 0,
                mask: 0b001,
            },
        });
        let next = step(0, &state, &BpfInsn::OrImm { dst: 1, imm: 0b100 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        // values {100, 101}: bit2 known one, bit0 unknown
        assert_eq!(
            b.tnum,
            Tnum {
                value: 0b100,
                mask: 0b001
            }
        );
    }

    #[test]
    fn step_alu32_truncates_tnum() {
        // 0x1_0000_0001 truncates to 1 in the tnum as well
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0x1_0000_0001,
            smax: 0x1_0000_0001,
            umin: 0x1_0000_0001,
            umax: 0x1_0000_0001,
            s32_min: 1,
            s32_max: 1,
            u32_min: 1,
            u32_max: 1,
            tnum: Tnum::constant(0x1_0000_0001),
        });
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.tnum, Tnum::constant(1));
    }

    #[test]
    fn cond_branch_eq_narrows_tnum() {
        // r1 = {0, 1} (tnum) == 1: the taken side intersects the tnum
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 1,
            umin: 0,
            umax: 1,
            s32_min: 0,
            s32_max: 1,
            u32_min: 0,
            u32_max: 1,
            tnum: Tnum {
                value: 0,
                mask: 0b001,
            },
        });
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(1));
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
        assert_eq!(nexts.len(), 2);
        let (_, taken) = &nexts[0];
        let RegState::Scalar(b) = taken.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.tnum, Tnum::constant(1));
    }

    #[test]
    fn cond_branch_jne_keeps_tnum() {
        // r1 = {0, 1} != 1: the taken side keeps the sound over-approximation
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 1,
            umin: 0,
            umax: 1,
            s32_min: 0,
            s32_max: 1,
            u32_min: 0,
            u32_max: 1,
            tnum: Tnum {
                value: 0,
                mask: 0b001,
            },
        });
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(1));
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
        let (_, taken) = &nexts[0];
        let RegState::Scalar(b) = taken.regs[1] else {
            panic!("expected scalar");
        };
        // the exclusion narrows the range to [0, 0] and the sync pins the
        // tnum down to the constant 0 — exact, not just over-approximated
        assert_eq!(b.tnum, Tnum::constant(0));
        // the fall-through (equality) intersects
        let (_, fall) = &nexts[1];
        let RegState::Scalar(b) = fall.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.tnum, Tnum::constant(1));
    }

    #[test]
    fn spill_fill_preserves_tnum() {
        // the stack slot stores the full RegState, tnum included (#42)
        let mut state = VerifierState::initial();
        state.regs[2] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 1,
            umin: 0,
            umax: 1,
            s32_min: 0,
            s32_max: 1,
            u32_min: 0,
            u32_max: 1,
            tnum: Tnum {
                value: 0,
                mask: 0b001,
            },
        });
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -8,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], state.regs[2]);
        let RegState::Scalar(b) = next.regs[3] else {
            panic!("expected scalar");
        };
        assert_eq!(
            b.tnum,
            Tnum {
                value: 0,
                mask: 0b001
            }
        );
    }

    #[test]
    fn step_alu32_range_wrap() {
        // w1: [0xFFFFFFF0, 0xFFFFFFFF] += 0x10 wraps to [0, 0xF]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(
            ScalarBounds {
                smin: 0xFFFF_FFF0,
                smax: 0xFFFF_FFFF,
                umin: 0xFFFF_FFF0,
                umax: 0xFFFF_FFFF,
                s32_min: -0x10,
                s32_max: -1,
                u32_min: 0xFFFF_FFF0,
                u32_max: 0xFFFF_FFFF,
                tnum: Tnum::unknown(),
            }
            .synced(),
        );
        let next = step(0, &state, &BpfInsn::Add32Imm { dst: 1, imm: 0x10 }).unwrap();
        let RegState::Scalar(b) = next.regs[1] else {
            panic!("expected scalar");
        };
        assert_eq!(b.signed(), (0, 0xF));
        assert_eq!(b.unsigned(), (0, 0xF));
        // a range crossing the 32-bit boundary widens to the full range
        state.regs[1] = RegState::Scalar(
            ScalarBounds {
                smin: 0xFFFF_FFF0,
                smax: 0x1_0000_0010,
                umin: 0xFFFF_FFF0,
                umax: 0x1_0000_0010,
                s32_min: i32::MIN,
                s32_max: i32::MAX,
                u32_min: 0,
                u32_max: u32::MAX,
                tnum: Tnum::unknown(),
            }
            .synced(),
        );
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
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
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
        assert_eq!(
            valid.regs[0],
            RegState::PtrToMapValue {
                min_offset: 0,
                max_offset: 0,
                align_off: 0,
                value_size: 8,
            }
        );
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
    fn step_add_reg_stack_ptr_computed_aligned() {
        // r1 = r10; r1 += -32; r1 += r2 with r2 = {0, 8} (tnum low three
        // bits known zero): every resulting offset is in-frame and
        // 8-byte aligned → ACCEPT (#45)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 8,
            umin: 0,
            umax: 8,
            s32_min: 0,
            s32_max: 8,
            u32_min: 0,
            u32_max: 8,
            tnum: Tnum {
                value: 0,
                mask: 0b1000,
            },
        });
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(
            next.regs[1],
            RegState::PtrToStack {
                min_offset: -32,
                max_offset: -24,
                align_off: 0,
            }
        );
        // the frame pointer itself is untouched
        assert_eq!(next.regs[10], ptr_stack(0));
    }

    #[test]
    fn step_add_reg_stack_ptr_exact_result() {
        // r2 = 8 (constant): the result is exact; alignment is not even
        // needed for the acceptance
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(8));
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], ptr_stack(-24));
    }

    #[test]
    fn step_add_reg_stack_ptr_widens_interval() {
        // #87: out-of-frame arithmetic is no longer rejected — the
        // interval widens; access-time checks reject any later access
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 1000,
            umin: 0,
            umax: 1000,
            s32_min: 0,
            s32_max: 1000,
            u32_min: 0,
            u32_max: 1000,
            tnum: Tnum::unknown(),
        });
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        let RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } = next.regs[1]
        else {
            panic!("expected stack pointer");
        };
        assert_eq!((min_offset, max_offset), (-32, 968));
        assert_eq!(align_off, ALIGN_UNKNOWN);
        // r1 = r10 (offset 0) + [0, 8] → interval [0, 8]
        let mut state = VerifierState::initial();
        state.regs[1] = ptr_stack(0);
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(0, 8));
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        let RegState::PtrToStack {
            min_offset,
            max_offset,
            ..
        } = next.regs[1]
        else {
            panic!("expected stack pointer");
        };
        assert_eq!((min_offset, max_offset), (0, 8));
    }

    #[test]
    fn step_add_reg_stack_ptr_tracks_unknown_align() {
        // the scalar's low three bits are unknown → the pointer tracks
        // ALIGN_UNKNOWN without rejecting; the alignment requirement
        // moves to access time (#87)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds {
            smin: 0,
            smax: 8,
            umin: 0,
            umax: 8,
            s32_min: 0,
            s32_max: 8,
            u32_min: 0,
            u32_max: 8,
            tnum: Tnum {
                value: 0,
                mask: 0b101,
            },
        });
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        let RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } = next.regs[1]
        else {
            panic!("expected stack pointer");
        };
        assert_eq!((min_offset, max_offset), (-32, -24));
        assert_eq!(align_off, ALIGN_UNKNOWN);
    }

    #[test]
    fn step_add_reg_stack_ptr_known_misalignment() {
        // r2 low bits known 1: the result is provably misaligned, which
        // is still "not provably 8-byte aligned" for a computed offset
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds {
            smin: 1,
            smax: 1,
            umin: 1,
            umax: 1,
            s32_min: 1,
            s32_max: 1,
            u32_min: 1,
            u32_max: 1,
            tnum: Tnum::constant(1),
        });
        // exact result (r2 is a constant): accepted — access-time checks
        // cover exact offsets
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        assert_eq!(next.regs[1], ptr_stack(-31));
    }

    #[test]
    fn step_add_imm_ptr_stack_alignment() {
        // alignment survives immediate arithmetic: r10 += -8 keeps mod 8
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        let RegState::PtrToStack { align_off, .. } = next.regs[10] else {
            panic!("expected stack pointer");
        };
        assert_eq!(align_off, 0);
        let next = step(0, &next, &BpfInsn::AddImm { dst: 10, imm: -4 }).unwrap();
        let RegState::PtrToStack { align_off, .. } = next.regs[10] else {
            panic!("expected stack pointer");
        };
        assert_eq!(align_off, 4);
    }

    #[test]
    fn step_add_reg_stack_ptr_unbounded_addend_rejected() {
        // the kernel's arithmetic-time sanity check
        // (check_reg_sane_offset_scalar): an addend with an unbounded
        // minimum is rejected at arithmetic time (#90)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: -32,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds::unknown());
        let err = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap_err();
        assert!(
            err.message.contains("unbounded min value"),
            "{}",
            err.message
        );
        // a bounded addend still widens the interval (the i32 clamp
        // keeps the arithmetic overflow-safe)
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(-(1 << 29), 1 << 29));
        let err = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap_err();
        assert!(err.message.contains("out of bounds"), "{}", err.message);
        state.regs[2] = RegState::Scalar(ScalarBounds::from_signed(0, 1000));
        let next = step(0, &state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
        let RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } = next.regs[1]
        else {
            panic!("expected stack pointer");
        };
        assert_eq!((min_offset, max_offset), (-32, 968));
        assert_eq!(align_off, ALIGN_UNKNOWN);
    }

    #[test]
    fn step_add_reg_stack_ptr_pointer_src_rejected() {
        // PtrToStack + PtrToStack is still rejected
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::AddReg { dst: 10, src: 1 }).unwrap_err();
        assert!(err.message.contains("register-offset"), "{}", err.message);
    }

    #[test]
    fn step_add_imm_ptr_stack() {
        // r10 += -8 → PtrToStack(-8): the frame pointer moves down one slot
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(-8));
    }

    #[test]
    fn step_add_imm_ptr_stack_chain() {
        // r10 += -8; r10 += -8 → offset -16
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -8 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(-16));
    }

    #[test]
    fn step_add_imm_ptr_stack_copied_reg() {
        // r5 = r10; r5 += -16 → a copied stack pointer moves independently
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovReg { dst: 5, src: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 5, imm: -16 }).unwrap();
        assert_eq!(next.regs[5], ptr_stack(-16));
        // the frame pointer itself is untouched
        assert_eq!(next.regs[10], ptr_stack(0));
    }

    #[test]
    fn step_add_imm_ptr_stack_out_of_frame() {
        // #87: r10 += 8 / r10 += -520 widen the interval without
        // rejecting — access-time checks reject any later access
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: 8 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(8));
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -520 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(-520));
    }

    #[test]
    fn step_add_imm_ptr_stack_bounds_edges() {
        // offset -512 is the last valid slot; one step past it widens
        // the interval without rejecting (#87)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -512 }).unwrap();
        assert_eq!(state.regs[10], ptr_stack(-512));
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: -1 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(-513));
    }

    #[test]
    fn step_add_imm_ptr_stack_zero() {
        // adding 0 keeps the pointer (no-op)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::AddImm { dst: 10, imm: 0 }).unwrap();
        assert_eq!(next.regs[10], ptr_stack(0));
    }

    // ── Access-time stack validation (#87) ──────────────────────────────────

    #[test]
    fn access_time_out_of_frame_access_rejected() {
        // r6 = r10 - 32 + [0, 248] → [r6] exceeds the frame at access time
        let mut state = VerifierState::initial();
        state.regs[6] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: 216,
            align_off: 0,
        };
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("512 byte frame"), "{}", err.message);
        // the same out-of-frame pointer without an access still passes
        let next = step(0, &state, &BpfInsn::MovReg { dst: 7, src: 6 }).unwrap();
        assert_eq!(next.regs[7], state.regs[6]);
    }

    #[test]
    fn access_time_misaligned_access_rejected() {
        // r6 with unknown low bits → the access alignment is not provable
        let mut state = VerifierState::initial();
        state.regs[6] = RegState::PtrToStack {
            min_offset: -32,
            max_offset: 0,
            align_off: ALIGN_UNKNOWN,
        };
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("alignment"), "{}", err.message);
        // a fixed misaligned offset on r10 stays rejected
        let err = step(
            0,
            &VerifierState::initial(),
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -4,
            },
        )
        .unwrap_err();
        assert!(
            err.message.contains("not 8-byte aligned"),
            "{}",
            err.message
        );
    }

    #[test]
    fn access_time_non_stack_base_rejected() {
        // [r1] with R1 = PtrToCtx is not implemented (kernel ctx loads
        // are out of the subset)
        let state = VerifierState::initial();
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 1,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("non-stack pointer"), "{}", err.message);
        let err = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 1,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("non-stack pointer"), "{}", err.message);
    }

    #[test]
    fn access_time_computed_exact_roundtrip() {
        // r6 = r10 - 32 (exact) → store + load through r6 roundtrips
        // the spilled state
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 7 }).unwrap();
        let state = step(0, &state, &BpfInsn::MovReg { dst: 6, src: 10 }).unwrap();
        let state = step(0, &state, &BpfInsn::AddImm { dst: 6, imm: -32 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 6,
                offset: 0,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::constant(7)));
    }

    #[test]
    fn access_time_variable_store_scrubs_spill() {
        // r6 interval [-256, -8]: a variable-offset store initializes
        // the covered range and destroys spill info (#87)
        let mut state = VerifierState::initial();
        state.regs[6] = RegState::PtrToStack {
            min_offset: -256,
            max_offset: -8,
            align_off: 0,
        };
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(7));
        let next = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 6,
                offset: 0,
            },
        )
        .unwrap();
        for slot in 0..=31 {
            assert_eq!(
                next.stack.slots[slot],
                StackSlot::Initialized,
                "slot {slot}"
            );
        }
        assert_eq!(next.stack.slots[32], StackSlot::Uninit);
        // an exact load from a covered slot yields an unknown scalar
        let loaded = step(
            1,
            &next,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -16,
            },
        )
        .unwrap();
        assert_eq!(loaded.regs[3], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn access_time_variable_load_over_uninit_rejected() {
        let mut state = VerifierState::initial();
        state.regs[6] = RegState::PtrToStack {
            min_offset: -256,
            max_offset: -8,
            align_off: 0,
        };
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("uninitialized"), "{}", err.message);
    }

    #[test]
    fn access_time_variable_load_over_spilled_pointer_rejected() {
        // spill a context pointer at r10-8, then read through a
        // variable base covering that slot → indirect read is rejected
        // (kernel: "invalid indirect read from stack")
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
            },
        )
        .unwrap();
        let mut state = state;
        state.regs[6] = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        let err = step(
            1,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("indirect read"), "{}", err.message);
    }

    #[test]
    fn access_time_variable_load_over_spilled_scalar_ok() {
        // spilled scalars in the range are fine; the result is an
        // unknown scalar
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 5 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
            },
        )
        .unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -16,
            },
        )
        .unwrap();
        let mut state = state;
        state.regs[6] = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        let next = step(
            1,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 6,
                offset: 0,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::unknown()));
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
        // with a non-constant operand the inequality never narrows: for
        // every value of dst there is a differing src value (only a
        // constant operand can be excluded — #44)
        let ((true_dst, true_src), _) =
            refine_ne(ScalarBounds::constant(5), ScalarBounds::from_signed(0, 100));
        assert_eq!(true_dst.signed(), (5, 5));
        assert_eq!(true_src.signed(), (0, 100));
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
    fn refine_mirrors_kernel_equations() {
        // the kernel's reg_set_min_max equations on a fixed example set
        // (dst vs a constant val), kernel/bpf/verifier.c (#44):
        //   JGT:   false umax = min(umax, val);      true umin = max(umin, val + 1)
        //   JSGT:  false smax = min(smax, val);      true smin = max(smin, val + 1)
        //   JGE:   false umax = min(umax, val - 1);  true umin = max(umin, val)
        //   JSGE:  false smax = min(smax, val - 1);  true smin = max(smin, val)
        //   JLT:   false umin = max(umin, val);      true umax = min(umax, val - 1)
        //   JSLT:  false smin = max(smin, val);      true smax = min(smax, val - 1)
        //   JLE:   false umin = max(umin, val + 1);  true umax = min(umax, val)
        //   JSLE:  false smin = max(smin, val + 1);  true smax = min(smax, val)
        let dst = ScalarBounds::from_signed(0, 100);
        let val = ScalarBounds::constant(42);
        let (t, f) = refine_cmp(CondOp::Ugt, dst, val);
        assert_eq!(t.0.signed(), (43, 100)); // true umin = max(0, 42+1)
        assert_eq!(f.0.signed(), (0, 42)); // false umax = min(100, 42)
        let (t, f) = refine_cmp(CondOp::Sgt, dst, val);
        assert_eq!(t.0.signed(), (43, 100));
        assert_eq!(f.0.signed(), (0, 42));
        let (t, f) = refine_cmp(CondOp::Uge, dst, val);
        assert_eq!(t.0.signed(), (42, 100)); // true umin = max(0, 42)
        assert_eq!(f.0.signed(), (0, 41)); // false umax = min(100, 42-1)
        let (t, f) = refine_cmp(CondOp::Sge, dst, val);
        assert_eq!(t.0.signed(), (42, 100));
        assert_eq!(f.0.signed(), (0, 41));
        let (t, f) = refine_cmp(CondOp::Ult, dst, val);
        assert_eq!(t.0.signed(), (0, 41)); // true umax = min(100, 42-1)
        assert_eq!(f.0.signed(), (42, 100)); // false umin = max(0, 42)
        let (t, f) = refine_cmp(CondOp::Slt, dst, val);
        assert_eq!(t.0.signed(), (0, 41));
        assert_eq!(f.0.signed(), (42, 100));
        let (t, f) = refine_cmp(CondOp::Ule, dst, val);
        assert_eq!(t.0.signed(), (0, 42)); // true umax = min(100, 42)
        assert_eq!(f.0.signed(), (43, 100)); // false umin = max(0, 42+1)
        let (t, f) = refine_cmp(CondOp::Sle, dst, val);
        assert_eq!(t.0.signed(), (0, 42));
        assert_eq!(f.0.signed(), (43, 100));
    }

    #[test]
    fn refine_eq_fall_excludes_constant() {
        // r1 = [0, 42] == 42: the taken side is the constant, the
        // fall-through excludes it where a single interval allows it
        let ((true_dst, _), (false_dst, _)) =
            refine_eq(ScalarBounds::from_signed(0, 42), ScalarBounds::constant(42));
        assert_eq!(true_dst.signed(), (42, 42));
        assert_eq!(false_dst.signed(), (0, 41));
        // the complement of a mid-range constant is not representable
        let ((_, _), (false_dst, _)) = refine_eq(
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::constant(42),
        );
        assert_eq!(false_dst.signed(), (0, 100));
        // a non-constant operand is never excluded
        let ((_, _), (false_dst, false_src)) = refine_eq(
            ScalarBounds::from_signed(0, 100),
            ScalarBounds::from_signed(40, 60),
        );
        assert_eq!(false_dst.signed(), (0, 100));
        assert_eq!(false_src.signed(), (40, 60));
    }

    #[test]
    fn is_branch_taken_unsigned_pruning() {
        // infeasible-branch pruning works for unsigned comparisons (#44):
        // r1 = -1 (u64::MAX) vs 0
        let r1 = ScalarBounds::constant(-1);
        let zero = ScalarBounds::constant(0);
        // JGT: MAX > 0 always → the fall-through is pruned
        assert!(matches!(
            is_branch_taken(CondOp::Ugt, r1, zero),
            BranchVerdict::AlwaysTaken
        ));
        // JLE: MAX <= 0 never → the taken branch is pruned
        assert!(matches!(
            is_branch_taken(CondOp::Ule, r1, zero),
            BranchVerdict::AlwaysNotTaken
        ));
        // JGE on a negative range: [-10, -1] as u64 is [MAX-9, MAX] ≥ 0
        let neg = ScalarBounds::from_signed(-10, -1);
        assert!(matches!(
            is_branch_taken(CondOp::Uge, neg, zero),
            BranchVerdict::AlwaysTaken
        ));
        // and the signed family prunes the mirror image
        assert!(matches!(
            is_branch_taken(CondOp::Slt, neg, zero),
            BranchVerdict::AlwaysTaken
        ));
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

    // ── Immediate compares (BPF_J*_K, #57) ───────────────────────────────────

    #[test]
    fn successors_jeq_imm_always_taken() {
        // the immediate form materializes the constant: r1 == 42 with
        // r1 = 42 → only the taken successor is explored
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(42));
        let nexts = successors(
            0,
            &BpfInsn::JeqImm {
                dst: 1,
                imm: 42,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 2);
        // only the register operand is refined — there is no source
        // register for the immediate to write back to
        assert_eq!(
            nexts[0].1.regs[1],
            RegState::Scalar(ScalarBounds::constant(42))
        );
    }

    #[test]
    fn successors_jeq_imm_refines_like_reg_form() {
        // `jeq r1, 7` must refine r1 exactly like `r2 = 7; jeq r1, r2`
        // (the kernel folds BPF_K into a constant source register)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));

        // reg form with a constant source register
        let mut reg_state = state;
        reg_state.regs[2] = RegState::Scalar(ScalarBounds::constant(7));
        let reg_nexts = successors(
            0,
            &BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &reg_state,
        )
        .unwrap();

        // imm form
        let imm_nexts = successors(
            0,
            &BpfInsn::JeqImm {
                dst: 1,
                imm: 7,
                offset: 1,
            },
            &state,
        )
        .unwrap();

        // the same successors with the same refinement of r1 (the reg
        // form additionally keeps the constant in r2 on both branches)
        assert_eq!(imm_nexts.len(), reg_nexts.len());
        for (imm_succ, reg_succ) in imm_nexts.iter().zip(reg_nexts.iter()) {
            assert_eq!(imm_succ.0, reg_succ.0);
            assert_eq!(imm_succ.1.regs[1], reg_succ.1.regs[1]);
            assert_eq!(
                reg_succ.1.regs[2],
                RegState::Scalar(ScalarBounds::constant(7))
            );
        }
    }

    #[test]
    fn successors_null_check_imm_zero() {
        // `if r0 == 0` with r0 = PtrToMapValueOrNull — the clang idiom
        // for the #27 NULL check in its immediate form: the taken
        // branch becomes the scalar 0, the fall-through a valid map
        // value pointer
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
        let nexts = successors(
            0,
            &BpfInsn::JeqImm {
                dst: 0,
                imm: 0,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        let (taken_pc, taken) = &nexts[0];
        assert_eq!(*taken_pc, 2);
        assert_eq!(taken.regs[0], RegState::Scalar(ScalarBounds::constant(0)));
        let (fall_pc, fall) = &nexts[1];
        assert_eq!(*fall_pc, 1);
        assert_eq!(
            fall.regs[0],
            RegState::PtrToMapValue {
                min_offset: 0,
                max_offset: 0,
                align_off: 0,
                value_size: 8,
            }
        );
    }

    #[test]
    fn successors_jsgt_imm_negative_sign_extends() {
        // the imm is sign-extended like the kernel's imm32:
        // jsgt r1, -1 with r1 in [0, 10] is always taken (0 > -1)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 10));
        let nexts = successors(
            0,
            &BpfInsn::JsgtImm {
                dst: 1,
                imm: -1,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 2);
    }

    #[test]
    fn successors_imm_pointer_compare_rejected() {
        // a pointer compared to an immediate is rejected like the
        // reg-form mixed-type comparison (r1 = PtrToCtx at entry)
        let state = VerifierState::initial();
        let err = successors(
            0,
            &BpfInsn::JeqImm {
                dst: 1,
                imm: 0,
                offset: 1,
            },
            &state,
        )
        .unwrap_err();
        assert!(err.message.contains("different types"), "{}", err.message);
    }

    #[test]
    fn successors_null_check_issue_example() {
        // issue example: r0 = PtrToMapValueOrNull; if r0 == 0 (via r1 = 0)
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
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
        assert_eq!(
            fall.regs[0],
            RegState::PtrToMapValue {
                min_offset: 0,
                max_offset: 0,
                align_off: 0,
                value_size: 8,
            }
        );
    }

    #[test]
    fn successors_null_check_reversed_operands() {
        // the constant 0 may also be the dst register: if r1 == r0 with r1 = 0
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
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
        assert_eq!(
            nexts[1].1.regs[0],
            RegState::PtrToMapValue {
                min_offset: 0,
                max_offset: 0,
                align_off: 0,
                value_size: 8,
            }
        );
    }

    #[test]
    fn successors_null_check_nonzero_scalar_rejected() {
        // only the constant 0 enables a NULL check; other scalars keep the
        // different-types rejection
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
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
        state.regs[0] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
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
        state.regs[0] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
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
        state.regs[0] = RegState::PtrToMapValueOrNull { value_size: 8 };
        let err = step(0, &state, &BpfInsn::AddImm { dst: 0, imm: 8 }).unwrap_err();
        assert!(err.message.contains("NULL"));
    }

    #[test]
    fn step_add_imm_map_value_ptr_rejected() {
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
        // #89: ADD widens the offset interval instead of rejecting
        let next = step(0, &state, &BpfInsn::AddImm { dst: 0, imm: 8 }).unwrap();
        let RegState::PtrToMapValue {
            min_offset,
            max_offset,
            value_size,
            ..
        } = next.regs[0]
        else {
            panic!("expected map value pointer");
        };
        assert_eq!((min_offset, max_offset), (8, 8));
        assert_eq!(value_size, 8);
        // SUB is still rejected
        let err = step(0, &state, &BpfInsn::SubImm { dst: 0, imm: 1 }).unwrap_err();
        assert!(err.message.contains("map value pointer"));
    }

    // ── Helpers (v0.3) ──────────────────────────────────────────────────────

    #[test]
    fn step_call_map_lookup_ok() {
        // R1 = map pointer, R2 = key pointer → after the call R0 is the
        // nullable map value pointer (#27's producer) and the argument
        // registers are clobbered (#29)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = ptr_stack(-8);
        state.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        let next = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap();
        assert_eq!(
            next.regs[0],
            RegState::PtrToMapValueOrNull { value_size: 8 }
        );
        assert_eq!(next.regs[1], RegState::Uninit);
        assert_eq!(next.regs[2], RegState::Uninit);
    }

    #[test]
    fn step_call_prandom() {
        // no arguments → R0 becomes an unknown scalar (full range)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::Call { imm: 7 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn step_call_map_update_ok() {
        // map_update(map, key, value, flags): all four args validated,
        // returns 0 on success
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = ptr_stack(-8);
        state.regs[3] = ptr_stack(-16);
        state.regs[4] = RegState::Scalar(ScalarBounds::constant(0));
        state.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        state.stack.slots[1] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        let next = step(0, &state, &BpfInsn::Call { imm: 2 }).unwrap();
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(0)));
    }

    #[test]
    fn step_call_map_update_missing_value() {
        // R3 (the value pointer) is uninitialized → #14 error
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = ptr_stack(-8);
        state.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        let err = step(0, &state, &BpfInsn::Call { imm: 2 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn step_call_map_lookup_key_buffer_uninit() {
        // the key buffer slot must be initialized before the call
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = ptr_stack(-8);
        let err = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap_err();
        assert!(err.message.contains("uninitialized"), "{}", err.message);
        // a spilled pointer is not readable as a key buffer
        state.stack.slots[0] = StackSlot::Spilled(RegState::PtrToCtx);
        let err = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap_err();
        assert!(err.message.contains("indirect read"), "{}", err.message);
    }

    #[test]
    fn step_call_map_lookup_key_buffer_non_stack() {
        // R2 must be a stack pointer (a map value pointer is not a key
        // buffer yet)
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
        let err = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap_err();
        assert!(err.message.contains("map key buffer"), "{}", err.message);
    }

    #[test]
    fn access_time_map_value_access() {
        // r0 = map value [0..0], value_size 8: [r0] loads an unknown
        // scalar, [r0+8] is out of bounds, [r0-1] is misaligned
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 4,
                base: 0,
                offset: 0,
            },
        )
        .unwrap();
        assert_eq!(next.regs[4], RegState::Scalar(ScalarBounds::unknown()));
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 4,
                base: 0,
                offset: 8,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("map value"), "{}", err.message);
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 4,
                base: 0,
                offset: -1,
            },
        )
        .unwrap_err();
        assert!(
            err.message.contains("not 8-byte aligned"),
            "{}",
            err.message
        );
        // an in-bounds store is accepted (map memory is concrete-side)
        state.regs[4] = RegState::Scalar(ScalarBounds::constant(1));
        step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 4,
                base: 0,
                offset: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn access_time_map_value_unaligned_interval() {
        // an interval with unknown alignment cannot be accessed
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 4,
            align_off: ALIGN_UNKNOWN,
            value_size: 8,
        };
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 4,
                base: 0,
                offset: 0,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("alignment"), "{}", err.message);
    }

    #[test]
    fn step_add_scalar_plus_map_value_ptr() {
        // scalar += map value pointer inherits the pointer state (#89)
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::Scalar(ScalarBounds::constant(1));
        state.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
        let next = step(0, &state, &BpfInsn::AddReg { dst: 0, src: 1 }).unwrap();
        assert_eq!(
            next.regs[0],
            RegState::PtrToMapValue {
                min_offset: 1,
                max_offset: 1,
                align_off: 1,
                value_size: 8,
            }
        );
    }

    #[test]
    fn step_call_arg_mismatch() {
        // R1 is the context pointer, not a map pointer → rejected
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap_err();
        assert!(err.message.contains("map pointer"), "{}", err.message);
    }

    #[test]
    fn step_call_unknown_helper() {
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::Call { imm: 99 }).unwrap_err();
        assert!(err.message.contains("unknown helper 99"));
    }

    #[test]
    fn step_call_uninit_arg() {
        // R2 (the key pointer) is uninitialized → #14 error
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        let err = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap_err();
        assert!(err.message.contains("uninitialized"), "{}", err.message);
    }

    #[test]
    fn step_call_clobbers_r1_to_r5_preserves_r6_to_r9() {
        // the eBPF calling convention: R1..R5 are scratch, R6..R9 callee-saved
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::PtrToMap {
            key_size: 4,
            value_size: 8,
        };
        state.regs[2] = ptr_stack(-8);
        state.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        state.regs[3] = RegState::Scalar(ScalarBounds::constant(1));
        state.regs[4] = RegState::Scalar(ScalarBounds::constant(2));
        state.regs[5] = RegState::Scalar(ScalarBounds::constant(3));
        state.regs[6] = RegState::Scalar(ScalarBounds::constant(10));
        state.regs[7] = RegState::Scalar(ScalarBounds::constant(11));
        state.regs[8] = RegState::Scalar(ScalarBounds::constant(12));
        state.regs[9] = RegState::Scalar(ScalarBounds::constant(13));

        let next = step(0, &state, &BpfInsn::Call { imm: 1 }).unwrap();
        // R0 = return type, R1..R5 invalidated
        assert_eq!(
            next.regs[0],
            RegState::PtrToMapValueOrNull { value_size: 8 }
        );
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
        assert_eq!(next.regs[10], ptr_stack(0));
    }
}
