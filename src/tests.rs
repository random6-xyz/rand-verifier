use super::*;

// ── helpers ──────────────────────────────────────────────────────────────

/// Build a raw 8-byte instruction:
/// [op, (src << 4 | dst), offset_le, imm_le]
fn insn_bytes(op: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = op;
    b[1] = (src << 4) | (dst & 0x0F);
    b[2..4].copy_from_slice(&offset.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

/// Concatenate 8-byte instructions into a raw program byte stream.
fn prog_bytes(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flatten().copied().collect()
}

/// Decode a single raw instruction (shorthand for parse_insn tests).
fn parse(op: u8, dst: u8, src: u8, offset: i16, imm: i32) -> BpfInsn {
    parse_insn(&insn_bytes(op, dst, src, offset, imm))
}

// ── parse_insn ───────────────────────────────────────────────────────────

#[test]
fn parse_insn_mov_imm() {
    let insn = parse(opcode::MOV_IMM, 1, 0, 0, 42);
    assert!(matches!(insn, BpfInsn::MovImm { dst: 1, imm: 42 }));
}

#[test]
fn parse_insn_mov_reg() {
    let insn = parse(opcode::MOV_REG, 2, 3, 0, 0);
    assert!(matches!(insn, BpfInsn::MovReg { dst: 2, src: 3 }));
}

#[test]
fn parse_insn_add_imm() {
    // negative imm must be preserved
    let insn = parse(opcode::ADD_IMM, 1, 0, 0, -7);
    assert!(matches!(insn, BpfInsn::AddImm { dst: 1, imm: -7 }));
}

#[test]
fn parse_insn_add_reg() {
    let insn = parse(opcode::ADD_REG, 0, 6, 0, 0);
    assert!(matches!(insn, BpfInsn::AddReg { dst: 0, src: 6 }));
}

#[test]
fn parse_insn_ld_stack() {
    // negative stack offset (frame-pointer relative)
    let insn = parse(opcode::LD_STACK, 0, 0, -8, 0);
    assert!(matches!(insn, BpfInsn::LdStack { dst: 0, offset: -8 }));
}

#[test]
fn parse_insn_st_stack() {
    let insn = parse(opcode::ST_STACK, 0, 1, -8, 0);
    assert!(matches!(insn, BpfInsn::StStack { src: 1, offset: -8 }));
}

#[test]
fn parse_insn_jeq() {
    let insn = parse(opcode::JEQ, 1, 2, 4, 0);
    assert!(matches!(
        insn,
        BpfInsn::Jeq {
            dst: 1,
            src: 2,
            offset: 4
        }
    ));
}

#[test]
fn parse_insn_jgt() {
    let insn = parse(opcode::JGT, 1, 2, -4, 0);
    assert!(matches!(
        insn,
        BpfInsn::Jgt {
            dst: 1,
            src: 2,
            offset: -4
        }
    ));
}

#[test]
fn parse_insn_jmp() {
    let insn = parse(opcode::JMP, 0, 0, 3, 0);
    assert!(matches!(insn, BpfInsn::Jmp { offset: 3 }));
}

#[test]
fn parse_insn_call() {
    let insn = parse(opcode::CALL, 0, 0, 0, 100);
    assert!(matches!(insn, BpfInsn::Call { imm: 100 }));
}

#[test]
fn parse_insn_exit() {
    let insn = parse(opcode::EXIT, 0, 0, 0, 0);
    assert!(matches!(insn, BpfInsn::Exit));
}

// ── RegState (v0.2) ─────────────────────────────────────────────────────

#[test]
fn reg_state_initial_state() {
    let regs = initial_reg_state();
    assert_eq!(regs.len(), 11);

    // R0 = Uninit
    assert_eq!(regs[0], RegState::Uninit);

    // R1 = PtrToCtx
    assert_eq!(regs[1], RegState::PtrToCtx);

    // R2..R9 = Uninit
    for i in 2..=9 {
        assert_eq!(regs[i], RegState::Uninit);
    }

    // R10 = PtrToStack(0)
    assert_eq!(regs[10], RegState::PtrToStack { offset: 0 });
}

#[test]
fn reg_state_scalar_equality() {
    let c = RegState::Scalar { min: 10, max: 10 };
    assert_eq!(c, RegState::Scalar { min: 10, max: 10 });
    assert_ne!(c, RegState::Scalar { min: 10, max: 11 });
    assert_ne!(c, RegState::Uninit);
}

#[test]
fn reg_state_display() {
    assert_eq!(RegState::Uninit.to_string(), "UNINIT");
    assert_eq!(
        RegState::Scalar { min: 0, max: 100 }.to_string(),
        "SCALAR(0..100)"
    );
    assert_eq!(
        RegState::PtrToStack { offset: -8 }.to_string(),
        "PTR_STACK(-8)"
    );
    assert_eq!(RegState::PtrToCtx.to_string(), "PTR_CTX");
}

// ── VerifierState (v0.2) ─────────────────────────────────────────────────

#[test]
fn verifier_state_initial() {
    let state = VerifierState::initial();

    // registers match the #11 initial state
    assert_eq!(state.regs, initial_reg_state());

    // the stack frame starts with every slot uninitialized (#17)
    assert_eq!(state.stack, StackState::new());
}

#[test]
fn verifier_state_initial_matches_issue_spec() {
    let state = VerifierState::initial();

    // R0 = Uninit
    assert_eq!(state.regs[0], RegState::Uninit);

    // R1 = PtrToCtx
    assert_eq!(state.regs[1], RegState::PtrToCtx);

    // R2..R9 = Uninit
    for i in 2..=9 {
        assert_eq!(state.regs[i], RegState::Uninit);
    }

    // R10 = PtrToStack(0)
    assert_eq!(state.regs[10], RegState::PtrToStack { offset: 0 });
}

// ── StackState (v0.2) ────────────────────────────────────────────────────

#[test]
fn stack_state_new_all_uninit() {
    let stack = StackState::new();
    assert_eq!(stack.slots.len(), STACK_SLOTS);
    assert!(stack.slots.iter().all(|s| *s == StackSlot::Uninit));
}

#[test]
fn stack_slot_constants() {
    // the 512-byte frame split into 8-byte slots → 64 slots
    assert_eq!(STACK_SIZE, 512);
    assert_eq!(STACK_SLOT_SIZE, 8);
    assert_eq!(STACK_SLOTS, 64);
}

#[test]
fn stack_slot_display() {
    assert_eq!(StackSlot::Uninit.to_string(), "UNINIT");
    assert_eq!(StackSlot::Scalar.to_string(), "SCALAR");
}

#[test]
fn stack_state_equality() {
    let a = StackState::new();
    let mut b = StackState::new();
    b.slots[0] = StackSlot::Scalar;
    assert_ne!(a, b);
}

// ── Stack load/store (v0.2) ──────────────────────────────────────────────

#[test]
fn st_stack_writes_scalar_slot() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::StStack { src: 2, offset: -8 }).unwrap();
    assert_eq!(next.stack.slots[0], StackSlot::Scalar);
    // the source register is unchanged
    assert_eq!(next.regs[2], RegState::Scalar { min: 10, max: 10 });
}

#[test]
fn st_stack_offsets_map_to_slots() {
    // -8 → slot 0, -16 → slot 1, -512 → slot 63
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let next = step(
        &state,
        &BpfInsn::StStack {
            src: 2,
            offset: -512,
        },
    )
    .unwrap();
    assert_eq!(next.stack.slots[63], StackSlot::Scalar);
    assert_eq!(next.stack.slots[0], StackSlot::Uninit);
}

#[test]
fn st_stack_rejects_uninit_src() {
    // storing r0 before it is written → #14 error
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::StStack { src: 0, offset: -8 }).unwrap_err();
    assert!(err.message.contains("uninitialized"));
}

#[test]
fn st_stack_rejects_pointer_spill() {
    // storing a pointer is not representable yet → #30
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::StStack { src: 1, offset: -8 }).unwrap_err();
    assert!(err.message.contains("#30"));
}

#[test]
fn ld_stack_after_store() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let state = step(&state, &BpfInsn::StStack { src: 2, offset: -8 }).unwrap();
    let next = step(&state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap();
    // the slot carries no range, so the loaded scalar is unknown (full range)
    assert_eq!(
        next.regs[0],
        RegState::Scalar {
            min: i64::MIN,
            max: i64::MAX
        }
    );
}

#[test]
fn ld_stack_before_store_rejected() {
    // issue example: load [r10 - 8] with no prior store → REJECT
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap_err();
    assert!(err.message.contains("uninitialized"));
    assert!(err.message.contains("write before read"));
}

#[test]
fn ld_stack_slot_granularity() {
    // a store at -16 does not make -8 readable (slot-level granularity)
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let state = step(
        &state,
        &BpfInsn::StStack {
            src: 2,
            offset: -16,
        },
    )
    .unwrap();
    let err = step(&state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap_err();
    assert!(err.message.contains("write before read"));
}

#[test]
fn stack_invalid_offsets_rejected() {
    let state = VerifierState::initial();
    // wrong direction: r10 + N (positive) and the frame pointer itself (0)
    for offset in [8, 0] {
        let err = step(&state, &BpfInsn::LdStack { dst: 0, offset }).unwrap_err();
        assert!(err.message.contains("points away"), "offset {}", offset);
    }
    // beyond the 512-byte frame
    let err = step(
        &state,
        &BpfInsn::LdStack {
            dst: 0,
            offset: -520,
        },
    )
    .unwrap_err();
    assert!(err.message.contains("exceeds"));
    // not 8-byte aligned
    for offset in [-7, -4] {
        let err = step(&state, &BpfInsn::LdStack { dst: 0, offset }).unwrap_err();
        assert!(
            err.message.contains("not 8-byte aligned"),
            "offset {}",
            offset
        );
    }
    // a store with a wrong-direction offset is rejected too
    let err = step(&state, &BpfInsn::StStack { src: 1, offset: 8 }).unwrap_err();
    assert!(err.message.contains("points away"));
}

#[test]
fn stack_bounds_frame_edges() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    // both frame edges are valid
    for offset in [-8, -512] {
        let next = step(&state, &BpfInsn::StStack { src: 2, offset }).unwrap();
        let idx = stack_slot_index(offset as i32).unwrap();
        assert_eq!(next.stack.slots[idx], StackSlot::Scalar);
    }
    // one byte beyond each edge is rejected
    for offset in [-7, -513] {
        assert!(
            step(&state, &BpfInsn::StStack { src: 2, offset }).is_err(),
            "offset {}",
            offset
        );
    }
}

#[test]
fn stack_slot_index_mapping() {
    assert_eq!(stack_slot_index(-8).unwrap(), 0);
    assert_eq!(stack_slot_index(-16).unwrap(), 1);
    assert_eq!(stack_slot_index(-512).unwrap(), 63);
}

// ── step (v0.2) ──────────────────────────────────────────────────────────

#[test]
fn step_mov_imm_issue_example() {
    // Before: R2 = Uninit;  r2 = 10;  After: R2 = Scalar(10..10)
    let state = VerifierState::initial();
    let next = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    assert_eq!(next.regs[2], RegState::Scalar { min: 10, max: 10 });
    // other registers untouched
    assert_eq!(next.regs[1], RegState::PtrToCtx);
    assert_eq!(next.regs[10], RegState::PtrToStack { offset: 0 });
}

#[test]
fn step_mov_imm_overwrites() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::MovImm { dst: 2, imm: 20 }).unwrap();
    assert_eq!(next.regs[2], RegState::Scalar { min: 20, max: 20 });
}

#[test]
fn step_mov_imm_negative() {
    // i32 imm is sign-extended into the i64 scalar range
    let state = VerifierState::initial();
    let next = step(&state, &BpfInsn::MovImm { dst: 0, imm: -7 }).unwrap();
    assert_eq!(next.regs[0], RegState::Scalar { min: -7, max: -7 });
}

#[test]
fn step_mov_reg_copies_scalar() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::MovReg { dst: 3, src: 2 }).unwrap();
    assert_eq!(next.regs[3], RegState::Scalar { min: 10, max: 10 });
}

#[test]
fn step_mov_reg_copies_pointers() {
    let state = VerifierState::initial();
    let next = step(&state, &BpfInsn::MovReg { dst: 4, src: 1 }).unwrap();
    assert_eq!(next.regs[4], RegState::PtrToCtx);
    let next = step(&state, &BpfInsn::MovReg { dst: 5, src: 10 }).unwrap();
    assert_eq!(next.regs[5], RegState::PtrToStack { offset: 0 });
}

#[test]
fn step_mov_reg_uninit_rejected() {
    // issue example: r0 = r2 with R2 uninitialized → REJECT
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::MovReg { dst: 0, src: 2 }).unwrap_err();
    assert!(err.message.contains("r2"));
    assert!(err.message.contains("uninitialized"));
}

#[test]
fn step_mov_reg_self_copy_uninit_rejected() {
    // r2 = r2 with R2 uninitialized is still a read → REJECT
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::MovReg { dst: 2, src: 2 }).unwrap_err();
    assert!(err.message.contains("uninitialized"));
}

#[test]
fn step_mov_reg_uninit_after_write_ok() {
    // r2 = 10 then r0 = r2 → the read is allowed once written
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::MovReg { dst: 0, src: 2 }).unwrap();
    assert_eq!(next.regs[0], RegState::Scalar { min: 10, max: 10 });
}

#[test]
fn step_exit_unchanged() {
    let state = VerifierState::initial();
    let next = step(&state, &BpfInsn::Exit).unwrap();
    assert_eq!(next, state);
}

#[test]
fn step_stub_errors_reference_issue() {
    let state = VerifierState::initial();
    // control flow → #23
    let err = step(
        &state,
        &BpfInsn::Jeq {
            dst: 0,
            src: 1,
            offset: 1,
        },
    )
    .unwrap_err();
    assert!(err.message.contains("#23"));
}

#[test]
fn step_invalid_register_rejected() {
    let state = VerifierState::initial();
    // dst 11 is out of range (valid: r0..r10)
    let err = step(&state, &BpfInsn::MovImm { dst: 11, imm: 1 }).unwrap_err();
    assert!(err.message.contains("invalid register r11"));
    // src 12 is out of range
    let err = step(&state, &BpfInsn::MovReg { dst: 0, src: 12 }).unwrap_err();
    assert!(err.message.contains("invalid register r12"));
}

#[test]
fn step_is_pure() {
    // the input state is not mutated
    let state = VerifierState::initial();
    let _ = step(&state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
    assert_eq!(state.regs[2], RegState::Uninit);
}

#[test]
fn read_reg_initialized_regs() {
    let state = VerifierState::initial();
    // R1 (PtrToCtx) and R10 (PtrToStack) are readable at entry
    assert_eq!(read_reg(&state, 1).unwrap(), RegState::PtrToCtx);
    assert_eq!(
        read_reg(&state, 10).unwrap(),
        RegState::PtrToStack { offset: 0 }
    );
}

#[test]
fn read_reg_uninit_rejected() {
    let state = VerifierState::initial();
    let err = read_reg(&state, 2).unwrap_err();
    assert!(err.message.contains("register r2 is uninitialized"));
}

#[test]
fn read_reg_out_of_range_rejected() {
    let state = VerifierState::initial();
    let err = read_reg(&state, 11).unwrap_err();
    assert!(err.message.contains("invalid register r11"));
}

// ── ALU (v0.2) ───────────────────────────────────────────────────────────

#[test]
fn step_add_imm_issue_example() {
    // issue example: r1 = 10; r1 += 20 → R1 = Scalar(30..30)
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::AddImm { dst: 1, imm: 20 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 30, max: 30 });
}

#[test]
fn step_add_imm_negative() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::AddImm { dst: 1, imm: -3 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 7, max: 7 });
}

#[test]
fn step_add_reg_constants() {
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
    let state = step(&state, &BpfInsn::MovImm { dst: 2, imm: 5 }).unwrap();
    let next = step(&state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 15, max: 15 });
    // the source register is unchanged
    assert_eq!(next.regs[2], RegState::Scalar { min: 5, max: 5 });
}

#[test]
fn step_add_reg_self() {
    // r1 += r1 doubles the value
    let state = VerifierState::initial();
    let state = step(&state, &BpfInsn::MovImm { dst: 1, imm: 10 }).unwrap();
    let next = step(&state, &BpfInsn::AddReg { dst: 1, src: 1 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 20, max: 20 });
}

#[test]
fn step_add_imm_range() {
    // range shift, a preview of #16: [0, 100] + 10 → [10, 110]
    let mut state = VerifierState::initial();
    state.regs[1] = RegState::Scalar { min: 0, max: 100 };
    let next = step(&state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 10, max: 110 });
}

#[test]
fn step_add_reg_ranges() {
    // [0, 100] + [5, 5] → [5, 105]
    let mut state = VerifierState::initial();
    state.regs[1] = RegState::Scalar { min: 0, max: 100 };
    state.regs[2] = RegState::Scalar { min: 5, max: 5 };
    let next = step(&state, &BpfInsn::AddReg { dst: 1, src: 2 }).unwrap();
    assert_eq!(next.regs[1], RegState::Scalar { min: 5, max: 105 });
}

#[test]
fn step_add_uninit_rejected() {
    // r0 += 1 with R0 uninitialized → #14 error
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::AddImm { dst: 0, imm: 1 }).unwrap_err();
    assert!(err.message.contains("uninitialized"));
    // r0 += r2 with R2 uninitialized → #14 error
    let err = step(&state, &BpfInsn::AddReg { dst: 0, src: 2 }).unwrap_err();
    assert!(err.message.contains("uninitialized"));
}

#[test]
fn step_add_ptr_rejected() {
    // r1 += 10 with R1 = PtrToCtx → pointer arithmetic error (#20)
    let state = VerifierState::initial();
    let err = step(&state, &BpfInsn::AddImm { dst: 1, imm: 10 }).unwrap_err();
    assert!(err.message.contains("#20"));
    assert!(err.message.contains("pointer arithmetic"));
    // r0 += r10 with R10 = PtrToStack → pointer arithmetic error (#20)
    let state = step(&state, &BpfInsn::MovImm { dst: 0, imm: 1 }).unwrap();
    let err = step(&state, &BpfInsn::AddReg { dst: 0, src: 10 }).unwrap_err();
    assert!(err.message.contains("#20"));
}

// ── Branch refinement (v0.2) ─────────────────────────────────────────────

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
fn add_subprog_no_calls() {
    let insns = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
    let subprogs = add_subprog(&insns).unwrap();
    assert_eq!(subprogs, vec![0]);
}

#[test]
fn add_subprog_collects_and_sorts() {
    // call targets 4 and 2 → sorted with the main entry 0
    let insns = vec![
        BpfInsn::Call { imm: 4 },
        BpfInsn::Call { imm: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    let subprogs = add_subprog(&insns).unwrap();
    assert_eq!(subprogs, vec![0, 2, 4]);
}

#[test]
fn add_subprog_dedup_target() {
    // two calls to the same target → registered once
    let insns = vec![
        BpfInsn::Call { imm: 2 },
        BpfInsn::Call { imm: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    let subprogs = add_subprog(&insns).unwrap();
    assert_eq!(subprogs, vec![0, 2]);
}

#[test]
fn add_subprog_out_of_range() {
    // call target beyond the program → error
    let insns = vec![BpfInsn::Call { imm: 99 }, BpfInsn::Exit];
    assert!(add_subprog(&insns).is_err());
}

// ── find_subprog_range ───────────────────────────────────────────────────

#[test]
fn find_subprog_range_first() {
    let subprogs = [0, 5, 10];
    assert_eq!(find_subprog_range(3, &subprogs, 12), (0, 5));
}

#[test]
fn find_subprog_range_middle() {
    let subprogs = [0, 5, 10];
    assert_eq!(find_subprog_range(7, &subprogs, 12), (5, 10));
}

#[test]
fn find_subprog_range_last() {
    let subprogs = [0, 5, 10];
    assert_eq!(find_subprog_range(11, &subprogs, 12), (10, 12));
}

#[test]
fn find_subprog_range_at_boundary() {
    let subprogs = [0, 5, 10];
    // an insn at a subprog entry belongs to the subprog that starts there
    assert_eq!(find_subprog_range(5, &subprogs, 12), (5, 10));
}

// ── visit_insn ───────────────────────────────────────────────────────────

#[test]
fn visit_insn_exit() {
    let insns = vec![BpfInsn::Exit];
    let nexts = visit_insn(0, &insns, &[0]).unwrap();
    assert!(nexts.is_empty());
}

#[test]
fn visit_insn_jmp() {
    // target = idx + 1 + offset = 0 + 1 + 2 = 3
    let insns = vec![
        BpfInsn::Jmp { offset: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    let nexts = visit_insn(0, &insns, &[0]).unwrap();
    assert_eq!(nexts, vec![3]);
}

#[test]
fn visit_insn_jmp_crosses_boundary() {
    // subprog [0, 2): target 0 + 1 + 2 = 3 is out of range
    let insns = vec![
        BpfInsn::Jmp { offset: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    assert!(visit_insn(0, &insns, &[0, 2]).is_err());
}

#[test]
fn visit_insn_cond_branch() {
    // Jeq: branch target 0 + 1 + 1 = 2, fall-through 1
    let insns = vec![
        BpfInsn::Jeq {
            dst: 1,
            src: 2,
            offset: 1,
        },
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    let nexts = visit_insn(0, &insns, &[0]).unwrap();
    assert_eq!(nexts, vec![2, 1]);
}

#[test]
fn visit_insn_call() {
    // Call imm is an absolute insn index: callee 2, return address 1
    let insns = vec![BpfInsn::Call { imm: 2 }, BpfInsn::Exit, BpfInsn::Exit];
    let nexts = visit_insn(0, &insns, &[0, 2]).unwrap();
    assert_eq!(nexts, vec![2, 1]);
}

#[test]
fn visit_insn_alu_fallthrough() {
    let insns = vec![BpfInsn::AddImm { dst: 0, imm: 1 }, BpfInsn::Exit];
    let nexts = visit_insn(0, &insns, &[0]).unwrap();
    assert_eq!(nexts, vec![1]);
}

#[test]
fn visit_insn_fallthrough_crosses_boundary() {
    // insn 1 is the last insn of subprog [0, 2): fall-through 2 crosses
    let insns = vec![
        BpfInsn::Call { imm: 2 },
        BpfInsn::MovImm { dst: 0, imm: 1 },
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    assert!(visit_insn(1, &insns, &[0, 2]).is_err());
}

#[test]
fn visit_insn_error_carries_insn_idx() {
    // subprog [0, 2): target 0 + 1 + 2 = 3 is out of range → err at insn 0
    let insns = vec![
        BpfInsn::Jmp { offset: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    let err = visit_insn(0, &insns, &[0, 2]).unwrap_err();
    assert_eq!(err.insn_idx, 0);
    assert!(err.message.contains("jump target 3"));
}

// ── check_cfg ────────────────────────────────────────────────────────────

#[test]
fn check_cfg_valid_simple() {
    let insns = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
    assert!(check_cfg(&insns, &[0]).is_ok());
}

#[test]
fn check_cfg_valid_with_subprog() {
    // main [0, 2): Call → subprog [2, 4), both end with Exit
    let insns = vec![
        BpfInsn::Call { imm: 2 },
        BpfInsn::Exit,
        BpfInsn::MovImm { dst: 0, imm: 1 },
        BpfInsn::Exit,
    ];
    assert!(check_cfg(&insns, &[0, 2]).is_ok());
}

#[test]
fn check_cfg_unreachable_insn() {
    // Jmp offset 1 skips insn 1 (target = 0 + 1 + 1 = 2)
    let insns = vec![
        BpfInsn::Jmp { offset: 1 },
        BpfInsn::MovImm { dst: 0, imm: 1 }, // unreachable
        BpfInsn::Exit,
    ];
    assert!(check_cfg(&insns, &[0]).is_err());
}

#[test]
fn check_cfg_fallthrough_violation() {
    // insn 1 falls through from subprog [0, 2) into subprog [2, 4)
    let insns = vec![
        BpfInsn::Call { imm: 2 },
        BpfInsn::MovImm { dst: 0, imm: 1 },
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    assert!(check_cfg(&insns, &[0, 2]).is_err());
}

#[test]
fn check_cfg_jmp_out_of_subprog() {
    // Jmp at 0 in subprog [0, 2): target 0 + 1 + 2 = 3 crosses the boundary
    let insns = vec![
        BpfInsn::Jmp { offset: 2 },
        BpfInsn::Exit,
        BpfInsn::Exit,
        BpfInsn::Exit,
    ];
    assert!(check_cfg(&insns, &[0, 2]).is_err());
}

#[test]
fn check_cfg_back_edge_rejected() {
    // Jeq R1==R1, offset -1 → jump to itself (target = 0 + 1 - 1 = 0):
    // this path never reaches EXIT → must be rejected with a loop error
    let insns = vec![
        BpfInsn::Jeq {
            dst: 1,
            src: 1,
            offset: -1,
        },
        BpfInsn::Exit,
    ];
    let err = check_cfg(&insns, &[0]).unwrap_err();
    assert_eq!(err.insn_idx, 0);
    assert!(err.message.contains("loop"));
}

#[test]
fn check_cfg_multi_insn_loop_rejected() {
    // 0: jmp +0 → 1    (target = 0 + 1 + 0 = 1)
    // 1: jmp -2 → 0    (target = 1 + 1 - 2 = 0) — 2-instruction loop
    let insns = vec![BpfInsn::Jmp { offset: 0 }, BpfInsn::Jmp { offset: -2 }];
    assert!(check_cfg(&insns, &[0]).is_err());
}

#[test]
fn check_cfg_valid_with_join() {
    // if/else join, no loop:
    // 0: jeq r1,r2,+1 → 2    (target = 0 + 1 + 1 = 2)
    // 1: jmp +1 → 3          (target = 1 + 1 + 1 = 3)
    // 2: r0 = 1 → falls to 3
    // 3: exit
    let insns = vec![
        BpfInsn::Jeq {
            dst: 1,
            src: 2,
            offset: 1,
        },
        BpfInsn::Jmp { offset: 1 },
        BpfInsn::MovImm { dst: 0, imm: 1 },
        BpfInsn::Exit,
    ];
    assert!(check_cfg(&insns, &[0]).is_ok());
}

#[test]
fn check_cfg_error_carries_insn_idx() {
    // Jmp offset 1 skips insn 1 (target = 0 + 1 + 1 = 2) → err at insn 1
    let insns = vec![
        BpfInsn::Jmp { offset: 1 },
        BpfInsn::MovImm { dst: 0, imm: 1 }, // unreachable
        BpfInsn::Exit,
    ];
    let err = check_cfg(&insns, &[0]).unwrap_err();
    assert_eq!(err.insn_idx, 1);
    assert!(err.message.contains("unreachable"));
}

// ── setup_prog (file I/O path) ───────────────────────────────────────────

/// Writes a temp file and loads it via BpfVerifierEnv::setup_prog.
#[test]
fn setup_prog_reads_program() {
    let insns = [
        insn_bytes(opcode::MOV_IMM, 0, 0, 0, 42),
        insn_bytes(opcode::EXIT, 0, 0, 0, 0),
    ];
    let path = std::env::temp_dir().join(format!(
        "rand_verifier_setup_prog_{}.bpf",
        std::process::id()
    ));
    std::fs::write(&path, prog_bytes(&insns)).unwrap();

    let mut env = BpfVerifierEnv::new();
    let insn_cnt = env.setup_prog(path.to_str().unwrap().to_string()).unwrap();

    assert_eq!(insn_cnt, 2);
    assert_eq!(env.prog.insn_cnt, 2);
    assert_eq!(env.prog.insns.len(), 2);
    assert!(matches!(
        env.prog.insns[0],
        BpfInsn::MovImm { dst: 0, imm: 42 }
    ));
    assert!(matches!(env.prog.insns[1], BpfInsn::Exit));

    std::fs::remove_file(&path).ok();
}

// ── nano test corpus (file fixtures) ─────────────────────────────────────

/// Load a corpus program file and run the full verification pipeline.
fn verify_corpus_program(path: &std::path::Path) -> Verdict {
    let mut env = BpfVerifierEnv::new();
    env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
    env.verify().unwrap()
}

/// Every program under tests/programs/nano/accept/ must pass verification.
#[test]
fn corpus_accept_all() {
    let dir = std::path::Path::new("tests/programs/nano/accept");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        // skip docs and directories; corpus files have no extension
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        let verdict = verify_corpus_program(&path);
        assert!(
            matches!(verdict, Verdict::Safe),
            "accept program {:?} was rejected",
            path
        );
        count += 1;
    }
    assert!(count > 0, "no accept programs found in {:?}", dir);
}

/// Every program under tests/programs/nano/reject/ must fail verification.
#[test]
fn corpus_reject_all() {
    let dir = std::path::Path::new("tests/programs/nano/reject");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        // skip docs and directories; corpus files have no extension
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        match verify_corpus_program(&path) {
            Verdict::Safe => panic!("reject program {:?} was accepted", path),
            Verdict::Unsafe(failure) => {
                println!("rejected as expected: {:?} → {}", path, failure);
                count += 1;
            }
        }
    }
    assert!(count > 0, "no reject programs found in {:?}", dir);
}
