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
