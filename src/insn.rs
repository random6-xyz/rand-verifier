// ── BPF instruction representation ──────────────────────────────────────────

/// Opcodes of the mini subset (a simplified custom encoding, not the
/// real eBPF opcode space).
pub(crate) mod opcode {
    pub const MOV_IMM: u8 = 0x01;
    pub const MOV_REG: u8 = 0x02;
    pub const ADD_IMM: u8 = 0x03;
    pub const ADD_REG: u8 = 0x04;
    pub const LD_STACK: u8 = 0x05;
    pub const ST_STACK: u8 = 0x06;
    pub const JEQ: u8 = 0x07;
    pub const JGT: u8 = 0x08;
    pub const JMP: u8 = 0x09;
    pub const CALL: u8 = 0x0A;
    pub const EXIT: u8 = 0x0B;
}

#[derive(Debug, Clone)]
// register fields (dst/src/imm/offset) are consumed by state tracking (v0.2)
pub(crate) enum BpfInsn {
    MovImm { dst: u8, imm: i32 },
    MovReg { dst: u8, src: u8 },
    AddImm { dst: u8, imm: i32 },
    AddReg { dst: u8, src: u8 },
    LdStack { dst: u8, offset: i16 },
    StStack { src: u8, offset: i16 },
    Jeq { dst: u8, src: u8, offset: i16 },
    Jgt { dst: u8, src: u8, offset: i16 },
    Jmp { offset: i16 },
    Call { imm: i32 },
    Exit,
}

/// Decode one 8-byte instruction from raw bytecode.
pub(crate) fn parse_insn(bytes: &[u8]) -> BpfInsn {
    let op = bytes[0];
    let regs = bytes[1];
    let dst = regs & 0x0F;
    let src = (regs >> 4) & 0x0F;
    let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
    let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    match op {
        opcode::MOV_IMM => BpfInsn::MovImm { dst, imm },
        opcode::MOV_REG => BpfInsn::MovReg { dst, src },
        opcode::ADD_IMM => BpfInsn::AddImm { dst, imm },
        opcode::ADD_REG => BpfInsn::AddReg { dst, src },
        opcode::LD_STACK => BpfInsn::LdStack { dst, offset },
        opcode::ST_STACK => BpfInsn::StStack { src, offset },
        opcode::JEQ => BpfInsn::Jeq { dst, src, offset },
        opcode::JGT => BpfInsn::Jgt { dst, src, offset },
        opcode::JMP => BpfInsn::Jmp { offset },
        opcode::CALL => BpfInsn::Call { imm },
        opcode::EXIT => BpfInsn::Exit,
        _ => panic!("Unknown opcode: {:#04x}", op),
    }
}

/// Render a single instruction in a readable eBPF-like syntax.
pub(crate) fn disassemble(insn: &BpfInsn) -> String {
    match insn {
        BpfInsn::MovImm { dst, imm } => format!("r{} = {}", dst, imm),
        BpfInsn::MovReg { dst, src } => format!("r{} = r{}", dst, src),
        BpfInsn::AddImm { dst, imm } => format!("r{} += {}", dst, imm),
        BpfInsn::AddReg { dst, src } => format!("r{} += r{}", dst, src),
        BpfInsn::LdStack { dst, offset } => format!("r{} = [r10{:+}]", dst, offset),
        BpfInsn::StStack { src, offset } => format!("[r10{:+}] = r{}", offset, src),
        BpfInsn::Jeq { dst, src, offset } => {
            format!("if r{} == r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            format!("if r{} > r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jmp { offset } => format!("goto {:+}", offset),
        BpfInsn::Call { imm } => format!("call {}", imm),
        BpfInsn::Exit => "exit".to_string(),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

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
    fn disassemble_instructions() {
        assert_eq!(disassemble(&BpfInsn::MovImm { dst: 2, imm: 10 }), "r2 = 10");
        assert_eq!(disassemble(&BpfInsn::MovReg { dst: 0, src: 2 }), "r0 = r2");
        assert_eq!(disassemble(&BpfInsn::AddImm { dst: 2, imm: 5 }), "r2 += 5");
        assert_eq!(disassemble(&BpfInsn::AddReg { dst: 1, src: 2 }), "r1 += r2");
        assert_eq!(
            disassemble(&BpfInsn::LdStack { dst: 0, offset: -8 }),
            "r0 = [r10-8]"
        );
        assert_eq!(
            disassemble(&BpfInsn::StStack {
                src: 2,
                offset: -16
            }),
            "[r10-16] = r2"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 == r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: -2
            }),
            "if r1 > r2 goto -2"
        );
        assert_eq!(disassemble(&BpfInsn::Jmp { offset: 3 }), "goto +3");
        assert_eq!(disassemble(&BpfInsn::Call { imm: 2 }), "call 2");
        assert_eq!(disassemble(&BpfInsn::Exit), "exit");
    }
}
