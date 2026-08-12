// ── BPF instruction representation ──────────────────────────────────────────

/// Opcodes of the mini subset (a simplified custom encoding, not the
/// real eBPF opcode space).
///
/// The Meso extension (#39) adds the ALU family (SUB/AND/OR/XOR/shifts),
/// the ALU32 forms (base op | [`ALU32_FLAG`], cf. the kernel's BPF_ALU vs
/// BPF_ALU64 class split) and the signed/unsigned compare variants.
pub(crate) mod opcode {
    pub const MOV_IMM: u8 = 0x01;
    pub const MOV_REG: u8 = 0x02;
    pub const ADD_IMM: u8 = 0x03;
    pub const ADD_REG: u8 = 0x04;
    pub const LD_STACK: u8 = 0x05;
    pub const ST_STACK: u8 = 0x06;
    pub const JEQ: u8 = 0x07;
    pub const JGT: u8 = 0x08; // unsigned greater-than (kernel BPF_JGT)
    pub const JMP: u8 = 0x09;
    pub const CALL: u8 = 0x0A;
    pub const EXIT: u8 = 0x0B;

    // ALU64: SUB/AND/OR/XOR/shifts (imm and reg forms)
    pub const SUB_IMM: u8 = 0x0C;
    pub const SUB_REG: u8 = 0x0D;
    pub const AND_IMM: u8 = 0x0E;
    pub const AND_REG: u8 = 0x0F;
    pub const OR_IMM: u8 = 0x10;
    pub const OR_REG: u8 = 0x11;
    pub const XOR_IMM: u8 = 0x12;
    pub const XOR_REG: u8 = 0x13;
    pub const LSH_IMM: u8 = 0x14;
    pub const LSH_REG: u8 = 0x15;
    pub const RSH_IMM: u8 = 0x16;
    pub const RSH_REG: u8 = 0x17;
    pub const ARSH_IMM: u8 = 0x18;
    pub const ARSH_REG: u8 = 0x19;

    // compares: unsigned family (JGT exists above) and signed family
    pub const JNE: u8 = 0x1A;
    pub const JGE: u8 = 0x1B;
    pub const JLT: u8 = 0x1C;
    pub const JLE: u8 = 0x1D;
    pub const JSGT: u8 = 0x1E;
    pub const JSGE: u8 = 0x1F;
    pub const JSLT: u8 = 0x20;
    pub const JSLE: u8 = 0x21;

    /// Flag bit that turns an ALU64 opcode into its ALU32 form, like the
    /// kernel's BPF_ALU class vs BPF_ALU64 class split. ALU32 results are
    /// truncated to 32 bits and zero-extended into the 64-bit register.
    pub const ALU32_FLAG: u8 = 0x40;

    // ALU32 forms of every ALU op (ADD included): base op | ALU32_FLAG
    pub const ADD32_IMM: u8 = ADD_IMM | ALU32_FLAG;
    pub const ADD32_REG: u8 = ADD_REG | ALU32_FLAG;
    pub const SUB32_IMM: u8 = SUB_IMM | ALU32_FLAG;
    pub const SUB32_REG: u8 = SUB_REG | ALU32_FLAG;
    pub const AND32_IMM: u8 = AND_IMM | ALU32_FLAG;
    pub const AND32_REG: u8 = AND_REG | ALU32_FLAG;
    pub const OR32_IMM: u8 = OR_IMM | ALU32_FLAG;
    pub const OR32_REG: u8 = OR_REG | ALU32_FLAG;
    pub const XOR32_IMM: u8 = XOR_IMM | ALU32_FLAG;
    pub const XOR32_REG: u8 = XOR_REG | ALU32_FLAG;
    pub const LSH32_IMM: u8 = LSH_IMM | ALU32_FLAG;
    pub const LSH32_REG: u8 = LSH_REG | ALU32_FLAG;
    pub const RSH32_IMM: u8 = RSH_IMM | ALU32_FLAG;
    pub const RSH32_REG: u8 = RSH_REG | ALU32_FLAG;
    pub const ARSH32_IMM: u8 = ARSH_IMM | ALU32_FLAG;
    pub const ARSH32_REG: u8 = ARSH_REG | ALU32_FLAG;
}

#[derive(Debug, Clone)]
// register fields (dst/src/imm/offset) are consumed by state tracking (v0.2)
pub(crate) enum BpfInsn {
    MovImm { dst: u8, imm: i32 },
    MovReg { dst: u8, src: u8 },
    // ALU64
    AddImm { dst: u8, imm: i32 },
    AddReg { dst: u8, src: u8 },
    SubImm { dst: u8, imm: i32 },
    SubReg { dst: u8, src: u8 },
    AndImm { dst: u8, imm: i32 },
    AndReg { dst: u8, src: u8 },
    OrImm { dst: u8, imm: i32 },
    OrReg { dst: u8, src: u8 },
    XorImm { dst: u8, imm: i32 },
    XorReg { dst: u8, src: u8 },
    LshImm { dst: u8, imm: i32 },
    LshReg { dst: u8, src: u8 },
    RshImm { dst: u8, imm: i32 },
    RshReg { dst: u8, src: u8 },
    ArshImm { dst: u8, imm: i32 },
    ArshReg { dst: u8, src: u8 },
    // ALU32 (#39): truncating, zero-extended forms of every ALU op
    Add32Imm { dst: u8, imm: i32 },
    Add32Reg { dst: u8, src: u8 },
    Sub32Imm { dst: u8, imm: i32 },
    Sub32Reg { dst: u8, src: u8 },
    And32Imm { dst: u8, imm: i32 },
    And32Reg { dst: u8, src: u8 },
    Or32Imm { dst: u8, imm: i32 },
    Or32Reg { dst: u8, src: u8 },
    Xor32Imm { dst: u8, imm: i32 },
    Xor32Reg { dst: u8, src: u8 },
    Lsh32Imm { dst: u8, imm: i32 },
    Lsh32Reg { dst: u8, src: u8 },
    Rsh32Imm { dst: u8, imm: i32 },
    Rsh32Reg { dst: u8, src: u8 },
    Arsh32Imm { dst: u8, imm: i32 },
    Arsh32Reg { dst: u8, src: u8 },
    LdStack { dst: u8, offset: i16 },
    StStack { src: u8, offset: i16 },
    // compares: equality, unsigned family, signed family (#39)
    Jeq { dst: u8, src: u8, offset: i16 },
    Jne { dst: u8, src: u8, offset: i16 },
    Jgt { dst: u8, src: u8, offset: i16 },
    Jge { dst: u8, src: u8, offset: i16 },
    Jlt { dst: u8, src: u8, offset: i16 },
    Jle { dst: u8, src: u8, offset: i16 },
    Jsgt { dst: u8, src: u8, offset: i16 },
    Jsge { dst: u8, src: u8, offset: i16 },
    Jslt { dst: u8, src: u8, offset: i16 },
    Jsle { dst: u8, src: u8, offset: i16 },
    Jmp { offset: i16 },
    Call { imm: i32 },
    Exit,
}

impl BpfInsn {
    /// Whether this instruction forks into a taken branch and a
    /// fall-through successor (all compare opcodes).
    pub(crate) fn is_conditional_branch(&self) -> bool {
        matches!(
            self,
            BpfInsn::Jeq { .. }
                | BpfInsn::Jne { .. }
                | BpfInsn::Jgt { .. }
                | BpfInsn::Jge { .. }
                | BpfInsn::Jlt { .. }
                | BpfInsn::Jle { .. }
                | BpfInsn::Jsgt { .. }
                | BpfInsn::Jsge { .. }
                | BpfInsn::Jslt { .. }
                | BpfInsn::Jsle { .. }
        )
    }

    /// Whether this instruction is expanded by `successors()` instead of
    /// `step()`: terminal (exit), unconditional jumps and comparisons.
    pub(crate) fn is_control_flow(&self) -> bool {
        matches!(self, BpfInsn::Exit | BpfInsn::Jmp { .. }) || self.is_conditional_branch()
    }
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
        opcode::SUB_IMM => BpfInsn::SubImm { dst, imm },
        opcode::SUB_REG => BpfInsn::SubReg { dst, src },
        opcode::AND_IMM => BpfInsn::AndImm { dst, imm },
        opcode::AND_REG => BpfInsn::AndReg { dst, src },
        opcode::OR_IMM => BpfInsn::OrImm { dst, imm },
        opcode::OR_REG => BpfInsn::OrReg { dst, src },
        opcode::XOR_IMM => BpfInsn::XorImm { dst, imm },
        opcode::XOR_REG => BpfInsn::XorReg { dst, src },
        opcode::LSH_IMM => BpfInsn::LshImm { dst, imm },
        opcode::LSH_REG => BpfInsn::LshReg { dst, src },
        opcode::RSH_IMM => BpfInsn::RshImm { dst, imm },
        opcode::RSH_REG => BpfInsn::RshReg { dst, src },
        opcode::ARSH_IMM => BpfInsn::ArshImm { dst, imm },
        opcode::ARSH_REG => BpfInsn::ArshReg { dst, src },
        opcode::ADD32_IMM => BpfInsn::Add32Imm { dst, imm },
        opcode::ADD32_REG => BpfInsn::Add32Reg { dst, src },
        opcode::SUB32_IMM => BpfInsn::Sub32Imm { dst, imm },
        opcode::SUB32_REG => BpfInsn::Sub32Reg { dst, src },
        opcode::AND32_IMM => BpfInsn::And32Imm { dst, imm },
        opcode::AND32_REG => BpfInsn::And32Reg { dst, src },
        opcode::OR32_IMM => BpfInsn::Or32Imm { dst, imm },
        opcode::OR32_REG => BpfInsn::Or32Reg { dst, src },
        opcode::XOR32_IMM => BpfInsn::Xor32Imm { dst, imm },
        opcode::XOR32_REG => BpfInsn::Xor32Reg { dst, src },
        opcode::LSH32_IMM => BpfInsn::Lsh32Imm { dst, imm },
        opcode::LSH32_REG => BpfInsn::Lsh32Reg { dst, src },
        opcode::RSH32_IMM => BpfInsn::Rsh32Imm { dst, imm },
        opcode::RSH32_REG => BpfInsn::Rsh32Reg { dst, src },
        opcode::ARSH32_IMM => BpfInsn::Arsh32Imm { dst, imm },
        opcode::ARSH32_REG => BpfInsn::Arsh32Reg { dst, src },
        opcode::LD_STACK => BpfInsn::LdStack { dst, offset },
        opcode::ST_STACK => BpfInsn::StStack { src, offset },
        opcode::JEQ => BpfInsn::Jeq { dst, src, offset },
        opcode::JNE => BpfInsn::Jne { dst, src, offset },
        opcode::JGT => BpfInsn::Jgt { dst, src, offset },
        opcode::JGE => BpfInsn::Jge { dst, src, offset },
        opcode::JLT => BpfInsn::Jlt { dst, src, offset },
        opcode::JLE => BpfInsn::Jle { dst, src, offset },
        opcode::JSGT => BpfInsn::Jsgt { dst, src, offset },
        opcode::JSGE => BpfInsn::Jsge { dst, src, offset },
        opcode::JSLT => BpfInsn::Jslt { dst, src, offset },
        opcode::JSLE => BpfInsn::Jsle { dst, src, offset },
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
        BpfInsn::SubImm { dst, imm } => format!("r{} -= {}", dst, imm),
        BpfInsn::SubReg { dst, src } => format!("r{} -= r{}", dst, src),
        BpfInsn::AndImm { dst, imm } => format!("r{} &= {}", dst, imm),
        BpfInsn::AndReg { dst, src } => format!("r{} &= r{}", dst, src),
        BpfInsn::OrImm { dst, imm } => format!("r{} |= {}", dst, imm),
        BpfInsn::OrReg { dst, src } => format!("r{} |= r{}", dst, src),
        BpfInsn::XorImm { dst, imm } => format!("r{} ^= {}", dst, imm),
        BpfInsn::XorReg { dst, src } => format!("r{} ^= r{}", dst, src),
        BpfInsn::LshImm { dst, imm } => format!("r{} <<= {}", dst, imm),
        BpfInsn::LshReg { dst, src } => format!("r{} <<= r{}", dst, src),
        BpfInsn::RshImm { dst, imm } => format!("r{} >>= {}", dst, imm),
        BpfInsn::RshReg { dst, src } => format!("r{} >>= r{}", dst, src),
        BpfInsn::ArshImm { dst, imm } => format!("r{} s>>= {}", dst, imm),
        BpfInsn::ArshReg { dst, src } => format!("r{} s>>= r{}", dst, src),
        // ALU32 forms use the kernel's w-register notation: the operation
        // is 32-bit and the result is zero-extended into the r-register
        BpfInsn::Add32Imm { dst, imm } => format!("w{} += {}", dst, imm),
        BpfInsn::Add32Reg { dst, src } => format!("w{} += r{}", dst, src),
        BpfInsn::Sub32Imm { dst, imm } => format!("w{} -= {}", dst, imm),
        BpfInsn::Sub32Reg { dst, src } => format!("w{} -= r{}", dst, src),
        BpfInsn::And32Imm { dst, imm } => format!("w{} &= {}", dst, imm),
        BpfInsn::And32Reg { dst, src } => format!("w{} &= r{}", dst, src),
        BpfInsn::Or32Imm { dst, imm } => format!("w{} |= {}", dst, imm),
        BpfInsn::Or32Reg { dst, src } => format!("w{} |= r{}", dst, src),
        BpfInsn::Xor32Imm { dst, imm } => format!("w{} ^= {}", dst, imm),
        BpfInsn::Xor32Reg { dst, src } => format!("w{} ^= r{}", dst, src),
        BpfInsn::Lsh32Imm { dst, imm } => format!("w{} <<= {}", dst, imm),
        BpfInsn::Lsh32Reg { dst, src } => format!("w{} <<= r{}", dst, src),
        BpfInsn::Rsh32Imm { dst, imm } => format!("w{} >>= {}", dst, imm),
        BpfInsn::Rsh32Reg { dst, src } => format!("w{} >>= r{}", dst, src),
        BpfInsn::Arsh32Imm { dst, imm } => format!("w{} s>>= {}", dst, imm),
        BpfInsn::Arsh32Reg { dst, src } => format!("w{} s>>= r{}", dst, src),
        BpfInsn::LdStack { dst, offset } => format!("r{} = [r10{:+}]", dst, offset),
        BpfInsn::StStack { src, offset } => format!("[r10{:+}] = r{}", offset, src),
        BpfInsn::Jeq { dst, src, offset } => {
            format!("if r{} == r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jne { dst, src, offset } => {
            format!("if r{} != r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            format!("if r{} > r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jge { dst, src, offset } => {
            format!("if r{} >= r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jlt { dst, src, offset } => {
            format!("if r{} < r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jle { dst, src, offset } => {
            format!("if r{} <= r{} goto {:+}", dst, src, offset)
        }
        // signed compares use the kernel's s-prefix notation
        BpfInsn::Jsgt { dst, src, offset } => {
            format!("if r{} s> r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jsge { dst, src, offset } => {
            format!("if r{} s>= r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jslt { dst, src, offset } => {
            format!("if r{} s< r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jsle { dst, src, offset } => {
            format!("if r{} s<= r{} goto {:+}", dst, src, offset)
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

    // ── ALU extension (Meso #39) ─────────────────────────────────────────────

    #[test]
    fn parse_insn_sub_imm() {
        let insn = parse(opcode::SUB_IMM, 1, 0, 0, -7);
        assert!(matches!(insn, BpfInsn::SubImm { dst: 1, imm: -7 }));
    }

    #[test]
    fn parse_insn_sub_reg() {
        let insn = parse(opcode::SUB_REG, 0, 6, 0, 0);
        assert!(matches!(insn, BpfInsn::SubReg { dst: 0, src: 6 }));
    }

    #[test]
    fn parse_insn_and_or_xor() {
        assert!(matches!(
            parse(opcode::AND_IMM, 1, 0, 0, 8),
            BpfInsn::AndImm { dst: 1, imm: 8 }
        ));
        assert!(matches!(
            parse(opcode::AND_REG, 1, 2, 0, 0),
            BpfInsn::AndReg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::OR_IMM, 1, 0, 0, 8),
            BpfInsn::OrImm { dst: 1, imm: 8 }
        ));
        assert!(matches!(
            parse(opcode::OR_REG, 1, 2, 0, 0),
            BpfInsn::OrReg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::XOR_IMM, 1, 0, 0, 8),
            BpfInsn::XorImm { dst: 1, imm: 8 }
        ));
        assert!(matches!(
            parse(opcode::XOR_REG, 1, 2, 0, 0),
            BpfInsn::XorReg { dst: 1, src: 2 }
        ));
    }

    #[test]
    fn parse_insn_shifts() {
        assert!(matches!(
            parse(opcode::LSH_IMM, 1, 0, 0, 4),
            BpfInsn::LshImm { dst: 1, imm: 4 }
        ));
        assert!(matches!(
            parse(opcode::LSH_REG, 1, 2, 0, 0),
            BpfInsn::LshReg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::RSH_IMM, 1, 0, 0, 4),
            BpfInsn::RshImm { dst: 1, imm: 4 }
        ));
        assert!(matches!(
            parse(opcode::RSH_REG, 1, 2, 0, 0),
            BpfInsn::RshReg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::ARSH_IMM, 1, 0, 0, 4),
            BpfInsn::ArshImm { dst: 1, imm: 4 }
        ));
        assert!(matches!(
            parse(opcode::ARSH_REG, 1, 2, 0, 0),
            BpfInsn::ArshReg { dst: 1, src: 2 }
        ));
    }

    #[test]
    fn parse_insn_alu32_forms() {
        // ALU32 opcodes are the ALU64 base op with the ALU32 flag bit
        assert!(matches!(
            parse(opcode::ADD32_IMM, 1, 0, 0, 5),
            BpfInsn::Add32Imm { dst: 1, imm: 5 }
        ));
        assert!(matches!(
            parse(opcode::ADD32_REG, 1, 2, 0, 0),
            BpfInsn::Add32Reg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::SUB32_IMM, 1, 0, 0, 5),
            BpfInsn::Sub32Imm { dst: 1, imm: 5 }
        ));
        assert!(matches!(
            parse(opcode::AND32_REG, 1, 2, 0, 0),
            BpfInsn::And32Reg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::OR32_IMM, 1, 0, 0, 5),
            BpfInsn::Or32Imm { dst: 1, imm: 5 }
        ));
        assert!(matches!(
            parse(opcode::XOR32_REG, 1, 2, 0, 0),
            BpfInsn::Xor32Reg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::LSH32_IMM, 1, 0, 0, 4),
            BpfInsn::Lsh32Imm { dst: 1, imm: 4 }
        ));
        assert!(matches!(
            parse(opcode::RSH32_REG, 1, 2, 0, 0),
            BpfInsn::Rsh32Reg { dst: 1, src: 2 }
        ));
        assert!(matches!(
            parse(opcode::ARSH32_IMM, 1, 0, 0, 4),
            BpfInsn::Arsh32Imm { dst: 1, imm: 4 }
        ));
    }

    #[test]
    fn parse_insn_compare_variants() {
        assert!(matches!(
            parse(opcode::JNE, 1, 2, 1, 0),
            BpfInsn::Jne {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JGE, 1, 2, 1, 0),
            BpfInsn::Jge {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JLT, 1, 2, 1, 0),
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JLE, 1, 2, 1, 0),
            BpfInsn::Jle {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JSGT, 1, 2, 1, 0),
            BpfInsn::Jsgt {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JSGE, 1, 2, 1, 0),
            BpfInsn::Jsge {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JSLT, 1, 2, 1, 0),
            BpfInsn::Jslt {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
        assert!(matches!(
            parse(opcode::JSLE, 1, 2, 1, 0),
            BpfInsn::Jsle {
                dst: 1,
                src: 2,
                offset: 1
            }
        ));
    }

    #[test]
    fn parse_insn_unknown_opcode_panics() {
        // an unused opcode value is still rejected by the decoder
        let result = std::panic::catch_unwind(|| parse(0x7F, 0, 0, 0, 0));
        assert!(result.is_err());
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

    // ── ALU extension (Meso #39) ─────────────────────────────────────────────

    #[test]
    fn disassemble_alu_extension() {
        assert_eq!(disassemble(&BpfInsn::SubImm { dst: 2, imm: 3 }), "r2 -= 3");
        assert_eq!(disassemble(&BpfInsn::SubReg { dst: 1, src: 2 }), "r1 -= r2");
        assert_eq!(disassemble(&BpfInsn::AndImm { dst: 2, imm: 3 }), "r2 &= 3");
        assert_eq!(disassemble(&BpfInsn::AndReg { dst: 1, src: 2 }), "r1 &= r2");
        assert_eq!(disassemble(&BpfInsn::OrImm { dst: 2, imm: 3 }), "r2 |= 3");
        assert_eq!(disassemble(&BpfInsn::OrReg { dst: 1, src: 2 }), "r1 |= r2");
        assert_eq!(disassemble(&BpfInsn::XorImm { dst: 2, imm: 3 }), "r2 ^= 3");
        assert_eq!(disassemble(&BpfInsn::XorReg { dst: 1, src: 2 }), "r1 ^= r2");
        assert_eq!(disassemble(&BpfInsn::LshImm { dst: 2, imm: 4 }), "r2 <<= 4");
        assert_eq!(
            disassemble(&BpfInsn::LshReg { dst: 1, src: 2 }),
            "r1 <<= r2"
        );
        assert_eq!(disassemble(&BpfInsn::RshImm { dst: 2, imm: 4 }), "r2 >>= 4");
        assert_eq!(
            disassemble(&BpfInsn::RshReg { dst: 1, src: 2 }),
            "r1 >>= r2"
        );
        assert_eq!(
            disassemble(&BpfInsn::ArshImm { dst: 2, imm: 4 }),
            "r2 s>>= 4"
        );
        assert_eq!(
            disassemble(&BpfInsn::ArshReg { dst: 1, src: 2 }),
            "r1 s>>= r2"
        );
    }

    #[test]
    fn disassemble_alu32_forms() {
        // ALU32 uses the kernel's w-register notation
        assert_eq!(
            disassemble(&BpfInsn::Add32Imm { dst: 2, imm: 5 }),
            "w2 += 5"
        );
        assert_eq!(
            disassemble(&BpfInsn::Add32Reg { dst: 1, src: 2 }),
            "w1 += r2"
        );
        assert_eq!(
            disassemble(&BpfInsn::Sub32Imm { dst: 2, imm: 5 }),
            "w2 -= 5"
        );
        assert_eq!(
            disassemble(&BpfInsn::And32Imm { dst: 2, imm: 3 }),
            "w2 &= 3"
        );
        assert_eq!(
            disassemble(&BpfInsn::Or32Reg { dst: 1, src: 2 }),
            "w1 |= r2"
        );
        assert_eq!(
            disassemble(&BpfInsn::Xor32Imm { dst: 2, imm: 3 }),
            "w2 ^= 3"
        );
        assert_eq!(
            disassemble(&BpfInsn::Lsh32Imm { dst: 2, imm: 4 }),
            "w2 <<= 4"
        );
        assert_eq!(
            disassemble(&BpfInsn::Rsh32Imm { dst: 2, imm: 4 }),
            "w2 >>= 4"
        );
        assert_eq!(
            disassemble(&BpfInsn::Arsh32Imm { dst: 2, imm: 4 }),
            "w2 s>>= 4"
        );
    }

    #[test]
    fn disassemble_compare_variants() {
        assert_eq!(
            disassemble(&BpfInsn::Jne {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 != r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jge {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 >= r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 < r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jle {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 <= r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jsgt {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 s> r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jsge {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 s>= r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jslt {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 s< r2 goto +1"
        );
        assert_eq!(
            disassemble(&BpfInsn::Jsle {
                dst: 1,
                src: 2,
                offset: 1
            }),
            "if r1 s<= r2 goto +1"
        );
    }
}
