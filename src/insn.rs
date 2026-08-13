// ── BPF instruction representation ──────────────────────────────────────────

/// Opcodes of the supported eBPF subset, using the kernel's UAPI encoding
/// (include/uapi/linux/bpf.h): `code = class | op | src` with the same
/// field layout as `struct bpf_insn`. This is the encoding clang and the
/// kernel selftests emit, so programs can be fed to the verifier as-is
/// (issue #56).
///
/// ALU32 is the separate BPF_ALU class (0x04) vs BPF_ALU64 (0x07), like
/// the kernel; ALU32 results are truncated to 32 bits and zero-extended
/// into the 64-bit register.
pub(crate) mod opcode {
    // ALU64 (class 0x07) — BPF_K (0x00) / BPF_X (0x08) source forms
    pub const MOV_IMM: u8 = 0xb7; // BPF_ALU64 | BPF_MOV | BPF_K
    pub const MOV_REG: u8 = 0xbf; // BPF_ALU64 | BPF_MOV | BPF_X
    pub const ADD_IMM: u8 = 0x07; // BPF_ALU64 | BPF_ADD | BPF_K
    pub const ADD_REG: u8 = 0x0f; // BPF_ALU64 | BPF_ADD | BPF_X
    pub const SUB_IMM: u8 = 0x17;
    pub const SUB_REG: u8 = 0x1f;
    pub const AND_IMM: u8 = 0x57;
    pub const AND_REG: u8 = 0x5f;
    pub const OR_IMM: u8 = 0x47;
    pub const OR_REG: u8 = 0x4f;
    pub const XOR_IMM: u8 = 0xa7;
    pub const XOR_REG: u8 = 0xaf;
    pub const LSH_IMM: u8 = 0x67;
    pub const LSH_REG: u8 = 0x6f;
    pub const RSH_IMM: u8 = 0x77;
    pub const RSH_REG: u8 = 0x7f;
    pub const ARSH_IMM: u8 = 0xc7;
    pub const ARSH_REG: u8 = 0xcf;

    // ALU32 (class 0x04)
    pub const ADD32_IMM: u8 = 0x04;
    pub const ADD32_REG: u8 = 0x0c;
    pub const SUB32_IMM: u8 = 0x14;
    pub const SUB32_REG: u8 = 0x1c;
    pub const AND32_IMM: u8 = 0x54;
    pub const AND32_REG: u8 = 0x5c;
    pub const OR32_IMM: u8 = 0x44;
    pub const OR32_REG: u8 = 0x4c;
    pub const XOR32_IMM: u8 = 0xa4;
    pub const XOR32_REG: u8 = 0xac;
    pub const LSH32_IMM: u8 = 0x64;
    pub const LSH32_REG: u8 = 0x6c;
    pub const RSH32_IMM: u8 = 0x74;
    pub const RSH32_REG: u8 = 0x7c;
    pub const ARSH32_IMM: u8 = 0xc4;
    pub const ARSH32_REG: u8 = 0xcc;

    // loads/stores — only 8-byte (DW) accesses with the frame pointer
    // as the base register are supported
    pub const LD_STACK: u8 = 0x79; // BPF_LDX | BPF_MEM | BPF_DW, src_reg = R10
    pub const ST_STACK: u8 = 0x7b; // BPF_STX | BPF_MEM | BPF_DW, dst_reg = R10

    // jumps (class 0x05): every compare exists in the register-register
    // (BPF_X) and the immediate (BPF_K) form (#57)
    pub const JMP: u8 = 0x05; // BPF_JA
    pub const JEQ: u8 = 0x1d; // BPF_JMP | BPF_JEQ | BPF_X
    pub const JEQ_IMM: u8 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    pub const JNE: u8 = 0x5d; // BPF_JMP | BPF_JNE | BPF_X
    pub const JNE_IMM: u8 = 0x55; // BPF_JMP | BPF_JNE | BPF_K
    pub const JGT: u8 = 0x2d; // BPF_JMP | BPF_JGT | BPF_X (unsigned)
    pub const JGT_IMM: u8 = 0x25; // BPF_JMP | BPF_JGT | BPF_K (unsigned)
    pub const JGE: u8 = 0x3d; // BPF_JMP | BPF_JGE | BPF_X (unsigned)
    pub const JGE_IMM: u8 = 0x35; // BPF_JMP | BPF_JGE | BPF_K (unsigned)
    pub const JLT: u8 = 0xad; // BPF_JMP | BPF_JLT | BPF_X (unsigned)
    pub const JLT_IMM: u8 = 0xa5; // BPF_JMP | BPF_JLT | BPF_K (unsigned)
    pub const JLE: u8 = 0xbd; // BPF_JMP | BPF_JLE | BPF_X (unsigned)
    pub const JLE_IMM: u8 = 0xb5; // BPF_JMP | BPF_JLE | BPF_K (unsigned)
    pub const JSGT: u8 = 0x6d; // BPF_JMP | BPF_JSGT | BPF_X (signed)
    pub const JSGT_IMM: u8 = 0x65; // BPF_JMP | BPF_JSGT | BPF_K (signed)
    pub const JSGE: u8 = 0x7d; // BPF_JMP | BPF_JSGE | BPF_X (signed)
    pub const JSGE_IMM: u8 = 0x75; // BPF_JMP | BPF_JSGE | BPF_K (signed)
    pub const JSLT: u8 = 0xcd; // BPF_JMP | BPF_JSLT | BPF_X (signed)
    pub const JSLT_IMM: u8 = 0xc5; // BPF_JMP | BPF_JSLT | BPF_K (signed)
    pub const JSLE: u8 = 0xdd; // BPF_JMP | BPF_JSLE | BPF_X (signed)
    pub const JSLE_IMM: u8 = 0xd5; // BPF_JMP | BPF_JSLE | BPF_K (signed)
    pub const CALL: u8 = 0x85; // BPF_JMP | BPF_CALL — imm is the helper id
    pub const EXIT: u8 = 0x95; // BPF_JMP | BPF_EXIT
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
    // immediate forms of every compare (BPF_J*_K, #57)
    JeqImm { dst: u8, imm: i32, offset: i16 },
    JneImm { dst: u8, imm: i32, offset: i16 },
    JgtImm { dst: u8, imm: i32, offset: i16 },
    JgeImm { dst: u8, imm: i32, offset: i16 },
    JltImm { dst: u8, imm: i32, offset: i16 },
    JleImm { dst: u8, imm: i32, offset: i16 },
    JsgtImm { dst: u8, imm: i32, offset: i16 },
    JsgeImm { dst: u8, imm: i32, offset: i16 },
    JsltImm { dst: u8, imm: i32, offset: i16 },
    JsleImm { dst: u8, imm: i32, offset: i16 },
    Jmp { offset: i16 },
    Call { imm: i32 },
    Exit,
}

impl BpfInsn {
    /// Whether this instruction forks into a taken branch and a
    /// fall-through successor (all compare opcodes, register and
    /// immediate forms).
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
        )
    }

    /// Whether this instruction is expanded by `successors()` instead of
    /// `step()`: terminal (exit), unconditional jumps and comparisons.
    pub(crate) fn is_control_flow(&self) -> bool {
        matches!(self, BpfInsn::Exit | BpfInsn::Jmp { .. }) || self.is_conditional_branch()
    }
}

/// A decode-level rejection, mirroring the kernel's instruction checks
/// (`bpf_opcode_in_insntable` + `check_insn_fields` in verifier.c).
/// Decode failures are program rejections — never internal errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The opcode is not in the kernel's instruction table.
    UnknownOpcode { op: u8 },
    /// A valid kernel opcode this verifier does not implement yet.
    Unsupported { op: u8, reason: &'static str },
    /// A register field names a register above R10 (kernel: "R%d is invalid").
    InvalidRegister { reg: u8 },
    /// Non-zero reserved fields (kernel's check_*_fields messages).
    ReservedFields { message: &'static str },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnknownOpcode { op } => write!(f, "unknown opcode {:#04x}", op),
            DecodeError::Unsupported { op, reason } => {
                write!(f, "unsupported instruction {:#04x}: {}", op, reason)
            }
            DecodeError::InvalidRegister { reg } => write!(f, "R{} is invalid", reg),
            DecodeError::ReservedFields { message } => f.write_str(message),
        }
    }
}

/// Is `op` one of the supported ALU/ALU64/MOV opcodes (all BPF_ALU and
/// BPF_ALU64 forms this verifier implements)?
fn is_supported_alu(op: u8) -> bool {
    matches!(
        op,
        opcode::MOV_IMM
            | opcode::MOV_REG
            | opcode::ADD_IMM
            | opcode::ADD_REG
            | opcode::SUB_IMM
            | opcode::SUB_REG
            | opcode::AND_IMM
            | opcode::AND_REG
            | opcode::OR_IMM
            | opcode::OR_REG
            | opcode::XOR_IMM
            | opcode::XOR_REG
            | opcode::LSH_IMM
            | opcode::LSH_REG
            | opcode::RSH_IMM
            | opcode::RSH_REG
            | opcode::ARSH_IMM
            | opcode::ARSH_REG
            | opcode::ADD32_IMM
            | opcode::ADD32_REG
            | opcode::SUB32_IMM
            | opcode::SUB32_REG
            | opcode::AND32_IMM
            | opcode::AND32_REG
            | opcode::OR32_IMM
            | opcode::OR32_REG
            | opcode::XOR32_IMM
            | opcode::XOR32_REG
            | opcode::LSH32_IMM
            | opcode::LSH32_REG
            | opcode::RSH32_IMM
            | opcode::RSH32_REG
            | opcode::ARSH32_IMM
            | opcode::ARSH32_REG
    )
}

/// Reason for rejecting a valid kernel opcode that this verifier does
/// not implement yet. `None` means the opcode is not in the kernel's
/// instruction table at all (`unknown opcode`).
fn unsupported_reason(op: u8) -> Option<&'static str> {
    match op & 0x07 {
        // BPF_LD: 64-bit immediates (0x18) and the legacy loads
        0x00 => Some("BPF_LD (ldimm64 and legacy absolute/indirect loads) is not implemented"),
        // BPF_ST: store-immediate
        0x02 => Some("BPF_ST (store-immediate) is not implemented"),
        // BPF_JMP32: 32-bit compares
        0x06 => Some("BPF_JMP32 (32-bit compares) is not implemented"),
        // BPF_LDX / BPF_STX: only the DW MEM stack forms are implemented
        // (0x79 / 0x7b are matched before this helper is consulted)
        0x01 => Some("only 8-byte loads from the stack frame are implemented"),
        0x03 => Some("only 8-byte stores to the stack frame are implemented"),
        // BPF_ALU / BPF_ALU64
        0x04 | 0x07 => match op & 0xf0 {
            0x20 | 0x30 | 0x90 => Some("MUL/DIV/MOD are not implemented"),
            0x80 => Some("BPF_NEG is not implemented"),
            0xd0 => Some("BPF_END is not implemented"),
            0xb0 => Some("32-bit MOV (BPF_ALU | BPF_MOV) is not implemented"),
            _ => None,
        },
        // BPF_JMP
        0x05 => match op {
            0x45 | 0x4d => Some("BPF_JSET is not implemented"),
            0x0d => Some("indirect jumps (BPF_JA|BPF_X) are not implemented"),
            _ => None,
        },
        _ => None,
    }
}

/// Decode one 8-byte instruction from raw bytecode (kernel `struct
/// bpf_insn` layout: `[code, (src_reg << 4 | dst_reg), off_le16, imm_le32]`).
///
/// The checks mirror the kernel's order: register range first ("R%d is
/// invalid"), then opcode validity ("unknown opcode"), then reserved
/// fields (check_insn_fields, "BPF_* uses reserved fields"). Valid
/// kernel opcodes the verifier does not implement are rejected as
/// unsupported.
pub(crate) fn parse_insn(bytes: &[u8]) -> Result<BpfInsn, DecodeError> {
    let op = bytes[0];
    let regs = bytes[1];
    let dst = regs & 0x0F;
    let src = (regs >> 4) & 0x0F;
    let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
    let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    // the kernel's register-range pass rejects R11..R15 before the
    // opcode checks (verifier.c: "R%d is invalid")
    if dst > 10 {
        return Err(DecodeError::InvalidRegister { reg: dst });
    }
    if src > 10 {
        return Err(DecodeError::InvalidRegister { reg: src });
    }

    match op {
        // ALU / ALU64 / MOV — field rules mirror check_alu_fields:
        // BPF_X requires imm == 0, BPF_K requires src_reg == 0, and
        // off must be 0 for every supported op (the kernel allows off
        // hints only for MOV/32-bit subreg movs and DIV/MOD, none of
        // which are implemented here)
        _ if is_supported_alu(op) => {
            let is_x = op & 0x08 != 0; // the kernel's BPF_SRC bit
            if (is_x && imm != 0) || (!is_x && src != 0) || offset != 0 {
                let message = if op == opcode::MOV_IMM || op == opcode::MOV_REG {
                    "BPF_MOV uses reserved fields"
                } else {
                    "BPF_ALU uses reserved fields"
                };
                return Err(DecodeError::ReservedFields { message });
            }
            Ok(match op {
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
                _ => unreachable!("is_supported_alu covered the opcode"),
            })
        }
        // conditional compares — BPF_J*_X (imm reserved) and BPF_J*_K
        // (src_reg reserved, #57): mirrors check_jmp_fields
        opcode::JEQ
        | opcode::JNE
        | opcode::JGT
        | opcode::JGE
        | opcode::JLT
        | opcode::JLE
        | opcode::JSGT
        | opcode::JSGE
        | opcode::JSLT
        | opcode::JSLE
        | opcode::JEQ_IMM
        | opcode::JNE_IMM
        | opcode::JGT_IMM
        | opcode::JGE_IMM
        | opcode::JLT_IMM
        | opcode::JLE_IMM
        | opcode::JSGT_IMM
        | opcode::JSGE_IMM
        | opcode::JSLT_IMM
        | opcode::JSLE_IMM => {
            let is_x = op & 0x08 != 0; // the kernel's BPF_SRC bit
            if (is_x && imm != 0) || (!is_x && src != 0) {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_JMP uses reserved fields",
                });
            }
            Ok(match op {
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
                opcode::JEQ_IMM => BpfInsn::JeqImm { dst, imm, offset },
                opcode::JNE_IMM => BpfInsn::JneImm { dst, imm, offset },
                opcode::JGT_IMM => BpfInsn::JgtImm { dst, imm, offset },
                opcode::JGE_IMM => BpfInsn::JgeImm { dst, imm, offset },
                opcode::JLT_IMM => BpfInsn::JltImm { dst, imm, offset },
                opcode::JLE_IMM => BpfInsn::JleImm { dst, imm, offset },
                opcode::JSGT_IMM => BpfInsn::JsgtImm { dst, imm, offset },
                opcode::JSGE_IMM => BpfInsn::JsgeImm { dst, imm, offset },
                opcode::JSLT_IMM => BpfInsn::JsltImm { dst, imm, offset },
                opcode::JSLE_IMM => BpfInsn::JsleImm { dst, imm, offset },
                _ => unreachable!("compare opcode matched above"),
            })
        }
        // BPF_JA: src_reg, dst_reg and imm are reserved (check_jmp_fields)
        opcode::JMP => {
            if src != 0 || dst != 0 || imm != 0 {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_JA uses reserved fields",
                });
            }
            Ok(BpfInsn::Jmp { offset })
        }
        // BPF_CALL: dst_reg must be R0 and off must be 0. src_reg 0 is a
        // helper call (imm = helper id, kernel convention); 1 and 2 are
        // BPF_PSEUDO_CALL / BPF_PSEUDO_KFUNC_CALL, not implemented.
        opcode::CALL => {
            if dst != 0 || offset != 0 {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_CALL uses reserved fields",
                });
            }
            match src {
                0 => Ok(BpfInsn::Call { imm }),
                1 => Err(DecodeError::Unsupported {
                    op,
                    reason: "BPF-to-BPF calls (BPF_PSEUDO_CALL) are not implemented",
                }),
                2 => Err(DecodeError::Unsupported {
                    op,
                    reason: "kfunc calls (BPF_PSEUDO_KFUNC_CALL) are not implemented",
                }),
                _ => Err(DecodeError::ReservedFields {
                    message: "BPF_CALL uses reserved fields",
                }),
            }
        }
        // BPF_EXIT: src_reg, dst_reg and imm are reserved (check_jmp_fields)
        opcode::EXIT => {
            if src != 0 || dst != 0 || imm != 0 {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_EXIT uses reserved fields",
                });
            }
            Ok(BpfInsn::Exit)
        }
        // BPF_LDX|BPF_MEM|BPF_DW with R10 as the base register
        opcode::LD_STACK => {
            if imm != 0 {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_LDX uses reserved fields",
                });
            }
            if src != 10 {
                return Err(DecodeError::Unsupported {
                    op,
                    reason: "loads from a non-stack base register are not implemented",
                });
            }
            Ok(BpfInsn::LdStack { dst, offset })
        }
        // BPF_STX|BPF_MEM|BPF_DW with R10 as the base register
        opcode::ST_STACK => {
            if imm != 0 {
                return Err(DecodeError::ReservedFields {
                    message: "BPF_STX uses reserved fields",
                });
            }
            if dst != 10 {
                return Err(DecodeError::Unsupported {
                    op,
                    reason: "stores to a non-stack base register are not implemented",
                });
            }
            Ok(BpfInsn::StStack { src, offset })
        }
        _ => {
            if let Some(reason) = unsupported_reason(op) {
                Err(DecodeError::Unsupported { op, reason })
            } else {
                Err(DecodeError::UnknownOpcode { op })
            }
        }
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
        // immediate forms (#57): the kernel's `if rX == imm` notation
        BpfInsn::JeqImm { dst, imm, offset } => {
            format!("if r{} == {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JneImm { dst, imm, offset } => {
            format!("if r{} != {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JgtImm { dst, imm, offset } => {
            format!("if r{} > {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JgeImm { dst, imm, offset } => {
            format!("if r{} >= {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JltImm { dst, imm, offset } => {
            format!("if r{} < {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JleImm { dst, imm, offset } => {
            format!("if r{} <= {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JsgtImm { dst, imm, offset } => {
            format!("if r{} s> {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JsgeImm { dst, imm, offset } => {
            format!("if r{} s>= {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JsltImm { dst, imm, offset } => {
            format!("if r{} s< {} goto {:+}", dst, imm, offset)
        }
        BpfInsn::JsleImm { dst, imm, offset } => {
            format!("if r{} s<= {} goto {:+}", dst, imm, offset)
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
        // BPF_LDX|BPF_MEM|BPF_DW: the base register field (src_reg)
        // must name R10 (the frame pointer)
        let insn = parse(opcode::LD_STACK, 0, 10, -8, 0);
        assert!(matches!(insn, BpfInsn::LdStack { dst: 0, offset: -8 }));
    }

    #[test]
    fn parse_insn_st_stack() {
        // BPF_STX|BPF_MEM|BPF_DW: the base register field (dst_reg)
        // must name R10 (the frame pointer)
        let insn = parse(opcode::ST_STACK, 10, 1, -8, 0);
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
        // the immediate is the helper id (kernel convention)
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
        // ALU32 is the BPF_ALU class (0x04), not a flag on the ALU64 op
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

    // ── Real-ISA decode rules (issue #56) ───────────────────────────────────

    #[test]
    fn parse_insn_unknown_opcode_rejected() {
        // an opcode outside the kernel's instruction table is a decode
        // error, not a panic (0xef: ALU64 class with an unused op bits)
        let err = parse_insn(&insn_bytes(0xEF, 0, 0, 0, 0)).unwrap_err();
        assert_eq!(err, DecodeError::UnknownOpcode { op: 0xEF });
        assert_eq!(err.to_string(), "unknown opcode 0xef");
    }

    #[test]
    fn parse_insn_invalid_register() {
        // register fields above R10 are rejected like the kernel
        // ("R%d is invalid"), before any opcode check
        let err = parse_insn(&insn_bytes(opcode::MOV_IMM, 11, 0, 0, 0)).unwrap_err();
        assert_eq!(err, DecodeError::InvalidRegister { reg: 11 });
        let err = parse_insn(&insn_bytes(opcode::MOV_REG, 0, 15, 0, 0)).unwrap_err();
        assert_eq!(err, DecodeError::InvalidRegister { reg: 15 });
    }

    #[test]
    fn parse_insn_reserved_fields() {
        // BPF_K form with a non-zero src_reg
        let err = parse_insn(&insn_bytes(opcode::ADD_IMM, 1, 2, 0, 5)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_ALU uses reserved fields"
            }
        );
        // BPF_X form with a non-zero imm
        let err = parse_insn(&insn_bytes(opcode::ADD_REG, 1, 2, 0, 5)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_ALU uses reserved fields"
            }
        );
        // MOV uses its own message
        let err = parse_insn(&insn_bytes(opcode::MOV_IMM, 1, 2, 0, 5)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_MOV uses reserved fields"
            }
        );
        // compare X-form with a non-zero imm
        let err = parse_insn(&insn_bytes(opcode::JEQ, 1, 2, 1, 3)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_JMP uses reserved fields"
            }
        );
        // JA with a non-zero src_reg / dst_reg / imm
        let err = parse_insn(&insn_bytes(opcode::JMP, 1, 0, 2, 0)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_JA uses reserved fields"
            }
        );
        // EXIT with a non-zero imm
        let err = parse_insn(&insn_bytes(opcode::EXIT, 0, 0, 0, 1)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_EXIT uses reserved fields"
            }
        );
        // CALL with a non-zero dst_reg or off
        let err = parse_insn(&insn_bytes(opcode::CALL, 1, 0, 0, 7)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_CALL uses reserved fields"
            }
        );
        let err = parse_insn(&insn_bytes(opcode::CALL, 0, 0, 1, 7)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_CALL uses reserved fields"
            }
        );
        // LDX/STX with a non-zero imm
        let err = parse_insn(&insn_bytes(opcode::LD_STACK, 0, 10, -8, 1)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_LDX uses reserved fields"
            }
        );
        let err = parse_insn(&insn_bytes(opcode::ST_STACK, 10, 1, -8, 1)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_STX uses reserved fields"
            }
        );
    }

    #[test]
    fn parse_insn_ld_st_base_register() {
        // LDX with a base other than R10 and STX with a base other than
        // R10 are valid kernel instructions the verifier does not
        // implement (map/ctx access) — explicit unsupported errors
        let err = parse_insn(&insn_bytes(opcode::LD_STACK, 0, 1, -8, 0)).unwrap_err();
        assert!(matches!(err, DecodeError::Unsupported { op: 0x79, .. }));
        let err = parse_insn(&insn_bytes(opcode::ST_STACK, 1, 2, -8, 0)).unwrap_err();
        assert!(matches!(err, DecodeError::Unsupported { op: 0x7b, .. }));
    }

    #[test]
    fn parse_insn_call_src_reg_rules() {
        // src_reg 1/2 are BPF_PSEUDO_CALL / BPF_PSEUDO_KFUNC_CALL —
        // valid kernel calls, not implemented here
        let err = parse_insn(&insn_bytes(opcode::CALL, 0, 1, 0, 7)).unwrap_err();
        assert!(matches!(err, DecodeError::Unsupported { op: 0x85, .. }));
        let err = parse_insn(&insn_bytes(opcode::CALL, 0, 2, 0, 7)).unwrap_err();
        assert!(matches!(err, DecodeError::Unsupported { op: 0x85, .. }));
        // src_reg 3+ is a reserved field violation
        let err = parse_insn(&insn_bytes(opcode::CALL, 0, 3, 0, 7)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_CALL uses reserved fields"
            }
        );
    }

    #[test]
    fn parse_insn_unsupported_opcodes() {
        // every unimplemented kernel opcode class gets a structured
        // Unsupported error with a reason
        let unsupported = [
            // BPF_LD|BPF_IMM|BPF_DW (ldimm64)
            (0x18u8, "ldimm64"),
            // BPF_ST|BPF_MEM|BPF_DW (store-immediate)
            (0x7a, "BPF_ST"),
            // BPF_JMP32|BPF_JA
            (0x06, "BPF_JMP32"),
            // BPF_ALU64|BPF_MUL|BPF_K
            (0x27, "MUL"),
            // BPF_ALU|BPF_NEG
            (0x84, "BPF_NEG"),
            // BPF_ALU64|BPF_END
            (0xd7, "BPF_END"),
            // BPF_ALU|BPF_MOV|BPF_K (32-bit MOV)
            (0xb4, "MOV"),
            // BPF_JMP|BPF_JSET|BPF_K
            (0x45, "BPF_JSET"),
            // BPF_LDX|BPF_MEM|BPF_W
            (0x61, "loads"),
            // BPF_STX|BPF_ATOMIC|BPF_DW
            (0xdb, "stores"),
        ];
        for (op, needle) in unsupported {
            let err = parse_insn(&insn_bytes(op, 0, 0, 0, 0)).unwrap_err();
            assert!(
                matches!(err, DecodeError::Unsupported { .. }),
                "op {:#04x} should be unsupported, got {:?}",
                op,
                err
            );
            let text = err.to_string();
            assert!(
                text.contains(needle),
                "op {:#04x}: {:?} does not mention {:?}",
                op,
                err,
                needle
            );
        }
    }

    #[test]
    fn parse_insn_compare_imm_forms() {
        // the BPF_J*_K forms decode to the immediate compare variants
        // (#57); the immediate is the compare operand
        assert!(matches!(
            parse(opcode::JEQ_IMM, 1, 0, 2, 42),
            BpfInsn::JeqImm {
                dst: 1,
                imm: 42,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JNE_IMM, 1, 0, 2, -1),
            BpfInsn::JneImm {
                dst: 1,
                imm: -1,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JGT_IMM, 1, 0, 2, 5),
            BpfInsn::JgtImm {
                dst: 1,
                imm: 5,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JGE_IMM, 1, 0, 2, 5),
            BpfInsn::JgeImm {
                dst: 1,
                imm: 5,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JLT_IMM, 1, 0, 2, 5),
            BpfInsn::JltImm {
                dst: 1,
                imm: 5,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JLE_IMM, 1, 0, 2, 5),
            BpfInsn::JleImm {
                dst: 1,
                imm: 5,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JSGT_IMM, 1, 0, 2, -7),
            BpfInsn::JsgtImm {
                dst: 1,
                imm: -7,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JSGE_IMM, 1, 0, 2, -7),
            BpfInsn::JsgeImm {
                dst: 1,
                imm: -7,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JSLT_IMM, 1, 0, 2, -7),
            BpfInsn::JsltImm {
                dst: 1,
                imm: -7,
                offset: 2
            }
        ));
        assert!(matches!(
            parse(opcode::JSLE_IMM, 1, 0, 2, -7),
            BpfInsn::JsleImm {
                dst: 1,
                imm: -7,
                offset: 2
            }
        ));
    }

    #[test]
    fn parse_insn_compare_imm_reserved_src() {
        // the BPF_J*_K form reserves src_reg (check_jmp_fields)
        let err = parse_insn(&insn_bytes(opcode::JEQ_IMM, 1, 2, 1, 5)).unwrap_err();
        assert_eq!(
            err,
            DecodeError::ReservedFields {
                message: "BPF_JMP uses reserved fields"
            }
        );
    }

    #[test]
    fn parse_insn_real_layout() {
        // pin the raw byte layout of one instruction: kernel
        // bpf_insn is [code, dst|src, off_le16, imm_le32]
        // r1 = 42  →  BPF_ALU64|BPF_MOV|BPF_K, dst_reg = 1
        let insn = parse_insn(&[0xb7, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00]).unwrap();
        assert!(matches!(insn, BpfInsn::MovImm { dst: 1, imm: 42 }));
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

    #[test]
    fn disassemble_compare_imm_forms() {
        assert_eq!(
            disassemble(&BpfInsn::JeqImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 == 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JneImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 != 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JgtImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 > 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JgeImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 >= 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JltImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 < 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JleImm {
                dst: 1,
                imm: 5,
                offset: 2
            }),
            "if r1 <= 5 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JsgtImm {
                dst: 1,
                imm: -1,
                offset: 2
            }),
            "if r1 s> -1 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JsgeImm {
                dst: 1,
                imm: -1,
                offset: 2
            }),
            "if r1 s>= -1 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JsltImm {
                dst: 1,
                imm: -1,
                offset: 2
            }),
            "if r1 s< -1 goto +2"
        );
        assert_eq!(
            disassemble(&BpfInsn::JsleImm {
                dst: 1,
                imm: -1,
                offset: 2
            }),
            "if r1 s<= -1 goto +2"
        );
    }
}
