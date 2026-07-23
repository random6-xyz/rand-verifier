use crate::error::DecodeError;
use crate::instruction::{INSN_SIZE, Instruction, Reg, opcode};

// ─── Decoder ─────────────────────────────────────────────────────────

/// Decode raw eBPF bytecode into a sequence of instructions.
///
/// Each eBPF instruction is a fixed 64-bit (8-byte) encoding in
/// little-endian byte order:
///
/// ```text
/// +------------------------+----------------+----+----+--------+
/// |     immediate (32)     |  offset (16)   |src |dst | opcode |
/// |                        |                |reg |reg |  (8)   |
/// |                        |                |(4) |(4) |        |
/// +------------------------+----------------+----+----+--------+
///    MSB (byte 7)                                    LSB (byte 0)
/// ```
///
/// # Errors
///
/// Returns [`DecodeError`] if the bytecode contains:
/// - Truncated instructions (length not a multiple of 8 bytes)
/// - Invalid register numbers (not in 0..=10)
/// - Unsupported opcodes
pub fn decode(bytes: &[u8]) -> Result<Vec<Instruction>, DecodeError> {
    if !bytes.len().is_multiple_of(INSN_SIZE) {
        return Err(DecodeError::Truncated);
    }

    let count = bytes.len() / INSN_SIZE;
    let mut instructions = Vec::with_capacity(count);

    for chunk in bytes.chunks_exact(INSN_SIZE) {
        // SAFETY: chunks_exact always yields exactly INSN_SIZE elements.
        let raw = u64::from_le_bytes(chunk.try_into().unwrap());

        let op = (raw & 0xFF) as u8;
        let dst = ((raw >> 8) & 0x0F) as u8;
        let src = ((raw >> 12) & 0x0F) as u8;
        let off = ((raw >> 16) & 0xFFFF) as i16;
        let imm = ((raw >> 32) & 0xFFFF_FFFF) as i32;

        let insn = decode_one(op, dst, src, off, imm)?;
        instructions.push(insn);
    }

    Ok(instructions)
}

/// Convert a raw register byte into a [`Reg`], or return `DecodeError`.
fn require_reg(val: u8) -> Result<Reg, DecodeError> {
    Reg::try_from(val).map_err(|_| DecodeError::InvalidRegister(val))
}

/// Decode a single instruction from its raw fields.
fn decode_one(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> Result<Instruction, DecodeError> {
    match op {
        // ALU64 — MOV
        opcode::MOV64_IMM => {
            let dst = require_reg(dst)?;
            Ok(Instruction::MovImm { dst, imm })
        }
        opcode::MOV64_REG => {
            let dst = require_reg(dst)?;
            let src = require_reg(src)?;
            Ok(Instruction::MovReg { dst, src })
        }

        // ALU64 — ADD
        opcode::ADD64_IMM => {
            let dst = require_reg(dst)?;
            Ok(Instruction::AddImm { dst, imm })
        }
        opcode::ADD64_REG => {
            let dst = require_reg(dst)?;
            let src = require_reg(src)?;
            Ok(Instruction::AddReg { dst, src })
        }

        // JMP — unconditional
        opcode::JA => Ok(Instruction::Jump { offset: off }),

        // JMP — conditional
        opcode::JEQ_IMM => {
            let dst = require_reg(dst)?;
            Ok(Instruction::JumpEqImm {
                dst,
                imm,
                offset: off,
            })
        }

        // JMP — exit
        opcode::EXIT => Ok(Instruction::Exit),

        _ => Err(DecodeError::UnsupportedOpcode(op)),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::Reg;

    /// Build a raw 8-byte instruction from its fields.
    fn encode(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let raw: u64 = (op as u64)
            | ((dst as u64) << 8)
            | ((src as u64) << 12)
            | ((off as u16 as u64) << 16)
            | ((imm as u32 as u64) << 32);
        raw.to_le_bytes()
    }

    // ── Empty / truncated ────────────────────────────────

    #[test]
    fn decode_empty_bytecode() {
        let result = decode(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_truncated_input() {
        // 7 bytes instead of 8
        let result = decode(&[0x00; 7]);
        assert_eq!(result, Err(DecodeError::Truncated));

        // 9 bytes — extra trailing byte
        let result = decode(&[0x00; 9]);
        assert_eq!(result, Err(DecodeError::Truncated));
    }

    // ── Single instructions ──────────────────────────────

    #[test]
    fn decode_mov64_imm() {
        let bytes = encode(opcode::MOV64_IMM, 0, 0, 0, 42);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 42
            }
        );
    }

    #[test]
    fn decode_mov64_reg() {
        let bytes = encode(opcode::MOV64_REG, 1, 2, 0, 0);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            Instruction::MovReg {
                dst: Reg::R1,
                src: Reg::R2
            }
        );
    }

    #[test]
    fn decode_add64_imm() {
        let bytes = encode(opcode::ADD64_IMM, 3, 0, 0, 5);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            Instruction::AddImm {
                dst: Reg::R3,
                imm: 5
            }
        );
    }

    #[test]
    fn decode_add64_reg() {
        let bytes = encode(opcode::ADD64_REG, 4, 5, 0, 0);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            Instruction::AddReg {
                dst: Reg::R4,
                src: Reg::R5
            }
        );
    }

    #[test]
    fn decode_ja() {
        let bytes = encode(opcode::JA, 0, 0, 3, 0);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Instruction::Jump { offset: 3 });
    }

    #[test]
    fn decode_ja_negative_offset() {
        let bytes = encode(opcode::JA, 0, 0, -2, 0);
        let result = decode(&bytes).unwrap();
        assert_eq!(result[0], Instruction::Jump { offset: -2 });
    }

    #[test]
    fn decode_jeq_imm() {
        let bytes = encode(opcode::JEQ_IMM, 1, 0, 4, 100);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            Instruction::JumpEqImm {
                dst: Reg::R1,
                imm: 100,
                offset: 4
            }
        );
    }

    #[test]
    fn decode_exit() {
        let bytes = encode(opcode::EXIT, 0, 0, 0, 0);
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], Instruction::Exit);
    }

    // ── Multi-instruction program ────────────────────────

    #[test]
    fn decode_small_program() {
        // r0 = 0
        // r1 = 10
        // if r0 == 0 goto +2
        // r1 = 99
        // exit

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 0, 0, 0, 0));
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 1, 0, 0, 10));
        bytes.extend_from_slice(&encode(opcode::JEQ_IMM, 0, 0, 2, 0));
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 1, 0, 0, 99));
        bytes.extend_from_slice(&encode(opcode::EXIT, 0, 0, 0, 0));

        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(
            result[0],
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 0
            }
        );
        assert_eq!(result[4], Instruction::Exit);
    }

    #[test]
    fn decode_16_instructions() {
        // 16 mov instructions — verify capacity pre-allocation works.
        // Registers wrap every 11 to stay in R0..R10.
        let mut bytes = Vec::new();
        for i in 0..16 {
            let reg = (i % 11) as u8;
            bytes.extend_from_slice(&encode(opcode::MOV64_IMM, reg, 0, 0, i * 10));
        }
        let result = decode(&bytes).unwrap();
        assert_eq!(result.len(), 16);
        for (i, insn) in result.iter().enumerate() {
            let reg = (i % 11) as u8;
            assert_eq!(
                insn,
                &Instruction::MovImm {
                    dst: Reg::try_from(reg).unwrap(),
                    imm: i as i32 * 10
                }
            );
        }
    }

    // ── Errors ───────────────────────────────────────────

    #[test]
    fn decode_invalid_dst_register() {
        let bytes = encode(opcode::MOV64_IMM, 12, 0, 0, 0); // R12 doesn't exist
        let result = decode(&bytes);
        assert_eq!(result, Err(DecodeError::InvalidRegister(12)));
    }

    #[test]
    fn decode_invalid_src_register() {
        let bytes = encode(opcode::MOV64_REG, 0, 11, 0, 0); // R11 doesn't exist
        let result = decode(&bytes);
        assert_eq!(result, Err(DecodeError::InvalidRegister(11)));
    }

    #[test]
    fn decode_unsupported_opcode() {
        let bytes = encode(0x00, 0, 0, 0, 0); // BPF_LD — not in our subset
        let result = decode(&bytes);
        assert_eq!(result, Err(DecodeError::UnsupportedOpcode(0x00)));
    }

    #[test]
    fn decode_unsupported_opcode_0xff() {
        let bytes = encode(0xFF, 0, 0, 0, 0);
        let result = decode(&bytes);
        assert_eq!(result, Err(DecodeError::UnsupportedOpcode(0xFF)));
    }

    #[test]
    fn decode_truncated_mid_program() {
        // Two full instructions plus a trailing byte
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 0, 0, 0, 0));
        bytes.extend_from_slice(&encode(opcode::EXIT, 0, 0, 0, 0));
        bytes.push(0x00); // extra byte makes length 17

        let result = decode(&bytes);
        assert_eq!(result, Err(DecodeError::Truncated));
    }

    // ── Roundtrip (decode → display) ─────────────────────

    #[test]
    fn decode_display_roundtrip() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 0, 0, 0, 1));
        bytes.extend_from_slice(&encode(opcode::MOV64_IMM, 1, 0, 0, 10));
        bytes.extend_from_slice(&encode(opcode::ADD64_IMM, 0, 0, 0, 5));
        bytes.extend_from_slice(&encode(opcode::JEQ_IMM, 0, 0, 1, 15));
        bytes.extend_from_slice(&encode(opcode::EXIT, 0, 0, 0, 0));

        let instructions = decode(&bytes).unwrap();
        let displayed: Vec<String> = instructions.iter().map(|i| i.to_string()).collect();

        assert_eq!(displayed[0], "r0 = 1");
        assert_eq!(displayed[1], "r1 = 10");
        assert_eq!(displayed[2], "r0 += 5");
        assert_eq!(displayed[3], "if r0 == 15 goto +1");
        assert_eq!(displayed[4], "exit");
    }
}
