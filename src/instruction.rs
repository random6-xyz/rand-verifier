use std::fmt;

// ─── Registers ───────────────────────────────────────────────────────

/// eBPF register (R0-R10).
///
/// | Register | Convention |
/// |----------|------------|
/// | R0       | Return value from helpers / exit value |
/// | R1-R5    | Function arguments (caller-saved) |
/// | R6-R9    | Callee-saved |
/// | R10      | Stack pointer (read-only frame pointer) |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reg {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
}

impl Reg {
    /// Total number of eBPF registers (R0 through R10).
    pub const COUNT: usize = 11;

    /// Return the register number as a `u8`.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::R0 => 0,
            Self::R1 => 1,
            Self::R2 => 2,
            Self::R3 => 3,
            Self::R4 => 4,
            Self::R5 => 5,
            Self::R6 => 6,
            Self::R7 => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
        }
    }
}

/// Error returned when a raw register number is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRegister(pub u8);

impl fmt::Display for InvalidRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid register number: {}", self.0)
    }
}

impl TryFrom<u8> for Reg {
    type Error = InvalidRegister;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::R0),
            1 => Ok(Self::R1),
            2 => Ok(Self::R2),
            3 => Ok(Self::R3),
            4 => Ok(Self::R4),
            5 => Ok(Self::R5),
            6 => Ok(Self::R6),
            7 => Ok(Self::R7),
            8 => Ok(Self::R8),
            9 => Ok(Self::R9),
            10 => Ok(Self::R10),
            n => Err(InvalidRegister(n)),
        }
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::R0 => write!(f, "r0"),
            Self::R1 => write!(f, "r1"),
            Self::R2 => write!(f, "r2"),
            Self::R3 => write!(f, "r3"),
            Self::R4 => write!(f, "r4"),
            Self::R5 => write!(f, "r5"),
            Self::R6 => write!(f, "r6"),
            Self::R7 => write!(f, "r7"),
            Self::R8 => write!(f, "r8"),
            Self::R9 => write!(f, "r9"),
            Self::R10 => write!(f, "r10"),
        }
    }
}

// ─── Opcode constants ────────────────────────────────────────────────

/// Raw eBPF opcode constants for the instruction subset.
///
/// Each eBPF instruction is 64 bits:
/// `opcode:8 | dst:4 | src:4 | offset:16 | imm:32`
///
/// The opcode byte encodes both the instruction class (low 3 bits)
/// and the operation within that class.
pub mod opcode {
    // ALU64 class (0x07)
    /// `dst = imm` — 64-bit move immediate
    pub const MOV64_IMM: u8 = 0xb7;
    /// `dst = src` — 64-bit move register
    pub const MOV64_REG: u8 = 0xbf;
    /// `dst += imm` — 64-bit add immediate
    pub const ADD64_IMM: u8 = 0x07;
    /// `dst += src` — 64-bit add register
    pub const ADD64_REG: u8 = 0x0f;

    // JMP class (0x05)
    /// `goto +offset` — unconditional jump
    pub const JA: u8 = 0x05;
    /// `if dst == imm goto +offset` — jump if equal (64-bit)
    pub const JEQ_IMM: u8 = 0x15;
    /// `exit` — return from program
    pub const EXIT: u8 = 0x95;
}

/// Size of a single eBPF instruction in bytes.
pub const INSN_SIZE: usize = 8;

// ─── Instructions ────────────────────────────────────────────────────

/// A single eBPF instruction (subset for nano verifier).
///
/// Covers the minimal set needed for CFG construction:
/// `MOV`, `ADD`, `JA`, `JEQ`, `EXIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction {
    /// `r{dst} = {imm}`
    MovImm { dst: Reg, imm: i32 },
    /// `r{dst} = r{src}`
    MovReg { dst: Reg, src: Reg },

    /// `r{dst} += {imm}`
    AddImm { dst: Reg, imm: i32 },
    /// `r{dst} += r{src}`
    AddReg { dst: Reg, src: Reg },

    /// `goto PC + {offset}`
    Jump { offset: i16 },
    /// `if r{dst} == {imm} goto PC + {offset}`
    JumpEqImm { dst: Reg, imm: i32, offset: i16 },

    /// `exit`
    Exit,
}

impl Instruction {
    /// Returns `true` if this instruction is an unconditional jump (`JA`).
    #[must_use]
    pub fn is_jump(&self) -> bool {
        matches!(self, Self::Jump { .. })
    }

    /// Returns `true` if this instruction is a conditional jump (e.g., `JEQ`).
    #[must_use]
    pub fn is_conditional_jump(&self) -> bool {
        matches!(self, Self::JumpEqImm { .. })
    }

    /// Returns `true` if this instruction is any kind of branch (conditional or unconditional).
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.is_jump() || self.is_conditional_jump()
    }

    /// Returns `true` if this instruction is an `exit`.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        matches!(self, Self::Exit)
    }

    /// Returns `true` if execution should fall through to the next instruction.
    ///
    /// Fallthrough applies to all instructions except unconditional jumps and exit.
    #[must_use]
    pub fn is_fallthrough(&self) -> bool {
        !matches!(self, Self::Jump { .. } | Self::Exit)
    }

    /// Returns the branch offset if this is a jump instruction, or `None`.
    #[must_use]
    pub fn jump_offset(&self) -> Option<i16> {
        match self {
            Self::Jump { offset } | Self::JumpEqImm { offset, .. } => Some(*offset),
            _ => None,
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MovImm { dst, imm } => write!(f, "{dst} = {imm}"),
            Self::MovReg { dst, src } => write!(f, "{dst} = {src}"),
            Self::AddImm { dst, imm } => {
                if *imm >= 0 {
                    write!(f, "{dst} += {imm}")
                } else {
                    write!(f, "{dst} -= {}", -imm)
                }
            }
            Self::AddReg { dst, src } => write!(f, "{dst} += {src}"),
            Self::Jump { offset } => write!(f, "goto +{offset}"),
            Self::JumpEqImm { dst, imm, offset } => {
                write!(f, "if {dst} == {imm} goto +{offset}")
            }
            Self::Exit => write!(f, "exit"),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Reg ─────────────────────────────────────────────────

    #[test]
    fn reg_from_valid_u8() {
        assert_eq!(Reg::try_from(0).unwrap(), Reg::R0);
        assert_eq!(Reg::try_from(10).unwrap(), Reg::R10);
        assert_eq!(Reg::try_from(5).unwrap(), Reg::R5);
    }

    #[test]
    fn reg_from_invalid_u8() {
        assert!(Reg::try_from(11).is_err());
        assert!(Reg::try_from(255).is_err());
    }

    #[test]
    fn reg_to_u8_roundtrip() {
        for n in 0..11u8 {
            let reg = Reg::try_from(n).unwrap();
            assert_eq!(reg.to_u8(), n);
        }
    }

    #[test]
    fn reg_display() {
        assert_eq!(format!("{}", Reg::R0), "r0");
        assert_eq!(format!("{}", Reg::R10), "r10");
        assert_eq!(format!("{}", Reg::R5), "r5");
    }

    #[test]
    fn reg_count() {
        assert_eq!(Reg::COUNT, 11);
    }

    // ── Instruction classification ─────────────────────────

    #[test]
    fn instruction_is_jump() {
        assert!(Instruction::Jump { offset: 1 }.is_jump());
        assert!(
            !Instruction::JumpEqImm {
                dst: Reg::R0,
                imm: 0,
                offset: 1
            }
            .is_jump()
        );
        assert!(!Instruction::Exit.is_jump());
        assert!(
            !Instruction::MovImm {
                dst: Reg::R0,
                imm: 0
            }
            .is_jump()
        );
    }

    #[test]
    fn instruction_is_conditional_jump() {
        assert!(
            Instruction::JumpEqImm {
                dst: Reg::R0,
                imm: 0,
                offset: 1
            }
            .is_conditional_jump()
        );
        assert!(!Instruction::Jump { offset: 1 }.is_conditional_jump());
        assert!(!Instruction::Exit.is_conditional_jump());
    }

    #[test]
    fn instruction_is_exit() {
        assert!(Instruction::Exit.is_exit());
        assert!(!Instruction::Jump { offset: 0 }.is_exit());
        assert!(
            !Instruction::MovImm {
                dst: Reg::R0,
                imm: 42
            }
            .is_exit()
        );
    }

    #[test]
    fn instruction_is_fallthrough() {
        assert!(
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 1
            }
            .is_fallthrough()
        );
        assert!(
            Instruction::MovReg {
                dst: Reg::R0,
                src: Reg::R1
            }
            .is_fallthrough()
        );
        assert!(
            Instruction::AddImm {
                dst: Reg::R0,
                imm: 1
            }
            .is_fallthrough()
        );
        assert!(
            Instruction::AddReg {
                dst: Reg::R0,
                src: Reg::R1
            }
            .is_fallthrough()
        );
        assert!(
            Instruction::JumpEqImm {
                dst: Reg::R0,
                imm: 42,
                offset: 3
            }
            .is_fallthrough()
        );
        assert!(!Instruction::Jump { offset: 1 }.is_fallthrough());
        assert!(!Instruction::Exit.is_fallthrough());
    }

    #[test]
    fn instruction_is_branch() {
        assert!(Instruction::Jump { offset: 1 }.is_branch());
        assert!(
            Instruction::JumpEqImm {
                dst: Reg::R0,
                imm: 0,
                offset: 1
            }
            .is_branch()
        );
        assert!(!Instruction::Exit.is_branch());
        assert!(
            !Instruction::MovImm {
                dst: Reg::R0,
                imm: 0
            }
            .is_branch()
        );
    }

    #[test]
    fn instruction_jump_offset() {
        assert_eq!(Instruction::Jump { offset: 5 }.jump_offset(), Some(5));
        assert_eq!(Instruction::Jump { offset: -3 }.jump_offset(), Some(-3));
        assert_eq!(
            Instruction::JumpEqImm {
                dst: Reg::R1,
                imm: 10,
                offset: 7
            }
            .jump_offset(),
            Some(7)
        );
        assert_eq!(Instruction::Exit.jump_offset(), None);
        assert_eq!(
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 0
            }
            .jump_offset(),
            None
        );
    }

    // ── Display ────────────────────────────────────────────

    #[test]
    fn instruction_display() {
        assert_eq!(
            format!(
                "{}",
                Instruction::MovImm {
                    dst: Reg::R0,
                    imm: 42
                }
            ),
            "r0 = 42"
        );
        assert_eq!(
            format!(
                "{}",
                Instruction::MovReg {
                    dst: Reg::R1,
                    src: Reg::R2
                }
            ),
            "r1 = r2"
        );
        assert_eq!(
            format!(
                "{}",
                Instruction::AddImm {
                    dst: Reg::R3,
                    imm: 5
                }
            ),
            "r3 += 5"
        );
        assert_eq!(
            format!(
                "{}",
                Instruction::AddImm {
                    dst: Reg::R3,
                    imm: -5
                }
            ),
            "r3 -= 5"
        );
        assert_eq!(
            format!(
                "{}",
                Instruction::AddReg {
                    dst: Reg::R4,
                    src: Reg::R5
                }
            ),
            "r4 += r5"
        );
        assert_eq!(format!("{}", Instruction::Jump { offset: 3 }), "goto +3");
        assert_eq!(
            format!(
                "{}",
                Instruction::JumpEqImm {
                    dst: Reg::R6,
                    imm: 1,
                    offset: 2
                }
            ),
            "if r6 == 1 goto +2"
        );
        assert_eq!(format!("{}", Instruction::Exit), "exit");
    }

    // ── Opcode constants ───────────────────────────────────

    #[test]
    fn opcode_uniqueness() {
        // Ensure opcodes in the subset don't overlap
        let ops = vec![
            opcode::MOV64_IMM,
            opcode::MOV64_REG,
            opcode::ADD64_IMM,
            opcode::ADD64_REG,
            opcode::JA,
            opcode::JEQ_IMM,
            opcode::EXIT,
        ];
        let mut sorted = ops.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ops.len(), "opcodes must be unique");
    }
}
