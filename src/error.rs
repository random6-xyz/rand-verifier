/// Errors that occur during bytecode decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The bytecode was truncated (incomplete instruction).
    Truncated,
    /// An invalid register number was used.
    InvalidRegister(u8),
    /// An unknown or unsupported opcode was encountered.
    UnsupportedOpcode(u8),
}

/// Errors that occur during verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Jump targets an instruction outside the program bounds.
    InvalidJumpTarget { pc: usize, target: isize },
    /// An instruction is not reachable from the entry point.
    UnreachableInstruction { pc: usize },
    /// A reachable code path does not end with an `exit` instruction.
    MissingExit { pc: usize },
    /// A backward jump was detected (not allowed in nano verifier).
    BackwardJump { pc: usize, target: usize },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated bytecode"),
            Self::InvalidRegister(reg) => write!(f, "invalid register: R{reg}"),
            Self::UnsupportedOpcode(op) => write!(f, "unsupported opcode: 0x{op:02x}"),
        }
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJumpTarget { pc, target } => {
                write!(f, "instruction {pc}: jump target {target} is out of bounds")
            }
            Self::UnreachableInstruction { pc } => {
                write!(f, "instruction {pc} is unreachable")
            }
            Self::MissingExit { pc } => {
                write!(f, "instruction {pc}: path does not terminate with exit")
            }
            Self::BackwardJump { pc, target } => {
                write!(
                    f,
                    "instruction {pc}: backward jump to {target} is not allowed"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}
impl std::error::Error for VerifyError {}
