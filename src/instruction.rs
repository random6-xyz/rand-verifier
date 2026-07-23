/// eBPF register (R0-R10).
///
/// - R0: return value from helpers / exit value
/// - R1-R5: function arguments (caller-saved)
/// - R6-R9: callee-saved
/// - R10: stack pointer (read-only frame pointer)
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
