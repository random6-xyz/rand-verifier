use std::fmt;

use crate::instruction::Instruction;

// ─── Instruction index ───────────────────────────────────────────────

/// Index into a program's instruction list.
///
/// Wraps a `usize` for type-safe instruction indexing in traces and errors.
/// Display renders as `insn #3` for human-readable verifier output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InsnIndex(pub usize);

impl InsnIndex {
    /// Return the index of the next (fallthrough) instruction.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Compute the jump target for `pc + offset`.
    ///
    /// Returns `None` if the target would underflow (negative `pc + offset`).
    /// Overflow is allowed — the caller should bounds-check against the program length.
    #[must_use]
    pub fn checked_jump(self, offset: i16) -> Option<Self> {
        if offset < 0 {
            let abs = (-offset) as usize;
            self.0.checked_sub(abs).map(Self)
        } else {
            Some(Self(self.0.saturating_add(offset as usize)))
        }
    }
}

impl fmt::Display for InsnIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "insn #{}", self.0)
    }
}

impl From<usize> for InsnIndex {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

// ─── Program ─────────────────────────────────────────────────────────

/// A decoded eBPF program.
///
/// Wraps a sequence of [`Instruction`]s and provides indexed access
/// via [`InsnIndex`] for type-safe addressing.
#[derive(Debug, Clone)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

impl Program {
    /// Create a new program from a vector of instructions.
    #[must_use]
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }

    /// Return the number of instructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Return `true` if the program has no instructions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Get the instruction at the given index, if within bounds.
    #[must_use]
    pub fn get(&self, index: InsnIndex) -> Option<&Instruction> {
        self.instructions.get(index.0)
    }

    /// Return `true` if the given index is within the program bounds.
    #[must_use]
    pub fn contains_index(&self, index: InsnIndex) -> bool {
        index.0 < self.instructions.len()
    }

    /// Iterate over `(InsnIndex, &Instruction)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (InsnIndex, &Instruction)> {
        self.instructions
            .iter()
            .enumerate()
            .map(|(i, insn)| (InsnIndex(i), insn))
    }
}

impl fmt::Display for Program {
    /// Pretty-print the full program with instruction numbers.
    ///
    /// Example output:
    /// ```text
    /// 0: r0 = 1
    /// 1: if r0 == 0 goto +2
    /// 2: r0 = 2
    /// 3: exit
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.instructions.is_empty() {
            return Ok(());
        }
        let width = if self.instructions.len() > 1 {
            (self.instructions.len() - 1).to_string().len()
        } else {
            1
        };
        for (i, insn) in self.instructions.iter().enumerate() {
            writeln!(f, "{i:>width$}: {insn}")?;
        }
        Ok(())
    }
}

impl From<Vec<Instruction>> for Program {
    fn from(instructions: Vec<Instruction>) -> Self {
        Self::new(instructions)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{Instruction, Reg};

    // ── InsnIndex ─────────────────────────────────────────

    #[test]
    fn insn_index_display() {
        assert_eq!(InsnIndex(0).to_string(), "insn #0");
        assert_eq!(InsnIndex(7).to_string(), "insn #7");
        assert_eq!(InsnIndex(42).to_string(), "insn #42");
    }

    #[test]
    fn insn_index_next() {
        assert_eq!(InsnIndex(0).next(), InsnIndex(1));
        assert_eq!(InsnIndex(5).next(), InsnIndex(6));
    }

    #[test]
    fn insn_index_checked_jump_forward() {
        assert_eq!(InsnIndex(0).checked_jump(3), Some(InsnIndex(3)));
        assert_eq!(InsnIndex(5).checked_jump(1), Some(InsnIndex(6)));
        // Large forward jump is allowed (caller checks bounds)
        assert_eq!(InsnIndex(0).checked_jump(1000), Some(InsnIndex(1000)));
    }

    #[test]
    fn insn_index_checked_jump_backward() {
        assert_eq!(InsnIndex(5).checked_jump(-2), Some(InsnIndex(3)));
        assert_eq!(InsnIndex(10).checked_jump(-10), Some(InsnIndex(0)));
    }

    #[test]
    fn insn_index_checked_jump_underflow() {
        // Jump before instruction 0
        assert_eq!(InsnIndex(2).checked_jump(-3), None);
        assert_eq!(InsnIndex(0).checked_jump(-1), None);
    }

    #[test]
    fn insn_index_from_usize() {
        let idx: InsnIndex = 3.into();
        assert_eq!(idx, InsnIndex(3));
    }

    // ── Program ───────────────────────────────────────────

    #[test]
    fn program_new_and_len() {
        let prog = Program::new(vec![
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 1,
            },
            Instruction::Exit,
        ]);
        assert_eq!(prog.len(), 2);
        assert!(!prog.is_empty());
    }

    #[test]
    fn program_empty() {
        let prog = Program::new(vec![]);
        assert!(prog.is_empty());
        assert_eq!(prog.len(), 0);
    }

    #[test]
    fn program_get_in_bounds() {
        let insn = Instruction::MovImm {
            dst: Reg::R1,
            imm: 42,
        };
        let prog = Program::new(vec![insn.clone()]);
        assert_eq!(prog.get(InsnIndex(0)), Some(&insn));
    }

    #[test]
    fn program_get_out_of_bounds() {
        let prog = Program::new(vec![Instruction::Exit]);
        assert_eq!(prog.get(InsnIndex(1)), None);
        assert_eq!(prog.get(InsnIndex(100)), None);
    }

    #[test]
    fn program_contains_index() {
        let prog = Program::new(vec![Instruction::Exit]);
        assert!(prog.contains_index(InsnIndex(0)));
        assert!(!prog.contains_index(InsnIndex(1)));
        assert!(!prog.contains_index(InsnIndex(10)));
    }

    #[test]
    fn program_iter() {
        let prog = Program::new(vec![
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 0,
            },
            Instruction::Exit,
        ]);
        let pairs: Vec<_> = prog.iter().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0, InsnIndex(0));
        assert_eq!(pairs[1].0, InsnIndex(1));
    }

    #[test]
    fn program_from_vec() {
        let prog: Program = vec![Instruction::Exit].into();
        assert_eq!(prog.len(), 1);
    }

    // ── Program Display ───────────────────────────────────

    #[test]
    fn program_display_single_instruction() {
        let prog = Program::new(vec![Instruction::Exit]);
        assert_eq!(prog.to_string(), "0: exit\n");
    }

    #[test]
    fn program_display_multiple_instructions() {
        let prog = Program::new(vec![
            Instruction::MovImm {
                dst: Reg::R0,
                imm: 0,
            },
            Instruction::AddImm {
                dst: Reg::R0,
                imm: 1,
            },
            Instruction::Exit,
        ]);
        let expected = "0: r0 = 0\n1: r0 += 1\n2: exit\n";
        assert_eq!(prog.to_string(), expected);
    }

    #[test]
    fn program_display_alignment() {
        // With 10+ instructions, single-digit indices get right-aligned
        let instructions: Vec<Instruction> = (0..12).map(|_| Instruction::Exit).collect();
        let prog = Program::new(instructions);
        let output = prog.to_string();

        // First line (index 0) should be padded to 2 chars
        let first_line = output.lines().next().unwrap();
        assert_eq!(first_line, " 0: exit");

        // Line 10 should be 2 chars wide (no extra padding)
        let line10 = output.lines().nth(10).unwrap();
        assert_eq!(line10, "10: exit");
    }
}
