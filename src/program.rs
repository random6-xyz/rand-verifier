use crate::instruction::Instruction;

/// Index into a program's instruction list.
///
/// Wraps a `usize` for type-safe instruction indexing in traces and errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InsnIndex(pub usize);

/// A decoded eBPF program.
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

    /// Return true if the program has no instructions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Get the instruction at the given index, if within bounds.
    #[must_use]
    pub fn get(&self, index: InsnIndex) -> Option<&Instruction> {
        self.instructions.get(index.0)
    }
}
