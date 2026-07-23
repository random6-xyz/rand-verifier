use crate::instruction::Instruction;
use crate::program::{InsnIndex, Program};

/// A node in the control-flow graph.
#[derive(Debug, Clone)]
pub struct CfgNode {
    /// The instruction index this node corresponds to.
    pub index: InsnIndex,
    /// Successor instruction indices.
    pub successors: Vec<InsnIndex>,
}

/// A control-flow graph representing program structure.
#[derive(Debug, Clone)]
pub struct Cfg {
    /// All nodes in the CFG, one per instruction.
    pub nodes: Vec<CfgNode>,
    /// The entry point (always instruction 0 for a valid program).
    pub entry: InsnIndex,
}

impl Cfg {
    /// Build a CFG from a decoded program.
    ///
    /// Each instruction becomes a node with edges determined by
    /// the instruction type (unconditional jump, conditional jump, fallthrough).
    #[must_use]
    pub fn from_program(program: &Program) -> Self {
        // TODO: fully implement in issue #5
        let nodes: Vec<CfgNode> = program
            .instructions
            .iter()
            .enumerate()
            .map(|(i, _insn)| CfgNode {
                index: InsnIndex(i),
                successors: if i + 1 < program.len() && !matches!(_insn, Instruction::Exit) {
                    vec![InsnIndex(i + 1)]
                } else {
                    Vec::new()
                },
            })
            .collect();

        Self {
            nodes,
            entry: InsnIndex(0),
        }
    }
}
