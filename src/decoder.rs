use crate::error::DecodeError;
use crate::instruction::Instruction;

/// Decode raw eBPF bytecode into a sequence of instructions.
///
/// Each eBPF instruction is a fixed 64-bit (8-byte) encoding.
/// This decoder handles the subset of opcodes needed for the nano verifier.
///
/// # Errors
///
/// Returns `DecodeError` if the bytecode contains:
/// - Truncated instructions (not a multiple of 8 bytes)
/// - Invalid register numbers
/// - Unsupported opcodes
pub fn decode(_bytes: &[u8]) -> Result<Vec<Instruction>, DecodeError> {
    // TODO: fully implement in issue #3
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_empty_bytecode() {
        let result = decode(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
