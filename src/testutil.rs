// ── Shared test helpers ──────────────────────────────────────────────────────

use crate::insn::{BpfInsn, parse_insn};

/// A stack pointer at an exact offset (test shorthand).
pub(crate) fn ptr_stack(offset: i32) -> crate::state::RegState {
    crate::state::RegState::PtrToStack {
        min_offset: offset,
        max_offset: offset,
        align_off: offset.rem_euclid(8) as u8,
    }
}

/// Build a raw 8-byte instruction:
/// [op, (src << 4 | dst), offset_le, imm_le]
pub(crate) fn insn_bytes(op: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = op;
    b[1] = (src << 4) | (dst & 0x0F);
    b[2..4].copy_from_slice(&offset.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

/// Concatenate 8-byte instructions into a raw program byte stream.
pub(crate) fn prog_bytes(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flatten().copied().collect()
}

/// Decode a single raw instruction (shorthand for parse_insn tests).
/// Panics on decode errors — tests use `parse_insn` directly for the
/// error cases.
pub(crate) fn parse(op: u8, dst: u8, src: u8, offset: i16, imm: i32) -> BpfInsn {
    parse_insn(&insn_bytes(op, dst, src, offset, imm)).expect("instruction decodes")
}
