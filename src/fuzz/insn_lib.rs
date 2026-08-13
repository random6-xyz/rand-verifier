// ── Typed instruction builders, value pools, and the encoder (v0.7, #65) ────

//! Typed building blocks for fuzz program generation, following
//! syzkaller's structured instruction templates
//! ([sys/linux/bpf_prog.txt](https://github.com/google/syzkaller/blob/master/sys/linux/bpf_prog.txt)):
//! builders can only emit decodable instructions (the kernel `struct
//! bpf_insn` encoding), so the generator never produces garbage.
//!
//! This module is deterministic — random selection of values belongs to
//! the generator (`crate::fuzz::gen`, #66).

use crate::insn::{BpfInsn, opcode};

#[cfg(test)]
use crate::insn::parse_insn;

// ── Encoder (the inverse of parse_insn) ─────────────────────────────────────

/// Encode a decoded instruction back into the raw kernel 8-byte
/// encoding (`[code, (src_reg << 4 | dst_reg), off:le16, imm:le32]`).
/// The inverse of `parse_insn`: `parse_insn(&encode(&i)) == Ok(i)` for
/// every builder output. Field rules mirror `parse_insn` — BPF_X forms
/// use `imm = 0`, BPF_K forms use `src_reg = 0`.
pub fn encode(insn: &BpfInsn) -> [u8; 8] {
    let (code, dst, src, off, imm) = match insn {
        // ALU64
        BpfInsn::MovImm { dst, imm } => (opcode::MOV_IMM, *dst, 0, 0, *imm),
        BpfInsn::MovReg { dst, src } => (opcode::MOV_REG, *dst, *src, 0, 0),
        BpfInsn::AddImm { dst, imm } => (opcode::ADD_IMM, *dst, 0, 0, *imm),
        BpfInsn::AddReg { dst, src } => (opcode::ADD_REG, *dst, *src, 0, 0),
        BpfInsn::SubImm { dst, imm } => (opcode::SUB_IMM, *dst, 0, 0, *imm),
        BpfInsn::SubReg { dst, src } => (opcode::SUB_REG, *dst, *src, 0, 0),
        BpfInsn::AndImm { dst, imm } => (opcode::AND_IMM, *dst, 0, 0, *imm),
        BpfInsn::AndReg { dst, src } => (opcode::AND_REG, *dst, *src, 0, 0),
        BpfInsn::OrImm { dst, imm } => (opcode::OR_IMM, *dst, 0, 0, *imm),
        BpfInsn::OrReg { dst, src } => (opcode::OR_REG, *dst, *src, 0, 0),
        BpfInsn::XorImm { dst, imm } => (opcode::XOR_IMM, *dst, 0, 0, *imm),
        BpfInsn::XorReg { dst, src } => (opcode::XOR_REG, *dst, *src, 0, 0),
        BpfInsn::LshImm { dst, imm } => (opcode::LSH_IMM, *dst, 0, 0, *imm),
        BpfInsn::LshReg { dst, src } => (opcode::LSH_REG, *dst, *src, 0, 0),
        BpfInsn::RshImm { dst, imm } => (opcode::RSH_IMM, *dst, 0, 0, *imm),
        BpfInsn::RshReg { dst, src } => (opcode::RSH_REG, *dst, *src, 0, 0),
        BpfInsn::ArshImm { dst, imm } => (opcode::ARSH_IMM, *dst, 0, 0, *imm),
        BpfInsn::ArshReg { dst, src } => (opcode::ARSH_REG, *dst, *src, 0, 0),
        // ALU32
        BpfInsn::Add32Imm { dst, imm } => (opcode::ADD32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Add32Reg { dst, src } => (opcode::ADD32_REG, *dst, *src, 0, 0),
        BpfInsn::Sub32Imm { dst, imm } => (opcode::SUB32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Sub32Reg { dst, src } => (opcode::SUB32_REG, *dst, *src, 0, 0),
        BpfInsn::And32Imm { dst, imm } => (opcode::AND32_IMM, *dst, 0, 0, *imm),
        BpfInsn::And32Reg { dst, src } => (opcode::AND32_REG, *dst, *src, 0, 0),
        BpfInsn::Or32Imm { dst, imm } => (opcode::OR32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Or32Reg { dst, src } => (opcode::OR32_REG, *dst, *src, 0, 0),
        BpfInsn::Xor32Imm { dst, imm } => (opcode::XOR32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Xor32Reg { dst, src } => (opcode::XOR32_REG, *dst, *src, 0, 0),
        BpfInsn::Lsh32Imm { dst, imm } => (opcode::LSH32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Lsh32Reg { dst, src } => (opcode::LSH32_REG, *dst, *src, 0, 0),
        BpfInsn::Rsh32Imm { dst, imm } => (opcode::RSH32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Rsh32Reg { dst, src } => (opcode::RSH32_REG, *dst, *src, 0, 0),
        BpfInsn::Arsh32Imm { dst, imm } => (opcode::ARSH32_IMM, *dst, 0, 0, *imm),
        BpfInsn::Arsh32Reg { dst, src } => (opcode::ARSH32_REG, *dst, *src, 0, 0),
        // stack accesses — DW only, frame-pointer relative (R10)
        BpfInsn::LdStack { dst, offset } => (opcode::LD_STACK, *dst, 10, *offset, 0),
        BpfInsn::StStack { src, offset } => (opcode::ST_STACK, 10, *src, *offset, 0),
        // compares — register and immediate forms
        BpfInsn::Jeq { dst, src, offset } => (opcode::JEQ, *dst, *src, *offset, 0),
        BpfInsn::Jne { dst, src, offset } => (opcode::JNE, *dst, *src, *offset, 0),
        BpfInsn::Jgt { dst, src, offset } => (opcode::JGT, *dst, *src, *offset, 0),
        BpfInsn::Jge { dst, src, offset } => (opcode::JGE, *dst, *src, *offset, 0),
        BpfInsn::Jlt { dst, src, offset } => (opcode::JLT, *dst, *src, *offset, 0),
        BpfInsn::Jle { dst, src, offset } => (opcode::JLE, *dst, *src, *offset, 0),
        BpfInsn::Jsgt { dst, src, offset } => (opcode::JSGT, *dst, *src, *offset, 0),
        BpfInsn::Jsge { dst, src, offset } => (opcode::JSGE, *dst, *src, *offset, 0),
        BpfInsn::Jslt { dst, src, offset } => (opcode::JSLT, *dst, *src, *offset, 0),
        BpfInsn::Jsle { dst, src, offset } => (opcode::JSLE, *dst, *src, *offset, 0),
        BpfInsn::JeqImm { dst, imm, offset } => (opcode::JEQ_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JneImm { dst, imm, offset } => (opcode::JNE_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JgtImm { dst, imm, offset } => (opcode::JGT_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JgeImm { dst, imm, offset } => (opcode::JGE_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JltImm { dst, imm, offset } => (opcode::JLT_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JleImm { dst, imm, offset } => (opcode::JLE_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JsgtImm { dst, imm, offset } => (opcode::JSGT_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JsgeImm { dst, imm, offset } => (opcode::JSGE_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JsltImm { dst, imm, offset } => (opcode::JSLT_IMM, *dst, 0, *offset, *imm),
        BpfInsn::JsleImm { dst, imm, offset } => (opcode::JSLE_IMM, *dst, 0, *offset, *imm),
        // control
        BpfInsn::Jmp { offset } => (opcode::JMP, 0, 0, *offset, 0),
        BpfInsn::Call { imm } => (opcode::CALL, 0, 0, 0, *imm),
        BpfInsn::Exit => (opcode::EXIT, 0, 0, 0, 0),
    };
    let mut b = [0u8; 8];
    b[0] = code;
    b[1] = (src << 4) | (dst & 0x0F);
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

// ── Typed builders ──────────────────────────────────────────────────────────

macro_rules! alu_k_builder {
    ($name:ident => $variant:ident) => {
        /// ALU64 with an immediate source (`BPF_K`).
        pub fn $name(dst: u8, imm: i32) -> BpfInsn {
            BpfInsn::$variant { dst, imm }
        }
    };
}
macro_rules! alu_x_builder {
    ($name:ident => $variant:ident) => {
        /// ALU64 with a register source (`BPF_X`).
        pub fn $name(dst: u8, src: u8) -> BpfInsn {
            BpfInsn::$variant { dst, src }
        }
    };
}
macro_rules! alu32_k_builder {
    ($name:ident => $variant:ident) => {
        /// ALU32 (truncating, zero-extending) with an immediate source.
        pub fn $name(dst: u8, imm: i32) -> BpfInsn {
            BpfInsn::$variant { dst, imm }
        }
    };
}
macro_rules! alu32_x_builder {
    ($name:ident => $variant:ident) => {
        /// ALU32 (truncating, zero-extending) with a register source.
        pub fn $name(dst: u8, src: u8) -> BpfInsn {
            BpfInsn::$variant { dst, src }
        }
    };
}
macro_rules! cmp_x_builder {
    ($name:ident => $variant:ident) => {
        /// Conditional compare with a register source (`BPF_J*_X`).
        pub fn $name(dst: u8, src: u8, offset: i16) -> BpfInsn {
            BpfInsn::$variant { dst, src, offset }
        }
    };
}
macro_rules! cmp_k_builder {
    ($name:ident => $variant:ident) => {
        /// Conditional compare with an immediate source (`BPF_J*_K`).
        pub fn $name(dst: u8, imm: i32, offset: i16) -> BpfInsn {
            BpfInsn::$variant { dst, imm, offset }
        }
    };
}

// ALU64 — K forms
alu_k_builder!(mov_imm => MovImm);
alu_k_builder!(add_imm => AddImm);
alu_k_builder!(sub_imm => SubImm);
alu_k_builder!(and_imm => AndImm);
alu_k_builder!(or_imm => OrImm);
alu_k_builder!(xor_imm => XorImm);
alu_k_builder!(lsh_imm => LshImm);
alu_k_builder!(rsh_imm => RshImm);
alu_k_builder!(arsh_imm => ArshImm);
// ALU64 — X forms
alu_x_builder!(mov_reg => MovReg);
alu_x_builder!(add_reg => AddReg);
alu_x_builder!(sub_reg => SubReg);
alu_x_builder!(and_reg => AndReg);
alu_x_builder!(or_reg => OrReg);
alu_x_builder!(xor_reg => XorReg);
alu_x_builder!(lsh_reg => LshReg);
alu_x_builder!(rsh_reg => RshReg);
alu_x_builder!(arsh_reg => ArshReg);
// ALU32 — K forms (no MOV32 — MovImm/MovReg are ALU64 only)
alu32_k_builder!(add32_imm => Add32Imm);
alu32_k_builder!(sub32_imm => Sub32Imm);
alu32_k_builder!(and32_imm => And32Imm);
alu32_k_builder!(or32_imm => Or32Imm);
alu32_k_builder!(xor32_imm => Xor32Imm);
alu32_k_builder!(lsh32_imm => Lsh32Imm);
alu32_k_builder!(rsh32_imm => Rsh32Imm);
alu32_k_builder!(arsh32_imm => Arsh32Imm);
// ALU32 — X forms
alu32_x_builder!(add32_reg => Add32Reg);
alu32_x_builder!(sub32_reg => Sub32Reg);
alu32_x_builder!(and32_reg => And32Reg);
alu32_x_builder!(or32_reg => Or32Reg);
alu32_x_builder!(xor32_reg => Xor32Reg);
alu32_x_builder!(lsh32_reg => Lsh32Reg);
alu32_x_builder!(rsh32_reg => Rsh32Reg);
alu32_x_builder!(arsh32_reg => Arsh32Reg);

/// Load an 8-byte stack slot into `dst`: `dst = *(u64 *)(r10 + offset)`.
pub fn ld_stack(dst: u8, offset: i16) -> BpfInsn {
    BpfInsn::LdStack { dst, offset }
}

/// Store `src` into an 8-byte stack slot: `*(u64 *)(r10 + offset) = src`.
pub fn st_stack(src: u8, offset: i16) -> BpfInsn {
    BpfInsn::StStack { src, offset }
}

// compares — X forms (dst, src, offset)
cmp_x_builder!(jeq => Jeq);
cmp_x_builder!(jne => Jne);
cmp_x_builder!(jgt => Jgt);
cmp_x_builder!(jge => Jge);
cmp_x_builder!(jlt => Jlt);
cmp_x_builder!(jle => Jle);
cmp_x_builder!(jsgt => Jsgt);
cmp_x_builder!(jsge => Jsge);
cmp_x_builder!(jslt => Jslt);
cmp_x_builder!(jsle => Jsle);
// compares — K forms (dst, imm, offset)
cmp_k_builder!(jeq_imm => JeqImm);
cmp_k_builder!(jne_imm => JneImm);
cmp_k_builder!(jgt_imm => JgtImm);
cmp_k_builder!(jge_imm => JgeImm);
cmp_k_builder!(jlt_imm => JltImm);
cmp_k_builder!(jle_imm => JleImm);
cmp_k_builder!(jsgt_imm => JsgtImm);
cmp_k_builder!(jsge_imm => JsgeImm);
cmp_k_builder!(jslt_imm => JsltImm);
cmp_k_builder!(jsle_imm => JsleImm);

/// Unconditional jump: `goto pc + 1 + offset` (kernel relative offset).
pub fn jmp(offset: i16) -> BpfInsn {
    BpfInsn::Jmp { offset }
}

/// Helper call: `imm` is the kernel helper id (`BPF_JMP|BPF_CALL`).
pub fn call(helper_id: i32) -> BpfInsn {
    BpfInsn::Call { imm: helper_id }
}

/// Program exit (`BPF_JMP|BPF_EXIT`).
pub fn exit() -> BpfInsn {
    BpfInsn::Exit
}

// ── Value pools ─────────────────────────────────────────────────────────────

/// Interesting 16-bit offsets: syzkaller's `bpf_insn_offsets` pool
/// (sys/linux/bpf_prog.txt). Used for both branch offsets and stack
/// access offsets.
pub const OFFSETS: &[i16] = &[
    0, 1, 2, 4, 6, 8, 12, 16, 24, 32, 48, 64, 80, 128, 256, -1, -2, -4, -8, -12, -16, -32, -64,
];

/// Interesting 32-bit immediates: syzkaller's `bpf_insn_immediates` pool
/// plus the i32 boundary values. Wider boundaries (UINT32_MAX, INT64_*)
/// do not fit the i32 imm field — the ALU32/ALU64 opcode width covers
/// the truncation/extension dimension instead.
pub const IMMEDIATES: &[i32] = &[0, 1, 4, 8, 16, -1, -4, -16, i32::MIN, i32::MAX];

/// Large immediates that force 32/64-bit overflow on ADD/SUB — the
/// stress values for the overflow idiom (#67).
pub const LARGE_IMMEDIATES: &[i32] = &[
    1_000_000_000,
    -1_000_000_000,
    2_000_000_000,
    -2_000_000_000,
    i32::MAX,
    i32::MIN,
    0x7FFF_FFFF,
    -0x4000_0000,
];

/// Every register index R0..R10.
pub const REGS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

/// Registers usable as ALU/compare operands. R10 is the read-only frame
/// pointer (the kernel rejects arithmetic on it), so it is excluded.
pub const ALU_REGS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

/// The opcode family of an instruction, coarser than the individual
/// variants — used for coverage statistics in the campaign runner
/// (#69). The families match the milestone's target dimensions.
pub fn opcode_family(insn: &BpfInsn) -> &'static str {
    match insn {
        BpfInsn::MovImm { .. }
        | BpfInsn::MovReg { .. }
        | BpfInsn::AddImm { .. }
        | BpfInsn::AddReg { .. }
        | BpfInsn::SubImm { .. }
        | BpfInsn::SubReg { .. }
        | BpfInsn::AndImm { .. }
        | BpfInsn::AndReg { .. }
        | BpfInsn::OrImm { .. }
        | BpfInsn::OrReg { .. }
        | BpfInsn::XorImm { .. }
        | BpfInsn::XorReg { .. }
        | BpfInsn::LshImm { .. }
        | BpfInsn::LshReg { .. }
        | BpfInsn::RshImm { .. }
        | BpfInsn::RshReg { .. }
        | BpfInsn::ArshImm { .. }
        | BpfInsn::ArshReg { .. } => "alu64",
        BpfInsn::Add32Imm { .. }
        | BpfInsn::Add32Reg { .. }
        | BpfInsn::Sub32Imm { .. }
        | BpfInsn::Sub32Reg { .. }
        | BpfInsn::And32Imm { .. }
        | BpfInsn::And32Reg { .. }
        | BpfInsn::Or32Imm { .. }
        | BpfInsn::Or32Reg { .. }
        | BpfInsn::Xor32Imm { .. }
        | BpfInsn::Xor32Reg { .. }
        | BpfInsn::Lsh32Imm { .. }
        | BpfInsn::Lsh32Reg { .. }
        | BpfInsn::Rsh32Imm { .. }
        | BpfInsn::Rsh32Reg { .. }
        | BpfInsn::Arsh32Imm { .. }
        | BpfInsn::Arsh32Reg { .. } => "alu32",
        BpfInsn::Jeq { .. }
        | BpfInsn::JeqImm { .. }
        | BpfInsn::Jne { .. }
        | BpfInsn::JneImm { .. } => "cmp_eq",
        BpfInsn::Jgt { .. }
        | BpfInsn::JgtImm { .. }
        | BpfInsn::Jge { .. }
        | BpfInsn::JgeImm { .. }
        | BpfInsn::Jlt { .. }
        | BpfInsn::JltImm { .. }
        | BpfInsn::Jle { .. }
        | BpfInsn::JleImm { .. } => "cmp_unsigned",
        BpfInsn::Jsgt { .. }
        | BpfInsn::JsgtImm { .. }
        | BpfInsn::Jsge { .. }
        | BpfInsn::JsgeImm { .. }
        | BpfInsn::Jslt { .. }
        | BpfInsn::JsltImm { .. }
        | BpfInsn::Jsle { .. }
        | BpfInsn::JsleImm { .. } => "cmp_signed",
        BpfInsn::LdStack { .. } | BpfInsn::StStack { .. } => "stack",
        BpfInsn::Call { .. } => "helper",
        BpfInsn::Jmp { .. } => "jmp",
        BpfInsn::Exit => "exit",
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::insn_bytes;

    /// One builder output per supported opcode — the exhaustive builder
    /// inventory. Used by the round-trip and coverage tests.
    fn all_builders() -> Vec<BpfInsn> {
        vec![
            // ALU64 K/X
            mov_imm(0, 0),
            mov_reg(0, 1),
            add_imm(1, 0),
            add_reg(1, 2),
            sub_imm(2, 0),
            sub_reg(2, 3),
            and_imm(3, 0),
            and_reg(3, 4),
            or_imm(4, 0),
            or_reg(4, 5),
            xor_imm(5, 0),
            xor_reg(5, 6),
            lsh_imm(6, 0),
            lsh_reg(6, 7),
            rsh_imm(7, 0),
            rsh_reg(7, 8),
            arsh_imm(8, 0),
            arsh_reg(8, 9),
            // ALU32 K/X
            add32_imm(1, 0),
            add32_reg(1, 2),
            sub32_imm(2, 0),
            sub32_reg(2, 3),
            and32_imm(3, 0),
            and32_reg(3, 4),
            or32_imm(4, 0),
            or32_reg(4, 5),
            xor32_imm(5, 0),
            xor32_reg(5, 6),
            lsh32_imm(6, 0),
            lsh32_reg(6, 7),
            rsh32_imm(7, 0),
            rsh32_reg(7, 8),
            arsh32_imm(8, 0),
            arsh32_reg(8, 9),
            // stack
            ld_stack(6, -8),
            st_stack(6, -8),
            // compares X
            jeq(0, 1, 1),
            jne(0, 1, 1),
            jgt(0, 1, 1),
            jge(0, 1, 1),
            jlt(0, 1, 1),
            jle(0, 1, 1),
            jsgt(0, 1, 1),
            jsge(0, 1, 1),
            jslt(0, 1, 1),
            jsle(0, 1, 1),
            // compares K
            jeq_imm(0, 0, 1),
            jne_imm(0, 0, 1),
            jgt_imm(0, 0, 1),
            jge_imm(0, 0, 1),
            jlt_imm(0, 0, 1),
            jle_imm(0, 0, 1),
            jsgt_imm(0, 0, 1),
            jsge_imm(0, 0, 1),
            jslt_imm(0, 0, 1),
            jsle_imm(0, 0, 1),
            // control
            jmp(1),
            call(7),
            exit(),
        ]
    }

    /// Every builder output must encode and decode back to itself.
    #[test]
    fn encode_roundtrip() {
        for insn in all_builders() {
            let bytes = encode(&insn);
            let decoded =
                parse_insn(&bytes).unwrap_or_else(|e| panic!("{insn:?} failed to decode: {e}"));
            assert_eq!(decoded, insn, "round-trip mismatch");
        }
    }

    /// The encoder must reproduce the exact kernel byte encoding.
    #[test]
    fn encode_known_bytes() {
        assert_eq!(
            encode(&mov_imm(0, 42)),
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 42)
        );
        assert_eq!(
            encode(&add_reg(0, 2)),
            insn_bytes(opcode::ADD_REG, 0, 2, 0, 0)
        );
        assert_eq!(
            encode(&add32_imm(3, -1)),
            insn_bytes(opcode::ADD32_IMM, 3, 0, 0, -1)
        );
        assert_eq!(
            encode(&jeq_imm(1, 0, 2)),
            insn_bytes(opcode::JEQ_IMM, 1, 0, 2, 0)
        );
        assert_eq!(
            encode(&ld_stack(6, -8)),
            insn_bytes(opcode::LD_STACK, 6, 10, -8, 0)
        );
        assert_eq!(
            encode(&st_stack(6, -8)),
            insn_bytes(opcode::ST_STACK, 10, 6, -8, 0)
        );
        assert_eq!(encode(&call(7)), insn_bytes(opcode::CALL, 0, 0, 0, 7));
        assert_eq!(encode(&exit()), insn_bytes(opcode::EXIT, 0, 0, 0, 0));
    }

    /// The builder inventory covers exactly the supported opcode table:
    /// every opcode constant decodes from some builder output, and no
    /// builder output uses an opcode outside the table.
    #[test]
    fn opcode_coverage() {
        let supported = [
            opcode::MOV_IMM,
            opcode::MOV_REG,
            opcode::ADD_IMM,
            opcode::ADD_REG,
            opcode::SUB_IMM,
            opcode::SUB_REG,
            opcode::AND_IMM,
            opcode::AND_REG,
            opcode::OR_IMM,
            opcode::OR_REG,
            opcode::XOR_IMM,
            opcode::XOR_REG,
            opcode::LSH_IMM,
            opcode::LSH_REG,
            opcode::RSH_IMM,
            opcode::RSH_REG,
            opcode::ARSH_IMM,
            opcode::ARSH_REG,
            opcode::ADD32_IMM,
            opcode::ADD32_REG,
            opcode::SUB32_IMM,
            opcode::SUB32_REG,
            opcode::AND32_IMM,
            opcode::AND32_REG,
            opcode::OR32_IMM,
            opcode::OR32_REG,
            opcode::XOR32_IMM,
            opcode::XOR32_REG,
            opcode::LSH32_IMM,
            opcode::LSH32_REG,
            opcode::RSH32_IMM,
            opcode::RSH32_REG,
            opcode::ARSH32_IMM,
            opcode::ARSH32_REG,
            opcode::LD_STACK,
            opcode::ST_STACK,
            opcode::JEQ,
            opcode::JEQ_IMM,
            opcode::JNE,
            opcode::JNE_IMM,
            opcode::JGT,
            opcode::JGT_IMM,
            opcode::JGE,
            opcode::JGE_IMM,
            opcode::JLT,
            opcode::JLT_IMM,
            opcode::JLE,
            opcode::JLE_IMM,
            opcode::JSGT,
            opcode::JSGT_IMM,
            opcode::JSGE,
            opcode::JSGE_IMM,
            opcode::JSLT,
            opcode::JSLT_IMM,
            opcode::JSLE,
            opcode::JSLE_IMM,
            opcode::JMP,
            opcode::CALL,
            opcode::EXIT,
        ];

        let mut builder_codes: Vec<u8> = all_builders().iter().map(|i| encode(i)[0]).collect();
        builder_codes.sort_unstable();
        let mut supported_codes = supported.to_vec();
        supported_codes.sort_unstable();

        assert_eq!(
            builder_codes, supported_codes,
            "builder inventory and the opcode table drifted apart"
        );
        assert_eq!(all_builders().len(), supported.len());
    }

    /// The value pools stay within their field widths and carry the
    /// boundary values the fuzzer relies on.
    #[test]
    fn value_pool_bounds() {
        assert!(OFFSETS.contains(&0));
        assert!(OFFSETS.contains(&256));
        assert!(OFFSETS.contains(&-64));
        assert!(IMMEDIATES.contains(&i32::MIN));
        assert!(IMMEDIATES.contains(&i32::MAX));
        assert!(IMMEDIATES.contains(&0));
        assert!(IMMEDIATES.contains(&-1));
        assert_eq!(REGS.len(), 11);
        assert!(REGS.contains(&10));
        assert_eq!(ALU_REGS.len(), 10);
        assert!(!ALU_REGS.contains(&10), "R10 must not be an ALU operand");
    }
}
