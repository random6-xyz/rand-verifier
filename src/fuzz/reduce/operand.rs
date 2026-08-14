// ── Operand-level minimization (v0.8, #80) ───────────────────────────────────

//! After instruction-level reduction a reproducer is minimal in *count*
//! but not in *content*: immediates may be huge, ALU instructions may
//! use register sources where the immediate form is semantically
//! shorter, registers may occupy high indices, and stack offsets may
//! be large. This module emits oracle-validated candidates for four
//! transforms (deterministic order, one change per candidate):
//!
//! - **immediate shrinking** — replace an imm with a simpler value
//!   (the v0.7 interesting-values pool: 0, 1, -1, i32 min/max; only
//!   strictly smaller magnitude);
//! - **ALU X→K form** — a register-form ALU whose source register is a
//!   known MOV64-imm constant becomes the immediate form;
//! - **register lowering** — the highest used register is renamed to
//!   the lowest unused one (R0 — the exit convention — and R10 — the
//!   frame pointer — are never renamed);
//! - **stack-offset shrinking** — stack accesses move toward 0 in
//!   8-byte steps.
//!
//! Every candidate is a *proposal*: the driver's oracle keeps the
//! first one that preserves the finding and repeats the cycle to a
//! fixpoint. Decode-level conservative (a constant producer is only a
//! `MOV64 imm`; any other write clears the known value).

use crate::fuzz::insn_lib::encode;
use crate::insn::{BpfInsn, parse_insn};

/// The interesting-values pool (v0.7 #65), in preference order.
const VALUE_POOL: [i32; 5] = [0, 1, -1, i32::MIN, i32::MAX];

/// One operand transform candidate: the pass name and the rewritten
/// program (one single change).
pub type OperandCandidate = (&'static str, Vec<u8>);

/// All operand-minimization candidates for a program, in deterministic
/// order: immediate shrinking (pc-ascending, pool order), ALU X→K,
/// register lowering, stack-offset shrinking.
pub fn operand_candidates(bytes: &[u8]) -> Vec<OperandCandidate> {
    let Some(insns) = decode(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // 1. immediate shrinking
    for (pc, insn) in insns.iter().enumerate() {
        let Some(orig) = imm_of(insn) else {
            continue;
        };
        for &value in &VALUE_POOL {
            if value == orig || value.unsigned_abs() >= orig.unsigned_abs() {
                continue; // strictly smaller magnitude only
            }
            let mut chunk = encode(insn).to_vec();
            chunk[4..8].copy_from_slice(&value.to_le_bytes());
            out.push(("immediate", patch(bytes, pc, &chunk)));
        }
    }

    // 2. ALU X→K: a known-constant source register becomes the imm
    let mut known: [Option<i32>; 11] = [None; 11];
    for (pc, insn) in insns.iter().enumerate() {
        if let Some(src) = x_form_source(insn)
            && let Some(value) = known[src as usize]
        {
            let mut chunk = encode(insn).to_vec();
            chunk[0] &= !0x08; // BPF_SRC bit: X → K
            chunk[1] &= 0x0f; // src_reg = 0 (reserved for K forms)
            chunk[4..8].copy_from_slice(&value.to_le_bytes());
            out.push(("alu-form", patch(bytes, pc, &chunk)));
        }
        apply_def(&mut known, insn);
    }

    // 3. register lowering: highest used → lowest unused (R0/R10 fixed)
    if let Some((from, to)) = lowering_pair(&insns) {
        let rewritten: Vec<u8> = insns
            .iter()
            .flat_map(|insn| rename_reg(encode(insn), from, to))
            .collect();
        out.push(("reg-lower", rewritten));
    }

    // 4. stack-offset shrinking toward 0, 8-byte steps
    for (pc, insn) in insns.iter().enumerate() {
        let Some(offset) = stack_offset(insn) else {
            continue;
        };
        let mag = (offset.abs() as i64) / 8;
        for k in 1..mag {
            let value = if offset < 0 { -(k * 8) } else { k * 8 };
            let mut chunk = encode(insn).to_vec();
            chunk[2..4].copy_from_slice(&(value as i16).to_le_bytes());
            out.push(("stack-offset", patch(bytes, pc, &chunk)));
        }
    }

    out
}

/// The imm of an instruction that carries one (K-form ALUs/MOV, imm
/// compares) — `None` for everything else (X-forms reserve imm, CALL
/// imm is the helper id, LD/ST/JMP/EXIT have no imm).
fn imm_of(insn: &BpfInsn) -> Option<i32> {
    match insn {
        BpfInsn::MovImm { imm, .. }
        | BpfInsn::AddImm { imm, .. }
        | BpfInsn::SubImm { imm, .. }
        | BpfInsn::AndImm { imm, .. }
        | BpfInsn::OrImm { imm, .. }
        | BpfInsn::XorImm { imm, .. }
        | BpfInsn::LshImm { imm, .. }
        | BpfInsn::RshImm { imm, .. }
        | BpfInsn::ArshImm { imm, .. }
        | BpfInsn::Add32Imm { imm, .. }
        | BpfInsn::Sub32Imm { imm, .. }
        | BpfInsn::And32Imm { imm, .. }
        | BpfInsn::Or32Imm { imm, .. }
        | BpfInsn::Xor32Imm { imm, .. }
        | BpfInsn::Lsh32Imm { imm, .. }
        | BpfInsn::Rsh32Imm { imm, .. }
        | BpfInsn::Arsh32Imm { imm, .. }
        | BpfInsn::JeqImm { imm, .. }
        | BpfInsn::JneImm { imm, .. }
        | BpfInsn::JgtImm { imm, .. }
        | BpfInsn::JgeImm { imm, .. }
        | BpfInsn::JltImm { imm, .. }
        | BpfInsn::JleImm { imm, .. }
        | BpfInsn::JsgtImm { imm, .. }
        | BpfInsn::JsgeImm { imm, .. }
        | BpfInsn::JsltImm { imm, .. }
        | BpfInsn::JsleImm { imm, .. } => Some(*imm),
        _ => None,
    }
}

/// The source register of a register-form (X) ALU — `None` for
/// everything else.
fn x_form_source(insn: &BpfInsn) -> Option<u8> {
    match insn {
        BpfInsn::MovReg { src, .. }
        | BpfInsn::AddReg { src, .. }
        | BpfInsn::SubReg { src, .. }
        | BpfInsn::AndReg { src, .. }
        | BpfInsn::OrReg { src, .. }
        | BpfInsn::XorReg { src, .. }
        | BpfInsn::LshReg { src, .. }
        | BpfInsn::RshReg { src, .. }
        | BpfInsn::ArshReg { src, .. }
        | BpfInsn::Add32Reg { src, .. }
        | BpfInsn::Sub32Reg { src, .. }
        | BpfInsn::And32Reg { src, .. }
        | BpfInsn::Or32Reg { src, .. }
        | BpfInsn::Xor32Reg { src, .. }
        | BpfInsn::Lsh32Reg { src, .. }
        | BpfInsn::Rsh32Reg { src, .. }
        | BpfInsn::Arsh32Reg { src, .. } => Some(*src),
        _ => None,
    }
}

/// Apply the register definition of one instruction to the known-
/// constant map (a value is known only when written by `MOV64 imm`;
/// anything else clears it; MOV copies; CALL clobbers R0..R5).
fn apply_def(known: &mut [Option<i32>; 11], insn: &BpfInsn) {
    match insn {
        BpfInsn::MovImm { dst, imm } => known[*dst as usize] = Some(*imm),
        BpfInsn::MovReg { dst, src } => known[*dst as usize] = known[*src as usize],
        BpfInsn::Call { .. } => {
            for slot in known.iter_mut().take(6) {
                *slot = None;
            }
        }
        BpfInsn::LdMem { dst, .. } => known[*dst as usize] = None,
        BpfInsn::StMem { .. } => {}
        // every ALU write and the exit produce/require non-constants
        insn if has_alu_dst(insn) => {
            if let Some(dst) = alu_dst(insn) {
                known[dst as usize] = None;
            }
        }
        _ => {}
    }
}

/// Whether an instruction writes an ALU destination register.
fn has_alu_dst(insn: &BpfInsn) -> bool {
    !matches!(
        insn,
        BpfInsn::Call { .. } | BpfInsn::Exit | BpfInsn::Jmp { .. } | BpfInsn::StMem { .. }
    ) && !insn.is_conditional_branch()
}

/// The destination register of an ALU/MOV/load instruction.
fn alu_dst(insn: &BpfInsn) -> Option<u8> {
    match insn {
        BpfInsn::MovImm { dst, .. }
        | BpfInsn::MovReg { dst, .. }
        | BpfInsn::AddImm { dst, .. }
        | BpfInsn::AddReg { dst, .. }
        | BpfInsn::SubImm { dst, .. }
        | BpfInsn::SubReg { dst, .. }
        | BpfInsn::AndImm { dst, .. }
        | BpfInsn::AndReg { dst, .. }
        | BpfInsn::OrImm { dst, .. }
        | BpfInsn::OrReg { dst, .. }
        | BpfInsn::XorImm { dst, .. }
        | BpfInsn::XorReg { dst, .. }
        | BpfInsn::LshImm { dst, .. }
        | BpfInsn::LshReg { dst, .. }
        | BpfInsn::RshImm { dst, .. }
        | BpfInsn::RshReg { dst, .. }
        | BpfInsn::ArshImm { dst, .. }
        | BpfInsn::ArshReg { dst, .. }
        | BpfInsn::Add32Imm { dst, .. }
        | BpfInsn::Add32Reg { dst, .. }
        | BpfInsn::Sub32Imm { dst, .. }
        | BpfInsn::Sub32Reg { dst, .. }
        | BpfInsn::And32Imm { dst, .. }
        | BpfInsn::And32Reg { dst, .. }
        | BpfInsn::Or32Imm { dst, .. }
        | BpfInsn::Or32Reg { dst, .. }
        | BpfInsn::Xor32Imm { dst, .. }
        | BpfInsn::Xor32Reg { dst, .. }
        | BpfInsn::Lsh32Imm { dst, .. }
        | BpfInsn::Lsh32Reg { dst, .. }
        | BpfInsn::Rsh32Imm { dst, .. }
        | BpfInsn::Rsh32Reg { dst, .. }
        | BpfInsn::Arsh32Imm { dst, .. }
        | BpfInsn::Arsh32Reg { dst, .. }
        | BpfInsn::LdMem { dst, .. } => Some(*dst),
        _ => None,
    }
}

/// The stack offset of a stack load/store — `None` for everything else.
fn stack_offset(insn: &BpfInsn) -> Option<i16> {
    match insn {
        BpfInsn::LdMem { offset, .. } | BpfInsn::StMem { offset, .. } => Some(*offset),
        _ => None,
    }
}

/// The (from, to) register-lowering pair: the highest used register
/// in R1..R9 renamed to the lowest unused one. R0 (exit convention)
/// and R10 (frame pointer) are never renamed. `None` when every used
/// register already sits as low as possible.
fn lowering_pair(insns: &[BpfInsn]) -> Option<(u8, u8)> {
    let mut used = [false; 11];
    for insn in insns {
        mark_regs(&mut used, insn);
    }
    let highest = (1..=9).rev().find(|&r| used[r as usize])?;
    let lowest_unused = (1..=9).find(|&r| !used[r as usize] && r < highest)?;
    Some((highest, lowest_unused))
}

/// Mark every register an instruction references (R0 and R10 included
/// for the *usage* census — they are excluded from renaming).
fn mark_regs(used: &mut [bool; 11], insn: &BpfInsn) {
    match insn {
        BpfInsn::MovImm { dst, .. }
        | BpfInsn::AddImm { dst, .. }
        | BpfInsn::SubImm { dst, .. }
        | BpfInsn::AndImm { dst, .. }
        | BpfInsn::OrImm { dst, .. }
        | BpfInsn::XorImm { dst, .. }
        | BpfInsn::LshImm { dst, .. }
        | BpfInsn::RshImm { dst, .. }
        | BpfInsn::ArshImm { dst, .. }
        | BpfInsn::Add32Imm { dst, .. }
        | BpfInsn::Sub32Imm { dst, .. }
        | BpfInsn::And32Imm { dst, .. }
        | BpfInsn::Or32Imm { dst, .. }
        | BpfInsn::Xor32Imm { dst, .. }
        | BpfInsn::Lsh32Imm { dst, .. }
        | BpfInsn::Rsh32Imm { dst, .. }
        | BpfInsn::Arsh32Imm { dst, .. }
        | BpfInsn::LdMem { dst, .. }
        | BpfInsn::LdImm64 { dst, .. }
        | BpfInsn::LdMapFd { dst, .. }
        | BpfInsn::LdMapValue { dst, .. } => used[*dst as usize] = true,
        BpfInsn::LdImm64Second { .. } => {}
        BpfInsn::MovReg { dst, src }
        | BpfInsn::AddReg { dst, src }
        | BpfInsn::SubReg { dst, src }
        | BpfInsn::AndReg { dst, src }
        | BpfInsn::OrReg { dst, src }
        | BpfInsn::XorReg { dst, src }
        | BpfInsn::LshReg { dst, src }
        | BpfInsn::RshReg { dst, src }
        | BpfInsn::ArshReg { dst, src }
        | BpfInsn::Add32Reg { dst, src }
        | BpfInsn::Sub32Reg { dst, src }
        | BpfInsn::And32Reg { dst, src }
        | BpfInsn::Or32Reg { dst, src }
        | BpfInsn::Xor32Reg { dst, src }
        | BpfInsn::Lsh32Reg { dst, src }
        | BpfInsn::Rsh32Reg { dst, src }
        | BpfInsn::Arsh32Reg { dst, src } => {
            used[*dst as usize] = true;
            used[*src as usize] = true;
        }
        BpfInsn::StMem { src, .. } => used[*src as usize] = true,
        BpfInsn::Jeq { dst, src, .. }
        | BpfInsn::Jne { dst, src, .. }
        | BpfInsn::Jgt { dst, src, .. }
        | BpfInsn::Jge { dst, src, .. }
        | BpfInsn::Jlt { dst, src, .. }
        | BpfInsn::Jle { dst, src, .. }
        | BpfInsn::Jsgt { dst, src, .. }
        | BpfInsn::Jsge { dst, src, .. }
        | BpfInsn::Jslt { dst, src, .. }
        | BpfInsn::Jsle { dst, src, .. } => {
            used[*dst as usize] = true;
            used[*src as usize] = true;
        }
        BpfInsn::JeqImm { dst, .. }
        | BpfInsn::JneImm { dst, .. }
        | BpfInsn::JgtImm { dst, .. }
        | BpfInsn::JgeImm { dst, .. }
        | BpfInsn::JltImm { dst, .. }
        | BpfInsn::JleImm { dst, .. }
        | BpfInsn::JsgtImm { dst, .. }
        | BpfInsn::JsgeImm { dst, .. }
        | BpfInsn::JsltImm { dst, .. }
        | BpfInsn::JsleImm { dst, .. } => used[*dst as usize] = true,
        BpfInsn::Jmp { .. } | BpfInsn::Call { .. } | BpfInsn::Exit => {}
    }
}

/// Rename register `from` → `to` in one encoded instruction (register
/// fields live in byte 1: dst = low nibble, src = high nibble).
fn rename_reg(mut chunk: [u8; 8], from: u8, to: u8) -> [u8; 8] {
    let dst = chunk[1] & 0x0f;
    let src = chunk[1] >> 4;
    let new_dst = if dst == from { to } else { dst };
    let new_src = if src == from { to } else { src };
    chunk[1] = (new_src << 4) | new_dst;
    chunk
}

/// Replace one encoded instruction in the raw program.
fn patch(bytes: &[u8], pc: usize, chunk: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[pc * 8..pc * 8 + 8].copy_from_slice(chunk);
    out
}

fn decode(bytes: &[u8]) -> Option<Vec<BpfInsn>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return None;
    }
    bytes
        .chunks_exact(8)
        .map(parse_insn)
        .collect::<Result<_, _>>()
        .ok()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::parse_insn;
    use crate::testutil::{insn_bytes, prog_bytes};

    fn decode_all(bytes: &[u8]) -> Vec<BpfInsn> {
        bytes
            .chunks_exact(8)
            .map(|c| parse_insn(c).unwrap())
            .collect()
    }

    #[test]
    fn immediate_shrinking_candidates() {
        // r0 = 12345; exit — 0, 1, -1 are strictly smaller
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 12345),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = operand_candidates(&bytes);
        let values: Vec<(usize, i32)> = candidates
            .iter()
            .filter(|(name, _)| *name == "immediate")
            .map(|(_, c)| {
                let insns = decode_all(c);
                match insns[0] {
                    BpfInsn::MovImm { imm, .. } => (0, imm),
                    _ => panic!("unexpected insn"),
                }
            })
            .collect();
        assert!(values.contains(&(0, 0)));
        assert!(values.contains(&(0, 1)));
        assert!(values.contains(&(0, -1)));
        // nothing equal or larger
        assert!(
            !values
                .iter()
                .any(|&(_, v)| v == 12345 || v.unsigned_abs() > 12345)
        );
    }

    #[test]
    fn call_imm_never_rewritten() {
        // call 2 must keep its helper id
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x85, 0, 0, 0, 2), // call 2
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        for (_, candidate) in operand_candidates(&bytes) {
            let insns = decode_all(&candidate);
            for insn in &insns {
                if let BpfInsn::Call { imm } = insn {
                    assert_eq!(*imm, 2);
                }
            }
        }
    }

    #[test]
    fn alu_x_form_to_k_form() {
        // r2 = 5; r1 += r2 → r1 += 5 (the constant is known)
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 2, 0, 0, 5),
            insn_bytes(0x0f, 1, 2, 0, 0), // r1 += r2
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = operand_candidates(&bytes);
        assert!(
            candidates.iter().any(|(name, c)| {
                *name == "alu-form"
                    && matches!(decode_all(c)[1], BpfInsn::AddImm { dst: 1, imm: 5 })
            }),
            "expected an alu-form candidate, got {candidates:?}"
        );
    }

    #[test]
    fn alu_x_form_uses_latest_known_constant() {
        // r2 = 5; r2 = 9; r1 += r2 — the known value at the use is the
        // latest MovImm (9), and the rewrite is exactly that
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 2, 0, 0, 5),
            insn_bytes(0xb7, 2, 0, 0, 9),
            insn_bytes(0x0f, 1, 2, 0, 0),
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert!(
            operand_candidates(&bytes).iter().any(|(name, c)| {
                *name == "alu-form"
                    && matches!(decode_all(c)[2], BpfInsn::AddImm { dst: 1, imm: 9 })
            }),
            "the rewrite must use the latest known constant (9)"
        );
    }

    #[test]
    fn alu_x_form_cleared_by_alu_write() {
        // r2 = 5; r2 += 1; r1 += r2 — r2 is computed, not a constant
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 2, 0, 0, 5),
            insn_bytes(0x07, 2, 0, 0, 1), // r2 += 1
            insn_bytes(0x0f, 1, 2, 0, 0),
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert!(
            !operand_candidates(&bytes)
                .iter()
                .any(|(name, _)| *name == "alu-form")
        );
    }

    #[test]
    fn register_lowering_moves_high_to_low() {
        // r9 = 1; r0 = r9; exit — r9 lowers to the lowest unused (r1)
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 9, 0, 0, 1),
            insn_bytes(0xbf, 0, 9, 0, 0), // r0 = r9
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = operand_candidates(&bytes);
        assert!(
            candidates.iter().any(|(name, c)| {
                *name == "reg-lower"
                    && decode_all(c)
                        .iter()
                        .all(|i| !matches!(i, BpfInsn::MovImm { dst: 9, .. }))
            }),
            "expected a reg-lower candidate, got {candidates:?}"
        );
    }

    #[test]
    fn register_lowering_keeps_r10_and_r0() {
        // r9 = 5; [r10-8] = r9; r0 = [r10-8]; exit — R10 and R0 fixed
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 9, 0, 0, 5),
            insn_bytes(0x7b, 10, 9, -8, 0), // [r10-8] = r9
            insn_bytes(0x79, 0, 10, -8, 0), // r0 = [r10-8]
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = operand_candidates(&bytes);
        let lower = candidates
            .iter()
            .find(|(name, _)| *name == "reg-lower")
            .expect("expected a reg-lower candidate");
        for insn in decode_all(&lower.1) {
            match insn {
                BpfInsn::StMem {
                    src,
                    base: 10,
                    offset,
                } => {
                    assert_eq!(offset, -8);
                    assert_ne!(src, 10);
                }
                BpfInsn::LdMem {
                    dst,
                    base: 10,
                    offset,
                } => {
                    assert_eq!(offset, -8);
                    assert_eq!(dst, 0);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn register_lowering_none_when_compact() {
        // r1 = 1; r0 = r1; exit — no lowering possible
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 1),
            insn_bytes(0xbf, 0, 1, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert!(
            !operand_candidates(&bytes)
                .iter()
                .any(|(name, _)| *name == "reg-lower")
        );
    }

    #[test]
    fn stack_offset_shrinks_toward_zero() {
        // [r10-80] = r1; r0 = [r10-80]; exit
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x7b, 10, 1, -80, 0),
            insn_bytes(0x79, 0, 10, -80, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = operand_candidates(&bytes);
        // collect the patched stack offsets from both stack insns
        let mut offsets = Vec::new();
        for (name, c) in &candidates {
            if *name != "stack-offset" {
                continue;
            }
            for insn in decode_all(c) {
                if let BpfInsn::StMem { offset, .. } | BpfInsn::LdMem { offset, .. } = insn
                    && offset != -80
                {
                    offsets.push(offset); // the patched one
                }
            }
        }
        assert!(offsets.contains(&-8));
        assert!(offsets.contains(&-16));
        assert!(
            offsets.iter().all(|&o| o > -80 && o < 0 && o % 8 == 0),
            "unexpected offsets: {offsets:?}"
        );
    }

    #[test]
    fn operand_candidates_are_deterministic() {
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 9, 0, 0, 12345),
            insn_bytes(0x7b, 10, 9, -40, 0),
            insn_bytes(0x0f, 1, 9, 0, 0),
            insn_bytes(0x79, 0, 10, -40, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(operand_candidates(&bytes), operand_candidates(&bytes));
    }

    #[test]
    fn operand_candidates_rewritten_programs_decode() {
        // every candidate must be a valid instruction stream
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 2, 0, 0, 7),
            insn_bytes(0x1f, 3, 2, 0, 0), // r3 -= r2
            insn_bytes(0x7b, 10, 3, -24, 0),
            insn_bytes(0x79, 0, 10, -24, 0),
            insn_bytes(0xb7, 1, 0, 0, 999999),
            insn_bytes(0x5d, 1, 3, 2, 0), // if r1 != r3 goto +2
            insn_bytes(0x95, 0, 0, 0, 0),
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        for (name, candidate) in operand_candidates(&bytes) {
            let insns = decode_all(&candidate);
            assert_eq!(insns.len(), 9, "{name}: bad decode");
        }
    }
}
