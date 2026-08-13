// ── Instruction deletion with branch-offset fixup (v0.8, #77) ───────────────

//! Every reduction pass deletes instructions, but eBPF branch offsets
//! are relative to the next instruction (`branch_target = pc + 1 + off`,
//! the kernel convention), so raw deletion silently rewrites the
//! program. This module is the one correct deletion primitive: delete
//! an arbitrary set of instruction indices, re-base every `BPF_JMP`
//! offset, and leave everything else (CALL imm = helper id, LD/ST stack
//! offsets) untouched. Deletions that would make a jump target escape
//! (target removed, target out of range, offset out of i16) return
//! `None` — the caller's oracle decides what to do next.

use crate::fuzz::insn_lib::encode;
use crate::insn::{BpfInsn, parse_insn};

/// Delete a set of instructions from a raw bytecode stream, re-basing
/// branch offsets (`pc + 1 + off`, kernel convention).
///
/// - `remove` may be unsorted and contain duplicates — treated as a set.
/// - A surviving branch whose target was removed, or whose re-based
///   offset would leave the program or overflow `i16`, yields `None`
///   (the deletion is rejected, not silently reinterpreted).
/// - CALL imm (helper id) and LD/ST stack offsets are never touched.
/// - Deterministic: same input + same set → byte-identical output.
pub fn delete_insns(bytes: &[u8], remove: &[u32]) -> Option<Vec<u8>> {
    if !bytes.len().is_multiple_of(8) || bytes.is_empty() {
        return None;
    }
    let len = (bytes.len() / 8) as u32;

    // decode (the caller's programs are replay-valid, so a decode
    // failure is a defensive None)
    let mut insns = Vec::with_capacity(len as usize);
    for chunk in bytes.chunks_exact(8) {
        insns.push(parse_insn(chunk).ok()?);
    }

    // normalize the removal set
    let mut remove: Vec<u32> = remove.to_vec();
    remove.sort_unstable();
    remove.dedup();
    if remove.iter().any(|&i| i >= len) {
        return None;
    }
    let removed: std::collections::BTreeSet<u32> = remove.iter().copied().collect();

    // old index -> new index (None when removed)
    let mut new_index = vec![None; len as usize];
    let mut next: u32 = 0;
    for old in 0..len {
        if !removed.contains(&old) {
            new_index[old as usize] = Some(next);
            next += 1;
        }
    }

    let mut out = Vec::with_capacity(next as usize * 8);
    for old in 0..len {
        let Some(new_idx) = new_index[old as usize] else {
            continue;
        };
        let insn = &insns[old as usize];
        let mut chunk = encode(insn).to_vec();
        if let Some(offset) = branch_offset(insn) {
            // kernel semantics: target = pc + 1 + off
            let target = old as i64 + 1 + offset as i64;
            if target < 0 || target >= len as i64 {
                return None;
            }
            let Some(new_target) = new_index[target as usize] else {
                return None; // the jump target was deleted
            };
            let new_off = new_target as i64 - new_idx as i64 - 1;
            let Ok(new_off) = i16::try_from(new_off) else {
                return None; // the re-based offset no longer fits
            };
            chunk[2..4].copy_from_slice(&new_off.to_le_bytes());
        }
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// The code offset of a branch instruction — `None` for everything
/// else (ALU/MOV/LD/ST: their offset field is a stack offset or zero;
/// CALL/EXIT: off must be 0 and is never re-based).
pub(crate) fn branch_offset(insn: &BpfInsn) -> Option<i16> {
    match insn {
        BpfInsn::Jmp { offset } => Some(*offset),
        BpfInsn::Jeq { offset, .. }
        | BpfInsn::Jne { offset, .. }
        | BpfInsn::Jgt { offset, .. }
        | BpfInsn::Jge { offset, .. }
        | BpfInsn::Jlt { offset, .. }
        | BpfInsn::Jle { offset, .. }
        | BpfInsn::Jsgt { offset, .. }
        | BpfInsn::Jsge { offset, .. }
        | BpfInsn::Jslt { offset, .. }
        | BpfInsn::Jsle { offset, .. }
        | BpfInsn::JeqImm { offset, .. }
        | BpfInsn::JneImm { offset, .. }
        | BpfInsn::JgtImm { offset, .. }
        | BpfInsn::JgeImm { offset, .. }
        | BpfInsn::JltImm { offset, .. }
        | BpfInsn::JleImm { offset, .. }
        | BpfInsn::JsgtImm { offset, .. }
        | BpfInsn::JsgeImm { offset, .. }
        | BpfInsn::JsltImm { offset, .. }
        | BpfInsn::JsleImm { offset, .. } => Some(*offset),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::generator::{GenConfig, Generator};
    use crate::fuzz::prng::SplitMix64;
    use crate::testutil::{insn_bytes, prog_bytes};

    fn insns(bytes: &[u8]) -> Vec<BpfInsn> {
        bytes
            .chunks_exact(8)
            .map(|c| parse_insn(c).unwrap())
            .collect()
    }

    /// The decoded jump target of every branch: `(src, target)` pairs.
    fn jump_targets(bytes: &[u8]) -> Vec<(u32, u32)> {
        let insns = insns(bytes);
        let mut out = Vec::new();
        for (i, insn) in insns.iter().enumerate() {
            if let Some(off) = branch_offset(insn) {
                let target = i as i64 + 1 + off as i64;
                assert!(target >= 0, "branch target before the program start");
                out.push((i as u32, target as u32));
            }
        }
        out
    }

    // ── basic behavior ──────────────────────────────────────────────────────

    #[test]
    fn delete_middle_insn_adjusts_offsets() {
        // r0 = 0; jeq r0, 0 +2; r1 = 1; r0 = 2; exit
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x15, 0, 0, 2, 0), // if r0 == 0 goto +2 (→ insn 4)
            insn_bytes(0xb7, 1, 0, 0, 1),
            insn_bytes(0xb7, 0, 0, 0, 2),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        // delete insn 2 (r1 = 1): the branch now skips only r0 = 2
        let out = delete_insns(&bytes, &[2]).unwrap();
        let decoded = insns(&out);
        assert_eq!(decoded.len(), 4);
        match &decoded[1] {
            BpfInsn::JeqImm { offset, .. } => assert_eq!(*offset, 1),
            other => panic!("expected jeq, got {other:?}"),
        }
        assert!(jump_targets(&out).contains(&(1, 3)));
    }

    #[test]
    fn delete_branch_target_rejected() {
        // r0 = 0; jmp +1; r1 = 1; exit — the jmp's target is insn 3
        // (kernel pc + 1 + off); deleting it must be rejected
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x05, 0, 0, 1, 0), // jmp +1 → insn 3
            insn_bytes(0xb7, 1, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert!(delete_insns(&bytes, &[3]).is_none());
        // deleting a non-target insn stays fine
        assert!(delete_insns(&bytes, &[2]).is_some());
    }

    #[test]
    fn empty_deletion_is_identity() {
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)]);
        assert_eq!(delete_insns(&bytes, &[]).unwrap(), bytes);
    }

    #[test]
    fn delete_everything_leaves_one_or_empty() {
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 1), insn_bytes(0x95, 0, 0, 0, 0)]);
        // deleting both is allowed — the caller's oracle rejects the
        // result (an empty program), the fixup itself never panics
        let out = delete_insns(&bytes, &[0, 1]).unwrap();
        assert!(out.is_empty());
        // deleting one leaves one instruction
        let out = delete_insns(&bytes, &[0]).unwrap();
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn call_imm_and_stack_offsets_untouched() {
        // r1 = 5; [r10-8] = r1; r0 = [r10-8]; call 1; exit — with a
        // dead branch in between that gets deleted
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x7b, 10, 1, -8, 0), // [r10-8] = r1
            insn_bytes(0x05, 0, 0, 1, 0),   // jmp +1 (dead hop)
            insn_bytes(0x79, 0, 10, -8, 0), // r0 = [r10-8]
            insn_bytes(0x85, 0, 0, 0, 1),   // call 1
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let out = delete_insns(&bytes, &[2]).unwrap();
        let decoded = insns(&out);
        assert_eq!(decoded.len(), 5);
        assert!(matches!(
            decoded[1],
            BpfInsn::StStack { src: 1, offset: -8 }
        ));
        assert!(matches!(
            decoded[2],
            BpfInsn::LdStack { dst: 0, offset: -8 }
        ));
        assert!(matches!(decoded[3], BpfInsn::Call { imm: 1 }));
    }

    #[test]
    fn unsorted_and_duplicate_removal_set() {
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0xb7, 1, 0, 0, 1),
            insn_bytes(0xb7, 2, 0, 0, 2),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let out = delete_insns(&bytes, &[2, 0, 2]).unwrap();
        assert_eq!(out.len(), 16);
        assert!(matches!(insns(&out)[0], BpfInsn::MovImm { dst: 1, .. }));
    }

    #[test]
    fn invalid_inputs_rejected() {
        // not a multiple of 8
        assert!(delete_insns(&[0u8; 7], &[]).is_none());
        // empty input
        assert!(delete_insns(&[], &[]).is_none());
        // out-of-range removal index
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 1)]);
        assert!(delete_insns(&bytes, &[5]).is_none());
        // undecodable input
        assert!(delete_insns(&[0xef, 0, 0, 0, 0, 0, 0, 0], &[]).is_none());
    }

    // ── property: fixup preserves kernel-identical jump targets ────────────

    /// Random framed programs (reusing the v0.7 generator) and random
    /// deletion sets: the fixup must preserve kernel-identical jump
    /// *targets* — for every surviving branch, the re-based target
    /// index must equal the mapped original target index. (Decoded
    /// instruction *text* comparison is too strict: a branch that is
    /// itself a jump target has its offset re-based too.)
    #[test]
    fn fixup_preserves_jump_targets_1000_cases() {
        let cfg = GenConfig {
            min_len: 8,
            max_len: 60,
        };
        let mut kept = 0;
        let mut rejected = 0;
        for seed in 0..1000u64 {
            let mut generator = Generator::new(seed);
            let program = generator.gen_mixed_program(&cfg, 30);
            let bytes: Vec<u8> = program.iter().flat_map(encode).collect();

            let mut rng = SplitMix64::new(seed.wrapping_mul(0x9E37_79B9));
            let mut remove = Vec::new();
            for i in 0..program.len() {
                if rng.below(4) == 0 {
                    remove.push(i as u32);
                }
            }
            // keep the deletion meaningful: at least one instruction
            if remove.is_empty() {
                remove.push(rng.below(program.len() as u64) as u32);
            }

            let Some(out) = delete_insns(&bytes, &remove) else {
                rejected += 1;
                continue;
            };
            kept += 1;

            // the old->new index map (same rule as the fixup)
            let mut remove = remove.clone();
            remove.sort_unstable();
            remove.dedup();
            let removed: std::collections::BTreeSet<u32> = remove.iter().copied().collect();
            let mut mapped = vec![None; program.len()];
            let mut next = 0u32;
            for (old, slot) in mapped.iter_mut().enumerate() {
                if !removed.contains(&(old as u32)) {
                    *slot = Some(next);
                    next += 1;
                }
            }

            // every output chunk decodes cleanly (no reserved-field
            // violations introduced by the re-base)
            let new_insns = insns(&out);
            assert_eq!(new_insns.len(), next as usize, "seed {seed}");

            // every surviving branch's re-based target equals the
            // mapped original target
            let new_branches = jump_targets(&out);
            let expect_branches = jump_targets(&bytes)
                .iter()
                .filter(|(src, _)| !removed.contains(src))
                .count();
            assert_eq!(new_branches.len(), expect_branches, "seed {seed}");
            for (src, target) in jump_targets(&bytes) {
                let Some(new_src) = mapped[src as usize] else {
                    continue; // deleted branch
                };
                let Some(new_target) = mapped[target as usize] else {
                    panic!("seed {seed}: fixup kept a branch to a deleted target");
                };
                assert!(
                    new_branches.contains(&(new_src, new_target)),
                    "seed {seed}: branch {src}->{target} became {new_src}->? — target changed"
                );
            }
        }
        // the test must actually exercise both paths
        assert!(kept > 300, "too few successful deletions ({kept})");
        assert!(
            rejected > 300,
            "no rejected deletions — property too weak ({rejected})"
        );
    }

    #[test]
    fn fixup_is_deterministic() {
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x15, 0, 0, 2, 0),
            insn_bytes(0xb7, 1, 0, 0, 1),
            insn_bytes(0xb7, 0, 0, 0, 2),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let a = delete_insns(&bytes, &[2]).unwrap();
        let b = delete_insns(&bytes, &[2]).unwrap();
        assert_eq!(a, b);
    }
}
