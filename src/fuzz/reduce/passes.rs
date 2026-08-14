// ── CFG-level reduction passes (v0.8, #79) ───────────────────────────────────

//! Cheap structural passes that shrink a program before (and between)
//! ddmin rounds, using only the decoded CFG:
//!
//! - **backward slice** — keep only instructions on a path to the
//!   failure anchor (the mini failure pc, or the concrete violation
//!   pc), plus the exits, so the program stays structurally valid;
//! - **dead-code elimination** — drop instructions unreachable from
//!   entry;
//! - **branch simplification** — a conditional branch with a statically
//!   dead side becomes the live side's unconditional jump (or is
//!   deleted), opening the dead region to the next slice.
//!
//! Passes emit *candidates* — the driver's oracle validates each one
//! and rolls back failures (the v0.8 design: passes are aggressive,
//! the oracle is the filter). All candidates are deterministic:
//! index-ascending.

use crate::fuzz::insn_lib::encode;
use crate::fuzz::reduce::fixup::{branch_offset, delete_insns};
use crate::insn::BpfInsn;

/// The successors of one instruction in the decoded CFG. Both sides of
/// a conditional branch are explored (like the verifier); out-of-range
/// targets contribute nothing.
fn successors(insns: &[BpfInsn], pc: u32) -> Vec<u32> {
    let insn = &insns[pc as usize];
    let len = insns.len() as i64;
    let mut out = Vec::with_capacity(2);
    match insn {
        BpfInsn::Exit => {}
        BpfInsn::Jmp { offset } => {
            let target = pc as i64 + 1 + *offset as i64;
            if (0..len).contains(&target) {
                out.push(target as u32);
            }
        }
        insn if insn.is_conditional_branch() => {
            if (pc + 1) < insns.len() as u32 {
                out.push(pc + 1);
            }
            if let Some(offset) = branch_offset(insn) {
                let target = pc as i64 + 1 + offset as i64;
                if (0..len).contains(&target) {
                    out.push(target as u32);
                }
            }
        }
        _ => {
            if (pc + 1) < insns.len() as u32 {
                out.push(pc + 1);
            }
        }
    }
    out
}

/// Forward reachability from entry (pc 0). `skip_edge` removes one
/// edge from the traversal — the "is this side dead?" test.
fn reachable(insns: &[BpfInsn], skip_edge: Option<(u32, u32)>) -> Vec<bool> {
    let mut seen = vec![false; insns.len()];
    if insns.is_empty() {
        return seen;
    }
    let mut stack = vec![0u32];
    while let Some(pc) = stack.pop() {
        let pc = pc as usize;
        if pc >= insns.len() || seen[pc] {
            continue;
        }
        seen[pc] = true;
        for next in successors(insns, pc as u32) {
            if next as usize >= insns.len() {
                continue;
            }
            if skip_edge == Some((pc as u32, next)) {
                continue;
            }
            stack.push(next);
        }
    }
    seen
}

/// Backward reachability: the set of instructions from which `anchor`
/// is reachable (the reverse of `successors`).
fn backward_reachable(insns: &[BpfInsn], anchor: u32) -> Vec<bool> {
    let mut preds = vec![Vec::new(); insns.len()];
    for pc in 0..insns.len() {
        for next in successors(insns, pc as u32) {
            if (next as usize) < insns.len() {
                preds[next as usize].push(pc as u32);
            }
        }
    }
    let mut seen = vec![false; insns.len()];
    let mut stack = vec![anchor];
    while let Some(pc) = stack.pop() {
        let pc = pc as usize;
        if pc >= insns.len() || seen[pc] {
            continue;
        }
        seen[pc] = true;
        stack.extend(preds[pc].iter().copied());
    }
    seen
}

/// The failure anchor of a program: the mini failure instruction, or
/// the first concrete coverage-violation pc when mini accepts (the
/// rv-soundness-bug shape). `None` for accepted, concretely safe
/// programs — those get no slice.
pub fn failure_anchor(bytes: &[u8]) -> Option<u32> {
    let mut env = crate::env::BpfVerifierEnv::new();
    env.setup_prog_bytes(bytes).ok()?;
    let verdict = env.verify().ok()?;
    match verdict {
        crate::error::Verdict::Unsafe(failure) => Some(failure.insn_idx()),
        _ => crate::fuzz::oracle::first_violation_pc(&env),
    }
}

/// Dead-code elimination: delete every instruction unreachable from
/// entry. `None` when nothing is unreachable (or the deletion is
/// invalid).
pub fn dead_code(bytes: &[u8]) -> Option<Vec<u8>> {
    let insns = decode(bytes)?;
    let seen = reachable(&insns, None);
    let remove: Vec<u32> = (0..insns.len() as u32)
        .filter(|&i| !seen[i as usize])
        .collect();
    if remove.is_empty() {
        return None;
    }
    delete_insns(bytes, &remove)
}

/// Backward slice: keep only instructions on a path to `anchor`, plus
/// every exit (so the program stays structurally valid and the failure
/// still sits on a fall-through path to exit). `None` when the anchor
/// is missing/out of range or nothing can be removed.
pub fn slice_to_anchor(bytes: &[u8], anchor: Option<u32>) -> Option<Vec<u8>> {
    let insns = decode(bytes)?;
    let anchor = anchor?;
    if anchor as usize >= insns.len() {
        return None;
    }
    let mut keep = backward_reachable(&insns, anchor);
    for (i, insn) in insns.iter().enumerate() {
        if matches!(insn, BpfInsn::Exit) {
            keep[i] = true;
        }
    }
    let remove: Vec<u32> = (0..insns.len() as u32)
        .filter(|&i| !keep[i as usize])
        .collect();
    if remove.is_empty() {
        return None;
    }
    delete_insns(bytes, &remove)
}

/// Branch simplification: one candidate per conditional branch with a
/// statically dead side (unreachable from entry without that branch's
/// edge). A dead fall-through makes the branch an unconditional jump;
/// a dead target makes the branch deletable. Candidates are returned
/// in pc-ascending order; the driver's oracle keeps the first that
/// preserves the finding.
pub fn simplify_dead_side(bytes: &[u8]) -> Vec<Vec<u8>> {
    let Some(insns) = decode(bytes) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for (pc, insn) in insns.iter().enumerate() {
        if !insn.is_conditional_branch() {
            continue;
        }
        let pc = pc as u32;
        let fall = pc + 1;
        let Some(offset) = branch_offset(insn) else {
            continue;
        };
        let target = pc as i64 + 1 + offset as i64;
        if target < 0 || target >= insns.len() as i64 {
            continue;
        }
        let target = target as u32;

        // the fall-through is dead: the branch always jumps
        if (fall as usize) < insns.len() && !reachable(&insns, Some((pc, fall)))[fall as usize] {
            let mut rewritten = insns.clone();
            rewritten[pc as usize] = BpfInsn::Jmp { offset };
            candidates.push(encode_all(&rewritten));
        }
        // the target is dead: the branch never jumps
        if !reachable(&insns, Some((pc, target)))[target as usize]
            && let Some(out) = delete_insns(bytes, &[pc])
        {
            candidates.push(out);
        }
    }
    candidates
}

fn decode(bytes: &[u8]) -> Option<Vec<BpfInsn>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return None;
    }
    crate::insn::decode_program(bytes).ok()
}

fn encode_all(insns: &[BpfInsn]) -> Vec<u8> {
    insns.iter().flat_map(encode).collect()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{insn_bytes, prog_bytes};

    #[test]
    fn dead_code_removes_unreachable_tail() {
        // r0 = 1; jmp +1; r1 = 5; r0 = 0; exit — the jmp's target is
        // insn 3 (pc + 1 + off), so only insn 2 (r1 = 5) is unreachable
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x05, 0, 0, 1, 0), // jmp +1 → insn 3
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let out = dead_code(&bytes).unwrap();
        let decoded: Vec<BpfInsn> = decode(&out).unwrap();
        assert_eq!(decoded.len(), 4);
        assert!(
            !decoded
                .iter()
                .any(|i| matches!(i, BpfInsn::MovImm { dst: 1, .. }))
        );
        // the jmp now points at the insn right after it
        assert!(matches!(decoded[1], BpfInsn::Jmp { offset: 0 }));
        assert!(matches!(decoded[3], BpfInsn::Exit));
    }

    #[test]
    fn dead_code_none_when_fully_reachable() {
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 1), insn_bytes(0x95, 0, 0, 0, 0)]);
        assert!(dead_code(&bytes).is_none());
    }

    #[test]
    fn slice_keeps_only_paths_to_the_failure() {
        // the taken side of the branch (r3 + its exit) never reaches
        // the failure — the slice must drop it, keeping the fall side
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 1), // r1 = 1
            insn_bytes(0xb7, 2, 0, 0, 2), // r2 = 2
            insn_bytes(0x5d, 1, 2, 2, 0), // if r1 != r2 goto +2 (→ 5)
            insn_bytes(0xb7, 3, 0, 0, 3), // r3 = 3 (taken side)
            insn_bytes(0x95, 0, 0, 0, 0), // exit (taken side)
            insn_bytes(0xb7, 4, 0, 0, 4), // r4 = 4 (fall side)
            insn_bytes(0x1f, 4, 0, 0, 0), // r4 -= r0  ← anchor (uninit)
            insn_bytes(0x95, 0, 0, 0, 0), // exit
        ]);
        let out = slice_to_anchor(&bytes, Some(6)).unwrap();
        let decoded: Vec<BpfInsn> = decode(&out).unwrap();
        // the taken side (r3) is off the failure path and removed
        assert_eq!(decoded.len(), 7, "{decoded:?}");
        assert!(
            !decoded
                .iter()
                .any(|i| matches!(i, BpfInsn::MovImm { dst: 3, .. }))
        );
        assert!(
            decoded
                .iter()
                .any(|i| matches!(i, BpfInsn::MovImm { dst: 4, .. }))
        );
    }

    #[test]
    fn slice_keeps_exits() {
        // the failure is the last insn before a jump over the exit:
        // the exit must survive the slice
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 4, 0, 0, 1), // r4 = 1
            insn_bytes(0x1f, 4, 0, 0, 0), // r4 -= r0  ← anchor
            insn_bytes(0x05, 0, 0, 1, 0), // jmp +1 → 4
            insn_bytes(0x95, 0, 0, 0, 0), // exit (3)
            insn_bytes(0x95, 0, 0, 0, 0), // exit (4)
        ]);
        let out = slice_to_anchor(&bytes, Some(1)).unwrap();
        let decoded: Vec<BpfInsn> = decode(&out).unwrap();
        assert!(
            decoded
                .iter()
                .filter(|i| matches!(i, BpfInsn::Exit))
                .count()
                >= 1
        );
    }

    #[test]
    fn slice_no_anchor_yields_nothing() {
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 1), insn_bytes(0x95, 0, 0, 0, 0)]);
        assert!(slice_to_anchor(&bytes, None).is_none());
    }

    #[test]
    fn simplify_dead_fallthrough_becomes_unconditional_jump() {
        // r0 = 0; jeq r0, 0, +3; r1 = 5; r2 = 6; exit; r0 = 1; exit
        // the fall-through (2,3,4) is only reachable via the branch —
        // dead without the branch's fall-through edge
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x15, 0, 0, 3, 0), // if r0 == 0 goto +3 (→ 5)
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0xb7, 2, 0, 0, 6),
            insn_bytes(0x95, 0, 0, 0, 0),
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = simplify_dead_side(&bytes);
        let rewritten = candidates
            .iter()
            .find(|c| decode(c).is_some_and(|d| matches!(d[1], BpfInsn::Jmp { offset: 3 })))
            .expect("a dead fall-through must rewrite the branch to a jump");
        assert_eq!(decode(rewritten).unwrap().len(), 7);
    }

    #[test]
    fn simplify_dead_target_deletes_branch() {
        // r0 = 0; jeq r0, 0, +2; r1 = 5; exit; r2 = 7; exit
        // the target (4) is only reachable via the branch — dead
        // without the branch's jump edge: the branch is deletable
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x15, 0, 0, 2, 0), // if r0 == 0 goto +2 (→ 4)
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x95, 0, 0, 0, 0),
            insn_bytes(0xb7, 2, 0, 0, 7),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = simplify_dead_side(&bytes);
        assert!(
            candidates.iter().any(|c| {
                decode(c).is_some_and(|d| {
                    !d.iter().any(|i| i.is_conditional_branch()) // the branch is gone
                })
            }),
            "the dead-target branch must be deletable"
        );
    }

    #[test]
    fn simplify_zero_offset_branch_is_deletable() {
        // jeq r0, 0, +0: taken and fall-through land on the same
        // instruction — a control-flow no-op, deletable
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x15, 0, 0, 0, 0), // if r0 == 0 goto +0
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        let candidates = simplify_dead_side(&bytes);
        assert!(
            candidates.iter().any(|c| decode(c)
                .is_some_and(|d| d.len() == 3 && !d.iter().any(|i| i.is_conditional_branch()))),
            "a zero-offset branch must be deletable"
        );
    }

    #[test]
    fn failure_anchor_finds_mini_failure_pc() {
        // uninit r4 at insn 1
        let bytes = prog_bytes(&[
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x1f, 4, 0, 0, 0), // r4 -= r0 (uninit)
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ]);
        assert_eq!(failure_anchor(&bytes), Some(1));
    }

    #[test]
    fn failure_anchor_none_on_clean_accept() {
        let bytes = prog_bytes(&[insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)]);
        assert_eq!(failure_anchor(&bytes), None);
    }

    // ── corpus-wide: reject fixtures keep their classification ─────────────

    /// The mini-reason-preserving oracle: the program must still be
    /// rejected with the same reason category as `original`.
    fn category_oracle(original: &crate::diff::SideVerdict, bytes: &[u8]) -> bool {
        let mut env = crate::env::BpfVerifierEnv::new();
        if env.setup_prog_bytes(bytes).is_err() {
            return false;
        }
        match env.verify().ok() {
            Some(crate::error::Verdict::Unsafe(failure)) => {
                crate::diff::mini_side(Some(&failure)) == *original
            }
            _ => false,
        }
    }

    #[test]
    fn corpus_reject_fixtures_survive_cfg_passes() {
        let dir = std::path::Path::new("tests/programs/reject");
        let mut checked = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            // the original classification
            let mut env = crate::env::BpfVerifierEnv::new();
            env.setup_prog_bytes(&bytes).unwrap();
            let original = match env.verify().unwrap() {
                crate::error::Verdict::Unsafe(f) => crate::diff::mini_side(Some(&f)),
                _ => continue, // reject fixtures only
            };
            let oracle = |c: &[u8]| category_oracle(&original, c);

            // run the passes to a fixpoint, keeping only oracle-valid
            // candidates
            let mut current = bytes.clone();
            loop {
                let anchor = failure_anchor(&current);
                let mut next: Option<Vec<u8>> = None;
                for candidate in [
                    dead_code(&current),
                    slice_to_anchor(&current, anchor),
                    slice_to_anchor(&current, anchor).and_then(|s| dead_code(&s)),
                ]
                .into_iter()
                .flatten()
                {
                    if candidate.len() < current.len() && oracle(&candidate) {
                        next = Some(candidate);
                        break;
                    }
                }
                if next.is_none() {
                    for candidate in simplify_dead_side(&current) {
                        if candidate.len() < current.len() && oracle(&candidate) {
                            next = Some(candidate);
                            break;
                        }
                    }
                }
                match next {
                    Some(c) => current = c,
                    None => break,
                }
            }
            assert!(
                current.len() <= bytes.len(),
                "{} grew during reduction",
                path.display()
            );
            assert!(
                oracle(&current),
                "{} lost its classification",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 25, "corpus too small: {checked}");
    }
}
