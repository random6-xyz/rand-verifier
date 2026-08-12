// ── Control flow graph checks (nano pass) ───────────────────────────────────

use crate::error::VerificationFailure;
use crate::insn::BpfInsn;

/// Maximum number of subprograms in one program.
const MAX_SUBPROGS: usize = 256;

/// Validate and register a single call target as a subprogram entry point.
fn register_subprog(
    call_idx: u32,
    target_offset: i32,
    insn_cnt: u32,
    subprogs: &mut Vec<u32>,
) -> Result<(), VerificationFailure> {
    // offset range check
    let target = target_offset as u32;
    if target >= insn_cnt {
        return Err(VerificationFailure::new(
            call_idx,
            format!("call target {} is out of range (0..{})", target, insn_cnt),
        ));
    }

    // dedup
    if subprogs.contains(&target) {
        return Ok(());
    }

    // max subprog check
    if subprogs.len() >= MAX_SUBPROGS {
        return Err(VerificationFailure::new(
            call_idx,
            format!("exceeded maximum number of subprograms ({})", MAX_SUBPROGS),
        ));
    }

    subprogs.push(target);
    subprogs.sort_unstable();

    Ok(())
}

/// Walk all instructions and collect subprogram entry points.
/// Returns a sorted Vec starting with the main program (index 0).
pub(crate) fn add_subprog(insns: &[BpfInsn]) -> Result<Vec<u32>, VerificationFailure> {
    let insn_cnt = insns.len() as u32;
    let mut subprogs = vec![0u32];

    for (idx, insn) in insns.iter().enumerate() {
        // helper calls use negative immediates (kernel convention) and
        // are not subprograms
        if let BpfInsn::Call { imm } = insn
            && *imm >= 0
        {
            register_subprog(idx as u32, *imm, insn_cnt, &mut subprogs)?;
        }
    }

    Ok(subprogs)
}

/// Return the [start, end) range of the subprogram that contains `insn_idx`.
pub(crate) fn find_subprog_range(insn_idx: u32, subprogs: &[u32], insn_cnt: u32) -> (u32, u32) {
    let start = subprogs
        .iter()
        .rfind(|&&s| s <= insn_idx)
        .copied()
        .unwrap_or(0);
    let end = subprogs
        .iter()
        .find(|&&s| s > insn_idx)
        .copied()
        .unwrap_or(insn_cnt);
    (start, end)
}

/// DFS visit state: NotVisited → Discovering → Explored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VisitState {
    NotVisited,
    Discovering,
    Explored,
}

/// Process one instruction: verify branch/fall-through boundaries and
/// return the list of successor instruction indices.
pub(crate) fn visit_insn(
    idx: u32,
    insns: &[BpfInsn],
    subprogs: &[u32],
) -> Result<Vec<u32>, VerificationFailure> {
    let insn_cnt = insns.len() as u32;
    let (start, end) = find_subprog_range(idx, subprogs, insn_cnt);

    let nexts = match &insns[idx as usize] {
        // terminal — no successors
        BpfInsn::Exit => vec![],
        // unconditional jump — no fall-through
        BpfInsn::Jmp { offset } => {
            // BPF branch target is PC-relative to the next insn: idx + 1 + offset
            let target = (idx as i32 + 1 + *offset as i32) as u32;
            if target < start || target >= end {
                return Err(VerificationFailure::new(
                    idx,
                    format!(
                        "jump target {} crosses subprogram boundary [{}, {})",
                        target, start, end
                    ),
                ));
            }
            vec![target]
        }
        // conditional branches — branch target + fall-through
        BpfInsn::Jeq { offset, .. }
        | BpfInsn::Jne { offset, .. }
        | BpfInsn::Jgt { offset, .. }
        | BpfInsn::Jge { offset, .. }
        | BpfInsn::Jlt { offset, .. }
        | BpfInsn::Jle { offset, .. }
        | BpfInsn::Jsgt { offset, .. }
        | BpfInsn::Jsge { offset, .. }
        | BpfInsn::Jslt { offset, .. }
        | BpfInsn::Jsle { offset, .. } => {
            // BPF branch target is PC-relative to the next insn: idx + 1 + offset
            let target = (idx as i32 + 1 + *offset as i32) as u32;
            if target < start || target >= end {
                return Err(VerificationFailure::new(
                    idx,
                    format!(
                        "branch target {} crosses subprogram boundary [{}, {})",
                        target, start, end
                    ),
                ));
            }
            vec![target, idx + 1]
        }
        // subprogram call (imm >= 0) — callee entry + return address;
        // helper calls (imm < 0, kernel convention) fall straight through
        BpfInsn::Call { imm } => {
            if *imm < 0 {
                return Ok(vec![idx + 1]);
            }
            let target = *imm as u32;
            if target >= insn_cnt {
                return Err(VerificationFailure::new(
                    idx,
                    format!("call target {} is out of range (0..{})", target, insn_cnt),
                ));
            }
            vec![target, idx + 1]
        }
        // everything else — straight-line fall-through
        _ => vec![idx + 1],
    };

    // prevent fall-through out of the current subprogram
    if nexts.contains(&(idx + 1)) && idx + 1 >= end {
        return Err(VerificationFailure::new(
            idx,
            format!("falls through out of subprogram [{}, {})", start, end),
        ));
    }

    Ok(nexts)
}

/// Check the control flow graph with an iterative DFS:
/// - every instruction must be reachable from the entry (insn 0)
/// - branches must stay within their subprogram
/// - no instruction may fall through into another subprogram
/// - back edges (loops) are allowed — bounded-loop support (#46) moves
///   the termination reasoning into the path exploration, which tracks
///   loop convergence and a re-entry budget
///
/// The stack holds (insn_idx, next_child) pairs so the DFS mimics recursion:
/// a node stays "Discovering" (gray) until all of its children are fully
/// explored, so an edge to a gray node is exactly a back edge. Returns the
/// loop heads (the targets of back edges) for the path exploration.
pub(crate) fn check_cfg(
    insns: &[BpfInsn],
    subprogs: &[u32],
) -> Result<Vec<u32>, VerificationFailure> {
    let insn_cnt = insns.len();
    let mut state = vec![VisitState::NotVisited; insn_cnt];
    let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
    let mut loop_heads = Vec::new();
    state[0] = VisitState::Discovering;

    while let Some((idx, child)) = stack.pop() {
        let nexts = visit_insn(idx, insns, subprogs)?;

        if child < nexts.len() {
            // process the next child; the node itself stays Discovering
            stack.push((idx, child + 1));
            let nxt = nexts[child];
            match state[nxt as usize] {
                VisitState::NotVisited => {
                    state[nxt as usize] = VisitState::Discovering;
                    stack.push((nxt, 0));
                }
                // edge to a node still being explored = back edge = loop:
                // its target is a loop head that the path exploration
                // must bound (#46)
                VisitState::Discovering => {
                    if !loop_heads.contains(&nxt) {
                        loop_heads.push(nxt);
                    }
                }
                VisitState::Explored => {}
            }
        } else {
            // all children explored — mark the node finished
            state[idx as usize] = VisitState::Explored;
        }
    }

    // any instruction left NotVisited is unreachable dead code
    for (i, s) in state.iter().enumerate() {
        if *s == VisitState::NotVisited {
            return Err(VerificationFailure::new(
                i as u32,
                "unreachable instruction",
            ));
        }
    }

    Ok(loop_heads)
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::*;

    #[test]
    fn add_subprog_no_calls() {
        let insns = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let subprogs = add_subprog(&insns).unwrap();
        assert_eq!(subprogs, vec![0]);
    }

    #[test]
    fn add_subprog_collects_and_sorts() {
        // call targets 4 and 2 → sorted with the main entry 0
        let insns = vec![
            BpfInsn::Call { imm: 4 },
            BpfInsn::Call { imm: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let subprogs = add_subprog(&insns).unwrap();
        assert_eq!(subprogs, vec![0, 2, 4]);
    }

    #[test]
    fn add_subprog_dedup_target() {
        // two calls to the same target → registered once
        let insns = vec![
            BpfInsn::Call { imm: 2 },
            BpfInsn::Call { imm: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let subprogs = add_subprog(&insns).unwrap();
        assert_eq!(subprogs, vec![0, 2]);
    }

    #[test]
    fn add_subprog_out_of_range() {
        // call target beyond the program → error
        let insns = vec![BpfInsn::Call { imm: 99 }, BpfInsn::Exit];
        assert!(add_subprog(&insns).is_err());
    }

    // ── find_subprog_range ───────────────────────────────────────────────────

    #[test]
    fn find_subprog_range_first() {
        let subprogs = [0, 5, 10];
        assert_eq!(find_subprog_range(3, &subprogs, 12), (0, 5));
    }

    #[test]
    fn find_subprog_range_middle() {
        let subprogs = [0, 5, 10];
        assert_eq!(find_subprog_range(7, &subprogs, 12), (5, 10));
    }

    #[test]
    fn find_subprog_range_last() {
        let subprogs = [0, 5, 10];
        assert_eq!(find_subprog_range(11, &subprogs, 12), (10, 12));
    }

    #[test]
    fn find_subprog_range_at_boundary() {
        let subprogs = [0, 5, 10];
        // an insn at a subprog entry belongs to the subprog that starts there
        assert_eq!(find_subprog_range(5, &subprogs, 12), (5, 10));
    }

    // ── visit_insn ───────────────────────────────────────────────────────────

    #[test]
    fn visit_insn_exit() {
        let insns = vec![BpfInsn::Exit];
        let nexts = visit_insn(0, &insns, &[0]).unwrap();
        assert!(nexts.is_empty());
    }

    #[test]
    fn visit_insn_jmp() {
        // target = idx + 1 + offset = 0 + 1 + 2 = 3
        let insns = vec![
            BpfInsn::Jmp { offset: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let nexts = visit_insn(0, &insns, &[0]).unwrap();
        assert_eq!(nexts, vec![3]);
    }

    #[test]
    fn visit_insn_jmp_crosses_boundary() {
        // subprog [0, 2): target 0 + 1 + 2 = 3 is out of range
        let insns = vec![
            BpfInsn::Jmp { offset: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        assert!(visit_insn(0, &insns, &[0, 2]).is_err());
    }

    #[test]
    fn visit_insn_cond_branch() {
        // Jeq: branch target 0 + 1 + 1 = 2, fall-through 1
        let insns = vec![
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let nexts = visit_insn(0, &insns, &[0]).unwrap();
        assert_eq!(nexts, vec![2, 1]);
    }

    #[test]
    fn visit_insn_call() {
        // Call imm is an absolute insn index: callee 2, return address 1
        let insns = vec![BpfInsn::Call { imm: 2 }, BpfInsn::Exit, BpfInsn::Exit];
        let nexts = visit_insn(0, &insns, &[0, 2]).unwrap();
        assert_eq!(nexts, vec![2, 1]);
    }

    #[test]
    fn visit_insn_alu_fallthrough() {
        let insns = vec![BpfInsn::AddImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let nexts = visit_insn(0, &insns, &[0]).unwrap();
        assert_eq!(nexts, vec![1]);
    }

    #[test]
    fn visit_insn_fallthrough_crosses_boundary() {
        // insn 1 is the last insn of subprog [0, 2): fall-through 2 crosses
        let insns = vec![
            BpfInsn::Call { imm: 2 },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        assert!(visit_insn(1, &insns, &[0, 2]).is_err());
    }

    #[test]
    fn visit_insn_error_carries_insn_idx() {
        // subprog [0, 2): target 0 + 1 + 2 = 3 is out of range → err at insn 0
        let insns = vec![
            BpfInsn::Jmp { offset: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let err = visit_insn(0, &insns, &[0, 2]).unwrap_err();
        assert_eq!(err.insn_idx, 0);
        assert!(err.message.contains("jump target 3"));
    }

    // ── check_cfg ────────────────────────────────────────────────────────────

    #[test]
    fn check_cfg_valid_simple() {
        let insns = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        assert!(check_cfg(&insns, &[0]).is_ok());
    }

    #[test]
    fn check_cfg_valid_with_subprog() {
        // main [0, 2): Call → subprog [2, 4), both end with Exit
        let insns = vec![
            BpfInsn::Call { imm: 2 },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert!(check_cfg(&insns, &[0, 2]).is_ok());
    }

    #[test]
    fn check_cfg_unreachable_insn() {
        // Jmp offset 1 skips insn 1 (target = 0 + 1 + 1 = 2)
        let insns = vec![
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 1 }, // unreachable
            BpfInsn::Exit,
        ];
        assert!(check_cfg(&insns, &[0]).is_err());
    }

    #[test]
    fn check_cfg_fallthrough_violation() {
        // insn 1 falls through from subprog [0, 2) into subprog [2, 4)
        let insns = vec![
            BpfInsn::Call { imm: 2 },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        assert!(check_cfg(&insns, &[0, 2]).is_err());
    }

    #[test]
    fn check_cfg_jmp_out_of_subprog() {
        // Jmp at 0 in subprog [0, 2): target 0 + 1 + 2 = 3 crosses the boundary
        let insns = vec![
            BpfInsn::Jmp { offset: 2 },
            BpfInsn::Exit,
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        assert!(check_cfg(&insns, &[0, 2]).is_err());
    }

    #[test]
    fn check_cfg_back_edge_allowed() {
        // Jeq R1==R1, offset -1 → jump to itself (target = 0 + 1 - 1 = 0):
        // back edges are allowed (#46); the target is reported as a loop
        // head and the exit stays reachable
        let insns = vec![
            BpfInsn::Jeq {
                dst: 1,
                src: 1,
                offset: -1,
            },
            BpfInsn::Exit,
        ];
        let loop_heads = check_cfg(&insns, &[0]).unwrap();
        assert_eq!(loop_heads, vec![0]);
    }

    #[test]
    fn check_cfg_multi_insn_loop_allowed() {
        // 0: jmp +0 → 1    (target = 0 + 1 + 0 = 1)
        // 1: jmp -2 → 0    (target = 1 + 1 - 2 = 0) — 2-instruction loop
        let insns = vec![BpfInsn::Jmp { offset: 0 }, BpfInsn::Jmp { offset: -2 }];
        let loop_heads = check_cfg(&insns, &[0]).unwrap();
        assert_eq!(loop_heads, vec![0]);
    }

    #[test]
    fn check_cfg_loop_head_detection() {
        // a counter loop: 0: r1 = 0; 1: r1 += 1; 2: jlt r1, r2, -2 → 1;
        // 3: exit — the back edge targets pc 1
        let insns = vec![
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -2,
            },
            BpfInsn::Exit,
        ];
        let loop_heads = check_cfg(&insns, &[0]).unwrap();
        assert_eq!(loop_heads, vec![1]);
        // a program without loops reports no loop heads
        let insns = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let loop_heads = check_cfg(&insns, &[0]).unwrap();
        assert!(loop_heads.is_empty());
    }

    #[test]
    fn check_cfg_valid_with_join() {
        // if/else join, no loop:
        // 0: jeq r1,r2,+1 → 2    (target = 0 + 1 + 1 = 2)
        // 1: jmp +1 → 3          (target = 1 + 1 + 1 = 3)
        // 2: r0 = 1 → falls to 3
        // 3: exit
        let insns = vec![
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert!(check_cfg(&insns, &[0]).is_ok());
    }

    #[test]
    fn check_cfg_error_carries_insn_idx() {
        // Jmp offset 1 skips insn 1 (target = 0 + 1 + 1 = 2) → err at insn 1
        let insns = vec![
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 1 }, // unreachable
            BpfInsn::Exit,
        ];
        let err = check_cfg(&insns, &[0]).unwrap_err();
        assert_eq!(err.insn_idx, 1);
        assert!(err.message.contains("unreachable"));
    }
}
