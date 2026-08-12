// ── Mini pass: path-sensitive exploration ───────────────────────────────────

use std::collections::HashMap;

use crate::error::VerificationFailure;
use crate::exec::{WorkItem, successors};
use crate::insn::BpfInsn;
use crate::state::{RegState, VerifierState, read_reg};

/// Does `old` subsume `new`, i.e. is `new` strictly more specific?
///
/// A subsumed state needs no analysis: step() and successors() are
/// monotone, so every outcome reachable from `new` is also reachable
/// from `old`, and `old` has already been analyzed (#26).
pub(crate) fn subsumes(old: &VerifierState, new: &VerifierState) -> bool {
    old.regs
        .iter()
        .zip(&new.regs)
        .all(|(old, new)| reg_subsumes(*old, *new))
        && old.stack == new.stack
}

/// Per-register part of `subsumes`: the old bounds must contain the new
/// ones in both interpretations (#40).
pub(crate) fn reg_subsumes(old: RegState, new: RegState) -> bool {
    match (old, new) {
        (RegState::Uninit, RegState::Uninit) => true,
        (RegState::Scalar(old), RegState::Scalar(new)) => {
            old.smin <= new.smin
                && old.smax >= new.smax
                && old.umin <= new.umin
                && old.umax >= new.umax
        }
        (
            RegState::PtrToStack { offset: old_offset },
            RegState::PtrToStack { offset: new_offset },
        ) => old_offset == new_offset,
        (RegState::PtrToCtx, RegState::PtrToCtx) => true,
        (RegState::PtrToMap, RegState::PtrToMap) => true,
        (RegState::PtrToMapValue, RegState::PtrToMapValue) => true,
        (RegState::PtrToMapValueOrNull, RegState::PtrToMapValueOrNull) => true,
        // a nullable pointer is a superset of the non-null one
        (RegState::PtrToMapValueOrNull, RegState::PtrToMapValue) => true,
        // different types are never comparable
        _ => false,
    }
}

/// Bounds for the exploration (#32): exceeding either rejects the
/// program with a complexity error, mirroring the kernel's
/// BPF_COMPLEXITY_LIMIT_* checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifierLimits {
    /// Maximum number of distinct (pc, state) pairs analyzed.
    pub(crate) max_states: usize,
    /// Maximum number of worklist steps (states popped).
    pub(crate) max_steps: usize,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self {
            max_states: 1024,
            max_steps: 100_000,
        }
    }
}

/// Path-sensitive verification: explore every execution path with a
/// worklist until it is empty.
///
/// - states are processed LIFO (depth-first), like the kernel's
///   push_stack/pop_stack verifier stack
/// - a state is analyzed at most once per pc: a new state is skipped
///   when an already-analyzed state subsumes it (cf. the kernel's
///   is_state_visited / states_equal); step() and successors() are
///   monotone, so the subsumed state cannot reach a new outcome — the
///   first defense against state explosion (#25/#26)
/// - every path must reach `exit` with R0 initialized (cf. the kernel's
///   R0 !read_ok check at exit)
/// - branches ruled out by the static verdict (#24) are never explored
/// - termination is guaranteed because the nano pass (#6) rejects loops,
///   so the CFG is acyclic; the exploration is additionally bounded by
///   `limits` (#32)
///
/// Returns the number of distinct (pc, state) pairs analyzed.
pub(crate) fn verify_mini(program: &[BpfInsn]) -> Result<usize, VerificationFailure> {
    verify_mini_with_limits(program, &VerifierLimits::default())
}

/// `verify_mini` with explicit exploration limits (#32).
pub(crate) fn verify_mini_with_limits(
    program: &[BpfInsn],
    limits: &VerifierLimits,
) -> Result<usize, VerificationFailure> {
    let mut worklist = vec![WorkItem {
        pc: 0,
        state: VerifierState::initial(),
    }];
    // states already analyzed at each pc: a new state is skipped when an
    // analyzed one subsumes it, like the kernel's per-pc state list
    let mut visited: HashMap<u32, Vec<VerifierState>> = HashMap::new();
    let mut explored = 0usize;
    let mut steps = 0usize;

    while let Some(item) = worklist.pop() {
        // worklist bound: every pop counts, even skipped ones
        steps += 1;
        if steps > limits.max_steps {
            return Err(VerificationFailure::new(
                item.pc,
                format!(
                    "verification complexity limit exceeded (max_steps {})",
                    limits.max_steps
                ),
            ));
        }

        // skip states subsumed by an already-analyzed state at this pc
        let seen = visited.entry(item.pc).or_default();
        if seen.iter().any(|old| subsumes(old, &item.state)) {
            continue;
        }
        seen.push(item.state);
        explored += 1;
        // analyzed-state bound: this is where pruning pays off — without
        // subsumption (#26), diamond chains would hit this limit fast
        if explored > limits.max_states {
            return Err(VerificationFailure::new(
                item.pc,
                format!(
                    "verification complexity limit exceeded (max_states {})",
                    limits.max_states
                ),
            ));
        }

        let insn = program.get(item.pc as usize).ok_or_else(|| {
            VerificationFailure::new(item.pc, "internal error: pc out of program range")
        })?;

        // a path ends at exit; R0 must hold a valid value there
        if matches!(insn, BpfInsn::Exit) {
            read_reg(item.pc, &item.state, 0)
                .map_err(|_| VerificationFailure::new(item.pc, "r0 is uninitialized at exit"))?;
            continue;
        }

        for (next_pc, next_state) in successors(item.pc, insn, &item.state)? {
            worklist.push(WorkItem {
                pc: next_pc,
                state: next_state,
            });
        }
    }
    Ok(explored)
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::*;
    use crate::insn::*;
    use crate::state::*;

    #[test]
    fn verify_mini_straight_line() {
        // r0 = 42; exit → R0 is set before exit
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn verify_mini_error_carries_real_insn_idx() {
        // r0 = 1; r0 += r2; exit — r2 is uninitialized at insn 1
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::AddReg { dst: 0, src: 2 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program).unwrap_err();
        assert_eq!(err.insn_idx, 1);
        assert!(err.to_string().contains("at insn 1"));
    }

    #[test]
    fn verify_mini_stack_error_carries_real_insn_idx() {
        // r0 = 1; r0 = [r10-8]; exit — uninitialized stack slot at insn 1
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::LdStack { dst: 0, offset: -8 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program).unwrap_err();
        assert_eq!(err.insn_idx, 1);
    }

    #[test]
    fn verify_mini_exit_r0_uninit_rejected() {
        // exit with R0 never written → REJECT
        let program = vec![BpfInsn::Exit];
        let err = verify_mini(&program).unwrap_err();
        assert!(err.message.contains("r0 is uninitialized at exit"));
    }

    #[test]
    fn verify_mini_diamond_both_paths() {
        // both paths must reach exit with R0 set:
        // 0: r1 = 5
        // 1: r2 = 5
        // 2: jeq r1, r2, +2 → taken 5, fall 3
        // 3: r0 = 1
        // 4: jmp +1 → 6
        // 5: r0 = 2
        // 6: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::MovImm { dst: 2, imm: 5 },
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 2 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn verify_mini_feasible_path_missing_r0_rejected() {
        // r1=1 vs r2=2: jeq is always false (is_branch_taken), so only the
        // fall path runs — and it reaches exit without writing R0 → REJECT:
        // 0: r1 = 1
        // 1: r2 = 2
        // 2: jeq r1, r2, +1 → taken 4 (pruned), fall 3
        // 3: jmp +1 → 5
        // 4: r0 = 42
        // 5: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 2, imm: 2 },
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 42 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program).unwrap_err();
        assert!(err.message.contains("r0 is uninitialized at exit"));
    }

    #[test]
    fn verify_mini_infeasible_taken_branch_pruned() {
        // jeq with disjoint constants: the taken branch (exit directly, R0
        // unset) is infeasible and must be pruned, otherwise this would reject
        // 0: r1 = 7
        // 1: r2 = 5
        // 2: jeq r1, r2, +1 → taken 4 (infeasible), fall 3
        // 3: r0 = 1
        // 4: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 7 },
            BpfInsn::MovImm { dst: 2, imm: 5 },
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());

        // the expansion itself yields a single (fall) successor
        let mut state = VerifierState::initial();
        state = step(0, &state, &BpfInsn::MovImm { dst: 1, imm: 7 }).unwrap();
        state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 5 }).unwrap();
        let nexts = successors(
            2,
            &BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 1);
        assert_eq!(nexts[0].0, 3);
    }

    #[test]
    fn verify_mini_unknown_helper() {
        let program = vec![BpfInsn::Call { imm: -99 }, BpfInsn::Exit];
        let err = verify_mini(&program).unwrap_err();
        assert!(err.message.contains("unknown helper"));
    }

    #[test]
    fn verify_mini_jmp_out_of_range() {
        // branch target beyond the program → defensive error
        let program = vec![BpfInsn::Jmp { offset: 100 }, BpfInsn::Exit];
        let err = verify_mini(&program).unwrap_err();
        assert!(err.message.contains("pc out of program range"));
    }

    #[test]
    fn verify_mini_stack_pointer_in_branch() {
        // pointer arithmetic + stack roundtrip inside a diamond, both paths OK:
        // 0: r10 += -8
        // 1: r2 = 7
        // 2: [r10-8] = r2
        // 3: r1 = 1
        // 4: r3 = 1
        // 5: jeq r1, r3, +2 → taken 8, fall 6
        // 6: r0 = [r10-8]
        // 7: jmp +1 → 9
        // 8: r0 = [r10-8]
        // 9: exit
        let program = vec![
            BpfInsn::AddImm { dst: 10, imm: -8 },
            BpfInsn::MovImm { dst: 2, imm: 7 },
            BpfInsn::StStack { src: 2, offset: -8 },
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 1 },
            BpfInsn::Jeq {
                dst: 1,
                src: 3,
                offset: 2,
            },
            BpfInsn::LdStack { dst: 0, offset: -8 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::LdStack { dst: 0, offset: -8 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());
    }

    // ── Branch verdict (v0.3) ────────────────────────────────────────────────

    #[test]
    fn verify_mini_jgt_always_taken_prunes_fall() {
        // 35 > 10 is always true: the fall path (exit without R0) must be
        // pruned, otherwise verification would reject:
        // 0: r1 = 35
        // 1: r2 = 10
        // 2: jgt r1, r2, +1 → taken 4, fall 3 (pruned)
        // 3: exit
        // 4: r0 = 1
        // 5: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 35 },
            BpfInsn::MovImm { dst: 2, imm: 10 },
            BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn verify_mini_jgt_never_taken_prunes_taken() {
        // 5 > 40 is always false: the taken path (exit without R0) must be
        // pruned:
        // 0: r1 = 5
        // 1: r2 = 40
        // 2: jgt r1, r2, +1 → taken 4 (pruned), fall 3
        // 3: r0 = 1
        // 4: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::MovImm { dst: 2, imm: 40 },
            BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn verify_mini_dedup_join_state() {
        // both branches rejoin at pc 4 with the same state (r0 = 1); the
        // second visit is skipped (is_state_visited), so 5 distinct
        // (pc, state) pairs are analyzed instead of 6:
        // 0: jeq r10, r10, +2 → taken 3, fall 1
        // 1: r0 = 1
        // 2: jmp +1 → 4
        // 3: r0 = 1
        // 4: exit
        let program = vec![
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        assert_eq!(verify_mini(&program).unwrap(), 5);
    }

    #[test]
    fn verify_mini_dedup_distinct_join_states_not_merged() {
        // if the two branches write different values, the join states differ
        // and both are analyzed:
        // 0: jeq r10, r10, +2 → taken 3, fall 1
        // 1: r0 = 1
        // 2: jmp +1 → 4
        // 3: r0 = 2
        // 4: exit
        let program = vec![
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 0, imm: 2 },
            BpfInsn::Exit,
        ];
        // (4, r0=1) and (4, r0=2) are distinct → both counted
        assert_eq!(verify_mini(&program).unwrap(), 6);
    }

    // ── Subsumption (v0.3) ──────────────────────────────────────────────────

    #[test]
    fn subsumes_dual_ranges() {
        // subsumption requires containment in both interpretations (#40).
        // The states here are constructed directly (bypassing the sync)
        // to pin the predicate itself.
        let bounds = |smin: i64, smax: i64, umin: u64, umax: u64| ScalarBounds {
            smin,
            smax,
            umin,
            umax,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
        };
        let mut old = VerifierState::initial();
        old.regs[1] = RegState::Scalar(bounds(0, 100, 0, 100));
        let mut new = VerifierState::initial();
        new.regs[1] = RegState::Scalar(bounds(10, 20, 10, 20));
        assert!(subsumes(&old, &new));
        // the signed range contains the new one but the unsigned range
        // does not → not subsumed
        new.regs[1] = RegState::Scalar(bounds(10, 20, 0, 1000));
        assert!(!subsumes(&old, &new));
        // and vice versa
        new.regs[1] = RegState::Scalar(bounds(-50, 20, 0, 100));
        assert!(!subsumes(&old, &new));
    }

    #[test]
    fn subsumes_issue_example() {
        // issue example: old R1 = [0, 100] subsumes new R1 = [10, 20]
        let mut old = VerifierState::initial();
        old.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        let mut new = VerifierState::initial();
        new.regs[1] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
        assert!(subsumes(&old, &new));
    }

    #[test]
    fn subsumes_scalar_ranges() {
        let old = VerifierState::initial();
        let mut old = old;
        old.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        let mut new = VerifierState::initial();
        new.regs[1] = RegState::Scalar(ScalarBounds::from_signed(10, 20));

        // subsumption is reflexive: a state subsumes itself
        assert!(subsumes(&old, &old));
        assert!(subsumes(&new, &new));
        // a wider new range is not subsumed
        new.regs[1] = RegState::Scalar(ScalarBounds::from_signed(-50, 200));
        assert!(!subsumes(&old, &new));
        // equal ranges subsume each other
        new.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        assert!(subsumes(&old, &new));
        assert!(subsumes(&new, &old));
    }

    #[test]
    fn subsumes_reg_mismatch() {
        // different types are never comparable
        let old = VerifierState::initial();
        let mut new = VerifierState::initial();
        new.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        assert!(!subsumes(&old, &new)); // Uninit vs Scalar
        assert!(!subsumes(&new, &old));

        // pointer offsets must match exactly
        let mut shifted = VerifierState::initial();
        shifted.regs[10] = RegState::PtrToStack { offset: -8 };
        assert!(!subsumes(&old, &shifted));
        assert!(subsumes(&old, &old));
    }

    #[test]
    fn subsumes_stack_mismatch() {
        let mut old = VerifierState::initial();
        old.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(1)));
        let new = VerifierState::initial();
        // stack states differ → not subsumed even though the registers match
        assert!(!subsumes(&old, &new));
        assert!(!subsumes(&new, &old));
    }

    #[test]
    fn verify_mini_refined_state_subsumed_by_original() {
        // the refined branches of [0, 100] > 50 (R1 = [51, 100] / [0, 50])
        // are both subsumed by the original R1 = [0, 100]
        let mut state = VerifierState::initial();
        state.regs[1] = RegState::Scalar(ScalarBounds::from_signed(0, 100));
        state.regs[2] = RegState::Scalar(ScalarBounds::constant(50));
        let nexts = successors(
            0,
            &BpfInsn::Jgt {
                dst: 1,
                src: 2,
                offset: 1,
            },
            &state,
        )
        .unwrap();
        assert_eq!(nexts.len(), 2);
        let (_, taken) = &nexts[0];
        let (_, fall) = &nexts[1];
        assert!(subsumes(&state, taken));
        assert!(subsumes(&state, fall));
    }

    // ── Nullable pointers (v0.3) ─────────────────────────────────────────────

    #[test]
    fn subsumes_nullable_pointer() {
        // OrNull = {valid} ∪ {NULL} subsumes the non-null pointer
        let mut or_null = VerifierState::initial();
        or_null.regs[0] = RegState::PtrToMapValueOrNull;
        let mut valid = VerifierState::initial();
        valid.regs[0] = RegState::PtrToMapValue;
        assert!(subsumes(&or_null, &valid));
        assert!(!subsumes(&valid, &or_null));
        // same types subsume themselves
        assert!(subsumes(&or_null, &or_null));
        assert!(subsumes(&valid, &valid));
    }

    #[test]
    fn verify_mini_prandom_branch() {
        // end-to-end range program: prandom yields an unknown scalar, then a
        // branch refines it (#16 in a real program):
        // 0: call 7         → R0 = [MIN, MAX]
        // 1: r1 = 0
        // 2: jeq r0, r1, +1 → taken 4, fall 3
        // 3: exit           (R0 = [MIN, MAX])
        // 4: exit           (R0 = [0, 0])
        let program = vec![
            BpfInsn::Call { imm: -7 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::Jeq {
                dst: 0,
                src: 1,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        // both branches reach exit with R0 set (scalar in both cases)
        assert!(verify_mini(&program).is_ok());
    }

    // ── Verifier limits (v0.3) ───────────────────────────────────────────────

    #[test]
    fn verify_mini_limits_default_ok() {
        // the default limits accept normal programs
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn verify_mini_max_states_exceeded() {
        // r0 = 1; exit needs two distinct states (pc 0 and pc 1)
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let tight = VerifierLimits {
            max_states: 1,
            max_steps: 100,
        };
        let err = verify_mini_with_limits(&program, &tight).unwrap_err();
        assert!(
            err.message
                .contains("verification complexity limit exceeded")
        );
        assert!(err.message.contains("max_states"));

        // with enough room the same program is accepted
        let roomy = VerifierLimits {
            max_states: 2,
            max_steps: 100,
        };
        assert!(verify_mini_with_limits(&program, &roomy).is_ok());
    }

    #[test]
    fn verify_mini_max_steps_exceeded() {
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let limits = VerifierLimits {
            max_states: 100,
            max_steps: 1,
        };
        let err = verify_mini_with_limits(&program, &limits).unwrap_err();
        assert!(
            err.message
                .contains("verification complexity limit exceeded")
        );
        assert!(err.message.contains("max_steps"));
    }

    #[test]
    fn verify_mini_limits_defaults() {
        // sane defaults: generous enough for the corpus, small enough to
        // catch runaway exploration
        let limits = VerifierLimits::default();
        assert_eq!(limits.max_states, 1024);
        assert_eq!(limits.max_steps, 100_000);
    }

    #[test]
    fn verify_mini_helper_clobber_detected() {
        // reusing an argument register after a call is a #14 error:
        // 0: call 7   → R1..R5 invalidated
        // 1: r0 = r1  → R1 is uninitialized → REJECT
        // 2: exit
        let program = vec![
            BpfInsn::Call { imm: -7 },
            BpfInsn::MovReg { dst: 0, src: 1 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program).unwrap_err();
        assert!(err.message.contains("r1 is uninitialized"));
    }

    #[test]
    fn verify_mini_helper_preserves_callee_saved() {
        // a callee-saved register survives the call:
        // 0: r6 = 5
        // 1: call 7
        // 2: r0 = r6  → preserved → OK
        // 3: exit
        let program = vec![
            BpfInsn::MovImm { dst: 6, imm: 5 },
            BpfInsn::Call { imm: -7 },
            BpfInsn::MovReg { dst: 0, src: 6 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program).is_ok());
    }

    #[test]
    fn subsumes_ptr_to_map() {
        let mut map = VerifierState::initial();
        map.regs[1] = RegState::PtrToMap;
        let ctx = VerifierState::initial();
        // same type subsumes itself; a map pointer never subsumes a ctx
        // pointer (or vice versa)
        assert!(subsumes(&map, &map));
        assert!(!subsumes(&map, &ctx));
        assert!(!subsumes(&ctx, &map));
    }
}
