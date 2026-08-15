// ── Mini pass: path-sensitive exploration (issue #97) ───────────────────────

use std::collections::HashMap;

use crate::error::VerificationFailure;
use crate::exec::successors;
use crate::insn::BpfInsn;
use crate::liveness::{Liveness, analyze};
use crate::state::{RegState, VerifierState, read_reg};
use crate::state_eq::{ExactLevel, clean_state, states_equal, states_maybe_looping};

/// Bounds for the exploration (#32, #46): exceeding any of them rejects
/// the program with a complexity error, mirroring the kernel's
/// BPF_COMPLEXITY_LIMIT_* checks and BPF_MAX_LOOPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifierLimits {
    /// Maximum number of stored (checkpointed) states — the kernel's
    /// total_states analog. Deliberately smaller than the kernel's
    /// limits (its `BPF_COMPLEXITY_LIMIT_*`), like max_steps.
    pub(crate) max_states: usize,
    /// Maximum number of worklist steps (states popped).
    pub(crate) max_steps: usize,
    /// Maximum number of re-analyses of one loop head (#46): a
    /// simplified stand-in for the kernel's BPF_MAX_LOOPS (1 << 23) —
    /// deliberately smaller than `max_states` so the loop budget fires
    /// before the state budget for non-converging loops.
    pub(crate) max_loop_iterations: usize,
}

impl Default for VerifierLimits {
    fn default() -> Self {
        Self {
            max_states: 1024,
            max_steps: 100_000,
            // each loop iteration consumes ~2 analyzed states, so the
            // loop budget must stay below max_states / 2 to fire first
            max_loop_iterations: 256,
        }
    }
}

/// One stored (checkpointed) state — the kernel's
/// `bpf_verifier_state_list` entry (kernel/bpf/states.c).
///
/// - `state` is the arrival state cleaned with its pc's liveness
///   (kernel `clean_verifier_state` before storing);
/// - `parent` points at the checkpoint this path descended from
///   (kernel `cur->parent = new` — the parent chain that issue #98's
///   precision backtracking walks);
/// - `branches` counts the paths still pending under this checkpoint
///   (kernel `sl->state.branches`): a checkpoint with `branches == 0`
///   has been fully explored and proven safe, so it may prune
///   equivalent states; a checkpoint with `branches > 0` is still being
///   explored and only participates in infinite-loop detection.
struct Checkpoint {
    state: VerifierState,
    parent: Option<usize>,
    branches: usize,
    /// Prune statistics (kernel `hit_cnt`/`miss_cnt`): a state that
    /// misses much more often than it hits is evicted from the
    /// comparison list.
    hit_cnt: usize,
    miss_cnt: usize,
}

/// One worklist item: a path arriving at `pc` with abstract state
/// `state`. `last_cp` is the deepest checkpoint on this path's parent
/// chain — the checkpoint whose branch count this path belongs to.
struct WorkItem {
    pc: u32,
    state: VerifierState,
    last_cp: Option<usize>,
}

/// Adjust the branch count of every checkpoint on a path's parent
/// chain by `delta` (kernel `bpf_update_branch_counts`): every worklist
/// item is a path segment under the checkpoints on its chain, so each
/// push increments the whole chain and each pop decrements it again.
/// A checkpoint reaching 0 has no pending items under it anymore — it
/// is fully explored and safe to prune from.
fn bump_branches(checkpoints: &mut [Checkpoint], mut last_cp: Option<usize>, delta: i32) {
    while let Some(i) = last_cp {
        let cp = &mut checkpoints[i];
        if delta > 0 {
            cp.branches += 1;
        } else {
            cp.branches -= 1;
        }
        last_cp = cp.parent;
    }
}

/// The kernel's prune points (kernel/bpf/cfg.c): conditional jumps and
/// unconditional jump targets. `is_state_visited` is only called (and
/// states only stored) at these instructions.
fn compute_prune_points(program: &[BpfInsn]) -> Vec<bool> {
    let mut prune = vec![false; program.len()];
    for (i, insn) in program.iter().enumerate() {
        match insn {
            BpfInsn::Jmp { offset } => {
                let tgt = i as i64 + 1 + *offset as i64;
                if (0..program.len() as i64).contains(&tgt) {
                    prune[tgt as usize] = true;
                }
            }
            insn if insn.is_conditional_branch() => prune[i] = true,
            _ => {}
        }
    }
    prune
}

/// Path-sensitive verification: explore every execution path with a
/// worklist until it is empty, mirroring the kernel's do_check /
/// is_state_visited machinery (kernel/bpf/states.c):
///
/// - states are processed LIFO (depth-first), like the kernel's
///   push_stack/pop_stack verifier stack; at a conditional branch the
///   taken side is processed first, the fall-through is pushed (kernel
///   check_cond_jmp_op)
/// - `is_state_visited` runs at every prune point (conditional jumps
///   and unconditional jump targets): the arrival state is cleaned with
///   the pc's liveness masks, compared against the stored checkpoints
///   (states_equal — only live registers, kernel-style regsafe/
///   stacksafe), and either pruned (a completed equivalent checkpoint
///   exists), rejected (an in-progress identical checkpoint = infinite
///   loop, kernel "infinite loop detected at insn N"), or stored as a
///   new checkpoint (gated by the kernel's add_new_state heuristic)
/// - checkpoints track their parent and their pending branch count;
///   every completed path decrements the counts along its parent chain
///   (bpf_update_branch_counts), and a checkpoint with branches == 0 is
///   fully explored — only those prune later states
/// - every path must reach `exit` with R0 initialized (cf. the kernel's
///   R0 !read_ok check at exit); the structural pass guarantees that
///   every accepted program has a reachable exit
/// - branches ruled out by the static verdict (#24) are never explored
/// - termination is guaranteed by the exploration bounds (#32, #46):
///   loops converge when an arrival is pruned against a completed
///   checkpoint at a prune point; a non-converging loop hits the
///   `max_loop_iterations` budget and is rejected; `max_states` and
///   `max_steps` remain the outer bounds
///
/// Returns the number of stored checkpoints (the kernel's
/// `total_states` analog).
#[allow(dead_code)] // convenience entry kept for tests; the pipeline uses verify_mini_with_states (#53)
pub(crate) fn verify_mini(
    program: &[BpfInsn],
    loop_heads: &[u32],
) -> Result<usize, VerificationFailure> {
    verify_mini_with_limits(program, loop_heads, &VerifierLimits::default())
}

/// `verify_mini` with explicit exploration limits (#32, #46). `loop_heads`
/// are the targets of back edges (from the structural pass): the
/// exploration bounds how many times each loop head may be re-analyzed.
pub(crate) fn verify_mini_with_limits(
    program: &[BpfInsn],
    loop_heads: &[u32],
    limits: &VerifierLimits,
) -> Result<usize, VerificationFailure> {
    Ok(verify_mini_core(program, loop_heads, limits)?.0)
}

/// `verify_mini_with_limits` that also returns the per-pc abstract
/// states the exploration analyzed — the input of the abstract↔concrete
/// coverage checker (#52). The recorded states are cleaned with their
/// pc's liveness, exactly like the concrete side's recorded states.
pub(crate) fn verify_mini_with_states(
    program: &[BpfInsn],
    loop_heads: &[u32],
    limits: &VerifierLimits,
) -> Result<(usize, HashMap<u32, Vec<VerifierState>>), VerificationFailure> {
    verify_mini_core(program, loop_heads, limits)
}

/// The shared exploration core: runs the worklist and collects the
/// analyzed states per pc. Both public entry points are thin wrappers.
fn verify_mini_core(
    program: &[BpfInsn],
    loop_heads: &[u32],
    limits: &VerifierLimits,
) -> Result<(usize, HashMap<u32, Vec<VerifierState>>), VerificationFailure> {
    let liveness: Liveness = analyze(program);
    let prune_points = compute_prune_points(program);
    let mut worklist = vec![WorkItem {
        pc: 0,
        state: VerifierState::initial(),
        last_cp: None,
    }];
    // the stored checkpoints, indexed — one global pool so the parent
    // chain can span pcs (the kernel's explored-state list)
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    // per-pc checkpoint indices (the kernel's per-insn state list)
    let mut visited: HashMap<u32, Vec<usize>> = HashMap::new();
    // per-pc analyzed states — the input of the abstract↔concrete
    // coverage checker (#52)
    let mut analyzed: HashMap<u32, Vec<VerifierState>> = HashMap::new();
    // re-analyses per loop head (#46): exceeding the budget means the
    // loop never converges — REJECT like the kernel's "back-edge exceeds
    // max loops"
    let mut loop_iters: HashMap<u32, usize> = HashMap::new();
    let mut steps = 0usize;
    // the kernel's env->insn_processed / env->jmps_processed counters
    // and their snapshots at the last stored state (the add_new_state
    // heuristic in is_state_visited)
    let mut insn_processed = 0usize;
    let mut jmps_processed = 0usize;
    let mut prev_insn_processed = 0usize;
    let mut prev_jmps_processed = 0usize;

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
        let pc = item.pc;
        let insn = program.get(pc as usize).ok_or_else(|| {
            VerificationFailure::new(pc, "internal error: pc out of program range")
        })?;
        // the kernel counts the insn at the top of do_check, before
        // is_state_visited (account_processed_insn)
        insn_processed += 1;

        let live_regs = liveness.live_regs_before(pc);
        let live_stack = liveness.live_stack_before(pc);
        let mut cleaned = item.state;
        clean_state(&mut cleaned, live_regs, live_stack);

        // ── is_state_visited (kernel/bpf/states.c) ────────────────────
        let mut item_last_cp = item.last_cp;
        if prune_points[pc as usize] {
            // the add_new_state heuristic: after a stored state, only
            // store again once at least 2 jumps and 8 instructions were
            // processed (the kernel's "Do not add new state for future
            // pruning if the verifier hasn't seen at least 2 jumps and
            // at least 8 instructions")
            let mut add_new_state = insn_processed - prev_insn_processed >= 8
                && jmps_processed - prev_jmps_processed >= 2;
            let mut pruned = false;
            let mut evict: Vec<usize> = Vec::new();
            if let Some(list) = visited.get(&pc) {
                for &cp_idx in list {
                    // compare the arrival against this checkpoint
                    let equal = {
                        let cp = &checkpoints[cp_idx];
                        if cp.branches > 0 {
                            // an in-progress state: only infinite-loop
                            // detection — an identical revisit can never
                            // make progress (kernel states.c:
                            // states_maybe_looping + states_equal EXACT)
                            if states_maybe_looping(&cp.state, &cleaned)
                                && states_equal(&cp.state, &cleaned, ExactLevel::Exact, live_regs)
                            {
                                return Err(VerificationFailure::new(
                                    pc,
                                    format!("infinite loop detected at insn {}", pc),
                                ));
                            }
                            // the kernel's in-progress store throttle
                            // (states.c skip_inf_loop_check): while a
                            // loop is still being explored, only store
                            // a new state once at least 20 jumps and
                            // 100 instructions were processed since the
                            // last store — loop iterations would
                            // otherwise accumulate one checkpoint each
                            if insn_processed - prev_insn_processed < 100
                                && jmps_processed - prev_jmps_processed < 20
                            {
                                add_new_state = false;
                            }
                            false
                        } else {
                            states_equal(&cp.state, &cleaned, ExactLevel::NotExact, live_regs)
                        }
                    };
                    if equal {
                        // the current state is equivalent to a completed
                        // stored state: the path is safe, stop exploring
                        // (kernel: "found equivalent state, can prune
                        // the search")
                        checkpoints[cp_idx].hit_cnt += 1;
                        pruned = true;
                        break;
                    }
                    // miss accounting (kernel: `if (add_new_state)
                    // sl->miss_cnt++`) and eviction: a state that misses
                    // much more than it hits is unlikely to help pruning
                    // (kernel: `sl->miss_cnt > sl->hit_cnt * n + n`,
                    // n = 3)
                    if add_new_state {
                        checkpoints[cp_idx].miss_cnt += 1;
                    }
                    let cp = &checkpoints[cp_idx];
                    if cp.miss_cnt > cp.hit_cnt * 3 + 3 {
                        evict.push(cp_idx);
                    }
                }
            }
            if pruned {
                // the pruned path ends here — consume the item (its
                // parent-chain branch counts drop by one)
                bump_branches(&mut checkpoints, item.last_cp, -1);
                continue;
            }
            if !evict.is_empty()
                && let Some(list) = visited.get_mut(&pc)
            {
                list.retain(|i| !evict.contains(i));
            }
            if add_new_state {
                // store the checkpoint (kernel: bpf_copy_verifier_state
                // + `cur->parent = new`); the branch count starts at 0
                // and counts the pushed successors below
                let cp_idx = checkpoints.len();
                checkpoints.push(Checkpoint {
                    state: cleaned,
                    parent: item.last_cp,
                    branches: 0,
                    hit_cnt: 0,
                    miss_cnt: 0,
                });
                visited.entry(pc).or_default().push(cp_idx);
                prev_insn_processed = insn_processed;
                prev_jmps_processed = jmps_processed;
                item_last_cp = Some(cp_idx);
            }
        }

        // loop-head budget: a loop head that keeps producing new (not
        // pruned) states is not converging — bound it before the state
        // budget so the loop error is reported, like the kernel's
        // "back-edge exceeds max loops" (#46)
        if loop_heads.contains(&pc) {
            let iters = loop_iters.entry(pc).or_insert(0);
            *iters += 1;
            if *iters > limits.max_loop_iterations {
                return Err(VerificationFailure::new(
                    pc,
                    format!(
                        "back-edge exceeds max loops ({}) — the loop does not converge",
                        limits.max_loop_iterations
                    ),
                ));
            }
        }
        // stored-state bound: the checkpoint budget (the kernel's
        // BPF_COMPLEXITY_LIMIT_* family)
        if checkpoints.len() > limits.max_states {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "verification complexity limit exceeded (max_states {})",
                    limits.max_states
                ),
            ));
        }

        // record the analyzed arrival for the coverage checker (#52):
        // every concrete state at this pc must be covered by one of
        // these (the concrete side records states cleaned the same way)
        analyzed.entry(pc).or_default().push(cleaned);

        // the kernel counts jumps when the insn is actually processed
        // (do_check_insn: `env->jmps_processed++` for the JMP class)
        if insn.is_control_flow() || matches!(insn, BpfInsn::Call { .. }) {
            jmps_processed += 1;
        }

        // a path ends at exit; R0 must hold a valid value there
        if matches!(insn, BpfInsn::Exit) {
            let r0 = read_reg(pc, &item.state, 0)
                .map_err(|_| VerificationFailure::new(pc, "r0 is uninitialized at exit"))?;
            // the kernel requires R0 to be a scalar return value at
            // exit (check_return_code: "R0 leaks addr as return
            // value" / "R0 is not a known value (ctx)") — a pointer
            // in R0 is never a valid program return value
            if !matches!(r0, RegState::Scalar(_)) {
                return Err(VerificationFailure::new(
                    pc,
                    "r0 is not a scalar value at exit",
                ));
            }
            // the path ends here — consume the item (kernel
            // process_bpf_exit → bpf_update_branch_counts)
            bump_branches(&mut checkpoints, item.last_cp, -1);
            continue;
        }

        for (next_pc, next_state) in successors(pc, insn, &item.state)?.into_iter().rev() {
            // the kernel pushes the fall-through and continues with the
            // taken branch — with our LIFO worklist, pushing in reverse
            // reproduces that order (taken processed first)
            bump_branches(&mut checkpoints, item_last_cp, 1);
            worklist.push(WorkItem {
                pc: next_pc,
                state: next_state,
                last_cp: item_last_cp,
            });
        }
        // the item is consumed: its parent-chain branch counts drop by
        // one (every worklist item is a path segment; the kernel counts
        // paths, which only branch at forks — the per-push/per-pop
        // accounting is equivalent)
        bump_branches(&mut checkpoints, item.last_cp, -1);
    }
    Ok((checkpoints.len(), analyzed))
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
        assert!(verify_mini(&program, &[]).is_ok());
    }

    #[test]
    fn verify_mini_error_carries_real_insn_idx() {
        // r0 = 1; r0 += r2; exit — r2 is uninitialized at insn 1
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::AddReg { dst: 0, src: 2 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[]).unwrap_err();
        assert_eq!(err.insn_idx, 1);
        assert!(err.to_string().contains("at insn 1"));
    }

    #[test]
    fn verify_mini_stack_error_carries_real_insn_idx() {
        // r0 = 1; r0 = [r10-8]; exit — uninitialized stack slot at insn 1
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[]).unwrap_err();
        assert_eq!(err.insn_idx, 1);
    }

    #[test]
    fn verify_mini_exit_r0_uninit_rejected() {
        // exit with R0 never written → REJECT
        let program = vec![BpfInsn::Exit];
        let err = verify_mini(&program, &[]).unwrap_err();
        assert!(err.message.contains("r0 is uninitialized at exit"));
    }

    #[test]
    fn verify_mini_exit_r0_pointer_rejected() {
        // spill the ctx pointer, reload it into R0, exit — the kernel
        // rejects a pointer in R0 at exit ("R0 leaks addr as return
        // value" unprivileged / "R0 is not a known value" privileged,
        // check_return_code); the mini must mirror the rule
        // (mseed-99399-57 shape)
        let program = vec![
            BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
            },
            BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
            },
            BpfInsn::MovImm { dst: 5, imm: 0 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[]).unwrap_err();
        assert_eq!(err.insn_idx, 3);
        assert!(err.message.contains("r0 is not a scalar value at exit"));
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
        assert!(verify_mini(&program, &[]).is_ok());
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
        let err = verify_mini(&program, &[]).unwrap_err();
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
        assert!(verify_mini(&program, &[]).is_ok());

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
        let program = vec![BpfInsn::Call { imm: 99 }, BpfInsn::Exit];
        let err = verify_mini(&program, &[]).unwrap_err();
        assert!(err.message.contains("unknown helper"));
    }

    #[test]
    fn verify_mini_base_helpers_accepted() {
        // the kernel's bpf_base_func_proto family (no-argument scalar
        // returns) — ktime_get_ns (5), get_smp_processor_id (8),
        // get_numa_node_id (10), ktime_get_boot_ns (125),
        // ktime_get_coarse_ns (160), ktime_get_tai_ns (208) — must be
        // accepted like get_prandom_u32 (7); the kernel accepts them
        // even under unprivileged-equivalent rules (mseed-52555-5091
        // shape, mseed-65537-4391 socket-filter set)
        for imm in [5, 7, 8, 10, 125, 160, 208] {
            let program = vec![BpfInsn::Call { imm }, BpfInsn::Exit];
            assert!(
                verify_mini(&program, &[]).is_ok(),
                "helper {imm} should be accepted"
            );
        }
    }

    #[test]
    fn verify_mini_jmp_out_of_range() {
        // branch target beyond the program → defensive error
        let program = vec![BpfInsn::Jmp { offset: 100 }, BpfInsn::Exit];
        let err = verify_mini(&program, &[]).unwrap_err();
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
            BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
            },
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 1 },
            BpfInsn::Jeq {
                dst: 1,
                src: 3,
                offset: 2,
            },
            BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
            },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program, &[]).is_ok());
    }

    // ── Bounded loops (Meso #46) ─────────────────────────────────────────────

    #[test]
    fn verify_mini_bounded_counter_loop() {
        // the issue example: r0 = 0; r1 = 0; loop: r1 += 1; if r1 < 100
        // goto loop; exit — 100 iterations, all within the loop budget
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 2, imm: 100 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -2, // target = 4 + 1 - 2 = 3 (loop head)
            },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program, &[3]).is_ok());
    }

    #[test]
    fn verify_mini_bounded_loop_without_declared_head() {
        // a genuinely bounded loop terminates even without a declared
        // loop head: the counter exits by its value range, so the
        // exploration completes on its own (the head budget only bounds
        // loops that never converge)
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 2, imm: 100 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -2,
            },
            BpfInsn::Exit,
        ];
        assert!(verify_mini_with_limits(&program, &[], &VerifierLimits::default()).is_ok());
    }

    #[test]
    fn verify_mini_non_converging_loop_rejected() {
        // the counter never stops changing and the loop never exits:
        // the loop-head budget fires → REJECT with the kernel's message
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jeq {
                dst: 1,
                src: 1,
                offset: -2, // always taken back to pc 2 (loop head)
            },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[2]).unwrap_err();
        assert!(
            err.message.contains("back-edge exceeds max loops"),
            "{}",
            err.message
        );
    }

    #[test]
    fn verify_mini_loop_read_error_before_loop_machinery() {
        // the loop's branch reads an uninitialized register: the read
        // error fires on the first analysis of the branch insn, before
        // any loop detection or budget machinery (r2 is uninit at the
        // jeq; convergence itself is covered by the bounded-loop tests)
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jeq {
                dst: 1,
                src: 2,
                offset: -2,
            },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[2]).unwrap_err();
        assert!(err.message.contains("uninitialized"), "{}", err.message);
    }

    #[test]
    fn verify_mini_loop_limits_are_bounded() {
        // a tiny loop budget rejects even a small counter loop
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 2, imm: 100 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -2,
            },
            BpfInsn::Exit,
        ];
        let tight = VerifierLimits {
            max_states: 1024,
            max_steps: 100_000,
            max_loop_iterations: 10,
        };
        // (the default also works: 512 < max_states 1024 fires first)
        let err = verify_mini_with_limits(&program, &[3], &tight).unwrap_err();
        assert!(err.message.contains("back-edge exceeds max loops"));
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
        assert!(verify_mini(&program, &[]).is_ok());
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
        assert!(verify_mini(&program, &[]).is_ok());
    }

    // ── Kernel-style pruning (issue #97) ─────────────────────────────────────

    /// The kernel-style diamond test shape (26 insns, join at pc 25):
    /// both paths are long enough (≥ 8 insns and ≥ 2 jumps between
    /// stores) for the add_new_state heuristic to store checkpoints at
    /// the join, so the tests exercise the pruning machinery itself.
    /// `taken_r0` / `fall_r0` are the paths' r0 values; both paths also
    /// write a *dead* r7 (taken: 2, fall: 1) that is never read after
    /// the join:
    /// 0-5: r1..r6 = 1 (filler)
    /// 6: jeq r10, r10, +9 → taken 16, fall 7
    /// 7: r0 = fall_r0 ; 8: r7 = 1 ; 9-14: filler
    /// 15: jmp +6 → 22
    /// 16: r0 = taken_r0 ; 17: r7 = 2 ; 18-20: filler
    /// 21: jmp +3 → 25
    /// 22-23: filler ; 24: jmp +0 → 25
    /// 25: exit
    fn diamond(taken_r0: i32, fall_r0: i32) -> Vec<BpfInsn> {
        vec![
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 1 },
            BpfInsn::MovImm { dst: 4, imm: 1 },
            BpfInsn::MovImm { dst: 5, imm: 1 },
            BpfInsn::MovImm { dst: 6, imm: 1 },
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 9,
            },
            BpfInsn::MovImm {
                dst: 0,
                imm: fall_r0,
            },
            BpfInsn::MovImm { dst: 7, imm: 1 },
            BpfInsn::MovImm { dst: 9, imm: 1 },
            BpfInsn::MovImm { dst: 5, imm: 5 },
            BpfInsn::MovImm { dst: 6, imm: 6 },
            BpfInsn::MovImm { dst: 4, imm: 4 },
            BpfInsn::MovImm { dst: 3, imm: 3 },
            BpfInsn::MovImm { dst: 2, imm: 2 },
            BpfInsn::Jmp { offset: 6 },
            BpfInsn::MovImm {
                dst: 0,
                imm: taken_r0,
            },
            BpfInsn::MovImm { dst: 7, imm: 2 },
            BpfInsn::MovImm { dst: 9, imm: 2 },
            BpfInsn::MovImm { dst: 8, imm: 2 },
            BpfInsn::MovImm { dst: 5, imm: 5 },
            BpfInsn::Jmp { offset: 3 },
            BpfInsn::MovImm { dst: 6, imm: 6 },
            BpfInsn::MovImm { dst: 4, imm: 4 },
            BpfInsn::Jmp { offset: 0 },
            BpfInsn::Exit,
        ]
    }

    #[test]
    fn verify_mini_dedup_join_state() {
        // both branches rejoin at pc 25 with the same state; the second
        // arrival is pruned against the taken path's checkpoint
        // (states_equal), so exactly ONE checkpoint is stored at the
        // join — without the kernel-style pruning a second checkpoint
        // would be stored there
        let program = diamond(1, 1);
        // checkpoints: the taken path stores at the join (pc 25) and
        // the fall path at its own jump target (pc 22, also a prune
        // point) — 2 total. The dedup shows in the coverage map: the
        // fall's arrival at the join is pruned, so only ONE state is
        // analyzed at pc 25.
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(states.get(&25).unwrap().len(), 1);
    }

    #[test]
    fn verify_mini_dedup_distinct_join_states_not_merged() {
        // different r0 values (live at exit) → the join states differ
        // and both are stored
        let program = diamond(2, 1);
        // different r0 values (live at exit) → the join states differ,
        // so the fall's arrival is ANALYZED (not pruned): TWO states at
        // the join. The add_new_state heuristic still gates the third
        // store (fewer than 8 insns since the fall's own pc 22
        // checkpoint), so the checkpoint count stays 2 — like the
        // kernel's total_states.
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(states.get(&25).unwrap().len(), 2);
    }

    #[test]
    fn verify_mini_dead_register_difference_still_dedups() {
        // the paths write different r7 values, but r7 is never read
        // after the join: the liveness masks drop it from the
        // comparison (the kernel's live_regs_before behavior), so the
        // join states are still equal and the second arrival is pruned
        // (diamond(1, 1) has the built-in dead r7 = 2 vs 1 difference)
        let program = diamond(1, 1);
        let (_, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        // the dead r7 difference does not block the dedup: only ONE
        // state is analyzed at the join
        assert_eq!(states.get(&25).unwrap().len(), 1);
    }

    #[test]
    fn verify_mini_live_register_difference_blocks_dedup() {
        // the same shape, but r7 is read on the shared tail after the
        // join (25: r0 = r7; 26: exit): the paths' different r7 values
        // are live at the join, so the join states differ and both are
        // stored
        let mut program = diamond(1, 1);
        program.push(BpfInsn::MovReg { dst: 0, src: 7 });
        program.push(BpfInsn::Exit);
        // retarget the jumps to the new join at 26
        program[21] = BpfInsn::Jmp { offset: 4 };
        program[24] = BpfInsn::Jmp { offset: 1 };
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        // r7 is live at the join → the two arrivals differ → both are
        // analyzed (TWO states at the join pc 26)
        assert_eq!(count, 2);
        assert_eq!(states.get(&26).unwrap().len(), 2);
    }

    #[test]
    fn verify_mini_taken_branch_processed_first() {
        // the kernel processes the taken branch before the fall-through
        // (check_cond_jmp_op pushes the fall-through): with different
        // r0 values the join stores both checkpoints, and the coverage
        // map records the taken path's arrival (r0 = 2) first
        let program = diamond(2, 1);
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        assert_eq!(count, 2);
        let join = states.get(&25).expect("join pc recorded");
        assert_eq!(join.len(), 2);
        assert_eq!(
            join[0].regs[0],
            RegState::Scalar(ScalarBounds::constant(2)),
            "the taken path (r0 = 2) is analyzed first"
        );
        assert_eq!(join[1].regs[0], RegState::Scalar(ScalarBounds::constant(1)));
    }

    #[test]
    fn verify_mini_indirect_base_liveness_unsoundness_regression() {
        // regression for the reviewer finding on #97: the load at
        // [r6-8] (r6 = r10-8) really reads r10-16 (slot 1), but the
        // static liveness analysis cannot know the base's offset. The
        // taken path writes slot 1, the fall path does not; the fall's
        // read at the join must be REJECTED. Attributing the read to
        // the immediate offset alone (slot 0) would mark slot 1 dead,
        // clean it from the stored state, prune the fall path at the
        // join, and falsely ACCEPT the program:
        // 0: r6 = r10
        // 1: r6 += -8
        // 2: jeq r10, r10, +2 → taken 5, fall 3
        // 3: r0 = 0 ; 4: jmp +4 → 9
        // 5: r7 = 42 ; 6: [r10-16] = r7 ; 7: r0 = 0 ; 8: jmp +0 → 9
        // 9: r2 = [r6-8]  ← r10-16: uninit on the fall path → REJECT
        // 10: r0 = r2 ; 11: exit
        let program = vec![
            BpfInsn::MovReg { dst: 6, src: 10 },
            BpfInsn::AddImm { dst: 6, imm: -8 },
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Jmp { offset: 4 },
            BpfInsn::MovImm { dst: 7, imm: 42 },
            BpfInsn::StMem {
                src: 7,
                base: 10,
                offset: -16,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Jmp { offset: 0 },
            BpfInsn::LdMem {
                dst: 2,
                base: 6,
                offset: -8,
            },
            BpfInsn::MovReg { dst: 0, src: 2 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let err = verify_mini(&program, &heads).unwrap_err();
        assert!(err.message.contains("uninitialized"), "{}", err.message);
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
            BpfInsn::Call { imm: 7 },
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
        assert!(verify_mini(&program, &[]).is_ok());
    }

    // ── Verifier limits (v0.3) ───────────────────────────────────────────────

    #[test]
    fn verify_mini_limits_default_ok() {
        // the default limits accept normal programs
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        assert!(verify_mini(&program, &[]).is_ok());
    }

    #[test]
    fn verify_mini_max_states_exceeded() {
        // max_states bounds the stored checkpoints: a bounded counter
        // loop stores one checkpoint per iteration at its prune point
        // (after the add_new_state threshold), so a tight budget rejects
        // it while the default budget accepts it
        let program = vec![
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 2, imm: 100 },
            BpfInsn::MovImm { dst: 1, imm: 0 },
            BpfInsn::AddImm { dst: 1, imm: 1 },
            BpfInsn::Jlt {
                dst: 1,
                src: 2,
                offset: -2,
            },
            BpfInsn::Exit,
        ];
        // the kernel's in-progress store throttle (20 jmps / 100 insns
        // since the last store) keeps loop checkpoints sparse: the
        // 100-iteration loop stores 5, so a budget of 4 rejects it
        let tight = VerifierLimits {
            max_states: 4,
            max_steps: 100_000,
            max_loop_iterations: 4096,
        };
        let err = verify_mini_with_limits(&program, &[3], &tight).unwrap_err();
        assert!(
            err.message
                .contains("verification complexity limit exceeded")
        );
        assert!(err.message.contains("max_states"));

        // with enough room the same program is accepted
        let roomy = VerifierLimits {
            max_states: 1024,
            max_steps: 100_000,
            max_loop_iterations: 4096,
        };
        assert!(verify_mini_with_limits(&program, &[3], &roomy).is_ok());
    }

    #[test]
    fn verify_mini_max_steps_exceeded() {
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 1 }, BpfInsn::Exit];
        let limits = VerifierLimits {
            max_states: 100,
            max_steps: 1,
            max_loop_iterations: 4096,
        };
        let err = verify_mini_with_limits(&program, &[], &limits).unwrap_err();
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
        assert_eq!(limits.max_loop_iterations, 256);
    }

    #[test]
    fn verify_mini_helper_clobber_detected() {
        // reusing an argument register after a call is a #14 error:
        // 0: call 7   → R1..R5 invalidated
        // 1: r0 = r1  → R1 is uninitialized → REJECT
        // 2: exit
        let program = vec![
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovReg { dst: 0, src: 1 },
            BpfInsn::Exit,
        ];
        let err = verify_mini(&program, &[]).unwrap_err();
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
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovReg { dst: 0, src: 6 },
            BpfInsn::Exit,
        ];
        assert!(verify_mini(&program, &[]).is_ok());
    }
}

#[cfg(test)]
mod loop_fixed_point_tests {
    use super::*;
    use crate::insn::BpfInsn;

    /// A subsumed state at a loop pc whose successor loops back onto
    /// itself is a no-progress (infinite) loop. Regression: the old
    /// subsumption pruning used to hide it — the kernel rejects such
    /// programs with "infinite loop detected" (campaign finding
    /// mseed-999983-144: r0 = prandom(); if r0 >= 0x7fffffff goto -2).
    #[test]
    fn subsumed_fixed_point_loop_detected() {
        let program = vec![
            BpfInsn::Call { imm: 7 }, // r0 = prandom() — unknown scalar
            BpfInsn::MovImm { dst: 3, imm: 42 },
            BpfInsn::JgeImm {
                dst: 0,
                imm: 2147483647,
                offset: -2, // r0 >= 0x7fffffff → loop; r0 never changes
            },
            BpfInsn::Jle {
                dst: 0,
                src: 3,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 4, imm: 42 },
            BpfInsn::Jeq {
                dst: 0,
                src: 4,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let loop_heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let err = verify_mini(&program, &loop_heads).unwrap_err();
        assert!(err.message.contains("infinite loop"), "{}", err.message);
    }

    /// A bounded narrowing loop must still converge (no false
    /// infinite-loop detection).
    #[test]
    fn bounded_narrowing_loop_still_accepted() {
        // r2 = 3; loop: r2 -= 1; if r2 > 0 goto -2; r0 = 0; exit
        let program = vec![
            BpfInsn::MovImm { dst: 2, imm: 3 },
            BpfInsn::SubImm { dst: 2, imm: 1 },
            BpfInsn::JgtImm {
                dst: 2,
                imm: 0,
                offset: -2,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let loop_heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        assert!(verify_mini(&program, &loop_heads).is_ok());
    }
}
