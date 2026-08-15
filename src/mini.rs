// ── Mini pass: path-sensitive exploration (issue #97) ───────────────────────

use std::collections::HashMap;

use crate::error::VerificationFailure;
use crate::exec::successors;
use crate::insn::BpfInsn;
use crate::liveness::{Liveness, analyze};
use crate::state::{RegState, StackSlot, VerifierState, read_reg};
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

/// One executed instruction of a path segment: its pc and, for stack
/// accesses through a stack-pointer base, the covered slot range
/// (recorded at access time, so precision backtracking can resolve
/// fills/stores through computed stack pointers — the kernel's
/// jmp-history SPI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistEntry {
    pc: u32,
    slots: Option<(usize, usize)>,
}

/// One stored (checkpointed) state — the kernel's
/// `bpf_verifier_state_list` entry (kernel/bpf/states.c).
///
/// - `state` is the arrival state cleaned with its pc's liveness
///   (kernel `clean_verifier_state` before storing); precision
///   backtracking (#98) marks its scalars precise retroactively;
/// - `parent` points at the checkpoint this path descended from
///   (kernel `cur->parent = new` — the parent chain that precision
///   backtracking walks);
/// - `branches` counts the paths still pending under this checkpoint
///   (kernel `sl->state.branches`): a checkpoint with `branches == 0`
///   has been fully explored and proven safe, so it may prune
///   equivalent states; a checkpoint with `branches > 0` is still being
///   explored and only participates in infinite-loop detection;
/// - `segment` is the path segment ending at this checkpoint (the
///   instructions executed since the previous checkpoint) — precision
///   backtracking walks it when it moves to the parent state (the
///   kernel's per-state jmp_history + first/last insn idx).
struct Checkpoint {
    state: VerifierState,
    parent: Option<usize>,
    branches: usize,
    /// Prune statistics (kernel `hit_cnt`/`miss_cnt`): a state that
    /// misses much more often than it hits is evicted from the
    /// comparison list.
    hit_cnt: usize,
    miss_cnt: usize,
    /// The executed instructions since the previous checkpoint.
    segment: Vec<HistEntry>,
}

/// One worklist item: a path arriving at `pc` with abstract state
/// `state`. `last_cp` is the deepest checkpoint on this path's parent
/// chain — the checkpoint whose branch count this path belongs to.
/// `history` is the path segment executed since `last_cp` (the kernel's
/// jmp_history) — precision backtracking walks it (#98).
struct WorkItem {
    pc: u32,
    state: VerifierState,
    last_cp: Option<usize>,
    history: Vec<HistEntry>,
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

/// The kernel's scalar precision backtracking (#98, kernel/bpf/backtrack.c):
///
/// A value-dependent site (a static branch verdict, pointer+scalar ALU)
/// requires the operand registers precise. The requirement is propagated
/// BACKWARD through the path's executed instructions — each instruction
/// transforms the required set (a constant assignment resolves it, a mov
/// forwards it to the source, a stack fill forwards it to the slot, a
/// stack store forwards it to the stored register) — and into every
/// stored checkpoint on the parent chain, which is exactly what makes
/// the NOT_EXACT imprecise scalar shortcut sound: a checkpoint whose
/// scalar is precise enforces the range on future arrivals, so their
/// value-dependent decisions cannot diverge.
///
/// If the requirement cannot be resolved (the chain is exhausted or a
/// helper call consumed an argument), the conservative hammer is used:
/// every scalar in every chain checkpoint becomes precise (kernel
/// `bpf_mark_all_scalars_precise`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Backtrack {
    regs: u16,
    slots: u64,
}

impl Backtrack {
    fn is_empty(&self) -> bool {
        self.regs == 0 && self.slots == 0
    }
}

enum BacktrackOutcome {
    /// The requirement was fully resolved — stop the walk.
    Resolved,
    /// The instruction cannot be backtracked — fall back to marking
    /// every scalar precise.
    Fallback,
    /// Continue walking backward.
    Continue,
}

/// One instruction of the backward walk (kernel `backtrack_insn`).
fn backtrack_insn(
    insn: &BpfInsn,
    slots: Option<(usize, usize)>,
    bt: &mut Backtrack,
) -> BacktrackOutcome {
    let dst_bit = |r: u8| 1u16 << r;
    match insn {
        // `dreg = K` — a constant resolves the requirement
        BpfInsn::MovImm { dst, .. } => bt.regs &= !dst_bit(*dst),
        // `dreg = sreg` — the requirement moves to the source
        BpfInsn::MovReg { dst, src } => {
            if bt.regs & dst_bit(*dst) != 0 {
                bt.regs &= !dst_bit(*dst);
                if *src != 10 {
                    bt.regs |= dst_bit(*src);
                }
            }
        }
        // `dreg op= K` — the result depends on dreg's old value
        BpfInsn::AddImm { dst, .. }
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
        | BpfInsn::Arsh32Imm { dst, .. } => {
            let _ = dst;
        }
        // `dreg op= sreg` — both dreg (old value) and sreg contribute
        BpfInsn::AddReg { dst, src }
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
            if bt.regs & dst_bit(*dst) != 0 && *src != 10 {
                bt.regs |= dst_bit(*src);
            }
        }
        // `dreg = [base+off]`: a stack fill forwards the requirement to
        // the covered slots; a load from other memory has a
        // path-independent result — the requirement is dropped (kernel:
        // "Load from any other memory can be zero extended. No further
        // tracking necessary")
        BpfInsn::LdMem { dst, .. } => {
            if bt.regs & dst_bit(*dst) != 0 {
                bt.regs &= !dst_bit(*dst);
                if let Some((lo, hi)) = slots {
                    for s in lo..=hi {
                        bt.slots |= 1u64 << s;
                    }
                }
            }
        }
        // `[base+off] = sreg`: a stack store feeding a required slot
        // forwards the requirement to the stored register
        BpfInsn::StMem { src, .. } => {
            if let Some((lo, hi)) = slots {
                let mut hit = false;
                for s in lo..=hi {
                    if bt.slots & (1u64 << s) != 0 {
                        bt.slots &= !(1u64 << s);
                        hit = true;
                    }
                }
                if hit && *src != 10 {
                    bt.regs |= dst_bit(*src);
                }
            }
        }
        // ldimm64 family: constants/pointers resolve the requirement
        BpfInsn::LdImm64 { dst, .. }
        | BpfInsn::LdMapFd { dst, .. }
        | BpfInsn::LdMapValue { dst, .. } => bt.regs &= !dst_bit(*dst),
        BpfInsn::LdImm64Second { .. } => {}
        // a helper call or BPF-to-BPF call writes R0; the argument
        // registers were either consumed by the call's own checks or
        // are dead — a requirement still pending on them cannot be
        // resolved here (kernel: verifier_bug; we fall back
        // conservatively)
        BpfInsn::Call { .. } | BpfInsn::CallSub { .. } => {
            bt.regs &= !(1u16 << 0);
            if bt.regs & 0b111110 != 0 {
                return BacktrackOutcome::Fallback;
            }
        }
        BpfInsn::Exit => {}
        BpfInsn::Jmp { .. } => {}
        // a conditional jump in the history: the branch operands'
        // values determined the path's refinement — both contribute if
        // either is required (kernel: `dreg <cond> sreg` → both need
        // precision before this insn)
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
            if bt.regs & (dst_bit(*dst) | dst_bit(*src)) != 0 {
                bt.regs |= dst_bit(*dst) | dst_bit(*src);
            }
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
        | BpfInsn::JsleImm { dst, .. } => {
            let _ = dst;
        }
    }
    if bt.is_empty() {
        BacktrackOutcome::Resolved
    } else {
        BacktrackOutcome::Continue
    }
}

/// Mark the requirement in one stored checkpoint: required scalars
/// become precise (already-precise ones and non-scalars leave the
/// requirement).
fn mark_checkpoint(checkpoints: &mut [Checkpoint], cp_idx: usize, bt: &mut Backtrack) {
    let cp = &mut checkpoints[cp_idx];
    for r in 0..crate::state::NUM_REGS {
        if bt.regs & (1 << r) == 0 {
            continue;
        }
        bt.regs &= !(1 << r);
        if let RegState::Scalar(b) = &mut cp.state.regs[r] {
            b.precise = true;
        }
    }
    for s in 0..crate::state::STACK_SLOTS {
        if bt.slots & (1 << s) == 0 {
            continue;
        }
        bt.slots &= !(1 << s);
        if let StackSlot::Spilled(RegState::Scalar(b)) = &mut cp.state.stack.slots[s] {
            b.precise = true;
        }
    }
}

/// The conservative hammer (kernel `bpf_mark_all_scalars_precise`):
/// every scalar in every checkpoint on the chain becomes precise.
fn mark_all_scalars_precise(checkpoints: &mut [Checkpoint], mut last_cp: Option<usize>) {
    while let Some(i) = last_cp {
        let cp = &mut checkpoints[i];
        for reg in cp.state.regs.iter_mut() {
            if let RegState::Scalar(b) = reg {
                b.precise = true;
            }
        }
        for slot in cp.state.stack.slots.iter_mut() {
            if let StackSlot::Spilled(RegState::Scalar(b)) = slot {
                b.precise = true;
            }
        }
        last_cp = cp.parent;
    }
}

/// Walk the requirement backward through the path segments and mark the
/// chain checkpoints (kernel `bpf_mark_chain_precision`).
fn mark_chain_precision(
    program: &[BpfInsn],
    checkpoints: &mut [Checkpoint],
    mut last_cp: Option<usize>,
    segment: &[HistEntry],
    regs: u16,
) {
    let mut bt = Backtrack { regs, slots: 0 };
    if bt.is_empty() {
        return;
    }
    // the segments of the chain, deepest first: the item's own history,
    // then each checkpoint's segment
    let mut segments: Vec<Vec<HistEntry>> = Vec::new();
    segments.push(segment.to_vec());
    let mut cp = last_cp;
    while let Some(i) = cp {
        segments.push(checkpoints[i].segment.clone());
        cp = checkpoints[i].parent;
    }
    for seg in &segments {
        let mut fallback = false;
        for entry in seg.iter().rev() {
            let insn = &program[entry.pc as usize];
            match backtrack_insn(insn, entry.slots, &mut bt) {
                BacktrackOutcome::Resolved => return,
                BacktrackOutcome::Fallback => {
                    fallback = true;
                    break;
                }
                BacktrackOutcome::Continue => {}
            }
        }
        if fallback {
            break;
        }
        // mark the checkpoint this segment belongs to (the item's own
        // history belongs to the deepest checkpoint)
        let Some(i) = last_cp else {
            break;
        };
        mark_checkpoint(checkpoints, i, &mut bt);
        if bt.is_empty() {
            return;
        }
        last_cp = checkpoints[i].parent;
    }
    mark_all_scalars_precise(checkpoints, last_cp);
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

/// The destination register of an instruction (0 for insns without one).
fn insn_dst(insn: &BpfInsn) -> u8 {
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
        | BpfInsn::LdMem { dst, .. }
        | BpfInsn::LdImm64 { dst, .. }
        | BpfInsn::LdMapFd { dst, .. }
        | BpfInsn::LdMapValue { dst, .. }
        | BpfInsn::Jeq { dst, .. }
        | BpfInsn::Jne { dst, .. }
        | BpfInsn::Jgt { dst, .. }
        | BpfInsn::Jge { dst, .. }
        | BpfInsn::Jlt { dst, .. }
        | BpfInsn::Jle { dst, .. }
        | BpfInsn::Jsgt { dst, .. }
        | BpfInsn::Jsge { dst, .. }
        | BpfInsn::Jslt { dst, .. }
        | BpfInsn::Jsle { dst, .. }
        | BpfInsn::JeqImm { dst, .. }
        | BpfInsn::JneImm { dst, .. }
        | BpfInsn::JgtImm { dst, .. }
        | BpfInsn::JgeImm { dst, .. }
        | BpfInsn::JltImm { dst, .. }
        | BpfInsn::JleImm { dst, .. }
        | BpfInsn::JsgtImm { dst, .. }
        | BpfInsn::JsgeImm { dst, .. }
        | BpfInsn::JsltImm { dst, .. }
        | BpfInsn::JsleImm { dst, .. } => *dst,
        _ => 0,
    }
}

/// The source register of a reg-reg instruction.
fn insn_src(insn: &BpfInsn) -> Option<u8> {
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
        | BpfInsn::Arsh32Reg { src, .. }
        | BpfInsn::Jeq { src, .. }
        | BpfInsn::Jne { src, .. }
        | BpfInsn::Jgt { src, .. }
        | BpfInsn::Jge { src, .. }
        | BpfInsn::Jlt { src, .. }
        | BpfInsn::Jle { src, .. }
        | BpfInsn::Jsgt { src, .. }
        | BpfInsn::Jsge { src, .. }
        | BpfInsn::Jslt { src, .. }
        | BpfInsn::Jsle { src, .. } => Some(*src),
        _ => None,
    }
}

/// Whether a register state is a pointer (precision sites mark only
/// scalar operands — pointers are compared structurally).
fn is_pointer(state: RegState) -> bool {
    !matches!(state, RegState::Uninit | RegState::Scalar(_))
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
        history: Vec::new(),
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
            // the kernel forces a checkpoint when the jmp history grows
            // too long (`cur->jmp_history_cnt > 40` — ours counts every
            // instruction of the segment, so the bound is larger)
            let force_new_state = item.history.len() >= 64;
            let mut add_new_state = force_new_state
                || (insn_processed - prev_insn_processed >= 8
                    && jmps_processed - prev_jmps_processed >= 2);
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
                    segment: item.history.clone(),
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

        // an exit inside a subprogram returns to the caller (#100):
        // the callee's R0 becomes the caller's R0 (a scalar return, like
        // the kernel's check_return_code), the caller frame is restored
        // with its callee-saved registers, and the path continues at
        // the call site + 1. The kernel only rejects a STACK pointer
        // return here ("cannot return stack pointer to the caller" —
        // other pointer types are legal in static subprogs). The
        // OUTERMOST exit ends the path and requires a scalar R0.
        if matches!(insn, BpfInsn::Exit) && item.state.curframe > 0 {
            let r0 = read_reg(pc, &item.state, 0)
                .map_err(|_| VerificationFailure::new(pc, "r0 is uninitialized at subprog exit"))?;
            if matches!(r0, RegState::PtrToStack { .. }) {
                return Err(VerificationFailure::new(
                    pc,
                    "cannot return stack pointer to the caller",
                ));
            }
            // the callee's return address (its call site + 1); after
            // the pop, the state's ret_pc is the caller frame's own
            // return address for ITS eventual return
            let return_pc = item.state.ret_pc;
            let mut returned = item.state;
            returned.return_from_subprog();
            // the returned path continues at the call site + 1 with a
            // fresh history segment (#100)
            bump_branches(&mut checkpoints, item.last_cp, 1);
            worklist.push(WorkItem {
                pc: return_pc,
                state: returned,
                last_cp: item.last_cp,
                history: Vec::new(),
            });
            // the exit item is consumed
            bump_branches(&mut checkpoints, item.last_cp, -1);
            continue;
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

        let nexts = successors(pc, insn, &item.state)?;

        // ── precision requirements (#98) ─────────────────────────────
        // A conditional branch with exactly ONE successor used the
        // static verdict (is_branch_taken) to prune the other branch —
        // the operands' ranges decided it, so they must be precise in
        // the stored states (kernel check_cond_jmp_op: pred >= 0 →
        // mark_chain_precision on both operands). Scalar ALU on a
        // pointer destination derives the pointer's offset from the
        // scalar — the scalar must be precise too (kernel
        // adjust_reg_min_max_vals: mark_chain_precision(src)).
        let mut precision_regs: u16 = 0;
        if insn.is_conditional_branch() && nexts.len() == 1 {
            precision_regs |= 1 << insn_dst(insn);
            if let Some(src) = insn_src(insn) {
                precision_regs |= 1 << src;
            }
        } else if let Some(src) = insn_src(insn)
            && matches!(
                insn,
                BpfInsn::AddReg { .. }
                    | BpfInsn::SubReg { .. }
                    | BpfInsn::AndReg { .. }
                    | BpfInsn::OrReg { .. }
                    | BpfInsn::XorReg { .. }
                    | BpfInsn::Add32Reg { .. }
                    | BpfInsn::Sub32Reg { .. }
            )
            && is_pointer(item.state.regs[insn_dst(insn) as usize])
            && matches!(item.state.regs[src as usize], RegState::Scalar(_))
        {
            precision_regs |= 1 << src;
        } else if matches!(insn, BpfInsn::AddReg { .. })
            && matches!(
                item.state.regs[insn_dst(insn) as usize],
                RegState::Scalar(_)
            )
            && is_pointer(item.state.regs[insn_src(insn).unwrap() as usize])
        {
            // `scalar += pointer`: the scalar's value determines the
            // resulting pointer offset — it must be precise (kernel
            // adjust_reg_min_max_vals: mark_chain_precision(dst_reg)
            // for scalar += pointer)
            precision_regs |= 1 << insn_dst(insn);
        }
        if precision_regs != 0 {
            // the kernel links the freshly-stored checkpoint before the
            // instruction runs (`cur->parent = new` in is_state_visited),
            // so a value-dependent site at a store pc marks the NEW
            // checkpoint. When a checkpoint was stored at this pc, its
            // segment IS this item's history — pass the post-store chain
            // with an empty item segment so the history is walked once.
            let (mark_cp, mark_segment) = if item_last_cp != item.last_cp {
                (item_last_cp, Vec::new())
            } else {
                (item.last_cp, item.history.clone())
            };
            mark_chain_precision(
                program,
                &mut checkpoints,
                mark_cp,
                &mark_segment,
                precision_regs,
            );
        }
        // the history entry for the current instruction: the covered
        // slot range for stack accesses through a stack-pointer base
        // (resolves precision backtracking through computed pointers)
        let hist_entry = HistEntry {
            pc,
            slots: match insn {
                BpfInsn::LdMem { base, offset, .. } | BpfInsn::StMem { base, offset, .. }
                    if matches!(item.state.regs[*base as usize], RegState::PtrToStack { .. }) =>
                {
                    crate::exec::stack_access_range(pc, *base, &item.state, *offset).ok()
                }
                _ => None,
            },
        };
        for (next_pc, next_state) in nexts.into_iter().rev() {
            // the kernel pushes the fall-through and continues with the
            // taken branch — with our LIFO worklist, pushing in reverse
            // reproduces that order (taken processed first)
            bump_branches(&mut checkpoints, item_last_cp, 1);
            // the history resets at a stored checkpoint: the successors
            // of the storing item start a new segment at this pc (the
            // kernel clears the jmp history at is_state_visited)
            let history = if item_last_cp != item.last_cp {
                vec![hist_entry]
            } else {
                let mut h = item.history.clone();
                h.push(hist_entry);
                h
            };
            worklist.push(WorkItem {
                pc: next_pc,
                state: next_state,
                last_cp: item_last_cp,
                history,
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
    fn verify_mini_imprecise_join_difference_pruned() {
        // the paths write different r0 values, but NO value-dependent
        // use ever needs r0's range (the exit check is type-only): the
        // scalar stays imprecise, so the join states are equal and the
        // second arrival is pruned — the kernel's precision behavior
        // (#98): "if (!rold->precise && exact == NOT_EXACT) return
        // true"
        let program = diamond(2, 1);
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(states.get(&25).unwrap().len(), 1);
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
    fn verify_mini_precise_join_difference_blocks_dedup() {
        // the same shape, but the shared tail's branch compares r7
        // against a constant with a static verdict: the verdict's
        // precision backtracking marks r7 precise in the stored join
        // checkpoint, so the second arrival's different r7 is NOT
        // pruned — the soundness anchor of the imprecise shortcut:
        // 25: r0 = r7 ; 26: jgt r7, 100, +1 (always taken: 7/42 < 100)
        // 27: exit ; 28: exit
        let mut program = diamond(1, 1);
        program.push(BpfInsn::MovReg { dst: 0, src: 7 });
        program.push(BpfInsn::JgtImm {
            dst: 7,
            imm: 100,
            offset: 1,
        });
        program.push(BpfInsn::Exit);
        program.push(BpfInsn::Exit);
        // retarget the jumps to the new join at 26
        program[21] = BpfInsn::Jmp { offset: 4 };
        program[24] = BpfInsn::Jmp { offset: 1 };
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        // r7 is precise at the join → the two arrivals differ → both
        // are analyzed (TWO states at the join pc 26)
        assert_eq!(count, 2);
        assert_eq!(states.get(&26).unwrap().len(), 2);
    }

    #[test]
    fn verify_mini_taken_branch_processed_first() {
        // the kernel processes the taken branch before the fall-through
        // (check_cond_jmp_op pushes the fall-through): with a PRECISE
        // r7 difference (the tail's verdict marks it, see the test
        // above) both join arrivals are analyzed, and the coverage map
        // records the taken path's arrival (r7 = 2) first
        let mut program = diamond(1, 1);
        program.push(BpfInsn::MovReg { dst: 0, src: 7 });
        program.push(BpfInsn::JgtImm {
            dst: 7,
            imm: 100,
            offset: 1,
        });
        program.push(BpfInsn::Exit);
        program.push(BpfInsn::Exit);
        program[21] = BpfInsn::Jmp { offset: 4 };
        program[24] = BpfInsn::Jmp { offset: 1 };
        let (count, states) =
            verify_mini_with_states(&program, &[], &VerifierLimits::default()).unwrap();
        assert_eq!(count, 2);
        let join = states.get(&26).expect("join pc recorded");
        assert_eq!(join.len(), 2);
        assert_eq!(
            join[0].regs[7],
            RegState::Scalar(ScalarBounds::constant(2)),
            "the taken path (r7 = 2) is analyzed first"
        );
        assert_eq!(join[1].regs[7], RegState::Scalar(ScalarBounds::constant(1)));
    }

    #[test]
    fn verify_mini_branch_verdict_precision_prevents_false_accept() {
        // the soundness anchor of the imprecise scalar shortcut (#98):
        // the two paths' r7 values straddle the verdict boundary of the
        // shared tail's branch, so the verdicts (and the explored
        // continuations) differ. The taken path's verdict at pc 27
        // backtracks and marks r7 precise in the stored join
        // checkpoint; the fall path's arrival (r7 = 50) must NOT be
        // pruned against it — its continuation contains an
        // uninitialized stack read that the kernel rejects:
        // 0-5: r1..r6 = 1
        // 6: jeq r10, r10, +3 → taken 10, fall 7
        // 7: r0 = 0 ; 8: r7 = 50 ; 9: jmp +6 → 16
        // 10: r0 = 0 ; 11: r7 = 150 ; 12: r9 = 1 ; 13: r8 = 1
        // 14: jmp +1 → 16 ; 15: r6 = 6
        // 16: r0 = r7 ; 17: jgt r7, 100, +1 → taken 19, fall 18
        // 18: r2 = [r10-8]  ← uninit on the fall's verdict direction
        // 19: exit
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 1 },
            BpfInsn::MovImm { dst: 4, imm: 1 },
            BpfInsn::MovImm { dst: 5, imm: 1 },
            BpfInsn::MovImm { dst: 6, imm: 1 },
            BpfInsn::Jeq {
                dst: 10,
                src: 10,
                offset: 3,
            },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 7, imm: 50 },
            BpfInsn::Jmp { offset: 7 },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 7, imm: 150 },
            BpfInsn::MovImm { dst: 9, imm: 1 },
            BpfInsn::MovImm { dst: 8, imm: 1 },
            BpfInsn::MovImm { dst: 6, imm: 6 },
            BpfInsn::MovImm { dst: 5, imm: 5 },
            BpfInsn::Jmp { offset: 0 },
            BpfInsn::MovReg { dst: 0, src: 7 },
            BpfInsn::JgtImm {
                dst: 7,
                imm: 100,
                offset: 1,
            },
            BpfInsn::LdMem {
                dst: 2,
                base: 10,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let err = verify_mini(&program, &heads).unwrap_err();
        assert!(
            err.message.contains("uninitialized"),
            "the fall path's uninit read must be found: {}",
            err.message
        );
    }

    #[test]
    fn verify_mini_bounded_loop_checkpoint_count() {
        // the bounded counter loop: the jlt's static verdict marks r1
        // precise (the kernel: 204 processed insns, total_states 6 for
        // the 100-iteration loop), so the iterations do not collapse
        // via the imprecise shortcut — but the in-progress store
        // throttle keeps the CHECKPOINT count small, like the kernel's
        // total_states
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
        let count = verify_mini(&program, &[3]).unwrap();
        // the kernel stores 6 states for this loop; ours stays in the
        // same ballpark (a handful of checkpoints, not one per
        // iteration)
        assert!(count <= 8, "checkpoint count {count} too large");
    }

    #[test]
    fn verify_mini_scalar_plus_pointer_precision_regression() {
        // #98 review blocker 1: `scalar += pointer` derives the
        // pointer offset from the scalar, so the scalar must be marked
        // precise — otherwise the imprecise shortcut prunes a path
        // whose pointer offset leaves the frame:
        // 0: call 7 ; 1: r4 = 42 ; 2: [r10-8] = r4 ; 3: r5 = r0
        // 4: r6 = 15 ; 5: jgt r5, r6, +2 (unknown) → taken 8 (r0=0),
        //    fall 6 (r0=200)
        // 6: r0 = 200 ; 7: jmp +2 → 10
        // 8: r0 = 0 ; 9: jmp +1 → 11
        // 10: r3 = 3
        // 11: r0 += r10        (scalar += pointer — the join)
        // 12: r2 = [r0-8]      (r10-8 for r0=0; r10+192 for r0=200 → REJECT)
        // 13: r0 = r2 ; 14: exit
        let program = vec![
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovImm { dst: 4, imm: 42 },
            BpfInsn::StMem {
                src: 4,
                base: 10,
                offset: -8,
            },
            BpfInsn::MovReg { dst: 5, src: 0 },
            BpfInsn::MovImm { dst: 6, imm: 15 },
            BpfInsn::Jgt {
                dst: 5,
                src: 6,
                offset: 2,
            },
            BpfInsn::MovImm { dst: 0, imm: 200 },
            BpfInsn::Jmp { offset: 2 },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 3, imm: 3 },
            BpfInsn::AddReg { dst: 0, src: 10 },
            BpfInsn::LdMem {
                dst: 2,
                base: 0,
                offset: -8,
            },
            BpfInsn::MovReg { dst: 0, src: 2 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let err = verify_mini(&program, &heads).unwrap_err();
        assert!(
            err.message.contains("exceeds"),
            "the r0=200 path's out-of-frame access must be found: {}",
            err.message
        );
    }

    #[test]
    fn verify_mini_store_pc_site_marks_new_checkpoint() {
        // #98 review blocker 2: a value-dependent site at a pc that
        // ALSO stores a checkpoint must mark the NEW checkpoint (the
        // kernel links `cur->parent = new` before processing the
        // instruction) — otherwise the sibling path with a different
        // verdict direction is pruned and its unsafe continuation is
        // never checked:
        // 0: call 7 ; 1: r5 = r0 ; 2: r6 = 15 ; 3: r1 = 1 ; 4: r2 = 1
        // 5: r3 = 1 ; 6: r4 = 1
        // 7: jgt r5, r6, +3 (unknown) → taken 11 (A, r0=0), fall 8 (B, r0=200)
        // 8: r0 = 200 ; 9: r9 = 1 ; 10: jmp +3 → 14
        // 11: r0 = 0 ; 12: r9 = 1 ; 13: jmp +1 → 15
        // 14: r8 = 1
        // 15: jlt r0, r1, +2  (prune point AND verdict: A taken → 18;
        //                      B: 200<1 false → 16)
        // 16: r2 = [r10-8]     (uninit — B only → REJECT)
        // 17: r0 = r9 ; 18: exit
        let program = vec![
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovReg { dst: 5, src: 0 },
            BpfInsn::MovImm { dst: 6, imm: 15 },
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 2, imm: 1 },
            BpfInsn::MovImm { dst: 3, imm: 1 },
            BpfInsn::MovImm { dst: 4, imm: 1 },
            BpfInsn::Jgt {
                dst: 5,
                src: 6,
                offset: 3,
            },
            BpfInsn::MovImm { dst: 0, imm: 200 },
            BpfInsn::MovImm { dst: 9, imm: 1 },
            BpfInsn::Jmp { offset: 3 },
            BpfInsn::MovImm { dst: 0, imm: 0 },
            BpfInsn::MovImm { dst: 9, imm: 1 },
            BpfInsn::Jmp { offset: 1 },
            BpfInsn::MovImm { dst: 8, imm: 1 },
            BpfInsn::Jlt {
                dst: 0,
                src: 1,
                offset: 2,
            },
            BpfInsn::LdMem {
                dst: 2,
                base: 10,
                offset: -8,
            },
            BpfInsn::MovReg { dst: 0, src: 9 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let err = verify_mini(&program, &heads).unwrap_err();
        assert!(
            err.message.contains("uninitialized"),
            "the B path's uninit read must be found: {}",
            err.message
        );
    }

    #[test]
    fn verify_mini_subprog_call_basic() {
        // a simple BPF-to-BPF call (#100):
        // main:  r1 = 5 ; call sub @3 (r1 arg) ; r0 = r0 + 1 ; exit
        // sub @3: r0 = r1 ; r0 += 1 ; exit     (r0 = arg + 1)
        // → main's r0 = 6
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::CallSub { offset: 2 },
            BpfInsn::AddImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
            BpfInsn::MovReg { dst: 0, src: 1 },
            BpfInsn::AddImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        assert_eq!(subprogs, vec![0, 4]);
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        assert!(verify_mini(&program, &heads).is_ok());
    }

    #[test]
    fn verify_mini_subprog_callee_saved_and_args() {
        // the callee's r6..r9 are its own; the caller's survive the
        // call (restored on the return); the caller's r1..r5 are
        // clobbered:
        // main: r6 = 42 ; r1 = 7 ; call sub @5 ; r0 = r6 ; exit
        // sub @5: r6 = 0 ; r0 = r1 ; exit
        let program = vec![
            BpfInsn::MovImm { dst: 6, imm: 42 },
            BpfInsn::MovImm { dst: 1, imm: 7 },
            BpfInsn::CallSub { offset: 2 },
            BpfInsn::MovReg { dst: 0, src: 6 },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 6, imm: 0 },
            BpfInsn::MovReg { dst: 0, src: 1 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        assert_eq!(subprogs, vec![0, 5]);
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        // the main's r6 = 42 survives the call → r0 = 42 at exit
        let (_, states) =
            verify_mini_with_states(&program, &heads, &VerifierLimits::default()).unwrap();
        // the exit pc (4): r0 must be the restored 42
        let exit_states = states.get(&4).expect("exit pc analyzed");
        assert!(exit_states.iter().any(|st| matches!(
            st.regs[0],
            RegState::Scalar(b) if b.smin == 42
        )));
    }

    #[test]
    fn verify_mini_subprog_recursion_rejected() {
        // a subprogram calling itself: the call depth limit fires
        // a recursive subprogram whose state CHANGES per recursion (r1
        // decreases) — the loop detection cannot fire, and the call
        // depth grows until the frame limit rejects:
        // main: 0: call 7 ; 1: r1 = r0 ; 2: call sub @4 ; 3: exit
        // sub:  4: r1 -= 1 ; 5: jgt r1, 1, +1 → taken 7, fall 6
        //       6: exit ; 7: call sub @4 (self) ; 8: exit
        let program = vec![
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovReg { dst: 1, src: 0 },
            BpfInsn::CallSub { offset: 1 },
            BpfInsn::Exit,
            BpfInsn::AddImm { dst: 1, imm: -1 },
            BpfInsn::JgtImm {
                dst: 1,
                imm: 1,
                offset: 1,
            },
            BpfInsn::Exit,
            BpfInsn::CallSub { offset: -4 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        assert_eq!(subprogs, vec![0, 4]);
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        // the kernel rejects recursive programs; the mini rejects via
        // the frame-depth limit, the loop detection, or the exit checks
        assert!(verify_mini(&program, &heads).is_err());
    }

    #[test]
    fn verify_mini_nested_subprog_calls() {
        // nested BPF-to-BPF calls must return to the right caller
        // (#100 review BLOCKER: the return address is per frame):
        // main: 0: r1 = 1 ; 1: call A @4 ; 2: r0 += 1 ; 3: exit
        // A @4: 4: r6 = 7 ; 5: call B @8 ; 6: r0 = r6 ; 7: exit
        // B @8: 8: r0 = 1 ; 9: exit
        // B returns 1 to A; A's callee-saved r6 = 7 survives the nested
        // call; A returns 7 to main; main: 7 + 1 = 8
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::CallSub { offset: 2 },
            BpfInsn::AddImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 6, imm: 7 },
            BpfInsn::CallSub { offset: 2 },
            BpfInsn::MovReg { dst: 0, src: 6 },
            BpfInsn::Exit,
            BpfInsn::MovImm { dst: 0, imm: 1 },
            BpfInsn::Exit,
        ];
        let subprogs = crate::cfg::add_subprog(&program).unwrap();
        assert_eq!(subprogs, vec![0, 4, 8]);
        let heads = crate::cfg::check_cfg(&program, &subprogs).unwrap();
        let (_, states) =
            verify_mini_with_states(&program, &heads, &VerifierLimits::default()).unwrap();
        // the main's exit (pc 3): r0 = 8
        let exit_states = states.get(&3).expect("main exit analyzed");
        assert!(
            exit_states.iter().any(|st| matches!(
                st.regs[0],
                RegState::Scalar(b) if b.smin == 8
            )),
            "main r0 must be 8 after the nested calls"
        );
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
