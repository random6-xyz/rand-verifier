// ── ProgSpec runner: path exploration + safety checks (issue #112) ──────────

//! The independent safety-spec verifier (SpecCheck style, SOSP '25).
//! Walks every path of the program with dynamic-type values (u64
//! intervals + pointer kinds) and enforces the safety invariants:
//!
//! - SP1 control-flow safety: bounded exploration, no unbounded loops
//!   (a revisited identical state prunes the path; non-converging
//!   loops hit the state budget)
//! - SP2 memory safety: in-bounds, aligned, initialized accesses;
//!   NULL-checked nullable pointers; no narrow fills of spilled
//!   pointers; no partial writes over spills
//! - SP3 resource safety: every acquired reference is released before
//!   exit
//!
//! Deliberately NOT a clone of mini: a single wrapping u64 interval
//! instead of mini's four ranges + tnum, a visited-set loop handler
//! instead of kernel-style checkpoints/pruning, and its own helper
//! table ([`super::helper`]).

use std::collections::HashMap;

use crate::env::MapInfo;
use crate::insn::{BpfInsn, MemSize};

use super::helper::{SpecArg, SpecRet, dynptr_slots_of, spec_helper};
use super::state::{SPEC_SLOTS, SPEC_STACK_SIZE, SpecFrame, SpecStack, SpecState, Spill};
use super::value::{
    SpecValue, as_signed, range32, rng_add, rng_and, rng_arsh, rng_lsh, rng_mul, rng_or, rng_rsh,
    rng_sub, rng_xor,
};

/// A safety violation — the spec's rejection reason (displayed in the
/// verdict report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecFailure {
    pub(crate) pc: u32,
    pub(crate) message: String,
}

impl SpecFailure {
    pub(crate) fn new(pc: u32, message: impl Into<String>) -> Self {
        Self {
            pc,
            message: message.into(),
        }
    }
}

/// The spec verdict on one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpecVerdict {
    /// Every explored path satisfied the safety invariants (bounded
    /// evidence, like the concrete side — not a proof).
    Accept,
    /// A safety violation was found.
    Reject(SpecFailure),
    /// The program uses a surface the spec does not model (unknown
    /// helper, unsupported instruction) — a non-finding.
    Inconclusive,
}

/// Exploration limits for the spec runner.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpecLimits {
    pub(crate) max_states: usize,
    pub(crate) max_steps: usize,
}

impl Default for SpecLimits {
    fn default() -> Self {
        Self {
            max_states: 8192,
            max_steps: 200_000,
        }
    }
}

/// The kernel's arithmetic-time sanity bound (check_reg_sane_offset_*).
const BPF_MAX_VAR_OFF: i64 = 1 << 29;

/// Verify one program with the safety spec.
pub(crate) fn verify_spec(program: &[BpfInsn], maps: &HashMap<u32, MapInfo>) -> SpecVerdict {
    verify_spec_limited(program, maps, &SpecLimits::default())
}

pub(crate) fn verify_spec_limited(
    program: &[BpfInsn],
    maps: &HashMap<u32, MapInfo>,
    limits: &SpecLimits,
) -> SpecVerdict {
    let loop_heads = compute_loop_heads(program);
    let mut runner = SpecRunner {
        program,
        maps,
        visited: HashMap::new(),
        loop_heads,
        next_ref_id: 0x4000_0000,
        limits: *limits,
    };
    runner.run()
}

struct SpecRunner<'a> {
    program: &'a [BpfInsn],
    maps: &'a HashMap<u32, MapInfo>,
    /// (pc, state) pairs already explored — an identical revisit on a
    /// loop head is an infinite loop (kernel is_state_visited EXACT),
    /// elsewhere it prunes the path.
    visited: HashMap<(u32, SpecState), ()>,
    /// Back-edge targets: the pc of every jump whose target is
    /// strictly below the jump (kernel loop heads).
    loop_heads: Vec<u32>,
    next_ref_id: u32,
    limits: SpecLimits,
}

/// One worklist item.
struct WorkItem {
    pc: u32,
    state: SpecState,
}

impl<'a> SpecRunner<'a> {
    fn failure(&self, pc: u32, msg: impl Into<String>) -> SpecVerdict {
        SpecVerdict::Reject(SpecFailure::new(pc, msg))
    }

    fn run(&mut self) -> SpecVerdict {
        let mut worklist: Vec<WorkItem> = vec![WorkItem {
            pc: 0,
            state: SpecState::initial(),
        }];
        let mut steps = 0usize;

        while let Some(item) = worklist.pop() {
            steps += 1;
            if steps > self.limits.max_steps {
                return self.failure(item.pc, "spec exploration budget exceeded (max_steps)");
            }
            if self.visited.len() > self.limits.max_states {
                return self.failure(
                    item.pc,
                    "spec state budget exceeded (max_states — the program may not converge)",
                );
            }
            let Some(insn) = self.program.get(item.pc as usize) else {
                return self.failure(item.pc, "pc out of program range");
            };
            // convergence: an identical (pc, state) was already
            // explored — on a loop head that is an infinite loop
            // (kernel is_state_visited: states_maybe_looping EXACT →
            // "infinite loop detected"), elsewhere the path reached a
            // fixpoint and is pruned
            if self.visited.contains_key(&(item.pc, item.state)) {
                if self.loop_heads.contains(&item.pc) {
                    return self.failure(item.pc, "infinite loop detected");
                }
                continue;
            }
            self.visited.insert((item.pc, item.state), ());

            let pc = item.pc;
            let mut state = item.state;

            match *insn {
                // ── mov ──────────────────────────────────────────────
                BpfInsn::MovImm { dst, imm } => {
                    state.set_reg(dst, SpecValue::const_scalar(imm as u64));
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::MovReg { dst, src } => {
                    let v = state.reg(src);
                    if v == SpecValue::Uninit {
                        return self.failure(
                            pc,
                            format!("register r{src} is uninitialized (read by mov)"),
                        );
                    }
                    state.set_reg(dst, v);
                    self.push(&mut worklist, pc + 1, state);
                }

                // ── ALU64 ────────────────────────────────────────────
                BpfInsn::AddImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Add, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::AddReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Add, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::SubImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Sub, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::SubReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Sub, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::AndImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::And, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::AndReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::And, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::OrImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Or, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::OrReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Or, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::XorImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Xor, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::XorReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Xor, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::LshImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Lsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::LshReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Lsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::RshImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Rsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::RshReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Rsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::ArshImm { dst, imm } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Arsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::ArshReg { dst, src } => {
                    if let Err(v) = self.alu64(&mut state, pc, dst, Op::Arsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }

                // ── ALU32 ────────────────────────────────────────────
                BpfInsn::Add32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Add, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Add32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Add, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Sub32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Sub, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Sub32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Sub, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::And32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::And, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::And32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::And, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Or32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Or, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Or32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Or, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Xor32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Xor, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Xor32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Xor, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Lsh32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Lsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Lsh32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Lsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Rsh32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Rsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Rsh32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Rsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Arsh32Imm { dst, imm } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Arsh, Rhs::Imm(imm)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                BpfInsn::Arsh32Reg { dst, src } => {
                    if let Err(v) = self.alu32(&mut state, pc, dst, Op::Arsh, Rhs::Reg(src)) {
                        return v;
                    }
                    self.push(&mut worklist, pc + 1, state);
                }
                // ── memory ───────────────────────────────────────────
                BpfInsn::LdMem {
                    dst,
                    base,
                    offset,
                    size,
                    sign_extend,
                } => match self.load(&mut state, pc, base, offset as i64, size, sign_extend) {
                    Ok(v) => {
                        state.set_reg(dst, v);
                        self.push(&mut worklist, pc + 1, state);
                    }
                    Err(v) => return v,
                },
                BpfInsn::StMem {
                    src,
                    base,
                    offset,
                    size,
                } => {
                    let value = state.reg(src);
                    match self.store(&mut state, pc, base, offset as i64, size, value) {
                        Ok(()) => self.push(&mut worklist, pc + 1, state),
                        Err(v) => return v,
                    }
                }
                BpfInsn::StMemImm {
                    imm,
                    base,
                    offset,
                    size,
                } => {
                    let v = SpecValue::const_scalar(imm as u64);
                    match self.store(&mut state, pc, base, offset as i64, size, v) {
                        Ok(()) => self.push(&mut worklist, pc + 1, state),
                        Err(v) => return v,
                    }
                }

                // ── ldimm64 ──────────────────────────────────────────
                BpfInsn::LdImm64 { dst, imm } => {
                    state.set_reg(dst, SpecValue::const_scalar(imm));
                    self.push(&mut worklist, pc + 2, state);
                }
                BpfInsn::LdMapFd { dst, fd, .. } => {
                    let info = self.maps.get(&fd);
                    state.set_reg(
                        dst,
                        SpecValue::PtrToMap {
                            key_size: info.map(|m| m.key_size).unwrap_or(0),
                            value_size: info.map(|m| m.value_size).unwrap_or(0),
                            map_type: match info.map(|m| m.map_type) {
                                Some(crate::env::MapType::Ringbuf) => 1,
                                _ => 0,
                            },
                        },
                    );
                    self.push(&mut worklist, pc + 2, state);
                }
                BpfInsn::LdMapValue {
                    dst, fd, offset, ..
                } => {
                    let size = self.maps.get(&fd).map(|m| m.value_size).unwrap_or(0);
                    state.set_reg(
                        dst,
                        SpecValue::PtrToMapValue {
                            lo: offset as i64,
                            hi: offset as i64,
                            size,
                        },
                    );
                    self.push(&mut worklist, pc + 2, state);
                }
                BpfInsn::LdImm64Second { .. } => {
                    return self.failure(pc, "jump into the middle of ldimm64 insn");
                }

                // ── control flow ─────────────────────────────────────
                BpfInsn::Jmp { offset } => {
                    self.push(&mut worklist, branch_target(pc, offset), state);
                }
                BpfInsn::Jeq { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Eq,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jne { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ne,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jgt { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Gt,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jge { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ge,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jlt { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Lt,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jle { dst, src, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Le,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jsgt { dst, src, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Gt,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jsge { dst, src, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ge,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jslt { dst, src, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Lt,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::Jsle { dst, src, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Le,
                        state.reg(src),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JeqImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Eq,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JneImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ne,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JgtImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Gt,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JgeImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ge,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JltImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Lt,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JleImm { dst, imm, offset } => {
                    let _verdict = self.branch(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Le,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JsgtImm { dst, imm, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Gt,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JsgeImm { dst, imm, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Ge,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JsltImm { dst, imm, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Lt,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }
                BpfInsn::JsleImm { dst, imm, offset } => {
                    let _verdict = self.branch_signed(
                        &mut worklist,
                        pc,
                        state,
                        dst,
                        Cmp::Le,
                        SpecValue::const_scalar(imm as u64),
                        offset,
                    );
                    if _verdict != SpecVerdict::Accept {
                        return _verdict;
                    }
                }

                // ── calls ────────────────────────────────────────────
                BpfInsn::Call { imm } => match self.helper_call(&mut state, pc, imm) {
                    Ok(()) => self.push(&mut worklist, pc + 1, state),
                    Err(v) => return v,
                },
                BpfInsn::CallSub { offset } => {
                    let target = (pc as i64 + 1 + offset as i64) as u32;
                    // the kernel call convention: the callee receives
                    // R1..R5 as arguments, R6..R9 survive (callee-
                    // saved); the caller frame keeps everything and is
                    // restored at the return
                    let caller = SpecFrame {
                        regs: state.cur.regs,
                        stack: state.cur.stack,
                        ret_pc: pc + 1,
                    };
                    match push_frame(&mut state.saved, caller) {
                        Ok(()) => {
                            let mut callee = SpecFrame::callee();
                            for r in 1..=5 {
                                callee.regs[r] = state.cur.regs[r];
                            }
                            for r in 6..=9 {
                                callee.regs[r] = state.cur.regs[r];
                            }
                            state.cur = callee;
                            self.push(&mut worklist, target, state);
                        }
                        Err(_) => return self.failure(pc, "call depth exceeded (max call frames)"),
                    }
                }
                BpfInsn::CallKfunc { btf_id } => {
                    return self.failure(
                        pc,
                        format!("calling kernel function (btf id {btf_id}) is not allowed"),
                    );
                }
                BpfInsn::Exit => {
                    // R0 must be a scalar (kernel check_return_code)
                    match state.reg(0) {
                        SpecValue::Uninit => {
                            return self.failure(pc, "R0 is uninitialized at exit");
                        }
                        v if v.is_pointer() => {
                            return self.failure(pc, "R0 is not a scalar value at exit");
                        }
                        _ => {}
                    }
                    // SP3: every acquired reference must be released
                    if state.refs_cnt > 0 {
                        return self.failure(
                            pc,
                            format!("unreleased reference id={} at exit", state.refs[0]),
                        );
                    }
                    if caller_exists(state.saved) {
                        let return_pc = state.cur.ret_pc;
                        let mut state_has_caller = state;
                        let (mut caller, r0) = pop_frame(&mut state_has_caller.saved).unwrap();
                        caller.regs[0] = r0;
                        // the call clobbered the caller's argument
                        // registers
                        for r in 1..=5 {
                            caller.regs[r] = SpecValue::Uninit;
                        }
                        if matches!(r0, SpecValue::PtrToStack { .. }) {
                            return self.failure(pc, "cannot return stack pointer to the caller");
                        }
                        let mut state = state_has_caller;
                        state.cur = caller;
                        self.push(&mut worklist, return_pc, state);
                    } else {
                        // main exit — this path is safe
                        continue;
                    }
                }
            }
        }
        SpecVerdict::Accept
    }

    // ── dispatch helpers ─────────────────────────────────────────────

    fn push(&self, worklist: &mut Vec<WorkItem>, pc: u32, state: SpecState) {
        worklist.push(WorkItem { pc, state });
    }

    fn alu64(
        &self,
        state: &mut SpecState,
        pc: u32,
        dst: u8,
        op: Op,
        rhs: Rhs,
    ) -> Result<(), SpecVerdict> {
        let d = state.reg(dst);
        if d == SpecValue::Uninit {
            return Err(self.failure(pc, format!("register r{dst} is uninitialized (ALU)")));
        }
        let r = match rhs {
            Rhs::Imm(imm) => SpecValue::const_scalar(imm as u64),
            Rhs::Reg(src) => {
                let v = state.reg(src);
                if v == SpecValue::Uninit {
                    return Err(self.failure(pc, format!("register r{src} is uninitialized (ALU)")));
                }
                v
            }
        };
        // pointer arithmetic path: only const/scalar add onto a valid
        // pointer base is allowed (kernel check_alu_op)
        if d.is_pointer() {
            if op == Op::Add && r.is_scalar() {
                return self.ptr_add(state, pc, dst, r);
            }
            if op == Op::Sub {
                if r.is_pointer() {
                    return Err(self.failure(pc, "math between two pointers is not allowed (SUB)"));
                }
                return Err(self.failure(pc, "subtracting a scalar from a pointer is not allowed"));
            }
            return Err(self.failure(
                pc,
                "arithmetic on a pointer with a non-ADD operation is not allowed",
            ));
        }
        if r.is_pointer() {
            return Err(self.failure(
                pc,
                "arithmetic between a scalar and a pointer is not allowed",
            ));
        }
        let rd = d.as_scalar().unwrap();
        let rs = r.as_scalar().unwrap();
        let out = alu_range(op, rd, rs);
        state.set_reg(
            dst,
            SpecValue::Scalar {
                lo: out.0,
                hi: out.1,
            },
        );
        Ok(())
    }

    fn alu32(
        &self,
        state: &mut SpecState,
        pc: u32,
        dst: u8,
        op: Op,
        rhs: Rhs,
    ) -> Result<(), SpecVerdict> {
        let d = state.reg(dst);
        if d == SpecValue::Uninit {
            return Err(self.failure(pc, format!("register r{dst} is uninitialized (ALU32)")));
        }
        if d.is_pointer() {
            return Err(self.failure(pc, "32-bit arithmetic on a pointer is not allowed"));
        }
        let r = match rhs {
            Rhs::Imm(imm) => SpecValue::const_scalar(imm as u64),
            Rhs::Reg(src) => {
                let v = state.reg(src);
                if v == SpecValue::Uninit {
                    return Err(
                        self.failure(pc, format!("register r{src} is uninitialized (ALU32)"))
                    );
                }
                if v.is_pointer() {
                    return Err(self.failure(pc, "32-bit arithmetic on a pointer is not allowed"));
                }
                v
            }
        };
        let (d32, s32) = (
            range32(d.as_scalar().unwrap()),
            range32(r.as_scalar().unwrap()),
        );
        // ALU32: compute in 32-bit space; the result is zero-extended
        let out = alu_range(op, d32, s32);
        state.set_reg(
            dst,
            SpecValue::Scalar {
                lo: out.0,
                hi: out.1,
            },
        );
        Ok(())
    }

    /// The kernel's arithmetic-time pointer sanity checks
    /// (check_reg_sane_offset_scalar, BPF_MAX_VAR_OFF): a huge or
    /// unbounded addend makes the pointer escape the safe range.
    fn ptr_add(
        &self,
        state: &mut SpecState,
        pc: u32,
        dst: u8,
        addend: SpecValue,
    ) -> Result<(), SpecVerdict> {
        let a = addend.as_scalar().unwrap();
        // sane addend check (kernel check_reg_sane_offset_scalar,
        // generalized to both interval ends): the addend must fit the
        // safe pointer-offset range [-BPF_MAX_VAR_OFF, BPF_MAX_VAR_OFF]
        let (slo, shi) = match as_signed(a) {
            Some(s) => s,
            None => {
                return Err(self.failure(
                    pc,
                    "register with unbounded min value is not allowed as an addend",
                ));
            }
        };
        if slo <= -BPF_MAX_VAR_OFF || slo == i64::MIN || shi >= BPF_MAX_VAR_OFF {
            return Err(self.failure(
                pc,
                format!("value {slo}..{shi} makes pointer be out of bounds"),
            ));
        }
        match state.reg(dst) {
            SpecValue::PtrToStack { lo, hi } => {
                let (slo, shi) = as_signed(a).unwrap_or((0, 0));
                state.set_reg(
                    dst,
                    SpecValue::PtrToStack {
                        lo: lo.saturating_add(slo),
                        hi: hi.saturating_add(shi),
                    },
                );
                Ok(())
            }
            SpecValue::PtrToMapValue { lo, hi, size } => {
                let (slo, shi) = as_signed(a).unwrap_or((0, 0));
                state.set_reg(
                    dst,
                    SpecValue::PtrToMapValue {
                        lo: lo.saturating_add(slo),
                        hi: hi.saturating_add(shi),
                        size,
                    },
                );
                Ok(())
            }
            SpecValue::PtrToCtx => {
                // ctx += K with a bounded const is allowed; variable
                // addends are refused (the kernel's BPF_ADD on ctx
                // requires a constant)
                if let Some((slo, shi)) = as_signed(a)
                    && slo == shi
                {
                    Ok(())
                } else {
                    Err(self.failure(
                        pc,
                        "arithmetic on a context pointer with a variable addend is not allowed",
                    ))
                }
            }
            other => Err(self.failure(pc, format!("arithmetic on {other:?} is not allowed"))),
        }
    }

    fn helper_call(&mut self, state: &mut SpecState, pc: u32, id: i32) -> Result<(), SpecVerdict> {
        let Some(proto) = spec_helper(id) else {
            return Err(self.failure(pc, format!("unknown helper {id}")));
        };
        for (i, arg) in proto.args.iter().enumerate() {
            let reg = (i + 1) as u8;
            let v = state.reg(reg);
            self.check_arg(state, pc, i, reg, *arg, v, id)?;
        }
        // stack-writing helpers: dynptr_from_mem writes the dynptr
        // slot in R4; dynptr_read writes R1's buffer — both BEFORE the
        // call-clobber (they read the pre-call registers)
        if id == 197
            && let SpecValue::PtrToStack { lo, hi } = state.reg(4)
            && lo == hi
        {
            let (s1, s2) = dynptr_slots_of(lo).ok_or_else(|| {
                SpecVerdict::Reject(SpecFailure::new(pc, "dynptr slot out of frame"))
            })?;
            state.cur.stack.dynptr[s1] = true;
            state.cur.stack.dynptr[s2] = true;
            mark_range_init(&mut state.cur.stack, lo, 16);
        }
        if id == 201
            && let SpecValue::PtrToStack { lo, hi } = state.reg(1)
            && lo == hi
        {
            let len = match state.reg(2) {
                SpecValue::Scalar { lo, hi } if lo == hi => lo as i64,
                _ => return Err(self.failure(pc, "dynptr_read length is not a constant")),
            };
            // the dst buffer must be fully inside the frame (SP2)
            if lo < -(SPEC_STACK_SIZE as i64) || lo + len > 0 {
                return Err(self.failure(pc, "dynptr_read dst buffer out of the frame"));
            }
            mark_range_init(&mut state.cur.stack, lo, len);
        }
        // ringbuf submit/discard releases the R1 reference (kernel
        // ARG_PTR_TO_MEM | OBJ_RELEASE)
        if matches!(id, 132 | 133)
            && let SpecValue::PtrToMem { id: ref_id, .. } = state.reg(1)
            && !state.release_ref(ref_id)
        {
            return Err(self.failure(pc, format!("release of unacquired reference id={ref_id}")));
        }
        match proto.ret {
            SpecRet::Zero => state.set_reg(0, SpecValue::const_scalar(0)),
            SpecRet::UnknownScalar => state.set_reg(0, SpecValue::unknown_scalar()),
            SpecRet::UnknownU32 => {
                state.set_reg(
                    0,
                    SpecValue::Scalar {
                        lo: 0,
                        hi: u32::MAX as u64,
                    },
                );
            }
            SpecRet::MapValueOrNull => {
                let size = match state.reg(1) {
                    SpecValue::PtrToMap { value_size, .. } => value_size,
                    _ => 0,
                };
                self.next_ref_id += 1;
                state.set_reg(
                    0,
                    SpecValue::PtrToMapValueOrNull {
                        size,
                        id: self.next_ref_id,
                    },
                );
            }
            SpecRet::MemOrNull => {
                self.next_ref_id += 1;
                let id = self.next_ref_id;
                let size = match state.reg(2) {
                    SpecValue::Scalar { lo, hi } if lo == hi => lo as u32,
                    _ => 0,
                };
                state.set_reg(0, SpecValue::PtrToMemOrNull { size, id });
                state.acquire_ref(id).map_err(|e| self.failure(pc, e))?;
            }
        }
        // the kernel call convention: R1..R5 are clobbered
        for r in 1..=5 {
            state.set_reg(r, SpecValue::Uninit);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // the arg contract signature
    fn check_arg(
        &self,
        state: &SpecState,
        pc: u32,
        arg_idx: usize,
        reg: u8,
        expected: SpecArg,
        actual: SpecValue,
        id: i32,
    ) -> Result<(), SpecVerdict> {
        let ok = match expected {
            SpecArg::PtrToMap => matches!(actual, SpecValue::PtrToMap { .. }),
            SpecArg::PtrToStack => matches!(actual, SpecValue::PtrToStack { .. }),
            SpecArg::PtrToStackInit { size } => {
                if let SpecValue::PtrToStack { lo, hi } = actual
                    && lo == hi
                {
                    // determine the required size from the map metadata
                    // of the map pointer in R1: map_update's arg3 is
                    // the VALUE buffer (value_size), everything else
                    // keyed is the KEY buffer (key_size)
                    let n = if size == 0 {
                        match (id, arg_idx, state.reg(1)) {
                            (2, 2, SpecValue::PtrToMap { value_size, .. }) => value_size,
                            (1 | 2, _, SpecValue::PtrToMap { key_size, .. }) => key_size,
                            _ => 0,
                        }
                    } else {
                        size
                    };
                    let abs = SPEC_STACK_SIZE as i64 + lo;
                    (0..(n as i64)).all(|i| {
                        let idx = abs + i;
                        idx >= 0
                            && (idx as usize) < SPEC_STACK_SIZE
                            && state.cur.stack.init[idx as usize]
                    })
                } else {
                    false
                }
            }
            SpecArg::Scalar => actual.is_scalar(),
            SpecArg::PtrToMapValue => matches!(actual, SpecValue::PtrToMapValue { .. }),
            SpecArg::PtrToMem => matches!(actual, SpecValue::PtrToMem { .. }),
            SpecArg::PtrToDynptr => {
                if let SpecValue::PtrToStack { lo, hi } = actual
                    && lo == hi
                {
                    matches!(dynptr_slots_of(lo), Some((s1, s2)) if state.cur.stack.dynptr[s1] && state.cur.stack.dynptr[s2])
                } else {
                    false
                }
            }
            SpecArg::PtrToDynptrW => {
                // the write target: the slot must be in frame (the
                // runner marks the slot initialized after the call)
                if let SpecValue::PtrToStack { lo, hi } = actual
                    && lo == hi
                {
                    dynptr_slots_of(lo).is_some()
                } else {
                    false
                }
            }
            SpecArg::PtrToBtf => matches!(actual, SpecValue::PtrToBtfId { .. }),
        };
        if ok {
            Ok(())
        } else {
            Err(self.failure(
                pc,
                format!("R{reg} type mismatch for helper argument {expected:?}"),
            ))
        }
    }

    // ── memory access ─────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)] // the access signature (base, off, size, value)
    fn store(
        &self,
        state: &mut SpecState,
        pc: u32,
        base: u8,
        off: i64,
        size: MemSize,
        value: SpecValue,
    ) -> Result<(), SpecVerdict> {
        // (the spilled-value path below uses `value`; a lint keeps it
        // used across branches)
        let _ = &value;
        let base_v = state.reg(base);
        let bytes = size_bytes(size);
        match base_v {
            SpecValue::PtrToStack { lo, hi } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_stack_range(pc, start, end, bytes as i64)?;
                // a full 8-byte spill or a plain byte write
                if bytes == 8 && lo == hi {
                    let slot = slot_of(SPEC_STACK_SIZE as i64 + start).ok_or_else(|| {
                        SpecVerdict::Reject(SpecFailure::new(pc, "stack slot out of the frame"))
                    })?;
                    let spill = match value {
                        SpecValue::Scalar { lo, hi } => Spill::Scalar { lo, hi },
                        other => Spill::Ptr(other),
                    };
                    // a spill over an existing spill replaces it
                    state.cur.stack.spill[slot] = Some(spill);
                    mark_range_init(&mut state.cur.stack, start, 8);
                    return Ok(());
                }
                // narrow write over a spilled slot refuses pointer
                // corruption
                if lo == hi {
                    let abs = SPEC_STACK_SIZE as i64 + start;
                    // the slot containing the written bytes (floor — a
                    // 4-byte write may touch the upper half of a slot)
                    let slot = (abs / 8) as usize;
                    if slot >= SPEC_SLOTS {
                        return Err(self.failure(pc, "stack slot out of the frame"));
                    }
                    if matches!(state.cur.stack.spill[slot], Some(Spill::Ptr(_))) {
                        return Err(
                            self.failure(pc, "attempt to corrupt spilled pointer (narrow write)")
                        );
                    }
                    // the privileged kernel rule: a 4-byte store to the
                    // LSB half of an empty slot initializes the slot's
                    // other half as unknown (save_register_state marks
                    // the remainder MISC) — a later read of the other
                    // half is then initialized (partial_kill_read)
                    if bytes == 4
                        && start.rem_euclid(8) == 0
                        && state.cur.stack.spill[slot].is_none()
                    {
                        for i in 4..8 {
                            let idx = abs + i;
                            state.cur.stack.init[idx as usize] = true;
                            state.cur.stack.bytes[idx as usize] = 0;
                        }
                    }
                } else {
                    // variable-offset write: initialize every covered
                    // byte; a write touching a spilled slot is refused
                    // (kernel: "invalid indirect write to spilled
                    // value")
                    let first = (SPEC_STACK_SIZE as i64 + start) / 8;
                    let last = (SPEC_STACK_SIZE as i64 + end - 1) / 8;
                    for slot in first..=last {
                        if state
                            .cur
                            .stack
                            .spill
                            .get(slot as usize)
                            .is_some_and(|s| s.is_some())
                        {
                            return Err(self.failure(pc, "invalid indirect write to spilled value"));
                        }
                    }
                    for idx in (SPEC_STACK_SIZE as i64 + start).max(0)
                        ..(SPEC_STACK_SIZE as i64 + end).min(SPEC_STACK_SIZE as i64)
                    {
                        state.cur.stack.init[idx as usize] = true;
                        state.cur.stack.bytes[idx as usize] = 0;
                    }
                    return Ok(());
                }
                for i in 0..bytes {
                    let idx = SPEC_STACK_SIZE as i64 + start + i as i64;
                    let b = match value {
                        SpecValue::Scalar { lo, hi } if lo == hi => (lo >> (8 * i as u32)) as u8,
                        _ => 0,
                    };
                    state.cur.stack.init[idx as usize] = true;
                    state.cur.stack.bytes[idx as usize] = b;
                }
                Ok(())
            }
            SpecValue::PtrToMapValue {
                lo,
                hi,
                size: v_size,
            } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_map_range(pc, start, end, v_size as i64, bytes as i64)?;
                Ok(())
            }
            SpecValue::PtrToMem {
                lo,
                hi,
                size: m_size,
                ..
            } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_map_range(pc, start, end, m_size as i64, bytes as i64)?;
                Ok(())
            }
            SpecValue::PtrToMapValueOrNull { .. } => Err(self.failure(
                pc,
                "invalid mem access of a map value pointer (NULL not yet refined)",
            )),
            SpecValue::PtrNull => Err(self.failure(pc, "NULL pointer dereference")),
            _ => Err(self.failure(pc, "invalid mem access (non-pointer base)")),
        }
    }

    #[allow(clippy::too_many_arguments)] // the access signature (base, off, size, sign)
    fn load(
        &self,
        state: &mut SpecState,
        pc: u32,
        base: u8,
        off: i64,
        size: MemSize,
        sign_extend: bool,
    ) -> Result<SpecValue, SpecVerdict> {
        let base_v = state.reg(base);
        let bytes = size_bytes(size);
        match base_v {
            SpecValue::PtrToStack { lo, hi } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_stack_range(pc, start, end, bytes as i64)?;
                if lo != hi {
                    // variable-offset stack read: EVERY byte any access
                    // could touch (the full [start, end) interval) must
                    // be initialized and free of spilled values
                    // (kernel: "invalid indirect read from stack ...
                    // spilled")
                    let first = (SPEC_STACK_SIZE as i64 + start).max(0);
                    let last = (SPEC_STACK_SIZE as i64 + end).min(SPEC_STACK_SIZE as i64);
                    for idx in first..last {
                        if !state.cur.stack.init[idx as usize] {
                            return Err(self.failure(
                                pc,
                                "variable-offset stack read over uninitialized bytes",
                            ));
                        }
                    }
                    for slot in first / 8..(last - 1) / 8 + 1 {
                        if state
                            .cur
                            .stack
                            .spill
                            .get(slot as usize)
                            .is_some_and(|s| s.is_some())
                        {
                            return Err(self.failure(
                                pc,
                                "invalid indirect read from stack over a spilled value",
                            ));
                        }
                    }
                    return Ok(SpecValue::unknown_scalar());
                }
                // exact spill fill
                if bytes == 8
                    && let Some(slot) = slot_of(SPEC_STACK_SIZE as i64 + start)
                    && let Some(spill) = state.cur.stack.spill[slot]
                {
                    return Ok(match spill {
                        Spill::Scalar { lo, hi } => SpecValue::Scalar { lo, hi },
                        Spill::Ptr(p) => p,
                    });
                }
                // narrow fill of a spilled pointer — rejected
                if bytes < 8
                    && let Some(slot) = slot_of(SPEC_STACK_SIZE as i64 + start)
                    && matches!(state.cur.stack.spill[slot], Some(Spill::Ptr(_)))
                {
                    return Err(self.failure(
                        pc,
                        "narrow fill of a spilled pointer from stack (invalid read)",
                    ));
                }
                // byte-level init + value composition
                let mut v = 0u64;
                for i in 0..bytes {
                    let idx = SPEC_STACK_SIZE as i64 + start + i as i64;
                    if !state.cur.stack.init[idx as usize] {
                        return Err(self.failure(pc, "stack read of uninitialized bytes"));
                    }
                    v |= (state.cur.stack.bytes[idx as usize] as u64) << (8 * i as u32);
                }
                let v = apply_sign(v, bytes, sign_extend);
                Ok(SpecValue::const_scalar(v))
            }
            SpecValue::PtrToMapValue {
                lo,
                hi,
                size: v_size,
            } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_map_range(pc, start, end, v_size as i64, bytes as i64)?;
                // map value memory is initialized by definition
                Ok(SpecValue::unknown_scalar())
            }
            SpecValue::PtrToMem {
                lo,
                hi,
                size: m_size,
                ..
            } => {
                let start = lo.saturating_add(off);
                let end = hi.saturating_add(off).saturating_add(bytes as i64);
                self.check_map_range(pc, start, end, m_size as i64, bytes as i64)?;
                Ok(SpecValue::unknown_scalar())
            }
            SpecValue::PtrToMapValueOrNull { .. } => Err(self.failure(
                pc,
                "invalid mem access of a map value pointer (NULL not yet refined)",
            )),
            SpecValue::PtrNull => Err(self.failure(pc, "NULL pointer dereference")),
            SpecValue::Uninit => Err(self.failure(pc, "invalid mem access (uninitialized base)")),
            _ => Err(self.failure(pc, "invalid mem access (non-pointer base)")),
        }
    }

    /// SP2 stack range: in-frame bounds; size-alignment for widths >= 4
    /// (8-byte accesses 8-aligned, 4-byte accesses 4-aligned); the
    /// alignment applies to a variable offset only when every possible
    /// start point is on the grid.
    fn check_stack_range(
        &self,
        pc: u32,
        start: i64,
        end: i64,
        size: i64,
    ) -> Result<(), SpecVerdict> {
        if start < -(SPEC_STACK_SIZE as i64) || end > 0 {
            return Err(self.failure(pc, format!("invalid stack access (off {start}..{end})")));
        }
        if size >= 4 && !aligned_across(start, end - size, size) {
            return Err(self.failure(
                pc,
                format!("misaligned stack access (off {start}, size {size})"),
            ));
        }
        Ok(())
    }

    fn check_map_range(
        &self,
        pc: u32,
        start: i64,
        end: i64,
        bound: i64,
        size: i64,
    ) -> Result<(), SpecVerdict> {
        if start < 0 || end > bound {
            return Err(self.failure(
                pc,
                format!("invalid access to map value (off {start}..{end}, bound {bound})"),
            ));
        }
        if size >= 4 && !aligned_across(start, end - size, size) {
            return Err(self.failure(pc, format!("misaligned access (off {start}, size {size})")));
        }
        Ok(())
    }

    // ── control flow ───────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)] // the compare signature (dst, cmp, src, off)
    fn branch(
        &self,
        worklist: &mut Vec<WorkItem>,
        pc: u32,
        state: SpecState,
        dst: u8,
        cmp: Cmp,
        src: SpecValue,
        offset: i16,
    ) -> SpecVerdict {
        let target = branch_target(pc, offset);
        let d = state.cur.regs[dst as usize];
        if d.is_pointer() || src.is_pointer() {
            return self.pointer_branch(worklist, pc, state, dst, cmp, src, target);
        }
        let Some((dlo, dhi)) = d.as_scalar() else {
            return self.failure(pc, "comparison on an uninitialized register");
        };
        let Some((slo, shi)) = src.as_scalar() else {
            return self.failure(pc, "comparison against an uninitialized register");
        };
        let (taken, fall) = unsigned_cmp_refine((dlo, dhi), (slo, shi), cmp);
        self.emit_refined(worklist, state, dst, taken, fall, target, pc + 1)
    }

    #[allow(clippy::too_many_arguments)] // the compare signature (dst, cmp, src, off)
    fn branch_signed(
        &self,
        worklist: &mut Vec<WorkItem>,
        pc: u32,
        state: SpecState,
        dst: u8,
        cmp: Cmp,
        src: SpecValue,
        offset: i16,
    ) -> SpecVerdict {
        let target = branch_target(pc, offset);
        let d = state.cur.regs[dst as usize];
        if d.is_pointer() || src.is_pointer() {
            return self.failure(pc, "signed comparison on pointers is not allowed");
        }
        let Some((dlo, dhi)) = d.as_scalar() else {
            return self.failure(pc, "signed comparison on an uninitialized register");
        };
        let Some((slo, shi)) = src.as_scalar() else {
            return self.failure(pc, "signed comparison against an uninitialized register");
        };
        let (taken, fall) = signed_cmp_refine((dlo, dhi), (slo, shi), cmp);
        self.emit_refined(worklist, state, dst, taken, fall, target, pc + 1)
    }

    /// Push the refined branch successors; an empty interval list
    /// means the outcome is infeasible.
    #[allow(clippy::too_many_arguments)] // the refined successor lists
    fn emit_refined(
        &self,
        worklist: &mut Vec<WorkItem>,
        state: SpecState,
        dst: u8,
        taken: Vec<(u64, u64)>,
        fall: Vec<(u64, u64)>,
        target: u32,
        fall_pc: u32,
    ) -> SpecVerdict {
        for r in taken {
            let mut st = state;
            st.cur.regs[dst as usize] = SpecValue::Scalar { lo: r.0, hi: r.1 };
            self.push(worklist, target, st);
        }
        for r in fall {
            let mut st = state;
            st.cur.regs[dst as usize] = SpecValue::Scalar { lo: r.0, hi: r.1 };
            self.push(worklist, fall_pc, st);
        }
        SpecVerdict::Accept
    }

    /// Equality / NULL checks on pointers: refines nullable pointers
    /// (and releases the reference on the null side — kernel
    /// mark_ptr_or_null_regs) and refuses ordering compares.
    #[allow(clippy::too_many_arguments)] // the pointer compare signature
    fn pointer_branch(
        &self,
        worklist: &mut Vec<WorkItem>,
        pc: u32,
        state: SpecState,
        dst: u8,
        cmp: Cmp,
        src: SpecValue,
        target: u32,
    ) -> SpecVerdict {
        let d = state.cur.regs[dst as usize];
        match (d, src) {
            (SpecValue::PtrToMapValueOrNull { size, id }, SpecValue::Scalar { lo, hi })
                if lo == 0 && hi == 0 =>
            {
                let mut t = state;
                let mut f = state;
                // kernel mark_ptr_or_null_regs: every register holding
                // the same id is refined together (alias refinement)
                match cmp {
                    Cmp::Eq => {
                        for reg in t.cur.regs.iter_mut() {
                            if matches!(reg, SpecValue::PtrToMapValueOrNull { id: rid, .. } if *rid == id)
                            {
                                *reg = SpecValue::const_scalar(0);
                            }
                        }
                        for reg in f.cur.regs.iter_mut() {
                            if matches!(reg, SpecValue::PtrToMapValueOrNull { id: rid, .. } if *rid == id)
                            {
                                *reg = SpecValue::PtrToMapValue { lo: 0, hi: 0, size };
                            }
                        }
                    }
                    Cmp::Ne => {
                        for reg in f.cur.regs.iter_mut() {
                            if matches!(reg, SpecValue::PtrToMapValueOrNull { id: rid, .. } if *rid == id)
                            {
                                *reg = SpecValue::const_scalar(0);
                            }
                        }
                        for reg in t.cur.regs.iter_mut() {
                            if matches!(reg, SpecValue::PtrToMapValueOrNull { id: rid, .. } if *rid == id)
                            {
                                *reg = SpecValue::PtrToMapValue { lo: 0, hi: 0, size };
                            }
                        }
                    }
                    _ => {
                        return self.failure(
                            pc,
                            "ordering comparison on a nullable pointer is not allowed",
                        );
                    }
                }
                self.push(worklist, target, t);
                self.push(worklist, pc + 1, f);
                SpecVerdict::Accept
            }
            (SpecValue::PtrToMemOrNull { size, id }, SpecValue::Scalar { lo, hi })
                if lo == 0 && hi == 0 =>
            {
                let mut t = state;
                let mut f = state;
                // the reference is released on the null side (kernel
                // mark_ptr_or_null_regs) and lives on the non-null side
                match cmp {
                    Cmp::Eq => {
                        t.cur.regs[dst as usize] = SpecValue::const_scalar(0);
                        let _ = t.release_ref(id);
                        f.cur.regs[dst as usize] = SpecValue::PtrToMem {
                            lo: 0,
                            hi: 0,
                            size,
                            id,
                        };
                    }
                    Cmp::Ne => {
                        f.cur.regs[dst as usize] = SpecValue::const_scalar(0);
                        let _ = f.release_ref(id);
                        t.cur.regs[dst as usize] = SpecValue::PtrToMem {
                            lo: 0,
                            hi: 0,
                            size,
                            id,
                        };
                    }
                    _ => {
                        return self.failure(
                            pc,
                            "ordering comparison on a nullable mem pointer is not allowed",
                        );
                    }
                }
                self.push(worklist, target, t);
                self.push(worklist, pc + 1, f);
                SpecVerdict::Accept
            }
            (d, s)
                if matches!(d, SpecValue::PtrToStack { .. } | SpecValue::PtrToCtx)
                    && matches!(s, SpecValue::PtrToStack { .. } | SpecValue::PtrToCtx) =>
            {
                match cmp {
                    Cmp::Eq => self.push(worklist, target, state),
                    Cmp::Ne => self.push(worklist, pc + 1, state),
                    _ => return self.failure(pc, "ordering comparison of pointers is not allowed"),
                }
                SpecVerdict::Accept
            }
            // comparing a pointer to a non-null scalar or a different
            // kind: refuse (kernel "same type check failed")
            _ => self.failure(pc, "comparing different pointer kinds is not allowed"),
        }
    }
}

// ── free functions ──────────────────────────────────────────────────────────

type Range2 = (u64, u64);

/// One comparison operator, normalized to `dst CMP src`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

fn unsigned_cmp_refine(d: Range2, s: Range2, cmp: Cmp) -> (Vec<Range2>, Vec<Range2>) {
    let take = |d: Range2, s: Range2, cmp: Cmp| -> Vec<Range2> {
        match cmp {
            Cmp::Eq => {
                let lo = d.0.max(s.0);
                let hi = d.1.min(s.1);
                if lo <= hi { vec![(lo, hi)] } else { vec![] }
            }
            Cmp::Ne => {
                // dst != src: infeasible when src covers every dst
                // value; otherwise exclude the src interval from dst
                // (splitting into two intervals when src pokes into
                // the middle)
                if s.0 <= d.0 && s.1 >= d.1 {
                    vec![]
                } else {
                    let mut out = Vec::new();
                    if s.0 > d.0 {
                        out.push((d.0, d.1.min(s.0 - 1)));
                    }
                    if s.1 < d.1 {
                        out.push((s.1 + 1, d.1));
                    }
                    out
                }
            }
            Cmp::Lt => {
                if s.0 == 0 || d.0 > s.1 {
                    vec![]
                } else {
                    let hi = d.1.min(s.1 - 1);
                    if d.0 <= hi { vec![(d.0, hi)] } else { vec![] }
                }
            }
            Cmp::Le => {
                if d.0 > s.1 {
                    vec![]
                } else {
                    vec![(d.0, d.1.min(s.1))]
                }
            }
            Cmp::Gt => {
                if s.0 == u64::MAX || d.1 <= s.0 {
                    vec![]
                } else {
                    vec![(d.0.max(s.0 + 1), d.1)]
                }
            }
            Cmp::Ge => {
                if d.1 < s.0 {
                    vec![]
                } else {
                    vec![(d.0.max(s.0), d.1)]
                }
            }
        }
    };
    (take(d, s, cmp), take(d, s, negate(cmp)))
}

fn signed_cmp_refine(d: Range2, s: Range2, cmp: Cmp) -> (Vec<Range2>, Vec<Range2>) {
    // map both ranges into the SIGNED i64 view; if either straddles
    // the sign bit the branch stays unrefined (both outcomes open)
    let Some((dlo, dhi)) = as_signed(d) else {
        return (vec![d], vec![d]);
    };
    let Some((slo, shi)) = as_signed(s) else {
        return (vec![d], vec![d]);
    };
    let take = |dlo: i64, dhi: i64, slo: i64, shi: i64, cmp: Cmp| -> Vec<Range2> {
        match cmp {
            Cmp::Eq => {
                let lo = dlo.max(slo);
                let hi = dhi.min(shi);
                if lo <= hi {
                    vec![(lo as u64, hi as u64)]
                } else {
                    vec![]
                }
            }
            Cmp::Ne => {
                // dst != src in the signed view: infeasible when src
                // covers dst; otherwise exclude the src interval
                if slo <= dlo && shi >= dhi {
                    vec![]
                } else {
                    let mut out = Vec::new();
                    if slo > dlo {
                        out.push((dlo as u64, dhi.min(slo - 1) as u64));
                    }
                    if shi < dhi {
                        out.push(((shi + 1) as u64, dhi as u64));
                    }
                    out
                }
            }
            Cmp::Lt => {
                if dlo > shi || shi == i64::MIN {
                    vec![]
                } else {
                    let hi = dhi.min(shi - 1);
                    if dlo <= hi {
                        vec![(dlo as u64, hi as u64)]
                    } else {
                        vec![]
                    }
                }
            }
            Cmp::Le => {
                if dlo > shi {
                    vec![]
                } else {
                    vec![(dlo as u64, dhi.min(shi) as u64)]
                }
            }
            Cmp::Gt => {
                if dhi <= slo || slo == i64::MAX {
                    vec![]
                } else {
                    vec![(dlo.max(slo + 1) as u64, dhi as u64)]
                }
            }
            Cmp::Ge => {
                if dhi < slo {
                    vec![]
                } else {
                    vec![(dlo.max(slo) as u64, dhi as u64)]
                }
            }
        }
    };
    (
        take(dlo, dhi, slo, shi, cmp),
        take(dlo, dhi, slo, shi, negate(cmp)),
    )
}

fn negate(cmp: Cmp) -> Cmp {
    match cmp {
        Cmp::Eq => Cmp::Ne,
        Cmp::Ne => Cmp::Eq,
        Cmp::Lt => Cmp::Ge,
        Cmp::Ge => Cmp::Lt,
        Cmp::Gt => Cmp::Le,
        Cmp::Le => Cmp::Gt,
    }
}

/// Whether every point in `[lo, hi]` (the access start interval) is on
/// the `align` grid.
fn aligned_across(lo: i64, hi: i64, align: i64) -> bool {
    if lo == hi {
        return lo.rem_euclid(align) == 0;
    }
    lo.rem_euclid(align) == 0 && hi.rem_euclid(align) == 0 && ((hi - lo) % align == 0)
}

fn mark_range_init(stack: &mut SpecStack, off: i64, len: i64) {
    let base = SPEC_STACK_SIZE as i64 + off;
    for i in base.max(0)..(base + len).min(SPEC_STACK_SIZE as i64) {
        stack.init[i as usize] = true;
    }
}

fn slot_of(abs: i64) -> Option<usize> {
    if abs >= 0 && abs % 8 == 0 && abs + 8 <= SPEC_STACK_SIZE as i64 {
        Some(abs as usize / 8)
    } else {
        None
    }
}

fn size_bytes(size: MemSize) -> usize {
    match size {
        MemSize::B => 1,
        MemSize::H => 2,
        MemSize::W => 4,
        MemSize::DW => 8,
    }
}

fn branch_target(pc: u32, offset: i16) -> u32 {
    (pc as i64 + 1 + offset as i64) as u32
}

fn apply_sign(v: u64, bytes: usize, sign_extend: bool) -> u64 {
    if !sign_extend {
        return v;
    }
    match bytes {
        1 => (v as i8) as u64,
        2 => (v as i16) as u64,
        4 => (v as i32) as u64,
        _ => v,
    }
}

fn push_frame(saved: &mut [Option<SpecFrame>; 7], frame: SpecFrame) -> Result<(), ()> {
    let slot = saved.iter().position(|f| f.is_none()).ok_or(())?;
    saved[slot] = Some(frame);
    Ok(())
}

fn pop_frame(saved: &mut [Option<SpecFrame>; 7]) -> Option<(SpecFrame, SpecValue)> {
    let slot = saved.iter().rposition(|f| f.is_some())?;
    let fr = saved[slot].take().unwrap();
    Some((fr, SpecValue::Uninit)) // r0 filled by the caller below
}

fn caller_exists(saved: [Option<SpecFrame>; 7]) -> bool {
    saved.iter().any(|f| f.is_some())
}

/// Sound interval ALU over wrapping u64 (32-bit inputs are already
/// truncated — the result is zero-extended).
fn alu_range(op: Op, d: Range2, s: Range2) -> Range2 {
    match op {
        Op::Add => rng_add(d, s),
        Op::Sub => rng_sub(d, s),
        Op::And => rng_and(d, s),
        Op::Or => rng_or(d, s),
        Op::Xor => rng_xor(d, s),
        Op::Lsh => {
            if s.0 != s.1 || s.0 >= 64 {
                (0, 0)
            } else {
                rng_lsh(d, s.0 as u32)
            }
        }
        Op::Rsh => {
            if s.0 != s.1 || s.0 >= 64 {
                (0, 0)
            } else {
                rng_rsh(d, s.0 as u32)
            }
        }
        Op::Arsh => {
            if s.0 != s.1 || s.0 >= 64 {
                (0, 0)
            } else {
                rng_arsh(d, s.0 as u32)
            }
        }
        Op::Mul => rng_mul(d, s),
    }
}

/// Every pc that is the target of a backward jump (a back edge) — the
/// kernel's loop heads (verifier.c: "insn_idx is the loop head").
fn compute_loop_heads(program: &[BpfInsn]) -> Vec<u32> {
    let mut heads: Vec<u32> = Vec::new();
    for (i, insn) in program.iter().enumerate() {
        let pc = i as u32;
        let target = match insn {
            BpfInsn::Jmp { offset } => branch_target(pc, *offset),
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
            | BpfInsn::JsleImm { offset, .. } => branch_target(pc, *offset),
            _ => continue,
        };
        if target <= pc && !heads.contains(&target) {
            heads.push(target);
        }
    }
    heads
}

/// The ALU op view of the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Lsh,
    Rsh,
    Arsh,
    Mul,
}

#[derive(Debug, Clone, Copy)]
enum Rhs {
    Imm(i32),
    Reg(u8),
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::insn_bytes;
    use std::collections::HashMap;

    fn run(insns: &[[u8; 8]]) -> SpecVerdict {
        let bytes: Vec<u8> = insns.iter().flatten().copied().collect();
        let program = crate::insn::decode_program(&bytes).expect("decode");
        verify_spec(&program, &HashMap::new())
    }

    fn reject_contains(insns: &[[u8; 8]], needle: &str) -> bool {
        match run(insns) {
            SpecVerdict::Reject(f) => f.message.contains(needle),
            _ => false,
        }
    }

    /// The unsigned refinement never drops a feasible outcome and
    /// never emits an inverted interval.
    #[test]
    fn refine_unsigned_correctness() {
        // equality: taken = intersection, fall = exclusion split
        let (t, f) = unsigned_cmp_refine((0, 100), (42, 42), Cmp::Eq);
        assert_eq!(t, vec![(42, 42)]);
        assert_eq!(f, vec![(0, 41), (43, 100)]);
        // constant outside the interval: never taken
        let (t, _f) = unsigned_cmp_refine((0, 100), (200, 200), Cmp::Eq);
        assert!(t.is_empty());
        // Lt at the boundary: no inverted interval
        let (t, _f) = unsigned_cmp_refine((100, 100), (100, 100), Cmp::Lt);
        assert!(t.is_empty(), "100 < 100 is infeasible: {t:?}");
        let (t, _f) = unsigned_cmp_refine((5, 10), (10, 10), Cmp::Lt);
        assert_eq!(t, vec![(5, 9)]);
        // Gt
        let (t, _f) = unsigned_cmp_refine((0, 100), (10, 10), Cmp::Gt);
        assert_eq!(t, vec![(11, 100)]);
        // Ne against a covering range is infeasible
        let (t, _f) = unsigned_cmp_refine((5, 5), (0, 10), Cmp::Ne);
        assert!(t.is_empty());
    }

    /// The signed refinement compares in the i64 domain, including
    /// mixed-sign cases (jslt with a positive constant on a negative
    /// range is always taken).
    #[test]
    fn refine_signed_correctness() {
        let neg = (u64::MAX as i64).wrapping_sub(99) as u64; // -100
        let e = u64::MAX; // -1
        let minus50 = (u64::MAX as i64).wrapping_sub(49) as u64; // -50
        // [-100,-1] jslt -50: taken = [-100,-51], fall = [-50,-1]
        let (t, f) = signed_cmp_refine((neg, e), (minus50, minus50), Cmp::Lt);
        assert_eq!(t, vec![(neg, minus50 - 1)]);
        assert_eq!(f, vec![(minus50, e)]);
        // [-100,-1] jslt 100: always taken
        let (t, f) = signed_cmp_refine((neg, e), (100, 100), Cmp::Lt);
        assert_eq!(t, vec![(neg, e)]);
        assert!(f.is_empty());
        // a straddling range cannot refine (both outcomes stay open)
        let (t, f) = signed_cmp_refine((0, u64::MAX), (100, 100), Cmp::Lt);
        assert_eq!(t, vec![(0, u64::MAX)]);
        assert_eq!(f, vec![(0, u64::MAX)]);
        // boundary: -1 jsgt 0 is never taken
        let (t, _f) = signed_cmp_refine((e, e), (0, 0), Cmp::Gt);
        assert!(t.is_empty());
    }

    /// A BPF-to-BPF call returns the callee's R0 to the caller
    /// (regression for the review finding: the R0 was dropped).
    #[test]
    fn spec_subprog_returns_r0() {
        // r1 = 5; call sub @2; r0 = r0; exit; r0 = r1; r0 += 1; exit
        let insns = [
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0x85, 0, 1, 0, 2), // BPF_PSEUDO_CALL (src_reg=1)
            insn_bytes(0xbf, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
            insn_bytes(0xbf, 0, 1, 0, 0),
            insn_bytes(0x07, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
        // the callee's R0 is really 6: without the return-value
        // transfer, r0 = r0 at pc2 would reject on uninitialized r0
    }

    #[test]
    fn spec_accepts_minimal_exit() {
        let insns = [insn_bytes(0xb7, 0, 0, 0, 42), insn_bytes(0x95, 0, 0, 0, 0)];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    #[test]
    fn spec_rejects_uninit_read() {
        // r0 = r2 (uninit); exit
        let insns = [insn_bytes(0xbf, 0, 2, 0, 0), insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_rejects_uninit_stack_read() {
        // r0 = *(u64 *)(r10 - 8); exit
        let insns = [insn_bytes(0x79, 0, 10, -8, 0), insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_accepts_stack_roundtrip() {
        // r2 = 10; [r10-8] = r2; r0 = [r10-8]; exit
        let insns = [
            insn_bytes(0xb7, 2, 0, 0, 10),
            insn_bytes(0x7b, 10, 2, -8, 0),
            insn_bytes(0x79, 0, 10, -8, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    #[test]
    fn spec_branch_prunes_infeasible() {
        // r1 = 5; r2 = 7; jne r1, r2, +2; r0 = 0; exit; r0 = 1; exit
        let insns = [
            insn_bytes(0xb7, 1, 0, 0, 5),
            insn_bytes(0xb7, 2, 0, 0, 7),
            insn_bytes(0x5d, 1, 2, 2, 0),
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
            insn_bytes(0xb7, 0, 0, 0, 1),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    #[test]
    fn spec_rejects_stack_ptr_arith() {
        // r10 += 8; exit — R0 never set
        let insns = [insn_bytes(0x07, 10, 0, 0, 8), insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_bounded_loop_accepts() {
        // r0=0; r2=100; r1=0; r1+=1; jlt r1,r2,-2; exit
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0xb7, 2, 0, 0, 100),
            insn_bytes(0xb7, 1, 0, 0, 0),
            insn_bytes(0x07, 1, 0, 0, 1),
            insn_bytes(0xad, 1, 2, -2, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    #[test]
    fn spec_non_converging_loop_rejects() {
        // r0=0; r1=0; r1+=1; jeq r1,r1,-2; exit
        let insns = [
            insn_bytes(0xb7, 0, 0, 0, 0),
            insn_bytes(0xb7, 1, 0, 0, 0),
            insn_bytes(0x07, 1, 0, 0, 1),
            insn_bytes(0x1d, 1, 1, -2, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_rejects_invalid_shift() {
        // r2 = 1; r2 <<= 64; exit
        let insns = [
            insn_bytes(0xb7, 2, 0, 0, 1),
            insn_bytes(0x67, 2, 0, 0, 64),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_misaligned_8b_stack_write_rejects() {
        // r2 = 1; [r10-4] = r2 (8B store at -4) → misaligned
        let insns = [
            insn_bytes(0xb7, 2, 0, 0, 1),
            insn_bytes(0x7b, 10, 2, -4, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_rejects_exit_with_uninit_r0() {
        let insns = [insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(reject_contains(&insns, "R0 is uninitialized"));
    }

    #[test]
    fn spec_narrow_read_of_uninit_rejects() {
        // r0 = (u32)[r10-8]; exit (narrow_read_uninit)
        let insns = [insn_bytes(0x61, 0, 10, -8, 0), insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(matches!(run(&insns), SpecVerdict::Reject(_)));
    }

    #[test]
    fn spec_st_imm_zero_accepts() {
        // [r10-8] = 0; r0 = [r10-8]; exit
        let insns = [
            insn_bytes(0x7a, 10, 0, -8, 0),
            insn_bytes(0x79, 0, 10, -8, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    #[test]
    fn spec_alu32_zero_extend() {
        // r2 = -2147483648; w2 += 0; r2 += 1; r0 = r2; exit
        let insns = [
            insn_bytes(0xb7, 2, 0, 0, -2147483648i32),
            insn_bytes(0x04, 2, 0, 0, 0),
            insn_bytes(0x07, 2, 0, 0, 1),
            insn_bytes(0xbf, 0, 2, 0, 0),
            insn_bytes(0x95, 0, 0, 0, 0),
        ];
        assert_eq!(run(&insns), SpecVerdict::Accept);
    }

    /// The safety spec must accept the whole accept corpus and reject
    /// the whole reject corpus (issue #112's done condition). The
    /// per-fixture verdicts are printed for the documented verdict
    /// report (docs/spec-verdict-report.md).
    #[test]
    fn spec_corpus_accept_all() {
        let dir = std::path::Path::new("tests/programs/accept");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let mut env = crate::env::BpfVerifierEnv::new();
            env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
            let program = env.program_insns().to_vec();
            let verdict = verify_spec(&program, &env.maps);
            assert!(
                matches!(verdict, SpecVerdict::Accept),
                "spec rejected accept program {:?}: {verdict:?}",
                path
            );
            count += 1;
        }
        assert_eq!(
            count, 52,
            "expected the full accept corpus (60 files minus 8 .maps sidecars)"
        );
    }

    #[test]
    fn spec_corpus_reject_all() {
        let dir = std::path::Path::new("tests/programs/reject");
        let mut count = 0;
        let mut accepted: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let mut env = crate::env::BpfVerifierEnv::new();
            env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
            let program = env.program_insns().to_vec();
            let verdict = verify_spec(&program, &env.maps);
            if !matches!(verdict, SpecVerdict::Reject(_)) {
                accepted.push(format!(
                    "{} → {:?}",
                    path.file_stem().unwrap().to_str().unwrap(),
                    verdict
                ));
            }
            assert!(
                matches!(verdict, SpecVerdict::Reject(_)),
                "spec accepted reject program {:?}: {verdict:?}",
                path
            );
            count += 1;
        }
        assert_eq!(
            count, 47,
            "expected the full reject corpus (54 files minus 7 .maps sidecars); accepted: {accepted:#?}"
        );
    }

    #[test]
    fn spec_helper_unknown_rejects() {
        // call 999; exit
        let insns = [insn_bytes(0x85, 0, 0, 0, 999), insn_bytes(0x95, 0, 0, 0, 0)];
        assert!(reject_contains(&insns, "unknown helper"));
    }
}
