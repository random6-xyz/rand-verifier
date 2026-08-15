// ── Static liveness analysis (issue #97) ────────────────────────────────────
//
// Mirrors the kernel's `bpf_compute_live_registers()` (kernel/bpf/liveness.c)
// and the per-function-instance stack-slot liveness fixed point: for every
// instruction we compute the registers and stack slots that may be read
// *before* it, by solving
//
//     out[i] = ∪ { in[s] | s successor of i }
//     in[i]  = (out[i] \ def[i]) ∪ use[i]
//
// to a fixed point over the program's CFG. `in[i]` is exactly the kernel's
// `live_regs_before[i]` (mask_lo(in) | mask_hi(in)) resp. the stack
// `live_before` mask.
//
// The liveness masks drive the kernel-style state equality (#97):
//
// - `clean_state` (state_eq.rs) resets registers/stack slots that are dead
//   before an instruction to their not-initialized form before a state is
//   stored, exactly like the kernel's `clean_verifier_state()` /
//   `__clean_func_state()` (STACK_POISON / mark_reg_not_init);
// - `states_equal` compares only the registers that are live before the
//   stored state's instruction (`func_states_equal`'s `live_regs_before`).
//
// Soundness direction: the masks OVER-approximate liveness (a slot/register
// that *might* be read is live). An over-approximation keeps more state
// alive, which only makes cleaning and pruning more conservative — it can
// never erase state that a later instruction actually reads.

use crate::insn::BpfInsn;
use crate::state::STACK_SLOTS;

/// The liveness information of one program: for each instruction, the
/// registers and stack slots that may be read before it executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Liveness {
    /// Bit `r` of entry `i` set = register `r` may be live before insn `i`
    /// (mirrors the kernel's `insn_aux_data[i].live_regs_before`).
    live_regs_before: Vec<u16>,
    /// Bit `s` of entry `i` set = stack slot `s` may be live before insn `i`
    /// (mirrors the kernel's per-instance `live_before` stack mask).
    live_stack_before: Vec<u64>,
}

impl Liveness {
    /// Registers live before `pc` (a bitmask, bit `r` = register `r`).
    pub(crate) fn live_regs_before(&self, pc: u32) -> u16 {
        self.live_regs_before.get(pc as usize).copied().unwrap_or(0)
    }

    /// Stack slots live before `pc` (a bitmask, bit `s` = slot `s`).
    pub(crate) fn live_stack_before(&self, pc: u32) -> u64 {
        self.live_stack_before
            .get(pc as usize)
            .copied()
            .unwrap_or(0)
    }
}

/// Per-instruction use/def information: which registers and stack slots
/// the instruction reads (`use`) and writes (`def`).
struct InsnUseDef {
    use_regs: u16,
    def_regs: u16,
    read_slots: u64,
    write_slots: u64,
}

const NO_USE_DEF: InsnUseDef = InsnUseDef {
    use_regs: 0,
    def_regs: 0,
    read_slots: 0,
    write_slots: 0,
};

fn reg_bit(reg: u8) -> u16 {
    1u16 << reg
}

/// The stack slot a fixed 8-byte access at r10+`offset` touches
/// (mirrors `exec.rs`' slot mapping: slot(o) = (-o - 1) / 8), or `None`
/// when the access does not hit a valid single slot.
fn fixed_slot(offset: i16) -> Option<usize> {
    let off = offset as i32;
    if off >= 0 || off < -(crate::state::STACK_SIZE as i32) || off % 8 != 0 {
        return None;
    }
    Some(((-off) as usize - 1) / 8)
}

/// Every stack slot (conservative fallback for unknown access targets).
fn all_slots() -> u64 {
    u64::MAX >> (64 - STACK_SLOTS)
}

/// The stack slots an access through `base` at `offset` may touch.
///
/// Only a direct `r10 + offset` access has a statically known slot
/// (the frame pointer is fixed at 0). Any other base — a computed stack
/// pointer (`r6 = r10; r6 += k`) or a non-stack pointer — resolves to
/// an unknown r10-relative target, so the READ side conservatively
/// marks every slot live. (The kernel's liveness.c resolves FP-derived
/// pointers statically; the conservative fallback only over-approximates
/// liveness, which is sound.)
fn read_slots_for(base: u8, offset: i16) -> u64 {
    if base == 10 {
        fixed_slot(offset)
            .map(|s| 1u64 << s)
            .unwrap_or_else(all_slots)
    } else {
        all_slots()
    }
}

/// The stack slots an access through `base` at `offset` *definitely*
/// writes (the def side of the dataflow equation kills liveness). Only
/// a direct `r10 + offset` access has a known target; any other base
/// writes an unknown target, so NOTHING may be killed — killing a slot
/// that is actually read later would under-approximate liveness and
/// unsoundly clean a live slot (reviewer finding, #97).
fn write_slots_for(base: u8, offset: i16) -> u64 {
    if base == 10 {
        fixed_slot(offset).map(|s| 1u64 << s).unwrap_or(0)
    } else {
        0
    }
}

/// The subprogram entry containing insn `i` (0 = the main program).
fn subprog_entry_at(i: usize, program: &[BpfInsn]) -> Option<u32> {
    let mut starts = vec![0u32];
    for (pc, insn) in program.iter().enumerate() {
        if let BpfInsn::CallSub { offset } = insn {
            let target = (pc as i32 + 1 + *offset) as u32;
            if target as usize <= i && !starts.contains(&target) {
                starts.push(target);
            }
        }
    }
    starts.retain(|&s| (s as usize) <= i);
    starts.sort_unstable();
    starts.last().copied().filter(|&s| s != 0)
}

fn use_def(insn: &BpfInsn) -> InsnUseDef {
    let mut ud = NO_USE_DEF;
    match insn {
        BpfInsn::MovImm { dst, .. } => ud.def_regs = reg_bit(*dst),
        BpfInsn::MovReg { dst, src } => {
            ud.use_regs = reg_bit(*src);
            ud.def_regs = reg_bit(*dst);
        }
        // ALU64 and ALU32: `dst op= src/imm` reads `dst` (and `src`),
        // then writes `dst` (kernel compute_insn_live_regs: ALU/ALU64
        // default case — `def = dst`, `use = dst | src`).
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
            ud.use_regs = reg_bit(*dst);
            ud.def_regs = reg_bit(*dst);
        }
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
            ud.use_regs = reg_bit(*dst) | reg_bit(*src);
            ud.def_regs = reg_bit(*dst);
        }
        // loads read the base pointer and define the destination
        // (kernel BPF_LDX: `def = dst, use = src`)
        BpfInsn::LdMem { dst, base, offset } => {
            ud.use_regs = reg_bit(*base);
            ud.def_regs = reg_bit(*dst);
            ud.read_slots = read_slots_for(*base, *offset);
        }
        // stores read the value and the base pointer (kernel BPF_STX:
        // `use = dst | src`; BPF_ST: `use = dst`)
        BpfInsn::StMem { src, base, offset } => {
            ud.use_regs = reg_bit(*src) | reg_bit(*base);
            ud.write_slots = write_slots_for(*base, *offset);
        }
        // ldimm64 family: only the destination is defined (kernel
        // BPF_LD|BPF_IMM: `def = dst`); the second slot is a no-op.
        BpfInsn::LdImm64 { dst, .. }
        | BpfInsn::LdMapFd { dst, .. }
        | BpfInsn::LdMapValue { dst, .. } => ud.def_regs = reg_bit(*dst),
        BpfInsn::LdImm64Second { .. } => {}
        // helper calls and BPF-to-BPF calls read the argument
        // registers R1..R5 and clobber all caller-saved registers
        // R0..R5 (kernel BPF_CALL: `def = ALL_CALLER_SAVED_REGS`,
        // `use = r1..r5`)
        BpfInsn::Call { .. } | BpfInsn::CallSub { .. } | BpfInsn::CallKfunc { .. } => {
            ud.use_regs = reg_bit(1) | reg_bit(2) | reg_bit(3) | reg_bit(4) | reg_bit(5);
            ud.def_regs =
                reg_bit(0) | reg_bit(1) | reg_bit(2) | reg_bit(3) | reg_bit(4) | reg_bit(5);
        }
        // exit reads R0 (kernel BPF_EXIT: `use = r0` — the return value
        // is conceptually read at exit)
        BpfInsn::Exit => ud.use_regs = reg_bit(0),
        // unconditional jump: no registers (kernel BPF_JA: `use = 0`)
        BpfInsn::Jmp { .. } => {}
        // conditional jumps read both operands (kernel default JMP
        // case: `use = dst | src`)
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
            ud.use_regs = reg_bit(*dst) | reg_bit(*src);
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
            ud.use_regs = reg_bit(*dst);
        }
    }
    ud
}

/// The static successors of instruction `i`: the fall-through and/or the
/// jump target, mirroring the kernel's `bpf_insn_successors()`.
fn static_successors(i: usize, program: &[BpfInsn]) -> Vec<usize> {
    let insn = match program.get(i) {
        Some(insn) => insn,
        None => return Vec::new(),
    };
    let mut succ = Vec::with_capacity(2);
    match insn {
        // a subprogram's exit returns to every call site + 1 (#100);
        // the main program's exit is terminal
        BpfInsn::Exit => {
            if i != 0
                && let Some(start) = subprog_entry_at(i, program)
            {
                for (pc, insn) in program.iter().enumerate() {
                    if let BpfInsn::CallSub { offset } = insn {
                        let target = (pc as i32 + 1 + *offset) as u32;
                        if target == start {
                            succ.push(pc + 1);
                        }
                    }
                }
            }
        }
        BpfInsn::CallSub { offset } => {
            let tgt = i as i64 + 1 + *offset as i64;
            if tgt >= 0 && (tgt as usize) < program.len() {
                succ.push(tgt as usize);
            }
        }
        BpfInsn::Jmp { offset } => {
            let tgt = i as i64 + 1 + *offset as i64;
            if tgt >= 0 && (tgt as usize) < program.len() {
                succ.push(tgt as usize);
            }
        }
        insn if insn.is_conditional_branch() => {
            if i + 1 < program.len() {
                succ.push(i + 1);
            }
            let offset = match insn {
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
                | BpfInsn::JsleImm { offset, .. } => *offset,
                _ => unreachable!(),
            };
            let tgt = i as i64 + 1 + offset as i64;
            if tgt >= 0 && (tgt as usize) < program.len() {
                succ.push(tgt as usize);
            }
        }
        _ => {
            if i + 1 < program.len() {
                succ.push(i + 1);
            }
        }
    }
    succ
}

/// Compute the per-instruction liveness masks of a program by solving
/// the dataflow equations to a fixed point (kernel
/// `bpf_compute_live_registers()`).
pub(crate) fn analyze(program: &[BpfInsn]) -> Liveness {
    let n = program.len();
    let ud: Vec<InsnUseDef> = program.iter().map(use_def).collect();
    let mut in_regs = vec![0u16; n];
    let mut out_regs = vec![0u16; n];
    let mut in_slots = vec![0u64; n];
    let mut out_slots = vec![0u64; n];

    loop {
        let mut changed = false;
        for i in 0..n {
            let mut o_regs = 0u16;
            let mut o_slots = 0u64;
            for s in static_successors(i, program) {
                o_regs |= in_regs[s];
                o_slots |= in_slots[s];
            }
            let new_in_regs = (o_regs & !ud[i].def_regs) | ud[i].use_regs;
            let new_in_slots = (o_slots & !ud[i].write_slots) | ud[i].read_slots;
            if new_in_regs != in_regs[i] {
                in_regs[i] = new_in_regs;
                changed = true;
            }
            if new_in_slots != in_slots[i] {
                in_slots[i] = new_in_slots;
                changed = true;
            }
            if o_regs != out_regs[i] || o_slots != out_slots[i] {
                out_regs[i] = o_regs;
                out_slots[i] = o_slots;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    Liveness {
        live_regs_before: in_regs,
        live_stack_before: in_slots,
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::BpfInsn;

    fn live_regs(l: &Liveness, pc: u32) -> Vec<u8> {
        let mask = l.live_regs_before(pc);
        (0..crate::state::NUM_REGS as u8)
            .filter(|r| mask & (1 << r) != 0)
            .collect()
    }

    fn live_slots(l: &Liveness, pc: u32) -> Vec<usize> {
        let mask = l.live_stack_before(pc);
        (0..STACK_SLOTS).filter(|s| mask & (1 << s) != 0).collect()
    }

    #[test]
    fn straight_line_reg_liveness() {
        // r1 = 5; r0 = r1; r2 = 7; exit
        // - r1 is read at insn 1, but written at insn 0 before that
        //   read → its pre-insn-0 value is dead (liveness is "read
        //   before written", kernel in = (out \ def) ∪ use)
        // - r0 is read at exit → live before insn 2 (and later)
        // - r2 is written at insn 2 but never read → dead everywhere
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::MovReg { dst: 0, src: 1 },
            BpfInsn::MovImm { dst: 2, imm: 7 },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_regs(&l, 0), Vec::<u8>::new());
        assert_eq!(live_regs(&l, 1), vec![1]);
        assert_eq!(live_regs(&l, 2), vec![0]);
        assert_eq!(live_regs(&l, 3), vec![0]);
    }

    #[test]
    fn alu_reads_dst_and_src() {
        // r1 = 1; r2 = 2; r1 += r2; exit — r1 (dst) and r2 (src) are
        // live before the add; r0 is live too (read at exit)
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 1 },
            BpfInsn::MovImm { dst: 2, imm: 2 },
            BpfInsn::AddReg { dst: 1, src: 2 },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_regs(&l, 0), vec![0]);
        assert_eq!(live_regs(&l, 1), vec![0, 1]);
        assert_eq!(live_regs(&l, 2), vec![0, 1, 2]);
        assert_eq!(live_regs(&l, 3), vec![0]);
    }

    #[test]
    fn call_clobbers_caller_saved() {
        // r6 = 5; call 7; r0 = r6; exit — r6 (callee-saved) survives
        // the call; r1..r5 are read (args) before the call and clobbered
        // after it
        let program = vec![
            BpfInsn::MovImm { dst: 6, imm: 5 },
            BpfInsn::Call { imm: 7 },
            BpfInsn::MovReg { dst: 0, src: 6 },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_regs(&l, 0), vec![1, 2, 3, 4, 5]);
        assert_eq!(live_regs(&l, 1), vec![1, 2, 3, 4, 5, 6]);
        // after the call only r6 is live before the mov (r0 is written
        // there and read at exit)
        assert_eq!(live_regs(&l, 2), vec![6]);
        assert_eq!(live_regs(&l, 3), vec![0]);
    }

    #[test]
    fn exit_reads_r0() {
        // r0 = 42; exit — r0 is live before exit because exit reads it
        // (kernel BPF_EXIT: use = r0); before the mov it is dead (the
        // mov writes it first)
        let program = vec![BpfInsn::MovImm { dst: 0, imm: 42 }, BpfInsn::Exit];
        let l = analyze(&program);
        assert_eq!(live_regs(&l, 0), Vec::<u8>::new());
        assert_eq!(live_regs(&l, 1), vec![0]);
    }

    #[test]
    fn stack_slot_liveness() {
        // r1 = 5; [r10-8] = r1; r2 = [r10-8]; exit
        // slot 0 is read at insn 2 and written at insn 1 → live before
        // insn 2 only (the write kills it before insn 1)
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
            },
            BpfInsn::LdMem {
                dst: 2,
                base: 10,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_slots(&l, 0), Vec::<usize>::new());
        assert_eq!(live_slots(&l, 1), Vec::<usize>::new());
        assert_eq!(live_slots(&l, 2), vec![0]);
        assert_eq!(live_slots(&l, 3), Vec::<usize>::new());
    }

    #[test]
    fn dead_stack_slot_not_live() {
        // r1 = 5; [r10-8] = r1; r1 = 7; exit — slot 0 is written but
        // never read → dead everywhere
        let program = vec![
            BpfInsn::MovImm { dst: 1, imm: 5 },
            BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
            },
            BpfInsn::MovImm { dst: 1, imm: 7 },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_slots(&l, 0), Vec::<usize>::new());
    }

    #[test]
    fn loop_back_edge_liveness() {
        // the counter loop: r0 = 0; r2 = 100; r1 = 0; r1 += 1;
        // if r1 < r2 goto -2; exit — r1/r2 live across the back edge
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
        let l = analyze(&program);
        // before the increment: r1 is live (read by the add and the jlt),
        // r2 is live (read by the jlt), r0 is live (read at exit)
        assert_eq!(live_regs(&l, 3), vec![0, 1, 2]);
        // before the branch: r1 and r2 are live (read by the jlt)
        assert_eq!(live_regs(&l, 4), vec![0, 1, 2]);
        // r0 is live at exit
        assert_eq!(live_regs(&l, 5), vec![0]);
    }

    #[test]
    fn indirect_base_is_conservative() {
        // r6 = r10; r6 += -8; r1 = [r6]; exit — the load's base is not
        // the frame pointer, so the analysis conservatively marks every
        // slot live before it
        let program = vec![
            BpfInsn::MovReg { dst: 6, src: 10 },
            BpfInsn::AddImm { dst: 6, imm: -8 },
            BpfInsn::LdMem {
                dst: 1,
                base: 6,
                offset: 0,
            },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_slots(&l, 2), (0..STACK_SLOTS).collect::<Vec<_>>());
    }

    #[test]
    fn indirect_base_shifted_offset_is_conservative() {
        // r6 = r10; r6 += -8; r1 = [r6 - 8] — the real access is at
        // r10-16 (slot 1), but the static analysis cannot know the
        // base's offset, so EVERY slot must stay live — attributing
        // slot 0 here would let dead-slot cleaning erase slot 1 and
        // unsoundly prune a state whose slot-1 contents differ
        // (reviewer finding, #97)
        let program = vec![
            BpfInsn::MovReg { dst: 6, src: 10 },
            BpfInsn::AddImm { dst: 6, imm: -8 },
            BpfInsn::LdMem {
                dst: 1,
                base: 6,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        assert_eq!(live_slots(&l, 2), (0..STACK_SLOTS).collect::<Vec<_>>());
    }

    #[test]
    fn indirect_base_write_kills_nothing() {
        // r6 = r10; r6 += -8; [r6] = r1; r2 = [r10-8]; exit — the
        // indirect store's target is unknown, so the analysis must NOT
        // kill any slot's liveness: slot 0 stays live because the
        // direct load at [r10-8] reads it
        let program = vec![
            BpfInsn::MovReg { dst: 6, src: 10 },
            BpfInsn::AddImm { dst: 6, imm: -8 },
            BpfInsn::StMem {
                src: 1,
                base: 6,
                offset: 0,
            },
            BpfInsn::LdMem {
                dst: 2,
                base: 10,
                offset: -8,
            },
            BpfInsn::Exit,
        ];
        let l = analyze(&program);
        // slot 0 is live before the indirect store (the direct load
        // after it reads slot 0); an all-slots write attribution would
        // kill it here
        assert_eq!(live_slots(&l, 2), vec![0]);
    }
}
