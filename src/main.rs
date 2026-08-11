use anyhow::Result;
use std::env;
use std::fs;

// ── BPF opcodes ──────────────────────────────────────────────────────────────

#[allow(dead_code)]
mod opcode {
    pub const MOV_IMM: u8 = 0x01;
    pub const MOV_REG: u8 = 0x02;
    pub const ADD_IMM: u8 = 0x03;
    pub const ADD_REG: u8 = 0x04;
    pub const LD_STACK: u8 = 0x05;
    pub const ST_STACK: u8 = 0x06;
    pub const JEQ: u8 = 0x07;
    pub const JGT: u8 = 0x08;
    pub const JMP: u8 = 0x09;
    pub const CALL: u8 = 0x0A;
    pub const EXIT: u8 = 0x0B;
}

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_SUBPROGS: usize = 256;

// ── BPF instruction ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
// register fields (dst/src/imm/offset) are consumed by state tracking (v0.2)
#[allow(dead_code)]
enum BpfInsn {
    MovImm { dst: u8, imm: i32 },
    MovReg { dst: u8, src: u8 },
    AddImm { dst: u8, imm: i32 },
    AddReg { dst: u8, src: u8 },
    LdStack { dst: u8, offset: i16 },
    StStack { src: u8, offset: i16 },
    Jeq { dst: u8, src: u8, offset: i16 },
    Jgt { dst: u8, src: u8, offset: i16 },
    Jmp { offset: i16 },
    Call { imm: i32 },
    Exit,
}

fn parse_insn(bytes: &[u8]) -> BpfInsn {
    let op = bytes[0];
    let regs = bytes[1];
    let dst = regs & 0x0F;
    let src = (regs >> 4) & 0x0F;
    let offset = i16::from_le_bytes([bytes[2], bytes[3]]);
    let imm = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

    match op {
        opcode::MOV_IMM => BpfInsn::MovImm { dst, imm },
        opcode::MOV_REG => BpfInsn::MovReg { dst, src },
        opcode::ADD_IMM => BpfInsn::AddImm { dst, imm },
        opcode::ADD_REG => BpfInsn::AddReg { dst, src },
        opcode::LD_STACK => BpfInsn::LdStack { dst, offset },
        opcode::ST_STACK => BpfInsn::StStack { src, offset },
        opcode::JEQ => BpfInsn::Jeq { dst, src, offset },
        opcode::JGT => BpfInsn::Jgt { dst, src, offset },
        opcode::JMP => BpfInsn::Jmp { offset },
        opcode::CALL => BpfInsn::Call { imm },
        opcode::EXIT => BpfInsn::Exit,
        _ => panic!("Unknown opcode: {:#04x}", op),
    }
}

// ── Abstract register state (v0.2 Micro) ─────────────────────────────────────

/// Number of eBPF registers: R0..R10.
const NUM_REGS: usize = 11;

/// Abstract state of a single register during symbolic execution.
///
/// Instead of tracking concrete u64 values, the verifier tracks an abstract
/// value per register (cf. kernel verifier docs):
///
/// - `Uninit` — the register has never been written
/// - `Scalar` — a scalar in `[min, max]` (`min == max` means a constant)
/// - `PtrToStack` — pointer into the stack frame, offset relative to R10
/// - `PtrToCtx` — pointer to the program context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegState {
    Uninit,
    Scalar { min: i64, max: i64 },
    PtrToStack { offset: i32 },
    PtrToCtx,
}

impl std::fmt::Display for RegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegState::Uninit => write!(f, "UNINIT"),
            RegState::Scalar { min, max } => write!(f, "SCALAR({}..{})", min, max),
            RegState::PtrToStack { offset } => write!(f, "PTR_STACK({})", offset),
            RegState::PtrToCtx => write!(f, "PTR_CTX"),
        }
    }
}

/// Initial register state at program entry, following the eBPF calling
/// convention: R1 receives the context pointer, R10 is the read-only stack
/// frame pointer, all other registers start uninitialized.
#[allow(dead_code)] // consumed by abstract execution engine (#13)
fn initial_reg_state() -> [RegState; NUM_REGS] {
    let mut regs = [RegState::Uninit; NUM_REGS];
    regs[1] = RegState::PtrToCtx;
    regs[10] = RegState::PtrToStack { offset: 0 };
    regs
}

// ── Stack state (v0.2 Micro) ─────────────────────────────────────────────────

/// BPF stack size in bytes, fixed by the eBPF spec.
const STACK_SIZE: usize = 512;

/// Size of one stack slot in bytes (8-byte access granularity).
const STACK_SLOT_SIZE: usize = 8;

/// Number of stack slots: 512 / 8 = 64.
const STACK_SLOTS: usize = STACK_SIZE / STACK_SLOT_SIZE;

/// Abstract state of a single stack slot.
///
/// Slot-level granularity (not byte-level) keeps the model approachable;
/// scalar ranges and spilled pointer states are not tracked here yet (#30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackSlot {
    Uninit,
    Scalar,
}

impl std::fmt::Display for StackSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackSlot::Uninit => write!(f, "UNINIT"),
            StackSlot::Scalar => write!(f, "SCALAR"),
        }
    }
}

/// Abstract stack state: one slot per 8-byte cell of the 512-byte frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackState {
    slots: [StackSlot; STACK_SLOTS],
}

impl StackState {
    /// A fresh stack frame: every slot uninitialized.
    fn new() -> Self {
        Self {
            slots: [StackSlot::Uninit; STACK_SLOTS],
        }
    }
}

/// Map an r10-relative stack offset to a slot index.
///
/// Offsets must point into the frame (r10-512..r10-8) and be 8-byte
/// aligned: -8 → slot 0, -16 → slot 1, ..., -512 → slot 63. Each kind
/// of bounds violation is reported with its own message (#19).
fn stack_slot_index(offset: i32) -> Result<usize, VerificationFailure> {
    // wrong direction: r10 + N, or the frame pointer itself (r10 + 0)
    if offset >= 0 {
        return Err(VerificationFailure::new(
            NO_PC,
            format!(
                "stack access at r10{:+} points away from the frame (valid: r10-512..r10-8)",
                offset
            ),
        ));
    }
    // beyond the frame
    if offset < -(STACK_SIZE as i32) {
        return Err(VerificationFailure::new(
            NO_PC,
            format!(
                "stack access at r10{:+} exceeds the {} byte frame",
                offset, STACK_SIZE
            ),
        ));
    }
    // slot alignment
    if offset % (STACK_SLOT_SIZE as i32) != 0 {
        return Err(VerificationFailure::new(
            NO_PC,
            format!("stack access at r10{:+} is not 8-byte aligned", offset),
        ));
    }
    Ok(((-offset) as usize - 8) / STACK_SLOT_SIZE)
}

// ── Verifier state (v0.2 Micro) ──────────────────────────────────────────────

/// Unified verifier state carried through instruction simulation.
///
/// Holds the abstract state of all 11 registers plus the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerifierState {
    regs: [RegState; NUM_REGS],
    stack: StackState,
}

impl VerifierState {
    /// Initial state at program entry: R1 = PtrToCtx, R10 = PtrToStack(0),
    /// all other registers uninitialized, stack frame fully uninitialized.
    #[allow(dead_code)] // consumed by the micro verifier driver (#23)
    fn initial() -> Self {
        Self {
            regs: initial_reg_state(),
            stack: StackState::new(),
        }
    }
}

// ── Abstract instruction execution (v0.2 Micro) ──────────────────────────────

/// step() runs without program context; the driver loop assigns the real pc (#23).
const NO_PC: u32 = 0;

/// Validate a register number used as a write destination.
fn check_reg(reg: u8) -> Result<(), VerificationFailure> {
    if reg as usize >= NUM_REGS {
        Err(VerificationFailure::new(
            NO_PC,
            format!(
                "invalid register r{} (valid range is r0..r{})",
                reg,
                NUM_REGS - 1
            ),
        ))
    } else {
        Ok(())
    }
}

/// Read a register's abstract state.
///
/// This is the single read entry point for instructions: a register must
/// have been written before it is read, otherwise the read is rejected
/// (cf. the kernel verifier's "R%d !read_ok" error). Later issues reuse
/// this helper for their own read sites (#15, #17, #23, #28).
fn read_reg(state: &VerifierState, reg: u8) -> Result<RegState, VerificationFailure> {
    check_reg(reg)?;
    match state.regs[reg as usize] {
        RegState::Uninit => Err(VerificationFailure::new(
            NO_PC,
            format!("register r{} is uninitialized", reg),
        )),
        other => Ok(other),
    }
}

/// Read a register as a scalar (min, max) value.
///
/// ALU operations only accept scalars: uninitialized registers are
/// rejected by `read_reg` (#14), and pointers are rejected because
/// register-offset pointer arithmetic is not supported yet (only
/// pointer + immediate is allowed, #20).
fn read_scalar(state: &VerifierState, reg: u8) -> Result<(i64, i64), VerificationFailure> {
    match read_reg(state, reg)? {
        RegState::Scalar { min, max } => Ok((min, max)),
        RegState::PtrToStack { .. } | RegState::PtrToCtx => Err(VerificationFailure::new(
            NO_PC,
            format!(
                "register-offset pointer arithmetic on r{} is not supported yet (only immediate offsets)",
                reg
            ),
        )),
        RegState::Uninit => unreachable!("read_reg rejects uninitialized registers"),
    }
}

/// Symbolically execute a single instruction, producing the next state.
///
/// Instead of tracking concrete u64 values, registers are updated by
/// abstract rules: an immediate move produces a constant scalar range,
/// a register move copies the source's abstract state, and `exit`
/// terminates the path without changing the state.
///
/// Instructions that expand to a single successor are executed here;
/// control flow (Jmp/Jeq/Jgt) is expanded by the worklist driver (#23),
/// calls are not part of the subset yet (#28), and register-offset
/// pointer arithmetic is rejected (#20).
#[allow(dead_code)] // consumed by the micro verifier driver (#23)
fn step(state: &VerifierState, insn: &BpfInsn) -> Result<VerifierState, VerificationFailure> {
    match insn {
        // rX = imm → constant scalar
        BpfInsn::MovImm { dst, imm } => {
            check_reg(*dst)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar {
                min: *imm as i64,
                max: *imm as i64,
            };
            Ok(next)
        }
        // rX = rY → copy the source's abstract state;
        // the source must have been written before it is read (#14)
        BpfInsn::MovReg { dst, src } => {
            check_reg(*dst)?;
            let src_state = read_reg(state, *src)?;
            let mut next = *state;
            next.regs[*dst as usize] = src_state;
            Ok(next)
        }
        // terminal — the path ends here without changing the state
        BpfInsn::Exit => Ok(*state),
        // rX += imm → shift a scalar range, or a stack pointer offset:
        // pointer + immediate is the only allowed pointer arithmetic (#20)
        BpfInsn::AddImm { dst, imm } => {
            check_reg(*dst)?;
            let dst_state = read_reg(state, *dst)?;
            match dst_state {
                RegState::Scalar { min, max } => {
                    let mut next = *state;
                    next.regs[*dst as usize] = RegState::Scalar {
                        min: min.wrapping_add(*imm as i64),
                        max: max.wrapping_add(*imm as i64),
                    };
                    Ok(next)
                }
                // PtrToStack + Scalar => PtrToStack at the shifted offset;
                // the pointer must stay within the frame (cf. #19)
                RegState::PtrToStack { offset } => {
                    let new_offset = offset.wrapping_add(*imm);
                    if !(-(STACK_SIZE as i32)..=0).contains(&new_offset) {
                        return Err(VerificationFailure::new(
                            NO_PC,
                            format!(
                                "stack pointer r{} offset {} is out of the {} byte frame",
                                dst, new_offset, STACK_SIZE
                            ),
                        ));
                    }
                    let mut next = *state;
                    next.regs[*dst as usize] = RegState::PtrToStack { offset: new_offset };
                    Ok(next)
                }
                RegState::PtrToCtx => Err(VerificationFailure::new(
                    NO_PC,
                    format!("arithmetic on context pointer r{} is not allowed", dst),
                )),
                RegState::Uninit => unreachable!("read_reg rejects uninitialized registers"),
            }
        }
        // rX += rY → add the two scalar ranges; exact constants propagate
        // because a constant is a range with min == max
        BpfInsn::AddReg { dst, src } => {
            check_reg(*dst)?;
            let (dmin, dmax) = read_scalar(state, *dst)?;
            let (smin, smax) = read_scalar(state, *src)?;
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar {
                min: dmin.wrapping_add(smin),
                max: dmax.wrapping_add(smax),
            };
            Ok(next)
        }
        // r10[offset] = rY → store the source's abstract state to a stack
        // slot; only scalars are representable yet (pointer spill is #30)
        BpfInsn::StStack { src, offset } => {
            let slot = stack_slot_index(*offset as i32)?;
            let src_state = read_reg(state, *src)?;
            match src_state {
                RegState::Scalar { .. } => {}
                RegState::PtrToStack { .. } | RegState::PtrToCtx => {
                    return Err(VerificationFailure::new(
                        NO_PC,
                        format!("spilling pointer r{} is not supported yet (see #30)", src),
                    ));
                }
                RegState::Uninit => unreachable!("read_reg rejects uninitialized registers"),
            }
            let mut next = *state;
            next.stack.slots[slot] = StackSlot::Scalar;
            Ok(next)
        }
        // rX = r10[offset] → load a stack slot; a slot must have been
        // written before it is read (write-before-read, #18)
        BpfInsn::LdStack { dst, offset } => {
            check_reg(*dst)?;
            let slot = stack_slot_index(*offset as i32)?;
            match state.stack.slots[slot] {
                StackSlot::Uninit => {
                    return Err(VerificationFailure::new(
                        NO_PC,
                        format!(
                            "stack slot at offset {} is uninitialized (write before read)",
                            offset
                        ),
                    ));
                }
                StackSlot::Scalar => {}
            }
            // the slot carries no range yet, so a loaded scalar is unknown
            let mut next = *state;
            next.regs[*dst as usize] = RegState::Scalar {
                min: i64::MIN,
                max: i64::MAX,
            };
            Ok(next)
        }
        // control flow is expanded by the worklist driver (#23), which
        // produces multiple successor states — a single-state step()
        // cannot execute it; calls are not part of the subset yet
        BpfInsn::Jeq { .. } | BpfInsn::Jgt { .. } | BpfInsn::Jmp { .. } => {
            Err(VerificationFailure::new(
                NO_PC,
                "control flow is not executed by step() (see the worklist driver #23)",
            ))
        }
        BpfInsn::Call { .. } => Err(VerificationFailure::new(
            NO_PC,
            "call instruction not supported yet (see #28)",
        )),
    }
}

// ── Branch refinement (v0.2 Micro) ───────────────────────────────────────────

/// A scalar value range [min, max].
type ScalarRange = (i64, i64);

/// Both operands of a comparison refined for one branch side: (dst, src).
type RefinedPair = (ScalarRange, ScalarRange);

/// Refinement result of a comparison: (true branch, false branch).
type RefinedBranches = (RefinedPair, RefinedPair);

/// Refine two scalar ranges on the `dst > src` comparison.
///
/// Both operands are narrowed (cf. the kernel's adjust_scalar_min_max_vals):
///
/// - true branch:  dst >= src.min + 1, src <= dst.max - 1
/// - false branch: dst <= src.max,     src >= dst.min
///
/// A refined range with min > max means the branch is infeasible.
/// Comparisons are interpreted as signed (the kernel splits JGT/JSGT by
/// signedness; our subset has a single `Jgt`).
#[allow(dead_code)] // consumed by branch exploration (#24)
fn refine_gt(dst: ScalarRange, src: ScalarRange) -> RefinedBranches {
    // true: dst > src
    let true_dst = (dst.0.max(src.0.wrapping_add(1)), dst.1);
    let true_src = (src.0, src.1.min(dst.1.wrapping_sub(1)));
    // false: dst <= src
    let false_dst = (dst.0, dst.1.min(src.1));
    let false_src = (src.0.max(dst.0), src.1);
    ((true_dst, true_src), (false_dst, false_src))
}

/// Refine two scalar ranges on the `dst == src` comparison.
///
/// - true branch: both operands take the intersection of the two ranges
///   (min > max means the branch is infeasible)
/// - false branch: a single interval cannot represent the complement of
///   another interval, so no safe narrowing is possible — both are kept
#[allow(dead_code)] // consumed by branch exploration (#24)
fn refine_eq(dst: ScalarRange, src: ScalarRange) -> RefinedBranches {
    let inter = (dst.0.max(src.0), dst.1.min(src.1));
    ((inter, inter), (dst, src))
}

// ── Execution trace (v0.2 Micro) ─────────────────────────────────────────────

/// Render a single instruction in a readable eBPF-like syntax.
fn disassemble(insn: &BpfInsn) -> String {
    match insn {
        BpfInsn::MovImm { dst, imm } => format!("r{} = {}", dst, imm),
        BpfInsn::MovReg { dst, src } => format!("r{} = r{}", dst, src),
        BpfInsn::AddImm { dst, imm } => format!("r{} += {}", dst, imm),
        BpfInsn::AddReg { dst, src } => format!("r{} += r{}", dst, src),
        BpfInsn::LdStack { dst, offset } => format!("r{} = [r10{:+}]", dst, offset),
        BpfInsn::StStack { src, offset } => format!("[r10{:+}] = r{}", offset, src),
        BpfInsn::Jeq { dst, src, offset } => {
            format!("if r{} == r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            format!("if r{} > r{} goto {:+}", dst, src, offset)
        }
        BpfInsn::Jmp { offset } => format!("goto {:+}", offset),
        BpfInsn::Call { imm } => format!("call {}", imm),
        BpfInsn::Exit => "exit".to_string(),
    }
}

/// Render one trace entry for a step: the disassembled instruction
/// followed by the interesting registers.
///
/// The first step shows the entry-relevant state (R0, the exit-value
/// register, plus every initialized register); later steps show only the
/// registers whose state changed, mirroring the #21 example.
fn trace_step(pc: u32, insn: &BpfInsn, before: &VerifierState, after: &VerifierState) -> String {
    let mut out = format!("{}: {}\n", pc, disassemble(insn));
    if pc == 0 {
        // R0 is the exit value — always shown at the start
        out.push_str(&format!("  R0 = {}\n", after.regs[0]));
        for (i, reg) in after.regs.iter().enumerate().skip(1) {
            if *reg != RegState::Uninit {
                out.push_str(&format!("  R{} = {}\n", i, reg));
            }
        }
    } else {
        for (i, (before, after)) in before.regs.iter().zip(&after.regs).enumerate() {
            if before != after {
                out.push_str(&format!("  R{} = {}\n", i, after));
            }
        }
    }
    out
}

/// Execute a straight-line program and render the execution trace.
///
/// Micro-stage trace renderer: steps through every instruction in order
/// and stops at the first instruction step() cannot execute (control
/// flow is expanded by the worklist driver #23 instead).
#[allow(dead_code)] // rendered through the CLI once the worklist driver lands (#23)
fn run_trace(program: &[BpfInsn]) -> Result<String, VerificationFailure> {
    let mut out = String::new();
    let mut state = VerifierState::initial();
    for (pc, insn) in program.iter().enumerate() {
        let next = step(&state, insn)?;
        out.push_str(&trace_step(pc as u32, insn, &state, &next));
        out.push('\n');
        state = next;
    }
    Ok(out)
}

// ── Worklist path exploration (v0.3 Mini) ────────────────────────────────────

/// One pending state in the path exploration: an instruction index and
/// the verifier state carried to it (cf. the kernel's verifier stack).
struct WorkItem {
    pc: u32,
    state: VerifierState,
}

/// The conditional comparisons in the mini subset.
enum CondOp {
    Eq,
    Gt,
}

/// PC-relative branch target: the offset is relative to the next insn.
fn branch_target(pc: u32, offset: i16) -> u32 {
    (pc as i32 + 1 + offset as i32) as u32
}

/// A refined branch state is feasible unless a refined range is empty
/// (min > max), i.e. the branch can never be taken at run time.
fn is_feasible(state: &VerifierState, dst: u8, src: u8) -> bool {
    [dst, src]
        .into_iter()
        .all(|r| match state.regs[r as usize] {
            RegState::Scalar { min, max } => min <= max,
            _ => true,
        })
}

/// Expand the instruction at `pc` into its successor (pc, state) pairs.
///
/// Control flow is expanded here, not in `step()` (which is single-state):
/// exit terminates the path, Jmp follows only its target, Jeq/Jgt fork
/// into both branches with scalar range refinement (#16), and everything
/// else falls through via `step()`.
fn successors(
    pc: u32,
    insn: &BpfInsn,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    match insn {
        BpfInsn::Exit => Ok(vec![]),
        BpfInsn::Jmp { offset } => Ok(vec![(branch_target(pc, *offset), *state)]),
        BpfInsn::Jeq { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Eq, state)
        }
        BpfInsn::Jgt { dst, src, offset } => {
            cond_branch(pc, *dst, *src, *offset, CondOp::Gt, state)
        }
        BpfInsn::Call { .. } => Err(VerificationFailure::new(
            NO_PC,
            "call instruction not supported yet (see #28)",
        )),
        _ => {
            let next = step(state, insn)?;
            Ok(vec![(pc + 1, next)])
        }
    }
}

/// Fork a conditional branch into taken and fall-through successors.
///
/// Scalar operands are refined on both sides via #16 (like the kernel's
/// check_cond_jmp_op / regs_refine_cond_op); a branch narrowed to an
/// empty range is infeasible and pruned. Pointers of the same type may
/// be compared for equality without refinement (the NULL-check
/// foundation for #27); `>` on pointers and mixed-type comparisons are
/// rejected, mirroring the kernel.
fn cond_branch(
    pc: u32,
    dst: u8,
    src: u8,
    offset: i16,
    op: CondOp,
    state: &VerifierState,
) -> Result<Vec<(u32, VerifierState)>, VerificationFailure> {
    let dst_state = read_reg(state, dst)?;
    let src_state = read_reg(state, src)?;
    let taken_pc = branch_target(pc, offset);
    let fall_pc = pc + 1;

    let (taken, fall) = match (dst_state, src_state) {
        (
            RegState::Scalar {
                min: dmin,
                max: dmax,
            },
            RegState::Scalar {
                min: smin,
                max: smax,
            },
        ) => {
            let ((t_dst, t_src), (f_dst, f_src)) = match op {
                CondOp::Eq => refine_eq((dmin, dmax), (smin, smax)),
                CondOp::Gt => refine_gt((dmin, dmax), (smin, smax)),
            };
            let mut taken = *state;
            taken.regs[dst as usize] = RegState::Scalar {
                min: t_dst.0,
                max: t_dst.1,
            };
            taken.regs[src as usize] = RegState::Scalar {
                min: t_src.0,
                max: t_src.1,
            };
            let mut fall = *state;
            fall.regs[dst as usize] = RegState::Scalar {
                min: f_dst.0,
                max: f_dst.1,
            };
            fall.regs[src as usize] = RegState::Scalar {
                min: f_src.0,
                max: f_src.1,
            };
            (taken, fall)
        }
        // pointers of the same type: equality is allowed without
        // refinement; `>` on pointers is not
        (RegState::PtrToStack { .. }, RegState::PtrToStack { .. })
        | (RegState::PtrToCtx, RegState::PtrToCtx) => match op {
            CondOp::Eq => (*state, *state),
            CondOp::Gt => {
                return Err(VerificationFailure::new(
                    NO_PC,
                    format!("comparing pointers r{} > r{} is not allowed", dst, src),
                ));
            }
        },
        // read_reg rejects uninitialized registers before we get here
        (RegState::Uninit, _) | (_, RegState::Uninit) => {
            unreachable!("read_reg rejects uninitialized registers")
        }
        // scalar vs pointer, or pointers of different types
        _ => {
            return Err(VerificationFailure::new(
                NO_PC,
                format!(
                    "invalid comparison of r{} with r{} (different types)",
                    dst, src
                ),
            ));
        }
    };

    let mut out = Vec::with_capacity(2);
    if is_feasible(&taken, dst, src) {
        out.push((taken_pc, taken));
    }
    if is_feasible(&fall, dst, src) {
        out.push((fall_pc, fall));
    }
    Ok(out)
}

/// Path-sensitive verification: explore every execution path with a
/// worklist until it is empty.
///
/// - states are processed LIFO (depth-first), like the kernel's
///   push_stack/pop_stack verifier stack
/// - every path must reach `exit` with R0 initialized (cf. the kernel's
///   R0 !read_ok check at exit)
/// - branches narrowed to an empty range are pruned during expansion
/// - termination is guaranteed because the nano pass (#6) rejects loops,
///   so the CFG is acyclic; state dedup (#25/#26) and complexity limits
///   (#32) come later
#[allow(dead_code)] // consumed by the mini corpus runner (#33)
fn verify_mini(program: &[BpfInsn]) -> Result<(), VerificationFailure> {
    let mut worklist = vec![WorkItem {
        pc: 0,
        state: VerifierState::initial(),
    }];

    while let Some(item) = worklist.pop() {
        let insn = program.get(item.pc as usize).ok_or_else(|| {
            VerificationFailure::new(item.pc, "internal error: pc out of program range")
        })?;

        // a path ends at exit; R0 must hold a valid value there
        if matches!(insn, BpfInsn::Exit) {
            read_reg(&item.state, 0)
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
    Ok(())
}

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
fn add_subprog(insns: &[BpfInsn]) -> Result<Vec<u32>, VerificationFailure> {
    let insn_cnt = insns.len() as u32;
    let mut subprogs = vec![0u32];

    for (idx, insn) in insns.iter().enumerate() {
        if let BpfInsn::Call { imm } = insn {
            register_subprog(idx as u32, *imm, insn_cnt, &mut subprogs)?;
        }
    }

    Ok(subprogs)
}

// ── CFG check ──────────────────────────────────────────────────────────────

/// Return the [start, end) range of the subprogram that contains `insn_idx`.
fn find_subprog_range(insn_idx: u32, subprogs: &[u32], insn_cnt: u32) -> (u32, u32) {
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
enum VisitState {
    NotVisited,
    Discovering,
    Explored,
}

/// Process one instruction: verify branch/fall-through boundaries and
/// return the list of successor instruction indices.
fn visit_insn(
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
        BpfInsn::Jeq { offset, .. } | BpfInsn::Jgt { offset, .. } => {
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
        // subprogram call — callee entry + return address
        BpfInsn::Call { imm } => {
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
/// - no back edges: every reachable path must terminate with EXIT
///
/// The stack holds (insn_idx, next_child) pairs so the DFS mimics recursion:
/// a node stays "Discovering" (gray) until all of its children are fully
/// explored, so an edge to a gray node is exactly a back edge (loop).
fn check_cfg(insns: &[BpfInsn], subprogs: &[u32]) -> Result<(), VerificationFailure> {
    let insn_cnt = insns.len();
    let mut state = vec![VisitState::NotVisited; insn_cnt];
    let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
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
                // this path can never terminate with EXIT
                VisitState::Discovering => {
                    return Err(VerificationFailure::new(
                        idx,
                        format!("back edge to insn {} creates an unbounded loop", nxt),
                    ));
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

    Ok(())
}

// ── BPF program ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct BpfProg {
    name: String,
    location: String,
    raw_data: Vec<u8>,
    insns: Vec<BpfInsn>,
    subprogs: Vec<u32>,
    insn_cnt: u32,
}

#[derive(Debug)]
struct VerificationFailure {
    insn_idx: u32,   // instruction index where verification failed
    message: String, // e.g. "unbounded loop", "invalid access"
}

impl VerificationFailure {
    fn new(insn_idx: u32, message: impl Into<String>) -> Self {
        Self {
            insn_idx,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "verification failed at insn {}: {}",
            self.insn_idx, self.message
        )
    }
}

enum Verdict {
    Safe,
    Unsafe(VerificationFailure),
}

#[derive(Default)]
struct BpfVerifierEnv {
    pub prog: BpfProg, // BPF program data
    #[allow(dead_code)] // consumed by state tracking (v0.2)
    pub insn_idx: u32, // current checking instruction
}

impl BpfVerifierEnv {
    fn new() -> Self {
        Self::default()
    }

    /// Load a BPF program from a binary file and return the instruction count.
    fn setup_prog(&mut self, name: String) -> Result<u32> {
        let raw_data =
            fs::read(&name).map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", name, e))?;

        if raw_data.len() % 8 != 0 {
            anyhow::bail!(
                "Invalid BPF program: size {} is not a multiple of 8",
                raw_data.len()
            );
        }

        if raw_data.is_empty() {
            anyhow::bail!("BPF program is empty");
        }

        let insn_cnt = (raw_data.len() / 8) as u32;

        let insns: Vec<BpfInsn> = raw_data.chunks_exact(8).map(parse_insn).collect();

        self.prog.name = name.clone();
        self.prog.location = name;
        self.prog.raw_data = raw_data;
        self.prog.insns = insns;
        self.prog.insn_cnt = insn_cnt;

        Ok(insn_cnt)
    }

    /// Run verification. A verification failure is not an error —
    /// it is returned as Ok(Verdict::Unsafe(...)).
    fn verify(&mut self) -> Result<Verdict> {
        let subprogs = match add_subprog(&self.prog.insns) {
            Ok(subprogs) => subprogs,
            Err(failure) => return Ok(Verdict::Unsafe(failure)),
        };
        self.prog.subprogs = subprogs;

        match check_cfg(&self.prog.insns, &self.prog.subprogs) {
            Ok(()) => Ok(Verdict::Safe),
            Err(failure) => Ok(Verdict::Unsafe(failure)),
        }
    }
}

fn main() -> Result<()> {
    let mut bpf_verifier_env = BpfVerifierEnv::new();
    let args: Vec<String> = env::args().collect();

    let name = match args.get(1) {
        Some(name) => name.clone(),
        None => {
            anyhow::bail!(
                "Usage: {} <program_name>",
                args.first().unwrap_or(&"rand-verifier".into())
            );
        }
    };

    bpf_verifier_env.setup_prog(name)?;

    match bpf_verifier_env.verify()? {
        Verdict::Safe => {
            println!("Verification passed");
            Ok(())
        }
        Verdict::Unsafe(failure) => {
            println!("{}", failure);
            Ok(())
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
