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
#[allow(dead_code)] // consumed by abstract execution engine (#13)
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

// ── Verifier state (v0.2 Micro) ──────────────────────────────────────────────

/// Abstract stack state.
///
/// Placeholder until #17 introduces the real abstract stack state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackState;

/// Unified verifier state carried through instruction simulation.
///
/// Holds the abstract state of all 11 registers plus the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // consumed by abstract execution engine (#13)
struct VerifierState {
    regs: [RegState; NUM_REGS],
    stack: StackState,
}

impl VerifierState {
    /// Initial state at program entry: R1 = PtrToCtx, R10 = PtrToStack(0),
    /// all other registers uninitialized.
    #[allow(dead_code)] // consumed by abstract execution engine (#13)
    fn initial() -> Self {
        Self {
            regs: initial_reg_state(),
            stack: StackState,
        }
    }
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
