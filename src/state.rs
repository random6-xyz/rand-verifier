// ── Abstract register and stack state (v0.2 Micro) ──────────────────────────

use crate::error::VerificationFailure;
use crate::tnum::Tnum;

/// Number of eBPF registers: R0..R10.
pub(crate) const NUM_REGS: usize = 11;

/// Marker for an unknown pointer alignment (`align_off`).
pub(crate) const ALIGN_UNKNOWN: u8 = 0xFF;

/// The range bounds of a scalar register: the signed and the unsigned
/// interpretation tracked side by side (cf. the kernel's `smin`/`smax`
/// and `umin`/`umax` in `struct bpf_reg_state`, Meso #40).
///
/// Invariant: `smin <= smax` and `umin <= umax` — a scalar range is
/// never empty. Overflow handling (#43) falls back to the full range
/// instead of letting a range wrap into `min > max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScalarBounds {
    pub(crate) smin: i64,
    pub(crate) smax: i64,
    pub(crate) umin: u64,
    pub(crate) umax: u64,
    /// The 32-bit view (truncation) of the signed range: derived from
    /// `smin`/`smax` by the sync (#41). Exact when the range fits in one
    /// 32-bit window, the full 32-bit range otherwise.
    pub(crate) s32_min: i32,
    pub(crate) s32_max: i32,
    /// The 32-bit view of the unsigned range, derived the same way.
    pub(crate) u32_min: u32,
    pub(crate) u32_max: u32,
    /// The tracked number (kernel var_off, #42): bit-level precision on
    /// top of the ranges. Kept consistent with the ranges by the sync
    /// (the tnum is intersected with the range in `synced`).
    pub(crate) tnum: Tnum,
    /// Kernel scalar precision bit (#98): false by default; set only by
    /// precision backtracking on stored checkpoint states. Execution
    /// never sets it (the kernel: "don't set precise flag in current
    /// state, as precision tracking in the current state is
    /// unnecessary"). Never participates in value comparisons — the
    /// exactness levels ignore it (regs_exact in state_eq.rs), like the
    /// kernel's regs_exact()/states_maybe_looping() memcmp ranges.
    pub(crate) precise: bool,
    /// Kernel scalar linking id (#99): registers copied from the same
    /// source share an id, and a branch refinement of one is synced to
    /// the others (`sync_linked_regs`). 0 = not linked. `delta` is the
    /// constant offset of this register from the base of its link
    /// group (the kernel's BPF_ADD_CONST + delta). The idmap check in
    /// the state equality (state_eq.rs) requires id relationships to
    /// be preserved across pruning.
    pub(crate) id: u32,
    pub(crate) delta: i32,
}

impl ScalarBounds {
    /// A constant: both interpretations carry the same bits.
    pub(crate) const fn constant(value: i64) -> Self {
        Self {
            smin: value,
            smax: value,
            umin: value as u64,
            umax: value as u64,
            s32_min: value as i32,
            s32_max: value as i32,
            u32_min: value as u64 as u32,
            u32_max: value as u64 as u32,
            tnum: Tnum::constant(value as u64),
            precise: false,
            id: 0,
            delta: 0,
        }
    }

    /// Bounds for a range known in the signed interpretation. The
    /// unsigned range is derived when a single u64 interval exists
    /// (fully non-negative or fully negative — the bit range is the
    /// same in both interpretations), otherwise it is the full range —
    /// a sound over-approximation.
    #[allow(dead_code)] // used by tests and by #45 (pointer offsets)
    pub(crate) fn from_signed(min: i64, max: i64) -> Self {
        let bounds = if min < 0 && max >= 0 {
            // straddles zero: no single u64 interval exists
            Self {
                smin: min,
                smax: max,
                umin: 0,
                umax: u64::MAX,
                s32_min: i32::MIN,
                s32_max: i32::MAX,
                u32_min: 0,
                u32_max: u32::MAX,
                tnum: Tnum::unknown(),
                precise: false,
                id: 0,
                delta: 0,
            }
        } else {
            // both interpretations are the same bit range
            Self {
                smin: min,
                smax: max,
                umin: min as u64,
                umax: max as u64,
                s32_min: i32::MIN,
                s32_max: i32::MAX,
                u32_min: 0,
                u32_max: u32::MAX,
                tnum: Tnum::unknown(),
                precise: false,
                id: 0,
                delta: 0,
            }
        };
        bounds.synced()
    }

    /// Whether every bit of the value is known in both interpretations
    /// and the tnum agrees (consistent states satisfy this together).
    pub(crate) fn is_constant(&self) -> bool {
        self.smin == self.smax && self.umin == self.umax && self.tnum.is_constant()
    }

    /// The signed interval.
    pub(crate) fn signed(&self) -> (i64, i64) {
        (self.smin, self.smax)
    }

    /// The unsigned interval.
    pub(crate) fn unsigned(&self) -> (u64, u64) {
        (self.umin, self.umax)
    }

    /// The full range (a completely unknown value).
    pub(crate) const fn unknown() -> Self {
        Self {
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
            tnum: Tnum::unknown(),
            precise: false,
            id: 0,
            delta: 0,
        }
    }

    /// Whether the scalar is provably zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.smin == 0 && self.smax == 0 && self.umin == 0 && self.umax == 0
    }

    /// Kernel `reg_bounds_sync` / `__reg64_deduce_bounds` (simplified):
    /// when the signed interval does not cross zero, both interpretations
    /// are the same bit range and are combined; otherwise the unsigned
    /// range bounds the signed one where a single interval exists.
    /// Called after every ALU operation and branch refinement so the two
    /// interpretations stay consistent — this keeps branch pruning
    /// precise (#40).
    pub(crate) fn synced(mut self) -> Self {
        // an empty range (min > max) marks an infeasible branch: it must
        // never be healed into a non-empty state by the sync
        if self.smin > self.smax || self.umin > self.umax {
            return self;
        }
        if self.smin >= 0 || self.smax < 0 {
            // the signed interval does not cross zero: signed and
            // unsigned bounds are the same bit range — combine
            let lo = (self.smin as u64).max(self.umin);
            let hi = (self.smax as u64).min(self.umax);
            self.smin = lo as i64;
            self.smax = hi as i64;
            self.umin = lo;
            self.umax = hi;
        } else if self.umax < (1 << 63) {
            // the unsigned range is non-negative: it bounds smax
            self.smin = self.umin as i64;
            self.smax = self.smax.min(self.umax as i64);
        } else if self.umin >= (1 << 63) {
            // the unsigned range is negative: it bounds smin
            self.smin = self.smin.max(self.umin as i64);
            self.smax = self.umax as i64;
        }
        // derive the 32-bit ranges from the 64-bit ones (kernel
        // __update_reg32_bounds, simplified): exact when the range fits
        // in one 32-bit window, the full 32-bit range otherwise
        if self.umin >> 32 == self.umax >> 32 {
            self.u32_min = self.umin as u32;
            self.u32_max = self.umax as u32;
        } else {
            self.u32_min = 0;
            self.u32_max = u32::MAX;
        }
        if (self.smin as u64) >> 32 == (self.smax as u64) >> 32 {
            let lo = self.smin as i32;
            let hi = self.smax as i32;
            // the truncation can still cross the 32-bit sign bit within
            // the window (e.g. [0, 0xffffffff]): then the i32 view is two
            // intervals and widens to the full range
            if lo <= hi {
                self.s32_min = lo;
                self.s32_max = hi;
            } else {
                self.s32_min = i32::MIN;
                self.s32_max = i32::MAX;
            }
        } else {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        }
        // intersect the tnum with the range (kernel __reg_bound_offset):
        // a narrowed range pins down bits the tnum still had unknown
        self.tnum = self.tnum.intersect(Tnum::from_range(self.umin, self.umax));
        self
    }
}

/// Abstract state of a single register during symbolic execution.
///
/// Instead of tracking concrete u64 values, the verifier tracks an abstract
/// value per register (cf. kernel verifier docs):
///
/// - `Uninit` — the register has never been written
/// - `Scalar` — a scalar with signed and unsigned ranges ([#40])
/// - `PtrToStack` — pointer into the stack frame, offset relative to R10
/// - `PtrToCtx` — pointer to the program context
/// - `PtrToMap` — a fixed map pointer (kernel's CONST_PTR_TO_MAP)
/// - `PtrToMapValue` — pointer to a map value (non-null)
/// - `PtrToMapValueOrNull` — nullable map value pointer; must pass a
///   NULL check before use (#27)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegState {
    Uninit,
    Scalar(ScalarBounds),
    /// A pointer into the stack frame, offset relative to R10. The
    /// offset may be a range (computed pointer arithmetic, #45); the
    /// alignment tracks the known offset modulo 8.
    PtrToStack {
        min_offset: i32,
        max_offset: i32,
        /// Known offset modulo 8 (0..=7); [`ALIGN_UNKNOWN`] when the low
        /// three bits of the offset are not determined.
        align_off: u8,
    },
    PtrToCtx,
    /// A fixed map pointer (kernel's CONST_PTR_TO_MAP) carrying the
    /// map metadata resolved at load time (#89).
    PtrToMap {
        key_size: u32,
        value_size: u32,
    },
    /// A pointer into a map value (non-null) — an offset interval
    /// within the value; bounds are validated at access time against
    /// `value_size` (#89, kernel check_map_access). `id` is the lookup
    /// identity (#99): registers derived from the same lookup share it,
    /// so a NULL check on one refines all aliases (kernel
    /// mark_ptr_or_null_regs).
    PtrToMapValue {
        min_offset: i32,
        max_offset: i32,
        /// Known offset modulo 8 ([`ALIGN_UNKNOWN`] when not determined).
        align_off: u8,
        value_size: u32,
        id: u32,
    },
    /// Nullable map value pointer; must pass a NULL check before use
    /// (#27). Carries the map's value size for the refinement (#89)
    /// and the lookup identity (`id`, #99).
    PtrToMapValueOrNull {
        value_size: u32,
        id: u32,
    },
    /// A referenced memory buffer returned by an acquire helper
    /// (kernel PTR_TO_MEM, #101): the ringbuf reserve family. `id` is
    /// the reference identity; every register and spilled slot holding
    /// the same id must be released before the exit (kernel
    /// check_reference_leak).
    PtrToMem {
        min_offset: i32,
        max_offset: i32,
        /// Known offset modulo 8 ([`ALIGN_UNKNOWN`] when not determined).
        align_off: u8,
        id: u32,
    },
    /// The nullable acquire result (kernel PTR_TO_MEM_OR_NULL): a
    /// NULL check both refines the pointer and releases the reference
    /// on the null side (kernel mark_ptr_or_null_regs).
    PtrToMemOrNull {
        id: u32,
    },
}

/// Maximum simultaneously held references (kernel: bounded by the
/// registers and stack slots).
pub(crate) const MAX_REFS: usize = 8;

impl std::fmt::Display for RegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegState::Uninit => write!(f, "UNINIT"),
            RegState::Scalar(s) => write!(
                f,
                "SCALAR(s:{}..{},u:{:#x}..{:#x},t:{:#x}/{:#x})",
                s.smin, s.smax, s.umin, s.umax, s.tnum.value, s.tnum.mask
            ),
            RegState::PtrToStack {
                min_offset,
                max_offset,
                ..
            } => {
                if min_offset == max_offset {
                    write!(f, "PTR_STACK({})", min_offset)
                } else {
                    write!(f, "PTR_STACK({}..{})", min_offset, max_offset)
                }
            }
            RegState::PtrToCtx => write!(f, "PTR_CTX"),
            RegState::PtrToMap {
                key_size,
                value_size,
            } => write!(f, "PTR_MAP(k:{},v:{})", key_size, value_size),
            RegState::PtrToMapValue {
                min_offset,
                max_offset,
                value_size,
                ..
            } => {
                if min_offset == max_offset {
                    write!(f, "PTR_MAP_VALUE({},sz:{})", min_offset, value_size)
                } else {
                    write!(
                        f,
                        "PTR_MAP_VALUE({}..{},sz:{})",
                        min_offset, max_offset, value_size
                    )
                }
            }
            RegState::PtrToMapValueOrNull { value_size, .. } => {
                write!(f, "PTR_MAP_VALUE_OR_NULL(sz:{})", value_size)
            }
            RegState::PtrToMem {
                min_offset,
                max_offset,
                id,
                ..
            } => write!(
                f,
                "PTR_TO_MEM(off:{}..{}, ref:{})",
                min_offset, max_offset, id
            ),
            RegState::PtrToMemOrNull { id } => write!(f, "PTR_TO_MEM_OR_NULL(ref:{})", id),
        }
    }
}

/// Initial register state at program entry, following the eBPF calling
/// convention: R1 receives the context pointer, R10 is the read-only stack
/// frame pointer, all other registers start uninitialized.
pub(crate) fn initial_reg_state() -> [RegState; NUM_REGS] {
    let mut regs = [RegState::Uninit; NUM_REGS];
    regs[1] = RegState::PtrToCtx;
    regs[10] = RegState::PtrToStack {
        min_offset: 0,
        max_offset: 0,
        align_off: 0,
    };
    regs
}

// ── Stack state (v0.2 Micro) ─────────────────────────────────────────────────

/// BPF stack size in bytes, fixed by the eBPF spec.
pub(crate) const STACK_SIZE: usize = 512;

/// Size of one stack slot in bytes (8-byte access granularity).
pub(crate) const STACK_SLOT_SIZE: usize = 8;

/// Number of stack slots: 512 / 8 = 64.
pub(crate) const STACK_SLOTS: usize = STACK_SIZE / STACK_SLOT_SIZE;

/// Per-byte stack slot type (kernel `STACK_INVALID` / `STACK_MISC` /
/// `STACK_ZERO` / `STACK_SPILL`, #100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackByte {
    /// Never written (or dead-cleaned).
    Invalid,
    /// Written with an unknown value (variable-offset or partial
    /// writes; loads yield an unknown scalar).
    Misc,
    /// Known zero (kernel STACK_ZERO; loads yield the scalar 0).
    Zero,
    /// Part of a full 8-byte register spill (the register lives in
    /// `StackState::spilled`).
    Spill,
}

impl std::fmt::Display for StackByte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackByte::Invalid => write!(f, "INVALID"),
            StackByte::Misc => write!(f, "MISC"),
            StackByte::Zero => write!(f, "ZERO"),
            StackByte::Spill => write!(f, "SPILL"),
        }
    }
}

/// Abstract stack state: per-byte slot types plus the spilled register
/// of each 8-byte cell (valid while the cell's eight bytes are all
/// `Spill`), mirroring the kernel's `slot_type[BPF_REG_SIZE]` +
/// `spilled_ptr` per stack slot (#100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackState {
    pub(crate) bytes: [StackByte; STACK_SIZE],
    pub(crate) spilled: [Option<RegState>; STACK_SLOTS],
}

impl StackState {
    /// A fresh stack frame: every byte invalid, no spills.
    pub(crate) fn new() -> Self {
        Self {
            bytes: [StackByte::Invalid; STACK_SIZE],
            spilled: [None; STACK_SLOTS],
        }
    }
}

// ── Verifier state (v0.2 Micro) ──────────────────────────────────────────────

/// Maximum number of active verifier frames (kernel MAX_CALL_FRAMES).
pub(crate) const MAX_CALL_FRAMES: usize = 16;

/// The abstract state of one verifier frame (the kernel's
/// `bpf_func_state`, #100): registers plus stack. `ret_pc` is this
/// frame's return address — where the execution continues when THIS
/// frame returns (the kernel's per-frame `callsite` + 1); each frame
/// carries its own, so nested calls return correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameState {
    pub(crate) regs: [RegState; NUM_REGS],
    pub(crate) stack: StackState,
    pub(crate) ret_pc: u32,
}

impl FrameState {
    /// A fresh frame: R10 = the frame pointer, everything else
    /// uninitialized (the kernel's `init_func_state`).
    pub(crate) fn new() -> Self {
        Self {
            regs: initial_reg_state(),
            stack: StackState::new(),
            ret_pc: 0,
        }
    }
}

/// Unified verifier state carried through instruction simulation.
///
/// `regs`/`stack` are the CURRENT (deepest) frame — the kernel's
/// `frame[curframe]` — so every existing access site keeps meaning
/// "the executing frame". `saved` holds the caller frames of
/// BPF-to-BPF calls (#100): `saved[i]` is the frame at depth `i`
/// (Some while a call is active below it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifierState {
    pub(crate) regs: [RegState; NUM_REGS],
    pub(crate) stack: StackState,
    /// The caller frames of active BPF-to-BPF calls (#100).
    pub(crate) saved: [Option<FrameState>; MAX_CALL_FRAMES - 1],
    /// The current frame's depth (0 = the main program; the kernel's
    /// `curframe`).
    pub(crate) curframe: u8,
    /// The current frame's return address (#100).
    pub(crate) ret_pc: u32,
    /// Acquired reference ids (kernel `acquired_refs` + `refs[]`,
    /// #101): every id must be released before the exit.
    pub(crate) refs: [u32; MAX_REFS],
    pub(crate) refs_cnt: u8,
}

impl VerifierState {
    /// Initial state at program entry: R1 = PtrToCtx, R10 = PtrToStack(0),
    /// all other registers uninitialized, stack frame fully uninitialized.
    pub(crate) fn initial() -> Self {
        Self {
            regs: initial_reg_state(),
            stack: StackState::new(),
            saved: [None; MAX_CALL_FRAMES - 1],
            curframe: 0,
            ret_pc: 0,
            refs: [0; MAX_REFS],
            refs_cnt: 0,
        }
    }

    /// Enter a subprogram call (#100): save the current frame and set
    /// up a fresh callee frame with R1..R5 as the arguments (the
    /// kernel's `__check_func_call`). The callee-saved registers
    /// R6..R9 of the caller survive via the saved frame.
    pub(crate) fn call_subprog(&mut self, return_pc: u32) -> Result<(), &'static str> {
        if self.curframe as usize >= MAX_CALL_FRAMES - 1 {
            return Err("the call stack of 16 frames is too deep");
        }
        self.saved[self.curframe as usize] = Some(FrameState {
            regs: self.regs,
            stack: self.stack,
            ret_pc: self.ret_pc,
        });
        let args: [RegState; 5] = self.regs[1..=5].try_into().unwrap();
        self.curframe += 1;
        let mut callee = FrameState::new();
        callee.regs[1..=5].copy_from_slice(&args);
        self.regs = callee.regs;
        self.stack = callee.stack;
        self.ret_pc = return_pc;
        Ok(())
    }

    /// Return from a subprogram call (#100): restore the caller frame
    /// with the callee's R0 as the return value (the kernel's
    /// `check_func_call` return handling). The caller's argument
    /// registers R1..R5 are clobbered by the call, like helper calls.
    pub(crate) fn return_from_subprog(&mut self) -> Option<()> {
        if self.curframe == 0 {
            return None;
        }
        let ret = self.regs[0];
        self.curframe -= 1;
        let caller = self.saved[self.curframe as usize].take()?;
        self.ret_pc = caller.ret_pc;
        self.regs = caller.regs;
        self.stack = caller.stack;
        self.regs[0] = ret;
        for r in 1..=5 {
            self.regs[r] = RegState::Uninit;
        }
        Some(())
    }
}

// ── Register access helpers ──────────────────────────────────────────────────

/// Extract the scalar bounds of a register; panics for non-scalars.
#[cfg(test)]
pub(crate) fn as_scalar(state: RegState) -> ScalarBounds {
    match state {
        RegState::Scalar(b) => b,
        _ => panic!("expected a scalar register"),
    }
}

/// Validate a register number used as a write destination.
pub(crate) fn check_reg(pc: u32, reg: u8) -> Result<(), VerificationFailure> {
    if reg as usize >= NUM_REGS {
        Err(VerificationFailure::new(
            pc,
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
pub(crate) fn read_reg(
    pc: u32,
    state: &VerifierState,
    reg: u8,
) -> Result<RegState, VerificationFailure> {
    check_reg(pc, reg)?;
    match state.regs[reg as usize] {
        RegState::Uninit => Err(VerificationFailure::new(
            pc,
            format!("register r{} is uninitialized", reg),
        )),
        other => Ok(other),
    }
}

/// Read a register as a scalar value.
///
/// ALU operations only accept scalars: uninitialized registers are
/// rejected by `read_reg` (#14), and pointers are rejected because
/// register-offset pointer arithmetic is not supported yet (only
/// pointer + immediate is allowed, #20).
pub(crate) fn read_scalar(
    pc: u32,
    state: &VerifierState,
    reg: u8,
) -> Result<ScalarBounds, VerificationFailure> {
    match read_reg(pc, state, reg)? {
        RegState::Scalar(bounds) => Ok(bounds),
        RegState::PtrToStack { .. }
        | RegState::PtrToCtx
        | RegState::PtrToMap { .. }
        | RegState::PtrToMapValue { .. }
        | RegState::PtrToMapValueOrNull { .. }
        | RegState::PtrToMem { .. }
        | RegState::PtrToMemOrNull { .. } => Err(VerificationFailure::new(
            pc,
            format!(
                "register-offset pointer arithmetic on r{} is not supported yet (only immediate offsets)",
                reg
            ),
        )),
        RegState::Uninit => unreachable!("read_reg rejects uninitialized registers"),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::step;
    use crate::insn::BpfInsn;
    use crate::testutil::*;

    #[test]
    fn reg_state_initial_state() {
        let regs = initial_reg_state();
        assert_eq!(regs.len(), 11);

        // R0 = Uninit
        assert_eq!(regs[0], RegState::Uninit);

        // R1 = PtrToCtx
        assert_eq!(regs[1], RegState::PtrToCtx);

        // R2..R9 = Uninit
        for reg in &regs[2..=9] {
            assert_eq!(*reg, RegState::Uninit);
        }

        // R10 = PtrToStack(0)
        assert_eq!(regs[10], ptr_stack(0));
    }

    #[test]
    fn reg_state_scalar_equality() {
        let c = RegState::Scalar(ScalarBounds::constant(10));
        assert_eq!(c, RegState::Scalar(ScalarBounds::constant(10)));
        assert_ne!(c, RegState::Scalar(ScalarBounds::from_signed(10, 11)));
        assert_ne!(c, RegState::Uninit);
    }

    #[test]
    fn reg_state_display() {
        assert_eq!(RegState::Uninit.to_string(), "UNINIT");
        assert_eq!(
            RegState::Scalar(ScalarBounds::from_signed(0, 100)).to_string(),
            "SCALAR(s:0..100,u:0x0..0x64,t:0x0/0x7f)"
        );
        assert_eq!(
            RegState::Scalar(ScalarBounds::constant(-1)).to_string(),
            "SCALAR(s:-1..-1,u:0xffffffffffffffff..0xffffffffffffffff,t:0xffffffffffffffff/0x0)"
        );
        assert_eq!(ptr_stack(-8).to_string(), "PTR_STACK(-8)");
        assert_eq!(RegState::PtrToCtx.to_string(), "PTR_CTX");
        assert_eq!(
            RegState::PtrToMap {
                key_size: 4,
                value_size: 8,
            }
            .to_string(),
            "PTR_MAP(k:4,v:8)"
        );
        assert_eq!(
            RegState::PtrToMapValue {
                min_offset: 0,
                max_offset: 0,
                align_off: 0,
                value_size: 8,
                id: 0,
            }
            .to_string(),
            "PTR_MAP_VALUE(0,sz:8)"
        );
        assert_eq!(
            RegState::PtrToMapValueOrNull {
                value_size: 8,
                id: 0
            }
            .to_string(),
            "PTR_MAP_VALUE_OR_NULL(sz:8)"
        );
    }

    // ── Tnum (v0.3) ─────────────────────────────────────────────────────────

    #[test]
    fn verifier_state_initial() {
        let state = VerifierState::initial();

        // registers match the #11 initial state
        assert_eq!(state.regs, initial_reg_state());

        // the stack frame starts with every slot uninitialized (#17)
        assert_eq!(state.stack, StackState::new());
    }

    #[test]
    fn verifier_state_initial_matches_issue_spec() {
        let state = VerifierState::initial();

        // R0 = Uninit
        assert_eq!(state.regs[0], RegState::Uninit);

        // R1 = PtrToCtx
        assert_eq!(state.regs[1], RegState::PtrToCtx);

        // R2..R9 = Uninit
        for reg in &state.regs[2..=9] {
            assert_eq!(*reg, RegState::Uninit);
        }

        // R10 = PtrToStack(0)
        assert_eq!(state.regs[10], ptr_stack(0));
    }

    // ── ScalarBounds (Meso #40) ──────────────────────────────────────────────

    #[test]
    fn scalar_bounds_constant_both_interpretations() {
        // -1 is -1 signed and u64::MAX unsigned
        let c = ScalarBounds::constant(-1);
        assert_eq!(c.signed(), (-1, -1));
        assert_eq!(c.unsigned(), (u64::MAX, u64::MAX));
        assert!(c.is_constant());
        assert!(!ScalarBounds::unknown().is_constant());
        assert!(ScalarBounds::constant(0).is_zero());
        assert!(!c.is_zero());
    }

    #[test]
    fn scalar_bounds_from_signed_derives_unsigned() {
        // fully non-negative: the unsigned range matches
        assert_eq!(ScalarBounds::from_signed(0, 100).unsigned(), (0, 100));
        // fully negative: the unsigned range is the u64 view
        assert_eq!(
            ScalarBounds::from_signed(-10, -1).unsigned(),
            (u64::MAX - 9, u64::MAX)
        );
        // straddling zero: no single u64 interval → full range
        assert_eq!(ScalarBounds::from_signed(-10, 10).unsigned(), (0, u64::MAX));
    }

    #[test]
    fn scalar_bounds_sync_issue_example() {
        // the issue example: 0xffffffffffffffff is -1 signed and u64::MAX
        // unsigned, and both interpretations survive refinement correctly
        let r1 = ScalarBounds::constant(-1).synced();
        assert_eq!(r1.signed(), (-1, -1));
        assert_eq!(r1.unsigned(), (u64::MAX, u64::MAX));
        // a signed refinement narrows smax; the combine rule propagates it
        // to umax (both interpretations are the same bit range)
        let narrowed = ScalarBounds {
            smin: i64::MIN,
            smax: -5,
            umin: 0,
            umax: u64::MAX,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
            tnum: Tnum::unknown(),
            precise: false,
            id: 0,
            delta: 0,
        }
        .synced()
        .synced()
        .synced();
        assert_eq!(narrowed.signed(), (i64::MIN, -5));
        assert_eq!(narrowed.unsigned(), (1 << 63, u64::MAX - 4));
        // an unsigned refinement narrows umax; the sync propagates it to smax
        let narrowed = ScalarBounds {
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: 100,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
            tnum: Tnum::unknown(),
            precise: false,
            id: 0,
            delta: 0,
        }
        .synced()
        .synced()
        .synced();
        assert_eq!(narrowed.signed(), (0, 100));
        assert_eq!(narrowed.unsigned(), (0, 100));
    }

    // ── StackState (v0.2) ────────────────────────────────────────────────────

    #[test]
    fn stack_state_new_all_uninit() {
        let stack = StackState::new();
        assert_eq!(stack.bytes.len(), STACK_SIZE);
        assert!(stack.bytes.iter().all(|s| *s == StackByte::Invalid));
        assert!(stack.spilled.iter().all(|s| s.is_none()));
    }

    #[test]
    fn stack_slot_constants() {
        // the 512-byte frame split into 8-byte slots → 64 slots
        assert_eq!(STACK_SIZE, 512);
        assert_eq!(STACK_SLOT_SIZE, 8);
        assert_eq!(STACK_SLOTS, 64);
    }

    #[test]
    fn stack_slot_display() {
        assert_eq!(StackByte::Invalid.to_string(), "INVALID");
        assert_eq!(StackByte::Misc.to_string(), "MISC");
        assert_eq!(StackByte::Zero.to_string(), "ZERO");
        assert_eq!(StackByte::Spill.to_string(), "SPILL");
    }

    #[test]
    fn stack_state_equality() {
        let a = StackState::new();
        let mut b = StackState::new();
        b.bytes[0] = StackByte::Spill;
        b.spilled[0] = Some(RegState::Scalar(ScalarBounds::constant(1)));
        assert_ne!(a, b);
    }

    // ── Stack load/store (v0.2) ──────────────────────────────────────────────

    #[test]
    fn st_stack_writes_scalar_slot() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        // the full scalar range is spilled, not just an initialized marker
        assert_eq!(next.stack.bytes[0], StackByte::Spill);
        assert_eq!(
            next.stack.spilled[0],
            Some(RegState::Scalar(ScalarBounds::constant(10)))
        );
        // the source register is unchanged
        assert_eq!(next.regs[2], RegState::Scalar(ScalarBounds::constant(10)));
    }

    #[test]
    fn st_stack_offsets_map_to_slots() {
        // -8 → slot 0, -16 → slot 1, -512 → slot 63
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -512,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        assert_eq!(next.stack.bytes[63 * 8], StackByte::Spill);
        assert_eq!(
            next.stack.spilled[63],
            Some(RegState::Scalar(ScalarBounds::constant(10)))
        );
        assert_eq!(next.stack.bytes[0], StackByte::Invalid);
    }

    #[test]
    fn st_stack_rejects_uninit_src() {
        // storing r0 before it is written → #14 error
        let state = VerifierState::initial();
        let err = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn st_stack_spills_pointer() {
        // pointers are now spilled with their full state (#30)
        let state = VerifierState::initial();
        let next = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        assert_eq!(next.stack.bytes[0], StackByte::Spill);
        assert_eq!(next.stack.spilled[0], Some(RegState::PtrToCtx));
    }

    #[test]
    fn ld_stack_restores_pointer() {
        // spill r1 (PtrToCtx), then restore it into r5
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 5,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[5], RegState::PtrToCtx);
    }

    #[test]
    fn st_ld_stack_nullable_pointer_roundtrip() {
        // an OrNull pointer survives spill/fill — the NULL check is still
        // required after the fill
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull {
            value_size: 8,
            id: 0,
        };
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 5,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(
            next.regs[5],
            RegState::PtrToMapValueOrNull {
                value_size: 8,
                id: 0
            }
        );
    }

    #[test]
    fn ld_stack_after_store() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap();
        // the spilled range is restored exactly (#30)
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(10)));
    }

    #[test]
    fn ld_stack_before_store_rejected() {
        // issue example: load [r10 - 8] with no prior store → REJECT
        let state = VerifierState::initial();
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("uninitialized"));
        assert!(err.message.contains("write before read"));
    }

    #[test]
    fn ld_stack_slot_granularity() {
        // a store at -16 does not make -8 readable (slot-level granularity)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -16,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("write before read"));
    }

    #[test]
    fn stack_invalid_offsets_rejected() {
        let state = VerifierState::initial();
        // wrong direction: r10 + N (positive) and the frame pointer itself (0)
        for offset in [8, 0] {
            let err = step(
                0,
                &state,
                &BpfInsn::LdMem {
                    dst: 0,
                    base: 10,
                    offset,
                    size: crate::insn::MemSize::DW,
                    sign_extend: false,
                },
            )
            .unwrap_err();
            assert!(err.message.contains("points away"), "offset {}", offset);
        }
        // beyond the 512-byte frame
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 0,
                base: 10,
                offset: -520,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("exceeds"));
        // not 8-byte aligned
        for offset in [-7, -4] {
            let err = step(
                0,
                &state,
                &BpfInsn::LdMem {
                    dst: 0,
                    base: 10,
                    offset,
                    size: crate::insn::MemSize::DW,
                    sign_extend: false,
                },
            )
            .unwrap_err();
            assert!(
                err.message.contains("not 8-byte aligned"),
                "offset {}",
                offset
            );
        }
        // a store with a wrong-direction offset is rejected too
        let err = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: 8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("points away"));
    }

    #[test]
    fn stack_bounds_frame_edges() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        // both frame edges are valid
        for offset in [-8, -512] {
            let next = step(
                0,
                &state,
                &BpfInsn::StMem {
                    src: 2,
                    base: 10,
                    offset,
                    size: crate::insn::MemSize::DW,
                },
            )
            .unwrap();
            let idx = ((-offset) as usize - 8) / 8;
            assert_eq!(next.stack.bytes[idx * 8], StackByte::Spill);
            assert_eq!(
                next.stack.spilled[idx],
                Some(RegState::Scalar(ScalarBounds::constant(10)))
            );
        }
        // one byte beyond each edge is rejected
        for offset in [-7, -513] {
            assert!(
                step(
                    0,
                    &state,
                    &BpfInsn::StMem {
                        src: 2,
                        base: 10,
                        offset,
                        size: crate::insn::MemSize::DW,
                    }
                )
                .is_err(),
                "offset {}",
                offset
            );
        }
    }

    // ── step (v0.2) ──────────────────────────────────────────────────────────

    #[test]
    fn read_reg_initialized_regs() {
        let state = VerifierState::initial();
        // R1 (PtrToCtx) and R10 (PtrToStack) are readable at entry
        assert_eq!(read_reg(0, &state, 1).unwrap(), RegState::PtrToCtx);
        assert_eq!(read_reg(0, &state, 10).unwrap(), ptr_stack(0));
    }

    #[test]
    fn read_reg_uninit_rejected() {
        let state = VerifierState::initial();
        let err = read_reg(0, &state, 2).unwrap_err();
        assert!(err.message.contains("register r2 is uninitialized"));
    }

    #[test]
    fn read_reg_out_of_range_rejected() {
        let state = VerifierState::initial();
        let err = read_reg(0, &state, 11).unwrap_err();
        assert!(err.message.contains("invalid register r11"));
    }

    // ── ALU (v0.2) ───────────────────────────────────────────────────────────
    // ── Partial-width stack accesses (#100) ─────────────────────────────

    #[test]
    fn st_w_stack_partial_write() {
        // a 4-byte store at r10-4 is 4-aligned: the covered bytes
        // become MISC, the slot has no spill
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -4,
                size: crate::insn::MemSize::W,
            },
        )
        .unwrap();
        // the covered bytes [0..4) of the slot at r10-4
        assert_eq!(next.stack.bytes[0], StackByte::Misc);
        assert_eq!(next.stack.bytes[3], StackByte::Misc);
        assert_eq!(next.stack.bytes[4], StackByte::Invalid);
        assert!(next.stack.spilled[0].is_none());
    }

    #[test]
    fn ld_w_partial_read_unknown() {
        // a 4-byte read over the MISC bytes yields an unknown scalar
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -4,
                size: crate::insn::MemSize::W,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -4,
                size: crate::insn::MemSize::W,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn st_w_aligned_lsb_spill_and_narrow_fill() {
        // a 4-byte store at r10-8 is 8-aligned: a 4-byte spill anchored
        // at the slot's LSB (kernel save_register_state); a 4-byte
        // load at r10-8 truncates the spilled scalar
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::W,
            },
        )
        .unwrap();
        assert_eq!(state.stack.bytes[4], StackByte::Spill);
        assert_eq!(state.stack.bytes[7], StackByte::Spill);
        assert_eq!(state.stack.bytes[3], StackByte::Misc);
        assert_eq!(
            state.stack.spilled[0],
            Some(RegState::Scalar(ScalarBounds::constant(10)))
        );
        // the narrow fill at r10-8 restores the truncated constant
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::W,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::constant(10)));
    }

    #[test]
    fn ld_w_over_spill_middle_unknown() {
        // a 4-byte load at r10-4 of a full 8-byte spill is not LSB
        // anchored: the byte walk yields an unknown scalar (the
        // kernel's bpf_stack_narrow_access_ok requires the 8-byte
        // alignment)
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -4,
                size: crate::insn::MemSize::W,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn st_imm_dw_zero_marks_zero() {
        // BPF_ST of the immediate 0 at the aligned DW: the kernel
        // spills the const (save_register_state with the fake reg) —
        // the bytes are SPILL and the spilled scalar is the constant 0
        let state = VerifierState::initial();
        let next = step(
            0,
            &state,
            &BpfInsn::StMemImm {
                imm: 0,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        assert_eq!(next.stack.bytes[0], StackByte::Spill);
        assert_eq!(
            next.stack.spilled[0],
            Some(RegState::Scalar(ScalarBounds::constant(0)))
        );
        // a load returns the constant
        let next = step(
            0,
            &next,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::constant(0)));
    }

    #[test]
    fn st_imm_h_partial_unaligned_rejected() {
        // a 2-byte store at r10-6 is 2-aligned but not 8-aligned: the
        // kernel's else branch writes MISC bytes — the load yields an
        // unknown scalar
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::StMemImm {
                imm: 7,
                base: 10,
                offset: -6,
                size: crate::insn::MemSize::H,
            },
        )
        .unwrap();
        // the covered bytes [4..=5] of the frame (r10-6 and r10-5)
        assert_eq!(state.stack.bytes[4], StackByte::Misc);
        assert_eq!(state.stack.bytes[5], StackByte::Misc);
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -6,
                size: crate::insn::MemSize::H,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::unknown()));
    }

    #[test]
    fn partial_write_over_spilled_pointer_rejected() {
        // the kernel: "attempt to corrupt spilled pointer on stack" —
        // a partial write over a slot holding a spilled pointer
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let err = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -4,
                size: crate::insn::MemSize::W,
            },
        )
        .unwrap_err();
        assert!(
            err.message.contains("corrupt spilled pointer"),
            "{}",
            err.message
        );
    }

    #[test]
    fn sign_extending_loads() {
        // LDX|MEMSX: a byte load sign-extends the spilled constant
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 0x80 }).unwrap();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 2,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        // 0x80 = -128 as i8 → sign-extended to -128
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::B,
                sign_extend: true,
            },
        )
        .unwrap();
        assert_eq!(next.regs[3], RegState::Scalar(ScalarBounds::constant(-128)));
        // the zero-extending byte load yields 0x80
        let next = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 4,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::B,
                sign_extend: false,
            },
        )
        .unwrap();
        assert_eq!(next.regs[4], RegState::Scalar(ScalarBounds::constant(0x80)));
    }

    #[test]
    fn narrow_fill_of_pointer_rejected() {
        // the kernel: "invalid size of register fill" — a narrow load
        // of a spilled pointer
        let state = VerifierState::initial();
        let state = step(
            0,
            &state,
            &BpfInsn::StMem {
                src: 1,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::DW,
            },
        )
        .unwrap();
        let err = step(
            0,
            &state,
            &BpfInsn::LdMem {
                dst: 3,
                base: 10,
                offset: -8,
                size: crate::insn::MemSize::W,
                sign_extend: false,
            },
        )
        .unwrap_err();
        assert!(
            err.message.contains("invalid size of register fill"),
            "{}",
            err.message
        );
    }
}
