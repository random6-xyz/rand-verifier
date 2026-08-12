// ── Abstract register and stack state (v0.2 Micro) ──────────────────────────

use crate::error::VerificationFailure;

/// Number of eBPF registers: R0..R10.
pub(crate) const NUM_REGS: usize = 11;

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
            }
        };
        bounds.synced()
    }

    /// Whether every bit of the value is known in both interpretations.
    pub(crate) fn is_constant(&self) -> bool {
        self.smin == self.smax && self.umin == self.umax
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
    #[allow(dead_code)] // used by tests; helper returns construct it inline
    pub(crate) fn unknown() -> Self {
        Self {
            smin: i64::MIN,
            smax: i64::MAX,
            umin: 0,
            umax: u64::MAX,
            s32_min: i32::MIN,
            s32_max: i32::MAX,
            u32_min: 0,
            u32_max: u32::MAX,
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
            self.s32_min = self.smin as i32;
            self.s32_max = self.smax as i32;
        } else {
            self.s32_min = i32::MIN;
            self.s32_max = i32::MAX;
        }
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
    PtrToStack {
        offset: i32,
    },
    PtrToCtx,
    /// A fixed map pointer (kernel's CONST_PTR_TO_MAP). Never
    /// constructed yet — program loading that injects it lands in Meso.
    #[allow(dead_code)] // constructed only by program loading (Meso)
    PtrToMap,
    PtrToMapValue,
    PtrToMapValueOrNull,
}

impl std::fmt::Display for RegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegState::Uninit => write!(f, "UNINIT"),
            RegState::Scalar(s) => write!(
                f,
                "SCALAR(s:{}..{},u:{:#x}..{:#x})",
                s.smin, s.smax, s.umin, s.umax
            ),
            RegState::PtrToStack { offset } => write!(f, "PTR_STACK({})", offset),
            RegState::PtrToCtx => write!(f, "PTR_CTX"),
            RegState::PtrToMap => write!(f, "PTR_MAP"),
            RegState::PtrToMapValue => write!(f, "PTR_MAP_VALUE"),
            RegState::PtrToMapValueOrNull => write!(f, "PTR_MAP_VALUE_OR_NULL"),
        }
    }
}

/// Initial register state at program entry, following the eBPF calling
/// convention: R1 receives the context pointer, R10 is the read-only stack
/// frame pointer, all other registers start uninitialized.
pub(crate) fn initial_reg_state() -> [RegState; NUM_REGS] {
    let mut regs = [RegState::Uninit; NUM_REGS];
    regs[1] = RegState::PtrToCtx;
    regs[10] = RegState::PtrToStack { offset: 0 };
    regs
}

// ── Stack state (v0.2 Micro) ─────────────────────────────────────────────────

/// BPF stack size in bytes, fixed by the eBPF spec.
pub(crate) const STACK_SIZE: usize = 512;

/// Size of one stack slot in bytes (8-byte access granularity).
pub(crate) const STACK_SLOT_SIZE: usize = 8;

/// Number of stack slots: 512 / 8 = 64.
pub(crate) const STACK_SLOTS: usize = STACK_SIZE / STACK_SLOT_SIZE;

/// Abstract state of a single stack slot.
///
/// Slot-level granularity (not byte-level) keeps the model approachable.
/// A slot holds the full spilled register state, so pointers and scalar
/// ranges survive a store/load round-trip (#30) — like the kernel's
/// STACK_SPILL slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackSlot {
    Uninit,
    Spilled(RegState),
}

impl std::fmt::Display for StackSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackSlot::Uninit => write!(f, "UNINIT"),
            StackSlot::Spilled(state) => write!(f, "SPILLED({})", state),
        }
    }
}

/// Abstract stack state: one slot per 8-byte cell of the 512-byte frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackState {
    pub(crate) slots: [StackSlot; STACK_SLOTS],
}

impl StackState {
    /// A fresh stack frame: every slot uninitialized.
    pub(crate) fn new() -> Self {
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
pub(crate) fn stack_slot_index(pc: u32, offset: i32) -> Result<usize, VerificationFailure> {
    // wrong direction: r10 + N, or the frame pointer itself (r10 + 0)
    if offset >= 0 {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "stack access at r10{:+} points away from the frame (valid: r10-512..r10-8)",
                offset
            ),
        ));
    }
    // beyond the frame
    if offset < -(STACK_SIZE as i32) {
        return Err(VerificationFailure::new(
            pc,
            format!(
                "stack access at r10{:+} exceeds the {} byte frame",
                offset, STACK_SIZE
            ),
        ));
    }
    // slot alignment
    if offset % (STACK_SLOT_SIZE as i32) != 0 {
        return Err(VerificationFailure::new(
            pc,
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
pub(crate) struct VerifierState {
    pub(crate) regs: [RegState; NUM_REGS],
    pub(crate) stack: StackState,
}

impl VerifierState {
    /// Initial state at program entry: R1 = PtrToCtx, R10 = PtrToStack(0),
    /// all other registers uninitialized, stack frame fully uninitialized.
    pub(crate) fn initial() -> Self {
        Self {
            regs: initial_reg_state(),
            stack: StackState::new(),
        }
    }
}

// ── Register access helpers ──────────────────────────────────────────────────

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
        | RegState::PtrToMap
        | RegState::PtrToMapValue
        | RegState::PtrToMapValueOrNull => Err(VerificationFailure::new(
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
        assert_eq!(regs[10], RegState::PtrToStack { offset: 0 });
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
            "SCALAR(s:0..100,u:0x0..0x64)"
        );
        assert_eq!(
            RegState::Scalar(ScalarBounds::constant(-1)).to_string(),
            "SCALAR(s:-1..-1,u:0xffffffffffffffff..0xffffffffffffffff)"
        );
        assert_eq!(
            RegState::PtrToStack { offset: -8 }.to_string(),
            "PTR_STACK(-8)"
        );
        assert_eq!(RegState::PtrToCtx.to_string(), "PTR_CTX");
        assert_eq!(RegState::PtrToMap.to_string(), "PTR_MAP");
        assert_eq!(RegState::PtrToMapValue.to_string(), "PTR_MAP_VALUE");
        assert_eq!(
            RegState::PtrToMapValueOrNull.to_string(),
            "PTR_MAP_VALUE_OR_NULL"
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
        assert_eq!(state.regs[10], RegState::PtrToStack { offset: 0 });
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
        }
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
        }
        .synced()
        .synced();
        assert_eq!(narrowed.signed(), (0, 100));
        assert_eq!(narrowed.unsigned(), (0, 100));
    }

    // ── StackState (v0.2) ────────────────────────────────────────────────────

    #[test]
    fn stack_state_new_all_uninit() {
        let stack = StackState::new();
        assert_eq!(stack.slots.len(), STACK_SLOTS);
        assert!(stack.slots.iter().all(|s| *s == StackSlot::Uninit));
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
        assert_eq!(StackSlot::Uninit.to_string(), "UNINIT");
        assert_eq!(
            StackSlot::Spilled(RegState::PtrToCtx).to_string(),
            "SPILLED(PTR_CTX)"
        );
    }

    #[test]
    fn stack_state_equality() {
        let a = StackState::new();
        let mut b = StackState::new();
        b.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(1)));
        assert_ne!(a, b);
    }

    // ── Stack load/store (v0.2) ──────────────────────────────────────────────

    #[test]
    fn st_stack_writes_scalar_slot() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let next = step(0, &state, &BpfInsn::StStack { src: 2, offset: -8 }).unwrap();
        // the full scalar range is spilled, not just an initialized marker
        assert_eq!(
            next.stack.slots[0],
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(10)))
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
            &BpfInsn::StStack {
                src: 2,
                offset: -512,
            },
        )
        .unwrap();
        assert_eq!(
            next.stack.slots[63],
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(10)))
        );
        assert_eq!(next.stack.slots[0], StackSlot::Uninit);
    }

    #[test]
    fn st_stack_rejects_uninit_src() {
        // storing r0 before it is written → #14 error
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::StStack { src: 0, offset: -8 }).unwrap_err();
        assert!(err.message.contains("uninitialized"));
    }

    #[test]
    fn st_stack_spills_pointer() {
        // pointers are now spilled with their full state (#30)
        let state = VerifierState::initial();
        let next = step(0, &state, &BpfInsn::StStack { src: 1, offset: -8 }).unwrap();
        assert_eq!(next.stack.slots[0], StackSlot::Spilled(RegState::PtrToCtx));
    }

    #[test]
    fn ld_stack_restores_pointer() {
        // spill r1 (PtrToCtx), then restore it into r5
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::StStack { src: 1, offset: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::LdStack { dst: 5, offset: -8 }).unwrap();
        assert_eq!(next.regs[5], RegState::PtrToCtx);
    }

    #[test]
    fn st_ld_stack_nullable_pointer_roundtrip() {
        // an OrNull pointer survives spill/fill — the NULL check is still
        // required after the fill
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::PtrToMapValueOrNull;
        let state = step(0, &state, &BpfInsn::StStack { src: 0, offset: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::LdStack { dst: 5, offset: -8 }).unwrap();
        assert_eq!(next.regs[5], RegState::PtrToMapValueOrNull);
    }

    #[test]
    fn ld_stack_after_store() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        let state = step(0, &state, &BpfInsn::StStack { src: 2, offset: -8 }).unwrap();
        let next = step(0, &state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap();
        // the spilled range is restored exactly (#30)
        assert_eq!(next.regs[0], RegState::Scalar(ScalarBounds::constant(10)));
    }

    #[test]
    fn ld_stack_before_store_rejected() {
        // issue example: load [r10 - 8] with no prior store → REJECT
        let state = VerifierState::initial();
        let err = step(0, &state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap_err();
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
            &BpfInsn::StStack {
                src: 2,
                offset: -16,
            },
        )
        .unwrap();
        let err = step(0, &state, &BpfInsn::LdStack { dst: 0, offset: -8 }).unwrap_err();
        assert!(err.message.contains("write before read"));
    }

    #[test]
    fn stack_invalid_offsets_rejected() {
        let state = VerifierState::initial();
        // wrong direction: r10 + N (positive) and the frame pointer itself (0)
        for offset in [8, 0] {
            let err = step(0, &state, &BpfInsn::LdStack { dst: 0, offset }).unwrap_err();
            assert!(err.message.contains("points away"), "offset {}", offset);
        }
        // beyond the 512-byte frame
        let err = step(
            0,
            &state,
            &BpfInsn::LdStack {
                dst: 0,
                offset: -520,
            },
        )
        .unwrap_err();
        assert!(err.message.contains("exceeds"));
        // not 8-byte aligned
        for offset in [-7, -4] {
            let err = step(0, &state, &BpfInsn::LdStack { dst: 0, offset }).unwrap_err();
            assert!(
                err.message.contains("not 8-byte aligned"),
                "offset {}",
                offset
            );
        }
        // a store with a wrong-direction offset is rejected too
        let err = step(0, &state, &BpfInsn::StStack { src: 1, offset: 8 }).unwrap_err();
        assert!(err.message.contains("points away"));
    }

    #[test]
    fn stack_bounds_frame_edges() {
        let state = VerifierState::initial();
        let state = step(0, &state, &BpfInsn::MovImm { dst: 2, imm: 10 }).unwrap();
        // both frame edges are valid
        for offset in [-8, -512] {
            let next = step(0, &state, &BpfInsn::StStack { src: 2, offset }).unwrap();
            let idx = stack_slot_index(0, offset as i32).unwrap();
            assert_eq!(
                next.stack.slots[idx],
                StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(10)))
            );
        }
        // one byte beyond each edge is rejected
        for offset in [-7, -513] {
            assert!(
                step(0, &state, &BpfInsn::StStack { src: 2, offset }).is_err(),
                "offset {}",
                offset
            );
        }
    }

    #[test]
    fn stack_slot_index_mapping() {
        assert_eq!(stack_slot_index(0, -8).unwrap(), 0);
        assert_eq!(stack_slot_index(0, -16).unwrap(), 1);
        assert_eq!(stack_slot_index(0, -512).unwrap(), 63);
    }

    // ── step (v0.2) ──────────────────────────────────────────────────────────

    #[test]
    fn read_reg_initialized_regs() {
        let state = VerifierState::initial();
        // R1 (PtrToCtx) and R10 (PtrToStack) are readable at entry
        assert_eq!(read_reg(0, &state, 1).unwrap(), RegState::PtrToCtx);
        assert_eq!(
            read_reg(0, &state, 10).unwrap(),
            RegState::PtrToStack { offset: 0 }
        );
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
}
