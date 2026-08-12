// ── Concrete execution state model (v0.5 Concrete, #49) ─────────────────────

//! Concrete counterpart of the abstract [`VerifierState`]: the same program
//! executed with real `u64` values, so the abstract state can be checked to
//! always cover the concrete results (Phase 2).
//!
//! The containment test mirrors [`crate::mini::reg_subsumes`] (abstract ⊇
//! abstract) with the direction reversed: does the abstract state contain
//! this actual value?

use crate::state::{ALIGN_UNKNOWN, NUM_REGS, RegState, STACK_SLOTS, StackSlot, VerifierState};
use crate::tnum::Tnum;

/// Fixed virtual address of the stack frame base (R10), arbitrary but
/// disjoint from every other address class. The 512-byte frame spans
/// `STACK_BASE - 512 .. STACK_BASE`.
pub(crate) const STACK_BASE: u64 = 0x1000;

/// Fixed virtual address of the program context (R1 at entry).
pub(crate) const CTX_BASE: u64 = 0x2000;

/// Concrete register/stack state: `None` = uninitialized, mirroring the
/// abstract `RegState::Uninit` / `StackSlot::Uninit` slots 1:1.
///
/// `Option<u64>` keeps the correspondence exact: a concrete value where
/// the abstract side is uninitialized is an immediate coverage violation
/// (#52), so no value is ever invented for an uninitialized register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConcreteState {
    pub(crate) regs: [Option<u64>; NUM_REGS],
    /// One slot per 8-byte cell of the 512-byte frame, like the abstract
    /// `StackState`.
    pub(crate) stack: [Option<u64>; STACK_SLOTS],
}

impl ConcreteState {
    /// Initial state at program entry, mirroring the abstract
    /// `initial_reg_state()`: R1 = context pointer, R10 = frame pointer,
    /// everything else (registers and stack) uninitialized. Argument
    /// seeds arrive with helper-call modeling (#51), not at entry.
    #[allow(dead_code)] // constructed by the interpreter (#50); used by tests
    pub(crate) fn initial() -> Self {
        let mut regs = [None; NUM_REGS];
        regs[1] = Some(CTX_BASE);
        regs[10] = Some(STACK_BASE);
        Self {
            regs,
            stack: [None; STACK_SLOTS],
        }
    }
}

/// Does the tnum admit the value? The known bits (`!mask`) must match;
/// the unknown bits (`mask`) may be anything (kernel tnum semantics).
fn tnum_contains(t: Tnum, value: u64) -> bool {
    (value & !t.mask) == (t.value & !t.mask)
}

/// Does the abstract register state contain the concrete value?
///
/// The reverse direction of `reg_subsumes`: the abstract side must be at
/// least as broad as the actual value, never narrower.
pub(crate) fn abstract_covers(reg: RegState, value: u64) -> bool {
    match reg {
        // a concrete value where the abstract side is uninitialized can
        // never be covered — the abstract side must be initialized too
        RegState::Uninit => false,
        RegState::Scalar(bounds) => {
            // both interpretations plus the tnum must admit the value;
            // the 32-bit views are derived from the 64-bit ones by the
            // sync (#41), so re-checking them is redundant
            (bounds.smin..=bounds.smax).contains(&(value as i64))
                && (bounds.umin..=bounds.umax).contains(&value)
                && tnum_contains(bounds.tnum, value)
        }
        RegState::PtrToStack {
            min_offset,
            max_offset,
            align_off,
        } => {
            let offset = value.wrapping_sub(STACK_BASE) as i64;
            (min_offset as i64..=max_offset as i64).contains(&offset)
                && (align_off == ALIGN_UNKNOWN || offset.rem_euclid(8) as u8 == align_off)
        }
        RegState::PtrToCtx => value == CTX_BASE,
        // map pointers have no concrete address class yet — program
        // loading that injects them (Meso) assigns virtual addresses
        // here when it lands; until then no value is covered
        RegState::PtrToMap | RegState::PtrToMapValue | RegState::PtrToMapValueOrNull => false,
    }
}

/// Does the abstract state cover the whole concrete state — every
/// register and every stack slot?
///
/// Slot-level granularity mirrors the abstract stack (`StackState`):
/// an uninitialized slot pairs with `None`, a spilled register with
/// `Some(value)` plus `abstract_covers` on the spilled state.
#[allow(dead_code)] // used by the coverage checker (#52); used by tests
pub(crate) fn state_covers(abstract_state: &VerifierState, concrete: &ConcreteState) -> bool {
    abstract_state
        .regs
        .iter()
        .zip(&concrete.regs)
        .all(|(abstract_reg, value)| match value {
            None => matches!(abstract_reg, RegState::Uninit),
            Some(value) => abstract_covers(*abstract_reg, *value),
        })
        && abstract_state
            .stack
            .slots
            .iter()
            .zip(&concrete.stack)
            .all(|(abstract_slot, value)| match (abstract_slot, value) {
                (StackSlot::Uninit, None) => true,
                (StackSlot::Spilled(reg), Some(value)) => abstract_covers(*reg, *value),
                _ => false,
            })
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ScalarBounds;

    #[test]
    fn initial_mirrors_abstract() {
        let state = ConcreteState::initial();
        // R1 = context, R10 = frame pointer, everything else uninitialized
        assert_eq!(state.regs[1], Some(CTX_BASE));
        assert_eq!(state.regs[10], Some(STACK_BASE));
        assert!(state.regs[0..1].iter().all(|r| r.is_none()));
        assert!(state.regs[2..=9].iter().all(|r| r.is_none()));
        assert!(state.stack.iter().all(|s| s.is_none()));
    }

    #[test]
    fn scalar_constant_covers_exact() {
        let reg = RegState::Scalar(ScalarBounds::constant(42));
        assert!(abstract_covers(reg, 42));
        assert!(!abstract_covers(reg, 43));
        assert!(!abstract_covers(reg, 41));
    }

    #[test]
    fn scalar_range_boundaries() {
        // signed range -10..=10: both interpretations cover it, tnum unknown
        let reg = RegState::Scalar(ScalarBounds::from_signed(-10, 10));
        assert!(abstract_covers(reg, 10));
        assert!(abstract_covers(reg, 0));
        assert!(abstract_covers(reg, 10_u64.wrapping_neg())); // -10
        // just outside the signed range
        assert!(!abstract_covers(reg, 11));
        assert!(!abstract_covers(reg, 11_u64.wrapping_neg())); // -11
    }

    #[test]
    fn scalar_unsigned_signed_split() {
        // a range straddling zero has no single u64 interval: the
        // unsigned side is the full range, so only the signed side
        // discriminates (and both sides must pass — #40)
        let reg = RegState::Scalar(ScalarBounds::from_signed(-10, 10));
        // u64::MAX = -1 signed: inside the signed range and unsigned range
        assert!(abstract_covers(reg, u64::MAX));
        // 11: unsigned pass, signed fail → not covered
        assert!(!abstract_covers(reg, 11));
    }

    #[test]
    fn scalar_tnum_bit_mismatch() {
        // wide range with a constant tnum: only the tnum discriminates
        let mut bounds = ScalarBounds::from_signed(0, 15);
        bounds.tnum = Tnum::constant(0b1010);
        let reg = RegState::Scalar(bounds);
        assert!(abstract_covers(reg, 0b1010));
        // same range, wrong known bit
        assert!(!abstract_covers(reg, 0b1110));
    }

    #[test]
    fn ptr_stack_offset_and_range() {
        // exact offset 0: only the frame base itself
        let reg = RegState::PtrToStack {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
        };
        assert!(abstract_covers(reg, STACK_BASE));
        assert!(!abstract_covers(reg, STACK_BASE - 8));

        // computed offset range -16..=-8 (#45): boundary values only
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        assert!(abstract_covers(reg, STACK_BASE - 16));
        assert!(abstract_covers(reg, STACK_BASE - 8));
        assert!(!abstract_covers(reg, STACK_BASE - 7));
        assert!(!abstract_covers(reg, STACK_BASE - 17));
    }

    #[test]
    fn ptr_stack_alignment() {
        // offset in range but misaligned: align_off = 0 rejects mod-8 ≠ 0
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: 0,
        };
        assert!(abstract_covers(reg, STACK_BASE - 16));
        assert!(!abstract_covers(reg, STACK_BASE - 15));

        // unknown alignment accepts any offset in range (#45)
        let reg = RegState::PtrToStack {
            min_offset: -16,
            max_offset: -8,
            align_off: ALIGN_UNKNOWN,
        };
        assert!(abstract_covers(reg, STACK_BASE - 15));
    }

    #[test]
    fn ptr_ctx_exact_address() {
        assert!(abstract_covers(RegState::PtrToCtx, CTX_BASE));
        assert!(!abstract_covers(RegState::PtrToCtx, CTX_BASE + 1));
        assert!(!abstract_covers(RegState::PtrToCtx, STACK_BASE));
    }

    #[test]
    fn uninit_never_covers_value() {
        assert!(!abstract_covers(RegState::Uninit, 0));
        assert!(!abstract_covers(RegState::Uninit, u64::MAX));
    }

    #[test]
    fn map_ptr_family_not_covered() {
        // no concrete address class exists for map pointers yet
        for reg in [
            RegState::PtrToMap,
            RegState::PtrToMapValue,
            RegState::PtrToMapValueOrNull,
        ] {
            assert!(!abstract_covers(reg, 0));
            assert!(!abstract_covers(reg, u64::MAX));
        }
    }

    #[test]
    fn state_covers_initial_pair() {
        // the abstract initial state covers the concrete initial state
        assert!(state_covers(
            &VerifierState::initial(),
            &ConcreteState::initial()
        ));
    }

    #[test]
    fn state_covers_register_mismatch() {
        // concrete R0 = 0 where the abstract side is uninitialized
        let mut concrete = ConcreteState::initial();
        concrete.regs[0] = Some(0);
        assert!(!state_covers(&VerifierState::initial(), &concrete));
    }

    #[test]
    fn state_covers_stack_roundtrip() {
        // abstract: slot 0 spilled with the constant 42 (a stack
        // store/load round-trip, #30); concrete: the same slot holds 42
        let mut abstract_state = VerifierState::initial();
        abstract_state.stack.slots[0] =
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(42)));
        let mut concrete = ConcreteState::initial();
        concrete.stack[0] = Some(42);

        assert!(state_covers(&abstract_state, &concrete));

        // wrong value in the slot
        concrete.stack[0] = Some(43);
        assert!(!state_covers(&abstract_state, &concrete));

        // abstract spilled but concrete uninitialized
        concrete.stack[0] = None;
        assert!(!state_covers(&abstract_state, &concrete));

        // abstract uninitialized but concrete holds a value
        let abstract_state = VerifierState::initial();
        concrete.stack[0] = Some(42);
        assert!(!state_covers(&abstract_state, &concrete));
    }
}
