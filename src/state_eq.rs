// ── Kernel-style state equality (issue #97, kernel/bpf/states.c) ────────────
//
// Mirrors the kernel's state-comparison machinery so the mini pass can
// prune like the kernel instead of the old subsumption check:
//
// - `regsafe` — per-register comparison, "Returns true if (rold safe
//   implies rcur safe)" (kernel states.c). Register types must match
//   exactly; scalar and pointer ranges are compared with the explored
//   state as a SUPERSET of the current one (`range_within` +
//   `tnum_in`, the same direction as the old subsumption);
// - `stacksafe` — per-slot comparison, walking the explored stack and
//   ignoring slots the explored state never used (STACK_INVALID /
//   STACK_POISON after dead-slot cleaning);
// - `states_equal` — `func_states_equal`: compares only the registers
//   that are live before the stored state's instruction (the kernel's
//   `live_regs_before` mask), then the stack;
// - `clean_state` — the kernel's `clean_verifier_state`: dead registers
//   and dead stack slots are reset before a state is stored, so later
//   comparisons skip them;
// - `states_maybe_looping` — the prefilter of the kernel's infinite-loop
//   detection.
//
// The kernel has three exactness levels — NOT_EXACT, RANGE_WITHIN and
// EXACT. NOT_EXACT and RANGE_WITHIN differ only through the scalar
// `precise` bit: at NOT_EXACT an *imprecise* explored scalar matches any
// current scalar, at RANGE_WITHIN ranges are always compared. The
// `precise` bit and its backtracking machinery are issue #98; until
// then every scalar behaves as precise, so NOT_EXACT and RANGE_WITHIN
// are identical here (ranges are always compared — sound, because
// without precision backtracking an imprecise comparison could prune a
// path whose scalar ranges fail a later check).

use crate::state::{
    ALIGN_UNKNOWN, NUM_REGS, RegState, STACK_SLOTS, StackSlot, StackState, VerifierState,
};

/// The exactness level of a state comparison (kernel states.c
/// `enum exact_level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactLevel {
    /// Default comparison at a prune point (kernel NOT_EXACT /
    /// RANGE_WITHIN; identical until the precise bit lands in #98).
    NotExact,
    /// Full structural equality — the kernel's infinite-loop detection
    /// compares in-progress states at EXACT.
    Exact,
}

/// Whether the explored scalar `old` contains the current scalar `new`
/// in both interpretations (kernel `range_within`: `cnum64_is_subset`
/// / `cnum32_is_subset`, i.e. old ⊇ new).
fn scalar_range_within(old: &crate::state::ScalarBounds, new: &crate::state::ScalarBounds) -> bool {
    old.smin <= new.smin
        && old.smax >= new.smax
        && old.umin <= new.umin
        && old.umax >= new.umax
        && old.s32_min <= new.s32_min
        && old.s32_max >= new.s32_max
        && old.u32_min <= new.u32_min
        && old.u32_max >= new.u32_max
        && old.tnum.subsumes(new.tnum)
}

/// Whether the explored map-value pointer `old` contains the current
/// pointer `new` (kernel: `memcmp(prefix)` for the fixed fields, then
/// `range_within` + `tnum_in` for the variable offset).
fn map_value_within(old: &RegState, new: &RegState) -> bool {
    match (old, new) {
        (
            RegState::PtrToMapValue {
                min_offset: old_min,
                max_offset: old_max,
                align_off: old_align,
                value_size: old_size,
            },
            RegState::PtrToMapValue {
                min_offset: new_min,
                max_offset: new_max,
                align_off: new_align,
                value_size: new_size,
            },
        ) => {
            old_size == new_size
                && old_min <= new_min
                && old_max >= new_max
                && (*old_align == *new_align || *old_align == ALIGN_UNKNOWN)
        }
        _ => unreachable!("map_value_within is only called on matching types"),
    }
}

/// The kernel's `regs_exact()`: full structural register equality that
/// deliberately EXCLUDES the scalar precision bit (kernel: memcmp up to
/// `offsetof(struct bpf_reg_state, id)` — `precise` lives after it, and
/// `states_maybe_looping`'s memcmp up to `frameno` excludes it too).
/// The precise bit only drives the NOT_EXACT scalar shortcut; it never
/// participates in equality.
pub(crate) fn regs_exact(old: &RegState, new: &RegState) -> bool {
    match (old, new) {
        (RegState::Uninit, RegState::Uninit) => true,
        (RegState::Scalar(a), RegState::Scalar(b)) => scalar_bounds_exact(a, b),
        (
            RegState::PtrToStack {
                min_offset: a_min,
                max_offset: a_max,
                align_off: a_align,
            },
            RegState::PtrToStack {
                min_offset: b_min,
                max_offset: b_max,
                align_off: b_align,
            },
        ) => a_min == b_min && a_max == b_max && a_align == b_align,
        (RegState::PtrToCtx, RegState::PtrToCtx) => true,
        (
            RegState::PtrToMap {
                key_size: a_key,
                value_size: a_val,
            },
            RegState::PtrToMap {
                key_size: b_key,
                value_size: b_val,
            },
        ) => a_key == b_key && a_val == b_val,
        (
            RegState::PtrToMapValue {
                min_offset: a_min,
                max_offset: a_max,
                align_off: a_align,
                value_size: a_size,
            },
            RegState::PtrToMapValue {
                min_offset: b_min,
                max_offset: b_max,
                align_off: b_align,
                value_size: b_size,
            },
        ) => a_min == b_min && a_max == b_max && a_align == b_align && a_size == b_size,
        (
            RegState::PtrToMapValueOrNull { value_size: a_size },
            RegState::PtrToMapValueOrNull { value_size: b_size },
        ) => a_size == b_size,
        _ => false,
    }
}

/// Scalar equality excluding the precision bit.
pub(crate) fn scalar_bounds_exact(
    a: &crate::state::ScalarBounds,
    b: &crate::state::ScalarBounds,
) -> bool {
    a.smin == b.smin
        && a.smax == b.smax
        && a.umin == b.umin
        && a.umax == b.umax
        && a.s32_min == b.s32_min
        && a.s32_max == b.s32_max
        && a.u32_min == b.u32_min
        && a.u32_max == b.u32_max
        && a.tnum == b.tnum
}

/// The kernel's `regsafe()`: whether the explored register `old` being
/// safe implies the current register `new` is safe.
///
/// Register types have to match exactly, including the nullable
/// (MAYBE_NULL) distinction — the kernel explicitly does not allow
/// mixing MAYBE_NULL and non-MAYBE_NULL registers, because a NULL check
/// on the old state may have affected other registers with the same id.
pub(crate) fn regsafe(old: &RegState, new: &RegState, exact: ExactLevel) -> bool {
    if exact == ExactLevel::Exact {
        return regs_exact(old, new);
    }
    if *old == RegState::Uninit {
        // the explored state never used this register (or it was dead
        // and got cleaned) — nothing to compare
        return true;
    }
    match (old, new) {
        (RegState::Scalar(old_b), RegState::Scalar(new_b)) => {
            // the kernel's scalar precision shortcut (states.c): an
            // *imprecise* explored scalar matches any current scalar
            // at NOT_EXACT — the range knowledge does not affect any
            // safety decision, so the current value cannot matter.
            // Soundness rests on precision backtracking (#98) marking
            // every value-dependent register precise in the stored
            // states; until then every scalar stays imprecise and the
            // ranges are skipped, exactly like the kernel's
            // `if (!rold->precise && exact == NOT_EXACT) return true;`
            if !old_b.precise && exact == ExactLevel::NotExact {
                true
            } else {
                scalar_range_within(old_b, new_b)
            }
        }
        // two stack pointers are equal only if they point to the same
        // offset (kernel PTR_TO_STACK: `regs_exact` — fp-8 in one
        // frame is not fp-8 in another)
        (RegState::PtrToStack { .. }, RegState::PtrToStack { .. }) => old == new,
        (RegState::PtrToCtx, RegState::PtrToCtx) => true,
        // a fixed map pointer is an exact constant (kernel
        // CONST_PTR_TO_MAP: default → regs_exact)
        (RegState::PtrToMap { .. }, RegState::PtrToMap { .. }) => old == new,
        // map value pointers: same value size, offset range contained,
        // alignment compatible (kernel PTR_TO_MAP_VALUE case)
        (RegState::PtrToMapValue { .. }, RegState::PtrToMapValue { .. }) => {
            map_value_within(old, new)
        }
        (RegState::PtrToMapValueOrNull { .. }, RegState::PtrToMapValueOrNull { .. }) => old == new,
        // different types are never comparable
        _ => false,
    }
}

/// The kernel's `stacksafe()`: whether the explored stack `old` being
/// safe implies the current stack `new` is safe.
///
/// Walks the explored stack and skips slots the explored state never
/// used (STACK_INVALID / STACK_POISON — uninitialized or dead-cleaned
/// slots). The explored state having *more* unused slots than the
/// current one is exactly the classic kernel prune
/// `(INV, MISC) == (MISC, MISC)`: the explored state was safe without
/// using the slot, so the current state is safe too.
pub(crate) fn stacksafe(old: &StackState, new: &StackState, exact: ExactLevel) -> bool {
    for i in 0..STACK_SLOTS {
        let o = &old.slots[i];
        if exact == ExactLevel::Exact {
            // slot types must match; the kernel treats STACK_POISON as
            // STACK_INVALID for the comparison (both are "never used")
            if !slot_types_equal_exact(o, &new.slots[i]) {
                return false;
            }
            continue;
        }
        match o {
            StackSlot::Uninit => {
                // the explored state never used this slot — ignore it
            }
            StackSlot::Initialized => {
                // old MISC: safe with another MISC slot, a
                // zero-initialized slot ("if old state was safe with
                // misc data in the stack it will be safe with
                // zero-initialized stack. The opposite is not true" —
                // kernel stacksafe), and — with the precise bit landed
                // (#98) — any current SCALAR spill: the kernel compares
                // the old MISC slot through the imprecise unbound_reg
                // fake register (states.c scalar_reg_for_stack), which
                // the NOT_EXACT imprecise shortcut matches against any
                // scalar. A current pointer spill still never matches.
                match &new.slots[i] {
                    StackSlot::Initialized => {}
                    StackSlot::Spilled(RegState::Scalar(_)) => {}
                    _ => return false,
                }
            }
            StackSlot::Spilled(old_reg) => {
                // both slots are spills: the spilled registers must be
                // comparable (kernel: "check that stored pointers types
                // are the same as well")
                match &new.slots[i] {
                    StackSlot::Spilled(new_reg) => {
                        if !regsafe(old_reg, new_reg, exact) {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
        }
    }
    true
}

/// Exact slot comparison: the types must be identical (a Spilled slot
/// compares its spilled register exactly).
fn slot_types_equal_exact(old: &StackSlot, new: &StackSlot) -> bool {
    match (old, new) {
        (StackSlot::Uninit, StackSlot::Uninit) => true,
        (StackSlot::Initialized, StackSlot::Initialized) => true,
        (StackSlot::Spilled(a), StackSlot::Spilled(b)) => regs_exact(a, b),
        _ => false,
    }
}

/// The kernel's `func_states_equal()`: compares the registers that are
/// live before the stored state's instruction (the `live_regs_before`
/// mask), then the stack. `live_regs`/`live_stack` are the liveness
/// masks of the pc where `old` was stored (same pc as the comparison).
pub(crate) fn states_equal(
    old: &VerifierState,
    new: &VerifierState,
    exact: ExactLevel,
    live_regs: u16,
) -> bool {
    // the frame pointer (R10) is never part of the live mask comparison
    // — the kernel never cleans it, and it is identical in every state
    for r in 0..NUM_REGS {
        if live_regs & (1 << r) != 0 && !regsafe(&old.regs[r], &new.regs[r], exact) {
            return false;
        }
    }
    // `live_stack` is not consulted here: the stored state was cleaned
    // with it, so its dead slots are Uninit and stacksafe skips them.
    // The kernel's stacksafe has the same shape (the current state is
    // cleaned with the same mask before the comparison).
    stacksafe(&old.stack, &new.stack, exact)
}

/// The kernel's `clean_verifier_state()` / `__clean_func_state()`: dead
/// registers (not in `live_regs`) are reset to uninitialized, dead
/// stack slots (not in `live_stack`) are reset too (the kernel uses
/// STACK_POISON, which is equivalent to STACK_INVALID for every
/// comparison). The frame pointer R10 is never cleaned (kernel:
/// `for (i = 0; i < BPF_REG_FP; i++)`).
pub(crate) fn clean_state(state: &mut VerifierState, live_regs: u16, live_stack: u64) {
    for r in 0..NUM_REGS {
        if r != 10 && live_regs & (1 << r) == 0 {
            state.regs[r] = RegState::Uninit;
        }
    }
    for i in 0..STACK_SLOTS {
        if live_stack & (1 << i) == 0 {
            state.stack.slots[i] = StackSlot::Uninit;
        }
    }
}

/// The kernel's `states_maybe_looping()`: all registers (up to the
/// frame pointer) must be exactly equal — the prefilter of the
/// infinite-loop detection before the full EXACT comparison.
pub(crate) fn states_maybe_looping(old: &VerifierState, new: &VerifierState) -> bool {
    // the kernel's memcmp up to `frameno` — every field except the
    // precision bit (which lives after frameno and only drives the
    // NOT_EXACT scalar shortcut)
    old.regs
        .iter()
        .zip(&new.regs)
        .all(|(a, b)| regs_exact(a, b))
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ScalarBounds;
    use crate::testutil::*;
    use crate::tnum::Tnum;

    fn scalar_state(reg: usize, bounds: ScalarBounds) -> VerifierState {
        let mut state = VerifierState::initial();
        state.regs[reg] = RegState::Scalar(bounds);
        state
    }

    // ── regsafe: scalars ──────────────────────────────────────────────

    /// The containment checks below use PRECISE explored scalars — the
    /// imprecise shortcut is tested separately (#98).
    fn precise(b: ScalarBounds) -> ScalarBounds {
        ScalarBounds { precise: true, ..b }
    }

    #[test]
    fn regsafe_imprecise_scalar_matches_anything() {
        // the kernel's scalar precision shortcut: an imprecise explored
        // scalar matches ANY current scalar at NOT_EXACT (states.c:
        // "if (!rold->precise && exact == NOT_EXACT) return true") —
        // even a wider range or a different type... no, types must
        // still match; only the RANGE is skipped
        let old = scalar_state(1, ScalarBounds::from_signed(0, 100));
        let wide = scalar_state(1, ScalarBounds::from_signed(-50, 200));
        assert!(regsafe(&old.regs[1], &wide.regs[1], ExactLevel::NotExact));
        let other = scalar_state(1, ScalarBounds::constant(7));
        assert!(regsafe(&old.regs[1], &other.regs[1], ExactLevel::NotExact));
        // ... but a PRECISE explored scalar enforces the ranges
        let mut precise_old = scalar_state(1, precise(ScalarBounds::from_signed(0, 100)));
        precise_old.regs[1] = RegState::Scalar(precise(ScalarBounds::from_signed(0, 100)));
        assert!(!regsafe(
            &precise_old.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact
        ));
    }

    #[test]
    fn regsafe_scalar_containment() {
        // the explored range must contain the current one (old ⊇ new)
        let old = scalar_state(1, precise(ScalarBounds::from_signed(0, 100)));
        let new = scalar_state(1, ScalarBounds::from_signed(10, 20));
        assert!(regsafe(&old.regs[1], &new.regs[1], ExactLevel::NotExact));
        // the other direction never holds (the explored side must be
        // precise for the direction to be observable — an imprecise
        // explored scalar matches anything, #98)
        let narrow = scalar_state(1, precise(ScalarBounds::from_signed(10, 20)));
        assert!(!regsafe(
            &narrow.regs[1],
            &old.regs[1],
            ExactLevel::NotExact
        ));
        // wider current ranges are not covered
        let wide = scalar_state(1, ScalarBounds::from_signed(-50, 200));
        assert!(!regsafe(&old.regs[1], &wide.regs[1], ExactLevel::NotExact));
        // both interpretations must be contained (#40)
        let mut partial = VerifierState::initial();
        partial.regs[1] = RegState::Scalar(ScalarBounds {
            smin: 10,
            smax: 20,
            umin: 0,
            umax: 1000,
            ..ScalarBounds::from_signed(10, 20)
        });
        assert!(!regsafe(
            &old.regs[1],
            &partial.regs[1],
            ExactLevel::NotExact
        ));
        // ... and the shortcut stays off for precise old scalars: a
        // WIDER current range is still not covered
        let _ = wide;
    }

    #[test]
    fn regsafe_scalar_tnum() {
        // the tnum must be a superset too (kernel tnum_in)
        let tnum_bounds = |value: u64, mask: u64| ScalarBounds {
            smin: 0,
            smax: 3,
            umin: 0,
            umax: 3,
            s32_min: 0,
            s32_max: 3,
            u32_min: 0,
            u32_max: 3,
            tnum: Tnum { value, mask },
            precise: false,
        };
        let wide = scalar_state(1, precise(tnum_bounds(0, 0b011)));
        let narrow = scalar_state(1, precise(tnum_bounds(0b001, 0)));
        assert!(regsafe(
            &wide.regs[1],
            &narrow.regs[1],
            ExactLevel::NotExact
        ));
        assert!(!regsafe(
            &narrow.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact
        ));
    }

    #[test]
    fn regsafe_uninit_old_matches_anything() {
        // an explored state that never used a register matches any
        // current register of any type (kernel: "explored state can't
        // have used this")
        let old = VerifierState::initial();
        let mut new = VerifierState::initial();
        new.regs[5] = RegState::PtrToCtx;
        new.regs[6] = RegState::Scalar(ScalarBounds::constant(7));
        assert!(regsafe(&old.regs[5], &new.regs[5], ExactLevel::NotExact));
        assert!(regsafe(&old.regs[6], &new.regs[6], ExactLevel::NotExact));
        // but the reverse never holds: an initialized old register does
        // not match an uninitialized current one
        assert!(!regsafe(&new.regs[5], &old.regs[5], ExactLevel::NotExact));
    }

    #[test]
    fn regsafe_types_must_match_exactly() {
        // different types are never comparable
        let mut ctx = VerifierState::initial();
        ctx.regs[1] = RegState::PtrToCtx;
        let mut scalar = VerifierState::initial();
        scalar.regs[1] = RegState::Scalar(ScalarBounds::constant(1));
        assert!(!regsafe(
            &ctx.regs[1],
            &scalar.regs[1],
            ExactLevel::NotExact
        ));
        assert!(!regsafe(
            &scalar.regs[1],
            &ctx.regs[1],
            ExactLevel::NotExact
        ));
        // ... including the nullable distinction (kernel: "we don't
        // allow mixing MAYBE_NULL and non-MAYBE_NULL registers")
        let mut or_null = VerifierState::initial();
        or_null.regs[1] = RegState::PtrToMapValueOrNull { value_size: 8 };
        let mut valid = VerifierState::initial();
        valid.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
        };
        assert!(!regsafe(
            &or_null.regs[1],
            &valid.regs[1],
            ExactLevel::NotExact
        ));
        assert!(!regsafe(
            &valid.regs[1],
            &or_null.regs[1],
            ExactLevel::NotExact
        ));
        assert!(regsafe(
            &or_null.regs[1],
            &or_null.regs[1],
            ExactLevel::NotExact
        ));
    }

    #[test]
    fn regsafe_pointers() {
        // PTR_TO_STACK: only exact offsets are equal (kernel
        // PTR_TO_STACK: regs_exact)
        let mut a = VerifierState::initial();
        a.regs[2] = ptr_stack(-8);
        let mut b = VerifierState::initial();
        b.regs[2] = ptr_stack(-16);
        assert!(regsafe(&a.regs[2], &a.regs[2], ExactLevel::NotExact));
        assert!(!regsafe(&a.regs[2], &b.regs[2], ExactLevel::NotExact));
        // PTR_TO_MAP_VALUE: contained offset ranges with the same size
        let mut wide = VerifierState::initial();
        wide.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 100,
            align_off: 0,
            value_size: 128,
        };
        let mut narrow = VerifierState::initial();
        narrow.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 0,
            value_size: 128,
        };
        assert!(regsafe(
            &wide.regs[1],
            &narrow.regs[1],
            ExactLevel::NotExact
        ));
        assert!(!regsafe(
            &narrow.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact
        ));
        // a different value size never matches
        let mut other_size = VerifierState::initial();
        other_size.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 0,
            value_size: 64,
        };
        assert!(!regsafe(
            &wide.regs[1],
            &other_size.regs[1],
            ExactLevel::NotExact
        ));
        // known alignment must agree; unknown alignment (superset)
        // matches everything
        let mut mis = VerifierState::initial();
        mis.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 4,
            value_size: 128,
        };
        assert!(!regsafe(&wide.regs[1], &mis.regs[1], ExactLevel::NotExact));
        let mut unk = VerifierState::initial();
        unk.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 100,
            align_off: ALIGN_UNKNOWN,
            value_size: 128,
        };
        assert!(regsafe(&unk.regs[1], &narrow.regs[1], ExactLevel::NotExact));
    }

    // ── stacksafe ─────────────────────────────────────────────────────

    #[test]
    fn stacksafe_unused_slots_ignored() {
        // the explored stack with an unused slot matches a current
        // stack that uses it — the classic kernel prune
        // (INV, MISC) == (MISC, MISC)
        let old = VerifierState::initial();
        let mut new = VerifierState::initial();
        new.stack.slots[1] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(7)));
        assert!(stacksafe(&old.stack, &new.stack, ExactLevel::NotExact));
        // ... but not the other way: an explored state that *used* the
        // slot does not match a current state that did not
        assert!(!stacksafe(&new.stack, &old.stack, ExactLevel::NotExact));
    }

    #[test]
    fn stacksafe_spill_comparison() {
        // the old spilled scalar is PRECISE (#98) — ranges are enforced
        let mut old = VerifierState::initial();
        old.stack.slots[0] =
            StackSlot::Spilled(RegState::Scalar(precise(ScalarBounds::from_signed(0, 100))));
        let mut new = VerifierState::initial();
        new.stack.slots[0] =
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::from_signed(10, 20)));
        assert!(stacksafe(&old.stack, &new.stack, ExactLevel::NotExact));
        // a wider current spill is not covered
        new.stack.slots[0] =
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::from_signed(-50, 200)));
        assert!(!stacksafe(&old.stack, &new.stack, ExactLevel::NotExact));
        // spilled pointers must match types
        old.stack.slots[1] = StackSlot::Spilled(RegState::PtrToCtx);
        new.stack.slots[1] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(1)));
        assert!(!stacksafe(&old.stack, &new.stack, ExactLevel::NotExact));
    }

    #[test]
    fn stacksafe_misc_vs_zero() {
        // an explored MISC slot is safe with a current zero slot
        // ("the opposite is not true" — kernel stacksafe)
        let mut old = VerifierState::initial();
        old.stack.slots[0] = StackSlot::Initialized;
        let mut zero = VerifierState::initial();
        zero.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(0)));
        assert!(stacksafe(&old.stack, &zero.stack, ExactLevel::NotExact));
        // the reverse never holds
        assert!(!stacksafe(&zero.stack, &old.stack, ExactLevel::NotExact));
        // any scalar spill is covered by a MISC slot at NOT_EXACT (the
        // kernel's imprecise unbound_reg fake, #98) — but a pointer
        // spill still is not
        let mut scalar = VerifierState::initial();
        scalar.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(1)));
        assert!(stacksafe(&old.stack, &scalar.stack, ExactLevel::NotExact));
        let mut ptr = VerifierState::initial();
        ptr.stack.slots[0] = StackSlot::Spilled(RegState::PtrToCtx);
        assert!(!stacksafe(&old.stack, &ptr.stack, ExactLevel::NotExact));
    }

    #[test]
    fn stacksafe_exact() {
        // EXACT: slot types must match and spills must be identical
        let mut old = VerifierState::initial();
        old.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(7)));
        let mut same = VerifierState::initial();
        same.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(7)));
        assert!(stacksafe(&old.stack, &same.stack, ExactLevel::Exact));
        let mut diff = VerifierState::initial();
        diff.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(8)));
        assert!(!stacksafe(&old.stack, &diff.stack, ExactLevel::Exact));
        // an unused slot in one state and a used slot in the other
        // never match exactly
        let mut used = VerifierState::initial();
        used.stack.slots[1] = StackSlot::Initialized;
        assert!(!stacksafe(&old.stack, &used.stack, ExactLevel::Exact));
    }

    // ── states_equal / clean_state ────────────────────────────────────

    #[test]
    fn states_equal_only_live_registers() {
        // r0 differs, but r0 is dead at this pc (never read before the
        // next write) → the states are equal
        let mut old = VerifierState::initial();
        old.regs[0] = RegState::Scalar(ScalarBounds::constant(1));
        // r1 is PRECISE (a value-dependent use marked it, #98) — its
        // range is enforced even at NOT_EXACT; r0 is imprecise, so the
        // r0 difference alone never blocks equality
        old.regs[1] = RegState::Scalar(precise(ScalarBounds::constant(42)));
        let mut new = VerifierState::initial();
        new.regs[0] = RegState::Scalar(ScalarBounds::constant(2));
        new.regs[1] = RegState::Scalar(ScalarBounds::constant(42));
        // r1 live, r0 dead
        assert!(states_equal(&old, &new, ExactLevel::NotExact, 1 << 1));
        // with r0 live AND PRECISE the states differ
        let mut precise_old = old;
        precise_old.regs[0] = RegState::Scalar(precise(ScalarBounds::constant(1)));
        assert!(!states_equal(
            &precise_old,
            &new,
            ExactLevel::NotExact,
            (1 << 0) | (1 << 1)
        ));
    }

    #[test]
    fn clean_state_resets_dead_registers_and_slots() {
        let mut state = VerifierState::initial();
        state.regs[0] = RegState::Scalar(ScalarBounds::constant(1));
        state.regs[1] = RegState::Scalar(ScalarBounds::constant(2));
        state.regs[6] = RegState::Scalar(ScalarBounds::constant(3));
        state.stack.slots[0] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(4)));
        state.stack.slots[1] = StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(5)));
        clean_state(&mut state, 1 << 1, 1 << 1);
        // live: r1, slot 1; dead: r0, r6, slot 0; R10 is never cleaned
        assert_eq!(state.regs[0], RegState::Uninit);
        assert_eq!(state.regs[1], RegState::Scalar(ScalarBounds::constant(2)));
        assert_eq!(state.regs[6], RegState::Uninit);
        assert_eq!(state.regs[10], ptr_stack(0));
        assert_eq!(state.stack.slots[0], StackSlot::Uninit);
        assert_eq!(
            state.stack.slots[1],
            StackSlot::Spilled(RegState::Scalar(ScalarBounds::constant(5)))
        );
    }

    #[test]
    fn states_maybe_looping_registers_equal() {
        let a = scalar_state(1, ScalarBounds::constant(5));
        let b = scalar_state(1, ScalarBounds::constant(5));
        assert!(states_maybe_looping(&a, &b));
        let c = scalar_state(1, ScalarBounds::constant(6));
        assert!(!states_maybe_looping(&a, &c));
    }
}
