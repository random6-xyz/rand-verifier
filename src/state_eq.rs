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
// `precise` bit is set only by precision backtracking (#98) on stored
// checkpoint states, so the imprecise shortcut is live exactly like the
// kernel's `if (!rold->precise && exact == NOT_EXACT) return true;` —
// its soundness rests on the backtracking marking every value-dependent
// register precise. The idmap (check_ids) additionally requires id
// relationships to be preserved across pruning (#99).

use crate::state::{
    ALIGN_UNKNOWN, NUM_REGS, RegState, STACK_SIZE, STACK_SLOTS, ScalarBounds, StackByte,
    StackState, VerifierState,
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

/// The kernel's idmap (states.c `check_ids`): a mapping from the OLD
/// state's register ids to the NEW state's, built while comparing two
/// states. Id relationships must be preserved across pruning: two
/// registers that shared an id in the explored state must share one in
/// the current state, otherwise the linked-register refinement
/// downstream could diverge.
#[derive(Default)]
pub(crate) struct IdMap {
    pairs: Vec<(u32, u32)>,
    tmp_id_gen: u32,
}

/// The kernel's `check_ids()`.
fn check_ids(idmap: &mut IdMap, old_id: u32, cur_id: u32) -> bool {
    if (old_id == 0) != (cur_id == 0) {
        return false;
    }
    if old_id == 0 {
        return true;
    }
    for (old, cur) in &idmap.pairs {
        if *old == old_id {
            return *cur == cur_id;
        }
        if *cur == cur_id {
            return false;
        }
    }
    idmap.pairs.push((old_id, cur_id));
    true
}

/// The kernel's `check_scalar_ids()`: an independent old scalar (id 0)
/// accepts any current id; a linked old scalar gets a temporary id when
/// the current register is independent, so two old registers sharing an
/// id cannot both map to independent current registers.
fn check_scalar_ids(idmap: &mut IdMap, old_id: u32, cur_id: u32) -> bool {
    if old_id == 0 {
        return true;
    }
    let cur_id = if cur_id == 0 {
        idmap.tmp_id_gen += 1;
        idmap.tmp_id_gen
    } else {
        cur_id
    };
    check_ids(idmap, old_id, cur_id)
}

/// The kernel's `regsafe()`: whether the explored register `old` being
/// safe implies the current register `new` is safe.
///
/// Register types have to match exactly, including the nullable
/// (MAYBE_NULL) distinction — the kernel explicitly does not allow
/// mixing MAYBE_NULL and non-MAYBE_NULL registers, because a NULL check
/// on the old state may have affected other registers with the same id.
/// The kernel's `regs_exact()`: full structural register equality that
/// deliberately EXCLUDES the scalar precision bit (kernel: memcmp up to
/// `offsetof(struct bpf_reg_state, id)` — `precise` lives after it, and
/// `states_maybe_looping`'s memcmp up to `frameno` excludes it too).
/// The precise bit only drives the NOT_EXACT scalar shortcut; it never
/// participates in equality. The id RELATIONSHIPS are checked
/// separately via the idmap (`check_reg_ids`).
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
                ..
            },
            RegState::PtrToMapValue {
                min_offset: b_min,
                max_offset: b_max,
                align_off: b_align,
                value_size: b_size,
                ..
            },
        ) => a_min == b_min && a_max == b_max && a_align == b_align && a_size == b_size,
        (
            RegState::PtrToMapValueOrNull {
                value_size: a_size, ..
            },
            RegState::PtrToMapValueOrNull {
                value_size: b_size, ..
            },
        ) => a_size == b_size,
        _ => false,
    }
}

/// Scalar equality excluding the precision bit and the link id/delta
/// (the idmap checks those separately).
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

pub(crate) fn regsafe(
    old: &RegState,
    new: &RegState,
    exact: ExactLevel,
    idmap: &mut IdMap,
) -> bool {
    if exact == ExactLevel::Exact {
        return regs_exact(old, new) && check_reg_ids(idmap, old, new);
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
                // the kernel also requires the link deltas to match
                // (states.c: a linked old scalar's delta must equal the
                // current one, or the synced refinements diverge)
                (old_b.delta == new_b.delta || old_b.id == 0)
                    && scalar_range_within(old_b, new_b)
                    && check_scalar_ids(idmap, old_b.id, new_b.id)
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
        // alignment compatible, id relationship preserved (kernel
        // PTR_TO_MAP_VALUE case)
        (
            RegState::PtrToMapValue {
                min_offset: old_min,
                max_offset: old_max,
                align_off: old_align,
                value_size: old_size,
                id: old_id,
            },
            RegState::PtrToMapValue {
                min_offset: new_min,
                max_offset: new_max,
                align_off: new_align,
                value_size: new_size,
                id: new_id,
            },
        ) => {
            old_size == new_size
                && old_min <= new_min
                && old_max >= new_max
                && (*old_align == *new_align || *old_align == ALIGN_UNKNOWN)
                && check_ids(idmap, *old_id, *new_id)
        }
        (
            RegState::PtrToMapValueOrNull {
                value_size: old_size,
                id: old_id,
            },
            RegState::PtrToMapValueOrNull {
                value_size: new_size,
                id: new_id,
            },
        ) => old_size == new_size && check_ids(idmap, *old_id, *new_id),
        // referenced memory buffers: the offset range contained, the
        // reference identity preserved (kernel PTR_TO_MEM: the ref id
        // relationship is checked through the idmap, #101)
        (
            RegState::PtrToMem {
                min_offset: old_min,
                max_offset: old_max,
                id: old_id,
                ..
            },
            RegState::PtrToMem {
                min_offset: new_min,
                max_offset: new_max,
                id: new_id,
                ..
            },
        ) => old_min <= new_min && old_max >= new_max && check_ids(idmap, *old_id, *new_id),
        (RegState::PtrToMemOrNull { id: old_id }, RegState::PtrToMemOrNull { id: new_id }) => {
            check_ids(idmap, *old_id, *new_id)
        }
        // different types are never comparable
        _ => false,
    }
}

/// The id part of the kernel's `regs_exact`/EXACT comparisons: id
/// relationships must be preserved exactly.
fn check_reg_ids(idmap: &mut IdMap, old: &RegState, new: &RegState) -> bool {
    match (old, new) {
        (RegState::Scalar(a), RegState::Scalar(b)) => check_scalar_ids(idmap, a.id, b.id),
        (RegState::PtrToMapValue { id: a, .. }, RegState::PtrToMapValue { id: b, .. }) => {
            check_ids(idmap, *a, *b)
        }
        (
            RegState::PtrToMapValueOrNull { id: a, .. },
            RegState::PtrToMapValueOrNull { id: b, .. },
        ) => check_ids(idmap, *a, *b),
        (RegState::PtrToMem { id: a, .. }, RegState::PtrToMem { id: b, .. }) => {
            check_ids(idmap, *a, *b)
        }
        (RegState::PtrToMemOrNull { id: a }, RegState::PtrToMemOrNull { id: b }) => {
            check_ids(idmap, *a, *b)
        }
        _ => true,
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
pub(crate) fn stacksafe(
    old: &StackState,
    new: &StackState,
    exact: ExactLevel,
    idmap: &mut IdMap,
) -> bool {
    let mut i = 0usize;
    while i < STACK_SIZE {
        let o = old.bytes[i];
        let im = i % 8;
        let spi = i / 8;
        if exact == ExactLevel::Exact {
            // byte types must match; the kernel treats STACK_POISON as
            // STACK_INVALID for the comparison (both are "never used")
            if o != new.bytes[i] {
                return false;
            }
        }
        if o == StackByte::Invalid {
            // the explored state never used this byte — ignore it
            i += 1;
            continue;
        }
        // the kernel's scalar_reg_for_stack pair at 64/32-bit
        // boundaries: scalar spills vs MISC/ZERO/INVALID slots
        // compare through an imprecise unbound fake scalar (so a
        // MISC slot is safe with any scalar spill and vice versa)
        if im == 0 || im == 4 {
            let oreg = fake_scalar_for_stack(old, spi, im);
            let creg = fake_scalar_for_stack(new, spi, im);
            if let (Some(o), Some(c)) = (oreg, creg) {
                if !regsafe(&o, &c, exact, idmap) {
                    return false;
                }
                i += if im == 0 { 8 } else { 4 };
                continue;
            }
        }
        // "if old state was safe with misc data in the stack it will
        // be safe with zero-initialized stack. The opposite is not
        // true" (kernel stacksafe)
        if o == StackByte::Misc && new.bytes[i] == StackByte::Zero {
            i += 1;
            continue;
        }
        if o != new.bytes[i] {
            // Ex: old explored (safe) state has STACK_SPILL in this
            // byte, but current has STACK_MISC → not equivalent
            return false;
        }
        if im == 7 {
            // both slots are fully spills: the spilled registers must
            // be comparable (kernel: "check that stored pointers types
            // are the same as well")
            if o == StackByte::Spill {
                let Some(old_spilled) = old.spilled[spi].as_ref() else {
                    i += 1;
                    continue;
                };
                let Some(new_spilled) = new.spilled[spi].as_ref() else {
                    return false;
                };
                if !regsafe(old_spilled, new_spilled, exact, idmap) {
                    return false;
                }
            }
        }
        i += 1;
    }
    true
}

/// The kernel's `scalar_reg_for_stack`: a scalar spill (at the 64-bit
/// or 32-bit boundary) yields the spilled scalar; MISC/ZERO/INVALID
/// bytes yield an imprecise unbound scalar (so loads from them produce
/// an unbound scalar); pointer spills yield nothing.
/// The kernel's `scalar_reg_for_stack` + `is_stack_misc_after` /
/// `is_spilled_scalar_after`: a scalar spill covering `[im, 8)` yields
/// the spilled scalar (the 64-bit view at im == 0, the 32-bit subreg
/// at im == 4); all-MISC bytes from `im` to the slot end yield an
/// imprecise unbound scalar; everything else (including ZERO bytes —
/// "the opposite is not true") yields nothing.
fn fake_scalar_for_stack(stack: &StackState, spi: usize, im: usize) -> Option<RegState> {
    let bytes = &stack.bytes[spi * 8..spi * 8 + 8];
    if bytes[im..].iter().all(|x| *x == StackByte::Spill) {
        match stack.spilled[spi] {
            Some(r @ RegState::Scalar(_)) => {
                let s = match r {
                    RegState::Scalar(b) => b,
                    _ => unreachable!(),
                };
                if im == 0 {
                    Some(RegState::Scalar(s))
                } else {
                    // the 32-bit view (kernel: reg32 of the spilled
                    // register)
                    let mut sub = s;
                    sub.smin = sub.s32_min as i64;
                    sub.smax = sub.s32_max as i64;
                    sub.umin = sub.u32_min as u64;
                    sub.umax = sub.u32_max as u64;
                    sub.tnum = sub.tnum.subreg();
                    Some(RegState::Scalar(sub))
                }
            }
            _ => None,
        }
    } else if bytes[im..].iter().all(|x| *x == StackByte::Misc) {
        let mut unbound = ScalarBounds::unknown();
        unbound.precise = false;
        Some(RegState::Scalar(unbound))
    } else {
        None
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
    // the kernel's `states_equal` requires the same number of frames
    if old.curframe != new.curframe {
        return false;
    }
    // the kernel's `refsafe`: the same number of acquired references,
    // the ids related through the idmap (#101)
    if old.refs_cnt != new.refs_cnt {
        return false;
    }
    // one idmap per comparison (kernel reset_idmap_scratch)
    let mut idmap = IdMap::default();
    for i in 0..old.refs_cnt as usize {
        if !check_ids(&mut idmap, old.refs[i], new.refs[i]) {
            return false;
        }
    }
    // the frame pointer (R10) is never part of the live mask comparison
    // — the kernel never cleans it, and it is identical in every state
    for r in 0..NUM_REGS {
        if live_regs & (1 << r) != 0 && !regsafe(&old.regs[r], &new.regs[r], exact, &mut idmap) {
            return false;
        }
    }
    // `live_stack` is not consulted here: the stored state was cleaned
    // with it, so its dead slots are Uninit and stacksafe skips them.
    // The kernel's stacksafe has the same shape (the current state is
    // cleaned with the same mask before the comparison).
    if !stacksafe(&old.stack, &new.stack, exact, &mut idmap) {
        return false;
    }
    // the caller frames of active calls must match too (the kernel's
    // per-frame func_states_equal); they are not liveness-cleaned, so
    // the comparison is conservative
    for i in 0..crate::state::MAX_CALL_FRAMES - 1 {
        match (&old.saved[i], &new.saved[i]) {
            (None, None) => {}
            (Some(a), Some(b)) => {
                for r in 0..NUM_REGS {
                    if !regsafe(&a.regs[r], &b.regs[r], exact, &mut idmap) {
                        return false;
                    }
                }
                if !stacksafe(&a.stack, &b.stack, exact, &mut idmap) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
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
            for b in state.stack.bytes[i * 8..i * 8 + 8].iter_mut() {
                *b = crate::state::StackByte::Invalid;
            }
            state.stack.spilled[i] = None;
        }
    }
}

/// The kernel's `states_maybe_looping()`: all registers (up to the
/// frame pointer) must be exactly equal — the prefilter of the
/// infinite-loop detection before the full EXACT comparison.
pub(crate) fn states_maybe_looping(old: &VerifierState, new: &VerifierState) -> bool {
    // the kernel's memcmp up to `frameno` — every field except the
    // precision bit (which lives after frameno and only drives the
    // NOT_EXACT scalar shortcut); the reference count is part of the
    // state (kernel refsafe)
    old.refs_cnt == new.refs_cnt
        && old
            .regs
            .iter()
            .zip(&new.regs)
            .all(|(a, b)| regs_exact(a, b))
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Test helper: mark a full slot as a spill of `reg`.
    fn spill_slot(state: &mut VerifierState, slot: usize, reg: RegState) {
        for b in state.stack.bytes[slot * 8..slot * 8 + 8].iter_mut() {
            *b = StackByte::Spill;
        }
        state.stack.spilled[slot] = Some(reg);
    }

    /// Test helper: mark a full slot as MISC.
    fn misc_slot(state: &mut VerifierState, slot: usize) {
        for b in state.stack.bytes[slot * 8..slot * 8 + 8].iter_mut() {
            *b = StackByte::Misc;
        }
    }
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

    fn with_id(b: ScalarBounds, id: u32) -> ScalarBounds {
        ScalarBounds { id, ..b }
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
        assert!(regsafe(
            &old.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        let other = scalar_state(1, ScalarBounds::constant(7));
        assert!(regsafe(
            &old.regs[1],
            &other.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // ... but a PRECISE explored scalar enforces the ranges
        let mut precise_old = scalar_state(1, precise(ScalarBounds::from_signed(0, 100)));
        precise_old.regs[1] = RegState::Scalar(precise(ScalarBounds::from_signed(0, 100)));
        assert!(!regsafe(
            &precise_old.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
    }

    #[test]
    fn regsafe_scalar_containment() {
        // the explored range must contain the current one (old ⊇ new)
        let old = scalar_state(1, precise(ScalarBounds::from_signed(0, 100)));
        let new = scalar_state(1, ScalarBounds::from_signed(10, 20));
        assert!(regsafe(
            &old.regs[1],
            &new.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // the other direction never holds (the explored side must be
        // precise for the direction to be observable — an imprecise
        // explored scalar matches anything, #98)
        let narrow = scalar_state(1, precise(ScalarBounds::from_signed(10, 20)));
        assert!(!regsafe(
            &narrow.regs[1],
            &old.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // wider current ranges are not covered
        let wide = scalar_state(1, ScalarBounds::from_signed(-50, 200));
        assert!(!regsafe(
            &old.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
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
            ExactLevel::NotExact,
            &mut IdMap::default()
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
            id: 0,
            delta: 0,
        };
        let wide = scalar_state(1, precise(tnum_bounds(0, 0b011)));
        let narrow = scalar_state(1, precise(tnum_bounds(0b001, 0)));
        assert!(regsafe(
            &wide.regs[1],
            &narrow.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(!regsafe(
            &narrow.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
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
        assert!(regsafe(
            &old.regs[5],
            &new.regs[5],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(regsafe(
            &old.regs[6],
            &new.regs[6],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // but the reverse never holds: an initialized old register does
        // not match an uninitialized current one
        assert!(!regsafe(
            &new.regs[5],
            &old.regs[5],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
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
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(!regsafe(
            &scalar.regs[1],
            &ctx.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // ... including the nullable distinction (kernel: "we don't
        // allow mixing MAYBE_NULL and non-MAYBE_NULL registers")
        let mut or_null = VerifierState::initial();
        or_null.regs[1] = RegState::PtrToMapValueOrNull {
            value_size: 8,
            id: 0,
        };
        let mut valid = VerifierState::initial();
        valid.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 0,
            align_off: 0,
            value_size: 8,
            id: 0,
        };
        assert!(!regsafe(
            &or_null.regs[1],
            &valid.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(!regsafe(
            &valid.regs[1],
            &or_null.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(regsafe(
            &or_null.regs[1],
            &or_null.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
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
        assert!(regsafe(
            &a.regs[2],
            &a.regs[2],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(!regsafe(
            &a.regs[2],
            &b.regs[2],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // PTR_TO_MAP_VALUE: contained offset ranges with the same size
        let mut wide = VerifierState::initial();
        wide.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 100,
            align_off: 0,
            value_size: 128,

            id: 0,
        };
        let mut narrow = VerifierState::initial();
        narrow.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 0,
            value_size: 128,

            id: 0,
        };
        assert!(regsafe(
            &wide.regs[1],
            &narrow.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        assert!(!regsafe(
            &narrow.regs[1],
            &wide.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // a different value size never matches
        let mut other_size = VerifierState::initial();
        other_size.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 0,
            value_size: 64,

            id: 0,
        };
        assert!(!regsafe(
            &wide.regs[1],
            &other_size.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // known alignment must agree; unknown alignment (superset)
        // matches everything
        let mut mis = VerifierState::initial();
        mis.regs[1] = RegState::PtrToMapValue {
            min_offset: 10,
            max_offset: 20,
            align_off: 4,
            value_size: 128,

            id: 0,
        };
        assert!(!regsafe(
            &wide.regs[1],
            &mis.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        let mut unk = VerifierState::initial();
        unk.regs[1] = RegState::PtrToMapValue {
            min_offset: 0,
            max_offset: 100,
            align_off: ALIGN_UNKNOWN,
            value_size: 128,

            id: 0,
        };
        assert!(regsafe(
            &unk.regs[1],
            &narrow.regs[1],
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
    }

    // ── stacksafe ─────────────────────────────────────────────────────

    #[test]
    fn stacksafe_unused_slots_ignored() {
        // the explored stack with an unused slot matches a current
        // stack that uses it — the classic kernel prune
        // (INV, MISC) == (MISC, MISC)
        let old = VerifierState::initial();
        let mut new = VerifierState::initial();
        spill_slot(&mut new, 1, RegState::Scalar(ScalarBounds::constant(7)));
        assert!(stacksafe(
            &old.stack,
            &new.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // ... but not the other way: an explored state that *used* the
        // slot does not match a current state that did not
        assert!(!stacksafe(
            &new.stack,
            &old.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
    }

    #[test]
    fn stacksafe_spill_comparison() {
        // the old spilled scalar is PRECISE (#98) — ranges are enforced
        let mut old = VerifierState::initial();
        spill_slot(
            &mut old,
            0,
            RegState::Scalar(precise(ScalarBounds::from_signed(0, 100))),
        );
        let mut new = VerifierState::initial();
        spill_slot(
            &mut new,
            0,
            RegState::Scalar(ScalarBounds::from_signed(10, 20)),
        );
        assert!(stacksafe(
            &old.stack,
            &new.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // a wider current spill is not covered
        spill_slot(
            &mut new,
            0,
            RegState::Scalar(ScalarBounds::from_signed(-50, 200)),
        );
        assert!(!stacksafe(
            &old.stack,
            &new.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // spilled pointers must match types
        spill_slot(&mut old, 1, RegState::PtrToCtx);
        spill_slot(&mut new, 1, RegState::Scalar(ScalarBounds::constant(1)));
        assert!(!stacksafe(
            &old.stack,
            &new.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
    }

    #[test]
    fn stacksafe_misc_vs_zero() {
        // an explored MISC slot is safe with a current zero slot
        // ("the opposite is not true" — kernel stacksafe)
        let mut old = VerifierState::initial();
        misc_slot(&mut old, 0);
        let mut zero = VerifierState::initial();
        spill_slot(&mut zero, 0, RegState::Scalar(ScalarBounds::constant(0)));
        assert!(stacksafe(
            &old.stack,
            &zero.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // the reverse with a PRECISE spilled scalar never holds
        // ("the opposite is not true" — kernel stacksafe; the
        // imprecise shortcut would accept an imprecise spill)
        let mut precise_zero = VerifierState::initial();
        spill_slot(
            &mut precise_zero,
            0,
            RegState::Scalar(precise(ScalarBounds::constant(0))),
        );
        assert!(!stacksafe(
            &precise_zero.stack,
            &old.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        // any scalar spill is covered by a MISC slot at NOT_EXACT (the
        // kernel's imprecise unbound_reg fake, #98) — but a pointer
        // spill still is not
        let mut scalar = VerifierState::initial();
        spill_slot(&mut scalar, 0, RegState::Scalar(ScalarBounds::constant(1)));
        assert!(stacksafe(
            &old.stack,
            &scalar.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
        let mut ptr = VerifierState::initial();
        spill_slot(&mut ptr, 0, RegState::PtrToCtx);
        assert!(!stacksafe(
            &old.stack,
            &ptr.stack,
            ExactLevel::NotExact,
            &mut IdMap::default()
        ));
    }

    #[test]
    fn stacksafe_exact() {
        // EXACT: slot types must match and spills must be identical
        let mut old = VerifierState::initial();
        spill_slot(&mut old, 0, RegState::Scalar(ScalarBounds::constant(7)));
        let mut same = VerifierState::initial();
        spill_slot(&mut same, 0, RegState::Scalar(ScalarBounds::constant(7)));
        assert!(stacksafe(
            &old.stack,
            &same.stack,
            ExactLevel::Exact,
            &mut IdMap::default()
        ));
        let mut diff = VerifierState::initial();
        spill_slot(&mut diff, 0, RegState::Scalar(ScalarBounds::constant(8)));
        assert!(!stacksafe(
            &old.stack,
            &diff.stack,
            ExactLevel::Exact,
            &mut IdMap::default()
        ));
        // an unused slot in one state and a used slot in the other
        // never match exactly
        let mut used = VerifierState::initial();
        misc_slot(&mut used, 1);
        assert!(!stacksafe(
            &old.stack,
            &used.stack,
            ExactLevel::Exact,
            &mut IdMap::default()
        ));
    }

    // ── idmap (check_ids, #99) ───────────────────────────────────────

    #[test]
    fn idmap_requires_consistent_mapping() {
        // two registers sharing an id in the explored state must share
        // one in the current state
        let mut idmap = IdMap::default();
        assert!(check_ids(&mut idmap, 5, 9));
        assert!(check_ids(&mut idmap, 5, 9));
        assert!(!check_ids(&mut idmap, 5, 10));
        // an id maps to only one current id
        assert!(!check_ids(&mut idmap, 6, 9));
        // zero ids match only zero ids
        let mut idmap = IdMap::default();
        assert!(check_ids(&mut idmap, 0, 0));
        assert!(!check_ids(&mut idmap, 0, 1));
        assert!(!check_ids(&mut idmap, 1, 0));
    }

    #[test]
    fn scalar_ids_require_linked_groups() {
        // the kernel's check_scalar_ids: an independent old scalar (0)
        // accepts any current id
        let mut idmap = IdMap::default();
        assert!(check_scalar_ids(&mut idmap, 0, 7));
        // a linked old scalar maps to a current id — two old registers
        // with the SAME id cannot map to two independent current
        // registers (the temp-id rule)
        let mut idmap = IdMap::default();
        assert!(check_scalar_ids(&mut idmap, 3, 0)); // temp id
        assert!(!check_scalar_ids(&mut idmap, 3, 0)); // second temp id differs
        // a fresh map: a consistent explicit mapping passes
        let mut idmap = IdMap::default();
        assert!(check_scalar_ids(&mut idmap, 3, 4));
        assert!(check_scalar_ids(&mut idmap, 3, 4));
    }

    #[test]
    fn regsafe_enforces_id_relationships() {
        // two linked scalars in the explored state must stay linked in
        // the current state — otherwise the linked refinement
        // downstream could diverge
        let mut old = VerifierState::initial();
        old.regs[1] = RegState::Scalar(precise(with_id(ScalarBounds::from_signed(0, 100), 7)));
        old.regs[2] = RegState::Scalar(precise(with_id(ScalarBounds::from_signed(0, 100), 7)));
        let mut new = VerifierState::initial();
        new.regs[1] = RegState::Scalar(with_id(ScalarBounds::from_signed(10, 20), 11));
        new.regs[2] = RegState::Scalar(with_id(ScalarBounds::from_signed(10, 20), 11));
        // both linked with the same id → equal
        assert!(states_equal(&old, &new, ExactLevel::NotExact, 0b110));
        // split (1 linked, 2 independent) → NOT equal
        let mut split = VerifierState::initial();
        split.regs[1] = RegState::Scalar(with_id(ScalarBounds::from_signed(10, 20), 11));
        split.regs[2] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
        assert!(!states_equal(&old, &split, ExactLevel::NotExact, 0b110));
        // both independent → not equal (they were linked in old)
        let mut split = VerifierState::initial();
        split.regs[1] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
        split.regs[2] = RegState::Scalar(ScalarBounds::from_signed(10, 20));
        assert!(!states_equal(&old, &split, ExactLevel::NotExact, 0b110));
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
        for b in state.stack.bytes[0..8].iter_mut() {
            *b = StackByte::Spill;
        }
        state.stack.spilled[0] = Some(RegState::Scalar(ScalarBounds::constant(4)));
        for b in state.stack.bytes[8..16].iter_mut() {
            *b = StackByte::Spill;
        }
        state.stack.spilled[1] = Some(RegState::Scalar(ScalarBounds::constant(5)));
        clean_state(&mut state, 1 << 1, 1 << 1);
        // live: r1, slot 1; dead: r0, r6, slot 0; R10 is never cleaned
        assert_eq!(state.regs[0], RegState::Uninit);
        assert_eq!(state.regs[1], RegState::Scalar(ScalarBounds::constant(2)));
        assert_eq!(state.regs[6], RegState::Uninit);
        assert_eq!(state.regs[10], ptr_stack(0));
        assert_eq!(state.stack.bytes[0], StackByte::Invalid);
        assert_eq!(state.stack.bytes[8], StackByte::Spill);
        assert_eq!(
            state.stack.spilled[1],
            Some(RegState::Scalar(ScalarBounds::constant(5)))
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
