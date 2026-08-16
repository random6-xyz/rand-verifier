// ── Spec value model: dynamic types + u64 interval arithmetic ───────────────

//! The ProgSpec value model (issue #112). Independent of mini's
//! [`crate::state::ScalarBounds`] (four signed/unsigned ranges plus a
//! tnum): the spec tracks ONE wrapping-aware u64 interval per scalar
//! and a small set of dynamic pointer types, matching the SpecCheck
//! style (SOSP '25 Veritas).
//!
//! All interval arithmetic is module-2^64 and *sound*: the result
//! interval always contains every concrete wrap-round result, falling
//! back to the full range where an exact single interval does not
//! exist.

/// The dynamic value of one register or spilled slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SpecValue {
    /// Never written (kernel's NOT_INIT).
    Uninit,
    /// A u64 interval `[lo, hi]` (invariant: `lo <= hi`).
    Scalar { lo: u64, hi: u64 },
    /// Stack pointer, offset interval relative to R10 (valid access
    /// range `[-512, 0)`).
    PtrToStack { lo: i64, hi: i64 },
    /// Context pointer.
    PtrToCtx,
    /// A fixed map pointer (CONST_PTR_TO_MAP).
    PtrToMap {
        key_size: u32,
        value_size: u32,
        map_type: u8,
    },
    /// A non-null map value pointer with an offset interval inside the
    /// value.
    PtrToMapValue { lo: i64, hi: i64, size: u32 },
    /// A nullable map value pointer — must pass a NULL check before
    /// use. `id` links aliases: a NULL check on one refines them all
    /// (kernel mark_ptr_or_null_regs).
    PtrToMapValueOrNull { size: u32, id: u32 },
    /// A referenced memory buffer (ringbuf reserve / dynptr slice).
    PtrToMem {
        lo: i64,
        hi: i64,
        size: u32,
        id: u32,
    },
    /// The nullable acquire result.
    PtrToMemOrNull { size: u32, id: u32 },
}

/// A scalar interval — the wrapping-aware u64 interval.
pub(crate) type Range = (u64, u64);

impl SpecValue {
    /// The full unknown scalar.
    pub(crate) fn unknown_scalar() -> Self {
        SpecValue::Scalar {
            lo: 0,
            hi: u64::MAX,
        }
    }

    /// A constant scalar.
    pub(crate) fn const_scalar(v: u64) -> Self {
        SpecValue::Scalar { lo: v, hi: v }
    }

    pub(crate) fn is_scalar(&self) -> bool {
        matches!(self, SpecValue::Scalar { .. })
    }

    pub(crate) fn as_scalar(&self) -> Option<Range> {
        match self {
            SpecValue::Scalar { lo, hi } => Some((*lo, *hi)),
            _ => None,
        }
    }

    pub(crate) fn is_pointer(&self) -> bool {
        matches!(
            self,
            SpecValue::PtrToStack { .. }
                | SpecValue::PtrToCtx
                | SpecValue::PtrToMap { .. }
                | SpecValue::PtrToMapValue { .. }
                | SpecValue::PtrToMapValueOrNull { .. }
                | SpecValue::PtrToMem { .. }
                | SpecValue::PtrToMemOrNull { .. }
        )
    }
}

// ── 64-bit interval arithmetic (wrapping, sound) ───────────────────────────-

/// The pointwise image of `[a0,a1] ⊞ [b0,b1]` under 64-bit wrapping
/// addition, as a single interval when it is one, the full range
/// otherwise.
pub(crate) fn rng_add(a: Range, b: Range) -> Range {
    let lo = a.0 as u128 + b.0 as u128;
    let hi = a.1 as u128 + b.1 as u128;
    if lo >> 64 == hi >> 64 {
        (lo as u64, hi as u64)
    } else {
        (0, u64::MAX)
    }
}

/// Wrapping subtraction: `[a0,a1] ⊟ [b0,b1] = [a0-b1, a1-b0]`.
pub(crate) fn rng_sub(a: Range, b: Range) -> Range {
    let lo = a.0 as i128 - b.1 as i128;
    let hi = a.1 as i128 - b.0 as i128;
    // map the i128 span [lo, hi] into u64 wrapping; a single interval
    // survives iff the span is < 2^64 and fits in one 2^64 block
    let span = hi - lo;
    if span < (1i128 << 64) {
        // one block: the interval [lo, hi] may straddle 0 — first shift
        // into a canonical long position, then fold
        let folded_lo = ((lo.rem_euclid(1i128 << 64)) as u64) as i128;
        let folded_hi = folded_lo + span;
        if folded_hi < (1i128 << 64) {
            (folded_lo as u64, folded_hi as u64)
        } else {
            (0, u64::MAX)
        }
    } else {
        (0, u64::MAX)
    }
}

/// Bitwise AND: only the intersection of the possible 1-bits can
/// survive, so `[0, min(a1, b1)]` is sound (and exact for the upper
/// part).
pub(crate) fn rng_and(a: Range, b: Range) -> Range {
    (0, a.1.min(b.1))
}

/// Bitwise OR: the result is at least each operand's minimum (bit
/// setting never clears), upper bound is the full range.
pub(crate) fn rng_or(a: Range, b: Range) -> Range {
    (a.0 | b.0, u64::MAX)
}

/// Bitwise XOR on intervals: only the coarse bounds are sound.
pub(crate) fn rng_xor(_a: Range, _b: Range) -> Range {
    (0, u64::MAX)
}

/// Constant shift left: a range wrapping across a block boundary loses
/// its single-interval shape.
pub(crate) fn rng_lsh(a: Range, k: u32) -> Range {
    if k == 0 {
        return a;
    }
    if k >= 64 {
        return (0, 0);
    }
    // x << k is monotone within a block of size 2^(64-k); a range
    // spanning two blocks wraps multiple times
    if (a.0 >> (64 - k)) == (a.1 >> (64 - k)) {
        (a.0 << k, a.1 << k)
    } else {
        (0, u64::MAX)
    }
}

/// Constant logical shift right — monotone.
pub(crate) fn rng_rsh(a: Range, k: u32) -> Range {
    if k >= 64 {
        return (0, 0);
    }
    (a.0 >> k, a.1 >> k)
}

/// Constant arithmetic shift right — monotone on the signed view.
pub(crate) fn rng_arsh(a: Range, k: u32) -> Range {
    if k >= 64 {
        if (a.0 as i64) < 0 {
            return (u64::MAX, u64::MAX);
        }
        return (0, 0);
    }
    let lo = (a.0 as i64) >> k;
    let hi = (a.1 as i64) >> k;
    (lo as u64, hi as u64)
}

/// Multiplication: exact for constants, the full range otherwise
/// (sound; the corpus never multiplies non-constants).
pub(crate) fn rng_mul(a: Range, b: Range) -> Range {
    if a.0 == a.1 && b.0 == b.1 {
        let v = a.0.wrapping_mul(b.0);
        (v, v)
    } else {
        (0, u64::MAX)
    }
}

/// Truncate to 32 bits and zero-extend: the image of `[lo,hi]` under
/// `x ↦ x & 0xffff_ffff`, as a single 32-bit interval when it is one.
pub(crate) fn truncate32(x: u64) -> u64 {
    x & 0xFFFF_FFFF
}

pub(crate) fn range32(a: Range) -> Range {
    if a.0 >> 32 == a.1 >> 32 {
        (truncate32(a.0), truncate32(a.1))
    } else {
        (0, u32::MAX as u64)
    }
}

/// Interpret `[lo,hi]` as a signed i64 interval, when it is one
/// (`None` when the range straddles the sign bit).
pub(crate) fn as_signed(a: Range) -> Option<(i64, i64)> {
    // a single signed interval exists iff the range does not straddle
    // the sign bit
    if a.1 < (1 << 63) || a.0 >= (1 << 63) {
        Some((a.0 as i64, a.1 as i64))
    } else {
        None
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_add_exact() {
        assert_eq!(rng_add((1, 3), (5, 7)), (6, 10));
        // x ∈ [MAX-2, MAX], y ∈ {0, 1}: the image wraps around 0 and
        // is NOT a single interval → full range
        assert_eq!(rng_add((u64::MAX - 2, u64::MAX), (0, 1)), (0, u64::MAX));
        assert_eq!(
            rng_add((u64::MAX - 2, u64::MAX), (0, 0)),
            (u64::MAX - 2, u64::MAX)
        );
        // a span crossing a 2^64 boundary cannot be one interval
        assert_eq!(rng_add((0, u64::MAX), (0, 1)), (0, u64::MAX));
    }

    #[test]
    fn range_sub_exact() {
        assert_eq!(rng_sub((10, 20), (1, 5)), (5, 19));
        // x ∈ [0,5], y ∈ [10,12]: x-y ∈ [-12,-5] → [MAX-11, MAX-4]
        assert_eq!(rng_sub((0, 5), (10, 12)), (u64::MAX - 11, u64::MAX - 4));
        assert_eq!(rng_sub((0, u64::MAX), (0, u64::MAX)), (0, u64::MAX));
    }

    #[test]
    fn range_bitwise() {
        assert_eq!(rng_and((0, 255), (0, 15)), (0, 15));
        assert_eq!(rng_or((8, 8), (1, 2)), (9, u64::MAX));
        assert_eq!(rng_xor((0, 1), (0, 1)), (0, u64::MAX));
    }

    #[test]
    fn range_shifts() {
        assert_eq!(rng_lsh((1, 3), 2), (4, 12));
        // x ∈ [2^63+1, 2^64-1], x<<1 wraps to [2, 2^64-2] (evens) —
        // a single (over-approx) interval in the same 2^64 block
        assert_eq!(
            rng_lsh((0x8000_0000_0000_0001, 0xFFFF_FFFF_FFFF_FFFF), 1),
            (2, u64::MAX - 1)
        );
        assert_eq!(rng_rsh((16, 48), 3), (2, 6));
        // arithmetic shift: [-8,-1] >> 3 = -1/-1 (sign fill)
        assert_eq!(rng_arsh((u64::MAX - 7, u64::MAX), 3), (u64::MAX, u64::MAX));
        assert_eq!(rng_arsh((0x100, 0x1FF), 3), (0x20, 0x3F));
        // a shift >= 64 saturates by sign
        assert_eq!(rng_arsh((u64::MAX, u64::MAX), 64), (u64::MAX, u64::MAX));
        assert_eq!(rng_arsh((1, 1), 64), (0, 0));
    }

    #[test]
    fn truncation() {
        assert_eq!(range32((0x1_0000_0001, 0x1_0000_0003)), (1, 3));
        assert_eq!(range32((0, 0xFFFF_FFFF_FFFF_FFFF)), (0, u32::MAX as u64));
    }
}
