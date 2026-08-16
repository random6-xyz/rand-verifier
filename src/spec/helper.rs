// ── Spec helper-call contracts (issue #112) ─────────────────────────────────

//! The ProgSpec's own helper table. Independent of
//! [`crate::helper`]'s `ArgType`/`RegState` matching: it validates
//! arguments against the spec's dynamic [`SpecValue`] types and
//! declares the R0 result. The helper set mirrors the socket-filter
//! surface the corpus exercises (map family, prandom, ringbuf, dynptr;
//! the rest of the kernel's set rejects with "unknown helper").

/// Expected dynamic type of one helper argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecArg {
    /// A fixed map pointer (CONST_PTR_TO_MAP).
    PtrToMap,
    /// Any stack pointer (key/value/dst buffers).
    PtrToStack,
    /// A stack pointer whose pointed bytes are all initialized (a
    /// key buffer for map_lookup etc. — SP2 initialized-read rule).
    PtrToStackInit { size: u32 },
    /// Any scalar.
    Scalar,
    /// A non-null map value pointer (dynptr_from_mem data).
    PtrToMapValue,
    /// A referenced memory pointer (ringbuf submit/discard).
    PtrToMem,
    /// A stack pointer to an INITIALIZED 16-byte dynptr slot (the
    /// read helpers: dynptr_read/write/data).
    PtrToDynptr,
    /// A stack pointer to a 16-byte dynptr slot that the helper is
    /// about to initialize (dynptr_from_mem's arg4).
    PtrToDynptrW,
}

/// The R0 result of a helper call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecRet {
    /// The scalar constant 0 (RET_VOID).
    Zero,
    /// An unknown scalar.
    UnknownScalar,
    /// An unknown u32 (zero-extended — get_prandom_u32 etc.).
    UnknownU32,
    /// A nullable map value pointer; the value size is filled from the
    /// map metadata at the call site.
    MapValueOrNull,
    /// A nullable referenced memory buffer (ringbuf reserve): a fresh
    /// ref id is allocated at the call site.
    MemOrNull,
}

pub(crate) struct SpecHelper {
    pub(crate) args: &'static [SpecArg],
    pub(crate) ret: SpecRet,
}

/// The spec's helper table: id → contract.
pub(crate) fn spec_helper(id: i32) -> Option<&'static SpecHelper> {
    match id {
        // map_lookup_elem(map, key): the key buffer's `key_size` bytes
        // (map metadata) must be initialized
        1 => Some(&SpecHelper {
            args: &[SpecArg::PtrToMap, SpecArg::PtrToStackInit { size: 0 }],
            ret: SpecRet::MapValueOrNull,
        }),
        // map_update_elem(map, key, value, flags)
        2 => Some(&SpecHelper {
            args: &[
                SpecArg::PtrToMap,
                SpecArg::PtrToStackInit { size: 0 },
                SpecArg::PtrToStackInit { size: 0 },
                SpecArg::Scalar,
            ],
            ret: SpecRet::Zero,
        }),
        // ktime_get_ns / get_smp_processor_id / get_numa_node_id /
        // ktime_get_boot_ns / ktime_get_coarse_ns / ktime_get_tai_ns:
        // unknown scalar returns
        5 | 8 | 10 | 125 | 160 | 208 => Some(&SpecHelper {
            args: &[],
            ret: SpecRet::UnknownScalar,
        }),
        // get_prandom_u32: an unknown u32 (zero-extended) — the kernel
        // returns a 32-bit value, so a narrower range lets signed
        // branch refinement stay precise (computed_ptr_access)
        7 => Some(&SpecHelper {
            args: &[],
            ret: SpecRet::UnknownU32,
        }),
        // ringbuf_reserve(ringbuf_map, size, flags) → nullable
        // referenced mem
        131 => Some(&SpecHelper {
            args: &[SpecArg::PtrToMap, SpecArg::Scalar, SpecArg::Scalar],
            ret: SpecRet::MemOrNull,
        }),
        // ringbuf_submit / ringbuf_discard(mem, flags): releases the
        // reference
        132 | 133 => Some(&SpecHelper {
            args: &[SpecArg::PtrToMem, SpecArg::Scalar],
            ret: SpecRet::Zero,
        }),
        // dynptr_from_mem(data, size, flags, ptr): initializes the
        // 16-byte dynptr at the stack pointer in arg4 (the slot
        // becomes a dynptr marker)
        197 => Some(&SpecHelper {
            args: &[
                SpecArg::PtrToMapValue,
                SpecArg::Scalar,
                SpecArg::Scalar,
                SpecArg::PtrToDynptrW,
            ],
            ret: SpecRet::Zero,
        }),
        // dynptr_read(dst, len, src_dynptr, offset, flags): the dst
        // buffer's `len` bytes are written by the helper (SP1/SP2:
        // bounds of the dst buffer must be in-frame)
        201 => Some(&SpecHelper {
            args: &[
                SpecArg::PtrToStack,
                SpecArg::Scalar,
                SpecArg::PtrToDynptr,
                SpecArg::Scalar,
                SpecArg::Scalar,
            ],
            ret: SpecRet::Zero,
        }),
        // dynptr_write(dst_dynptr, offset, src, len, flags)
        202 => Some(&SpecHelper {
            args: &[
                SpecArg::PtrToDynptr,
                SpecArg::Scalar,
                SpecArg::PtrToStack,
                SpecArg::Scalar,
                SpecArg::Scalar,
            ],
            ret: SpecRet::Zero,
        }),
        // dynptr_data(ptr, offset, len) → nullable referenced slice of
        // the dynptr
        203 => Some(&SpecHelper {
            args: &[SpecArg::PtrToDynptr, SpecArg::Scalar, SpecArg::Scalar],
            ret: SpecRet::MemOrNull,
        }),
        _ => None,
    }
}

#[cfg(test)]
/// Whether the spec knows this helper id — test helper.
pub(crate) fn spec_known_helper(id: i32) -> bool {
    spec_helper(id).is_some()
}

/// The slot index of a dynptr slot start (16-byte aligned, so the
/// slot pair).
pub(crate) fn dynptr_slots_of(off: i64) -> Option<(usize, usize)> {
    // the dynptr occupies 16 bytes; look up via the byte index
    let idx = spec_stack_base_check(off)?;
    Some((idx / 8, idx / 8 + 1))
}

const fn spec_stack_base_check(off: i64) -> Option<usize> {
    let idx = 512i64 + off;
    if idx >= 0 && (idx as usize) + 16 <= 512 {
        Some(idx as usize)
    } else {
        None
    }
}

#[cfg(test)]
/// Does the dynptr at stack offset `off` cover a valid 16-byte slot?
pub(crate) fn dynptr_ok(off: i64) -> bool {
    spec_stack_base_check(off).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_set() {
        assert!(spec_known_helper(1));
        assert!(spec_known_helper(7));
        assert!(spec_known_helper(131));
        assert!(spec_known_helper(197));
        assert!(spec_known_helper(201));
        assert!(!spec_known_helper(0));
        assert!(!spec_known_helper(99));
    }

    #[test]
    fn dynptr_slots() {
        // r10-based offsets: -32 → bytes 480..496 → slots 60,61
        let (a, b) = dynptr_slots_of(-32).unwrap();
        assert_eq!((a, b), (60, 61));
        // -56 → bytes 456 → slots 57,58
        let (a, b) = dynptr_slots_of(-56).unwrap();
        assert_eq!((a, b), (57, 58));
        assert!(dynptr_ok(-32));
        assert!(!dynptr_ok(-513));
        assert!(!dynptr_ok(-4)); // too close to the frame top
    }
}
