// ── Helper function prototypes (v0.3 Mini) ──────────────────────────────────

use crate::error::VerificationFailure;
use crate::state::{RegState, ScalarBounds, VerifierState, read_reg};
use crate::tnum::Tnum;

/// Expected type of one helper argument (R1..R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgType {
    /// A fixed map pointer (kernel's CONST_PTR_TO_MAP).
    PtrToMap,
    /// A pointer into the stack frame (key/value buffers).
    PtrToStack,
    /// Any scalar value (flags etc.).
    Scalar,
    /// A referenced memory pointer (kernel PTR_TO_MEM, #101): the
    /// argument of the release helpers (ringbuf submit/discard).
    PtrToMem,
    /// A stack pointer covering a 16-byte dynptr slot (kernel
    /// ARG_PTR_TO_DYNPTR, #101).
    PtrToDynptr,
    /// A BTF-typed kernel object pointer (kernel ARG_PTR_TO_BTF_ID,
    /// #101): the kfunc family.
    PtrToBtf,
    /// A non-null map value pointer (the kernel's PTR_TO_MAP_VALUE
    /// argument family — e.g. bpf_dynptr_from_mem's data, #101).
    PtrToMapValue,
}

/// Kfunc prototype: argument types and the R0 result (the mini's view
/// of the kernel's kfunc declarations resolved through the vmlinux
/// BTF; the ids follow the vmlinux BTF of the reference kernel).
pub(crate) struct KfuncPrototype {
    pub(crate) args: &'static [ArgType],
    pub(crate) return_type: RegState,
    pub(crate) acquires_ref: bool,
    pub(crate) releases_ref: bool,
}

/// The kfunc table, keyed by the vmlinux BTF function type id (#101).
/// The kernel rejects every kfunc call for the socket-filter program
/// type ("calling kernel function ... is not allowed" — the kfuncs are
/// registered for the tracing types only), so the accept paths are
/// exercised by the unit tests; the fixtures stay on the reject side.
pub(crate) fn kfunc_prototype(btf_id: i32) -> Option<&'static KfuncPrototype> {
    match btf_id {
        // bpf_obj_drop(obj) → void: releases the reference (kernel
        // btf_kfunc_id_set + KF_RELEASE)
        94599 => Some(&KfuncPrototype {
            args: &[ArgType::PtrToBtf],
            return_type: UNKNOWN_SCALAR_ZERO,
            acquires_ref: false,
            releases_ref: true,
        }),
        // bpf_kptr_xchg(map, ptr) → the old kptr: acquires a reference
        // to the stored object
        94041 => Some(&KfuncPrototype {
            args: &[ArgType::PtrToMap, ArgType::PtrToBtf],
            return_type: RegState::PtrToBtfId {
                btf_id: 0,
                ref_obj_id: 0,
            },
            acquires_ref: true,
            releases_ref: false,
        }),
        // bpf_refcount_acquire(obj) → obj with a new reference
        94881 => Some(&KfuncPrototype {
            args: &[ArgType::PtrToBtf],
            return_type: RegState::PtrToBtfId {
                btf_id: 0,
                ref_obj_id: 0,
            },
            acquires_ref: true,
            releases_ref: false,
        }),
        _ => None,
    }
}

/// Whether the helper acquires a reference into R0 (kernel
/// RET_PTR_TO_MEM_OR_NULL with the acquire semantics, #101).
pub(crate) fn helper_acquires_ref(id: i32) -> bool {
    matches!(id, 131)
}

/// Whether the helper releases the reference passed in R1 (kernel
/// ARG_PTR_TO_MEM | OBJ_RELEASE, #101).
pub(crate) fn helper_releases_ref(id: i32) -> bool {
    matches!(id, 132 | 133)
}

/// Helper function prototype: argument types and the register state
/// placed in R0 after the call (cf. the kernel's bpf_func_proto).
pub(crate) struct HelperPrototype {
    pub(crate) args: &'static [ArgType],
    pub(crate) return_type: RegState,
}

/// The register state after a helper with an unknown scalar return
/// (the kernel's RET_INTEGER family — the full range, so every
/// concrete return value is covered).
const UNKNOWN_SCALAR: RegState = RegState::Scalar(ScalarBounds::unknown());

/// ringbuf_submit / ringbuf_discard: (mem, flags) → 0.
const RINGBUF_RELEASE: HelperPrototype = HelperPrototype {
    args: &[ArgType::PtrToMem, ArgType::Scalar],
    return_type: UNKNOWN_SCALAR_ZERO,
};

/// The scalar constant 0 (RET_VOID returns).
const UNKNOWN_SCALAR_ZERO: RegState = RegState::Scalar(ScalarBounds::constant(0));

/// The helper table: id → prototype (#28). The immediate of a
/// `BPF_JMP|BPF_CALL` instruction is the helper id (kernel convention);
/// BPF-to-BPF calls are rejected at decode time.
pub(crate) fn helper_prototype(id: i32) -> Option<&'static HelperPrototype> {
    match id {
        // BPF_FUNC_map_lookup_elem: map_lookup(map, key)
        1 => Some(&HelperPrototype {
            args: &[ArgType::PtrToMap, ArgType::PtrToStack],
            // the value size is filled from R1's map metadata at the
            // call site (the kernel builds the return from the map)
            return_type: RegState::PtrToMapValueOrNull {
                value_size: 0,
                id: 0,
            },
        }),
        // BPF_FUNC_map_update_elem: map_update(map, key, value, flags)
        2 => Some(&HelperPrototype {
            args: &[
                ArgType::PtrToMap,
                ArgType::PtrToStack,
                ArgType::PtrToStack,
                ArgType::Scalar,
            ],
            return_type: RegState::Scalar(ScalarBounds {
                smin: 0,
                smax: 0,
                umin: 0,
                umax: 0,
                s32_min: 0,
                s32_max: 0,
                u32_min: 0,
                u32_max: 0,
                tnum: Tnum { value: 0, mask: 0 },
                precise: false,
                id: 0,
                delta: 0,
            }),
        }),
        // BPF_FUNC_ktime_get_ns: no arguments, unknown u64 scalar
        // (kernel RET_INTEGER, bpf_base_func_proto)
        5 => Some(&HelperPrototype {
            args: &[],
            return_type: UNKNOWN_SCALAR,
        }),
        // BPF_FUNC_get_prandom_u32: no arguments, unknown u32 scalar
        7 => Some(&HelperPrototype {
            args: &[],
            return_type: UNKNOWN_SCALAR,
        }),
        // BPF_FUNC_get_smp_processor_id: no arguments, unknown scalar
        // (kernel RET_INTEGER, bpf_base_func_proto — allowed
        // unprivileged; mseed-52555-5091/-5206/-5265)
        8 => Some(&HelperPrototype {
            args: &[],
            return_type: UNKNOWN_SCALAR,
        }),
        // BPF_FUNC_get_numa_node_id: no arguments, unknown scalar
        // (kernel RET_INTEGER, bpf_base_func_proto)
        10 => Some(&HelperPrototype {
            args: &[],
            return_type: UNKNOWN_SCALAR,
        }),
        // BPF_FUNC_ringbuf_reserve: reserve(ringbuf_map, size, flags)
        // → PTR_TO_MEM_OR_NULL with a fresh reference (#101; the ref
        // id is assigned at the call site)
        131 => Some(&HelperPrototype {
            args: &[ArgType::PtrToMap, ArgType::Scalar, ArgType::Scalar],
            return_type: RegState::PtrToMemOrNull {
                id: 0,
                parent_id: 0,
                size: 0,
            },
        }),
        // BPF_FUNC_dynptr_from_mem (197): from_mem(data, size, flags,
        // ptr) — initializes the 16-byte dynptr at the stack pointer in
        // arg4 (kernel ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_LOCAL, #101)
        197 => Some(&HelperPrototype {
            args: &[
                ArgType::PtrToMapValue,
                ArgType::Scalar,
                ArgType::Scalar,
                ArgType::PtrToDynptr,
            ],
            return_type: UNKNOWN_SCALAR_ZERO,
        }),
        // BPF_FUNC_dynptr_read (201): read(dst, len, src_dynptr,
        // offset, flags) — copies out of the dynptr into the dst
        // buffer (initialized by the helper)
        201 => Some(&HelperPrototype {
            args: &[
                ArgType::PtrToStack,
                ArgType::Scalar,
                ArgType::PtrToDynptr,
                ArgType::Scalar,
                ArgType::Scalar,
            ],
            return_type: UNKNOWN_SCALAR_ZERO,
        }),
        // BPF_FUNC_dynptr_write (202): write(dst_dynptr, offset, src,
        // len, flags) — copies the src buffer into the dynptr
        202 => Some(&HelperPrototype {
            args: &[
                ArgType::PtrToDynptr,
                ArgType::Scalar,
                ArgType::PtrToStack,
                ArgType::Scalar,
                ArgType::Scalar,
            ],
            return_type: UNKNOWN_SCALAR_ZERO,
        }),
        // BPF_FUNC_dynptr_data (203): data(ptr, offset, len) → a
        // nullable referenced slice of the dynptr (kernel
        // RET_PTR_TO_DYNPTR_MEM_OR_NULL, #101); the id is filled at the
        // call site
        203 => Some(&HelperPrototype {
            args: &[ArgType::PtrToDynptr, ArgType::Scalar, ArgType::Scalar],
            return_type: RegState::PtrToMemOrNull {
                id: 0,
                parent_id: 0,
                size: 0,
            },
        }),
        // BPF_FUNC_ringbuf_submit / BPF_FUNC_ringbuf_discard:
        // submit(mem, flags) — releases the reference in R1 and
        // returns 0 (RET_VOID)
        132 | 133 => Some(&RINGBUF_RELEASE),
        // BPF_FUNC_ktime_get_boot_ns (125), BPF_FUNC_ktime_get_coarse_ns
        // (160), BPF_FUNC_ktime_get_tai_ns (208): no-argument
        // scalar-returning helpers of the socket-filter set
        // (net/core/filter.c: sk_filter_func_proto +
        // bpf_sk_base_func_proto). The fuzzer's mutator rewrites the
        // call immediate to any helper id, and the kernel accepts every
        // helper in the set — mini must mirror the set instead of
        // reporting "unknown helper" for valid ids (campaign finding
        // mseed-65537-4391: call 8 was rejected by mini, accepted by
        // the kernel).
        125 | 160 | 208 => Some(&HelperPrototype {
            args: &[],
            return_type: UNKNOWN_SCALAR,
        }),
        _ => None,
    }
}

/// Does the actual register state satisfy the expected argument type?
fn arg_matches(expected: ArgType, actual: RegState) -> bool {
    matches!(
        (expected, actual),
        (ArgType::PtrToMap, RegState::PtrToMap { .. })
            | (ArgType::PtrToStack, RegState::PtrToStack { .. })
            | (ArgType::PtrToMem, RegState::PtrToMem { .. })
            | (ArgType::PtrToDynptr, RegState::PtrToStack { .. })
            | (ArgType::PtrToBtf, RegState::PtrToBtfId { .. })
            | (ArgType::PtrToMapValue, RegState::PtrToMapValue { .. })
            | (ArgType::Scalar, RegState::Scalar(_))
    )
}

/// Validate R1..R5 against the helper's argument types, mirroring the
/// kernel's check_helper_call (#28).
pub(crate) fn check_helper_args(
    pc: u32,
    helper: &HelperPrototype,
    state: &VerifierState,
) -> Result<(), VerificationFailure> {
    check_call_args(pc, helper.args, state)
}

/// Validate the R1..R5 registers against the argument types (shared by
/// the helper table and the kfunc table, #101).
pub(crate) fn check_call_args(
    pc: u32,
    args: &[ArgType],
    state: &VerifierState,
) -> Result<(), VerificationFailure> {
    for (i, expected) in args.iter().enumerate() {
        let reg = (i + 1) as u8; // R1..R5
        let actual = read_reg(pc, state, reg)?;
        if !arg_matches(*expected, actual) {
            return Err(VerificationFailure::new(
                pc,
                format!(
                    "helper arg {}: r{} has type {}, expected {:?}",
                    i + 1,
                    reg,
                    actual,
                    expected
                ),
            ));
        }
    }
    Ok(())
}
