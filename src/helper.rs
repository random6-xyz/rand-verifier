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
    for (i, expected) in helper.args.iter().enumerate() {
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
