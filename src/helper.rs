// ── Helper function prototypes (v0.3 Mini) ──────────────────────────────────

use crate::error::VerificationFailure;
use crate::state::{RegState, ScalarBounds, VerifierState, read_reg};

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

/// The helper table: id → prototype (#28). Calls encode the helper id
/// as a negative immediate, like the kernel (positive immediates are
/// BPF-to-BPF calls, handled by the nano pass).
pub(crate) fn helper_prototype(id: i32) -> Option<&'static HelperPrototype> {
    match id {
        // BPF_FUNC_map_lookup_elem: map_lookup(map, key)
        1 => Some(&HelperPrototype {
            args: &[ArgType::PtrToMap, ArgType::PtrToStack],
            return_type: RegState::PtrToMapValueOrNull,
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
            }),
        }),
        // BPF_FUNC_get_prandom_u32: no arguments, unknown scalar
        7 => Some(&HelperPrototype {
            args: &[],
            return_type: RegState::Scalar(ScalarBounds {
                smin: i64::MIN,
                smax: i64::MAX,
                umin: 0,
                umax: u64::MAX,
            }),
        }),
        _ => None,
    }
}

/// Does the actual register state satisfy the expected argument type?
fn arg_matches(expected: ArgType, actual: RegState) -> bool {
    matches!(
        (expected, actual),
        (ArgType::PtrToMap, RegState::PtrToMap)
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
