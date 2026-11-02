//! Program-type context models (#135).
//!
//! The kernel answers context reads with the program's `is_valid_access`
//! op; this module is the table-driven equivalent for the model. Every
//! rule cites the kernel function it mirrors so a disagreement is easy to
//! check against the source tree:
//!
//! - `__sk_buff`: `bpf_skb_is_valid_access` + `tc_cls_act_is_valid_access`
//!   (sched_cls/sched_act/cgroup_skb) and `sk_filter_is_valid_access`
//!   (socket_filter), `net/core/filter.c`
//! - `xdp_md`: `__is_valid_xdp_access` + `xdp_is_valid_access`
//! - tracepoint: `tp_prog_is_valid_access`, `kernel/trace/bpf_trace.c`
//!
//! Pointer-typed fields (`data`, `data_end`, ...) are reported as
//! [`CtxAccess::Pointer`]: the model has no packet-pointer register type
//! yet, so those cases stay surface gaps instead of being approximated.

use crate::prog_type::ProgType;

/// The context model a program type uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxModel {
    /// `struct __sk_buff` as socket_filter sees it.
    SocketFilter,
    /// `struct __sk_buff` as sched_cls/sched_act/cgroup_skb see it.
    SchedCls,
    /// `struct xdp_md`.
    Xdp,
    /// The raw tracepoint data buffer (`PERF_MAX_TRACE_SIZE`).
    TracePoint,
}

/// Why a context access is not a plain scalar read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtxError {
    /// The kernel's `is_valid_access` rejects this (off, size) pair; the
    /// caller reports it as `invalid bpf_context access`.
    Invalid,
    /// The field exists but is pointer-typed (or otherwise outside the
    /// model): a surface gap, not a verdict.
    Unmodeled(&'static str),
}

/// The result of a valid context read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxAccess {
    /// A scalar field (or a narrow read inside a scalar field).
    Scalar,
    /// A pointer-typed field the model cannot represent yet.
    Pointer(&'static str),
}

/// `sizeof(struct __sk_buff)` (`include/uapi/linux/bpf.h`).
const SK_BUFF_SIZE: i32 = 192;
/// `PERF_MAX_TRACE_SIZE` (`include/linux/trace_events.h`).
const PERF_MAX_TRACE_SIZE: i32 = 8192;
/// `sizeof(struct xdp_md)`.
const XDP_MD_SIZE: i32 = 24;

// Offsets inside `struct __sk_buff` (uapi bpf.h, in declaration order).
const SKB_TC_CLASSID: i32 = 72;
const SKB_DATA: i32 = 76;
const SKB_DATA_END: i32 = 80;
const SKB_FAMILY_TO_LOCAL_PORT: std::ops::RangeInclusive<i32> = 88..=139;
const SKB_DATA_META: i32 = 140;
const SKB_FLOW_KEYS: i32 = 144;
const SKB_TSTAMP: i32 = 152;
const SKB_WIRE_LEN: i32 = 160;
const SKB_SK: i32 = 168;
const SKB_TSTAMP_TYPE: i32 = 180;
const SKB_PADDING: std::ops::RangeInclusive<i32> = 181..=183;
const SKB_HWTSTAMP: i32 = 184;

// Offsets inside `struct xdp_md`.
const XDP_DATA: i32 = 0;
const XDP_DATA_END: i32 = 4;
const XDP_DATA_META: i32 = 8;
const XDP_EGRESS_IFINDEX: i32 = 20;

/// Resolve a context read `[r1 + off]` of `size` bytes for `prog`.
///
/// The caller has already established that the base register holds the
/// context pointer (not a computed pointer beyond `reg->off`).
pub fn read(prog: ProgType, off: i32, size: u32) -> Result<CtxAccess, CtxError> {
    let Some(model) = prog.ctx_model() else {
        return Err(CtxError::Unmodeled("program type"));
    };
    match model {
        CtxModel::SocketFilter => skb_read(off, size, true),
        CtxModel::SchedCls => skb_read(off, size, false),
        CtxModel::Xdp => xdp_read(off, size),
        CtxModel::TracePoint => tracepoint_read(off, size),
    }
}

/// `sk_filter_is_valid_access` (socket_filter) and
/// `tc_cls_act_is_valid_access` (sched_cls/sched_act/cgroup_skb), both
/// falling through to `bpf_skb_is_valid_access`.
fn skb_read(off: i32, size: u32, socket_filter: bool) -> Result<CtxAccess, CtxError> {
    // bpf_skb_is_valid_access: off must be in the struct, aligned to size.
    if !(0..SK_BUFF_SIZE).contains(&off) || size == 0 || off % size as i32 != 0 {
        return Err(CtxError::Invalid);
    }
    // Pointer-typed fields. `data`/`data_end`/`data_meta` require the
    // 4-byte access (the `size != size_default` arm); `sk` is a 64-bit
    // pointer; `flow_keys` is rejected outright.
    match off {
        SKB_DATA => {
            return if size == 4 {
                Err(CtxError::Unmodeled("__sk_buff.data"))
            } else {
                Err(CtxError::Invalid)
            };
        }
        SKB_DATA_END => {
            return if size == 4 {
                Err(CtxError::Unmodeled("__sk_buff.data_end"))
            } else {
                Err(CtxError::Invalid)
            };
        }
        SKB_DATA_META => {
            return if size == 4 {
                Err(CtxError::Unmodeled("__sk_buff.data_meta"))
            } else {
                Err(CtxError::Invalid)
            };
        }
        SKB_FLOW_KEYS => return Err(CtxError::Invalid),
        SKB_SK => {
            return if size == 8 {
                Err(CtxError::Unmodeled("__sk_buff.sk"))
            } else {
                Err(CtxError::Invalid)
            };
        }
        _ => {}
    }
    if socket_filter {
        // sk_filter_is_valid_access rejects these offsets.
        if off == SKB_TC_CLASSID {
            return Err(CtxError::Invalid);
        }
        if SKB_FAMILY_TO_LOCAL_PORT.contains(&off) {
            return Err(CtxError::Invalid);
        }
        if matches!(off, SKB_TSTAMP | SKB_WIRE_LEN | SKB_HWTSTAMP) {
            return Err(CtxError::Invalid);
        }
    } else {
        // tc_cls_act_is_valid_access rejects the socket-only block.
        if SKB_FAMILY_TO_LOCAL_PORT.contains(&off) {
            return Err(CtxError::Invalid);
        }
    }
    // `tstamp_type` is a one-byte field; padding after it is
    // explicitly rejected (`bpf_skb_is_valid_access`).
    if off == SKB_TSTAMP_TYPE {
        return if size == 1 && !socket_filter {
            Ok(CtxAccess::Scalar)
        } else {
            Err(CtxError::Invalid)
        };
    }
    if SKB_PADDING.contains(&off) {
        return Err(CtxError::Invalid);
    }
    // `tstamp`/`hwtstamp` are 64-bit fields (only reachable for the
    // tc-style types here; socket_filter rejected them above).
    if matches!(off, SKB_TSTAMP | SKB_HWTSTAMP) {
        return if size == 8 {
            Ok(CtxAccess::Scalar)
        } else {
            Err(CtxError::Invalid)
        };
    }
    // Narrow reads: bpf_ctx_narrow_access_ok keeps the access inside one
    // 32-bit word (`(off & 3) + size <= 4`).
    if size > 4 || (off % 4) + size as i32 > 4 {
        return Err(CtxError::Invalid);
    }
    Ok(CtxAccess::Scalar)
}

/// `__is_valid_xdp_access` + `xdp_is_valid_access` (`net/core/filter.c`).
fn xdp_read(off: i32, size: u32) -> Result<CtxAccess, CtxError> {
    if !(0..XDP_MD_SIZE).contains(&off) || off % size as i32 != 0 || size != 4 {
        return Err(CtxError::Invalid);
    }
    match off {
        XDP_DATA => Err(CtxError::Unmodeled("xdp_md.data")),
        XDP_DATA_END => Err(CtxError::Unmodeled("xdp_md.data_end")),
        XDP_DATA_META => Err(CtxError::Unmodeled("xdp_md.data_meta")),
        // Only reachable with `expected_attach_type = BPF_XDP_DEVMAP`,
        // which the model does not carry; treat it as a gap.
        XDP_EGRESS_IFINDEX => Err(CtxError::Unmodeled("xdp_md.egress_ifindex")),
        _ => Ok(CtxAccess::Scalar),
    }
}

/// `tp_prog_is_valid_access` (`kernel/trace/bpf_trace.c`): reads only,
/// `off >= sizeof(void *)`, `off < PERF_MAX_TRACE_SIZE`, aligned.
fn tracepoint_read(off: i32, size: u32) -> Result<CtxAccess, CtxError> {
    let valid_size = matches!(size, 1 | 2 | 4 | 8);
    if !(8..PERF_MAX_TRACE_SIZE).contains(&off) || !valid_size || off % size as i32 != 0 {
        return Err(CtxError::Invalid);
    }
    Ok(CtxAccess::Scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skb_scalar_fields_and_narrow_reads() {
        // u32 fields plus narrow reads inside their word.
        for (off, size) in [(0, 4), (4, 2), (4, 2), (8, 4), (12, 1), (66, 2), (68, 4)] {
            assert_eq!(
                read(ProgType::SchedCls, off, size),
                Ok(CtxAccess::Scalar),
                "off {off} size {size}"
            );
        }
        // 64-bit fields.
        assert_eq!(
            read(ProgType::SchedCls, SKB_TSTAMP, 8),
            Ok(CtxAccess::Scalar)
        );
        assert_eq!(
            read(ProgType::SchedCls, SKB_HWTSTAMP, 8),
            Ok(CtxAccess::Scalar)
        );
        // cross-word and out-of-range accesses
        assert_eq!(
            read(ProgType::SchedCls, 6, 4),
            Err(CtxError::Invalid),
            "crosses a word boundary"
        );
        assert_eq!(read(ProgType::SchedCls, 192, 4), Err(CtxError::Invalid));
        assert_eq!(read(ProgType::SchedCls, -4, 4), Err(CtxError::Invalid));
    }

    #[test]
    fn skb_pointer_fields_are_surface_gaps() {
        assert_eq!(
            read(ProgType::SchedCls, SKB_DATA, 4),
            Err(CtxError::Unmodeled("__sk_buff.data"))
        );
        assert_eq!(
            read(ProgType::SchedCls, SKB_DATA_END, 4),
            Err(CtxError::Unmodeled("__sk_buff.data_end"))
        );
        assert_eq!(
            read(ProgType::SchedCls, SKB_SK, 8),
            Err(CtxError::Unmodeled("__sk_buff.sk"))
        );
        // flow_keys is never accessible
        assert_eq!(
            read(ProgType::SchedCls, SKB_FLOW_KEYS, 8),
            Err(CtxError::Invalid)
        );
        // pointer fields demand their natural width
        assert_eq!(
            read(ProgType::SchedCls, SKB_DATA, 8),
            Err(CtxError::Invalid)
        );
    }

    #[test]
    fn socket_filter_has_its_own_rejections() {
        // tc_classid, the socket-only block, tstamp/wire_len/hwtstamp
        assert_eq!(
            read(ProgType::SocketFilter, SKB_TC_CLASSID, 4),
            Err(CtxError::Invalid)
        );
        assert_eq!(read(ProgType::SocketFilter, 88, 4), Err(CtxError::Invalid));
        assert_eq!(
            read(ProgType::SocketFilter, SKB_TSTAMP, 8),
            Err(CtxError::Invalid)
        );
        // ... while sched_cls accepts the same offsets
        assert_eq!(
            read(ProgType::SchedCls, SKB_TC_CLASSID, 4),
            Ok(CtxAccess::Scalar)
        );
        assert_eq!(
            read(ProgType::SchedCls, SKB_TSTAMP, 8),
            Ok(CtxAccess::Scalar)
        );
        // tstamp_type: one byte for sched_cls, invalid for socket_filter
        assert_eq!(
            read(ProgType::SchedCls, SKB_TSTAMP_TYPE, 1),
            Ok(CtxAccess::Scalar)
        );
        assert_eq!(
            read(ProgType::SchedCls, SKB_TSTAMP_TYPE, 4),
            Err(CtxError::Invalid)
        );
        assert_eq!(
            read(ProgType::SocketFilter, SKB_TSTAMP_TYPE, 1),
            Err(CtxError::Invalid)
        );
    }

    #[test]
    fn xdp_reads() {
        assert_eq!(read(ProgType::Xdp, 12, 4), Ok(CtxAccess::Scalar));
        assert_eq!(read(ProgType::Xdp, 16, 4), Ok(CtxAccess::Scalar));
        assert_eq!(
            read(ProgType::Xdp, XDP_DATA, 4),
            Err(CtxError::Unmodeled("xdp_md.data"))
        );
        assert_eq!(
            read(ProgType::Xdp, XDP_EGRESS_IFINDEX, 4),
            Err(CtxError::Unmodeled("xdp_md.egress_ifindex"))
        );
        // only 32-bit reads, inside the struct
        assert_eq!(read(ProgType::Xdp, 12, 2), Err(CtxError::Invalid));
        assert_eq!(read(ProgType::Xdp, 24, 4), Err(CtxError::Invalid));
    }

    #[test]
    fn tracepoint_reads() {
        assert_eq!(read(ProgType::TracePoint, 8, 8), Ok(CtxAccess::Scalar));
        assert_eq!(read(ProgType::TracePoint, 16, 4), Ok(CtxAccess::Scalar));
        assert_eq!(read(ProgType::TracePoint, 1_000, 8), Ok(CtxAccess::Scalar));
        // off < sizeof(void *) and unaligned reads are rejected
        assert_eq!(read(ProgType::TracePoint, 0, 8), Err(CtxError::Invalid));
        assert_eq!(read(ProgType::TracePoint, 12, 8), Err(CtxError::Invalid));
        assert_eq!(read(ProgType::TracePoint, 8192, 8), Err(CtxError::Invalid));
        assert_eq!(read(ProgType::TracePoint, 16, 16), Err(CtxError::Invalid));
    }

    #[test]
    fn unmodelled_prog_types_report_the_type_gap() {
        assert_eq!(
            read(ProgType::SkLookup, 0, 4),
            Err(CtxError::Unmodeled("program type"))
        );
    }
}
