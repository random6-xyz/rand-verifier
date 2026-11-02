//! BPF program types (#135).
//!
//! The verifier's context-access rules are program-type specific: the same
//! `ldx [r1 + off]` is a valid `__sk_buff` field for sched_cls and an
//! invalid access for xdp. The model carries the type per program so the
//! context tables in [`crate::ctx`] can answer the access question the way
//! the kernel's `is_valid_access` op does.

use std::fmt;

/// The subset of `enum bpf_prog_type` the model names (the numbers are
/// the kernel ABI values from `include/uapi/linux/bpf.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgType {
    /// `BPF_PROG_TYPE_SOCKET_FILTER` (1). The historical default of the
    /// corpus: programs loaded without an explicit type.
    #[default]
    SocketFilter,
    Kprobe,
    SchedCls,
    SchedAct,
    TracePoint,
    Xdp,
    PerfEvent,
    CgroupSkb,
    CgroupSock,
    SockOps,
    SkSkb,
    CgroupDevice,
    RawTracePoint,
    CgroupSockAddr,
    CgroupSysctl,
    CgroupSockopt,
    Tracing,
    Ext,
    Lsm,
    SkLookup,
    Syscall,
    /// A type the model does not name (kept as its ABI number so the
    /// report can show it).
    Other(u32),
}

impl ProgType {
    /// The ABI number (`enum bpf_prog_type`).
    pub fn id(self) -> u32 {
        match self {
            ProgType::SocketFilter => 1,
            ProgType::Kprobe => 2,
            ProgType::SchedCls => 3,
            ProgType::SchedAct => 4,
            ProgType::TracePoint => 5,
            ProgType::Xdp => 6,
            ProgType::PerfEvent => 7,
            ProgType::CgroupSkb => 8,
            ProgType::CgroupSock => 9,
            ProgType::SockOps => 13,
            ProgType::SkSkb => 14,
            ProgType::CgroupDevice => 15,
            ProgType::RawTracePoint => 17,
            ProgType::CgroupSockAddr => 18,
            ProgType::CgroupSysctl => 23,
            ProgType::CgroupSockopt => 25,
            ProgType::Tracing => 26,
            ProgType::Ext => 28,
            ProgType::Lsm => 29,
            ProgType::SkLookup => 30,
            ProgType::Syscall => 31,
            ProgType::Other(id) => id,
        }
    }

    /// Decode an ABI number; unlisted values stay as [`ProgType::Other`].
    pub fn from_id(id: u32) -> Self {
        match id {
            1 => ProgType::SocketFilter,
            2 => ProgType::Kprobe,
            3 => ProgType::SchedCls,
            4 => ProgType::SchedAct,
            5 => ProgType::TracePoint,
            6 => ProgType::Xdp,
            7 => ProgType::PerfEvent,
            8 => ProgType::CgroupSkb,
            9 => ProgType::CgroupSock,
            13 => ProgType::SockOps,
            14 => ProgType::SkSkb,
            15 => ProgType::CgroupDevice,
            17 => ProgType::RawTracePoint,
            18 => ProgType::CgroupSockAddr,
            23 => ProgType::CgroupSysctl,
            25 => ProgType::CgroupSockopt,
            26 => ProgType::Tracing,
            28 => ProgType::Ext,
            29 => ProgType::Lsm,
            30 => ProgType::SkLookup,
            31 => ProgType::Syscall,
            other => ProgType::Other(other),
        }
    }

    /// Parse the corpus/agent spelling: `BPF_PROG_TYPE_SCHED_CLS`,
    /// `sched_cls`, `sched-cls` or the bare number.
    pub fn parse(value: &str) -> Option<Self> {
        let v = value.trim();
        if let Ok(id) = v.parse::<u32>() {
            return Some(Self::from_id(id));
        }
        let name = v
            .strip_prefix("BPF_PROG_TYPE_")
            .or_else(|| v.strip_prefix("prog_type="))
            .unwrap_or(v)
            .to_ascii_uppercase()
            .replace('-', "_");
        Some(match name.as_str() {
            "SOCKET_FILTER" | "SOCKETFILTER" => ProgType::SocketFilter,
            "KPROBE" => ProgType::Kprobe,
            "SCHED_CLS" | "SCHEDCLS" => ProgType::SchedCls,
            "SCHED_ACT" | "SCHEDACT" => ProgType::SchedAct,
            "TRACEPOINT" => ProgType::TracePoint,
            "XDP" => ProgType::Xdp,
            "PERF_EVENT" | "PERFEVENT" => ProgType::PerfEvent,
            "CGROUP_SKB" => ProgType::CgroupSkb,
            "CGROUP_SOCK" => ProgType::CgroupSock,
            "SOCK_OPS" => ProgType::SockOps,
            "SK_SKB" => ProgType::SkSkb,
            "CGROUP_DEVICE" => ProgType::CgroupDevice,
            "RAW_TRACEPOINT" => ProgType::RawTracePoint,
            "CGROUP_SOCK_ADDR" => ProgType::CgroupSockAddr,
            "CGROUP_SYSCTL" => ProgType::CgroupSysctl,
            "CGROUP_SOCKOPT" => ProgType::CgroupSockopt,
            "TRACING" => ProgType::Tracing,
            "EXT" => ProgType::Ext,
            "LSM" => ProgType::Lsm,
            "SK_LOOKUP" => ProgType::SkLookup,
            "SYSCALL" => ProgType::Syscall,
            _ => return None,
        })
    }

    /// The `BPF_PROG_TYPE_*` spelling used by the corpus manifest and the
    /// kernel logs.
    pub fn name(self) -> &'static str {
        match self {
            ProgType::SocketFilter => "BPF_PROG_TYPE_SOCKET_FILTER",
            ProgType::Kprobe => "BPF_PROG_TYPE_KPROBE",
            ProgType::SchedCls => "BPF_PROG_TYPE_SCHED_CLS",
            ProgType::SchedAct => "BPF_PROG_TYPE_SCHED_ACT",
            ProgType::TracePoint => "BPF_PROG_TYPE_TRACEPOINT",
            ProgType::Xdp => "BPF_PROG_TYPE_XDP",
            ProgType::PerfEvent => "BPF_PROG_TYPE_PERF_EVENT",
            ProgType::CgroupSkb => "BPF_PROG_TYPE_CGROUP_SKB",
            ProgType::CgroupSock => "BPF_PROG_TYPE_CGROUP_SOCK",
            ProgType::SockOps => "BPF_PROG_TYPE_SOCK_OPS",
            ProgType::SkSkb => "BPF_PROG_TYPE_SK_SKB",
            ProgType::CgroupDevice => "BPF_PROG_TYPE_CGROUP_DEVICE",
            ProgType::RawTracePoint => "BPF_PROG_TYPE_RAW_TRACEPOINT",
            ProgType::CgroupSockAddr => "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
            ProgType::CgroupSysctl => "BPF_PROG_TYPE_CGROUP_SYSCTL",
            ProgType::CgroupSockopt => "BPF_PROG_TYPE_CGROUP_SOCKOPT",
            ProgType::Tracing => "BPF_PROG_TYPE_TRACING",
            ProgType::Ext => "BPF_PROG_TYPE_EXT",
            ProgType::Lsm => "BPF_PROG_TYPE_LSM",
            ProgType::SkLookup => "BPF_PROG_TYPE_SK_LOOKUP",
            ProgType::Syscall => "BPF_PROG_TYPE_SYSCALL",
            ProgType::Other(_) => "BPF_PROG_TYPE_UNKNOWN",
        }
    }

    /// The context model of [`crate::ctx`] this type uses, if modelled.
    pub fn ctx_model(self) -> Option<crate::ctx::CtxModel> {
        use crate::ctx::CtxModel;
        match self {
            // `bpf_skb_is_valid_access` backs these four types
            // (sk_filter_is_valid_access adds its own rejections).
            ProgType::SocketFilter => Some(CtxModel::SocketFilter),
            ProgType::SchedCls | ProgType::SchedAct | ProgType::CgroupSkb => {
                Some(CtxModel::SchedCls)
            }
            ProgType::Xdp => Some(CtxModel::Xdp),
            ProgType::TracePoint => Some(CtxModel::TracePoint),
            _ => None,
        }
    }
}

impl fmt::Display for ProgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgType::Other(id) => write!(f, "BPF_PROG_TYPE_{id}"),
            other => f.write_str(other.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_corpus_spellings() {
        assert_eq!(
            ProgType::parse("BPF_PROG_TYPE_SCHED_CLS"),
            Some(ProgType::SchedCls)
        );
        assert_eq!(ProgType::parse("xdp"), Some(ProgType::Xdp));
        assert_eq!(ProgType::parse("tracepoint"), Some(ProgType::TracePoint));
        assert_eq!(ProgType::parse("3"), Some(ProgType::SchedCls));
        assert_eq!(ProgType::parse("nonsense"), None);
        assert_eq!(
            ProgType::parse("BPF_PROG_TYPE_SK_LOOKUP"),
            Some(ProgType::SkLookup)
        );
    }

    #[test]
    fn id_round_trip() {
        for ty in [
            ProgType::SocketFilter,
            ProgType::SchedCls,
            ProgType::Xdp,
            ProgType::TracePoint,
            ProgType::CgroupSkb,
            ProgType::SkLookup,
            ProgType::Tracing,
        ] {
            assert_eq!(ProgType::from_id(ty.id()), ty);
            assert!(ProgType::parse(ty.name()).is_some());
        }
        assert_eq!(ProgType::from_id(99), ProgType::Other(99));
        assert_eq!(ProgType::Other(99).to_string(), "BPF_PROG_TYPE_99");
    }

    #[test]
    fn only_the_modelled_types_have_a_ctx_model() {
        assert!(ProgType::SocketFilter.ctx_model().is_some());
        assert!(ProgType::SchedCls.ctx_model().is_some());
        assert!(ProgType::Xdp.ctx_model().is_some());
        assert!(ProgType::TracePoint.ctx_model().is_some());
        assert!(ProgType::SkLookup.ctx_model().is_none());
        assert!(ProgType::Tracing.ctx_model().is_none());
    }
}
