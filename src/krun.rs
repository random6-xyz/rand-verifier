// ── Kernel-side loading via the raw bpf() syscall (issues #59/#60) ──────────

use crate::klog::{ReasonCategory, categorize_reason, parse_verifier_log};

const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// 1 MiB verifier log buffer, like libbpf's default.
pub const LOG_BUF_SIZE: usize = 1 << 20;

/// `_LINUX_CAPABILITY_VERSION_3` (linux/capability.h).
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// CAP_PERFMON (linux/capability.h): the capability that makes the
/// kernel verifier lenient — `allow_uninit_stack` and `allow_ptr_leaks`
/// are both `bpf_token_capable(token, CAP_PERFMON)`
/// (include/linux/bpf.h).
const CAP_PERFMON: u32 = 38;

/// The outcome of loading a program into the real kernel verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelOutcome {
    /// The kernel verifier accepted the program.
    Accept,
    /// The kernel verifier rejected it; the reason is parsed from the
    /// verifier log.
    Reject {
        insn_idx: u32,
        message: String,
        category: ReasonCategory,
    },
    /// The load was not permitted (EPERM) — a privilege problem, not a
    /// verdict.
    Privilege,
    /// The kernel rejected the load with `errno` but the verifier log
    /// contained no error line (log truncated, or a non-verifier error).
    NoErrorLine { errno: i32 },
    /// The program could not even be prepared (empty, or not a multiple
    /// of 8 bytes).
    InvalidProgram,
}

/// The BPF_PROG_LOAD attributes, in the kernel UAPI `union bpf_attr`
/// layout: only the fields of a plain load. The kernel zero-initializes
/// its own copy and reads `size` bytes (verified against
/// kernel/bpf/syscall.c), so the fields beyond this struct (BTF, line
/// info, ...) are zero = "not provided".
#[repr(C)]
#[derive(Default)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
}

/// Raw `bpf(BPF_PROG_LOAD, ...)` syscall. `log_buf` receives the
/// verifier log. Returns the program fd, or the errno.
fn bpf_prog_load(insns: &[u8], log_buf: &mut [u8]) -> Result<i32, i32> {
    let mut attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
        insn_cnt: (insns.len() / 8) as u32,
        insns: insns.as_ptr() as u64,
        license: c"GPL".as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_LOAD as libc::c_int,
            &mut attr as *mut BpfProgLoadAttr as *mut libc::c_void,
            std::mem::size_of::<BpfProgLoadAttr>(),
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    } else {
        Ok(ret as i32)
    }
}

/// The NUL-terminated verifier log from the buffer.
fn log_text(log_buf: &[u8]) -> String {
    let end = log_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(log_buf.len());
    String::from_utf8_lossy(&log_buf[..end]).into_owned()
}

/// Drop CAP_PERFMON from the process so the kernel verifier applies its
/// strict rules: `allow_uninit_stack` and `allow_ptr_leaks` are false
/// for loaders without CAP_PERFMON (bpf_allow_uninit_stack /
/// bpf_allow_ptr_leaks in include/linux/bpf.h). Loading keeps working —
/// bpf_net_capable() needs only CAP_NET_ADMIN or CAP_SYS_ADMIN.
///
/// Returns a diagnostic message, or an error when the capability could
/// not be dropped.
pub fn drop_cap_perfmon() -> Result<String, String> {
    #[repr(C)]
    #[derive(Default)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default, Copy, Clone)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2]; // caps 0..31, 32..63
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader as *mut libc::c_void,
            data.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!(
            "capget failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let idx = (CAP_PERFMON / 32) as usize;
    let bit = 1u32 << (CAP_PERFMON % 32);
    let had_effective = data[idx].effective & bit != 0;
    let had_permitted = data[idx].permitted & bit != 0;
    data[idx].effective &= !bit;
    data[idx].permitted &= !bit;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapHeader as *const libc::c_void,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        return Err(format!(
            "capset failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // verify the drop took effect
    let mut after = [CapData::default(); 2];
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader as *mut libc::c_void,
            after.as_mut_ptr() as *mut libc::c_void,
        )
    };
    let gone = ret == 0 && after[idx].effective & bit == 0;
    if had_effective && !gone {
        Err("CAP_PERFMON still present after capset".to_string())
    } else if !had_effective && !had_permitted {
        Ok("CAP_PERFMON was not present in the process caps".to_string())
    } else {
        Ok("CAP_PERFMON dropped".to_string())
    }
}

/// Load a raw eBPF program (kernel `struct bpf_insn` encoding) into the
/// kernel verifier and classify the outcome.
///
/// Loading is privileged on most systems
/// (`kernel.unprivileged_bpf_disabled = 2`): without root / CAP_BPF the
/// outcome is [`KernelOutcome::Privilege`].
pub fn load_with_kernel(insns: &[u8]) -> KernelOutcome {
    load_with_kernel_verbose(insns).0
}

/// [`load_with_kernel`] plus the raw verifier log (diagnostics).
pub fn load_with_kernel_verbose(insns: &[u8]) -> (KernelOutcome, String) {
    if insns.is_empty() || !insns.len().is_multiple_of(8) {
        return (KernelOutcome::InvalidProgram, String::new());
    }
    let mut log_buf = vec![0u8; LOG_BUF_SIZE];
    let outcome = match bpf_prog_load(insns, &mut log_buf) {
        Ok(fd) => {
            // the fd is only a proof of acceptance — nothing to attach
            unsafe { libc::close(fd) };
            KernelOutcome::Accept
        }
        Err(errno) => {
            if errno == libc::EPERM {
                KernelOutcome::Privilege
            } else {
                let log = log_text(&log_buf);
                match parse_verifier_log(&log) {
                    Some((insn_idx, message)) => KernelOutcome::Reject {
                        insn_idx,
                        category: categorize_reason(&message),
                        message,
                    },
                    None => KernelOutcome::NoErrorLine { errno },
                }
            }
        }
    };
    (outcome, log_text(&log_buf))
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // real-encoding programs: r0 = 0; exit
    const MINIMAL_EXIT: [u8; 16] = [
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    // call unknown#99; exit — every kernel rejects this
    const UNKNOWN_HELPER: [u8; 16] = [
        0x85, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, // call 99
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    /// Smoke tests against the real kernel: skipped (not failed) when
    /// the bpf() syscall is not permitted — on privileged hosts (CI
    /// root runner, sudo) they assert the kernel behavior itself.

    #[test]
    fn kernel_load_accept_smoke() {
        match load_with_kernel(&MINIMAL_EXIT) {
            KernelOutcome::Privilege => {
                eprintln!("skipped: the bpf() syscall is not permitted here")
            }
            KernelOutcome::Accept => {}
            other => panic!("expected accept, got {:?}", other),
        }
    }

    #[test]
    fn kernel_load_reject_smoke() {
        match load_with_kernel(&UNKNOWN_HELPER) {
            KernelOutcome::Privilege => {
                eprintln!("skipped: the bpf() syscall is not permitted here")
            }
            KernelOutcome::Reject {
                insn_idx, category, ..
            } => {
                assert_eq!(insn_idx, 0);
                assert_eq!(category, ReasonCategory::HelperArgs);
            }
            other => panic!("expected reject, got {:?}", other),
        }
    }

    #[test]
    fn kernel_load_invalid_program() {
        assert_eq!(load_with_kernel(&[]), KernelOutcome::InvalidProgram);
        assert_eq!(load_with_kernel(&[0u8, 1u8]), KernelOutcome::InvalidProgram);
    }
}
