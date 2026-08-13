//! kernel-runner: load an eBPF program into the real Linux kernel
//! verifier via the raw `bpf()` syscall — no libbpf dependency
//! (issue #59).
//!
//! Usage:
//!
//! ```sh
//! kernel_run <program-file>   # verify one program
//! kernel_run --all            # verify every tests/programs corpus program
//! ```
//!
//! Loading is privileged on most systems
//! (`kernel.unprivileged_bpf_disabled = 2`): run as root / with CAP_BPF,
//! e.g. `sudo target/debug/kernel_run --all`.

use std::env;
use std::fs;
use std::mem;
use std::os::raw::{c_int, c_void};
use std::path::{Path, PathBuf};
use std::process;

use rand_verifier::insn::{disassemble, parse_insn};
use rand_verifier::klog::{ReasonCategory, categorize_reason, parse_verifier_log};

const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// 1 MiB verifier log buffer, like libbpf's default.
const LOG_BUF_SIZE: usize = 1 << 20;

/// The BPF_PROG_LOAD attributes, in the kernel UAPI `union bpf_attr`
/// layout: only the fields of a plain load. The kernel zero-initializes
/// its own copy and reads `size` bytes, so the fields beyond this
/// struct (BTF, line info, ...) are zero = "not provided".
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
            BPF_PROG_LOAD as c_int,
            &mut attr as *mut BpfProgLoadAttr as *mut c_void,
            mem::size_of::<BpfProgLoadAttr>(),
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

/// Print the disassembly of a program (decode errors are shown inline —
/// the kernel would reject them as "unknown opcode").
fn print_program(insns: &[u8]) {
    for (i, chunk) in insns.chunks_exact(8).enumerate() {
        match parse_insn(chunk) {
            Ok(insn) => println!("{:4}: {}", i, disassemble(&insn)),
            Err(e) => println!("{:4}: <{}>", i, e),
        }
    }
}

/// Load one program and print the outcome: ACCEPT / REJECT (+ reason
/// category) / privileged-load failure.
fn run_program(path: &Path, verbose: bool) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            println!("{}: cannot read: {}", path.display(), e);
            return;
        }
    };
    if data.is_empty() || data.len() % 8 != 0 {
        println!(
            "{}: not a valid program (empty or not a multiple of 8 bytes)",
            path.display()
        );
        return;
    }

    if verbose {
        print_program(&data);
    }

    let mut log_buf = vec![0u8; LOG_BUF_SIZE];
    match bpf_prog_load(&data, &mut log_buf) {
        Ok(fd) => {
            // the fd is only a proof of acceptance — nothing to attach
            unsafe { libc::close(fd) };
            println!("{}: ACCEPT", path.display());
        }
        Err(errno) => {
            if errno == libc::EPERM {
                println!(
                    "{}: EPERM — the bpf() syscall is not permitted (run as root / with CAP_BPF, or enable unprivileged BPF)",
                    path.display()
                );
                return;
            }
            let log = log_text(&log_buf);
            match parse_verifier_log(&log) {
                Some((insn_idx, message)) => {
                    let category = categorize_reason(&message);
                    println!(
                        "{}: REJECT at insn {}: {} [{}]",
                        path.display(),
                        insn_idx,
                        message,
                        category_name(category)
                    );
                    if verbose {
                        println!("--- verifier log ---");
                        println!("{}", log);
                    }
                }
                None => {
                    println!(
                        "{}: REJECT errno {} (no error line in the verifier log)",
                        path.display(),
                        errno
                    );
                    if verbose {
                        println!("--- verifier log ---");
                        println!("{}", log);
                    }
                }
            }
        }
    }
}

fn category_name(category: ReasonCategory) -> &'static str {
    match category {
        ReasonCategory::UninitRead => "UninitRead",
        ReasonCategory::StackBounds => "StackBounds",
        ReasonCategory::StackAlign => "StackAlign",
        ReasonCategory::PointerArith => "PointerArith",
        ReasonCategory::HelperArgs => "HelperArgs",
        ReasonCategory::CfgJump => "CfgJump",
        ReasonCategory::Loop => "Loop",
        ReasonCategory::Unreachable => "Unreachable",
        ReasonCategory::ExitR0 => "ExitR0",
        ReasonCategory::Complexity => "Complexity",
        ReasonCategory::Other => "Other",
    }
}

/// All corpus programs, accept first then reject (the #60 diff input).
fn corpus_programs() -> Vec<PathBuf> {
    let mut programs = Vec::new();
    for sub in ["accept", "reject"] {
        let dir = Path::new("tests/programs").join(sub);
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_none())
            .collect();
        entries.sort();
        programs.extend(entries);
    }
    programs
}

fn usage() -> ! {
    eprintln!(
        "Usage: kernel_run <program-file> | kernel_run --all\n\
         Loads an eBPF program into the kernel verifier via the raw bpf() syscall.\n\
         Requires root / CAP_BPF on systems with unprivileged BPF disabled."
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--all") => {
            for path in corpus_programs() {
                run_program(&path, false);
            }
        }
        Some(path) => run_program(Path::new(path), true),
        None => usage(),
    }
}
