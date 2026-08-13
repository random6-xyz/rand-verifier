//! diff: run every corpus program through rand-verifier and the real
//! kernel verifier and compare the verdicts (issue #60).
//!
//! ```sh
//! diff                # compare the whole corpus, print the table
//! diff --json out.json
//! ```
//!
//! Exit code: 1 when a non-whitelisted `kernel-accepts` finding exists
//! (a kernel precision candidate); 0 otherwise. The kernel side needs
//! root / CAP_BPF (run with sudo on hosts with unprivileged BPF
//! disabled).

use std::env;
use std::fs;
use std::path::Path;
use std::process;

use rand_verifier::diff::{DiffClass, SideVerdict, categorize_mini_reason, classify, whitelisted};
use rand_verifier::env::BpfVerifierEnv;
use rand_verifier::error::Verdict;
use rand_verifier::krun::{KernelOutcome, drop_cap_perfmon, load_with_kernel};

/// One compared program: the two verdicts plus the classification.
struct DiffEntry {
    name: String,
    mini: SideVerdict,
    mini_reason: Option<String>,
    kernel: SideVerdict,
    kernel_message: Option<String>,
    class: DiffClass,
    whitelisted: Option<&'static str>,
}

fn run_one(path: &Path) -> DiffEntry {
    let name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    // rand-verifier side
    let mut env = BpfVerifierEnv::new();
    env.setup_prog(path.to_string_lossy().into_owned())
        .unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    let (mini, mini_reason) = match env.verify().unwrap() {
        Verdict::Safe => (SideVerdict::Accept, None),
        Verdict::Unsafe(failure) => (
            SideVerdict::Reject {
                category: categorize_mini_reason(&failure),
            },
            Some(failure.message),
        ),
    };

    // kernel side
    let data = fs::read(path).unwrap();
    let (kernel, kernel_message) = match load_with_kernel(&data) {
        KernelOutcome::Accept => (SideVerdict::Accept, None),
        KernelOutcome::Reject {
            message, category, ..
        } => (SideVerdict::Reject { category }, Some(message)),
        KernelOutcome::Privilege => (SideVerdict::Skipped, Some("EPERM (privilege)".into())),
        KernelOutcome::NoErrorLine { errno } => (
            SideVerdict::Skipped,
            Some(format!("errno {} (no log line)", errno)),
        ),
        KernelOutcome::InvalidProgram => (SideVerdict::Skipped, Some("invalid program".into())),
    };

    let class = classify(&mini, &kernel);
    let whitelist = whitelisted(&name, &mini, &kernel);
    DiffEntry {
        name,
        mini,
        mini_reason,
        kernel,
        kernel_message,
        class,
        whitelisted: whitelist,
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let json_path = args
        .iter()
        .position(|a| a == "--json")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);

    // strict mode: drop CAP_PERFMON so the kernel verifier applies its
    // strict rules (allow_uninit_stack = false, no ptr-leak allowance)
    // — a like-for-like comparison with the rand-verifier side. Loading
    // still works with CAP_NET_ADMIN/CAP_SYS_ADMIN only.
    if unsafe { libc::geteuid() } == 0 {
        match drop_cap_perfmon() {
            Ok(msg) => eprintln!("strict mode: {}", msg),
            Err(e) => eprintln!("strict mode: {}", e),
        }
    }

    let mut entries = Vec::new();
    for sub in ["accept", "reject"] {
        let dir = Path::new("tests/programs").join(sub);
        let mut paths: Vec<_> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {}", dir.display(), e))
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_none())
            .collect();
        paths.sort();
        for path in paths {
            entries.push(run_one(&path));
        }
    }

    // ── table ───────────────────────────────────────────────────────────────
    println!(
        "{:<38} {:<8} {:<10} {:<8} {:<10} class",
        "program", "mini", "mini-reason", "kernel", "kernel-reason"
    );
    let mut counts = [0usize; 5]; // match, match-reject, kernel-stricter, kernel-accepts, skipped
    for e in &entries {
        let idx = match e.class {
            DiffClass::Match => 0,
            DiffClass::MatchReject => 1,
            DiffClass::KernelStricter => 2,
            DiffClass::KernelAccepts => 3,
            DiffClass::Skipped => 4,
        };
        counts[idx] += 1;
        let mini_reason = e
            .mini_reason
            .as_deref()
            .map(|r| r.split(' ').next().unwrap_or(""))
            .unwrap_or("-");
        let kernel_reason = e
            .kernel_message
            .as_deref()
            .map(|r| r.split(' ').next().unwrap_or(""))
            .unwrap_or("-");
        let star = if e.class == DiffClass::KernelAccepts && e.whitelisted.is_none() {
            " *"
        } else {
            ""
        };
        println!(
            "{:<38} {:<8} {:<10} {:<8} {:<10} {}{}",
            e.name,
            e.mini.name(),
            mini_reason,
            e.kernel.name(),
            kernel_reason,
            e.class.name(),
            star
        );
    }

    // ── summary ─────────────────────────────────────────────────────────────
    println!();
    println!(
        "{} match, {} match-reject, {} kernel-stricter, {} kernel-accepts, {} skipped",
        counts[0], counts[1], counts[2], counts[3], counts[4]
    );
    for e in &entries {
        if e.class == DiffClass::KernelAccepts {
            if let Some(reason) = e.whitelisted {
                println!("whitelisted: {} — {}", e.name, reason);
            } else {
                println!(
                    "FINDING: {} — kernel accepts, rand-verifier rejects",
                    e.name
                );
            }
        }
        if e.class == DiffClass::MatchReject {
            let mini_cat = match &e.mini {
                SideVerdict::Reject { category } => category,
                _ => unreachable!(),
            };
            let kernel_cat = match &e.kernel {
                SideVerdict::Reject { category } => category,
                _ => unreachable!(),
            };
            if mini_cat != kernel_cat {
                println!(
                    "reason mismatch: {} — mini {:?} vs kernel {:?}",
                    e.name, mini_cat, kernel_cat
                );
            }
        }
    }

    // ── JSON ────────────────────────────────────────────────────────────────
    if let Some(path) = json_path {
        let mut out = String::from("[\n");
        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                out.push_str(",\n");
            }
            let mini_cat = match &e.mini {
                SideVerdict::Reject { category } => format!("\"{:?}\"", category),
                _ => "null".to_string(),
            };
            let kernel_cat = match &e.kernel {
                SideVerdict::Reject { category } => format!("\"{:?}\"", category),
                _ => "null".to_string(),
            };
            let mini_reason = e
                .mini_reason
                .as_deref()
                .map(|r| format!("\"{}\"", json_escape(r)))
                .unwrap_or_else(|| "null".to_string());
            let kernel_message = e
                .kernel_message
                .as_deref()
                .map(|r| format!("\"{}\"", json_escape(r)))
                .unwrap_or_else(|| "null".to_string());
            let whitelisted = e
                .whitelisted
                .map(|r| format!("\"{}\"", json_escape(r)))
                .unwrap_or_else(|| "null".to_string());
            out.push_str(&format!(
                "  {{\"program\": \"{}\", \"mini_verdict\": \"{}\", \"mini_reason\": {}, \"mini_category\": {}, \"kernel_verdict\": \"{}\", \"kernel_message\": {}, \"kernel_category\": {}, \"class\": \"{}\", \"whitelisted\": {}}}",
                json_escape(&e.name),
                e.mini.name(),
                mini_reason,
                mini_cat,
                e.kernel.name(),
                kernel_message,
                kernel_cat,
                e.class.name(),
                whitelisted
            ));
        }
        out.push_str("\n]\n");
        fs::write(path, out).unwrap_or_else(|e| panic!("cannot write {}: {}", path, e));
        println!("\nreport written to {}", path);
    }

    // non-whitelisted kernel-accepts findings are the discovery contract
    let findings = entries
        .iter()
        .filter(|e| e.class == DiffClass::KernelAccepts && e.whitelisted.is_none())
        .count();
    if findings > 0 {
        process::exit(1);
    }
}
