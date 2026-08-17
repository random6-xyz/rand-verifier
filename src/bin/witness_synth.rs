//! witness_synth: precision-witness synthesis (Differential Synthesis,
//! issue #117).
//!
//! Searches the operator space for abstract inputs where a
//! tnum-augmented candidate operator is strictly more precise than
//! the spec's interval-only operator, synthesizes a concrete eBPF
//! witness program per gap (the concrete members loaded into
//! registers), validates it through the mini verifier, and writes the
//! ranked candidate list.
//!
//! ```sh
//! witness_synth                      # ranked list to stdout
//! witness_synth --out-dir tests/data/witnesses   # programs + list
//! ```

use std::fs;
use std::path::PathBuf;
use std::process;

use rand_verifier::smt::synth::{
    PrecisionWitness, candidates, find_gaps, opcodes, render_ranked, witness_program,
};
use rand_verifier::spec::{rng_add, rng_and, rng_or, rng_sub, rng_xor};

struct Args {
    out_dir: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!("usage: witness_synth [--out-dir <dir>]");
    process::exit(2);
}

fn main() -> anyhow::Result<()> {
    let mut args = Args { out_dir: None };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--out-dir" => {
                args.out_dir = Some(it.next().map(PathBuf::from).unwrap_or_else(|| usage()))
            }
            "--help" | "-h" => {
                eprintln!("usage: witness_synth [--out-dir <dir>]");
                process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage();
            }
        }
    }

    // (operator, old fn, candidate fn, opcode) — the candidate
    // operators mirror the kernel's tnum-backed tracking
    type RangeFn = fn((u64, u64), (u64, u64)) -> (u64, u64);
    let searches: [(&str, RangeFn, RangeFn, u8); 5] = [
        ("xor", rng_xor, candidates::xor_tnum, opcodes::XOR),
        ("or", rng_or, candidates::or_tnum, opcodes::OR),
        ("and", rng_and, candidates::and_tnum, opcodes::AND),
        ("add", rng_add, candidates::add_tnum, opcodes::ADD),
        ("sub", rng_sub, candidates::sub_tnum, opcodes::SUB),
    ];

    let mut ranked: Vec<PrecisionWitness> = Vec::new();
    for (name, old, new, _opcode) in searches {
        // exhaustive 6-bit search + randomized 64-bit sampling
        let mut gaps = find_gaps(name, old, new, 6, 50);
        gaps.extend(find_gaps(name, old, new, 64, 50));
        ranked.extend(gaps);
    }
    // rank: the largest precision improvement first (width ratio)
    ranked.sort_by(|a, b| {
        let ra = a.old_width as f64 / a.new_width.max(1) as f64;
        let rb = b.old_width as f64 / b.new_width.max(1) as f64;
        rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked.truncate(20);

    let list = render_ranked(&ranked);
    println!("{list}");

    if let Some(dir) = &args.out_dir {
        fs::create_dir_all(dir)?;
        for (i, w) in ranked.iter().enumerate() {
            let opcode = match w.operator {
                "xor" => opcodes::XOR,
                "or" => opcodes::OR,
                "and" => opcodes::AND,
                "add" => opcodes::ADD,
                "sub" => opcodes::SUB,
                _ => unreachable!(),
            };
            let prog = witness_program(w, opcode);
            let stem = format!("{}-{}", w.operator, i + 1);
            fs::write(dir.join(format!("{stem}.bin")), &prog)?;
            let mut dump = String::new();
            for (idx, insn) in rand_verifier::insn::decode_program(&prog)
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                dump.push_str(&format!("{idx:4}: {insn:?}\n"));
            }
            fs::write(dir.join(format!("{stem}.dump")), dump)?;
        }
        // the ranked list alongside the programs
        fs::write(dir.join("ranked.txt"), &list)?;
        println!("witness programs written under {}", dir.display());
    }

    // validate every witness through the mini verifier: a sound
    // witness program must be accepted
    let mut rejected = 0;
    for (i, w) in ranked.iter().enumerate() {
        let opcode = match w.operator {
            "xor" => opcodes::XOR,
            "or" => opcodes::OR,
            "and" => opcodes::AND,
            "add" => opcodes::ADD,
            "sub" => opcodes::SUB,
            _ => unreachable!(),
        };
        let prog = witness_program(w, opcode);
        let mut env = rand_verifier::env::BpfVerifierEnv::new();
        env.setup_prog_bytes(&prog)?;
        match env.verify() {
            Ok(rand_verifier::error::Verdict::Safe) => {}
            Ok(rand_verifier::error::Verdict::Unsafe(f)) => {
                eprintln!("witness {}-{} rejected: {}", w.operator, i + 1, f);
                rejected += 1;
            }
            Err(e) => {
                eprintln!("witness {}-{} verify error: {e}", w.operator, i + 1);
                rejected += 1;
            }
        }
    }
    if rejected > 0 {
        eprintln!("{rejected} witness program(s) rejected — reducer input issue");
        process::exit(1);
    }
    println!("all witnesses verified by mini");
    Ok(())
}
