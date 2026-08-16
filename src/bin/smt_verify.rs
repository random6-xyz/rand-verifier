//! smt_verify: bounded soundness runs over the abstract operators and
//! the violation catalog (issue #116).
//!
//! Runs every operator in scope through the soundness harness
//! (src/smt): exhaustive checks on small bit-widths, symbolic 64-bit
//! checks through z3, and randomized 64-bit checks. A non-empty
//! violation catalog exits 1 — every entry is operator, input class,
//! and a reproducible counterexample.
//!
//! ```sh
//! smt_verify                          # full run, catalog to stdout
//! smt_verify --catalog /tmp/cat.txt   # write the catalog to a file
//! ```

use std::path::PathBuf;
use std::process;

use rand_verifier::smt::verify::{
    RangeOp, TnumConcreteOp, exhaustive_range_binary, exhaustive_tnum_binary, exhaustive_tnum_mul,
    random_range_binary, random_tnum_mul, render_catalog, symbolic_range_binary,
    symbolic_tnum_binary, symbolic_tnum_shifts,
};

fn main() {
    let mut catalog_path: Option<PathBuf> = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--catalog" => {
                catalog_path = it.next().map(PathBuf::from);
            }
            "--help" | "-h" => {
                eprintln!("usage: smt_verify [--catalog <path>]");
                process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(2);
            }
        }
    }

    let mut violations = Vec::new();

    // tnum binary operators: exhaustive 4-bit + 6-bit (bounded), and
    // symbolic 64-bit rounds
    for op in [
        TnumConcreteOp::Add,
        TnumConcreteOp::Sub,
        TnumConcreteOp::Xor,
        TnumConcreteOp::And,
        TnumConcreteOp::Or,
    ] {
        violations.extend(exhaustive_tnum_binary(op, 4));
        violations.extend(exhaustive_tnum_binary(op, 6));
        violations.extend(symbolic_tnum_binary(op, 20));
    }
    // tnum shifts: every constant amount, symbolic 64-bit
    violations.extend(symbolic_tnum_shifts(20));
    // tnum_mul: exhaustive 4-bit + randomized 64-bit
    violations.extend(exhaustive_tnum_mul(4));
    violations.extend(random_tnum_mul(2000, 8));

    // range operators: exhaustive 4-bit, symbolic add/sub rounds,
    // randomized 64-bit
    for op in [RangeOp::Add, RangeOp::Sub, RangeOp::Mul] {
        violations.extend(exhaustive_range_binary(op, 4));
    }
    violations.extend(symbolic_range_binary(RangeOp::Add, 5));
    violations.extend(symbolic_range_binary(RangeOp::Sub, 5));
    for op in [RangeOp::Add, RangeOp::Sub, RangeOp::Mul] {
        violations.extend(random_range_binary(op, 2000, 16));
    }

    let catalog = render_catalog(&violations);
    match &catalog_path {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &catalog) {
                eprintln!("cannot write catalog: {e}");
                process::exit(2);
            }
            println!("violation catalog written to {}", path.display());
        }
        None => print!("{catalog}"),
    }
    if !violations.is_empty() {
        eprintln!("{} violation(s) found", violations.len());
        process::exit(1);
    }
    println!("all operators sound");
}
