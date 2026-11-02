//! TEMP analysis bin (not for commit): re-run the spec on raw prog.bin
//! files and print the SpecVerdict including the rejection reason.
//!
//! usage: cargo run --bin spec_repro -- <prog.bin> [<prog.bin> ...]

use std::collections::HashMap;
use std::fs;

fn main() {
    for path in std::env::args().skip(1) {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("{path}: read error: {e}");
                continue;
            }
        };
        let insns = match rand_verifier::insn::decode_program(&bytes) {
            Ok(i) => i,
            Err((idx, e)) => {
                println!("{path}: decode error at {idx}: {e}");
                continue;
            }
        };
        let maps: HashMap<u32, rand_verifier::env::MapInfo> = HashMap::new();
        let verdict = rand_verifier::spec::verify_spec(&insns, &maps);
        println!("{path}");
        match &verdict {
            rand_verifier::spec::SpecVerdict::Accept => println!("  spec: ACCEPT"),
            rand_verifier::spec::SpecVerdict::Reject(f) => {
                println!("  spec: REJECT pc={} {}", f.pc, f.message)
            }
            rand_verifier::spec::SpecVerdict::Inconclusive => println!("  spec: INCONCLUSIVE"),
        }
    }
}
