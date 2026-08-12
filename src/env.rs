// ── BPF program loading and the verification environment ────────────────────

use std::fs;

use anyhow::Result;

use crate::cfg::{add_subprog, check_cfg};
use crate::error::Verdict;
use crate::insn::{BpfInsn, parse_insn};
use crate::mini::verify_mini;

/// A loaded BPF program: raw bytecode plus decoded instructions and
/// subprogram entry points.
#[derive(Default)]
pub(crate) struct BpfProg {
    name: String,
    location: String,
    raw_data: Vec<u8>,
    pub(crate) insns: Vec<BpfInsn>,
    subprogs: Vec<u32>,
    pub(crate) insn_cnt: u32,
}

/// The verifier environment: owns the loaded program and runs the
/// full verification pipeline on it.
#[derive(Default)]
pub struct BpfVerifierEnv {
    pub(crate) prog: BpfProg, // BPF program data
}

impl BpfVerifierEnv {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a BPF program from a binary file and return the instruction count.
    pub fn setup_prog(&mut self, name: String) -> Result<u32> {
        let raw_data =
            fs::read(&name).map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", name, e))?;

        if raw_data.len() % 8 != 0 {
            anyhow::bail!(
                "Invalid BPF program: size {} is not a multiple of 8",
                raw_data.len()
            );
        }

        if raw_data.is_empty() {
            anyhow::bail!("BPF program is empty");
        }

        let insn_cnt = (raw_data.len() / 8) as u32;

        let insns: Vec<BpfInsn> = raw_data.chunks_exact(8).map(parse_insn).collect();

        self.prog.name = name.clone();
        self.prog.location = name;
        self.prog.raw_data = raw_data;
        self.prog.insns = insns;
        self.prog.insn_cnt = insn_cnt;

        Ok(insn_cnt)
    }

    /// Run the full verification pipeline: structural checks (nano),
    /// then path-sensitive exploration (mini — the most advanced pass,
    /// which includes the micro abstract execution). A verification
    /// failure is not an error — it is returned as Ok(Verdict::Unsafe).
    pub fn verify(&mut self) -> Result<Verdict> {
        let subprogs = match add_subprog(&self.prog.insns) {
            Ok(subprogs) => subprogs,
            Err(failure) => return Ok(Verdict::Unsafe(failure)),
        };
        self.prog.subprogs = subprogs;

        match check_cfg(&self.prog.insns, &self.prog.subprogs) {
            Ok(()) => {}
            Err(failure) => return Ok(Verdict::Unsafe(failure)),
        }

        match verify_mini(&self.prog.insns) {
            Ok(_) => Ok(Verdict::Safe),
            Err(failure) => Ok(Verdict::Unsafe(failure)),
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::*;
    use crate::testutil::*;

    #[test]
    fn setup_prog_reads_program() {
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 42),
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let path = std::env::temp_dir().join(format!(
            "rand_verifier_setup_prog_{}.bpf",
            std::process::id()
        ));
        std::fs::write(&path, prog_bytes(&insns)).unwrap();

        let mut env = BpfVerifierEnv::new();
        let insn_cnt = env.setup_prog(path.to_str().unwrap().to_string()).unwrap();

        assert_eq!(insn_cnt, 2);
        assert_eq!(env.prog.insn_cnt, 2);
        assert_eq!(env.prog.insns.len(), 2);
        assert!(matches!(
            env.prog.insns[0],
            BpfInsn::MovImm { dst: 0, imm: 42 }
        ));
        assert!(matches!(env.prog.insns[1], BpfInsn::Exit));

        std::fs::remove_file(&path).ok();
    }

    // ── test corpus (file fixtures) ─────────────────────────────────────────

    /// Load a corpus program file and run the full verification pipeline
    /// (nano structural checks + mini path exploration).
    fn verify_corpus_program(path: &std::path::Path) -> Verdict {
        let mut env = BpfVerifierEnv::new();
        env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
        env.verify().unwrap()
    }

    /// Every program under tests/programs/accept/ must pass verification.

    #[test]
    fn corpus_accept_all() {
        let dir = std::path::Path::new("tests/programs/accept");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            // skip docs and directories; corpus files have no extension
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let verdict = verify_corpus_program(&path);
            assert!(
                matches!(verdict, Verdict::Safe),
                "accept program {:?} was rejected",
                path
            );
            count += 1;
        }
        assert!(count > 0, "no accept programs found in {:?}", dir);
    }

    /// Every program under tests/programs/reject/ must fail verification.

    #[test]
    fn corpus_reject_all() {
        let dir = std::path::Path::new("tests/programs/reject");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            // skip docs and directories; corpus files have no extension
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            match verify_corpus_program(&path) {
                Verdict::Safe => panic!("reject program {:?} was accepted", path),
                Verdict::Unsafe(failure) => {
                    println!("rejected as expected: {:?} → {}", path, failure);
                    count += 1;
                }
            }
        }
        assert!(count > 0, "no reject programs found in {:?}", dir);
    }

    #[test]
    fn verify_includes_mini() {
        // the pipeline runs the most advanced pass: a program that passes
        // the structural (nano) checks but exits with R0 unset is rejected
        // by the path exploration (mini)
        let insns = [insn_bytes(opcode::EXIT, 0, 0, 0, 0)];
        let path = std::env::temp_dir().join(format!(
            "rand_verifier_verify_mini_{}.bpf",
            std::process::id()
        ));
        std::fs::write(&path, prog_bytes(&insns)).unwrap();

        let mut env = BpfVerifierEnv::new();
        env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
        match env.verify().unwrap() {
            Verdict::Safe => panic!("exit-only program was accepted by the full pipeline"),
            Verdict::Unsafe(failure) => {
                assert!(failure.message.contains("r0 is uninitialized at exit"));
            }
        }
        std::fs::remove_file(&path).ok();
    }

    // ── Worklist (v0.3) ──────────────────────────────────────────────────────
}
