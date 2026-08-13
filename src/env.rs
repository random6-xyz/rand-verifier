// ── BPF program loading and the verification environment ────────────────────

use std::fs;

use anyhow::Result;

use crate::cfg::{add_subprog, check_cfg};
use crate::concrete::{ConcreteReport, check_coverage, render_coverage_report, run_concrete};
use crate::error::{Verdict, VerificationFailure};
use crate::insn::{BpfInsn, parse_insn};
use crate::mini::{VerifierLimits, verify_mini_with_states};

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
    /// The first decode failure, if any: decode errors are program
    /// rejections (like the kernel's "unknown opcode"), so they are
    /// stored and reported by `verify()` as `Verdict::Unsafe` instead
    /// of aborting the load (issue #56).
    decode_error: Option<VerificationFailure>,
}

/// The verifier environment: owns the loaded program and runs the
/// full verification pipeline on it.
#[derive(Default)]
pub struct BpfVerifierEnv {
    pub(crate) prog: BpfProg, // BPF program data
    /// The concrete-side report of the last `verify()` call (v0.5).
    pub(crate) concrete_report: Option<ConcreteReport>,
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

        // decode every 8-byte instruction; the first decode error stops
        // the decode (like the kernel's per-instruction check loop)
        let mut insns = Vec::with_capacity(insn_cnt as usize);
        let mut decode_error = None;
        for (idx, chunk) in raw_data.chunks_exact(8).enumerate() {
            match parse_insn(chunk) {
                Ok(insn) => insns.push(insn),
                Err(e) => {
                    decode_error = Some(VerificationFailure::new(idx as u32, e.to_string()));
                    insns.clear();
                    break;
                }
            }
        }

        self.prog.name = name.clone();
        self.prog.location = name;
        self.prog.raw_data = raw_data;
        self.prog.insns = insns;
        self.prog.insn_cnt = insn_cnt;
        self.prog.decode_error = decode_error;

        Ok(insn_cnt)
    }

    /// Run the full verification pipeline: structural checks (nano),
    /// then path-sensitive exploration (mini — the most advanced pass,
    /// which includes the micro abstract execution). On accepted
    /// programs the concrete interpreter then runs and its reachable
    /// states are checked against the abstract states (Phase 2, #53);
    /// on rejected programs the concrete run is kept as an
    /// informational cross-check. A verification failure is not an
    /// error — it is returned as Ok(Verdict::Unsafe). The verdict is
    /// unchanged by the concrete side: an unsoundness is a model bug
    /// and is reported via [`BpfVerifierEnv::concrete_report_text`].
    pub fn verify(&mut self) -> Result<Verdict> {
        self.concrete_report = None;
        // a decode failure is a rejection: the program could not even be
        // decoded (unknown opcode, invalid register, reserved fields).
        // The concrete cross-check is skipped — there are no instructions
        // to run (issue #56).
        if let Some(failure) = &self.prog.decode_error {
            return Ok(Verdict::Unsafe(failure.clone()));
        }
        // structural checks (nano)
        let subprogs = match add_subprog(&self.prog.insns) {
            Ok(subprogs) => subprogs,
            Err(failure) => return self.reject_with_cross_check(failure, &[]),
        };
        self.prog.subprogs = subprogs;
        let loop_heads = match check_cfg(&self.prog.insns, &self.prog.subprogs) {
            Ok(loop_heads) => loop_heads,
            Err(failure) => return self.reject_with_cross_check(failure, &[]),
        };
        // path exploration (mini), collecting the per-pc abstract states
        match verify_mini_with_states(&self.prog.insns, &loop_heads, &VerifierLimits::default()) {
            Err(failure) => self.reject_with_cross_check(failure, &loop_heads),
            Ok((_, abstract_states)) => {
                // ACCEPT: concrete run + coverage check — the Phase 2
                // soundness question (every concrete visited state must
                // be covered by an abstract state at the same pc)
                let mut report = ConcreteReport::default();
                match run_concrete(&self.prog.insns, &loop_heads) {
                    Err(failure) => report.unexpected_failure = Some(failure),
                    Ok(run) => {
                        report.inconclusive = run.inconclusive;
                        report.violations = check_coverage(&abstract_states, &run);
                    }
                }
                self.concrete_report = Some(report);
                Ok(Verdict::Safe)
            }
        }
    }

    /// Run the concrete interpreter on a rejected program for an
    /// informational cross-check: concrete also fails (expected),
    /// concrete executes the program the abstract rejected (precision
    /// candidate), or the concrete run is inconclusive (non-termination
    /// candidate). Loop heads are unknown when the structural pass
    /// failed; the state/step budgets still bound the run.
    fn reject_with_cross_check(
        &mut self,
        failure: crate::error::VerificationFailure,
        loop_heads: &[u32],
    ) -> Result<Verdict> {
        let mut report = ConcreteReport::default();
        match run_concrete(&self.prog.insns, loop_heads) {
            Err(concrete_failure) => {
                report.reject_note = Some(format!(
                    "concrete cross-check: also fails {}",
                    concrete_failure
                ));
            }
            Ok(run) if run.inconclusive => {
                // keep the structured flag in sync with the note
                report.inconclusive = true;
                report.reject_note = Some(
                    "concrete cross-check: inconclusive (non-terminating loop candidate)"
                        .to_string(),
                );
            }
            Ok(_) => {
                report.reject_note = Some(
                    "concrete cross-check: the program executes concretely — precision candidate"
                        .to_string(),
                );
            }
        }
        self.concrete_report = Some(report);
        Ok(Verdict::Unsafe(failure))
    }

    /// The concrete-side report of the last verification: rendered text
    /// when the concrete side has anything noteworthy — coverage
    /// violations, an inconclusive run, an unexpected concrete failure,
    /// or a reject cross-check note. `None` only for a clean accept
    /// (no violations, conclusive run, no failures).
    pub fn concrete_report_text(&self) -> Option<String> {
        let report = self.concrete_report.as_ref()?;
        let mut out = String::new();
        if !report.violations.is_empty() {
            out.push_str(&format!(
                "concrete coverage: {} violation(s) — the abstract state does not cover the concrete run\n",
                report.violations.len()
            ));
            out.push_str(&render_coverage_report(
                &report.violations,
                &self.prog.insns,
            ));
        }
        if report.inconclusive {
            out.push_str(
                "concrete run inconclusive: exploration budget exceeded (non-terminating loop candidate)\n",
            );
        }
        if let Some(failure) = &report.unexpected_failure {
            out.push_str(&format!(
                "unexpected concrete failure (the abstract verifier accepted the program): {}\n",
                failure
            ));
        }
        if let Some(note) = &report.reject_note {
            out.push_str(&format!("{}\n", note));
        }
        if out.is_empty() { None } else { Some(out) }
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

    /// Every accept program must also be concretely clean: the abstract
    /// states must cover every concrete reachable state (v0.5, #54).
    /// `corpus_accept_all` only checks the verdict — this test fixes the
    /// Phase 2 soundness claim for the whole accept corpus.

    #[test]
    fn corpus_accept_concrete_clean() {
        let dir = std::path::Path::new("tests/programs/accept");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            // skip docs and directories; corpus files have no extension
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let mut env = BpfVerifierEnv::new();
            env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
            let verdict = env.verify().unwrap();
            assert!(
                matches!(verdict, Verdict::Safe),
                "accept program {:?} was rejected",
                path
            );
            let report = env.concrete_report.as_ref().expect("concrete report");
            assert!(
                report.violations.is_empty(),
                "accept program {:?} has coverage violations: {:?}",
                path,
                report.violations
            );
            assert!(
                !report.inconclusive,
                "accept program {:?} has an inconclusive concrete run",
                path
            );
            assert!(
                report.unexpected_failure.is_none(),
                "accept program {:?} has an unexpected concrete failure",
                path
            );
            count += 1;
        }
        assert!(count > 0, "no accept programs found in {:?}", dir);
    }

    /// Every reject program must produce a concrete cross-check note
    /// (the informational counterpart of the accept-side coverage check).

    #[test]
    fn corpus_reject_concrete_cross_check() {
        let dir = std::path::Path::new("tests/programs/reject");
        let mut count = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            // skip docs and directories; corpus files have no extension
            if !path.is_file() || path.extension().is_some() {
                continue;
            }
            let mut env = BpfVerifierEnv::new();
            env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
            let verdict = env.verify().unwrap();
            assert!(
                matches!(verdict, Verdict::Unsafe(_)),
                "reject program {:?} was accepted",
                path
            );
            let report = env.concrete_report.as_ref().expect("concrete report");
            let note = report
                .reject_note
                .as_deref()
                .expect("reject cross-check note");
            assert!(
                !note.is_empty(),
                "reject program {:?} has an empty note",
                path
            );
            assert!(
                report.unexpected_failure.is_none(),
                "reject program {:?} reported an unexpected concrete failure",
                path
            );
            count += 1;
        }
        assert!(count > 0, "no reject programs found in {:?}", dir);
    }

    // ── Concrete integration (v0.5, #53) ───────────────────────────────────

    /// Write a raw program to a temp file, verify it, and return the
    /// verdict plus the env (for the concrete report).
    fn verify_temp_program(insns: &[[u8; 8]], tag: &str) -> (Verdict, BpfVerifierEnv) {
        let path =
            std::env::temp_dir().join(format!("rand_verifier_{}_{}.bpf", tag, std::process::id()));
        std::fs::write(&path, prog_bytes(insns)).unwrap();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog(path.to_str().unwrap().to_string()).unwrap();
        let verdict = env.verify().unwrap();
        std::fs::remove_file(&path).ok();
        (verdict, env)
    }

    #[test]
    fn verify_accept_runs_concrete_clean() {
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 42),
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "accept_clean");
        assert!(matches!(verdict, Verdict::Safe));
        let report = env.concrete_report.as_ref().unwrap();
        assert!(report.violations.is_empty());
        assert!(!report.inconclusive);
        assert!(report.unexpected_failure.is_none());
        assert!(report.reject_note.is_none());
        // nothing noteworthy → no report text
        assert!(env.concrete_report_text().is_none());
    }

    #[test]
    fn verify_accept_prandom_program_clean() {
        // r0 = get_prandom_u32(-7); exit — helper seeds must all be
        // covered by the abstract unknown scalar range
        let insns = [
            insn_bytes(opcode::CALL, 0, 0, 0, 7),
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "accept_prandom");
        assert!(matches!(verdict, Verdict::Safe));
        let report = env.concrete_report.as_ref().unwrap();
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        assert!(!report.inconclusive);
        assert!(report.unexpected_failure.is_none());
    }

    #[test]
    fn verify_reject_uninit_cross_check() {
        // r0 = 1; r0 += r2 (uninitialized); exit
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 1),
            insn_bytes(opcode::ADD_REG, 0, 2, 0, 0),
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "reject_uninit");
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let report = env.concrete_report.as_ref().unwrap();
        let note = report.reject_note.as_deref().expect("reject note");
        assert!(note.contains("also fails"), "note: {}", note);
        assert!(env.concrete_report_text().is_some());
    }

    #[test]
    fn verify_reject_unreachable_precision_candidate() {
        // r0 = 1; jmp +1; r0 = 0; exit — insn 2 is unreachable (nano
        // reject), but the concrete interpreter executes the reachable
        // path fine → precision candidate
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 1),
            insn_bytes(opcode::JMP, 0, 0, 1, 0),
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 0),
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "reject_unreachable");
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let report = env.concrete_report.as_ref().unwrap();
        let note = report.reject_note.as_deref().expect("reject note");
        assert!(note.contains("executes concretely"), "note: {}", note);
    }

    #[test]
    fn verify_reject_nonterminating_loop_inconclusive_note() {
        // r0 = 0; r0 += 1; jmp -2 — a never-converging loop: the
        // abstract rejects it, the concrete run is inconclusive
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 0),
            insn_bytes(opcode::ADD_IMM, 0, 0, 0, 1),
            insn_bytes(opcode::JMP, 0, 0, -2, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "reject_loop");
        assert!(matches!(verdict, Verdict::Unsafe(_)));
        let report = env.concrete_report.as_ref().unwrap();
        // the structured flag stays in sync with the note
        assert!(report.inconclusive);
        let note = report.reject_note.as_deref().expect("reject note");
        assert!(note.contains("inconclusive"), "note: {}", note);
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

    #[test]
    fn verify_decode_error_is_rejection() {
        // a program with an unknown opcode is rejected at decode time
        // (issue #56), with the failing instruction index; there are no
        // instructions, so no concrete cross-check runs
        let insns = [
            insn_bytes(opcode::MOV_IMM, 0, 0, 0, 1),
            insn_bytes(0xEF, 0, 0, 0, 0), // not in the kernel instruction table
            insn_bytes(opcode::EXIT, 0, 0, 0, 0),
        ];
        let (verdict, env) = verify_temp_program(&insns, "decode_error");
        match verdict {
            Verdict::Safe => panic!("decode-error program was accepted"),
            Verdict::Unsafe(failure) => {
                assert_eq!(failure.insn_idx, 1);
                assert!(
                    failure.message.contains("unknown opcode"),
                    "{}",
                    failure.message
                );
            }
        }
        assert!(env.concrete_report.is_none());
    }

    // ── Worklist (v0.3) ──────────────────────────────────────────────────────
}
