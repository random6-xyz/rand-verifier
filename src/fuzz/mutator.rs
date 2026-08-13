// ── Seed-based mutation (v0.7, #71) ─────────────────────────────────────────

//! Mutation of known-good seed programs (syzkaller's `prog/mutation.go`
//! strategies: argument replacement, insert/delete, splice). The corpus
//! fixtures are verdict-known seeds; a mutation that flips a verdict
//! exposes a boundary in the verifier's reasoning.
//!
//! Mutations happen at the `BpfInsn` level (never raw bytes), so the
//! output always decodes. Structural validity is enforced here:
//! [`Mutator::try_mutate`] runs the nano checks (`add_subprog` +
//! `check_cfg`) and returns `None` for invalid mutants — the runner
//! counts the drop rate. The frame is preserved (the r0 init and the
//! trailing EXIT are never mutated), which keeps the validity rate
//! high.

use crate::cfg::{add_subprog, check_cfg};
use crate::fuzz::generator::gen_body_insn;
use crate::fuzz::insn_lib::{ALU_REGS, IMMEDIATES, OFFSETS};
use crate::fuzz::prng::SplitMix64;
use crate::insn::BpfInsn;

/// Mutates one seed program per call. The seed fully determines the
/// mutation sequence (in-house SplitMix64).
pub struct Mutator {
    rng: SplitMix64,
}

impl Mutator {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SplitMix64::new(seed),
        }
    }

    /// A deterministic `percent`-chance roll (mixing ratios, #71).
    pub fn chance(&mut self, percent: u64) -> bool {
        self.rng.below(100) < percent
    }

    /// A uniformly picked element of a pool (seed selection, #71).
    pub fn pick<'a, T>(&mut self, pool: &'a [T]) -> &'a T {
        &pool[self.rng.below(pool.len() as u64) as usize]
    }

    /// One mutation of `seed`. `other` is the second seed for the
    /// splice strategy. Returns `None` when the mutant fails the nano
    /// structural checks (dropped — the runner counts the rate).
    pub fn try_mutate(
        &mut self,
        seed: &[BpfInsn],
        other: Option<&[BpfInsn]>,
    ) -> Option<Vec<BpfInsn>> {
        // the frame (r0 init + EXIT) needs at least one body instruction
        if seed.len() < 3 {
            return None;
        }
        let roll = self.rng.below(100);
        let mutant = if roll < 50 {
            self.field_replace(seed)
        } else if roll < 70 {
            self.insert(seed)
        } else if roll < 85 {
            self.delete(seed)
        } else {
            match other {
                Some(b) if b.len() >= 2 => self.splice(seed, b),
                _ => self.field_replace(seed), // no second seed: fall back
            }
        };
        let subprogs = add_subprog(&mutant).ok()?;
        check_cfg(&mutant, &subprogs).ok()?;
        Some(mutant)
    }

    /// Replace one field (immediate / offset / register) of one body
    /// instruction, drawn from the interesting value pools.
    fn field_replace(&mut self, seed: &[BpfInsn]) -> Vec<BpfInsn> {
        let mut out = seed.to_vec();
        let idx = 1 + self.rng.below((out.len() - 2) as u64) as usize;
        let insn = &out[idx];
        out[idx] = match self.rng.below(3) {
            0 => replace_imm(insn, *self.rng.pick(IMMEDIATES)),
            1 => replace_off(insn, *self.rng.pick(OFFSETS)),
            _ => replace_reg(insn, *self.rng.pick(ALU_REGS)),
        };
        out
    }

    /// Insert one fresh instruction at a random body position (the
    /// weighted generator distribution, #66). Branch offsets may break
    /// — the nano check in `try_mutate` drops such mutants.
    fn insert(&mut self, seed: &[BpfInsn]) -> Vec<BpfInsn> {
        let mut out = seed.to_vec();
        let pos = 1 + self.rng.below((out.len() - 1) as u64) as usize; // before the EXIT
        out.insert(pos, gen_body_insn(&mut self.rng, pos, out.len()));
        out
    }

    /// Remove one random body instruction.
    fn delete(&mut self, seed: &[BpfInsn]) -> Vec<BpfInsn> {
        let mut out = seed.to_vec();
        if out.len() > 3 {
            let pos = 1 + self.rng.below((out.len() - 2) as u64) as usize;
            out.remove(pos);
        }
        out
    }

    /// Cut-and-join two seeds: the head of `a` (frame kept) plus the
    /// tail of `b` (EXIT kept).
    fn splice(&mut self, a: &[BpfInsn], b: &[BpfInsn]) -> Vec<BpfInsn> {
        let cut_a = 1 + self.rng.below((a.len() - 1) as u64) as usize;
        let cut_b = 1 + self.rng.below((b.len() - 1) as u64) as usize;
        let mut out = Vec::with_capacity(cut_a + (b.len() - cut_b));
        out.extend_from_slice(&a[..cut_a]);
        out.extend_from_slice(&b[cut_b..]);
        out
    }
}

/// Replace the immediate of an instruction (instructions without an
/// imm field are returned unchanged).
fn replace_imm(insn: &BpfInsn, imm: i32) -> BpfInsn {
    match insn {
        BpfInsn::MovImm { dst, .. } => BpfInsn::MovImm { dst: *dst, imm },
        BpfInsn::AddImm { dst, .. } => BpfInsn::AddImm { dst: *dst, imm },
        BpfInsn::SubImm { dst, .. } => BpfInsn::SubImm { dst: *dst, imm },
        BpfInsn::AndImm { dst, .. } => BpfInsn::AndImm { dst: *dst, imm },
        BpfInsn::OrImm { dst, .. } => BpfInsn::OrImm { dst: *dst, imm },
        BpfInsn::XorImm { dst, .. } => BpfInsn::XorImm { dst: *dst, imm },
        BpfInsn::LshImm { dst, .. } => BpfInsn::LshImm { dst: *dst, imm },
        BpfInsn::RshImm { dst, .. } => BpfInsn::RshImm { dst: *dst, imm },
        BpfInsn::ArshImm { dst, .. } => BpfInsn::ArshImm { dst: *dst, imm },
        BpfInsn::Add32Imm { dst, .. } => BpfInsn::Add32Imm { dst: *dst, imm },
        BpfInsn::Sub32Imm { dst, .. } => BpfInsn::Sub32Imm { dst: *dst, imm },
        BpfInsn::And32Imm { dst, .. } => BpfInsn::And32Imm { dst: *dst, imm },
        BpfInsn::Or32Imm { dst, .. } => BpfInsn::Or32Imm { dst: *dst, imm },
        BpfInsn::Xor32Imm { dst, .. } => BpfInsn::Xor32Imm { dst: *dst, imm },
        BpfInsn::Lsh32Imm { dst, .. } => BpfInsn::Lsh32Imm { dst: *dst, imm },
        BpfInsn::Rsh32Imm { dst, .. } => BpfInsn::Rsh32Imm { dst: *dst, imm },
        BpfInsn::Arsh32Imm { dst, .. } => BpfInsn::Arsh32Imm { dst: *dst, imm },
        BpfInsn::JeqImm { dst, offset, .. } => BpfInsn::JeqImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JneImm { dst, offset, .. } => BpfInsn::JneImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JgtImm { dst, offset, .. } => BpfInsn::JgtImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JgeImm { dst, offset, .. } => BpfInsn::JgeImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JltImm { dst, offset, .. } => BpfInsn::JltImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JleImm { dst, offset, .. } => BpfInsn::JleImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JsgtImm { dst, offset, .. } => BpfInsn::JsgtImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JsgeImm { dst, offset, .. } => BpfInsn::JsgeImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JsltImm { dst, offset, .. } => BpfInsn::JsltImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::JsleImm { dst, offset, .. } => BpfInsn::JsleImm {
            dst: *dst,
            imm,
            offset: *offset,
        },
        BpfInsn::Call { .. } => BpfInsn::Call { imm },
        other => other.clone(),
    }
}

/// Replace the offset of an instruction (jumps and stack accesses;
/// other instructions are returned unchanged).
fn replace_off(insn: &BpfInsn, offset: i16) -> BpfInsn {
    match insn {
        BpfInsn::LdStack { dst, .. } => BpfInsn::LdStack { dst: *dst, offset },
        BpfInsn::StStack { src, .. } => BpfInsn::StStack { src: *src, offset },
        BpfInsn::Jeq { dst, src, .. } => BpfInsn::Jeq {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jne { dst, src, .. } => BpfInsn::Jne {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jgt { dst, src, .. } => BpfInsn::Jgt {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jge { dst, src, .. } => BpfInsn::Jge {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jlt { dst, src, .. } => BpfInsn::Jlt {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jle { dst, src, .. } => BpfInsn::Jle {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jsgt { dst, src, .. } => BpfInsn::Jsgt {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jsge { dst, src, .. } => BpfInsn::Jsge {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jslt { dst, src, .. } => BpfInsn::Jslt {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::Jsle { dst, src, .. } => BpfInsn::Jsle {
            dst: *dst,
            src: *src,
            offset,
        },
        BpfInsn::JeqImm { dst, imm, .. } => BpfInsn::JeqImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JneImm { dst, imm, .. } => BpfInsn::JneImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JgtImm { dst, imm, .. } => BpfInsn::JgtImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JgeImm { dst, imm, .. } => BpfInsn::JgeImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JltImm { dst, imm, .. } => BpfInsn::JltImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JleImm { dst, imm, .. } => BpfInsn::JleImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JsgtImm { dst, imm, .. } => BpfInsn::JsgtImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JsgeImm { dst, imm, .. } => BpfInsn::JsgeImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JsltImm { dst, imm, .. } => BpfInsn::JsltImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::JsleImm { dst, imm, .. } => BpfInsn::JsleImm {
            dst: *dst,
            imm: *imm,
            offset,
        },
        BpfInsn::Jmp { .. } => BpfInsn::Jmp { offset },
        other => other.clone(),
    }
}

/// Replace the destination register of an instruction (register-source
/// forms keep their source; instructions without a register operand
/// are returned unchanged).
fn replace_reg(insn: &BpfInsn, reg: u8) -> BpfInsn {
    match insn {
        BpfInsn::MovImm { imm, .. } => BpfInsn::MovImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::MovReg { src, .. } => BpfInsn::MovReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::AddImm { imm, .. } => BpfInsn::AddImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::AddReg { src, .. } => BpfInsn::AddReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::SubImm { imm, .. } => BpfInsn::SubImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::SubReg { src, .. } => BpfInsn::SubReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::AndImm { imm, .. } => BpfInsn::AndImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::AndReg { src, .. } => BpfInsn::AndReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::OrImm { imm, .. } => BpfInsn::OrImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::OrReg { src, .. } => BpfInsn::OrReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::XorImm { imm, .. } => BpfInsn::XorImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::XorReg { src, .. } => BpfInsn::XorReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::LshImm { imm, .. } => BpfInsn::LshImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::LshReg { src, .. } => BpfInsn::LshReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::RshImm { imm, .. } => BpfInsn::RshImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::RshReg { src, .. } => BpfInsn::RshReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::ArshImm { imm, .. } => BpfInsn::ArshImm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::ArshReg { src, .. } => BpfInsn::ArshReg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Add32Imm { imm, .. } => BpfInsn::Add32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Add32Reg { src, .. } => BpfInsn::Add32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Sub32Imm { imm, .. } => BpfInsn::Sub32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Sub32Reg { src, .. } => BpfInsn::Sub32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::And32Imm { imm, .. } => BpfInsn::And32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::And32Reg { src, .. } => BpfInsn::And32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Or32Imm { imm, .. } => BpfInsn::Or32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Or32Reg { src, .. } => BpfInsn::Or32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Xor32Imm { imm, .. } => BpfInsn::Xor32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Xor32Reg { src, .. } => BpfInsn::Xor32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Lsh32Imm { imm, .. } => BpfInsn::Lsh32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Lsh32Reg { src, .. } => BpfInsn::Lsh32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Rsh32Imm { imm, .. } => BpfInsn::Rsh32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Rsh32Reg { src, .. } => BpfInsn::Rsh32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::Arsh32Imm { imm, .. } => BpfInsn::Arsh32Imm {
            dst: reg,
            imm: *imm,
        },
        BpfInsn::Arsh32Reg { src, .. } => BpfInsn::Arsh32Reg {
            dst: reg,
            src: *src,
        },
        BpfInsn::LdStack { offset, .. } => BpfInsn::LdStack {
            dst: reg,
            offset: *offset,
        },
        BpfInsn::StStack { offset, .. } => BpfInsn::StStack {
            src: reg,
            offset: *offset,
        },
        BpfInsn::Jeq { src, offset, .. } => BpfInsn::Jeq {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jne { src, offset, .. } => BpfInsn::Jne {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jgt { src, offset, .. } => BpfInsn::Jgt {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jge { src, offset, .. } => BpfInsn::Jge {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jlt { src, offset, .. } => BpfInsn::Jlt {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jle { src, offset, .. } => BpfInsn::Jle {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jsgt { src, offset, .. } => BpfInsn::Jsgt {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jsge { src, offset, .. } => BpfInsn::Jsge {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jslt { src, offset, .. } => BpfInsn::Jslt {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::Jsle { src, offset, .. } => BpfInsn::Jsle {
            dst: reg,
            src: *src,
            offset: *offset,
        },
        BpfInsn::JeqImm { imm, offset, .. } => BpfInsn::JeqImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JneImm { imm, offset, .. } => BpfInsn::JneImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JgtImm { imm, offset, .. } => BpfInsn::JgtImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JgeImm { imm, offset, .. } => BpfInsn::JgeImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JltImm { imm, offset, .. } => BpfInsn::JltImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JleImm { imm, offset, .. } => BpfInsn::JleImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JsgtImm { imm, offset, .. } => BpfInsn::JsgtImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JsgeImm { imm, offset, .. } => BpfInsn::JsgeImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JsltImm { imm, offset, .. } => BpfInsn::JsltImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        BpfInsn::JsleImm { imm, offset, .. } => BpfInsn::JsleImm {
            dst: reg,
            imm: *imm,
            offset: *offset,
        },
        other => other.clone(),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::BpfVerifierEnv;
    use crate::error::Verdict;
    use crate::fuzz::insn_lib::encode;

    /// Load every corpus fixture as a decoded seed.
    fn corpus_seeds() -> Vec<(String, Vec<BpfInsn>, &'static str)> {
        let mut seeds = Vec::new();
        for (dir, verdict) in [
            ("tests/programs/accept", "ACCEPT"),
            ("tests/programs/reject", "REJECT"),
        ] {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if !path.is_file() || path.extension().is_some() {
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap();
                let insns: Vec<BpfInsn> = bytes
                    .chunks_exact(8)
                    .map(|c| crate::insn::parse_insn(c).unwrap())
                    .collect();
                seeds.push((
                    path.file_stem().unwrap().to_string_lossy().into_owned(),
                    insns,
                    verdict,
                ));
            }
        }
        seeds
    }

    fn verify_bytes(insns: &[BpfInsn]) -> Verdict {
        let bytes: Vec<u8> = insns.iter().flat_map(encode).collect();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes).unwrap();
        env.verify().unwrap()
    }

    /// Returned mutants always pass the nano checks (guaranteed by
    /// `try_mutate`), and the validity rate stays above 50% across the
    /// whole corpus — documented by this fixed-seed test.
    #[test]
    fn mutate_validity() {
        let seeds = corpus_seeds();
        let mut total = 0usize;
        let mut valid = 0usize;
        for (si, (_, insns, _)) in seeds.iter().enumerate() {
            for m in 0..10 {
                let mut mutator = Mutator::new((si as u64) * 10 + m);
                total += 1;
                if mutator.try_mutate(insns, None).is_some() {
                    valid += 1;
                }
            }
        }
        assert!(
            valid > total / 2,
            "mutation validity rate too low: {valid}/{total}"
        );
    }

    /// A verdict-flipping mutation exists: an accepted corpus program
    /// mutates into a rejected one (fixed seed — the regression sample
    /// for #71's acceptance).
    #[test]
    fn mutate_verdict_flip() {
        let seeds = corpus_seeds();
        let mut flips = Vec::new();
        for m in 0..2000u64 {
            let mut mutator = Mutator::new(m);
            let (name, insns, verdict) = mutator.pick(&seeds);
            if let Some(mutant) = mutator.try_mutate(insns, None) {
                let new_verdict = verify_bytes(&mutant);
                let flipped = matches!(
                    (*verdict, &new_verdict),
                    ("ACCEPT", Verdict::Unsafe(_)) | ("REJECT", Verdict::Safe)
                );
                if flipped {
                    flips.push((m, name.clone(), *verdict, format!("{new_verdict:?}")));
                    if flips.len() >= 5 {
                        break;
                    }
                }
            }
        }
        assert!(
            !flips.is_empty(),
            "no verdict-flipping mutation found in 2000 seeds"
        );
        eprintln!("verdict flips found: {flips:?}");
    }

    /// Same seed → the same mutation sequence and outcome.
    #[test]
    fn mutate_deterministic() {
        let seeds = corpus_seeds();
        let (_, insns, _) = &seeds[0];
        let mut a = Mutator::new(9);
        let mut b = Mutator::new(9);
        let mut a_out = Vec::new();
        let mut b_out = Vec::new();
        for _ in 0..20 {
            a_out.push(a.try_mutate(insns, None));
            b_out.push(b.try_mutate(insns, None));
        }
        assert_eq!(a_out, b_out);
    }
}
