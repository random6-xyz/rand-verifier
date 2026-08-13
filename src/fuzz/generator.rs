// ── Deterministic, weighted random program generator (v0.7, #66) ────────────

//! Framed generation (syzkaller's `bpf_framed_program` idea): every
//! generated program is `[r0 = 0, body..., exit]`, so it is decodable,
//! has no unreachable instructions, and passes the nano structural
//! checks by construction. Only conditional branches appear inside the
//! body; an unconditional jump is emitted only as the last body
//! instruction (targeting a backward loop or the exit), so no
//! instruction is ever jumped over.
//!
//! Deterministic: a seed fully determines the output stream (in-house
//! SplitMix64). Random *values* come from the pools in
//! [`crate::fuzz::insn_lib`]; random *structure* is decided here.

use crate::fuzz::insn_lib;
use crate::fuzz::insn_lib::{ALU_REGS, IMMEDIATES, OFFSETS};
use crate::fuzz::prng::SplitMix64;
use crate::insn::BpfInsn;

/// Generation parameters.
pub struct GenConfig {
    /// Minimum body length (instructions between the r0 init and the exit).
    pub min_len: usize,
    /// Maximum body length.
    pub max_len: usize,
}

impl Default for GenConfig {
    fn default() -> Self {
        Self {
            min_len: 1,
            max_len: 100,
        }
    }
}

/// Per-family weights (percent, must sum to 100): ALU64 / ALU32 /
/// compare / stack / helper. The unconditional jump is a separate
/// decision made only for the last body instruction.
const WEIGHT_ALU64: u64 = 35;
const WEIGHT_ALU32: u64 = 15;
const WEIGHT_CMP: u64 = 30;
const WEIGHT_STACK: u64 = 15;
const WEIGHT_HELPER: u64 = 5;
/// Probability (percent) of the last body instruction being an
/// unconditional jump instead of a regular instruction.
const JMP_LAST_PERCENT: u64 = 20;
/// Probability (percent) of a backward (loop) edge when a branch is
/// generated.
const BACKWARD_PERCENT: u64 = 30;

/// The weighted random program generator.
pub struct Generator {
    rng: SplitMix64,
}

impl Generator {
    /// A new generator with the given seed.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SplitMix64::new(seed),
        }
    }

    /// Generate a framed program: `[r0 = 0, body..., exit]`.
    pub fn gen_program(&mut self, cfg: &GenConfig) -> Vec<BpfInsn> {
        let span = cfg.max_len.saturating_sub(cfg.min_len) + 1;
        let body_len = cfg.min_len + self.rng.below(span as u64) as usize;

        let mut insns = Vec::with_capacity(body_len + 2);
        // r0 init — satisfies the exit R0 check (mini) by construction
        insns.push(insn_lib::mov_imm(0, 0));

        for pc in 0..body_len {
            let is_last = pc == body_len - 1;
            if is_last && self.rng.below(100) < JMP_LAST_PERCENT {
                // unconditional jump to the exit — the only safe
                // unconditional jump: it has a single successor, so a
                // backward jump would leave the trailing EXIT
                // unreachable (nano rejects dead code). Loops come
                // from conditional backward edges instead (#66).
                insns.push(insn_lib::jmp((body_len - pc - 1) as i16));
            } else {
                insns.push(self.gen_body_insn(pc, body_len));
            }
        }

        insns.push(insn_lib::exit());
        insns
    }

    /// Encode a generated program into raw kernel bytes (`struct
    /// bpf_insn` encoding, #65) — ready for `env::setup_prog_bytes`
    /// and `krun::load_with_kernel`.
    pub fn gen_program_bytes(&mut self, cfg: &GenConfig) -> Vec<u8> {
        self.gen_program(cfg)
            .iter()
            .flat_map(insn_lib::encode)
            .collect()
    }

    /// One body instruction (never the unconditional jump — see the
    /// module docs). `pc` is the body index, `body_len` the body
    /// length; the exit sits at index `body_len`.
    fn gen_body_insn(&mut self, pc: usize, body_len: usize) -> BpfInsn {
        let roll = self.rng.below(100);
        if roll < WEIGHT_ALU64 {
            self.gen_alu(false)
        } else if roll < WEIGHT_ALU64 + WEIGHT_ALU32 {
            self.gen_alu(true)
        } else if roll < WEIGHT_ALU64 + WEIGHT_ALU32 + WEIGHT_CMP {
            self.gen_cmp(pc, body_len)
        } else if roll < WEIGHT_ALU64 + WEIGHT_ALU32 + WEIGHT_CMP + WEIGHT_STACK {
            self.gen_stack()
        } else if roll < WEIGHT_ALU64 + WEIGHT_ALU32 + WEIGHT_CMP + WEIGHT_STACK + WEIGHT_HELPER {
            self.gen_helper()
        } else {
            unreachable!("weights sum to 100")
        }
    }

    /// A random ALU instruction: op, K/X form, operands from the pools.
    fn gen_alu(&mut self, alu32: bool) -> BpfInsn {
        // op index: 0 = mov, 1 = add, 2 = sub, 3 = and, 4 = or, 5 = xor,
        // 6 = lsh, 7 = rsh, 8 = arsh. There is no MOV32 in the supported
        // subset, so ALU32 draws from 1..=8 only.
        let op = if alu32 {
            1 + self.rng.below(8) as usize
        } else {
            self.rng.below(9) as usize
        };
        let dst = *self.rng.pick(ALU_REGS);
        let k_form = self.rng.below(2) == 0;
        match (alu32, k_form, op) {
            (false, true, 0) => insn_lib::mov_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 0) => insn_lib::mov_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 1) => insn_lib::add_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 1) => insn_lib::add_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 2) => insn_lib::sub_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 2) => insn_lib::sub_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 3) => insn_lib::and_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 3) => insn_lib::and_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 4) => insn_lib::or_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 4) => insn_lib::or_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 5) => insn_lib::xor_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 5) => insn_lib::xor_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 6) => insn_lib::lsh_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 6) => insn_lib::lsh_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 7) => insn_lib::rsh_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 7) => insn_lib::rsh_reg(dst, *self.rng.pick(ALU_REGS)),
            (false, true, 8) => insn_lib::arsh_imm(dst, *self.rng.pick(IMMEDIATES)),
            (false, false, 8) => insn_lib::arsh_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 1) => insn_lib::add32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 1) => insn_lib::add32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 2) => insn_lib::sub32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 2) => insn_lib::sub32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 3) => insn_lib::and32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 3) => insn_lib::and32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 4) => insn_lib::or32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 4) => insn_lib::or32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 5) => insn_lib::xor32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 5) => insn_lib::xor32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 6) => insn_lib::lsh32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 6) => insn_lib::lsh32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 7) => insn_lib::rsh32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 7) => insn_lib::rsh32_reg(dst, *self.rng.pick(ALU_REGS)),
            (true, true, 8) => insn_lib::arsh32_imm(dst, *self.rng.pick(IMMEDIATES)),
            (true, false, 8) => insn_lib::arsh32_reg(dst, *self.rng.pick(ALU_REGS)),
            // (true, _, 0) — no MOV32 in the supported subset
            _ => unreachable!("all op/alu32/k_form combinations are covered"),
        }
    }

    /// A random conditional compare. The branch offset always points at
    /// a valid instruction: target = pc + 1 + offset in `[0, body_len]`
    /// (the exit sits at `body_len`). Backward edges (bounded-loop
    /// candidates) are allowed.
    fn gen_cmp(&mut self, pc: usize, body_len: usize) -> BpfInsn {
        const OPS: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let op = OPS[self.rng.below(OPS.len() as u64) as usize];
        let dst = *self.rng.pick(ALU_REGS);
        let k_form = self.rng.below(2) == 0;
        let offset = self.gen_branch_offset(pc, body_len);
        let src = *self.rng.pick(ALU_REGS);
        let imm = *self.rng.pick(IMMEDIATES);
        match (k_form, op) {
            (false, 0) => insn_lib::jeq(dst, src, offset),
            (true, 0) => insn_lib::jeq_imm(dst, imm, offset),
            (false, 1) => insn_lib::jne(dst, src, offset),
            (true, 1) => insn_lib::jne_imm(dst, imm, offset),
            (false, 2) => insn_lib::jgt(dst, src, offset),
            (true, 2) => insn_lib::jgt_imm(dst, imm, offset),
            (false, 3) => insn_lib::jge(dst, src, offset),
            (true, 3) => insn_lib::jge_imm(dst, imm, offset),
            (false, 4) => insn_lib::jlt(dst, src, offset),
            (true, 4) => insn_lib::jlt_imm(dst, imm, offset),
            (false, 5) => insn_lib::jle(dst, src, offset),
            (true, 5) => insn_lib::jle_imm(dst, imm, offset),
            (false, 6) => insn_lib::jsgt(dst, src, offset),
            (true, 6) => insn_lib::jsgt_imm(dst, imm, offset),
            (false, 7) => insn_lib::jsge(dst, src, offset),
            (true, 7) => insn_lib::jsge_imm(dst, imm, offset),
            (false, 8) => insn_lib::jslt(dst, src, offset),
            (true, 8) => insn_lib::jslt_imm(dst, imm, offset),
            (false, 9) => insn_lib::jsle(dst, src, offset),
            (true, 9) => insn_lib::jsle_imm(dst, imm, offset),
            _ => unreachable!("all op/k_form combinations are covered"),
        }
    }

    /// A branch offset for an instruction at body index `pc`: the
    /// target `pc + 1 + offset` lies in `[0, body_len]`. Forward edges
    /// point into the remaining body or at the exit; backward edges
    /// (30%) point at an earlier instruction, forming a loop.
    fn gen_branch_offset(&mut self, pc: usize, body_len: usize) -> i16 {
        if pc > 0 && self.rng.below(100) < BACKWARD_PERCENT {
            // target in [0, pc) — backward edge, bounded-loop candidate
            let target = self.rng.below(pc as u64) as usize;
            (target as i64 - pc as i64 - 1) as i16
        } else {
            // target in [pc + 1, body_len] — forward edge (body_len is
            // the exit), so no instruction is ever jumped over
            let ahead = (body_len - pc) as u64;
            let target = pc + 1 + self.rng.below(ahead) as usize;
            (target as i64 - pc as i64 - 1) as i16
        }
    }

    /// A stack access: frame-pointer-relative DW load or store with an
    /// offset from the pool. Write-before-read is enforced later by the
    /// mini pass — a rejected program is a normal fuzz outcome.
    fn gen_stack(&mut self) -> BpfInsn {
        let reg = *self.rng.pick(ALU_REGS);
        let offset = *self.rng.pick(OFFSETS);
        if self.rng.below(2) == 0 {
            insn_lib::ld_stack(reg, offset)
        } else {
            insn_lib::st_stack(reg, offset)
        }
    }

    /// A helper call: `get_prandom_u32` (id 7) needs no arguments and
    /// returns an unknown scalar in R0 — the supported helper scope
    /// (FUZZ_PLAN §11).
    fn gen_helper(&mut self) -> BpfInsn {
        insn_lib::call(7)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::{add_subprog, check_cfg};
    use crate::insn::BpfInsn;

    fn gen_prog(seed: u64, cfg: &GenConfig) -> Vec<BpfInsn> {
        Generator::new(seed).gen_program(cfg)
    }

    /// The opcode family of an instruction, for the distribution check.
    fn family_of(insn: &BpfInsn) -> &'static str {
        match insn {
            BpfInsn::MovImm { .. }
            | BpfInsn::MovReg { .. }
            | BpfInsn::AddImm { .. }
            | BpfInsn::AddReg { .. }
            | BpfInsn::SubImm { .. }
            | BpfInsn::SubReg { .. }
            | BpfInsn::AndImm { .. }
            | BpfInsn::AndReg { .. }
            | BpfInsn::OrImm { .. }
            | BpfInsn::OrReg { .. }
            | BpfInsn::XorImm { .. }
            | BpfInsn::XorReg { .. }
            | BpfInsn::LshImm { .. }
            | BpfInsn::LshReg { .. }
            | BpfInsn::RshImm { .. }
            | BpfInsn::RshReg { .. }
            | BpfInsn::ArshImm { .. }
            | BpfInsn::ArshReg { .. } => "alu64",
            BpfInsn::Add32Imm { .. }
            | BpfInsn::Add32Reg { .. }
            | BpfInsn::Sub32Imm { .. }
            | BpfInsn::Sub32Reg { .. }
            | BpfInsn::And32Imm { .. }
            | BpfInsn::And32Reg { .. }
            | BpfInsn::Or32Imm { .. }
            | BpfInsn::Or32Reg { .. }
            | BpfInsn::Xor32Imm { .. }
            | BpfInsn::Xor32Reg { .. }
            | BpfInsn::Lsh32Imm { .. }
            | BpfInsn::Lsh32Reg { .. }
            | BpfInsn::Rsh32Imm { .. }
            | BpfInsn::Rsh32Reg { .. }
            | BpfInsn::Arsh32Imm { .. }
            | BpfInsn::Arsh32Reg { .. } => "alu32",
            BpfInsn::Jgt { .. }
            | BpfInsn::JgtImm { .. }
            | BpfInsn::Jge { .. }
            | BpfInsn::JgeImm { .. }
            | BpfInsn::Jlt { .. }
            | BpfInsn::JltImm { .. }
            | BpfInsn::Jle { .. }
            | BpfInsn::JleImm { .. } => "cmp_unsigned",
            BpfInsn::Jsgt { .. }
            | BpfInsn::JsgtImm { .. }
            | BpfInsn::Jsge { .. }
            | BpfInsn::JsgeImm { .. }
            | BpfInsn::Jslt { .. }
            | BpfInsn::JsltImm { .. }
            | BpfInsn::Jsle { .. }
            | BpfInsn::JsleImm { .. } => "cmp_signed",
            BpfInsn::Jeq { .. }
            | BpfInsn::JeqImm { .. }
            | BpfInsn::Jne { .. }
            | BpfInsn::JneImm { .. } => "cmp_eq",
            BpfInsn::LdStack { .. } | BpfInsn::StStack { .. } => "stack",
            BpfInsn::Call { .. } => "helper",
            BpfInsn::Jmp { .. } => "jmp",
            BpfInsn::Exit => "exit",
        }
    }

    /// Same seed → byte-identical output; different seeds → the output
    /// differs (checked over 100 programs).
    #[test]
    fn gen_deterministic() {
        let cfg = GenConfig::default();
        assert_eq!(gen_prog(42, &cfg), gen_prog(42, &cfg));
        assert_eq!(gen_prog(42, &cfg), gen_prog(42, &cfg));

        let base = gen_prog(0, &cfg);
        let mut any_diff = false;
        for seed in 1..100 {
            if gen_prog(seed, &cfg) != base {
                any_diff = true;
                break;
            }
        }
        assert!(any_diff, "all seeds produced identical programs");
    }

    /// Every generated program decodes and passes the nano structural
    /// checks by construction (no unreachable instructions, valid jump
    /// targets, subprogram ends with exit, back edges allowed).
    #[test]
    fn gen_nano_valid() {
        let cfg = GenConfig::default();
        for seed in 0..100 {
            let insns = gen_prog(seed, &cfg);
            let subprogs = add_subprog(&insns).expect("add_subprog");
            check_cfg(&insns, &subprogs)
                .unwrap_or_else(|e| panic!("seed {seed}: nano rejected a generated program: {e}"));
        }
    }

    /// Over many programs every target opcode family from the milestone
    /// appears at least once.
    #[test]
    fn gen_distribution() {
        let cfg = GenConfig::default();
        let mut seen = std::collections::HashSet::new();
        for seed in 0..500 {
            for insn in gen_prog(seed, &cfg) {
                seen.insert(family_of(&insn));
            }
        }
        for family in [
            "alu64",
            "alu32",
            "cmp_unsigned",
            "cmp_signed",
            "cmp_eq",
            "stack",
            "helper",
            "jmp",
        ] {
            assert!(seen.contains(family), "family '{family}' never generated");
        }
    }

    /// The body length honours the configured bounds (the full program
    /// is body + 2 for the r0 init and the exit).
    #[test]
    fn gen_length_bounds() {
        // fixed length
        let cfg = GenConfig {
            min_len: 3,
            max_len: 3,
        };
        for seed in 0..20 {
            assert_eq!(gen_prog(seed, &cfg).len(), 5, "seed {seed}");
        }
        // default bounds
        let cfg = GenConfig::default();
        for seed in 0..100 {
            let len = gen_prog(seed, &cfg).len();
            assert!((3..=102).contains(&len), "seed {seed}: len {len}");
        }
    }

    /// The frame shape is fixed: r0 = 0 first, EXIT last.
    #[test]
    fn gen_frame_shape() {
        let cfg = GenConfig::default();
        for seed in 0..100 {
            let insns = gen_prog(seed, &cfg);
            assert_eq!(insns[0], insn_lib::mov_imm(0, 0), "seed {seed}");
            assert_eq!(*insns.last().unwrap(), BpfInsn::Exit, "seed {seed}");
        }
    }

    /// gen_program_bytes produces the raw kernel encoding of the same
    /// program (#65 encoder).
    #[test]
    fn gen_bytes_matches_encoding() {
        let cfg = GenConfig {
            min_len: 5,
            max_len: 5,
        };
        let mut g = Generator::new(11);
        let insns = g.gen_program(&cfg);
        let mut g2 = Generator::new(11);
        let bytes = g2.gen_program_bytes(&cfg);
        assert_eq!(bytes.len(), insns.len() * 8);
        for (i, insn) in insns.iter().enumerate() {
            assert_eq!(&bytes[i * 8..(i + 1) * 8], &insn_lib::encode(insn));
        }
    }
}
