// ── Verifier-stress idiom templates (v0.7, #67) ─────────────────────────────

//! Idiom templates that reliably exercise the milestone's precision-
//! sensitive semantics: overflow/wraparound, ALU32 truncation and
//! zero-extension, signed vs unsigned comparison refinement, branch
//! narrowing, stack spill/fill, the NULL-check idiom, and bounded
//! loops. Syzkaller reaches deep verifier features with idiom sequences
//! (`bpf_program_ringbuf`: reserve → null_check → body → free in
//! [sys/linux/bpf_prog.txt](https://github.com/google/syzkaller/blob/master/sys/linux/bpf_prog.txt));
//! these templates are the equivalent within the supported ISA subset.
//!
//! Every template body is **complete**: it sets its own r0 and ends
//! with an EXIT (or jumps to one), so the framed wrapper
//! ([`crate::fuzz::generator::Generator::gen_idiom_program`]) adds the
//! leading r0 init and only appends an EXIT when the body lacks one.
//! No template contains a mid-body EXIT — everything after one would
//! be unreachable dead code (nano rejects that).

use crate::fuzz::insn_lib;
use crate::fuzz::insn_lib::{IMMEDIATES, LARGE_IMMEDIATES};
use crate::fuzz::prng::SplitMix64;
use crate::insn::BpfInsn;

/// The available idiom templates, one per milestone focus area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Idiom {
    /// Unknown scalar (helper) or large constant plus repeated
    /// ADD/SUB with large immediates — wraparound and full-range
    /// fallback. Mirrors `tests/programs/accept/overflow_full_range`.
    OverflowChain,
    /// Boundary immediate → ALU32 op chain → ALU64 op — truncation,
    /// zero-extension, upper-32 known-zero. Mirrors
    /// `alu32_roundtrip` / `alu32_zero_extend`.
    Alu32Roundtrip,
    /// `call 7` then `JSGT` then `JGT` on the same register so both
    /// `smin/smax` and `umin/umax` narrow, then use the register.
    DualRefine,
    /// `call 7` then a chain of compares progressively shrinking the
    /// range, then use the register.
    NarrowingChain,
    /// store rX to [r10-8], clobber rX, reload, use — spill/fill
    /// roundtrip. Mirrors `stack_roundtrip`.
    SpillFill,
    /// `call 7`, NULL-check idiom (`jne r0, 0; +1; exit`) then use —
    /// syzkaller's `bpf_insn_null_check`. Mirrors
    /// `range_checked_access`.
    NullCheck,
    /// Counter register, increment, conditional backward edge —
    /// bounded loop. Mirrors `bounded_loop`.
    BoundedLoop,
}

/// All idioms, for iteration in tests.
pub const ALL_IDIOMS: &[Idiom] = &[
    Idiom::OverflowChain,
    Idiom::Alu32Roundtrip,
    Idiom::DualRefine,
    Idiom::NarrowingChain,
    Idiom::SpillFill,
    Idiom::NullCheck,
    Idiom::BoundedLoop,
];

/// A work register R1..R9 (never R0 — R0 carries the result/exit value).
fn work_reg(rng: &mut SplitMix64) -> u8 {
    1 + rng.below(9) as u8
}

/// Generate the body of one idiom template (complete: r0 set, EXIT at
/// the end or reachable). Random parameters come from `rng`; the
/// structure is fixed.
pub(crate) fn gen_idiom_body(idiom: Idiom, rng: &mut SplitMix64) -> Vec<BpfInsn> {
    match idiom {
        Idiom::OverflowChain => overflow_chain(rng),
        Idiom::Alu32Roundtrip => alu32_roundtrip(rng),
        Idiom::DualRefine => dual_refine(rng),
        Idiom::NarrowingChain => narrowing_chain(rng),
        Idiom::SpillFill => spill_fill(rng),
        Idiom::NullCheck => null_check(rng),
        Idiom::BoundedLoop => bounded_loop(rng),
    }
}

/// Unknown scalar (helper) or a large constant, then 2..=6 ADD/SUB
/// operations with large immediates/register sources. The helper
/// variant mirrors `overflow_full_range` (call 7 → add 1e9).
fn overflow_chain(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    let from_helper = rng.below(2) == 0;
    let chain_len = 2 + rng.below(5) as usize; // 2..=6
    if from_helper {
        insns.push(insn_lib::call(7)); // r0 = unknown scalar
        for _ in 0..chain_len {
            push_add_sub(rng, &mut insns, 0);
        }
    } else {
        let reg = work_reg(rng);
        insns.push(insn_lib::mov_imm(reg, *rng.pick(LARGE_IMMEDIATES)));
        for _ in 0..chain_len {
            push_add_sub(rng, &mut insns, reg);
        }
        insns.push(insn_lib::mov_reg(0, reg));
    }
    insns.push(insn_lib::exit());
    insns
}

/// One random ADD/SUB (imm or reg form, large immediate when imm) on
/// `dst`. The register-source form reads `dst` itself — every other
/// register may still be uninitialized at this point.
fn push_add_sub(rng: &mut SplitMix64, insns: &mut Vec<BpfInsn>, dst: u8) {
    let op = rng.below(2); // 0 = add, 1 = sub
    let k_form = rng.below(2) == 0;
    match (op, k_form) {
        (0, true) => insns.push(insn_lib::add_imm(dst, *rng.pick(LARGE_IMMEDIATES))),
        (0, false) => insns.push(insn_lib::add_reg(dst, dst)),
        (1, true) => insns.push(insn_lib::sub_imm(dst, *rng.pick(LARGE_IMMEDIATES))),
        (1, false) => insns.push(insn_lib::sub_reg(dst, dst)),
        _ => unreachable!(),
    }
}

/// Boundary immediate, 1..=4 ALU32 ops, one ALU64 op, use. Mirrors
/// `alu32_roundtrip` ([-1, add32 0, add32 1]) and `alu32_zero_extend`
/// ([INT32_MIN, add32 0, add64 1]).
fn alu32_roundtrip(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let reg = work_reg(rng);
    let mut insns = vec![insn_lib::mov_imm(reg, *rng.pick(IMMEDIATES))];
    let n = 1 + rng.below(4) as usize; // 1..=4 ALU32 ops
    for _ in 0..n {
        let op = rng.below(4); // 0 = add32, 1 = sub32, 2 = xor32, 3 = and32
        let k_form = rng.below(2) == 0;
        match (op, k_form) {
            (0, true) => insns.push(insn_lib::add32_imm(reg, *rng.pick(IMMEDIATES))),
            // register sources read `reg` itself — other registers may
            // still be uninitialized here
            (0, false) => insns.push(insn_lib::add32_reg(reg, reg)),
            (1, true) => insns.push(insn_lib::sub32_imm(reg, *rng.pick(IMMEDIATES))),
            (1, false) => insns.push(insn_lib::sub32_reg(reg, reg)),
            (2, true) => insns.push(insn_lib::xor32_imm(reg, *rng.pick(IMMEDIATES))),
            (2, false) => insns.push(insn_lib::xor32_reg(reg, reg)),
            (3, true) => insns.push(insn_lib::and32_imm(reg, *rng.pick(IMMEDIATES))),
            (3, false) => insns.push(insn_lib::and32_reg(reg, reg)),
            _ => unreachable!(),
        }
    }
    // one ALU64 op — exercises zero-extension of the 32-bit result
    if rng.below(2) == 0 {
        insns.push(insn_lib::add_imm(reg, 1));
    } else {
        insns.push(insn_lib::sub_imm(reg, 1));
    }
    insns.push(insn_lib::mov_reg(0, reg));
    insns.push(insn_lib::exit());
    insns
}

/// `call 7` → rC = imm → `jsgt r0, rC, +2` → `jgt r0, rC, +1` → use:
/// the taken paths exit, the fall-through narrows both `smax` and
/// `umax` before the use.
fn dual_refine(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let c = work_reg(rng);
    let imm = *rng.pick(IMMEDIATES);
    vec![
        insn_lib::call(7),
        insn_lib::mov_imm(c, imm),
        // jsgt at idx 2: taken → idx 5 (exit); fall → idx 3 (jgt)
        insn_lib::jsgt(0, c, 2),
        // jgt at idx 3: taken → idx 5 (exit); fall → idx 4 (use)
        insn_lib::jgt(0, c, 1),
        insn_lib::mov_reg(0, 0),
        insn_lib::exit(),
    ]
}

/// `call 7` → rC = imm → n compares (each taken path skips the rest to
/// the use) → use. Every compare narrows the range one more step.
fn narrowing_chain(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let c = work_reg(rng);
    let imm = *rng.pick(IMMEDIATES);
    let n = 2 + rng.below(5) as usize; // 2..=6 compares
    let mut insns = vec![insn_lib::call(7), insn_lib::mov_imm(c, imm)];
    for j in 0..n {
        // compare j sits at insns.len(); the use sits after all
        // compares, so the taken path skips the remaining compares:
        // offset = (remaining compares) + 1 (the use)
        let remaining = n - j - 1;
        let offset = (remaining + 1) as i16;
        let op = rng.below(8); // jgt, jge, jlt, jle, jsgt, jsge, jslt, jsle
        let k_form = rng.below(2) == 0;
        match (op, k_form) {
            (0, true) => insns.push(insn_lib::jgt_imm(0, imm, offset)),
            (0, false) => insns.push(insn_lib::jgt(0, c, offset)),
            (1, true) => insns.push(insn_lib::jge_imm(0, imm, offset)),
            (1, false) => insns.push(insn_lib::jge(0, c, offset)),
            (2, true) => insns.push(insn_lib::jlt_imm(0, imm, offset)),
            (2, false) => insns.push(insn_lib::jlt(0, c, offset)),
            (3, true) => insns.push(insn_lib::jle_imm(0, imm, offset)),
            (3, false) => insns.push(insn_lib::jle(0, c, offset)),
            (4, true) => insns.push(insn_lib::jsgt_imm(0, imm, offset)),
            (4, false) => insns.push(insn_lib::jsgt(0, c, offset)),
            (5, true) => insns.push(insn_lib::jsge_imm(0, imm, offset)),
            (5, false) => insns.push(insn_lib::jsge(0, c, offset)),
            (6, true) => insns.push(insn_lib::jslt_imm(0, imm, offset)),
            (6, false) => insns.push(insn_lib::jslt(0, c, offset)),
            (7, true) => insns.push(insn_lib::jsle_imm(0, imm, offset)),
            (7, false) => insns.push(insn_lib::jsle(0, c, offset)),
            _ => unreachable!(),
        }
    }
    insns.push(insn_lib::mov_reg(0, 0));
    insns.push(insn_lib::exit());
    insns
}

/// store rX to [r10-8], clobber rX, reload, use. Mirrors
/// `stack_roundtrip` / `pointer_spill_fill`.
fn spill_fill(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let reg = work_reg(rng);
    let offset: i16 = -8 * (1 + rng.below(4) as i16); // -8, -16, -24, -32
    vec![
        insn_lib::mov_imm(reg, *rng.pick(IMMEDIATES)),
        insn_lib::st_stack(reg, offset),
        insn_lib::mov_imm(reg, 0), // clobber
        insn_lib::ld_stack(reg, offset),
        insn_lib::mov_reg(0, reg),
        insn_lib::exit(),
    ]
}

/// `call 7` → rC = 0 → `jne r0, rC, +1` (non-null skips the exit) →
/// exit → use. Syzkaller's `bpf_insn_null_check`; mirrors
/// `range_checked_access`.
fn null_check(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let c = work_reg(rng);
    vec![
        insn_lib::call(7),
        insn_lib::mov_imm(c, 0),
        // jne at idx 2: taken (non-null) → idx 4 (use); fall (null) →
        // idx 3 (exit)
        insn_lib::jne(0, c, 1),
        insn_lib::exit(),
        insn_lib::mov_imm(0, 1),
        insn_lib::exit(),
    ]
}

/// counter = count (1..=100), index = 0, index += 1, `jlt index,
/// counter, -2`, use index. Mirrors `bounded_loop`.
fn bounded_loop(rng: &mut SplitMix64) -> Vec<BpfInsn> {
    let count = 1 + rng.below(100) as i32; // 1..=100
    let cnt_reg = work_reg(rng);
    let mut idx_reg = work_reg(rng);
    while idx_reg == cnt_reg {
        idx_reg = work_reg(rng);
    }
    vec![
        insn_lib::mov_imm(cnt_reg, count),
        insn_lib::mov_imm(idx_reg, 0),
        // loop head
        insn_lib::add_imm(idx_reg, 1),
        // jlt at idx 3: taken → idx 2 (loop head); fall → idx 4 (use)
        insn_lib::jlt(idx_reg, cnt_reg, -2),
        insn_lib::mov_reg(0, idx_reg),
        insn_lib::exit(),
    ]
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::BpfVerifierEnv;
    use crate::error::Verdict;
    use crate::fuzz::generator::Generator;

    fn gen_idiom(seed: u64, idiom: Idiom) -> Vec<BpfInsn> {
        Generator::new(seed).gen_idiom_program(idiom)
    }

    fn verify(insns: &[BpfInsn]) -> (Verdict, BpfVerifierEnv) {
        let bytes: Vec<u8> = insns.iter().flat_map(insn_lib::encode).collect();
        let mut env = BpfVerifierEnv::new();
        env.setup_prog_bytes(&bytes).unwrap();
        let verdict = env.verify().unwrap();
        (verdict, env)
    }

    /// Every idiom template (multiple seeds) verifies as Safe with a
    /// clean concrete run — mirroring the corpus fixtures they are
    /// modelled on (acceptance: reproduce the fixture's verdict).
    #[test]
    fn idiom_verdict_reproduction() {
        for idiom in ALL_IDIOMS {
            for seed in 0..5 {
                let (verdict, env) = verify(&gen_idiom(seed, *idiom));
                assert!(
                    matches!(verdict, Verdict::Safe),
                    "{idiom:?} seed {seed}: expected Safe, got {verdict:?}"
                );
                let report = env.concrete_report.as_ref().unwrap();
                assert!(
                    report.violations.is_empty(),
                    "{idiom:?} seed {seed}: coverage violations {:?}",
                    report.violations
                );
            }
        }
    }

    /// Each template contains its expected opcode/pattern mix.
    #[test]
    fn idiom_patterns() {
        // OverflowChain: an ADD/SUB somewhere (large-immediate imm
        // forms come from LARGE_IMMEDIATES by construction)
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::OverflowChain);
            let has_add_sub = insns.iter().any(|i| {
                matches!(
                    i,
                    BpfInsn::AddImm { .. }
                        | BpfInsn::AddReg { .. }
                        | BpfInsn::SubImm { .. }
                        | BpfInsn::SubReg { .. }
                )
            });
            assert!(has_add_sub, "overflow chain seed {seed}: no ADD/SUB");
        }

        // Alu32Roundtrip: at least one ALU32 op and one ALU64 op
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::Alu32Roundtrip);
            let has_alu32 = insns.iter().any(|i| {
                matches!(
                    i,
                    BpfInsn::Add32Imm { .. }
                        | BpfInsn::Add32Reg { .. }
                        | BpfInsn::Sub32Imm { .. }
                        | BpfInsn::Sub32Reg { .. }
                        | BpfInsn::Xor32Imm { .. }
                        | BpfInsn::Xor32Reg { .. }
                        | BpfInsn::And32Imm { .. }
                        | BpfInsn::And32Reg { .. }
                )
            });
            let has_alu64 = insns
                .iter()
                .any(|i| matches!(i, BpfInsn::AddImm { .. } | BpfInsn::SubImm { .. }));
            assert!(has_alu32 && has_alu64, "alu32 roundtrip seed {seed}");
        }

        // DualRefine: both a signed and an unsigned greater-than compare
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::DualRefine);
            let has_jsgt = insns
                .iter()
                .any(|i| matches!(i, BpfInsn::Jsgt { .. } | BpfInsn::JsgtImm { .. }));
            let has_jgt = insns
                .iter()
                .any(|i| matches!(i, BpfInsn::Jgt { .. } | BpfInsn::JgtImm { .. }));
            assert!(has_jsgt && has_jgt, "dual refine seed {seed}");
        }

        // NarrowingChain: at least two compares
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::NarrowingChain);
            let cmp_count = insns.iter().filter(|i| is_compare(i)).count();
            assert!(
                cmp_count >= 2,
                "narrowing chain seed {seed}: {cmp_count} compares"
            );
        }

        // SpillFill: store before load
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::SpillFill);
            let st = insns
                .iter()
                .position(|i| matches!(i, BpfInsn::StMem { .. }));
            let ld = insns
                .iter()
                .position(|i| matches!(i, BpfInsn::LdMem { .. }));
            assert!(
                matches!((st, ld), (Some(s), Some(l)) if s < l),
                "spill/fill seed {seed}"
            );
        }

        // NullCheck: helper call + jne + two exits
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::NullCheck);
            let has_call = insns.iter().any(|i| matches!(i, BpfInsn::Call { .. }));
            let has_jne = insns
                .iter()
                .any(|i| matches!(i, BpfInsn::Jne { .. } | BpfInsn::JneImm { .. }));
            let exits = insns.iter().filter(|i| matches!(i, BpfInsn::Exit)).count();
            assert!(has_call && has_jne && exits >= 2, "null check seed {seed}");
        }

        // BoundedLoop: a conditional branch with a negative offset
        for seed in 0..20 {
            let insns = gen_idiom(seed, Idiom::BoundedLoop);
            let has_back_edge = insns.iter().any(|i| {
                matches!(
                    i,
                    BpfInsn::Jlt { offset, .. }
                        | BpfInsn::JltImm { offset, .. }
                        | BpfInsn::Jle { offset, .. }
                        | BpfInsn::JleImm { offset, .. }
                        | BpfInsn::Jslt { offset, .. }
                        | BpfInsn::JsltImm { offset, .. }
                        | BpfInsn::Jsle { offset, .. }
                        | BpfInsn::JsleImm { offset, .. }
                        if *offset < 0
                )
            });
            assert!(has_back_edge, "bounded loop seed {seed}: no backward edge");
        }
    }

    /// Same seed → identical idiom output.
    #[test]
    fn idiom_deterministic() {
        for idiom in ALL_IDIOMS {
            assert_eq!(gen_idiom(42, *idiom), gen_idiom(42, *idiom));
        }
    }

    /// Every idiom output passes the nano structural checks (the
    /// templates are complete: no mid-body exit, valid offsets).
    #[test]
    fn idiom_nano_valid() {
        use crate::cfg::{add_subprog, check_cfg};
        for idiom in ALL_IDIOMS {
            for seed in 0..50 {
                let insns = gen_idiom(seed, *idiom);
                let subprogs = add_subprog(&insns).expect("add_subprog");
                check_cfg(&insns, &subprogs)
                    .unwrap_or_else(|e| panic!("{idiom:?} seed {seed}: nano rejected: {e}"));
            }
        }
    }

    fn is_compare(insn: &BpfInsn) -> bool {
        matches!(
            insn,
            BpfInsn::Jeq { .. }
                | BpfInsn::Jne { .. }
                | BpfInsn::Jgt { .. }
                | BpfInsn::Jge { .. }
                | BpfInsn::Jlt { .. }
                | BpfInsn::Jle { .. }
                | BpfInsn::Jsgt { .. }
                | BpfInsn::Jsge { .. }
                | BpfInsn::Jslt { .. }
                | BpfInsn::Jsle { .. }
                | BpfInsn::JeqImm { .. }
                | BpfInsn::JneImm { .. }
                | BpfInsn::JgtImm { .. }
                | BpfInsn::JgeImm { .. }
                | BpfInsn::JltImm { .. }
                | BpfInsn::JleImm { .. }
                | BpfInsn::JsgtImm { .. }
                | BpfInsn::JsgeImm { .. }
                | BpfInsn::JsltImm { .. }
                | BpfInsn::JsleImm { .. }
        )
    }
}
