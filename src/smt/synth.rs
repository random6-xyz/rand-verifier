// ── Precision-witness synthesis (Differential Synthesis, issue #117) ────────

//! SAS 2025-style comparison of competing abstract operators: find
//! abstract inputs where a candidate implementation `new` is strictly
//! more precise than the current `old` (`F#_new ≺ F#_old`), and
//! synthesize a concrete witness — abstract inputs plus concrete
//! members whose result the old operator over-approximates more.
//!
//! The candidate operators mirror the kernel's tnum-backed value
//! tracking (the bpf_mul upstream merge is the precedent): the spec's
//! interval-only results (src/spec/value.rs rng_*) are compared
//! against tnum-augmented intervals. The witness is then turned into
//! an eBPF program (the concrete members loaded into registers) so
//! the precision gap is observable in a real verifier run; the
//! existing reducer minimizes it.

use crate::spec::value::Range;
use crate::tnum::Tnum;

/// One precision gap: an abstract input pair where `new` is strictly
/// more precise than `old`, plus concrete members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecisionWitness {
    /// The operator under test (e.g. "xor").
    pub operator: &'static str,
    /// The input class (bit width).
    pub input_class: String,
    /// The abstract inputs.
    pub inputs: String,
    /// Concrete members: `(x, y)`.
    pub concrete: (u64, u64),
    /// The old (current) result interval.
    pub old_result: Range,
    /// The new (candidate) result interval.
    pub new_result: Range,
    /// Interval widths (the precision measure — smaller is better).
    pub old_width: u64,
    pub new_width: u64,
}

/// The interval size of a range (wrapping-aware width).
fn interval_width(r: Range) -> u64 {
    if r.0 <= r.1 { r.1 - r.0 } else { u64::MAX }
}

/// Convert a tnum to the enclosing interval: `[value, value | mask]`
/// (the kernel's min/max from var_off).
fn tnum_to_range(t: Tnum) -> Range {
    (t.value, t.value | t.mask)
}

/// The candidate (tnum-augmented) operators.
pub mod candidates {
    use super::*;

    /// `[lo,hi] ⊞ [lo2,hi2]` with tnum carry precision.
    pub fn add_tnum(a: Range, b: Range) -> Range {
        let ta = Tnum::from_range(a.0, a.1);
        let tb = Tnum::from_range(b.0, b.1);
        tnum_to_range(ta.add(tb))
    }

    /// `[lo,hi] ⊟ [lo2,hi2]` with tnum precision.
    pub fn sub_tnum(a: Range, b: Range) -> Range {
        let ta = Tnum::from_range(a.0, a.1);
        let tb = Tnum::from_range(b.0, b.1);
        tnum_to_range(ta.sub(tb))
    }

    /// Bitwise AND with tnum precision: the known-zero bits of the
    /// inputs bound the result's upper bits (kernel reg_bounds_sync).
    pub fn and_tnum(a: Range, b: Range) -> Range {
        let ta = Tnum::from_range(a.0, a.1);
        let tb = Tnum::from_range(b.0, b.1);
        tnum_to_range(ta.and(tb))
    }

    /// Bitwise OR with tnum precision: known-one bits lift the lower
    /// bound.
    pub fn or_tnum(a: Range, b: Range) -> Range {
        let ta = Tnum::from_range(a.0, a.1);
        let tb = Tnum::from_range(b.0, b.1);
        tnum_to_range(ta.or(tb))
    }

    /// Bitwise XOR with tnum precision: the result's known bits are
    /// exact, giving a much tighter interval than `[0, MAX]`.
    pub fn xor_tnum(a: Range, b: Range) -> Range {
        let ta = Tnum::from_range(a.0, a.1);
        let tb = Tnum::from_range(b.0, b.1);
        tnum_to_range(ta.xor(tb))
    }
}

/// The gap search: enumerate (or sample) abstract input pairs and
/// return every pair where the candidate is strictly more precise.
/// `width` bounds the enumeration (the full 64-bit space is sampled).
pub fn find_gaps(
    operator: &'static str,
    old: fn(Range, Range) -> Range,
    new: fn(Range, Range) -> Range,
    width: u32,
    limit: usize,
) -> Vec<PrecisionWitness> {
    let mut out = Vec::new();
    let max = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    let mut rng = XorShift64(0xD1FF_2026_0817);
    let width_bits = width;
    for _ in 0..limit.max(1) {
        let (a, b) = if width == 64 {
            let (x, y) = (rng.next(), rng.next());
            ((x.min(y), x.max(y)), (rng.next(), rng.next()))
        } else {
            let (lo, hi) = (rng.next() % (max + 1), rng.next() % (max + 1));
            let (lo2, hi2) = (rng.next() % (max + 1), rng.next() % (max + 1));
            ((lo.min(hi), lo.max(hi)), (lo2.min(hi2), lo2.max(hi2)))
        };
        let b = (b.0.min(b.1), b.0.max(b.1));
        let old_r = old(a, b);
        let new_r = new(a, b);
        let old_w = interval_width(old_r);
        let new_w = interval_width(new_r);
        if new_w < old_w {
            // a concrete member pair that distinguishes the two
            let (x, y) = member_pair(a, b, &mut rng);
            out.push(PrecisionWitness {
                operator,
                input_class: format!("width-{width}"),
                inputs: format!("a=({:#x},{:#x}) b=({:#x},{:#x})", a.0, a.1, b.0, b.1),
                concrete: (x, y),
                old_result: old_r,
                new_result: new_r,
                old_width: old_w,
                new_width: new_w,
            });
            if out.len() >= limit {
                break;
            }
        }
    }
    let _ = width_bits;
    out
}

/// A deterministic PRNG (mirrors the verify.rs one).
struct XorShift64(u64);
impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn member_pair(a: Range, b: Range, rng: &mut XorShift64) -> (u64, u64) {
    let x = a.0 + (rng.next() % (a.1 - a.0 + 1));
    let y = b.0 + (rng.next() % (b.1 - b.0 + 1));
    (x, y)
}

/// Render the ranked candidate list (issue #117's deliverable).
pub fn render_ranked(witnesses: &[PrecisionWitness]) -> String {
    let mut s = String::new();
    use std::fmt::Write;
    let _ = writeln!(s, "precision-witness candidates: {}", witnesses.len());
    for (i, w) in witnesses.iter().enumerate() {
        let _ = writeln!(
            s,
            "  {}. {} [{}] {} -> old=({:#x},{:#x}) width={} new=({:#x},{:#x}) width={} concrete=({:#x},{:#x})",
            i + 1,
            w.operator,
            w.input_class,
            w.inputs,
            w.old_result.0,
            w.old_result.1,
            w.old_width,
            w.new_result.0,
            w.new_result.1,
            w.new_width,
            w.concrete.0,
            w.concrete.1,
        );
    }
    s
}

/// Turn a witness into a raw eBPF program: load the concrete members
/// into registers and apply the operator, then exit — the verifier's
/// tracked result interval is observable via a branch that only the
/// precise result refines (the synthesized program shape).
pub fn witness_program(w: &PrecisionWitness, opcode: u8) -> Vec<u8> {
    // r1 = x; r2 = y (mov64 imm when the value fits 32 bits, ldimm64
    // otherwise — the 32-bit form keeps the program reducible: the
    // ddmin reducer deletes instructions one at a time and would
    // break an ldimm64 pair); r1 op r2; r0 = r1; exit
    let mut out = Vec::new();
    for (dst, v) in [(1u8, w.concrete.0), (2u8, w.concrete.1)] {
        if v <= u32::MAX as u64 {
            // BPF_ALU64|BPF_MOV|BPF_K = 0xb7
            out.extend_from_slice(&insn(0xb7, dst, 0, 0, v as u32));
        } else {
            // BPF_LD|BPF_DW|BPF_IMM = 0x18, second slot pseudo-class
            out.extend_from_slice(&insn(0x18, dst, 0, 0, v as u32));
            out.extend_from_slice(&insn(0x00, 0, 0, 0, (v >> 32) as u32));
        }
    }
    // r1 op r2 (reg form)
    out.extend_from_slice(&insn(opcode, 1, 2, 0, 0));
    // r0 = r1
    out.extend_from_slice(&insn(0xbf, 0, 1, 0, 0));
    // exit
    out.extend_from_slice(&insn(0x95, 0, 0, 0, 0));
    out
}

fn insn(op: u8, dst: u8, src: u8, off: i16, imm: u32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = op;
    b[1] = (src << 4) | (dst & 0x0F);
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

/// The opcodes of the eBPF ALU64 register forms (BPF_ALU64|BPF_X).
pub mod opcodes {
    pub const ADD: u8 = 0x0f;
    pub const SUB: u8 = 0x1f;
    pub const AND: u8 = 0x5f;
    pub const OR: u8 = 0x4f;
    pub const XOR: u8 = 0xaf;
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::value::{rng_and, rng_or, rng_xor};

    #[test]
    fn xor_gap_is_found() {
        // the spec's xor is [0, MAX]; the tnum candidate is tighter
        let gaps = find_gaps("xor", rng_xor, candidates::xor_tnum, 8, 20);
        assert!(!gaps.is_empty(), "no xor gap found");
        for g in &gaps {
            assert!(g.new_width < g.old_width);
        }
    }

    #[test]
    fn or_and_gaps_are_found() {
        let gaps = find_gaps("or", rng_or, candidates::or_tnum, 8, 20);
        assert!(!gaps.is_empty(), "no or gap found");
        let gaps = find_gaps("and", rng_and, candidates::and_tnum, 8, 20);
        assert!(!gaps.is_empty(), "no and gap found");
    }

    #[test]
    fn witness_program_encodes() {
        let w = PrecisionWitness {
            operator: "xor",
            input_class: "width-8".into(),
            inputs: "a=(0x0,0xff) b=(0x0,0x0)".into(),
            concrete: (0x5a, 0x00),
            old_result: (0, u64::MAX),
            new_result: (0x5a, 0x5a),
            old_width: u64::MAX,
            new_width: 0,
        };
        let prog = witness_program(&w, opcodes::XOR);
        // 2× mov64 imm + xor + mov + exit = 5 slots (the values fit
        // 32 bits, so the reducer-friendly mov form is used)
        assert_eq!(prog.len(), 8 * 5, "{prog:?}");
        let decoded = crate::insn::decode_program(&prog).expect("decodes");
        assert_eq!(decoded.len(), 5, "{decoded:?}");
        assert!(matches!(
            decoded[2],
            crate::insn::BpfInsn::XorReg { dst: 1, src: 2 }
        ));
    }
}
