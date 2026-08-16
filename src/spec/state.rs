// ── Spec state: registers, stack, frames ────────────────────────────────────

//! The ProgSpec execution state (issue #112). The stack model is
//! byte-granular initialization plus 8-byte spill slots, independent
//! of mini's [`crate::state::StackState`] (which tracks per-byte slot
//! kinds, spill metadata, dynptr byte types and reference ids).
//!
//! Safety invariants enforced at access time (SpecCheck SP2):
//! in-bounds, properly aligned, initialized reads; pointer spills
//! refuse partial (narrow) fills; partially covered spills refuse
//! narrowing writes.

use super::value::SpecValue;

/// Stack size (kernel BPF_MAX_VAR_SIZ... frame is 512 bytes).
pub(crate) const SPEC_STACK_SIZE: usize = 512;

/// Number of 8-byte spill slots.
pub(crate) const SPEC_SLOTS: usize = SPEC_STACK_SIZE / 8;

/// A spilled 8-byte stack slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Spill {
    /// A spilled scalar: the low 32 bits are exact; the high half may
    /// be unknown (a 32-bit store zero-extends, a 64-bit store is
    /// full-width).
    Scalar { lo: u64, hi: u64 },
    /// A spilled pointer with its full dynamic type.
    Ptr(SpecValue),
}

/// The spec's stack: byte initialization mask + values, plus the
/// 8-byte spill slots and dynptr markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SpecStack {
    pub(crate) bytes: [u8; SPEC_STACK_SIZE],
    pub(crate) init: [bool; SPEC_STACK_SIZE],
    pub(crate) spill: [Option<Spill>; SPEC_SLOTS],
    /// Slots holding an initialized dynptr (helper 197 / 238-243
    /// family).
    pub(crate) dynptr: [bool; SPEC_SLOTS],
}

impl SpecStack {
    /// The absolute byte index of a stack-relative offset `off`
    /// (`R10 = SPEC_STACK_SIZE`).
    pub(crate) fn byte_index(off: i64) -> Option<usize> {
        let idx = SPEC_STACK_SIZE as i64 + off;
        if idx >= 0 && (idx as usize) < SPEC_STACK_SIZE {
            Some(idx as usize)
        } else {
            None
        }
    }

    /// The slot index covering byte offset `off` (relative to R10).
    pub(crate) fn slot_of(off: i64) -> Option<usize> {
        let idx = SPEC_STACK_SIZE as i64 + off;
        if idx >= 0 && (idx as usize) < SPEC_STACK_SIZE {
            Some(idx as usize / 8)
        } else {
            None
        }
    }
}

/// One verifier frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SpecFrame {
    pub(crate) regs: [SpecValue; 11],
    pub(crate) stack: SpecStack,
    /// The return pc (call site + 1) for THIS frame — like the
    /// kernel's per-frame `callsite`.
    pub(crate) ret_pc: u32,
}

impl SpecFrame {
    /// A fresh main frame: R1 = ctx, R10 = stack base, the rest
    /// uninitialized.
    pub(crate) fn main() -> Self {
        let mut regs = [SpecValue::Uninit; 11];
        regs[1] = SpecValue::PtrToCtx;
        regs[10] = SpecValue::PtrToStack { lo: 0, hi: 0 };
        Self {
            regs,
            stack: SpecStack {
                bytes: [0; SPEC_STACK_SIZE],
                init: [false; SPEC_STACK_SIZE],
                spill: [None; SPEC_SLOTS],
                dynptr: [false; SPEC_SLOTS],
            },
            ret_pc: 0,
        }
    }

    /// A fresh callee frame: R10 = stack base, nothing else set.
    pub(crate) fn callee() -> Self {
        let mut regs = [SpecValue::Uninit; 11];
        regs[10] = SpecValue::PtrToStack { lo: 0, hi: 0 };
        Self {
            regs,
            stack: SpecStack {
                bytes: [0; SPEC_STACK_SIZE],
                init: [false; SPEC_STACK_SIZE],
                spill: [None; SPEC_SLOTS],
                dynptr: [false; SPEC_SLOTS],
            },
            ret_pc: 0,
        }
    }
}

/// The full spec state: the current frame plus the saved caller
/// frames of active BPF-to-BPF calls (max depth 8 — the kernel's
/// MAX_CALL_FRAMES is 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SpecState {
    pub(crate) cur: SpecFrame,
    pub(crate) saved: [Option<SpecFrame>; 7],
    /// Active acquired reference ids (ringbuf reserve, dynptr slices).
    pub(crate) refs: [u32; 8],
    pub(crate) refs_cnt: u8,
}

impl SpecState {
    pub(crate) fn initial() -> Self {
        Self {
            cur: SpecFrame::main(),
            saved: [None; 7],
            refs: [0; 8],
            refs_cnt: 0,
        }
    }

    pub(crate) fn reg(&self, r: u8) -> SpecValue {
        self.cur.regs[r as usize]
    }

    pub(crate) fn set_reg(&mut self, r: u8, v: SpecValue) {
        self.cur.regs[r as usize] = v;
    }

    /// Acquire a reference id (fresh, high space to avoid collisions
    /// with anything else).
    pub(crate) fn acquire_ref(&mut self, id: u32) -> Result<(), &'static str> {
        if self.refs_cnt as usize >= self.refs.len() {
            return Err("too many active references");
        }
        self.refs[self.refs_cnt as usize] = id;
        self.refs_cnt += 1;
        Ok(())
    }

    /// Release a reference by id (ringbuf submit/discard).
    pub(crate) fn release_ref(&mut self, id: u32) -> bool {
        let i = self.refs[..self.refs_cnt as usize]
            .iter()
            .position(|r| *r == id);
        match i {
            Some(i) => {
                self.refs[i] = self.refs[self.refs_cnt as usize - 1];
                self.refs_cnt -= 1;
                true
            }
            None => false,
        }
    }

    pub(crate) fn has_ref(&self, id: u32) -> bool {
        self.refs[..self.refs_cnt as usize].contains(&id)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_initial_state() {
        let f = SpecFrame::main();
        assert_eq!(f.regs[1], SpecValue::PtrToCtx);
        assert_eq!(f.regs[10], SpecValue::PtrToStack { lo: 0, hi: 0 });
        assert_eq!(f.regs[0], SpecValue::Uninit);
    }

    #[test]
    fn byte_index_mapping() {
        assert_eq!(SpecStack::byte_index(-1), Some(511));
        assert_eq!(SpecStack::byte_index(-512), Some(0));
        assert_eq!(SpecStack::byte_index(0), None);
        assert_eq!(SpecStack::byte_index(-513), None);
    }

    #[test]
    fn refs_acquire_release() {
        let mut s = SpecState::initial();
        s.acquire_ref(7).unwrap();
        s.acquire_ref(9).unwrap();
        assert!(s.has_ref(7));
        assert!(s.has_ref(9));
        assert!(s.release_ref(7));
        assert!(!s.has_ref(7));
        assert!(!s.release_ref(7));
        assert!(s.has_ref(9));
    }
}
