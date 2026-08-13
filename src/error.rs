// ── Verification error types ────────────────────────────────────────────────

/// A single verification failure: where it happened and why.
#[derive(Debug, Clone)]
pub struct VerificationFailure {
    pub(crate) insn_idx: u32,   // instruction index where verification failed
    pub(crate) message: String, // e.g. "unbounded loop", "invalid access"
}

impl VerificationFailure {
    pub(crate) fn new(insn_idx: u32, message: impl Into<String>) -> Self {
        Self {
            insn_idx,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "verification failed at insn {}: {}",
            self.insn_idx, self.message
        )
    }
}

/// The overall result of running the verification pipeline on a program.
pub enum Verdict {
    Safe,
    Unsafe(VerificationFailure),
}
