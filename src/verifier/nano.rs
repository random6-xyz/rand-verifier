use crate::cfg::Cfg;
use crate::error::VerifyError;
use crate::program::Program;

/// The nano verifier performs structural (CFG-level) verification
/// of eBPF programs.
///
/// It checks:
/// - All jump targets are valid
/// - No backward jumps
/// - All instructions are reachable
/// - Every reachable path terminates with `exit`
#[derive(Debug, Default)]
pub struct NanoVerifier;

impl NanoVerifier {
    /// Create a new nano verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Verify a program, returning `Ok(())` on acceptance or a `VerifyError` on rejection.
    ///
    /// # Errors
    ///
    /// Returns a `VerifyError` describing the first structural problem found.
    pub fn verify(&self, program: &Program) -> Result<(), VerifyError> {
        let _cfg = Cfg::from_program(program);

        // TODO: implement full verification in issues #6-#9:
        // 1. Validate jump targets
        // 2. Reject backward jumps
        // 3. Detect unreachable instructions (DFS from entry)
        // 4. Ensure all terminal nodes are Exit

        Ok(())
    }
}
