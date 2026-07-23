use rand_verifier::program::Program;
use rand_verifier::verifier::nano::NanoVerifier;

#[test]
fn nano_accepts_empty_program() {
    let verifier = NanoVerifier::new();
    let program = Program::new(vec![]);
    assert!(verifier.verify(&program).is_ok());
}
