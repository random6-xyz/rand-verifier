use rand_verifier::decoder;

#[test]
fn decode_empty_bytecode() {
    let result = decoder::decode(&[]);
    assert!(result.is_ok());
    let instructions = result.unwrap();
    assert!(instructions.is_empty());
}
