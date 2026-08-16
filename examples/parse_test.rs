fn main() {
    let m = rand_verifier::env::parse_maps_sidecar("tests/programs/accept/ringbuf_reserve_submit");
    println!("{:?}", m);
}
