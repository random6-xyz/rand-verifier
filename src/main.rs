use std::env;

use anyhow::Result;
use rand_verifier::env::BpfVerifierEnv;
use rand_verifier::error::Verdict;

fn main() -> Result<()> {
    let mut bpf_verifier_env = BpfVerifierEnv::new();
    let args: Vec<String> = env::args().collect();

    let name = match args.get(1) {
        Some(name) => name.clone(),
        None => {
            anyhow::bail!(
                "Usage: {} <program_name>",
                args.first().unwrap_or(&"rand-verifier".into())
            );
        }
    };

    bpf_verifier_env.setup_prog(name)?;

    match bpf_verifier_env.verify()? {
        Verdict::Safe => {
            println!("Verification passed");
            if let Some(report) = bpf_verifier_env.concrete_report_text() {
                println!("{}", report);
            }
            Ok(())
        }
        Verdict::Unsafe(failure) => {
            println!("{}", failure);
            if let Some(report) = bpf_verifier_env.concrete_report_text() {
                println!("{}", report);
            }
            Ok(())
        }
    }
}
