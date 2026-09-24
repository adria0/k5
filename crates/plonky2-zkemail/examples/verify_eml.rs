//! Complete `.eml` -> DKIM preparation -> Plonky2 proof -> verifier flow.

use anyhow::{Result, ensure};
use plonky2_zkemail::eml;
use std::{path::Path, time::Instant};

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const DEFAULT_EMAIL: &str = "examples/fixtures/test.eml";
const DEFAULT_KEY: &str = "examples/fixtures/icloud-dkim.json";

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() <= 2,
        "Usage: verify_eml [EMAIL.eml [TRUSTED_KEY.json]]"
    );
    let email_path = args
        .first()
        .map_or_else(|| Path::new(ROOT).join(DEFAULT_EMAIL), Into::into);
    let key_path = args
        .get(1)
        .map_or_else(|| Path::new(ROOT).join(DEFAULT_KEY), Into::into);

    println!("Proving {}...", email_path.display());
    let start = Instant::now();
    let proof = eml::prove(&email_path, &key_path)?;
    println!(
        "Verified d={}, s={} in {:.1}s: {}-byte proof, {} gate rows, {} padded rows.",
        proof.domain,
        proof.selector,
        start.elapsed().as_secs_f64(),
        proof.bytes.len(),
        proof.gate_rows,
        proof.padded_rows,
    );
    Ok(())
}
