//! Prove and verify the synthetic 2048-bit RSA/SHA-256 email fixture.
use anyhow::Result;
use num_bigint::BigUint;
use plonky2_zkemail::{
    email::{BodyWitness, EmailCircuit, EmailConfig, EmailWitness},
    print_circuit_size,
    sha256::{IV, pad},
};

fn main() -> Result<()> {
    let config = EmailConfig {
        max_header_bytes: 128,
        max_body_bytes: 64,
        ..EmailConfig::default()
    };
    let header = pad(include_bytes!("../tests/fixtures/header.txt"));
    let body = pad(b"Hello, Plonky2!\r\n");
    let modulus = BigUint::parse_bytes(
        include_str!("../tests/fixtures/modulus.hex")
            .trim()
            .as_bytes(),
        16,
    )
    .unwrap();
    let signature = BigUint::parse_bytes(
        include_str!("../tests/fixtures/signature.hex")
            .trim()
            .as_bytes(),
        16,
    )
    .unwrap();
    let state: [u8; 32] = IV
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let index = header.windows(3).position(|s| s == b"bh=").unwrap() + 3;
    let input = EmailWitness {
        header: &header,
        header_length: header.len(),
        signature: &signature,
        modulus: &modulus,
        header_mask: None,
        body: Some(BodyWitness {
            bytes: &body,
            length: body.len(),
            pre_hash: &state,
            hash_index: index,
            mask: None,
            decoded: None,
        }),
    };
    println!("Building the email circuit...");
    let circuit = EmailCircuit::build(&config);
    print_circuit_size(
        "Synthetic email circuit",
        circuit.gate_rows,
        circuit.data.common.degree(),
    );
    println!("Proving...");
    let proof = circuit.prove(&input)?;
    // In an application, compare these public inputs with trusted expectations.
    println!("Public inputs: {:?}", proof.public_inputs);
    circuit.data.verify(proof)?;
    println!("Proof verified.");
    Ok(())
}
