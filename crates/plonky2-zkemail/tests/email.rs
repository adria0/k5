use anyhow::Result;
use num_bigint::BigUint;
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
};
use plonky2_zkemail::{
    email::*,
    sha256::{IV, pad},
    utils::*,
    *,
};
use sha2::{Digest, Sha256};

#[test]
fn body_hash_is_bound_to_dkim_tag_and_index() -> Result<()> {
    let header = include_bytes!("fixtures/header.txt");
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 128);
    let index = b.add_virtual_target();
    let digest = body_hash_from_header(&mut b, &input, index);
    b.register_public_inputs(&digest);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("DKIM body-hash extraction", gate_rows, data.common.degree());
    let start = header.windows(3).position(|s| s == b"bh=").unwrap() + 3;
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, header)?;
    pw.set_target(index, F::from_canonical_usize(start))?;
    let proof = data.prove(pw)?;
    assert_eq!(
        proof.public_inputs,
        Sha256::digest(b"Hello, Plonky2!\r\n")
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect::<Vec<_>>()
    );
    data.verify(proof)?;
    // The source DFA rejects NUL and unpaired UTF-8 bytes inside tag values.
    for (offset, byte) in [
        (0, b'x'),
        (start - 1, b':'),
        (start + 44, b' '),
        (17, 0),
        (17, 0x80),
    ] {
        let mut bad = header.to_vec();
        bad[offset] = byte;
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, &bad)?;
        pw.set_target(index, F::from_canonical_usize(start))?;
        assert!(data.prove(pw).is_err());
    }
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, header)?;
    pw.set_target(index, F::from_canonical_usize(start + 1))?;
    assert!(data.prove(pw).is_err());
    // Matching after a CRLF and a valid multi-byte UTF-8 tag value.
    let prefixed = String::from_utf8(header.to_vec())
        .unwrap()
        .replace("v=1", "v=é");
    let prefixed = format!("from:someone@example.com\r\n{prefixed}");
    let start = prefixed
        .as_bytes()
        .windows(3)
        .position(|s| s == b"bh=")
        .unwrap()
        + 3;
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, prefixed.as_bytes())?;
    pw.set_target(index, F::from_canonical_usize(start))?;
    let proof = data.prove(pw)?;
    data.verify(proof)?;
    Ok(())
}

#[test]
fn email_2048_body_masks_and_decoding() -> Result<()> {
    let config = EmailConfig {
        max_header_bytes: 128,
        max_body_bytes: 64,
        modulus_bytes: 256,
        ignore_body_hash: false,
        header_mask: true,
        body_mask: true,
        remove_soft_line_breaks: true,
        allow_partial_body_hash: false,
    };
    let circuit = EmailCircuit::build(&config);
    print_circuit_size(
        "Email-2048 with masks",
        circuit.gate_rows,
        circuit.data.common.degree(),
    );
    let header = pad(include_bytes!("fixtures/header.txt"));
    let body = pad(b"Hello, Plonky2!\r\n");
    let signature =
        BigUint::parse_bytes(include_str!("fixtures/signature.hex").trim().as_bytes(), 16).unwrap();
    let modulus =
        BigUint::parse_bytes(include_str!("fixtures/modulus.hex").trim().as_bytes(), 16).unwrap();
    let state: [u8; 32] = IV
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let index = header.windows(3).position(|s| s == b"bh=").unwrap() + 3;
    let header_mask = vec![false; 128];
    let mut body_mask = vec![false; 64];
    body_mask[..5].fill(true);
    let witness = EmailWitness {
        header: &header,
        header_length: header.len(),
        signature: &signature,
        modulus: &modulus,
        header_mask: Some(&header_mask),
        body: Some(BodyWitness {
            bytes: &body,
            length: body.len(),
            pre_hash: &state,
            hash_index: index,
            mask: Some(&body_mask),
            decoded: Some(&body),
        }),
    };
    let proof = circuit.prove(&witness)?;
    assert_eq!(proof.public_inputs.len(), 36 + 128 + 64);
    assert_eq!(
        &proof.public_inputs[36 + 128..36 + 128 + 5],
        b"Hello".map(F::from_canonical_u8)
    );
    let mut tampered_proof = proof.clone();
    tampered_proof.public_inputs[4] += F::ONE;
    assert!(circuit.data.verify(tampered_proof).is_err());
    circuit.data.verify(proof)?;
    // The full-body circuit must reject an attacker-supplied chaining state.
    let mut wrong_state = state;
    wrong_state[0] ^= 1;
    let bad_state = EmailWitness {
        body: Some(BodyWitness {
            pre_hash: &wrong_state,
            ..witness.body.unwrap()
        }),
        ..witness
    };
    assert!(circuit.prove(&bad_state).is_err());
    // Alter signed body data while retaining the valid RSA signature.
    let mut bad_body = body.clone();
    bad_body[0] ^= 1;
    let bad = EmailWitness {
        body: Some(BodyWitness {
            bytes: &bad_body,
            length: body.len(),
            pre_hash: &state,
            hash_index: index,
            mask: Some(&body_mask),
            decoded: Some(&bad_body),
        }),
        ..witness
    };
    assert!(circuit.prove(&bad).is_err());
    Ok(())
}

#[test]
fn email_header_only() -> Result<()> {
    let config = EmailConfig {
        max_header_bytes: 128,
        ignore_body_hash: true,
        ..EmailConfig::default()
    };
    let circuit = EmailCircuit::build(&config);
    print_circuit_size(
        "Header-only email",
        circuit.gate_rows,
        circuit.data.common.degree(),
    );
    let header = pad(include_bytes!("fixtures/header.txt"));
    let signature =
        BigUint::parse_bytes(include_str!("fixtures/signature.hex").trim().as_bytes(), 16).unwrap();
    let modulus =
        BigUint::parse_bytes(include_str!("fixtures/modulus.hex").trim().as_bytes(), 16).unwrap();
    let witness = EmailWitness {
        header: &header,
        header_length: header.len(),
        signature: &signature,
        modulus: &modulus,
        header_mask: None,
        body: None,
    };
    let proof = circuit.prove(&witness)?;
    assert_eq!(proof.public_inputs.len(), 36);
    let expected: Vec<_> = Sha256::digest(include_bytes!("fixtures/header.txt"))
        .into_iter()
        .map(F::from_canonical_u8)
        .collect();
    assert_eq!(&proof.public_inputs[4..], expected);
    circuit.data.verify(proof)?;
    Ok(())
}
