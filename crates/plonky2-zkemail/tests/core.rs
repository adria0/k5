use anyhow::Result;
use num_bigint::BigUint;
use plonky2::{
    field::types::Field,
    iop::witness::{PartialWitness, WitnessWrite},
};
use plonky2_zkemail::{
    bigint::*,
    sha256::*,
    utils::{assert_zero_padding, bytes, set_bytes},
    *,
};
use sha2::{Digest, Sha256};

#[test]
fn sha_known_vectors_and_padding_boundaries() -> Result<()> {
    for message in [
        vec![],
        b"abc".to_vec(),
        vec![0xa5; 55],
        vec![0x7f; 56],
        vec![0x80; 64],
    ] {
        let mut b = Builder::new(circuit_config());
        let input = bytes(&mut b, message.len());
        let out = sha256(&mut b, &input);
        b.register_public_inputs(&out);
        let gate_rows = b.num_gates();
        let data = b.build::<C>();
        print_circuit_size(
            &format!("SHA-256 ({} input bytes)", message.len()),
            gate_rows,
            data.common.degree(),
        );
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, &message)?;
        let proof = data.prove(pw)?;
        let expected: Vec<_> = Sha256::digest(&message)
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect();
        assert_eq!(proof.public_inputs, expected);
        data.verify(proof)?;
    }
    Ok(())
}

#[test]
fn constrained_sha_padding_rejects_malformed_encodings() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 128);
    let length = b.add_virtual_target();
    assert_zero_padding(&mut b, &input, length);
    assert_sha256_padding(&mut b, &input, length);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("SHA-256 padding", gate_rows, data.common.degree());

    for message in [b"abc".as_slice(), &[b'x'; 56][..]] {
        let padded = pad(message);
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, &padded)?;
        pw.set_target(length, F::from_canonical_usize(padded.len()))?;
        let proof = data.prove(pw)?;
        data.verify(proof)?;
    }

    let valid = pad(b"abc");
    for offset in [3, 4, 63] {
        let mut malformed = valid.clone();
        malformed[offset] ^= 1;
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, &malformed)?;
        pw.set_target(length, F::from_canonical_usize(valid.len()))?;
        assert!(data.prove(pw).is_err(), "malformed byte at {offset}");
    }
    // A two-block encoding for a short message is not the minimal SHA padding.
    let mut extended = vec![0; 128];
    extended[..3].copy_from_slice(b"abc");
    extended[3] = 0x80;
    extended[127] = 24;
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, &extended)?;
    pw.set_target(length, F::from_canonical_usize(extended.len()))?;
    assert!(data.prove(pw).is_err());
    Ok(())
}

#[test]
fn variable_length_partial_state_and_invalid_lengths() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 128);
    let length = b.add_virtual_target();
    let pre: [_; 32] = bytes(&mut b, 32).try_into().unwrap();
    let out = sha256_padded(&mut b, &input, length, Some(&pre));
    b.register_public_inputs(&out);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("Partial SHA-256", gate_rows, data.common.degree());
    for message in [b"abc".to_vec(), vec![0x42; 150]] {
        let padded = pad(&message);
        let (state, suffix) = if padded.len() > 128 {
            let mut state = IV;
            let block: [u8; 64] = padded[..64].try_into().unwrap();
            sha2::compress256(&mut state, &[block.into()]);
            (state, &padded[64..])
        } else {
            (IV, padded.as_slice())
        };
        let state_bytes: Vec<_> = state.into_iter().flat_map(u32::to_be_bytes).collect();
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, suffix)?;
        set_bytes(&mut pw, &pre, &state_bytes)?;
        pw.set_target(length, F::from_canonical_usize(suffix.len()))?;
        let proof = data.prove(pw)?;
        let expected: Vec<_> = Sha256::digest(&message)
            .iter()
            .map(|&x| F::from_canonical_u8(x))
            .collect();
        assert_eq!(proof.public_inputs, expected);
        data.verify(proof)?;
    }
    for bad in [0, 63, 129, 192] {
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, &pad(b"abc"))?;
        set_bytes(
            &mut pw,
            &pre,
            &IV.into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>(),
        )?;
        pw.set_target(length, F::from_canonical_usize(bad))?;
        assert!(data.prove(pw).is_err());
    }
    Ok(())
}

#[test]
fn modular_multiplication_carries_and_forged_remainder() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let a = BigUintTarget::new(&mut b, 2);
    let c = BigUintTarget::new(&mut b, 2);
    let m = BigUintTarget::new(&mut b, 2);
    let mul = ModMulTarget::new(&mut b, &a, &c, &m);
    b.register_public_inputs(&mul.remainder.limbs);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("Modular multiplication", gate_rows, data.common.degree());
    let av = BigUint::from(0xffff_fffeu32);
    let cv = BigUint::from(0xffff_fffdu32);
    let mv = BigUint::from(0xffff_ffffu32);
    let mut pw = PartialWitness::new();
    a.set(&mut pw, &av)?;
    c.set(&mut pw, &cv)?;
    m.set(&mut pw, &mv)?;
    mul.set(&mut pw, &av, &cv, &mv)?;
    let proof = data.prove(pw)?;
    assert_eq!(proof.public_inputs, vec![F::from_canonical_u8(2), F::ZERO]);
    data.verify(proof)?;
    let mut pw = PartialWitness::new();
    a.set(&mut pw, &av)?;
    c.set(&mut pw, &cv)?;
    m.set(&mut pw, &mv)?;
    mul.quotient.set(&mut pw, &((&av * &cv) / &mv))?;
    mul.remainder.set(&mut pw, &BigUint::from(3u8))?;
    assert!(data.prove(pw).is_err());
    // A correct integer equation with a noncanonical remainder must also fail.
    let mut pw = PartialWitness::new();
    a.set(&mut pw, &BigUint::from(15u8))?;
    c.set(&mut pw, &BigUint::from(14u8))?;
    m.set(&mut pw, &BigUint::from(17u8))?;
    mul.quotient.set(&mut pw, &BigUint::from(11u8))?;
    mul.remainder.set(&mut pw, &BigUint::from(23u8))?;
    assert!(data.prove(pw).is_err());
    Ok(())
}

#[test]
fn rsa_original_1024_bit_fixture() -> Result<()> {
    let signature=BigUint::parse_bytes(b"102386562682221859025549328916727857389789009840935140645361501981959969535413501251999442013082353139290537518086128904993091119534674934202202277050635907008004079788691412782712147797487593510040249832242022835902734939817209358184800954336078838331094308355388211284440290335887813714894626653613586546719",10).unwrap();
    let modulus=BigUint::parse_bytes(b"106773687078109007595028366084970322147907086635176067918161636756354740353674098686965493426431314019237945536387044259034050617425729739578628872957481830432099721612688699974185290306098360072264136606623400336518126533605711223527682187548332314997606381158951535480830524587400401856271050333371205030999",10).unwrap();
    let limbs = [
        "1156466847851242602709362303526378170",
        "191372789510123109308037416804949834",
        "7204",
    ]
    .map(|s| BigUint::parse_bytes(s.as_bytes(), 10).unwrap());
    let digest = from_circom_limbs(&limbs, 121)?.to_bytes_be();
    assert_eq!(digest.len(), 32);
    let mut b = Builder::new(circuit_config());
    let input: [_; 32] = bytes(&mut b, 32).try_into().unwrap();
    // A 1024-bit key must also verify in a circuit with 2048-bit capacity.
    let rsa = rsa::RsaTarget::new(&mut b, &input, 256);
    b.register_public_inputs(&input);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("RSA-1024 fixture", gate_rows, data.common.degree());
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, &digest)?;
    rsa.set(&mut pw, &signature, &modulus)?;
    let proof = data.prove(pw)?;
    data.verify(proof)?;
    let mut bad_digest = digest;
    bad_digest[31] ^= 1;
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, &bad_digest)?;
    rsa.set(&mut pw, &signature, &modulus)?;
    assert!(data.prove(pw).is_err());
    Ok(())
}
