use anyhow::Result;
use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::Hasher,
};
use plonky2_zkemail::{utils::*, *};

#[test]
fn base64_and_native_poseidon() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 8);
    let decoded = base64_decode(&mut b, &input, 5);
    let packed = pack_bytes(&mut b, &decoded);
    let hash = poseidon(&mut b, &packed);
    b.register_public_inputs(&decoded);
    b.register_public_inputs(&hash.elements);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("Base64 and Poseidon", gate_rows, data.common.degree());
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, b"aGVsbG8=")?;
    let proof = data.prove(pw)?;
    assert_eq!(
        &proof.public_inputs[..5],
        b"hello".map(F::from_canonical_u8)
    );
    let packed = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let expected = PoseidonHash::hash_no_pad(&[F::ONE, F::from_canonical_u64(packed)]);
    assert_eq!(&proof.public_inputs[5..], expected.elements);
    data.verify(proof)?;
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, b"aGVsbG8!")?;
    assert!(data.prove(pw).is_err());
    Ok(())
}

#[test]
fn exact_soft_breaks_and_email_cleaning() -> Result<()> {
    for (encoded, decoded, soft) in [
        (b"a=\r\nb=\r\ncd".as_slice(), b"abcd".as_slice(), true),
        (b"a.b+tag@example.com", b"ab@example.com", false),
    ] {
        let mut b = Builder::new(circuit_config());
        let input = bytes(&mut b, 32);
        let output = bytes(&mut b, 32);
        let valid = if soft {
            remove_soft_line_breaks(&mut b, &input, &output)
        } else {
            clean_email_address(&mut b, &input, &output)
        };
        b.assert_one(valid.target);
        let gate_rows = b.num_gates();
        let data = b.build::<C>();
        let label = if soft {
            "Soft-line-break cleaning"
        } else {
            "Email-address cleaning"
        };
        print_circuit_size(label, gate_rows, data.common.degree());
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, encoded)?;
        set_bytes(&mut pw, &output, decoded)?;
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        let mut bad = decoded.to_vec();
        bad[0] ^= 1;
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, encoded)?;
        set_bytes(&mut pw, &output, &bad)?;
        assert!(data.prove(pw).is_err());
    }
    Ok(())
}

#[test]
fn substring_uniqueness_and_bounds() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 16);
    let start = b.add_virtual_target();
    let length = b.add_virtual_target();
    let out = reveal_substring(&mut b, &input, start, length, 4, true);
    b.register_public_inputs(&out);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("Substring extraction", gate_rows, data.common.degree());
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, b"hello world")?;
    pw.set_target(start, F::from_canonical_u8(6))?;
    pw.set_target(length, F::from_canonical_u8(4))?;
    let proof = data.prove(pw)?;
    assert_eq!(proof.public_inputs, b"worl".map(F::from_canonical_u8));
    data.verify(proof)?;
    for (text, index, len) in [
        (b"abc abc".as_slice(), 0, 3),
        (b"hello world", 14, 4),
        (b"hello world", 0, 0),
    ] {
        let mut pw = PartialWitness::new();
        set_bytes(&mut pw, &input, text)?;
        pw.set_target(start, F::from_canonical_u8(index))?;
        pw.set_target(length, F::from_canonical_u8(len))?;
        assert!(data.prove(pw).is_err());
    }
    Ok(())
}

#[test]
fn packing_endianness_masks_and_non_power_of_two_rotation() -> Result<()> {
    let mut b = Builder::new(circuit_config());
    let input = bytes(&mut b, 9);
    let packed = pack_bytes(&mut b, &input);
    let words = split_bytes_to_words(&mut b, &input, 16, 5);
    let shift = b.add_virtual_target();
    let rotated = var_shift_left(&mut b, &input, shift, 4);
    let mask: Vec<_> = (0..9).map(|_| b.add_virtual_bool_target_safe()).collect();
    let masked = byte_mask(&mut b, &input, &mask);
    b.register_public_inputs(&packed);
    b.register_public_inputs(&words);
    b.register_public_inputs(&rotated);
    b.register_public_inputs(&masked);
    let gate_rows = b.num_gates();
    let data = b.build::<C>();
    print_circuit_size("Byte packing and masks", gate_rows, data.common.degree());
    let mut pw = PartialWitness::new();
    set_bytes(&mut pw, &input, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    pw.set_target(shift, F::from_canonical_u8(8))?;
    for (i, &t) in mask.iter().enumerate() {
        pw.set_bool_target(t, i.is_multiple_of(2))?;
    }
    let proof = data.prove(pw)?;
    let expected = [
        0x07060504030201,
        0x0908,
        0x0809,
        0x0607,
        0x0405,
        0x0203,
        1,
        9,
        1,
        2,
        3,
        1,
        0,
        3,
        0,
        5,
        0,
        7,
        0,
        9,
    ]
    .map(F::from_canonical_u64);
    assert_eq!(proof.public_inputs, expected);
    data.verify(proof)?;
    Ok(())
}
