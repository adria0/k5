//! Byte, selection, and native Poseidon helpers.
use crate::{Builder, F};
use anyhow::{Result, ensure};
use plonky2::{
    field::types::Field,
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};

pub fn constant(b: &mut Builder, x: usize) -> Target {
    b.constant(F::from_canonical_usize(x))
}
pub fn eq_const(b: &mut Builder, x: Target, c: usize) -> BoolTarget {
    let c = constant(b, c);
    b.is_equal(x, c)
}

/// Compares integers with explicit 32-bit range constraints.
pub fn less_than(b: &mut Builder, x: Target, y: Target) -> BoolTarget {
    b.range_check(x, 32);
    b.range_check(y, 32);
    let diff = b.sub(x, y);
    let shifted = b.add_const(diff, F::from_canonical_u64(1 << 32));
    let bits = b.split_le(shifted, 33);
    b.not(bits[32])
}

pub fn bytes(b: &mut Builder, n: usize) -> Vec<Target> {
    let values = b.add_virtual_targets(n);
    for &x in &values {
        b.range_check(x, 8);
    }
    values
}

/// Sets a byte buffer and zero-fills unused capacity.
pub fn set_bytes(pw: &mut PartialWitness<F>, targets: &[Target], input: &[u8]) -> Result<()> {
    ensure!(input.len() <= targets.len(), "byte buffer exceeds capacity");
    for (i, &t) in targets.iter().enumerate() {
        pw.set_target(t, F::from_canonical_u8(input.get(i).copied().unwrap_or(0)))?;
    }
    Ok(())
}

/// Selects an element with an enforced in-bounds index.
pub fn item_at_index(b: &mut Builder, input: &[Target], index: Target) -> Target {
    assert!(!input.is_empty());
    let len = constant(b, input.len());
    let valid = less_than(b, index, len);
    b.assert_one(valid.target);
    let mut values = input.to_vec();
    values.resize(input.len().next_power_of_two(), b.zero());
    b.random_access(index, values)
}

/// Cyclic left shift, matching VarShiftLeft's rotation semantics.
pub fn var_shift_left(
    b: &mut Builder,
    input: &[Target],
    shift: Target,
    out_len: usize,
) -> Vec<Target> {
    assert!(!input.is_empty() && out_len <= input.len());
    let width = input.len().next_power_of_two().ilog2() as usize;
    let bits = b.split_le(shift, width);
    let mut values = input.to_vec();
    for (j, bit) in bits.into_iter().enumerate() {
        values = (0..input.len())
            .map(|i| b.select(bit, values[(i + (1 << j)) % input.len()], values[i]))
            .collect();
    }
    values.truncate(out_len);
    values
}

/// Extracts a bounded substring and zero-fills its remaining output capacity.
pub fn select_subarray(
    b: &mut Builder,
    input: &[Target],
    start: Target,
    length: Target,
    capacity: usize,
) -> Vec<Target> {
    assert!(capacity <= input.len());
    let bound = constant(b, input.len());
    let valid = less_than(b, start, bound);
    b.assert_one(valid.target);
    let max = constant(b, capacity + 1);
    let valid = less_than(b, length, max);
    b.assert_one(valid.target);
    let end = b.add(start, length);
    let max_end = constant(b, input.len() + 1);
    let valid = less_than(b, end, max_end);
    b.assert_one(valid.target);
    let rotated = var_shift_left(b, input, start, capacity);
    rotated
        .into_iter()
        .enumerate()
        .map(|(i, x)| {
            let i = constant(b, i);
            let active = less_than(b, i, length);
            b.mul(active.target, x)
        })
        .collect()
}

/// Constrains every element beyond the selected length to zero.
pub fn assert_zero_padding(b: &mut Builder, input: &[Target], length: Target) {
    let bound = constant(b, input.len() + 1);
    let valid = less_than(b, length, bound);
    b.assert_one(valid.target);
    for (i, &x) in input.iter().enumerate() {
        let i = constant(b, i);
        let active = less_than(b, i, length);
        let inactive = b.not(active);
        let tail = b.mul(inactive.target, x);
        b.assert_zero(tail);
    }
}

/// Reveals only bytes selected by a constrained binary mask.
pub fn byte_mask(b: &mut Builder, input: &[Target], mask: &[BoolTarget]) -> Vec<Target> {
    assert_eq!(input.len(), mask.len());
    input
        .iter()
        .zip(mask)
        .map(|(&x, &m)| {
            b.assert_bool(m);
            b.range_check(x, 8);
            b.mul(x, m.target)
        })
        .collect()
}

/// Packs seven little-endian bytes per field element (56 bits, no reduction).
pub fn pack_bytes(b: &mut Builder, input: &[Target]) -> Vec<Target> {
    input
        .chunks(7)
        .map(|chunk| {
            let mut sum = b.zero();
            for &x in chunk.iter().rev() {
                b.range_check(x, 8);
                sum = b.mul_const_add(F::from_canonical_u16(256), sum, x);
            }
            sum
        })
        .collect()
}

pub fn pack_byte_subarray(
    b: &mut Builder,
    input: &[Target],
    start: Target,
    length: Target,
    capacity: usize,
) -> Vec<Target> {
    let selected = select_subarray(b, input, start, length, capacity);
    pack_bytes(b, &selected)
}

/// Packs big-endian bits; a short final chunk is right-padded with zero bits.
pub fn pack_bits(b: &mut Builder, input: &[BoolTarget], width: usize) -> Vec<Target> {
    assert!((1..=63).contains(&width));
    input
        .chunks(width)
        .map(|chunk| {
            let mut bits = chunk.to_vec();
            bits.resize(width, b.constant_bool(false));
            for &bit in &bits {
                b.assert_bool(bit);
            }
            b.le_sum(bits.iter().rev())
        })
        .collect()
}

/// Parses bounded ASCII decimal digits without overflowing Goldilocks.
pub fn digit_bytes_to_int(b: &mut Builder, input: &[Target]) -> Target {
    assert!(input.len() <= 19);
    let mut out = b.zero();
    for &x in input {
        let digit = b.add_const(x, -F::from_canonical_u8(b'0'));
        let ten = constant(b, 10);
        let valid = less_than(b, digit, ten);
        b.assert_one(valid.target);
        out = b.mul_const_add(F::from_canonical_u8(10), out, digit);
    }
    out
}

/// Converts a big-endian byte string to little-endian words, without truncation.
pub fn split_bytes_to_words(
    b: &mut Builder,
    input: &[Target],
    width: usize,
    count: usize,
) -> Vec<Target> {
    assert!((1..=63).contains(&width) && count * width >= input.len() * 8);
    let mut bits: Vec<_> = input.iter().rev().flat_map(|&x| b.split_le(x, 8)).collect();
    bits.resize(count * width, b.constant_bool(false));
    bits.chunks(width)
        .map(|chunk| b.le_sum(chunk.iter()))
        .collect()
}

/// Circom's zero bytes in the pattern are wildcards, including interior zeros.
pub fn check_substring_match(b: &mut Builder, input: &[Target], pattern: &[Target]) -> BoolTarget {
    assert!(!pattern.is_empty() && input.len() == pattern.len());
    let first_zero = eq_const(b, pattern[0], 0);
    b.assert_zero(first_zero.target);
    let mut matched = b.constant_bool(true);
    for (&x, &p) in input.iter().zip(pattern) {
        let wildcard = eq_const(b, p, 0);
        let equal = b.is_equal(x, p);
        let ok = b.or(wildcard, equal);
        matched = b.and(matched, ok);
    }
    matched
}

/// Counts overlapping matches, treating missing tail bytes as zero.
pub fn count_substring_occurrences(
    b: &mut Builder,
    input: &[Target],
    pattern: &[Target],
) -> Target {
    assert!(input.len() >= pattern.len());
    let mut padded = input.to_vec();
    padded.resize(input.len() + pattern.len(), b.zero());
    let matches: Vec<_> = (0..input.len())
        .map(|i| check_substring_match(b, &padded[i..i + pattern.len()], pattern).target)
        .collect();
    b.add_many(matches)
}

/// Extracts a substring with an optional unique-occurrence constraint.
pub fn reveal_substring(
    b: &mut Builder,
    input: &[Target],
    start: Target,
    length: Target,
    capacity: usize,
    unique: bool,
) -> Vec<Target> {
    let out = select_subarray(b, input, start, length, capacity);
    if unique {
        let count = count_substring_occurrences(b, input, &out);
        b.assert_one(count);
    }
    out
}

/// Selects a contiguous regex reveal, constraining all bytes outside it to zero.
pub fn select_regex_reveal(
    b: &mut Builder,
    input: &[Target],
    start: Target,
    capacity: usize,
) -> Vec<Target> {
    let len = constant(b, capacity);
    let out = select_subarray(b, input, start, len, capacity);
    let empty = eq_const(b, out[0], 0);
    b.assert_zero(empty.target);
    let end = b.add(start, len);
    for (i, &x) in input.iter().enumerate() {
        let idx = constant(b, i);
        let before = less_than(b, idx, start);
        let inside_end = less_than(b, idx, end);
        let after = b.not(inside_end);
        let outside = b.or(before, after);
        let forbidden = b.mul(outside.target, x);
        b.assert_zero(forbidden);
    }
    out
}

pub fn pack_regex_reveal(
    b: &mut Builder,
    input: &[Target],
    start: Target,
    capacity: usize,
) -> Vec<Target> {
    let selected = select_regex_reveal(b, input, start, capacity);
    pack_bytes(b, &selected)
}

/// Native four-element Plonky2 Poseidon digest, with explicit input length.
pub fn poseidon(b: &mut Builder, input: &[Target]) -> HashOutTarget {
    let mut framed = vec![constant(b, input.len())];
    framed.extend_from_slice(input);
    b.hash_n_to_hash_no_pad::<PoseidonHash>(framed)
}

/// Merges neighboring bounded limbs before applying native Poseidon.
pub fn poseidon_large(b: &mut Builder, input: &[Target], limb_bits: usize) -> HashOutTarget {
    assert!((1..=31).contains(&limb_bits));
    for &x in input {
        b.range_check(x, limb_bits);
    }
    let merged: Vec<_> = input
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                b.mul_const_add(F::from_canonical_u64(1 << limb_bits), pair[1], pair[0])
            } else {
                pair[0]
            }
        })
        .collect();
    poseidon(b, &merged)
}

/// Hashes chunks of sixteen elements and folds the digests in order.
pub fn poseidon_modular(b: &mut Builder, input: &[Target]) -> HashOutTarget {
    assert!(!input.is_empty());
    let mut chunks = input.chunks(16);
    let mut out = poseidon(b, chunks.next().unwrap());
    for chunk in chunks {
        let next = poseidon(b, chunk);
        let mut pair = out.elements.to_vec();
        pair.extend(next.elements);
        out = poseidon(b, &pair);
    }
    out
}

pub fn email_nullifier(b: &mut Builder, signature: &[Target], limb_bits: usize) -> HashOutTarget {
    let hash = poseidon_large(b, signature, limb_bits);
    poseidon(b, &hash.elements)
}

/// Decodes Base64 with the original circuit's '='-as-zero behavior.
pub fn base64_decode(b: &mut Builder, input: &[Target], out_len: usize) -> Vec<Target> {
    assert_eq!(input.len(), out_len.div_ceil(3) * 4);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    let mut bits = Vec::new();
    for &x in input {
        let mut valid = b.zero();
        let mut value = b.zero();
        for (i, &ch) in alphabet.iter().enumerate() {
            let eq = eq_const(b, x, ch as usize);
            valid = b.add(valid, eq.target);
            value = b.mul_const_add(F::from_canonical_usize(i % 64), eq.target, value);
        }
        b.assert_one(valid);
        bits.extend(b.split_le(value, 6).into_iter().rev());
    }
    bits[..out_len * 8]
        .chunks(8)
        .map(|chunk| b.le_sum(chunk.iter().rev()))
        .collect()
}

/// Checks compaction exactly instead of using a small-field probabilistic RLC.
fn compact_matches(
    b: &mut Builder,
    input: &[Target],
    decoded: &[Target],
    remove: &[BoolTarget],
) -> BoolTarget {
    assert_eq!(input.len(), decoded.len());
    let mut index = b.zero();
    let mut valid = b.constant_bool(true);
    for (&x, &skip) in input.iter().zip(remove) {
        b.range_check(x, 8);
        let y = item_at_index(b, decoded, index);
        let equal = b.is_equal(x, y);
        let ok = b.or(skip, equal);
        valid = b.and(valid, ok);
        let keep = b.not(skip);
        index = b.add(index, keep.target);
    }
    for (i, &x) in decoded.iter().enumerate() {
        b.range_check(x, 8);
        let i = constant(b, i);
        let active = less_than(b, i, index);
        let zero = eq_const(b, x, 0);
        let ok = b.or(active, zero);
        valid = b.and(valid, ok);
    }
    valid
}

/// Verifies exact removal of every quoted-printable '=\r\n' sequence.
pub fn remove_soft_line_breaks(
    b: &mut Builder,
    input: &[Target],
    decoded: &[Target],
) -> BoolTarget {
    let mut remove = vec![b.constant_bool(false); input.len()];
    for i in 0..input.len().saturating_sub(2) {
        let eq = eq_const(b, input[i], 61);
        let cr = eq_const(b, input[i + 1], 13);
        let lf = eq_const(b, input[i + 2], 10);
        let pair = b.and(eq, cr);
        let matched = b.and(pair, lf);
        for slot in &mut remove[i..i + 3] {
            *slot = b.or(*slot, matched);
        }
    }
    compact_matches(b, input, decoded, &remove)
}

/// Removes local-part periods and the first plus alias, retaining the domain.
pub fn clean_email_address(b: &mut Builder, input: &[Target], decoded: &[Target]) -> BoolTarget {
    let mut domain = b.constant_bool(false);
    let mut alias = b.constant_bool(false);
    let mut remove = Vec::new();
    for &x in input {
        let at = eq_const(b, x, 64);
        domain = b.or(domain, at);
        let plus = eq_const(b, x, 43);
        alias = b.or(alias, plus);
        let dot = eq_const(b, x, 46);
        let omit = b.or(dot, alias);
        let local = b.not(domain);
        remove.push(b.and(local, omit));
    }
    compact_matches(b, input, decoded, &remove)
}
