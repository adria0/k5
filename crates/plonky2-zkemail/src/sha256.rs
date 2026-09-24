//! SHA-256 compression, variable padded lengths, and precomputed chaining states.
use crate::{Builder, F, utils::less_than};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
type Word = [BoolTarget; 32];

fn xor(b: &mut Builder, x: BoolTarget, y: BoolTarget) -> BoolTarget {
    let xy = b.mul(x.target, y.target);
    let sum = b.add(x.target, y.target);
    BoolTarget::new_unsafe(b.mul_const_add(-F::TWO, xy, sum))
}

fn constant(b: &mut Builder, x: u32) -> Word {
    std::array::from_fn(|i| b.constant_bool((x >> i) & 1 != 0))
}

/// Adds bounded words as integers before discarding the carry bits.
fn add(b: &mut Builder, words: &[Word]) -> Word {
    let values: Vec<_> = words.iter().map(|w| b.le_sum(w.iter())).collect();
    let sum = b.add_many(values);
    b.split_le(sum, 32 + words.len().ilog2() as usize + 1)[..32]
        .try_into()
        .unwrap()
}

/// Combines SHA's rotations, with an optional logical shift for small sigma.
fn sigma(b: &mut Builder, w: Word, a: usize, c: usize, d: usize, shift: bool) -> Word {
    std::array::from_fn(|i| {
        let x = xor(b, w[(i + a) % 32], w[(i + c) % 32]);
        let y = if shift && i + d >= 32 {
            b.constant_bool(false)
        } else {
            w[(i + d) % 32]
        };
        xor(b, x, y)
    })
}

/// Compresses one block; words and chaining state use little-endian bit order.
fn compress(b: &mut Builder, state: [Word; 8], block: &[Target]) -> [Word; 8] {
    let mut w = Vec::with_capacity(64);
    for bytes in block.chunks_exact(4) {
        let bits: Vec<_> = bytes.iter().rev().flat_map(|&x| b.split_le(x, 8)).collect();
        w.push(bits.try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = sigma(b, w[i - 15], 7, 18, 3, true);
        let s1 = sigma(b, w[i - 2], 17, 19, 10, true);
        w.push(add(b, &[w[i - 16], s0, w[i - 7], s1]));
    }
    let mut v = state;
    for i in 0..64 {
        let s1 = sigma(b, v[4], 6, 11, 25, false);
        let ch = std::array::from_fn(|j| {
            BoolTarget::new_unsafe(b.select(v[4][j], v[5][j].target, v[6][j].target))
        });
        let k = constant(b, K[i]);
        let t1 = add(b, &[v[7], s1, ch, k, w[i]]);
        let s0 = sigma(b, v[0], 2, 13, 22, false);
        let maj = std::array::from_fn(|j| {
            let x = xor(b, v[0][j], v[1][j]);
            BoolTarget::new_unsafe(b.select(x, v[2][j].target, v[0][j].target))
        });
        let t2 = add(b, &[s0, maj]);
        v = [
            add(b, &[t1, t2]),
            v[0],
            v[1],
            v[2],
            add(b, &[v[3], t1]),
            v[4],
            v[5],
            v[6],
        ];
    }
    std::array::from_fn(|i| add(b, &[state[i], v[i]]))
}

/// Hashes caller-padded bytes, selecting a positive multiple-of-64 length.
/// Like Circom, this checks block count, not SHA padding syntax. `pre_hash`
/// is a 32-byte big-endian chaining state, not a finalized prefix digest.
pub fn sha256_padded(
    b: &mut Builder,
    input: &[Target],
    length: Target,
    pre_hash: Option<&[Target; 32]>,
) -> [Target; 32] {
    assert!(!input.is_empty() && input.len().is_multiple_of(64));
    let mut state: [Word; 8] = if let Some(pre) = pre_hash {
        std::array::from_fn(|i| {
            pre[i * 4..i * 4 + 4]
                .iter()
                .rev()
                .flat_map(|&x| b.split_le(x, 8))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
    } else {
        std::array::from_fn(|i| constant(b, IV[i]))
    };
    let mut output = [b.zero(); 32];
    let mut choices = Vec::new();
    for (i, block) in input.chunks_exact(64).enumerate() {
        state = compress(b, state, block);
        let len = b.constant(F::from_canonical_usize((i + 1) * 64));
        let selected = b.is_equal(length, len);
        choices.push(selected.target);
        for j in 0..32 {
            let word = state[j / 4];
            let offset = (3 - j % 4) * 8;
            let byte = b.le_sum(word[offset..offset + 8].iter());
            output[j] = b.mul_add(selected.target, byte, output[j]);
        }
    }
    let valid = b.add_many(choices);
    b.assert_one(valid);
    output
}

/// Constrains a selected buffer prefix to contain standard SHA-256 padding.
/// The message length is recovered from its final 64-bit bit-count field.
pub fn assert_sha256_padding(b: &mut Builder, input: &[Target], length: Target) {
    assert!(!input.is_empty() && input.len().is_multiple_of(64));
    // The final bit count is at most 32 bits for the bounded email buffers.
    assert!(input.len() < (1 << 29));
    let mut last = [b.zero(); 8];
    let mut choices = Vec::new();
    for (i, block) in input.chunks_exact(64).enumerate() {
        let end = b.constant(F::from_canonical_usize((i + 1) * 64));
        let selected = b.is_equal(length, end);
        choices.push(selected.target);
        for j in 0..8 {
            last[j] = b.mul_add(selected.target, block[56 + j], last[j]);
        }
    }
    let selected_blocks = b.add_many(choices);
    b.assert_one(selected_blocks);
    for &byte in &last[..4] {
        b.assert_zero(byte);
    }
    let mut bit_length = b.zero();
    for &byte in &last[4..] {
        bit_length = b.mul_const_add(F::from_canonical_u16(256), bit_length, byte);
    }
    let bits = b.split_le(bit_length, 32);
    for &bit in &bits[..3] {
        b.assert_zero(bit.target);
    }
    let message_length = b.le_sum(bits[3..].iter());
    // Exactly the shortest block-aligned encoding containing 0x80 and 8 length bytes.
    let padded_min = b.add_const(message_length, F::from_canonical_u8(8));
    let at_least_min = less_than(b, padded_min, length);
    b.assert_one(at_least_min.target);
    let padded_max = b.add_const(message_length, F::from_canonical_u8(73));
    let at_most_max = less_than(b, length, padded_max);
    b.assert_one(at_most_max.target);
    let length_field_start = b.add_const(length, -F::from_canonical_u8(8));
    for (i, &byte) in input.iter().enumerate() {
        let pos = b.constant(F::from_canonical_usize(i));
        let marker = b.is_equal(pos, message_length);
        let expected = b.constant(F::from_canonical_u8(0x80));
        let difference = b.sub(byte, expected);
        let wrong_marker = b.mul(marker.target, difference);
        b.assert_zero(wrong_marker);
        let after_message = less_than(b, message_length, pos);
        let before_length = less_than(b, pos, length_field_start);
        let zero_padding = b.and(after_message, before_length);
        let nonzero_padding = b.mul(zero_padding.target, byte);
        b.assert_zero(nonzero_padding);
    }
}

/// Hashes a fixed-length, unpadded message, constructing standard padding in-circuit.
pub fn sha256(b: &mut Builder, input: &[Target]) -> [Target; 32] {
    let mut padded = input.to_vec();
    padded.push(b.constant(F::from_canonical_u8(0x80)));
    while padded.len() % 64 != 56 {
        padded.push(b.zero());
    }
    for byte in ((input.len() as u64) * 8).to_be_bytes() {
        padded.push(b.constant(F::from_canonical_u8(byte)));
    }
    let length = b.constant(F::from_canonical_usize(padded.len()));
    sha256_padded(b, &padded, length, None)
}

/// Prepares the padded input expected by the variable-length circuit.
pub fn pad(message: &[u8]) -> Vec<u8> {
    let mut out = message.to_vec();
    out.push(0x80);
    while out.len() % 64 != 56 {
        out.push(0);
    }
    out.extend_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    out
}

/// Bit-oriented Sha256General/Sha256Partial interface (big-endian bits).
pub fn sha256_bits_padded(
    b: &mut Builder,
    input: &[BoolTarget],
    bit_length: Target,
    pre_hash: Option<&[BoolTarget; 256]>,
) -> [BoolTarget; 256] {
    assert!(!input.is_empty() && input.len().is_multiple_of(512));
    for &bit in input {
        b.assert_bool(bit);
    }
    let bytes: Vec<_> = input
        .chunks(8)
        .map(|chunk| b.le_sum(chunk.iter().rev()))
        .collect();
    let pre: Option<[Target; 32]> = pre_hash.map(|pre| {
        for &bit in pre {
            b.assert_bool(bit);
        }
        pre.chunks(8)
            .map(|chunk| b.le_sum(chunk.iter().rev()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    });
    let byte_length = b.mul_const(F::from_canonical_u8(8).inverse(), bit_length);
    let out = sha256_padded(b, &bytes, byte_length, pre.as_ref());
    out.into_iter()
        .flat_map(|x| b.split_le(x, 8).into_iter().rev())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
