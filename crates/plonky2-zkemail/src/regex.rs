//! BodyHashRegex DFA from @zk-email/zk-regex-circom 2.3.2 (MIT).
//! Preserves the generated circuit's UTF-8, restart and reveal semantics.
use crate::{Builder, F, utils::eq_const};
use plonky2::{
    field::types::Field,
    iop::target::{BoolTarget, Target},
};
use std::sync::Arc;

// (source state, destination state, inclusive lower byte, inclusive upper byte).
const EDGES: &[(u8, u8, u8, u8)] = &[
    (1, 2, 10, 10),
    (2, 3, 100, 100),
    (3, 4, 107, 107),
    (4, 5, 105, 105),
    (5, 6, 109, 109),
    (6, 7, 45, 45),
    (7, 8, 115, 115),
    (8, 9, 105, 105),
    (9, 10, 103, 103),
    (10, 11, 110, 110),
    (11, 12, 97, 97),
    (12, 13, 116, 116),
    (13, 14, 117, 117),
    (14, 15, 114, 114),
    (15, 16, 101, 101),
    (16, 17, 58, 58),
    (17, 18, 97, 122),
    (18, 19, 61, 61),
    (18, 18, 97, 122),
    (19, 20, 1, 58),
    (19, 20, 60, 127),
    (19, 21, 194, 223),
    (19, 22, 224, 224),
    (19, 23, 225, 236),
    (19, 24, 237, 237),
    (19, 23, 238, 239),
    (19, 25, 240, 240),
    (19, 26, 241, 243),
    (19, 27, 244, 244),
    (20, 20, 1, 58),
    (20, 28, 59, 59),
    (20, 20, 60, 127),
    (20, 21, 194, 223),
    (20, 22, 224, 224),
    (20, 23, 225, 236),
    (20, 24, 237, 237),
    (20, 23, 238, 239),
    (20, 25, 240, 240),
    (20, 26, 241, 243),
    (20, 27, 244, 244),
    (21, 20, 128, 191),
    (22, 21, 160, 191),
    (23, 21, 128, 191),
    (24, 21, 128, 159),
    (25, 23, 144, 191),
    (26, 23, 128, 191),
    (27, 23, 128, 143),
    (28, 29, 32, 32),
    (29, 18, 97, 97),
    (29, 30, 98, 98),
    (29, 18, 99, 122),
    (30, 19, 61, 61),
    (30, 18, 97, 103),
    (30, 31, 104, 104),
    (30, 18, 105, 122),
    (31, 32, 61, 61),
    (31, 18, 97, 122),
    (32, 20, 1, 42),
    (32, 33, 43, 43),
    (32, 20, 44, 46),
    (32, 33, 47, 57),
    (32, 20, 58, 58),
    (32, 20, 60, 60),
    (32, 33, 61, 61),
    (32, 20, 62, 64),
    (32, 33, 65, 90),
    (32, 20, 91, 96),
    (32, 33, 97, 122),
    (32, 20, 123, 127),
    (32, 21, 194, 223),
    (32, 22, 224, 224),
    (32, 23, 225, 236),
    (32, 24, 237, 237),
    (32, 23, 238, 239),
    (32, 25, 240, 240),
    (32, 26, 241, 243),
    (32, 27, 244, 244),
    (33, 33, 43, 43),
    (33, 33, 47, 57),
    (33, 34, 59, 59),
    (33, 33, 61, 61),
    (33, 33, 65, 90),
    (33, 33, 97, 122),
];

/// Encodes a DFA transition and its restart flag in seven bits.
fn transition(state: u8, byte: u8) -> u16 {
    for &(from, to, lo, hi) in EDGES {
        if from == state && (lo..=hi).contains(&byte) {
            return to as u16;
        }
    }
    // Generated from_zero_enabled: restart only if no nonzero state survived.
    64 + if byte == 13 {
        1
    } else if byte == 255 {
        2
    } else {
        0
    }
}

/// Returns match existence and the exact generated-regex reveal mask.
pub fn body_hash_regex(b: &mut Builder, input: &[Target]) -> (BoolTarget, Vec<Target>) {
    assert!(!input.is_empty());
    // A lookup both constrains the transition and rejects byte 255, as Circom does.
    let table = Arc::new(
        (0u16..35)
            .flat_map(|state| {
                (0u16..255)
                    .map(move |byte| (state * 256 + byte, transition(state as u8, byte as u8)))
            })
            .collect(),
    );
    let table = b.add_lookup_table_from_pairs(table);
    let mut state = b.constant(F::from_canonical_u8(2)); // synthetic initial byte 255
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut restart = Vec::new();
    let mut accepted = b.constant_bool(false);
    for &x in input {
        b.range_check(x, 8);
        before.push(state);
        let key = b.mul_const_add(F::from_canonical_u16(256), state, x);
        let result = b.add_lookup_from_index(key, table);
        let bits = b.split_le(result, 7);
        state = b.le_sum(bits[..6].iter());
        restart.push(bits[6]);
        after.push(state);
        let final_state = eq_const(b, state, 34);
        accepted = b.or(accepted, final_state);
    }
    restart.push(b.constant_bool(false));
    let mut consecutive = b.constant_bool(false);
    let mut reveal = vec![b.zero(); input.len()];
    for i in (0..input.len()).rev() {
        let final_state = eq_const(b, after[i], 34);
        let suffix = b.or(final_state, consecutive);
        let zero = eq_const(b, after[i], 0);
        let changed = b.not(zero);
        let continuing = b.and(changed, suffix);
        let no_restart = b.not(restart[i + 1]);
        let boundary = b.or(no_restart, final_state);
        consecutive = b.and(boundary, continuing);
        let from_start = eq_const(b, before[i], 32);
        let from_value = eq_const(b, before[i], 33);
        let from = b.or(from_start, from_value);
        let to = eq_const(b, after[i], 33);
        let transition = b.and(from, to);
        let no_restart = b.not(restart[i]);
        let active = b.and(transition, no_restart);
        let active = b.and(active, consecutive);
        let active = b.and(active, accepted);
        reveal[i] = b.mul(active.target, input[i]);
    }
    (accepted, reveal)
}
