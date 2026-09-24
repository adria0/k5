//! RSA exponent 65537 and SHA-256 PKCS#1 v1.5 verification.
use crate::{
    Builder, F,
    bigint::{BigUintTarget, ModMulTarget, less_than},
};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use plonky2::{
    field::types::Field,
    iop::{target::Target, witness::PartialWitness},
};

#[derive(Clone, Debug)]
pub struct RsaTarget {
    pub signature: BigUintTarget,
    pub modulus: BigUintTarget,
    pub steps: Vec<ModMulTarget>,
}

impl RsaTarget {
    /// Binds a SHA-256 digest to an RSA signature. `modulus_bytes` is the
    /// maximum key size; padding follows the actual modulus byte length.
    pub fn new(b: &mut Builder, digest: &[Target; 32], modulus_bytes: usize) -> Self {
        assert!((62..=512).contains(&modulus_bytes) && modulus_bytes.is_multiple_of(2));
        let n = modulus_bytes / 2;
        let signature = BigUintTarget::new(b, n);
        let modulus = BigUintTarget::new(b, n);
        let odd = b.split_le(modulus.limbs[0], 16)[0];
        b.assert_one(odd.target);
        let reduced = less_than(b, &signature, &modulus);
        b.assert_one(reduced.target);
        let mut steps = Vec::with_capacity(17);
        let mut current = signature.clone();
        for _ in 0..16 {
            let step = ModMulTarget::new(b, &current, &current, &modulus);
            current = step.remainder.clone();
            steps.push(step);
        }
        let step = ModMulTarget::new(b, &current, &signature, &modulus);
        let encoded = rsa_pad(b, digest, &modulus);
        for (&expected, &actual) in encoded.limbs.iter().zip(&step.remainder.limbs) {
            b.connect(expected, actual);
        }
        steps.push(step);
        Self {
            signature,
            modulus,
            steps,
        }
    }

    /// Populates the signature, key, and modular-arithmetic auxiliaries.
    pub fn set(
        &self,
        pw: &mut PartialWitness<F>,
        signature: &BigUint,
        modulus: &BigUint,
    ) -> Result<()> {
        ensure!(signature < modulus, "signature must be reduced");
        self.signature.set(pw, signature)?;
        self.modulus.set(pw, modulus)?;
        let mut current = signature.clone();
        for step in &self.steps[..16] {
            current = step.set(pw, &current, &current, modulus)?;
        }
        self.steps[16].set(pw, &current, signature, modulus)?;
        Ok(())
    }
}

/// Constructs PKCS#1 v1.5 SHA-256 encoding for the modulus's actual byte length.
/// Leading zero capacity is ignored, and at least eight 0xff padding bytes
/// are required. All size decisions are constrained, not witness-side branches.
pub fn rsa_pad(b: &mut Builder, digest: &[Target; 32], modulus: &BigUintTarget) -> BigUintTarget {
    let capacity = 2 * modulus.limbs.len();
    assert!((62..=512).contains(&capacity));
    let mut modulus_bytes = Vec::with_capacity(capacity);
    for &limb in &modulus.limbs {
        let bits = b.split_le(limb, 16);
        modulus_bytes.push(b.le_sum(bits[..8].iter()));
        modulus_bytes.push(b.le_sum(bits[8..].iter()));
    }
    let mut nonzero_suffix = vec![b.constant_bool(false); capacity + 2];
    let zero = b.zero();
    for i in (0..capacity).rev() {
        let is_zero = b.is_equal(modulus_bytes[i], zero);
        let nonzero = b.not(is_zero);
        nonzero_suffix[i] = b.or(nonzero, nonzero_suffix[i + 1]);
    }
    let prefix: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut encoded = Vec::with_capacity(capacity);
    for &byte in digest.iter().rev() {
        b.range_check(byte, 8);
        encoded.push(byte);
    }
    encoded.extend(
        prefix
            .into_iter()
            .rev()
            .map(|x| b.constant(F::from_canonical_u8(x))),
    );
    encoded.push(zero);
    for i in 52..capacity {
        // Below the leading 0x01 byte, emit 0xff; above it, emit zero.
        let byte = b.mul_const_add(
            F::from_canonical_u8(254),
            nonzero_suffix[i + 2].target,
            nonzero_suffix[i + 1].target,
        );
        encoded.push(byte);
    }
    let ff = b.constant(F::from_canonical_u8(255));
    for &byte in &encoded[52..60] {
        b.connect(byte, ff);
    }
    let limbs = encoded
        .chunks_exact(2)
        .map(|pair| b.mul_const_add(F::from_canonical_u16(256), pair[1], pair[0]))
        .collect();
    BigUintTarget { limbs }
}
