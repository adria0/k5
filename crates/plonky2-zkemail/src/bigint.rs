//! Unsigned radix-2^16 arithmetic. No wide integer is reduced into Goldilocks.
use crate::{Builder, F};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::Zero;
use plonky2::{
    field::types::Field,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
};

#[derive(Clone, Debug)]
pub struct BigUintTarget {
    pub limbs: Vec<Target>,
}

impl BigUintTarget {
    /// Allocates little-endian, range-checked limbs (up to 4096 bits).
    pub fn new(b: &mut Builder, limbs: usize) -> Self {
        assert!((1..=256).contains(&limbs));
        let limbs = b.add_virtual_targets(limbs);
        for &x in &limbs {
            b.range_check(x, 16);
        }
        Self { limbs }
    }

    /// Writes bounded integer limbs without reducing them modulo the field.
    pub fn set(&self, pw: &mut PartialWitness<F>, value: &BigUint) -> Result<()> {
        ensure!(
            value.bits() <= (16 * self.limbs.len()) as u64,
            "integer exceeds allocated limbs"
        );
        let bytes = value.to_bytes_le();
        for (i, &t) in self.limbs.iter().enumerate() {
            let lo = bytes.get(2 * i).copied().unwrap_or(0) as u16;
            let hi = bytes.get(2 * i + 1).copied().unwrap_or(0) as u16;
            pw.set_target(t, F::from_canonical_u16(lo | (hi << 8)))?;
        }
        Ok(())
    }
}

/// Lexicographic comparison of equally sized, bounded little-endian limbs.
pub fn less_than(b: &mut Builder, a: &BigUintTarget, c: &BigUintTarget) -> BoolTarget {
    assert_eq!(a.limbs.len(), c.limbs.len());
    let mut lt = b.constant_bool(false);
    for (&a, &c) in a.limbs.iter().zip(&c.limbs) {
        b.range_check(a, 16);
        b.range_check(c, 16);
        let offset = b.constant(F::from_canonical_u32(1 << 16));
        let difference = b.sub(a, c);
        let shifted = b.add(difference, offset);
        let bits = b.split_le(shifted, 17);
        let smaller = b.not(bits[16]);
        let equal = b.is_equal(a, c);
        let carry = b.and(equal, lt);
        lt = b.or(smaller, carry);
    }
    lt
}

/// Normalizes a convolution plus an optional addend with bounded integer carries.
/// With <=256 limbs, every column is <2^41, far below the field modulus.
fn product(
    b: &mut Builder,
    a: &BigUintTarget,
    c: &BigUintTarget,
    add: Option<&BigUintTarget>,
) -> Vec<Target> {
    let n = a.limbs.len();
    assert_eq!(n, c.limbs.len());
    let mut carry = b.zero();
    let mut out = Vec::with_capacity(2 * n);
    for col in 0..2 * n {
        let mut sum = carry;
        for i in 0..n {
            if col >= i && col - i < n {
                sum = b.mul_add(a.limbs[i], c.limbs[col - i], sum);
            }
        }
        if let Some(add) = add
            && col < n
        {
            sum = b.add(sum, add.limbs[col]);
        }
        let bits = b.split_le(sum, 42);
        out.push(b.le_sum(bits[..16].iter()));
        carry = b.le_sum(bits[16..].iter());
    }
    b.assert_zero(carry);
    out
}

#[derive(Clone, Debug)]
pub struct ModMulTarget {
    pub quotient: BigUintTarget,
    pub remainder: BigUintTarget,
}

impl ModMulTarget {
    /// Constrains a*b = quotient*modulus + remainder over the integers.
    /// The canonical remainder also forces modulus > 0.
    pub fn new(
        b: &mut Builder,
        a: &BigUintTarget,
        c: &BigUintTarget,
        modulus: &BigUintTarget,
    ) -> Self {
        let n = modulus.limbs.len();
        assert!((1..=256).contains(&n));
        assert_eq!(a.limbs.len(), n);
        assert_eq!(c.limbs.len(), n);
        for &x in a.limbs.iter().chain(&c.limbs).chain(&modulus.limbs) {
            b.range_check(x, 16);
        }
        let quotient = BigUintTarget::new(b, n);
        let remainder = BigUintTarget::new(b, n);
        let lt = less_than(b, &remainder, modulus);
        b.assert_one(lt.target);
        let lhs = product(b, a, c, None);
        let rhs = product(b, &quotient, modulus, Some(&remainder));
        for (x, y) in lhs.into_iter().zip(rhs) {
            b.connect(x, y);
        }
        Self {
            quotient,
            remainder,
        }
    }

    /// Supplies auxiliary witnesses; the circuit independently checks all arithmetic.
    pub fn set(
        &self,
        pw: &mut PartialWitness<F>,
        a: &BigUint,
        c: &BigUint,
        modulus: &BigUint,
    ) -> Result<BigUint> {
        ensure!(!modulus.is_zero(), "zero modulus");
        let product = a * c;
        let q = &product / modulus;
        let r = product % modulus;
        self.quotient.set(pw, &q)?;
        self.remainder.set(pw, &r)?;
        Ok(r)
    }
}

/// Converts the original Circom little-endian limbs without field reduction.
pub fn from_circom_limbs(limbs: &[BigUint], bits: usize) -> Result<BigUint> {
    ensure!(bits > 0 && bits <= 256, "invalid limb width");
    let mut value = BigUint::zero();
    for limb in limbs.iter().rev() {
        ensure!(limb.bits() <= bits as u64, "Circom limb exceeds width");
        value = (value << bits) + limb;
    }
    Ok(value)
}
