//! Composition of SHA-256, RSA, and DKIM body binding.
use crate::{
    Builder, C, D, F, circuit_config,
    rsa::RsaTarget,
    sha256::{IV, assert_sha256_padding, sha256_padded},
    utils::*,
};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use plonky2::{
    field::types::Field,
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs},
};

#[derive(Clone, Debug)]
pub struct EmailConfig {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub modulus_bytes: usize,
    pub ignore_body_hash: bool,
    pub header_mask: bool,
    pub body_mask: bool,
    pub remove_soft_line_breaks: bool,
    /// Explicitly allows a trusted prefix chaining state instead of hashing the full body.
    pub allow_partial_body_hash: bool,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: 1024,
            max_body_bytes: 1536,
            modulus_bytes: 256,
            ignore_body_hash: false,
            header_mask: false,
            body_mask: false,
            remove_soft_line_breaks: false,
            allow_partial_body_hash: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BodyTarget {
    pub bytes: Vec<Target>,
    pub length: Target,
    pub pre_hash: [Target; 32],
    pub hash_index: Target,
    pub mask: Option<Vec<BoolTarget>>,
    pub decoded: Option<Vec<Target>>,
}

#[derive(Clone, Debug)]
pub struct EmailTarget {
    pub header: Vec<Target>,
    pub header_length: Target,
    pub rsa: RsaTarget,
    pub header_mask: Option<Vec<BoolTarget>>,
    pub body: Option<BodyTarget>,
    pub header_digest: [Target; 32],
    pub pubkey_hash: HashOutTarget,
    pub masked_header: Option<Vec<Target>>,
    pub masked_body: Option<Vec<Target>>,
}

/// Extracts the body hash using the source dependency's DFA and reveal rules.
pub fn body_hash_from_header(b: &mut Builder, header: &[Target], index: Target) -> [Target; 32] {
    let (matched, reveal) = crate::regex::body_hash_regex(b, header);
    b.assert_one(matched.target);
    let selected = select_regex_reveal(b, &reveal, index, 44);
    base64_decode(b, &selected, 32).try_into().unwrap()
}

impl EmailTarget {
    /// Builds the composable verifier. Register outputs explicitly, or use EmailCircuit.
    pub fn new(b: &mut Builder, config: &EmailConfig) -> Self {
        assert!(config.max_header_bytes > 0 && config.max_header_bytes.is_multiple_of(64));
        assert!(
            config.ignore_body_hash
                || (config.max_body_bytes > 0 && config.max_body_bytes.is_multiple_of(64))
        );
        assert!(!config.ignore_body_hash || (!config.body_mask && !config.remove_soft_line_breaks));
        let header = bytes(b, config.max_header_bytes);
        let header_length = b.add_virtual_target();
        assert_zero_padding(b, &header, header_length);
        assert_sha256_padding(b, &header, header_length);
        let header_digest = sha256_padded(b, &header, header_length, None);
        let rsa = RsaTarget::new(b, &header_digest, config.modulus_bytes);
        let pubkey_hash = poseidon_large(b, &rsa.modulus.limbs, 16);
        let header_mask = config.header_mask.then(|| {
            (0..header.len())
                .map(|_| b.add_virtual_bool_target_safe())
                .collect::<Vec<_>>()
        });
        let masked_header = header_mask.as_ref().map(|mask| byte_mask(b, &header, mask));
        let mut masked_body = None;
        let body = if config.ignore_body_hash {
            None
        } else {
            let body_bytes = bytes(b, config.max_body_bytes);
            let length = b.add_virtual_target();
            assert_zero_padding(b, &body_bytes, length);
            let pre_hash: [Target; 32] = bytes(b, 32).try_into().unwrap();
            if !config.allow_partial_body_hash {
                for (&target, byte) in pre_hash
                    .iter()
                    .zip(IV.into_iter().flat_map(u32::to_be_bytes))
                {
                    let initial = b.constant(F::from_canonical_u8(byte));
                    b.connect(target, initial);
                }
                assert_sha256_padding(b, &body_bytes, length);
            }
            let hash_index = b.add_virtual_target();
            // Extraction must be inside the authenticated portion, not unused capacity.
            let end = b.add_const(hash_index, F::from_canonical_u8(44));
            let in_header = less_than(b, end, header_length);
            b.assert_one(in_header.target);
            let expected = body_hash_from_header(b, &header, hash_index);
            let actual = sha256_padded(b, &body_bytes, length, Some(&pre_hash));
            for (a, c) in actual.into_iter().zip(expected) {
                b.connect(a, c);
            }
            let decoded = config.remove_soft_line_breaks.then(|| {
                let decoded = bytes(b, config.max_body_bytes);
                let valid = remove_soft_line_breaks(b, &body_bytes, &decoded);
                b.assert_one(valid.target);
                decoded
            });
            let mask = config.body_mask.then(|| {
                (0..body_bytes.len())
                    .map(|_| b.add_virtual_bool_target_safe())
                    .collect::<Vec<_>>()
            });
            masked_body = mask.as_ref().map(|mask| byte_mask(b, &body_bytes, mask));
            Some(BodyTarget {
                bytes: body_bytes,
                length,
                pre_hash,
                hash_index,
                mask,
                decoded,
            })
        };
        Self {
            header,
            header_length,
            rsa,
            header_mask,
            body,
            header_digest,
            pubkey_hash,
            masked_header,
            masked_body,
        }
    }

    /// Public-input order: key hash (4), header digest (32), optional masked
    /// header, optional masked body. The decoded body remains private.
    pub fn register_public_inputs(&self, b: &mut Builder) {
        b.register_public_inputs(&self.pubkey_hash.elements);
        b.register_public_inputs(&self.header_digest);
        if let Some(values) = &self.masked_header {
            b.register_public_inputs(values);
        }
        if let Some(values) = &self.masked_body {
            b.register_public_inputs(values);
        }
    }

    /// Assigns private inputs and the RSA auxiliaries required by this configuration.
    pub fn set(&self, pw: &mut PartialWitness<F>, input: &EmailWitness<'_>) -> Result<()> {
        set_bytes(pw, &self.header, input.header)?;
        pw.set_target(
            self.header_length,
            F::from_canonical_usize(input.header_length),
        )?;
        self.rsa.set(pw, input.signature, input.modulus)?;
        set_mask(pw, self.header_mask.as_deref(), input.header_mask)?;
        match (&self.body, &input.body) {
            (None, None) => {}
            (Some(t), Some(w)) => {
                set_bytes(pw, &t.bytes, w.bytes)?;
                pw.set_target(t.length, F::from_canonical_usize(w.length))?;
                pw.set_target(t.hash_index, F::from_canonical_usize(w.hash_index))?;
                set_bytes(pw, &t.pre_hash, w.pre_hash)?;
                set_mask(pw, t.mask.as_deref(), w.mask)?;
                match (&t.decoded, w.decoded) {
                    (None, None) => {}
                    (Some(t), Some(w)) => set_bytes(pw, t, w)?,
                    _ => anyhow::bail!("decoded body does not match circuit configuration"),
                }
            }
            _ => anyhow::bail!("body witness does not match circuit configuration"),
        }
        Ok(())
    }
}

/// Requires mask witnesses exactly when the corresponding feature is enabled.
fn set_mask(
    pw: &mut PartialWitness<F>,
    targets: Option<&[BoolTarget]>,
    mask: Option<&[bool]>,
) -> Result<()> {
    match (targets, mask) {
        (None, None) => Ok(()),
        (Some(t), Some(m)) => {
            ensure!(t.len() == m.len(), "mask length mismatch");
            for (&t, &v) in t.iter().zip(m) {
                pw.set_bool_target(t, v)?;
            }
            Ok(())
        }
        _ => anyhow::bail!("mask does not match circuit configuration"),
    }
}

#[derive(Clone, Copy)]
pub struct BodyWitness<'a> {
    pub bytes: &'a [u8],
    pub length: usize,
    pub pre_hash: &'a [u8; 32],
    pub hash_index: usize,
    pub mask: Option<&'a [bool]>,
    pub decoded: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
pub struct EmailWitness<'a> {
    pub header: &'a [u8],
    pub header_length: usize,
    pub signature: &'a BigUint,
    pub modulus: &'a BigUint,
    pub header_mask: Option<&'a [bool]>,
    pub body: Option<BodyWitness<'a>>,
}

pub struct EmailCircuit {
    pub targets: EmailTarget,
    pub data: CircuitData<F, C, D>,
    /// Gate rows before Plonky2 pads the trace to a power of two.
    pub gate_rows: usize,
}

impl EmailCircuit {
    /// Constructs a zero-knowledge proving and verification circuit.
    pub fn build(config: &EmailConfig) -> Self {
        let mut builder = Builder::new(circuit_config());
        let targets = EmailTarget::new(&mut builder, config);
        targets.register_public_inputs(&mut builder);
        let gate_rows = builder.num_gates();
        Self {
            targets,
            data: builder.build::<C>(),
            gate_rows,
        }
    }

    pub fn prove(&self, input: &EmailWitness<'_>) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        self.targets.set(&mut pw, input)?;
        self.data.prove(pw)
    }
}
