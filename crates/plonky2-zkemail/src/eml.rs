//! Preparation and proof generation for bounded DKIM-signed `.eml` messages.

use crate::{
    email::{BodyWitness, EmailCircuit, EmailConfig, EmailWitness},
    sha256::{IV, pad},
};
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const PREPARE_SCRIPT: &str = include_str!("../examples/eml/prepare.mjs");
static TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct PreparedEmail {
    domain: String,
    selector: String,
    header: Vec<u8>,
    body: Vec<u8>,
    body_hash_index: usize,
    modulus_hex: String,
    signature_hex: String,
}

/// A serialized Plonky2 proof and identifying information about its DKIM key.
pub struct EmailProof {
    pub bytes: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub gate_rows: usize,
    pub padded_rows: usize,
}

struct TemporaryScript(PathBuf);

impl TemporaryScript {
    fn create() -> Result<Self> {
        let id = TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "plonky2-zkemail-prepare-{}-{id}.mjs",
            std::process::id()
        ));
        fs::write(&path, PREPARE_SCRIPT)
            .with_context(|| format!("failed to write temporary helper {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for TemporaryScript {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Canonicalizes the email and validates its DKIM signature against a trusted
/// public-key record.
fn prepare(path: &Path, dkim_path: &Path) -> Result<PreparedEmail> {
    let script = TemporaryScript::create()?;
    let output = Command::new("node")
        .arg(&script.0)
        .arg(path)
        .arg(dkim_path)
        .output()
        .context("cannot run DKIM preparation; install Node.js 18 or later")?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    serde_json::from_slice(&output.stdout).context("invalid JSON from DKIM preparation")
}

/// Generates and verifies a Plonky2 proof for a DKIM-signed email.
///
/// `dkim_path` must name a JSON object with `domain`, `selector`, and `record`
/// fields, where `record` is the trusted DKIM TXT record.
///
/// This intentionally supports the bounded DKIM format documented by this
/// crate: one 2048-bit RSA-SHA256 signature using relaxed/relaxed
/// canonicalization and no partial-body `l=` tag.
pub fn prove(path: impl AsRef<Path>, dkim_path: impl AsRef<Path>) -> Result<EmailProof> {
    let prepared = prepare(path.as_ref(), dkim_path.as_ref())?;
    let modulus = BigUint::parse_bytes(prepared.modulus_hex.as_bytes(), 16)
        .context("invalid RSA modulus from DKIM preparation")?;
    let signature = BigUint::parse_bytes(prepared.signature_hex.as_bytes(), 16)
        .context("invalid RSA signature from DKIM preparation")?;
    let header = pad(&prepared.header);
    let body = pad(&prepared.body);
    let config = EmailConfig {
        max_header_bytes: header.len(),
        max_body_bytes: body.len(),
        modulus_bytes: 256,
        ..EmailConfig::default()
    };
    let state: [u8; 32] = IV
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("SHA-256 state is always 32 bytes");
    let witness = EmailWitness {
        header: &header,
        header_length: header.len(),
        signature: &signature,
        modulus: &modulus,
        header_mask: None,
        body: Some(BodyWitness {
            bytes: &body,
            length: body.len(),
            pre_hash: &state,
            hash_index: prepared.body_hash_index,
            mask: None,
            decoded: None,
        }),
    };

    let circuit = EmailCircuit::build(&config);
    let gate_rows = circuit.gate_rows;
    let padded_rows = circuit.data.common.degree();
    let proof = circuit.prove(&witness)?;
    circuit.data.verify(proof.clone())?;

    Ok(EmailProof {
        bytes: proof.to_bytes(),
        domain: prepared.domain,
        selector: prepared.selector,
        gate_rows,
        padded_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn embedded_helper_prepares_fixture() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let prepared = prepare(
            &root.join("examples/fixtures/test.eml"),
            &root.join("examples/fixtures/icloud-dkim.json"),
        )
        .unwrap();

        assert_eq!(prepared.domain, "icloud.com");
        assert_eq!(prepared.selector, "1a1hai");
        assert_eq!(prepared.body, b"Hello,\r\n\r\nHow are you?\r\n");
        assert_eq!(prepared.modulus_hex.len(), 512);
        assert_eq!(prepared.signature_hex.len(), 512);
        assert_eq!(
            &prepared.header[prepared.body_hash_index..prepared.body_hash_index + 44],
            b"7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU="
        );

        // The original Circom fixture represents this digest in 121-bit limbs.
        let limbs = [
            "1156466847851242602709362303526378170",
            "191372789510123109308037416804949834",
            "7204",
        ]
        .map(|value| BigUint::parse_bytes(value.as_bytes(), 10).unwrap());
        let expected = crate::bigint::from_circom_limbs(&limbs, 121).unwrap();
        assert_eq!(
            BigUint::from_bytes_be(&Sha256::digest(&prepared.header)),
            expected
        );
    }
}
