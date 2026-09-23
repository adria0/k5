// Hybrid Ed25519 + ML-DSA-44 signature key, stored in the `[key]` section.
//
// Both keys are stored as their 32 byte seeds (the Ed25519 secret key and the
// FIPS 204 `ξ` seed), together with the public keys, as hex. The aiwot id of
// the key is SHA-256(ed25519_public || ml_dsa_44_public):
//
// [key]
// algorithm = "Ed25519+ML-DSA-44"
// aiwot = "..."
// ed25519_seed = "..."
// ed25519_public = "..."
// ml_dsa_44_seed = "..."
// ml_dsa_44_public = "..."
//
// The public key is `ed25519_public (32) || ml_dsa_44_public (1312)`, and its
// SHA-256 is the aiwot id. A signature of a message `m` is
// `Ed25519(SHA-512(m)) (64) || ML-DSA-44(SHA-512(m)) (2420)`. ML-DSA-44 uses
// an empty context and hedged (randomized) signing.

use ed25519_dalek::{Signer as _, Verifier as _};
use fips204::{
    ml_dsa_44,
    traits::{KeyGen, SerDes, Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use super::{check_public, decode_hex, Error, Section};

const ALGORITHM: &str = "Ed25519+ML-DSA-44";

const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
/// Length of [`SigningKey::public`].
pub const PUBLIC_LEN: usize = ED25519_PUBLIC_LEN + ml_dsa_44::PK_LEN;
/// Length of a signature produced by [`SigningKey::sign`].
pub const SIGNATURE_LEN: usize = ED25519_SIG_LEN + ml_dsa_44::SIG_LEN;

/// The `[key]` section of `aiwot.toml`.
#[derive(Serialize, Deserialize)]
struct KeyConfig {
    algorithm: String,
    /// Derived from the public keys. Added on load if missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aiwot: Option<String>,
    ed25519_seed: String,
    ed25519_public: String,
    ml_dsa_44_seed: String,
    ml_dsa_44_public: String,
}

/// A hybrid Ed25519 + ML-DSA-44 signing key.
pub struct SigningKey {
    pub ed25519: ed25519_dalek::SigningKey,
    pub ml_dsa_44: ml_dsa_44::PrivateKey,
    ml_dsa_44_public: ml_dsa_44::PublicKey,
    ml_dsa_44_seed: [u8; 32],
}

impl SigningKey {
    fn from_seeds(ed25519_seed: [u8; 32], ml_dsa_44_seed: [u8; 32]) -> Self {
        let (ml_dsa_44_public, ml_dsa_44) = ml_dsa_44::KG::keygen_from_seed(&ml_dsa_44_seed);

        Self {
            ed25519: ed25519_dalek::SigningKey::from_bytes(&ed25519_seed),
            ml_dsa_44,
            ml_dsa_44_public,
            ml_dsa_44_seed,
        }
    }

    pub fn ed25519_public(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }

    pub fn ml_dsa_44_public(&self) -> Vec<u8> {
        self.ml_dsa_44_public.clone().into_bytes().to_vec()
    }

    /// The hybrid public key: `ed25519_public || ml_dsa_44_public`.
    pub fn public(&self) -> Vec<u8> {
        let mut public = self.ed25519_public().to_vec();
        public.extend(self.ml_dsa_44_public());
        public
    }

    /// The aiwot id: SHA-256 of the hybrid public key.
    pub fn aiwot(&self) -> String {
        aiwot(&self.public())
    }

    /// Signs SHA-512(`message`) with both keys: `ed25519_sig || ml_dsa_44_sig`.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let digest = Sha512::digest(message);

        let mut signature = Vec::with_capacity(SIGNATURE_LEN);
        signature.extend(self.ed25519.sign(&digest).to_bytes());
        signature.extend(self.ml_dsa_44.try_sign(&digest, &[])?);

        Ok(signature)
    }
}

/// The aiwot id of a hybrid public key: its SHA-256.
pub fn aiwot(public: &[u8]) -> String {
    hex::encode(Sha256::digest(public))
}

/// Verifies a signature produced by [`SigningKey::sign`] against a hybrid
/// public key. Both signatures must be valid.
pub fn verify(message: &[u8], public: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public.len() != PUBLIC_LEN {
        return Err(format!("public key must be {PUBLIC_LEN} bytes, got {}", public.len()).into());
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(format!(
            "signature must be {SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )
        .into());
    }

    let (ed25519_public, ml_dsa_44_public) = public.split_at(ED25519_PUBLIC_LEN);
    let (ed25519_sig, ml_dsa_44_sig) = signature.split_at(ED25519_SIG_LEN);

    let digest = Sha512::digest(message);

    let ed25519_key = ed25519_dalek::VerifyingKey::from_bytes(ed25519_public.try_into()?)?;
    ed25519_key
        .verify(&digest, &ed25519_dalek::Signature::from_slice(ed25519_sig)?)
        .map_err(|_| "invalid Ed25519 signature")?;

    let ml_dsa_44_key = ml_dsa_44::PublicKey::try_from_bytes(ml_dsa_44_public.try_into()?)?;
    if !ml_dsa_44_key.verify(&digest, ml_dsa_44_sig.try_into()?, &[]) {
        return Err("invalid ML-DSA-44 signature".into());
    }

    Ok(())
}

impl Section for SigningKey {
    const NAME: &'static str = "key";

    fn generate() -> Result<Self, Error> {
        let mut ed25519_seed = [0u8; 32];
        let mut ml_dsa_44_seed = [0u8; 32];
        getrandom::getrandom(&mut ed25519_seed)?;
        getrandom::getrandom(&mut ml_dsa_44_seed)?;

        Ok(Self::from_seeds(ed25519_seed, ml_dsa_44_seed))
    }

    fn from_toml(value: toml::Value) -> Result<Self, Error> {
        let config: KeyConfig = value.try_into()?;
        if config.algorithm != ALGORITHM {
            return Err(format!(
                "unsupported algorithm `{}`, expected `{ALGORITHM}`",
                config.algorithm
            )
            .into());
        }

        let key = Self::from_seeds(
            decode_hex("ed25519_seed", &config.ed25519_seed)?,
            decode_hex("ml_dsa_44_seed", &config.ml_dsa_44_seed)?,
        );
        check_public("ed25519_public", &config.ed25519_public, &key.ed25519_public())?;
        check_public(
            "ml_dsa_44_public",
            &config.ml_dsa_44_public,
            &key.ml_dsa_44_public(),
        )?;
        if let Some(aiwot) = &config.aiwot {
            if !aiwot.eq_ignore_ascii_case(&key.aiwot()) {
                return Err("aiwot does not match the public keys".into());
            }
        }

        Ok(key)
    }

    fn to_toml(&self) -> Result<toml::Value, Error> {
        Ok(toml::Value::try_from(KeyConfig {
            algorithm: ALGORITHM.to_string(),
            aiwot: Some(self.aiwot()),
            ed25519_seed: hex::encode(self.ed25519.to_bytes()),
            ed25519_public: hex::encode(self.ed25519_public()),
            ml_dsa_44_seed: hex::encode(self.ml_dsa_44_seed),
            ml_dsa_44_public: hex::encode(self.ml_dsa_44_public()),
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aiwot() {
        let key = SigningKey::from_seeds([1; 32], [2; 32]);

        let mut public = key.ed25519_public().to_vec();
        public.extend(key.ml_dsa_44_public());
        assert_eq!(key.aiwot(), hex::encode(Sha256::digest(&public)));
        assert_eq!(key.ml_dsa_44_public().len(), 1312);
    }

    #[test]
    fn test_sign_verify() {
        let key = SigningKey::from_seeds([1; 32], [2; 32]);
        let public = key.public();
        assert_eq!(public.len(), PUBLIC_LEN);

        let signature = key.sign(b"hello").unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        verify(b"hello", &public, &signature).unwrap();

        // Wrong message.
        assert!(verify(b"hellO", &public, &signature).is_err());

        // Tampering with either signature is detected.
        for idx in [0, SIGNATURE_LEN - 1] {
            let mut tampered = signature.clone();
            tampered[idx] ^= 1;
            assert!(verify(b"hello", &public, &tampered).is_err());
        }

        // Another key's public key does not verify.
        let other = SigningKey::from_seeds([3; 32], [4; 32]);
        assert!(verify(b"hello", &other.public(), &signature).is_err());
    }

    #[test]
    fn test_round_trip() {
        let key = SigningKey::generate().unwrap();
        let restored = SigningKey::from_toml(key.to_toml().unwrap()).unwrap();
        assert_eq!(restored.aiwot(), key.aiwot());
    }
}
