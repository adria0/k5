// Hybrid X25519MLKEM768 key encapsulation key, stored in the `[kem]` section:
//
// [kem]
// algorithm = "X25519MLKEM768"
// x25519_secret = "..."      # 32 bytes
// x25519_public = "..."      # 32 bytes
// ml_kem_768_seed = "..."    # 64 bytes, FIPS 203 `d || z`
// ml_kem_768_public = "..."  # 1184 bytes, encapsulation key
//
// The X25519MLKEM768 public key (as in draft-ietf-tls-ecdhe-mlkem) is
// `ml_kem_768_public || x25519_public`. This key does not affect the aiwot id.

use fips203::{
    ml_kem_768,
    traits::{KeyGen, SerDes},
};
use serde::{Deserialize, Serialize};

use super::{check_public, decode_hex, Error, Section};

const ALGORITHM: &str = "X25519MLKEM768";

#[derive(Serialize, Deserialize)]
struct KemConfig {
    algorithm: String,
    x25519_secret: String,
    x25519_public: String,
    ml_kem_768_seed: String,
    ml_kem_768_public: String,
}

/// A hybrid X25519MLKEM768 key encapsulation key.
pub struct KemKey {
    // Not used for decapsulation yet.
    #[allow(dead_code)]
    pub x25519: x25519_dalek::StaticSecret,
    x25519_public: x25519_dalek::PublicKey,
    // Not used for decapsulation yet.
    #[allow(dead_code)]
    pub ml_kem_768: ml_kem_768::DecapsKey,
    ml_kem_768_public: ml_kem_768::EncapsKey,
    ml_kem_768_seed: [u8; 64],
}

impl KemKey {
    fn from_secrets(x25519_secret: [u8; 32], ml_kem_768_seed: [u8; 64]) -> Self {
        let x25519 = x25519_dalek::StaticSecret::from(x25519_secret);

        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&ml_kem_768_seed[..32]);
        z.copy_from_slice(&ml_kem_768_seed[32..]);
        let (ml_kem_768_public, ml_kem_768) = ml_kem_768::KG::keygen_from_seed(d, z);

        Self {
            x25519_public: x25519_dalek::PublicKey::from(&x25519),
            x25519,
            ml_kem_768,
            ml_kem_768_public,
            ml_kem_768_seed,
        }
    }

    pub fn x25519_public(&self) -> [u8; 32] {
        self.x25519_public.to_bytes()
    }

    pub fn ml_kem_768_public(&self) -> Vec<u8> {
        self.ml_kem_768_public.clone().into_bytes().to_vec()
    }

    /// The X25519MLKEM768 public key: `ml_kem_768_public || x25519_public`.
    // Not used yet.
    #[allow(dead_code)]
    pub fn public(&self) -> Vec<u8> {
        let mut public = self.ml_kem_768_public();
        public.extend(self.x25519_public());
        public
    }
}

impl Section for KemKey {
    const NAME: &'static str = "kem";

    fn generate() -> Result<Self, Error> {
        let mut x25519_secret = [0u8; 32];
        let mut ml_kem_768_seed = [0u8; 64];
        getrandom::getrandom(&mut x25519_secret)?;
        getrandom::getrandom(&mut ml_kem_768_seed)?;

        Ok(Self::from_secrets(x25519_secret, ml_kem_768_seed))
    }

    fn from_toml(value: toml::Value) -> Result<Self, Error> {
        let config: KemConfig = value.try_into()?;
        if config.algorithm != ALGORITHM {
            return Err(format!(
                "unsupported algorithm `{}`, expected `{ALGORITHM}`",
                config.algorithm
            )
            .into());
        }

        let key = Self::from_secrets(
            decode_hex("x25519_secret", &config.x25519_secret)?,
            decode_hex("ml_kem_768_seed", &config.ml_kem_768_seed)?,
        );
        check_public("x25519_public", &config.x25519_public, &key.x25519_public())?;
        check_public(
            "ml_kem_768_public",
            &config.ml_kem_768_public,
            &key.ml_kem_768_public(),
        )?;

        Ok(key)
    }

    fn to_toml(&self) -> Result<toml::Value, Error> {
        Ok(toml::Value::try_from(KemConfig {
            algorithm: ALGORITHM.to_string(),
            x25519_secret: hex::encode(self.x25519.to_bytes()),
            x25519_public: hex::encode(self.x25519_public()),
            ml_kem_768_seed: hex::encode(self.ml_kem_768_seed),
            ml_kem_768_public: hex::encode(self.ml_kem_768_public()),
        })?)
    }
}

#[cfg(test)]
mod tests {
    use fips203::traits::{Decaps, Encaps};

    use super::*;

    #[test]
    fn test_round_trip() {
        let key = KemKey::generate().unwrap();
        assert_eq!(key.public().len(), 1184 + 32);

        let restored = KemKey::from_toml(key.to_toml().unwrap()).unwrap();
        assert_eq!(restored.public(), key.public());

        // The restored ML-KEM key decapsulates what the original public key
        // encapsulates.
        let (shared, ciphertext) = key.ml_kem_768_public.encaps_from_seed(&[3; 32]);
        assert_eq!(
            restored.ml_kem_768.try_decaps(&ciphertext).unwrap(),
            shared
        );

        // The restored X25519 key agrees with the original.
        let peer = x25519_dalek::StaticSecret::from([7; 32]);
        let peer_public = x25519_dalek::PublicKey::from(&peer);
        assert_eq!(
            restored.x25519.diffie_hellman(&peer_public).to_bytes(),
            peer.diffie_hellman(&key.x25519_public).to_bytes()
        );
    }
}
