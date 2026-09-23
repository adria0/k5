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
//
// Encapsulation to a public key produces `ml_kem_768_ciphertext (1088) ||
// x25519_ephemeral_public (32)` and a 32 byte key derived with HKDF-SHA256
// from `ml_kem_768_shared || x25519_shared`, bound to the ciphertext, the
// recipient public key and a caller supplied context.

use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::{check_public, decode_hex, Error, Section};

const ALGORITHM: &str = "X25519MLKEM768";

const X25519_LEN: usize = 32;
/// Length of an X25519MLKEM768 public key.
pub const PUBLIC_LEN: usize = ml_kem_768::EK_LEN + X25519_LEN;
/// Length of an X25519MLKEM768 encapsulation.
pub const CIPHERTEXT_LEN: usize = ml_kem_768::CT_LEN + X25519_LEN;

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
    pub x25519: x25519_dalek::StaticSecret,
    x25519_public: x25519_dalek::PublicKey,
    pub ml_kem_768: ml_kem_768::DecapsKey,
    ml_kem_768_public: ml_kem_768::EncapsKey,
    ml_kem_768_seed: [u8; 64],
}

impl KemKey {
    /// Deterministically derives a key from its secrets.
    pub fn from_secrets(x25519_secret: [u8; 32], ml_kem_768_seed: [u8; 64]) -> Self {
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
    pub fn public(&self) -> Vec<u8> {
        let mut public = self.ml_kem_768_public();
        public.extend(self.x25519_public());
        public
    }

    /// Recovers the key of an [`encapsulate`] to this key's public key.
    pub fn decapsulate(&self, ciphertext: &[u8], context: &[u8]) -> Result<[u8; 32], Error> {
        if ciphertext.len() != CIPHERTEXT_LEN {
            return Err(format!(
                "KEM ciphertext must be {CIPHERTEXT_LEN} bytes, got {}",
                ciphertext.len()
            )
            .into());
        }
        let (ml_kem_ct, x25519_ephemeral) = ciphertext.split_at(ml_kem_768::CT_LEN);

        let ml_kem_ct = ml_kem_768::CipherText::try_from_bytes(ml_kem_ct.try_into()?)?;
        let ml_kem_shared = self.ml_kem_768.try_decaps(&ml_kem_ct)?.into_bytes();

        let x25519_ephemeral: [u8; X25519_LEN] = x25519_ephemeral.try_into()?;
        let x25519_shared = self
            .x25519
            .diffie_hellman(&x25519_dalek::PublicKey::from(x25519_ephemeral));
        if !x25519_shared.was_contributory() {
            return Err("invalid X25519 ephemeral key".into());
        }

        combine(
            &ml_kem_shared,
            x25519_shared.as_bytes(),
            ciphertext,
            &self.public(),
            context,
        )
    }
}

/// Encapsulates a fresh key to an X25519MLKEM768 `public` key, returning the
/// ciphertext and the key.
pub fn encapsulate(public: &[u8], context: &[u8]) -> Result<(Vec<u8>, [u8; 32]), Error> {
    if public.len() != PUBLIC_LEN {
        return Err(format!(
            "KEM public key must be {PUBLIC_LEN} bytes, got {}",
            public.len()
        )
        .into());
    }
    let (ml_kem_public, x25519_public) = public.split_at(ml_kem_768::EK_LEN);

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    let ml_kem_public = ml_kem_768::EncapsKey::try_from_bytes(ml_kem_public.try_into()?)?;
    let (ml_kem_shared, ml_kem_ct) = ml_kem_public.encaps_from_seed(&seed);

    let mut ephemeral = [0u8; X25519_LEN];
    getrandom::getrandom(&mut ephemeral)?;
    let ephemeral = x25519_dalek::StaticSecret::from(ephemeral);
    let x25519_public: [u8; X25519_LEN] = x25519_public.try_into()?;
    let x25519_shared = ephemeral.diffie_hellman(&x25519_dalek::PublicKey::from(x25519_public));
    if !x25519_shared.was_contributory() {
        return Err("invalid X25519 public key".into());
    }

    let mut ciphertext = ml_kem_ct.into_bytes().to_vec();
    ciphertext.extend(x25519_dalek::PublicKey::from(&ephemeral).as_bytes());

    let key = combine(
        &ml_kem_shared.into_bytes(),
        x25519_shared.as_bytes(),
        &ciphertext,
        public,
        context,
    )?;

    Ok((ciphertext, key))
}

/// Derives the key from both shared secrets with HKDF-SHA256, binding the
/// ciphertext, the recipient public key and the context.
fn combine(
    ml_kem_shared: &[u8],
    x25519_shared: &[u8],
    ciphertext: &[u8],
    public: &[u8],
    context: &[u8],
) -> Result<[u8; 32], Error> {
    let mut ikm = ml_kem_shared.to_vec();
    ikm.extend(x25519_shared);

    let mut info = b"aiwot X25519MLKEM768 v1".to_vec();
    info.extend(ciphertext);
    info.extend(public);
    info.extend(context);

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(&info, &mut key)
        .map_err(|_| "HKDF expand failed")?;

    Ok(key)
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
        assert_eq!(restored.ml_kem_768.try_decaps(&ciphertext).unwrap(), shared);

        // Hybrid encapsulation round trip, bound to the context.
        let (ciphertext, key_a) = encapsulate(&key.public(), b"ctx").unwrap();
        assert_eq!(ciphertext.len(), CIPHERTEXT_LEN);
        assert_eq!(restored.decapsulate(&ciphertext, b"ctx").unwrap(), key_a);
        assert_ne!(restored.decapsulate(&ciphertext, b"other").unwrap(), key_a);
        let other = KemKey::generate().unwrap();
        assert_ne!(other.decapsulate(&ciphertext, b"ctx").unwrap(), key_a);

        // The restored X25519 key agrees with the original.
        let peer = x25519_dalek::StaticSecret::from([7; 32]);
        let peer_public = x25519_dalek::PublicKey::from(&peer);
        assert_eq!(
            restored.x25519.diffie_hellman(&peer_public).to_bytes(),
            peer.diffie_hellman(&key.x25519_public).to_bytes()
        );
    }
}
