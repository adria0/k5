// Signed messages: the OpenPGP Cleartext Signature Framework
// (`-----BEGIN PGP SIGNED MESSAGE-----`).
//
// A signed message carries no public key: verifying it resolves the signer's
// public key by the fingerprint in the signature from a [`Keyring`], as a
// real PGP keyring would. Verifying a message from a k5 whose self
// attestation has not been fetched into the keyring fails.

use std::collections::HashMap;

use pgp::{
    composed::{CleartextSignedMessage, SignedPublicKey, SignedSecretKey},
    types::Password,
};
use rand::rngs::OsRng;

pub type Error = Box<dyn std::error::Error>;

/// Public keys of known signers, by k5 id (OpenPGP fingerprint).
pub type Keyring = HashMap<String, SignedPublicKey>;

/// A verified signed message.
pub struct Verified {
    /// The k5 id of the signer.
    pub from: String,
    pub msg: String,
}

/// Signs `msg` with `key`, returning the armored cleartext-signed message.
pub fn sign(key: &SignedSecretKey, msg: &str) -> Result<String, Error> {
    let signed = CleartextSignedMessage::sign(OsRng, msg, &key.primary_key, &Password::empty())?;

    Ok(signed.to_armored_string(Default::default())?)
}

/// Verifies an armored cleartext-signed message, resolving the signer's
/// public key from `keyring` by the fingerprint carried in the signature.
pub fn verify(armored: &str, keyring: &Keyring) -> Result<Verified, Error> {
    let (signed, _) = CleartextSignedMessage::from_string(armored)?;
    let signature = signed
        .signatures()
        .first()
        .ok_or("signed message has no signature")?;
    let from = signature
        .issuer_fingerprint()
        .first()
        .ok_or("signature has no issuer fingerprint")?
        .to_string();

    let public = keyring
        .get(&from)
        .ok_or_else(|| format!("unknown signer k5:{from}: fetch its self attestation first"))?;
    signed.verify(public)?;

    // `signed_text` normalizes line endings to CRLF for hashing; every
    // statement in this codebase is authored with plain `\n`.
    Ok(Verified {
        from,
        msg: signed.signed_text().replace("\r\n", "\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    fn keyring_of(keys: &crate::key::Keys) -> Keyring {
        Keyring::from([(keys.k5(), keys.public())])
    }

    #[test]
    fn test_round_trip() {
        let keys = test_keys();
        let keyring = keyring_of(&keys);

        let armored = sign(&keys.secret, "hello\nworld").unwrap();
        assert!(armored.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));

        let verified = verify(&armored, &keyring).unwrap();
        assert_eq!(verified.from, keys.k5());
        assert_eq!(verified.msg, "hello\nworld");
    }

    #[test]
    fn test_unknown_signer() {
        let keys = test_keys();
        let armored = sign(&keys.secret, "hello").unwrap();

        // Without the signer's key in the keyring, verification fails.
        assert!(verify(&armored, &Keyring::new()).is_err());
    }

    #[test]
    fn test_tampering() {
        let keys = test_keys();
        let keyring = keyring_of(&keys);
        let armored = sign(&keys.secret, "hello").unwrap();

        let tampered = armored.replace("hello", "hellO");
        assert!(verify(&tampered, &keyring).is_err());

        // Signed by someone else than claimed: verification against the
        // wrong keyring entry fails.
        let other = test_keys();
        let mut mixed = Keyring::new();
        mixed.insert(keys.k5(), other.public());
        assert!(verify(&armored, &mixed).is_err());
    }
}
