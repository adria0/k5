// Signcrypted messages: an OpenPGP message, signed by the sender and
// encrypted to the MlKem768X25519 encryption subkey of the recipient, taken
// from its verified self attestation (`me`).
//
// The signed statement, inside the encryption, is
//
// aiwot signcrypt
// from:<aiwot of the sender>
// to:<aiwot of the recipient>
// <message>
//
// Unlike the Cleartext Signature Framework, an OpenPGP encrypted+signed
// message carries no public signer information once decrypted, so `from` is
// only a claim until the signature is checked against the public key it
// names, resolved from a [`Keyring`] (as a real PGP keyring would). `to`
// binds the recipient into what was signed, so the message cannot be
// re-encrypted to someone else as if sent to them.

use pgp::{
    composed::{Message, MessageBuilder, SignedPublicSubKey},
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::Password,
};
use rand::rngs::OsRng;

use crate::{
    attestations::{me, Error},
    key::Keys,
    message::Keyring,
};

const HEADER: &str = "aiwot signcrypt";

/// A decrypted and verified signcrypted message.
pub struct Opened {
    /// The aiwot id of the sender.
    pub from: String,
    pub msg: String,
}

/// Normalizes an aiwot given on the command line: without the `aiwot:`
/// prefix, lowercase.
pub fn recipient_aiwot(aiwot: &str) -> String {
    let aiwot = aiwot.trim();
    aiwot
        .strip_prefix("aiwot:")
        .unwrap_or(aiwot)
        .to_ascii_lowercase()
}

/// Returns the `MlKem768X25519` encryption subkey of `aiwot` from its self
/// attestation in the attestations directory, which must be valid.
pub async fn recipient_encryption_key(aiwot: &str) -> Result<SignedPublicSubKey, Error> {
    let aiwot = recipient_aiwot(aiwot);
    let path = me::path(&aiwot);

    let record = match tokio::fs::read_to_string(&path).await {
        Ok(record) => record,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "no self attestation of aiwot:{aiwot} ({path}): its encryption key is unknown"
            )
            .into())
        }
        Err(e) => return Err(e.into()),
    };

    let me = me::verify(&record).map_err(|e| format!("invalid self attestation {path}: {e}"))?;
    if me.aiwot != aiwot {
        return Err(format!("{path} is the self attestation of aiwot:{}", me.aiwot).into());
    }

    me.public
        .public_subkeys
        .into_iter()
        .next()
        .ok_or_else(|| format!("{path} has no encryption subkey").into())
}

/// Signs `msg` with `keys` and encrypts it to `to_key`, addressed to `to`.
pub fn seal(
    keys: &Keys,
    to: &str,
    to_key: &SignedPublicSubKey,
    msg: &str,
) -> Result<String, Error> {
    let mut builder = MessageBuilder::from_bytes("", statement(&keys.aiwot(), to, msg))
        .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
    builder
        .sign(
            &keys.secret.primary_key,
            Password::empty(),
            HashAlgorithm::Sha3_512,
        )
        .encrypt_to_key(OsRng, to_key)?;

    Ok(builder.to_armored_string(OsRng, Default::default())?)
}

/// Decrypts a signcrypted message addressed to `keys`, resolving the
/// sender's public key from `keyring` by its claimed identity and verifying
/// the signature against it.
pub fn open(keys: &Keys, armored: &str, keyring: &Keyring) -> Result<Opened, Error> {
    let (msg, _) = Message::from_armor(armored.as_bytes())?;
    let mut msg = msg
        .decrypt(&Password::empty(), &keys.secret)
        .map_err(|_| "decryption failed: not encrypted to this key, or tampered")?;

    let plaintext = msg
        .as_data_string()
        .map_err(|_| "decryption failed: not encrypted to this key, or tampered")?;
    let (from, to, body) = parse_statement(&plaintext)?;
    if to != keys.aiwot() {
        return Err(format!("message is for aiwot:{to}, not for aiwot:{}", keys.aiwot()).into());
    }

    let sender = keyring
        .get(&from)
        .ok_or_else(|| format!("unknown sender aiwot:{from}: fetch its self attestation first"))?;
    msg.verify(sender)?;

    Ok(Opened { from, msg: body })
}

fn statement(from: &str, to: &str, msg: &str) -> String {
    format!("{HEADER}\nfrom:{from}\nto:{to}\n{msg}")
}

/// Parses a signcrypt statement into its sender, recipient and message.
fn parse_statement(statement: &str) -> Result<(String, String, String), Error> {
    let rest = statement
        .strip_prefix(&format!("{HEADER}\n"))
        .ok_or("not a signcrypt statement")?;
    let (from, rest) = rest
        .split_once('\n')
        .ok_or("invalid signcrypt statement: missing `to:`")?;
    let from = from
        .strip_prefix("from:")
        .ok_or("invalid signcrypt statement: expected `from:`")?;
    let (to, msg) = rest
        .split_once('\n')
        .ok_or("invalid signcrypt statement: missing message")?;
    let to = to
        .strip_prefix("to:")
        .ok_or("invalid signcrypt statement: expected `to:`")?;

    let check_aiwot = |aiwot: &str| {
        (aiwot.len() == 64 && aiwot.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| aiwot.to_ascii_lowercase())
            .ok_or_else(|| Error::from(format!("invalid aiwot `{aiwot}`")))
    };

    Ok((check_aiwot(from)?, check_aiwot(to)?, msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    fn keyring_of(keys: &Keys) -> Keyring {
        Keyring::from([(keys.aiwot(), keys.public())])
    }

    #[test]
    fn test_seal_open() {
        let alice = test_keys();
        let bob = test_keys();

        let sealed = seal(
            &alice,
            &bob.aiwot(),
            &bob.encryption_subkey().unwrap(),
            "hi Bob\n# msg\n",
        )
        .unwrap();
        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(!sealed.contains("hi Bob"));

        let opened = open(&bob, &sealed, &keyring_of(&alice)).unwrap();
        assert_eq!(opened.msg, "hi Bob\n# msg\n");
        assert_eq!(opened.from, alice.aiwot());

        // Someone else cannot open it.
        let eve = test_keys();
        assert!(open(&eve, &sealed, &keyring_of(&alice)).is_err());

        // Without the sender's key in the keyring, opening fails.
        assert!(open(&bob, &sealed, &Keyring::new()).is_err());
    }

    #[test]
    fn test_recipient_binding() {
        // A message Alice signcrypted to Bob, decrypted by Bob and
        // re-encrypted by him to Carol, is rejected by Carol.
        let alice = test_keys();
        let bob = test_keys();
        let carol = test_keys();

        let mut builder =
            MessageBuilder::from_bytes("", statement(&alice.aiwot(), &bob.aiwot(), "for Bob"))
                .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
        builder
            .sign(
                &alice.secret.primary_key,
                Password::empty(),
                HashAlgorithm::Sha3_512,
            )
            .encrypt_to_key(OsRng, &carol.encryption_subkey().unwrap())
            .unwrap();
        let forwarded = builder
            .to_armored_string(OsRng, Default::default())
            .unwrap();

        assert!(open(&carol, &forwarded, &keyring_of(&alice)).is_err());
    }
}
