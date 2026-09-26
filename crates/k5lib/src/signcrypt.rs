// Signcrypted messages: an OpenPGP message, signed by the sender and
// encrypted to the MlKem768X25519 encryption subkey of the recipient, taken
// from its verified self attestation (`me`).
//
// The signed statement, inside the encryption, is
//
// k5 signcrypt
// from:<k5 of the sender>
// to:<k5 of the recipient>
// <message>
//
// Unlike the Cleartext Signature Framework, an OpenPGP encrypted+signed
// message carries no public signer information once decrypted, so `from` is
// only a claim until the signature is checked against the public key it
// names, resolved from a [`Keyring`] (as a real PGP keyring would). `to`
// binds the recipient into what was signed, so the message cannot be
// re-encrypted to someone else as if sent to them.

use anyhow::{anyhow, Context as _};
use pgp::{
    composed::{Message, MessageBuilder, SignedPublicSubKey},
    crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::Password,
};
use rand::rngs::OsRng;

use crate::{
    attestations::{me, Error},
    db::Db,
    k5id::K5Id,
    key::Keys,
    message::Keyring,
};

const HEADER: &str = "k5 signcrypt";

/// A decrypted and verified signcrypted message.
pub struct Opened {
    /// The k5 id of the sender.
    pub from: String,
    pub msg: String,
}

/// Returns the `MlKem768X25519` encryption subkey of `k5` from its self
/// attestation in `db`, which must be valid.
pub async fn recipient_encryption_key(db: &dyn Db, k5: &K5Id) -> Result<SignedPublicSubKey, Error> {
    let name = me::name(k5);
    let path = db.location(&name);

    let Some(record) = db.get(&name).await? else {
        return Err(anyhow!(
            "no self attestation of k5:{k5} ({path}): its encryption key is unknown"
        ));
    };

    let me = me::verify(&record).map_err(|e| anyhow!("invalid self attestation {path}: {e}"))?;
    if me.k5 != k5.as_str() {
        return Err(anyhow!("{path} is the self attestation of k5:{}", me.k5));
    }

    me.public
        .public_subkeys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{path} has no encryption subkey"))
}

/// Signs `msg` with `keys` and encrypts it to `to_key`, addressed to `to`.
pub fn seal(
    keys: &Keys,
    to: &str,
    to_key: &SignedPublicSubKey,
    msg: &str,
) -> Result<String, Error> {
    let mut builder = MessageBuilder::from_bytes("", statement(&keys.k5(), to, msg))
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
        .map_err(|_| anyhow!("decryption failed: not encrypted to this key, or tampered"))?;

    let plaintext = msg
        .as_data_string()
        .map_err(|_| anyhow!("decryption failed: not encrypted to this key, or tampered"))?;
    let (from, to, body) = parse_statement(&plaintext)?;
    if to != keys.k5() {
        return Err(anyhow!("message is for k5:{to}, not for k5:{}", keys.k5()));
    }

    let sender = keyring
        .get(&from)
        .with_context(|| format!("unknown sender k5:{from}: fetch its self attestation first"))?;
    msg.verify(sender)?;

    Ok(Opened { from, msg: body })
}

/// Decrypts the local copy of a message the local k5 sent: sealed by
/// [`seal`] with the local encryption subkey, so it is stored encrypted like
/// received messages. It must be signed by the local key. Returns the
/// recipient and the message.
pub fn open_own(keys: &Keys, armored: &str) -> Result<(String, String), Error> {
    let (msg, _) = Message::from_armor(armored.as_bytes())?;
    let mut msg = msg
        .decrypt(&Password::empty(), &keys.secret)
        .map_err(|_| anyhow!("decryption failed: not encrypted to this key, or tampered"))?;

    let plaintext = msg
        .as_data_string()
        .map_err(|_| anyhow!("decryption failed: not encrypted to this key, or tampered"))?;
    let (from, to, body) = parse_statement(&plaintext)?;
    if from != keys.k5() {
        return Err(anyhow!(
            "sent copy from k5:{from}, not from k5:{}",
            keys.k5()
        ));
    }
    msg.verify(&keys.public())?;

    Ok((to, body))
}

fn statement(from: &str, to: &str, msg: &str) -> String {
    format!("{HEADER}\nfrom:{from}\nto:{to}\n{msg}")
}

/// Parses a signcrypt statement into its sender, recipient and message.
fn parse_statement(statement: &str) -> Result<(String, String, String), Error> {
    let rest = statement
        .strip_prefix(&format!("{HEADER}\n"))
        .context("not a signcrypt statement")?;
    let (from, rest) = rest
        .split_once('\n')
        .context("invalid signcrypt statement: missing `to:`")?;
    let from = from
        .strip_prefix("from:")
        .context("invalid signcrypt statement: expected `from:`")?;
    let (to, msg) = rest
        .split_once('\n')
        .context("invalid signcrypt statement: missing message")?;
    let to = to
        .strip_prefix("to:")
        .context("invalid signcrypt statement: expected `to:`")?;

    Ok((
        K5Id::parse_strict(from)?.into(),
        K5Id::parse_strict(to)?.into(),
        msg.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    fn keyring_of(keys: &Keys) -> Keyring {
        Keyring::from([(keys.k5(), keys.public())])
    }

    #[test]
    fn test_seal_open() {
        let alice = test_keys();
        let bob = test_keys();

        let sealed = seal(
            &alice,
            &bob.k5(),
            &bob.encryption_subkey().unwrap(),
            "hi Bob\n# msg\n",
        )
        .unwrap();
        assert!(sealed.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(!sealed.contains("hi Bob"));

        let opened = open(&bob, &sealed, &keyring_of(&alice)).unwrap();
        assert_eq!(opened.msg, "hi Bob\n# msg\n");
        assert_eq!(opened.from, alice.k5());

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
            MessageBuilder::from_bytes("", statement(&alice.k5(), &bob.k5(), "for Bob"))
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
