// Signcrypted messages: signed by the sender and encrypted to the X25519MLKEM768
// key of the recipient, taken from its verified self attestation (`me`).
//
// # to
// <aiwot of the recipient>
// # kem
// <X25519MLKEM768 encapsulation, base58, 100 characters per line>
// # ciphertext
// <ChaCha20-Poly1305 encryption of the signed message, base58, 100 characters per line>
//
// The encrypted signed message (`# from`, `# msg`, `# pbk`, `# signature`)
// signs
//
// aiwot signcrypt
// to:<aiwot of the recipient>
// <message>
//
// so the sender is only known to the recipient, and the signature binds the
// recipient: it cannot be re-encrypted to someone else as if sent to them.
// The encryption key is derived from the encapsulation with `# to` as
// context, and the nonce is zero as each key encrypts a single message.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};

use crate::{
    attestations::{me, Error},
    key::{self, KemKey, SigningKey},
    message::{self, SignedMessage},
};

const HEADER: &str = "aiwot signcrypt";

/// A decrypted and verified signcrypted message.
pub struct Opened {
    /// The verified signed message; `msg` is the signcrypt statement.
    pub signed: SignedMessage,
    /// The message.
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

/// Returns the X25519MLKEM768 public key of `aiwot` from its self
/// attestation in the attestations directory, which must be valid.
pub async fn recipient_kem(aiwot: &str) -> Result<Vec<u8>, Error> {
    let aiwot = recipient_aiwot(aiwot);
    let path = me::path(&aiwot);

    // Self attestations written before `self_attestation` have a legacy name.
    let mut found = None;
    for path in [me::path(&aiwot), me::legacy_path(&aiwot)] {
        match tokio::fs::read_to_string(&path).await {
            Ok(record) => {
                found = Some((path, record));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let Some((path, record)) = found else {
        return Err(format!(
            "no self attestation of aiwot:{aiwot} ({path}): its KEM key is unknown"
        )
        .into());
    };

    let me = me::verify(&record).map_err(|e| format!("invalid self attestation {path}: {e}"))?;
    if me.aiwot != aiwot {
        return Err(format!("{path} is the self attestation of aiwot:{}", me.aiwot).into());
    }

    Ok(me.kem_public)
}

/// Signs `msg` with `key` and encrypts it to `to` with its KEM public key.
pub fn seal(key: &SigningKey, to: &str, to_kem: &[u8], msg: &str) -> Result<String, Error> {
    let signed = SignedMessage::sign(key, &statement(to, msg))?;

    let (kem, aead_key) = key::encapsulate(to_kem, to.as_bytes())?;
    let ciphertext = ChaCha20Poly1305::new(&aead_key.into())
        .encrypt(&Default::default(), signed.to_markdown().as_bytes())
        .map_err(|_| "encryption failed")?;

    Ok(format!(
        "# to\n{to}\n# kem\n{}\n# ciphertext\n{}\n",
        message::encode(&kem),
        message::encode(&ciphertext)
    ))
}

/// Decrypts a signcrypted message addressed to `me`, verifying its signature
/// and that it was signed for `me`.
pub fn open(kem: &KemKey, me: &str, markdown: &str) -> Result<Opened, Error> {
    let (to, encapsulation, ciphertext) = split(markdown)?;
    if !to.eq_ignore_ascii_case(me) {
        return Err(format!("message is for aiwot:{to}, not for aiwot:{me}").into());
    }

    let aead_key = kem.decapsulate(&message::decode("kem", encapsulation)?, to.as_bytes())?;
    let plaintext = ChaCha20Poly1305::new(&aead_key.into())
        .decrypt(
            &Default::default(),
            message::decode("ciphertext", ciphertext)?.as_slice(),
        )
        .map_err(|_| "decryption failed: not encrypted to this key, or tampered")?;

    let signed = SignedMessage::parse(std::str::from_utf8(&plaintext)?)?;
    signed.verify()?;

    let msg = signed
        .msg
        .strip_prefix(&format!("{HEADER}\nto:{to}\n"))
        .ok_or("the signed message is not a signcrypt statement for this recipient")?
        .to_string();

    Ok(Opened { signed, msg })
}

fn statement(to: &str, msg: &str) -> String {
    format!("{HEADER}\nto:{to}\n{msg}")
}

/// Splits a signcrypted message into its `# to`, `# kem` and `# ciphertext`
/// sections.
fn split(markdown: &str) -> Result<(&str, &str, &str), Error> {
    let rest = markdown
        .strip_prefix("# to\n")
        .ok_or("missing `# to` section")?;
    let (to, rest) = rest
        .split_once("\n# kem\n")
        .ok_or("missing `# kem` section")?;
    let (kem, ciphertext) = rest
        .split_once("\n# ciphertext\n")
        .ok_or("missing `# ciphertext` section")?;

    let to = to.trim();
    if to.len() != 64 || !to.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid recipient `{to}`").into());
    }

    Ok((to, kem, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{test_kem_key, test_signing_key};

    #[test]
    fn test_seal_open() {
        let alice = test_signing_key();
        let bob = test_signing_key();
        let bob_kem = test_kem_key();

        let sealed = seal(&alice, &bob.aiwot(), &bob_kem.public(), "hi Bob\n# msg\n").unwrap();
        assert!(sealed.starts_with(&format!("# to\n{}\n# kem\n", bob.aiwot())));
        assert!(sealed.lines().all(|line| line.len() <= 100));
        assert!(!sealed.contains("hi Bob"));
        assert!(!sealed.contains(&alice.aiwot()));

        let opened = open(&bob_kem, &bob.aiwot(), &sealed).unwrap();
        assert_eq!(opened.msg, "hi Bob\n# msg\n");
        assert_eq!(opened.signed.from, alice.aiwot());

        // Someone else cannot open it.
        let eve = test_signing_key();
        let eve_kem = test_kem_key();
        assert!(open(&eve_kem, &eve.aiwot(), &sealed).is_err());
        let readdressed = sealed.replace(&bob.aiwot(), &eve.aiwot());
        assert!(open(&eve_kem, &eve.aiwot(), &readdressed).is_err());

        // Changing the recipient breaks the key derivation.
        assert!(open(&bob_kem, &eve.aiwot(), &readdressed).is_err());
    }

    #[test]
    fn test_recipient_binding() {
        // A message Alice signcrypted to Bob, decrypted by Bob and
        // re-encrypted by him to Carol, is rejected by Carol.
        let alice = test_signing_key();
        let bob = test_signing_key();
        let carol = test_signing_key();
        let carol_kem = test_kem_key();

        let signed = SignedMessage::sign(&alice, &statement(&bob.aiwot(), "for Bob")).unwrap();
        let (kem, aead_key) =
            key::encapsulate(&carol_kem.public(), carol.aiwot().as_bytes()).unwrap();
        let ciphertext = ChaCha20Poly1305::new(&aead_key.into())
            .encrypt(&Default::default(), signed.to_markdown().as_bytes())
            .unwrap();
        let forwarded = format!(
            "# to\n{}\n# kem\n{}\n# ciphertext\n{}\n",
            carol.aiwot(),
            message::encode(&kem),
            message::encode(&ciphertext)
        );

        assert!(open(&carol_kem, &carol.aiwot(), &forwarded).is_err());
    }
}
