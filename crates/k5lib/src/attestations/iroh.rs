// Iroh attestations: where a k5 can be reached peer to peer.
//
// A k5 cannot be dialed by its id: the k5 is the fingerprint of an OpenPGP
// key, while an iroh endpoint is addressed by a plain Ed25519 public key. So
// each k5 has its own iroh key, and publishes its public key (the endpoint
// id) in a statement signed by the k5 key, with a detached OpenPGP signature:
//
// k5 iroh
// k5:<k5>
// endpoint:<endpoint id: 32 bytes, hex>
// date:<creation time, RFC 3339>
//
// The record is stored as `<k5>-iroh.md`, one per k5: it travels with the
// other attestations through export and merge, so the web of trust is how
// peers find each other, and a newer record replaces an older one (key
// rotation). As in `keysignparty`, the `# info` section is for humans only;
// the statement must be signed by the k5 it names.

use anyhow::{anyhow, Context as _};
use pgp::{
    composed::{Deserializable, DetachedSignature},
    crypto::hash::HashAlgorithm,
    types::Password,
};
use rand::rngs::OsRng;

use super::{me, Error, Profile};
use crate::{db::Db, k5id::K5Id, key::Keys, message::Keyring};

/// Type of iroh attestation records.
pub const RECORD_TYPE: &str = "iroh";

const STATEMENT_HEADER: &str = "k5 iroh";

/// A verified iroh attestation.
pub struct Iroh {
    pub k5: String,
    /// The iroh endpoint id (Ed25519 public key), 64 hex characters.
    pub endpoint: String,
    pub date: String,
}

impl Iroh {
    pub fn profile(&self) -> Profile {
        Profile {
            platform: RECORD_TYPE,
            user: self.endpoint.clone(),
            k5: self.k5.clone(),
        }
    }
}

/// Database entry name of the iroh attestation of `k5`.
pub fn name(k5: &str) -> String {
    format!("{k5}-{RECORD_TYPE}.md")
}

/// Creates a signed attestation that the k5 of `keys` is reachable at the
/// iroh `endpoint`, returning the record.
pub fn create(keys: &Keys, endpoint: &str) -> Result<String, Error> {
    let endpoint = parse_endpoint(endpoint)?;
    let k5 = keys.k5();
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let statement = statement(&k5, &endpoint, &date);
    let signature = DetachedSignature::sign_text_data(
        OsRng,
        &keys.secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha3_512,
        statement.as_bytes(),
    )?;
    let armored_signature = signature.to_armored_string(Default::default())?;

    let iroh = Iroh { k5, endpoint, date };
    Ok(format!(
        "# info\n\
         \n\
         - Type: {RECORD_TYPE}\n\
         - Fake: false\n\
         - Created: {date}\n\
         - Profile: {profile}\n\
         \n\
         # statement\n\
         {statement}\n\
         # signature\n\
         {armored_signature}",
        date = iroh.date,
        profile = iroh.profile(),
    ))
}

/// Verifies an iroh record, resolving the signer's public key from `keyring`
/// by the fingerprint carried in the signature. The signer must be the k5
/// the statement names.
pub fn verify(record: &str, keyring: &Keyring) -> Result<Iroh, Error> {
    let (_, rest) = record
        .split_once("\n# statement\n")
        .context("iroh record has no `# statement` section")?;
    let (statement, signature) = rest
        .rsplit_once("\n# signature\n")
        .context("iroh record has no `# signature` section")?;

    let (signature, _) = DetachedSignature::from_string(signature)?;
    let signer = signature
        .signature
        .issuer_fingerprint()
        .first()
        .context("signature has no issuer fingerprint")?
        .to_string();
    let signer_key = keyring
        .get(&signer)
        .with_context(|| format!("unknown signer k5:{signer}: fetch its self attestation first"))?;
    signature.verify(signer_key, statement.as_bytes())?;

    let iroh = parse_statement(statement)?;
    if iroh.k5 != signer {
        return Err(anyhow!(
            "iroh record of k5:{} signed by k5:{signer}",
            iroh.k5
        ));
    }

    Ok(iroh)
}

/// Makes sure `db` contains a valid iroh attestation of `keys` at `endpoint`,
/// creating it if missing or different. Returns where it was written, if it
/// was.
pub async fn ensure(db: &dyn Db, keys: &Keys, endpoint: &str) -> Result<Option<String>, Error> {
    let endpoint = parse_endpoint(endpoint)?;
    let k5 = keys.k5();
    let name = name(&k5);

    if let Some(record) = db.get(&name).await? {
        let keyring = Keyring::from([(k5.clone(), keys.public())]);
        if verify(&record, &keyring).is_ok_and(|iroh| iroh.endpoint == endpoint) {
            return Ok(None);
        }
    }

    let record = create(keys, &endpoint)?;
    db.put(&name, &record).await?;

    Ok(Some(db.location(&name)))
}

/// The iroh attestation of `k5` in `db`, verified against the self
/// attestation of `k5` in `db`. `None` if either is missing.
pub async fn lookup(db: &dyn Db, k5: &K5Id) -> Result<Option<Iroh>, Error> {
    let Some(record) = db.get(&name(k5)).await? else {
        return Ok(None);
    };
    let Some(me) = me::lookup(db, k5).await? else {
        return Ok(None);
    };

    let iroh = verify(&record, &Keyring::from([(me.k5, me.public)]))?;
    if iroh.k5 != k5.as_str() {
        return Err(anyhow!(
            "{} is the iroh attestation of k5:{}",
            name(k5),
            iroh.k5
        ));
    }

    Ok(Some(iroh))
}

/// Whether the iroh record `new` was created after `existing`, from their
/// `- Created:` fields. Used to replace a record on key rotation.
pub fn is_newer(new: &str, existing: &str) -> bool {
    let created = |record| {
        super::info_field(record, "- Created:")
            .and_then(|date| chrono::DateTime::parse_from_rfc3339(date).ok())
    };
    match (created(new), created(existing)) {
        (Some(new), Some(existing)) => new > existing,
        (Some(_), None) => true,
        _ => false,
    }
}

fn statement(k5: &str, endpoint: &str, date: &str) -> String {
    format!("{STATEMENT_HEADER}\nk5:{k5}\nendpoint:{endpoint}\ndate:{date}")
}

fn parse_statement(statement: &str) -> Result<Iroh, Error> {
    let mut lines = statement.split('\n');
    let mut field = |prefix: &str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(prefix))
            .ok_or_else(|| anyhow!("invalid iroh statement: expected `{prefix}`"))
    };

    field(STATEMENT_HEADER)?
        .is_empty()
        .then_some(())
        .context("invalid iroh statement header")?;
    let k5 = K5Id::parse_strict(field("k5:")?)?.into();
    let endpoint = parse_endpoint(field("endpoint:")?)?;
    let date = field("date:")?.to_string();
    chrono::DateTime::parse_from_rfc3339(&date)
        .map_err(|e| anyhow!("invalid iroh statement date `{date}`: {e}"))?;
    if lines.next().is_some() {
        return Err(anyhow!("invalid iroh statement: unexpected content"));
    }

    Ok(Iroh { k5, endpoint, date })
}

/// Parses an iroh endpoint id: 32 bytes, hex.
pub fn parse_endpoint(endpoint: &str) -> Result<String, Error> {
    parse_hex32(endpoint, "iroh endpoint id")
}

fn parse_hex32(value: &str, what: &str) -> Result<String, Error> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "invalid {what} `{value}`: expected 64 hex characters"
        ));
    }

    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    const ENDPOINT: &str = "4f1c0b7e2d9a6385c1e0f7a2b9d4c6e8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9";

    #[test]
    fn test_create_verify() {
        let keys = test_keys();
        let keyring = Keyring::from([(keys.k5(), keys.public())]);

        let record = create(&keys, &ENDPOINT.to_uppercase()).unwrap();
        assert!(record.starts_with("# info\n\n- Type: iroh\n- Fake: false\n"));

        let iroh = verify(&record, &keyring).unwrap();
        assert_eq!(iroh.k5, keys.k5());
        assert_eq!(iroh.endpoint, ENDPOINT);
        assert_eq!(
            iroh.profile().to_string(),
            format!("iroh/{ENDPOINT}/k5:{}", keys.k5())
        );

        // Changing the endpoint breaks the signature.
        let other = ENDPOINT.replace('4', "5");
        assert!(verify(&record.replace(ENDPOINT, &other), &keyring).is_err());

        // Unknown signer.
        assert!(verify(&record, &Keyring::new()).is_err());

        assert!(create(&keys, "not hex").is_err());
    }

    #[test]
    fn test_signed_by_another_k5() {
        // A statement naming k5 A, signed by B, is rejected.
        let (a, b) = (test_keys(), test_keys());
        let statement = statement(&a.k5(), ENDPOINT, "2026-01-01T00:00:00Z");
        let signature = DetachedSignature::sign_text_data(
            OsRng,
            &b.secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha3_512,
            statement.as_bytes(),
        )
        .unwrap()
        .to_armored_string(Default::default())
        .unwrap();
        let record = format!("# info\n\n# statement\n{statement}\n# signature\n{signature}");

        let keyring = Keyring::from([(b.k5(), b.public())]);
        let err = verify(&record, &keyring).err().unwrap().to_string();
        assert!(err.contains("signed by"), "{err}");
    }

    #[test]
    fn test_is_newer() {
        let older = "# info\n\n- Created: 2026-01-01T00:00:00Z\n";
        let newer = "# info\n\n- Created: 2026-02-01T00:00:00Z\n";
        assert!(is_newer(newer, older));
        assert!(!is_newer(older, newer));
        assert!(!is_newer(older, older));
    }
}
