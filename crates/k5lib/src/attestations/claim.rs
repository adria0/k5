// Name claims: the name a k5 gives itself, in a statement signed by that
// k5, with a detached OpenPGP signature:
//
// k5 name
// k5:<k5>
// name:<name>
// date:<creation time, RFC 3339>
//
// Unlike a keysign (someone else vouching for a name), a claim is only what
// the k5 says about itself. The record is stored as `<k5>-name.md`, one per
// k5: it travels with the other attestations through export and merge, and a
// newer claim replaces an older one (a rename). As in `iroh`, the `# info`
// section is for humans only; the statement must be signed by the k5 it
// names.

use anyhow::anyhow;
use pgp::{composed::DetachedSignature, crypto::hash::HashAlgorithm, types::Password};
use rand::rngs::OsRng;

use super::{keysignparty::check_name, me, signed_statement, Error, Profile};
use crate::{db::Db, k5id::K5Id, key::Keys, message::Keyring};

/// Type of name claim records.
pub const RECORD_TYPE: &str = "name";

const STATEMENT_HEADER: &str = "k5 name";

/// Longest name, in characters.
const MAX_NAME: usize = 64;

/// A verified name claim.
pub struct Claim {
    pub k5: String,
    pub name: String,
    pub date: String,
}

impl Claim {
    pub fn profile(&self) -> Profile {
        Profile {
            platform: RECORD_TYPE,
            user: self.name.clone(),
            k5: self.k5.clone(),
        }
    }
}

/// Database entry name of the name claim of `k5`.
pub fn file_name(k5: &str) -> String {
    format!("{k5}-{RECORD_TYPE}.md")
}

/// Creates a signed claim that the k5 of `keys` is called `name`, returning
/// the record.
pub fn create(keys: &Keys, name: &str) -> Result<String, Error> {
    check(name)?;
    let k5 = keys.k5();
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let statement = statement(&k5, name, &date);
    let signature = DetachedSignature::sign_text_data(
        OsRng,
        &keys.secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha3_512,
        statement.as_bytes(),
    )?;
    let armored_signature = signature.to_armored_string(Default::default())?;

    let claim = Claim {
        k5,
        name: name.to_string(),
        date,
    };
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
        date = claim.date,
        profile = claim.profile(),
    ))
}

/// Verifies a name claim, resolving the signer's public key from `keyring`
/// by the fingerprint carried in the signature. The signer must be the k5
/// the statement names.
pub fn verify(record: &str, keyring: &Keyring) -> Result<Claim, Error> {
    let (statement, signer) = signed_statement(record, keyring, RECORD_TYPE)?;
    let claim = parse_statement(statement)?;
    if claim.k5 != signer {
        return Err(anyhow!(
            "name claim of k5:{} signed by k5:{signer}",
            claim.k5
        ));
    }

    Ok(claim)
}

/// Claims `name` for the k5 of `keys` in `db`, replacing its previous claim.
/// Returns where it was stored.
pub async fn set(db: &dyn Db, keys: &Keys, name: &str) -> Result<String, Error> {
    let record = create(keys, name)?;
    // Check the record before storing it.
    verify(&record, &Keyring::from([(keys.k5(), keys.public())]))?;

    let file = file_name(&keys.k5());
    db.put(&file, &record).await?;

    Ok(db.location(&file))
}

/// The name claim of `k5` in `db`, verified against the self attestation of
/// `k5` in `db`. `None` if either is missing.
pub async fn lookup(db: &dyn Db, k5: &K5Id) -> Result<Option<Claim>, Error> {
    let Some(record) = db.get(&file_name(k5)).await? else {
        return Ok(None);
    };
    let Some(me) = me::lookup(db, k5).await? else {
        return Ok(None);
    };

    let claim = verify(&record, &Keyring::from([(me.k5, me.public)]))?;
    if claim.k5 != k5.as_str() {
        return Err(anyhow!(
            "{} is the name claim of k5:{}",
            file_name(k5),
            claim.k5
        ));
    }

    Ok(Some(claim))
}

/// A name must be trimmed, not empty, without control characters and at
/// most [`MAX_NAME`] characters.
fn check(name: &str) -> Result<(), Error> {
    check_name(name)?;
    if name.chars().count() > MAX_NAME {
        return Err(anyhow!("name longer than {MAX_NAME} characters"));
    }

    Ok(())
}

fn statement(k5: &str, name: &str, date: &str) -> String {
    format!("{STATEMENT_HEADER}\nk5:{k5}\nname:{name}\ndate:{date}")
}

fn parse_statement(statement: &str) -> Result<Claim, Error> {
    let mut lines = statement.split('\n');
    let mut field = |prefix: &str| {
        lines
            .next()
            .and_then(|line| line.strip_prefix(prefix))
            .ok_or_else(|| anyhow!("invalid name statement: expected `{prefix}`"))
    };

    if !field(STATEMENT_HEADER)?.is_empty() {
        return Err(anyhow!("invalid name statement header"));
    }
    let k5 = K5Id::parse_strict(field("k5:")?)?.into();
    let name = field("name:")?.to_string();
    check(&name)?;
    let date = field("date:")?.to_string();
    chrono::DateTime::parse_from_rfc3339(&date)
        .map_err(|e| anyhow!("invalid name statement date `{date}`: {e}"))?;
    if lines.next().is_some() {
        return Err(anyhow!("invalid name statement: unexpected content"));
    }

    Ok(Claim { k5, name, date })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db::FsDb, key::test_keys};

    #[test]
    fn test_create_verify() {
        let keys = test_keys();
        let keyring = Keyring::from([(keys.k5(), keys.public())]);

        let record = create(&keys, "Adrià Massanet").unwrap();
        assert!(record.starts_with("# info\n\n- Type: name\n- Fake: false\n"));

        let claim = verify(&record, &keyring).unwrap();
        assert_eq!(
            (claim.k5.as_str(), claim.name.as_str()),
            (keys.k5().as_str(), "Adrià Massanet")
        );
        assert_eq!(
            claim.profile().to_string(),
            format!("name/Adrià Massanet/k5:{}", keys.k5())
        );

        // Changing the name breaks the signature.
        assert!(verify(&record.replace("name:Adrià", "name:Eve"), &keyring).is_err());
        // Unknown signer.
        assert!(verify(&record, &Keyring::new()).is_err());

        for name in ["", " padded", "line\nbreak", &"x".repeat(MAX_NAME + 1)] {
            assert!(create(&keys, name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn test_signed_by_another_k5() {
        // A claim naming k5 A, signed by B, is rejected.
        let (a, b) = (test_keys(), test_keys());
        let statement = statement(&a.k5(), "Alice", "2026-01-01T00:00:00Z");
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

    #[tokio::test]
    async fn test_set_lookup() {
        let dir = std::env::temp_dir().join(format!("k5-claim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = FsDb::new(&dir);
        let keys = test_keys();
        let k5 = K5Id::parse(&keys.k5()).unwrap();
        me::ensure(&db, &keys).await.unwrap();

        assert!(lookup(&db, &k5).await.unwrap().is_none());
        set(&db, &keys, "Alice").await.unwrap();
        assert_eq!(lookup(&db, &k5).await.unwrap().unwrap().name, "Alice");
        // A rename replaces it.
        set(&db, &keys, "Alice B.").await.unwrap();
        assert_eq!(lookup(&db, &k5).await.unwrap().unwrap().name, "Alice B.");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
