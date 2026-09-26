// Export of the attestations of a database as a signed message.
//
// The message is a bundle with each record encoded as base58:
//
// k5 export
// date:<creation time, RFC 3339>
// count:<number of attestations>
// attestation:<file name>
// <base58 of the record, 100 characters per line>
// ...
//
// and is signed like any other message, so the export can be checked with
// `msg verify`, which also verifies each bundled attestation, and merged with
// `attest merge`.
//
// Merging follows the web of trust. Key sign party attestations are edges
// `signer -> subject`, from the local attestations and the export; the
// trusted k5s are the local one and all those reachable from it. First, the
// key sign party attestations whose signer is trusted are merged; then, the
// other attestations about trusted k5s. The rest are reported as untrusted.

use std::collections::{HashMap, HashSet};

use super::{check, iroh, keyring, keysignparty, Error, Invalid, ProfileAttestation};
use crate::{
    db::Db,
    key::Keys,
    message::{self, Keyring},
};

const HEADER: &str = "k5 export";
const ATTESTATION_PREFIX: &str = "attestation:";
/// Maximum length of the base58 lines.
const LINE_WIDTH: usize = 100;

/// An attestation record in an export.
pub struct Exported {
    pub file: String,
    pub record: String,
}

type VerifiedExport = (Exported, Result<ProfileAttestation, String>);

/// A signed export.
pub struct Export {
    /// The signed message markdown.
    pub markdown: String,
    /// Number of exported attestations.
    pub count: usize,
    /// Invalid records in the database, not exported.
    pub skipped: Vec<Invalid>,
}

/// Creates a signed export of the valid attestations in `db`. Invalid
/// records are skipped.
pub async fn create(db: &dyn Db, keys: &Keys, notary_key: &str) -> Result<Export, Error> {
    let mut exported = Vec::new();
    let mut skipped = Vec::new();
    // Bound first: a temporary of the `for` expression would live across the
    // loop's awaits, making the future not `Send`.
    let checked = check(db, None, notary_key).await?;
    for checked in checked {
        match checked.result {
            Ok(_) => exported.push(Exported {
                record: db
                    .get(&checked.file)
                    .await?
                    .ok_or_else(|| format!("{} was removed while exporting", checked.file))?,
                file: checked.file,
            }),
            Err(error) => skipped.push(Invalid {
                file: checked.file,
                error,
            }),
        }
    }

    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let markdown = message::sign(&keys.secret, &bundle(&date, &exported))?;

    Ok(Export {
        markdown,
        count: exported.len(),
        skipped,
    })
}

/// Returns whether a signed message is an export.
pub fn is_export(msg: &str) -> bool {
    msg.starts_with(&format!("{HEADER}\n"))
}

/// Verifies each attestation of an export, as [`check`] does for the entries
/// of `db`, whose self attestations make the keyring.
pub async fn verify(
    db: &dyn Db,
    msg: &str,
    notary_key: &str,
) -> Result<Vec<super::Checked>, Error> {
    let keyring = keyring(db).await?;

    Ok(verify_all(msg, notary_key, &keyring)?
        .into_iter()
        .map(|(exported, result)| super::Checked {
            file: exported.file,
            result,
        })
        .collect())
}

/// What happened to an attestation of an export on merge.
pub enum Outcome {
    Added(ProfileAttestation),
    /// Replaced a different existing record (`force`).
    Replaced(ProfileAttestation),
    /// An identical record already exists.
    Unchanged(ProfileAttestation),
    /// A different record with the same name exists, and `force` is not set.
    Conflict(ProfileAttestation),
    /// There is no trust path to the signer of a key sign party attestation,
    /// or to the k5 of any other attestation.
    Untrusted(ProfileAttestation),
    Invalid(String),
}

/// The merge of an attestation of an export.
pub struct Merged {
    pub file: String,
    pub outcome: Outcome,
}

/// Merges into `db` the valid attestations of a signed export that are on
/// a trust path from `me`: first the key sign party attestations, then the
/// others. Returns the signer and what happened to each attestation. Fails
/// without merging anything if the signature is invalid or the message is not
/// an export.
pub async fn merge(
    db: &dyn Db,
    markdown: &str,
    me: &str,
    notary_key: &str,
    force: bool,
) -> Result<(String, Vec<Merged>), Error> {
    let keyring = keyring(db).await?;
    let signed = message::verify(markdown, &keyring)?;
    if !is_export(&signed.msg) {
        return Err("not an export: the signed message is not an attestation bundle".into());
    }

    let local: Vec<ProfileAttestation> = check(db, None, notary_key)
        .await?
        .into_iter()
        .filter_map(|checked| checked.result.ok())
        .collect();
    let mut candidates = verify_all(&signed.msg, notary_key, &keyring)?;

    let trusted = trusted(
        me,
        local.iter().chain(
            candidates
                .iter()
                .filter_map(|(_, result)| result.as_ref().ok()),
        ),
    );

    // Key sign party attestations first, then the others.
    candidates.sort_by_key(|(_, result)| !result.as_ref().is_ok_and(is_keysign));

    let mut merged = Vec::new();
    for (exported, result) in candidates {
        let outcome = match result {
            Ok(attestation) if is_trusted(&attestation, &trusted) => {
                store(db, &exported, attestation, force).await?
            }
            Ok(attestation) => Outcome::Untrusted(attestation),
            Err(e) => Outcome::Invalid(e),
        };
        merged.push(Merged {
            file: exported.file,
            outcome,
        });
    }

    Ok((signed.from, merged))
}

pub fn is_keysign(attestation: &ProfileAttestation) -> bool {
    attestation.profile.platform == keysignparty::RECORD_TYPE
}

/// Returns the k5s reachable from `me` through the key sign party
/// attestations, `me` included.
pub fn trusted<'a>(
    me: &str,
    attestations: impl Iterator<Item = &'a ProfileAttestation>,
) -> HashSet<String> {
    let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
    for attestation in attestations.filter(|attestation| is_keysign(attestation)) {
        if let Some(signer) = &attestation.signer {
            edges
                .entry(signer.as_str())
                .or_default()
                .push(attestation.profile.k5.as_str());
        }
    }

    let me = me.to_ascii_lowercase();
    let mut trusted = HashSet::from([me.clone()]);
    let mut pending = vec![me];
    while let Some(k5) = pending.pop() {
        for subject in edges.get(k5.as_str()).into_iter().flatten() {
            if trusted.insert(subject.to_string()) {
                pending.push(subject.to_string());
            }
        }
    }

    trusted
}

/// A key sign party attestation is trusted if its signer is; any other
/// attestation if the k5 it is about is.
fn is_trusted(attestation: &ProfileAttestation, trusted: &HashSet<String>) -> bool {
    if is_keysign(attestation) {
        attestation
            .signer
            .as_ref()
            .is_some_and(|signer| trusted.contains(signer))
    } else {
        trusted.contains(&attestation.profile.k5)
    }
}

/// Stores a verified attestation, unless a different record with the same
/// name exists and `force` is not set.
async fn store(
    db: &dyn Db,
    exported: &Exported,
    attestation: ProfileAttestation,
    force: bool,
) -> Result<Outcome, Error> {
    let replaced = match db.get(&exported.file).await? {
        Some(existing) if existing == exported.record => {
            return Ok(Outcome::Unchanged(attestation))
        }
        // A newer iroh record replaces the older one: its k5 rotated its
        // iroh key.
        Some(existing)
            if attestation.profile.platform == iroh::RECORD_TYPE
                && iroh::is_newer(&exported.record, &existing) =>
        {
            true
        }
        Some(_) if !force => return Ok(Outcome::Conflict(attestation)),
        Some(_) => true,
        None => false,
    };

    db.put(&exported.file, &exported.record).await?;

    Ok(if replaced {
        Outcome::Replaced(attestation)
    } else {
        Outcome::Added(attestation)
    })
}

/// Verifies each attestation of an export.
fn verify_all(
    msg: &str,
    notary_key: &str,
    keyring: &Keyring,
) -> Result<Vec<VerifiedExport>, Error> {
    Ok(parse(msg)?
        .into_iter()
        .map(|exported| {
            let result = verify_one(&exported, notary_key, keyring).map_err(|e| e.to_string());
            (exported, result)
        })
        .collect())
}

fn verify_one(
    exported: &Exported,
    notary_key: &str,
    keyring: &Keyring,
) -> Result<ProfileAttestation, Error> {
    check_safe_file_name(&exported.file)?;

    let attestation =
        super::verify(&exported.record, notary_key, keyring)?.attestation(exported.file.clone())?;
    super::check_file_name(&exported.file, &attestation)?;

    Ok(attestation)
}

/// File names come from the export, so they must be safe entry names for
/// any database (no path separators, nothing hidden).
fn check_safe_file_name(file: &str) -> Result<(), Error> {
    if file.is_empty()
        || file.starts_with('.')
        || file.contains(['/', '\\'])
        || file.contains("..")
        || file.chars().any(char::is_control)
        || !file.ends_with(".md")
    {
        return Err(format!("unsafe file name `{file}`").into());
    }

    Ok(())
}

fn bundle(date: &str, exported: &[Exported]) -> String {
    let mut bundle = format!("{HEADER}\ndate:{date}\ncount:{}", exported.len());
    for exported in exported {
        bundle.push_str(&format!(
            "\n{ATTESTATION_PREFIX}{}\n{}",
            exported.file,
            encode(exported.record.as_bytes())
        ));
    }

    bundle
}

fn parse(msg: &str) -> Result<Vec<Exported>, Error> {
    let mut lines = msg.split('\n');
    if lines.next() != Some(HEADER) {
        return Err("not an export: missing header".into());
    }
    lines
        .next()
        .and_then(|line| line.strip_prefix("date:"))
        .ok_or("invalid export: expected `date:`")?;
    let count: usize = lines
        .next()
        .and_then(|line| line.strip_prefix("count:"))
        .ok_or("invalid export: expected `count:`")?
        .parse()?;

    let mut exported = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in lines {
        if let Some(file) = line.strip_prefix(ATTESTATION_PREFIX) {
            exported.extend(current.take().map(decode).transpose()?);
            current = Some((file.to_string(), String::new()));
        } else {
            let (_, encoded) = current
                .as_mut()
                .ok_or("invalid export: data before the first attestation")?;
            encoded.push_str(line);
        }
    }
    exported.extend(current.map(decode).transpose()?);

    if exported.len() != count {
        return Err(format!(
            "invalid export: expected {count} attestations, found {}",
            exported.len()
        )
        .into());
    }

    Ok(exported)
}

fn decode((file, encoded): (String, String)) -> Result<Exported, Error> {
    let record = String::from_utf8(
        bs58::decode(&encoded)
            .into_vec()
            .map_err(|e| format!("invalid base58 in attestation {file}: {e}"))?,
    )
    .map_err(|_| format!("attestation {file} is not valid UTF-8"))?;

    Ok(Exported { file, record })
}

/// Encodes as base58 in lines of at most [`LINE_WIDTH`] characters.
fn encode(data: &[u8]) -> String {
    let encoded = bs58::encode(data).into_string();

    encoded
        .as_bytes()
        .chunks(LINE_WIDTH)
        .map(|line| std::str::from_utf8(line).expect("base58 is ascii"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{attestations::keysignparty, key::test_keys};

    #[tokio::test]
    async fn test_bundle_round_trip() {
        let signer = test_keys();
        let subject = test_keys().k5();
        let keyring = Keyring::from([(signer.k5(), signer.public())]);
        let (file, record) = keysignparty::create(&signer, &subject, "Alice", false).unwrap();

        let exported = vec![
            Exported {
                file: file.clone(),
                record: record.clone(),
            },
            Exported {
                file: "junk.md".to_string(),
                record: "junk".to_string(),
            },
        ];
        let msg = bundle("now", &exported);
        assert!(is_export(&msg));
        // The base58 lines are at most 100 characters.
        assert!(msg
            .lines()
            .filter(|line| !line.starts_with(ATTESTATION_PREFIX))
            .all(|line| line.len() <= 100));

        let parsed = parse(&msg).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].file, file);
        assert_eq!(parsed[0].record, record);

        let checked = verify_all(&msg, "", &keyring).unwrap();
        assert_eq!(
            checked[0].1.as_ref().unwrap().to_string(),
            format!("keysignparty:Alice (signed by k5:{})", signer.k5())
        );
        assert!(checked[1].1.is_err());

        // A wrong count is detected.
        assert!(parse(&msg.replace("count:2", "count:3")).is_err());
    }

    #[test]
    fn test_web_of_trust() {
        use crate::attestations::{me, Attested};

        let [me_key, bob, carol, dave, eve, frank] = std::array::from_fn(|_| test_keys());
        let keysign = |signer: &Keys, subject: &Keys| {
            let (file, record) = keysignparty::create(signer, &subject.k5(), "x", false).unwrap();
            let keyring = Keyring::from([(signer.k5(), signer.public())]);
            Attested::KeySign(keysignparty::verify(&record, &keyring).unwrap())
                .attestation(file)
                .unwrap()
        };
        let me_attestation = |key: &Keys| {
            let record = me::create(key, false).unwrap();
            Attested::Me(Box::new(me::verify(&record).unwrap()))
                .attestation(String::new())
                .unwrap()
        };

        // Local: I signed Bob. Export: Bob signed Carol, Carol signed Dave,
        // Eve signed Frank, and the self attestations of Dave and Frank.
        let local = [keysign(&me_key, &bob)];
        let exported = [
            keysign(&carol, &dave),
            keysign(&bob, &carol),
            keysign(&eve, &frank),
            me_attestation(&dave),
            me_attestation(&frank),
        ];

        let trusted = trusted(&me_key.k5(), local.iter().chain(exported.iter()));
        let expected: HashSet<String> = [&me_key, &bob, &carol, &dave]
            .iter()
            .map(|key| key.k5())
            .collect();
        assert_eq!(trusted, expected);

        let decisions: Vec<bool> = exported
            .iter()
            .map(|attestation| is_trusted(attestation, &trusted))
            .collect();
        // Carol->Dave and Bob->Carol are on the path from me, Eve->Frank is
        // not; Dave is trusted, Frank is not.
        assert_eq!(decisions, [true, true, false, true, false]);
    }

    #[test]
    fn test_unsafe_file_names() {
        for file in [
            "../x.md",
            "a/b.md",
            "a\\b.md",
            ".hidden.md",
            "",
            "x.txt",
            "x..md",
        ] {
            assert!(check_safe_file_name(file).is_err(), "{file}");
        }
        assert!(check_safe_file_name(&format!("{}-self_attestation.md", "ab".repeat(32))).is_ok());

        // A valid record under a path escaping the directory is rejected.
        let signer = test_keys();
        let subject = test_keys().k5();
        let (file, record) = keysignparty::create(&signer, &subject, "Alice", false).unwrap();
        let exported = Exported {
            file: format!("{subject}-../../{file}"),
            record,
        };
        let keyring = Keyring::from([(signer.k5(), signer.public())]);
        assert!(verify_one(&exported, "", &keyring).is_err());
    }
}
