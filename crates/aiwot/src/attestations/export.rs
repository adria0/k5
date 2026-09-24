// Export of the attestations in [`DIR`] as a signed message.
//
// The message is a bundle with each record encoded as base58:
//
// aiwot export
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
// trusted aiwots are the local one and all those reachable from it. First, the
// key sign party attestations whose signer is trusted are merged; then, the
// other attestations about trusted aiwots. The rest are reported as untrusted.

use std::collections::{HashMap, HashSet};

use super::{check, keysignparty, Error, ProfileAttestation, DIR};
use crate::{
    key::SigningKey,
    message::{self, SignedMessage},
};

const HEADER: &str = "aiwot export";
const ATTESTATION_PREFIX: &str = "attestation:";

/// An attestation record in an export.
pub struct Exported {
    pub file: String,
    pub record: String,
}

type VerifiedExport = (Exported, Result<ProfileAttestation, String>);

/// Creates a signed export of the valid attestations in [`DIR`], returning
/// the signed message markdown and the number of exported attestations.
/// Invalid records are reported and skipped.
pub async fn create(key: &SigningKey, notary_key: &str) -> Result<(String, usize), Error> {
    let mut exported = Vec::new();
    for checked in check(None, notary_key).await? {
        match checked.result {
            Ok(_) => exported.push(Exported {
                record: tokio::fs::read_to_string(format!("{DIR}/{}", checked.file)).await?,
                file: checked.file,
            }),
            Err(e) => eprintln!(
                "Not exporting invalid attestation {DIR}/{}: {e}",
                checked.file
            ),
        }
    }

    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let signed = SignedMessage::sign(key, &bundle(&date, &exported))?;

    Ok((signed.to_markdown(), exported.len()))
}

/// Returns whether a signed message is an export.
pub fn is_export(msg: &str) -> bool {
    msg.starts_with(&format!("{HEADER}\n"))
}

/// Verifies each attestation of an export, as [`check`] does for the files
/// in [`DIR`].
pub fn verify(msg: &str, notary_key: &str) -> Result<Vec<super::Checked>, Error> {
    Ok(verify_all(msg, notary_key)?
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
    /// or to the aiwot of any other attestation.
    Untrusted(ProfileAttestation),
    Invalid(String),
}

/// The merge of an attestation of an export.
pub struct Merged {
    pub file: String,
    pub outcome: Outcome,
}

/// Merges into [`DIR`] the valid attestations of a signed export that are on
/// a trust path from `me`: first the key sign party attestations, then the
/// others. Returns the signer and what happened to each attestation. Fails
/// without merging anything if the signature is invalid or the message is not
/// an export.
pub async fn merge(
    markdown: &str,
    me: &str,
    notary_key: &str,
    force: bool,
) -> Result<(String, Vec<Merged>), Error> {
    let signed = SignedMessage::parse(markdown)?;
    signed.verify()?;
    if !is_export(&signed.msg) {
        return Err("not an export: the signed message is not an attestation bundle".into());
    }

    let local: Vec<ProfileAttestation> = check(None, notary_key)
        .await?
        .into_iter()
        .filter_map(|checked| checked.result.ok())
        .collect();
    let mut candidates = verify_all(&signed.msg, notary_key)?;

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
                store(&exported, attestation, force).await?
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

/// Returns the aiwots reachable from `me` through the key sign party
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
                .push(attestation.profile.aiwot.as_str());
        }
    }

    let me = me.to_ascii_lowercase();
    let mut trusted = HashSet::from([me.clone()]);
    let mut pending = vec![me];
    while let Some(aiwot) = pending.pop() {
        for subject in edges.get(aiwot.as_str()).into_iter().flatten() {
            if trusted.insert(subject.to_string()) {
                pending.push(subject.to_string());
            }
        }
    }

    trusted
}

/// A key sign party attestation is trusted if its signer is; any other
/// attestation if the aiwot it is about is.
fn is_trusted(attestation: &ProfileAttestation, trusted: &HashSet<String>) -> bool {
    if is_keysign(attestation) {
        attestation
            .signer
            .as_ref()
            .is_some_and(|signer| trusted.contains(signer))
    } else {
        trusted.contains(&attestation.profile.aiwot)
    }
}

/// Stores a verified attestation, unless a different record with the same
/// name exists and `force` is not set.
async fn store(
    exported: &Exported,
    attestation: ProfileAttestation,
    force: bool,
) -> Result<Outcome, Error> {
    let path = format!("{DIR}/{}", exported.file);

    let replaced = match tokio::fs::read_to_string(&path).await {
        Ok(existing) if existing == exported.record => return Ok(Outcome::Unchanged(attestation)),
        Ok(_) if !force => return Ok(Outcome::Conflict(attestation)),
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };

    tokio::fs::create_dir_all(DIR).await?;
    tokio::fs::write(&path, &exported.record).await?;

    Ok(if replaced {
        Outcome::Replaced(attestation)
    } else {
        Outcome::Added(attestation)
    })
}

/// Verifies each attestation of an export.
fn verify_all(msg: &str, notary_key: &str) -> Result<Vec<VerifiedExport>, Error> {
    Ok(parse(msg)?
        .into_iter()
        .map(|exported| {
            let result = verify_one(&exported, notary_key).map_err(|e| e.to_string());
            (exported, result)
        })
        .collect())
}

fn verify_one(exported: &Exported, notary_key: &str) -> Result<ProfileAttestation, Error> {
    check_safe_file_name(&exported.file)?;

    let attestation =
        super::verify(&exported.record, notary_key)?.attestation(exported.file.clone())?;
    super::check_file_name(&exported.file, &attestation)?;

    Ok(attestation)
}

/// File names come from the export, so they must not escape [`DIR`].
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
            message::encode(exported.record.as_bytes())
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
    let record = String::from_utf8(message::decode(&file, &encoded)?)
        .map_err(|_| format!("attestation {file} is not valid UTF-8"))?;

    Ok(Exported { file, record })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{attestations::keysignparty, key::test_signing_key};

    #[test]
    fn test_bundle_round_trip() {
        let signer = test_signing_key();
        let subject = test_signing_key().aiwot();
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

        let checked = verify(&msg, "").unwrap();
        assert_eq!(
            checked[0].result.as_ref().unwrap().to_string(),
            format!("keysignparty:Alice (signed by aiwot:{})", signer.aiwot())
        );
        assert!(checked[1].result.is_err());

        // A wrong count is detected.
        assert!(parse(&msg.replace("count:2", "count:3")).is_err());
    }

    #[test]
    fn test_web_of_trust() {
        use crate::{
            attestations::{me, Attested},
            key::test_kem_key,
        };

        let [me_key, bob, carol, dave, eve, frank] = std::array::from_fn(|_| test_signing_key());
        let keysign = |signer: &crate::key::SigningKey, subject: &crate::key::SigningKey| {
            let (file, record) =
                keysignparty::create(signer, &subject.aiwot(), "x", false).unwrap();
            Attested::KeySign(keysignparty::verify(&record).unwrap())
                .attestation(file)
                .unwrap()
        };
        let me_attestation = |key: &crate::key::SigningKey| {
            let record = me::create(key, &test_kem_key(), false).unwrap();
            Attested::Me(me::verify(&record).unwrap())
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

        let trusted = trusted(&me_key.aiwot(), local.iter().chain(exported.iter()));
        let expected: HashSet<String> = [&me_key, &bob, &carol, &dave]
            .iter()
            .map(|key| key.aiwot())
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
        let signer = test_signing_key();
        let subject = test_signing_key().aiwot();
        let (file, record) = keysignparty::create(&signer, &subject, "Alice", false).unwrap();
        let exported = Exported {
            file: format!("{subject}-../../{file}"),
            record,
        };
        assert!(verify_one(&exported, "").is_err());
    }
}
