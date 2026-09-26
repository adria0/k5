// Email attestations: a zero-knowledge proof (Plonky2, `plonky2_zkemail`)
// that an email was DKIM-signed by the domain of its sender, whose subject
// contains a k5. It proves the owner of the address put the k5 there, as a
// tweet or a gist does for X and GitHub.
//
// The email is one its owner sends to themselves, with `k5:<k5>` in the
// subject. Its signed header is public in the record (only the headers of
// the DKIM `h=` list, then the DKIM signature header without its
// signature); its body is not included, nor proven. The record holds:
//
// # info           for humans only
// # dkim           the DKIM key record (`v=DKIM1; k=rsa; p=...`)
// # header         the signed header, base64
// # proof          the proof, base64
//
// Verifying it checks the proof against the key and the header, then reads
// the header: the DKIM domain and selector come from its (signed) DKIM
// signature header, there must be exactly one `From` (the address, whose
// domain must be the DKIM domain or a subdomain of it) and one `Subject`,
// with the k5.
//
// The key is trusted as published in DNS when the attestation was made (see
// `k5net::dkim_key`): a verifier can look it up again.

use anyhow::{anyhow, bail, Context as _};
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2_zkemail::eml::{self, TrustedKey};

use super::{tlsnotary::plugins::find_k5, Error, Profile};
use crate::k5id::K5Id;

pub use plonky2_zkemail::eml::dkim_selector;

/// Type of email attestation records.
pub const RECORD_TYPE: &str = "zkemail";
/// Platform of the profiles they prove.
pub const PLATFORM: &str = "email";

/// Width of the base64 lines of a record.
const LINE_WIDTH: usize = 100;

/// A verified email attestation.
pub struct Email {
    /// The sender's address, lowercase.
    pub address: String,
    pub k5: String,
    /// The DKIM domain and selector of the key that signed it.
    pub domain: String,
    pub selector: String,
    /// When the attestation was made (its `# info`), if given.
    pub created: String,
}

impl Email {
    pub fn profile(&self) -> Profile {
        Profile {
            platform: PLATFORM,
            user: self.address.clone(),
            k5: self.k5.clone(),
        }
    }
}

/// Proves the raw email `eml` signed by `key` (minutes of CPU: run it off
/// async threads) and returns the attestation's file name and record.
pub fn create(eml: &[u8], key: &TrustedKey) -> Result<(String, String), Error> {
    let proven = eml::prove_header(eml, key)?;
    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let identity = identity(&proven.header)?;

    let record = format!(
        "# info\n\
         \n\
         - Type: {RECORD_TYPE}\n\
         - Fake: false\n\
         - Created: {created}\n\
         - Profile: {PLATFORM}/{address}/k5:{k5}\n\
         - DKIM: d={domain} s={selector}\n\
         \n\
         # dkim\n\
         {dkim}\n\
         # header\n\
         {header}\n\
         # proof\n\
         {proof}\n",
        address = identity.address,
        k5 = identity.k5,
        domain = identity.domain,
        selector = identity.selector,
        dkim = key.record,
        header = wrap(&STANDARD.encode(&proven.header)),
        proof = wrap(&STANDARD.encode(&proven.proof)),
    );
    // Check the record before handing it out.
    let email = verify(&record)?;
    let file = format!("{}-{PLATFORM}-{}.md", email.k5, email.address).replace(['/', '\\'], "_");

    Ok((file, record))
}

/// Verifies an email attestation record.
pub fn verify(record: &str) -> Result<Email, Error> {
    let section = |name: &str, next: Option<&str>| -> Result<String, Error> {
        let (_, rest) = record
            .split_once(&format!("\n# {name}\n"))
            .with_context(|| format!("zkemail record has no `# {name}` section"))?;
        let body = match next {
            Some(next) => {
                rest.split_once(&format!("\n# {next}\n"))
                    .with_context(|| format!("zkemail record has no `# {next}` section"))?
                    .0
            }
            None => rest,
        };
        Ok(body.trim().to_string())
    };
    let dkim = section("dkim", Some("header"))?;
    let header = STANDARD
        .decode(section("header", Some("proof"))?.replace('\n', ""))
        .context("invalid zkemail header encoding")?;
    let proof = STANDARD
        .decode(section("proof", None)?.replace('\n', ""))
        .context("invalid zkemail proof encoding")?;

    let mut email = identity(&header)?;
    let key = TrustedKey {
        domain: email.domain.clone(),
        selector: email.selector.clone(),
        record: dkim,
    };
    eml::verify_header(&header, &proof, &key)?;
    email.created = super::info_field(record, "- Created:")
        .unwrap_or_default()
        .to_string();

    Ok(email)
}

/// Who a signed header proves: the sender's address and the k5 of the
/// subject, and the DKIM domain and selector of its signature.
fn identity(header: &[u8]) -> Result<Email, Error> {
    let header = std::str::from_utf8(header).context("the signed header is not UTF-8")?;
    // Relaxed canonicalization: lowercase names, `name:value` lines.
    let lines: Vec<(&str, &str)> = header
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .collect();
    let only = |name: &str| -> Result<&str, Error> {
        let mut values = lines.iter().filter(|(n, _)| *n == name).map(|(_, v)| *v);
        match (values.next(), values.next()) {
            (Some(value), None) => Ok(value),
            (None, _) => Err(anyhow!("the signed header has no {name}")),
            (Some(_), Some(_)) => Err(anyhow!("the signed header has several {name}")),
        }
    };

    let (domain, selector) = dkim_tags(only("dkim-signature")?)?;
    let address = address(only("from")?)?;
    let (_, address_domain) = address.rsplit_once('@').context("invalid address")?;
    if address_domain != domain && !address_domain.ends_with(&format!(".{domain}")) {
        bail!("{address} is not of the signing domain {domain}");
    }
    let k5 = find_k5(only("subject")?).context("the subject has no `k5:`")?;
    let k5 = String::from(K5Id::parse_strict(k5)?);

    Ok(Email {
        address,
        k5,
        domain,
        selector,
        created: String::new(),
    })
}

/// The `d=` and `s=` of a DKIM signature header's value, lowercase.
fn dkim_tags(value: &str) -> Result<(String, String), Error> {
    let tag = |name: &str| {
        value
            .split(';')
            .filter_map(|tag| tag.split_once('='))
            .find(|(key, _)| key.trim() == name)
            .map(|(_, value)| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .with_context(|| format!("the DKIM signature has no {name}="))
    };

    Ok((tag("d")?, tag("s")?))
}

/// The address of a `From` value (`Name <address>` or `address`),
/// lowercase.
fn address(from: &str) -> Result<String, Error> {
    let address = match (from.rfind('<'), from.rfind('>')) {
        (Some(start), Some(end)) if start < end => &from[start + 1..end],
        _ => from,
    }
    .trim()
    .to_ascii_lowercase();
    match address.split_once('@') {
        Some((local, domain))
            if !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !address.contains(char::is_whitespace) =>
        {
            Ok(address)
        }
        _ => Err(anyhow!("invalid sender address `{address}`")),
    }
}

/// `text` in lines of [`LINE_WIDTH`] characters.
fn wrap(text: &str) -> String {
    text.as_bytes()
        .chunks(LINE_WIDTH)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const K5: &str = "04d3b0f990d5564e5d7a698940483d07e030f37a9dfb112ad337dd23b512c785";

    fn header(from: &str, subject: &str) -> Vec<u8> {
        format!(
            "from:{from}\r\nsubject:{subject}\r\nto:me@example.com\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=Example.com; s=sel1; h=from:subject:to; bh=x; b="
        )
        .into_bytes()
    }

    #[test]
    fn test_identity() {
        let email = identity(&header("Alice <Alice@Example.com>", &format!("my k5:{K5}"))).unwrap();
        assert_eq!(
            (
                email.address.as_str(),
                email.k5.as_str(),
                email.domain.as_str(),
                email.selector.as_str()
            ),
            ("alice@example.com", K5, "example.com", "sel1")
        );
        // A subdomain of the signing domain.
        assert!(identity(&header("a@mail.example.com", &format!("k5:{K5}"))).is_ok());

        // Another domain, a lookalike, no k5, an invalid address.
        for (from, subject) in [
            ("a@other.com", format!("k5:{K5}")),
            ("a@badexample.com", format!("k5:{K5}")),
            ("a@example.com", "hello".to_string()),
            ("not an address", format!("k5:{K5}")),
        ] {
            assert!(
                identity(&header(from, &subject)).is_err(),
                "{from} {subject}"
            );
        }

        // Several From headers.
        let mut twice = b"from:b@example.com\r\n".to_vec();
        twice.extend(header("a@example.com", &format!("k5:{K5}")));
        assert!(identity(&twice).is_err());
    }

    /// A real attestation cannot be made without an email whose subject
    /// has a k5; the fixture's does not.
    #[test]
    fn test_record_needs_a_k5_email() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../plonky2-zkemail");
        let eml = std::fs::read(root.join("examples/fixtures/test.eml")).unwrap();
        let (domain, selector) = dkim_selector(&eml).unwrap();
        assert_eq!(
            (domain.as_str(), selector.as_str()),
            ("icloud.com", "1a1hai")
        );
        let err = identity(
            b"from:a@icloud.com\r\nsubject:hi\r\ndkim-signature:d=icloud.com; s=1a1hai; b=",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("k5"), "{err}");
    }

    /// A DKIM-signed email from `from` about `subject`, as a mail server of
    /// `domain` would sign it with `private`: relaxed/relaxed, the body
    /// hashed, `from:to:subject` signed.
    fn signed_email(private: &rsa::RsaPrivateKey, from: &str, subject: &str) -> Vec<u8> {
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::{Digest, Sha256};

        let body = "hello from k5\r\n";
        let body_hash = STANDARD.encode(Sha256::digest(body.as_bytes()));
        let headers = [
            ("From", from),
            ("To", "alice@example.com"),
            ("Subject", subject),
        ];
        let tags = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=k5test; h=from:to:subject; bh={body_hash}; b="
        );
        // Relaxed: lowercase names, no space around the colon.
        let mut signed: String = headers
            .iter()
            .map(|(name, value)| format!("{}:{value}\r\n", name.to_ascii_lowercase()))
            .collect();
        signed.push_str(&format!("dkim-signature:{tags}"));
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private.clone());
        let signature = STANDARD.encode(signer.sign(signed.as_bytes()).to_bytes());

        let mut eml = format!("DKIM-Signature: {tags}{signature}\r\n");
        for (name, value) in headers {
            eml.push_str(&format!("{name}: {value}\r\n"));
        }
        eml.push_str("\r\n");
        eml.push_str(body);
        eml.into_bytes()
    }

    /// Makes an attestation of a DKIM-signed email with a k5 in its
    /// subject, and verifies it. A real proof: slow.
    #[test]
    fn test_create_verify() {
        use rsa::pkcs8::EncodePublicKey;

        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let key = TrustedKey {
            domain: "example.com".to_string(),
            selector: "k5test".to_string(),
            record: format!("v=DKIM1; k=rsa; p={}", STANDARD.encode(spki.as_bytes())),
        };
        let eml = signed_email(
            &private,
            "Alice <Alice@example.com>",
            &format!("k5 k5:{K5}"),
        );
        assert_eq!(
            dkim_selector(&eml).unwrap(),
            ("example.com".to_string(), "k5test".to_string())
        );

        let (file, record) = create(&eml, &key).unwrap();
        // To try other verifiers (e.g. a phone) with a real record.
        if let Some(dir) = std::env::var_os("K5_ZKEMAIL_RECORD") {
            std::fs::write(std::path::Path::new(&dir).join(&file), &record).unwrap();
        }
        assert_eq!(file, format!("{K5}-email-alice@example.com.md"));
        assert!(record.starts_with("# info\n\n- Type: zkemail\n- Fake: false\n"));
        assert!(
            !record.contains("hello from k5"),
            "the body is not published"
        );
        let email = verify(&record).unwrap();
        assert_eq!(
            (
                email.address.as_str(),
                email.k5.as_str(),
                email.domain.as_str()
            ),
            ("alice@example.com", K5, "example.com")
        );
        assert_eq!(
            email.profile().to_string(),
            format!("email/alice@example.com/k5:{K5}")
        );

        // Another k5 in the published header: its digest is not the proof's.
        let header = record
            .split("\n# header\n")
            .nth(1)
            .unwrap()
            .split("\n# proof\n")
            .next()
            .unwrap();
        let decoded =
            String::from_utf8(STANDARD.decode(header.replace('\n', "")).unwrap()).unwrap();
        let other = decoded.replace(K5, &"a".repeat(64));
        let tampered = record.replace(header, &wrap(&STANDARD.encode(other)));
        assert!(verify(&tampered).is_err());
        // Another key.
        let other_key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let other_spki = other_key.to_public_key().to_public_key_der().unwrap();
        let swapped = record.replace(
            &key.record,
            &format!(
                "v=DKIM1; k=rsa; p={}",
                STANDARD.encode(other_spki.as_bytes())
            ),
        );
        assert!(verify(&swapped).is_err());

        // An email of another domain than its signer's is not attested.
        let foreign = signed_email(&private, "eve@evil.com", &format!("k5:{K5}"));
        assert!(create(&foreign, &key).is_err());
    }

    #[test]
    fn test_verify_rejects_broken_records() {
        assert!(verify("# info\n").is_err());
        let record = "# info\n\n# dkim\nv=DKIM1; k=rsa; p=AAAA\n# header\n!!!\n# proof\nAAAA\n";
        assert!(verify(record).is_err());
    }
}
