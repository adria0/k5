//! Preparation and proof generation for bounded DKIM-signed `.eml` messages.

use crate::{
    email::{BodyWitness, EmailCircuit, EmailConfig, EmailWitness},
    sha256::{IV, pad},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use num_bigint::BigUint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

const RSA_ENCRYPTION_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[derive(Clone, Debug, Deserialize)]
struct TrustedKey {
    domain: String,
    selector: String,
    record: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreparedEmail {
    domain: String,
    selector: String,
    header: Vec<u8>,
    body: Vec<u8>,
    body_hash_index: usize,
    modulus: BigUint,
    signature: BigUint,
}

/// A serialized Plonky2 proof and identifying information about its DKIM key.
pub struct EmailProof {
    pub bytes: Vec<u8>,
    pub domain: String,
    pub selector: String,
    pub gate_rows: usize,
    pub padded_rows: usize,
}

/// Normalizes LF input while rejecting bare CR octets.
fn normalize_crlf(raw: &[u8]) -> Result<Vec<u8>> {
    let mut normalized = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'\r' => {
                ensure!(
                    raw.get(index + 1) == Some(&b'\n'),
                    "bare CR line endings are unsupported"
                );
                normalized.extend_from_slice(b"\r\n");
                index += 2;
            }
            b'\n' => {
                normalized.extend_from_slice(b"\r\n");
                index += 1;
            }
            byte => {
                normalized.push(byte);
                index += 1;
            }
        }
    }
    Ok(normalized)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_headers(input: &[u8]) -> Result<Vec<Header>> {
    let mut headers: Vec<Header> = Vec::new();
    for line in input.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b" ") || line.starts_with(b"\t") {
            let header = headers.last_mut().context("orphan header continuation")?;
            header.value.extend_from_slice(b"\r\n");
            header.value.extend_from_slice(line);
            continue;
        }

        let colon = line
            .iter()
            .position(|&byte| byte == b':')
            .context("malformed email header")?;
        let name = &line[..colon];
        ensure!(
            !name.is_empty()
                && name
                    .iter()
                    .all(|&byte| (0x21..=0x39).contains(&byte) || (0x3b..=0x7e).contains(&byte)),
            "malformed email header"
        );
        headers.push(Header {
            name: name.to_vec(),
            value: line[colon + 1..].to_vec(),
        });
    }
    Ok(headers)
}

fn trim_wsp(value: &str) -> &str {
    value.trim_matches([' ', '\t', '\r', '\n'])
}

/// Parses a DKIM tag list and rejects duplicate or malformed tags.
fn tags(value: &[u8]) -> Result<BTreeMap<String, String>> {
    let value = std::str::from_utf8(value).context("DKIM tags are not ASCII")?;
    let mut result = BTreeMap::new();
    for part in value.split(';') {
        let part = trim_wsp(part);
        if part.is_empty() {
            continue;
        }
        let equals = part.find('=').context("malformed or duplicate DKIM tag")?;
        let name = part[..equals].trim_end_matches([' ', '\t']);
        ensure!(
            !name.is_empty()
                && name.as_bytes()[0].is_ascii_lowercase()
                && name
                    .bytes()
                    .skip(1)
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                && !result.contains_key(name),
            "malformed or duplicate DKIM tag"
        );
        result.insert(name.to_owned(), trim_wsp(&part[equals + 1..]).to_owned());
    }
    Ok(result)
}

fn decode_base64(value: Option<&String>, label: &str) -> Result<Vec<u8>> {
    let text: String = value
        .with_context(|| format!("missing {label}"))?
        .chars()
        .filter(|character| !matches!(character, ' ' | '\t' | '\r' | '\n'))
        .collect();
    let decoded = STANDARD
        .decode(&text)
        .with_context(|| format!("invalid {label}"))?;
    ensure!(
        !text.is_empty() && STANDARD.encode(&decoded) == text,
        "invalid {label}"
    );
    Ok(decoded)
}

/// Applies relaxed header canonicalization while preserving non-ASCII octets.
fn relaxed_header(header: &Header) -> Vec<u8> {
    let mut output: Vec<u8> = header.name.iter().map(u8::to_ascii_lowercase).collect();
    output.push(b':');

    let mut value = Vec::with_capacity(header.value.len());
    let mut index = 0;
    let mut pending_space = false;
    while index < header.value.len() {
        if header.value[index..].starts_with(b"\r\n") {
            index += 2;
        } else if matches!(header.value[index], b' ' | b'\t') {
            pending_space = !value.is_empty();
            index += 1;
        } else {
            if pending_space {
                value.push(b' ');
                pending_space = false;
            }
            value.push(header.value[index]);
            index += 1;
        }
    }
    output.extend(value);
    output
}

/// Applies relaxed body canonicalization.
fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut lines = Vec::new();
    for line in body.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let mut canonical = Vec::with_capacity(line.len());
        let mut pending_space = false;
        for &byte in line {
            if matches!(byte, b' ' | b'\t') {
                pending_space = true;
            } else {
                if pending_space {
                    canonical.push(b' ');
                    pending_space = false;
                }
                canonical.push(byte);
            }
        }
        lines.push(canonical);
    }
    while lines.last().is_some_and(Vec::is_empty) {
        lines.pop();
    }
    let mut output = lines.join(b"\r\n".as_slice());
    if !output.is_empty() {
        output.extend_from_slice(b"\r\n");
    }
    output
}

/// Selects repeated signed headers from the bottom upward in `h=` order.
fn signed_headers(headers: &[Header], names: &[String]) -> Vec<u8> {
    let mut used = vec![false; headers.len()];
    let mut output = Vec::new();
    for name in names {
        if let Some(index) = (0..headers.len()).rev().find(|&index| {
            !used[index] && headers[index].name.eq_ignore_ascii_case(name.as_bytes())
        }) {
            used[index] = true;
            output.extend(relaxed_header(&headers[index]));
            output.extend_from_slice(b"\r\n");
        }
    }
    output
}

fn blank_signature(value: &[u8]) -> Vec<u8> {
    value
        .split(|&byte| byte == b';')
        .map(|part| {
            let mut index = part
                .iter()
                .take_while(|&&byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
                .count();
            if part
                .get(index)
                .is_some_and(|byte| byte.eq_ignore_ascii_case(&b'b'))
            {
                index += 1;
                while matches!(part.get(index), Some(b' ' | b'\t')) {
                    index += 1;
                }
                if part.get(index) == Some(&b'=') {
                    return &part[..=index];
                }
            }
            part
        })
        .collect::<Vec<_>>()
        .join(b";".as_slice())
}

struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, tag: u8) -> Result<&'a [u8]> {
        ensure!(
            self.input.get(self.offset) == Some(&tag),
            "invalid RSA public-key DER"
        );
        self.offset += 1;
        let first = *self
            .input
            .get(self.offset)
            .context("truncated RSA public-key DER")?;
        self.offset += 1;
        let length = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            ensure!(
                (1..=4).contains(&count),
                "invalid RSA public-key DER length"
            );
            ensure!(
                self.offset + count <= self.input.len(),
                "truncated RSA public-key DER"
            );
            let mut length = 0usize;
            for &byte in &self.input[self.offset..self.offset + count] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(byte)))
                    .context("RSA public-key DER length overflow")?;
            }
            self.offset += count;
            ensure!(length >= 128, "non-canonical RSA public-key DER length");
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .context("RSA public-key DER length overflow")?;
        ensure!(end <= self.input.len(), "truncated RSA public-key DER");
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn finish(self) -> Result<()> {
        ensure!(
            self.offset == self.input.len(),
            "trailing RSA public-key DER data"
        );
        Ok(())
    }
}

fn positive_integer(value: &[u8]) -> Result<&[u8]> {
    ensure!(
        !value.is_empty() && value[0] & 0x80 == 0,
        "invalid RSA public-key integer"
    );
    let value = value.strip_prefix(&[0]).unwrap_or(value);
    ensure!(
        !value.is_empty() && (value.len() == 1 || value[0] != 0),
        "invalid RSA public-key integer"
    );
    Ok(value)
}

/// Extracts a 2048-bit RSA modulus and verifies exponent 65537 from SPKI DER.
fn rsa_key_from_spki(der: &[u8]) -> Result<BigUint> {
    let mut document = DerReader::new(der);
    let subject_public_key_info = document.take(0x30)?;
    document.finish()?;
    let mut spki = DerReader::new(subject_public_key_info);

    let algorithm = spki.take(0x30)?;
    let mut algorithm = DerReader::new(algorithm);
    ensure!(
        algorithm.take(0x06)? == RSA_ENCRYPTION_OID,
        "expected an RSA DKIM public key"
    );
    ensure!(
        algorithm.take(0x05)?.is_empty(),
        "invalid RSA algorithm parameters"
    );
    algorithm.finish()?;

    let bit_string = spki.take(0x03)?;
    spki.finish()?;
    ensure!(
        bit_string.first() == Some(&0),
        "invalid RSA public-key bit string"
    );
    let mut wrapped_key = DerReader::new(&bit_string[1..]);
    let key = wrapped_key.take(0x30)?;
    wrapped_key.finish()?;
    let mut key = DerReader::new(key);
    let modulus = positive_integer(key.take(0x02)?)?;
    let exponent = positive_integer(key.take(0x02)?)?;
    key.finish()?;
    ensure!(exponent == [0x01, 0x00, 0x01], "RSA exponent must be 65537");
    ensure!(modulus.len() == 256, "expected a 2048-bit RSA key");
    Ok(BigUint::from_bytes_be(modulus))
}

/// Performs the inexpensive host-side PKCS#1 v1.5 check before proving.
fn verify_rsa_sha256(modulus: &BigUint, signature: &BigUint, message: &[u8]) -> Result<()> {
    ensure!(signature < modulus, "DKIM RSA signature mismatch");
    let encoded = signature
        .modpow(&BigUint::from(65_537u32), modulus)
        .to_bytes_be();
    ensure!(encoded.len() <= 256, "DKIM RSA signature mismatch");
    let mut encoded_message = vec![0; 256 - encoded.len()];
    encoded_message.extend(encoded);

    let digest = Sha256::digest(message);
    let padding_end = 256 - SHA256_DIGEST_INFO_PREFIX.len() - digest.len() - 1;
    ensure!(
        encoded_message.starts_with(&[0x00, 0x01])
            && padding_end >= 10
            && encoded_message[2..padding_end]
                .iter()
                .all(|&byte| byte == 0xff)
            && encoded_message[padding_end] == 0
            && encoded_message[padding_end + 1..].starts_with(SHA256_DIGEST_INFO_PREFIX)
            && encoded_message[padding_end + 1 + SHA256_DIGEST_INFO_PREFIX.len()..] == digest[..],
        "DKIM RSA signature mismatch"
    );
    Ok(())
}

/// Canonicalizes and validates the bounded DKIM input used by the circuit.
fn prepare_email(raw: &[u8], trusted_key: &TrustedKey) -> Result<PreparedEmail> {
    let message = normalize_crlf(raw)?;
    let boundary = find_bytes(&message, b"\r\n\r\n").context("missing header/body separator")?;
    let headers = parse_headers(&message[..boundary])?;
    let signatures: Vec<_> = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(b"dkim-signature"))
        .collect();
    ensure!(signatures.len() == 1, "expected exactly one DKIM signature");
    let dkim = signatures[0];
    let signature_tags = tags(&dkim.value)?;
    ensure!(
        signature_tags.get("v").map(String::as_str) == Some("1"),
        "expected DKIM v=1"
    );
    ensure!(
        signature_tags.get("a").map(String::as_str) == Some("rsa-sha256"),
        "expected rsa-sha256"
    );
    ensure!(
        signature_tags.get("c").map(String::as_str) == Some("relaxed/relaxed"),
        "expected relaxed/relaxed canonicalization"
    );
    ensure!(
        !signature_tags.contains_key("l"),
        "partial-body l= signatures are unsupported"
    );
    ensure!(
        signature_tags.get("d") == Some(&trusted_key.domain)
            && signature_tags.get("s") == Some(&trusted_key.selector),
        "signing domain/selector does not match the trusted key record"
    );
    if let Some(identity) = signature_tags.get("i") {
        let (local, identity_domain) =
            identity.rsplit_once('@').context("invalid DKIM identity")?;
        ensure!(
            !local.contains('@') && !identity_domain.is_empty(),
            "invalid DKIM identity"
        );
        let identity_domain = identity_domain.to_ascii_lowercase();
        let signing_domain = trusted_key.domain.to_ascii_lowercase();
        ensure!(
            identity_domain == signing_domain
                || identity_domain.ends_with(&format!(".{signing_domain}")),
            "DKIM identity domain is outside the signing domain"
        );
    }

    let body = relaxed_body(&message[boundary + 4..]);
    let body_hash = Sha256::digest(&body);
    ensure!(
        decode_base64(signature_tags.get("bh"), "body hash")? == body_hash[..],
        "DKIM body hash mismatch"
    );
    let names: Vec<String> = signature_tags
        .get("h")
        .map_or("", String::as_str)
        .to_ascii_lowercase()
        .split(':')
        .map(trim_wsp)
        .map(str::to_owned)
        .collect();
    ensure!(
        names.iter().any(|name| name == "from")
            && headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case(b"from")),
        "a signed From header is required"
    );
    ensure!(
        names.iter().all(|name| {
            name != "dkim-signature"
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| (0x21..=0x39).contains(&byte) || (0x3b..=0x7e).contains(&byte))
        }),
        "unsupported signed-header list"
    );

    let mut prefix = signed_headers(&headers, &names);
    let signed_dkim = relaxed_header(&Header {
        name: dkim.name.clone(),
        value: blank_signature(&dkim.value),
    });
    let marker = b"; bh=";
    let marker_index = find_bytes(&signed_dkim, marker)
        .context("body hash formatting is unsupported by the circuit regex")?;
    let hash_start = marker_index + marker.len();
    let hash_end = hash_start + 44;
    ensure!(
        signed_dkim.get(hash_end) == Some(&b';')
            && signed_dkim
                .get(hash_start..hash_end)
                .is_some_and(|value| value
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(byte)))
            && signed_dkim[hash_start..hash_end] == STANDARD.encode(body_hash).as_bytes()[..],
        "body hash formatting is unsupported by the circuit regex"
    );
    let body_hash_index = prefix.len() + hash_start;
    prefix.extend(signed_dkim);

    let key_tags = tags(trusted_key.record.as_bytes())?;
    ensure!(
        key_tags.get("v").map(String::as_str) == Some("DKIM1")
            && key_tags.get("k").map(String::as_str) == Some("rsa"),
        "expected an RSA DKIM public key"
    );
    let modulus = rsa_key_from_spki(&decode_base64(key_tags.get("p"), "public key")?)?;
    let signature_bytes = decode_base64(signature_tags.get("b"), "signature")?;
    ensure!(signature_bytes.len() == 256, "DKIM RSA signature mismatch");
    let signature = BigUint::from_bytes_be(&signature_bytes);
    verify_rsa_sha256(&modulus, &signature, &prefix)?;

    Ok(PreparedEmail {
        domain: trusted_key.domain.clone(),
        selector: trusted_key.selector.clone(),
        header: prefix,
        body,
        body_hash_index,
        modulus,
        signature,
    })
}

/// Reads, canonicalizes, and validates an email and its trusted DKIM record.
fn prepare(path: &Path, dkim_path: &Path) -> Result<PreparedEmail> {
    let raw = fs::read(path).with_context(|| format!("failed to read email {}", path.display()))?;
    let key: TrustedKey = serde_json::from_slice(
        &fs::read(dkim_path)
            .with_context(|| format!("failed to read DKIM key {}", dkim_path.display()))?,
    )
    .context("invalid trusted DKIM key JSON")?;
    prepare_email(&raw, &key)
}

/// Generates and verifies a Plonky2 proof for a DKIM-signed email.
///
/// `dkim_path` must name a JSON object with `domain`, `selector`, and `record`
/// fields, where `record` is the trusted DKIM TXT record.
///
/// This intentionally supports the bounded DKIM format documented by this
/// crate: one 2048-bit RSA-SHA256 signature using relaxed/relaxed
/// canonicalization and no partial-body `l=` tag.
pub fn prove(path: impl AsRef<Path>, dkim_path: impl AsRef<Path>) -> Result<EmailProof> {
    let prepared = prepare(path.as_ref(), dkim_path.as_ref())?;
    let header = pad(&prepared.header);
    let body = pad(&prepared.body);
    let config = EmailConfig {
        max_header_bytes: header.len(),
        max_body_bytes: body.len(),
        modulus_bytes: 256,
        ..EmailConfig::default()
    };
    let state: [u8; 32] = IV
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("SHA-256 state is always 32 bytes");
    let witness = EmailWitness {
        header: &header,
        header_length: header.len(),
        signature: &prepared.signature,
        modulus: &prepared.modulus,
        header_mask: None,
        body: Some(BodyWitness {
            bytes: &body,
            length: body.len(),
            pre_hash: &state,
            hash_index: prepared.body_hash_index,
            mask: None,
            decoded: None,
        }),
    };

    let circuit = EmailCircuit::build(&config);
    let gate_rows = circuit.gate_rows;
    let padded_rows = circuit.data.common.degree();
    let proof = circuit.prove(&witness)?;
    circuit.data.verify(proof.clone())?;

    Ok(EmailProof {
        bytes: proof.to_bytes(),
        domain: prepared.domain,
        selector: prepared.selector,
        gate_rows,
        padded_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, TrustedKey) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let raw = fs::read(root.join("examples/fixtures/test.eml")).unwrap();
        let key = serde_json::from_slice(
            &fs::read(root.join("examples/fixtures/icloud-dkim.json")).unwrap(),
        )
        .unwrap();
        (raw, key)
    }

    fn error(input: Result<PreparedEmail>, expected: &str) {
        let message = input.unwrap_err().to_string();
        assert!(
            message.contains(expected),
            "expected `{expected}` in `{message}`"
        );
    }

    #[test]
    fn prepares_fixture_with_lf_or_smtp_line_endings() {
        let (raw, key) = fixture();
        let prepared = prepare_email(&raw, &key).unwrap();
        let smtp = String::from_utf8(raw.clone())
            .unwrap()
            .replace('\n', "\r\n");
        assert_eq!(prepare_email(smtp.as_bytes(), &key).unwrap(), prepared);
        assert_eq!(prepared.domain, "icloud.com");
        assert_eq!(prepared.selector, "1a1hai");
        assert_eq!(prepared.body, b"Hello,\r\n\r\nHow are you?\r\n");
        assert_eq!(prepared.modulus.to_bytes_be().len(), 256);
        assert_eq!(prepared.signature.to_bytes_be().len(), 256);
        assert_eq!(
            &prepared.header[prepared.body_hash_index..prepared.body_hash_index + 44],
            b"7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU="
        );

        let limbs = [
            "1156466847851242602709362303526378170",
            "191372789510123109308037416804949834",
            "7204",
        ]
        .map(|value| BigUint::parse_bytes(value.as_bytes(), 10).unwrap());
        let expected = crate::bigint::from_circom_limbs(&limbs, 121).unwrap();
        assert_eq!(
            BigUint::from_bytes_be(&Sha256::digest(&prepared.header)),
            expected
        );
    }

    #[test]
    fn relaxed_canonicalization_handles_folding_and_whitespace() {
        assert_eq!(
            relaxed_header(&Header {
                name: b"SUBJECT".to_vec(),
                value: b" \tHello\r\n\t world \t".to_vec(),
            }),
            b"subject:Hello world"
        );
        assert_eq!(
            relaxed_body(b" \tHello \t\r\nworld\t \r\n\r\n"),
            b" Hello\r\nworld\r\n"
        );
        assert!(relaxed_body(b"\t \r\n\r\n").is_empty());

        let (raw, key) = fixture();
        let variant = String::from_utf8(raw.clone())
            .unwrap()
            .replace("Subject: Hello", "SUBJECT:\r\n\tHello \t");
        assert_eq!(
            prepare_email(variant.as_bytes(), &key).unwrap(),
            prepare_email(&raw, &key).unwrap()
        );
    }

    #[test]
    fn repeated_signed_headers_are_selected_bottom_up() {
        let headers = [
            Header {
                name: b"X-Tag".to_vec(),
                value: b"top".to_vec(),
            },
            Header {
                name: b"x-tag".to_vec(),
                value: b"bottom".to_vec(),
            },
        ];
        let names = ["x-tag".to_owned(), "x-tag".to_owned(), "x-tag".to_owned()];
        assert_eq!(
            signed_headers(&headers, &names),
            b"x-tag:bottom\r\nx-tag:top\r\n"
        );
    }

    #[test]
    fn rejects_tampering_and_wrong_trust_anchors() {
        let (raw, key) = fixture();
        error(
            prepare_email(
                &String::from_utf8(raw.clone())
                    .unwrap()
                    .replace("How are you?", "How are we?")
                    .into_bytes(),
                &key,
            ),
            "body hash mismatch",
        );
        error(
            prepare_email(
                &String::from_utf8(raw.clone())
                    .unwrap()
                    .replace("Subject: Hello", "Subject: Changed")
                    .into_bytes(),
                &key,
            ),
            "RSA signature mismatch",
        );
        let mut wrong = key.clone();
        wrong.domain = "example.com".to_owned();
        error(prepare_email(&raw, &wrong), "domain/selector");
        let mut wrong = key.clone();
        wrong.selector = "other".to_owned();
        error(prepare_email(&raw, &wrong), "domain/selector");
        let mut wrong = key.clone();
        wrong.record = wrong.record.replacen("p=", "p=A", 1);
        assert!(prepare_email(&raw, &wrong).is_err());
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_signatures() {
        let (raw, key) = fixture();
        let raw = String::from_utf8(raw).unwrap();
        for (before, after, expected) in [
            ("c=relaxed/relaxed", "c=simple/relaxed", "relaxed/relaxed"),
            ("a=rsa-sha256", "a=rsa-sha1", "rsa-sha256"),
            ("v=1;", "v=1; l=0;", "partial-body"),
            ("v=1;", "v=1; v=1;", "duplicate"),
            (
                "d=icloud.com;",
                "d=icloud.com; i=user@example.com;",
                "identity domain",
            ),
        ] {
            error(
                prepare_email(raw.replacen(before, after, 1).as_bytes(), &key),
                expected,
            );
        }
        error(
            prepare_email(format!("DKIM-Signature: v=1;\n{raw}").as_bytes(), &key),
            "exactly one",
        );
    }
}
