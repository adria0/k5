// The k5 wire protocol, over iroh QUIC connections with ALPN [`ALPN`].
//
// A connection starts with a hello on its first bidirectional stream: each
// side sends its self attestation and its iroh attestation (the dialer first,
// then the listener if it accepts the dialer). A first contact by ticket
// sends a pairing hello instead ([`PAIR`]), which the listener also accepts
// from a k5 not on its web of trust while its pairing window is open. Every
// later request is a new bidirectional stream. A payload is one kind byte
// followed by UTF-8 text; the sender finishes the stream after it, so the end
// of the stream delimits it, and the receiver reads it with a size limit.

use anyhow::{anyhow, Context as _};
use k5lib::Error;

/// ALPN of the k5 protocol.
pub const ALPN: &[u8] = b"k5/1";

/// Hello: the self attestation and the iroh attestation of the sender.
pub const HELLO: u8 = b'H';
/// A hello for a first contact by ticket (pairing), as [`HELLO`].
pub const PAIR: u8 = b'P';
/// A signcrypted message (armored) for the receiver.
pub const MESSAGE: u8 = b'M';
/// A request for the receiver's signed export (`attest export`).
pub const EXPORT_REQUEST: u8 = b'E';
/// The signed export, answering [`EXPORT_REQUEST`].
pub const EXPORT: u8 = b'X';
/// Success, with no content.
pub const OK: u8 = b'O';
/// Refusal or failure, with the reason.
pub const REFUSED: u8 = b'R';

/// Size limits of the payloads, by kind.
pub const HELLO_LIMIT: usize = 256 * 1024;
pub const MESSAGE_LIMIT: usize = 1024 * 1024;
pub const EXPORT_LIMIT: usize = 64 * 1024 * 1024;

/// Separates the two records of a hello. Records are text without NUL.
const RECORD_SEPARATOR: char = '\0';

/// Prefix of the text form of a ticket.
const TICKET_PREFIX: &str = "k5ticket:";

pub fn encode(kind: u8, text: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + text.len());
    payload.push(kind);
    payload.extend_from_slice(text.as_bytes());
    payload
}

/// Splits a payload into its kind and text.
pub fn decode(payload: &[u8]) -> Result<(u8, String), Error> {
    let (&kind, text) = payload.split_first().context("empty payload")?;
    let text = String::from_utf8(text.to_vec()).context("payload is not UTF-8")?;

    Ok((kind, text))
}

/// The text of a hello: the self attestation and the iroh attestation.
pub fn hello(me_record: &str, iroh_record: &str) -> String {
    format!("{me_record}{RECORD_SEPARATOR}{iroh_record}")
}

/// Splits the text of a hello into the self attestation and the iroh
/// attestation.
pub fn parse_hello(text: &str) -> Result<(&str, &str), Error> {
    text.split_once(RECORD_SEPARATOR)
        .context("invalid hello: expected two records")
}

/// The text form of a ticket: how to reach an endpoint, for a first contact
/// with a k5 whose iroh attestation is not known yet.
pub fn ticket(addr: &iroh::EndpointAddr) -> Result<String, Error> {
    use base64::Engine;

    let json = serde_json::to_vec(addr)?;
    Ok(format!(
        "{TICKET_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    ))
}

/// Parses the text form of a ticket.
pub fn parse_ticket(ticket: &str) -> Result<iroh::EndpointAddr, Error> {
    use base64::Engine;

    let encoded = ticket
        .trim()
        .strip_prefix(TICKET_PREFIX)
        .ok_or_else(|| anyhow!("invalid ticket: expected `{TICKET_PREFIX}...`"))?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid ticket")?;
    serde_json::from_slice(&json).context("invalid ticket")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload() {
        assert_eq!(
            decode(&encode(MESSAGE, "hi")).unwrap(),
            (MESSAGE, "hi".into())
        );
        assert!(decode(&[]).is_err());
        assert!(decode(&[OK, 0xff]).is_err());
    }

    #[test]
    fn test_hello() {
        assert_eq!(parse_hello(&hello("a", "b")).unwrap(), ("a", "b"));
        assert!(parse_hello("a").is_err());
    }

    #[test]
    fn test_ticket() {
        let id = iroh::SecretKey::generate().public();
        let addr = iroh::EndpointAddr::new(id).with_ip_addr("127.0.0.1:4433".parse().unwrap());

        let ticket = ticket(&addr).unwrap();
        assert!(ticket.starts_with(TICKET_PREFIX));
        assert_eq!(parse_ticket(&ticket).unwrap(), addr);
        assert!(parse_ticket("nope").is_err());
    }
}
