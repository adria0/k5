// Signed messages, stored as markdown:
//
// # from
// <aiwot id of the signer>
// # msg
// <the message>
// # pbk
// <hybrid public key, base58, 100 characters per line>
// # signature
// <hybrid signature of the message, base58, 100 characters per line>

use crate::key::{self, SigningKey};

pub type Error = Box<dyn std::error::Error>;

/// Maximum length of the base58 lines.
const LINE_WIDTH: usize = 100;

pub struct SignedMessage {
    pub from: String,
    pub msg: String,
    pub public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedMessage {
    /// Signs `msg` with `key`.
    pub fn sign(key: &SigningKey, msg: &str) -> Result<Self, Error> {
        Ok(Self {
            from: key.aiwot(),
            msg: msg.to_string(),
            public: key.public(),
            signature: key.sign(msg.as_bytes())?,
        })
    }

    /// Checks that `from` is the aiwot id of the public key and that the
    /// signature of the message is valid.
    pub fn verify(&self) -> Result<(), Error> {
        let aiwot = key::aiwot(&self.public);
        if !self.from.eq_ignore_ascii_case(&aiwot) {
            return Err(format!(
                "`from` {} is not the aiwot of the public key ({aiwot})",
                self.from
            )
            .into());
        }

        key::verify_signature(self.msg.as_bytes(), &self.public, &self.signature)
    }

    pub fn to_markdown(&self) -> String {
        format!(
            "# from\n{}\n# msg\n{}\n# pbk\n{}\n# signature\n{}\n",
            self.from,
            self.msg,
            encode(&self.public),
            encode(&self.signature)
        )
    }

    pub fn parse(markdown: &str) -> Result<Self, Error> {
        // The message may contain anything, so the sections around it are
        // located from the outside in. Base58 never contains `#`.
        let rest = markdown
            .strip_prefix("# from\n")
            .ok_or("missing `# from` section")?;
        let (from, rest) = rest
            .split_once("\n# msg\n")
            .ok_or("missing `# msg` section")?;
        let (rest, signature) = rest
            .rsplit_once("\n# signature\n")
            .ok_or("missing `# signature` section")?;
        let (msg, public) = rest
            .rsplit_once("\n# pbk\n")
            .ok_or("missing `# pbk` section")?;

        Ok(Self {
            from: from.trim().to_string(),
            msg: msg.to_string(),
            public: decode("pbk", public)?,
            signature: decode("signature", signature)?,
        })
    }
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

fn decode(name: &str, section: &str) -> Result<Vec<u8>, Error> {
    let encoded: String = section.split_whitespace().collect();

    bs58::decode(encoded)
        .into_vec()
        .map_err(|e| format!("invalid base58 in `# {name}`: {e}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_signing_key;

    #[test]
    fn test_round_trip() {
        let key = test_signing_key();
        let signed = SignedMessage::sign(&key, "hello\n# pbk\nworld").unwrap();

        let markdown = signed.to_markdown();
        assert!(markdown.lines().all(|line| line.len() <= LINE_WIDTH));

        let parsed = SignedMessage::parse(&markdown).unwrap();
        assert_eq!(parsed.from, key.aiwot());
        assert_eq!(parsed.msg, "hello\n# pbk\nworld");
        parsed.verify().unwrap();
    }

    #[test]
    fn test_tampering() {
        let key = test_signing_key();
        let markdown = SignedMessage::sign(&key, "hello").unwrap().to_markdown();

        let tampered = markdown.replace("\nhello\n", "\nhellO\n");
        assert!(SignedMessage::parse(&tampered).unwrap().verify().is_err());

        let other = test_signing_key();
        let mut signed = SignedMessage::parse(&markdown).unwrap();
        signed.from = other.aiwot();
        assert!(signed.verify().is_err());
    }
}
