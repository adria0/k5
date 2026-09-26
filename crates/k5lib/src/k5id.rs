// The k5 id: the hex encoded OpenPGP fingerprint of a k5's primary key, 64
// lowercase hex characters.
//
// A [`K5Id`] is only built by parsing, so holding one means the id is well
// formed and in its canonical form: it can be compared as a string and used
// in record and file names.

use std::{fmt, ops::Deref, str::FromStr};

use anyhow::anyhow;

use crate::Error;

/// Length of a k5 id: a 32 byte fingerprint, hex.
const LEN: usize = 64;

/// A well formed k5 id, lowercase, without the `k5:` prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct K5Id(String);

impl K5Id {
    /// Parses a k5 id given by a user: surrounding whitespace and a `k5:`
    /// prefix are allowed, and any case.
    pub fn parse(k5: &str) -> Result<Self, Error> {
        let k5 = k5.trim();
        Self::parse_strict(k5.strip_prefix("k5:").unwrap_or(k5))
    }

    /// Parses a k5 id as written in a signed statement: exactly 64 hex
    /// characters, of any case.
    pub fn parse_strict(k5: &str) -> Result<Self, Error> {
        if k5.len() != LEN || !k5.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid k5 `{k5}`: expected {LEN} hex characters"));
        }

        Ok(Self(k5.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for K5Id {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for K5Id {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<K5Id> for String {
    fn from(k5: K5Id) -> Self {
        k5.0
    }
}

impl FromStr for K5Id {
    type Err = Error;

    fn from_str(k5: &str) -> Result<Self, Error> {
        Self::parse(k5)
    }
}

impl fmt::Display for K5Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let hex = "ab".repeat(32);
        for input in [
            hex.clone(),
            hex.to_uppercase(),
            format!("k5:{hex}"),
            format!("  k5:{}\n", hex.to_uppercase()),
        ] {
            assert_eq!(K5Id::parse(&input).unwrap().as_str(), hex, "{input}");
        }

        for input in [
            "",
            "k5:",
            "ab",
            &"zz".repeat(32),
            &"ab".repeat(33),
            "../../x",
        ] {
            assert!(K5Id::parse(input).is_err(), "{input}");
        }

        // Statements hold the bare hex only.
        assert!(K5Id::parse_strict(&hex).is_ok());
        assert!(K5Id::parse_strict(&format!("k5:{hex}")).is_err());
        assert!(K5Id::parse_strict(&format!(" {hex}")).is_err());
    }
}
