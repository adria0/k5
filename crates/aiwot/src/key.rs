// Keys stored in `aiwot.toml`, one section each:
//
// - `[key]`: hybrid Ed25519 + ML-DSA-44 signature key. Its public keys define
//   the aiwot id.
// - `[kem]`: hybrid X25519MLKEM768 key encapsulation key.
//
// Missing sections are generated on startup. Other settings in the file are
// preserved.

mod kem;
mod signing;

use std::path::Path;

pub use kem::KemKey;
pub use signing::SigningKey;
pub(crate) use signing::{aiwot, verify as verify_signature};

pub type Error = Box<dyn std::error::Error>;

/// A key stored in its own section of `aiwot.toml`.
trait Section: Sized {
    /// Section name in `aiwot.toml`.
    const NAME: &'static str;

    /// Generates a new key from the OS random number generator.
    fn generate() -> Result<Self, Error>;

    /// Restores a key, checking that the stored values are consistent.
    fn from_toml(value: toml::Value) -> Result<Self, Error>;

    fn to_toml(&self) -> Result<toml::Value, Error>;
}

/// The keys of this aiwot instance.
pub struct Keys {
    pub signing: SigningKey,
    // Not used yet.
    #[allow(dead_code)]
    pub kem: KemKey,
    /// Names of the sections generated in this run.
    pub created: Vec<&'static str>,
}

/// Loads the keys from the config file, generating and storing the missing
/// ones.
pub fn load_or_create(path: &Path) -> Result<Keys, Error> {
    let mut config: toml::Table = match std::fs::read_to_string(path) {
        Ok(content) => content
            .parse()
            .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(e.into()),
    };

    let mut changed = false;
    let mut created = Vec::new();
    let signing = section::<SigningKey>(&mut config, &mut changed, &mut created)
        .map_err(|e| format!("invalid [{}] in {}: {e}", SigningKey::NAME, path.display()))?;
    let kem = section::<KemKey>(&mut config, &mut changed, &mut created)
        .map_err(|e| format!("invalid [{}] in {}: {e}", KemKey::NAME, path.display()))?;

    if changed {
        write_private(path, &toml::to_string(&config)?)?;
    }

    Ok(Keys {
        signing,
        kem,
        created,
    })
}

/// Loads a section, generating it if missing. Rewrites the section if its
/// stored form is outdated (e.g. a derived field is missing).
fn section<T: Section>(
    config: &mut toml::Table,
    changed: &mut bool,
    created: &mut Vec<&'static str>,
) -> Result<T, Error> {
    let key = match config.get(T::NAME) {
        Some(value) => T::from_toml(value.clone())?,
        None => {
            created.push(T::NAME);
            T::generate()?
        }
    };

    let value = key.to_toml()?;
    if config.get(T::NAME) != Some(&value) {
        config.insert(T::NAME.to_string(), value);
        *changed = true;
    }

    Ok(key)
}

fn decode_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], Error> {
    hex::decode(value)
        .map_err(|e| format!("{name}: {e}"))?
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes").into())
}

/// Checks that a stored public value matches the one derived from the secret.
fn check_public(name: &str, stored: &str, derived: &[u8]) -> Result<(), Error> {
    if !stored.eq_ignore_ascii_case(&hex::encode(derived)) {
        return Err(format!("{name} does not match the secret key").into());
    }

    Ok(())
}

/// A new random signing key.
#[cfg(test)]
pub fn test_signing_key() -> SigningKey {
    SigningKey::generate().unwrap()
}

/// Writes a file readable only by the owner.
fn write_private(path: &Path, content: &str) -> Result<(), Error> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    options.open(path)?.write_all(content.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create() {
        let dir = std::env::temp_dir().join(format!("aiwot-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aiwot.toml");
        std::fs::write(&path, "other = 1\n").unwrap();

        let keys = load_or_create(&path).unwrap();
        assert_eq!(keys.created, ["key", "kem"]);

        let loaded = load_or_create(&path).unwrap();
        assert!(loaded.created.is_empty());
        assert_eq!(loaded.signing.aiwot(), keys.signing.aiwot());
        assert_eq!(loaded.kem.public(), keys.kem.public());

        // Other settings are preserved.
        let config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(config["other"].as_integer(), Some(1));

        // A missing section is generated without touching the others.
        let mut config = config;
        config.remove("kem");
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let regenerated = load_or_create(&path).unwrap();
        assert_eq!(regenerated.created, ["kem"]);
        assert_eq!(regenerated.signing.aiwot(), keys.signing.aiwot());
        assert_ne!(regenerated.kem.public(), keys.kem.public());

        // A tampered public key is rejected.
        let tampered = std::fs::read_to_string(&path).unwrap().replace(
            &hex::encode(keys.signing.ed25519_public()),
            &"00".repeat(32),
        );
        std::fs::write(&path, tampered).unwrap();
        assert!(load_or_create(&path).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
