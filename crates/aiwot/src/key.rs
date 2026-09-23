// Keys stored in `aiwot.toml`, one section each:
//
// - `[key]`: hybrid Ed25519 + ML-DSA-44 signature key. Its public keys define
//   the aiwot id.
// - `[kem]`: hybrid X25519MLKEM768 key encapsulation key.
//
// The file is created by `aiwot init`, and never generated implicitly. Other
// settings in the file are preserved.

mod kem;
mod signing;

use std::path::Path;

pub use kem::{encapsulate, KemKey};
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
    pub kem: KemKey,
}

/// Generates new keys and stores them in a new config file. Fails if the file
/// already exists, so keys are never overwritten.
pub fn create(path: &Path) -> Result<Keys, Error> {
    let keys = Keys {
        signing: SigningKey::generate()?,
        kem: KemKey::generate()?,
    };
    store(path, &keys, toml::Table::new())?;

    Ok(keys)
}

/// Stores `keys` and `settings` in a new config file. Fails if the file
/// already exists, so keys are never overwritten.
pub fn store(path: &Path, keys: &Keys, settings: toml::Table) -> Result<(), Error> {
    let mut config = settings;
    config.insert(SigningKey::NAME.to_string(), keys.signing.to_toml()?);
    config.insert(KemKey::NAME.to_string(), keys.kem.to_toml()?);
    write_private(path, &toml::to_string(&config)?, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} already exists: keys are not overwritten",
                path.display()
            )
            .into()
        } else {
            Error::from(e)
        }
    })?;

    Ok(())
}

/// Loads the keys from the config file. Rewrites a section if its stored
/// form is outdated (e.g. a derived field is missing).
pub fn load(path: &Path) -> Result<Keys, Error> {
    let mut config: toml::Table = match std::fs::read_to_string(path) {
        Ok(content) => content
            .parse()
            .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} not found: run `aiwot init` to create your keys",
                path.display()
            )
            .into())
        }
        Err(e) => return Err(e.into()),
    };

    let mut changed = false;
    let signing = section::<SigningKey>(&mut config, &mut changed)
        .map_err(|e| format!("invalid [{}] in {}: {e}", SigningKey::NAME, path.display()))?;
    let kem = section::<KemKey>(&mut config, &mut changed)
        .map_err(|e| format!("invalid [{}] in {}: {e}", KemKey::NAME, path.display()))?;

    if changed {
        write_private(path, &toml::to_string(&config)?, false)?;
    }

    Ok(Keys { signing, kem })
}

/// Loads a section, which must exist. Updates it in `config` if its stored
/// form is outdated.
fn section<T: Section>(config: &mut toml::Table, changed: &mut bool) -> Result<T, Error> {
    let key = T::from_toml(config.get(T::NAME).ok_or("missing section")?.clone())?;

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

/// A new random key encapsulation key.
#[cfg(test)]
pub fn test_kem_key() -> KemKey {
    KemKey::generate().unwrap()
}

/// Writes a file readable only by the owner. With `create_new`, fails if the
/// file exists.
fn write_private(path: &Path, content: &str, create_new: bool) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    if create_new {
        options.write(true).create_new(true);
    } else {
        options.write(true).create(true).truncate(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    options.open(path)?.write_all(content.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_load() {
        let dir = std::env::temp_dir().join(format!("aiwot-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aiwot.toml");
        let _ = std::fs::remove_file(&path);

        // Nothing is generated implicitly.
        assert!(load(&path).is_err());
        assert!(!path.exists());

        let keys = create(&path).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.signing.aiwot(), keys.signing.aiwot());
        assert_eq!(loaded.kem.public(), keys.kem.public());

        // Existing keys are never overwritten.
        assert!(create(&path).is_err());
        assert_eq!(load(&path).unwrap().signing.aiwot(), keys.signing.aiwot());

        // Other settings are preserved when a section is updated.
        let mut config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        config.insert("other".to_string(), toml::Value::Integer(1));
        config["key"].as_table_mut().unwrap().remove("aiwot");
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        load(&path).unwrap();
        let config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(config["other"].as_integer(), Some(1));
        assert_eq!(
            config["key"]["aiwot"].as_str(),
            Some(keys.signing.aiwot().as_str())
        );

        // A missing section is an error, not regenerated.
        let mut without_kem = config.clone();
        without_kem.remove("kem");
        std::fs::write(&path, toml::to_string(&without_kem).unwrap()).unwrap();
        assert!(load(&path).is_err());

        // A tampered public key is rejected.
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let tampered = std::fs::read_to_string(&path).unwrap().replace(
            &hex::encode(keys.signing.ed25519_public()),
            &"00".repeat(32),
        );
        std::fs::write(&path, tampered).unwrap();
        assert!(load(&path).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
