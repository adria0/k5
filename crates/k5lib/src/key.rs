// Keys stored in `k5.toml`:
//
// [key]
// algorithm = "MlDsa65Ed25519+MlKem768X25519"
// k5 = "..."             # OpenPGP fingerprint of the primary key, hex
// secret_key = """
// -----BEGIN PGP PRIVATE KEY BLOCK-----
// ...
// -----END PGP PRIVATE KEY BLOCK-----
// """
//
// One OpenPGP v6 key: a MlDsa65Ed25519 primary (signing and certifying) with
// a MlKem768X25519 encryption subkey. The primary key's OpenPGP fingerprint
// is the k5 id.
//
// This uses rpgp's `draft-pqc` feature, which implements the post-quantum
// composite algorithms of draft-ietf-openpgp-pqc. That draft, and rpgp's
// implementation of it, are not yet stable: upstream marks `draft-pqc`
// experimental and not for production use, so the on-wire format may still
// change before the draft is finalized.
//
// The file is created by `k5 init`, and never generated implicitly. Other
// settings in the file are preserved.

use std::path::Path;

use pgp::{
    composed::{
        Deserializable, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey,
        SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey, SubkeyParamsBuilder,
    },
    types::{KeyDetails, KeyVersion},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub type Error = Box<dyn std::error::Error>;

const NAME: &str = "key";
const ALGORITHM: &str = "MlDsa65Ed25519+MlKem768X25519";

/// The `[key]` section of `k5.toml`.
#[derive(Serialize, Deserialize)]
struct KeyConfig {
    algorithm: String,
    /// Derived from the secret key. Added on load if missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    k5: Option<String>,
    secret_key: String,
}

/// The keys of this k5 instance: one OpenPGP key, a `MlDsa65Ed25519`
/// primary (signing and certifying) with a `MlKem768X25519` encryption
/// subkey.
pub struct Keys {
    pub secret: SignedSecretKey,
}

impl Keys {
    /// The k5 id: the hex encoded OpenPGP fingerprint of the primary key.
    pub fn k5(&self) -> String {
        k5(&self.secret)
    }

    /// The public key: the primary key and the encryption subkey, without any
    /// secret material.
    pub fn public(&self) -> SignedPublicKey {
        self.secret.to_public_key()
    }

    /// The `MlKem768X25519` encryption subkey.
    pub fn encryption_subkey(&self) -> Result<SignedPublicSubKey, Error> {
        // `generate()` only populates `secret_subkeys`; the public form of
        // each subkey is derived on demand, as `to_public_key()` also does.
        self.secret
            .secret_subkeys
            .first()
            .map(SignedSecretSubKey::signed_public_key)
            .ok_or_else(|| "the key has no encryption subkey".into())
    }

    /// A new random pair of keys.
    pub fn generate() -> Result<Self, Error> {
        let params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::MlDsa65Ed25519)
            .can_sign(true)
            .can_certify(true)
            .passphrase(None)
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::MlKem768X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()?,
            )
            .build()?;

        let secret = params.generate(OsRng)?;
        secret.verify_bindings()?;

        Ok(Self { secret })
    }

    fn from_toml(value: toml::Value) -> Result<Self, Error> {
        let config: KeyConfig = value.try_into()?;
        if config.algorithm != ALGORITHM {
            return Err(format!(
                "unsupported algorithm `{}`, expected `{ALGORITHM}`",
                config.algorithm
            )
            .into());
        }

        let (secret, _) = SignedSecretKey::from_string(&config.secret_key)
            .map_err(|e| format!("invalid secret_key: {e}"))?;
        secret
            .verify_bindings()
            .map_err(|e| format!("invalid secret key: {e}"))?;

        let keys = Self { secret };
        if let Some(k5) = &config.k5 {
            if !k5.eq_ignore_ascii_case(&keys.k5()) {
                return Err("k5 does not match the secret key".into());
            }
        }

        Ok(keys)
    }

    fn to_toml(&self) -> Result<toml::Value, Error> {
        Ok(toml::Value::try_from(KeyConfig {
            algorithm: ALGORITHM.to_string(),
            k5: Some(self.k5()),
            secret_key: self.secret.to_armored_string(Default::default())?,
        })?)
    }
}

/// The k5 id of an OpenPGP key: the hex encoded fingerprint of its primary
/// key.
pub fn k5(key: &SignedSecretKey) -> String {
    key.primary_key.fingerprint().to_string()
}

/// Generates new keys and stores them in a new config file. Fails if the file
/// already exists, so keys are never overwritten.
pub fn create(path: &Path) -> Result<Keys, Error> {
    let keys = Keys::generate()?;
    store(path, &keys, toml::Table::new())?;

    Ok(keys)
}

/// Stores `keys` and `settings` in a new config file. Fails if the file
/// already exists, so keys are never overwritten.
pub fn store(path: &Path, keys: &Keys, settings: toml::Table) -> Result<(), Error> {
    let mut config = settings;
    config.insert(NAME.to_string(), keys.to_toml()?);
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

/// Loads the keys from the config file. Rewrites the `[key]` section if its
/// stored form is outdated (e.g. a derived field is missing).
pub fn load(path: &Path) -> Result<Keys, Error> {
    let mut config: toml::Table = match std::fs::read_to_string(path) {
        Ok(content) => content
            .parse()
            .map_err(|e| format!("invalid {}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} not found: run `k5 init` to create your keys",
                path.display()
            )
            .into())
        }
        Err(e) => return Err(e.into()),
    };

    let value = config.get(NAME).cloned().ok_or_else(|| {
        format!(
            "invalid {}: missing [{NAME}] section (this looks like a k5.toml from before \
             the switch to OpenPGP keys; run `k5 init` with a new config file)",
            path.display()
        )
    })?;
    let keys = Keys::from_toml(value)
        .map_err(|e| format!("invalid [{NAME}] in {}: {e}", path.display()))?;

    let stored = keys.to_toml()?;
    if config.get(NAME) != Some(&stored) {
        config.insert(NAME.to_string(), stored);
        write_private(path, &toml::to_string(&config)?, false)?;
    }

    Ok(keys)
}

/// A section of the existing config file other than `[key]`, e.g. settings of
/// another component. `None` if the section is missing.
pub fn load_section(path: &Path, name: &str) -> Result<Option<toml::Value>, Error> {
    Ok(read_config(path)?.remove(name))
}

/// Sets a section of the existing config file other than `[key]`, keeping
/// the others.
pub fn store_section(path: &Path, name: &str, value: toml::Value) -> Result<(), Error> {
    if name == NAME {
        return Err(format!("the [{NAME}] section is not stored this way").into());
    }
    let mut config = read_config(path)?;
    config.insert(name.to_string(), value);
    write_private(path, &toml::to_string(&config)?, false)?;

    Ok(())
}

fn read_config(path: &Path) -> Result<toml::Table, Error> {
    Ok(std::fs::read_to_string(path)?
        .parse()
        .map_err(|e| format!("invalid {}: {e}", path.display()))?)
}

/// A new random pair of keys.
#[cfg(test)]
pub fn test_keys() -> Keys {
    Keys::generate().unwrap()
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
        let dir = std::env::temp_dir().join(format!("k5-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k5.toml");
        let _ = std::fs::remove_file(&path);

        // Nothing is generated implicitly.
        assert!(load(&path).is_err());
        assert!(!path.exists());

        let keys = create(&path).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.k5(), keys.k5());

        // Existing keys are never overwritten.
        assert!(create(&path).is_err());
        assert_eq!(load(&path).unwrap().k5(), keys.k5());

        // Other settings are preserved when the section is updated.
        let mut config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        config.insert("other".to_string(), toml::Value::Integer(1));
        config["key"].as_table_mut().unwrap().remove("k5");
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        load(&path).unwrap();
        let config: toml::Table = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(config["other"].as_integer(), Some(1));
        assert_eq!(config["key"]["k5"].as_str(), Some(keys.k5().as_str()));

        // A missing section is an error, not regenerated.
        let mut without_key = config.clone();
        without_key.remove("key");
        std::fs::write(&path, toml::to_string(&without_key).unwrap()).unwrap();
        assert!(load(&path).is_err());

        // A tampered k5 id is rejected.
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace(&keys.k5(), &"0".repeat(keys.k5().len()));
        std::fs::write(&path, tampered).unwrap();
        assert!(load(&path).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sections() {
        let dir = std::env::temp_dir().join(format!("k5-sections-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k5.toml");
        let _ = std::fs::remove_file(&path);
        let keys = create(&path).unwrap();

        assert_eq!(load_section(&path, "iroh").unwrap(), None);
        let value = toml::Value::Table(toml::Table::from_iter([(
            "secret_key".to_string(),
            toml::Value::String("ab".to_string()),
        )]));
        store_section(&path, "iroh", value.clone()).unwrap();
        assert_eq!(load_section(&path, "iroh").unwrap(), Some(value));
        // The keys are kept.
        assert_eq!(load(&path).unwrap().k5(), keys.k5());
        assert!(store_section(&path, NAME, toml::Value::Boolean(true)).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
