// k5gui: the k5 window (`gui`), a front end of the k5 API (`k5lib::api`) that
// also talks to other k5s peer to peer (`k5net`). [`start`] opens the local
// identity (creating it on the first run) and runs the window; the desktop
// binary (`main.rs`) calls it with its command line, the Android app
// (`k5android`) with the app's private storage.
//
// Notary settings come from the caller or, if it gives none, from the
// `[notary]` section of the config file:
//
// [notary]
// host = "notary.example.com"
// port = 7047          # default 7047
// tls = true           # default false
// max_sent = 4096      # default 4096
// max_recv = 16384     # default 16384

pub mod clipboard;
pub mod gui;
pub mod qr;
pub mod scanner;

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use k5lib::{
    api::{NotaryConfig, K5},
    db::FsDb,
    key,
};

/// Default notary port.
pub const DEFAULT_NOTARY_PORT: u16 = 7047;
/// Default limits of a notarization, in bytes: sent to and received from the
/// attested server.
pub const DEFAULT_MAX_SENT: usize = 1 << 12;
pub const DEFAULT_MAX_RECV: usize = 1 << 14;

/// Section of the config file with the notary settings.
const NOTARY_SECTION: &str = "notary";

/// How to start the window.
pub struct Options {
    /// Config file with the keys, created with new keys if missing.
    pub config: PathBuf,
    /// Database directory: attestations, inbox, sent messages and TLSNotary
    /// presentations.
    pub db: PathBuf,
    /// Expected notary public key (compressed secp256k1, hex).
    pub notary_key: String,
    /// The notary that attests profiles; `None` for the `[notary]` section
    /// of the config file, if any.
    pub notary: Option<NotaryConfig>,
    /// Do not go online: messages are only copied to the clipboard.
    pub offline: bool,
    /// Email attestations can be made (proving takes minutes and a lot of
    /// memory: not on phones).
    pub email_proofs: bool,
    /// The camera, to read tickets from QR codes; `None` if there is none.
    pub scanner: Option<Box<dyn scanner::Scanner>>,
}

/// Opens the local identity, creating it on the first run, and runs the
/// window until it is closed. Must run on the main thread, outside any tokio
/// runtime.
pub fn start(options: Options) -> anyhow::Result<()> {
    let (k5, created) = open_or_init(&options.config)?;
    if created {
        log::info!(
            "Created {} with new keys: k5:{}",
            options.config.display(),
            k5.k5()
        );
    }
    let k5 = k5
        .with_db(FsDb::new(options.db.join("attestations")))
        .with_inbox(FsDb::new(options.db.join("inbox")))
        .with_sent(FsDb::new(options.db.join("sent")))
        .with_notary_key(&options.notary_key);
    let created = tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(k5.ensure_self_attestation())?;
    if let Some(created) = created {
        if let Some(reason) = created.replaced {
            log::info!("Replacing self attestation {}: {reason}", created.path);
        }
        log::info!("Created self attestation {}", created.path);
    }

    let notary = match options.notary {
        Some(notary) => Some(notary),
        None => notary_section(&options.config)?,
    };
    let attesting = gui::Attesting {
        notary,
        presentations: options.db.join("presentations"),
        email_proofs: options.email_proofs,
    };

    gui::run(
        k5,
        options.config,
        options.offline,
        attesting,
        options.scanner,
    )
}

/// Opens the keys of the config file `config`, or, if there is none, creates
/// it with new keys (and its directory), as `k5cli init` does. Returns
/// whether it was created.
pub fn open_or_init(config: &Path) -> anyhow::Result<(K5, bool)> {
    if config.try_exists()? {
        return Ok((K5::open(config)?, false));
    }
    if let Some(dir) = config.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }

    Ok((K5::init(config)?, true))
}

/// The notary of the `[notary]` section of the config file `config`, `None`
/// if there is none.
fn notary_section(config: &Path) -> anyhow::Result<Option<NotaryConfig>> {
    let Some(section) = key::load_section(config, NOTARY_SECTION)? else {
        return Ok(None);
    };
    let invalid =
        |field: &str| format!("invalid [{NOTARY_SECTION}] {field} in {}", config.display());
    let number = |field: &str, default: usize| -> anyhow::Result<usize> {
        match section.get(field) {
            None => Ok(default),
            Some(value) => value
                .as_integer()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| anyhow!(invalid(field))),
        }
    };

    let host = section
        .get("host")
        .and_then(toml::Value::as_str)
        .with_context(|| invalid("host"))?
        .to_string();
    let port = u16::try_from(number("port", DEFAULT_NOTARY_PORT.into())?)
        .map_err(|_| anyhow!(invalid("port")))?;
    let tls = match section.get("tls") {
        None => false,
        Some(value) => value.as_bool().with_context(|| invalid("tls"))?,
    };

    Ok(Some(NotaryConfig {
        host,
        port,
        tls,
        max_sent: number("max_sent", DEFAULT_MAX_SENT)?,
        max_recv: number("max_recv", DEFAULT_MAX_RECV)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("k5gui-{name}-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_open_or_init() {
        let dir = temp_dir("init");
        let config = dir.join("new").join("k5.toml");

        // The first run creates the config, in a new directory.
        let (created, was_created) = open_or_init(&config).unwrap();
        assert!(was_created);
        assert!(config.exists());

        // The next ones open it: the same keys, never replaced.
        let (opened, was_created) = open_or_init(&config).unwrap();
        assert!(!was_created);
        assert_eq!(opened.k5(), created.k5());

        // An invalid config is an error, not replaced with new keys.
        std::fs::write(&config, "not toml [").unwrap();
        assert!(open_or_init(&config).is_err());
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "not toml [");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_notary_section() {
        let dir = temp_dir("notary");
        let config = dir.join("k5.toml");
        open_or_init(&config).unwrap();
        let set = |section: &str| {
            let value: toml::Value = toml::from_str(section).unwrap();
            key::store_section(&config, NOTARY_SECTION, value).unwrap();
        };

        // None configured.
        assert!(notary_section(&config).unwrap().is_none());

        // Only the host: the defaults.
        set("host = \"notary.example.com\"");
        let notary = notary_section(&config).unwrap().unwrap();
        assert_eq!(notary.host, "notary.example.com");
        assert_eq!(notary.port, DEFAULT_NOTARY_PORT);
        assert!(!notary.tls);
        assert_eq!(
            (notary.max_sent, notary.max_recv),
            (DEFAULT_MAX_SENT, DEFAULT_MAX_RECV)
        );

        // Everything.
        set("host = \"n\"\nport = 443\ntls = true\nmax_sent = 1\nmax_recv = 2");
        let notary = notary_section(&config).unwrap().unwrap();
        assert_eq!(
            (notary.port, notary.tls, notary.max_sent, notary.max_recv),
            (443, true, 1, 2)
        );

        // Invalid values are errors.
        for section in [
            "port = 7047",
            "host = \"n\"\nport = 70000",
            "host = \"n\"\ntls = \"yes\"",
        ] {
            set(section);
            assert!(notary_section(&config).is_err(), "{section}");
        }
        // The keys are kept.
        assert!(open_or_init(&config).is_ok());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
