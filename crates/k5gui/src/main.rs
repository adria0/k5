// k5 desktop interface: opens the local identity (creating it on the first
// run) and runs the window (`gui`), a front end of the k5 API (`k5lib::api`)
// that also talks to other k5s peer to peer (`k5net`).

mod gui;

use std::path::Path;

use clap::Parser;

use k5lib::{
    api::{NotaryConfig, DEFAULT_NOTARY_KEY, K5},
    db::FsDb,
};

#[derive(Parser, Debug)]
#[command(version, about = "Terminal-style window: search the attestations, inspect the dossier of an identity, send it a signed or signcrypted message (peer to peer, or copied to the clipboard), sync attestations with it, read the messages received, and attest your profiles with a remote TLSNotary notary", long_about = None)]
struct Cli {
    /// Configuration file with the keys, created with new keys if missing
    /// (as `k5cli init` does). Its `[iroh]` section, with the peer-to-peer
    /// key, is added if missing.
    #[clap(long, default_value = "k5.toml")]
    config: std::path::PathBuf,
    /// Database directory: attestations in `<DB>/attestations`, received
    /// messages in `<DB>/inbox`, copies of the messages sent in `<DB>/sent`,
    /// TLSNotary presentations in `<DB>/presentations`.
    #[clap(long, default_value = "db")]
    db: std::path::PathBuf,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are ignored.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
    /// TLSNotary notary server that attests your profiles (X, GitHub,
    /// website). It must sign with `--notary-key`. Without it, profiles
    /// cannot be attested from the window.
    #[clap(long)]
    notary_host: Option<String>,
    /// Notary server port.
    #[clap(long, default_value_t = 7047)]
    notary_port: u16,
    /// Connect to the notary using TLS.
    #[clap(long)]
    notary_tls: bool,
    /// Maximum number of bytes sent to the attested server (request). Must
    /// not exceed the notary's limit.
    #[clap(long, default_value_t = 1 << 12)]
    max_sent: usize,
    /// Maximum number of bytes received from the attested server. Must not
    /// exceed the notary's limit.
    #[clap(long, default_value_t = 1 << 14)]
    max_recv: usize,
    /// Do not go online: messages are only copied to the clipboard.
    #[clap(long)]
    offline: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let (k5, created) = open_or_init(&cli.config)?;
    if created {
        eprintln!(
            "Created {} with new keys: k5:{}",
            cli.config.display(),
            k5.k5()
        );
    }
    let k5 = k5
        .with_db(FsDb::new(cli.db.join("attestations")))
        .with_inbox(FsDb::new(cli.db.join("inbox")))
        .with_sent(FsDb::new(cli.db.join("sent")))
        .with_notary_key(&cli.notary_key);
    let created = tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(k5.ensure_self_attestation())?;
    if let Some(created) = created {
        if let Some(reason) = created.replaced {
            eprintln!("Replacing self attestation {}: {reason}", created.path);
        }
        eprintln!("Created self attestation {}", created.path);
    }

    let notary = cli.notary_host.map(|host| NotaryConfig {
        host,
        port: cli.notary_port,
        tls: cli.notary_tls,
        max_sent: cli.max_sent,
        max_recv: cli.max_recv,
    });
    let attesting = gui::Attesting {
        notary,
        presentations: cli.db.join("presentations"),
    };

    // The window runs on the main thread, outside any tokio runtime.
    gui::run(k5, cli.config, cli.offline, attesting)
}

/// Opens the keys of the config file `config`, or, if there is none, creates
/// it with new keys (and its directory), as `k5cli init` does. Returns
/// whether it was created.
fn open_or_init(config: &Path) -> anyhow::Result<(K5, bool)> {
    if config.try_exists()? {
        return Ok((K5::open(config)?, false));
    }
    if let Some(dir) = config.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }

    Ok((K5::init(config)?, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_or_init() {
        let dir = std::env::temp_dir().join(format!("k5gui-init-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
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
}
