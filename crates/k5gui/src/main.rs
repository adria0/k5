// k5 desktop interface: the command line of the k5 window (`k5gui::start`).

use clap::Parser;

use k5lib::api::{NotaryConfig, DEFAULT_NOTARY_KEY};

use k5gui::{Options, DEFAULT_MAX_RECV, DEFAULT_MAX_SENT, DEFAULT_NOTARY_PORT};

#[derive(Parser, Debug)]
#[command(version, about = "Terminal-style window: search the attestations, inspect the dossier of an identity, send it a signed or signcrypted message (peer to peer, or copied to the clipboard), sync attestations with it, read the messages received, and attest your profiles with a remote TLSNotary notary", long_about = None)]
struct Cli {
    /// Configuration file with the keys, created with new keys if missing
    /// (as `k5cli init` does). Its `[iroh]` section, with the peer-to-peer
    /// key, is added if missing; its `[notary]` section, if any, sets the
    /// notary when `--notary-host` is not given.
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
    /// website). It must sign with `--notary-key`. Without it (nor a
    /// `[notary]` section in the config file), profiles cannot be attested
    /// from the window.
    #[clap(long)]
    notary_host: Option<String>,
    /// Notary server port.
    #[clap(long, default_value_t = DEFAULT_NOTARY_PORT)]
    notary_port: u16,
    /// Connect to the notary using TLS.
    #[clap(long)]
    notary_tls: bool,
    /// Maximum number of bytes sent to the attested server (request). Must
    /// not exceed the notary's limit.
    #[clap(long, default_value_t = DEFAULT_MAX_SENT)]
    max_sent: usize,
    /// Maximum number of bytes received from the attested server. Must not
    /// exceed the notary's limit.
    #[clap(long, default_value_t = DEFAULT_MAX_RECV)]
    max_recv: usize,
    /// Do not go online: messages are only copied to the clipboard.
    #[clap(long)]
    offline: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    log::set_logger(&Stderr).map_err(|e| anyhow::anyhow!("{e}"))?;
    log::set_max_level(log::LevelFilter::Info);

    k5gui::start(Options {
        config: cli.config,
        db: cli.db,
        notary_key: cli.notary_key,
        notary: cli.notary_host.map(|host| NotaryConfig {
            host,
            port: cli.notary_port,
            tls: cli.notary_tls,
            max_sent: cli.max_sent,
            max_recv: cli.max_recv,
        }),
        offline: cli.offline,
        // No camera on the desktop: tickets are pasted.
        scanner: None,
    })
}

/// Prints k5gui's messages (not those of its dependencies) on stderr.
struct Stderr;

impl log::Log for Stderr {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("k5gui")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}", record.args());
        }
    }

    fn flush(&self) {}
}
