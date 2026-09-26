// k5 desktop interface: opens the local identity and runs the window
// (`gui`), a front end of the k5 API (`k5lib::api`) that also talks to other
// k5s peer to peer (`k5net`).

mod gui;

use clap::Parser;

use k5lib::{
    api::{DEFAULT_NOTARY_KEY, K5},
    db::FsDb,
};

#[derive(Parser, Debug)]
#[command(version, about = "Terminal-style window: search the attestations, inspect the dossier of an identity, send it a signed or signcrypted message (peer to peer, or copied to the clipboard), sync attestations with it, and read the messages received", long_about = None)]
struct Cli {
    /// Configuration file with the keys, created by `k5cli init`. Its
    /// `[iroh]` section, with the peer-to-peer key, is added if missing.
    #[clap(long, default_value = "k5.toml")]
    config: std::path::PathBuf,
    /// Database directory: attestations in `<DB>/attestations`, received
    /// messages in `<DB>/inbox`.
    #[clap(long, default_value = "db")]
    db: std::path::PathBuf,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are ignored.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
    /// Do not go online: messages are only copied to the clipboard.
    #[clap(long)]
    offline: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let k5 = K5::open(&cli.config)?
        .with_db(FsDb::new(cli.db.join("attestations")))
        .with_inbox(FsDb::new(cli.db.join("inbox")))
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

    // The window runs on the main thread, outside any tokio runtime.
    gui::run(k5, cli.config, cli.offline)
}
