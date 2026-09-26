// A notary server run in-process, used when no notary host is given.
//
// It listens on a free localhost port, without TLS nor authorization, and
// signs attestations with the secp256k1 key embedded in the binary
// (`local-notary.pem`), whose public key is the default notary key the
// verifier expects ([`DEFAULT_NOTARY_KEY`]). The notary server only loads keys
// from a file, so the key is written to a temporary file while it runs.

use std::{path::PathBuf, time::Duration};

use k256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use notary_server::{NotarizationProperties, NotaryServerProperties};
use tokio::task::JoinHandle;

#[cfg(doc)]
use k5lib::api::DEFAULT_NOTARY_KEY;
use k5lib::{api::NotaryConfig, Error};

const HOST: &str = "127.0.0.1";

/// Signing key of the local notary (PKCS#8 PEM).
const KEY_PEM: &str = include_str!("../local-notary.pem");

/// A running local notary server, stopped when dropped.
pub struct LocalNotary {
    /// Configuration to connect to the notary.
    pub config: NotaryConfig,
    /// Public key the notary signs with (compressed secp256k1, hex).
    pub key_hex: String,
    server: JoinHandle<()>,
    key_path: PathBuf,
}

impl Drop for LocalNotary {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_file(&self.key_path);
    }
}

/// Starts a local notary accepting up to `max_sent` and `max_recv` bytes.
pub async fn start(max_sent: usize, max_recv: usize) -> Result<LocalNotary, Error> {
    let key_hex = public_key_hex()?;

    let key_path = std::env::temp_dir().join(format!("k5-local-notary-{}.pem", std::process::id()));
    tokio::fs::write(&key_path, KEY_PEM).await?;

    // Pick a free port. The listener is dropped so the server can bind it.
    let port = std::net::TcpListener::bind((HOST, 0))?.local_addr()?.port();

    let properties = NotaryServerProperties {
        host: HOST.to_string(),
        port,
        notarization: NotarizationProperties {
            max_sent_data: max_sent,
            max_recv_data: max_recv,
            private_key_path: Some(key_path.to_string_lossy().into_owned()),
            ..Default::default()
        },
        ..Default::default()
    };

    let server = tokio::spawn(async move {
        if let Err(err) = notary_server::run_server(&properties).await {
            eprintln!("Local notary server failed: {err}");
        }
    });
    // From here, dropping `local` stops the server and removes the key file.
    let local = LocalNotary {
        config: NotaryConfig {
            host: HOST.to_string(),
            port,
            tls: false,
            max_sent,
            max_recv,
        },
        key_hex,
        server,
        key_path,
    };

    // Wait for the server to listen.
    let mut attempts = 0;
    while tokio::net::TcpStream::connect((HOST, port)).await.is_err() {
        attempts += 1;
        if local.server.is_finished() || attempts > 100 {
            return Err(format!("local notary server did not start on {HOST}:{port}").into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Ok(local)
}

/// Public key of the embedded signing key (compressed, hex).
fn public_key_hex() -> Result<String, Error> {
    let key = SigningKey::from_pkcs8_pem(KEY_PEM)
        .map_err(|err| format!("invalid embedded local notary key: {err}"))?;

    Ok(hex::encode(
        key.verifying_key().to_encoded_point(true).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_is_the_default_notary_key() {
        assert_eq!(public_key_hex().unwrap(), k5lib::api::DEFAULT_NOTARY_KEY);
    }
}
