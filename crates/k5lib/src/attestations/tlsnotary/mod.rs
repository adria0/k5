// TLSNotary attestations.
//
// A URL is notarized with a remote Notary server using MPC-TLS. The resulting
// presentation reveals the whole request (except the User-Agent value) and
// response, and is stored as a record with an `# info` section, for humans
// only, and a `# binary` section with the base64 encoded presentation. The
// profile is extracted from the verified session by the `plugins`.

use std::time::Duration;

use base64::prelude::*;
use http_body_util::Empty;
use hyper::{body::Bytes, Request};
use hyper_util::rt::TokioIo;
use rangeset::{Difference, RangeSet};
use spansy::Spanned;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{
    attestation::Attestation,
    presentation::{Presentation, PresentationOutput},
    request::RequestConfig,
    signing::VerifyingKey,
    transcript::{Transcript, TranscriptCommitConfig},
    CryptoProvider, Secrets,
};
use tlsn_formats::http::Requests;
use tlsn_prover::{Prover, ProverConfig};

pub mod plugins;

use super::{Error, Profile};
use crate::db::Db;
use plugins::{Session, Target};

/// Type of TLSNotary attestation records.
pub const RECORD_TYPE: &str = "tlsn";

const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

/// Notary server and protocol limits.
#[derive(Clone)]
pub struct NotaryConfig {
    pub host: String,
    pub port: u16,
    /// Connect to the notary using TLS.
    pub tls: bool,
    /// Maximum number of bytes sent to the server.
    pub max_sent: usize,
    /// Maximum number of bytes received from the server.
    pub max_recv: usize,
}

/// The result of [`attest`].
pub struct Notarized {
    /// Path of the stored attestation record, or why none was stored (no
    /// plugin recognizes the profile).
    pub record: Result<String, String>,
}

/// Notarizes `url`, writing the presentation to `presentation_path` and, if a
/// plugin extracts a profile from the session, an attestation record to
/// `db`. `progress` receives a message at each step of the notarization.
pub async fn attest(
    db: &dyn Db,
    config: &NotaryConfig,
    url: &str,
    presentation_path: &str,
    progress: &mut dyn FnMut(&str),
) -> Result<Notarized, Error> {
    let target = plugins::target(url)?;

    let (attestation, secrets, session_id) = notarize(config, &target, progress).await?;

    let presentation = present(&attestation, &secrets)?;
    let presentation_bytes = bincode::serialize(&presentation)?;
    tokio::fs::write(presentation_path, &presentation_bytes).await?;

    let verified = verify_presentation(presentation)?;
    let record = match verified.profile() {
        Some(Ok(profile)) => {
            let record = Record {
                url,
                config,
                session_id: &session_id,
                verified: &verified,
                profile: &profile,
                presentation: &presentation_bytes,
            };
            Ok(record.store(db).await?)
        }
        Some(Err(err)) => Err(err.to_string()),
        None => Err(format!("{} is not a known profile.", verified.server_name)),
    };

    Ok(Notarized { record })
}

/// A notarization, stored as the entry `<k5>-<platform>-<user>.md`.
struct Record<'a> {
    url: &'a str,
    config: &'a NotaryConfig,
    session_id: &'a str,
    verified: &'a Verified,
    profile: &'a Profile,
    presentation: &'a [u8],
}

impl Record<'_> {
    /// Stores the record in `db`, returning where.
    async fn store(&self, db: &dyn Db) -> Result<String, Error> {
        let Profile { platform, user, k5 } = self.profile;
        let file_name = format!("{k5}-{platform}-{user}.md").replace(['/', '\\'], "_");

        db.put(&file_name, &self.to_markdown()).await?;

        Ok(db.location(&file_name))
    }

    fn to_markdown(&self) -> String {
        let verified = self.verified;
        let (request_head, _) = split_http(&verified.sent);
        let (response_head, response_body) = split_http(&verified.recv);

        format!(
            "# info\n\
             \n\
             - Type: {record_type}\n\
             - Fake: false\n\
             - Created: {created}\n\
             - Profile: {profile}\n\
             - URL: {url}\n\
             - Server: {server}\n\
             - TLS session time: {time}\n\
             - Notary: {notary_host}:{notary_port}\n\
             - Notary session id: {session_id}\n\
             - Notary key: {alg} {key}\n\
             - Presentation size: {size} bytes\n\
             \n\
             ## Request\n\
             \n\
             Undisclosed data is shown as X.\n\
             \n\
             ```http\n{request_head}\n```\n\
             \n\
             ## Response headers\n\
             \n\
             ```http\n{response_head}\n```\n\
             \n\
             ## Response body\n\
             \n\
             ```\n{response_body}\n```\n\
             \n\
             # binary\n\
             \n\
             {binary}\n",
            record_type = RECORD_TYPE,
            created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            profile = self.profile,
            url = self.url,
            server = verified.server_name,
            time = verified
                .time
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            notary_host = self.config.host,
            notary_port = self.config.port,
            session_id = self.session_id,
            alg = verified.alg,
            key = verified.key_hex,
            size = self.presentation.len(),
            response_body = response_body.trim_end(),
            binary = BASE64_STANDARD.encode(self.presentation),
        )
    }
}

/// Returns the base64 `# binary` section of an attestation record.
fn record_binary(record: &str) -> Result<&str, Error> {
    if !record.starts_with("# info") {
        return Err("not an attestation record: missing `# info` section".into());
    }

    Ok(record
        .split_once("\n# binary\n")
        .map(|(_, section)| section.trim())
        .filter(|section| !section.is_empty())
        .ok_or("attestation record has no `# binary` section")?)
}

/// Splits an HTTP message into its head (with `\n` line endings) and body.
fn split_http(message: &str) -> (String, &str) {
    let (head, body) = message.split_once("\r\n\r\n").unwrap_or((message, ""));

    (head.replace("\r\n", "\n"), body)
}

/// Verifies a TLSNotary record, which must be signed by `notary_key`.
pub fn verify(record: &str, notary_key: &str) -> Result<Verified, Error> {
    let presentation: Presentation =
        bincode::deserialize(&BASE64_STANDARD.decode(record_binary(record)?)?)?;

    let verified = verify_presentation(presentation)?;
    if !verified.key_hex.eq_ignore_ascii_case(notary_key) {
        return Err(format!(
            "presentation is signed with unexpected {} key {}, expected {}",
            verified.alg, verified.key_hex, notary_key
        )
        .into());
    }

    Ok(verified)
}

async fn notarize(
    config: &NotaryConfig,
    target: &Target,
    progress: &mut dyn FnMut(&str),
) -> Result<(Attestation, Secrets, String), Error> {
    let notary_client = NotaryClient::builder()
        .host(config.host.clone())
        .port(config.port)
        .enable_tls(config.tls)
        .build()?;

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(config.max_sent)
        .max_recv_data(config.max_recv)
        .build()?;

    progress(&format!(
        "Requesting notarization from {}:{}",
        config.host, config.port
    ));

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await?;

    progress(&format!("Notarization session accepted: {session_id}"));

    let prover_config = ProverConfig::builder()
        .server_name(target.host.as_str())
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(config.max_sent)
                .max_recv_data(config.max_recv)
                .build()?,
        )
        .crypto_provider(CryptoProvider::default())
        .build()?;

    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    let client_socket = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;

    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

    tokio::spawn(connection);

    let host_header = if target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let request = Request::builder()
        .uri(target.path.as_str())
        .header("Host", host_header)
        .header("Accept", "*/*")
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .body(Empty::<Bytes>::new())?;

    progress(&format!(
        "Starting an MPC TLS connection with {}, requesting {}",
        target.host, target.path
    ));

    let size_hint = |err: &dyn std::fmt::Display| {
        format!(
            "{err}\n\nThe connection failed. If the log above says \"attempted to receive more \
             data than was configured\", the response is larger than --max-recv ({}). Raise \
             --max-recv; the notary must allow it too (NS_NOTARIZATION__MAX_RECV_DATA on the \
             notary server).",
            config.max_recv
        )
    };

    let response = request_sender
        .send_request(request)
        .await
        .map_err(|e| size_hint(&e))?;

    progress(&format!(
        "Got a response from the server: {}",
        response.status()
    ));

    if !response.status().is_success() {
        return Err(format!("unexpected status: {}", response.status()).into());
    }

    // Read the whole body so the full response ends up in the transcript.
    http_body_util::BodyExt::collect(response.into_body())
        .await
        .map_err(|e| size_hint(&e))?;

    let mut prover = prover_task.await?.map_err(|e| size_hint(&e))?;

    let (sent, recv) = reveal_ranges(prover.transcript())?;

    let mut builder = TranscriptCommitConfig::builder(prover.transcript());
    builder.commit_sent(&sent)?;
    builder.commit_recv(&recv)?;
    let transcript_commit = builder.build()?;

    let mut builder = RequestConfig::builder();
    builder.transcript_commit(transcript_commit);
    let request_config = builder.build()?;

    #[allow(deprecated)]
    let (attestation, secrets) = prover.notarize(&request_config).await?;

    progress("Notarization complete!");

    Ok((attestation, secrets, session_id))
}

/// Returns the sent and received ranges to commit to and reveal: the whole
/// transcript except the User-Agent header value. The response is treated as
/// opaque bytes so any content type or transfer encoding is supported.
fn reveal_ranges(transcript: &Transcript) -> Result<(RangeSet<usize>, RangeSet<usize>), Error> {
    let (sent_len, recv_len) = transcript.len();

    let request = Requests::new(Bytes::copy_from_slice(transcript.sent()))
        .next()
        .ok_or("no request in transcript")??;

    let mut sent = RangeSet::from(0..sent_len);
    for header in request.headers_with_name("user-agent") {
        sent = sent.difference(header.value.span().indices());
    }

    Ok((sent, RangeSet::from(0..recv_len)))
}

/// Builds a presentation revealing the committed ranges.
fn present(attestation: &Attestation, secrets: &Secrets) -> Result<Presentation, Error> {
    let (sent, recv) = reveal_ranges(secrets.transcript())?;

    let mut builder = secrets.transcript_proof_builder();
    builder.reveal_sent(&sent)?;
    builder.reveal_recv(&recv)?;
    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut builder = attestation.presentation_builder(&provider);
    builder
        .identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);

    Ok(builder.build()?)
}

/// The authenticated content of a verified presentation.
pub struct Verified {
    pub alg: String,
    pub key_hex: String,
    pub server_name: String,
    pub time: chrono::DateTime<chrono::Utc>,
    pub sent: String,
    pub recv: String,
}

impl Verified {
    pub fn session(&self) -> Session<'_> {
        Session {
            server_name: &self.server_name,
            sent: &self.sent,
            recv: &self.recv,
        }
    }

    /// The profile proven by the session, or `None` if no plugin handles it.
    pub fn profile(&self) -> Option<Result<Profile, Error>> {
        plugins::profile(&self.session())
    }
}

/// Verifies a presentation. The caller decides whether to trust the notary
/// key.
fn verify_presentation(presentation: Presentation) -> Result<Verified, Error> {
    let VerifyingKey { alg, data } = presentation.verifying_key();
    let alg = alg.to_string();
    let key_hex = hex::encode(data);

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&CryptoProvider::default())?;

    let server_name = server_name.ok_or("server name not revealed")?.to_string();
    let mut partial_transcript = transcript.ok_or("transcript not revealed")?;
    partial_transcript.set_unauthed(b'X');

    Ok(Verified {
        alg,
        key_hex,
        server_name,
        time: chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time),
        sent: String::from_utf8_lossy(partial_transcript.sent_unsafe()).into_owned(),
        recv: String::from_utf8_lossy(partial_transcript.received_unsafe()).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_binary() {
        let record = "# info\n\n- Type: tlsn\n\n## Request\n\n# binary\n\nAAAA\n";
        assert_eq!(record_binary(record).unwrap(), "AAAA");

        assert!(record_binary("# from\n").is_err());
        assert!(record_binary("# info\n\n- Type: tlsn\n").is_err());
    }
}
