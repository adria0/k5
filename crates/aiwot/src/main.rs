// Notarizes an HTTPS URL using a remote Notary server and builds a
// presentation of it (`notarize`), or verifies such a presentation (`verify`).
//
// Platform specific behavior (X, GitHub, websites) lives in `plugins`.

mod key;
mod message;
mod plugins;

use std::time::Duration;

use base64::prelude::*;
use clap::{Args, Parser, Subcommand};
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

use message::SignedMessage;
use plugins::{Profile, Session, Target};

const AIWOT_VERSION: &str = "0.1";
const ATTESTATIONS_DIR: &str = "db/attestations";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

const DEFAULT_NOTARY_KEY: &str =
    "02f37514ced12c58460456a07b42042894f413ff63f9a3f0824fbe86e6c7da6764";

#[derive(Parser, Debug)]
#[command(version, about = "Notarize profiles with a remote TLSNotary server, and sign and verify messages with a hybrid post-quantum key", long_about = None)]
struct Cli {
    /// Configuration file. A hybrid Ed25519 + ML-DSA-44 signature key and a
    /// hybrid X25519MLKEM768 key encapsulation key are generated and stored in
    /// it if missing.
    #[clap(long, global = true, default_value = "aiwot.toml")]
    config: std::path::PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Notarize an HTTPS URL, writing a presentation to disk.
    Notarize(NotarizeArgs),
    /// Verify a signed message written by `sign` (listing the verified
    /// attestations of the signer found in `db/attestations/`), or an attestation
    /// record written by `notarize`. The file type is detected from its
    /// content.
    #[command(alias = "verify-msg")]
    Verify(VerifyArgs),
    /// Sign a message with the hybrid Ed25519 + ML-DSA-44 key, printing the
    /// signed message and writing it to a file.
    Sign(SignArgs),
}

#[derive(Args, Debug)]
struct SignArgs {
    /// Message to sign.
    msg: String,
    /// Output file.
    #[clap(long, default_value = "msg.md")]
    out: String,
}

#[derive(Args, Debug)]
struct NotarizeArgs {
    /// HTTPS URL to notarize. Tweet URLs are fetched through X's syndication
    /// endpoint.
    #[clap(default_value = "https://x.com/adria0/status/2102469944159989833?s=20")]
    url: String,
    /// Notary server host.
    #[clap(long, default_value = "134.122.76.100")]
    notary_host: String,
    /// Notary server port.
    #[clap(long, default_value_t = 7047)]
    notary_port: u16,
    /// Connect to the notary using TLS.
    #[clap(long)]
    notary_tls: bool,
    /// Maximum number of bytes sent to the server (request). Must not exceed
    /// the notary's limit.
    #[clap(long, default_value_t = 1 << 12)]
    max_sent: usize,
    /// Maximum number of bytes received from the server (response headers and
    /// body). Must not exceed the notary's limit.
    #[clap(long, default_value_t = 1 << 14)]
    max_recv: usize,
    /// Output presentation file.
    #[clap(long, default_value = "presentation.tlsn")]
    out: String,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Signed message (`msg.md`) or attestation record (`db/attestations/*.md`)
    /// to verify.
    #[clap(default_value = "msg.md")]
    file: String,
    /// Expected notary public key (compressed secp256k1, hex). Attestations
    /// signed by a different key are rejected.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let keys = key::load_or_create(&cli.config)?;
    eprintln!("AIWOT {AIWOT_VERSION} - aiwot:{}", keys.signing.aiwot());
    for section in &keys.created {
        let description = match *section {
            "key" => "hybrid Ed25519 + ML-DSA-44 signature key",
            "kem" => "hybrid X25519MLKEM768 key encapsulation key",
            other => other,
        };
        eprintln!("Created {description} in {}", cli.config.display());
    }

    match cli.command {
        Command::Notarize(args) => run_notarize(&args).await,
        Command::Verify(args) => run_verify(&args).await,
        Command::Sign(args) => run_sign(&args, &keys.signing).await,
    }
}

async fn run_notarize(args: &NotarizeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let target = plugins::target(&args.url)?;

    let (attestation, secrets, session_id) = notarize(args, &target).await?;

    let presentation = present(&attestation, &secrets)?;
    let presentation_bytes = bincode::serialize(&presentation)?;
    tokio::fs::write(&args.out, &presentation_bytes).await?;

    let verified = verify_presentation(presentation)?;
    let session = verified.session();
    match plugins::profile(&session) {
        Some(Ok(profile)) => {
            let record = Record {
                args,
                session_id: &session_id,
                verified: &verified,
                profile: &profile,
                presentation: &presentation_bytes,
            };
            println!("{}", record.store().await?);
        }
        Some(Err(err)) => eprintln!("No attestation record stored: {err}"),
        None => eprintln!(
            "No attestation record stored: {} is not a known profile.",
            verified.server_name
        ),
    }

    Ok(())
}

/// A notarization stored in `db/attestations/<aiwot>-<platform>-<user>.md`.
struct Record<'a> {
    args: &'a NotarizeArgs,
    session_id: &'a str,
    verified: &'a Verified,
    profile: &'a Profile,
    presentation: &'a [u8],
}

impl Record<'_> {
    /// Writes the record, returning its path.
    async fn store(&self) -> Result<String, Box<dyn std::error::Error>> {
        let Profile {
            platform,
            user,
            aiwot,
        } = self.profile;
        let file_name = format!("{aiwot}-{platform}-{user}.md").replace(['/', '\\'], "_");
        let path = format!("{ATTESTATIONS_DIR}/{file_name}");

        tokio::fs::create_dir_all(ATTESTATIONS_DIR).await?;
        tokio::fs::write(&path, self.to_markdown()).await?;

        Ok(path)
    }

    fn to_markdown(&self) -> String {
        let verified = self.verified;
        let (request_head, _) = split_http(&verified.sent);
        let (response_head, response_body) = split_http(&verified.recv);

        format!(
            "# info\n\
             \n\
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
            created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            profile = self.profile,
            url = self.args.url,
            server = verified.server_name,
            time = verified.time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            notary_host = self.args.notary_host,
            notary_port = self.args.notary_port,
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
fn record_binary(record: &str) -> Result<&str, Box<dyn std::error::Error>> {
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

async fn run_sign(args: &SignArgs, key: &key::SigningKey) -> Result<(), Box<dyn std::error::Error>> {
    let signed = SignedMessage::sign(key, &args.msg)?;
    let markdown = signed.to_markdown();

    // Check the output before handing it out.
    SignedMessage::parse(&markdown)?.verify()?;

    print!("{markdown}");
    tokio::fs::write(&args.out, &markdown).await?;
    eprintln!("Signed message written to {}", args.out);

    Ok(())
}

/// Verifies a signed message and lists the attestations of its signer.
async fn verify_msg(content: &str, notary_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let signed = SignedMessage::parse(content)?;
    signed.verify()?;

    println!("Valid signature from aiwot:{}", signed.from);

    let profiles = attested_by(&signed.from, notary_key).await?;
    if profiles.is_empty() {
        println!("Not attested by any profile in {ATTESTATIONS_DIR}/");
    }
    for profile in profiles {
        println!("Attested by {}:{}", profile.platform, profile.user);
    }

    Ok(())
}

/// Returns the profiles of the valid attestation records in
/// [`ATTESTATIONS_DIR`] whose aiwot is `aiwot`. Every candidate record is
/// fully verified; invalid ones are reported and skipped.
async fn attested_by(
    aiwot: &str,
    notary_key: &str,
) -> Result<Vec<Profile>, Box<dyn std::error::Error>> {
    let mut entries = match tokio::fs::read_dir(ATTESTATIONS_DIR).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let prefix = format!("{}-", aiwot.to_ascii_lowercase());
    let mut paths = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.starts_with(&prefix) && name.ends_with(".md") {
            paths.push(entry.path());
        }
    }
    paths.sort();

    let mut profiles = Vec::new();
    for path in paths {
        let profile = async {
            let record = tokio::fs::read_to_string(&path).await?;
            let verified = verify_record(&record, notary_key)?;
            let profile = plugins::profile(&verified.session())
                .ok_or("not a known profile")??;
            if !profile.aiwot.eq_ignore_ascii_case(aiwot) {
                return Err(format!("attests aiwot:{}", profile.aiwot).into());
            }
            Ok::<_, Box<dyn std::error::Error>>(profile)
        }
        .await;

        match profile {
            Ok(profile) => profiles.push(profile),
            Err(e) => eprintln!("Ignoring invalid attestation {}: {e}", path.display()),
        }
    }

    Ok(profiles)
}

/// Verifies an attestation record, which must be signed by `notary_key`.
fn verify_record(record: &str, notary_key: &str) -> Result<Verified, Box<dyn std::error::Error>> {
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

async fn run_verify(args: &VerifyArgs) -> Result<(), Box<dyn std::error::Error>> {
    let content = tokio::fs::read_to_string(&args.file).await?;

    if content.starts_with("# from") {
        verify_msg(&content, &args.notary_key).await
    } else if content.starts_with("# info") {
        verify_attestation(&content, &args.notary_key)
    } else {
        Err(format!(
            "{} is neither a signed message (`# from`) nor an attestation record (`# info`)",
            args.file
        )
        .into())
    }
}

/// Verifies an attestation record and prints its profile, or the full
/// transcript if no plugin handles it.
fn verify_attestation(record: &str, notary_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let verified = verify_record(record, notary_key)?;

    if let Some(profile) = plugins::profile(&verified.session()) {
        println!("{}", profile?);
        return Ok(());
    }

    println!(
        "Presentation is signed with {} key: {}",
        verified.alg, verified.key_hex
    );
    println!("-------------------------------------------------------------------");
    println!(
        "Verified that the data below came from a session with {} at {}.",
        verified.server_name, verified.time
    );
    println!("Undisclosed data is shown as X.\n");
    println!("Data sent:\n\n{}\n", verified.sent);
    println!("Data received:\n\n{}\n", verified.recv);
    println!("-------------------------------------------------------------------");

    Ok(())
}
async fn notarize(
    args: &NotarizeArgs,
    target: &Target,
) -> Result<(Attestation, Secrets, String), Box<dyn std::error::Error>> {
    let notary_client = NotaryClient::builder()
        .host(args.notary_host.clone())
        .port(args.notary_port)
        .enable_tls(args.notary_tls)
        .build()?;

    let notarization_request = NotarizationRequest::builder()
        .max_sent_data(args.max_sent)
        .max_recv_data(args.max_recv)
        .build()?;

    println!(
        "Requesting notarization from {}:{}",
        args.notary_host, args.notary_port
    );

    let Accepted {
        io: notary_connection,
        id: session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await?;

    println!("Notarization session accepted: {session_id}");

    let prover_config = ProverConfig::builder()
        .server_name(target.host.as_str())
        .protocol_config(
            ProtocolConfig::builder()
                .max_sent_data(args.max_sent)
                .max_recv_data(args.max_recv)
                .build()?,
        )
        .crypto_provider(CryptoProvider::default())
        .build()?;

    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    let client_socket =
        tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;

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

    println!(
        "Starting an MPC TLS connection with {}, requesting {}",
        target.host, target.path
    );

    let size_hint = |err: &dyn std::fmt::Display| {
        format!(
            "{err}\n\nThe connection failed. If the log above says \"attempted to receive more \
             data than was configured\", the response is larger than --max-recv ({}). Raise \
             --max-recv; the notary must allow it too (NS_NOTARIZATION__MAX_RECV_DATA on the \
             notary server).",
            args.max_recv
        )
    };

    let response = request_sender
        .send_request(request)
        .await
        .map_err(|e| size_hint(&e))?;

    println!("Got a response from the server: {}", response.status());

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

    println!("Notarization complete!");

    Ok((attestation, secrets, session_id))
}

/// Returns the sent and received ranges to commit to and reveal: the whole
/// transcript except the User-Agent header value. The response is treated as
/// opaque bytes so any content type or transfer encoding is supported.
fn reveal_ranges(
    transcript: &Transcript,
) -> Result<(RangeSet<usize>, RangeSet<usize>), Box<dyn std::error::Error>> {
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
fn present(
    attestation: &Attestation,
    secrets: &Secrets,
) -> Result<Presentation, Box<dyn std::error::Error>> {
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
struct Verified {
    alg: String,
    key_hex: String,
    server_name: String,
    time: chrono::DateTime<chrono::Utc>,
    sent: String,
    recv: String,
}

impl Verified {
    fn session(&self) -> Session<'_> {
        Session {
            server_name: &self.server_name,
            sent: &self.sent,
            recv: &self.recv,
        }
    }
}

/// Verifies a presentation. The caller decides whether to trust the notary
/// key.
fn verify_presentation(presentation: Presentation) -> Result<Verified, Box<dyn std::error::Error>> {
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

