// aiwot command line: notarize and keysign attestations of aiwot profiles,
// sign messages with the OpenPGP post-quantum key, and verify both.
//
// Attestations live in `attestations`: TLSNotary (with its platform plugins
// for X, GitHub and websites) and key sign party.

mod attestations;
mod fakegraph;
mod graph;
mod key;
mod message;
mod parallel;
mod signcrypt;

use clap::{Args, Parser, Subcommand};

use attestations::{keysignparty, tlsnotary, Attested};
use key::Keys;

const DEFAULT_NOTARY_KEY: &str =
    "02f37514ced12c58460456a07b42042894f413ff63f9a3f0824fbe86e6c7da6764";

#[derive(Parser, Debug)]
#[command(version, about = "Notarize profiles with a remote TLSNotary server, and sign and verify messages with an OpenPGP post-quantum key", long_about = None)]
struct Cli {
    /// Configuration file with the keys, created by `init`.
    #[clap(long, global = true, default_value = "aiwot.toml")]
    config: std::path::PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create the configuration file with a new OpenPGP key: a MlDsa65Ed25519
    /// signing key with a MlKem768X25519 encryption subkey (post-quantum
    /// composite algorithms). Fails if the file already exists.
    Init,
    /// Print your aiwot.
    Me,
    /// Create, list, search, audit, export and merge attestations.
    Attest(AttestArgs),
    /// Sign, signcrypt and verify messages.
    Msg(MsgArgs),
    /// Generate a deterministic fake social graph: identities in `db/ids/`,
    /// keysigning each other like a human social network (all reachable from
    /// your aiwot), with self attestations and fake X, GitHub and website
    /// attestations, all stored in `db/attestations/` and marked as fake.
    /// Audits the result.
    Fakegraph(FakegraphArgs),
    /// Write a Graphviz digraph of the verified attestations: keysigns
    /// between aiwots, and the social profiles of each aiwot.
    Makedot(MakedotArgs),
    #[cfg(feature = "zkemail")]
    /// Generate a Plonky2 proof for a DKIM-signed email.
    Zkemail(ZkemailArgs),
}

#[cfg(feature = "zkemail")]
#[derive(Args, Debug)]
struct ZkemailArgs {
    /// DKIM-signed RFC 5322 email file.
    eml: std::path::PathBuf,
    /// JSON file containing the trusted DKIM domain, selector, and TXT record.
    dkim: std::path::PathBuf,
    /// File to which the serialized Plonky2 proof is written.
    #[clap(long)]
    output: std::path::PathBuf,
}

#[derive(Args, Debug)]
struct MakedotArgs {
    /// Output file.
    #[clap(long, default_value = "graph.dot")]
    out: String,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are ignored.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Args, Debug)]
struct FakegraphArgs {
    /// Number of identities, up to 500.
    n: usize,
    /// Seed of the identities and connections, in hex (0x...) or decimal
    /// [default: 0xdeadcafe].
    seed: Option<String>,
}

#[derive(Args, Debug)]
struct MsgArgs {
    #[command(subcommand)]
    command: MsgCommand,
}

#[derive(Subcommand, Debug)]
enum MsgCommand {
    /// Sign a message with the MlDsa65Ed25519 signing key, printing the
    /// OpenPGP signed message and writing it to a file.
    Sign(SignArgs),
    /// Sign a message and encrypt it to an aiwot, using the MlKem768X25519
    /// encryption subkey of its self attestation in `db/attestations/`.
    /// Prints the signcrypted OpenPGP message and writes it to a file.
    Signcrypt(SigncryptArgs),
    /// Verify a signed message (listing the verified attestations of the
    /// signer found in `db/attestations/`), decrypt and verify a signcrypted
    /// message, or verify an attestation record. The file type is detected
    /// from its content.
    Verify(VerifyArgs),
}

#[derive(Args, Debug)]
struct AttestArgs {
    #[command(subcommand)]
    command: AttestCommand,
}

#[derive(Subcommand, Debug)]
enum AttestCommand {
    /// Notarize an HTTPS URL with TLSNotary, storing an attestation in
    /// `db/attestations/` if a plugin recognizes the profile.
    New(NotarizeArgs),
    /// Verify all the attestations in `db/attestations/` and print them as a
    /// tree of aiwots, with a subtree of attributes per attestation.
    List(ListArgs),
    /// Verify all the attestations in `db/attestations/` and print, as
    /// `list` does, those whose user (handle, domain, name...) matches a
    /// regex. Prefix it with `(?i)` to ignore case.
    Search(SearchArgs),
    /// Verify every attestation in `db/attestations/`, reporting each file.
    /// Exits with an error if any is invalid.
    Audit(ListArgs),
    /// Export the valid attestations in `db/attestations/` as a signed
    /// message, each attestation encoded as base58.
    Export(ExportArgs),
    /// Merge into `db/attestations/` the valid attestations of a file
    /// written by `attest export` that are on your web of trust, after
    /// verifying its signature: first the keysign attestations whose signer
    /// is reachable from you through keysigns, then the other attestations
    /// about reachable aiwots.
    Merge(MergeArgs),
    /// Attest, key signing party style, that you know the owner of an aiwot,
    /// signing it with your key. The attestation is stored in
    /// `db/attestations/`.
    #[command(alias = "keysignparty")]
    Keysign(KeysignArgs),
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are ignored.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Args, Debug)]
struct SearchArgs {
    /// Regex matched against the user of each attestation.
    pattern: String,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are ignored.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Output file.
    #[clap(long, default_value = "export.md")]
    out: String,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are not exported.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Args, Debug)]
struct MergeArgs {
    /// Export file to merge.
    #[clap(default_value = "export.md")]
    file: String,
    /// Replace existing attestations with the same name but different
    /// content.
    #[clap(long)]
    force: bool,
    /// Expected notary public key (compressed secp256k1, hex). TLSNotary
    /// attestations signed by a different key are not merged.
    #[clap(long, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Args, Debug)]
struct KeysignArgs {
    /// The aiwot you attest, with or without the `aiwot:` prefix.
    aiwot: String,
    /// The name of its owner.
    name: String,
}

#[derive(Args, Debug)]
struct SigncryptArgs {
    /// The recipient aiwot, with or without the `aiwot:` prefix.
    aiwot: String,
    /// Message to sign and encrypt.
    msg: String,
    /// Output file.
    #[clap(long, default_value = "msg.md")]
    out: String,
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

    #[cfg(feature = "zkemail")]
    {
        if let Command::Zkemail(args) = &cli.command {
            return run_zkemail(args);
        }
    }

    let keys = match cli.command {
        Command::Init => key::create(&cli.config)?,
        _ => key::load(&cli.config)?,
    };
    if let Command::Init = cli.command {
        eprintln!(
            "Created OpenPGP key (MlDsa65Ed25519 signing key with a MlKem768X25519 encryption \
             subkey) in {}",
            cli.config.display()
        );
    }
    if let Some(path) = attestations::me::ensure(&keys).await? {
        eprintln!("Created self attestation {path}");
    }

    match cli.command {
        Command::Init => Ok(()),
        Command::Me => {
            println!("{}", keys.aiwot());
            Ok(())
        }
        Command::Attest(AttestArgs { command }) => match command {
            AttestCommand::New(args) => run_notarize(&args).await,
            AttestCommand::List(args) => run_list(&args).await,
            AttestCommand::Search(args) => run_search(&args).await,
            AttestCommand::Audit(args) => run_audit(&args).await,
            AttestCommand::Export(args) => run_export(&args, &keys).await,
            AttestCommand::Merge(args) => run_merge(&args, &keys.aiwot()).await,
            AttestCommand::Keysign(args) => run_keysign(&args, &keys).await,
        },
        Command::Makedot(args) => run_makedot(&args, &keys.aiwot()).await,
        Command::Fakegraph(args) => run_fakegraph(&args, &keys).await,
        Command::Msg(MsgArgs { command }) => match command {
            MsgCommand::Sign(args) => run_sign(&args, &keys).await,
            MsgCommand::Signcrypt(args) => run_signcrypt(&args, &keys).await,
            MsgCommand::Verify(args) => run_verify(&args, &keys).await,
        },
        #[cfg(feature = "zkemail")]
        Command::Zkemail(_) => unreachable!("zkemail is handled before loading aiwot keys"),
    }
}

/// Generates a proof synchronously because proving is CPU-bound and this
/// command performs no concurrent asynchronous work.
#[cfg(feature = "zkemail")]
fn run_zkemail(args: &ZkemailArgs) -> Result<(), Box<dyn std::error::Error>> {
    let proof = plonky2_zkemail::eml::prove(&args.eml, &args.dkim)?;
    std::fs::write(&args.output, &proof.bytes)?;
    println!(
        "Generated {}-byte proof for d={}, s={} ({} gate rows, {} padded rows): {}",
        proof.bytes.len(),
        proof.domain,
        proof.selector,
        proof.gate_rows,
        proof.padded_rows,
        args.output.display()
    );
    Ok(())
}

async fn run_notarize(args: &NotarizeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = tlsnotary::NotaryConfig {
        host: args.notary_host.clone(),
        port: args.notary_port,
        tls: args.notary_tls,
        max_sent: args.max_sent,
        max_recv: args.max_recv,
    };

    if let Some(path) = tlsnotary::attest(&config, &args.url, &args.out).await? {
        println!("{path}");
    }

    Ok(())
}

async fn run_list(args: &ListArgs) -> Result<(), Box<dyn std::error::Error>> {
    let attestations = attestations::list(&args.notary_key).await?;
    if attestations.is_empty() {
        println!("No attestations in {}/", attestations::DIR);
    }
    print_tree(&attestations);

    Ok(())
}

async fn run_search(args: &SearchArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pattern = regex::Regex::new(&args.pattern)
        .map_err(|e| format!("invalid regex `{}`: {e}", args.pattern))?;

    let found: Vec<_> = attestations::list(&args.notary_key)
        .await?
        .into_iter()
        .filter(|attestation| pattern.is_match(&attestation.profile.user))
        .collect();
    if found.is_empty() {
        println!(
            "No attestations in {}/ with a user matching `{}`",
            attestations::DIR,
            args.pattern
        );
    }
    print_tree(&found);

    Ok(())
}

/// Prints attestations sorted by aiwot as a tree of aiwots, with a subtree
/// of attributes per attestation.
fn print_tree(attestations: &[attestations::ProfileAttestation]) {
    let mut groups: Vec<(&str, Vec<&attestations::ProfileAttestation>)> = Vec::new();
    for attestation in attestations {
        match groups.last_mut() {
            Some((aiwot, group)) if *aiwot == attestation.profile.aiwot => group.push(attestation),
            _ => groups.push((&attestation.profile.aiwot, vec![attestation])),
        }
    }

    for (aiwot, group) in groups {
        println!("aiwot:{aiwot}");
        for (idx, attestation) in group.iter().enumerate() {
            let last = idx + 1 == group.len();
            println!(
                "{} {}:{}",
                if last { "└──" } else { "├──" },
                attestation.profile.platform,
                attestation.profile.user
            );

            let indent = if last { "    " } else { "│   " };
            let file = ("file", attestation.file.clone());
            let attributes: Vec<_> = attestation.attributes.iter().chain([&file]).collect();
            for (idx, (name, value)) in attributes.iter().enumerate() {
                let branch = if idx + 1 == attributes.len() {
                    "└──"
                } else {
                    "├──"
                };
                println!("{indent}{branch} {name}: {value}");
            }
        }
    }
}

async fn run_audit(args: &ListArgs) -> Result<(), Box<dyn std::error::Error>> {
    let checked = attestations::audit(&args.notary_key).await?;

    let mut invalid = 0;
    for checked in &checked {
        match &checked.result {
            Ok(attestation) => println!("OK    {}  {attestation}", checked.file),
            Err(e) => {
                invalid += 1;
                println!("FAIL  {}  {e}", checked.file);
            }
        }
    }

    println!(
        "{} files in {}/: {} valid, {invalid} invalid",
        checked.len(),
        attestations::DIR,
        checked.len() - invalid
    );
    if invalid > 0 {
        return Err(format!("{invalid} invalid attestations").into());
    }

    Ok(())
}

async fn run_export(args: &ExportArgs, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let (markdown, count) = attestations::export::create(keys, &args.notary_key).await?;

    // Check the output before handing it out.
    message::verify(&markdown, &attestations::keyring().await?)?;

    tokio::fs::write(&args.out, &markdown).await?;
    eprintln!("Exported {count} attestations");
    println!("{}", args.out);

    Ok(())
}

async fn run_merge(args: &MergeArgs, me: &str) -> Result<(), Box<dyn std::error::Error>> {
    use attestations::export::Outcome;

    let markdown = tokio::fs::read_to_string(&args.file).await?;
    let (signer, merged) =
        attestations::export::merge(&markdown, me, &args.notary_key, args.force).await?;

    println!("Valid signature from aiwot:{signer}");

    let mut invalid = 0;
    let mut untrusted = 0;
    let mut stored = 0;
    for merged in &merged {
        let file = &merged.file;
        match &merged.outcome {
            Outcome::Added(attestation) => {
                stored += 1;
                println!("MERGED     {file}  {attestation}");
            }
            Outcome::Replaced(attestation) => {
                stored += 1;
                println!("REPLACED   {file}  {attestation}");
            }
            Outcome::Unchanged(attestation) => println!("UNCHANGED  {file}  {attestation}"),
            Outcome::Conflict(attestation) => println!(
                "SKIPPED    {file}  {attestation}: a different record exists (use --force to replace)"
            ),
            Outcome::Untrusted(attestation) => {
                untrusted += 1;
                println!("UNTRUSTED  {file}  {attestation}: no trust path from your aiwot");
            }
            Outcome::Invalid(e) => {
                invalid += 1;
                println!("FAIL       {file}  {e}");
            }
        }
    }

    println!(
        "{} attestations in {}: {stored} merged, {untrusted} untrusted, {invalid} invalid",
        merged.len(),
        args.file
    );
    if invalid > 0 {
        return Err(format!("{invalid} invalid attestations").into());
    }

    Ok(())
}

async fn run_fakegraph(
    args: &FakegraphArgs,
    keys: &Keys,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = match &args.seed {
        Some(seed) => fakegraph::parse_seed(seed)?,
        None => fakegraph::DEFAULT_SEED,
    };
    let summary = fakegraph::run(keys, args.n, seed).await?;

    println!(
        "Generated {} identities in {}/ from seed {seed:#x} ({} already existed)",
        summary.identities,
        fakegraph::DIR,
        summary.existing
    );
    println!(
        "Generated {} keysign attestations in {}/: yours of the first {} identities, and \
         {} to {} per identity ({:.1} on average), up to {} keysigning the same identity",
        summary.keysigns,
        attestations::DIR,
        summary.roots,
        summary.min_connections,
        summary.max_connections,
        summary.mean_connections,
        summary.max_keysigned_by
    );
    println!(
        "Generated {} self attestations in {}/, with the KEM keys of the identities",
        summary.me_records,
        attestations::DIR
    );
    let per_platform: Vec<String> = summary
        .fakes_per_platform
        .iter()
        .map(|(platform, count)| format!("{platform}: {count}"))
        .collect();
    println!(
        "Generated {} fake profile attestations in {}/ ({})",
        summary
            .fakes_per_platform
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>(),
        attestations::DIR,
        per_platform.join(", ")
    );
    println!("All generated attestations are marked as fake");
    println!(
        "Audit OK: all identities match the seed, all attestations verify and are fake, and \
         all identities are reachable from aiwot:{}",
        keys.aiwot()
    );

    Ok(())
}

async fn run_makedot(args: &MakedotArgs, me: &str) -> Result<(), Box<dyn std::error::Error>> {
    let attestations = attestations::list(&args.notary_key).await?;
    let dot = graph::dot(me, &attestations);

    tokio::fs::write(&args.out, &dot).await?;
    eprintln!(
        "{} aiwots and {} keysigns, from {} attestations in {}/",
        dot.lines().filter(|line| line.contains(" [label=")).count(),
        dot.lines().filter(|line| line.contains(" -> ")).count(),
        attestations.len(),
        attestations::DIR
    );
    println!("{}", args.out);

    Ok(())
}

async fn run_sign(args: &SignArgs, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let armored = message::sign(&keys.secret, &args.msg)?;

    // Check the output before handing it out.
    message::verify(&armored, &attestations::keyring().await?)?;

    print!("{armored}");
    tokio::fs::write(&args.out, &armored).await?;
    eprintln!("Signed message written to {}", args.out);

    Ok(())
}

/// Verifies a signed message and lists the attestations of its signer.
async fn verify_msg(content: &str, notary_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = attestations::keyring().await?;
    let signed = message::verify(content, &keyring)?;

    println!("Valid signature from aiwot:{}", signed.from);

    if attestations::export::is_export(&signed.msg) {
        let checked = attestations::export::verify(&signed.msg, notary_key).await?;
        println!("Export of {} attestations:", checked.len());
        for checked in &checked {
            match &checked.result {
                Ok(attestation) => println!("OK    {}  {attestation}", checked.file),
                Err(e) => println!("FAIL  {}  {e}", checked.file),
            }
        }
    }

    print_attested_by(&signed.from, notary_key).await
}

/// Prints the verified attestations of `aiwot`.
async fn print_attested_by(
    aiwot: &str,
    notary_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let attestations = attestations::attested_by(aiwot, notary_key).await?;
    if attestations.is_empty() {
        println!("Not attested by any profile in {}/", attestations::DIR);
    }
    for attestation in attestations {
        println!("Attested by {attestation}");
    }

    Ok(())
}

async fn run_keysign(args: &KeysignArgs, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = attestations::keyring().await?;
    println!(
        "{}",
        keysignparty::attest(keys, &args.aiwot, &args.name, &keyring).await?
    );

    Ok(())
}

async fn run_verify(args: &VerifyArgs, keys: &Keys) -> Result<(), Box<dyn std::error::Error>> {
    let content = tokio::fs::read_to_string(&args.file).await?;

    if content.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
        verify_msg(&content, &args.notary_key).await
    } else if content.starts_with("-----BEGIN PGP MESSAGE-----") {
        verify_signcrypted(&content, keys, &args.notary_key).await
    } else if content.starts_with("# info") {
        verify_attestation(&content, &args.notary_key).await
    } else {
        Err(format!(
            "{} is neither a signed message, a signcrypted message nor an attestation record \
             (`# info`)",
            args.file
        )
        .into())
    }
}

async fn run_signcrypt(
    args: &SigncryptArgs,
    keys: &Keys,
) -> Result<(), Box<dyn std::error::Error>> {
    let to_key = signcrypt::recipient_encryption_key(&args.aiwot).await?;
    let to = signcrypt::recipient_aiwot(&args.aiwot);
    let sealed = signcrypt::seal(keys, &to, &to_key, &args.msg)?;

    print!("{sealed}");
    tokio::fs::write(&args.out, &sealed).await?;
    eprintln!("Signcrypted message for aiwot:{to} written to {}", args.out);

    Ok(())
}

/// Decrypts a signcrypted message addressed to us, verifies it and lists the
/// attestations of its sender.
async fn verify_signcrypted(
    content: &str,
    keys: &Keys,
    notary_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = attestations::keyring().await?;
    let opened = signcrypt::open(keys, content, &keyring)?;

    println!("Decrypted message for aiwot:{}", keys.aiwot());
    println!("Valid signature from aiwot:{}", opened.from);
    println!("# msg\n{}", opened.msg);

    print_attested_by(&opened.from, notary_key).await
}

/// Verifies an attestation record and prints its profile (and signer for key
/// sign party attestations), or the full transcript if no plugin handles a
/// TLSNotary record.
async fn verify_attestation(
    record: &str,
    notary_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let keyring = attestations::keyring().await?;
    let attested = attestations::verify(record, notary_key, &keyring)?;
    let fake = if attested.is_fake() { " [fake]" } else { "" };
    let verified = match attested {
        Attested::Tlsn(verified) => verified,
        Attested::KeySign(keysign) => {
            println!(
                "{} signed by aiwot:{}{fake}",
                keysign.profile(),
                keysign.signer
            );
            return Ok(());
        }
        Attested::Me(me) => {
            println!(
                "{} encryption_subkey:{}{fake}",
                me.profile(),
                me.encryption_fingerprint().unwrap_or_default(),
            );
            return Ok(());
        }
        Attested::Fake(fake) => {
            println!(
                "{} [fake] server:{}, no TLS session nor notary",
                fake.profile(),
                fake.server
            );
            return Ok(());
        }
    };

    if let Some(profile) = tlsnotary::plugins::profile(&verified.session()) {
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
