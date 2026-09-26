// k5 command line: a console front end of the k5 API (`k5lib::api`),
// which does the work. This file only parses arguments, reads and writes the
// files named on the command line, and prints the results. When no notary
// host is given, `notarize` runs the integrated notary server
// (`local_notary`), which lives here and not in the library.

mod fakegraph;
mod local_notary;
mod p2p;

use anyhow::{anyhow, Context as _};
use clap::{Args, Parser, Subcommand};

use k5lib::api::{
    Attested, Listing, MergeReport, NotaryConfig, Outcome, ProfileAttestation, Verification,
    ATTESTATIONS_DIR, DEFAULT_NOTARY_KEY, K5,
};

#[derive(Parser, Debug)]
#[command(version, about = "Notarize profiles with a remote TLSNotary server, and sign and verify messages with an OpenPGP post-quantum key", long_about = None)]
struct Cli {
    /// Configuration file with the keys, created by `init`.
    #[clap(long, global = true, default_value = "k5.toml")]
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
    /// Print your k5.
    Me,
    /// Create, list, search, audit, export and merge attestations.
    Attest(AttestArgs),
    /// Sign, signcrypt and verify messages.
    Msg(MsgArgs),
    /// Generate a deterministic fake social graph: identities in `db/ids/`,
    /// keysigning each other like a human social network (all reachable from
    /// your k5), with self attestations and fake X, GitHub and website
    /// attestations, all stored in `db/attestations/` and marked as fake.
    /// Audits the result.
    Fakegraph(FakegraphArgs),
    /// Write a Graphviz digraph of the verified attestations: keysigns
    /// between k5s, and the social profiles of each k5.
    Makedot(MakedotArgs),
    /// Talk to other k5s peer to peer over iroh: deliver signcrypted
    /// messages, merge their attestations. Only k5s on your web of trust.
    P2p(p2p::P2pArgs),
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
    /// Sign a message and encrypt it to a k5, using the MlKem768X25519
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
    /// tree of k5s, with a subtree of attributes per attestation.
    List(ListArgs),
    /// Verify all the attestations in `db/attestations/` and print, as
    /// `list` does, those whose user (handle, domain, name...) matches a
    /// regex. Prefix it with `(?i)` to ignore case.
    Search(SearchArgs),
    /// Verify every attestation in `db/attestations/`, reporting each file.
    /// Exits with an error if any is invalid.
    Audit(ListArgs),
    /// Export the valid attestations in `db/attestations/` as a signed
    /// message, each attestation encoded as base64.
    Export(ExportArgs),
    /// Merge into `db/attestations/` the valid attestations of a file
    /// written by `attest export` that are on your web of trust, after
    /// verifying its signature: first the keysign attestations whose signer
    /// is reachable from you through keysigns, then the other attestations
    /// about reachable k5s.
    Merge(MergeArgs),
    /// Attest, key signing party style, that you know the owner of a k5,
    /// signing it with your key. The attestation is stored in
    /// `db/attestations/`.
    #[command(alias = "keysignparty")]
    Keysign(KeysignArgs),
    /// Attest your email address with a zero-knowledge proof of a
    /// DKIM-signed email: one you sent to yourself with `k5:<your k5>` in
    /// the subject, saved as a `.eml` file. The DKIM key is fetched from DNS.
    /// Proving takes minutes. The email's signed header is published in the
    /// attestation; its body is not.
    Email {
        /// The email, as a `.eml` file.
        eml: std::path::PathBuf,
    },
    /// Claim your name: a statement signed by your k5, shared with your
    /// attestations. Replaces your previous claim.
    Name {
        /// Your name, as others will see it.
        name: String,
    },
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
    /// The k5 you attest, with or without the `k5:` prefix.
    k5: String,
    /// The name of its owner.
    name: String,
}

#[derive(Args, Debug)]
struct SigncryptArgs {
    /// The recipient k5, with or without the `k5:` prefix.
    k5: String,
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
    /// Notary server host (e.g. 134.122.76.100). If not given, the notary
    /// embedded in k5cli is started on localhost for this notarization; it
    /// signs with the default notary key.
    #[clap(long)]
    notary_host: Option<String>,
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
async fn main() -> anyhow::Result<()> {
    // Only warnings by default: the libraries' progress (iroh's network
    // probes, plonky2 building the circuit of an email attestation...) is
    // noise here. `RUST_LOG` shows more, e.g. `RUST_LOG=info`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let k5 = match cli.command {
        Command::Init => {
            let k5 = K5::init(&cli.config)?;
            eprintln!(
                "Created OpenPGP key (MlDsa65Ed25519 signing key with a MlKem768X25519 \
                 encryption subkey) in {}",
                cli.config.display()
            );
            k5
        }
        _ => K5::open(&cli.config)?,
    };
    if let Some(created) = k5.ensure_self_attestation().await? {
        if let Some(reason) = created.replaced {
            eprintln!("Replacing self attestation {}: {reason}", created.path);
        }
        eprintln!("Created self attestation {}", created.path);
    }

    match cli.command {
        Command::Init => Ok(()),
        Command::Me => {
            println!("{}", k5.k5());
            Ok(())
        }
        Command::Attest(AttestArgs { command }) => match command {
            AttestCommand::New(args) => run_notarize(&args, &k5).await,
            AttestCommand::List(args) => run_list(&k5.with_notary_key(&args.notary_key)).await,
            AttestCommand::Search(args) => {
                run_search(&args, &k5.with_notary_key(&args.notary_key)).await
            }
            AttestCommand::Audit(args) => run_audit(&k5.with_notary_key(&args.notary_key)).await,
            AttestCommand::Export(args) => {
                run_export(&args, &k5.with_notary_key(&args.notary_key)).await
            }
            AttestCommand::Merge(args) => {
                run_merge(&args, &k5.with_notary_key(&args.notary_key)).await
            }
            AttestCommand::Keysign(args) => run_keysign(&args, &k5).await,
            AttestCommand::Email { eml } => run_attest_email(&eml, &k5).await,
            AttestCommand::Name { name } => {
                k5.ensure_self_attestation().await?;
                println!("{}", k5.claim_name(&name).await?);
                Ok(())
            }
        },
        Command::Makedot(args) => run_makedot(&args, &k5.with_notary_key(&args.notary_key)).await,
        Command::P2p(args) => p2p::run(args, k5, &cli.config).await,
        Command::Fakegraph(args) => run_fakegraph(&args, &k5).await,
        Command::Msg(MsgArgs { command }) => match command {
            MsgCommand::Sign(args) => run_sign(&args, &k5).await,
            MsgCommand::Signcrypt(args) => run_signcrypt(&args, &k5).await,
            MsgCommand::Verify(args) => {
                run_verify(&args, &k5.with_notary_key(&args.notary_key)).await
            }
        },
    }
}

async fn run_attest_email(eml: &std::path::Path, k5: &K5) -> anyhow::Result<()> {
    let raw = std::fs::read(eml).with_context(|| format!("cannot read {}", eml.display()))?;
    let (domain, selector) = k5lib::api::dkim_selector(&raw)?;
    println!("Fetching the DKIM key of {domain} (selector {selector}) ...");
    let key = k5net::dkim_key(&domain, &selector).await?;
    println!("Proving the signed header (this takes a while) ...");
    k5.ensure_self_attestation().await?;
    println!("{}", k5.attest_email(raw, key).await?);

    Ok(())
}

async fn run_notarize(args: &NotarizeArgs, k5: &K5) -> anyhow::Result<()> {
    // Kept alive until the notarization is done.
    let (config, _local_notary) = match &args.notary_host {
        Some(host) => {
            let config = NotaryConfig {
                host: host.clone(),
                port: args.notary_port,
                tls: args.notary_tls,
                max_sent: args.max_sent,
                max_recv: args.max_recv,
            };
            (config, None)
        }
        None => {
            let local = local_notary::start(args.max_sent, args.max_recv).await?;
            println!(
                "Started a local notary on {}:{} signing with {}",
                local.config.host, local.config.port, local.key_hex
            );
            (local.config.clone(), Some(local))
        }
    };

    let notarized = k5
        .notarize(&config, &args.url, &args.out, &mut |step| {
            println!("{step}")
        })
        .await?;
    match notarized.record {
        Ok(path) => println!("{path}"),
        Err(reason) => eprintln!("No attestation record stored: {reason}"),
    }

    Ok(())
}

/// Reports the invalid records skipped by a listing.
fn print_invalid(listing: &Listing) {
    for invalid in &listing.invalid {
        eprintln!(
            "Ignoring invalid attestation {ATTESTATIONS_DIR}/{}: {}",
            invalid.file, invalid.error
        );
    }
}

async fn run_list(k5: &K5) -> anyhow::Result<()> {
    let listing = k5.list().await?;
    print_invalid(&listing);
    if listing.attestations.is_empty() {
        println!("No attestations in {ATTESTATIONS_DIR}/");
    }
    print_tree(&listing.attestations);

    Ok(())
}

async fn run_search(args: &SearchArgs, k5: &K5) -> anyhow::Result<()> {
    let found = k5.search(&args.pattern).await?;
    print_invalid(&found);
    if found.attestations.is_empty() {
        println!(
            "No attestations in {ATTESTATIONS_DIR}/ with a user matching `{}`",
            args.pattern
        );
    }
    print_tree(&found.attestations);

    Ok(())
}

/// Prints attestations sorted by k5 as a tree of k5s, with a subtree
/// of attributes per attestation.
fn print_tree(attestations: &[ProfileAttestation]) {
    let mut groups: Vec<(&str, Vec<&ProfileAttestation>)> = Vec::new();
    for attestation in attestations {
        match groups.last_mut() {
            Some((k5, group)) if *k5 == attestation.profile.k5 => group.push(attestation),
            _ => groups.push((&attestation.profile.k5, vec![attestation])),
        }
    }

    for (k5, group) in groups {
        println!("k5:{k5}");
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

async fn run_audit(k5: &K5) -> anyhow::Result<()> {
    let checked = k5.audit().await?;

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
        "{} files in {ATTESTATIONS_DIR}/: {} valid, {invalid} invalid",
        checked.len(),
        checked.len() - invalid
    );
    if invalid > 0 {
        return Err(anyhow!("{invalid} invalid attestations"));
    }

    Ok(())
}

async fn run_export(args: &ExportArgs, k5: &K5) -> anyhow::Result<()> {
    let export = k5.export().await?;
    for skipped in &export.skipped {
        eprintln!(
            "Not exporting invalid attestation {ATTESTATIONS_DIR}/{}: {}",
            skipped.file, skipped.error
        );
    }

    tokio::fs::write(&args.out, &export.markdown).await?;
    eprintln!("Exported {} attestations", export.count);
    println!("{}", args.out);

    Ok(())
}

async fn run_merge(args: &MergeArgs, k5: &K5) -> anyhow::Result<()> {
    let markdown = tokio::fs::read_to_string(&args.file).await?;
    let report = k5.merge(&markdown, args.force).await?;

    print_merge(&report, &args.file)
}

/// Prints what a merge did with each attestation of the export from
/// `source`. Fails if any was invalid.
fn print_merge(report: &MergeReport, source: &str) -> anyhow::Result<()> {
    println!("Valid signature from k5:{}", report.signer);

    let mut invalid = 0;
    let mut untrusted = 0;
    let mut stored = 0;
    for merged in &report.merged {
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
                println!("UNTRUSTED  {file}  {attestation}: no trust path from your k5");
            }
            Outcome::Invalid(e) => {
                invalid += 1;
                println!("FAIL       {file}  {e}");
            }
        }
    }

    println!(
        "{} attestations in {source}: {stored} merged, {untrusted} untrusted, {invalid} invalid",
        report.merged.len(),
    );
    if invalid > 0 {
        return Err(anyhow!("{invalid} invalid attestations"));
    }

    Ok(())
}

async fn run_fakegraph(args: &FakegraphArgs, k5: &K5) -> anyhow::Result<()> {
    let seed = match &args.seed {
        Some(seed) => fakegraph::parse_seed(seed)?,
        None => fakegraph::DEFAULT_SEED,
    };
    let summary = fakegraph::run(k5.keys(), k5.db(), args.n, seed).await?;

    println!(
        "Generated {} identities in {}/ from seed {seed:#x} ({} already existed)",
        summary.identities,
        fakegraph::DIR,
        summary.existing
    );
    println!(
        "Generated {} keysign attestations in {ATTESTATIONS_DIR}/: yours of the first {} \
         identities, and {} to {} per identity ({:.1} on average), up to {} keysigning the \
         same identity",
        summary.keysigns,
        summary.roots,
        summary.min_connections,
        summary.max_connections,
        summary.mean_connections,
        summary.max_keysigned_by
    );
    println!(
        "Generated {} self attestations in {ATTESTATIONS_DIR}/, with the KEM keys of the \
         identities",
        summary.me_records,
    );
    let per_platform: Vec<String> = summary
        .fakes_per_platform
        .iter()
        .map(|(platform, count)| format!("{platform}: {count}"))
        .collect();
    println!(
        "Generated {} fake profile attestations in {ATTESTATIONS_DIR}/ ({})",
        summary
            .fakes_per_platform
            .iter()
            .map(|(_, count)| count)
            .sum::<usize>(),
        per_platform.join(", ")
    );
    println!("All generated attestations are marked as fake");
    println!(
        "Audit OK: all identities match the seed, all attestations verify and are fake, and \
         all identities are reachable from k5:{}",
        k5.k5()
    );

    Ok(())
}

async fn run_makedot(args: &MakedotArgs, k5: &K5) -> anyhow::Result<()> {
    let graph = k5.graph().await?;

    tokio::fs::write(&args.out, &graph.dot).await?;
    eprintln!(
        "{} k5s and {} keysigns, from {} attestations in {ATTESTATIONS_DIR}/",
        graph.k5s, graph.keysigns, graph.attestations,
    );
    println!("{}", args.out);

    Ok(())
}

async fn run_sign(args: &SignArgs, k5: &K5) -> anyhow::Result<()> {
    let armored = k5.sign(&args.msg).await?;

    print!("{armored}");
    tokio::fs::write(&args.out, &armored).await?;
    eprintln!("Signed message written to {}", args.out);

    Ok(())
}

async fn run_keysign(args: &KeysignArgs, k5: &K5) -> anyhow::Result<()> {
    println!("{}", k5.keysign(&args.k5, &args.name).await?);

    Ok(())
}

async fn run_signcrypt(args: &SigncryptArgs, k5: &K5) -> anyhow::Result<()> {
    let sealed = k5.signcrypt(&args.k5, &args.msg).await?;

    print!("{}", sealed.armored);
    tokio::fs::write(&args.out, &sealed.armored).await?;
    eprintln!(
        "Signcrypted message for k5:{} written to {}",
        sealed.to, args.out
    );

    Ok(())
}

async fn run_verify(args: &VerifyArgs, k5: &K5) -> anyhow::Result<()> {
    let content = tokio::fs::read_to_string(&args.file).await?;

    match k5
        .verify(&content)
        .await
        .map_err(|e| anyhow!("{}: {e:#}", args.file))?
    {
        Verification::Signed {
            from,
            export,
            attested_by,
            ..
        } => {
            println!("Valid signature from k5:{from}");
            if let Some(checked) = export {
                println!("Export of {} attestations:", checked.len());
                for checked in &checked {
                    match &checked.result {
                        Ok(attestation) => println!("OK    {}  {attestation}", checked.file),
                        Err(e) => println!("FAIL  {}  {e}", checked.file),
                    }
                }
            }
            print_attested_by(&attested_by);
        }
        Verification::Signcrypted {
            from,
            msg,
            attested_by,
        } => {
            println!("Decrypted message for k5:{}", k5.k5());
            println!("Valid signature from k5:{from}");
            println!("# msg\n{msg}");
            print_attested_by(&attested_by);
        }
        Verification::Attestation(attested) => print_attested(attested)?,
    }

    Ok(())
}

/// Prints the verified attestations of the author of a message.
fn print_attested_by(listing: &Listing) {
    print_invalid(listing);
    if listing.attestations.is_empty() {
        println!("Not attested by any profile in {ATTESTATIONS_DIR}/");
    }
    for attestation in &listing.attestations {
        println!("Attested by {attestation}");
    }
}

/// Prints a verified attestation record: its profile (and signer for key
/// sign party attestations), or the full transcript if no plugin handles a
/// TLSNotary record.
fn print_attested(attested: Attested) -> anyhow::Result<()> {
    let fake = if attested.is_fake() { " [fake]" } else { "" };
    let verified = match attested {
        Attested::Tlsn(verified) => verified,
        Attested::KeySign(keysign) => {
            println!(
                "{} signed by k5:{}{fake}",
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
        Attested::Iroh(iroh) => {
            println!("{} created:{}{fake}", iroh.profile(), iroh.date);
            return Ok(());
        }
        Attested::Claim(claim) => {
            println!("{} created:{}{fake}", claim.profile(), claim.date);
            return Ok(());
        }
        Attested::Email(email) => {
            println!(
                "{} dkim:d={} s={} created:{}",
                email.profile(),
                email.domain,
                email.selector,
                email.created
            );
            return Ok(());
        }
    };

    if let Some(profile) = verified.profile() {
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
