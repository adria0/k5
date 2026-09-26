// `k5cli p2p`: a console front end of the peer-to-peer node (`k5net`), on
// n0's network. The iroh key is kept in the `[iroh]` section of the config
// file, created on first use.

use std::{path::Path, sync::Arc};

use clap::{Args, Subcommand};

use k5lib::api::{DEFAULT_NOTARY_KEY, K5};
use k5net::{Event, Network, Node};

#[derive(Args, Debug)]
pub struct P2pArgs {
    #[command(subcommand)]
    command: P2pCommand,
    /// Expected notary public key (compressed secp256k1, hex), to verify the
    /// attestations, e.g. of the web of trust.
    #[clap(long, global = true, default_value = DEFAULT_NOTARY_KEY)]
    notary_key: String,
}

#[derive(Subcommand, Debug)]
enum P2pCommand {
    /// Print your ticket, then serve until Ctrl-C: receive messages into the
    /// inbox and answer sync requests of k5s on your web of trust. For 10
    /// minutes, k5s not on it yet may pair with the ticket.
    Listen,
    /// Pair with the k5 of a ticket, so each learns how to reach the other,
    /// and print the check phrase. If it matches theirs, keysign each other
    /// to talk (`attest keysign`).
    Connect {
        /// Ticket printed by `p2p listen` (`k5ticket:...`).
        ticket: String,
    },
    /// Sign a message, encrypt it to a k5 and deliver it.
    Send {
        /// The recipient k5, with or without the `k5:` prefix.
        k5: String,
        /// Message to sign, encrypt and deliver.
        msg: String,
    },
    /// Merge the attestations of a k5 that are on your web of trust, as
    /// `attest merge` does with an export file.
    Sync {
        /// The k5 to sync with, with or without the `k5:` prefix.
        k5: String,
    },
    /// Print the messages received.
    Inbox,
}

pub async fn run(args: P2pArgs, k5: K5, config: &Path) -> anyhow::Result<()> {
    let k5 = Arc::new(k5.with_notary_key(&args.notary_key));

    if let P2pCommand::Inbox = args.command {
        return print_inbox(&k5).await;
    }

    let secret = k5net::load_or_create_secret(config)?;
    let node = Node::spawn(k5.clone(), secret, Network::N0, print_event).await?;
    eprintln!("Online as endpoint {}", node.endpoint_id());

    let result = match args.command {
        P2pCommand::Listen => {
            println!("{}", node.ticket().await?);
            eprintln!("Serving k5:{} until Ctrl-C", k5.k5());
            tokio::signal::ctrl_c().await?;
            Ok(())
        }
        P2pCommand::Connect { ticket } => node.connect_ticket(&ticket).await.map(|contact| {
            println!("Connected to k5:{}", contact.k5);
            println!("Check phrase: {}", contact.phrase);
            if !contact.trusted {
                println!(
                    "Not on your web of trust: if the phrase matches theirs, keysign it with \
                     `k5cli attest keysign k5:{} <name>`",
                    contact.k5
                );
            }
        }),
        P2pCommand::Send { k5: to, msg } => node.send(&to, &msg).await.map(|()| {
            println!("Message delivered to {to}");
        }),
        P2pCommand::Sync { k5: peer } => node
            .sync(&peer)
            .await
            .and_then(|report| crate::print_merge(&report, &format!("the export of {peer}"))),
        P2pCommand::Inbox => unreachable!("handled before going online"),
    };

    node.shutdown().await?;
    result
}

fn print_event(event: Event) {
    match event {
        Event::Received { from, msg } => println!("MESSAGE    from k5:{from}\n{msg}"),
        Event::Served { k5 } => println!("SYNC       sent the export to k5:{k5}"),
        Event::Paired {
            k5,
            trusted,
            phrase,
        } => {
            println!("PAIRED     k5:{k5}, check phrase: {phrase}");
            if !trusted {
                println!(
                    "           not on your web of trust: if the phrase matches theirs, \
                     keysign it with `k5cli attest keysign k5:{k5} <name>`"
                );
            }
        }
        Event::Refused { endpoint, reason } => {
            println!("REFUSED    endpoint {endpoint}: {reason}")
        }
        Event::Error(e) => println!("ERROR      {e}"),
    }
}

async fn print_inbox(k5: &K5) -> anyhow::Result<()> {
    let messages = k5.read_inbox().await?;
    if messages.is_empty() {
        println!("No messages");
    }
    for message in messages {
        match message.opened {
            Ok(opened) => println!(
                "{}  from k5:{}\n{}\n",
                message.name, opened.from, opened.msg
            ),
            Err(e) => println!("{}  UNREADABLE: {e}\n", message.name),
        }
    }

    Ok(())
}
