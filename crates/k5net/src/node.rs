// A k5 node: an iroh endpoint that serves the k5 protocol (`proto`) for the
// local k5, and dials other k5s to send them messages or sync with them.
//
// Every operation opens a connection, says hello (both sides prove their k5
// and check the other is on their web of trust, see `peer`), makes one
// request and closes. Incoming requests are answered by the router's
// protocol handler: messages go to the inbox, export requests are answered
// with a signed export. What happens is reported through the events callback.
//
// A first contact by ticket is a pairing: issuing a ticket opens a pairing
// window, during which a k5 not on the web of trust may connect with it. Both
// sides store each other's records and get a check phrase (see `peer`), to
// compare before keysigning each other; until then, the new peer's requests
// are refused.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context as _};
use iroh::{
    address_lookup::MemoryLookup,
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, RelayMode, SecretKey,
};
use k5lib::{
    api::{MergeReport, K5},
    k5id::K5Id,
    key, Error,
};

use crate::{
    peer::{self, Peer},
    proto::{
        self, ALPN, EXPORT, EXPORT_LIMIT, EXPORT_REQUEST, HELLO, HELLO_LIMIT, MESSAGE,
        MESSAGE_LIMIT, OK, PAIR, REFUSED,
    },
};

/// Section of `k5.toml` with the iroh secret key.
const CONFIG_SECTION: &str = "iroh";

/// How long a refused peer is given to read the refusal.
const REFUSAL_GRACE: Duration = Duration::from_secs(10);

/// How many messages a peer may deliver per [`MESSAGE_WINDOW`]; more are
/// refused, so a trusted peer cannot fill the inbox.
const MESSAGE_RATE: u32 = 30;
const MESSAGE_WINDOW: Duration = Duration::from_secs(60);

/// How long a ticket waits for a home relay, so it can be used from another
/// network.
const TICKET_RELAY_WAIT: Duration = Duration::from_secs(10);

/// How long issuing a ticket lets k5s not on the web of trust pair.
pub const PAIRING_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How the endpoint finds and reaches other endpoints.
pub enum Network {
    /// n0's public infrastructure: endpoints publish and resolve their
    /// addresses through n0's DNS/pkarr servers, and connect through n0's
    /// relays until a direct path is found.
    N0,
    /// Localhost only, no relays: endpoints find each other through a shared
    /// in-memory address book, where each node registers itself. For tests.
    Local(MemoryLookup),
}

/// What a node reports while serving.
#[derive(Debug)]
pub enum Event {
    /// A message was received and stored in the inbox.
    Received { from: String, msg: String },
    /// A peer was sent the local signed export.
    Served { k5: String },
    /// A k5 connected with the ticket (a pairing): its records were stored.
    /// `phrase` is the check phrase to compare with it before keysigning it;
    /// `trusted` tells whether it already is on the web of trust.
    Paired {
        k5: String,
        trusted: bool,
        phrase: String,
    },
    /// A connection was refused: unknown or untrusted peer, invalid hello.
    Refused { endpoint: String, reason: String },
    /// A connection failed while serving it.
    Error(String),
}

/// A k5 met by ticket, from [`Node::connect_ticket`].
#[derive(Debug)]
pub struct Contact {
    pub k5: String,
    /// On the web of trust already.
    pub trusted: bool,
    /// The check phrase, the same on both sides.
    pub phrase: String,
}

/// A running node, stopped by [`Node::shutdown`].
pub struct Node {
    router: Router,
    k5: Arc<K5>,
    /// Uses relays: tickets wait for the home relay.
    relays: bool,
    pairing: Arc<Pairing>,
}

/// Until when k5s not on the web of trust may pair.
#[derive(Default)]
struct Pairing(Mutex<Option<Instant>>);

impl Pairing {
    fn open(&self, duration: Duration) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now() + duration);
    }

    fn close(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn is_open(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|until| Instant::now() < until)
    }
}

impl Node {
    /// Starts a node for `k5` with the iroh key `secret`, and makes sure the
    /// database holds the local self attestation and iroh attestation, which
    /// are sent to peers.
    pub async fn spawn(
        k5: Arc<K5>,
        secret: SecretKey,
        network: Network,
        events: impl Fn(Event) + Send + Sync + 'static,
    ) -> Result<Self, Error> {
        let builder = match &network {
            Network::N0 => Endpoint::builder(presets::N0),
            Network::Local(lookup) => Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .address_lookup(lookup.clone())
                .bind_addr("127.0.0.1:0")?,
        };
        let endpoint = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;

        k5.ensure_self_attestation().await?;
        k5.ensure_iroh_attestation(&peer::endpoint_hex(&endpoint.id()))
            .await?;

        if let Network::Local(lookup) = &network {
            let mut addr = EndpointAddr::new(endpoint.id());
            for socket in endpoint.bound_sockets() {
                addr = addr.with_ip_addr(socket);
            }
            lookup.add_endpoint_info(addr);
        }

        let pairing = Arc::new(Pairing::default());
        let handler = Handler {
            k5: k5.clone(),
            events: Arc::new(events),
            rates: Arc::default(),
            pairing: pairing.clone(),
            local: endpoint.id(),
        };
        let router = Router::builder(endpoint).accept(ALPN, handler).spawn();

        Ok(Self {
            router,
            k5,
            relays: matches!(network, Network::N0),
            pairing,
        })
    }

    /// The iroh endpoint id of the node, hex.
    pub fn endpoint_id(&self) -> String {
        peer::endpoint_hex(&self.router.endpoint().id())
    }

    /// A ticket to reach this node, for a first contact with a k5 that does
    /// not have its iroh attestation yet. Opens the pairing window for
    /// [`PAIRING_WINDOW`]: k5s not on the web of trust may connect with it.
    /// With relays, first waits (a while) for the home relay, so the ticket
    /// also works from other networks, not only with the direct addresses.
    pub async fn ticket(&self) -> Result<String, Error> {
        self.pairing.open(PAIRING_WINDOW);
        let endpoint = self.router.endpoint();
        if self.relays {
            let _ = tokio::time::timeout(TICKET_RELAY_WAIT, endpoint.online()).await;
        }

        proto::ticket(&endpoint.addr())
    }

    /// Closes the pairing window: only k5s on the web of trust are accepted.
    pub fn stop_pairing(&self) {
        self.pairing.close();
    }

    /// Pairs with the k5 of a ticket, which may not be on the web of trust
    /// yet: exchanges hellos, so each side stores the other's records, and
    /// returns who it is, with the check phrase to compare before keysigning
    /// it.
    pub async fn connect_ticket(&self, ticket: &str) -> Result<Contact, Error> {
        let session = self.open(proto::parse_ticket(ticket)?, None, true).await?;
        session.close();
        let phrase = peer::check_phrase(
            (&self.k5.k5(), &self.router.endpoint().id()),
            (&session.peer.k5, &session.conn.remote_id()),
        );

        Ok(Contact {
            k5: session.peer.k5.clone(),
            trusted: session.trusted,
            phrase,
        })
    }

    /// Whether `k5`, on the web of trust, answers: connects to it and says
    /// hello.
    pub async fn ping(&self, k5: &str) -> Result<(), Error> {
        self.dial(k5).await?.close();
        Ok(())
    }

    /// Signs `msg`, encrypts it to `to` and delivers it to `to`, which must
    /// have an iroh attestation and be on the web of trust. Once delivered, a
    /// copy is kept with the messages sent.
    pub async fn send(&self, to: &str, msg: &str) -> Result<(), Error> {
        let session = self.dial(to).await?;
        let sealed = self.k5.signcrypt(&session.peer.k5, msg).await?;
        let result = session
            .request(MESSAGE, &sealed.armored, MESSAGE_LIMIT)
            .await;
        session.close();

        match result? {
            (OK, _) => self
                .k5
                .record_sent(&session.peer.k5, msg)
                .await
                .context("delivered, but the sent copy was not saved"),
            (REFUSED, reason) => Err(anyhow!("k5:{to} refused the message: {reason}")),
            (kind, _) => bail!(unexpected(kind)),
        }
    }

    /// Fetches the signed export of `peer` and merges it into the database,
    /// as `attest merge` does (only what is on the web of trust).
    pub async fn sync(&self, peer: &str) -> Result<MergeReport, Error> {
        let session = self.dial(peer).await?;
        let result = session.request(EXPORT_REQUEST, "", EXPORT_LIMIT).await;
        session.close();

        match result? {
            (EXPORT, markdown) => self.k5.merge(&markdown, false).await,
            (REFUSED, reason) => Err(anyhow!("k5:{peer} refused the sync: {reason}")),
            (kind, _) => bail!(unexpected(kind)),
        }
    }

    /// Stops accepting connections and closes the endpoint.
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.router.shutdown().await?;
        Ok(())
    }

    /// Connects to the k5 `k5`, by the endpoint of its iroh attestation.
    async fn dial(&self, k5: &str) -> Result<Session, Error> {
        let k5 = K5Id::parse(k5)?;
        let iroh = self.k5.iroh_endpoint(&k5).await?.with_context(|| {
            format!("k5:{k5} has no iroh attestation: connect to it with a ticket first")
        })?;
        let id = peer::parse_endpoint(&iroh.endpoint)?;

        self.open(EndpointAddr::new(id), Some(k5.as_str()), false)
            .await
    }

    /// Connects to `addr` and exchanges hellos. With `expected`, the peer must
    /// prove to be that k5. With `pair`, a pairing hello: the peer may not be
    /// on the web of trust.
    async fn open(
        &self,
        addr: EndpointAddr,
        expected: Option<&str>,
        pair: bool,
    ) -> Result<Session, Error> {
        let conn = self
            .router
            .endpoint()
            .connect(addr, ALPN)
            .await
            .context("cannot connect")?;
        let session = |(peer, trusted)| Session {
            conn: conn.clone(),
            peer,
            trusted,
        };

        let hello = peer::local_hello(&self.k5).await?;
        let kind = if pair { PAIR } else { HELLO };
        let (kind, text) = request(&conn, kind, &hello, HELLO_LIMIT).await?;
        let result = async {
            match kind {
                HELLO => {}
                REFUSED => bail!("refused by the peer: {text}"),
                kind => bail!(unexpected(kind)),
            }
            let (me_record, iroh_record) = proto::parse_hello(&text)?;
            let peer = peer::verify(me_record, iroh_record, &conn.remote_id())?;
            if let Some(expected) = expected {
                if peer.k5 != expected {
                    bail!("the endpoint of k5:{expected} is k5:{}", peer.k5);
                }
            }
            let trusted = peer::is_trusted(&self.k5, &peer.k5).await?;
            if !trusted && !pair {
                bail!("k5:{} is not on your web of trust", peer.k5);
            }
            peer::store(&self.k5, &peer).await?;

            Ok((peer, trusted))
        }
        .await;

        match result {
            Ok(peer) => Ok(session(peer)),
            Err(e) => {
                conn.close(1u32.into(), b"refused");
                Err(e)
            }
        }
    }
}

/// An open connection to a verified peer: trusted, unless paired.
struct Session {
    conn: Connection,
    peer: Peer,
    trusted: bool,
}

impl Session {
    async fn request(&self, kind: u8, text: &str, limit: usize) -> Result<(u8, String), Error> {
        request(&self.conn, kind, text, limit).await
    }

    fn close(&self) {
        self.conn.close(0u32.into(), b"done");
    }
}

/// Sends a request on a new stream and reads the response.
async fn request(
    conn: &Connection,
    kind: u8,
    text: &str,
    limit: usize,
) -> Result<(u8, String), Error> {
    let (mut send, mut recv) = conn.open_bi().await?;
    reply(&mut send, kind, text).await?;
    read(&mut recv, limit).await
}

/// Writes a payload and finishes the stream.
async fn reply(send: &mut SendStream, kind: u8, text: &str) -> Result<(), Error> {
    send.write_all(&proto::encode(kind, text)).await?;
    send.finish()?;

    Ok(())
}

async fn read(recv: &mut RecvStream, limit: usize) -> Result<(u8, String), Error> {
    let payload = recv.read_to_end(limit).await?;
    proto::decode(&payload)
}

fn unexpected(kind: u8) -> String {
    format!("unexpected response `{}`", kind as char)
}

/// Serves the k5 protocol for the local k5.
#[derive(Clone)]
struct Handler {
    k5: Arc<K5>,
    events: Arc<dyn Fn(Event) + Send + Sync>,
    rates: Arc<Rates>,
    pairing: Arc<Pairing>,
    /// The local endpoint id, for check phrases.
    local: iroh::EndpointId,
}

/// Messages delivered by each k5 in its current window: when the window
/// started, and how many.
#[derive(Default)]
struct Rates(Mutex<HashMap<String, (Instant, u32)>>);

impl Rates {
    /// Counts a message delivered by `k5` at `now`, returning whether it is
    /// within [`MESSAGE_RATE`].
    fn allow(&self, k5: &str, now: Instant) -> bool {
        let mut rates = self.0.lock().unwrap_or_else(|e| e.into_inner());
        rates.retain(|_, (start, _)| now.saturating_duration_since(*start) < MESSAGE_WINDOW);
        let (_, count) = rates.entry(k5.to_string()).or_insert((now, 0));
        *count += 1;

        *count <= MESSAGE_RATE
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Handler").finish_non_exhaustive()
    }
}

impl ProtocolHandler for Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        if let Err(e) = self.serve(&conn).await {
            (self.events)(Event::Error(format!(
                "connection from {}: {e:#}",
                peer::endpoint_hex(&conn.remote_id())
            )));
            conn.close(2u32.into(), b"error");
        }

        Ok(())
    }
}

impl Handler {
    async fn serve(&self, conn: &Connection) -> Result<(), Error> {
        let remote = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await?;
        let (kind, text) = read(&mut recv, HELLO_LIMIT).await?;
        let pairing = kind == PAIR;
        let verified = if kind == HELLO || pairing {
            proto::parse_hello(&text)
                .and_then(|(me_record, iroh_record)| peer::verify(me_record, iroh_record, &remote))
        } else {
            Err(anyhow!("expected a hello, got `{}`", kind as char))
        };
        let trusted = match &verified {
            Ok(peer) => peer::is_trusted(&self.k5, &peer.k5).await?,
            Err(_) => false,
        };
        let refusal = match &verified {
            Err(e) => Some(format!("{e:#}")),
            // A pairing while the window is open: the peer may keysign later.
            Ok(_) if trusted || (pairing && self.pairing.is_open()) => None,
            Ok(peer) => Some(format!("k5:{} is not on the web of trust", peer.k5)),
        };
        if let Some(reason) = refusal {
            reply(&mut send, REFUSED, &reason).await?;
            (self.events)(Event::Refused {
                endpoint: peer::endpoint_hex(&remote),
                reason,
            });
            // Let the peer read the refusal; it closes the connection.
            let _ = tokio::time::timeout(REFUSAL_GRACE, conn.closed()).await;
            return Ok(());
        }
        let peer = verified?;

        peer::store(&self.k5, &peer).await?;
        reply(&mut send, HELLO, &peer::local_hello(&self.k5).await?).await?;
        if pairing {
            let phrase = peer::check_phrase((&self.k5.k5(), &self.local), (&peer.k5, &remote));
            (self.events)(Event::Paired {
                k5: peer.k5.clone(),
                trusted,
                phrase,
            });
        }

        // Requests, one per stream, until the peer closes the connection.
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let (kind, text) = read(&mut recv, MESSAGE_LIMIT).await?;
            match kind {
                // Paired, but not keysigned yet.
                _ if !trusted => {
                    let reason = format!("k5:{} is not on the web of trust yet", peer.k5);
                    reply(&mut send, REFUSED, &reason).await?;
                }
                MESSAGE if !self.rates.allow(&peer.k5, Instant::now()) => {
                    reply(&mut send, REFUSED, "too many messages, try again later").await?;
                }
                MESSAGE => {
                    let received = self.k5.receive(&peer.k5, &text).await;
                    let received = received
                        .map_err(|e| format!("{e:#}"))
                        .and_then(|message| message.opened);
                    match received {
                        Ok(opened) => {
                            reply(&mut send, OK, "").await?;
                            (self.events)(Event::Received {
                                from: opened.from,
                                msg: opened.msg,
                            });
                        }
                        Err(e) => reply(&mut send, REFUSED, &e).await?,
                    }
                }
                EXPORT_REQUEST => {
                    let export = self.k5.export().await.map_err(|e| format!("{e:#}"));
                    match export {
                        Ok(export) => {
                            reply(&mut send, EXPORT, &export.markdown).await?;
                            (self.events)(Event::Served {
                                k5: peer.k5.clone(),
                            });
                        }
                        Err(e) => reply(&mut send, REFUSED, &e).await?,
                    }
                }
                kind => reply(&mut send, REFUSED, &unexpected(kind)).await?,
            }
        }

        Ok(())
    }
}

/// The iroh secret key of the node, from the `[iroh]` section of the config
/// file `config`, created and stored there if missing.
pub fn load_or_create_secret(config: &Path) -> Result<SecretKey, Error> {
    if let Some(section) = key::load_section(config, CONFIG_SECTION)? {
        let hex = section
            .get("secret_key")
            .and_then(toml::Value::as_str)
            .with_context(|| {
                format!(
                    "[{CONFIG_SECTION}] of {} has no secret_key",
                    config.display()
                )
            })?;
        let bytes: [u8; 32] = hex::decode(hex)
            .with_context(|| format!("invalid [{CONFIG_SECTION}] secret_key"))?
            .try_into()
            .map_err(|_| anyhow!("invalid [{CONFIG_SECTION}] secret_key: expected 32 bytes"))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let secret = SecretKey::generate();
    let section = toml::Table::from_iter([(
        "secret_key".to_string(),
        toml::Value::String(hex::encode(secret.to_bytes())),
    )]);
    key::store_section(config, CONFIG_SECTION, toml::Value::Table(section))?;

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rates() {
        let rates = Rates::default();
        let start = Instant::now();

        for _ in 0..MESSAGE_RATE {
            assert!(rates.allow("a", start));
        }
        assert!(!rates.allow("a", start));
        // Each k5 has its own rate.
        assert!(rates.allow("b", start));
        // A new window starts after the current one.
        assert!(rates.allow("a", start + MESSAGE_WINDOW));
    }
}
