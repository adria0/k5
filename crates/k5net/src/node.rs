// A k5 node: an iroh endpoint that serves the k5 protocol (`proto`) for the
// local k5, and dials other k5s to send them messages or sync with them.
//
// Every operation opens a connection, says hello (both sides prove their k5
// and check the other is on their web of trust, see `peer`), makes one
// request and closes. Incoming requests are answered by the router's
// protocol handler: messages go to the inbox, export requests are answered
// with a signed export. What happens is reported through the events callback.

use std::{path::Path, sync::Arc, time::Duration};

use iroh::{
    address_lookup::MemoryLookup,
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, RelayMode, SecretKey,
};
use k5lib::{
    api::{MergeReport, K5},
    key, Error,
};

use crate::{
    peer::{self, Peer},
    proto::{
        self, ALPN, EXPORT, EXPORT_LIMIT, EXPORT_REQUEST, HELLO, HELLO_LIMIT, MESSAGE,
        MESSAGE_LIMIT, OK, REFUSED,
    },
};

/// Section of `k5.toml` with the iroh secret key.
const CONFIG_SECTION: &str = "iroh";

/// How long a refused peer is given to read the refusal.
const REFUSAL_GRACE: Duration = Duration::from_secs(10);

/// How long a ticket waits for a home relay, so it can be used from another
/// network.
const TICKET_RELAY_WAIT: Duration = Duration::from_secs(10);

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
    /// A connection was refused: unknown or untrusted peer, invalid hello.
    Refused { endpoint: String, reason: String },
    /// A connection failed while serving it.
    Error(String),
}

/// A running node, stopped by [`Node::shutdown`].
pub struct Node {
    router: Router,
    k5: Arc<K5>,
    /// Uses relays: tickets wait for the home relay.
    relays: bool,
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
                .bind_addr("127.0.0.1:0")
                .map_err(|e| e.to_string())?,
        };
        let endpoint = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| e.to_string())?;

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

        let handler = Handler {
            k5: k5.clone(),
            events: Arc::new(events),
        };
        let router = Router::builder(endpoint).accept(ALPN, handler).spawn();

        Ok(Self {
            router,
            k5,
            relays: matches!(network, Network::N0),
        })
    }

    /// The iroh endpoint id of the node, hex.
    pub fn endpoint_id(&self) -> String {
        peer::endpoint_hex(&self.router.endpoint().id())
    }

    /// A ticket to reach this node, for a first contact with a k5 that does
    /// not have its iroh attestation yet. With relays, first waits (a
    /// while) for the home relay, so the ticket also works from other
    /// networks, not only with the direct addresses.
    pub async fn ticket(&self) -> Result<String, Error> {
        let endpoint = self.router.endpoint();
        if self.relays {
            let _ = tokio::time::timeout(TICKET_RELAY_WAIT, endpoint.online()).await;
        }

        Ok(proto::ticket(&endpoint.addr())?)
    }

    /// Connects to the endpoint of a ticket and exchanges hellos, so each
    /// side stores the other's records. Returns the k5 of the peer.
    pub async fn connect_ticket(&self, ticket: &str) -> Result<String, Error> {
        let session = self.open(proto::parse_ticket(ticket)?, None).await?;
        session.close();

        Ok(session.peer.k5)
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
                .map_err(|e| format!("delivered, but the sent copy was not saved: {e}").into()),
            (REFUSED, reason) => Err(format!("k5:{to} refused the message: {reason}").into()),
            (kind, _) => Err(unexpected(kind).into()),
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
            (REFUSED, reason) => Err(format!("k5:{peer} refused the sync: {reason}").into()),
            (kind, _) => Err(unexpected(kind).into()),
        }
    }

    /// Stops accepting connections and closes the endpoint.
    pub async fn shutdown(self) -> Result<(), Error> {
        self.router.shutdown().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Connects to the k5 `k5`, by the endpoint of its iroh attestation.
    async fn dial(&self, k5: &str) -> Result<Session, Error> {
        let k5 = k5
            .trim()
            .strip_prefix("k5:")
            .unwrap_or(k5.trim())
            .to_ascii_lowercase();
        let iroh = self.k5.iroh_endpoint(&k5).await?.ok_or_else(|| {
            format!("k5:{k5} has no iroh attestation: connect to it with a ticket first")
        })?;
        let id = peer::parse_endpoint(&iroh.endpoint)?;

        self.open(EndpointAddr::new(id), Some(&k5)).await
    }

    /// Connects to `addr` and exchanges hellos. With `expected`, the peer must
    /// prove to be that k5.
    async fn open(&self, addr: EndpointAddr, expected: Option<&str>) -> Result<Session, Error> {
        let conn = self
            .router
            .endpoint()
            .connect(addr, ALPN)
            .await
            .map_err(|e| format!("cannot connect: {e}"))?;
        let session = |peer| Session {
            conn: conn.clone(),
            peer,
        };

        let hello = peer::local_hello(&self.k5).await?;
        let (kind, text) = request(&conn, HELLO, &hello, HELLO_LIMIT).await?;
        let result = async {
            match kind {
                HELLO => {}
                REFUSED => return Err(format!("refused by the peer: {text}")),
                kind => return Err(unexpected(kind)),
            }
            let (me_record, iroh_record) = proto::parse_hello(&text)?;
            let peer = peer::verify(me_record, iroh_record, &conn.remote_id())?;
            if let Some(expected) = expected {
                if peer.k5 != expected {
                    return Err(format!("the endpoint of k5:{expected} is k5:{}", peer.k5));
                }
            }
            if !peer::is_trusted(&self.k5, &peer.k5).await? {
                return Err(format!("k5:{} is not on your web of trust", peer.k5));
            }
            peer::store(&self.k5, &peer).await?;

            Ok(peer)
        }
        .await;

        match result {
            Ok(peer) => Ok(session(peer)),
            Err(e) => {
                conn.close(1u32.into(), b"refused");
                Err(e.into())
            }
        }
    }
}

/// An open connection to a verified, trusted peer.
struct Session {
    conn: Connection,
    peer: Peer,
}

impl Session {
    async fn request(&self, kind: u8, text: &str, limit: usize) -> Result<(u8, String), Error> {
        Ok(request(&self.conn, kind, text, limit).await?)
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
) -> Result<(u8, String), String> {
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    reply(&mut send, kind, text).await?;
    let payload = recv.read_to_end(limit).await.map_err(|e| e.to_string())?;
    proto::decode(&payload)
}

/// Writes a payload and finishes the stream.
async fn reply(send: &mut SendStream, kind: u8, text: &str) -> Result<(), String> {
    send.write_all(&proto::encode(kind, text))
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())
}

async fn read(recv: &mut RecvStream, limit: usize) -> Result<(u8, String), String> {
    let payload = recv.read_to_end(limit).await.map_err(|e| e.to_string())?;
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
                "connection from {}: {e}",
                peer::endpoint_hex(&conn.remote_id())
            )));
            conn.close(2u32.into(), b"error");
        }

        Ok(())
    }
}

impl Handler {
    async fn serve(&self, conn: &Connection) -> Result<(), String> {
        let remote = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
        let (kind, text) = read(&mut recv, HELLO_LIMIT).await?;
        let verified = if kind == HELLO {
            proto::parse_hello(&text)
                .and_then(|(me_record, iroh_record)| peer::verify(me_record, iroh_record, &remote))
        } else {
            Err(format!("expected a hello, got `{}`", kind as char))
        };
        let refusal = match &verified {
            Err(e) => Some(e.clone()),
            Ok(peer) if !peer::is_trusted(&self.k5, &peer.k5).await? => {
                Some(format!("k5:{} is not on the web of trust", peer.k5))
            }
            Ok(_) => None,
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

        // Requests, one per stream, until the peer closes the connection.
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let (kind, text) = read(&mut recv, MESSAGE_LIMIT).await?;
            match kind {
                MESSAGE => {
                    let received = self.k5.receive(&peer.k5, &text).await;
                    let received = received
                        .map_err(|e| e.to_string())
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
                    let export = self.k5.export().await.map_err(|e| e.to_string());
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
            .ok_or_else(|| {
                format!(
                    "[{CONFIG_SECTION}] of {} has no secret_key",
                    config.display()
                )
            })?;
        let bytes: [u8; 32] = hex::decode(hex)
            .map_err(|e| format!("invalid [{CONFIG_SECTION}] secret_key: {e}"))?
            .try_into()
            .map_err(|_| format!("invalid [{CONFIG_SECTION}] secret_key: expected 32 bytes"))?;
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
