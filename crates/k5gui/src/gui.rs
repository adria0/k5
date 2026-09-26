// `k5gui`: a Slint desktop front end of the k5 API (`ui/k5.slint`).
//
// The window runs on the main thread. A worker thread owns the [`K5`], a
// tokio runtime and the peer-to-peer node (`k5net`), and serves the requests
// of the window: it loads and verifies the attestations once (and on rescan),
// then answers searches and dossiers from that cache, delivers messages and
// syncs with peers. Results go back to the window as plain data through
// `upgrade_in_event_loop`.
//
// The node runs on the runtime's threads and reports what it serves
// (received messages, refused peers...) as requests to the worker.
//
// Messages are shown as conversations, one per k5, with the messages sent
// and received. A message to a k5 with an iroh attestation is delivered peer
// to peer; to any other, it is signcrypted and copied to the clipboard, ready
// to be handed to the recipient.
//
// The profiles of the local k5 (X, GitHub, website) are attested with a
// remote TLSNotary notary, given on the command line: the page that shows the
// k5 is notarized and stored as an attestation.
//
// A first contact by ticket is a pairing: both windows show the same check
// phrase, and after comparing them each side keysigns the other. From time
// to time, the trusted k5s that can be reached peer to peer are checked for
// presence (shown as ONLINE), and synced with every [`SYNC_INTERVAL`] unless
// automatic sync is off.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use slint::{ComponentHandle, ModelRc, VecModel};

use k5lib::api::{
    Conversation, MergeReport, NotaryConfig, Outcome, ProfileAttestation, Verification, K5,
};
use k5net::{Event, Network, Node, PAIRING_WINDOW};

slint::include_modules!();

/// Platforms of the self attestations, never shown (their only use, the KEM
/// key, is in the dossier), and of the keysigns.
const SELF: &str = "self_attestation";
const KEYSIGN: &str = "keysignparty";
/// Platform of the iroh attestations, never shown: they only tell whether a
/// k5 can be reached peer to peer.
const IROH: &str = "iroh";
/// Maximum number of search results shown.
const MAX_HITS: usize = 300;
/// When the first presence check runs, and how often the next ones do.
const FIRST_PROBE: Duration = Duration::from_secs(5);
const PROBE_INTERVAL: Duration = Duration::from_secs(60);
/// How long a peer has to answer a presence check, or to send its export.
const PING_TIMEOUT: Duration = Duration::from_secs(15);
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// How often each peer that answers is synced with, when automatic sync is
/// on.
const SYNC_INTERVAL: Duration = Duration::from_secs(10 * 60);

enum Request {
    Rescan,
    Search(String),
    Select(String),
    Sync(String),
    /// Show the conversation with a k5.
    OpenChat(String),
    /// Back to the list of conversations.
    CloseChat,
    /// Send a message in the conversation with a k5.
    ChatSend {
        to: String,
        msg: String,
    },
    CopyTicket,
    ConnectTicket(String),
    /// Attest a profile of the local k5: its kind (`x`, `github`, `site`,
    /// `email`) and what identifies it (a URL, a domain).
    Attest {
        kind: String,
        input: String,
    },
    /// Copy `k5:<the local k5>` to the clipboard.
    CopyK5,
    /// Show the attestations of the local k5.
    ShowMe,
    /// Verify pasted content.
    Verify(String),
    /// Keysign a k5 with a name.
    Keysign {
        k5: String,
        name: String,
    },
    ToggleAutoSync,
    /// Time for a presence check (and automatic sync).
    Tick,
    /// The results of a presence check.
    Probed(Vec<Probe>),
    /// Something the node did.
    Net(Event),
}

/// A peer checked for presence, from [`Worker::probe`].
struct Probe {
    k5: String,
    /// It answered.
    online: bool,
    /// Synced with it, with this many new or updated records.
    synced: Option<usize>,
}

/// How the profiles of the local k5 are attested.
pub struct Attesting {
    /// The remote notary, `None` if there is none.
    pub notary: Option<NotaryConfig>,
    /// Where the TLSNotary presentations are written.
    pub presentations: PathBuf,
}

/// Opens the window, blocking until it is closed. Unless `offline`, starts
/// the peer-to-peer node, with the iroh key of the config file `config`.
pub fn run(k5: K5, config: PathBuf, offline: bool, attesting: Attesting) -> anyhow::Result<()> {
    let ui = AppWindow::new()?;
    ui.set_me(short(&k5.k5()).into());
    ui.set_me_k5(k5.k5().into());
    ui.set_me_glyph(ModelRc::new(VecModel::from(glyph(&k5.k5()))));
    if let Some(notary) = &attesting.notary {
        ui.set_notary(format!("{}:{}", notary.host, notary.port).into());
    }

    let (tx, rx) = mpsc::channel();
    ui.on_search({
        let tx = tx.clone();
        move |query| {
            let _ = tx.send(Request::Search(query.into()));
        }
    });
    ui.on_select({
        let tx = tx.clone();
        move |k5| {
            let _ = tx.send(Request::Select(k5.into()));
        }
    });
    ui.on_open_chat({
        let tx = tx.clone();
        move |k5| {
            let _ = tx.send(Request::OpenChat(k5.into()));
        }
    });
    ui.on_close_chat({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::CloseChat);
        }
    });
    ui.on_chat_send({
        let tx = tx.clone();
        move |to, msg| {
            let _ = tx.send(Request::ChatSend {
                to: to.into(),
                msg: msg.into(),
            });
        }
    });
    ui.on_rescan({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::Rescan);
        }
    });
    ui.on_sync({
        let tx = tx.clone();
        move |k5| {
            let _ = tx.send(Request::Sync(k5.into()));
        }
    });
    ui.on_copy_ticket({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::CopyTicket);
        }
    });
    ui.on_connect_ticket({
        let tx = tx.clone();
        move |ticket| {
            let _ = tx.send(Request::ConnectTicket(ticket.into()));
        }
    });
    ui.on_attest({
        let tx = tx.clone();
        move |kind, input| {
            let _ = tx.send(Request::Attest {
                kind: kind.into(),
                input: input.into(),
            });
        }
    });
    ui.on_copy_k5({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::CopyK5);
        }
    });
    ui.on_open_me({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::ShowMe);
        }
    });
    ui.on_verify({
        let tx = tx.clone();
        move |content| {
            let _ = tx.send(Request::Verify(content.into()));
        }
    });
    ui.on_keysign({
        let tx = tx.clone();
        move |k5, name| {
            let _ = tx.send(Request::Keysign {
                k5: k5.into(),
                name: name.into(),
            });
        }
    });
    ui.on_toggle_auto_sync({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::ToggleAutoSync);
        }
    });
    // Presence checks and automatic sync, until the window is closed.
    thread::spawn({
        let tx = tx.clone();
        move || {
            thread::sleep(FIRST_PROBE);
            while tx.send(Request::Tick).is_ok() {
                thread::sleep(PROBE_INTERVAL);
            }
        }
    });

    let weak = ui.as_weak();
    let events = tx.clone();
    thread::spawn(move || {
        let node = (!offline).then_some((config, events));
        Worker::new(Arc::new(k5), weak, attesting).serve(rx, node)
    });
    tx.send(Request::Rescan)?;

    ui.run()?;

    Ok(())
}

struct Worker {
    k5: Arc<K5>,
    /// Shared with the presence checks, which run on the runtime.
    node: Option<Arc<Node>>,
    /// Where the presence checks report.
    requests: Option<mpsc::Sender<Request>>,
    /// The peers that answered the last presence check.
    live: HashSet<String>,
    auto_sync: bool,
    /// When each peer was last synced with automatically.
    last_sync: HashMap<String, Instant>,
    /// A presence check is running.
    probing: bool,
    ui: slint::Weak<AppWindow>,
    /// The verified attestations, as of the last scan.
    attestations: Vec<ProfileAttestation>,
    trusted: HashSet<String>,
    query: String,
    clipboard: Option<arboard::Clipboard>,
    /// The conversations, as of the last load.
    conversations: Vec<Conversation>,
    /// The k5 whose conversation is shown.
    open_chat: Option<String>,
    /// Messages received while their conversation was not shown, by k5.
    unread: HashMap<String, usize>,
    attesting: Attesting,
}

impl Worker {
    fn new(k5: Arc<K5>, ui: slint::Weak<AppWindow>, attesting: Attesting) -> Self {
        Self {
            attesting,
            k5,
            node: None,
            requests: None,
            live: HashSet::new(),
            auto_sync: true,
            last_sync: HashMap::new(),
            probing: false,
            ui,
            attestations: Vec::new(),
            trusted: HashSet::new(),
            query: String::new(),
            clipboard: None,
            conversations: Vec::new(),
            open_chat: None,
            unread: HashMap::new(),
        }
    }

    /// Serves the requests until the window is closed. With `node`, first
    /// starts the peer-to-peer node with the iroh key of that config file,
    /// reporting its events on that channel.
    fn serve(
        mut self,
        rx: mpsc::Receiver<Request>,
        node: Option<(PathBuf, mpsc::Sender<Request>)>,
    ) {
        // Multi-threaded: the node keeps serving on the runtime's threads
        // while this one waits for requests.
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => return self.status(format!("ERROR: {e:#}"), false),
        };
        if let Some((config, events)) = node {
            self.start_node(&runtime, &config, events);
        }

        while let Ok(request) = rx.recv() {
            match request {
                Request::Rescan => {
                    self.rescan(&runtime);
                    self.load_chats(&runtime);
                }
                Request::Search(query) => {
                    self.query = query;
                    self.search();
                }
                Request::Select(k5) => self.select(&k5),
                Request::Sync(k5) => self.sync(&runtime, &k5),
                Request::OpenChat(k5) => self.open_chat(&k5),
                Request::CloseChat => {
                    self.open_chat = None;
                    self.post_chats();
                }
                Request::ChatSend { to, msg } => self.chat_send(&runtime, &to, &msg),
                Request::CopyTicket => self.copy_ticket(&runtime),
                Request::ConnectTicket(ticket) => self.connect_ticket(&runtime, &ticket),
                Request::Attest { kind, input } => self.attest(&runtime, &kind, &input),
                Request::ShowMe => self.show_me(),
                Request::CopyK5 => {
                    let status = match self.copy(format!("k5:{}", self.k5.k5())) {
                        Ok(()) => "K5 COPIED TO CLIPBOARD".to_string(),
                        Err(e) => format!("COPY TO CLIPBOARD FAILED: {e:#}"),
                    };
                    self.status(status, false);
                }
                Request::Verify(content) => self.verify(&runtime, &content),
                Request::Keysign { k5, name } => self.keysign(&runtime, &k5, &name),
                Request::ToggleAutoSync => {
                    self.auto_sync = !self.auto_sync;
                    let on = self.auto_sync;
                    let _ = self
                        .ui
                        .upgrade_in_event_loop(move |ui| ui.set_auto_sync(on));
                    self.status(
                        format!("AUTO SYNC {}", if on { "ON" } else { "OFF" }),
                        false,
                    );
                }
                Request::Tick => self.probe(&runtime),
                Request::Probed(probes) => self.probed(&runtime, probes),
                Request::Net(event) => self.net_event(&runtime, event),
            }
        }

        if let Some(node) = self.node.take() {
            let _ = runtime.block_on(node.shutdown());
        }
    }

    /// Starts the peer-to-peer node on n0's network, with the iroh key of the
    /// config file `config` (created if missing).
    fn start_node(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        config: &std::path::Path,
        events: mpsc::Sender<Request>,
    ) {
        self.status("GOING ONLINE ...".to_string(), true);
        self.requests = Some(events.clone());
        let secret = match k5net::load_or_create_secret(config) {
            Ok(secret) => secret,
            Err(e) => return self.status(format!("OFFLINE: {e:#}"), false),
        };
        let spawned = runtime.block_on(Node::spawn(
            self.k5.clone(),
            secret,
            Network::N0,
            move |event| {
                let _ = events.send(Request::Net(event));
            },
        ));
        match spawned {
            Ok(node) => {
                let endpoint = short(&node.endpoint_id());
                let _ = self.ui.upgrade_in_event_loop(move |ui| {
                    ui.set_endpoint(endpoint.into());
                });
                self.node = Some(Arc::new(node));
                self.status(String::new(), false);
            }
            Err(e) => self.status(format!("OFFLINE: {e:#}"), false),
        }
    }

    fn status(&self, status: String, busy: bool) {
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_status(status.into());
            ui.set_busy(busy);
        });
    }

    fn rescan(&mut self, runtime: &tokio::runtime::Runtime) {
        self.status(format!("SCANNING {} ...", self.k5.db().location("")), true);

        let listing = match runtime.block_on(self.k5.list()) {
            Ok(listing) => listing,
            Err(e) => return self.status(format!("SCAN FAILED: {e:#}"), false),
        };
        self.trusted = self.k5.web_of_trust(&listing.attestations);
        self.attestations = listing.attestations;

        let ids: BTreeSet<&str> = self
            .attestations
            .iter()
            .map(|attestation| attestation.profile.k5.as_str())
            .collect();
        let (ids, trusted) = (ids.len(), self.trusted.len());
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_stats_ids(ids.to_string().into());
            ui.set_stats_trusted(trusted.to_string().into());
        });
        let status = match listing.invalid.len() {
            0 => String::new(),
            invalid => format!("{invalid} INVALID RECORDS IGNORED"),
        };
        self.status(status, false);
        self.search();
        let owned = owned(&self.k5.k5(), &self.attestations);
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_owned(ModelRc::new(VecModel::from(owned)));
        });
    }

    /// Shows the attestations of the local k5, as of the last scan.
    fn show_me(&self) {
        let _ = self.ui.upgrade_in_event_loop(|ui| {
            ui.set_attest_kind("".into());
            ui.set_show_me(true);
        });
    }

    /// Posts the k5s matching the query (see [`hits`]).
    fn search(&self) {
        let hits = hits(&self.k5.k5(), &self.attestations, &self.query, &self.live);
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_hits(ModelRc::new(VecModel::from(hits)));
        });
    }

    /// Posts the dossier of `k5`: its profile counts, whether it has an
    /// encryption subkey, and its trust path.
    fn select(&self, k5: &str) {
        let attestations: Vec<&ProfileAttestation> = self
            .attestations
            .iter()
            .filter(|attestation| attestation.profile.k5 == k5)
            .collect();
        let count = |platform: &str| {
            attestations
                .iter()
                .filter(|attestation| attestation.profile.platform == platform)
                .count() as i32
        };
        let attribute = |attestation: &ProfileAttestation, name: &str| {
            attestation
                .attributes
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };

        let kem = attestations
            .iter()
            .filter(|attestation| attestation.profile.platform == "self_attestation")
            .filter_map(|attestation| attribute(attestation, "encryption_subkey"))
            .any(|subkey| !subkey.is_empty());
        let name = ["X", "github", "site", "keysignparty"]
            .iter()
            .find_map(|platform| {
                attestations
                    .iter()
                    .find(|attestation| attestation.profile.platform == *platform)
                    .map(|attestation| attestation.profile.user.clone())
            })
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let (k5_a, k5_b) = k5.split_at(k5.len() / 2);

        let dossier = Dossier {
            k5: k5.into(),
            k5_a: k5_a.into(),
            k5_b: k5_b.into(),
            name: name.into(),
            kem,
            online: self.online(k5),
            live: self.live.contains(k5),
            trusted: self.trusted.contains(k5),
            me: k5 == self.k5.k5(),
            x: count("X"),
            github: count("github"),
            site: count("site"),
            keysign: count("keysignparty"),
        };

        let glyph = glyph(k5);
        let me = self.k5.k5();
        let path: Vec<Link> = self
            .k5
            .trust_path(&self.attestations, k5)
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|node| Link {
                label: if *node == me {
                    "ME".into()
                } else {
                    card_label(&self.attestations, node).into()
                },
                short: short(node).into(),
                me: *node == me,
            })
            .collect();

        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_dossier(dossier);
            ui.set_glyph(ModelRc::new(VecModel::from(glyph)));
            ui.set_path(ModelRc::new(VecModel::from(path)));
            ui.set_has_dossier(true);
            ui.set_show_me(false);
        });
    }

    /// Whether `k5` has an iroh attestation: it can be reached peer to peer.
    fn online(&self, k5: &str) -> bool {
        self.attestations
            .iter()
            .any(|attestation| attestation.profile.k5 == k5 && attestation.profile.platform == IROH)
    }

    /// Shows the conversation with `k5`, marking it read.
    fn open_chat(&mut self, k5: &str) {
        self.open_chat = Some(k5.to_string());
        self.unread.remove(k5);

        let name = who(&self.k5.k5(), &self.attestations, k5);
        let (k5, short) = (k5.to_string(), short(k5));
        let reachable = self.node.is_some() && self.online(&k5);
        let live = self.live.contains(&k5);
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_chat_name(name.into());
            ui.set_chat_short(short.into());
            ui.set_chat_reachable(reachable);
            ui.set_chat_online(live);
            ui.set_has_dossier(false);
            ui.set_show_me(false);
            ui.set_show_chats(true);
            ui.set_chat_k5(k5.into());
        });
        self.post_chats();
    }

    /// Sends `msg` to `to`: delivered peer to peer if `to` can be reached,
    /// else signcrypted and copied to the clipboard, to be handed over.
    /// Either way it is kept with the messages sent.
    fn chat_send(&mut self, runtime: &tokio::runtime::Runtime, to: &str, msg: &str) {
        let status = if let Some(node) = self.node.as_ref().filter(|_| self.online(to)) {
            self.status("DELIVERING MESSAGE ...".to_string(), true);
            match runtime.block_on(node.send(to, msg)) {
                Ok(()) => String::new(),
                Err(e) => return self.status(format!("DELIVERY FAILED: {e:#}"), false),
            }
        } else {
            self.status("SEALING MESSAGE ...".to_string(), true);
            let sealed = runtime.block_on(async {
                let sealed = self.k5.signcrypt(to, msg).await?;
                self.k5.record_sent(to, msg).await?;
                Ok::<_, k5lib::Error>(sealed.armored)
            });
            let armored = match sealed {
                Ok(armored) => armored,
                Err(e) => return self.status(format!("SEND FAILED: {e:#}"), false),
            };
            match self.copy(armored) {
                Ok(()) => "NOT REACHABLE PEER TO PEER: MESSAGE COPIED TO CLIPBOARD".to_string(),
                Err(e) => format!("COPY TO CLIPBOARD FAILED: {e:#}"),
            }
        };

        let _ = self.ui.upgrade_in_event_loop(|ui| ui.set_draft("".into()));
        self.load_chats(runtime);
        self.status(status, false);
    }

    /// Merges the attestations of the peer `k5` that are on the web of trust.
    fn sync(&mut self, runtime: &tokio::runtime::Runtime, k5: &str) {
        let Some(node) = &self.node else {
            return self.status("OFFLINE".to_string(), false);
        };
        let who = who(&self.k5.k5(), &self.attestations, k5);
        self.status(format!("SYNCING WITH {who} ..."), true);

        let report = match runtime.block_on(node.sync(k5)) {
            Ok(report) => report,
            Err(e) => return self.status(format!("SYNC FAILED: {e:#}"), false),
        };
        let count = |f: fn(&Outcome) -> bool| {
            report
                .merged
                .iter()
                .filter(|merged| f(&merged.outcome))
                .count()
        };
        let merged = new_records(&report);
        let untrusted = count(|outcome| matches!(outcome, Outcome::Untrusted(_)));
        let invalid = count(|outcome| matches!(outcome, Outcome::Invalid(_)));

        self.rescan(runtime);
        self.select(k5);
        self.status(
            format!("SYNCED WITH {who}: {merged} NEW, {untrusted} UNTRUSTED, {invalid} INVALID"),
            false,
        );
    }

    /// Copies the ticket of the node, for a first contact, to the clipboard.
    fn copy_ticket(&mut self, runtime: &tokio::runtime::Runtime) {
        let Some(node) = &self.node else {
            return self.status("OFFLINE".to_string(), false);
        };
        self.status("MAKING TICKET ...".to_string(), true);
        let status = match runtime
            .block_on(node.ticket())
            .map_err(|e| format!("{e:#}"))
        {
            Ok(ticket) => match self.copy(ticket) {
                Ok(()) => format!(
                    "TICKET COPIED TO CLIPBOARD: PAIRING OPEN FOR {} MINUTES",
                    PAIRING_WINDOW.as_secs() / 60
                ),
                Err(e) => format!("COPY TO CLIPBOARD FAILED: {e:#}"),
            },
            Err(e) => format!("NO TICKET: {e:#}"),
        };
        self.status(status, false);
    }

    /// Pairs with the k5 of a ticket, so each side learns how to reach the
    /// other, and shows the check phrase.
    fn connect_ticket(&mut self, runtime: &tokio::runtime::Runtime, ticket: &str) {
        let Some(node) = self.node.clone() else {
            return self.status("OFFLINE".to_string(), false);
        };
        self.status("CONNECTING ...".to_string(), true);

        match runtime.block_on(node.connect_ticket(ticket)) {
            Ok(contact) => {
                self.live.insert(contact.k5.clone());
                self.rescan(runtime);
                let who = who(&self.k5.k5(), &self.attestations, &contact.k5);
                self.show_pairing(&contact.k5, contact.trusted, &contact.phrase);
                self.status(format!("PAIRED WITH {who}"), false);
            }
            Err(e) => self.status(format!("CONNECT FAILED: {e:#}"), false),
        }
    }

    /// Shows the pairing dialog: the k5 met by ticket and the check phrase.
    fn show_pairing(&self, k5: &str, trusted: bool, phrase: &str) {
        let mut who = who(&self.k5.k5(), &self.attestations, k5);
        if !who.contains("k5:") {
            who = format!("{who} (k5:{})", short(k5));
        }
        let (k5, phrase) = (k5.to_string(), phrase.to_uppercase());
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_pair_k5(k5.into());
            ui.set_pair_who(who.into());
            ui.set_pair_phrase(phrase.into());
            ui.set_pair_trusted(trusted);
            ui.set_pair_name("".into());
            ui.set_pairing(true);
        });
    }

    /// Keysigns `k5` as `name`, after comparing the check phrases.
    fn keysign(&mut self, runtime: &tokio::runtime::Runtime, k5: &str, name: &str) {
        let name = name.trim();
        self.status("KEYSIGNING ...".to_string(), true);
        match runtime.block_on(self.k5.keysign(k5, name)) {
            Ok(_) => {
                self.rescan(runtime);
                self.status(format!("KEYSIGNED k5:{} AS {name}", short(k5)), false);
            }
            Err(e) => self.status(format!("KEYSIGN FAILED: {e:#}"), false),
        }
    }

    /// Verifies a signed message, a message for the local k5 or an
    /// attestation record, and shows the verdict.
    fn verify(&mut self, runtime: &tokio::runtime::Runtime, content: &str) {
        self.status("VERIFYING ...".to_string(), true);
        let verdict = match runtime.block_on(self.k5.verify(content.trim())) {
            Ok(verification) => self.verdict(verification),
            Err(e) => Verdict {
                ok: false,
                title: "NOT VERIFIED".into(),
                who: "".into(),
                trust: "".into(),
                body: format!("{e:#}").into(),
            },
        };
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_verdict(verdict);
            ui.set_has_verdict(true);
        });
        self.status(String::new(), false);
    }

    /// What a verification says, for the VERIFY screen.
    fn verdict(&self, verification: Verification) -> Verdict {
        let me = self.k5.k5();
        let signed_by = |k5: &str| format!("BY {}", who(&me, &self.attestations, k5));
        let verdict = |title: String, who: String, trust: String, body: String| Verdict {
            ok: true,
            title: title.into(),
            who: who.into(),
            trust: trust.into(),
            body: body.into(),
        };

        match verification {
            Verification::Signed {
                from,
                msg,
                export: None,
                ..
            } => verdict(
                "SIGNED MESSAGE".to_string(),
                signed_by(&from),
                self.trust(&from),
                msg,
            ),
            Verification::Signed {
                from,
                export: Some(checked),
                ..
            } => {
                let valid = checked.iter().filter(|check| check.result.is_ok()).count();
                let lines: Vec<String> = checked
                    .iter()
                    .map(|check| match &check.result {
                        Ok(attestation) => format!(
                            "OK    {}:{} k5:{}",
                            label(attestation.profile.platform),
                            attestation.profile.user,
                            short(&attestation.profile.k5)
                        ),
                        Err(e) => format!("FAIL  {}: {e}", check.file),
                    })
                    .collect();
                verdict(
                    format!(
                        "SIGNED EXPORT: {valid} OF {} ATTESTATIONS VALID",
                        checked.len()
                    ),
                    signed_by(&from),
                    self.trust(&from),
                    lines.join("\n"),
                )
            }
            Verification::Signcrypted { from, msg, .. } => verdict(
                "SIGNCRYPTED MESSAGE FOR YOU".to_string(),
                signed_by(&from),
                self.trust(&from),
                msg,
            ),
            Verification::Attestation(attested) => match attested.attestation(String::new()) {
                Ok(attestation) => {
                    let profile = &attestation.profile;
                    let details: Vec<String> = attestation
                        .attributes
                        .iter()
                        .map(|(key, value)| format!("{key}: {value}"))
                        .collect();
                    verdict(
                        format!("ATTESTATION: {}:{}", label(profile.platform), profile.user),
                        format!("OF {}", who(&me, &self.attestations, &profile.k5)),
                        self.trust(&profile.k5),
                        details.join("\n"),
                    )
                }
                Err(e) => Verdict {
                    ok: false,
                    title: "NOT A KNOWN PROFILE".into(),
                    who: "".into(),
                    trust: "".into(),
                    body: format!("{e:#}").into(),
                },
            },
        }
    }

    /// Whether `k5` is on the web of trust, and how many keysigns away.
    fn trust(&self, k5: &str) -> String {
        if k5 == self.k5.k5() {
            return "THAT IS YOU".to_string();
        }
        match self.k5.trust_path(&self.attestations, k5) {
            Some(path) => {
                let away = path.len().saturating_sub(1);
                let plural = if away == 1 { "" } else { "S" };
                format!("ON YOUR WEB OF TRUST, {away} KEYSIGN{plural} AWAY")
            }
            None => "NOT ON YOUR WEB OF TRUST".to_string(),
        }
    }

    /// Checks which trusted peers that can be reached peer to peer answer,
    /// syncing with those due (see [`SYNC_INTERVAL`]) instead of just saying
    /// hello, on the runtime. The results come back as [`Request::Probed`].
    fn probe(&mut self, runtime: &tokio::runtime::Runtime) {
        let (Some(node), Some(requests)) = (self.node.clone(), self.requests.clone()) else {
            return;
        };
        if self.probing {
            return;
        }
        let me = self.k5.k5();
        let peers: Vec<String> = self
            .trusted
            .iter()
            .filter(|k5| **k5 != me && self.online(k5))
            .cloned()
            .collect();
        if peers.is_empty() {
            return;
        }
        let now = Instant::now();
        let jobs: Vec<(String, bool)> = peers
            .into_iter()
            .map(|k5| {
                let due = self.auto_sync
                    && self
                        .last_sync
                        .get(&k5)
                        .is_none_or(|last| now.duration_since(*last) >= SYNC_INTERVAL);
                if due {
                    self.last_sync.insert(k5.clone(), now);
                }
                (k5, due)
            })
            .collect();

        self.probing = true;
        runtime.spawn(async move {
            let mut checks = tokio::task::JoinSet::new();
            for (k5, sync) in jobs {
                let node = node.clone();
                checks.spawn(async move {
                    let answered = if sync {
                        tokio::time::timeout(SYNC_TIMEOUT, node.sync(&k5))
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .map(|report| Some(new_records(&report)))
                    } else {
                        tokio::time::timeout(PING_TIMEOUT, node.ping(&k5))
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .map(|()| None)
                    };
                    Probe {
                        k5,
                        online: answered.is_some(),
                        synced: answered.flatten(),
                    }
                });
            }
            let mut probes = Vec::new();
            while let Some(probe) = checks.join_next().await {
                probes.extend(probe.ok());
            }
            let _ = requests.send(Request::Probed(probes));
        });
    }

    /// Shows who answered the presence check, and what automatic sync
    /// brought.
    fn probed(&mut self, runtime: &tokio::runtime::Runtime, probes: Vec<Probe>) {
        self.probing = false;
        let me = self.k5.k5();
        let mut synced = Vec::new();
        for probe in probes {
            if probe.online {
                self.live.insert(probe.k5.clone());
            } else {
                self.live.remove(&probe.k5);
            }
            if let Some(new) = probe.synced.filter(|new| *new > 0) {
                synced.push(format!(
                    "{new} FROM {}",
                    who(&me, &self.attestations, &probe.k5)
                ));
            }
        }

        if synced.is_empty() {
            self.search();
        } else {
            self.rescan(runtime);
            self.status(format!("AUTO SYNC: {} NEW", synced.join(", ")), false);
        }
        let live = self
            .open_chat
            .as_ref()
            .is_some_and(|k5| self.live.contains(k5));
        let _ = self
            .ui
            .upgrade_in_event_loop(move |ui| ui.set_chat_online(live));
    }

    /// Attests a profile of the local k5 with the notary: notarizes the page
    /// that shows the k5 and stores the attestation. On success, shows the
    /// dossier of the local k5.
    fn attest(&mut self, runtime: &tokio::runtime::Runtime, kind: &str, input: &str) {
        let Some(notary) = self.attesting.notary.clone() else {
            return self.status(
                "NO NOTARY: START K5GUI WITH --notary-host".to_string(),
                false,
            );
        };
        let url = match attest_url(kind, input) {
            Ok(url) => url,
            Err(e) => return self.status(format!("CANNOT ATTEST: {e}"), false),
        };
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_millis());
        let presentation = self
            .attesting
            .presentations
            .join(format!("{kind}-{millis}.tlsn"));
        if let Err(e) = std::fs::create_dir_all(&self.attesting.presentations) {
            return self.status(format!("ATTEST FAILED: {e:#}"), false);
        }

        self.status(format!("NOTARIZING {url} ..."), true);
        let ui = self.ui.clone();
        let notarized = runtime.block_on(self.k5.notarize(
            &notary,
            &url,
            &presentation.to_string_lossy(),
            &mut |step| {
                let step = step.to_uppercase();
                let _ = ui.upgrade_in_event_loop(move |ui| ui.set_status(step.into()));
            },
        ));
        let stored = match notarized.map(|notarized| notarized.record) {
            Ok(Ok(stored)) => stored,
            Ok(Err(reason)) => return self.status(format!("NOT ATTESTED: {reason}"), false),
            Err(e) => return self.status(format!("ATTEST FAILED: {e:#}"), false),
        };

        // Records are named after the k5 they attest.
        let me = self.k5.k5();
        let file = Path::new(&stored)
            .file_name()
            .map_or(stored.clone(), |file| file.to_string_lossy().into_owned());
        self.rescan(runtime);
        if !file.starts_with(&me) {
            return self.status(
                format!("ATTESTED, BUT THE PAGE SHOWS ANOTHER K5: {file}"),
                false,
            );
        }
        self.show_me();
        self.status(format!("ATTESTED: {file}"), false);
    }

    /// Reports what the node did.
    fn net_event(&mut self, runtime: &tokio::runtime::Runtime, event: Event) {
        let me = self.k5.k5();
        let status = match event {
            Event::Received { from, .. } => {
                self.live.insert(from.clone());
                // The sender's records may have just arrived with its hello:
                // rescan so the conversation knows who it is.
                if !self.attestations.iter().any(|a| a.profile.k5 == from) {
                    self.rescan(runtime);
                }
                if self.open_chat.as_deref() != Some(from.as_str()) {
                    *self.unread.entry(from.clone()).or_default() += 1;
                }
                self.load_chats(runtime);
                format!("MESSAGE FROM {}", who(&me, &self.attestations, &from))
            }
            Event::Served { k5 } => {
                format!(
                    "SHARED ATTESTATIONS WITH {}",
                    who(&me, &self.attestations, &k5)
                )
            }
            Event::Paired {
                k5,
                trusted,
                phrase,
            } => {
                // Its records arrived with the hello.
                self.live.insert(k5.clone());
                self.rescan(runtime);
                self.show_pairing(&k5, trusted, &phrase);
                format!("PAIRED WITH {}", who(&me, &self.attestations, &k5))
            }
            Event::Refused { endpoint, reason } => {
                format!("REFUSED {}: {reason}", short(&endpoint))
            }
            Event::Error(e) => format!("P2P ERROR: {e:#}"),
        };
        self.status(status, false);
    }

    /// Loads the conversations and posts them.
    fn load_chats(&mut self, runtime: &tokio::runtime::Runtime) {
        match runtime.block_on(self.k5.conversations()) {
            Ok(conversations) => self.conversations = conversations,
            Err(e) => return self.status(format!("MESSAGES FAILED: {e:#}"), false),
        }
        self.post_chats();
    }

    /// Posts the list of conversations, the messages of the open one and the
    /// number of unread messages.
    fn post_chats(&self) {
        let me = self.k5.k5();
        let chats: Vec<Chat> = self
            .conversations
            .iter()
            .filter_map(|conversation| {
                let last = conversation.messages.last()?;
                Some(Chat {
                    k5: conversation.k5.as_str().into(),
                    name: who(&me, &self.attestations, &conversation.k5).into(),
                    short: short(&conversation.k5).into(),
                    last: first_line(&last.msg).into(),
                    time: time(last.time).into(),
                    outgoing: last.outgoing,
                    unread: self.unread.get(&conversation.k5).copied().unwrap_or(0) as i32,
                })
            })
            .collect();
        let bubbles: Vec<Bubble> = self
            .open_chat
            .as_ref()
            .and_then(|k5| self.conversations.iter().find(|c| &c.k5 == k5))
            .map(|conversation| {
                conversation
                    .messages
                    .iter()
                    .map(|message| Bubble {
                        msg: message.msg.as_str().into(),
                        time: time(message.time).into(),
                        outgoing: message.outgoing,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let unread = self.unread.values().sum::<usize>() as i32;

        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_chats(ModelRc::new(VecModel::from(chats)));
            ui.set_bubbles(ModelRc::new(VecModel::from(bubbles)));
            ui.set_unread(unread);
        });
    }

    /// Puts `text` on the clipboard. The clipboard is kept open: on Linux its
    /// content is lost when it is closed.
    fn copy(&mut self, text: String) -> Result<(), arboard::Error> {
        let clipboard = match &mut self.clipboard {
            Some(clipboard) => clipboard,
            None => self.clipboard.insert(arboard::Clipboard::new()?),
        };
        clipboard.set_text(text)
    }
}

/// The URL the notary attests for a profile of `kind` identified by `input`:
/// the tweet URL (`x`), the raw gist (`github`, from a gist URL), or
/// `k5.txt` on the domain (`site`).
fn attest_url(kind: &str, input: &str) -> Result<String, String> {
    let input = input.trim();
    match kind {
        // The X plugin fetches tweets through X's syndication endpoint.
        "x" if input.starts_with("https://") => Ok(input.to_string()),
        "x" => Err("EXPECTED THE https:// URL OF THE TWEET".to_string()),
        "github" => gist_url(input),
        "site" => {
            let domain = input
                .strip_prefix("https://")
                .or_else(|| input.strip_prefix("http://"))
                .unwrap_or(input);
            let domain = domain
                .split('/')
                .next()
                .unwrap_or_default()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            // As the site plugin requires: a domain without subdomain.
            let labels: Vec<&str> = domain.split('.').collect();
            if labels.len() != 2 || labels.iter().any(|label| label.is_empty()) {
                return Err(format!(
                    "`{domain}` IS NOT A DOMAIN WITHOUT SUBDOMAIN, E.G. example.com"
                ));
            }
            Ok(format!("https://{domain}/k5.txt"))
        }
        "email" => Err("EMAIL ATTESTATIONS ARE NOT AVAILABLE YET".to_string()),
        other => Err(format!("UNKNOWN PROFILE `{other}`")),
    }
}

/// The raw URL of a gist, which the GitHub plugin attests: a raw URL as is,
/// and `https://gist.github.com/<user>/<id>` as its raw content.
fn gist_url(input: &str) -> Result<String, String> {
    const RAW: &str = "https://gist.githubusercontent.com/";
    const PAGE: &str = "https://gist.github.com/";

    if input.starts_with(RAW) {
        return Ok(input.to_string());
    }
    let path = input
        .strip_prefix(PAGE)
        .ok_or_else(|| format!("EXPECTED A GIST URL: {PAGE}<USER>/<ID>"))?;
    let path = path.split(['#', '?']).next().unwrap_or_default();
    match path.split('/').collect::<Vec<_>>()[..] {
        [user, id, ..] if !user.is_empty() && !id.is_empty() => Ok(format!("{RAW}{user}/{id}/raw")),
        _ => Err(format!("EXPECTED A GIST URL: {PAGE}<USER>/<ID>")),
    }
}

/// Display name of a platform.
fn label(platform: &str) -> String {
    match platform {
        "keysignparty" => "KEYSIGN".to_string(),
        "self_attestation" => "SELF".to_string(),
        other => other.to_uppercase(),
    }
}

/// When a message was sent or received: the time if today, else the date
/// and time, in local time.
fn time(millis: u64) -> String {
    use chrono::TimeZone;

    let Some(time) = chrono::Local.timestamp_millis_opt(millis as i64).single() else {
        return String::new();
    };
    if time.date_naive() == chrono::Local::now().date_naive() {
        time.format("%H:%M").to_string()
    } else {
        time.format("%Y-%m-%d %H:%M").to_string()
    }
}

/// The first line of a message, for the list of conversations.
fn first_line(msg: &str) -> &str {
    msg.lines().next().unwrap_or("")
}

/// `0123abcd…cdef` for a long hex string.
fn short(hex: &str) -> String {
    if hex.len() <= 16 {
        return hex.to_string();
    }
    format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
}

/// The search results for `query`: the k5s other than the local one (`me`)
/// with a profile or a keysign (self and iroh attestations are never shown)
/// whose user or k5 contains the query, ignoring case, one per k5, by who
/// they are, marking those that can be reached peer to peer (with an iroh
/// attestation) and those that answered the last presence check (`live`).
/// An empty query matches everything.
fn hits(
    me: &str,
    attestations: &[ProfileAttestation],
    query: &str,
    live: &HashSet<String>,
) -> Vec<Hit> {
    let query = query.trim().to_lowercase();
    let query = query.strip_prefix("k5:").unwrap_or(&query);

    let matching: BTreeSet<&str> = attestations
        .iter()
        .filter(|attestation| attestation.profile.k5 != me)
        .filter(|attestation| !matches!(attestation.profile.platform, SELF | IROH))
        .filter(|attestation| {
            attestation.profile.user.to_lowercase().contains(query)
                || attestation.profile.k5.contains(query)
        })
        .map(|attestation| attestation.profile.k5.as_str())
        .collect();
    let p2p: HashSet<&str> = attestations
        .iter()
        .filter(|attestation| attestation.profile.platform == IROH)
        .map(|attestation| attestation.profile.k5.as_str())
        .collect();
    let mut hits: Vec<Hit> = matching
        .into_iter()
        .map(|k5| Hit {
            k5: k5.into(),
            short: short(k5).into(),
            label: card_label(attestations, k5).into(),
            p2p: p2p.contains(k5),
            online: live.contains(k5),
        })
        .collect();
    hits.sort_by_cached_key(|hit| hit.label.to_lowercase());
    hits.truncate(MAX_HITS);

    hits
}

/// The records a sync added or updated.
fn new_records(report: &MergeReport) -> usize {
    report
        .merged
        .iter()
        .filter(|merged| matches!(merged.outcome, Outcome::Added(_) | Outcome::Replaced(_)))
        .count()
}

/// The attestations of the local k5 (`me`), for the ME screen: its profiles
/// first, then the keysigns of it, its self attestation and its peer-to-peer
/// endpoint.
fn owned(me: &str, attestations: &[ProfileAttestation]) -> Vec<Owned> {
    let attribute = |attestation: &ProfileAttestation, name: &str| {
        attestation
            .attributes
            .iter()
            .find(|(key, _)| *key == name)
            .map_or(String::new(), |(_, value)| value.clone())
    };
    // The day of an RFC 3339 time.
    let day = |time: String| time.get(..10).map_or(time.clone(), str::to_string);

    let mut owned: Vec<(u8, Owned)> = attestations
        .iter()
        .filter(|attestation| attestation.profile.k5 == me)
        .map(|attestation| {
            let user = &attestation.profile.user;
            let date = || day(attribute(attestation, "date"));
            let (rank, icon, title, detail) = match attestation.profile.platform {
                KEYSIGN => {
                    let signer = attestation.signer.as_deref().unwrap_or_default();
                    let by = who(me, attestations, signer);
                    (
                        1,
                        "keysign",
                        format!("KEYSIGNED AS {user}"),
                        format!("BY {by} · {}", date()),
                    )
                }
                SELF => (
                    2,
                    "self",
                    "SELF ATTESTATION".to_string(),
                    format!("PUBLIC KEYS · {}", date()),
                ),
                IROH => (
                    3,
                    "p2p",
                    "P2P ENDPOINT".to_string(),
                    format!("{} · {}", short(user), date()),
                ),
                platform => {
                    // Notarized at a time, or generated (fake) at a date.
                    let time = Some(attribute(attestation, "time"))
                        .filter(|time| !time.is_empty())
                        .map_or_else(date, day);
                    let server = attribute(attestation, "server");
                    (
                        0,
                        icon(platform),
                        format!("{} : {user}", label(platform)),
                        format!("{server} · {time}"),
                    )
                }
            };
            let fake = if attestation.fake { "  FAKE" } else { "" };
            let owned = Owned {
                icon: icon.into(),
                title: title.into(),
                detail: format!("{detail}{fake}").into(),
            };
            (rank, owned)
        })
        .collect();
    owned.sort_by_cached_key(|(rank, owned)| (*rank, owned.title.to_string()));

    owned.into_iter().map(|(_, owned)| owned).collect()
}

/// PixelIcon of a profile platform.
fn icon(platform: &str) -> &'static str {
    match platform {
        "X" => "x",
        "github" => "github",
        "site" => "site",
        _ => "other",
    }
}

/// The profiles of `k5` among `attestations`, `X:handle · GITHUB:user`, if
/// it has any.
fn profiles(attestations: &[ProfileAttestation], k5: &str) -> Option<String> {
    let profiles: BTreeSet<String> = attestations
        .iter()
        .filter(|attestation| attestation.profile.k5 == k5)
        .filter(|attestation| !matches!(attestation.profile.platform, SELF | KEYSIGN | IROH))
        .map(|attestation| {
            format!(
                "{}:{}",
                label(attestation.profile.platform),
                attestation.profile.user
            )
        })
        .collect();

    (!profiles.is_empty()).then(|| profiles.into_iter().collect::<Vec<_>>().join(" · "))
}

/// The name `k5` was keysigned with, among `attestations`, if any.
fn keysigned_name<'a>(attestations: &'a [ProfileAttestation], k5: &str) -> Option<&'a str> {
    attestations
        .iter()
        .find(|attestation| attestation.profile.k5 == k5 && attestation.profile.platform == KEYSIGN)
        .map(|attestation| attestation.profile.user.as_str())
}

/// Who `k5` is, on a card that also shows its short id: its profiles, or
/// else the name it was keysigned with.
fn card_label(attestations: &[ProfileAttestation], k5: &str) -> String {
    profiles(attestations, k5)
        .or_else(|| keysigned_name(attestations, k5).map(str::to_string))
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

/// Who `k5` is, among `attestations` (`me` being the local k5): its
/// profiles (`X:handle · GITHUB:user`), or else the name it was keysigned
/// with, or else its short id.
fn who(me: &str, attestations: &[ProfileAttestation], k5: &str) -> String {
    if k5 == me {
        return "YOU".to_string();
    }
    if let Some(profiles) = profiles(attestations, k5) {
        return profiles;
    }

    match keysigned_name(attestations, k5) {
        Some(name) => format!("{name} (k5:{})", short(k5)),
        None => format!("k5:{}", short(k5)),
    }
}

/// A 9x9 horizontally symmetric identicon from the bits of `k5`.
fn glyph(k5: &str) -> Vec<i32> {
    let bits: Vec<bool> = k5
        .chars()
        .filter_map(|c| c.to_digit(16))
        .flat_map(|nibble| (0..4).map(move |bit| nibble >> bit & 1 == 1))
        .collect();

    (0..81)
        .map(|i| {
            let (row, col) = (i / 9, i % 9);
            let col = col.min(8 - col);
            bits.get(row * 5 + col).copied().unwrap_or(false) as i32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders the window with sample data to `$K5_SNAPSHOT/search.ppm`,
    /// `search-typed.ppm`, `menu.ppm`, `menu-attest.ppm`, `chats.ppm`,
    /// `chat.ppm`, `chat-draft.ppm`, `dossier.ppm`, `connect.ppm`,
    /// `attest-x.ppm`, `attest-site.ppm`, `attest-email.ppm`, `me.ppm`,
    /// `verify.ppm`, `verify-invalid.ppm` and `pairing.ppm`, with the software
    /// renderer, to look at the design without a display.
    #[test]
    #[ignore = "writes window snapshots to $K5_SNAPSHOT"]
    fn snapshot() {
        use std::rc::Rc;

        use slint::platform::{
            software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
            Platform, WindowAdapter,
        };

        struct Offscreen(Rc<MinimalSoftwareWindow>);
        impl Platform for Offscreen {
            fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
                Ok(self.0.clone())
            }
        }

        let dir = std::env::var("K5_SNAPSHOT").expect("set K5_SNAPSHOT to a directory");
        let (width, height) = (430, 932);
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(Offscreen(window.clone()))).unwrap();
        window.set_size(slint::PhysicalSize::new(width, height));

        let ui = AppWindow::new().unwrap();
        let me = "04d3b0f990d5564e5d7a698940483d07e030f37a9dfb112ad337dd23b512c785";
        let bob = "21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd";
        ui.set_me(short(me).into());
        ui.set_me_k5(me.into());
        ui.set_me_glyph(ModelRc::new(VecModel::from(glyph(me))));
        ui.set_notary("notary.example.com:7047".into());
        ui.set_stats_ids("51".into());
        ui.set_stats_trusted("41".into());
        let hit = |label: &str, k5: &str, p2p, online| Hit {
            k5: k5.into(),
            short: short(k5).into(),
            label: label.into(),
            p2p,
            online,
        };
        let carol = "9f3c0a7e55d1b2c4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1";
        let dave = "5a1f0c3e9b7d2468ace013579bdf2468ace013579bdf2468ace013579bdf2468";
        ui.set_hits(ModelRc::new(VecModel::from(vec![
            hit("GITHUB:bob · X:bob_builds", bob, true, true),
            hit("Carol", carol, false, false),
            hit("X:dave_d", dave, true, false),
        ])));
        ui.set_dossier(Dossier {
            k5: me.into(),
            k5_a: me[..32].into(),
            k5_b: me[32..].into(),
            name: "adria0".into(),
            kem: true,
            online: true,
            live: true,
            trusted: true,
            me: false,
            x: 1,
            github: 1,
            site: 1,
            keysign: 1,
        });
        ui.set_glyph(ModelRc::new(VecModel::from(glyph(me))));
        let link = |label: &str, k5: &str, me| Link {
            label: label.into(),
            short: short(k5).into(),
            me,
        };
        ui.set_path(ModelRc::new(VecModel::from(vec![
            link("GITHUB:adria0 · SITE:ethbcn.dev · X:adria0", me, false),
            link("X:bob_builds · GITHUB:bob", bob, false),
            link("ME", me, true),
        ])));
        ui.set_endpoint(short(bob).into());
        let chat = |k5: &str, name: &str, last: &str, time: &str, outgoing, unread| Chat {
            k5: k5.into(),
            name: name.into(),
            short: short(k5).into(),
            last: last.into(),
            time: time.into(),
            outgoing,
            unread,
        };
        ui.set_chats(ModelRc::new(VecModel::from(vec![
            chat(
                bob,
                "X:bob_builds · GITHUB:bob",
                "see you at the party",
                "18:42",
                false,
                2,
            ),
            chat(
                me,
                "adria0",
                "sent you my gist",
                "2026-09-24 10:03",
                true,
                0,
            ),
        ])));
        ui.set_unread(2);
        let bubble = |msg: &str, time: &str, outgoing| Bubble {
            msg: msg.into(),
            time: time.into(),
            outgoing,
        };
        ui.set_bubbles(ModelRc::new(VecModel::from(vec![
            bubble(
                "hey bob, are you coming to the keysigning party?",
                "18:30",
                true,
            ),
            bubble("yes! bring your k5 printed", "18:41", false),
            bubble("see you at the party", "18:42", false),
        ])));
        ui.set_chat_name("X:bob_builds · GITHUB:bob".into());
        ui.set_chat_short(short(bob).into());
        ui.set_chat_reachable(true);
        ui.show().unwrap();

        let render = |name: &str| {
            slint::platform::update_timers_and_animations();
            window.request_redraw();
            let mut buffer = vec![slint::Rgb8Pixel::default(); (width * height) as usize];
            window.draw_if_needed(|renderer| {
                renderer.render(&mut buffer, width as usize);
            });
            let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
            for pixel in &buffer {
                ppm.extend([pixel.r, pixel.g, pixel.b]);
            }
            std::fs::write(format!("{dir}/{name}.ppm"), ppm).unwrap();
        };
        render("search");
        // The cursor follows what is typed.
        for key in "adr".chars() {
            use slint::platform::WindowEvent;

            let text: slint::SharedString = key.into();
            window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
            window.dispatch_event(WindowEvent::KeyReleased { text });
        }
        render("search-typed");

        // The menu opens from the button at the right of the main row.
        let click = |x: f32, y: f32| {
            use slint::platform::{PointerEventButton, WindowEvent};

            let position = slint::LogicalPosition::new(x, y);
            let button = PointerEventButton::Left;
            window.dispatch_event(WindowEvent::PointerPressed { position, button });
            window.dispatch_event(WindowEvent::PointerReleased { position, button });
        };
        let menu_x = width as f32 - 20.0 - 20.0;
        let menu_y = menu_row_y(&window, width, height);
        click(menu_x, menu_y);
        render("menu");
        // The entries reach the window: the popup's rows start below its
        // border and padding, 46px apart.
        let entry = |row: f32| menu_y + 20.0 + 6.0 + 3.0 + 6.0 + row * 46.0 + 22.0;
        let tickets = Rc::new(std::cell::Cell::new(0));
        ui.on_copy_ticket({
            let tickets = tickets.clone();
            move || tickets.set(tickets.get() + 1)
        });
        let mes = Rc::new(std::cell::Cell::new(0));
        ui.on_open_me({
            let mes = mes.clone();
            move || mes.set(mes.get() + 1)
        });
        let toggles = Rc::new(std::cell::Cell::new(0));
        ui.on_toggle_auto_sync({
            let toggles = toggles.clone();
            move || toggles.set(toggles.get() + 1)
        });
        click(menu_x, entry(0.0));
        assert_eq!(mes.get(), 1, "ME");
        click(menu_x, menu_y);
        click(menu_x, entry(1.0));
        assert!(ui.get_verifying(), "VERIFY");
        ui.set_verifying(false);
        click(menu_x, menu_y);
        click(menu_x, entry(2.0));
        assert_eq!(tickets.get(), 1, "TICKET");
        click(menu_x, menu_y);
        click(menu_x, entry(3.0));
        assert!(ui.get_connecting(), "CONNECT");
        ui.set_connecting(false);
        click(menu_x, menu_y);
        click(menu_x, entry(4.0));
        assert_eq!(toggles.get(), 1, "AUTO SYNC");
        click(menu_x, menu_y);
        click(menu_x, entry(5.0));
        click(menu_x, entry(2.0));
        assert_eq!(ui.get_attest_kind(), "x", "MY X");
        ui.set_attest_kind("".into());
        click(menu_x, menu_y);
        // `ATTEST >`, the sixth entry.
        click(menu_x, entry(5.0));
        render("menu-attest");
        // Close it.
        click(20.0, height as f32 - 20.0);

        ui.set_show_chats(true);
        render("chats");
        ui.set_chat_k5(bob.into());
        render("chat");
        ui.set_draft("thanks, see you".into());
        render("chat-draft");
        ui.set_chat_k5("".into());
        ui.set_show_chats(false);
        ui.set_has_dossier(true);
        render("dossier");
        ui.set_has_dossier(false);
        ui.set_connecting(true);
        render("connect");
        ui.set_connecting(false);
        ui.set_attest_kind("x".into());
        render("attest-x");
        ui.set_attest_kind("site".into());
        ui.set_attest_input("example.com".into());
        render("attest-site");
        ui.set_attest_kind("email".into());
        render("attest-email");
        ui.set_attest_kind("".into());
        let owned = |icon: &str, title: &str, detail: &str| Owned {
            icon: icon.into(),
            title: title.into(),
            detail: detail.into(),
        };
        ui.set_owned(ModelRc::new(VecModel::from(vec![
            owned("x", "X : adria0", "cdn.syndication.twimg.com · 2026-09-24"),
            owned(
                "github",
                "GITHUB : adria0",
                "gist.githubusercontent.com · 2026-09-24",
            ),
            owned(
                "keysign",
                "KEYSIGNED AS Adria",
                "BY X:bob_builds · GITHUB:bob · 2026-09-25",
            ),
            owned("self", "SELF ATTESTATION", "PUBLIC KEYS · 2026-09-20"),
            owned(
                "p2p",
                "P2P ENDPOINT",
                &format!("{} · 2026-09-26", short(bob)),
            ),
        ])));
        ui.set_show_me(true);
        render("me");
        ui.set_show_me(false);

        ui.set_verifying(true);
        ui.set_verify_input("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-512\n\nsee you at the party\n-----BEGIN PGP SIGNATURE-----".into());
        ui.set_verdict(Verdict {
            ok: true,
            title: "SIGNED MESSAGE".into(),
            who: "BY GITHUB:bob · X:bob_builds".into(),
            trust: "ON YOUR WEB OF TRUST, 1 KEYSIGN AWAY".into(),
            body: "see you at the party".into(),
        });
        ui.set_has_verdict(true);
        render("verify");
        ui.set_verdict(Verdict {
            ok: false,
            title: "NOT VERIFIED".into(),
            who: "".into(),
            trust: "".into(),
            body: "unknown signer k5:21e0a274…: fetch its self attestation first".into(),
        });
        render("verify-invalid");
        ui.set_verifying(false);

        ui.set_pair_k5(bob.into());
        ui.set_pair_who(format!("k5:{}", short(bob)).into());
        ui.set_pair_phrase("TIGER CANOE MAPLE ORBIT".into());
        ui.set_pair_trusted(false);
        ui.set_pairing(true);
        render("pairing");
        ui.set_pairing(false);
    }

    /// The vertical center of the main row (chats and menu) of the search
    /// screen: the first row, below the header, with a dark border pixel at
    /// the right edge of the content.
    fn menu_row_y(
        window: &slint::platform::software_renderer::MinimalSoftwareWindow,
        width: u32,
        height: u32,
    ) -> f32 {
        let mut buffer = vec![slint::Rgb8Pixel::default(); (width * height) as usize];
        window.request_redraw();
        window.draw_if_needed(|renderer| {
            renderer.render(&mut buffer, width as usize);
        });
        // The right border of the menu button, 20px padding from the edge.
        let x = (width - 21) as usize;
        let dark = |y: usize| {
            let pixel = buffer[y * width as usize + x];
            (pixel.r as u32 + pixel.g as u32 + pixel.b as u32) < 150
        };
        let top = (100..height as usize)
            .find(|&y| dark(y))
            .expect("no menu button");
        top as f32 + 20.0
    }

    #[test]
    fn test_attest_url() {
        let tweet = "https://x.com/adria0/status/2102469944159989833?s=20";
        assert_eq!(attest_url("x", &format!(" {tweet} ")).unwrap(), tweet);
        assert!(attest_url("x", "x.com/adria0/status/1").is_err());

        let raw = "https://gist.githubusercontent.com/adria0/0123abcd/raw/k5.txt";
        assert_eq!(attest_url("github", raw).unwrap(), raw);
        for page in [
            "https://gist.github.com/adria0/0123abcd",
            "https://gist.github.com/adria0/0123abcd#file-k5-txt",
            "https://gist.github.com/adria0/0123abcd/",
        ] {
            assert_eq!(
                attest_url("github", page).unwrap(),
                "https://gist.githubusercontent.com/adria0/0123abcd/raw",
                "{page}"
            );
        }
        assert!(attest_url("github", "https://gist.github.com/adria0").is_err());
        assert!(attest_url("github", "https://github.com/adria0").is_err());

        for domain in [
            "example.com",
            "https://Example.com/",
            "http://example.com/k5.txt",
        ] {
            assert_eq!(
                attest_url("site", domain).unwrap(),
                "https://example.com/k5.txt",
                "{domain}"
            );
        }
        assert!(attest_url("site", "www.example.com").is_err());
        assert!(attest_url("site", "localhost").is_err());

        assert!(attest_url("email", "me@example.com").is_err());
    }

    #[test]
    fn test_glyph() {
        let glyph = glyph(&"a5".repeat(32));
        assert_eq!(glyph.len(), 81);
        for row in glyph.chunks(9) {
            let mirrored: Vec<i32> = row.iter().rev().copied().collect();
            assert_eq!(row, mirrored);
        }
    }

    #[test]
    fn test_who() {
        use k5lib::api::Profile;

        let attestation = |platform: &'static str, user: &str, k5: &str| ProfileAttestation {
            profile: Profile {
                platform,
                user: user.to_string(),
                k5: k5.to_string(),
            },
            signer: None,
            attributes: Vec::new(),
            file: String::new(),
            fake: false,
        };
        let [me, alice, bob, carol] = ["a", "b", "c", "d"].map(|c| c.repeat(64));
        let attestations = [
            attestation("github", "alice", &alice),
            attestation("X", "alice_x", &alice),
            attestation(SELF, "self", &alice),
            attestation(KEYSIGN, "Alice", &alice),
            attestation(SELF, "self", &bob),
            attestation(KEYSIGN, "Bob", &bob),
        ];

        assert_eq!(who(&me, &attestations, &me), "YOU");
        assert_eq!(who(&me, &attestations, &alice), "GITHUB:alice · X:alice_x");
        assert_eq!(
            who(&me, &attestations, &bob),
            format!("Bob (k5:{})", short(&bob))
        );
        assert_eq!(
            who(&me, &attestations, &carol),
            format!("k5:{}", short(&carol))
        );
    }

    #[test]
    fn test_hits() {
        use k5lib::api::Profile;

        let attestation = |platform: &'static str, user: &str, k5: &str| ProfileAttestation {
            profile: Profile {
                platform,
                user: user.to_string(),
                k5: k5.to_string(),
            },
            signer: None,
            attributes: Vec::new(),
            file: String::new(),
            fake: false,
        };
        let [me, alice, bob, carol] = ["a", "b", "c", "d"].map(|c| c.repeat(64));
        let attestations = [
            attestation("X", "zed", &me),
            attestation("github", "alice", &alice),
            attestation("X", "alice_x", &alice),
            attestation(SELF, "self", &alice),
            attestation(KEYSIGN, "Alice", &alice),
            attestation(KEYSIGN, "Alice", &alice),
            attestation(SELF, "self", &bob),
            attestation(KEYSIGN, "Bob", &bob),
            attestation(IROH, "endpoint", &bob),
            // Only a self attestation: never listed.
            attestation(SELF, "self", &carol),
        ];
        let listed = |query: &str| -> Vec<(String, String)> {
            hits(&me, &attestations, query, &HashSet::new())
                .into_iter()
                .map(|hit| (hit.k5.into(), hit.label.into()))
                .collect()
        };

        // One entry per k5 but the local one, by label.
        assert_eq!(
            listed(""),
            [
                (bob.clone(), "Bob".to_string()),
                (alice.clone(), "GITHUB:alice · X:alice_x".to_string()),
            ]
        );
        assert!(listed("zed").is_empty(), "the local k5 is not listed");
        // Matches any profile or keysigned name, or the k5.
        assert_eq!(listed("ALICE_X")[0].0, alice, "ignoring case");
        assert_eq!(listed("alice").len(), 1, "one entry per k5");
        assert_eq!(listed("Bob")[0].0, bob);
        assert_eq!(listed(&format!("k5:{}", &bob[..8]))[0].0, bob);
        assert!(listed("self").is_empty());
        // Iroh attestations only mark who can be reached peer to peer.
        assert!(listed("endpoint").is_empty());
        // Who answered the last presence check is marked online.
        let live = HashSet::from([bob.clone()]);
        let online: Vec<bool> = hits(&me, &attestations, "", &live)
            .iter()
            .map(|hit| hit.online)
            .collect();
        assert_eq!(online, [true, false]);
        let p2p: Vec<bool> = hits(&me, &attestations, "", &live)
            .iter()
            .map(|hit| hit.p2p)
            .collect();
        assert_eq!(p2p, [true, false]);
    }

    #[test]
    fn test_owned() {
        use k5lib::api::Profile;

        let [me, bob] = ["a", "b"].map(|c| c.repeat(64));
        let endpoint = "e".repeat(64);
        let attestation = |platform: &'static str,
                           user: &str,
                           k5: &str,
                           signer: Option<&str>,
                           attributes: Vec<(&'static str, &str)>| {
            ProfileAttestation {
                profile: Profile {
                    platform,
                    user: user.to_string(),
                    k5: k5.to_string(),
                },
                signer: signer.map(str::to_string),
                attributes: attributes
                    .into_iter()
                    .map(|(key, value)| (key, value.to_string()))
                    .collect(),
                file: String::new(),
                fake: false,
            }
        };
        let attestations = [
            attestation(
                IROH,
                &endpoint,
                &me,
                Some(&me),
                vec![("date", "2026-09-03T00:00:00Z")],
            ),
            attestation(
                SELF,
                "self",
                &me,
                Some(&me),
                vec![("date", "2026-09-01T00:00:00Z")],
            ),
            attestation(
                KEYSIGN,
                "Adria",
                &me,
                Some(&bob),
                vec![("date", "2026-09-02T10:00:00Z")],
            ),
            attestation(
                "X",
                "adria0",
                &me,
                None,
                vec![("server", "api.x.com"), ("time", "2026-09-04T12:00:00Z")],
            ),
            attestation("github", "bob", &bob, None, vec![]),
            attestation(KEYSIGN, "Bob", &bob, Some(&me), vec![]),
        ];

        let owned: Vec<(String, String, String)> = owned(&me, &attestations)
            .into_iter()
            .map(|owned| (owned.icon.into(), owned.title.into(), owned.detail.into()))
            .collect();
        let row = |icon: &str, title: &str, detail: &str| {
            (icon.to_string(), title.to_string(), detail.to_string())
        };
        // Profiles, keysigns, self attestation, endpoint; not bob's.
        assert_eq!(
            owned,
            [
                row("x", "X : adria0", "api.x.com · 2026-09-04"),
                row(
                    "keysign",
                    "KEYSIGNED AS Adria",
                    "BY GITHUB:bob · 2026-09-02"
                ),
                row("self", "SELF ATTESTATION", "PUBLIC KEYS · 2026-09-01"),
                row(
                    "p2p",
                    "P2P ENDPOINT",
                    &format!("{} · 2026-09-03", short(&endpoint))
                ),
            ]
        );
    }

    #[test]
    fn test_short() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(&"0123456789abcdef".repeat(4)), "01234567…cdef");
    }
}
