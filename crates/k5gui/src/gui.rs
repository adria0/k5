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

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
};

use slint::{ComponentHandle, ModelRc, VecModel};

use k5lib::api::{Conversation, Outcome, ProfileAttestation, K5};
use k5net::{Event, Network, Node};

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
    /// Something the node did.
    Net(Event),
}

/// Opens the window, blocking until it is closed. Unless `offline`, starts
/// the peer-to-peer node, with the iroh key of the config file `config`.
pub fn run(k5: K5, config: PathBuf, offline: bool) -> Result<(), Box<dyn std::error::Error>> {
    let ui = AppWindow::new()?;
    ui.set_me(short(&k5.k5()).into());

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

    let weak = ui.as_weak();
    let events = tx.clone();
    thread::spawn(move || {
        let node = (!offline).then_some((config, events));
        Worker::new(Arc::new(k5), weak).serve(rx, node)
    });
    tx.send(Request::Rescan)?;

    ui.run()?;

    Ok(())
}

struct Worker {
    k5: Arc<K5>,
    node: Option<Node>,
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
}

impl Worker {
    fn new(k5: Arc<K5>, ui: slint::Weak<AppWindow>) -> Self {
        Self {
            k5,
            node: None,
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
            Err(e) => return self.status(format!("ERROR: {e}"), false),
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
        let secret = match k5net::load_or_create_secret(config) {
            Ok(secret) => secret,
            Err(e) => return self.status(format!("OFFLINE: {e}"), false),
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
                self.node = Some(node);
                self.status(String::new(), false);
            }
            Err(e) => self.status(format!("OFFLINE: {e}"), false),
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
            Err(e) => return self.status(format!("SCAN FAILED: {e}"), false),
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
    }

    /// Posts the attestations whose user or k5 contains the query, ignoring
    /// case, deduplicated by profile. An empty query matches everything.
    fn search(&self) {
        let query = self.query.trim().to_lowercase();
        let query = query.strip_prefix("k5:").unwrap_or(&query);

        let mut hits: Vec<Hit> = Vec::new();
        for attestation in &self.attestations {
            let profile = &attestation.profile;
            if matches!(profile.platform, SELF | IROH) {
                continue;
            }
            if !profile.user.to_lowercase().contains(query) && !profile.k5.contains(query) {
                continue;
            }
            let platform = platform(profile.platform);
            let existing = hits.iter().position(|hit| {
                hit.platform == platform && hit.user == profile.user && hit.k5 == profile.k5
            });
            match existing {
                Some(idx) => hits[idx].count += 1,
                None if hits.len() < MAX_HITS => hits.push(Hit {
                    platform: platform.into(),
                    label: label(profile.platform).into(),
                    user: profile.user.as_str().into(),
                    k5: profile.k5.as_str().into(),
                    short: short(&profile.k5).into(),
                    count: 1,
                }),
                None => {}
            }
        }

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
                    who(&me, &self.attestations, node).into()
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
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_chat_name(name.into());
            ui.set_chat_short(short.into());
            ui.set_chat_reachable(reachable);
            ui.set_has_dossier(false);
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
                Err(e) => return self.status(format!("DELIVERY FAILED: {e}"), false),
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
                Err(e) => return self.status(format!("SEND FAILED: {e}"), false),
            };
            match self.copy(armored) {
                Ok(()) => "NOT REACHABLE PEER TO PEER: MESSAGE COPIED TO CLIPBOARD".to_string(),
                Err(e) => format!("COPY TO CLIPBOARD FAILED: {e}"),
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
            Err(e) => return self.status(format!("SYNC FAILED: {e}"), false),
        };
        let count = |f: fn(&Outcome) -> bool| {
            report
                .merged
                .iter()
                .filter(|merged| f(&merged.outcome))
                .count()
        };
        let merged = count(|outcome| matches!(outcome, Outcome::Added(_) | Outcome::Replaced(_)));
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
        let status = match runtime.block_on(node.ticket()).map_err(|e| e.to_string()) {
            Ok(ticket) => match self.copy(ticket) {
                Ok(()) => "TICKET COPIED TO CLIPBOARD".to_string(),
                Err(e) => format!("COPY TO CLIPBOARD FAILED: {e}"),
            },
            Err(e) => format!("NO TICKET: {e}"),
        };
        self.status(status, false);
    }

    /// Connects to the k5 of a ticket, so each side learns how to reach the
    /// other.
    fn connect_ticket(&mut self, runtime: &tokio::runtime::Runtime, ticket: &str) {
        let Some(node) = &self.node else {
            return self.status("OFFLINE".to_string(), false);
        };
        self.status("CONNECTING ...".to_string(), true);

        match runtime.block_on(node.connect_ticket(ticket)) {
            Ok(k5) => {
                self.rescan(runtime);
                let who = who(&self.k5.k5(), &self.attestations, &k5);
                self.status(format!("CONNECTED TO {who}"), false);
            }
            Err(e) => self.status(format!("CONNECT FAILED: {e}"), false),
        }
    }

    /// Reports what the node did.
    fn net_event(&mut self, runtime: &tokio::runtime::Runtime, event: Event) {
        let me = self.k5.k5();
        let status = match event {
            Event::Received { from, .. } => {
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
            Event::Refused { endpoint, reason } => {
                format!("REFUSED {}: {reason}", short(&endpoint))
            }
            Event::Error(e) => format!("P2P ERROR: {e}"),
        };
        self.status(status, false);
    }

    /// Loads the conversations and posts them.
    fn load_chats(&mut self, runtime: &tokio::runtime::Runtime) {
        match runtime.block_on(self.k5.conversations()) {
            Ok(conversations) => self.conversations = conversations,
            Err(e) => return self.status(format!("MESSAGES FAILED: {e}"), false),
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

/// Icon key of a platform.
fn platform(platform: &str) -> &'static str {
    match platform {
        "X" => "x",
        "github" => "github",
        "site" => "site",
        "keysignparty" => "keysign",
        "self_attestation" => "self",
        _ => "other",
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

/// Who `k5` is, among `attestations` (`me` being the local k5): its
/// profiles (`X:handle · GITHUB:user`), or else the name it was keysigned
/// with, or else its short id.
fn who(me: &str, attestations: &[ProfileAttestation], k5: &str) -> String {
    if k5 == me {
        return "YOU".to_string();
    }
    let about = || {
        attestations
            .iter()
            .filter(move |attestation| attestation.profile.k5 == k5)
    };

    let profiles: BTreeSet<String> = about()
        .filter(|attestation| !matches!(attestation.profile.platform, SELF | KEYSIGN | IROH))
        .map(|attestation| {
            format!(
                "{}:{}",
                label(attestation.profile.platform),
                attestation.profile.user
            )
        })
        .collect();
    if !profiles.is_empty() {
        return profiles.into_iter().collect::<Vec<_>>().join(" · ");
    }

    match about().find(|attestation| attestation.profile.platform == KEYSIGN) {
        Some(keysign) => format!("{} (k5:{})", keysign.profile.user, short(k5)),
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
    /// `chats.ppm`, `chat.ppm`, `chat-draft.ppm`, `dossier.ppm` and
    /// `connect.ppm`, with the software renderer, to look at the design
    /// without a display.
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
        ui.set_stats_ids("51".into());
        ui.set_stats_trusted("41".into());
        let hit = |platform: &str, label: &str, user: &str, k5: &str, count| Hit {
            platform: platform.into(),
            label: label.into(),
            user: user.into(),
            k5: k5.into(),
            short: short(k5).into(),
            count,
        };
        ui.set_hits(ModelRc::new(VecModel::from(vec![
            hit("x", "X", "adria0", me, 1),
            hit("github", "GITHUB", "adria0", me, 1),
            hit("site", "SITE", "ethbcn.dev", me, 1),
            hit("keysign", "KEYSIGN", "BobTheBuilder", bob, 3),
            hit("x", "X", "bob_builds", bob, 1),
            hit("other", "OTHER", "mystery", bob, 1),
        ])));
        ui.set_dossier(Dossier {
            k5: me.into(),
            k5_a: me[..32].into(),
            k5_b: me[32..].into(),
            name: "adria0".into(),
            kem: true,
            online: true,
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
    fn test_short() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(&"0123456789abcdef".repeat(4)), "01234567…cdef");
    }
}
