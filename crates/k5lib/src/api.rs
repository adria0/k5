// The k5 API: every operation of the command line, returning data instead
// of printing it.
//
// An [`K5`] is the local identity (the keys of a config file) plus the
// notary key TLSNotary attestations must be signed with, and the [`Db`]
// attestations are read from and written to: by default an [`FsDb`] in
// [`ATTESTATIONS_DIR`].
//
// Nothing here writes to stdout or stderr: warnings (invalid records that were
// skipped, a replaced self attestation...) are part of the returned values,
// and long running operations report progress through a callback.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
};

use crate::{
    attestations::{self, export, iroh, keysignparty, me, tlsnotary},
    db::{Db, FsDb},
    graph,
    key::{self, Keys},
    message, signcrypt,
};
pub use crate::{
    attestations::{
        export::{Export, Merged, Outcome},
        iroh::Iroh,
        keysignparty::KeySign,
        me::{Created, Me},
        tlsnotary::{Notarized, NotaryConfig, Verified as TlsnVerified},
        Attested, Checked, Invalid, Listing, Profile, ProfileAttestation,
    },
    db::{DIR as ATTESTATIONS_DIR, INBOX_DIR, SENT_DIR},
    signcrypt::Opened,
    Error,
};

/// Default notary public key (compressed secp256k1, hex): the key of the
/// local notary embedded in k5cli.
pub const DEFAULT_NOTARY_KEY: &str =
    "03ddbf1ec1788139adbdb4e6e4decba9639687526028e694185cda2277457b2b1f";

/// The local k5.
pub struct K5 {
    keys: Keys,
    notary_key: String,
    db: Box<dyn Db>,
    inbox: Box<dyn Db>,
    sent: Box<dyn Db>,
}

/// A message of a [`Conversation`].
pub struct ChatMessage {
    /// When it was received or sent, in milliseconds since the Unix epoch.
    pub time: u64,
    /// Sent by the local k5.
    pub outgoing: bool,
    pub msg: String,
}

/// The messages exchanged with a k5, oldest first.
pub struct Conversation {
    /// The other k5.
    pub k5: String,
    pub messages: Vec<ChatMessage>,
}

/// A message of the inbox, from [`K5::read_inbox`].
pub struct InboxMessage {
    /// Entry name in the inbox.
    pub name: String,
    /// The decrypted and verified message, or why it could not be opened.
    pub opened: Result<Opened, String>,
}

/// The result of [`K5::merge`].
pub struct MergeReport {
    /// The k5 that signed the export.
    pub signer: String,
    pub merged: Vec<Merged>,
}

/// The result of [`K5::graph`].
pub struct Graph {
    /// Graphviz digraph.
    pub dot: String,
    pub k5s: usize,
    pub keysigns: usize,
    /// Number of verified attestations the graph was built from.
    pub attestations: usize,
}

/// A signcrypted message, from [`K5::signcrypt`].
pub struct Signcrypted {
    /// The normalized recipient k5.
    pub to: String,
    /// The armored OpenPGP message.
    pub armored: String,
}

/// The result of [`K5::verify`], by kind of content.
pub enum Verification {
    /// A signed message.
    Signed {
        /// The k5 of the signer.
        from: String,
        msg: String,
        /// Each bundled attestation, if the message is an export.
        export: Option<Vec<Checked>>,
        /// Verified attestations of the signer.
        attested_by: Listing,
    },
    /// A signcrypted message, decrypted with the local keys.
    Signcrypted {
        /// The k5 of the sender.
        from: String,
        msg: String,
        /// Verified attestations of the sender.
        attested_by: Listing,
    },
    /// An attestation record.
    Attestation(Attested),
}

impl K5 {
    /// Creates a new config file with new keys. Fails if the file exists.
    pub fn init(config: &Path) -> Result<Self, Error> {
        Ok(Self::new(key::create(config)?))
    }

    /// Loads the keys of an existing config file.
    pub fn open(config: &Path) -> Result<Self, Error> {
        Ok(Self::new(key::load(config)?))
    }

    fn new(keys: Keys) -> Self {
        Self {
            keys,
            notary_key: DEFAULT_NOTARY_KEY.to_string(),
            db: Box::new(FsDb::default()),
            inbox: Box::new(FsDb::new(INBOX_DIR)),
            sent: Box::new(FsDb::new(SENT_DIR)),
        }
    }

    /// Sets the database attestations are read from and written to, instead
    /// of the [`FsDb`] in [`ATTESTATIONS_DIR`].
    pub fn with_db(mut self, db: impl Db + 'static) -> Self {
        self.db = Box::new(db);
        self
    }

    /// Sets the inbox received messages are stored in, instead of the
    /// [`FsDb`] in [`INBOX_DIR`].
    pub fn with_inbox(mut self, inbox: impl Db + 'static) -> Self {
        self.inbox = Box::new(inbox);
        self
    }

    /// Sets where copies of the messages sent are stored, instead of the
    /// [`FsDb`] in [`SENT_DIR`].
    pub fn with_sent(mut self, sent: impl Db + 'static) -> Self {
        self.sent = Box::new(sent);
        self
    }

    /// Sets the notary public key (compressed secp256k1, hex) TLSNotary
    /// attestations must be signed with; others are rejected.
    pub fn with_notary_key(mut self, notary_key: &str) -> Self {
        self.notary_key = notary_key.to_string();
        self
    }

    /// The local k5 id.
    pub fn k5(&self) -> String {
        self.keys.k5()
    }

    /// The local keys.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The database of attestations.
    pub fn db(&self) -> &dyn Db {
        self.db.as_ref()
    }

    /// Makes sure the attestations contain a valid self attestation of the
    /// local keys, creating it if missing or outdated.
    pub async fn ensure_self_attestation(&self) -> Result<Option<Created>, Error> {
        me::ensure(self.db(), &self.keys).await
    }

    /// Makes sure the attestations contain a valid iroh attestation of the
    /// local k5 at `endpoint` (an iroh endpoint id, hex), creating it if
    /// missing or different. Returns where it was written, if it was.
    pub async fn ensure_iroh_attestation(&self, endpoint: &str) -> Result<Option<String>, Error> {
        iroh::ensure(self.db(), &self.keys, endpoint).await
    }

    /// The iroh endpoint `k5` can be reached at, from its iroh attestation,
    /// or `None` if there is none.
    pub async fn iroh_endpoint(&self, k5: &str) -> Result<Option<Iroh>, Error> {
        iroh::lookup(self.db(), k5).await
    }

    /// Notarizes an HTTPS URL with TLSNotary, writing the presentation to
    /// `presentation_path` and storing an attestation if a plugin recognizes
    /// the profile.
    pub async fn notarize(
        &self,
        config: &NotaryConfig,
        url: &str,
        presentation_path: &str,
        progress: &mut dyn FnMut(&str),
    ) -> Result<Notarized, Error> {
        tlsnotary::attest(self.db(), config, url, presentation_path, progress).await
    }

    /// All the valid attestations, sorted by k5 and profile.
    pub async fn list(&self) -> Result<Listing, Error> {
        attestations::list(self.db(), &self.notary_key).await
    }

    /// The valid attestations whose user (handle, domain, name...) matches
    /// the regex `pattern`.
    pub async fn search(&self, pattern: &str) -> Result<Listing, Error> {
        let pattern =
            regex::Regex::new(pattern).map_err(|e| format!("invalid regex `{pattern}`: {e}"))?;

        let mut listing = self.list().await?;
        listing
            .attestations
            .retain(|attestation| pattern.is_match(&attestation.profile.user));

        Ok(listing)
    }

    /// The valid attestations of `k5`.
    pub async fn attested_by(&self, k5: &str) -> Result<Listing, Error> {
        attestations::attested_by(self.db(), k5, &self.notary_key).await
    }

    /// The k5s reachable from the local one through the keysigns among
    /// `attestations`, the local one included.
    pub fn web_of_trust(&self, attestations: &[ProfileAttestation]) -> HashSet<String> {
        export::trusted(&self.k5(), attestations.iter())
    }

    /// The shortest chain of keysigns from the local k5 to `to` among
    /// `attestations`: the k5s from the local one to `to`, both included, or
    /// `None` if `to` is not on the web of trust.
    pub fn trust_path(&self, attestations: &[ProfileAttestation], to: &str) -> Option<Vec<String>> {
        let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
        for attestation in attestations.iter().filter(|a| export::is_keysign(a)) {
            if let Some(signer) = &attestation.signer {
                edges
                    .entry(signer.as_str())
                    .or_default()
                    .push(attestation.profile.k5.as_str());
            }
        }

        // Breadth first from the local k5, remembering who reached whom.
        let me = self.k5().to_ascii_lowercase();
        let to = to.to_ascii_lowercase();
        let mut previous: HashMap<&str, &str> = HashMap::new();
        let mut queue = VecDeque::from([me.as_str()]);
        while let Some(k5) = queue.pop_front() {
            if k5 == to {
                let mut path = vec![k5.to_string()];
                let mut k5 = k5;
                while let Some(signer) = previous.get(k5) {
                    path.push(signer.to_string());
                    k5 = signer;
                }
                path.reverse();
                return Some(path);
            }
            for &subject in edges.get(k5).into_iter().flatten() {
                if subject != me && !previous.contains_key(subject) {
                    previous.insert(subject, k5);
                    queue.push_back(subject);
                }
            }
        }

        None
    }

    /// Verifies every attestation record, sorted by file name.
    pub async fn audit(&self) -> Result<Vec<Checked>, Error> {
        attestations::audit(self.db(), &self.notary_key).await
    }

    /// Exports the valid attestations as a signed message.
    pub async fn export(&self) -> Result<Export, Error> {
        let export = export::create(self.db(), &self.keys, &self.notary_key).await?;

        // Check the output before handing it out.
        message::verify(&export.markdown, &attestations::keyring(self.db()).await?)?;

        Ok(export)
    }

    /// Merges the valid attestations of an export that are on the web of
    /// trust of the local k5. `force` replaces existing records with the
    /// same name but different content.
    pub async fn merge(&self, markdown: &str, force: bool) -> Result<MergeReport, Error> {
        let (signer, merged) =
            export::merge(self.db(), markdown, &self.k5(), &self.notary_key, force).await?;

        Ok(MergeReport { signer, merged })
    }

    /// Attests that `k5` belongs to `name`, storing the attestation.
    /// Returns where it was stored.
    pub async fn keysign(&self, k5: &str, name: &str) -> Result<String, Error> {
        let keyring = attestations::keyring(self.db()).await?;
        keysignparty::attest(self.db(), &self.keys, k5, name, &keyring).await
    }

    /// Builds a Graphviz digraph of the verified attestations.
    pub async fn graph(&self) -> Result<Graph, Error> {
        let listing = self.list().await?;
        let dot = graph::dot(&self.k5(), &listing.attestations);

        Ok(Graph {
            k5s: dot.lines().filter(|line| line.contains(" [label=")).count(),
            keysigns: dot.lines().filter(|line| line.contains(" -> ")).count(),
            attestations: listing.attestations.len(),
            dot,
        })
    }

    /// Signs `msg`, returning the armored cleartext-signed message.
    pub async fn sign(&self, msg: &str) -> Result<String, Error> {
        let armored = message::sign(&self.keys.secret, msg)?;

        // Check the output before handing it out.
        message::verify(&armored, &attestations::keyring(self.db()).await?)?;

        Ok(armored)
    }

    /// Signs `msg` and encrypts it to the encryption subkey of the self
    /// attestation of `to` (with or without the `k5:` prefix).
    pub async fn signcrypt(&self, to: &str, msg: &str) -> Result<Signcrypted, Error> {
        let to_key = signcrypt::recipient_encryption_key(self.db(), to).await?;
        let to = signcrypt::recipient_k5(to);
        let armored = signcrypt::seal(&self.keys, &to, &to_key, msg)?;

        Ok(Signcrypted { to, armored })
    }

    /// Accepts a signcrypted message delivered by `from`: it must be
    /// addressed to the local k5 and signed by `from`, whose self
    /// attestation must be in the database. Stores it, still encrypted, in
    /// the inbox.
    pub async fn receive(&self, from: &str, armored: &str) -> Result<InboxMessage, Error> {
        let from = signcrypt::recipient_k5(from);
        let sender = me::lookup(self.db(), &from)
            .await?
            .ok_or_else(|| format!("no self attestation of the sender k5:{from}"))?;
        let opened = signcrypt::open(
            &self.keys,
            armored,
            &message::Keyring::from([(sender.k5, sender.public)]),
        )?;
        if opened.from != from {
            return Err(format!("message from k5:{} delivered by k5:{from}", opened.from).into());
        }

        let name = message_name(&from)?;
        self.inbox.put(&name, armored).await?;

        Ok(InboxMessage {
            name,
            opened: Ok(opened),
        })
    }

    /// Keeps a copy of `msg`, sent to `to`: signcrypted to the local key, so
    /// it is stored encrypted like received messages.
    pub async fn record_sent(&self, to: &str, msg: &str) -> Result<(), Error> {
        let to = signcrypt::recipient_k5(to);
        let armored = signcrypt::seal(&self.keys, &to, &self.keys.encryption_subkey()?, msg)?;
        self.sent.put(&message_name(&to)?, &armored).await
    }

    /// The conversations with other k5s: the messages received and sent,
    /// the most recently active first. Messages that cannot be opened are
    /// left out (the inbox reports them).
    pub async fn conversations(&self) -> Result<Vec<Conversation>, Error> {
        let mut by_k5: HashMap<String, Vec<ChatMessage>> = HashMap::new();
        for message in self.read_inbox().await? {
            if let Ok(opened) = message.opened {
                by_k5.entry(opened.from).or_default().push(ChatMessage {
                    time: message_time(&message.name),
                    outgoing: false,
                    msg: opened.msg,
                });
            }
        }

        let names = self.sent.names().await?;
        for name in names.into_iter().filter(|name| name.ends_with(".asc")) {
            let Some(armored) = self.sent.get(&name).await? else {
                continue;
            };
            if let Ok((to, msg)) = signcrypt::open_own(&self.keys, &armored) {
                by_k5.entry(to).or_default().push(ChatMessage {
                    time: message_time(&name),
                    outgoing: true,
                    msg,
                });
            }
        }

        let mut conversations: Vec<Conversation> = by_k5
            .into_iter()
            .map(|(k5, mut messages)| {
                messages.sort_by_key(|message| message.time);
                Conversation { k5, messages }
            })
            .collect();
        let last = |conversation: &Conversation| {
            conversation
                .messages
                .last()
                .map_or(0, |message| message.time)
        };
        conversations.sort_by_key(|conversation| std::cmp::Reverse(last(conversation)));

        Ok(conversations)
    }

    /// The messages of the inbox, oldest first, decrypted and verified.
    pub async fn read_inbox(&self) -> Result<Vec<InboxMessage>, Error> {
        let keyring = attestations::keyring(self.db()).await?;
        let mut names: Vec<String> = self
            .inbox
            .names()
            .await?
            .into_iter()
            .filter(|name| name.ends_with(".asc"))
            .collect();
        names.sort();

        let mut messages = Vec::with_capacity(names.len());
        for name in names {
            let opened = match self.inbox.get(&name).await {
                Ok(Some(armored)) => {
                    signcrypt::open(&self.keys, &armored, &keyring).map_err(|e| e.to_string())
                }
                Ok(None) => Err("removed while reading".to_string()),
                Err(e) => Err(e.to_string()),
            };
            messages.push(InboxMessage { name, opened });
        }

        Ok(messages)
    }

    /// Verifies a signed message, a signcrypted message addressed to the
    /// local k5, or an attestation record, detected from `content`.
    pub async fn verify(&self, content: &str) -> Result<Verification, Error> {
        let keyring = attestations::keyring(self.db()).await?;

        if content.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            let signed = message::verify(content, &keyring)?;
            let export = if export::is_export(&signed.msg) {
                Some(export::verify(self.db(), &signed.msg, &self.notary_key).await?)
            } else {
                None
            };

            Ok(Verification::Signed {
                attested_by: self.attested_by(&signed.from).await?,
                from: signed.from,
                msg: signed.msg,
                export,
            })
        } else if content.starts_with("-----BEGIN PGP MESSAGE-----") {
            let opened = signcrypt::open(&self.keys, content, &keyring)?;

            Ok(Verification::Signcrypted {
                attested_by: self.attested_by(&opened.from).await?,
                from: opened.from,
                msg: opened.msg,
            })
        } else if content.starts_with("# info") {
            Ok(Verification::Attestation(attestations::verify(
                content,
                &self.notary_key,
                &keyring,
            )?))
        } else {
            Err(
                "neither a signed message, a signcrypted message nor an attestation record \
                 (`# info`)"
                    .into(),
            )
        }
    }
}

/// Name of a stored message with `k5`: `<ms since epoch>-<random>-<k5>.asc`,
/// so names sort by time and never collide.
fn message_name(k5: &str) -> Result<String, Error> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    Ok(format!(
        "{millis:013}-{:08x}-{k5}.asc",
        rand::random::<u32>()
    ))
}

/// When a stored message was received or sent, from its name.
fn message_time(name: &str) -> u64 {
    name.split('-')
        .next()
        .and_then(|millis| millis.parse().ok())
        .unwrap_or(0)
}

/// Generates a Plonky2 proof for a DKIM-signed email. Proving is CPU-bound,
/// so this is synchronous.
#[cfg(feature = "zkemail")]
pub fn zkemail(eml: &Path, dkim: &Path) -> Result<plonky2_zkemail::eml::EmailProof, Error> {
    Ok(plonky2_zkemail::eml::prove(eml, dkim)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test_keys;

    #[test]
    fn test_k5_is_send_sync() {
        // Shared as `Arc<K5>` by the peer-to-peer node's tasks.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<K5>();
    }

    /// A k5 with new keys and its database and inbox in a new temporary
    /// directory.
    fn temp_k5(name: &str) -> (K5, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "k5-api-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let k5 = K5::new(test_keys())
            .with_db(FsDb::new(dir.join("attestations")))
            .with_inbox(FsDb::new(dir.join("inbox")))
            .with_sent(FsDb::new(dir.join("sent")));
        (k5, dir)
    }

    #[tokio::test]
    async fn test_receive_and_read_inbox() {
        let (alice, alice_dir) = temp_k5("alice");
        let (bob, bob_dir) = temp_k5("bob");
        let carol = K5::new(test_keys());
        // Each knows the other's self attestation.
        for (from, to) in [(&alice, &bob), (&bob, &alice)] {
            from.ensure_self_attestation().await.unwrap();
            let name = me::name(&from.k5());
            let record = from.db().get(&name).await.unwrap().unwrap();
            to.db().put(&name, &record).await.unwrap();
        }

        let sealed = alice.signcrypt(&bob.k5(), "hello bob").await.unwrap();

        // Delivered by someone else than its signer: rejected.
        assert!(bob.receive(&carol.k5(), &sealed.armored).await.is_err());
        // Not addressed to alice.
        assert!(alice.receive(&alice.k5(), &sealed.armored).await.is_err());

        let received = bob.receive(&alice.k5(), &sealed.armored).await.unwrap();
        assert!(received.name.ends_with(&format!("-{}.asc", alice.k5())));

        let inbox = bob.read_inbox().await.unwrap();
        assert_eq!(inbox.len(), 1);
        let opened = inbox[0].opened.as_ref().unwrap();
        assert_eq!(
            (opened.from.as_str(), opened.msg.as_str()),
            (alice.k5().as_str(), "hello bob")
        );

        // Alice keeps her copy; bob replies.
        alice.record_sent(&bob.k5(), "hello bob").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let reply = bob.signcrypt(&alice.k5(), "hi alice").await.unwrap();
        alice.receive(&bob.k5(), &reply.armored).await.unwrap();

        let conversations = alice.conversations().await.unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].k5, bob.k5());
        let messages: Vec<(bool, &str)> = conversations[0]
            .messages
            .iter()
            .map(|message| (message.outgoing, message.msg.as_str()))
            .collect();
        assert_eq!(messages, [(true, "hello bob"), (false, "hi alice")]);
        // The sent copy is stored encrypted.
        let sent = alice.sent.names().await.unwrap();
        let stored = alice.sent.get(&sent[0]).await.unwrap().unwrap();
        assert!(
            stored.starts_with("-----BEGIN PGP MESSAGE-----"),
            "{stored}"
        );
        // Only the sender can read it back: bob's key does not open it.
        assert!(signcrypt::open_own(&bob.keys, &stored).is_err());

        std::fs::remove_dir_all(alice_dir).unwrap();
        std::fs::remove_dir_all(bob_dir).unwrap();
    }

    #[test]
    fn test_trust_path() {
        let k5 = K5::new(test_keys());
        let me = k5.k5();
        let [bob, carol, dave, eve] = ["b", "c", "d", "e"].map(|c| c.repeat(64));
        let keysign = |signer: &str, subject: &str| ProfileAttestation {
            profile: Profile {
                platform: keysignparty::RECORD_TYPE,
                user: String::new(),
                k5: subject.to_string(),
            },
            signer: Some(signer.to_string()),
            attributes: Vec::new(),
            file: String::new(),
            fake: false,
        };
        // me -> bob -> carol -> dave, and a shortcut me -> carol; eve signs
        // dave but nobody signs eve.
        let attestations = [
            keysign(&me, &bob),
            keysign(&bob, &carol),
            keysign(&carol, &dave),
            keysign(&me, &carol),
            keysign(&eve, &dave),
            keysign(&dave, &bob),
        ];

        assert_eq!(k5.trust_path(&attestations, &me), Some(vec![me.clone()]));
        assert_eq!(
            k5.trust_path(&attestations, &dave),
            Some(vec![me.clone(), carol.clone(), dave.clone()])
        );
        assert_eq!(
            k5.trust_path(&attestations, &bob),
            Some(vec![me.clone(), bob.clone()])
        );
        assert_eq!(k5.trust_path(&attestations, &eve), None);
    }
}
