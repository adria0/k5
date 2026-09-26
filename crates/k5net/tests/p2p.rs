// Nodes on localhost, finding each other through a shared in-memory address
// book (no n0 infrastructure): first contact by ticket, messages both ways,
// sync, and refusal of k5s outside the web of trust.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use k5lib::{
    api::{Outcome, K5},
    db::FsDb,
};
use k5net::{load_or_create_secret, Event, MemoryLookup, Network, Node};

struct TestNode {
    k5: Arc<K5>,
    node: Node,
    events: Arc<Mutex<Vec<Event>>>,
    dir: PathBuf,
}

impl TestNode {
    async fn spawn(name: &str, lookup: &MemoryLookup) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "k5net-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("k5.toml");
        let k5 = Arc::new(
            K5::init(&config)
                .unwrap()
                .with_db(FsDb::new(dir.join("attestations")))
                .with_inbox(FsDb::new(dir.join("inbox")))
                .with_sent(FsDb::new(dir.join("sent"))),
        );
        let secret = load_or_create_secret(&config).unwrap();
        // Stored once, loaded after.
        assert_eq!(
            load_or_create_secret(&config).unwrap().public(),
            secret.public()
        );

        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let node = Node::spawn(
            k5.clone(),
            secret,
            Network::Local(lookup.clone()),
            move |event| sink.lock().unwrap().push(event),
        )
        .await
        .unwrap();

        Self {
            k5,
            node,
            events,
            dir,
        }
    }

    fn k5(&self) -> String {
        self.k5.k5()
    }

    /// Waits for an event matching `f`, which is removed and returned.
    async fn event<T>(&self, f: impl Fn(&Event) -> Option<T>) -> T {
        for _ in 0..100 {
            {
                let mut events = self.events.lock().unwrap();
                if let Some(index) = events.iter().position(|event| f(event).is_some()) {
                    return f(&events.remove(index)).unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no such event, got: {:?}", self.events.lock().unwrap());
    }

    async fn stop(self) {
        self.node.shutdown().await.unwrap();
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_messages_and_sync() {
    let lookup = MemoryLookup::new();
    let alice = TestNode::spawn("alice", &lookup).await;
    let bob = TestNode::spawn("bob", &lookup).await;

    // Unknown to each other: alice cannot dial bob by his k5.
    let err = alice.node.send(&bob.k5(), "hi").await.unwrap_err();
    assert!(err.to_string().contains("no iroh attestation"), "{err}");

    // They meet and keysign each other, then alice uses bob's ticket.
    alice.k5.keysign(&bob.k5(), "Bob").await.unwrap();
    bob.k5.keysign(&alice.k5(), "Alice").await.unwrap();
    let peer = alice
        .node
        .connect_ticket(&bob.node.ticket().await.unwrap())
        .await
        .unwrap();
    assert_eq!(peer, bob.k5());

    // Both learned the other's iroh attestation from the hello.
    for (node, other) in [(&alice, &bob), (&bob, &alice)] {
        let iroh = node.k5.iroh_endpoint(&other.k5()).await.unwrap().unwrap();
        assert_eq!(iroh.endpoint, other.node.endpoint_id());
    }

    // Messages, both ways, by k5.
    alice.node.send(&bob.k5(), "hello bob").await.unwrap();
    let (from, msg) = bob
        .event(|event| match event {
            Event::Received { from, msg } => Some((from.clone(), msg.clone())),
            _ => None,
        })
        .await;
    assert_eq!(
        (from.as_str(), msg.as_str()),
        (alice.k5().as_str(), "hello bob")
    );
    let inbox = bob.k5.read_inbox().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].opened.as_ref().unwrap().msg, "hello bob");

    bob.node
        .send(&format!("k5:{}", alice.k5()), "hi alice")
        .await
        .unwrap();
    let msg = alice
        .event(|event| match event {
            Event::Received { msg, .. } => Some(msg.clone()),
            _ => None,
        })
        .await;
    assert_eq!(msg, "hi alice");

    // Each side sees the conversation, both ways, in order.
    for (node, other, messages) in [
        (&alice, &bob, [(true, "hello bob"), (false, "hi alice")]),
        (&bob, &alice, [(false, "hello bob"), (true, "hi alice")]),
    ] {
        let conversations = node.k5.conversations().await.unwrap();
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].k5, other.k5());
        let got: Vec<(bool, &str)> = conversations[0]
            .messages
            .iter()
            .map(|message| (message.outgoing, message.msg.as_str()))
            .collect();
        assert_eq!(got, messages);
    }

    // Sync: bob keysigned carol; alice trusts bob, so she merges it.
    let carol = K5::init(&bob.dir.join("carol.toml")).unwrap();
    let keysign = bob.k5.keysign(&carol.k5(), "Carol").await.unwrap();
    let report = alice.node.sync(&bob.k5()).await.unwrap();
    assert_eq!(report.signer, bob.k5());
    let added: Vec<&str> = report
        .merged
        .iter()
        .filter(|merged| matches!(merged.outcome, Outcome::Added(_)))
        .map(|merged| merged.file.as_str())
        .collect();
    assert!(
        added.iter().any(|file| keysign.ends_with(file)),
        "{keysign} not in {added:?}"
    );
    let served = bob
        .event(|event| match event {
            Event::Served { k5 } => Some(k5.clone()),
            _ => None,
        })
        .await;
    assert_eq!(served, alice.k5());
    // carol is now on alice's web of trust, through bob.
    let listing = alice.k5.list().await.unwrap();
    assert!(alice
        .k5
        .web_of_trust(&listing.attestations)
        .contains(&carol.k5()));

    alice.stop().await;
    bob.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_untrusted_is_refused() {
    let lookup = MemoryLookup::new();
    let alice = TestNode::spawn("alice", &lookup).await;
    let mallory = TestNode::spawn("mallory", &lookup).await;

    // mallory trusts alice, but alice does not know mallory: alice refuses.
    mallory.k5.keysign(&alice.k5(), "Alice").await.unwrap();
    let err = mallory
        .node
        .connect_ticket(&alice.node.ticket().await.unwrap())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not on the web of trust"), "{err}");
    let (endpoint, reason) = alice
        .event(|event| match event {
            Event::Refused { endpoint, reason } => Some((endpoint.clone(), reason.clone())),
            _ => None,
        })
        .await;
    assert_eq!(endpoint, mallory.node.endpoint_id());
    assert!(reason.contains(&mallory.k5()), "{reason}");
    // Nothing of mallory was stored by alice.
    assert!(alice
        .k5
        .iroh_endpoint(&mallory.k5())
        .await
        .unwrap()
        .is_none());

    // The other way: alice does not trust mallory, so she refuses to talk to
    // her, even though mallory would accept.
    let err = alice
        .node
        .connect_ticket(&mallory.node.ticket().await.unwrap())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not on your web of trust"),
        "{err}"
    );

    alice.stop().await;
    mallory.stop().await;
}
