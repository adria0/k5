// Who is on the other end of a connection.
//
// iroh authenticates the remote endpoint id (QUIC/TLS proves the peer holds
// its secret key), but not the k5. The peer proves its k5 in the hello with
// its self attestation and its iroh attestation, signed by that k5 and naming
// the authenticated endpoint id. A replayed record is useless without the
// endpoint's secret key.
//
// Access is limited to the web of trust: the k5s reachable from the local
// one through keysigns, as `attest merge` does.
//
// A first contact (pairing) also gives both sides a check phrase: words from
// a hash of both k5s and both endpoint ids. Read aloud, matching phrases
// prove each side paired with the k5 the other one sees, so they can keysign
// each other.

use anyhow::{anyhow, bail, Context as _};
use iroh::EndpointId;
use k5lib::{
    api::K5,
    attestations::{iroh as iroh_record, me},
    message::Keyring,
    Error,
};
use sha2::{Digest, Sha256};

/// A peer whose k5 was proven by its records.
pub struct Peer {
    pub k5: String,
    me_record: String,
    iroh_record: String,
}

/// The hex form of an endpoint id, as in iroh attestations.
pub fn endpoint_hex(id: &EndpointId) -> String {
    hex::encode(id.as_bytes())
}

/// Parses the hex form of an endpoint id.
pub fn parse_endpoint(endpoint: &str) -> Result<EndpointId, Error> {
    let invalid = || format!("invalid endpoint id `{endpoint}`");
    let bytes: [u8; 32] = hex::decode(endpoint)
        .with_context(invalid)?
        .try_into()
        .map_err(|_| anyhow!("{}: expected 32 bytes", invalid()))?;
    EndpointId::from_bytes(&bytes).with_context(invalid)
}

/// Verifies the records of a hello from the endpoint `remote`: a self
/// attestation, and an iroh attestation signed by the same k5 naming
/// `remote`.
pub fn verify(me_record: &str, iroh_record: &str, remote: &EndpointId) -> Result<Peer, Error> {
    let me = me::verify(me_record).context("invalid self attestation")?;
    if me.fake {
        bail!("fake identity");
    }
    let keyring = Keyring::from([(me.k5.clone(), me.public)]);
    let iroh = iroh_record::verify(iroh_record, &keyring).context("invalid iroh attestation")?;
    if iroh.k5 != me.k5 {
        bail!(
            "iroh attestation of k5:{} with the self attestation of k5:{}",
            iroh.k5,
            me.k5
        );
    }
    if iroh.endpoint != endpoint_hex(remote) {
        bail!(
            "iroh attestation of k5:{} is for endpoint {}, not {}",
            iroh.k5,
            iroh.endpoint,
            endpoint_hex(remote)
        );
    }

    Ok(Peer {
        k5: me.k5,
        me_record: me_record.to_string(),
        iroh_record: iroh_record.to_string(),
    })
}

/// Number of words of a check phrase: 32 bits.
const PHRASE_WORDS: usize = 4;

/// Words of the check phrases, one per byte value: short, distinct and easy
/// to say.
const WORDS: [&str; 256] = [
    "acid", "acorn", "actor", "adobe", "agent", "alarm", "album", "alley", "amber", "anchor",
    "angel", "ankle", "apple", "apron", "arrow", "atlas", "attic", "audio", "badge", "bagel",
    "baker", "bamboo", "banjo", "barn", "basil", "beach", "beard", "bell", "bench", "berry",
    "bison", "blade", "blanket", "bloom", "board", "bolt", "bonus", "boot", "bottle", "brain",
    "brick", "bridge", "broom", "bubble", "bucket", "buffalo", "bugle", "butter", "cabin", "cable",
    "cactus", "camel", "camera", "candle", "canoe", "canyon", "carpet", "carrot", "castle",
    "cedar", "chalk", "cherry", "chess", "chimney", "cider", "circus", "clock", "cloud", "clover",
    "cobra", "cocoa", "comet", "copper", "coral", "cotton", "cowboy", "crane", "crayon", "cricket",
    "crown", "cube", "cup", "daisy", "dance", "delta", "denim", "desert", "diamond", "dinner",
    "dolphin", "donkey", "dragon", "drum", "eagle", "earth", "echo", "elbow", "ember", "engine",
    "falcon", "feather", "fence", "fern", "fiddle", "finger", "flame", "flute", "forest", "fossil",
    "fox", "frost", "galaxy", "garden", "garlic", "gecko", "ginger", "glacier", "globe", "goat",
    "grape", "gravel", "guitar", "hammer", "harbor", "harp", "hazel", "helmet", "hero", "honey",
    "hotel", "igloo", "island", "ivory", "jacket", "jaguar", "jelly", "jewel", "jungle", "kayak",
    "kettle", "kitten", "koala", "ladder", "lagoon", "lamp", "lantern", "lemon", "lens", "lily",
    "lion", "lizard", "lobster", "magnet", "mango", "maple", "marble", "meadow", "melon", "mirror",
    "monkey", "moon", "moss", "motor", "mountain", "mouse", "mustard", "napkin", "needle", "nest",
    "noodle", "oasis", "ocean", "olive", "onion", "orange", "orbit", "otter", "owl", "paddle",
    "panda", "paper", "parrot", "peach", "pearl", "pebble", "pencil", "pepper", "piano", "pickle",
    "pillow", "pilot", "pine", "planet", "plum", "pocket", "pony", "potato", "pumpkin", "puzzle",
    "quartz", "quilt", "rabbit", "radio", "rainbow", "raven", "ribbon", "river", "robot", "rocket",
    "rose", "ruby", "saddle", "salmon", "sand", "saturn", "scarf", "shark", "shell", "silver",
    "sketch", "sled", "snail", "snow", "socket", "spider", "spoon", "squid", "star", "stone",
    "storm", "sugar", "summer", "sunset", "swan", "table", "tiger", "toast", "tomato", "torch",
    "tower", "train", "tulip", "turtle", "umbrella", "valley", "velvet", "violin", "volcano",
    "wagon", "walnut", "whale", "window", "winter", "wizard", "wolf", "zebra",
];

/// The check phrase of a pairing between two k5s at their endpoints: the
/// same on both sides, whichever is local.
pub fn check_phrase(a: (&str, &EndpointId), b: (&str, &EndpointId)) -> String {
    let side = |(k5, endpoint): (&str, &EndpointId)| format!("{k5}\n{}", endpoint_hex(endpoint));
    let (first, second) = {
        let (a, b) = (side(a), side(b));
        if a <= b {
            (a, b)
        } else {
            (b, a)
        }
    };
    let hash = Sha256::digest(format!("k5 pairing\n{first}\n{second}").as_bytes());

    hash[..PHRASE_WORDS]
        .iter()
        .map(|&byte| WORDS[byte as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `k5` is on the web of trust of the local k5. Runs for any peer
/// with valid records, so it only verifies the keysigns, not the whole
/// database.
pub async fn is_trusted(local: &K5, k5: &str) -> Result<bool, Error> {
    Ok(local.trusted().await?.contains(k5))
}

/// Stores the records of a verified peer: its self attestation if missing, and
/// its iroh attestation if missing or newer, so the peer can be reached by its
/// k5 later.
pub async fn store(local: &K5, peer: &Peer) -> Result<(), Error> {
    let db = local.db();
    let me_name = me::name(&peer.k5);
    if db.get(&me_name).await?.is_none() {
        db.put(&me_name, &peer.me_record).await?;
    }

    let iroh_name = iroh_record::name(&peer.k5);
    let stale = match db.get(&iroh_name).await? {
        None => true,
        Some(existing) => {
            existing != peer.iroh_record && iroh_record::is_newer(&peer.iroh_record, &existing)
        }
    };
    if stale {
        db.put(&iroh_name, &peer.iroh_record).await?;
    }

    Ok(())
}

/// The hello of the local k5: its self attestation and its iroh attestation,
/// from the database.
pub async fn local_hello(local: &K5) -> Result<String, Error> {
    let k5 = local.k5();
    let get = |name: String| async move {
        local
            .db()
            .get(&name)
            .await?
            .with_context(|| format!("missing {name}"))
    };

    Ok(crate::proto::hello(
        &get(me::name(&k5)).await?,
        &get(iroh_record::name(&k5)).await?,
    ))
}

#[cfg(test)]
mod tests {
    use k5lib::key::Keys;

    use super::*;

    /// The hello records of new keys at a new endpoint.
    fn records() -> (String, String, EndpointId) {
        let keys = Keys::generate().unwrap();
        let id = iroh::SecretKey::generate().public();
        (
            me::create(&keys, false).unwrap(),
            iroh_record::create(&keys, &endpoint_hex(&id)).unwrap(),
            id,
        )
    }

    #[test]
    fn test_verify() {
        let (me_a, iroh_a, id_a) = records();
        let (me_b, iroh_b, id_b) = records();

        let peer = verify(&me_a, &iroh_a, &id_a).unwrap();
        assert_eq!(peer.k5, me::verify(&me_a).unwrap().k5);

        // Replaying a's records from another endpoint.
        let err = verify(&me_a, &iroh_a, &id_b).err().unwrap().to_string();
        assert!(err.contains("is for endpoint"), "{err}");
        // Mixing the records of two k5s.
        assert!(verify(&me_a, &iroh_b, &id_b).is_err());
        assert!(verify(&me_b, &iroh_a, &id_a).is_err());
        // A fake identity.
        let keys = Keys::generate().unwrap();
        let fake = me::create(&keys, true).unwrap();
        let iroh = iroh_record::create(&keys, &endpoint_hex(&id_a)).unwrap();
        assert!(verify(&fake, &iroh, &id_a).is_err());
    }

    #[test]
    fn test_check_phrase() {
        let [a, b] = [
            iroh::SecretKey::generate().public(),
            iroh::SecretKey::generate().public(),
        ];
        let [k5_a, k5_b] = ["a".repeat(64), "b".repeat(64)];

        let phrase = check_phrase((&k5_a, &a), (&k5_b, &b));
        assert_eq!(phrase.split(' ').count(), PHRASE_WORDS);
        // The same on both sides.
        assert_eq!(check_phrase((&k5_b, &b), (&k5_a, &a)), phrase);
        // Another endpoint or another k5: another phrase.
        let c = iroh::SecretKey::generate().public();
        assert_ne!(check_phrase((&k5_a, &a), (&k5_b, &c)), phrase);
        assert_ne!(check_phrase((&k5_a, &a), (&"c".repeat(64), &b)), phrase);

        // One word per byte value.
        let words: std::collections::HashSet<&str> = WORDS.into_iter().collect();
        assert_eq!(words.len(), 256);
    }

    #[test]
    fn test_endpoint_hex() {
        let id = iroh::SecretKey::generate().public();
        assert_eq!(parse_endpoint(&endpoint_hex(&id)).unwrap(), id);
        assert!(parse_endpoint("zz").is_err());
    }
}
