// Generation of a deterministic social graph of identities.
//
// `n` identities with common names are derived from a seed and stored as
// config files in [`DIR`]. The keysigns between them follow the Holme–Kim
// model of social networks: Barabási–Albert preferential attachment (a few
// well connected hubs, most identities with 1 or 2 keysigns) plus triad
// formation (friends of friends, for clustering), with mutual keysigns as in
// key signing parties. Each identity keysigns between 1 and
// [`MAX_CONNECTIONS`] others, and every identity is reachable from the local
// k5, which keysigns the first [`ROOTS`] identities. The keysign
// attestations are stored in
// the attestations directory, so they pass the web of trust of
// `attest merge`, together with a self attestation (`me`) of each identity,
// which publishes its key encapsulation key so messages can be signcrypted to
// it, and fake X (90%), website (10%) and GitHub (10%) attestations of each
// identity, with at least an X one. All of them are marked as fake.
//
// Identities, names and connections only depend on the seed. The attestation
// records are not byte for byte reproducible, as they carry their creation
// date and ML-DSA signatures are randomized.

use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
};

use pgp::{
    composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder},
    types::{KeyDetails, KeyVersion},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use crate::parallel::parallel_map;

use crate::{
    attestations::{self, export, fake, keysignparty, me, Attested, Error, ProfileAttestation},
    key::{self, Keys},
};

/// Directory of the identity config files.
pub const DIR: &str = "db/ids";
/// Maximum number of identities.
pub const MAX_IDS: usize = 500;
/// Default seed.
pub const DEFAULT_SEED: u64 = 0xdeadcafe;

/// Maximum number of identities an identity keysigns.
const MAX_CONNECTIONS: usize = 10;
/// Number of identities keysigned by the local k5. They keysign each
/// other, as the initial core of the graph.
const ROOTS: usize = 3;
/// Probability that a further link of a newcomer goes to a friend of its
/// previous link (Holme–Kim triad formation).
const TRIAD_PROBABILITY: f64 = 0.5;
/// Probability that a newcomer keysigns back a further link. The first link is
/// always mutual.
const RECIPROCITY: f64 = 0.5;
/// Probability of each fake profile of an identity. An identity with none of
/// them gets an X account.
const FAKE_PROFILES: [(&str, f64); 3] = [("X", 0.9), ("site", 0.1), ("github", 0.1)];

const FIRST_NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy", "Karl",
    "Laura", "Mallory", "Nina", "Oscar", "Peggy", "Quentin", "Rupert", "Sybil", "Trent", "Ursula",
    "Victor", "Walter", "Xavier", "Yvonne", "Zoe", "Anna", "Ben", "Clara", "Daniel", "Elena",
    "Felix", "Greta", "Hugo", "Iris", "Jonas", "Kira", "Leo", "Maria", "Noah", "Olga", "Pablo",
    "Rosa", "Sam", "Tina", "Uma", "Vera", "Will", "Yara", "Zack",
];

const LAST_NAMES: &[&str] = &[
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Martinez",
    "Lopez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee",
    "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
    "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter",
    "Roberts", "Gomez", "Phillips", "Evans",
];

/// A generated identity.
pub struct Identity {
    pub name: String,
    pub path: PathBuf,
    pub keys: Keys,
}

/// A keysign of the graph: `signer` (an identity, or the local k5 if
/// `None`) keysigns identity `subject`.
struct Edge {
    signer: Option<usize>,
    subject: usize,
}

/// The result of `fakegraph`, after its audit.
pub struct Summary {
    pub identities: usize,
    /// Identity config files that already existed.
    pub existing: usize,
    pub keysigns: usize,
    /// Self attestations of the identities.
    pub me_records: usize,
    /// Number of fake profile attestations of each platform.
    pub fakes_per_platform: Vec<(&'static str, usize)>,
    pub roots: usize,
    pub min_connections: usize,
    pub max_connections: usize,
    /// Average number of identities an identity keysigns.
    pub mean_connections: f64,
    /// Maximum number of identities keysigning an identity.
    pub max_keysigned_by: usize,
}

/// Parses a seed, in hex with a `0x` prefix or in decimal.
pub fn parse_seed(seed: &str) -> Result<u64, Error> {
    let parsed = match seed.strip_prefix("0x").or_else(|| seed.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => seed.parse(),
    };

    parsed.map_err(|_| format!("invalid seed `{seed}`: expected hex (0x...) or decimal").into())
}

/// Generates `n` identities and their keysigns from `seed`, then audits the
/// result.
pub async fn run(me: &Keys, n: usize, seed: u64) -> Result<Summary, Error> {
    if !(2..=MAX_IDS).contains(&n) {
        return Err(format!("the number of identities must be between 2 and {MAX_IDS}").into());
    }

    let mut rng = Rng::new(seed);
    let names = names(&mut rng, n);
    let connections = graph(&mut rng, n);
    let profiles = fake_profiles(&mut rng, &names);

    // Identities. Existing config files must all hold the expected identity
    // before anything is written.
    let identities: Vec<Identity> = names
        .into_iter()
        .enumerate()
        .map(|(index, name)| Identity {
            path: PathBuf::from(format!(
                "{DIR}/{}.toml",
                name.to_ascii_lowercase().replace(' ', "_")
            )),
            keys: derive_keys(seed, index as u64),
            name,
        })
        .collect();

    let mut existing = 0;
    for identity in identities.iter().filter(|identity| identity.path.exists()) {
        check_identity(identity)?;
        existing += 1;
    }

    tokio::fs::create_dir_all(DIR).await?;
    for identity in identities.iter().filter(|identity| !identity.path.exists()) {
        let mut settings = toml::Table::new();
        settings.insert(
            "name".to_string(),
            toml::Value::String(identity.name.clone()),
        );
        key::store(&identity.path, &identity.keys, settings)?;
    }

    // Keysigns.
    let edges: Vec<Edge> = (0..n.min(ROOTS))
        .map(|subject| Edge {
            signer: None,
            subject,
        })
        .chain(
            connections
                .iter()
                .enumerate()
                .flat_map(|(signer, subjects)| {
                    subjects.iter().map(move |&subject| Edge {
                        signer: Some(signer),
                        subject,
                    })
                }),
        )
        .collect();

    // Signing and base58 encoding dominate, so records are created in
    // parallel. They are not verified here, as the audit verifies them all.
    let records = parallel_map(&edges, |edge| {
        let signer = edge.signer.map_or(me, |signer| &identities[signer].keys);
        let subject = &identities[edge.subject];
        keysignparty::create(signer, &subject.keys.k5(), &subject.name, true)
            .map_err(|e| e.to_string())
    });

    tokio::fs::create_dir_all(attestations::DIR).await?;
    let mut paths = Vec::with_capacity(edges.len());
    for record in records {
        let (file_name, record) = record?;
        let path = format!("{}/{file_name}", attestations::DIR);
        tokio::fs::write(&path, record).await?;
        paths.push(path);
    }

    // Self attestations of the identities, with their encryption keys.
    let me_records = parallel_map(&identities, |identity| {
        me::create(&identity.keys, true).map_err(|e| e.to_string())
    });
    for (identity, record) in identities.iter().zip(me_records) {
        tokio::fs::write(me::path(&identity.keys.k5()), record?).await?;
    }

    // Fake profile attestations.
    let fakes: Vec<(usize, &'static str, &str)> = profiles
        .iter()
        .enumerate()
        .flat_map(|(index, profiles)| {
            profiles
                .iter()
                .map(move |(platform, user)| (index, *platform, user.as_str()))
        })
        .collect();
    let fake_records = parallel_map(&fakes, |(index, platform, user)| {
        fake::create(&identities[*index].keys, platform, user).map_err(|e| e.to_string())
    });
    let mut fake_paths = Vec::with_capacity(fakes.len());
    for record in fake_records {
        let (file_name, record) = record?;
        let path = format!("{}/{file_name}", attestations::DIR);
        tokio::fs::write(&path, record).await?;
        fake_paths.push(path);
    }

    audit(me, &identities, &edges, &paths, &fakes, &fake_paths).await?;

    let fakes_per_platform = FAKE_PROFILES
        .iter()
        .map(|&(platform, _)| {
            let count = fakes.iter().filter(|(_, p, _)| *p == platform).count();
            (platform, count)
        })
        .collect();

    let degrees: Vec<usize> = connections.iter().map(BTreeSet::len).collect();
    Ok(Summary {
        identities: n,
        existing,
        keysigns: edges.len(),
        me_records: n,
        fakes_per_platform,
        roots: n.min(ROOTS),
        min_connections: degrees.iter().copied().min().unwrap_or_default(),
        max_connections: degrees.iter().copied().max().unwrap_or_default(),
        mean_connections: degrees.iter().sum::<usize>() as f64 / n as f64,
        max_keysigned_by: {
            let mut keysigned_by = vec![0; n];
            for subject in connections.iter().flatten() {
                keysigned_by[*subject] += 1;
            }
            keysigned_by.into_iter().max().unwrap_or_default()
        },
    })
}

/// Checks the generated identities and attestations from disk: every identity
/// config matches its derived keys and name; every keysign, self attestation
/// and fake profile attestation is valid, fake, and as expected; every
/// identity keysigns between 1 and [`MAX_CONNECTIONS`] others and has at least
/// one fake profile, at most one per platform; and every identity is on a
/// trust path from the local k5.
async fn audit(
    me: &Keys,
    identities: &[Identity],
    edges: &[Edge],
    paths: &[String],
    fakes: &[(usize, &'static str, &str)],
    fake_paths: &[String],
) -> Result<(), Error> {
    for identity in identities {
        check_identity(identity)?;
    }

    // Every self attestation is written to disk before this runs, so a
    // single keyring built once covers every signer.
    let keyring = attestations::keyring().await?;

    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        records.push((path, tokio::fs::read_to_string(path).await?));
    }
    let verified = parallel_map(&records, |(path, record)| {
        match attestations::verify(record, "", &keyring).map_err(|e| format!("{path}: {e}"))? {
            Attested::KeySign(keysign) if keysign.fake => Ok(keysign),
            _ => Err(format!("{path}: not a fake keysign")),
        }
    });

    let mut attestations: Vec<ProfileAttestation> = Vec::with_capacity(edges.len());
    let mut degrees: HashMap<usize, usize> = HashMap::new();
    for ((edge, path), keysign) in edges.iter().zip(paths).zip(verified) {
        let keysign = keysign?;

        let signer = edge
            .signer
            .map_or_else(|| me.k5(), |signer| identities[signer].keys.k5());
        let subject = &identities[edge.subject];
        if keysign.signer != signer
            || keysign.subject != subject.keys.k5()
            || keysign.name != subject.name
        {
            return Err(format!("{path}: unexpected keysign").into());
        }

        if let Some(signer) = edge.signer {
            *degrees.entry(signer).or_default() += 1;
        }
        attestations.push(Attested::KeySign(keysign).attestation(path.clone())?);
    }

    for (index, identity) in identities.iter().enumerate() {
        let degree = degrees.get(&index).copied().unwrap_or_default();
        if !(1..=MAX_CONNECTIONS).contains(&degree) {
            return Err(format!("{} keysigns {degree} identities", identity.name).into());
        }
    }

    let mut me_records = Vec::with_capacity(identities.len());
    for identity in identities {
        let path = me::path(&identity.keys.k5());
        me_records.push((path.clone(), tokio::fs::read_to_string(&path).await?));
    }
    let verified = parallel_map(&me_records, |(path, record)| {
        match attestations::verify(record, "", &keyring).map_err(|e| format!("{path}: {e}"))? {
            Attested::Me(me) if me.fake => Ok(me),
            _ => Err(format!("{path}: not a fake self attestation")),
        }
    });
    for (identity, me) in identities.iter().zip(verified) {
        let me = me?;
        if me.k5 != identity.keys.k5()
            || me.encryption_fingerprint()
                != Some(identity.keys.encryption_subkey()?.fingerprint().to_string())
        {
            return Err(format!(
                "self attestation of {} does not match its keys",
                identity.name
            )
            .into());
        }
    }

    let mut fake_records = Vec::with_capacity(fake_paths.len());
    for path in fake_paths {
        fake_records.push((path, tokio::fs::read_to_string(path).await?));
    }
    let verified = parallel_map(&fake_records, |(path, record)| match attestations::verify(
        record, "", &keyring,
    )
    .map_err(|e| format!("{path}: {e}"))?
    {
        Attested::Fake(fake) => Ok(fake),
        _ => Err(format!("{path}: not a fake profile attestation")),
    });
    let mut fake_counts = vec![0; identities.len()];
    for (&(index, platform, user), fake) in fakes.iter().zip(verified) {
        let fake = fake?;
        let identity = &identities[index];
        if fake.k5 != identity.keys.k5() || fake.platform != platform || fake.user != user {
            return Err(format!(
                "unexpected fake {platform} attestation of {}",
                identity.name
            )
            .into());
        }
        fake_counts[index] += 1;
    }
    for (identity, count) in identities.iter().zip(fake_counts) {
        if !(1..=FAKE_PROFILES.len()).contains(&count) {
            return Err(format!("{} has {count} fake profile attestations", identity.name).into());
        }
    }

    let trusted = export::trusted(&me.k5(), attestations.iter());
    for identity in identities {
        if !trusted.contains(&identity.keys.k5()) {
            return Err(format!("{} is not reachable from your k5", identity.name).into());
        }
    }

    Ok(())
}

/// Checks that an identity config file holds the expected keys and name.
fn check_identity(identity: &Identity) -> Result<(), Error> {
    let path = identity.path.display();
    let loaded = key::load(&identity.path)?;
    if loaded.k5() != identity.keys.k5()
        || loaded.encryption_subkey()?.fingerprint()
            != identity.keys.encryption_subkey()?.fingerprint()
    {
        return Err(format!("{path} does not hold the identity derived from the seed").into());
    }

    let config: toml::Table = std::fs::read_to_string(&identity.path)?.parse()?;
    if config.get("name").and_then(toml::Value::as_str) != Some(identity.name.as_str()) {
        return Err(format!("{path} is not the identity of {}", identity.name).into());
    }

    Ok(())
}

/// The fixed key creation time of every identity `derive_keys` generates, so
/// that regenerating the same (seed, index) always yields the same OpenPGP
/// fingerprints.
fn fakegraph_epoch() -> pgp::types::Timestamp {
    pgp::types::Timestamp::from_secs(1_700_000_000)
}

/// Derives the keys of identity `index`: a deterministic OpenPGP key, seeded
/// from `seed` and `index` alone, with a fixed creation time so its
/// fingerprints are reproducible.
fn derive_keys(seed: u64, index: u64) -> Keys {
    let mut rng = ChaCha8Rng::from_seed(derive(seed, "openpgp_key_seed", index));

    let params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V6)
        .key_type(KeyType::MlDsa65Ed25519)
        .can_sign(true)
        .can_certify(true)
        .passphrase(None)
        .created_at(fakegraph_epoch())
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V6)
                .key_type(KeyType::MlKem768X25519)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(None)
                .created_at(fakegraph_epoch())
                .build()
                .expect("valid subkey params"),
        )
        .build()
        .expect("valid key params");

    let secret = params
        .generate(&mut rng)
        .expect("deterministic key generation");
    secret.verify_bindings().expect("valid generated key");

    Keys { secret }
}

/// Unique names for `n` identities.
fn names(rng: &mut Rng, n: usize) -> Vec<String> {
    let mut used = BTreeSet::new();
    let mut names = Vec::with_capacity(n);
    while names.len() < n {
        let combination = rng.below(FIRST_NAMES.len() * LAST_NAMES.len());
        if used.insert(combination) {
            names.push(format!(
                "{} {}",
                FIRST_NAMES[combination / LAST_NAMES.len()],
                LAST_NAMES[combination % LAST_NAMES.len()]
            ));
        }
    }

    names
}

/// The fake profiles of each identity: each platform with its
/// [`FAKE_PROFILES`] probability, and an X account if none. Users are derived
/// from the name.
fn fake_profiles(rng: &mut Rng, names: &[String]) -> Vec<Vec<(&'static str, String)>> {
    names
        .iter()
        .map(|name| {
            let mut platforms: Vec<&'static str> = FAKE_PROFILES
                .iter()
                .filter_map(|&(platform, probability)| rng.chance(probability).then_some(platform))
                .collect();
            if platforms.is_empty() {
                platforms.push("X");
            }

            let handle = name.to_ascii_lowercase().replace(' ', "");
            platforms
                .into_iter()
                .map(|platform| match platform {
                    "site" => (platform, format!("{handle}.com")),
                    _ => (platform, handle.clone()),
                })
                .collect()
        })
        .collect()
}

/// The identities each identity keysigns, following the Holme–Kim model.
///
/// The [`ROOTS`] keysign each other. Then each identity joins with 1 to 3
/// links (with probabilities 5/8, 1/4 and 1/8) to earlier identities. The first
/// link goes to an identity chosen with probability proportional to its
/// connections (preferential attachment); each further link, with probability
/// [`TRIAD_PROBABILITY`], to a friend of the previous link (triad formation),
/// otherwise again by preferential attachment. The earlier identity keysigns
/// the newcomer, so everyone is reachable from the roots, and the newcomer
/// keysigns back its first link, so everyone keysigns at least one identity,
/// and its further links with probability [`RECIPROCITY`]. No identity keysigns
/// more than [`MAX_CONNECTIONS`].
fn graph(rng: &mut Rng, n: usize) -> Vec<BTreeSet<usize>> {
    let mut graph = Graph {
        keysigns: vec![BTreeSet::new(); n],
        friends: vec![BTreeSet::new(); n],
    };

    let roots = ROOTS.min(n);
    for signer in 0..roots {
        for subject in 0..roots {
            graph.link(signer, subject);
        }
    }

    for newcomer in roots..n {
        let links = match rng.below(8) {
            0..=4 => 1,
            5 | 6 => 2,
            _ => 3,
        };

        let mut linked: Vec<usize> = Vec::new();
        for link in 0..links {
            let can_sign = |graph: &Graph, identity: usize| {
                identity < newcomer
                    && !linked.contains(&identity)
                    && graph.keysigns[identity].len() < MAX_CONNECTIONS
            };

            let friend = match linked.last() {
                Some(&previous) if rng.chance(TRIAD_PROBABILITY) => {
                    let friends: Vec<usize> = graph.friends[previous]
                        .iter()
                        .copied()
                        .filter(|&friend| can_sign(&graph, friend))
                        .collect();
                    (!friends.is_empty()).then(|| friends[rng.below(friends.len())])
                }
                _ => None,
            };
            let signer = friend.or_else(|| {
                // Preferential attachment: weight connections + 1.
                let candidates: Vec<(usize, usize)> = (0..newcomer)
                    .filter(|&identity| can_sign(&graph, identity))
                    .map(|identity| (identity, graph.friends[identity].len() + 1))
                    .collect();
                let total: usize = candidates.iter().map(|(_, weight)| weight).sum();
                (total > 0).then(|| {
                    let mut pick = rng.below(total);
                    candidates
                        .iter()
                        .find(|(_, weight)| {
                            let found = pick < *weight;
                            pick = pick.saturating_sub(*weight);
                            found
                        })
                        .expect("pick is below the total weight")
                        .0
                })
            });

            let Some(signer) = signer else {
                // Everyone earlier keysigns [`MAX_CONNECTIONS`] identities
                // already, which the sparse graph never gets close to.
                assert!(link > 0, "no identity can keysign identity {newcomer}");
                break;
            };
            graph.link(signer, newcomer);
            if link == 0 || rng.chance(RECIPROCITY) {
                graph.link(newcomer, signer);
            }
            linked.push(signer);
        }
    }

    graph.keysigns
}

/// A graph being generated.
struct Graph {
    /// The identities each identity keysigns.
    keysigns: Vec<BTreeSet<usize>>,
    /// The identities each identity keysigns or is keysigned by.
    friends: Vec<BTreeSet<usize>>,
}

impl Graph {
    fn link(&mut self, signer: usize, subject: usize) {
        if signer != subject && self.keysigns[signer].len() < MAX_CONNECTIONS {
            self.keysigns[signer].insert(subject);
            self.friends[signer].insert(subject);
            self.friends[subject].insert(signer);
        }
    }
}

/// 32 bytes derived from the seed for `label` and `index`.
fn derive(seed: u64, label: &str, index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"k5 fakegraph");
    hasher.update(seed.to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(index.to_be_bytes());

    hasher.finalize().into()
}

/// A deterministic random number generator from the seed.
struct Rng {
    seed: u64,
    counter: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { seed, counter: 0 }
    }

    fn next_u64(&mut self) -> u64 {
        let bytes = derive(self.seed, "rng", self.counter);
        self.counter += 1;

        u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"))
    }

    /// A number in `0..n`. The modulo bias is negligible for the small `n`
    /// used here.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// A number in `(0, 1]`.
    fn unit(&mut self) -> f64 {
        ((self.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64
    }

    /// True with probability `p`.
    fn chance(&mut self, p: f64) -> bool {
        self.unit() <= p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seed() {
        assert_eq!(parse_seed("0xdeadcafe").unwrap(), DEFAULT_SEED);
        assert_eq!(parse_seed("42").unwrap(), 42);
        assert!(parse_seed("0xzz").is_err());
    }

    #[test]
    fn test_deterministic() {
        let graph_of = |seed| {
            let mut rng = Rng::new(seed);
            (names(&mut rng, 50), graph(&mut rng, 50))
        };
        assert_eq!(graph_of(1), graph_of(1));
        assert_ne!(graph_of(1), graph_of(2));

        assert_eq!(derive_keys(7, 3).k5(), derive_keys(7, 3).k5());
        assert_ne!(derive_keys(7, 3).k5(), derive_keys(7, 4).k5());
    }

    #[test]
    fn test_fake_profiles() {
        let mut rng = Rng::new(DEFAULT_SEED);
        let names = names(&mut rng, MAX_IDS);
        let profiles = fake_profiles(&mut rng, &names);

        let key = crate::key::test_keys();
        let mut per_platform: HashMap<&str, usize> = HashMap::new();
        for (index, (name, profiles)) in names.iter().zip(&profiles).enumerate() {
            // At least one profile, at most one per platform.
            assert!(!profiles.is_empty(), "{name}");
            let platforms: BTreeSet<_> = profiles.iter().map(|(platform, _)| platform).collect();
            assert_eq!(platforms.len(), profiles.len(), "{name}");
            for (platform, _) in profiles {
                *per_platform.entry(platform).or_default() += 1;
            }
            // They are valid fake profiles (signing is slow: check a sample).
            if index < 20 {
                for (platform, user) in profiles {
                    fake::create(&key, platform, user).unwrap();
                }
            }
        }

        // About 90% X (plus the 8% with nothing else), 10% site and GitHub.
        let share = |platform| per_platform[platform] as f64 / MAX_IDS as f64;
        assert!((0.9..1.0).contains(&share("X")), "X {}", share("X"));
        assert!(
            (0.05..0.15).contains(&share("site")),
            "site {}",
            share("site")
        );
        assert!(
            (0.05..0.15).contains(&share("github")),
            "github {}",
            share("github")
        );
    }

    #[test]
    fn test_graph() {
        for n in [2, 3, 4, 11, 100, MAX_IDS] {
            let mut rng = Rng::new(DEFAULT_SEED);
            let names = names(&mut rng, n);
            assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), n);

            let connections = graph(&mut rng, n);
            for (signer, subjects) in connections.iter().enumerate() {
                assert!((1..=MAX_CONNECTIONS).contains(&subjects.len()));
                assert!(!subjects.contains(&signer));
            }

            // Every identity is reachable from the roots.
            let mut reached: BTreeSet<usize> = (0..n.min(ROOTS)).collect();
            let mut pending: Vec<usize> = reached.iter().copied().collect();
            while let Some(signer) = pending.pop() {
                for &subject in &connections[signer] {
                    if reached.insert(subject) {
                        pending.push(subject);
                    }
                }
            }
            assert_eq!(reached.len(), n, "n = {n}");
        }
    }

    #[test]
    fn test_graph_is_human() {
        let mut rng = Rng::new(DEFAULT_SEED);
        let connections = graph(&mut rng, MAX_IDS);

        // Sparse: under 3 keysigns per identity, most with 1 or 2.
        let degrees: Vec<usize> = connections.iter().map(BTreeSet::len).collect();
        let mean = degrees.iter().sum::<usize>() as f64 / MAX_IDS as f64;
        assert!((1.5..3.0).contains(&mean), "mean {mean}");
        let few = degrees.iter().filter(|&&degree| degree <= 2).count();
        assert!(few > MAX_IDS / 2, "{few} with 1 or 2 keysigns");

        // Heavy tailed: a few hubs are keysigned by many.
        let mut keysigned_by = vec![0usize; MAX_IDS];
        for subject in connections.iter().flatten() {
            keysigned_by[*subject] += 1;
        }
        keysigned_by.sort_unstable();
        let (median, max) = (keysigned_by[MAX_IDS / 2], keysigned_by[MAX_IDS - 1]);
        assert!(max >= 5 * median.max(1), "median {median}, max {max}");

        // Mostly mutual, and clustered: friends of friends are friends.
        let mutual = connections
            .iter()
            .enumerate()
            .flat_map(|(signer, subjects)| subjects.iter().map(move |&subject| (signer, subject)))
            .filter(|&(signer, subject)| connections[subject].contains(&signer))
            .count();
        let edges: usize = degrees.iter().sum();
        assert!(mutual * 2 > edges, "{mutual} mutual of {edges}");

        let linked =
            |a: usize, b: usize| connections[a].contains(&b) || connections[b].contains(&a);
        let triangles = (0..MAX_IDS)
            .flat_map(|a| (a + 1..MAX_IDS).map(move |b| (a, b)))
            .filter(|&(a, b)| linked(a, b))
            .map(|(a, b)| {
                (b + 1..MAX_IDS)
                    .filter(|&c| linked(a, c) && linked(b, c))
                    .count()
            })
            .sum::<usize>();
        assert!(triangles > MAX_IDS / 10, "{triangles} triangles");
    }
}
