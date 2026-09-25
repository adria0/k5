// The k5 API: every operation of the command line, returning data instead
// of printing it.
//
// An [`K5`] is the local identity (the keys of a config file) plus the
// notary key TLSNotary attestations must be signed with. Attestations are
// read from and written to [`ATTESTATIONS_DIR`].
//
// Nothing here writes to stdout or stderr: warnings (invalid records that were
// skipped, a replaced self attestation...) are part of the returned values,
// and long running operations report progress through a callback.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
};

use crate::{
    attestations::{self, export, keysignparty, me, tlsnotary},
    fakegraph, graph,
    key::{self, Keys},
    message, signcrypt,
};
pub use crate::{
    attestations::{
        export::{Export, Merged, Outcome},
        keysignparty::KeySign,
        me::{Created, Me},
        tlsnotary::{Notarized, NotaryConfig, Verified as TlsnVerified},
        Attested, Checked, Invalid, Listing, Profile, ProfileAttestation, DIR as ATTESTATIONS_DIR,
    },
    fakegraph::{Summary as FakegraphSummary, DEFAULT_SEED, DIR as IDS_DIR, MAX_IDS},
    Error,
};

/// Default notary public key (compressed secp256k1, hex).
pub const DEFAULT_NOTARY_KEY: &str =
    "02f37514ced12c58460456a07b42042894f413ff63f9a3f0824fbe86e6c7da6764";

/// The local k5.
pub struct K5 {
    keys: Keys,
    notary_key: String,
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
        }
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

    /// Makes sure the attestations contain a valid self attestation of the
    /// local keys, creating it if missing or outdated.
    pub async fn ensure_self_attestation(&self) -> Result<Option<Created>, Error> {
        me::ensure(&self.keys).await
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
        tlsnotary::attest(config, url, presentation_path, progress).await
    }

    /// All the valid attestations, sorted by k5 and profile.
    pub async fn list(&self) -> Result<Listing, Error> {
        attestations::list(&self.notary_key).await
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
        attestations::attested_by(k5, &self.notary_key).await
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
        attestations::audit(&self.notary_key).await
    }

    /// Exports the valid attestations as a signed message.
    pub async fn export(&self) -> Result<Export, Error> {
        let export = export::create(&self.keys, &self.notary_key).await?;

        // Check the output before handing it out.
        message::verify(&export.markdown, &attestations::keyring().await?)?;

        Ok(export)
    }

    /// Merges the valid attestations of an export that are on the web of
    /// trust of the local k5. `force` replaces existing records with the
    /// same name but different content.
    pub async fn merge(&self, markdown: &str, force: bool) -> Result<MergeReport, Error> {
        let (signer, merged) = export::merge(markdown, &self.k5(), &self.notary_key, force).await?;

        Ok(MergeReport { signer, merged })
    }

    /// Attests that `k5` belongs to `name`, storing the attestation.
    /// Returns its path.
    pub async fn keysign(&self, k5: &str, name: &str) -> Result<String, Error> {
        let keyring = attestations::keyring().await?;
        keysignparty::attest(&self.keys, k5, name, &keyring).await
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

    /// Generates a deterministic fake social graph of `n` identities from
    /// `seed`, and audits it.
    pub async fn fakegraph(&self, n: usize, seed: u64) -> Result<FakegraphSummary, Error> {
        fakegraph::run(&self.keys, n, seed).await
    }

    /// Signs `msg`, returning the armored cleartext-signed message.
    pub async fn sign(&self, msg: &str) -> Result<String, Error> {
        let armored = message::sign(&self.keys.secret, msg)?;

        // Check the output before handing it out.
        message::verify(&armored, &attestations::keyring().await?)?;

        Ok(armored)
    }

    /// Signs `msg` and encrypts it to the encryption subkey of the self
    /// attestation of `to` (with or without the `k5:` prefix).
    pub async fn signcrypt(&self, to: &str, msg: &str) -> Result<Signcrypted, Error> {
        let to_key = signcrypt::recipient_encryption_key(to).await?;
        let to = signcrypt::recipient_k5(to);
        let armored = signcrypt::seal(&self.keys, &to, &to_key, msg)?;

        Ok(Signcrypted { to, armored })
    }

    /// Verifies a signed message, a signcrypted message addressed to the
    /// local k5, or an attestation record, detected from `content`.
    pub async fn verify(&self, content: &str) -> Result<Verification, Error> {
        let keyring = attestations::keyring().await?;

        if content.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            let signed = message::verify(content, &keyring)?;
            let export = if export::is_export(&signed.msg) {
                Some(export::verify(&signed.msg, &self.notary_key).await?)
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

/// Parses a fakegraph seed, in hex with a `0x` prefix or in decimal.
pub fn parse_seed(seed: &str) -> Result<u64, Error> {
    fakegraph::parse_seed(seed)
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
