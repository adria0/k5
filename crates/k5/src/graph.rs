// Graphviz digraph of the attestations: which k5 keysigns which, and the
// social profiles (TLSNotary attestations, real or fake) of each k5.
//
// Nodes are labeled with their profiles, one per line (`X:handle`,
// `github:user`, `site:domain`). A k5 without profiles is labeled with its
// hex, split in lines of 8 characters. The local k5 has a double border,
// and k5s with fake profiles a dashed one.

use std::collections::{BTreeMap, BTreeSet};

use crate::attestations::{export, me, ProfileAttestation};

/// Length of the lines of a k5 hex in a label.
const HEX_LINE: usize = 8;

/// The profiles of a k5.
#[derive(Default)]
struct Node {
    profiles: BTreeSet<String>,
    fake: bool,
}

/// Builds the digraph of `attestations`, `me` being the local k5.
pub fn dot(me: &str, attestations: &[ProfileAttestation]) -> String {
    let mut nodes: BTreeMap<&str, Node> = BTreeMap::new();
    let mut edges: BTreeSet<(&str, &str)> = BTreeSet::new();

    nodes.entry(me).or_default();
    for attestation in attestations {
        let subject = attestation.profile.k5.as_str();
        let node = nodes.entry(subject).or_default();

        if export::is_keysign(attestation) {
            if let Some(signer) = attestation.signer.as_deref() {
                edges.insert((signer, subject));
                nodes.entry(signer).or_default();
            }
        } else if attestation.profile.platform != me::RECORD_TYPE {
            node.profiles.insert(format!(
                "{}:{}",
                attestation.profile.platform, attestation.profile.user
            ));
            node.fake |= attestation.fake;
        }
    }

    let mut dot = String::from("digraph k5 {\n    node [shape=box];\n");
    for (k5, node) in &nodes {
        let label = if node.profiles.is_empty() {
            k5.as_bytes()
                .chunks(HEX_LINE)
                .map(|line| String::from_utf8_lossy(line).into_owned())
                .collect::<Vec<_>>()
                .join("\\n")
        } else {
            node.profiles
                .iter()
                .map(|profile| escape(profile))
                .collect::<Vec<_>>()
                .join("\\n")
        };

        let mut attributes = vec![format!("label=\"{label}\"")];
        if *k5 == me {
            attributes.push("peripheries=2".to_string());
        }
        if node.fake {
            attributes.push("style=dashed".to_string());
        }
        dot.push_str(&format!("    \"{k5}\" [{}];\n", attributes.join(", ")));
    }
    for (signer, subject) in &edges {
        dot.push_str(&format!("    \"{signer}\" -> \"{subject}\";\n"));
    }
    dot.push_str("}\n");

    dot
}

/// Escapes a string for a double quoted DOT label.
fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestations::Profile;

    fn attestation(
        platform: &'static str,
        user: &str,
        k5: &str,
        signer: Option<&str>,
        fake: bool,
    ) -> ProfileAttestation {
        ProfileAttestation {
            profile: Profile {
                platform,
                user: user.to_string(),
                k5: k5.to_string(),
            },
            signer: signer.map(str::to_string),
            attributes: Vec::new(),
            file: String::new(),
            fake,
        }
    }

    #[test]
    fn test_dot() {
        let [me, bob, carol] = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let attestations = [
            attestation("keysignparty", "Bob", &bob, Some(&me), false),
            attestation("keysignparty", "Bob", &bob, Some(&me), false),
            attestation("keysignparty", "Carol", &carol, Some(&bob), true),
            attestation("X", "bob", &bob, None, false),
            attestation("github", "bob\"", &bob, None, false),
            attestation("site", "carol.com", &carol, None, true),
            attestation(me::RECORD_TYPE, "self", &carol, Some(&carol), true),
        ];

        let dot = dot(&me, &attestations);
        assert_eq!(
            dot,
            format!(
                "digraph k5 {{\n    node [shape=box];\n    \
                 \"{me}\" [label=\"aaaaaaaa\\naaaaaaaa\\naaaaaaaa\\naaaaaaaa\\naaaaaaaa\\naaaaaaaa\\naaaaaaaa\\naaaaaaaa\", peripheries=2];\n    \
                 \"{bob}\" [label=\"X:bob\\ngithub:bob\\\"\"];\n    \
                 \"{carol}\" [label=\"site:carol.com\", style=dashed];\n    \
                 \"{me}\" -> \"{bob}\";\n    \
                 \"{bob}\" -> \"{carol}\";\n\
                 }}\n"
            )
        );
    }
}
