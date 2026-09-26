// k5net: k5 peer to peer over iroh.
//
// Two k5s talk directly, addressed by public key, to send each other private
// (signcrypted) messages and to merge each other's attestations.
//
// A k5 cannot be dialed by its id (an OpenPGP fingerprint), so each k5 has its
// own iroh key, stored in the `[iroh]` section of `k5.toml`, and publishes its
// endpoint id in an iroh attestation signed by the k5 key
// (`k5lib::attestations::iroh`). Those records travel with the others through
// export and merge, so the web of trust is how k5s find each other; n0's
// address lookup and relays then find the way to the endpoint. A first
// contact uses a ticket instead (`Node::ticket` / `Node::connect_ticket`).
//
// Only k5s on the web of trust (reachable through keysigns) are served.

mod node;
mod peer;
mod proto;

pub use iroh::{address_lookup::MemoryLookup, SecretKey};
pub use node::{load_or_create_secret, Event, Network, Node};
