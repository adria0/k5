// k5: notarize and keysign attestations of k5 profiles, sign messages
// with the OpenPGP post-quantum key, and verify both.
//
// [`api`] is the entry point, used by the command line: an [`api::K5`]
// exposes every operation, returning data instead of printing it. The other
// modules are the building blocks it is made of.
//
// Attestations live in `attestations`: TLSNotary (with its platform plugins
// for X, GitHub and websites) and key sign party.

pub mod api;
pub mod attestations;
pub mod fakegraph;
pub mod graph;
pub mod key;
pub mod message;
mod parallel;
pub mod signcrypt;

pub type Error = Box<dyn std::error::Error>;
