//! Qnero note primitives, down to the layer that needs no lattice
//! cryptography.
//!
//! Everything here is Poseidon2 over Goldilocks: digests and their domain
//! tags, the two-layer note commitment, the nullifier rules, and the spend
//! credential the circuit derives `pk` from. `qnero-notes` builds the rest of
//! the wallet on top, adding ML-KEM viewing keys, bech32m addresses and note
//! encryption, and re-exports all of this so a wallet keeps one import.
//!
//! **Why the split.** ML-KEM is a heavy and version-churny dependency, and
//! nothing between a note commitment and a verified proof needs it. The spend
//! circuit, the batch aggregators and `pallet-shielded` all reach for `Digest`
//! and the domain tags and none of them encrypts anything, so the edge from
//! those crates to `ml-kem` was reachable but never used. It is not a
//! hypothetical cost: a Cargo lock file resolves optional dependencies too, so
//! one workspace linking the verifier had `ml-kem` in its graph, where it
//! collided with the `ml-kem` the chain's own post-quantum Noise transport
//! pins. Cutting the edge at the package level is what removes the collision.
//!
//! `docs/CIRCUIT.md` section 3 is the authority on the hash rules here.

#![forbid(unsafe_code)]

pub mod digest;
pub mod error;
pub mod keys;
pub mod miner;
pub mod note;

pub use digest::{Digest, Felt};
pub use error::NoteError;
pub use keys::{derive_ak, derive_pk, DerivedKeys};
pub use miner::{MinerKey, MINER_KEY_HRP, MINER_KEY_VERSION};
pub use note::{
    coinbase_r, coinbase_rho, commitment_from_inner, dummy_nullifier, entry_rho, note_inner,
    nullifier, output_rho, Note, MAX_VALUE, VALUE_BITS,
};
