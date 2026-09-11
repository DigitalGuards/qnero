//! The Qnero v0 shielded spend circuit (the leaf).
//!
//! One leaf is one shielded transfer: up to two input notes, exactly two
//! output notes, a public fee, and a digest binding the output ciphertexts.
//! The private batch aggregator, one layer up, is where zero knowledge is
//! applied and is the on-chain transaction unit. A raw leaf proof is non-ZK by
//! design and must never cross a trust boundary; see
//! [`config::qnero_leaf_circuit_config`].
//!
//! Layout and the tree leaf rule are documented in `docs/CIRCUIT.md`; the
//! public-input indices live in [`layout`], the batch layouts M3 wraps them in
//! in [`batch_layout`], the padding sentinel in [`padding`] and the
//! proof-system parameters a verifier must insist on in [`params`]. All four
//! compile on their own, so a verifier reads them without the prover stack.
//!
//! Forked from Quantus-Network/qp-zk-circuits (MIT); see NOTICE and CHANGES.md.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "circuit"), no_std)]

pub mod batch_layout;
pub mod layout;
pub mod padding;
pub mod params;

/// Plonky2 configuration shared by every Qnero circuit. `D = 2` is the field
/// extension degree, `C` the Poseidon-over-Goldilocks config, `F` Goldilocks.
#[cfg(feature = "circuit")]
pub use plonky2::{C, D, F};

#[cfg(feature = "circuit")]
pub mod circuit;
#[cfg(feature = "circuit")]
pub mod config;
#[cfg(feature = "circuit")]
pub mod convert;
#[cfg(feature = "circuit")]
pub mod gadgets;
#[cfg(feature = "circuit")]
pub mod header;
#[cfg(feature = "circuit")]
pub mod merkle;
#[cfg(feature = "circuit")]
pub mod note_gadget;
#[cfg(feature = "circuit")]
pub mod sensitive;
#[cfg(feature = "circuit")]
pub mod witness;

#[cfg(feature = "circuit")]
pub use circuit::{QneroSpendCircuit, SpendTargets};
#[cfg(feature = "circuit")]
pub use config::{
    qnero_leaf_circuit_config, qnero_leaf_zk_circuit_config, qnero_private_batch_circuit_config,
    qnero_public_batch_circuit_config,
};
#[cfg(feature = "circuit")]
pub use header::HeaderInputs;
#[cfg(feature = "circuit")]
pub use merkle::{CommitmentTree, MerklePath, MAX_DEPTH};
#[cfg(feature = "circuit")]
pub use sensitive::Secret;
#[cfg(feature = "circuit")]
pub use witness::{fill_witness, InputNote, OutputNote, SpendWitness};
