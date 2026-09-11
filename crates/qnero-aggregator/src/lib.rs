//! Qnero batch aggregation: the two recursive layers above the spend leaf.
//!
//! ```text
//! leaf proof        one shielded transfer, 26 public inputs, non-ZK
//!   |  N of them
//! private batch     zero knowledge, 5 + 21*N public inputs, the on-chain
//!   |               transaction unit a wallet submits
//!   |  n_inner of them
//! public batch      an aggregator's bundle, 4 + n_inner*(5 + 21*N) public
//!                   inputs, non-ZK
//! ```
//!
//! Both layers verify their inner proofs recursively against a verifier key
//! baked in as circuit constants. [`recursive`] has the reason, and what a
//! witnessed key would let a prover do.
//!
//! # What the private batch is for
//!
//! Two things, and they are separate. It amortizes verification: the chain
//! verifies one proof for N. And it is where zero knowledge is applied,
//! because a leaf proof's FRI openings leak the structure of the notes it
//! spends and must never leave the wallet.
//!
//! # The forwarding contract
//!
//! Every non-padding slot's **two** nullifiers, **two** output commitments,
//! fee and `ct_digest` reach the aggregated public inputs unchanged, and all
//! `2N` real nullifiers are constrained pairwise distinct. A wrapper that
//! carried one nullifier per leaf, which is the shape upstream's private batch
//! has, would drop every leaf's `nf_2` at this boundary: a note spent from
//! input slot 1 would never be marked used and could be spent again without
//! limit. `docs/CIRCUIT.md` section 8 states the contract; `batch_layout` in
//! `qnero-circuit` is where the positions live.
//!
//! # Padding
//!
//! A batch has a fixed number of slots. Empty ones are filled with the padding
//! leaf, recognised by the sentinel block hash in `qnero_circuit::padding`,
//! and every value a padding slot would publish is masked here: its nullifiers
//! are replaced with hashes of caller-supplied fresh randomness, and its
//! commitments, fee and `ct_digest` are zeroed. The wrapper trusts no
//! invariant that crosses a circuit boundary.
//!
//! Forked from Quantus-Network/qp-zk-circuits (MIT); see NOTICE and CHANGES.md.

#![forbid(unsafe_code)]

pub mod artifacts;
pub mod config;
pub mod padding_proof;
pub mod private_batch;
pub mod public_batch;
pub mod recursive;

#[cfg(test)]
mod test_fixtures;

pub use config::{validate_proof_count, CircuitBinsConfig, MAX_PROOF_COUNT};
pub use padding_proof::{
    canonical_padding_leaf_public_inputs, generate_padding_leaf_proof,
    validate_padding_leaf_template,
};
pub use private_batch::{PrivateBatchTargets, QneroPrivateBatchCircuit, QneroPrivateBatchProver};
pub use public_batch::{
    PublicBatchInputs, PublicBatchTargets, QneroPublicBatchCircuit, QneroPublicBatchProver,
};

/// Plonky2 types every layer shares, re-exported so a caller does not have to
/// name the plonky2 crate to hold a proof.
pub use qnero_circuit::{C, D, F};

/// A proof at any layer.
pub type Proof = plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>;
