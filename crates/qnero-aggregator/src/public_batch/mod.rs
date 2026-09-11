//! The public batch: `n_inner` private batches into one proof.
//!
//! # Admission boundary
//!
//! [`QneroPublicBatchProver::prove_batch`] verifies every inner proof against
//! the pinned private-batch verifier, enforces the one-block rule, refuses a
//! caller-supplied padding batch and refuses two inner proofs that publish the
//! same nullifier, all before proving, which at production sizes takes tens of
//! seconds.
//!
//! The nullifier rule is the one with no circuit counterpart: comparing every
//! inner's `2N` nullifiers against every other's is not affordable in circuit
//! at the chain's dimensions, so this is the only place a duplicated inner is
//! caught before the chain rejects the whole settlement.
//!
//! The low-level witness filler is crate-private for the same reason it is at
//! the private batch:
//!
//! ```compile_fail
//! use qnero_aggregator::public_batch::witness::fill_public_batch_witness;
//! ```
//!
//! ```
//! use qnero_aggregator::public_batch::QneroPublicBatchProver;
//! ```

pub mod circuit;
pub mod prover;
pub(crate) mod witness;

pub use circuit::{PublicBatchTargets, QneroPublicBatchCircuit};
pub use prover::{PublicBatchInputs, QneroPublicBatchProver};
