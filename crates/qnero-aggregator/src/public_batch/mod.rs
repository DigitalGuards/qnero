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
//! A repeated inner proof is refused by the circuit as well, keyed on the
//! first nullifier of its first slot. What has no circuit counterpart is the
//! general nullifier rule: comparing every inner's `2N` nullifiers against
//! every other's is not affordable at the chain's dimensions, so two
//! *different* private batches that settle one note are caught here and
//! nowhere else before the chain rejects the whole settlement.
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
