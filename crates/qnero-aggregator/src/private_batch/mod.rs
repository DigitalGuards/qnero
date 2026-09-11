//! The private batch: `N` leaf proofs into one zero-knowledge proof.
//!
//! # Admission boundary
//!
//! [`QneroPrivateBatchProver::aggregate`] is where untrusted proofs enter. It
//! verifies every leaf against the pinned leaf verifier, rejects batches the
//! circuit could never prove (mixed blocks, repeated nullifiers, nothing but
//! padding), pads with the validated padding template and shuffles, all before
//! the recursive proving run, which on phone-class hardware is the difference
//! between a millisecond rejection and minutes of work.
//!
//! The low-level witness filler does structural checks only, so it stays
//! crate-private:
//!
//! ```compile_fail
//! use qnero_aggregator::private_batch::witness::fill_private_batch_witness;
//! ```
//!
//! A `compile_fail` doctest passes on any compile error, including a renamed
//! crate or module, so this passing companion pins the same path prefix and
//! leaves the `witness` segment's privacy as the only thing that can fail
//! above:
//!
//! ```
//! use qnero_aggregator::private_batch::QneroPrivateBatchProver;
//! ```

pub mod circuit;
pub mod prover;
pub(crate) mod witness;

pub use circuit::{PrivateBatchTargets, QneroPrivateBatchCircuit};
pub use prover::{PrivateBatchBuildMetrics, QneroPrivateBatchProver};
