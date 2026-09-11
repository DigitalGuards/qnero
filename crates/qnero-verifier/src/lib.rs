//! Verification of Qnero proofs: the batch proofs a runtime settles, and
//! behind a non-default feature, the leaf proofs a wallet aggregates.
//!
//! This crate depends on `qp-plonky2-verifier` and on `qnero-circuit` with its
//! circuit feature off, so it pulls in neither the prover stack nor the note
//! primitives, and it is `no_std` plus `alloc` with default features off. That
//! is what lets `pallet-shielded` link it into a wasm runtime at M4.
//!
//! # What a runtime verifies
//!
//! The private batch, and above it the public batch. Both are in [`batch`].
//! The leaf entry points are behind the `leaf` feature, off by default,
//! because a leaf proof does not blind and is not a transaction: it is an
//! input to the wallet's own aggregator and must never cross a trust
//! boundary. A runtime that took this crate with default features cannot name
//! them.
//!
//! # Two things every loader here does
//!
//! It holds an artifact to a profile before trusting it, and it requires proof
//! bytes to be the canonical encoding of the proof they decode to. Neither is
//! optional: plonky2's structural check on deserialized verifier data rejects
//! almost nothing, and its proof reader stops as soon as it has read a whole
//! proof without checking that the buffer is exhausted.
//!
//! Forked in shape from Quantus-Network/qp-zk-circuits (MIT); see NOTICE and
//! CHANGES.md.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use anyhow::{ensure, Result};
use qnero_circuit::layout::DIGEST_FELTS;
use qp_plonky2_verifier::{CommonCircuitData, D, F};

pub mod batch;
#[cfg(feature = "leaf")]
pub mod leaf;

pub use batch::{
    parse_private_batch_public_input_felts, parse_private_batch_public_inputs,
    parse_public_batch_public_input_felts, parse_public_batch_public_inputs, BatchLeafSlot,
    PrivateBatchPublicInputs, PublicBatchPublicInputs, QneroPrivateBatchVerifier,
    QneroPublicBatchVerifier,
};
#[cfg(feature = "leaf")]
pub use leaf::{parse_public_input_felts, parse_public_inputs, LeafPublicInputs, QneroVerifier};

/// Size cap on a serialized verifier artifact, applied before it is parsed.
///
/// The canonical artifacts are a few hundred kilobytes at most. The cap bounds
/// the work done on an untrusted blob before anything about it has been
/// checked.
pub const MAX_VERIFIER_ARTIFACT_BYTES: usize = 1024 * 1024;

/// Size cap on a serialized proof, applied before it is parsed.
pub const MAX_PROOF_BYTES: usize = 1024 * 1024;

/// Read one 4-felt digest out of a public-input vector.
pub(crate) fn digest_at(public_inputs: &[F], start: usize) -> [F; DIGEST_FELTS] {
    core::array::from_fn(|i| public_inputs[start + i])
}

/// Refuse deserialized common data whose index structure does not describe its
/// own gate list.
///
/// Verification iterates these ranges. A gate's filter is a product over its
/// selector group, so a group of `0..2^40` is not a wrong answer, it is a
/// verifier that never returns: one flipped bit in the length byte of a
/// published artifact is enough, and it survives everything else this crate
/// checks, because the circuit digest does not cover the selector layout and a
/// parameter floor never looks at it. Bounding the ranges by the gate list
/// turns that into a refused artifact.
///
/// This is not a general defence against a crafted artifact. A hostile build
/// host has other unbounded parameters to reach for, inside individual gates,
/// and an artifact is only as trustworthy as the build that produced it. What
/// this closes is the case a runtime can actually meet: a corrupted or
/// truncated file that would otherwise hang the verifier instead of failing.
pub(crate) fn ensure_common_data_is_structurally_sound(
    common: &CommonCircuitData<F, D>,
    label: &str,
) -> Result<()> {
    let gates = common.gates.len();
    ensure!(
        common.selectors_info.selector_indices.len() == gates,
        "the {} artifact has {} selector indices for {} gates",
        label,
        common.selectors_info.selector_indices.len(),
        gates
    );
    for (index, group) in common.selectors_info.groups.iter().enumerate() {
        ensure!(
            group.start <= group.end && group.end <= gates,
            "the {} artifact's selector group {} is {}..{}, which does not index its {} gates",
            label,
            index,
            group.start,
            group.end,
            gates
        );
    }
    ensure!(
        common.k_is.len() == common.config.num_routed_wires,
        "the {} artifact carries {} coset shifts for {} routed wires",
        label,
        common.k_is.len(),
        common.config.num_routed_wires
    );
    Ok(())
}
