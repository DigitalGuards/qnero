//! Witness filling for the public batch.
//!
//! Structural checks only; the admission boundary is
//! [`QneroPublicBatchProver::prove_batch`](super::QneroPublicBatchProver::prove_batch).

use anyhow::{anyhow, bail, Result};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};

use qnero_circuit::convert::digest_to_felts;
use qnero_circuit::F;
use qnero_notes::Digest;

use crate::artifacts::ensure_proof_shape_matches_targets;
use crate::public_batch::circuit::PublicBatchTargets;
use crate::Proof;

pub(crate) fn fill_public_batch_witness(
    pw: &mut PartialWitness<F>,
    targets: &PublicBatchTargets,
    private_batch_proofs: &[Proof],
    aggregator_address: &Digest,
) -> Result<()> {
    if private_batch_proofs.len() != targets.private_batch_proofs.len() {
        bail!(
            "the batch has {} private-batch proofs, but the circuit has {} slots",
            private_batch_proofs.len(),
            targets.private_batch_proofs.len()
        );
    }

    let address = digest_to_felts(aggregator_address);
    for (target, limb) in targets.aggregator_address.iter().zip(address) {
        pw.set_target(*target, limb)
            .map_err(|e| anyhow!("failed to write the aggregator address: {}", e))?;
    }

    for (slot, (proof_target, proof)) in targets
        .private_batch_proofs
        .iter()
        .zip(private_batch_proofs)
        .enumerate()
    {
        ensure_proof_shape_matches_targets(proof_target, proof, slot, "private-batch proof")?;
        pw.set_proof_with_pis_target(proof_target, proof)
            .map_err(|e| {
                anyhow!(
                    "failed to write the private-batch proof at slot {}: {}",
                    slot,
                    e
                )
            })?;
    }

    Ok(())
}
