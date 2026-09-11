//! Witness filling for the private batch.
//!
//! Structural checks only. This is not an admission boundary: cryptographic
//! verification of each leaf, cross-slot compatibility, the non-all-padding
//! rule and padding itself all happen in
//! [`QneroPrivateBatchProver::aggregate`](super::QneroPrivateBatchProver::aggregate),
//! which is why this module is `pub(crate)`.

use anyhow::{anyhow, bail, Result};

use plonky2::iop::witness::{PartialWitness, WitnessWrite};

use qnero_circuit::batch_layout::DIGEST_FELTS;
use qnero_circuit::layout::NUM_INPUTS;
use qnero_circuit::F;

use crate::artifacts::ensure_proof_shape_matches_targets;
use crate::private_batch::circuit::PrivateBatchTargets;
use crate::Proof;

/// One padding-nullifier preimage per input slot of one leaf slot.
pub type SlotPaddingPreimages = [[F; DIGEST_FELTS]; NUM_INPUTS];

/// Write a padded, shuffled leaf-proof vector and its padding randomness into
/// the circuit's targets.
pub(crate) fn fill_private_batch_witness(
    pw: &mut PartialWitness<F>,
    targets: &PrivateBatchTargets,
    proofs: &[Proof],
    padding_nullifier_preimages: &[SlotPaddingPreimages],
) -> Result<()> {
    let slots = targets.leaf_proofs.len();

    if proofs.len() != slots {
        bail!(
            "the batch has {} leaf proofs, but the circuit has {} slots",
            proofs.len(),
            slots
        );
    }
    if targets.padding_nullifier_preimages.len() != slots {
        bail!(
            "the circuit's target layout is inconsistent: {} padding-preimage slots against {} \
             leaf slots",
            targets.padding_nullifier_preimages.len(),
            slots
        );
    }
    if padding_nullifier_preimages.len() != slots {
        bail!(
            "got {} padding-preimage sets, but the circuit has {} slots",
            padding_nullifier_preimages.len(),
            slots
        );
    }

    for (slot, (proof_target, proof)) in targets.leaf_proofs.iter().zip(proofs).enumerate() {
        // The full shape preflight has to run before the writer touches a
        // target: see `ensure_proof_shape_matches_targets`.
        ensure_proof_shape_matches_targets(proof_target, proof, slot, "leaf proof")?;
        pw.set_proof_with_pis_target(proof_target, proof)
            .map_err(|e| anyhow!("failed to write the leaf proof at slot {}: {}", slot, e))?;
    }

    for (slot, (slot_targets, slot_values)) in targets
        .padding_nullifier_preimages
        .iter()
        .zip(padding_nullifier_preimages)
        .enumerate()
    {
        for input in 0..NUM_INPUTS {
            for limb in 0..DIGEST_FELTS {
                pw.set_target(slot_targets[input][limb], slot_values[input][limb])
                    .map_err(|e| {
                        anyhow!(
                            "failed to write padding preimage {} limb {} at slot {}: {}",
                            input,
                            limb,
                            slot,
                            e
                        )
                    })?;
            }
        }
    }

    Ok(())
}
