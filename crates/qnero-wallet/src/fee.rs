//! The fee floor, computed before the witness is built.
//!
//! The fee is a public input of the leaf proof, fixed at proving time and not
//! raisable afterwards (`docs/CIRCUIT.md` section 9.7). Both terms of the
//! floor are known before proving, because the ciphertext sizes are: a
//! `NoteCiphertext` is a fixed 1731 bytes plus the memo. So a wallet owes the
//! arithmetic first and proves second, or it pays for a proof the chain
//! refuses with `PayloadUnderpaid`.

use crate::metadata::ChainMetadata;

/// The per-slot floor: `MinLeafFee + ceil(ciphertext bytes / quantum)`.
pub fn slot_fee_floor(metadata: &ChainMetadata, ct_1_len: usize, ct_2_len: usize) -> u64 {
    let bytes = ct_1_len as u64 + ct_2_len as u64;
    metadata
        .min_leaf_fee
        .saturating_add(bytes.div_ceil(u64::from(metadata.ciphertext_bytes_per_fee_quantum)))
}

/// The whole-submission floor, over every real slot a submission carries.
///
/// ```text
/// (settling slots + skipped slots) * MinLeafFee
///     + ceil(carried bytes / CiphertextBytesPerFeeQuantum)
/// ```
///
/// A wallet's own submission is one private batch with one real slot and no
/// skipped segment, so this equals the per-slot floor. It is written out
/// because it is the bound the pallet actually applies, and because the two
/// stop agreeing the moment a wallet sends more than one transfer in a batch.
pub fn submission_fee_floor(metadata: &ChainMetadata, real_slots: u64, carried_bytes: u64) -> u64 {
    metadata
        .min_leaf_fee
        .saturating_mul(real_slots)
        .saturating_add(
            carried_bytes.div_ceil(u64::from(metadata.ciphertext_bytes_per_fee_quantum)),
        )
}

/// A ciphertext that exceeds `MaxCiphertextBytes` fails the extrinsic's SCALE
/// decode, after the proof committing to those exact bytes exists. So the
/// check happens before proving.
pub fn ensure_ciphertext_fits(
    metadata: &ChainMetadata,
    len: usize,
    what: &str,
) -> anyhow::Result<()> {
    if len > metadata.max_ciphertext_bytes as usize {
        anyhow::bail!(
            "the {what} ciphertext is {len} bytes and this runtime caps one at {}. Shorten the \
             memo: the extrinsic would fail to decode after the proof was built.",
            metadata.max_ciphertext_bytes
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> ChainMetadata {
        ChainMetadata {
            shielded_pallet_index: 24,
            submit_private_batch: 0,
            submit_public_batch: 1,
            shield: 2,
            block_hash_window: 256,
            min_leaf_fee: 1,
            ciphertext_bytes_per_fee_quantum: 512,
            max_ciphertext_bytes: 2048,
            signed_extensions: Vec::new(),
        }
    }

    /// The two figures `docs/CIRCUIT.md` section 9.7 pins: two real
    /// ciphertexts (3462 bytes) pay eight quanta, two padded to the cap (4096)
    /// pay nine.
    #[test]
    fn the_slot_floor_matches_the_documented_endpoints() {
        assert_eq!(slot_fee_floor(&runtime(), 1731, 1731), 8);
        assert_eq!(slot_fee_floor(&runtime(), 2048, 2048), 9);
    }

    /// A started quantum is a whole quantum.
    #[test]
    fn a_partial_quantum_of_payload_rounds_up() {
        assert_eq!(slot_fee_floor(&runtime(), 1, 0), 2);
        assert_eq!(slot_fee_floor(&runtime(), 512, 0), 2);
        assert_eq!(slot_fee_floor(&runtime(), 513, 0), 3);
        assert_eq!(slot_fee_floor(&runtime(), 0, 0), 1);
    }

    /// For the submission a wallet sends, one real slot in one segment, the
    /// two floors are the same number. The pallet applies both.
    #[test]
    fn the_submission_floor_equals_the_slot_floor_for_a_single_transfer() {
        let metadata = runtime();
        let slot = slot_fee_floor(&metadata, 1731, 1731);
        assert_eq!(submission_fee_floor(&metadata, 1, 3462), slot);
    }

    #[test]
    fn an_oversized_ciphertext_is_refused_before_proving() {
        let metadata = runtime();
        assert!(ensure_ciphertext_fits(&metadata, 2048, "payment").is_ok());
        assert!(ensure_ciphertext_fits(&metadata, 2049, "payment").is_err());
    }
}
