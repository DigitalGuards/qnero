//! The fee floor, computed before the witness is built.
//!
//! The fee is a public input of the leaf proof, fixed at proving time and not
//! raisable afterwards (`docs/CIRCUIT.md` section 9.7). Both terms of the
//! floor are known before proving, because the ciphertext sizes are: a
//! `NoteCiphertext` is a fixed 1731 bytes plus the memo. So a wallet owes the
//! arithmetic first and proves second, or it pays for a proof the chain
//! refuses with `PayloadUnderpaid`.

use crate::metadata::ChainMetadata;

/// The per-slot floor: `MinLeafFee + ceil(ciphertext bytes / the byte bucket)`.
pub fn slot_fee_floor(metadata: &ChainMetadata, ct_1_len: usize, ct_2_len: usize) -> u64 {
    let bytes = ct_1_len as u64 + ct_2_len as u64;
    metadata
        .min_leaf_fee
        .saturating_add(bytes.div_ceil(bytes_per_fee_quantum(metadata)))
}

/// The divisor, clamped the way the pallet clamps it.
///
/// `pallet_shielded::bytes_per_fee_quantum` is
/// `u64::from(T::CiphertextBytesPerFeeQuantum::get().max(1))`, and the clamp is
/// what keeps a misconfigured runtime from dividing by zero on a live block.
/// The value reaches the wallet from `state_getMetadata` on whatever endpoint
/// `--node` names, so a node that declares it as zero would panic the wallet
/// inside the fee arithmetic, before any error path runs.
fn bytes_per_fee_quantum(metadata: &ChainMetadata) -> u64 {
    u64::from(metadata.ciphertext_bytes_per_fee_quantum.max(1))
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
        .saturating_add(carried_bytes.div_ceil(bytes_per_fee_quantum(metadata)))
}

/// A ciphertext that exceeds `MaxCiphertextBytes` fails the extrinsic's SCALE
/// decode, after the proof committing to those exact bytes exists. So the
/// check happens before proving.
///
/// The message names the pad. Every memo this wallet writes is padded to
/// `memo::MEMO_BYTES`, so a ciphertext is a fixed
/// `CIPHERTEXT_FIXED_BYTES + MEMO_BYTES` whatever the memo says and shortening
/// one moves nothing. Telling an operator to shorten a memo here would send
/// them after a length that cannot reach this branch.
pub fn ensure_ciphertext_fits(
    metadata: &ChainMetadata,
    len: usize,
    what: &str,
) -> anyhow::Result<()> {
    if len > metadata.max_ciphertext_bytes as usize {
        anyhow::bail!(
            "the {what} ciphertext is {len} bytes and this runtime caps one at {}. Every memo is \
             padded to memo::MEMO_BYTES ({}), so a ciphertext is a fixed size and shortening the \
             memo will not move it: the pad is what has to come down. The extrinsic would fail to \
             decode after the proof committing to those bytes was built.",
            metadata.max_ciphertext_bytes,
            crate::memo::MEMO_BYTES
        );
    }
    Ok(())
}

/// Check the compiled-in memo pad against the runtime's own ciphertext bound.
///
/// `crate::metadata` states the rule this closes: no chain value gets a
/// compiled-in copy, because a pinned constant is a wallet that builds a proof
/// against the wrong rule and finds out after paying for it. `MEMO_BYTES` is a
/// derivative of the chain's own ciphertext length and it is pinned at compile
/// time, so the two are compared here, once per command, beside
/// `ChainMetadata::ensure_known_storage`.
///
/// Without the comparison a runtime that lowered `ShieldedMaxCiphertextBytes`
/// anywhere into `[CIPHERTEXT_FIXED_BYTES, CIPHERTEXT_FIXED_BYTES +
/// MEMO_BYTES)` would fail every send and every shield, memoless ones
/// included, and the only message the operator saw would be
/// `ensure_ciphertext_fits` telling them about a size no memo of theirs
/// controls.
///
/// The cap is what this checks, and it is all that is left to check. The pad
/// used to be decided by a second, tighter bound: it had to keep an honest
/// pair a fee bucket below a pair padded to `MaxCiphertextBytes`, because the
/// chain did not parse these bytes and nothing held a submission to a real
/// ciphertext shape. The exact-length settlement rule refuses that shape
/// outright, so the separation priced a state nobody can reach and the
/// machinery that reasoned about it is gone. What holds `MEMO_BYTES` now is
/// `qnero_circuit::profile::ensure_supported`, which the spend path runs
/// before anything else: a runtime carrying a different ciphertext length
/// carries a different profile, and strict equality refuses it there.
pub fn ensure_memo_pad_fits(metadata: &ChainMetadata) -> anyhow::Result<()> {
    let padded = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
    let cap = metadata.max_ciphertext_bytes as usize;
    if padded > cap {
        anyhow::bail!(
            "this wallet pads every memo to memo::MEMO_BYTES ({}), so each output ciphertext is \
             {padded} bytes, and this runtime caps one at {}. MEMO_BYTES is the constant that has \
             to shrink, to at most {}, and every wallet on the chain has to agree on the size or \
             the padding buys nothing.",
            crate::memo::MEMO_BYTES,
            metadata.max_ciphertext_bytes,
            cap.saturating_sub(crate::memo::CIPHERTEXT_FIXED_BYTES)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> ChainMetadata {
        ChainMetadata {
            protocol_profile: qnero_circuit::profile::SUPPORTED_PROFILE,
            shielded_pallet_index: 24,
            submit_private_batch: 0,
            submit_public_batch: 1,
            shield: 2,
            block_hash_window: 256,
            min_leaf_fee: 1,
            ciphertext_bytes_per_fee_quantum: 512,
            max_ciphertext_bytes: 2048,
            signed_extensions: Vec::new(),
            extrinsic_version: 4,
            storage: Vec::new(),
        }
    }

    /// The figure `docs/CIRCUIT.md` section 9.7 pins: the padded pair a
    /// settlement may carry, 3584 bytes, pays eight steps of fee, one flat plus
    /// seven of payload.
    ///
    /// The second endpoint this used to pin, a pair padded to the cap at nine
    /// steps, is not a price any more. The exact-length settlement rule refuses
    /// that pair, and `a_pair_padded_to_the_cap_is_refused_not_priced` in the
    /// pallet is where it now lands. The arithmetic below is still the general
    /// floor, because the payload term still prices a skipped position's
    /// carried bytes.
    #[test]
    fn the_slot_floor_matches_the_documented_endpoint() {
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        assert_eq!(sent, qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES);
        assert_eq!(slot_fee_floor(&runtime(), sent, sent), 8);
    }

    /// `MEMO_BYTES` is a compiled-in derivative of a metadata value, so the
    /// two are compared against the runtime the wallet is actually talking to.
    #[test]
    fn a_pad_the_runtime_cannot_take_is_refused_by_name() {
        let metadata = runtime();
        assert!(ensure_memo_pad_fits(&metadata).is_ok());

        // A runtime that lowered the cap to just above a memoless ciphertext:
        // the one-line change `ShieldedMaxCiphertextBytes`' own documentation
        // invites, since it reasons from the 1731-byte real ciphertext.
        let mut narrow = runtime();
        narrow.max_ciphertext_bytes = 1_780;
        let refused =
            ensure_memo_pad_fits(&narrow).expect_err("a padded ciphertext does not fit under 1780");
        let message = refused.to_string();
        assert!(message.contains("MEMO_BYTES"), "{message}");
        assert!(message.contains("1780"), "{message}");
        // The advice is the pad, because no memo length reaches this.
        assert!(!message.contains("Shorten"), "{message}");
    }
    /// A started bucket is a whole bucket.
    #[test]
    fn a_partial_bucket_of_payload_rounds_up() {
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
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        let slot = slot_fee_floor(&metadata, sent, sent);
        assert_eq!(submission_fee_floor(&metadata, 1, 2 * sent as u64), slot);
    }

    /// A node is free to answer whatever it likes for a constant, and a zero
    /// divisor would panic inside the fee arithmetic before any error path
    /// runs. The pallet clamps for the same reason.
    #[test]
    fn a_zero_divisor_does_not_panic_the_fee_arithmetic() {
        let mut metadata = runtime();
        metadata.ciphertext_bytes_per_fee_quantum = 0;
        assert_eq!(slot_fee_floor(&metadata, 1731, 1731), 1 + 3462);
        assert_eq!(submission_fee_floor(&metadata, 1, 3462), 1 + 3462);
    }

    #[test]
    fn an_oversized_ciphertext_is_refused_before_proving() {
        let metadata = runtime();
        assert!(ensure_ciphertext_fits(&metadata, 2048, "payment").is_ok());
        assert!(ensure_ciphertext_fits(&metadata, 2049, "payment").is_err());
    }
}
