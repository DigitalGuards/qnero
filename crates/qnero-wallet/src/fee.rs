//! The fee floor, computed before the witness is built.
//!
//! The fee is a public input of the leaf proof, fixed at proving time and not
//! raisable afterwards (`docs/CIRCUIT.md` section 9.7). Both terms of the
//! floor are known before proving, because the ciphertext sizes are: a
//! `NoteCiphertext` is a fixed 1731 bytes plus the memo. So a wallet owes the
//! arithmetic first and proves second, or it pays for a proof the chain
//! refuses with `PayloadUnderpaid`.

use std::sync::atomic::{AtomicBool, Ordering};

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
/// derivative of `MaxCiphertextBytes` and it is pinned at compile time, so the
/// two are compared here, once per command, beside
/// `ChainMetadata::ensure_known_storage`.
///
/// Without the comparison a runtime that lowered `ShieldedMaxCiphertextBytes`
/// anywhere into `[CIPHERTEXT_FIXED_BYTES, CIPHERTEXT_FIXED_BYTES +
/// MEMO_BYTES)` would fail every send and every shield, memoless ones
/// included, and the only message the operator saw would be
/// `ensure_ciphertext_fits` telling them about a size no memo of theirs
/// controls.
///
/// The cap is the looser of the two bounds, and it is the only one that is a
/// refusal. The tighter one is the fee, and it is a warning: see
/// [`memo_pad_separation_warning`].
///
/// `memo::MEMO_BYTES` is decided by two bounds and the tighter one wins. The
/// tighter one is the fee. A slot's payload term is
/// `ceil((len(ct_1) + len(ct_2)) / CiphertextBytesPerFeeQuantum)`, and the
/// runtime sizes that divisor so an honest pair and a pair padded to
/// `MaxCiphertextBytes` land in different buckets. The chain never parses
/// these bytes and `Shielded::Ciphertexts` is never pruned, so once the two
/// buckets merge a settler pads both ciphertexts to the cap, writes the extra
/// bytes of permanent state and pays exactly what an honest spend pays.
///
/// Checking only the cap left that open. A runtime that widened the divisor,
/// with the cap untouched, passed the guard while the separation the pad was
/// chosen for was gone, and neither this wallet's own fee test nor the
/// pallet's byte-floor test would have said so: each builds its own fixture
/// and pins 61 against that, so both stay green against any runtime at all.
/// Both values reach `ChainMetadata` from `state_getMetadata`, so the
/// comparison is against the runtime the wallet is actually talking to.
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
    if let Some(warning) = memo_pad_separation_warning(metadata) {
        warn_once(&warning);
    }
    Ok(())
}

/// Printed at most once per process.
///
/// The warning is a property of the runtime, so it is the same sentence on
/// every command; repeating it per send would train an operator to skip it.
static SEPARATION_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_once(warning: &str) {
    if !SEPARATION_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!("warning: {warning}");
    }
}

/// The fee-separation complaint, or `None` when this runtime separates the two
/// buckets.
///
/// A warning and not a refusal, which is the whole of this function. The
/// property is chain wide: the payload term prices nothing for *anyone* on a
/// runtime whose divisor swallowed the gap, and a settler who wants the free
/// permanent state pads to the cap whatever this wallet does. Refusing here
/// fixed none of that and stopped every send and every shield this wallet
/// makes, which is the one outcome that helps nobody: the operator cannot
/// change `CiphertextBytesPerFeeQuantum`, and the wallet shrinking its own pad
/// below what every other wallet on the chain uses would publish its own
/// ciphertext length, which is the leak the pad exists to close.
///
/// So the wallet says what the runtime did, keeps the pad every other wallet
/// on the chain uses, and sends.
pub fn memo_pad_separation_warning(metadata: &ChainMetadata) -> Option<String> {
    let padded = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
    let cap = metadata.max_ciphertext_bytes as usize;
    if slot_fee_floor(metadata, padded, padded) < slot_fee_floor(metadata, cap, cap) {
        return None;
    }
    let advice = match largest_separating_pad(metadata) {
        Some(pad) => format!(
            "a coordinated move of memo::MEMO_BYTES down to {pad} would restore it, and every \
             wallet on the chain has to make it together"
        ),
        None => format!(
            "no pad restores it under this runtime: even an unpadded pair of {} bytes each pays \
             what a pair padded to the cap pays, so the divisor is what has to come down",
            crate::memo::CIPHERTEXT_FIXED_BYTES
        ),
    };
    Some(format!(
        "this runtime's payload fee prices nothing. This wallet pads every memo to \
         memo::MEMO_BYTES ({}), so the pair of ciphertexts a spend publishes is {} bytes and \
         pays {} QNR of payload fee, and a pair padded to this runtime's cap of {cap} bytes \
         each pays {}. A settler can pad both outputs to the cap and write {} bytes of permanent \
         state per slot for what an honest spend pays. It is a property of the chain and not of \
         this spend, so the spend goes ahead. This runtime charges 0.01 QNR per {} ciphertext \
         bytes; {advice}.",
        crate::memo::MEMO_BYTES,
        2 * padded,
        crate::units::qnr(slot_fee_floor(metadata, padded, padded)),
        crate::units::qnr(slot_fee_floor(metadata, cap, cap)),
        2 * cap.saturating_sub(padded),
        bytes_per_fee_quantum(metadata)
    ))
}

/// The largest memo pad that keeps this wallet's own pair a fee bucket below a
/// pair padded to the runtime's cap, or `None` when no pad does.
///
/// A pair of `total` bytes pays `ceil(total / q)`. The cap's pair pays
/// `ceil(2 * cap / q)`, so the largest total strictly below that bucket is
/// `(ceil(2 * cap / q) - 1) * q`, and half of it less the fixed part of a
/// ciphertext is the pad. At the M4 runtime's 512 and 2048 that is
/// `(8 - 1) * 512 / 2 - 1731 = 61`, which is where `memo::MEMO_BYTES` comes
/// from.
pub fn largest_separating_pad(metadata: &ChainMetadata) -> Option<usize> {
    let quantum = bytes_per_fee_quantum(metadata);
    let cap = metadata.max_ciphertext_bytes as u64;
    let cap_bucket = cap.checked_mul(2)?.div_ceil(quantum);
    let largest_total = cap_bucket.checked_sub(1)?.checked_mul(quantum)?;
    let each = largest_total / 2;
    usize::try_from(each)
        .ok()?
        .checked_sub(crate::memo::CIPHERTEXT_FIXED_BYTES)
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

    /// The two figures `docs/CIRCUIT.md` section 9.7 pins: two real
    /// ciphertexts (3462 bytes) pay eight steps of fee, two padded to the cap (4096)
    /// pay nine.
    #[test]
    fn the_slot_floor_matches_the_documented_endpoints() {
        assert_eq!(
            slot_fee_floor(
                &runtime(),
                crate::memo::CIPHERTEXT_FIXED_BYTES,
                crate::memo::CIPHERTEXT_FIXED_BYTES
            ),
            8
        );
        assert_eq!(slot_fee_floor(&runtime(), 2048, 2048), 9);
    }

    /// The regression: the memo pad is chosen against the cap, and it has to
    /// be chosen against the divisor too.
    ///
    /// `ShieldedCiphertextBytesPerFeeQuantum` is sized so that a real pair and
    /// a pair padded to `MaxCiphertextBytes` fall in different buckets. The
    /// chain never parses these bytes and `Shielded::Ciphertexts` is never
    /// pruned, so if the two buckets merge a settler pads both ciphertexts to
    /// the cap, writes the extra bytes of permanent state and pays exactly
    /// what an honest spend pays. A 256-byte pad put this wallet's own pair at
    /// 3974 bytes, which shares a bucket with 4096, so every real spend on the
    /// chain sat at the merged endpoint while both trees stayed green: the
    /// pallet pins 1731 against the cap and 1731 is a size this wallet no
    /// longer sends.
    #[test]
    fn the_wallets_own_pair_stays_a_bucket_below_a_padded_one() {
        let metadata = runtime();
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        let cap = metadata.max_ciphertext_bytes as usize;
        assert!(
            slot_fee_floor(&metadata, sent, sent) < slot_fee_floor(&metadata, cap, cap),
            "a pair this wallet sends ({sent} bytes each) pays {} and a pair padded to the cap \
             ({cap} bytes each) pays {}: the payload term prices nothing",
            slot_fee_floor(&metadata, sent, sent),
            slot_fee_floor(&metadata, cap, cap)
        );
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
    /// The regression, and the correction on top of it.
    ///
    /// `memo.rs` states that two bounds decide `MEMO_BYTES` and the tighter
    /// one wins, and the tighter one is the fee: `2 * (1731 + 61) = 3584` has
    /// to sit a bucket below `2 * 2048 = 4096`. The guard compared
    /// `1731 + 61` against `MaxCiphertextBytes` and nothing else, so a runtime
    /// that widened `CiphertextBytesPerFeeQuantum` with the cap untouched
    /// passed it while the separation was gone, and a settler could again pad
    /// both outputs to the cap, write 512 bytes of permanent state per slot
    /// and pay what an honest spend pays.
    ///
    /// The correction is that it is a warning. The property is chain wide: a
    /// settler pads to the cap whatever this wallet does, so refusing stopped
    /// every send and every shield this wallet makes and fixed nothing. The
    /// wallet says what the runtime did and sends.
    ///
    /// Neither existing gate sees the merge: this module's own separation test
    /// and the pallet's byte-floor test each build a fixture and pin 61
    /// against that fixture, so both stay green against any runtime at all.
    /// This one is against `ChainMetadata`, which is what `state_getMetadata`
    /// fills in.
    #[test]
    fn a_runtime_whose_divisor_merges_the_fee_buckets_warns_and_still_sends() {
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;

        // The runtime the pad was tuned against: both bounds hold and there is
        // nothing to say.
        assert!(ensure_memo_pad_fits(&runtime()).is_ok());
        assert_eq!(memo_pad_separation_warning(&runtime()), None);

        // The divisor doubled, nothing else changed. The cap check still
        // passes, because 1792 is under 2048.
        let mut widened = runtime();
        widened.ciphertext_bytes_per_fee_quantum = 1_024;
        let cap = widened.max_ciphertext_bytes as usize;
        assert!(
            sent <= cap,
            "the cap check is not what is supposed to catch this"
        );
        assert_eq!(
            slot_fee_floor(&widened, sent, sent),
            slot_fee_floor(&widened, cap, cap),
            "the fixture has to be one where the buckets actually merge"
        );
        let message =
            memo_pad_separation_warning(&widened).expect("the merged buckets are reported");
        assert!(message.contains("prices nothing"), "{message}");
        assert!(message.contains("1024"), "{message}");
        // At 1024 bytes to the bucket against a 2048-byte cap, no pad at all
        // restores the separation: an unpadded pair is 3462 bytes and a capped
        // one 4096, and both are the fourth bucket.
        assert_eq!(largest_separating_pad(&widened), None);
        assert!(
            message.contains("the divisor is what has to come down"),
            "{message}"
        );
        // The spend goes ahead. A wallet that refused here could not send at
        // all on a chain whose runtime it does not control.
        assert!(
            ensure_memo_pad_fits(&widened).is_ok(),
            "a chain-wide property is not this spend's refusal"
        );

        // A runtime that widened the divisor by less still separates the two,
        // at a smaller pad, and the message names that pad rather than sending
        // an operator to guess. At 1160 bytes to the bucket a pair may reach
        // 3480 bytes, so each ciphertext may reach 1740 and the pad is 9.
        let mut slightly = runtime();
        slightly.ciphertext_bytes_per_fee_quantum = 1_160;
        assert_eq!(largest_separating_pad(&slightly), Some(9));
        let message = memo_pad_separation_warning(&slightly)
            .expect("61 does not separate under that divisor");
        assert!(message.contains("down to 9"), "{message}");
        assert!(ensure_memo_pad_fits(&slightly).is_ok());
    }

    /// Where `memo::MEMO_BYTES` comes from, computed rather than asserted.
    ///
    /// The pad is the largest that keeps this wallet's pair a fee bucket below
    /// a pair padded to the cap, and at the M4 runtime's 512-byte bucket and
    /// 2048-byte cap that is exactly 61.
    #[test]
    fn the_pad_is_the_largest_one_the_m4_runtime_separates() {
        assert_eq!(
            largest_separating_pad(&runtime()),
            Some(crate::memo::MEMO_BYTES)
        );
        let metadata = runtime();
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        let cap = metadata.max_ciphertext_bytes as usize;
        assert!(slot_fee_floor(&metadata, sent, sent) < slot_fee_floor(&metadata, cap, cap));
        // One byte more and the separation is gone, which is what "largest"
        // means.
        assert_eq!(
            slot_fee_floor(&metadata, sent + 1, sent + 1),
            slot_fee_floor(&metadata, cap, cap)
        );
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
