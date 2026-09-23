//! The fee floor, computed before the witness is built.
//!
//! The fee is a public input of the leaf proof, fixed at proving time and not
//! raisable afterwards (`docs/CIRCUIT.md` section 9.7). Both terms of the
//! floor are known before proving, because the ciphertext sizes are: a
//! `NoteCiphertext` is a fixed 1731 bytes plus the memo. So a wallet owes the
//! arithmetic first and proves second, or it pays for a proof the chain
//! refuses with `PayloadUnderpaid`.
//!
//! Both terms of the floor come from runtime metadata, which no state root
//! covers, and an overpaid fee is credited to the block author. So each one is
//! held inside a compiled-in bound before it prices anything:
//! [`ensure_fee_constants_are_sane`].

use crate::metadata::ChainMetadata;
use crate::units::qnr;

/// The widest `MinLeafFee` this wallet will price a spend against, in pool
/// steps.
///
/// The chain declares 1 (`chain/runtime/src/configs/mod.rs`), so this leaves a
/// runtime upgrade sixty-four times the room it uses today.
pub const MAX_TRUSTED_MIN_LEAF_FEE: u64 = 64;

/// The narrowest `CiphertextBytesPerFeeQuantum` this wallet will price a spend
/// against, in bytes.
///
/// The chain declares 512, so this leaves an upgrade room to make a byte of
/// payload eight times dearer.
pub const MIN_TRUSTED_BYTES_PER_FEE_QUANTUM: u32 = 64;

/// The widest fee this wallet pays for one slot, in pool steps.
pub const MAX_TRUSTED_SLOT_FEE: u64 = 256;

/// A fee at or under this is paid whatever the amount is, in pool steps.
///
/// An honest slot costs 8, and a payment may legitimately be smaller than a
/// few times that: `dev_node_e2e` sends 5. Below the allowance there is
/// nothing worth stopping a spend over.
pub const HIGH_FEE_ALLOWANCE: u64 = 16;

/// Above the allowance, a fee may take at most this share of the amount.
pub const HIGH_FEE_AMOUNT_SHARE: u64 = 2;

/// The bounds this wallet holds a runtime's fee constants inside.
///
/// `MinLeafFee` and `CiphertextBytesPerFeeQuantum` arrive in runtime metadata,
/// which is the node's own word: no state root covers it, so a node answers
/// what it likes. Those two decide the floor, a caller that names no `--fee`
/// pays exactly the floor, and the chain credits an overpayment to the block
/// author. A node that multiplied either constant by a thousand would be paid
/// a thousandfold, and `fee_runs_away` would not see it: that bound is
/// measured against the same floor.
///
/// The chain's real values price an honest settlement slot at 8 steps, and the
/// bounds above are wide multiples of each term, so a fee change the chain
/// makes on purpose is still taken and a fee change a node invents is refused
/// by name. A runtime that wanted more than these would ship with a wallet
/// that carries the new bound.
///
/// `wallet-web/src/wallet/fee.ts` holds the same three numbers.
pub fn ensure_fee_constants_are_sane(metadata: &ChainMetadata) -> anyhow::Result<()> {
    if metadata.min_leaf_fee > MAX_TRUSTED_MIN_LEAF_FEE {
        anyhow::bail!(
            "this node declares MinLeafFee as {} pool steps ({} QNR) and this wallet pays at \
             most {} ({} QNR). Runtime metadata is the node's own word, no state root covers \
             it, and the chain pays an overpaid fee to the block author. Nothing has been \
             built and nothing has been submitted.",
            metadata.min_leaf_fee,
            qnr(metadata.min_leaf_fee),
            MAX_TRUSTED_MIN_LEAF_FEE,
            qnr(MAX_TRUSTED_MIN_LEAF_FEE)
        );
    }
    if metadata.ciphertext_bytes_per_fee_quantum < MIN_TRUSTED_BYTES_PER_FEE_QUANTUM {
        anyhow::bail!(
            "this node declares CiphertextBytesPerFeeQuantum as {} bytes and this wallet prices \
             a spend against at least {MIN_TRUSTED_BYTES_PER_FEE_QUANTUM}. The divisor is what a \
             step of fee buys, so a small one is a large fee, and runtime metadata is the node's \
             own word. Nothing has been built and nothing has been submitted.",
            metadata.ciphertext_bytes_per_fee_quantum
        );
    }
    Ok(())
}

/// The fee this spend would pay, against the absolute per-slot ceiling.
pub fn ensure_fee_within_ceiling(fee: u64) -> anyhow::Result<()> {
    if fee > MAX_TRUSTED_SLOT_FEE {
        anyhow::bail!(
            "this spend would pay {} QNR for one slot and this wallet pays at most {} QNR. The \
             fee comes from constants the node declares and the chain credits an overpayment to \
             the block author. Nothing has been built and nothing has been submitted.",
            qnr(fee),
            qnr(MAX_TRUSTED_SLOT_FEE)
        );
    }
    Ok(())
}

/// The fee against the amount it is charged on.
///
/// The ceiling above bounds what a hostile node can take per spend; this
/// bounds what it can take out of a small payment. The allowance is what keeps
/// an honest floor from stopping a genuinely small one.
pub fn fee_outruns_amount(fee: u64, amount: u64) -> bool {
    fee > HIGH_FEE_ALLOWANCE && fee.saturating_mul(HIGH_FEE_AMOUNT_SHARE) > amount
}

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

    /// The bounds on what a node may charge.
    ///
    /// `MinLeafFee` and `CiphertextBytesPerFeeQuantum` come out of runtime
    /// metadata, which no state root covers, and a caller that names no
    /// `--fee` pays the floor those two compute. So an inflated constant is
    /// money handed to the block author, and every case here is a node that
    /// declared one. `wallet-web/tests/fee.test.ts` holds the counterparts.
    #[test]
    fn the_constants_the_chain_itself_declares_are_taken() {
        assert!(ensure_fee_constants_are_sane(&runtime()).is_ok());
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        assert!(ensure_fee_within_ceiling(slot_fee_floor(&runtime(), sent, sent)).is_ok());
    }

    #[test]
    fn an_inflated_min_leaf_fee_is_refused_by_name() {
        let mut greedy = runtime();
        greedy.min_leaf_fee = MAX_TRUSTED_MIN_LEAF_FEE + 1;
        let refused = ensure_fee_constants_are_sane(&greedy)
            .expect_err("a node may not price a slot at whatever it likes");
        assert!(refused.to_string().contains("MinLeafFee"), "{refused}");

        // The whole point: nothing else would have stopped it. The floor
        // these constants compute is the fee the wallet pays, because
        // `resolve_fee`'s `None` arm takes the floor unchanged.
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        assert_eq!(
            slot_fee_floor(&greedy, sent, sent),
            MAX_TRUSTED_MIN_LEAF_FEE + 8
        );

        // And a fee change the chain makes on purpose still sends.
        let mut at_the_bound = runtime();
        at_the_bound.min_leaf_fee = MAX_TRUSTED_MIN_LEAF_FEE;
        assert!(ensure_fee_constants_are_sane(&at_the_bound).is_ok());
    }

    #[test]
    fn a_divisor_small_enough_to_make_payload_dear_is_refused() {
        let mut greedy = runtime();
        greedy.ciphertext_bytes_per_fee_quantum = MIN_TRUSTED_BYTES_PER_FEE_QUANTUM - 1;
        let refused = ensure_fee_constants_are_sane(&greedy)
            .expect_err("a divisor below the bound prices a byte of payload too dearly");
        assert!(
            refused.to_string().contains("CiphertextBytesPerFeeQuantum"),
            "{refused}"
        );

        let mut at_the_bound = runtime();
        at_the_bound.ciphertext_bytes_per_fee_quantum = MIN_TRUSTED_BYTES_PER_FEE_QUANTUM;
        assert!(ensure_fee_constants_are_sane(&at_the_bound).is_ok());
    }

    /// A zero divisor is clamped to one inside the arithmetic, and the clamp
    /// alone would have paid 3463 steps for one slot. The bound refuses it.
    #[test]
    fn a_zero_divisor_is_refused_where_the_clamp_would_have_paid() {
        let mut broken = runtime();
        broken.ciphertext_bytes_per_fee_quantum = 0;
        assert!(ensure_fee_constants_are_sane(&broken).is_err());
    }

    #[test]
    fn a_slot_fee_over_the_absolute_ceiling_is_refused() {
        assert!(ensure_fee_within_ceiling(MAX_TRUSTED_SLOT_FEE).is_ok());
        assert!(ensure_fee_within_ceiling(MAX_TRUSTED_SLOT_FEE + 1).is_err());
    }

    #[test]
    fn a_fee_taking_more_than_half_the_amount_outruns_it() {
        let fee = HIGH_FEE_ALLOWANCE + 1;
        assert!(!fee_outruns_amount(fee, fee * 2));
        assert!(fee_outruns_amount(fee, fee * 2 - 1));
    }

    /// An honest slot costs eight steps, and `dev_node_e2e` sends five. The
    /// allowance is what keeps the share rule off a genuinely small payment.
    #[test]
    fn an_honest_floor_does_not_outrun_a_small_payment() {
        let sent = crate::memo::CIPHERTEXT_FIXED_BYTES + crate::memo::MEMO_BYTES;
        let floor = slot_fee_floor(&runtime(), sent, sent);
        assert!(floor <= HIGH_FEE_ALLOWANCE);
        assert!(!fee_outruns_amount(floor, 5));
    }

    #[test]
    fn an_oversized_ciphertext_is_refused_before_proving() {
        let metadata = runtime();
        assert!(ensure_ciphertext_fits(&metadata, 2048, "payment").is_ok());
        assert!(ensure_ciphertext_fits(&metadata, 2049, "payment").is_err());
    }
}
