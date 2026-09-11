//! Public-input layout of the Qnero private and public batch proofs (M3).
//!
//! Like [`crate::layout`], this module has no dependencies, so a verifier
//! reads a batch proof's public inputs without the prover stack. The
//! aggregator writes these positions and `qnero-verifier` reads them.
//!
//! Private batch, `N` leaf slots:
//!
//! ```text
//! index          felts  value
//!   0..4           4    block_hash     shared by every non-padding slot
//!      4           1    block_number   height of that block
//!  then, for slot i in 0..N, at slot_start(i):
//!   +0..4          4    nf_1           nullifier of the leaf's input 1
//!   +4..8          4    nf_2           nullifier of the leaf's input 2
//!   +8..12         4    cm_1           commitment of the leaf's output 1
//!  +12..16         4    cm_2           commitment of the leaf's output 2
//!     +16          1    fee            that leaf's public fee
//!  +17..21         4    ct_digest      digest of that leaf's ciphertexts
//! ```
//!
//! Total: `5 + 21 * N` felts. There is no trailing padding: the length is a
//! function of `N` alone.
//!
//! Every field of a slot is forwarded from the leaf proof unchanged, except in
//! a padding slot, where the wrapper masks all six (see `docs/CIRCUIT.md`
//! section 8). Both nullifiers are carried: a wrapper that forwarded one per
//! leaf would drop every leaf's `nf_2`, and a note spent from input slot 1
//! would never be marked used.
//!
//! Public batch, `n_inner` private batches of `N` leaves each:
//!
//! ```text
//! index                       felts  value
//!   0..4                        4    aggregator_address
//!  then, for inner i, at public_batch_inner_start(i, N):
//!   the whole private-batch public-input vector above, unchanged
//! ```
//!
//! Total: `4 + n_inner * (5 + 21 * N)` felts. Forwarding is order preserving
//! and each inner owns one contiguous segment, so the chain can attribute a
//! settlement failure to one inner proof.
//!
//! A padding inner keeps the sentinel block hash and has its whole slot region
//! zeroed, so a chain must skip such a segment whole and must never settle a
//! zero nullifier: every padding segment of every batch publishes the same
//! `2N` all-zero values, and settling them rejects the next padding segment as
//! a double spend. `qnero_verifier::PrivateBatchPublicInputs::is_padding` is
//! that test and `PublicBatchPublicInputs::settleable_batches` applies it. See
//! `docs/CIRCUIT.md` section 8.6 for the whole settlement contract.

/// Felts in a 32-byte Poseidon2 digest.
pub const DIGEST_FELTS: usize = 4;

/// Largest supported proof count per aggregation layer.
///
/// The work of building either batch circuit grows with the count (one
/// recursive verifier per slot, plus a quadratic nullifier-distinctness loop
/// at the private batch), so every entry point that takes a count from outside
/// bounds it before allocating or computing a layout offset.
pub const MAX_PROOF_COUNT: usize = 64;

// --- private batch ---

pub const BLOCK_HASH_START: usize = 0;
pub const BLOCK_NUMBER_INDEX: usize = BLOCK_HASH_START + DIGEST_FELTS;

/// Felts before the first leaf slot.
pub const HEADER_LEN: usize = BLOCK_NUMBER_INDEX + 1;

/// Offsets inside one leaf slot.
pub const SLOT_NULLIFIER_START: usize = 0;
pub const SLOT_COMMITMENT_START: usize = SLOT_NULLIFIER_START + 2 * DIGEST_FELTS;
pub const SLOT_FEE_INDEX: usize = SLOT_COMMITMENT_START + 2 * DIGEST_FELTS;
pub const SLOT_CT_DIGEST_START: usize = SLOT_FEE_INDEX + 1;

/// Felts per leaf slot.
pub const SLOT_LEN: usize = SLOT_CT_DIGEST_START + DIGEST_FELTS;

/// First index of leaf slot `i` in a private-batch public-input vector.
pub const fn slot_start(slot: usize) -> usize {
    HEADER_LEN + slot * SLOT_LEN
}

/// First index of nullifier `i` (0-based) of leaf slot `slot`.
pub const fn slot_nullifier_index(slot: usize, i: usize) -> usize {
    slot_start(slot) + SLOT_NULLIFIER_START + i * DIGEST_FELTS
}

/// First index of output commitment `j` (0-based) of leaf slot `slot`.
pub const fn slot_commitment_index(slot: usize, j: usize) -> usize {
    slot_start(slot) + SLOT_COMMITMENT_START + j * DIGEST_FELTS
}

/// Index of leaf slot `slot`'s fee.
pub const fn slot_fee_index(slot: usize) -> usize {
    slot_start(slot) + SLOT_FEE_INDEX
}

/// First index of leaf slot `slot`'s `ct_digest`.
pub const fn slot_ct_digest_index(slot: usize) -> usize {
    slot_start(slot) + SLOT_CT_DIGEST_START
}

/// Public inputs of a private-batch proof over `num_leaves` slots.
///
/// Unchecked arithmetic, like the rest of this module's `num_leaves`
/// helpers. Call [`validate_proof_count`] on any count that came from outside
/// before reaching these: an astronomical value wraps in a release build.
pub const fn private_batch_pi_len(num_leaves: usize) -> usize {
    HEADER_LEN + num_leaves * SLOT_LEN
}

// --- public batch ---

pub const AGGREGATOR_ADDRESS_LEN: usize = DIGEST_FELTS;
pub const AGGREGATOR_ADDRESS_START: usize = 0;

/// Felts before the first forwarded private batch.
pub const PUBLIC_BATCH_HEADER_LEN: usize = AGGREGATOR_ADDRESS_START + AGGREGATOR_ADDRESS_LEN;

/// First index of inner private batch `inner` in a public-batch public-input
/// vector, for a private batch of `num_leaves` slots.
pub const fn public_batch_inner_start(inner: usize, num_leaves: usize) -> usize {
    PUBLIC_BATCH_HEADER_LEN + inner * private_batch_pi_len(num_leaves)
}

/// Public inputs of a public-batch proof over `n_inner` private batches of
/// `num_leaves` slots each.
pub const fn public_batch_pi_len(n_inner: usize, num_leaves: usize) -> usize {
    PUBLIC_BATCH_HEADER_LEN + n_inner * private_batch_pi_len(num_leaves)
}

/// `true` when `count` is a supported per-layer proof count.
///
/// The checked front door for the helpers above. Callers that want an error
/// message wrap this; the constant-arithmetic helpers assume it already
/// returned `true`.
pub const fn validate_proof_count(count: usize) -> bool {
    count > 0 && count <= MAX_PROOF_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_offsets_are_the_documented_ones() {
        assert_eq!(BLOCK_HASH_START, 0);
        assert_eq!(BLOCK_NUMBER_INDEX, 4);
        assert_eq!(HEADER_LEN, 5);
        assert_eq!(SLOT_NULLIFIER_START, 0);
        assert_eq!(SLOT_COMMITMENT_START, 8);
        assert_eq!(SLOT_FEE_INDEX, 16);
        assert_eq!(SLOT_CT_DIGEST_START, 17);
        assert_eq!(SLOT_LEN, 21);
    }

    #[test]
    fn private_batch_indices_are_contiguous() {
        assert_eq!(slot_start(0), 5);
        assert_eq!(slot_start(1), 26);
        assert_eq!(slot_nullifier_index(1, 0), 26);
        assert_eq!(slot_nullifier_index(1, 1), 30);
        assert_eq!(slot_commitment_index(1, 0), 34);
        assert_eq!(slot_commitment_index(1, 1), 38);
        assert_eq!(slot_fee_index(1), 42);
        assert_eq!(slot_ct_digest_index(1), 43);
        assert_eq!(slot_start(2), 47);
        assert_eq!(private_batch_pi_len(7), 5 + 7 * 21);
        assert_eq!(private_batch_pi_len(7), 152);
    }

    #[test]
    fn public_batch_indices_are_contiguous() {
        assert_eq!(public_batch_inner_start(0, 7), 4);
        assert_eq!(public_batch_inner_start(1, 7), 4 + 152);
        assert_eq!(public_batch_pi_len(2, 7), 4 + 2 * 152);
    }

    #[test]
    fn proof_counts_outside_the_supported_range_are_rejected() {
        assert!(!validate_proof_count(0));
        assert!(validate_proof_count(1));
        assert!(validate_proof_count(MAX_PROOF_COUNT));
        assert!(!validate_proof_count(MAX_PROOF_COUNT + 1));
    }
}
