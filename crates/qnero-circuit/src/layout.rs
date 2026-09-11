//! Public-input layout of the Qnero v0 spend leaf.
//!
//! This module is the single source of truth for where each public value sits
//! in a leaf proof. It has no dependencies so a verifier can read a proof's
//! public inputs without pulling in the prover stack.
//!
//! ```text
//! index  felts  value
//!   0..4    4   block_hash      Poseidon2 hash of the block header preimage
//!      4    1   block_number    height of that block
//!   5..9    4   nf_1            nullifier of input note 1
//!  9..13    4   nf_2            nullifier of input note 2
//! 13..17    4   cm_out_1        commitment of output note 1
//! 17..21    4   cm_out_2        commitment of output note 2
//!     21    1   fee             public fee, 62 bits
//! 22..26    4   ct_digest       digest of the output ciphertexts, bound by the chain
//! ```
//!
//! The order is positional: `SpendTargets::new` registers the targets in
//! exactly this order and `public_input_len_matches_layout` asserts the total
//! against the built circuit. Reordering two registrations silently shifts
//! every index downstream of the change, so change both together.

/// Felts in a 32-byte Poseidon2 digest.
pub const DIGEST_FELTS: usize = 4;

/// Input notes per leaf. Any of them may be a dummy.
pub const NUM_INPUTS: usize = 2;

/// Output notes per leaf. Always exactly this many, so the shape of a leaf
/// carries no information about how many real outputs a transfer had.
pub const NUM_OUTPUTS: usize = 2;

pub const BLOCK_HASH_START: usize = 0;
pub const BLOCK_NUMBER_INDEX: usize = BLOCK_HASH_START + DIGEST_FELTS;
pub const NULLIFIER_START: usize = BLOCK_NUMBER_INDEX + 1;
pub const COMMITMENT_START: usize = NULLIFIER_START + NUM_INPUTS * DIGEST_FELTS;
pub const FEE_INDEX: usize = COMMITMENT_START + NUM_OUTPUTS * DIGEST_FELTS;
pub const CT_DIGEST_START: usize = FEE_INDEX + 1;

/// Total public inputs of one leaf proof.
pub const PUBLIC_INPUT_LEN: usize = CT_DIGEST_START + DIGEST_FELTS;

/// First index of nullifier `i` (0-based).
pub const fn nullifier_index(i: usize) -> usize {
    NULLIFIER_START + i * DIGEST_FELTS
}

/// First index of output commitment `j` (0-based).
pub const fn commitment_index(j: usize) -> usize {
    COMMITMENT_START + j * DIGEST_FELTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_indices_are_the_documented_ones() {
        assert_eq!(BLOCK_HASH_START, 0);
        assert_eq!(BLOCK_NUMBER_INDEX, 4);
        assert_eq!(nullifier_index(0), 5);
        assert_eq!(nullifier_index(1), 9);
        assert_eq!(commitment_index(0), 13);
        assert_eq!(commitment_index(1), 17);
        assert_eq!(FEE_INDEX, 21);
        assert_eq!(CT_DIGEST_START, 22);
        assert_eq!(PUBLIC_INPUT_LEN, 26);
    }
}
