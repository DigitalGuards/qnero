//! The batch padding sentinel: the one header preimage a padding leaf binds
//! to, and the block hash it produces.
//!
//! A private batch aggregates a fixed number of leaf proofs. A wallet with
//! fewer real transfers than slots fills the rest with padding leaves, which
//! must be genuine proofs of this same leaf circuit (the batch bakes the leaf
//! verifier key in as constants), yet must consume no note and settle nothing.
//!
//! The rule, chosen at M3 from the two candidates in `docs/CIRCUIT.md` section
//! 8:
//!
//! **A padding leaf is a leaf whose `block_hash` is [`PADDING_BLOCK_HASH`],
//! the Poseidon2 hash of one fixed, publicly known header preimage.**
//!
//! What that buys, against Wormhole's all-zero-`block_hash` sentinel:
//!
//! - The header binding stays **unconditional**. A padding leaf hashes a real
//!   preimage like every other leaf, so nothing in the circuit has to be
//!   switched off, and no leaf can publish a `block_hash` it did not compute.
//!   Upstream has to make its binding conditional, because no preimage hashes
//!   to zero, and a conditional binding is a constraint an attacker wants
//!   switched on by the same bit that unlocks the padding path.
//! - The sentinel cannot be claimed by a leaf that also spends a note. The
//!   padding preimage carries the empty `zk_tree_root`, so a real input inside
//!   a padding leaf would have to hash a Merkle path to the all-zero digest,
//!   which is a preimage attack on Poseidon2. It is nevertheless not what
//!   keeps a padding slot from settling anything: the batch wrapper masks
//!   every value a padding slot publishes, trusting no invariant that crosses
//!   a circuit boundary.
//! - One sentinel serves all three layers. A padding leaf, an all-padding
//!   private batch and a padding inner of a public batch all carry this same
//!   block hash, so the chain has one rule to recognise padding by.
//!
//! The preimage is public by design. Its `parent_hash` is a domain-separated
//! Poseidon2 digest, which is outside the image of any chain's block hashing,
//! so no chain can ever produce a header equal to it; every other field is
//! zero, including the block number and the empty commitment-tree root.

/// Block number a padding leaf publishes.
pub const PADDING_BLOCK_NUMBER: u32 = 0;

/// `block_hash` of the padding header preimage, as four canonical Goldilocks
/// limbs. In the 32-byte little-endian-per-limb encoding that is
/// `34b4e468a910702ae5c6124a10a5ed2e2eea369e90faa8bb5244e83015939269`.
///
/// Pinned here, in a module that compiles without the circuit feature, so a
/// verifier and the chain can recognise a padding slot without the prover
/// stack. `padding_block_hash_is_the_hash_of_the_padding_header` recomputes it
/// from [`padding_header`] and fails if the two ever diverge.
pub const PADDING_BLOCK_HASH: [u64; 4] = [
    0x2a7010a968e4b434,
    0x2eeda5104a12c6e5,
    0xbba8fa909e36ea2e,
    0x6992931530e84452,
];

#[cfg(feature = "circuit")]
mod with_circuit {
    use anyhow::Result;
    use qnero_notes::Digest;

    use crate::header::{HeaderInputs, DIGEST_LOGS_SIZE};
    use crate::layout::{NUM_INPUTS, NUM_OUTPUTS};
    use crate::merkle::empty_digest;
    use crate::witness::{InputNote, OutputNote, SpendWitness};

    /// Domain separator of the padding header's `parent_hash`.
    ///
    /// A real header's `parent_hash` is the Poseidon2 hash of the previous
    /// header; this is the hash of a fixed ASCII string. Producing a chain
    /// whose header hashes to it is a preimage attack, so no real block can
    /// ever be the padding block.
    pub const PADDING_PARENT_HASH_DOMAIN: &[u8] = b"qnero/padding-header";

    /// Domain separators of the padding leaf's fixed witness values. None of
    /// them is secret: a padding leaf proves no membership and moves no value,
    /// so its witness carries nothing to hide, and a deterministic template
    /// can be built once and reused in every padding slot.
    pub const PADDING_ASK_DOMAIN: &[u8] = b"qnero/padding-ask";
    pub const PADDING_NK_DOMAIN: &[u8] = b"qnero/padding-nk";
    pub const PADDING_PK_DOMAIN: &[u8] = b"qnero/padding-pk";

    /// The one header preimage a padding leaf binds to.
    ///
    /// `zk_tree_root` is the empty digest, so the tree it names holds no note.
    /// `state_root` and `extrinsics_root` are zero, and so are the digest
    /// logs.
    pub fn padding_header() -> HeaderInputs {
        HeaderInputs::new(
            Digest::hash_bytes(&[PADDING_PARENT_HASH_DOMAIN]),
            super::PADDING_BLOCK_NUMBER,
            [0u8; Digest::LEN],
            [0u8; Digest::LEN],
            empty_digest(),
            &[0u8; DIGEST_LOGS_SIZE],
        )
        .expect("the padding header's digest logs are the documented length")
    }

    /// `block_hash` of [`padding_header`], recomputed.
    pub fn padding_block_hash() -> Digest {
        padding_header().block_hash()
    }

    /// The padding leaf's witness: both inputs dummy, both outputs worth zero,
    /// no fee.
    ///
    /// Deterministic, so the padding leaf proof is a reproducible artifact
    /// that a builder publishes once and a wallet clones into every empty
    /// slot. Nothing it publishes reaches the chain: the batch wrapper
    /// replaces a padding slot's nullifiers with hashes of fresh randomness
    /// and zeroes its commitments, fee and `ct_digest`, so cloning one
    /// template into many slots cannot collide.
    ///
    /// The two dummy inputs carry different `rho`, because the leaf requires
    /// its two published nullifiers to differ (constraint 5).
    pub fn padding_leaf_witness() -> SpendWitness {
        let ask = Digest::hash_bytes(&[PADDING_ASK_DOMAIN]);
        let nk = Digest::hash_bytes(&[PADDING_NK_DOMAIN]);
        let keys = qnero_notes::keys::DerivedKeys { ask, nk };
        let pk = Digest::hash_bytes(&[PADDING_PK_DOMAIN]);

        let depth = 1;
        let inputs: [InputNote; NUM_INPUTS] = core::array::from_fn(|index| {
            InputNote::dummy(
                &keys,
                Digest::hash_bytes(&[b"qnero/padding-rho", &[index as u8]]),
                Digest::hash_bytes(&[b"qnero/padding-r", &[index as u8]]),
                depth,
            )
        });
        let outputs: [OutputNote; NUM_OUTPUTS] = core::array::from_fn(|index| {
            OutputNote::new(
                pk,
                0,
                Digest::hash_bytes(&[b"qnero/padding-out-r", &[index as u8]]),
            )
        });

        SpendWitness {
            header: padding_header(),
            depth,
            inputs,
            outputs,
            fee: 0,
            ct_digest: empty_digest(),
        }
    }

    /// The padding leaf's witness, validated the way the prover validates any
    /// witness. Used by the artifact builder, which must not ship a template
    /// the leaf circuit would refuse.
    pub fn validated_padding_leaf_witness() -> Result<SpendWitness> {
        let witness = padding_leaf_witness();
        witness.validate()?;
        Ok(witness)
    }
}

#[cfg(feature = "circuit")]
pub use with_circuit::*;

#[cfg(feature = "circuit")]
mod gadget {
    use plonky2::field::types::Field as _;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::iop::target::BoolTarget;
    use plonky2::plonk::circuit_builder::CircuitBuilder;

    use crate::gadgets::digests_are_equal;
    use crate::{D, F};

    /// [`super::PADDING_BLOCK_HASH`] as circuit constants.
    pub fn padding_block_hash_target(builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        HashOutTarget {
            elements: core::array::from_fn(|i| {
                builder.constant(F::from_canonical_u64(super::PADDING_BLOCK_HASH[i]))
            }),
        }
    }

    /// `block_hash == PADDING_BLOCK_HASH`: the padding flag, derived in
    /// circuit from a public input and a constant. No witness feeds it.
    pub fn is_padding_block_hash(
        builder: &mut CircuitBuilder<F, D>,
        block_hash: HashOutTarget,
    ) -> BoolTarget {
        let sentinel = padding_block_hash_target(builder);
        digests_are_equal(builder, block_hash.elements, sentinel.elements)
    }
}

#[cfg(feature = "circuit")]
pub use gadget::{is_padding_block_hash, padding_block_hash_target};

#[cfg(all(test, feature = "circuit"))]
mod tests {
    use super::*;
    use qnero_notes::Digest;

    /// The pinned constant is what the padding header actually hashes to.
    ///
    /// [`PADDING_BLOCK_HASH`] is the sentinel every layer recognises padding
    /// by, and it is pinned as limbs in a module that cannot compute it. A
    /// change to the header preimage, to the digest-log encoding or to the
    /// sponge would otherwise leave every layer agreeing on a value no leaf
    /// can produce, and no padding leaf would prove.
    #[test]
    fn padding_block_hash_is_the_hash_of_the_padding_header() {
        let recomputed = padding_block_hash();
        let pinned: [u64; 4] = core::array::from_fn(|i| recomputed.felts()[i].as_canonical_u64());
        assert_eq!(
            pinned,
            PADDING_BLOCK_HASH,
            "PADDING_BLOCK_HASH is stale; the padding header now hashes to {}",
            recomputed.to_hex()
        );
    }

    /// The sentinel is a Poseidon2 output, so it is neither the all-zero
    /// digest Wormhole uses nor a value a real header reaches by accident.
    #[test]
    fn the_sentinel_is_not_the_zero_digest() {
        assert_ne!(PADDING_BLOCK_HASH, [0u64; 4]);
    }

    /// The padding leaf must be a witness the leaf circuit accepts, and it
    /// must carry no value at all: both inputs dummy, both outputs zero, no
    /// fee.
    #[test]
    fn the_padding_witness_is_valid_and_carries_no_value() {
        let witness = validated_padding_leaf_witness().expect("the padding witness validates");
        assert!(witness.inputs.iter().all(|input| input.is_dummy));
        assert!(witness.outputs.iter().all(|output| output.value == 0));
        assert_eq!(witness.fee, 0);
        assert_eq!(witness.header.block_hash(), padding_block_hash());
        assert_eq!(witness.ct_digest, crate::merkle::empty_digest());
    }

    /// Both dummy slots must publish different nullifiers, or the leaf's
    /// constraint 5 refuses the template.
    #[test]
    fn the_padding_leafs_two_nullifiers_differ() {
        let witness = padding_leaf_witness();
        assert_ne!(witness.inputs[0].nullifier(), witness.inputs[1].nullifier());
    }

    /// The padding header's `parent_hash` is a domain-separated digest, so it
    /// is not a block hash any chain produces.
    #[test]
    fn the_padding_parent_hash_is_domain_separated() {
        assert_eq!(
            padding_header().parent_hash,
            Digest::hash_bytes(&[PADDING_PARENT_HASH_DOMAIN])
        );
    }
}
