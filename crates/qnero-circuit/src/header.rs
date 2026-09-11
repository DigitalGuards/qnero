//! The block header fragment.
//!
//! Forked from `qp-zk-circuits` `wormhole/circuit/src/block_header/`. The
//! preimage order and the digest-log encoding are the chain's, so a Qnero leaf
//! binds to a real Quantus-style header:
//!
//! ```text
//! block_hash = Poseidon2(parent_hash(4) || block_number(1) || state_root(4)
//!                        || extrinsics_root(4) || zk_tree_root(4) || digest(28))
//! ```
//!
//! Only `block_hash` and `block_number` are public. `zk_tree_root` stays
//! private and is what the input notes prove membership in: the public
//! `block_hash` commits to the header, the header commits to the root, and the
//! root is reached by hashing each note's Merkle path. That chain is what
//! makes a leaf unforgeable against a tree the chain never had.
//!
//! The four 32-byte fields are not decoded the same way, and the asymmetry is
//! the chain's. `parent_hash` is a previous block hash and `zk_tree_root` is a
//! Poseidon2 node hash, so both are four canonical Goldilocks limbs and take
//! the strict [`Digest`] decode. `state_root` and `extrinsics_root` are
//! Blake2-256 outputs, which are not field elements at all: roughly one header
//! in 500 million has a limb at or above the modulus. The chain hashes those
//! two through the reducing 8-bytes-per-felt decode, making `block_hash` a
//! lossy commitment to them, so this fragment takes them as raw bytes and
//! reduces them the same way. Validating them instead would leave a wallet
//! unable to prove any spend anchored at such a block, with an error naming a
//! hash the chain considers perfectly valid.

use anyhow::{ensure, Result};
use plonky2::field::types::Field as _;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::Hasher;
use qnero_notes::Digest;
use qp_poseidon_core::serialization::bytes_to_digest_lossy;

use crate::convert::{digest_from_felts, digest_to_felts};
use crate::{D, F};

/// Bytes of digest logs carried by a header.
pub const DIGEST_LOGS_SIZE: usize = 110;

/// 110 bytes at 4 bytes per field element plus a terminator.
pub const DIGEST_LOGS_FELTS: usize = 28;

#[derive(Debug, Clone)]
pub struct HeaderTargets {
    pub parent_hash: HashOutTarget,
    /// Registered as a public input by `SpendTargets::new`, held here so the
    /// preimage can be collected in one place.
    pub block_number: Target,
    pub state_root: HashOutTarget,
    pub extrinsics_root: HashOutTarget,
    /// Private. Bound to every input note's Merkle root.
    pub zk_tree_root: HashOutTarget,
    pub digest: [Target; DIGEST_LOGS_FELTS],
}

impl HeaderTargets {
    /// `block_number` is passed in because the public-input order is decided
    /// by `SpendTargets::new`; this fragment registers no public input of its
    /// own.
    pub fn new(builder: &mut CircuitBuilder<F, D>, block_number: Target) -> Self {
        Self {
            parent_hash: builder.add_virtual_hash(),
            block_number,
            state_root: builder.add_virtual_hash(),
            extrinsics_root: builder.add_virtual_hash(),
            zk_tree_root: builder.add_virtual_hash(),
            digest: core::array::from_fn(|_| builder.add_virtual_target()),
        }
    }

    /// The header preimage, in the chain's order.
    pub fn preimage(&self) -> Vec<Target> {
        let mut preimage = Vec::with_capacity(4 + 1 + 4 + 4 + 4 + DIGEST_LOGS_FELTS);
        preimage.extend_from_slice(&self.parent_hash.elements);
        preimage.push(self.block_number);
        preimage.extend_from_slice(&self.state_root.elements);
        preimage.extend_from_slice(&self.extrinsics_root.elements);
        preimage.extend_from_slice(&self.zk_tree_root.elements);
        preimage.extend_from_slice(&self.digest);
        preimage
    }
}

/// Witness values for one header.
#[derive(Clone)]
pub struct HeaderInputs {
    pub parent_hash: Digest,
    pub block_number: u32,
    /// Blake2-256, already reduced mod p by [`HeaderInputs::new`].
    pub state_root: Digest,
    /// Blake2-256, already reduced mod p by [`HeaderInputs::new`].
    pub extrinsics_root: Digest,
    pub zk_tree_root: Digest,
    pub digest: [F; DIGEST_LOGS_FELTS],
}

/// Redacting `Debug`: the digest logs are witness material that identify the
/// exact header preimage behind the public `block_hash`. Everything else here
/// is public chain data and stays visible for debugging a hash mismatch.
impl core::fmt::Debug for HeaderInputs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HeaderInputs")
            .field("parent_hash", &self.parent_hash)
            .field("block_number", &self.block_number)
            .field("state_root", &self.state_root)
            .field("extrinsics_root", &self.extrinsics_root)
            .field("zk_tree_root", &self.zk_tree_root)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

impl HeaderInputs {
    /// Build from a header's fields.
    ///
    /// `state_root` and `extrinsics_root` are taken as raw bytes and reduced
    /// mod p, because they are Blake2-256 outputs that need not be canonical;
    /// `parent_hash` and `zk_tree_root` are Poseidon2 outputs and are taken as
    /// validated digests. See the module docs for why the two halves differ.
    /// `digest_logs` is encoded the way the chain encodes it, 4 bytes per
    /// field element plus a terminator.
    pub fn new(
        parent_hash: Digest,
        block_number: u32,
        state_root: [u8; Digest::LEN],
        extrinsics_root: [u8; Digest::LEN],
        zk_tree_root: Digest,
        digest_logs: &[u8],
    ) -> Result<Self> {
        ensure!(
            digest_logs.len() == DIGEST_LOGS_SIZE,
            "header digest logs must be {} bytes, got {}",
            DIGEST_LOGS_SIZE,
            digest_logs.len()
        );
        let felts = qp_poseidon_core::serialization::bytes_to_felts(digest_logs);
        ensure!(
            felts.len() == DIGEST_LOGS_FELTS,
            "header digest logs encoded to {} field elements, expected {}",
            felts.len(),
            DIGEST_LOGS_FELTS
        );
        let digest = core::array::from_fn(|i| crate::convert::felt_to_plonky2(felts[i]));

        Ok(Self {
            parent_hash,
            block_number,
            state_root: Digest(bytes_to_digest_lossy(&state_root)),
            extrinsics_root: Digest(bytes_to_digest_lossy(&extrinsics_root)),
            zk_tree_root,
            digest,
        })
    }

    /// The header preimage, in the same order as [`HeaderTargets::preimage`].
    pub fn preimage(&self) -> Vec<F> {
        let mut preimage = Vec::with_capacity(4 + 1 + 4 + 4 + 4 + DIGEST_LOGS_FELTS);
        preimage.extend_from_slice(&digest_to_felts(&self.parent_hash));
        preimage.push(F::from_canonical_u32(self.block_number));
        preimage.extend_from_slice(&digest_to_felts(&self.state_root));
        preimage.extend_from_slice(&digest_to_felts(&self.extrinsics_root));
        preimage.extend_from_slice(&digest_to_felts(&self.zk_tree_root));
        preimage.extend_from_slice(&self.digest);
        preimage
    }

    /// `block_hash = Poseidon2(preimage)`, off circuit.
    pub fn block_hash(&self) -> Digest {
        let out = Poseidon2Hash::hash_no_pad(&self.preimage()).elements;
        digest_from_felts(&out)
    }
}

/// Constrain `block_hash == Poseidon2(header preimage)` and the block number's
/// width.
///
/// The binding is unconditional. Upstream makes it conditional on an
/// in-circuit dummy sentinel so a batch can be padded with dummy leaves; see
/// `docs/CIRCUIT.md` for how Qnero pads instead.
pub fn constrain_header(
    builder: &mut CircuitBuilder<F, D>,
    block_hash: HashOutTarget,
    header: &HeaderTargets,
) {
    builder.range_check(header.block_number, 32);
    let computed = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(header.preimage());
    builder.connect_hashes(block_hash, computed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;

    fn sample_header() -> HeaderInputs {
        HeaderInputs::new(
            Digest::hash_bytes(&[b"parent"]),
            42,
            Digest::hash_bytes(&[b"state"]).to_bytes(),
            Digest::hash_bytes(&[b"extrinsics"]).to_bytes(),
            Digest::hash_bytes(&[b"zk-tree"]),
            &[0xEE; DIGEST_LOGS_SIZE],
        )
        .unwrap()
    }

    /// The block hash against a fixed preimage, pinned as bytes.
    ///
    /// Everything else in this crate compares Qnero against Qnero: the
    /// in-circuit sponge against `Poseidon2Hash::hash_no_pad`, the header
    /// against itself. The chain computes this same value through
    /// `qp-poseidon-core`'s byte API over the same 45 field elements, so a
    /// change in either sponge or in the digest-log encoding would leave every
    /// test green while no leaf could bind to a real block. This is the vector
    /// that fails instead.
    #[test]
    fn the_block_hash_of_a_fixed_header_is_pinned() {
        let header = HeaderInputs::new(
            Digest::from_bytes(&[0x11; 32]).unwrap(),
            7,
            [0x22; 32],
            [0x33; 32],
            Digest::from_bytes(&[0x44; 32]).unwrap(),
            &[0x55; DIGEST_LOGS_SIZE],
        )
        .unwrap();
        assert_eq!(
            header.preimage().len(),
            4 + 1 + 4 + 4 + 4 + DIGEST_LOGS_FELTS
        );
        assert_eq!(
            header.block_hash().to_hex(),
            "5055010c6fc864a8da3afb365632f7ffe95264cfd83aa033a9a9fe8979688574"
        );
    }

    /// `state_root` and `extrinsics_root` are Blake2-256 outputs, which need
    /// not be canonical field elements. The chain reduces them mod p when it
    /// hashes a header, so this fragment must reduce them too: validating them
    /// would leave a wallet unable to prove any spend anchored at a block
    /// whose state root has a limb at or above the modulus, which is roughly
    /// one header in 500 million, with an error naming a hash the chain
    /// considers perfectly valid.
    #[test]
    fn the_blake2_roots_are_reduced_rather_than_validated() {
        const ORDER: u64 = 0xFFFF_FFFF_0000_0001;

        let mut aliased = [0u8; 32];
        aliased[..8].copy_from_slice(&(ORDER + 1).to_le_bytes());
        let mut reduced = [0u8; 32];
        reduced[..8].copy_from_slice(&1u64.to_le_bytes());

        let build = |state_root: [u8; 32]| {
            HeaderInputs::new(
                Digest::hash_bytes(&[b"parent"]),
                9,
                state_root,
                [0x33; 32],
                Digest::hash_bytes(&[b"zk-tree"]),
                &[0x55; DIGEST_LOGS_SIZE],
            )
            .unwrap()
        };

        assert_eq!(build(aliased).block_hash(), build(reduced).block_hash());
    }

    #[test]
    fn digest_logs_must_be_the_right_length() {
        assert!(HeaderInputs::new(
            Digest::hash_bytes(&[b"a"]),
            1,
            Digest::hash_bytes(&[b"b"]).to_bytes(),
            Digest::hash_bytes(&[b"c"]).to_bytes(),
            Digest::hash_bytes(&[b"d"]),
            &[0u8; DIGEST_LOGS_SIZE - 1],
        )
        .is_err());
    }

    #[test]
    fn block_hash_covers_the_whole_preimage() {
        let header = sample_header();
        let baseline = header.block_hash();

        let mut changed = header.clone();
        changed.zk_tree_root = Digest::hash_bytes(&[b"other-zk-tree"]);
        assert_ne!(changed.block_hash(), baseline);

        let mut changed = header.clone();
        changed.block_number += 1;
        assert_ne!(changed.block_hash(), baseline);
    }

    #[test]
    fn header_debug_redacts_the_digest_logs() {
        let header = sample_header();
        let dump = format!("{header:?}");
        for felt in header.digest.iter() {
            let value = felt.to_canonical_u64();
            if value > 0xFFFF {
                assert!(
                    !dump.contains(&value.to_string()),
                    "digest field element {value} leaked in Debug output"
                );
            }
        }
    }
}
