//! 32-byte digests that are exactly four canonical Goldilocks field elements.

use qp_poseidon_core::serialization::{bytes_to_digest, digest_to_bytes};
use qp_poseidon_core::{hash_bytes, hash_to_felts, Goldilocks, POSEIDON2_OUTPUT};

use crate::error::NoteError;

pub type Felt = Goldilocks;

/// Four canonical Goldilocks limbs. Always constructed from a Poseidon output
/// or validated from bytes, so it can be fed straight into a circuit witness.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [Felt; POSEIDON2_OUTPUT]);

impl Digest {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, NoteError> {
        bytes_to_digest(bytes)
            .map(Digest)
            .map_err(|_| NoteError::NonCanonicalDigest)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, NoteError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| NoteError::NonCanonicalDigest)?;
        Self::from_bytes(&arr)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        digest_to_bytes(&self.0)
    }

    pub fn felts(&self) -> &[Felt; POSEIDON2_OUTPUT] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Poseidon2 over bytes (byte-mode sponge). Used for key derivation that
    /// never enters a circuit.
    pub fn hash_bytes(parts: &[&[u8]]) -> Self {
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(p);
        }
        let out = hash_bytes(&buf);
        Self::from_bytes(&out).expect("Poseidon output limbs are canonical")
    }

    /// Poseidon2 over field elements with a leading domain tag. This is the
    /// in-circuit hash: `hash_n_to_hash_no_pad` over the same input layout.
    pub fn hash_felts(domain: Felt, parts: &[&[Felt]]) -> Self {
        let mut input = Vec::with_capacity(1 + parts.iter().map(|p| p.len()).sum::<usize>());
        input.push(domain);
        for p in parts {
            input.extend_from_slice(p);
        }
        Digest(hash_to_felts(&input))
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

/// Domain tags. One felt each, first sponge input, one tag per rule.
pub mod domain {
    use super::Felt;
    pub const AK: Felt = Felt::new(0x716e_0001); // "qn" 0001
    pub const PK: Felt = Felt::new(0x716e_0002);
    pub const NOTE: Felt = Felt::new(0x716e_0003);
    pub const CM: Felt = Felt::new(0x716e_0004);
    pub const NF: Felt = Felt::new(0x716e_0005);
    /// Seed of an output note's `rho`. The circuit derives it from both
    /// nullifiers the leaf publishes, so two outputs can never carry the same
    /// `rho`.
    pub const RHO: Felt = Felt::new(0x716e_0006);
    /// Nullifier of a padding input slot. A dummy slot publishes a nullifier
    /// like a real one, so the public inputs do not show which slots were
    /// real, and this tag keeps that published value out of the image of the
    /// real nullifier function. Without it a dummy slot is an unauthenticated
    /// nullifier: anyone holding a victim's `nk` could publish the victim's
    /// nullifier from a slot that proves no membership and burn the note.
    pub const NF_DUMMY: Felt = Felt::new(0x716e_0007);
    /// Nullifier a padding slot of a private batch publishes. The batch
    /// wrapper hashes a fresh random preimage under this tag and emits the
    /// result in place of the padding leaf's own nullifiers, so the chain can
    /// settle every published nullifier of a segment by one rule. Its own tag
    /// keeps that prover-chosen value outside the image of both leaf
    /// nullifier functions: a padding slot must never be able to settle a
    /// nullifier that belongs to a note.
    ///
    /// This buys a fixed proof shape and a fixed public-input length. It does
    /// not hide the count: the wrapper zeroes a padding slot's commitment
    /// pair and no real slot's can be zero, so which slots were padding, and
    /// how many real transfers a batch carries, are public. Whether a chain
    /// settles a padding slot's nullifiers at all is an open decision,
    /// `docs/CIRCUIT.md` section 8.6.
    pub const NF_BATCH_PADDING: Felt = Felt::new(0x716e_0008);
    /// `rho` of a note created outside a spend proof: a shield at M4, a
    /// coinbase at M6.
    ///
    /// Inside a spend the circuit derives `rho_out_j = H(RHO, nf_1, nf_2, j)`
    /// from the nullifiers the leaf publishes, so a sender has no choice to
    /// abuse. An entry has no spent nullifier to derive from, so it takes a
    /// tag of its own over a unique on-chain identifier; [`super::entry_rho`]
    /// is the rule. It must not reuse `NF_BATCH_PADDING`, which is the value
    /// immediately below it: that would put a padding slot's emitted
    /// nullifier and an entry note's `rho` in one image.
    pub const RHO_ENTRY: Felt = Felt::new(0x716e_0009);
    /// `rho` of the coinbase note a block mints to its author.
    ///
    /// A coinbase is a note created outside a spend proof, like a shield, and
    /// it needs the same thing a shield needs: a `rho` fixed by a unique
    /// on-chain identifier, so that no two notes created this way share a
    /// nullifier seed. It does not reuse [`RHO_ENTRY`] because its identifier
    /// is a different tuple. A shield hashes `(block_number, entry_index)`
    /// and a coinbase hashes the block number alone, since a block mints
    /// exactly one coinbase; sharing the tag would put a coinbase of block
    /// `n` and a shield of block `n` at entry index `0` on one preimage, and
    /// [`super::coinbase_rho`] is the rule.
    pub const RHO_COINBASE: Felt = Felt::new(0x716e_000a);
    /// `r` of a coinbase note: the commitment randomness the block author's
    /// node derives from its coinbase viewing key and the block number.
    ///
    /// A coinbase note is the one note whose recipient is decided before the
    /// block exists, by an operator configuring a node, so it is derived rather
    /// than encrypted: `r = H(R_COINBASE, cvk, block_number)`, and a wallet
    /// holding `cvk` recomputes it for every block. Its own tag keeps that
    /// value out of the image of [`RHO_COINBASE`], which hashes the same block
    /// number, so a coinbase note's `rho` and its `r` can never be one value.
    pub const R_COINBASE: Felt = Felt::new(0x716e_000b);
}

#[cfg(test)]
mod tests {
    use super::domain;
    use super::Felt;

    /// Every domain tag names one rule. Two rules sharing a tag is a silent
    /// failure: the hashes still compute, the tests of each rule still pass,
    /// and what breaks is the separation between them. `NF` and
    /// `NF_BATCH_PADDING` colliding would let a padding slot of a private
    /// batch publish a real note's nullifier and burn it; `CM` and `NOTE`
    /// colliding would let a note's inner commitment be passed off as a
    /// commitment. So the list is checked as a list.
    #[test]
    fn domain_tags_are_pairwise_distinct() {
        let tags: [(&str, Felt); 11] = [
            ("AK", domain::AK),
            ("PK", domain::PK),
            ("NOTE", domain::NOTE),
            ("CM", domain::CM),
            ("NF", domain::NF),
            ("RHO", domain::RHO),
            ("NF_DUMMY", domain::NF_DUMMY),
            ("NF_BATCH_PADDING", domain::NF_BATCH_PADDING),
            ("RHO_ENTRY", domain::RHO_ENTRY),
            ("RHO_COINBASE", domain::RHO_COINBASE),
            ("R_COINBASE", domain::R_COINBASE),
        ];
        for (i, (name_a, a)) in tags.iter().enumerate() {
            for (name_b, b) in tags.iter().skip(i + 1) {
                assert_ne!(a, b, "domain tags {} and {} collide", name_a, name_b);
            }
        }
    }

    /// The tags are a contiguous block from `0x716e_0001`, and the next free
    /// value is what a new rule takes. A rule added on top of an existing
    /// value would pass the distinctness check above only by removing the one
    /// it displaced, so the range is pinned too.
    #[test]
    fn domain_tags_occupy_the_documented_range() {
        let expected: [(&str, u64); 11] = [
            ("AK", 0x716e_0001),
            ("PK", 0x716e_0002),
            ("NOTE", 0x716e_0003),
            ("CM", 0x716e_0004),
            ("NF", 0x716e_0005),
            ("RHO", 0x716e_0006),
            ("NF_DUMMY", 0x716e_0007),
            ("NF_BATCH_PADDING", 0x716e_0008),
            ("RHO_ENTRY", 0x716e_0009),
            ("RHO_COINBASE", 0x716e_000a),
            ("R_COINBASE", 0x716e_000b),
        ];
        let actual = [
            domain::AK,
            domain::PK,
            domain::NOTE,
            domain::CM,
            domain::NF,
            domain::RHO,
            domain::NF_DUMMY,
            domain::NF_BATCH_PADDING,
            domain::RHO_ENTRY,
            domain::RHO_COINBASE,
            domain::R_COINBASE,
        ];
        for ((name, want), got) in expected.iter().zip(actual.iter()) {
            assert_eq!(
                Felt::new(*want),
                *got,
                "domain tag {} moved off its documented value",
                name
            );
        }
    }
}
