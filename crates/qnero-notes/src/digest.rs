//! 32-byte digests that are exactly four canonical Goldilocks field elements.

use qp_poseidon_core::serialization::{bytes_to_digest, digest_to_bytes};
use qp_poseidon_core::{hash_bytes, hash_to_felts, Goldilocks, POSEIDON2_OUTPUT};

use crate::error::NotesError;

pub type Felt = Goldilocks;

/// Four canonical Goldilocks limbs. Always constructed from a Poseidon output
/// or validated from bytes, so it can be fed straight into a circuit witness.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest(pub [Felt; POSEIDON2_OUTPUT]);

impl Digest {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, NotesError> {
        bytes_to_digest(bytes)
            .map(Digest)
            .map_err(|_| NotesError::NonCanonicalDigest)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, NotesError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| NotesError::NonCanonicalDigest)?;
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

/// Domain tags. One felt each, first sponge input, never reused.
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
}
