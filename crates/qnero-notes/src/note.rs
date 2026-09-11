//! Notes and their commitments.

use rand_core::{CryptoRng, RngCore};

use crate::digest::{domain, Digest, Felt};
use crate::error::NotesError;

/// Values are range-checked to 62 bits inside the circuit so that a sum of
/// four of them can never wrap the 64-bit Goldilocks field.
pub const VALUE_BITS: u32 = 62;
pub const MAX_VALUE: u64 = (1u64 << VALUE_BITS) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// Recipient's note receiving key.
    pub pk: Digest,
    /// Amount in the smallest unit.
    pub value: u64,
    /// Nullifier seed, unique per note.
    pub rho: Digest,
    /// Commitment randomness.
    pub r: Digest,
}

impl Note {
    pub fn new(pk: Digest, value: u64, rho: Digest, r: Digest) -> Result<Self, NotesError> {
        if value > MAX_VALUE {
            return Err(NotesError::ValueTooLarge(value));
        }
        Ok(Self { pk, value, rho, r })
    }

    /// Fresh `rho` and `r` from the RNG, hashed so they are canonical digests.
    pub fn random<R: RngCore + CryptoRng + ?Sized>(
        rng: &mut R,
        pk: Digest,
        value: u64,
    ) -> Result<Self, NotesError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let rho = Digest::hash_bytes(&[b"qnero/rho", &seed]);
        let r = Digest::hash_bytes(&[b"qnero/r", &seed]);
        Self::new(pk, value, rho, r)
    }

    /// `inner = H(NOTE, pk, rho, r)`. Hides everything except the value.
    pub fn inner(&self) -> Digest {
        note_inner(&self.pk, &self.rho, &self.r)
    }

    /// `cm = H(CM, inner, value)`. The leaf stored in the commitment tree.
    pub fn commitment(&self) -> Digest {
        commitment_from_inner(&self.inner(), self.value)
    }

    /// `nf = H(NF, nk, rho)`. Published when the note is spent.
    pub fn nullifier(&self, nk: &Digest) -> Digest {
        nullifier(nk, &self.rho)
    }
}

/// `inner = H(NOTE, pk, rho, r)`, on loose fields.
///
/// The free functions exist because the spend circuit's witness carries note
/// fields that have not been through [`Note::new`], including deliberately
/// out-of-range values a negative test feeds to the circuit's range checks.
/// [`Note`] is the checked constructor; these are the hash rules themselves.
pub fn note_inner(pk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NOTE, &[pk.felts(), rho.felts(), r.felts()])
}

/// `nf = H(NF, nk, rho)`, on loose fields.
pub fn nullifier(nk: &Digest, rho: &Digest) -> Digest {
    Digest::hash_felts(domain::NF, &[nk.felts(), rho.felts()])
}

/// Recompute a commitment from its public opening. Used by the chain for
/// coinbase notes, where `inner` and `value` are published and `pk` stays
/// hidden inside `inner`.
pub fn commitment_from_inner(inner: &Digest, value: u64) -> Digest {
    Digest::hash_felts(domain::CM, &[inner.felts(), &[Felt::new(value)]])
}

/// `rho = H(RHO, nf, index)`: the nullifier seed of output note `index` of a
/// spend whose first published nullifier is `nf`.
///
/// A sender does not choose an output's `rho`. The spend circuit derives it
/// from the nullifier it publishes for its first input, so that every note
/// the pool ever creates has a distinct `rho`: the chain refuses a nullifier
/// it has already seen, which makes `nf` unique over the life of the chain,
/// and `index` separates the two outputs of one spend.
///
/// A freely chosen `rho` is a griefing vector. `nf = H(NF, nk, rho)` depends
/// only on the recipient's key and `rho`, so a sender who pays the same
/// recipient twice with one `rho` creates two notes that share a nullifier,
/// of which the recipient can spend exactly one; the other is stranded for
/// good, at the cost of the smaller note.
pub fn output_rho(nf: &Digest, index: u64) -> Digest {
    Digest::hash_felts(domain::RHO, &[nf.felts(), &[Felt::new(index)]])
}
