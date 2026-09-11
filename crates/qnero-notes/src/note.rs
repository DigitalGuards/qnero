//! Notes and their commitments.

use rand_core::{CryptoRng, RngCore};

use crate::digest::{domain, Digest, Felt};
use crate::error::NotesError;

/// Values are range-checked to 62 bits inside the circuit so that a sum of
/// four of them can never wrap the 64-bit Goldilocks field.
pub const VALUE_BITS: u32 = 62;
pub const MAX_VALUE: u64 = (1u64 << VALUE_BITS) - 1;

#[derive(Clone, PartialEq, Eq)]
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

/// Redacting `Debug`: every field of a note is linkable material. The leaf
/// publishes `nf = H(NF, nk, rho, r)` on chain, so anyone holding a log line
/// with `rho` and `r` beside a settled nullifier learns the amount and the
/// recipient key that nullifier belongs to. `InputNote`, `OutputNote` and the
/// prover types redact the same values; this is where they come from.
impl core::fmt::Debug for Note {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Note")
            .field("pk", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("rho", &"[REDACTED]")
            .field("r", &"[REDACTED]")
            .finish()
    }
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

    /// `nf = H(NF, nk, rho, r)`. Published when the note is spent.
    pub fn nullifier(&self, nk: &Digest) -> Digest {
        nullifier(nk, &self.rho, &self.r)
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

/// `nf = H(NF, nk, rho, r)`, on loose fields.
///
/// `r` is in the preimage so that `nk` alone is not a spend-linkability key
/// for the whole pool. An output's `rho` is a public function of the leaf that
/// created it (see [`output_rho`]), so the candidate `rho` set for the entire
/// chain is public data; were the nullifier a function of `(nk, rho)` only, a
/// holder of `nk` could hash every published pair against every leaf and
/// recover exactly which notes that wallet spent, with no viewing key and no
/// decryption. `r` is known only to the note's sender and holder, which is the
/// same role Orchard gives `psi`. It also means a leaked `nk` cannot be used
/// to compute a victim's nullifier from public data alone.
pub fn nullifier(nk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NF, &[nk.felts(), rho.felts(), r.felts()])
}

/// `nf = H(NF_DUMMY, nk, rho, r)`: the nullifier a padding input slot
/// publishes.
///
/// Same shape as [`nullifier`] under a different domain tag. A dummy slot
/// proves no membership and carries no `ask`, so whatever it publishes is
/// unauthenticated; the separate tag is what keeps that value out of the image
/// of the real nullifier function. Without it, a holder of a victim's `nk`
/// could put the victim's nullifier in a dummy slot of their own leaf and have
/// the chain settle it, which burns the victim's note permanently while
/// proving nothing about it.
pub fn dummy_nullifier(nk: &Digest, rho: &Digest, r: &Digest) -> Digest {
    Digest::hash_felts(domain::NF_DUMMY, &[nk.felts(), rho.felts(), r.felts()])
}

/// Recompute a commitment from its public opening. Used by the chain for
/// coinbase notes, where `inner` and `value` are published and `pk` stays
/// hidden inside `inner`.
pub fn commitment_from_inner(inner: &Digest, value: u64) -> Digest {
    Digest::hash_felts(domain::CM, &[inner.felts(), &[Felt::new(value)]])
}

/// `rho = H(RHO, nf_1, nf_2, index)`: the nullifier seed of output note
/// `index` of a spend that published `nf_1` and `nf_2`.
///
/// A sender does not choose an output's `rho`. The spend circuit derives it
/// from both nullifiers the leaf publishes, so that every note the pool ever
/// creates has a distinct `rho`, and `index` separates the two outputs of one
/// spend.
///
/// Both nullifiers are in the preimage because a leaf may carry its real
/// input in either slot. At least one input is real,
/// a real note's nullifier is settled exactly once over the life of the chain,
/// and the chain refuses a nullifier it has already seen, so the pair
/// `(nf_1, nf_2)` can never repeat no matter which slot holds the dummy.
/// Deriving from slot 0 alone would rest the whole uniqueness argument on a
/// prover-chosen value whenever slot 0 is the dummy.
///
/// A freely chosen `rho` is a griefing vector. `nf` depends on the recipient's
/// key, `rho` and `r`, and a sender picks all three for a note it creates, so
/// a sender who pays the same recipient twice with one `(rho, r)` creates two
/// notes that share a nullifier, of which the recipient can spend exactly one;
/// the other is stranded for good, at the cost of the smaller note.
pub fn output_rho(nf_1: &Digest, nf_2: &Digest, index: u64) -> Digest {
    Digest::hash_felts(
        domain::RHO,
        &[nf_1.felts(), nf_2.felts(), &[Felt::new(index)]],
    )
}
