//! A zeroize-on-drop container for the spend credential.
//!
//! Forked from `qp-zk-circuits` `wormhole/circuit/src/sensitive.rs`, narrowed
//! to the one shape Qnero needs: a validated 32-byte [`Digest`].
//!
//! `ask` and `nk` are the two values that spend a note. Held as plain
//! `Digest`, which is `Copy`, every move duplicates them into a stack frame,
//! a log line or a crash dump that no drop-time scrub can reach. [`Secret`]
//! gives them three properties instead:
//!
//! - **Zeroized on drop**, through the [`zeroize`] crate, whose writes the
//!   optimizer may not elide. This crate is `#![forbid(unsafe_code)]`, so the
//!   volatile scrubbing lives in that vetted dependency.
//! - **No `Debug`**: a container holding one cannot derive `Debug`, which
//!   forces a redacting manual implementation.
//! - **Move-only** (no `Clone`, no `Copy`): the only way to duplicate the
//!   value is the explicitly named [`Secret::expose_digest`], so every copy is
//!   searchable and visible in review.
//!
//! Scope. This covers the copies Qnero owns. The copies plonky2 keeps inside
//! `PartialWitness` and `ProverCircuitData` during proving, and the transient
//! rate-aligned buffer `hash_no_pad` allocates for a sponge input, are not
//! reachable from here and would need upstream support to scrub.

use qnero_note_core::{Digest, NoteError};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A spend-credential digest, zeroized when it drops.
///
/// Construction validates the same invariant as [`Digest`] (every 8-byte limb
/// is a canonical Goldilocks element), so [`Secret::expose_digest`] rebuilds
/// the field-element form without re-deciding it.
///
/// Equality is constant time: comparing against an attacker-supplied candidate
/// must not leak the secret through timing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; Digest::LEN]);

impl PartialEq for Secret {
    /// Accumulate XOR differences over every byte with no data-dependent
    /// branch. [`core::hint::black_box`] on the accumulator keeps the
    /// optimizer from rewriting the loop into an early-exit compare.
    fn eq(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            difference = core::hint::black_box(difference | (a ^ b));
        }
        difference == 0
    }
}

impl Eq for Secret {}

impl Secret {
    /// Take ownership of a secret: validate it, move it in, and zeroize the
    /// caller's buffer so no copy is left behind at the call site.
    ///
    /// The source is scrubbed on the error path too: a non-canonical digest is
    /// useless to the caller, and leaving it readable would defeat the point.
    pub fn new(bytes: &mut [u8; Digest::LEN]) -> Result<Self, NoteError> {
        let validated = Digest::from_bytes(bytes).map(|_| Self(*bytes));
        bytes.zeroize();
        validated
    }

    /// Duplicate the secret as a `Copy` [`Digest`].
    ///
    /// The returned value escapes this container's zeroization, so keep it
    /// transient: write it into a witness and let it go out of scope. The
    /// deliberate name is what makes every such duplication greppable.
    pub fn expose_digest(&self) -> Digest {
        Digest::from_bytes(&self.0).expect("a Secret is validated at construction")
    }
}

/// For call sites that already hold the value as a `Copy` [`Digest`] (key
/// derivation, tests). This cannot scrub the caller's original, so a secret
/// that arrives as bytes should enter through [`Secret::new`] instead.
impl From<Digest> for Secret {
    fn from(digest: Digest) -> Self {
        Self(digest.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_round_trips_through_its_digest() {
        let digest = Digest::hash_bytes(&[b"sensitive/round-trip"]);
        assert_eq!(Secret::from(digest).expose_digest(), digest);
    }

    #[test]
    fn new_validates_and_scrubs_the_source() {
        let mut bytes = Digest::hash_bytes(&[b"sensitive/new"]).to_bytes();
        let expected = bytes;
        let secret = Secret::new(&mut bytes).unwrap();
        assert_eq!(secret.expose_digest().to_bytes(), expected);
        assert_eq!(bytes, [0u8; Digest::LEN]);
    }

    /// A limb at or above the Goldilocks modulus is not a digest. The source
    /// is scrubbed anyway, so a rejected secret leaves nothing readable.
    #[test]
    fn new_rejects_a_non_canonical_digest_and_still_scrubs() {
        const ORDER: u64 = 0xFFFF_FFFF_0000_0001;
        let mut bytes = [0u8; Digest::LEN];
        bytes[..8].copy_from_slice(&ORDER.to_le_bytes());
        assert!(Secret::new(&mut bytes).is_err());
        assert_eq!(bytes, [0u8; Digest::LEN]);
    }

    #[test]
    fn equality_compares_the_whole_value() {
        let a = Secret::from(Digest::hash_bytes(&[b"sensitive/a"]));
        let b = Secret::from(Digest::hash_bytes(&[b"sensitive/a"]));
        let c = Secret::from(Digest::hash_bytes(&[b"sensitive/c"]));
        assert!(a == b);
        assert!(a != c);
    }
}
