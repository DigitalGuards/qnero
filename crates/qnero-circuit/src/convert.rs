//! Conversions between `qnero-notes` field elements and plonky2 field
//! elements.
//!
//! `qnero-notes` hashes with `qp-poseidon-core`, whose `Goldilocks` is a
//! distinct type from plonky2's `GoldilocksField` even though both are the
//! same prime field. Everything crossing that boundary goes through here, by
//! canonical `u64`, so a silent reinterpretation is impossible.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use qnero_notes::{Digest, Felt as NoteFelt};

use crate::F;

/// One field element, by canonical value.
pub fn felt_to_plonky2(felt: NoteFelt) -> F {
    F::from_canonical_u64(felt.as_canonical_u64())
}

/// One field element, back.
pub fn felt_from_plonky2(felt: F) -> NoteFelt {
    use plonky2::field::types::PrimeField64;
    NoteFelt::new(felt.to_canonical_u64())
}

/// A 32-byte digest as four plonky2 field elements.
pub fn digest_to_felts(digest: &Digest) -> [F; 4] {
    core::array::from_fn(|i| felt_to_plonky2(digest.felts()[i]))
}

/// A 32-byte digest as a plonky2 `HashOut`.
pub fn digest_to_hashout(digest: &Digest) -> HashOut<F> {
    HashOut {
        elements: digest_to_felts(digest),
    }
}

/// Four plonky2 field elements back into a digest.
pub fn digest_from_felts(felts: &[F; 4]) -> Digest {
    Digest(core::array::from_fn(|i| felt_from_plonky2(felts[i])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_round_trip() {
        let digest = Digest::hash_bytes(&[b"convert/round-trip"]);
        assert_eq!(digest_from_felts(&digest_to_felts(&digest)), digest);
    }
}
