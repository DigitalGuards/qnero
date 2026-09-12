//! The rules a chain evaluates natively, outside any circuit.
//!
//! Everything here compiles without the `circuit` feature, so `pallet-shielded`
//! reaches it through `qnero-verifier` on a wasm runtime without the prover
//! stack, the note primitives or plonky2. [`padding`](crate::padding) carries
//! the padding sentinel for the same reason.
//!
//! Two rules live here, and both are rules the circuit deliberately does not
//! enforce:
//!
//! - [`ct_digest`], which binds a leaf's output ciphertexts to its proof. The
//!   circuit treats `ct_digest` as a free public input, so the comparison the
//!   chain makes is the whole binding.
//! - [`commitment`], the outer half of the note commitment. A note created
//!   outside a spend proof, a shield at M4 and a coinbase at M6, has no
//!   circuit to compute its `cm`, so the chain computes it from a public value
//!   and an opaque `inner`. The `rho` such a note carries is a wallet's rule,
//!   `qnero_note_core::entry_rho`, over an identifier the chain publishes and
//!   never hashes.
//!
//! This is the single definition of both. A wallet calls the same functions,
//! so the two sides cannot drift.

use alloc::vec::Vec;

use qp_poseidon_core::serialization::bytes_to_digest;
use qp_poseidon_core::{hash_bytes, hash_to_bytes, Goldilocks};

/// Domain tags, one felt each, first sponge input, one tag per rule. These
/// mirror `qnero_note_core::digest::domain`, which is the wallet-side copy;
/// `domain_tags_match_qnero_notes` in this crate's tests asserts the two
/// agree.
pub mod domain {
    /// `cm = H(CM, inner, value)`.
    ///
    /// The only tag the chain evaluates. Every other rule in the note
    /// primitives is a wallet's, `RHO_ENTRY` included: a recipient uses that
    /// one to recompute the `rho` of a note created outside a spend proof
    /// (`qnero_note_core::entry_rho`), and the chain publishes the identifier the
    /// rule hashes without ever hashing it itself.
    pub const CM: u64 = 0x716e_0004;
}

/// Maximum commitment-tree depth the spend circuit can prove.
///
/// A depth-16 4-ary tree holds 4^16, about 4.3 billion, commitments. The
/// circuit pays for all sixteen levels on every proof regardless of the tree's
/// real depth, so raising it costs every prover, and changing it at all is a
/// coordinated release of new circuit crates plus a runtime upgrade carrying
/// the regenerated verifier.
///
/// It lives here, in the layout-only surface, because it is a value the chain
/// has to agree on and `pallet-zk-tree` links no prover stack:
/// `CIRCUIT_MAX_TREE_DEPTH` there must equal this, and `pallet-shielded`
/// const-asserts the two. [`crate::merkle::MAX_DEPTH`] is this same constant
/// under the name the circuit code uses.
pub const MAX_TREE_DEPTH: usize = 16;

/// Bits a note value is range checked to.
///
/// The balance equation in the spend circuit is a field equation, and its
/// no-wrap argument holds only while every term is below `2^62`: two inputs sum
/// below `2^63` and two outputs plus a fee below `3 * 2^62`, both under the
/// Goldilocks modulus. Every path that creates a note carries the bound, a
/// shield and a coinbase included, so this is a consensus rule and not a
/// wallet-side convention.
pub const VALUE_BITS: u32 = 62;

/// Largest value a note may carry.
pub const MAX_VALUE: u64 = (1u64 << VALUE_BITS) - 1;

/// Domain prefix of the ciphertext digest.
///
/// Byte-mode hashing uses an ASCII prefix where field-mode hashing uses a
/// one-felt tag. `ct_digest` is never recomputed inside a circuit, so it stays
/// on the byte-mode sponge.
pub const CT_DIGEST_PREFIX: &[u8] = b"qnero/ct";

/// `ct_digest`: the leaf public input that binds a spend proof to the
/// ciphertexts submitted with it.
///
/// ```text
/// ct_digest = H_bytes("qnero/ct" || u32_le(count)
///                     || u32_le(len_1) || ct_1 || ... || u32_le(len_n) || ct_n)
/// ```
///
/// `ct_i` is one output's ciphertext bytes, in output order, so `ct_1` belongs
/// to `cm_out_1`.
///
/// The circuit treats `ct_digest` as a free public input: hashing kilobytes of
/// ML-KEM and AEAD ciphertext in circuit would dominate the proof, so the
/// chain recomputes this digest from the bytes it was handed and compares.
/// That comparison binds the ciphertexts only while the rule is unambiguous,
/// which is what the count and the per-ciphertext length prefixes are for. A
/// bare concatenation would let two different output pairs share a preimage,
/// and a relayer could then swap the ciphertexts attached to a settled leaf
/// for a colliding pair, pass the comparison, and leave the recipient unable
/// to decrypt a note whose commitment is already in the tree.
///
/// Both sides call this. A wallet computes it over the ciphertexts it is about
/// to submit; `pallet-shielded` recomputes it over the ciphertexts in the
/// extrinsic, in the same order, and rejects the leaf when they differ.
pub fn ct_digest(ciphertexts: &[&[u8]]) -> [u8; 32] {
    let total: usize =
        4 + CT_DIGEST_PREFIX.len() + ciphertexts.iter().map(|ct| 4 + ct.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(CT_DIGEST_PREFIX);
    buf.extend_from_slice(&(ciphertexts.len() as u32).to_le_bytes());
    for ct in ciphertexts {
        buf.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        buf.extend_from_slice(ct);
    }
    hash_bytes(&buf)
}

/// `cm = H(CM, inner, value)`, the outer half of the two-layer note
/// commitment.
///
/// `inner = H(NOTE, pk, rho, r)` stays opaque to the chain, which is what
/// keeps a shielded note's recipient and randomness private while its value is
/// public. Returns `None` when `inner` is not four canonical Goldilocks limbs:
/// the 8-bytes-per-felt decode reduces mod p, so a non-canonical alias would
/// otherwise commit to the same note as a genuine `inner`.
///
/// `value` enters as a single field element over its full 62-bit range, which
/// is the leaf circuit's encoding. The caller owns the range check: the
/// no-wrap argument behind the circuit's balance equation holds only while
/// every value in the pool is below `2^62`, and this function does not know
/// whether its caller is a spend.
pub fn commitment(inner: &[u8; 32], value: u64) -> Option<[u8; 32]> {
    let inner_felts = bytes_to_digest(inner).ok()?;
    let mut preimage = [Goldilocks::ZERO; 6];
    preimage[0] = Goldilocks::new(domain::CM);
    preimage[1..5].copy_from_slice(&inner_felts);
    preimage[5] = Goldilocks::from_u64(value);
    Some(hash_to_bytes(&preimage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_digest_is_injective_in_the_count_and_the_lengths() {
        let a: &[u8] = b"first ciphertext";
        let b: &[u8] = b"second";
        let base = ct_digest(&[a, b]);
        assert_eq!(base, ct_digest(&[a, b]));
        // Order is the binding to output order.
        assert_ne!(base, ct_digest(&[b, a]));
        // The count prefix separates a shorter list.
        assert_ne!(base, ct_digest(&[a]));
        assert_ne!(base, ct_digest(&[]));
        // The length prefixes stop a boundary from moving. Without them these
        // two share a preimage.
        assert_ne!(ct_digest(&[b"ab", b"c"]), ct_digest(&[b"a", b"bc"]));
    }

    #[test]
    fn commitment_refuses_a_non_canonical_inner() {
        let canonical = [0u8; 32];
        assert!(commitment(&canonical, 7).is_some());
        let mut alias = [0u8; 32];
        // p = 2^64 - 2^32 + 1 in the first limb: an alias of zero under the
        // reducing decode.
        alias[..8].copy_from_slice(&qp_poseidon_core::goldilocks::P.to_le_bytes());
        assert!(commitment(&alias, 7).is_none());
    }

    #[test]
    fn commitment_binds_the_value() {
        let inner = [1u8; 32];
        assert_ne!(
            commitment(&inner, 1).expect("canonical"),
            commitment(&inner, 2).expect("canonical")
        );
    }

    #[test]
    #[cfg(feature = "circuit")]
    fn the_value_bound_matches_the_note_primitives() {
        assert_eq!(MAX_VALUE, qnero_note_core::MAX_VALUE);
        assert_eq!(VALUE_BITS, qnero_note_core::VALUE_BITS);
    }

    /// `chain` restates `CM` because it must compile without the note
    /// primitives, so the two copies are compared wherever both are
    /// reachable. A `CM` that drifted would put every shielded entry note's
    /// commitment outside the image the spend circuit checks membership
    /// against, and the notes would be unspendable with nothing on chain to
    /// point at.
    #[test]
    #[cfg(feature = "circuit")]
    fn domain_tags_match_qnero_notes() {
        use qp_poseidon_core::Goldilocks;
        assert_eq!(
            Goldilocks::new(domain::CM),
            qnero_note_core::digest::domain::CM
        );
    }

    /// One rule, one implementation: the `cm` the chain computes for a note
    /// created outside a spend proof is the `cm` the note primitives compute
    /// for the same note, which is the `cm` the spend circuit recomputes when
    /// that note is later spent.
    #[test]
    #[cfg(feature = "circuit")]
    fn commitment_matches_the_note_primitives() {
        use qnero_note_core::{commitment_from_inner, note_inner, Digest};
        let pk = Digest::hash_bytes(&[b"pk"]);
        let rho = Digest::hash_bytes(&[b"rho"]);
        let r = Digest::hash_bytes(&[b"r"]);
        let inner = note_inner(&pk, &rho, &r);
        let value = 42_000_000u64;
        assert_eq!(
            commitment(&inner.to_bytes(), value).expect("canonical inner"),
            commitment_from_inner(&inner, value).to_bytes()
        );
    }
}
