//! The note hashes, in circuit.
//!
//! Every function here mirrors one function of `qnero-notes` exactly: the same
//! domain tag as the first field element, the same operand order, the same
//! Poseidon2 sponge. The domain constants are imported from `qnero-notes`, so
//! the two copies cannot drift.
//!
//! `hash_n_to_hash_no_pad_p2::<Poseidon2Hash>` is the in-circuit twin of
//! `qp_poseidon_core::hash_to_felts`: zero initial state, additive absorption
//! in rate-8 chunks, `10*` padding, four-element squeeze. The similarly named
//! `hash_n_to_hash_no_pad` is a different, overwrite-mode sponge. Using it
//! would build, prove and verify against itself while diverging from every
//! wallet-side commitment, so the choice is pinned by the parity tests.

use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use qnero_notes::digest::{domain, Felt as NoteFelt};

use crate::convert::felt_to_plonky2;
use crate::{D, F};

/// `Poseidon2(domain, parts...)`, the shape `Digest::hash_felts` uses.
pub fn hash_with_domain(
    builder: &mut CircuitBuilder<F, D>,
    domain_tag: NoteFelt,
    parts: &[&[Target]],
) -> HashOutTarget {
    let len = 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut preimage = Vec::with_capacity(len);
    preimage.push(builder.constant(felt_to_plonky2(domain_tag)));
    for part in parts {
        preimage.extend_from_slice(part);
    }
    builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage)
}

/// `ak = H(AK, ask)`.
pub fn derive_ak(builder: &mut CircuitBuilder<F, D>, ask: HashOutTarget) -> HashOutTarget {
    hash_with_domain(builder, domain::AK, &[&ask.elements])
}

/// `pk = H(PK, ak, nk)`.
pub fn derive_pk(
    builder: &mut CircuitBuilder<F, D>,
    ask: HashOutTarget,
    nk: HashOutTarget,
) -> HashOutTarget {
    let ak = derive_ak(builder, ask);
    hash_with_domain(builder, domain::PK, &[&ak.elements, &nk.elements])
}

/// `inner = H(NOTE, pk, rho, r)`.
pub fn note_inner(
    builder: &mut CircuitBuilder<F, D>,
    pk: HashOutTarget,
    rho: HashOutTarget,
    r: HashOutTarget,
) -> HashOutTarget {
    hash_with_domain(
        builder,
        domain::NOTE,
        &[&pk.elements, &rho.elements, &r.elements],
    )
}

/// `cm = H(CM, inner, value)`.
///
/// The value is one field element over its full 62-bit range. The Wormhole
/// leaf splits a `u64` into two 32-bit limbs; Qnero deliberately does not, and
/// the caller range-checks the single element.
pub fn note_commitment(
    builder: &mut CircuitBuilder<F, D>,
    inner: HashOutTarget,
    value: Target,
) -> HashOutTarget {
    hash_with_domain(builder, domain::CM, &[&inner.elements, &[value]])
}

/// `nf = H(NF, nk, rho)`.
pub fn note_nullifier(
    builder: &mut CircuitBuilder<F, D>,
    nk: HashOutTarget,
    rho: HashOutTarget,
) -> HashOutTarget {
    hash_with_domain(builder, domain::NF, &[&nk.elements, &rho.elements])
}
