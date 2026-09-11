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

use plonky2::field::types::Field as _;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::target::{BoolTarget, Target};
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
    let tag = builder.constant(felt_to_plonky2(domain_tag));
    hash_with_domain_target(builder, tag, parts)
}

/// `Poseidon2(domain, parts...)` with the tag supplied as a wire.
///
/// Used where the tag itself is chosen in circuit: a dummy input slot hashes
/// its nullifier under `NF_DUMMY` and a real one under `NF`, selected by the
/// `is_dummy` bit. A tag that is a wire costs the same permutation as a
/// constant one; only the select in front of it is extra.
pub fn hash_with_domain_target(
    builder: &mut CircuitBuilder<F, D>,
    domain_tag: Target,
    parts: &[&[Target]],
) -> HashOutTarget {
    let len = 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut preimage = Vec::with_capacity(len);
    preimage.push(domain_tag);
    for part in parts {
        preimage.extend_from_slice(part);
    }
    builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage)
}

/// The domain tag of a nullifier, as a wire: `NF_DUMMY` when `is_dummy`,
/// `NF` otherwise.
pub fn nullifier_domain_tag(builder: &mut CircuitBuilder<F, D>, is_dummy: BoolTarget) -> Target {
    let real = builder.constant(felt_to_plonky2(domain::NF));
    let dummy = builder.constant(felt_to_plonky2(domain::NF_DUMMY));
    builder.select(is_dummy, dummy, real)
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

/// `rho = H(RHO, nf_1, nf_2, index)`: the nullifier seed of output note
/// `index`.
///
/// The mirror of `qnero_notes::output_rho`. An output's `rho` is derived from
/// both nullifiers the leaf publishes, so a sender cannot hand two notes the
/// same `rho` and strand one of them; see that function for the griefing
/// vector this closes and for why both nullifiers are in the preimage.
pub fn output_rho(
    builder: &mut CircuitBuilder<F, D>,
    nullifier_1: HashOutTarget,
    nullifier_2: HashOutTarget,
    index: u64,
) -> HashOutTarget {
    let index = builder.constant(F::from_canonical_u64(index));
    hash_with_domain(
        builder,
        domain::RHO,
        &[&nullifier_1.elements, &nullifier_2.elements, &[index]],
    )
}

/// `nf = H(NF, nk, rho, r)`.
pub fn note_nullifier(
    builder: &mut CircuitBuilder<F, D>,
    nk: HashOutTarget,
    rho: HashOutTarget,
    r: HashOutTarget,
) -> HashOutTarget {
    let tag = builder.constant(felt_to_plonky2(domain::NF));
    note_nullifier_tagged(builder, tag, nk, rho, r)
}

/// `nf = H(tag, nk, rho, r)` with the domain tag supplied as a wire.
///
/// The mirror of `qnero_notes::nullifier` and `qnero_notes::dummy_nullifier`,
/// which differ only in that tag. `r` is in the preimage so that `nk` alone
/// does not link a wallet's spends; see `qnero_notes::nullifier`.
pub fn note_nullifier_tagged(
    builder: &mut CircuitBuilder<F, D>,
    domain_tag: Target,
    nk: HashOutTarget,
    rho: HashOutTarget,
    r: HashOutTarget,
) -> HashOutTarget {
    hash_with_domain_target(
        builder,
        domain_tag,
        &[&nk.elements, &rho.elements, &r.elements],
    )
}

#[cfg(test)]
mod tests {
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};

    use super::*;
    use crate::config::qnero_leaf_circuit_config;
    use crate::convert::{digest_to_felts, digest_to_hashout};
    use crate::C;
    use qnero_notes::{dummy_nullifier, nullifier, Digest};

    /// Both nullifier tags, pinned against `qnero-notes`.
    ///
    /// The leaf selects the tag in circuit, so the parity tests on a full leaf
    /// only ever exercise the tagged entry point. This covers the constant-tag
    /// helper too, and pins that the dummy tag really does produce a different
    /// value for the same key material, which is the property that stops a
    /// padding slot from burning someone's note.
    #[test]
    fn both_nullifier_tags_match_qnero_notes() {
        let nk = Digest::hash_bytes(&[b"gadget/nk"]);
        let rho = Digest::hash_bytes(&[b"gadget/rho"]);
        let r = Digest::hash_bytes(&[b"gadget/r"]);

        for is_dummy in [false, true] {
            let mut builder = CircuitBuilder::<F, D>::new(qnero_leaf_circuit_config());
            let nk_target = builder.add_virtual_hash();
            let rho_target = builder.add_virtual_hash();
            let r_target = builder.add_virtual_hash();

            let flag = builder.constant_bool(is_dummy);
            let tag = nullifier_domain_tag(&mut builder, flag);
            let tagged = note_nullifier_tagged(&mut builder, tag, nk_target, rho_target, r_target);
            let plain = note_nullifier(&mut builder, nk_target, rho_target, r_target);
            builder.register_public_inputs(&tagged.elements);
            builder.register_public_inputs(&plain.elements);

            let data = builder.build::<C>();
            let mut pw = PartialWitness::<F>::new();
            pw.set_hash_target(nk_target, digest_to_hashout(&nk))
                .unwrap();
            pw.set_hash_target(rho_target, digest_to_hashout(&rho))
                .unwrap();
            pw.set_hash_target(r_target, digest_to_hashout(&r)).unwrap();
            let proof = data.prove(pw).expect("the gadget circuit proves");

            let expected = if is_dummy {
                dummy_nullifier(&nk, &rho, &r)
            } else {
                nullifier(&nk, &rho, &r)
            };
            assert_eq!(proof.public_inputs[..4], digest_to_felts(&expected));
            // The constant-tag helper is always the real one.
            assert_eq!(
                proof.public_inputs[4..8],
                digest_to_felts(&nullifier(&nk, &rho, &r))
            );
        }

        assert_ne!(nullifier(&nk, &rho, &r), dummy_nullifier(&nk, &rho, &r));
    }
}
