//! The off-circuit hash must equal what a Plonky2 circuit computes with
//! `hash_n_to_hash_no_pad::<Poseidon2Hash>` over the same felts, otherwise
//! wallet-side commitments and in-circuit commitments diverge.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::plonk::config::Hasher;
use qnero_notes::digest::domain;
use qnero_notes::{dummy_nullifier, nullifier, output_rho, Digest, Felt, Note, SpendingKey};

fn to_p2(f: &Felt) -> GoldilocksField {
    GoldilocksField::from_canonical_u64(f.as_canonical_u64())
}

fn plonky2_hash(domain: Felt, parts: &[&[Felt]]) -> [u64; 4] {
    let mut input = vec![to_p2(&domain)];
    for p in parts {
        input.extend(p.iter().map(to_p2));
    }
    let out = Poseidon2Hash::hash_no_pad(&input).elements;
    core::array::from_fn(|i| out[i].to_canonical_u64())
}

fn as_u64s(d: &Digest) -> [u64; 4] {
    core::array::from_fn(|i| d.felts()[i].as_canonical_u64())
}

#[test]
fn commitment_and_nullifier_match_plonky2_poseidon2() {
    let sk = SpendingKey::from_bytes([11u8; 32]);
    let rho = Digest::hash_bytes(&[b"parity/rho"]);
    let r = Digest::hash_bytes(&[b"parity/r"]);
    let note = Note::new(sk.pk(), 777, rho, r).unwrap();

    let ak = sk.ak();
    let ask = sk.ask();
    let nk = sk.nk();
    assert_eq!(as_u64s(&ak), plonky2_hash(domain::AK, &[ask.felts()]));
    assert_eq!(
        as_u64s(&sk.pk()),
        plonky2_hash(domain::PK, &[ak.felts(), nk.felts()])
    );
    let inner = note.inner();
    assert_eq!(
        as_u64s(&inner),
        plonky2_hash(domain::NOTE, &[note.pk.felts(), rho.felts(), r.felts()])
    );
    assert_eq!(
        as_u64s(&note.commitment()),
        plonky2_hash(domain::CM, &[inner.felts(), &[Felt::new(777)]])
    );
    let nf = note.nullifier(&nk);
    assert_eq!(
        as_u64s(&nf),
        plonky2_hash(domain::NF, &[nk.felts(), rho.felts(), r.felts()])
    );
    let nf_dummy = dummy_nullifier(&nk, &rho, &r);
    assert_eq!(
        as_u64s(&nf_dummy),
        plonky2_hash(domain::NF_DUMMY, &[nk.felts(), rho.felts(), r.felts()])
    );
    let nf_2 = Note::new(sk.pk(), 8, Digest::hash_bytes(&[b"parity/rho2"]), r)
        .unwrap()
        .nullifier(&nk);
    for index in 0..2u64 {
        assert_eq!(
            as_u64s(&output_rho(&nf, &nf_2, index)),
            plonky2_hash(
                domain::RHO,
                &[nf.felts(), nf_2.felts(), &[Felt::new(index)]]
            )
        );
    }
}

/// `r` is in the nullifier preimage, so `nk` plus a publicly derivable `rho`
/// is not enough to recompute a note's nullifier. Every output note's `rho` is
/// a public function of the leaf that created it, so without `r` a leaked `nk`
/// would link every spend of that wallet to the leaf that funded it.
#[test]
fn the_nullifier_binds_the_commitment_randomness() {
    let sk = SpendingKey::from_bytes([12u8; 32]);
    let nk = sk.nk();
    let rho = Digest::hash_bytes(&[b"binding/rho"]);
    let r_a = Digest::hash_bytes(&[b"binding/r-a"]);
    let r_b = Digest::hash_bytes(&[b"binding/r-b"]);

    assert_ne!(nullifier(&nk, &rho, &r_a), nullifier(&nk, &rho, &r_b));
}

/// A dummy input slot's nullifier is domain separated from a real one, so a
/// value published by a slot that proves no membership can never equal the
/// nullifier of a note in the tree. Both are uniform Poseidon2 outputs, so the
/// separation costs no distinguishability in the public inputs.
#[test]
fn a_dummy_nullifier_is_never_a_real_one() {
    let sk = SpendingKey::from_bytes([13u8; 32]);
    let nk = sk.nk();
    let rho = Digest::hash_bytes(&[b"dummy-sep/rho"]);
    let r = Digest::hash_bytes(&[b"dummy-sep/r"]);

    assert_ne!(nullifier(&nk, &rho, &r), dummy_nullifier(&nk, &rho, &r));
}
