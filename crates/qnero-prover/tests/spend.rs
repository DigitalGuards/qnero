//! End-to-end tests for the Qnero v0 spend leaf.
//!
//! Everything here runs in release: proving a leaf in a debug build takes
//! minutes.

use std::sync::OnceLock;

use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::config::qnero_leaf_circuit_config;
use qnero_circuit::convert::digest_to_felts;
use qnero_circuit::header::HeaderInputs;
use qnero_circuit::layout::{
    commitment_index, nullifier_index, BLOCK_NUMBER_INDEX, CT_DIGEST_START, FEE_INDEX,
    PUBLIC_INPUT_LEN,
};
use qnero_circuit::merkle::{CommitmentTree, MerklePath};
use qnero_circuit::witness::{fill_witness, InputNote, OutputNote, SpendWitness};
use qnero_circuit::{C, D, F};
use qnero_notes::keys::DerivedKeys;
use qnero_notes::{Digest, Note, SpendingKey, MAX_VALUE};
use qnero_prover::{prove_leaf, QneroProver};
use qnero_verifier::{parse_public_input_felts, LeafPublicInputs, QneroVerifier};

const BLOCK_NUMBER: u32 = 4242;

fn digest(tag: &str) -> Digest {
    Digest::hash_bytes(&[b"qnero-test/", tag.as_bytes()])
}

/// The circuit and its targets, built once for the whole test binary.
fn circuit() -> &'static (SpendTargets, CircuitData<F, C, D>) {
    static CIRCUIT: OnceLock<(SpendTargets, CircuitData<F, C, D>)> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        let circuit = QneroSpendCircuit::default();
        let targets = circuit.targets();
        (targets, circuit.build())
    })
}

fn header_for(root: Digest) -> HeaderInputs {
    HeaderInputs::new(
        digest("parent"),
        BLOCK_NUMBER,
        digest("state-root"),
        digest("extrinsics-root"),
        root,
        &[0xAB; qnero_circuit::header::DIGEST_LOGS_SIZE],
    )
    .expect("header digest logs are the right length")
}

fn sender_keys() -> DerivedKeys {
    SpendingKey::from_bytes([7u8; 32]).derived()
}

fn recipient_pk() -> Digest {
    SpendingKey::from_bytes([9u8; 32]).pk()
}

/// A tree holding `owned` at known indices, padded with decoys.
fn tree_with(owned: &[Digest]) -> (CommitmentTree, Vec<usize>) {
    let mut leaves: Vec<Digest> = Vec::new();
    let mut indices = Vec::new();
    for (i, commitment) in owned.iter().enumerate() {
        leaves.push(digest(&format!("decoy-{i}-a")));
        leaves.push(digest(&format!("decoy-{i}-b")));
        indices.push(leaves.len());
        leaves.push(*commitment);
    }
    leaves.push(digest("decoy-tail"));
    let depth = CommitmentTree::depth_for(leaves.len()).unwrap();
    (CommitmentTree::new(&leaves, depth).unwrap(), indices)
}

/// Two real inputs of 500 and 300, paying 700 out with 90 change and a fee of
/// 10.
fn two_real_inputs() -> SpendWitness {
    let keys = sender_keys();
    let note_a = Note::new(keys.pk(), 500, digest("rho-a"), digest("r-a")).unwrap();
    let note_b = Note::new(keys.pk(), 300, digest("rho-b"), digest("r-b")).unwrap();
    let (tree, indices) = tree_with(&[note_a.commitment(), note_b.commitment()]);

    let payment = Note::new(recipient_pk(), 700, digest("rho-out"), digest("r-out")).unwrap();
    let change = Note::new(keys.pk(), 90, digest("rho-change"), digest("r-change")).unwrap();

    SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note_a, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::real(&keys, &note_b, tree.path(indices[1]).unwrap()).unwrap(),
        ],
        outputs: [OutputNote::new(&payment), OutputNote::new(&change)],
        fee: 10,
        ct_digest: digest("ciphertexts"),
    }
}

/// One real input of 500 and one dummy, paying 480 out with 15 change and a
/// fee of 5.
fn one_real_one_dummy() -> SpendWitness {
    let keys = sender_keys();
    let note = Note::new(keys.pk(), 500, digest("rho-solo"), digest("r-solo")).unwrap();
    let (tree, indices) = tree_with(&[note.commitment()]);

    let payment = Note::new(recipient_pk(), 480, digest("rho-out2"), digest("r-out2")).unwrap();
    let change = Note::new(keys.pk(), 15, digest("rho-change2"), digest("r-change2")).unwrap();

    SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::dummy(&keys, digest("dummy-rho"), digest("dummy-r"), tree.depth()),
        ],
        outputs: [OutputNote::new(&payment), OutputNote::new(&change)],
        fee: 5,
        ct_digest: digest("ciphertexts-2"),
    }
}

/// Read a proof's public inputs through the verifier crate's parser. Field
/// elements are the same type on both sides; only the proof struct differs,
/// which is why a real verifier takes bytes.
fn public_of(proof: &ProofWithPublicInputs<F, C, D>) -> LeafPublicInputs {
    parse_public_input_felts(&proof.public_inputs).unwrap()
}

fn prove_with_shared_circuit(
    witness: &SpendWitness,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (targets, data) = circuit();
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, witness, targets)?;
    data.prove(pw)
}

/// A tampered witness must either fail to prove or produce a proof that fails
/// to verify. Which of the two depends on where the constraint bites, and a
/// test that demanded one specific failure mode would pin an implementation
/// detail of plonky2 and miss the property.
fn assert_rejected(witness: &SpendWitness, what: &str) {
    let (_, data) = circuit();
    match prove_with_shared_circuit(witness) {
        Err(error) => {
            eprintln!("rejected [{what}]: {error}");
        }
        Ok(proof) => {
            assert!(
                data.verify(proof).is_err(),
                "{what}: an invalid witness produced a proof that verified"
            );
        }
    }
}

#[test]
fn two_real_inputs_prove_and_verify() {
    let witness = two_real_inputs();

    let proof = prove_leaf(qnero_leaf_circuit_config(), &witness).expect("leaf proves");

    // The verifier crate is loaded the way a runtime loads it: from the
    // serialized verifier artifact, checking a serialized proof.
    let artifact = QneroSpendCircuit::new(qnero_leaf_circuit_config())
        .unwrap()
        .build_verifier()
        .to_bytes(&plonky2::util::serialization::DefaultGateSerializer)
        .expect("verifier data serializes");
    let verifier = QneroVerifier::from_artifact_bytes(&artifact).unwrap();
    let public = verifier
        .verify_proof_bytes(&proof.to_bytes())
        .expect("leaf verifies");

    assert_eq!(proof.public_inputs.len(), PUBLIC_INPUT_LEN);
    assert_eq!(proof.public_inputs, witness.public_inputs());

    // The public inputs say what the chain will act on.
    assert_eq!(
        public.block_hash,
        digest_to_felts(&witness.header.block_hash())
    );
    assert_eq!(public.block_number.to_canonical_u64(), BLOCK_NUMBER as u64);
    assert_eq!(public.fee.to_canonical_u64(), 10);
    assert_eq!(public.ct_digest, digest_to_felts(&witness.ct_digest));
}

/// Parity: what the circuit publishes is what `qnero-notes` computes for the
/// same notes and keys. A divergence between the two hash implementations
/// would show up here.
#[test]
fn published_nullifiers_and_commitments_match_qnero_notes() {
    let keys = sender_keys();
    let note_a = Note::new(keys.pk(), 500, digest("rho-a"), digest("r-a")).unwrap();
    let note_b = Note::new(keys.pk(), 300, digest("rho-b"), digest("r-b")).unwrap();
    let payment = Note::new(recipient_pk(), 700, digest("rho-out"), digest("r-out")).unwrap();
    let change = Note::new(keys.pk(), 90, digest("rho-change"), digest("r-change")).unwrap();

    let witness = two_real_inputs();
    let proof = prove_with_shared_circuit(&witness).expect("leaf proves");
    let public = public_of(&proof);

    assert_eq!(
        public.nullifiers[0],
        digest_to_felts(&note_a.nullifier(&keys.nk))
    );
    assert_eq!(
        public.nullifiers[1],
        digest_to_felts(&note_b.nullifier(&keys.nk))
    );
    assert_eq!(
        public.commitments[0],
        digest_to_felts(&payment.commitment())
    );
    assert_eq!(public.commitments[1], digest_to_felts(&change.commitment()));

    // And the indices those values were read from are the documented ones.
    assert_eq!(
        proof.public_inputs[nullifier_index(0)..nullifier_index(0) + 4],
        digest_to_felts(&note_a.nullifier(&keys.nk))
    );
    assert_eq!(
        proof.public_inputs[commitment_index(1)..commitment_index(1) + 4],
        digest_to_felts(&change.commitment())
    );
    assert_eq!(
        proof.public_inputs[BLOCK_NUMBER_INDEX].to_canonical_u64(),
        BLOCK_NUMBER as u64
    );
    assert_eq!(proof.public_inputs[FEE_INDEX].to_canonical_u64(), 10);
    assert_eq!(
        proof.public_inputs[CT_DIGEST_START..CT_DIGEST_START + 4],
        digest_to_felts(&witness.ct_digest)
    );
}

#[test]
fn one_real_input_and_one_dummy_prove_and_verify() {
    let witness = one_real_one_dummy();
    let (_, data) = circuit();
    let proof = prove_with_shared_circuit(&witness).expect("leaf with a dummy input proves");
    data.verify(proof.clone())
        .expect("leaf with a dummy verifies");

    // The dummy still publishes a nullifier, so a dummy slot is not visible in
    // the public inputs.
    let public = public_of(&proof);
    let keys = sender_keys();
    assert_eq!(
        public.nullifiers[1],
        digest_to_felts(&qnero_notes::nullifier(&keys.nk, &digest("dummy-rho")))
    );
    assert_ne!(public.nullifiers[0], public.nullifiers[1]);
}

#[test]
fn a_wrong_ask_cannot_prove() {
    let mut witness = two_real_inputs();
    witness.inputs[0].ask = digest("not-the-spend-key");
    assert_rejected(&witness, "wrong ask");
}

#[test]
fn a_wrong_nullifier_key_cannot_prove() {
    let mut witness = two_real_inputs();
    witness.inputs[1].nk = digest("not-the-nullifier-key");
    assert_rejected(&witness, "wrong nk");
}

#[test]
fn a_wrong_merkle_sibling_cannot_prove() {
    let mut witness = two_real_inputs();
    witness.inputs[0].path.siblings[0][0] = digest("tampered-sibling");
    assert_rejected(&witness, "wrong merkle sibling");
}

#[test]
fn a_wrong_position_hint_cannot_prove() {
    let mut witness = two_real_inputs();
    let position = &mut witness.inputs[0].path.positions[0];
    *position = (*position + 1) % 4;
    assert_rejected(&witness, "wrong position hint");
}

#[test]
fn a_note_outside_the_tree_cannot_prove() {
    let keys = sender_keys();
    let minted = Note::new(keys.pk(), 500, digest("rho-forged"), digest("r-forged")).unwrap();
    let (tree, indices) = tree_with(&[minted.commitment()]);

    // A second tree the header never committed to.
    let mut witness = one_real_one_dummy();
    witness.inputs[0] = InputNote::real(&keys, &minted, tree.path(indices[0]).unwrap()).unwrap();
    assert_rejected(&witness, "note from another tree");
}

#[test]
fn a_balance_off_by_one_cannot_prove() {
    let mut witness = two_real_inputs();
    witness.fee += 1;
    assert_rejected(&witness, "fee one too high");

    let mut witness = two_real_inputs();
    witness.outputs[0].value += 1;
    assert_rejected(&witness, "output one too high");

    let mut witness = two_real_inputs();
    witness.outputs[1].value -= 1;
    assert_rejected(&witness, "output one too low");
}

#[test]
fn an_output_value_of_two_to_the_62_cannot_prove() {
    let keys = sender_keys();
    // Two maximal inputs, so the balance holds over the integers and only the
    // 62-bit range check stands between the prover and an out-of-range output.
    let note_a = Note::new(keys.pk(), MAX_VALUE, digest("rho-max-a"), digest("r-max-a")).unwrap();
    let note_b = Note::new(keys.pk(), 1, digest("rho-one"), digest("r-one")).unwrap();
    let (tree, indices) = tree_with(&[note_a.commitment(), note_b.commitment()]);

    let witness = SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note_a, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::real(&keys, &note_b, tree.path(indices[1]).unwrap()).unwrap(),
        ],
        outputs: [
            // MAX_VALUE + 1 = 2^62, one above the range.
            OutputNote {
                pk: recipient_pk(),
                value: MAX_VALUE + 1,
                rho: digest("rho-overflow"),
                r: digest("r-overflow"),
            },
            OutputNote {
                pk: keys.pk(),
                value: 0,
                rho: digest("rho-zero"),
                r: digest("r-zero"),
            },
        ],
        fee: 0,
        ct_digest: digest("ciphertexts-overflow"),
    };

    assert_eq!(
        witness.inputs.iter().map(|i| i.value as u128).sum::<u128>(),
        witness
            .outputs
            .iter()
            .map(|o| o.value as u128)
            .sum::<u128>()
            + witness.fee as u128,
        "the fixture must balance over the integers, so only the range check can reject it"
    );
    assert_rejected(&witness, "output value 2^62");
}

#[test]
fn a_fee_above_the_value_range_cannot_prove() {
    let keys = sender_keys();
    let note_a = Note::new(keys.pk(), MAX_VALUE, digest("rho-fee-a"), digest("r-fee-a")).unwrap();
    let note_b = Note::new(keys.pk(), MAX_VALUE, digest("rho-fee-b"), digest("r-fee-b")).unwrap();
    let (tree, indices) = tree_with(&[note_a.commitment(), note_b.commitment()]);

    // fee = 2^63 - 2, which balances the two maximal inputs exactly but is a
    // bit wider than a note value may be. Keeping the fee inside 62 bits is
    // what stops the balance equation from being satisfied by a field wrap.
    let fee = 2 * MAX_VALUE;
    let witness = SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note_a, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::real(&keys, &note_b, tree.path(indices[1]).unwrap()).unwrap(),
        ],
        outputs: [
            OutputNote {
                pk: recipient_pk(),
                value: 0,
                rho: digest("rho-fee-out"),
                r: digest("r-fee-out"),
            },
            OutputNote {
                pk: keys.pk(),
                value: 0,
                rho: digest("rho-fee-change"),
                r: digest("r-fee-change"),
            },
        ],
        fee,
        ct_digest: digest("ciphertexts-fee"),
    };

    assert_eq!(
        witness.inputs.iter().map(|i| i.value as u128).sum::<u128>(),
        fee as u128,
        "the fixture must balance over the integers"
    );
    assert_rejected(&witness, "fee above the value range");
}

#[test]
fn a_dummy_input_carrying_value_cannot_prove() {
    let mut witness = one_real_one_dummy();
    witness.inputs[1].value = 25;
    witness.outputs[0].value += 25;
    assert_rejected(&witness, "dummy input carrying value");
}

#[test]
fn two_identical_nullifiers_cannot_prove() {
    let keys = sender_keys();
    let note = Note::new(keys.pk(), 500, digest("rho-twice"), digest("r-twice")).unwrap();
    let (tree, indices) = tree_with(&[note.commitment()]);
    let path = tree.path(indices[0]).unwrap();

    let payment = Note::new(recipient_pk(), 995, digest("rho-o"), digest("r-o")).unwrap();
    let change = Note::new(keys.pk(), 0, digest("rho-c"), digest("r-c")).unwrap();

    // The same note offered as both inputs: the tree accepts both paths, so
    // only the in-circuit distinctness check stands in the way.
    let witness = SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, path.clone()).unwrap(),
            InputNote::real(&keys, &note, path).unwrap(),
        ],
        outputs: [OutputNote::new(&payment), OutputNote::new(&change)],
        fee: 5,
        ct_digest: digest("ciphertexts-double"),
    };
    assert_rejected(&witness, "the same note spent twice in one leaf");
}

#[test]
fn a_tampered_public_input_fails_verification() {
    let (_, data) = circuit();
    let witness = two_real_inputs();
    let proof = prove_with_shared_circuit(&witness).expect("leaf proves");
    data.verify(proof.clone())
        .expect("the untampered proof verifies");

    for index in [
        FEE_INDEX,
        BLOCK_NUMBER_INDEX,
        nullifier_index(0),
        CT_DIGEST_START,
    ] {
        let mut tampered = proof.clone();
        tampered.public_inputs[index] += F::ONE;
        assert!(
            data.verify(tampered).is_err(),
            "public input {index} could be changed after proving"
        );
    }
}

/// A prover can always build a header that hashes consistently. What it cannot
/// do is make that header's hash equal the hash of a block the chain actually
/// produced, which is the check the chain performs on `block_hash`.
#[test]
fn a_forged_tree_cannot_reuse_an_honest_block_hash() {
    let honest_block_hash = two_real_inputs().header.block_hash();

    let keys = sender_keys();
    let minted = Note::new(keys.pk(), 1_000_000, digest("rho-mint"), digest("r-mint")).unwrap();
    let (forged_tree, indices) = tree_with(&[minted.commitment()]);

    let payment = Note::new(recipient_pk(), 999_999, digest("rho-m1"), digest("r-m1")).unwrap();
    let change = Note::new(keys.pk(), 0, digest("rho-m2"), digest("r-m2")).unwrap();
    let witness = SpendWitness {
        header: header_for(forged_tree.root()),
        depth: forged_tree.depth(),
        inputs: [
            InputNote::real(&keys, &minted, forged_tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::dummy(
                &keys,
                digest("rho-m-dummy"),
                digest("r-m-dummy"),
                forged_tree.depth(),
            ),
        ],
        outputs: [OutputNote::new(&payment), OutputNote::new(&change)],
        fee: 1,
        ct_digest: digest("ciphertexts-mint"),
    };

    // The leaf is internally consistent, so it proves.
    let proof = prove_with_shared_circuit(&witness).expect("a self-consistent leaf proves");
    circuit().1.verify(proof.clone()).unwrap();

    // And it is useless: its block hash is not the honest one, so no block at
    // this height carries it.
    assert_ne!(
        proof.public_inputs[..4],
        digest_to_felts(&honest_block_hash),
        "a forged tree produced the honest block hash"
    );
}

#[test]
fn the_built_circuit_matches_the_documented_layout() {
    let (_, data) = circuit();
    assert_eq!(data.common.num_public_inputs, PUBLIC_INPUT_LEN);
    assert_eq!(PUBLIC_INPUT_LEN, 26);
    assert_eq!(nullifier_index(0), 5);
    assert_eq!(commitment_index(0), 13);
    assert_eq!(FEE_INDEX, 21);
    assert_eq!(CT_DIGEST_START, 22);
}

#[test]
fn a_witness_cannot_be_committed_twice() {
    let witness = two_real_inputs();
    let prover = QneroProver::new(qnero_leaf_circuit_config())
        .unwrap()
        .commit(&witness)
        .unwrap();
    assert!(prover.commit(&witness).is_err());
}

#[test]
fn a_path_of_the_wrong_depth_is_rejected() {
    let mut witness = two_real_inputs();
    witness.inputs[0].path = MerklePath::dummy(witness.depth + 1);
    assert!(fill_witness(&mut PartialWitness::<F>::new(), &witness, &circuit().0).is_err());
}

/// Reports the leaf's size. Ignored by default because it is a measurement,
/// not an assertion: run it with
/// `cargo test -p qnero-prover --release -- --ignored --nocapture`.
#[test]
#[ignore]
fn leaf_gate_count() {
    let build_start = std::time::Instant::now();
    let circuit = QneroSpendCircuit::default();
    let gates = circuit.num_gates();
    let data = circuit.build();
    let build = build_start.elapsed();

    let witness = two_real_inputs();
    let cold_start = std::time::Instant::now();
    let _cold_proof = prove_with_shared_circuit(&witness).unwrap();
    let cold = cold_start.elapsed();
    let warm_start = std::time::Instant::now();
    let proof = prove_with_shared_circuit(&witness).unwrap();
    let warm = warm_start.elapsed();

    let verify_start = std::time::Instant::now();
    data.verify(proof.clone()).unwrap();
    let verify = verify_start.elapsed();

    println!("qnero leaf circuit (2 inputs, 2 outputs, MAX_DEPTH=16)");
    println!("  gates before padding : {gates}");
    println!("  degree_bits          : {}", data.common.degree_bits());
    println!("  public inputs        : {}", data.common.num_public_inputs);
    println!(
        "  zero knowledge       : {}",
        data.common.config.zero_knowledge
    );
    println!("  build                : {build:?}");
    println!("  prove, first in run  : {cold:?}");
    println!("  prove, warm          : {warm:?}");
    println!("  verify               : {verify:?}");
    println!("  proof bytes          : {}", proof.to_bytes().len());
}
