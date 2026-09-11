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
use qnero_notes::{output_rho, Digest, Note, SpendingKey, MAX_VALUE};
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
        digest("state-root").to_bytes(),
        digest("extrinsics-root").to_bytes(),
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
///
/// An output carries no `rho`: the circuit derives it from the leaf's first
/// published nullifier, and `SpendWitness::output_rho` is the wallet-side
/// mirror of that rule.
fn two_real_inputs() -> SpendWitness {
    let keys = sender_keys();
    let note_a = Note::new(keys.pk(), 500, digest("rho-a"), digest("r-a")).unwrap();
    let note_b = Note::new(keys.pk(), 300, digest("rho-b"), digest("r-b")).unwrap();
    let (tree, indices) = tree_with(&[note_a.commitment(), note_b.commitment()]);

    SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note_a, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::real(&keys, &note_b, tree.path(indices[1]).unwrap()).unwrap(),
        ],
        outputs: [
            OutputNote::new(recipient_pk(), 700, digest("r-out")),
            OutputNote::new(keys.pk(), 90, digest("r-change")),
        ],
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

    SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, tree.path(indices[0]).unwrap()).unwrap(),
            InputNote::dummy(&keys, digest("dummy-rho"), digest("dummy-r"), tree.depth()),
        ],
        outputs: [
            OutputNote::new(recipient_pk(), 480, digest("r-out2")),
            OutputNote::new(keys.pk(), 15, digest("r-change2")),
        ],
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
///
/// What this must never accept is a rejection that came from the front door.
/// `SpendWitness::validate` and `fill_witness` run before plonky2 does, so if a
/// later hardening pass moved a value range or the dummy contract into
/// `validate`, every negative test here would keep passing while the in-circuit
/// checks they exist to protect went unexercised. Both are therefore asserted
/// to succeed, and only `prove` may reject.
fn assert_rejected(witness: &SpendWitness, what: &str) {
    let (targets, data) = circuit();
    witness
        .validate()
        .expect("the fixture must be structurally valid, so only the circuit can reject it");
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, witness, targets)
        .expect("witness filling must succeed, so only the circuit can reject the fixture");

    if let Ok(proof) = data.prove(pw) {
        assert!(
            data.verify(proof).is_err(),
            "{what}: an invalid witness produced a proof that verified"
        );
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

    let witness = two_real_inputs();
    // The output notes as `qnero-notes` sees them, carrying the `rho` the leaf
    // derives.
    let nf_1 = note_a.nullifier(&keys.nk);
    let payment = Note::new(recipient_pk(), 700, output_rho(&nf_1, 0), digest("r-out")).unwrap();
    let change = Note::new(keys.pk(), 90, output_rho(&nf_1, 1), digest("r-change")).unwrap();
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

/// A leaf with every input marked dummy proves nothing: no spend key, no note
/// in the tree, zero value, zero fee. It would still publish two nullifiers and
/// two output commitments, which the chain writes into permanent state, and
/// settlement extrinsics are fee-free, so nothing else would charge for it.
/// Constraint 9 is what stops a prover who holds no notes at all from producing
/// a leaf. It does not bound how many leaves a prover can produce: a leaf mints
/// two notes and consumes at most two, so one note is enough to keep going. A
/// minimum fee at M4 is what bounds leaf count.
#[test]
fn both_inputs_dummy_cannot_prove() {
    let keys = sender_keys();
    // The header is an honest block's: its preimage is public chain data, so an
    // attacker can always supply one. Everything else in this witness is junk
    // and every other constraint is satisfied by it: values balance at zero,
    // the two nullifiers differ because the dummies get different `rho`, and
    // the paths are empty because no membership is checked.
    let honest = two_real_inputs();
    let witness = SpendWitness {
        header: honest.header.clone(),
        depth: honest.depth,
        inputs: [
            InputNote::dummy(
                &keys,
                digest("all-dummy-rho-1"),
                digest("all-dummy-r-1"),
                honest.depth,
            ),
            InputNote::dummy(
                &keys,
                digest("all-dummy-rho-2"),
                digest("all-dummy-r-2"),
                honest.depth,
            ),
        ],
        outputs: [
            OutputNote::new(recipient_pk(), 0, digest("all-dummy-out-r-1")),
            OutputNote::new(recipient_pk(), 0, digest("all-dummy-out-r-2")),
        ],
        fee: 0,
        ct_digest: digest("ciphertexts-all-dummy"),
    };

    assert_rejected(&witness, "both inputs dummy");
}

/// The 62-bit range check on an *input* value. The output and fee checks have
/// their own tests; without this one, deleting the input check leaves the whole
/// suite green while the no-wrap argument behind constraint 8 loses its
/// circuit-side half.
#[test]
fn an_input_value_of_two_to_the_62_cannot_prove() {
    let keys = sender_keys();
    // Built field by field, because `Note::new` caps the value at MAX_VALUE.
    // The tree is then seeded with the commitment this out-of-range value
    // produces, so pk derivation, membership and the nullifier all pass and
    // only the range check can reject the leaf.
    let mut over_range = InputNote {
        ask: keys.ask,
        nk: keys.nk,
        value: MAX_VALUE + 1,
        rho: digest("rho-in-over"),
        r: digest("r-in-over"),
        path: MerklePath::dummy(1),
        is_dummy: false,
    };
    let second = Note::new(keys.pk(), 0, digest("rho-in-zero"), digest("r-in-zero")).unwrap();
    let (tree, indices) = tree_with(&[over_range.commitment(), second.commitment()]);
    over_range.path = tree.path(indices[0]).unwrap();

    let witness = SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            over_range,
            InputNote::real(&keys, &second, tree.path(indices[1]).unwrap()).unwrap(),
        ],
        outputs: [
            OutputNote::new(recipient_pk(), MAX_VALUE, digest("r-in-out-1")),
            OutputNote::new(keys.pk(), 1, digest("r-in-out-2")),
        ],
        fee: 0,
        ct_digest: digest("ciphertexts-input-range"),
    };

    assert_eq!(
        witness.inputs.iter().map(|i| i.value as u128).sum::<u128>(),
        witness
            .outputs
            .iter()
            .map(|o| o.value as u128)
            .sum::<u128>()
            + witness.fee as u128,
        "the fixture must balance over the integers, so only the input range check can reject it"
    );
    assert_rejected(&witness, "input value 2^62");
}

/// A failed proof is the routine outcome of a stale Merkle path or an index off
/// by one, so a wallet will log it. Plonky2 names the two conflicting field
/// elements in that error, which are note values and Merkle node limbs.
#[test]
fn a_failed_proof_does_not_leak_the_witness() {
    let mut witness = two_real_inputs();
    // Off by one on the fee: structurally valid, so it reaches plonky2 and
    // fails there on the balance equation.
    witness.fee += 1;

    let error = QneroProver::new(qnero_leaf_circuit_config())
        .unwrap()
        .commit(&witness)
        .expect("a structurally valid witness commits")
        .prove()
        .expect_err("an unbalanced leaf cannot prove");

    let message = format!("{error:#}");
    assert_eq!(message, "failed to prove the leaf");
    assert!(
        !message.chars().any(|c| c.is_ascii_digit()),
        "the proving error carries witness field elements: {message}"
    );
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
            OutputNote::new(recipient_pk(), MAX_VALUE + 1, digest("r-overflow")),
            OutputNote::new(keys.pk(), 0, digest("r-zero")),
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
            OutputNote::new(recipient_pk(), 0, digest("r-fee-out")),
            OutputNote::new(keys.pk(), 0, digest("r-fee-change")),
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

    // The same note offered as both inputs: the tree accepts both paths, so
    // only the in-circuit distinctness check stands in the way.
    let witness = SpendWitness {
        header: header_for(tree.root()),
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, path.clone()).unwrap(),
            InputNote::real(&keys, &note, path).unwrap(),
        ],
        outputs: [
            OutputNote::new(recipient_pk(), 995, digest("r-o")),
            OutputNote::new(keys.pk(), 0, digest("r-c")),
        ],
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
        outputs: [
            OutputNote::new(recipient_pk(), 999_999, digest("r-m1")),
            OutputNote::new(keys.pk(), 0, digest("r-m2")),
        ],
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
    // `qnero-verifier` refuses an artifact whose degree does not match this,
    // so a circuit that grows past 512 rows has to say so in `params` and in
    // any regenerated artifact.
    assert_eq!(
        data.common.fri_params.degree_bits,
        qnero_circuit::params::LEAF_DEGREE_BITS
    );
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

/// The ZK leaf config is not a production configuration: privacy is applied one
/// layer up, at the private batch. The plumbing still has to stay alive, and
/// `zk_config_is_gated_by_the_feature` passes vacuously when the feature is
/// off, so this is the test that actually exercises plonky2's row blinding.
/// Run with `cargo test -p qnero-prover --release --features zk`.
#[cfg(feature = "zk")]
#[test]
fn a_zero_knowledge_leaf_proves_and_verifies() {
    use qnero_circuit::config::qnero_leaf_zk_circuit_config;

    let config = qnero_leaf_zk_circuit_config();
    assert!(config.zero_knowledge);

    let circuit = QneroSpendCircuit::new(config).expect("the zk config builds with the feature on");
    let targets = circuit.targets();
    let data = circuit.build();

    let witness = two_real_inputs();
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, &witness, &targets).unwrap();
    let proof = data.prove(pw).expect("a blinded leaf proves");

    assert_eq!(proof.public_inputs, witness.public_inputs());
    data.verify(proof).expect("a blinded leaf verifies");
}

/// An output's `rho` is derived from the leaf's first published nullifier, so
/// a sender cannot choose it and cannot repeat one.
///
/// A free `rho` is a griefing vector, because `nf = H(NF, nk, rho)` does not
/// depend on the note's value or on `r`: a sender paying one recipient twice
/// with the same `rho` creates two notes that share a nullifier, of which the
/// recipient can spend exactly one. The circuit's distinctness check
/// (constraint 5) catches that only inside a single leaf, and the chain's
/// used-nullifier set catches it only after the victim has already spent one
/// of the two, by which point the other is stranded for good.
#[test]
fn output_rho_is_derived_from_the_published_nullifier() {
    let witness = two_real_inputs();
    let proof = prove_with_shared_circuit(&witness).expect("leaf proves");
    let public = public_of(&proof);

    // The rule, stated against `qnero-notes` as well as against the witness
    // helper, so both copies of it are pinned.
    let nf_1 = witness.inputs[0].nullifier();
    for index in 0..2 {
        assert_eq!(witness.output_rho(index), output_rho(&nf_1, index as u64));

        let derived = Note::new(
            witness.outputs[index].pk,
            witness.outputs[index].value,
            witness.output_rho(index),
            witness.outputs[index].r,
        )
        .unwrap();
        assert_eq!(
            public.commitments[index],
            digest_to_felts(&derived.commitment()),
            "output {index} did not commit to the derived rho"
        );

        // What the leaf would have published had the sender picked `rho`.
        let chosen = Note::new(
            witness.outputs[index].pk,
            witness.outputs[index].value,
            digest("a-rho-the-sender-picked"),
            witness.outputs[index].r,
        )
        .unwrap();
        assert_ne!(
            public.commitments[index],
            digest_to_felts(&chosen.commitment())
        );
    }

    // The two outputs of one leaf differ, and no other leaf can reach either
    // value: `nf_1` is settled once, so a second leaf reusing it is refused on
    // chain before its outputs exist.
    assert_ne!(witness.output_rho(0), witness.output_rho(1));
    let other = one_real_one_dummy();
    for a in 0..2 {
        for b in 0..2 {
            assert_ne!(witness.output_rho(a), other.output_rho(b));
        }
    }
}

/// A `u64` at or above the Goldilocks modulus is the one range the circuit
/// cannot police: the witness carries it as its reduction, which is below
/// `2^32` and therefore inside the 62-bit range check. It is also the range a
/// wallet lands in by accident, since a wrapping `total_in - payment - fee`
/// underflows to `2^64 - k`. So it is rejected before the circuit, and this
/// pins that the front door is the only place it can be.
#[test]
fn a_value_at_or_above_the_field_modulus_is_rejected() {
    const ORDER: u64 = 0xFFFF_FFFF_0000_0001;

    for value in [ORDER, ORDER + 1000, u64::MAX] {
        let mut witness = two_real_inputs();
        witness.inputs[0].value = value;
        assert!(
            witness.validate().is_err(),
            "input value {value} reached the circuit, which would prove its reduction"
        );

        let mut witness = two_real_inputs();
        witness.outputs[0].value = value;
        assert!(
            witness.validate().is_err(),
            "output value {value} reached the circuit"
        );

        let mut witness = two_real_inputs();
        witness.fee = value;
        assert!(
            witness.validate().is_err(),
            "fee {value} reached the circuit"
        );
    }

    // One below the modulus still reaches the circuit, which rejects it on the
    // 62-bit range check. The front door bounds nothing the circuit can see.
    let mut witness = two_real_inputs();
    witness.inputs[0].value = ORDER - 1;
    witness
        .validate()
        .expect("a canonical value is the circuit\'s business");
    assert_rejected(&witness, "input value just below the modulus");
}

/// Verifier artifacts arrive as bytes, and a public-input count of 26 says
/// nothing about whether verification means anything. Plonky2's own check on
/// deserialized config rejects only a zero challenge count, a zero constant
/// count and fewer than three routed wires, so an artifact over this exact
/// layout with one query round and no grinding would otherwise be accepted and
/// would verify forged proofs.
#[test]
fn a_weakened_verifier_artifact_is_rejected() {
    let mut weak = qnero_leaf_circuit_config();
    weak.security_bits = 1;
    weak.num_challenges = 1;
    weak.fri_config.num_query_rounds = 1;
    weak.fri_config.proof_of_work_bits = 0;

    let artifact = QneroSpendCircuit::new(weak)
        .expect("a weak config is still structurally valid")
        .build_verifier()
        .to_bytes(&plonky2::util::serialization::DefaultGateSerializer)
        .expect("verifier data serializes");

    // It is shaped like a leaf: same layout, same public-input count.
    let error = QneroVerifier::from_artifact_bytes(&artifact)
        .expect_err("a downgraded artifact must be refused");
    let message = error.to_string();
    assert!(
        message.contains("below the canonical"),
        "unexpected rejection reason: {message}"
    );
}

/// Proof bytes are the natural transaction identity at M4. Plonky2 stops
/// reading when it has a whole proof and never checks the buffer is empty, and
/// it decodes each public input with an unreduced constructor whose range check
/// is a debug assertion, so without a canonical-encoding check one leaf has
/// unlimited distinct encodings.
#[test]
fn only_the_canonical_proof_encoding_is_accepted() {
    const ORDER: u64 = 0xFFFF_FFFF_0000_0001;

    let verifier = QneroVerifier::from_artifact_bytes(
        &circuit()
            .1
            .verifier_data()
            .to_bytes(&plonky2::util::serialization::DefaultGateSerializer)
            .expect("verifier data serializes"),
    )
    .expect("the canonical artifact is accepted");

    let proof = prove_with_shared_circuit(&two_real_inputs()).expect("leaf proves");
    let bytes = proof.to_bytes();
    verifier
        .verify_proof_bytes(&bytes)
        .expect("the canonical encoding verifies");

    // Trailing padding. The proof reads identically and, unchecked, verifies.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0u8; 1024]);
    assert!(
        verifier.verify_proof_bytes(&padded).is_err(),
        "a proof with 1 KiB appended was accepted"
    );

    // A public input re-encoded as `x + p`. The public inputs are the tail of
    // the encoding, `PUBLIC_INPUT_LEN` field elements of 8 little-endian bytes
    // each, so the block number sits at a known offset.
    let tail = bytes.len() - PUBLIC_INPUT_LEN * 8;
    let at = tail + BLOCK_NUMBER_INDEX * 8;
    let mut aliased = bytes.clone();
    let limb = u64::from_le_bytes(aliased[at..at + 8].try_into().unwrap());
    assert_eq!(
        limb, BLOCK_NUMBER as u64,
        "public inputs are not where expected"
    );
    aliased[at..at + 8].copy_from_slice(&(limb + ORDER).to_le_bytes());
    assert!(
        verifier.verify_proof_bytes(&aliased).is_err(),
        "a non-canonical public-input limb was accepted"
    );
}

/// Reports the leaf's size. Ignored by default because it is a measurement,
/// not an assertion: run it with
/// `cargo test -p qnero-prover --release -- --ignored --nocapture`.
///
/// One circuit instance throughout. Proving through the shared `OnceLock`
/// circuit would build a second copy inside the cold timer, so the first
/// number would be a build plus a prove, and the proof would then be verified
/// against a different instance than it was produced by.
#[test]
#[ignore]
fn leaf_gate_count() {
    let build_start = std::time::Instant::now();
    let circuit = QneroSpendCircuit::default();
    let gates = circuit.num_gates();
    let targets = circuit.targets();
    let data = circuit.build();
    let build = build_start.elapsed();

    let witness = two_real_inputs();
    let prove_once = || {
        let mut pw = PartialWitness::<F>::new();
        fill_witness(&mut pw, &witness, &targets).unwrap();
        data.prove(pw).unwrap()
    };

    let cold_start = std::time::Instant::now();
    let _cold_proof = prove_once();
    let cold = cold_start.elapsed();
    let warm_start = std::time::Instant::now();
    let proof = prove_once();
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
    println!("  prove, cold          : {cold:?}");
    println!("  prove, warm          : {warm:?}");
    println!("  verify               : {verify:?}");
    println!("  proof bytes          : {}", proof.to_bytes().len());
}
