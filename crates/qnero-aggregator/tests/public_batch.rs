//! The public batch end to end: aggregate private batches under one
//! aggregator address, verify the result, and check that a proof naming a
//! different aggregator is refused.
//!
//! The dimensions here are small, two leaves per private batch and two private
//! batches per public batch, because this test is about the wrapper's rules
//! and not about how long a 53-slot batch takes to prove. Everything expensive
//! is shared through a `OnceLock`.

mod common;

use std::sync::OnceLock;

use plonky2::field::types::PrimeField64;
use qnero_aggregator::artifacts::serialize_public_batch_verifier_data;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_aggregator::public_batch::prover::validate_padding_private_batch_template;
use qnero_aggregator::public_batch::{PublicBatchInputs, QneroPublicBatchProver};
use qnero_aggregator::Proof;
use qnero_circuit::config::{
    qnero_private_batch_circuit_config, qnero_public_batch_circuit_config,
};
use qnero_circuit::convert::digest_to_felts;
use qnero_circuit::padding::PADDING_BLOCK_HASH;
use qnero_notes::Digest;
use qnero_verifier::{parse_public_batch_public_input_felts, QneroPublicBatchVerifier};

const NUM_LEAVES: usize = 2;
const NUM_INNER: usize = 2;

fn aggregator_address() -> Digest {
    common::digest("aggregator")
}

fn private_batch_prover() -> &'static QneroPrivateBatchProver {
    static PROVER: OnceLock<QneroPrivateBatchProver> = OnceLock::new();
    PROVER.get_or_init(|| {
        let (_, leaf) = common::leaf_circuit();
        QneroPrivateBatchProver::new(
            qnero_private_batch_circuit_config(),
            leaf.common.clone(),
            &leaf.verifier_only,
            NUM_LEAVES,
            common::padding_leaf_proof().clone(),
        )
        .expect("the private batch prover builds")
    })
}

/// One real private batch and the all-padding template, proved once each.
fn inner_proofs() -> &'static (Proof, Proof) {
    static PROOFS: OnceLock<(Proof, Proof)> = OnceLock::new();
    PROOFS.get_or_init(|| {
        let block = common::block_with_notes("public-batch", 1);
        let real = private_batch_prover()
            .aggregate(vec![block.transfer_proof(0)])
            .expect("the real private batch proves");
        let padding = private_batch_prover()
            .prove_padding_batch()
            .expect("the all-padding private batch proves");
        (real, padding)
    })
}

fn public_batch_prover() -> &'static QneroPublicBatchProver {
    static PROVER: OnceLock<QneroPublicBatchProver> = OnceLock::new();
    PROVER.get_or_init(|| {
        let private_batch = private_batch_prover().verifier_data();
        let (_, padding) = inner_proofs();
        QneroPublicBatchProver::new(
            qnero_public_batch_circuit_config(),
            private_batch.common.clone(),
            &private_batch.verifier_only,
            NUM_INNER,
            NUM_LEAVES,
            padding.clone(),
        )
        .expect("the public batch prover builds")
    })
}

/// One real private batch plus padding, proved once.
fn public_batch() -> &'static Proof {
    static PROOF: OnceLock<Proof> = OnceLock::new();
    PROOF.get_or_init(|| {
        let (real, _) = inner_proofs();
        public_batch_prover()
            .prove_batch(PublicBatchInputs {
                proofs: vec![real.clone()],
                aggregator_address: aggregator_address(),
            })
            .expect("the public batch proves")
    })
}

/// (c) A public batch over one real private batch and one padding inner
/// verifies, and its segments say which is which.
#[test]
fn a_public_batch_over_one_real_inner_verifies() {
    let artifact = serialize_public_batch_verifier_data(
        &public_batch_prover().verifier_data(),
        NUM_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let verifier = QneroPublicBatchVerifier::from_artifact_bytes(&artifact, NUM_INNER, NUM_LEAVES)
        .expect("the freshly built artifact passes its own profile");

    let public = verifier
        .verify_proof_bytes(&public_batch().to_bytes())
        .expect("the public batch verifies against the artifact");

    assert_eq!(
        public.aggregator_address,
        digest_to_felts(&aggregator_address())
    );
    assert_eq!(public.batches.len(), NUM_INNER);

    let real: Vec<_> = public
        .batches
        .iter()
        .filter(|batch| !batch.is_padding())
        .collect();
    assert_eq!(real.len(), 1, "exactly one inner segment is a real batch");
    assert_eq!(real[0].slots.len(), NUM_LEAVES);
    assert!(
        real[0].slots.iter().any(|slot| !slot.is_padding()),
        "the real inner segment must carry at least one real leaf slot"
    );

    // The padding inner keeps its sentinel header, which is how the chain
    // recognises a segment to skip, and everything after the header is zeroed
    // so a cloned template cannot publish the same nullifiers twice.
    let padding: Vec<_> = public
        .batches
        .iter()
        .filter(|batch| batch.is_padding())
        .collect();
    assert_eq!(padding.len(), 1);
    let sentinel: [u64; 4] = core::array::from_fn(|i| padding[0].block_hash[i].to_canonical_u64());
    assert_eq!(sentinel, PADDING_BLOCK_HASH);
    for slot in &padding[0].slots {
        assert!(slot.is_padding());
        assert!(slot
            .nullifiers
            .iter()
            .all(|nullifier| nullifier.iter().all(|limb| limb.to_canonical_u64() == 0)));
        assert_eq!(slot.fee.to_canonical_u64(), 0);
    }
}

/// (c) A proof that names another aggregator is refused.
///
/// The address is a free witness: anyone holding the inner proofs can re-prove
/// the same batch under their own address, and the result verifies
/// cryptographically. Nothing in circuit can stop that, so the aggregator has
/// to compare the exposed address against its own off circuit, and this is
/// that check.
#[test]
fn a_public_batch_naming_another_aggregator_is_refused() {
    let prover = public_batch_prover();
    let proof = public_batch().clone();

    prover
        .verify(proof.clone(), &aggregator_address())
        .expect("the batch names this aggregator");

    let error = prover
        .verify(proof, &common::digest("someone-else"))
        .expect_err("a batch naming another aggregator must be refused");
    assert!(error.to_string().contains("aggregator"), "got: {error}");
}

/// Editing the aggregator address in the public inputs breaks the proof
/// itself, so the off-circuit check is not the only thing standing between a
/// forged address and settlement.
#[test]
fn an_edited_aggregator_address_fails_verification() {
    let artifact = serialize_public_batch_verifier_data(
        &public_batch_prover().verifier_data(),
        NUM_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    let verifier =
        QneroPublicBatchVerifier::from_artifact_bytes(&artifact, NUM_INNER, NUM_LEAVES).unwrap();

    let mut tampered = public_batch().clone();
    tampered.public_inputs[0] += plonky2::field::types::Field::ONE;

    assert!(
        verifier.verify_proof_bytes(&tampered.to_bytes()).is_err(),
        "a public batch with an edited aggregator address must not verify"
    );
}

/// Inner proofs anchored at different blocks are refused: the chain resolves
/// one block hash per settlement.
#[test]
fn inner_batches_from_two_blocks_are_refused() {
    let (real, _) = inner_proofs();
    let other_block = common::block_with_notes("public-batch-other", 1);
    let other = private_batch_prover()
        .aggregate(vec![other_block.transfer_proof(0)])
        .expect("the second private batch proves");

    let error = public_batch_prover()
        .prove_batch(PublicBatchInputs {
            proofs: vec![real.clone(), other],
            aggregator_address: aggregator_address(),
        })
        .expect_err("two blocks in one public batch must be refused");
    assert!(
        error.to_string().contains("different block"),
        "got: {error}"
    );
}

/// A leaf proof is not a private-batch proof, and the length check says so
/// before any proving starts.
#[test]
fn a_proof_that_is_not_a_private_batch_is_refused() {
    let error = public_batch_prover()
        .prove_batch(PublicBatchInputs {
            proofs: vec![common::padding_leaf_proof().clone()],
            aggregator_address: aggregator_address(),
        })
        .expect_err("a leaf proof is not a private batch");
    assert!(
        format!("{error:#}").contains("public inputs"),
        "got: {error:#}"
    );
}

/// The public-batch artifact is meaningful only with the dimensions it was
/// built for.
#[test]
fn the_artifact_is_refused_under_the_wrong_dimensions() {
    let artifact = serialize_public_batch_verifier_data(
        &public_batch_prover().verifier_data(),
        NUM_INNER,
        NUM_LEAVES,
    )
    .unwrap();
    assert!(
        QneroPublicBatchVerifier::from_artifact_bytes(&artifact, NUM_INNER + 1, NUM_LEAVES)
            .is_err()
    );
    assert!(
        QneroPublicBatchVerifier::from_artifact_bytes(&artifact, NUM_INNER, NUM_LEAVES + 1)
            .is_err()
    );
}

/// The public batch forwards each inner proof's public inputs verbatim into
/// one contiguous segment, which is what lets the chain attribute a segment to
/// an inner proof.
#[test]
fn each_inner_segment_is_forwarded_verbatim() {
    let (real, _) = inner_proofs();
    let public =
        parse_public_batch_public_input_felts(&public_batch().public_inputs, NUM_INNER, NUM_LEAVES)
            .unwrap();

    let expected =
        qnero_verifier::parse_private_batch_public_input_felts(&real.public_inputs, NUM_LEAVES)
            .unwrap();
    assert!(
        public.batches.contains(&expected),
        "the real inner proof's public inputs must appear unchanged as one segment"
    );
}

/// The same private-batch proof in two inner slots is refused, here in
/// milliseconds, ahead of the proving run.
///
/// The circuit refuses it too, keyed on the first nullifier of the inner's
/// first slot; `the_circuit_refuses_a_replayed_inner_batch` is that test. This
/// one holds the admission check, which is what an honest aggregator meets and
/// what keeps the refusal off the expensive path.
#[test]
fn the_same_inner_proof_twice_is_refused() {
    let (real, _) = inner_proofs();
    let error = public_batch_prover()
        .prove_batch(PublicBatchInputs {
            proofs: vec![real.clone(), real.clone()],
            aggregator_address: aggregator_address(),
        })
        .expect_err("one private-batch proof in two inner slots must be refused");
    assert!(error.to_string().contains("nullifier"), "got: {error}");
}

/// Two distinct private batches that spend the same note are refused for the
/// same reason, so the rule keys on nullifiers. This half has no circuit
/// counterpart: comparing every inner's `2N` nullifiers against every other's
/// is not affordable at the chain's dimensions, so the admission check and the
/// chain's settled-nullifier set are the only things that see it.
#[test]
fn two_inner_batches_settling_one_note_are_refused() {
    let block = common::block_with_notes("public-batch-shared-note", 1);
    let one = private_batch_prover()
        .aggregate(vec![block.transfer_proof(0)])
        .expect("the first private batch proves");
    let two = private_batch_prover()
        .aggregate(vec![block.transfer_proof(0)])
        .expect("the second private batch proves");
    assert_ne!(
        one.to_bytes(),
        two.to_bytes(),
        "the two batches are different proofs of the same spend"
    );

    let error = public_batch_prover()
        .prove_batch(PublicBatchInputs {
            proofs: vec![one, two],
            aggregator_address: aggregator_address(),
        })
        .expect_err("two inner proofs settling one note must be refused");
    assert!(error.to_string().contains("nullifier"), "got: {error}");
}

/// Padding is this prover's to append. A caller supplying it is refused
/// wherever the padding sits, and a vector of nothing but padding falls under
/// the same rule.
///
/// The all-padding template is a published artifact anyone can download. It
/// settles nothing, so accepting one as an input would let anyone burn an
/// aggregator's slots with a file they did not prove. Both shapes are asserted
/// on the sentinel message: one admission rule covers them, and a test that
/// asserted only on the word "padding" would pass on the other rule's message
/// too.
#[test]
fn a_caller_supplied_padding_inner_is_refused() {
    let (real, padding) = inner_proofs();
    for proofs in [
        vec![real.clone(), padding.clone()],
        vec![padding.clone(), real.clone()],
        vec![padding.clone()],
    ] {
        let error = public_batch_prover()
            .prove_batch(PublicBatchInputs {
                proofs,
                aggregator_address: aggregator_address(),
            })
            .expect_err("a caller-supplied padding inner must be refused");
        assert!(
            error.to_string().contains("carries the padding sentinel"),
            "got: {error}"
        );
    }
}

/// A real private batch is not the all-padding template.
///
/// The template is what every empty inner slot is filled with, and the byte
/// pin in `artifacts` covers only the `*_verifier.bin` files, so this
/// validator is the only thing standing between a substituted
/// `padding_private_batch_proof.bin` and every batch an aggregator proves.
#[test]
fn a_real_private_batch_is_not_the_padding_template() {
    let (real, padding) = inner_proofs();
    let verifier = private_batch_prover().verifier_data();

    // The control: the genuine template passes.
    validate_padding_private_batch_template(padding, &verifier, NUM_LEAVES)
        .expect("the all-padding private batch is the padding template");

    let error = validate_padding_private_batch_template(real, &verifier, NUM_LEAVES)
        .expect_err("a real private batch must not be accepted as padding");
    assert!(
        error.to_string().contains("padding block hash"),
        "got: {error}"
    );
}

/// Public inputs that look like padding are not enough: the template must also
/// be a proof of the private-batch circuit.
///
/// This pins the verification half of the validator. Without it the check
/// degrades to a comparison against values an attacker chooses.
#[test]
fn padding_shaped_public_inputs_alone_are_not_the_padding_template() {
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use qnero_circuit::batch_layout::{private_batch_pi_len, BLOCK_HASH_START, BLOCK_NUMBER_INDEX};
    use qnero_circuit::padding::PADDING_BLOCK_NUMBER;
    use qnero_circuit::{C, D, F};

    let mut public = vec![F::ZERO; private_batch_pi_len(NUM_LEAVES)];
    for (i, limb) in PADDING_BLOCK_HASH.iter().enumerate() {
        public[BLOCK_HASH_START + i] = F::from_canonical_u64(*limb);
    }
    public[BLOCK_NUMBER_INDEX] = F::from_canonical_u32(PADDING_BLOCK_NUMBER);

    let mut builder =
        CircuitBuilder::<F, D>::new(qnero_circuit::config::qnero_public_batch_circuit_config());
    for value in &public {
        let target = builder.constant(*value);
        builder.register_public_input(target);
    }
    let data = builder.build::<C>();
    let impostor = data
        .prove(plonky2::iop::witness::PartialWitness::new())
        .expect("the stand-in circuit proves");

    let error = validate_padding_private_batch_template(
        &impostor,
        &private_batch_prover().verifier_data(),
        NUM_LEAVES,
    )
    .expect_err("a proof of another circuit must not be accepted as padding");
    assert!(
        error.to_string().contains("failed verification"),
        "got: {error}"
    );
}
