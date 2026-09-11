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
use qnero_aggregator::artifacts::serialize_verifier_data;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
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
    let artifact =
        serialize_verifier_data(&public_batch_prover().verifier_data(), "public batch").unwrap();
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
    let artifact =
        serialize_verifier_data(&public_batch_prover().verifier_data(), "public batch").unwrap();
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

/// An all-padding public batch settles nothing, so the prover refuses it.
#[test]
fn an_all_padding_public_batch_is_refused() {
    let (_, padding) = inner_proofs();
    let error = public_batch_prover()
        .prove_batch(PublicBatchInputs {
            proofs: vec![padding.clone()],
            aggregator_address: aggregator_address(),
        })
        .expect_err("an all-padding public batch must be refused");
    assert!(error.to_string().contains("padding"), "got: {error}");
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
    let artifact =
        serialize_verifier_data(&public_batch_prover().verifier_data(), "public batch").unwrap();
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
