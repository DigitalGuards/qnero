//! The private batch end to end: aggregate leaf proofs, verify the result
//! through the artifact a runtime would hold, and check the forwarding
//! contract slot by slot.
//!
//! The slot count is the chain default, 7, so these tests exercise the real
//! shape. Both proving runs are shared through a `OnceLock`, because proving a
//! 7-slot batch takes tens of seconds and none of these tests is about how
//! long that takes.

mod common;

use std::sync::OnceLock;

use plonky2::field::types::{Field, PrimeField64};
use qnero_aggregator::artifacts::serialize_verifier_data;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_aggregator::Proof;
use qnero_circuit::config::qnero_private_batch_circuit_config;
use qnero_circuit::convert::digest_to_felts;
use qnero_circuit::padding::PADDING_BLOCK_HASH;
use qnero_circuit::F;
use qnero_verifier::{
    parse_private_batch_public_input_felts, BatchLeafSlot, PrivateBatchPublicInputs,
    QneroPrivateBatchVerifier,
};

/// The chain default: 7 leaf slots per private batch.
const NUM_LEAVES: usize = 7;

fn prover() -> &'static QneroPrivateBatchProver {
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

fn block() -> &'static common::Block {
    static BLOCK: OnceLock<common::Block> = OnceLock::new();
    BLOCK.get_or_init(|| common::block_with_notes("private-batch", 3))
}

/// One real transfer padded to seven slots. Proved once.
fn batch_of_one() -> &'static (Proof, Proof) {
    static BATCH: OnceLock<(Proof, Proof)> = OnceLock::new();
    BATCH.get_or_init(|| {
        let leaf = block().transfer_proof(0);
        let batch = prover()
            .aggregate(vec![leaf.clone()])
            .expect("one real leaf and six padding slots aggregate");
        (leaf, batch)
    })
}

/// Two real transfers of different notes, padded to seven slots. Proved once.
fn batch_of_two() -> &'static (Vec<Proof>, Proof) {
    static BATCH: OnceLock<(Vec<Proof>, Proof)> = OnceLock::new();
    BATCH.get_or_init(|| {
        let leaves = vec![block().transfer_proof(1), block().transfer_proof(2)];
        let batch = prover()
            .aggregate(leaves.clone())
            .expect("two real leaves aggregate");
        (leaves, batch)
    })
}

/// The verifier a runtime would hold: built from the serialized artifact, held
/// to the private-batch profile, never from a live prover.
fn batch_verifier() -> &'static QneroPrivateBatchVerifier {
    static VERIFIER: OnceLock<QneroPrivateBatchVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        let artifact = serialize_verifier_data(&prover().verifier_data(), "private batch").unwrap();
        QneroPrivateBatchVerifier::from_artifact_bytes(&artifact, NUM_LEAVES)
            .expect("the freshly built artifact passes its own profile")
    })
}

/// Verify a batch proof the way a runtime does: from bytes, through the
/// artifact, reading the public inputs back out.
fn verify_bytes(proof: &Proof) -> PrivateBatchPublicInputs {
    batch_verifier()
        .verify_proof_bytes(&proof.to_bytes())
        .expect("the batch proof verifies against the artifact")
}

fn leaf_slot_of(leaf: &Proof) -> BatchLeafSlot {
    // The two plonky2 crates define distinct proof types over the same field,
    // so a proof crosses the boundary as its public-input slice or as bytes.
    let public = qnero_verifier::parse_public_input_felts(&leaf.public_inputs)
        .expect("the leaf proof's public inputs parse");
    BatchLeafSlot {
        nullifiers: public.nullifiers,
        commitments: public.commitments,
        fee: public.fee,
        ct_digest: public.ct_digest,
    }
}

fn is_zero(digest: &[F; 4]) -> bool {
    digest.iter().all(|limb| limb.to_canonical_u64() == 0)
}

/// Everything a padding slot must look like: no commitments, no fee, no
/// ciphertext digest, and two nullifiers that are neither zero nor the padding
/// leaf's own.
fn assert_padding_slot(slot: &BatchLeafSlot, padding_leaf: &BatchLeafSlot) {
    assert!(
        slot.is_padding(),
        "a padding slot must carry no commitments"
    );
    assert_eq!(slot.fee, F::ZERO, "a padding slot must carry no fee");
    assert!(
        is_zero(&slot.ct_digest),
        "a padding slot must carry no ciphertext digest"
    );
    for (index, nullifier) in slot.nullifiers.iter().enumerate() {
        assert!(
            !is_zero(nullifier),
            "a padding slot's nullifier {index} must not be zero: the chain settles it like any \
             other, and zero is the value it skips"
        );
        assert!(
            !padding_leaf.nullifiers.contains(nullifier),
            "a padding slot published the padding leaf template's own nullifier {index}; the \
             template is a fixed artifact cloned into every empty slot, so its nullifiers must \
             never reach the chain"
        );
    }
}

/// (a) One real leaf and six padding slots aggregate, and the result verifies
/// against the generated verifier artifact.
///
/// This is the shape a wallet submits most often: one transfer, six empty
/// slots. It is also where the padding rule earns its keep, since six of the
/// seven slots hold the same cloned template proof.
#[test]
fn one_real_leaf_and_six_padding_slots_aggregate_and_verify() {
    let (leaf, batch) = batch_of_one();
    let public = verify_bytes(batch);

    let expected = leaf_slot_of(leaf);
    let padding_leaf = leaf_slot_of(common::padding_leaf_proof());

    assert_eq!(public.slots.len(), NUM_LEAVES);
    assert!(!public.is_padding());

    let real: Vec<&BatchLeafSlot> = public
        .slots
        .iter()
        .filter(|slot| !slot.is_padding())
        .collect();
    assert_eq!(real.len(), 1, "exactly one slot holds a real transfer");
    assert_eq!(
        *real[0], expected,
        "the real slot must forward the leaf's two nullifiers, two commitments, fee and \
         ct_digest unchanged"
    );

    for slot in public.slots.iter().filter(|slot| slot.is_padding()) {
        assert_padding_slot(slot, &padding_leaf);
    }

    // Every published nullifier is distinct, padding included, so the chain
    // can settle all 14 by one rule.
    let mut published: Vec<[u64; 4]> = public
        .slots
        .iter()
        .flat_map(|slot| slot.nullifiers.iter())
        .map(|nullifier| core::array::from_fn(|i| nullifier[i].to_canonical_u64()))
        .collect();
    published.sort_unstable();
    let count = published.len();
    published.dedup();
    assert_eq!(
        published.len(),
        count,
        "published nullifiers must be unique"
    );
}

/// (b) Two real leaves spending different notes aggregate, and each leaf's
/// values come out in one slot, in the documented order.
///
/// This is the forwarding contract. A wrapper that carried one nullifier per
/// leaf, which is the shape upstream's private batch has, would pass every
/// other test in this file and silently drop each leaf's `nf_2`, leaving a
/// note spent from input slot 1 unmarked and spendable again.
///
/// Slot order is not asserted: the prover shuffles uniformly, which is what
/// hides where the padding sits, and the circuit picks its block reference by
/// prefix scan so no position means anything.
#[test]
fn two_real_leaves_land_in_the_documented_slots() {
    let (leaves, batch) = batch_of_two();
    let public = verify_bytes(batch);

    let block = block();
    assert_eq!(
        public.block_hash,
        digest_to_felts(&block.header.block_hash()),
        "the batch publishes the block every real leaf is anchored at"
    );
    assert_eq!(
        public.block_number,
        F::from_canonical_u32(common::BLOCK_NUMBER)
    );

    let real: Vec<&BatchLeafSlot> = public
        .slots
        .iter()
        .filter(|slot| !slot.is_padding())
        .collect();
    assert_eq!(real.len(), 2);

    for leaf in leaves {
        let expected = leaf_slot_of(leaf);
        assert!(
            real.iter().any(|slot| **slot == expected),
            "a real leaf's slot is missing from the batch public inputs"
        );
    }

    // The two leaves spend different notes, so all four real nullifiers differ.
    let mut nullifiers: Vec<[u64; 4]> = real
        .iter()
        .flat_map(|slot| slot.nullifiers.iter())
        .map(|nullifier| core::array::from_fn(|i| nullifier[i].to_canonical_u64()))
        .collect();
    assert_eq!(nullifiers.len(), 4);
    nullifiers.sort_unstable();
    nullifiers.dedup();
    assert_eq!(nullifiers.len(), 4);
}

/// (c) A batch proof whose public inputs were edited fails verification.
///
/// The chain reads nullifiers out of the public inputs and settles them, so a
/// proof that could be re-pointed at a different nullifier after the fact
/// would let a settled batch mark the wrong note spent.
#[test]
fn a_tampered_nullifier_fails_verification() {
    let (_, batch) = batch_of_one();

    let mut tampered = batch.clone();
    let index = qnero_circuit::batch_layout::slot_nullifier_index(0, 0);
    tampered.public_inputs[index] += F::ONE;

    assert!(
        batch_verifier()
            .verify_proof_bytes(&tampered.to_bytes())
            .is_err(),
        "a batch proof with an edited nullifier must not verify"
    );
}

/// Two real leaves anchored at different blocks are refused.
///
/// The circuit forces every non-padding slot to agree with the batch's block
/// reference, so such a batch is unprovable; the prover refuses it up front so
/// a wallet does not spend tens of seconds discovering that.
#[test]
fn leaves_from_two_blocks_are_refused() {
    let other = common::block_with_notes("another-block", 1);
    let leaves = vec![block().transfer_proof(0), other.transfer_proof(0)];

    let error = prover()
        .aggregate(leaves)
        .expect_err("two blocks in one batch must be refused");
    assert!(
        error.to_string().contains("different block"),
        "got: {error}"
    );
}

/// The same leaf proof twice is refused.
///
/// Both copies publish the same two nullifiers. The circuit constrains all
/// `2N` real nullifiers pairwise distinct, so the batch is unprovable; without
/// that constraint the chain would settle one nullifier once while the batch
/// carried two commitments' worth of new notes.
#[test]
fn the_same_leaf_proof_twice_is_refused() {
    let leaf = block().transfer_proof(0);
    let error = prover()
        .aggregate(vec![leaf.clone(), leaf])
        .expect_err("a replayed leaf proof must be refused");
    assert!(
        error.to_string().contains("already published"),
        "got: {error}"
    );
}

/// A batch of nothing but padding settles nothing, so the prover refuses to
/// spend a proving window on it. The artifact builder produces exactly such a
/// batch as the public batch's padding template, and it fills the witness
/// directly rather than coming through here.
#[test]
fn an_all_padding_batch_is_refused() {
    let error = prover()
        .aggregate(vec![common::padding_leaf_proof().clone()])
        .expect_err("an all-padding batch must be refused");
    assert!(error.to_string().contains("padding"), "got: {error}");
}

#[test]
fn an_empty_or_oversized_batch_is_refused() {
    assert!(prover().aggregate(Vec::new()).is_err());

    let leaf = block().transfer_proof(0);
    let too_many: Vec<Proof> = (0..NUM_LEAVES + 1).map(|_| leaf.clone()).collect();
    let error = prover()
        .aggregate(too_many)
        .expect_err("more proofs than slots must be refused");
    assert!(error.to_string().contains("slots"), "got: {error}");
}

/// A proof of something else, at the same public-input length, is refused
/// before proving starts.
#[test]
fn a_proof_that_is_not_a_leaf_proof_is_refused() {
    let (_, batch) = batch_of_one();
    let error = prover()
        .aggregate(vec![batch.clone()])
        .expect_err("a batch proof is not a leaf proof");
    assert!(
        format!("{error:#}").contains("public inputs"),
        "got: {error:#}"
    );
}

/// The verifier artifact is only meaningful together with the slot count it
/// was built for, so loading it under another count fails on the
/// public-input length.
#[test]
fn the_artifact_is_refused_under_the_wrong_slot_count() {
    let artifact = serialize_verifier_data(&prover().verifier_data(), "private batch").unwrap();
    let error = QneroPrivateBatchVerifier::from_artifact_bytes(&artifact, NUM_LEAVES - 1)
        .expect_err("the wrong slot count must be refused");
    assert!(error.to_string().contains("public inputs"), "got: {error}");
}

/// An all-padding batch carries the sentinel block hash, which is what the
/// public batch recognises its own padding by. Nothing here proves one; this
/// pins the reading rule against the constant.
#[test]
fn the_padding_sentinel_is_what_marks_an_all_padding_batch() {
    let (_, batch) = batch_of_one();
    let public = parse_private_batch_public_input_felts(&batch.public_inputs, NUM_LEAVES).unwrap();
    let sentinel: [u64; 4] = core::array::from_fn(|i| public.block_hash[i].to_canonical_u64());
    assert_ne!(sentinel, PADDING_BLOCK_HASH);
    assert!(!public.is_padding());
}
