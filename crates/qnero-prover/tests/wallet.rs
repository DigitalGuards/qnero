//! The wallet's path from notes to a submittable transaction.
//!
//! Two slots rather than the chain default, because this test is about the
//! API's shape and not about batch size.

use plonky2::field::types::PrimeField64;
use qnero_aggregator::artifacts::serialize_verifier_data;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::CommitmentTree;
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{Digest, Note, SpendingKey};
use qnero_prover::WalletProver;
use qnero_verifier::QneroPrivateBatchVerifier;

const NUM_LEAVES: usize = 2;

fn digest(tag: &str) -> Digest {
    Digest::hash_bytes(&[b"qnero-wallet-test/", tag.as_bytes()])
}

/// One transfer, built the way a wallet builds one: from `qnero-notes` types
/// and a Merkle path out of the chain's tree.
fn transfer() -> SpendWitness {
    let keys = SpendingKey::from_bytes([3u8; 32]).derived();
    let recipient = SpendingKey::from_bytes([4u8; 32]).pk();
    let note = Note::new(keys.pk(), 1_000, digest("rho"), digest("r")).unwrap();

    let leaves = [digest("decoy"), note.commitment(), digest("decoy-2")];
    let tree =
        CommitmentTree::new(&leaves, CommitmentTree::depth_for(leaves.len()).unwrap()).unwrap();
    let header = HeaderInputs::new(
        digest("parent"),
        77,
        digest("state-root").to_bytes(),
        digest("extrinsics-root").to_bytes(),
        tree.root(),
        &[0x7A; DIGEST_LOGS_SIZE],
    )
    .unwrap();

    SpendWitness {
        header,
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, tree.path(1).unwrap()).unwrap(),
            InputNote::dummy_random(&mut rand::rng(), &keys, tree.depth()),
        ],
        outputs: [
            OutputNote::new(recipient, 900, digest("out-r")),
            OutputNote::new(keys.pk(), 97, digest("change-r")),
        ],
        fee: 3,
        ct_digest: digest("ciphertexts"),
    }
}

/// A wallet builds its provers once, proves a transfer, and the bytes it would
/// submit verify against the batch verifier a runtime holds.
///
/// The leaf proof never leaves [`WalletProver`]: it is not zero knowledge, and
/// the private batch is the transaction.
#[test]
fn a_wallet_proves_a_submission_that_verifies() {
    let wallet = WalletProver::new(NUM_LEAVES).expect("the wallet prover builds");
    assert_eq!(wallet.num_leaves(), NUM_LEAVES);

    let witness = transfer();
    let expected_fee = witness.fee;
    let expected_nullifiers = [witness.inputs[0].nullifier(), witness.inputs[1].nullifier()];
    let expected_commitments = [witness.output_commitment(0), witness.output_commitment(1)];

    let bytes = wallet
        .prove_submission_bytes(vec![witness])
        .expect("the submission proves");

    let artifact = serialize_verifier_data(&wallet.batch_verifier_data(), "private batch").unwrap();
    let verifier = QneroPrivateBatchVerifier::from_artifact_bytes(&artifact, NUM_LEAVES).unwrap();
    let public = verifier
        .verify_proof_bytes(&bytes)
        .expect("what the wallet submits verifies");

    let real: Vec<_> = public
        .slots
        .iter()
        .filter(|slot| !slot.is_padding())
        .collect();
    assert_eq!(real.len(), 1, "one transfer, one real slot");
    assert_eq!(real[0].fee.to_canonical_u64(), expected_fee);
    for (index, nullifier) in expected_nullifiers.iter().enumerate() {
        let published: [u64; 4] =
            core::array::from_fn(|limb| real[0].nullifiers[index][limb].to_canonical_u64());
        let expected: [u64; 4] =
            core::array::from_fn(|limb| nullifier.felts()[limb].as_canonical_u64());
        assert_eq!(
            published, expected,
            "the batch must publish both of the leaf's nullifiers"
        );
    }
    for (index, commitment) in expected_commitments.iter().enumerate() {
        let published: [u64; 4] =
            core::array::from_fn(|limb| real[0].commitments[index][limb].to_canonical_u64());
        let expected: [u64; 4] =
            core::array::from_fn(|limb| commitment.felts()[limb].as_canonical_u64());
        assert_eq!(published, expected);
    }
}

/// More transfers than slots is a caller bug, and an empty submission is one
/// too: both are refused before any proving starts.
#[test]
fn a_submission_must_fit_the_batch() {
    let wallet = WalletProver::new(NUM_LEAVES).expect("the wallet prover builds");
    assert!(wallet.prove_submission(Vec::new()).is_err());

    let too_many: Vec<SpendWitness> = (0..NUM_LEAVES + 1).map(|_| transfer()).collect();
    let error = wallet
        .prove_submission(too_many)
        .expect_err("more transfers than slots must be refused");
    assert!(error.to_string().contains("slots"), "got: {error}");
}
