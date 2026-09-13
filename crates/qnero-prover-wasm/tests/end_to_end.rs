//! The browser path, run natively: fixture, request, proof, verify.
//!
//! Two leaf slots, which is the cheapest batch that exercises the shape. The
//! chain's six is what `native_bench.rs` measures, under `--ignored`, because a
//! six-slot private batch is tens of seconds single threaded and that does not
//! belong in a default gate.

use qnero_prover_wasm::fixture::synthetic_transfer_request;
use qnero_prover_wasm::prove::{build_from_source, prove_transfer, verify};
use qnero_prover_wasm::request::TransferRequest;

const NUM_LEAVES: usize = 2;

#[test]
fn a_browser_request_proves_and_verifies() {
    let json = synthetic_transfer_request(&"11".repeat(32), &"12".repeat(32), 2).unwrap();
    let request: TransferRequest = serde_json::from_str(&json).unwrap();

    let built = build_from_source(NUM_LEAVES).expect("both circuits build");
    let submission = prove_transfer(&built.prover, &request).expect("the transfer proves");

    assert_eq!(submission.report.num_leaves, NUM_LEAVES);
    assert_eq!(submission.proof.len(), submission.report.proof_bytes);
    assert!(
        submission.proof.len() < 512 * 1024,
        "a settlement blob over MAX_PROOF_BYTES is refused before it is parsed"
    );
    assert_eq!(
        submission.ciphertexts[0].len(),
        submission.ciphertexts[1].len(),
        "a padded pair is two ciphertexts of one size"
    );

    // The proof the caller gets back is the one the verifier accepts.
    verify(&built.prover, &submission.proof).expect("the submitted bytes verify");

    // And a proof with one byte changed is not.
    let mut tampered = submission.proof.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(verify(&built.prover, &tampered).is_err());
}

/// The recipient reads the note out of the ciphertext the submission carried,
/// and it opens the commitment the proof published. That is the round trip a
/// payment actually needs, and nothing in the proving path checks it.
#[test]
fn the_recipient_decrypts_the_output_this_submission_published() {
    let sender = "21".repeat(32);
    let recipient = "22".repeat(32);
    let json = synthetic_transfer_request(&sender, &recipient, 2).unwrap();
    let request: TransferRequest = serde_json::from_str(&json).unwrap();

    let built = build_from_source(NUM_LEAVES).expect("both circuits build");
    let submission = prove_transfer(&built.prover, &request).expect("the transfer proves");

    let payment_commitment = &submission.report.public_inputs.commitments[0];
    let decrypted = qnero_prover_wasm::scan::decrypt_note_json(
        &recipient,
        &submission.ciphertexts[0],
        payment_commitment,
    )
    .expect("the recipient reads their own output");

    let note: serde_json::Value = serde_json::from_str(&decrypted).unwrap();
    assert_eq!(note["value"], 900);
    assert_eq!(note["memo"], "M8");
    assert_eq!(note["commitment"], payment_commitment.as_str());
}

/// A request that names a different `N` from the chain's produces a proof the
/// runtime's embedded verifier cannot read, and it says so only after the full
/// proving cost. The constant is copied into this crate, so the copy is held
/// to the builder's definition rather than to a literal that a later `N` would
/// leave behind.
#[test]
fn the_chain_slot_count_is_the_builders() {
    assert_eq!(
        qnero_prover_wasm::CHAIN_NUM_LEAVES,
        qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS
    );
}
