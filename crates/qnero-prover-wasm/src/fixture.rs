//! A synthetic 2-in / 2-out transfer, the shape the prover tests use.
//!
//! This exists because the browser cannot build one. A request names a Merkle
//! path into a tree whose root the header commits to, and both the tree and
//! the root are Poseidon2 over Goldilocks; there is no JS that computes them.
//! So the fixture is generated on this side of the boundary, and the harness
//! asks for it by seed.
//!
//! It is a fixture and nothing else: the notes are invented, the header is
//! invented, and no chain has ever seen either. A wallet builds its request
//! from notes it scanned and a header it fetched. What the fixture guarantees
//! is that the witness is *valid*, so the measurement is of a proof that would
//! settle rather than of a proving run that fails halfway.
//!
//! # Why one real input is a 2-in measurement
//!
//! The fixture fills one input slot with a real note and lets
//! [`crate::request`] fill the second with a randomized dummy, on a three-leaf
//! tree, one level deep at arity 4. The proving cost is the same as a genuine
//! two-note spend against a full tree: both input slots are always present in
//! the circuit, `merkle_root_from_path` evaluates all `MAX_DEPTH = 20` levels
//! for each of them whatever the witness says (`qnero-circuit/src/merkle.rs`),
//! and the witness fills every level for the dummy too. A dummy costs what a
//! real note costs, which is the point: a leaf that proved faster with one
//! input would publish how many notes it spent.

use anyhow::Result;
use qnero_circuit::header::DIGEST_LOGS_SIZE;
use qnero_circuit::merkle::CommitmentTree;
use qnero_notes::{Digest, Note};
use serde_json::json;

/// Build a request for one synthetic transfer.
///
/// `seed_hex` is the sender's spending seed, `recipient_seed_hex` the
/// receiver's. `decoys` is how many other leaves sit in the tree beside the
/// note being spent, which is what sets the tree depth and so the number of
/// Merkle levels the circuit walks; the circuit pads to `MAX_DEPTH` either way,
/// so this does not move the proving cost.
pub fn synthetic_transfer_request(
    seed_hex: &str,
    recipient_seed_hex: &str,
    decoys: usize,
) -> Result<String> {
    let sender = crate::request::spending_key_from_hex(seed_hex)?;
    let recipient = crate::request::spending_key_from_hex(recipient_seed_hex)?;

    let rho = Digest::hash_bytes(&[b"qnero-wasm-fixture/rho", seed_hex.as_bytes()]);
    let r = Digest::hash_bytes(&[b"qnero-wasm-fixture/r", seed_hex.as_bytes()]);
    let value = 1_000u64;
    let note = Note::new(sender.pk(), value, rho, r)?;

    let mut leaves = Vec::with_capacity(decoys + 1);
    for index in 0..decoys {
        leaves.push(Digest::hash_bytes(&[
            b"qnero-wasm-fixture/decoy",
            &(index as u64).to_le_bytes(),
        ]));
    }
    let leaf_index = leaves.len();
    leaves.push(note.commitment());

    let tree = CommitmentTree::new(&leaves, CommitmentTree::depth_for(leaves.len())?)?;
    let path = tree.path(leaf_index)?;

    let siblings: Vec<Vec<String>> = path
        .siblings
        .iter()
        .map(|level| level.iter().map(|sibling| sibling.to_hex()).collect())
        .collect();

    let payment = 900u64;
    let fee = 3u64;
    let change = value - payment - fee;

    let request = json!({
        "seed": seed_hex,
        "anchor": {
            "parent_hash": Digest::hash_bytes(&[b"qnero-wasm-fixture/parent"]).to_hex(),
            "block_number": 77,
            "state_root": Digest::hash_bytes(&[b"qnero-wasm-fixture/state"]).to_hex(),
            "extrinsics_root": Digest::hash_bytes(&[b"qnero-wasm-fixture/extrinsics"]).to_hex(),
            "zk_tree_root": tree.root().to_hex(),
            "digest_logs": hex::encode([0x7Au8; DIGEST_LOGS_SIZE]),
        },
        "tree_depth": tree.depth(),
        "inputs": [{
            "value": value,
            "rho": rho.to_hex(),
            "r": r.to_hex(),
            "path": {
                "siblings": siblings,
                "positions": path.positions,
            },
        }],
        "outputs": [
            {
                "address": recipient.address().encode(),
                "value": payment,
                "memo": "M8",
            },
            {
                "address": sender.address().encode(),
                "value": change,
                "memo": "",
            },
        ],
        "fee": fee,
    });

    Ok(request.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::TransferRequest;

    /// The fixture has to produce a witness that validates, or every
    /// measurement built on it is a measurement of a failure.
    #[test]
    fn the_fixture_builds_a_valid_witness() {
        let json = synthetic_transfer_request(&"03".repeat(32), &"04".repeat(32), 2).unwrap();
        let request: TransferRequest = serde_json::from_str(&json).unwrap();
        let prepared = request.prepare().expect("the fixture witness validates");
        assert_eq!(
            prepared.witness.depth, 1,
            "three leaves is one level of arity 4"
        );
        assert_eq!(prepared.witness.fee, 3);
    }

    /// Both ciphertexts come out at one length, whatever the memos say. An
    /// unpadded pair publishes which of a settlement's two leaves is the
    /// sender's change.
    #[test]
    fn both_output_ciphertexts_are_one_length() {
        let json = synthetic_transfer_request(&"05".repeat(32), &"06".repeat(32), 3).unwrap();
        let request: TransferRequest = serde_json::from_str(&json).unwrap();
        let prepared = request.prepare().unwrap();
        let outputs = prepared.encrypt_outputs().unwrap();
        assert_eq!(
            outputs[0].ciphertext.len(),
            outputs[1].ciphertext.len(),
            "a padded pair is two ciphertexts of one size"
        );
        assert_eq!(
            outputs[0].ciphertext.len(),
            qnero_notes::CIPHERTEXT_FIXED_BYTES + qnero_notes::MEMO_BYTES
        );
    }
}
