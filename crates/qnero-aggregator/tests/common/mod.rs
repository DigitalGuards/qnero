//! Shared fixtures for the batch tests.
//!
//! Everything here runs in release: proving a leaf in a debug build takes
//! minutes, and a batch takes far longer than that.
//!
//! The leaf circuit is built once per test binary and shared, because every
//! test needs leaf proofs and the build is not what any of them is testing.

#![allow(dead_code)]

use std::sync::OnceLock;

use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;
use qnero_aggregator::Proof;
use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::CommitmentTree;
use qnero_circuit::witness::{fill_witness, InputNote, OutputNote, SpendWitness};
use qnero_circuit::{C, D, F};
use qnero_notes::keys::DerivedKeys;
use qnero_notes::{Digest, Note, SpendingKey};

pub const BLOCK_NUMBER: u32 = 4242;

pub fn digest(tag: &str) -> Digest {
    Digest::hash_bytes(&[b"qnero-batch-test/", tag.as_bytes()])
}

pub fn sender_keys() -> DerivedKeys {
    SpendingKey::from_bytes([11u8; 32]).derived()
}

pub fn recipient_pk() -> Digest {
    SpendingKey::from_bytes([13u8; 32]).pk()
}

/// The leaf circuit, built once for the whole test binary.
pub fn leaf_circuit() -> &'static (SpendTargets, CircuitData<F, C, D>) {
    static CIRCUIT: OnceLock<(SpendTargets, CircuitData<F, C, D>)> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        let circuit = QneroSpendCircuit::default();
        let targets = circuit.targets();
        (targets, circuit.build())
    })
}

pub fn prove_leaf(witness: &SpendWitness) -> Proof {
    let (targets, data) = leaf_circuit();
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, witness, targets).expect("the leaf witness fills");
    data.prove(pw).expect("the leaf proves")
}

/// The canonical padding leaf proof, built once for the whole test binary.
pub fn padding_leaf_proof() -> &'static Proof {
    static PROOF: OnceLock<Proof> = OnceLock::new();
    PROOF.get_or_init(|| {
        let (targets, data) = leaf_circuit();
        qnero_aggregator::generate_padding_leaf_proof(data, targets)
            .expect("the padding leaf proves")
    })
}

/// A block whose commitment tree holds `count` notes owned by [`sender_keys`],
/// one per transfer, plus decoys.
pub struct Block {
    pub header: HeaderInputs,
    pub tree: CommitmentTree,
    pub notes: Vec<Note>,
    pub indices: Vec<usize>,
}

/// Build a block with `count` spendable notes. `tag` separates two blocks that
/// must differ.
pub fn block_with_notes(tag: &str, count: usize) -> Block {
    let keys = sender_keys();
    let mut leaves = Vec::new();
    let mut notes = Vec::new();
    let mut indices = Vec::new();
    for index in 0..count {
        leaves.push(digest(&format!("{tag}-decoy-{index}")));
        let note = Note::new(
            keys.pk(),
            500 + index as u64,
            digest(&format!("{tag}-rho-{index}")),
            digest(&format!("{tag}-r-{index}")),
        )
        .expect("the note value is in range");
        indices.push(leaves.len());
        leaves.push(note.commitment());
        notes.push(note);
    }
    leaves.push(digest(&format!("{tag}-decoy-tail")));

    let depth = CommitmentTree::depth_for(leaves.len()).expect("the tree fits");
    let tree = CommitmentTree::new(&leaves, depth).expect("the tree builds");
    let header = HeaderInputs::new(
        digest(&format!("{tag}-parent")),
        BLOCK_NUMBER,
        digest(&format!("{tag}-state-root")).to_bytes(),
        digest(&format!("{tag}-extrinsics-root")).to_bytes(),
        tree.root(),
        &[0xAB; DIGEST_LOGS_SIZE],
    )
    .expect("the header digest logs are the right length");

    Block {
        header,
        tree,
        notes,
        indices,
    }
}

impl Block {
    /// A transfer spending note `index` of this block: one real input, one
    /// fresh dummy, two outputs and a fee.
    pub fn transfer(&self, index: usize) -> SpendWitness {
        let keys = sender_keys();
        let note = &self.notes[index];
        let path = self
            .tree
            .path(self.indices[index])
            .expect("the note is in the tree");
        let fee = 1 + index as u64;
        let paid = note.value - fee - 10;

        SpendWitness {
            header: self.header.clone(),
            depth: self.tree.depth(),
            inputs: [
                InputNote::real(&keys, note, path).expect("the keys own the note"),
                InputNote::dummy_random(&mut rand::rng(), &keys, self.tree.depth()),
            ],
            outputs: [
                OutputNote::new(recipient_pk(), paid, digest(&format!("out-r-{index}"))),
                OutputNote::new(keys.pk(), 10, digest(&format!("change-r-{index}"))),
            ],
            fee,
            ct_digest: digest(&format!("ciphertexts-{index}")),
        }
    }

    /// The proof of [`Block::transfer`].
    pub fn transfer_proof(&self, index: usize) -> Proof {
        prove_leaf(&self.transfer(index))
    }
}
