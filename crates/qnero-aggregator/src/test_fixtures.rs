//! Leaf fixtures shared by this crate's unit tests.
//!
//! Building the leaf circuit and proving a leaf is the setup cost of almost
//! every test here, and none of them is testing that. One `OnceLock` for the
//! whole lib test binary, and one place the witness shape lives.

use std::sync::OnceLock;

use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;

use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::CommitmentTree;
use qnero_circuit::witness::{fill_witness, InputNote, OutputNote, SpendWitness};
use qnero_circuit::{C, D, F};
use qnero_note_core::{DerivedKeys, Digest, Note};

use crate::Proof;

/// The leaf circuit, built once for the whole test binary.
pub fn leaf_circuit() -> &'static (SpendTargets, CircuitData<F, C, D>) {
    static CIRCUIT: OnceLock<(SpendTargets, CircuitData<F, C, D>)> = OnceLock::new();
    CIRCUIT.get_or_init(|| {
        let circuit = QneroSpendCircuit::default();
        let targets = circuit.targets();
        (targets, circuit.build())
    })
}

fn digest(label: &str, tag: &str) -> Digest {
    Digest::hash_bytes(&[
        b"qnero-aggregator-fixture/",
        label.as_bytes(),
        tag.as_bytes(),
    ])
}

/// A real transfer: one note spent in a block named by `tag`, one fresh dummy
/// input, two outputs and a fee.
pub fn leaf_witness(tag: &str) -> SpendWitness {
    let keys = DerivedKeys {
        ask: Digest::hash_bytes(&[b"qnero-aggregator-fixture/ask"]),
        nk: Digest::hash_bytes(&[b"qnero-aggregator-fixture/nk"]),
    };
    let note = Note::new(keys.pk(), 100, digest("rho", tag), digest("r", tag))
        .expect("the note value is in range");
    let leaves = [digest("decoy", tag), note.commitment()];
    let tree = CommitmentTree::new(&leaves, 1).expect("the tree builds");
    let header = HeaderInputs::new(
        digest("parent", tag),
        12,
        [0x31; Digest::LEN],
        [0x42; Digest::LEN],
        tree.root(),
        &[0u8; DIGEST_LOGS_SIZE],
    )
    .expect("the digest logs are the right length");

    SpendWitness {
        header,
        depth: tree.depth(),
        inputs: [
            InputNote::real(&keys, &note, tree.path(1).expect("the note is in the tree"))
                .expect("the keys own the note"),
            InputNote::dummy(
                &keys,
                digest("dummy-rho", tag),
                digest("dummy-r", tag),
                tree.depth(),
            ),
        ],
        outputs: [
            OutputNote::new(keys.pk(), 90, digest("out-r", tag)),
            OutputNote::new(keys.pk(), 5, digest("change-r", tag)),
        ],
        fee: 5,
        ct_digest: digest("ct", tag),
    }
}

/// The proof of [`leaf_witness`].
pub fn leaf_proof(tag: &str) -> Proof {
    let (targets, data) = leaf_circuit();
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, &leaf_witness(tag), targets).expect("the leaf witness fills");
    data.prove(pw).expect("the leaf proves")
}
