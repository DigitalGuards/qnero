//! The private batch's cost at the chain default, measured once.
//!
//! Ignored by default: it builds and proves a 7-slot batch, which is tens of
//! seconds. Run it deliberately, with the thread pool bounded:
//!
//! ```text
//! RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-aggregator \
//!     --features parallel --test bench -- --ignored --nocapture
//! ```
//!
//! Without the `parallel` feature plonky2 is single threaded and
//! `RAYON_NUM_THREADS` does nothing, which is the default on purpose: a wallet
//! should not saturate a machine unasked. Both numbers are worth having, so
//! the output names which one it measured.
//!
//! Proving time is reported as a mean over several proofs. The FRI challenge
//! carries 16 grinding bits and the search for them is a geometric random
//! variable seeded by the transcript, so a single warm number compared against
//! another single warm number measures grinding luck. At this circuit size the
//! grind is a small share of the total, which is the opposite of the leaf,
//! where it dominates.

mod common;

use std::time::{Duration, Instant};

use qnero_aggregator::artifacts::serialize_verifier_data;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_circuit::config::qnero_private_batch_circuit_config;
use qnero_verifier::QneroPrivateBatchVerifier;

/// The chain default.
const NUM_LEAVES: usize = 7;

/// Enough samples to report a mean without turning the run into a bench suite.
const SAMPLES: usize = 3;

#[test]
#[ignore]
fn private_batch_cost_at_the_chain_default() {
    let block = common::block_with_notes("bench", SAMPLES);
    let (_, leaf_data) = common::leaf_circuit();

    let start = Instant::now();
    let (prover, metrics) = QneroPrivateBatchProver::new_with_metrics(
        qnero_private_batch_circuit_config(),
        leaf_data.common.clone(),
        &leaf_data.verifier_only,
        NUM_LEAVES,
        common::padding_leaf_proof().clone(),
    )
    .expect("the private batch prover builds");
    let build = start.elapsed();

    // One real transfer and six padding slots: the shape a wallet submits most
    // often, and the most expensive one per settled transfer.
    let mut timings = Vec::with_capacity(SAMPLES);
    let mut proof = None;
    for sample in 0..SAMPLES {
        let leaf = block.transfer_proof(sample);
        let start = Instant::now();
        let produced = prover.aggregate(vec![leaf]).expect("the batch proves");
        timings.push(start.elapsed());
        proof = Some(produced);
    }
    let proof = proof.expect("at least one sample");
    let bytes = proof.to_bytes();

    let artifact = serialize_verifier_data(&prover.verifier_data(), "private batch").unwrap();
    let verifier = QneroPrivateBatchVerifier::from_artifact_bytes(&artifact, NUM_LEAVES).unwrap();
    let start = Instant::now();
    verifier
        .verify_proof_bytes(&bytes)
        .expect("the batch verifies");
    let verify = start.elapsed();

    timings.sort_unstable();
    let total: Duration = timings.iter().sum();
    let mean = total / SAMPLES as u32;

    println!("qnero private batch (N = {NUM_LEAVES} leaf slots, 1 real and 6 padding)");
    println!("  parallel             : {}", cfg!(feature = "parallel"));
    println!(
        "  RAYON_NUM_THREADS    : {}",
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| String::from("unset"))
    );
    println!("  leaf degree_bits     : {}", metrics.leaf_degree_bits);
    println!("  gates before padding : {}", metrics.unpadded_gates);
    println!("  degree_bits          : {}", metrics.degree_bits);
    println!("  padded gates         : {}", metrics.padded_gates);
    println!("  public inputs        : {}", proof.public_inputs.len());
    println!("  zero knowledge       : true");
    println!("  build                : {build:?}");
    println!("  prove, mean of {SAMPLES}     : {mean:?}");
    println!("  prove, min           : {:?}", timings[0]);
    println!("  prove, max           : {:?}", timings[SAMPLES - 1]);
    println!("  verify               : {verify:?}");
    println!("  proof bytes          : {}", bytes.len());
    println!("  verifier artifact    : {} bytes", artifact.len());
}
