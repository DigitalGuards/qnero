//! The native side of the M8 measurement.
//!
//! Same crate, same request JSON and same code path as the browser run, on
//! this machine's own CPU, so the two columns in `docs/BENCH.md` differ in the
//! target and in nothing else.
//!
//! ```text
//! RAYON_NUM_THREADS=1 nice -n 19 cargo test -j 2 --release \
//!   -p qnero-prover-wasm --test native_bench -- --ignored --nocapture
//! ```
//!
//! Ignored by default: a six-slot private batch is tens of seconds single
//! threaded, three times over, and that does not belong in a gate. `parallel`
//! is off everywhere in this crate's tree, so `RAYON_NUM_THREADS` changes
//! nothing here and is set only to say so.

use qnero_prover_wasm::fixture::synthetic_transfer_request;
use qnero_prover_wasm::prove::{
    build_from_source, prove_transfer, prove_zk_leaf, CHAIN_NUM_LEAVES,
};
use qnero_prover_wasm::request::TransferRequest;

const RUNS: usize = 3;

fn request(tag: u8) -> TransferRequest {
    let json = synthetic_transfer_request(
        &format!("{:02x}", tag).repeat(32),
        &format!("{:02x}", tag.wrapping_add(1)).repeat(32),
        2,
    )
    .expect("the fixture builds");
    serde_json::from_str(&json).expect("the fixture parses")
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a duration"));
    values[values.len() / 2]
}

fn line(label: &str, values: &[f64]) {
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    println!(
        "{label}: median {:.1} ms, min {:.1} ms, max {:.1} ms, runs {:?}",
        median(values.to_vec()),
        min,
        max,
        values
            .iter()
            .map(|v| (v * 10.0).round() / 10.0)
            .collect::<Vec<_>>()
    );
}

/// Leaf and private batch at the chain's `N = 6`, three runs, single threaded.
#[test]
#[ignore = "tens of seconds per run; this is the M8 measurement"]
fn native_single_thread_at_the_chain_slot_count() {
    println!("--- qnero-prover-wasm native, N = {CHAIN_NUM_LEAVES}, single threaded ---");

    let built = build_from_source(CHAIN_NUM_LEAVES).expect("both circuits build");
    println!(
        "circuit build (leaf + private batch, one process): {:.1} ms, leaf degree_bits {}, \
         private batch degree_bits {}",
        built.build.millis, built.build.leaf_degree_bits, built.build.private_batch_degree_bits
    );

    let mut leaf = Vec::with_capacity(RUNS);
    let mut batch = Vec::with_capacity(RUNS);
    let mut verify = Vec::with_capacity(RUNS);
    let mut proof_bytes = 0usize;

    for run in 0..RUNS {
        let submission =
            prove_transfer(&built.prover, &request(0x30 + run as u8)).expect("the transfer proves");
        for phase in &submission.report.phases {
            match phase.phase {
                "leaf_prove" => leaf.push(phase.millis),
                "private_batch_prove" => batch.push(phase.millis),
                "private_batch_verify" => verify.push(phase.millis),
                other => panic!("unexpected phase {other}"),
            }
        }
        proof_bytes = submission.report.proof_bytes;
    }

    line("leaf prove (non-ZK)", &leaf);
    line("private batch prove", &batch);
    line("private batch verify", &verify);
    println!("private batch proof: {proof_bytes} bytes");
    assert!(proof_bytes < 512 * 1024, "MAX_PROOF_BYTES is 512 KiB");
}

/// The zero-knowledge leaf on its own: what a phone would hand a delegated
/// batcher.
#[test]
#[ignore = "builds a second leaf circuit per run; this is the M8 measurement"]
fn native_zero_knowledge_leaf() {
    println!("--- qnero-prover-wasm native, zero-knowledge leaf, single threaded ---");

    let mut build = Vec::with_capacity(RUNS);
    let mut prove = Vec::with_capacity(RUNS);
    let mut proof_bytes = 0usize;
    let mut degree_bits = 0usize;

    for run in 0..RUNS {
        let report = prove_zk_leaf(&request(0x40 + run as u8)).expect("the ZK leaf proves");
        assert!(report.zero_knowledge, "this is the blinded configuration");
        build.push(report.build_millis);
        prove.push(report.prove_millis);
        proof_bytes = report.proof_bytes;
        degree_bits = report.degree_bits;
    }

    line("ZK leaf build", &build);
    line("ZK leaf prove", &prove);
    println!("ZK leaf proof: {proof_bytes} bytes, degree_bits {degree_bits}");
}
