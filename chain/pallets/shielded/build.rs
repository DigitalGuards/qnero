//! Build script for `pallet-shielded`.
//!
//! Generates the Qnero circuit artifact set and leaves it in `OUT_DIR` for
//! `include_bytes!`, so the verifier a runtime settles against is always the
//! one the circuit crates in this tree produce. Nothing binary is committed.
//!
//! Two things here are load bearing.
//!
//! The artifacts go into a **dedicated subdirectory** of `OUT_DIR`, never
//! `OUT_DIR` itself: `generate_all_artifacts` stages the set in a hidden
//! sibling and swaps it in by rename, which renames the target directory away
//! and replaces it wholesale. Pointed at `OUT_DIR` it would delete everything
//! else this build produced.
//!
//! And both sizing knobs are declared with `cargo:rerun-if-env-changed`.
//! Without that, Cargo reuses a previous `OUT_DIR` after one of the vars is
//! unset and silently embeds a verifier built for other dimensions, which
//! surfaces much later as a public-input length failure.

use std::{env, path::Path, time::Instant};

/// The dimensions, read from the circuit builder so one definition serves both.
///
/// Six leaf slots per private batch, because M3 measured that seven recursive
/// verifiers cross a degree boundary: blinding adds about 9000 rows, so a batch
/// fits `degree_bits = 15` only below about 23700 gates and seven verifiers are
/// 24324. Six fits, seven pays about 2x in wallet proving time and about 2x in
/// memory (2.1 GiB peak against roughly half that) for one more slot per batch.
/// Fifty-three private batches per public batch is an aggregator-side cost,
/// paid on a server, and a larger batch amortizes the proving cost over more
/// settlements. `docs/BENCH.md` carries the measurements.
///
/// These are the builder's own defaults on purpose. A wallet or an aggregator
/// that generates its artifact set with no `QNERO_NUM_*` set gets whatever the
/// builder defaults to, and a set built at other dimensions produces proofs
/// whose public-input length the chain's embedded verifier refuses. One
/// definition is what keeps the two ends on the same number.
use qnero_circuit_builder::{DEFAULT_NUM_LEAF_PROOFS, DEFAULT_NUM_PRIVATE_BATCH_PROOFS};

fn main() {
	println!("cargo:rerun-if-env-changed=QNERO_NUM_LEAF_PROOFS");
	println!("cargo:rerun-if-env-changed=QNERO_NUM_PRIVATE_BATCH_PROOFS");

	let num_leaf_proofs: usize = env::var("QNERO_NUM_LEAF_PROOFS")
		.map(|v| v.parse().expect("QNERO_NUM_LEAF_PROOFS must be a usize"))
		.unwrap_or(DEFAULT_NUM_LEAF_PROOFS);
	let num_private_batch_proofs: usize = env::var("QNERO_NUM_PRIVATE_BATCH_PROOFS")
		.map(|v| v.parse().expect("QNERO_NUM_PRIVATE_BATCH_PROOFS must be a usize"))
		.unwrap_or(DEFAULT_NUM_PRIVATE_BATCH_PROOFS);

	let out_dir = env::var("OUT_DIR").expect("OUT_DIR is set for a build script");
	let artifacts = Path::new(&out_dir).join("qnero-artifacts");

	println!(
		"cargo:warning=[pallet-shielded] generating circuit artifacts (leaf slots {num_leaf_proofs}, private batches per public batch {num_private_batch_proofs})"
	);
	let start = Instant::now();

	// `include_padding_batch = false`: the all-padding private-batch proof is
	// an input a public-batch *prover* needs, and proving it costs a full
	// recursive run. A runtime only verifies.
	qnero_circuit_builder::generate_all_artifacts(
		&artifacts,
		num_leaf_proofs,
		Some(num_private_batch_proofs),
		false,
	)
	.expect("failed to generate the Qnero circuit artifacts");

	println!(
		"cargo:warning=[pallet-shielded] circuit artifacts generated in {:.1}s",
		start.elapsed().as_secs_f64()
	);
}
