//! Building the two circuits once, and proving one submission per payment.
//!
//! The staging is the same one `qnero-wallet` uses, and it is deliberate: a
//! witness first with a placeholder `ct_digest`, then the ciphertexts (whose
//! `rho` the witness derives from its own nullifiers), then the digest over
//! them, then the proof. Nothing is proved in between.
//!
//! # What does not cross the boundary
//!
//! The leaf proof. It is built with `standard_recursion_config`, which does
//! not blind, and its FRI openings leak the structure of the notes it spends.
//! [`prove_transfer`] proves the leaf and aggregates it in one call, and the
//! only thing that reaches JS is the private-batch proof, which is the
//! transaction. There is no entry point here that returns leaf bytes.

use anyhow::{Context, Result};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qnero_circuit::chain::ct_digest;
use qnero_circuit::{C, D, F};
use qnero_notes::Digest;
use qnero_prover::WalletProver;
use serde::Serialize;

use crate::clock::timed;
use crate::memory::{self, MemorySpan};
use crate::request::{SubmissionPublicInputs, TransferRequest};

/// The chain's leaf slots per private batch.
///
/// `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS` is the definition, and that
/// crate is a `std::fs` staging tool this module must not link, so the number
/// is copied here and `the_chain_default_is_the_builders_default` holds the
/// copy to the definition. That test reaches the builder through a
/// dev-dependency, which never enters the cdylib and never appears in
/// `cargo tree -e normal`, so the copy is checked without linking the tool. A
/// set built at another `N` produces proofs whose public-input length the
/// runtime's embedded verifier cannot read, and the rejection arrives only
/// after the full proving cost has been paid.
pub const CHAIN_NUM_LEAVES: usize = 6;

/// Timings and memory for one call, in the shape the harness prints.
#[derive(Debug, Serialize)]
pub struct PhaseReport {
    pub phase: &'static str,
    pub millis: f64,
    pub memory: MemorySpan,
}

/// What one submission produced, minus the bytes themselves.
#[derive(Debug, Serialize)]
pub struct SubmissionReport {
    pub num_leaves: usize,
    pub proof_bytes: usize,
    pub ciphertext_bytes: [usize; 2],
    pub public_inputs: SubmissionPublicInputs,
    pub phases: Vec<PhaseReport>,
    /// The module's high-water mark once this call finished. It counts every
    /// circuit already resident, so it sizes a worker rather than this call.
    pub peak_linear_memory_bytes_since_init: usize,
    /// What this call grew linear memory by, over what it found on entry.
    pub linear_memory_growth_bytes: usize,
}

/// What building the circuits cost, and the dimensions they came out at.
#[derive(Debug, Serialize)]
pub struct BuildReport {
    pub phase: &'static str,
    pub millis: f64,
    pub memory: MemorySpan,
    /// The non-ZK leaf's degree, a published parameter a verifier holds an
    /// artifact to.
    pub leaf_degree_bits: usize,
    /// The private batch's degree, read off the circuit that was just built.
    /// 15 at the chain's `N = 6`; seven recursive verifiers do not fit it,
    /// which is the whole argument for six.
    pub private_batch_degree_bits: usize,
}

/// A built prover, with what it cost to build.
pub struct BuiltProver {
    pub prover: WalletProver,
    pub build: BuildReport,
}

fn build_report(
    prover: &WalletProver,
    phase: &'static str,
    millis: f64,
    memory: MemorySpan,
) -> BuildReport {
    BuildReport {
        phase,
        millis,
        memory,
        leaf_degree_bits: qnero_circuit::params::LEAF_DEGREE_BITS,
        private_batch_degree_bits: prover.batch_verifier_data().common.degree_bits(),
    }
}

/// Build both circuits from source, proving the padding leaf on the way.
///
/// Reads nothing. Every circuit is a function of the compiled code, which is
/// what makes a poisoned artifact a non-issue at this layer.
pub fn build_from_source(num_leaves: usize) -> Result<BuiltProver> {
    let before = MemorySpan::start();
    let (prover, millis) = timed(|| WalletProver::new(num_leaves));
    let prover = prover.context("failed to build the wallet prover from source")?;
    let build = build_report(
        &prover,
        "circuit_build_from_source",
        millis,
        MemorySpan::end(before),
    );
    Ok(BuiltProver { prover, build })
}

/// Build both circuits from a published artifact set.
///
/// The leaf circuit is rebuilt from source either way: the artifact set's
/// `leaf_verifier.bin` is pinned to that rebuild by raw bytes and the rebuild
/// is what gets baked in, so a substituted copy cannot reach the circuit. What
/// the bytes save is proving the padding leaf, which is one leaf prove.
///
/// These are the bytes half of the loaders. The directory half goes through
/// `std::fs`, which compiles for wasm32 and fails at runtime with an io error,
/// so it must never be called here.
pub fn build_from_artifacts(
    leaf_verifier: &[u8],
    padding_leaf_proof: &[u8],
    num_leaves: usize,
) -> Result<BuiltProver> {
    let before = MemorySpan::start();
    let (prover, millis) =
        timed(|| WalletProver::from_artifact_bytes(leaf_verifier, padding_leaf_proof, num_leaves));
    let prover = prover.context("failed to build the wallet prover from the artifact set")?;
    let build = build_report(
        &prover,
        "circuit_build_from_artifacts",
        millis,
        MemorySpan::end(before),
    );
    Ok(BuiltProver { prover, build })
}

/// What a browser wallet submits: the proof and the two ciphertexts.
pub struct Submission {
    pub proof: Vec<u8>,
    pub ciphertexts: [Vec<u8>; 2],
    pub report: SubmissionReport,
}

/// Prove one transfer end to end.
///
/// Leaf, then aggregate, then verify the wallet's own proof before it goes
/// anywhere. Verifying costs milliseconds and turns a wallet-side mistake into
/// a local error; the pool refuses a bad settlement without saying which public
/// input was wrong.
pub fn prove_transfer(prover: &WalletProver, request: &TransferRequest) -> Result<Submission> {
    // The memory this call found. What it grows from here is the only part of
    // the high-water mark this call is responsible for.
    let entry = MemorySpan::start();
    let mut prepared = request.prepare()?;

    let [first, second] = prepared.encrypt_outputs()?;
    let ciphertexts = [first.ciphertext, second.ciphertext];
    // `ct_1` belongs to `cm_out_1`, and `ct_digest` length-prefixes each
    // ciphertext under a count, so the order is part of the rule. One
    // implementation, shared with the pallet.
    let digest = ct_digest(&[&ciphertexts[0], &ciphertexts[1]]);
    prepared.witness.ct_digest = Digest::from_bytes(&digest)
        .map_err(|_| anyhow::anyhow!("ct_digest is not a canonical digest"))?;
    prepared.witness.validate()?;

    let mut phases = Vec::new();

    // The leaf proof lives in this scope and dies in it.
    let before = MemorySpan::start();
    let (leaf, millis) = timed(|| prover.prove_leaf(&prepared.witness));
    let leaf = leaf?;
    phases.push(PhaseReport {
        phase: "leaf_prove",
        millis,
        memory: MemorySpan::end(before),
    });

    let before = MemorySpan::start();
    let (batch, millis) = timed(|| prover.aggregate(vec![leaf]));
    let batch = batch.context("failed to prove the private batch")?;
    phases.push(PhaseReport {
        phase: "private_batch_prove",
        millis,
        memory: MemorySpan::end(before),
    });

    // Both copies are made before the clock starts. `verify` consumes the
    // proof and the proof is needed afterwards for its bytes, and
    // `batch_verifier_data` clones the common circuit data on every call, so
    // leaving either inside the timed region reports a deep copy of 150908
    // bytes as part of a stage named for the verify. Measured, that copy was
    // about a third of the wasm figure.
    let verifier = prover.batch_verifier_data();
    let to_verify = batch.clone();
    let before = MemorySpan::start();
    let (verified, millis) = timed(|| verifier.verify(to_verify));
    verified
        .map_err(|_| anyhow::anyhow!("this wallet's own private-batch proof does not verify"))?;
    phases.push(PhaseReport {
        phase: "private_batch_verify",
        millis,
        memory: MemorySpan::end(before),
    });

    let proof = batch.to_bytes();
    let call = memory::record_call(entry);
    let report = SubmissionReport {
        num_leaves: prover.num_leaves(),
        proof_bytes: proof.len(),
        ciphertext_bytes: [ciphertexts[0].len(), ciphertexts[1].len()],
        public_inputs: prepared.public_inputs()?,
        phases,
        peak_linear_memory_bytes_since_init: call.peak_bytes_since_init,
        linear_memory_growth_bytes: call.growth_bytes,
    };

    Ok(Submission {
        proof,
        ciphertexts,
        report,
    })
}

/// Verify a private-batch proof against this prover's own circuit.
pub fn verify(prover: &WalletProver, proof_bytes: &[u8]) -> Result<f64> {
    let verifier = prover.batch_verifier_data();
    let proof =
        ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.to_vec(), &verifier.common)
            .map_err(|_| anyhow::anyhow!("the proof bytes do not deserialize for this circuit"))?;
    let (result, millis) = timed(|| verifier.verify(proof));
    result.map_err(|_| anyhow::anyhow!("the proof does not verify"))?;
    Ok(millis)
}

/// What one zero-knowledge leaf cost: build and prove time, the size it came
/// out at, and the degree blinding pushed it to.
#[derive(Debug, Serialize)]
pub struct ZkLeafReport {
    pub build_millis: f64,
    pub prove_millis: f64,
    pub proof_bytes: usize,
    pub zero_knowledge: bool,
    /// What blinding costs before anything is proved: the non-ZK leaf is 9,
    /// and the blinding rows plonky2 adds push this well past it. Every
    /// committed polynomial is extended over `2^(degree_bits + 3)` rows, so
    /// this number is the proving cost.
    pub degree_bits: usize,
    pub phases: Vec<PhaseReport>,
    /// The module's high-water mark once this call finished, which in a warm
    /// worker includes the private-batch circuit this call never touches.
    /// Sizing a delegated leaf-only prover takes a run where nothing else was
    /// built: `www/run.mjs --zk-only`.
    pub peak_linear_memory_bytes_since_init: usize,
    /// What this call grew linear memory by, over what it found on entry.
    pub linear_memory_growth_bytes: usize,
}

/// Build a zero-knowledge leaf circuit and prove one transfer with it.
///
/// Not the production path: the production leaf is non-ZK on purpose, because
/// it is aggregated by the wallet that made it and privacy is applied one layer
/// up. This measures the other shape, where a phone proves a blinded leaf and
/// hands it to somebody else's batcher. `docs/DESIGN.md` section 8 carries what
/// that costs in privacy.
///
/// It builds its own circuit per call, which makes it a measurement entry
/// point and keeps it off any payment path. The proof does not leave this
/// function: a ZK leaf is safe to hand out, and handing one out is a decision
/// for the milestone that builds the delegated batcher to make deliberately.
pub fn prove_zk_leaf(request: &TransferRequest) -> Result<ZkLeafReport> {
    use qnero_circuit::config::qnero_leaf_zk_circuit_config;

    let entry = MemorySpan::start();
    let mut prepared = request.prepare()?;
    let outputs = prepared.encrypt_outputs()?;
    let digest = ct_digest(&[&outputs[0].ciphertext, &outputs[1].ciphertext]);
    prepared.witness.ct_digest = Digest::from_bytes(&digest)
        .map_err(|_| anyhow::anyhow!("ct_digest is not a canonical digest"))?;
    prepared.witness.validate()?;

    let config = qnero_leaf_zk_circuit_config();
    let zero_knowledge = config.zero_knowledge;

    let mut phases = Vec::new();
    let before = MemorySpan::start();
    let (prover, build_millis) = timed(|| qnero_prover::QneroProver::new(config));
    let prover = prover.context("failed to build the zero-knowledge leaf circuit")?;
    let degree_bits = prover.circuit_data.common.degree_bits();
    phases.push(PhaseReport {
        phase: "zk_leaf_build",
        millis: build_millis,
        memory: MemorySpan::end(before),
    });

    let before = MemorySpan::start();
    let (proof, prove_millis) = timed(|| prover.commit(&prepared.witness)?.prove());
    let proof = proof.context("failed to prove the zero-knowledge leaf")?;
    phases.push(PhaseReport {
        phase: "zk_leaf_prove",
        millis: prove_millis,
        memory: MemorySpan::end(before),
    });

    let call = memory::record_call(entry);
    Ok(ZkLeafReport {
        build_millis,
        prove_millis,
        proof_bytes: proof.to_bytes().len(),
        zero_knowledge,
        degree_bits,
        phases,
        peak_linear_memory_bytes_since_init: call.peak_bytes_since_init,
        linear_memory_growth_bytes: call.growth_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qnero_circuit::batch_layout::private_batch_pi_len;

    /// The copy is held to the definition, so moving the chain's `N` moves
    /// this crate's with it. Asserting the literal 6 here would have let the
    /// browser prover keep building six-slot batches a seven-slot runtime
    /// cannot read, with every gate green and the rejection arriving only
    /// after the full proving cost.
    ///
    /// `qnero-circuit-builder` is a dev-dependency: it never enters the
    /// cdylib, and `cargo tree -e normal` for the wasm target does not list it.
    #[test]
    fn the_chain_default_is_the_builders_default() {
        assert_eq!(
            CHAIN_NUM_LEAVES,
            qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS
        );
    }

    /// What a wrong `N` costs is a full proving run before the runtime says
    /// no, so the public-input length the current `N` implies is pinned too.
    /// `5 + 21 * 6 = 131`.
    #[test]
    fn the_private_batch_public_inputs_are_one_three_one() {
        assert_eq!(CHAIN_NUM_LEAVES, 6);
        assert_eq!(private_batch_pi_len(CHAIN_NUM_LEAVES), 131);
    }
}
