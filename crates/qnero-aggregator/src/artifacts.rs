//! Reading, writing and pinning circuit artifacts, and the proof-shape
//! preflight every witness filler runs.
//!
//! # What an artifact set is
//!
//! One verifier file per layer, plus the padding templates a partial batch is
//! filled with. A layer's file is the whole `VerifierCircuitData`: its common
//! data and its verifier-only data together, as `to_bytes` writes them.
//! Upstream splits those into two files per layer, which a consumer then has
//! to pair up correctly; one file per layer cannot be mismatched, and it is
//! the single deserialization boundary `qnero-verifier` already had for the
//! leaf. **No layer ever emits or loads prover data.** Prover data
//! carries the witness generators and the target list that decides which
//! witness values become public inputs, so a poisoned prover artifact could
//! make a wallet publish its own spend credential, or the preimages that
//! reveal which slots were padding. Every prover in this crate rebuilds its
//! circuit from source, which it has to do anyway.
//!
//! # How an artifact is pinned
//!
//! By serializing a canonical rebuild and comparing raw bytes, never by
//! deserializing the untrusted side first. `CommonCircuitData::from_bytes`
//! reserves vector capacity from length fields in the artifact before those
//! lengths are proven consistent with the rest of the file, so a small but
//! poisoned buffer can force a large transient allocation before any check
//! runs. The `load_canonical_*` functions therefore return the **rebuild**,
//! not the parsed bytes.

use anyhow::{anyhow, bail, Context, Result};
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::DefaultGateSerializer;
use std::path::Path;

use qnero_circuit::config::{qnero_leaf_circuit_config, qnero_private_batch_circuit_config};
use qnero_circuit::{QneroSpendCircuit, C, D, F};

use crate::private_batch::QneroPrivateBatchCircuit;
use crate::public_batch::QneroPublicBatchCircuit;

/// Largest artifact file this crate will read.
///
/// Bounds the allocation before pinning can reject a wrong file. Artifact
/// directories are expected to come from a trusted build, so this is a sanity
/// bound. An adversary with write access to one is outside the threat model.
pub const MAX_ARTIFACT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Read an artifact file, refusing an oversized one before allocating for its
/// contents. The size comes from `metadata`, so a planted sparse file is
/// rejected without being buffered.
pub fn read_artifact_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat artifact file {}", path.display()))?;
    if metadata.len() > MAX_ARTIFACT_FILE_BYTES {
        bail!(
            "artifact file {} is {} bytes, above the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_ARTIFACT_FILE_BYTES
        );
    }
    std::fs::read(path).with_context(|| format!("failed to read artifact file {}", path.display()))
}

/// Write a set of artifact files into a directory, removing named stale ones.
///
/// Whole-directory staging (see `qnero-circuit-builder`) is what makes a
/// regenerate atomic; this is the per-file half.
pub fn commit_artifact_set(
    bins_dir: &Path,
    files: &[(&str, Vec<u8>)],
    remove_stale: &[&str],
) -> Result<()> {
    std::fs::create_dir_all(bins_dir)
        .with_context(|| format!("failed to create artifact dir {}", bins_dir.display()))?;
    for (name, bytes) in files {
        let path = bins_dir.join(name);
        std::fs::write(&path, bytes)
            .with_context(|| format!("failed to write artifact {}", path.display()))?;
    }
    for name in remove_stale {
        let path = bins_dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to remove stale artifact {}", path.display()))
            }
        }
    }
    Ok(())
}

/// Serialize a layer's verifier data into the one file an artifact set carries
/// for it.
pub fn serialize_verifier_data(
    verifier_data: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<Vec<u8>> {
    verifier_data
        .to_bytes(&DefaultGateSerializer)
        .map_err(|e| anyhow!("failed to serialize the {} verifier data: {}", label, e))
}

/// The canonical leaf verifier data, rebuilt from source.
pub fn canonical_leaf_verifier_data() -> VerifierCircuitData<F, C, D> {
    QneroSpendCircuit::new(qnero_leaf_circuit_config())
        .expect("the canonical leaf config is valid")
        .build_verifier()
}

/// The canonical private-batch verifier data for `num_leaves`, rebuilt from
/// source over `leaf`.
pub fn canonical_private_batch_verifier_data(
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaves: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    Ok(QneroPrivateBatchCircuit::new(
        qnero_private_batch_circuit_config(),
        &leaf.common,
        &leaf.verifier_only,
        num_leaves,
    )?
    .build_verifier())
}

/// The canonical public-batch verifier data, rebuilt from source over
/// `private_batch`.
pub fn canonical_public_batch_verifier_data(
    private_batch: &VerifierCircuitData<F, C, D>,
    num_private_batch_proofs: usize,
    num_leaves: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    Ok(QneroPublicBatchCircuit::new(
        qnero_circuit::config::qnero_public_batch_circuit_config(),
        &private_batch.common,
        &private_batch.verifier_only,
        num_private_batch_proofs,
        num_leaves,
    )?
    .build_verifier())
}

/// Compare untrusted artifact bytes with a canonical rebuild, byte for byte.
///
/// The untrusted side is never deserialized: see the module docs.
fn ensure_artifact_bytes_match_canonical(
    bytes: &[u8],
    canonical: &VerifierCircuitData<F, C, D>,
    label: &str,
) -> Result<()> {
    let canonical_bytes = serialize_verifier_data(canonical, label)?;
    if bytes != canonical_bytes.as_slice() {
        bail!(
            "the {} verifier artifact does not match the canonical circuit",
            label
        );
    }
    Ok(())
}

/// Pin leaf artifact bytes to the canonical leaf circuit and return the
/// rebuild.
pub fn load_canonical_leaf_verifier_data(bytes: &[u8]) -> Result<VerifierCircuitData<F, C, D>> {
    let canonical = canonical_leaf_verifier_data();
    ensure_artifact_bytes_match_canonical(bytes, &canonical, "leaf")?;
    Ok(canonical)
}

/// Pin private-batch artifact bytes to the canonical private-batch circuit for
/// `num_leaves` and return the rebuild.
pub fn load_canonical_private_batch_verifier_data(
    bytes: &[u8],
    leaf: &VerifierCircuitData<F, C, D>,
    num_leaves: usize,
) -> Result<VerifierCircuitData<F, C, D>> {
    let canonical = canonical_private_batch_verifier_data(leaf, num_leaves)?;
    ensure_artifact_bytes_match_canonical(bytes, &canonical, "private batch")?;
    Ok(canonical)
}

/// A proof's public-input count, checked before anything indexes into it.
pub fn ensure_proof_public_input_len(
    proof: &ProofWithPublicInputs<F, C, D>,
    expected: usize,
    label: &str,
) -> Result<()> {
    if proof.public_inputs.len() != expected {
        bail!(
            "{} has {} public inputs, expected {}",
            label,
            proof.public_inputs.len(),
            expected
        );
    }
    Ok(())
}

fn ensure_len_matches(
    actual: usize,
    expected: usize,
    label: &str,
    slot: usize,
    what: &str,
) -> Result<()> {
    if actual != expected {
        bail!(
            "{} at slot {} is malformed: {} has length {}, but the circuit expects {}",
            label,
            slot,
            what,
            actual,
            expected
        );
    }
    Ok(())
}

/// Check a proof's whole internal shape against the targets it is about to be
/// written into.
///
/// `set_proof_with_pis_target` assigns a proof through three length-sensitive
/// paths: `zip_eq`, which panics; debug-only length asserts, which in a
/// release build leave a partial assignment; and plain `zip`, which silently
/// leaves trailing targets unset. A proof with the right public-input count
/// but inconsistent internal vectors would crash the process or defer the
/// failure to proving time, and plonky2's own shape validation is private to
/// its crate and runs only inside `verify`. So the shape is checked here, at a
/// `Result` boundary, before any target is written.
pub fn ensure_proof_shape_matches_targets(
    proof_target: &ProofWithPublicInputsTarget<D>,
    proof: &ProofWithPublicInputs<F, C, D>,
    slot: usize,
    label: &str,
) -> Result<()> {
    ensure_len_matches(
        proof.public_inputs.len(),
        proof_target.public_inputs.len(),
        label,
        slot,
        "public inputs",
    )?;

    let p = &proof.proof;
    let t = &proof_target.proof;

    ensure_len_matches(
        p.wires_cap.0.len(),
        t.wires_cap.0.len(),
        label,
        slot,
        "wires_cap",
    )?;
    ensure_len_matches(
        p.plonk_zs_partial_products_cap.0.len(),
        t.plonk_zs_partial_products_cap.0.len(),
        label,
        slot,
        "plonk_zs_partial_products_cap",
    )?;
    ensure_len_matches(
        p.quotient_polys_cap.0.len(),
        t.quotient_polys_cap.0.len(),
        label,
        slot,
        "quotient_polys_cap",
    )?;

    let o = &p.openings;
    let ot = &t.openings;
    for (actual, expected, what) in [
        (o.constants.len(), ot.constants.len(), "openings.constants"),
        (
            o.plonk_sigmas.len(),
            ot.plonk_sigmas.len(),
            "openings.plonk_sigmas",
        ),
        (o.wires.len(), ot.wires.len(), "openings.wires"),
        (o.plonk_zs.len(), ot.plonk_zs.len(), "openings.plonk_zs"),
        (
            o.plonk_zs_next.len(),
            ot.plonk_zs_next.len(),
            "openings.plonk_zs_next",
        ),
        (
            o.partial_products.len(),
            ot.partial_products.len(),
            "openings.partial_products",
        ),
        (
            o.quotient_polys.len(),
            ot.quotient_polys.len(),
            "openings.quotient_polys",
        ),
        (o.lookup_zs.len(), ot.lookup_zs.len(), "openings.lookup_zs"),
        (
            o.lookup_zs_next.len(),
            ot.next_lookup_zs.len(),
            "openings.lookup_zs_next",
        ),
    ] {
        ensure_len_matches(actual, expected, label, slot, what)?;
    }

    let f = &p.opening_proof;
    let ft = &t.opening_proof;

    ensure_len_matches(
        f.commit_phase_merkle_caps.len(),
        ft.commit_phase_merkle_caps.len(),
        label,
        slot,
        "opening_proof.commit_phase_merkle_caps",
    )?;
    for (i, (cap, cap_target)) in f
        .commit_phase_merkle_caps
        .iter()
        .zip(ft.commit_phase_merkle_caps.iter())
        .enumerate()
    {
        ensure_len_matches(
            cap.0.len(),
            cap_target.0.len(),
            label,
            slot,
            &format!("opening_proof.commit_phase_merkle_caps[{i}]"),
        )?;
    }

    ensure_len_matches(
        f.query_round_proofs.len(),
        ft.query_round_proofs.len(),
        label,
        slot,
        "opening_proof.query_round_proofs",
    )?;
    for (i, (round, round_target)) in f
        .query_round_proofs
        .iter()
        .zip(ft.query_round_proofs.iter())
        .enumerate()
    {
        ensure_len_matches(
            round.initial_trees_proof.evals_proofs.len(),
            round_target.initial_trees_proof.evals_proofs.len(),
            label,
            slot,
            &format!("opening_proof.query_round_proofs[{i}].initial_trees_proof.evals_proofs"),
        )?;
        for (j, ((evals, merkle), (evals_target, merkle_target))) in round
            .initial_trees_proof
            .evals_proofs
            .iter()
            .zip(round_target.initial_trees_proof.evals_proofs.iter())
            .enumerate()
        {
            ensure_len_matches(
                evals.len(),
                evals_target.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].evals_proofs[{j}].evals"),
            )?;
            ensure_len_matches(
                merkle.siblings.len(),
                merkle_target.siblings.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].evals_proofs[{j}].siblings"),
            )?;
        }

        ensure_len_matches(
            round.steps.len(),
            round_target.steps.len(),
            label,
            slot,
            &format!("opening_proof.query_round_proofs[{i}].steps"),
        )?;
        for (j, (step, step_target)) in round
            .steps
            .iter()
            .zip(round_target.steps.iter())
            .enumerate()
        {
            ensure_len_matches(
                step.evals.len(),
                step_target.evals.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].steps[{j}].evals"),
            )?;
            ensure_len_matches(
                step.merkle_proof.siblings.len(),
                step_target.merkle_proof.siblings.len(),
                label,
                slot,
                &format!("opening_proof.query_round_proofs[{i}].steps[{j}].merkle_proof.siblings"),
            )?;
        }
    }

    ensure_len_matches(
        f.final_poly.coeffs.len(),
        ft.final_poly.0.len(),
        label,
        slot,
        "opening_proof.final_poly",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qnero-artifacts-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn artifact_files_round_trip_and_stale_ones_are_removed() {
        let dir = temp_dir("commit");
        commit_artifact_set(
            &dir,
            &[("a.bin", b"one".to_vec()), ("b.bin", b"two".to_vec())],
            &[],
        )
        .unwrap();
        assert_eq!(read_artifact_file(&dir.join("a.bin")).unwrap(), b"one");

        commit_artifact_set(&dir, &[("a.bin", b"new".to_vec())], &["b.bin"]).unwrap();
        assert_eq!(read_artifact_file(&dir.join("a.bin")).unwrap(), b"new");
        assert!(!dir.join("b.bin").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The size check reads the file's metadata, so an oversized file is
    /// refused without being read into memory.
    #[test]
    fn an_oversized_artifact_is_refused_before_it_is_read() {
        let dir = temp_dir("oversized");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("huge.bin");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_ARTIFACT_FILE_BYTES + 1)
            .unwrap();
        let error = read_artifact_file(&path).unwrap_err();
        assert!(error.to_string().contains("above the"), "got: {error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Pinning must reject a poisoned artifact by comparing bytes, without
    /// asking plonky2 to deserialize length fields it has not checked.
    #[test]
    fn poisoned_leaf_artifacts_are_refused_by_the_byte_pin() {
        let mut poisoned = vec![0u8; 4096];
        for chunk in poisoned.chunks_mut(8) {
            chunk.copy_from_slice(&(usize::MAX / 16).to_le_bytes());
        }
        let error = load_canonical_leaf_verifier_data(&poisoned).unwrap_err();
        assert!(
            error.to_string().contains("does not match the canonical"),
            "got: {error}"
        );
    }

    /// `qnero-verifier` restates both batch configs, because
    /// `qnero-circuit`'s own constructors live behind its circuit feature and
    /// pull in plonky2's prover, which cannot be compiled into a runtime. This
    /// crate is the one place that sees both sides, so it is where the
    /// duplication is held honest. Without it, a config change here would
    /// leave every published artifact refused by the runtime that is supposed
    /// to load it, and nothing would say why.
    #[test]
    fn the_verifier_expects_the_configs_this_crate_builds_with() {
        assert_eq!(
            qnero_private_batch_circuit_config(),
            qnero_verifier::batch::expected_private_batch_config(),
            "the private-batch config and the one qnero-verifier expects have drifted"
        );
        assert_eq!(
            qnero_circuit::config::qnero_public_batch_circuit_config(),
            qnero_verifier::batch::expected_public_batch_config(),
            "the public-batch config and the one qnero-verifier expects have drifted"
        );
    }

    #[test]
    fn canonical_leaf_artifacts_pass_their_own_pin() {
        let canonical = canonical_leaf_verifier_data();
        let bytes = serialize_verifier_data(&canonical, "leaf").unwrap();
        load_canonical_leaf_verifier_data(&bytes).unwrap();
    }

    /// One flipped bit in a published artifact must be refused, not
    /// deserialized and used.
    #[test]
    fn a_bit_flipped_leaf_artifact_is_refused() {
        let canonical = canonical_leaf_verifier_data();
        let mut bytes = serialize_verifier_data(&canonical, "leaf").unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(load_canonical_leaf_verifier_data(&bytes).is_err());
    }
}
