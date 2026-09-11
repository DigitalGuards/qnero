//! Generating the Qnero circuit artifact set.
//!
//! # What it produces
//!
//! ```text
//! leaf_verifier.bin                 verifier data for the spend leaf
//! padding_leaf_proof.bin            the canonical padding leaf proof
//! private_batch_verifier.bin        verifier data for the private batch
//! padding_private_batch_proof.bin   an all-padding private batch (optional)
//! public_batch_verifier.bin         verifier data for the public batch
//! config.json                       the dimensions the set was built for
//! qnero_circuit_config.rs           those dimensions as Rust constants
//! ```
//!
//! A verifier file is one whole `VerifierCircuitData`: common data and
//! verifier-only data together, which is what `qnero-verifier` deserializes.
//! **No prover artifact is produced at any layer**, and none can be loaded:
//! prover data carries the target list that decides which witness values
//! become public inputs, so a poisoned one could make a wallet publish its own
//! spend credential.
//!
//! A pallet embeds `private_batch_verifier.bin` and
//! `public_batch_verifier.bin` with `include_bytes!` and includes
//! `qnero_circuit_config.rs` for the dimensions to check their public-input
//! lengths against. Those two are the only artifacts a runtime can use:
//! `qnero-verifier`'s leaf entry points sit behind its non-default `leaf`
//! feature, so a runtime taking the crate with default features has nothing
//! that can name `leaf_verifier.bin`. That file is a wallet-side input, and it
//! is what `QneroPrivateBatchProver::new_from_artifact_dir` pins its baked-in
//! verifier key against. The two padding proofs are wallet-side and
//! aggregator-side inputs as well.
//!
//! # Trust boundary
//!
//! This runs on a build host that is trusted for the duration of the run. A
//! local filesystem adversary racing the publisher is out of scope. What is in
//! scope, and enforced: the padding templates are validated before they are
//! published, every verifier file is read back through `qnero-verifier`'s own
//! profile before the set is committed, and the set is staged and swapped in
//! whole so a failed run cannot leave a mixed generation behind.
//!
//! Forked in shape from Quantus-Network/qp-zk-circuits (MIT); see NOTICE and
//! CHANGES.md.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use qnero_aggregator::artifacts::{
    canonical_public_batch_verifier_data, commit_artifact_set, read_artifact_file,
    serialize_public_batch_verifier_data, serialize_verifier_data,
};
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_aggregator::{generate_padding_leaf_proof, CircuitBinsConfig};
use qnero_circuit::config::{qnero_leaf_circuit_config, qnero_private_batch_circuit_config};
use qnero_circuit::QneroSpendCircuit;
use qnero_verifier::{QneroPrivateBatchVerifier, QneroPublicBatchVerifier, QneroVerifier};

/// The file a pallet's `build.rs` includes to learn the dimensions.
pub const CIRCUIT_CONFIG_SNIPPET: &str = "qnero_circuit_config.rs";

/// The chain defaults, and why they are what they are.
///
/// Seven leaves per private batch is a wallet-side memory decision: it is what
/// a phone can prove. Fifty-three private batches per public batch is an
/// aggregator-side cost decision, amortizing one on-chain verification across
/// many wallets.
///
/// They live in the library, so that a pallet's `build.rs`, which calls
/// [`generate_all_artifacts`] directly and cannot depend on a bin target,
/// reads the same numbers the CLI and the docs do.
/// Shipping `N = 6` is an open decision (`docs/BENCH.md`), and when it lands
/// it has to move in one place.
pub const DEFAULT_NUM_LEAF_PROOFS: usize = 7;
/// See [`DEFAULT_NUM_LEAF_PROOFS`].
pub const DEFAULT_NUM_PRIVATE_BATCH_PROOFS: usize = 53;

/// Generate the whole artifact set into `output_dir`.
///
/// `include_padding_batch` controls the all-padding private-batch proof, which
/// only a public-batch prover needs and which costs a full recursive proving
/// run. A runtime build leaves it off.
///
/// The set is staged in a hidden sibling directory and swapped into place by
/// rename once every stage has succeeded. Any previous contents of
/// `output_dir` are replaced wholesale.
pub fn generate_all_artifacts<P: AsRef<Path>>(
    output_dir: P,
    num_leaf_proofs: usize,
    num_private_batch_proofs: Option<usize>,
    include_padding_batch: bool,
) -> Result<()> {
    // Dimensions are bounded before anything is built or written: a bad count
    // would otherwise drive a circuit build whose cost scales with it.
    let config = CircuitBinsConfig::new(num_leaf_proofs, num_private_batch_proofs)?;

    let output_path = output_dir.as_ref();
    let staging = create_staging_dir(output_path)?;

    let generated = (|| -> Result<()> {
        generate_into(&staging, config, include_padding_batch)?;
        // Written last: its presence is what marks a staged set complete.
        config.save(&staging)
    })();

    if let Err(e) = generated {
        // A partial stage is worthless, and the previous set is still in
        // place, so the staging directory can go.
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }

    commit_staging_dir(&staging, output_path)
}

fn generate_into(
    staging: &Path,
    config: CircuitBinsConfig,
    include_padding_batch: bool,
) -> Result<()> {
    // --- leaf ---
    let leaf_circuit = QneroSpendCircuit::new(qnero_leaf_circuit_config())?;
    let leaf_targets = leaf_circuit.targets();
    let leaf_data = leaf_circuit.build();
    // Proved before the circuit data is consumed into verifier data.
    let padding_leaf = generate_padding_leaf_proof(&leaf_data, &leaf_targets)?;
    let leaf_verifier = leaf_data.verifier_data();
    let leaf_verifier_bytes = serialize_verifier_data(&leaf_verifier, "leaf")?;

    commit_artifact_set(
        staging,
        &[
            ("leaf_verifier.bin", leaf_verifier_bytes),
            ("padding_leaf_proof.bin", padding_leaf.to_bytes()),
        ],
        &[],
    )?;
    check_staged_artifact(
        staging,
        "leaf_verifier.bin",
        QneroVerifier::from_artifact_bytes,
    )?;

    // --- private batch ---
    //
    // Built through the prover, because the same build is what proves the
    // all-padding template; the padding leaf is revalidated on the way in.
    let private_batch = QneroPrivateBatchProver::new(
        qnero_private_batch_circuit_config(),
        leaf_verifier.common.clone(),
        &leaf_verifier.verifier_only,
        config.num_leaf_proofs,
        padding_leaf,
    )?;
    let private_batch_verifier = private_batch.verifier_data();
    let private_batch_bytes = serialize_verifier_data(&private_batch_verifier, "private batch")?;

    let mut files: Vec<(&str, Vec<u8>)> = vec![("private_batch_verifier.bin", private_batch_bytes)];
    let mut remove_stale: Vec<&str> = Vec::new();
    if include_padding_batch {
        files.push((
            "padding_private_batch_proof.bin",
            private_batch.prove_padding_batch()?.to_bytes(),
        ));
    } else {
        // A stale template from an earlier run would not verify against the
        // fresh verifier data, and a consumer would only find out at load
        // time.
        remove_stale.push("padding_private_batch_proof.bin");
    }
    commit_artifact_set(staging, &files, &remove_stale)?;
    check_staged_artifact(staging, "private_batch_verifier.bin", |bytes| {
        QneroPrivateBatchVerifier::from_artifact_bytes(bytes, config.num_leaf_proofs)
    })?;

    // --- public batch ---
    if let Some(num_inner) = config.num_private_batch_proofs {
        let public_batch_verifier = canonical_public_batch_verifier_data(
            &private_batch_verifier,
            num_inner,
            config.num_leaf_proofs,
        )?;
        // Written with its dimension header: the public-batch profile cannot
        // tell one dimension pair from another by itself.
        let bytes = serialize_public_batch_verifier_data(
            &public_batch_verifier,
            num_inner,
            config.num_leaf_proofs,
        )?;
        commit_artifact_set(staging, &[("public_batch_verifier.bin", bytes)], &[])?;
        check_staged_artifact(staging, "public_batch_verifier.bin", |bytes| {
            QneroPublicBatchVerifier::from_artifact_bytes(bytes, num_inner, config.num_leaf_proofs)
        })?;
    }

    commit_artifact_set(
        staging,
        &[(
            CIRCUIT_CONFIG_SNIPPET,
            circuit_config_snippet(config).into_bytes(),
        )],
        &[],
    )
}

/// Read a staged verifier file back through the loader its consumer uses.
///
/// The builder writes what it built, so every profile check in
/// `qnero-verifier` would otherwise first run inside the pallet that embeds
/// the set: on another machine, and after the tens of minutes a set at the
/// chain dimensions costs. A batch artifact's degree grows with its
/// dimensions and is held to a ceiling
/// ([`qnero_circuit::params::MAX_BATCH_DEGREE_BITS`]), and each layer's
/// expected [`CircuitConfig`](qp_plonky2::plonk::circuit_data::CircuitConfig)
/// is restated inside the verifier, so the two crates can drift. Reading the
/// published bytes back costs milliseconds and turns the staging-then-rename
/// guarantee from "this set is complete" into "this set is loadable".
///
/// It reads the file back, so a short write is caught here too.
fn check_staged_artifact<T>(
    staging: &Path,
    name: &str,
    load: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<()> {
    let bytes = read_artifact_file(&staging.join(name))
        .with_context(|| format!("failed to read the staged {name} back"))?;
    load(&bytes).with_context(|| {
        format!(
            "the staged {name} does not load through qnero-verifier's profile; refusing to \
             publish a set a consumer would reject"
        )
    })?;
    Ok(())
}

/// The dimensions as Rust constants, for a pallet to `include!`.
///
/// `NUM_PRIVATE_BATCH_PROOFS` is emitted only for a set that has a public
/// batch, so a pallet that needs it fails to compile against a
/// private-batch-only set, where it would otherwise embed a number nothing
/// produced.
pub fn circuit_config_snippet(config: CircuitBinsConfig) -> String {
    let mut snippet = String::from(
        "// Generated by qnero-circuit-builder. Do not edit.\n\
         // These are the dimensions the verifier artifacts beside this file\n\
         // were built for; a proof's public-input length is a function of them.\n",
    );
    snippet.push_str(&format!(
        "pub const NUM_LEAF_PROOFS: usize = {};\n",
        config.num_leaf_proofs
    ));
    if let Some(num_inner) = config.num_private_batch_proofs {
        snippet.push_str(&format!(
            "pub const NUM_PRIVATE_BATCH_PROOFS: usize = {num_inner};\n"
        ));
    }
    snippet
}

/// Create a private staging directory beside `output_dir`, on the same
/// filesystem so the final rename is atomic, under an unpredictable name so a
/// concurrent run or a crashed one cannot collide with it.
fn create_staging_dir(output_dir: &Path) -> Result<PathBuf> {
    let Some(name) = output_dir.file_name().and_then(|name| name.to_str()) else {
        bail!(
            "the output path {} has no usable directory name; pass an explicit directory",
            output_dir.display()
        );
    };
    if let Some(parent) = output_dir.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create the output parent {}", parent.display())
            })?;
        }
    }
    for _ in 0..8 {
        let candidate = output_dir.with_file_name(format!(
            ".{}.staging-{}-{:016x}",
            name,
            std::process::id(),
            rand::random::<u64>()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to create the staging dir {}", candidate.display())
                })
            }
        }
    }
    bail!(
        "failed to create a fresh staging directory beside {}; remove stale .{}.staging-* \
         entries and retry",
        output_dir.display(),
        name
    );
}

/// Swap a fully staged directory into place.
///
/// A pre-existing output directory is moved aside first and removed after the
/// swap, and restored if the swap fails.
fn commit_staging_dir(staging: &Path, output_dir: &Path) -> Result<()> {
    if !staging.is_dir() {
        bail!(
            "the staged path {} is not a directory; refusing to publish",
            staging.display()
        );
    }

    let mut aside_name = staging.file_name().unwrap_or_default().to_os_string();
    aside_name.push(".previous");
    let aside = staging.with_file_name(aside_name);

    let had_previous = output_dir.exists();
    if had_previous {
        if !output_dir.is_dir() {
            let _ = std::fs::remove_dir_all(staging);
            bail!(
                "the output path {} exists and is not a directory; move it aside and retry",
                output_dir.display()
            );
        }
        if let Err(e) = std::fs::rename(output_dir, &aside) {
            let _ = std::fs::remove_dir_all(staging);
            return Err(e).with_context(|| {
                format!(
                    "failed to move the previous artifact set {} aside",
                    output_dir.display()
                )
            });
        }
    }

    if let Err(e) = std::fs::rename(staging, output_dir) {
        if had_previous {
            // The staged set is now the only new copy, so it is never deleted
            // before the previous one is back in place.
            let restored = std::fs::rename(&aside, output_dir);
            let _ = std::fs::remove_dir_all(staging);
            return Err(e).with_context(|| match restored {
                Ok(()) => format!(
                    "failed to publish the staged artifacts into {}; the previous set was \
                     restored",
                    output_dir.display()
                ),
                Err(restore_error) => format!(
                    "failed to publish the staged artifacts into {}, and restoring the previous \
                     set also failed ({}); the previous set is at {} and the new one at {}",
                    output_dir.display(),
                    restore_error,
                    aside.display(),
                    staging.display()
                ),
            });
        }
        return Err(e).with_context(|| {
            format!(
                "failed to publish the staged artifacts into {}; they remain at {}",
                output_dir.display(),
                staging.display()
            )
        });
    }

    if had_previous {
        if let Err(e) = std::fs::remove_dir_all(&aside) {
            eprintln!(
                "warning: published the artifact set to {}, but failed to remove the previous \
                 copy at {}: {e}",
                output_dir.display(),
                aside.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test's own, created empty.
    ///
    /// Every output path a test passes lives inside its sandbox, so no test
    /// writes a `.staging-` entry into the shared temporary directory. A run
    /// killed mid-build would otherwise leave one there and fail an unrelated
    /// assertion on every later run.
    fn sandbox(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("qnero-builder-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the sandbox directory is created");
        dir
    }

    #[test]
    fn the_snippet_carries_both_dimensions() {
        let snippet = circuit_config_snippet(CircuitBinsConfig::new(7, Some(53)).unwrap());
        assert!(snippet.contains("pub const NUM_LEAF_PROOFS: usize = 7;"));
        assert!(snippet.contains("pub const NUM_PRIVATE_BATCH_PROOFS: usize = 53;"));
    }

    /// A private-batch-only set has no public-batch dimension, and the snippet
    /// must not invent one.
    #[test]
    fn the_snippet_omits_a_public_batch_count_it_does_not_have() {
        let snippet = circuit_config_snippet(CircuitBinsConfig::new(4, None).unwrap());
        assert!(snippet.contains("NUM_LEAF_PROOFS"));
        assert!(!snippet.contains("NUM_PRIVATE_BATCH_PROOFS"));
    }

    /// Dimensions are validated before any circuit is built, so a bad request
    /// costs nothing and leaves no staging directory behind.
    #[test]
    fn out_of_range_dimensions_are_refused_before_anything_is_written() {
        let root = sandbox("bad-dimensions");
        let dir = root.join("artifacts");
        assert!(generate_all_artifacts(&dir, 0, None, false).is_err());
        assert!(generate_all_artifacts(&dir, 1, Some(0), false).is_err());
        assert!(!dir.exists());
        // A staging directory would have been created beside `dir`, which is
        // inside this test's own sandbox.
        assert!(staging_entries(&root).is_empty());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A verifier file that its own consumer cannot load never reaches the
    /// published set.
    ///
    /// The three generator stages read every verifier file back through
    /// `qnero-verifier` before the staged set is committed, so a profile
    /// mismatch between the crate that builds an artifact and the crate that
    /// loads it surfaces on the build host. Without the read-back it would
    /// first surface inside the pallet that embeds the set.
    #[test]
    fn a_staged_verifier_file_that_does_not_load_is_refused() {
        let root = sandbox("unloadable-artifact");
        std::fs::write(root.join("leaf_verifier.bin"), b"not a verifier").unwrap();

        let error = check_staged_artifact(
            &root,
            "leaf_verifier.bin",
            QneroVerifier::from_artifact_bytes,
        )
        .expect_err("an artifact that does not load must be refused");
        let message = format!("{error:#}");
        assert!(
            message.contains("qnero-verifier's profile"),
            "got: {message}"
        );

        // A missing file is refused the same way.
        assert!(
            check_staged_artifact(&root, "absent.bin", QneroVerifier::from_artifact_bytes).is_err()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// An output path that is a file is refused, and the staged set is
    /// cleaned up.
    #[test]
    fn a_file_at_the_output_path_is_refused() {
        let root = sandbox("output-is-a-file");
        let output = root.join("artifacts");
        std::fs::write(&output, b"not a directory").unwrap();

        let staging = create_staging_dir(&output).unwrap();
        std::fs::write(staging.join("leaf_verifier.bin"), b"fresh").unwrap();
        let error = commit_staging_dir(&staging, &output).unwrap_err();
        assert!(format!("{error:#}").contains("not a directory"));
        assert!(!staging.exists());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Publishing replaces the previous set wholesale: a file from an older
    /// generation does not survive into the new directory.
    #[test]
    fn publishing_replaces_the_previous_set() {
        let root = sandbox("replace");
        let output = root.join("artifacts");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("stale.bin"), b"from an older generation").unwrap();

        let staging = create_staging_dir(&output).unwrap();
        std::fs::write(staging.join("leaf_verifier.bin"), b"fresh").unwrap();
        commit_staging_dir(&staging, &output).unwrap();

        assert!(!output.join("stale.bin").exists());
        assert_eq!(
            std::fs::read(output.join("leaf_verifier.bin")).unwrap(),
            b"fresh"
        );
        assert!(staging_entries(&root).is_empty());

        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Staging entries left inside `dir`.
    ///
    /// It lists the directory it is handed. An earlier version resolved
    /// `dir.parent()`, which made one caller assert against the shared
    /// temporary directory: a `.staging-` entry another test left behind
    /// failed this one, and a leak in the directory under test went unseen.
    fn staging_entries(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".staging-"))
            })
            .collect()
    }
}
