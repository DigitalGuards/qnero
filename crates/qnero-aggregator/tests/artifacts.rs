//! The artifact round trip: the builder writes a set, the loaders read it, and
//! a corrupted file does not pass.
//!
//! Small dimensions, because this is about the files and not about batch size.

mod common;

use std::path::{Path, PathBuf};

use qnero_aggregator::artifacts::read_artifact_file;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_aggregator::CircuitBinsConfig;
use qnero_circuit_builder::{generate_all_artifacts, CIRCUIT_CONFIG_SNIPPET};
use qnero_verifier::{QneroPrivateBatchVerifier, QneroPublicBatchVerifier, QneroVerifier};
// `qp-plonky2-verifier` carries its own copy of the circuit-data types, so
// these are not the ones `qp-plonky2` exposes and both have to be named here.
use qp_plonky2_verifier::{
    VerifierCircuitData as RuntimeVerifierData, C as RuntimeC, D as RUNTIME_D, F as RuntimeF,
};

const NUM_LEAVES: usize = 2;
const NUM_INNER: usize = 2;

/// An output directory inside a sandbox of this test's own.
///
/// The builder stages a set in a hidden sibling of its output directory, so an
/// output path directly under the shared temporary directory leaves a
/// `.staging-` entry there when a run is killed mid-build. One sandbox per
/// test keeps that inside the test.
fn temp_dir(tag: &str) -> PathBuf {
    let sandbox = std::env::temp_dir().join(format!(
        "qnero-artifact-round-trip-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&sandbox);
    std::fs::create_dir_all(&sandbox).expect("the sandbox directory is created");
    sandbox.join("artifacts")
}

fn file_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the artifact directory exists")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// (d) The builder writes the set, every loader reads its own file, and a
/// proof made from the published artifacts verifies against the published
/// verifier.
///
/// This is the only test that exercises the artifacts as files, which is how a
/// pallet and a wallet actually meet them.
#[test]
fn the_artifact_set_round_trips_through_the_loaders() {
    let dir = temp_dir("round-trip");
    generate_all_artifacts(&dir, NUM_LEAVES, Some(NUM_INNER), true)
        .expect("the artifact set generates");

    assert_eq!(
        file_names(&dir),
        vec![
            "config.json".to_string(),
            "leaf_verifier.bin".to_string(),
            "padding_leaf_proof.bin".to_string(),
            "padding_private_batch_proof.bin".to_string(),
            "private_batch_verifier.bin".to_string(),
            "public_batch_verifier.bin".to_string(),
            "qnero_circuit_config.rs".to_string(),
        ],
        "the published set is exactly these files, and never a prover artifact"
    );

    let config = CircuitBinsConfig::load(&dir).expect("config.json loads");
    assert_eq!(config.num_leaf_proofs, NUM_LEAVES);
    assert_eq!(config.num_private_batch_proofs, Some(NUM_INNER));

    let snippet = std::fs::read_to_string(dir.join(CIRCUIT_CONFIG_SNIPPET)).unwrap();
    assert!(snippet.contains(&format!("pub const NUM_LEAF_PROOFS: usize = {NUM_LEAVES};")));
    assert!(snippet.contains(&format!(
        "pub const NUM_PRIVATE_BATCH_PROOFS: usize = {NUM_INNER};"
    )));

    // Each loader takes its own file and holds it to its own profile.
    let leaf_artifact = read_artifact_file(&dir.join("leaf_verifier.bin")).unwrap();
    let leaf_verifier = QneroVerifier::from_artifact_bytes(&leaf_artifact)
        .expect("the leaf artifact passes the leaf profile");
    let padding_leaf = read_artifact_file(&dir.join("padding_leaf_proof.bin")).unwrap();
    leaf_verifier
        .verify_proof_bytes(&padding_leaf)
        .expect("the published padding leaf proof verifies");

    let private_batch_artifact =
        read_artifact_file(&dir.join("private_batch_verifier.bin")).unwrap();
    let private_batch_verifier =
        QneroPrivateBatchVerifier::from_artifact_bytes(&private_batch_artifact, NUM_LEAVES)
            .expect("the private-batch artifact passes its profile");

    let public_batch_artifact = read_artifact_file(&dir.join("public_batch_verifier.bin")).unwrap();
    QneroPublicBatchVerifier::from_artifact_bytes(&public_batch_artifact, NUM_INNER, NUM_LEAVES)
        .expect("the public-batch artifact passes its profile");

    // The public-batch file carries the dimension pair it was built for. Its
    // public-input count cannot stand in for that: `4 + n * (5 + 21 * N)`
    // collides for supported pairs, so an artifact from a partial redeploy
    // would otherwise load under the wrong dimensions and split every proof it
    // verified at the wrong offsets.
    assert!(
        public_batch_artifact.starts_with(&qnero_verifier::PUBLIC_BATCH_ARTIFACT_MAGIC),
        "the public-batch artifact must begin with its dimension header"
    );
    assert!(
        QneroPublicBatchVerifier::from_artifact_bytes(
            &public_batch_artifact,
            NUM_INNER,
            NUM_LEAVES + 1
        )
        .is_err(),
        "the artifact must not load under dimensions it was not built for"
    );
    let mut flipped_header = public_batch_artifact.clone();
    flipped_header[0] ^= 0x01;
    assert!(
        QneroPublicBatchVerifier::from_artifact_bytes(&flipped_header, NUM_INNER, NUM_LEAVES)
            .is_err(),
        "a flipped bit in the dimension header must be refused"
    );

    // The published all-padding batch is a real proof of the published
    // circuit, which is what the public batch pads with.
    let padding_batch = read_artifact_file(&dir.join("padding_private_batch_proof.bin")).unwrap();
    let padding_public = private_batch_verifier
        .verify_proof_bytes(&padding_batch)
        .expect("the published padding private batch verifies");
    assert!(padding_public.is_padding());

    // A wallet builds its prover from the same directory, and what it proves
    // verifies against the published verifier.
    let prover = QneroPrivateBatchProver::new_from_artifact_dir(&dir)
        .expect("the prover builds from the published artifacts");
    assert_eq!(prover.num_leaves(), NUM_LEAVES);

    let block = common::block_with_notes("artifacts", 1);
    let batch = prover
        .aggregate(vec![block.transfer_proof(0)])
        .expect("the batch proves");
    let public = private_batch_verifier
        .verify_proof_bytes(&batch.to_bytes())
        .expect("a batch proved from the published artifacts verifies against them");
    assert!(!public.is_padding());

    // The sandbox, and with it the output directory inside it.
    std::fs::remove_dir_all(dir.parent().expect("the output dir sits in a sandbox")).unwrap();
}

/// (d) A corrupted artifact does not quietly become a working verifier.
///
/// A flipped bit lands either in something the profile checks, and the loader
/// refuses it, or in the verifier key and the proof then fails against it.
/// Both are acceptable; silently verifying is not, and neither is hanging.
///
/// The hang is the interesting one and it is why the profile checks the
/// artifact's index structure. One bit in a length byte turned a selector
/// group of `0..6` into `0..2^40`, which every other check accepted: the
/// circuit digest does not cover the selector layout, and the parameter floor
/// never looks at it. Verification then evaluated a gate filter as a product
/// over a trillion terms and never returned. The aggregator's own byte pin is
/// stricter and refuses any flip outright, but a runtime has no canonical
/// rebuild to compare against, so what it can check is what this test holds
/// the loader to.
#[test]
fn a_bit_flipped_artifact_never_verifies_a_real_proof() {
    let dir = temp_dir("bit-flip");
    generate_all_artifacts(&dir, NUM_LEAVES, None, false).expect("the artifact set generates");

    let artifact = read_artifact_file(&dir.join("private_batch_verifier.bin")).unwrap();
    let prover = QneroPrivateBatchProver::new_from_artifact_dir(&dir).unwrap();
    let block = common::block_with_notes("bit-flip", 1);
    let batch = prover
        .aggregate(vec![block.transfer_proof(0)])
        .expect("the batch proves")
        .to_bytes();

    // The canonical artifact does verify it, so the failures below are the
    // flips and nothing else.
    QneroPrivateBatchVerifier::from_artifact_bytes(&artifact, NUM_LEAVES)
        .unwrap()
        .verify_proof_bytes(&batch)
        .expect("the canonical artifact verifies the batch");

    for position in [
        0,
        artifact.len() / 3,
        artifact.len() / 2,
        artifact.len() - 1,
    ] {
        let mut flipped = artifact.clone();
        flipped[position] ^= 0x01;
        if flipped == artifact {
            continue;
        }

        let outcome = QneroPrivateBatchVerifier::from_artifact_bytes(&flipped, NUM_LEAVES)
            .and_then(|verifier| verifier.verify_proof_bytes(&batch));
        assert!(
            outcome.is_err(),
            "an artifact with a flipped bit at byte {position} verified a real proof"
        );
    }

    // The sandbox, and with it the output directory inside it.
    std::fs::remove_dir_all(dir.parent().expect("the output dir sits in a sandbox")).unwrap();
}

/// (d) A corrupted selector index is refused at load, and does not become a
/// panic at the first verification.
///
/// `selectors_info` carries two vectors that plonky2 deserializes
/// independently: one range per selector group, and one group index per gate.
/// The profile bounded the ranges, which closed the non-terminating gate
/// filter, and left the indices unbounded. Constraint evaluation reads
/// `groups[selector_indices[gate]]` directly, so an index past the group count
/// survives every other check in the profile and then panics inside plonky2:
/// a trap in the wasm runtime that embeds the artifact, an abort in a wallet.
/// The bit-flip test above misses it because its four positions never land in
/// the index region.
#[test]
fn a_selector_index_past_the_group_count_is_refused_at_load() {
    let dir = temp_dir("selector-index");
    generate_all_artifacts(&dir, NUM_LEAVES, None, false).expect("the artifact set generates");
    let artifact = read_artifact_file(&dir.join("private_batch_verifier.bin")).unwrap();

    let mut data = RuntimeVerifierData::<RuntimeF, RuntimeC, RUNTIME_D>::from_bytes(
        artifact.clone(),
        &qp_plonky2_verifier::util::serialization::DefaultGateSerializer,
    )
    .expect("the published artifact deserializes");

    // Unmodified, it passes the profile: the failure below is the index alone.
    QneroPrivateBatchVerifier::new(data.clone(), NUM_LEAVES)
        .expect("the canonical artifact passes its profile");

    let groups = data.common.selectors_info.groups.len();
    assert!(groups > 0, "the artifact has selector groups to index");
    data.common.selectors_info.selector_indices[0] = groups;

    let error = QneroPrivateBatchVerifier::new(data, NUM_LEAVES)
        .expect_err("an out-of-range selector index must be refused");
    assert!(
        error.to_string().contains("selects selector group"),
        "got: {error}"
    );

    // The sandbox, and with it the output directory inside it.
    std::fs::remove_dir_all(dir.parent().expect("the output dir sits in a sandbox")).unwrap();
}

/// A runtime build skips the all-padding private batch, which costs a full
/// recursive proving run and only a public-batch prover needs. The set must
/// then not carry a stale one from an earlier run.
#[test]
fn a_set_without_the_padding_batch_carries_no_stale_one() {
    let dir = temp_dir("no-padding-batch");
    generate_all_artifacts(&dir, NUM_LEAVES, Some(NUM_INNER), true)
        .expect("the first set generates");
    assert!(dir.join("padding_private_batch_proof.bin").exists());

    generate_all_artifacts(&dir, NUM_LEAVES, Some(NUM_INNER), false)
        .expect("the second set generates");
    assert!(
        !dir.join("padding_private_batch_proof.bin").exists(),
        "a stale padding batch from an earlier run must not survive a regenerate"
    );
    assert!(dir.join("public_batch_verifier.bin").exists());

    // The sandbox, and with it the output directory inside it.
    std::fs::remove_dir_all(dir.parent().expect("the output dir sits in a sandbox")).unwrap();
}
