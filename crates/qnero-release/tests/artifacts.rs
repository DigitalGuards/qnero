mod common;

use common::{keygen, success, TestDir, BIN, OTHER_REVISION, REVISION};
use qnero_release::{sign, verify, SIGNING_CONTEXT};
use qp_rusty_crystals_dilithium::{ml_dsa_87::Keypair, SensitiveBytes32};
use std::{fs, path::Path, process::Command};
use zeroize::Zeroizing;

fn fixture() -> TestDir {
    let dir = TestDir::new();
    keygen(&dir);
    dir.write("artifacts/bin/qnero-node", vec![0xaa; 150_001]);
    dir.write("artifacts/www/app.js", "export const app = 1;\n");
    sign(
        &dir.join("artifacts"),
        &dir.join("signer.release-key"),
        REVISION,
        &["bin".into(), "www".into()],
        &dir.join("manifest.json"),
        &dir.join("manifest.sig"),
    )
    .unwrap();
    dir
}

fn verify_bundle(dir: &TestDir, output: Option<&Path>) -> anyhow::Result<qnero_release::Manifest> {
    verify(
        &dir.join("artifacts"),
        &dir.join("trusted.pub"),
        REVISION,
        &dir.join("manifest.json"),
        &dir.join("manifest.sig"),
        &["bin".into(), "www".into()],
        output,
    )
}

fn resign(dir: &TestDir, manifest: &[u8], context: Option<&[u8]>) {
    let encoded = Zeroizing::new(fs::read(dir.join("signer.release-key")).unwrap());
    let seed = encoded.strip_prefix(b"QNERO_RELEASE_PRIVATE_V1\n").unwrap();
    let mut seed = Zeroizing::new(<[u8; 32]>::try_from(seed).unwrap());
    let key = Keypair::generate(&mut SensitiveBytes32::from(&mut *seed));
    let signature = key.sign(manifest, context, None).unwrap();
    dir.write("manifest.json", manifest);
    dir.write("manifest.sig", signature);
}

#[test]
fn verifies_binary_bytes_and_publishes_the_complete_snapshot() {
    let dir = fixture();
    let output = dir.join("verified");
    let manifest = verify_bundle(&dir, Some(&output)).unwrap();
    assert_eq!(manifest.files.len(), 2);
    for path in ["bin/qnero-node", "www/app.js"] {
        assert_eq!(
            fs::read(output.join(path)).unwrap(),
            fs::read(dir.join(&format!("artifacts/{path}"))).unwrap()
        );
    }
    assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".qnero-release-")));
}

#[test]
fn digest_failure_removes_the_private_partial_snapshot() {
    let dir = fixture();
    // The first file verifies and is copied; the second fails its same-size digest.
    dir.write("artifacts/www/app.js", "export const app = 2;\n");
    let output = dir.join("verified");
    assert!(verify_bundle(&dir, Some(&output))
        .unwrap_err()
        .to_string()
        .contains("SHA-512"));
    assert!(!output.exists());
    assert!(!fs::read_dir(dir.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".qnero-release-")));
}

#[test]
fn refuses_existing_key_manifest_signature_and_snapshot_outputs() {
    let dir = fixture();
    let private_before = fs::read(dir.join("signer.release-key")).unwrap();
    assert!(
        qnero_release::keygen(&dir.join("signer.release-key"), &dir.join("another.pub")).is_err()
    );
    assert!(fs::read(dir.join("signer.release-key")).unwrap() == private_before);
    let manifest_before = fs::read(dir.join("manifest.json")).unwrap();
    assert!(sign(
        &dir.join("artifacts"),
        &dir.join("signer.release-key"),
        REVISION,
        &["bin".into()],
        &dir.join("manifest.json"),
        &dir.join("fresh.sig")
    )
    .is_err());
    assert_eq!(
        fs::read(dir.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert!(sign(
        &dir.join("artifacts"),
        &dir.join("signer.release-key"),
        REVISION,
        &["bin".into()],
        &dir.join("fresh.json"),
        &dir.join("manifest.sig")
    )
    .is_err());
    assert!(!dir.join("fresh.json").exists());
    dir.write("verified/marker", "keep this existing directory");
    assert!(verify_bundle(&dir, Some(&dir.join("verified"))).is_err());
    assert_eq!(
        fs::read(dir.join("verified/marker")).unwrap(),
        b"keep this existing directory"
    );
}

#[test]
fn public_key_can_be_recovered_from_the_private_seed() {
    let dir = fixture();
    let output = Command::new(BIN)
        .arg("public-key")
        .arg("--private-key")
        .arg(dir.join("signer.release-key"))
        .arg("--public-key")
        .arg(dir.join("recovered.pub"))
        .output()
        .unwrap();
    success(&output);
    assert_eq!(
        fs::read(dir.join("trusted.pub")).unwrap(),
        fs::read(dir.join("recovered.pub")).unwrap()
    );
    assert!(qnero_release::export_public(
        &dir.join("signer.release-key"),
        &dir.join("recovered.pub")
    )
    .is_err());
    let output = Command::new(BIN)
        .arg("fingerprint")
        .arg("--public-key")
        .arg(dir.join("recovered.pub"))
        .output()
        .unwrap();
    success(&output);
    let manifest = verify_bundle(&dir, None).unwrap();
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        manifest.public_key_sha512
    );
}

#[test]
fn signatures_from_another_domain_are_rejected() {
    let dir = fixture();
    let bytes = fs::read(dir.join("manifest.json")).unwrap();
    for context in [None, Some(b"QUANTUS_EXTRINSIC".as_slice())] {
        resign(&dir, &bytes, context);
        assert!(verify_bundle(&dir, None)
            .unwrap_err()
            .to_string()
            .contains("trusted key"));
    }
}

#[test]
fn rejects_signed_paths_that_could_escape_or_alias_the_snapshot() {
    let dir = fixture();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    for path in [
        "../escape",
        "/absolute",
        "bin/../escape",
        "bin//node",
        "bin/./node",
        "bin\\node",
        "bin/CON.txt",
        "bin/lpt1",
        "bin/trailing.",
        "bin/a:b",
        "bin/with space",
        "",
    ] {
        let mut value = original.clone();
        value["files"][0]["path"] = path.into();
        resign(
            &dir,
            &serde_json::to_vec(&value).unwrap(),
            Some(SIGNING_CONTEXT),
        );
        assert!(
            verify_bundle(&dir, Some(&dir.join("verified"))).is_err(),
            "accepted path {path}"
        );
        assert!(!dir.join("verified").exists());
    }
}

#[test]
fn rejects_authenticated_metadata_with_wrong_schema_identity_or_duplicates() {
    let dir = fixture();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    for (field, value) in [
        ("schema", "other-schema"),
        ("repository", "https://example.invalid/qnero"),
        ("algorithm", "ECDSA"),
        ("revision", OTHER_REVISION),
        ("public_key_sha512", "wrong-key"),
    ] {
        let mut changed = original.clone();
        changed[field] = value.into();
        resign(
            &dir,
            &serde_json::to_vec(&changed).unwrap(),
            Some(SIGNING_CONTEXT),
        );
        assert!(verify_bundle(&dir, None).is_err(), "accepted {field}");
    }
    let mut duplicate = original.clone();
    duplicate["files"][1] = duplicate["files"][0].clone();
    duplicate["files"][1]["path"] = "BIN/QNERO-NODE".into();
    resign(
        &dir,
        &serde_json::to_vec(&duplicate).unwrap(),
        Some(SIGNING_CONTEXT),
    );
    assert!(verify_bundle(&dir, None)
        .unwrap_err()
        .to_string()
        .contains("duplicate"));
    let mut unknown = original.clone();
    unknown["unrecognized"] = true.into();
    resign(
        &dir,
        &serde_json::to_vec(&unknown).unwrap(),
        Some(SIGNING_CONTEXT),
    );
    assert!(verify_bundle(&dir, None)
        .unwrap_err()
        .to_string()
        .contains("invalid signed release manifest"));
}

#[test]
fn rejects_truncated_oversized_or_malformed_signatures_and_public_keys() {
    let dir = fixture();
    let signature = fs::read(dir.join("manifest.sig")).unwrap();
    for bytes in [&signature[..signature.len() - 1], b"", &[0u8; 4628]] {
        dir.write("manifest.sig", bytes);
        assert!(verify_bundle(&dir, None).is_err());
    }
    dir.write("manifest.sig", &signature);
    dir.write("trusted.pub", b"invalid release key");
    assert!(verify_bundle(&dir, None).is_err());
}

#[test]
fn requires_a_full_expected_revision() {
    let dir = fixture();
    for revision in [
        "",
        "main",
        "0123456",
        "0123456789ABCDEF0123456789ABCDEF01234567",
    ] {
        assert!(verify(
            &dir.join("artifacts"),
            &dir.join("trusted.pub"),
            revision,
            &dir.join("manifest.json"),
            &dir.join("manifest.sig"),
            &[],
            None
        )
        .is_err());
    }
}

#[cfg(unix)]
#[test]
fn signing_rejects_publicly_readable_private_keys() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    assert_eq!(
        fs::metadata(dir.join("signer.release-key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::set_permissions(
        dir.join("signer.release-key"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(sign(
        &dir.join("artifacts"),
        &dir.join("signer.release-key"),
        REVISION,
        &["bin".into()],
        &dir.join("another.json"),
        &dir.join("another.sig")
    )
    .unwrap_err()
    .to_string()
    .contains("owner-only"));
}

#[cfg(unix)]
#[test]
fn executable_permission_is_authenticated_and_sanitized_in_the_snapshot() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture();
    fs::remove_file(dir.join("manifest.json")).unwrap();
    fs::remove_file(dir.join("manifest.sig")).unwrap();
    fs::set_permissions(
        dir.join("artifacts/bin/qnero-node"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();
    sign(
        &dir.join("artifacts"),
        &dir.join("signer.release-key"),
        REVISION,
        &["bin".into(), "www".into()],
        &dir.join("manifest.json"),
        &dir.join("manifest.sig"),
    )
    .unwrap();
    fs::set_permissions(
        dir.join("artifacts/bin/qnero-node"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let output = dir.join("verified");
    verify_bundle(&dir, Some(&output)).unwrap();
    assert_eq!(
        fs::metadata(output.join("bin/qnero-node"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(output.join("www/app.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
}
