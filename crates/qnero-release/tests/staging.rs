#![cfg(unix)]

mod common;
use common::{keygen, success, TestDir, BIN, OTHER_REVISION, REVISION};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output},
};

const SOURCE: &str = "crates/qnero-prover-wasm/www";
const GLUE: &str = "export function deriveAccount() {}\n";
const FILES: [(&str, &str); 5] = [
    ("pkg/qnero_prover_wasm.js", GLUE),
    (
        "pkg/qnero_prover_wasm_bg.wasm",
        "single-threaded module bytes\n",
    ),
    ("pkg-threaded/qnero_prover_wasm.js", GLUE),
    (
        "pkg-threaded/qnero_prover_wasm_bg.wasm",
        "threaded module bytes\n",
    ),
    (
        "pkg-threaded/snippets/wasm-bindgen-rayon-0/src/workerHelpers.js",
        "export const pool = 1;\n",
    ),
];

struct Fixture(TestDir);

impl Fixture {
    fn new() -> Self {
        let dir = TestDir::new();
        dir.write(
            "wallet-web/scripts/stage-wasm.sh",
            include_bytes!("../../../wallet-web/scripts/stage-wasm.sh"),
        );
        dir.write(
            "crates/qnero-prover-wasm/src/lib.rs",
            "#[wasm_bindgen(js_name = deriveAccount)]\n",
        );
        for (path, bytes) in FILES {
            dir.write(&format!("{SOURCE}/{path}"), bytes);
        }
        // Existing staged bytes must survive every authentication failure.
        dir.write(
            "wallet-web/public/wasm/qnero_prover_wasm.js",
            "old single glue",
        );
        dir.write(
            "wallet-web/public/wasm/threaded/qnero_prover_wasm.js",
            "old threaded glue",
        );
        keygen(&dir);
        Self(dir)
    }

    fn sign(&self, paths: &[&str]) {
        let output = Command::new(BIN)
            .arg("sign")
            .arg("--root")
            .arg(self.0.join(SOURCE))
            .arg("--private-key")
            .arg(self.0.join("signer.release-key"))
            .arg("--revision")
            .arg(REVISION)
            .arg("--manifest")
            .arg(self.0.join("manifest.json"))
            .arg("--signature")
            .arg(self.0.join("manifest.sig"))
            .args(paths)
            .output()
            .unwrap();
        success(&output);
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new("bash");
        cmd.current_dir(self.0.path());
        cmd.arg(self.0.join("wallet-web/scripts/stage-wasm.sh"))
            .arg("--threaded")
            .env("QNERO_WASM_PREBUILT", "1")
            .env("QNERO_RELEASE_VERIFIER", BIN)
            .env("QNERO_RELEASE_PUBLIC_KEY", self.0.join("trusted.pub"))
            .env("QNERO_RELEASE_REVISION", REVISION)
            .env("QNERO_RELEASE_MANIFEST", self.0.join("manifest.json"))
            .env("QNERO_RELEASE_SIGNATURE", self.0.join("manifest.sig"));
        cmd
    }

    fn reject(&self, cmd: &mut Command, reason: &str) {
        let output = cmd.output().unwrap();
        assert!(!output.status.success(), "unexpected stage success");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(reason), "expected {reason}: {stderr}");
        assert_eq!(
            fs::read(self.0.join("wallet-web/public/wasm/qnero_prover_wasm.js")).unwrap(),
            b"old single glue"
        );
        assert_eq!(
            fs::read(
                self.0
                    .join("wallet-web/public/wasm/threaded/qnero_prover_wasm.js")
            )
            .unwrap(),
            b"old threaded glue"
        );
    }

    fn assert_staged(&self, output: &Output) {
        success(output);
        for (path, bytes) in FILES {
            let target = path
                .strip_prefix("pkg/")
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!("threaded/{}", path.strip_prefix("pkg-threaded/").unwrap())
                });
            assert_eq!(
                fs::read(self.0.join(&format!("wallet-web/public/wasm/{target}"))).unwrap(),
                bytes.as_bytes()
            );
        }
    }
}

#[test]
fn stages_both_signed_packages_and_worker() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.assert_staged(&fixture.command().output().unwrap());
}

#[test]
fn requires_the_independently_supplied_key_manifest_and_signature() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.reject(
        fixture.command().env_remove("QNERO_RELEASE_PUBLIC_KEY"),
        "separately trusted public",
    );
    fixture.reject(
        fixture
            .command()
            .env("QNERO_RELEASE_MANIFEST", fixture.0.join("missing.json")),
        "authentication failed",
    );
    fixture.reject(
        fixture
            .command()
            .env("QNERO_RELEASE_SIGNATURE", fixture.0.join("missing.sig")),
        "authentication failed",
    );
}

#[test]
fn rejects_an_attackers_signed_bundle_with_the_pinned_key() {
    let fixture = Fixture::new();
    let attacker = TestDir::new();
    keygen(&attacker);
    let output = Command::new(BIN)
        .arg("sign")
        .arg("--root")
        .arg(fixture.0.join(SOURCE))
        .arg("--private-key")
        .arg(attacker.join("signer.release-key"))
        .arg("--revision")
        .arg(REVISION)
        .arg("--manifest")
        .arg(fixture.0.join("manifest.json"))
        .arg("--signature")
        .arg(fixture.0.join("manifest.sig"))
        .args(["pkg", "pkg-threaded"])
        .output()
        .unwrap();
    success(&output);
    fixture.reject(&mut fixture.command(), "trusted key");
}

#[test]
fn rejects_rollback_to_a_different_signed_revision() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.reject(
        fixture
            .command()
            .env("QNERO_RELEASE_REVISION", OTHER_REVISION),
        "expected commit",
    );
}

#[test]
fn rejects_a_modified_manifest_or_signature() {
    for path in ["manifest.json", "manifest.sig"] {
        let fixture = Fixture::new();
        fixture.sign(&["pkg", "pkg-threaded"]);
        let mut bytes = fs::read(fixture.0.join(path)).unwrap();
        bytes[20] ^= 1;
        fixture.0.write(path, bytes);
        fixture.reject(&mut fixture.command(), "trusted key");
    }
}

#[test]
fn rejects_edited_glue_and_worker_even_when_exports_still_match() {
    for (path, bytes) in [FILES[0], FILES[4]] {
        let fixture = Fixture::new();
        fixture.sign(&["pkg", "pkg-threaded"]);
        fixture.0.write(
            &format!("{SOURCE}/{path}"),
            bytes.replace("{}", "{ }").replace("= 1", "= 2"),
        );
        fixture.reject(&mut fixture.command(), "does not match");
    }
}

#[test]
fn requires_glue_and_worker_coverage_and_rejects_extra_copied_files() {
    for omitted in [FILES[0].0, FILES[4].0] {
        let fixture = Fixture::new();
        let selected: Vec<_> = FILES
            .iter()
            .map(|(path, _)| *path)
            .filter(|path| *path != omitted)
            .collect();
        fixture.sign(&selected);
        fixture.reject(&mut fixture.command(), "leaves out required file");
    }
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.0.write(
        &format!("{SOURCE}/pkg-threaded/extra.js"),
        "unsigned worker",
    );
    fixture.reject(&mut fixture.command(), "leaves out required file");
}

#[test]
fn rejects_symlinked_artifacts() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    let path = fixture.0.join(&format!("{SOURCE}/{}", FILES[0].0));
    fs::remove_file(&path).unwrap();
    fixture.0.write("outside.js", GLUE);
    symlink(fixture.0.join("outside.js"), path).unwrap();
    fixture.reject(&mut fixture.command(), "symlink");
}

#[test]
fn signed_stale_threaded_exports_leave_both_previous_packages_intact() {
    let fixture = Fixture::new();
    fixture.0.write(
        &format!("{SOURCE}/{}", FILES[2].0),
        "export function oldName() {}\n",
    );
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.reject(&mut fixture.command(), "threaded prover is stale");
}

#[test]
fn missing_module_leaves_both_previous_packages_intact() {
    let fixture = Fixture::new();
    fs::remove_file(fixture.0.join(&format!("{SOURCE}/{}", FILES[3].0))).unwrap();
    fixture.sign(&["pkg", "pkg-threaded"]);
    fixture.reject(&mut fixture.command(), "threaded prover wasm is missing");
}

#[test]
fn stages_the_snapshot_when_original_files_change_after_verification() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    let wrapper = fixture.0.join("verifier-wrapper.sh");
    fixture.0.write("verifier-wrapper.sh", b"#!/usr/bin/env bash\nset -euo pipefail\n\"${REAL_QNERO_RELEASE}\" \"$@\"\nprintf 'changed after verification' > \"${IMPORTED_GLUE}\"\n");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let output = fixture
        .command()
        .env("QNERO_RELEASE_VERIFIER", wrapper)
        .env("REAL_QNERO_RELEASE", BIN)
        .env(
            "IMPORTED_GLUE",
            fixture.0.join(&format!("{SOURCE}/{}", FILES[0].0)),
        )
        .output()
        .unwrap();
    fixture.assert_staged(&output);
    assert_eq!(
        fs::read(fixture.0.join(&format!("{SOURCE}/{}", FILES[0].0))).unwrap(),
        b"changed after verification"
    );
}

#[test]
fn local_build_staging_works_without_release_keys() {
    let fixture = Fixture::new();
    let output = fixture
        .command()
        .env("QNERO_WASM_PREBUILT", "0")
        .env_remove("QNERO_RELEASE_PUBLIC_KEY")
        .env_remove("QNERO_RELEASE_VERIFIER")
        .output()
        .unwrap();
    fixture.assert_staged(&output);
}

#[test]
fn refuses_an_invalid_prebuilt_flag() {
    let fixture = Fixture::new();
    fixture.reject(
        fixture.command().env("QNERO_WASM_PREBUILT", "yes"),
        "must be 0 or 1",
    );
}

#[test]
fn needs_both_modules_and_threaded_staging() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    let mut cmd = Command::new("bash");
    cmd.arg(fixture.0.join("wallet-web/scripts/stage-wasm.sh"))
        .env("QNERO_WASM_PREBUILT", "1");
    fixture.reject(&mut cmd, "needs --threaded");
    fs::remove_dir_all(fixture.0.join(&format!("{SOURCE}/pkg-threaded"))).unwrap();
    fixture.reject(&mut fixture.command(), "no threaded module");
}

// Keep paths passed to the script as real filesystem paths, including spaces.
#[test]
fn accepts_a_trusted_public_key_path_with_spaces() {
    let fixture = Fixture::new();
    fixture.sign(&["pkg", "pkg-threaded"]);
    let public = fixture.0.join("trusted public.pub");
    fs::copy(fixture.0.join("trusted.pub"), &public).unwrap();
    assert!(Path::new(&public).exists());
    fixture.assert_staged(
        &fixture
            .command()
            .env("QNERO_RELEASE_PUBLIC_KEY", public)
            .output()
            .unwrap(),
    );
}
