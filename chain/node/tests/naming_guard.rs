//! The rename guard: nothing this binary answers an operator with says
//! "Quantus".
//!
//! Qnero forked the Quantus Network chain, and the fork kept every upstream
//! crate name it did not have to change: `pallet-zk-tree`, `sc-consensus-qpow`,
//! `qp-*`, `quantus-miner-api`. What it did change is the surface an operator
//! types and reads, because two names for one binary is what makes a bug
//! report unanswerable. The node package and the runtime package are
//! `qnero-node` and `qnero-runtime`, and this test is what keeps them that way
//! through the next subtree merge, which will arrive carrying upstream's names
//! in every file it touches.
//!
//! Three surfaces, and they are the three an operator meets first:
//!
//! - `--version`, the line every bug report opens with.
//! - `--help`, which carries the package description as its about text.
//! - the dev chain spec's `name`, `id` and `tokenSymbol`, which a wallet, an explorer and an
//!   exchange each read out of the spec file rather than out of the runtime, so a wrong symbol
//!   there is a wrong unit everywhere and no runtime upgrade corrects it.
//!
//! `CARGO_BIN_EXE_qnero-node` is the binary Cargo built for this test, so the
//! first two thirds cannot be skipped and cannot run against a stale build.
//!
//! The fourth surface, the startup banner `sc_cli` prints before any other log
//! line, is out of reach from here: it appears under neither flag. It is
//! covered by `the_startup_banner_names_qnero_and_no_upstream_maintainer` in
//! `src/command.rs`, which reads `impl_name`, `author` and `description`
//! directly.

use std::process::Command;

/// The binary under test, built by Cargo for this test target.
const NODE: &str = env!("CARGO_BIN_EXE_qnero-node");

/// The word this fork does not say to its operators, in the only spelling that
/// matters: lowercased, so `Quantus`, `QUANTUS` and `quantus-node` all match.
const FORBIDDEN: &str = "quantus";

struct Output {
	stdout: String,
	stderr: String,
	ok: bool,
}

fn node(args: &[&str]) -> Output {
	let output = Command::new(NODE)
		.args(args)
		.output()
		.unwrap_or_else(|error| panic!("running `{NODE} {}` failed: {error}", args.join(" ")));
	Output {
		stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
		stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		ok: output.status.success(),
	}
}

/// Fail with the offending line rather than with the whole stream: `--help` is
/// a hundred lines and a chain spec is megabytes.
fn assert_says_nothing_of_quantus(what: &str, text: &str) {
	let offending: Vec<&str> = text
		.lines()
		.filter(|line| line.to_ascii_lowercase().contains(FORBIDDEN))
		.collect();
	assert!(offending.is_empty(), "{what} still says Quantus:\n{}", offending.join("\n"));
}

#[test]
fn the_version_string_names_qnero_and_not_quantus() {
	let output = node(&["--version"]);
	assert!(output.ok, "--version failed: {}", output.stderr);
	assert!(
		output.stdout.to_ascii_lowercase().contains("qnero-node"),
		"--version does not name the binary qnero-node: {}",
		output.stdout
	);
	assert_says_nothing_of_quantus("--version", &output.stdout);
}

#[test]
fn the_help_text_names_qnero_and_not_quantus() {
	let output = node(&["--help"]);
	assert!(output.ok, "--help failed: {}", output.stderr);
	assert!(output.stdout.contains("Qnero"), "--help never says Qnero: {}", output.stdout);
	assert_says_nothing_of_quantus("--help", &output.stdout);
}

/// The dev chain spec, built by the binary itself.
///
/// This half needs the runtime wasm, which `SKIP_WASM_BUILD=1` omits: without
/// it `development_chain_spec` returns its own "wasm not available" and there
/// is no spec to read. That one case is a skip, and only when the variable is
/// actually set, so a missing wasm for any other reason is still a failure.
#[test]
fn the_dev_chain_spec_names_qnero_and_the_token_qnr() {
	let output = node(&["build-spec", "--chain", "dev", "--disable-default-bootnode"]);
	if !output.ok {
		let skipped_the_wasm = std::env::var_os("SKIP_WASM_BUILD").is_some() &&
			output.stderr.contains("wasm not available");
		if skipped_the_wasm {
			eprintln!(
				"SKIP_WASM_BUILD is set and this binary carries no runtime wasm; \
				 skipping the dev chain spec half of the rename guard"
			);
			return;
		}
		panic!("build-spec --chain dev failed: {}", output.stderr);
	}

	let spec: serde_json::Value =
		serde_json::from_str(&output.stdout).expect("build-spec writes a JSON chain spec");

	assert_eq!(spec["name"].as_str(), Some("Qnero DevNet"), "the dev spec's name");
	assert_eq!(spec["id"].as_str(), Some("qnero-dev"), "the dev spec's id");
	assert_eq!(spec["protocolId"].as_str(), Some("qnero-devnet"), "the dev spec's protocol id");
	assert_eq!(
		spec["properties"]["tokenSymbol"].as_str(),
		Some("QNR"),
		"the dev spec's token symbol"
	);

	// Everything except the genesis, which is the runtime wasm as hex and
	// carries whatever byte sequences the compiler emitted.
	let mut header = spec.clone();
	if let Some(object) = header.as_object_mut() {
		object.remove("genesis");
	}
	assert_says_nothing_of_quantus(
		"the dev chain spec outside its genesis",
		&serde_json::to_string_pretty(&header).expect("the spec header re-serializes"),
	);
}
