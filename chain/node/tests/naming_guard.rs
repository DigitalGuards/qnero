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
//! - `--help`, both the root one and every subcommand's, since a subcommand's help is where an
//!   upstream doc comment lands when a subtree merge restores one.
//! - the chain spec of every `--chain` id this node accepts: its `name`, `id`, `protocolId` and
//!   `tokenSymbol` are what a wallet, an explorer and an exchange read out of the spec file they
//!   hold, so a wrong name or a wrong symbol there is wrong everywhere and no runtime upgrade
//!   corrects it.
//!
//! `CARGO_BIN_EXE_qnero-node` is the binary Cargo built for this test, so the
//! flag halves cannot be skipped and cannot run against a stale build.
//!
//! The fourth surface, the startup banner `sc_cli` prints before any other log
//! line, is out of reach from here: it appears under neither flag. It is
//! covered by `the_startup_banner_names_qnero_and_no_upstream_maintainer` in
//! `src/command.rs`, which reads `impl_name`, `author`, `description` and
//! `support_url` directly.

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

/// Fail with the offending lines only: `--help` is a hundred lines and a chain
/// spec is megabytes.
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

/// Every subcommand's own help, which the root `--help` does not carry.
///
/// `RunCmd`'s flags are flattened into the root help, so a `quantus` string
/// there shows up in the test above. A doc comment on `purge-chain`, on
/// `build-spec` or on the `key` tree does not: it appears only under that
/// subcommand's `--help`, which is where an upstream doc comment lands when a
/// subtree merge restores one. One process spawn each, against the binary
/// Cargo has already built.
#[test]
fn no_subcommand_help_says_quantus() {
	let subcommands: [&[&str]; 10] = [
		&["key"],
		&["key", "qnero"],
		&["build-spec"],
		&["check-block"],
		&["export-blocks"],
		&["export-state"],
		&["import-blocks"],
		&["purge-chain"],
		&["revert"],
		&["chain-info"],
	];

	for subcommand in subcommands {
		let mut args = subcommand.to_vec();
		args.push("--help");
		let output = node(&args);
		let printed = format!("{}{}", output.stdout, output.stderr);
		assert!(output.ok, "`qnero-node {} --help` failed: {printed}", subcommand.join(" "));
		assert_says_nothing_of_quantus(&format!("`{} --help`", subcommand.join(" ")), &printed);
	}
}

/// Build one chain spec with the binary, or report that the wasm is absent.
///
/// A spec needs the runtime wasm, which `SKIP_WASM_BUILD=1` omits: without it
/// every preset builder returns its own "wasm not available" and there is no
/// spec to read. That one case is a skip, and only when the variable is
/// actually set, so a missing wasm for any other reason is still a failure.
fn chain_spec(id: &str) -> Option<serde_json::Value> {
	let output = node(&["build-spec", "--chain", id, "--disable-default-bootnode"]);
	if !output.ok {
		let skipped_the_wasm = std::env::var_os("SKIP_WASM_BUILD").is_some() &&
			output.stderr.contains("wasm not available");
		if skipped_the_wasm {
			eprintln!(
				"SKIP_WASM_BUILD is set and this binary carries no runtime wasm; \
				 skipping the chain spec half of the rename guard for --chain {id}"
			);
			return None;
		}
		panic!("build-spec --chain {id} failed: {}", output.stderr);
	}

	Some(serde_json::from_str(&output.stdout).expect("build-spec writes a JSON chain spec"))
}

/// Whether the runtime will build the `mainnet` preset at all.
///
/// `preset_names` is the runtime's own list and it omits `mainnet` while
/// `mainnet_vesting::FINALIZED` is `false`, which it is: the allocation table
/// still pays a placeholder address nobody holds a key for, so `build-spec
/// --chain mainnet` refuses: a spec built from that table would mint 2% of the
/// supply into an account that can never spend it. The refusal is the flag
/// doing its job. Independent cryptographic qualification is also required.
/// The two `mainnet` ids keep their rows in the list below, so this guard
/// covers them again when both release conditions are satisfied.
fn the_mainnet_preset_builds() -> bool {
	use qnero_runtime::genesis_config_presets::{preset_names, MAINNET_RUNTIME_PRESET};

	preset_names()
		.iter()
		.any(|listed| AsRef::<str>::as_ref(listed) == MAINNET_RUNTIME_PRESET)
}

/// The public testnet's four identifying fields, pinned by value.
///
/// These are what a wallet, an explorer and a miner read out of the spec file
/// they are handed, and no runtime upgrade reaches a file somebody already
/// holds. They are also what the committed raw spec at
/// `node/chain-specs/qnero-testnet.json` carries, so a rename here without a
/// regeneration would leave the id in the file disagreeing with the id the
/// binary answers to.
#[test]
fn the_public_testnet_spec_names_qnero_testnet() {
	let Some(spec) = chain_spec("qnero-testnet") else { return };

	assert_eq!(spec["name"].as_str(), Some("Qnero Testnet"), "the testnet spec's name");
	assert_eq!(spec["id"].as_str(), Some("qnero-testnet"), "the testnet spec's id");
	assert_eq!(
		spec["protocolId"].as_str(),
		Some("qnero-testnet"),
		"the testnet spec's protocol id"
	);
	assert_eq!(
		spec["properties"]["tokenSymbol"].as_str(),
		Some("QNR"),
		"the testnet spec's token symbol"
	);
	assert_eq!(spec["chainType"].as_str(), Some("Live"), "the testnet spec's chain type");

	// Two fields that sit outside genesis and that a public spec must not
	// carry until Qnero runs the peers and the server they would name. The
	// bootnode list is filled in at deploy, from the key the seed node
	// actually holds.
	let bootnodes = spec["bootNodes"].as_array().expect("bootNodes is an array");
	assert!(bootnodes.is_empty(), "the testnet spec ships with a bootnode already in it");
	let telemetry = &spec["telemetryEndpoints"];
	assert!(
		telemetry.is_null() || telemetry.as_array().is_some_and(|list| list.is_empty()),
		"the testnet spec carries a telemetry endpoint: {telemetry}"
	);
}

/// Everything a spec says about itself, with the genesis dropped.
///
/// The genesis is the runtime wasm as hex and carries whatever byte sequences
/// the compiler emitted, including the crate names in its panic paths.
fn spec_header(spec: &serde_json::Value) -> String {
	let mut header = spec.clone();
	if let Some(object) = header.as_object_mut() {
		object.remove("genesis");
	}
	serde_json::to_string_pretty(&header).expect("the spec header re-serializes")
}

/// The dev chain spec, built by the binary itself. This is the one preset the
/// project runs, so its four identifying fields are pinned by value.
#[test]
fn the_dev_chain_spec_names_qnero_and_the_token_qnr() {
	let Some(spec) = chain_spec("dev") else { return };

	assert_eq!(spec["name"].as_str(), Some("Qnero DevNet"), "the dev spec's name");
	assert_eq!(spec["id"].as_str(), Some("qnero-dev"), "the dev spec's id");
	assert_eq!(spec["protocolId"].as_str(), Some("qnero-devnet"), "the dev spec's protocol id");
	assert_eq!(
		spec["properties"]["tokenSymbol"].as_str(),
		Some("QNR"),
		"the dev spec's token symbol"
	);

	assert_says_nothing_of_quantus("the dev chain spec outside its genesis", &spec_header(&spec));
}

/// Every `--chain` id this node accepts, and none of them says Quantus.
///
/// `mainnet` is why this test exists. It answered with the chain name
/// `Quantus` and the protocol id `quantus` while building this tree's runtime
/// genesis, and the dev-only guard above saw none of it, because a preset that
/// is never the one the project runs is still a preset the binary hands out on
/// request. A spec file is the artifact no runtime upgrade reaches: whoever
/// holds it reads the name in it until somebody hands them another file.
///
/// The list is `load_spec` in `src/command.rs`, aliases included. A new id
/// there needs a row here, and `every_chain_id_this_node_accepts_is_a_qnero_chain`
/// beside `load_spec` is what keeps the two lists the same length.
#[test]
fn no_chain_spec_this_node_builds_says_quantus() {
	for id in [
		"dev",
		"qnero-dev",
		"heisenberg",
		"heisenberg_live_spec",
		"planck",
		"planck_live_spec",
		"mainnet",
		"mainnet_live_spec",
		"qnero-testnet",
		"qnero-testnet_live_spec",
	] {
		if id.starts_with("mainnet") && !the_mainnet_preset_builds() {
			eprintln!(
				"the runtime does not list the mainnet preset, so --chain {id} builds no spec; \
				 skipping it here until the genesis allocation is decided"
			);
			continue;
		}
		let Some(spec) = chain_spec(id) else { return };

		assert_eq!(
			spec["properties"]["tokenSymbol"].as_str(),
			Some("QNR"),
			"--chain {id} does not name the token QNR"
		);
		assert_says_nothing_of_quantus(
			&format!("the --chain {id} spec outside its genesis"),
			&spec_header(&spec),
		);
	}
}
