use quantus_runtime::{
	genesis_config_presets::{
		HEISENBERG_RUNTIME_PRESET, MAINNET_RUNTIME_PRESET, PLANCK_RUNTIME_PRESET,
	},
	WASM_BINARY,
};
use sc_service::{ChainType, Properties};
use sc_telemetry::TelemetryEndpoints;
use serde_json::json;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

/// Chain properties, one set for every preset this node builds.
///
/// The token symbol is `QNR` on every Qnero chain, dev and live alike. It is
/// one function rather than four literals because the symbol is the one field
/// of a chain spec a runtime upgrade cannot correct: wallets, explorers and
/// exchanges read it out of the spec file an operator already holds, so a
/// preset that shipped another symbol would keep naming another unit until
/// every one of them was handed a new file. `every_preset_names_the_token_qnr`
/// is the test.
pub(crate) fn qnero_properties() -> Properties {
	let mut properties = Properties::new();
	properties.insert("tokenDecimals".into(), json!(12));
	properties.insert("tokenSymbol".into(), json!("QNR"));
	properties.insert("ss58Format".into(), json!(189));
	properties
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Qnero DevNet wasm not available".to_string())?,
		None,
	)
	.with_name("Qnero DevNet")
	.with_id("qnero-dev")
	.with_protocol_id("qnero-devnet")
	.with_chain_type(ChainType::Development)
	.with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// Heisenberg — internal integration testnet, **not** mainnet.
///
/// Genesis intentionally endows the well-known Dilithium accounts
/// (`crystal_alice` / `dilithium_bob` / `crystal_charlie`, seeds `[0]/` /
/// `[1]` / `[2]`) and uses them as treasury signers and tech-collective
/// members. Those private keys are public by design so integrators and CI can
/// exercise governance, treasury, and transfer flows without distributing
/// secrets. Tokens have no monetary value; the network may be reset. Do not
/// treat Heisenberg key material, balances, or authority as production-grade.
pub fn heisenberg_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	let telemetry_endpoints = TelemetryEndpoints::new(vec![(
		"/dns/shard-telemetry.quantus.cat/tcp/443/x-parity-wss/%2Fsubmit%2F".to_string(),
		0,
	)])
	.expect("Telemetry endpoints config is valid; qed");

	let boot_nodes = vec![
		"/dns/a1-p2p-heisenberg.quantus.cat/tcp/30333/p2p/Qmdts9fu3NCMFnvLdD1dHAHFer8EPzVDXxVnyPxRKA3Gkt"
			.parse()
			.unwrap(),
		"/dns/a2-p2p-heisenberg.quantus.cat/tcp/30333/p2p/QmcKHndoiNRdiT6iVp6ugj8bNse5Vd5WmCoE9YWn9kNaTM"
			.parse()
			.unwrap(),
	];

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Heisenberg")
	.with_id("heisenberg")
	.with_protocol_id("heisenberg")
	.with_boot_nodes(boot_nodes)
	.with_telemetry_endpoints(telemetry_endpoints)
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(HEISENBERG_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// Mainnet. Genesis comes from the `mainnet` runtime preset; the allocation
/// table is `runtime/src/genesis_config_presets/mainnet_vesting.rs`. Spec
/// building panics until that table is finalized. Bootnodes are added once
/// infrastructure exists (`bootNodes` is outside genesis).
pub fn mainnet_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	let telemetry_endpoints = TelemetryEndpoints::new(vec![(
		"/dns/shard-telemetry.quantus.cat/tcp/443/x-parity-wss/%2Fsubmit%2F".to_string(),
		0,
	)])
	.expect("Telemetry endpoints config is valid; qed");

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Quantus")
	.with_id("mainnet")
	.with_protocol_id("quantus")
	.with_telemetry_endpoints(telemetry_endpoints)
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(MAINNET_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// Planck network — live treasury signers + faucet; dev dilithium accounts for testing.
pub fn planck_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	let telemetry_endpoints = TelemetryEndpoints::new(vec![(
		"/dns/shard-telemetry.quantus.cat/tcp/443/x-parity-wss/%2Fsubmit%2F".to_string(),
		0,
	)])
	.expect("Telemetry endpoints config is valid; qed");

	let boot_nodes = vec![
		"/dns/a1-p2p-planck.quantus.cat/tcp/30333/p2p/QmQ4AywkRZuv2L4XKb71Y3erk2DpQPNUTmMS2LGEEr5q8r"
			.parse()
			.unwrap(),
		"/dns/a2-p2p-planck.quantus.cat/tcp/30333/p2p/QmZT5LVJjBWf3QeJY6JKcFY6bCJoWucji96pKwpgbfTgic"
			.parse()
			.unwrap(),
		"/ip4/72.61.118.55/tcp/30333/p2p/QmbctLKQojifo6bym7a1ypph55n1nSw58YZGDkGtgRNVmF"
			.parse()
			.unwrap(),
	];

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Planck")
	.with_id("planck")
	.with_protocol_id("planck")
	.with_boot_nodes(boot_nodes)
	.with_telemetry_endpoints(telemetry_endpoints)
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(PLANCK_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Every preset this node builds names the same token, `QNR`.
	///
	/// The symbol reached v1 split four ways: `QNR` on the dev preset, `HEI`
	/// on Heisenberg, `PLK` on Planck and `QTC` on mainnet, with the docs
	/// saying `QTC`. A wallet, an explorer and an exchange each read the symbol
	/// out of the chain spec rather than out of the runtime, so a split symbol
	/// is a split unit for every one of them, and no runtime upgrade corrects
	/// it: the spec file is already in the operator's hand.
	///
	/// Two halves, and the split is deliberate. [`qnero_properties`] is the one
	/// map every builder reads, so pinning it pins every preset's symbol
	/// wherever this test runs, `SKIP_WASM_BUILD=1` included. Building each
	/// preset is what proves the builders still read it, and that half needs
	/// the runtime wasm, so without it every builder returns its own
	/// "wasm not available" and the match below demands exactly that error and
	/// nothing else.
	///
	/// It also pins the preset list. A preset added to the runtime without a
	/// row here is a spec whose properties nothing checks, so the count is
	/// asserted against `genesis_config_presets::preset_names`, which is the
	/// runtime's own list.
	#[test]
	fn every_preset_names_the_token_qnr() {
		let properties = qnero_properties();
		assert_eq!(
			properties.get("tokenSymbol").and_then(|symbol| symbol.as_str()),
			Some("QNR"),
			"the one properties map every preset reads does not name the token QNR"
		);
		assert_eq!(properties.get("tokenDecimals").and_then(|value| value.as_u64()), Some(12));
		assert_eq!(properties.get("ss58Format").and_then(|value| value.as_u64()), Some(189));

		let built: [(&str, Result<ChainSpec, String>); 4] = [
			("dev", development_chain_spec()),
			(HEISENBERG_RUNTIME_PRESET, heisenberg_chain_spec()),
			(PLANCK_RUNTIME_PRESET, planck_chain_spec()),
			(MAINNET_RUNTIME_PRESET, mainnet_chain_spec()),
		];

		assert_eq!(
			built.len(),
			quantus_runtime::genesis_config_presets::preset_names().len(),
			"the runtime's preset list moved; every preset needs a builder here or its \
			 chain properties are checked by nothing"
		);

		for (name, spec) in built {
			match spec {
				Ok(spec) => assert_eq!(
					spec.properties(),
					properties,
					"preset {name:?} does not carry the one Qnero properties map"
				),
				Err(error) => assert!(
					error.contains("wasm not available"),
					"preset {name:?} failed to build for a reason that is not a missing \
					 runtime wasm: {error}"
				),
			}
		}
	}
}
