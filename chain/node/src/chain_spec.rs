use qnero_runtime::{
	genesis_config_presets::{
		HEISENBERG_RUNTIME_PRESET, MAINNET_RUNTIME_PRESET, PLANCK_RUNTIME_PRESET,
		QNERO_TESTNET_RUNTIME_PRESET,
	},
	WASM_BINARY,
};
use sc_service::{ChainType, Properties};
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
///
/// The symbol is written in a second place, and the two have to agree:
/// `runtime/build.rs` passes it to `enable_metadata_hash`, which is the label
/// an offline or hardware signer displays when it decodes a call under the
/// `on-chain-release-build` feature. Change one and change the other.
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

/// Heisenberg, an internal integration testnet.
///
/// Genesis intentionally endows the well-known Dilithium accounts
/// (`crystal_alice` / `dilithium_bob` / `crystal_charlie`, seeds `[0]/` /
/// `[1]` / `[2]`) and uses them as treasury signers. Those private keys are
/// public by design so integrators and CI can exercise treasury and transfer
/// flows without distributing secrets. They used to seed a tech collective
/// too, which the runtime no longer has. Tokens have no monetary value; the network may be reset. Do not
/// treat Heisenberg key material, balances, or authority as production-grade.
///
/// The upstream telemetry endpoint and bootnodes are gone. This builder emits
/// this tree's genesis, so upstream's peers refuse it on genesis hash, and an
/// operator who started it published a node name, a client version and a block
/// height to a third party's telemetry server for a network it was never on.
/// Both fields sit outside genesis, so removing them changes no chain. Qnero
/// fills them in when Qnero runs peers and a telemetry server of its own.
pub fn heisenberg_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Heisenberg")
	.with_id("heisenberg")
	.with_protocol_id("heisenberg")
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(HEISENBERG_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// Mainnet. Genesis comes from the `mainnet` runtime preset; the allocation
/// table is `runtime/src/genesis_config_presets/mainnet_vesting.rs`. Spec
/// building panics until that table is finalized. Bootnodes are added once
/// infrastructure exists (`bootNodes` is outside genesis).
///
/// The name and the protocol id are Qnero's. They answered `Quantus` and
/// `quantus` until this pass, on a preset that builds this tree's runtime, and
/// a spec file is the one artifact no runtime upgrade reaches: a wallet, an
/// explorer or an exchange handed that file would have labelled a Qnero chain
/// with upstream's name for as long as it held the file. The upstream
/// telemetry endpoint is gone for the reason given on `heisenberg_chain_spec`.
pub fn mainnet_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Qnero")
	.with_id("mainnet")
	.with_protocol_id("qnero")
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(MAINNET_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// Planck network: live treasury signers plus a faucet, and dev dilithium
/// accounts for testing. Upstream telemetry and bootnodes are gone, for the
/// reason given on [`heisenberg_chain_spec`].
pub fn planck_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Planck")
	.with_id("planck")
	.with_protocol_id("planck")
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(PLANCK_RUNTIME_PRESET)
	.with_properties(properties)
	.build())
}

/// The Qnero public testnet.
///
/// The first chain in this file that is Qnero's own network rather than an
/// upstream identity kept for reference. Its genesis is the `qnero-testnet`
/// runtime preset: one endowed faucet account, a 120 s target, and a mining
/// difficulty sized for the hash rate the chain has on day one.
///
/// `bootNodes` is empty here and stays empty in the committed raw spec. It
/// sits outside genesis, so the peer id of the seed node is written into the
/// file after the key exists and the genesis hash does not move
/// (`docs/TESTNET.md`). `telemetryEndpoints` stays absent for the reason given
/// on [`heisenberg_chain_spec`]: Qnero runs no telemetry server, and telemetry
/// defaults on for a `ChainType::Live` chain, so the node is also started with
/// `--no-telemetry`.
pub fn qnero_testnet_chain_spec() -> Result<ChainSpec, String> {
	let properties = qnero_properties();

	Ok(ChainSpec::builder(
		WASM_BINARY.ok_or_else(|| "Runtime wasm not available".to_string())?,
		None,
	)
	.with_name("Qnero Testnet")
	.with_id("qnero-testnet")
	.with_protocol_id("qnero-testnet")
	.with_chain_type(ChainType::Live)
	.with_genesis_config_preset_name(QNERO_TESTNET_RUNTIME_PRESET)
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
	/// row here is a spec whose properties nothing checks, so every name in
	/// `genesis_config_presets::preset_names`, which is the runtime's own
	/// list, has to find a builder below. The list is three or four names long
	/// depending on `mainnet_vesting::FINALIZED`, so its length is the wrong
	/// thing to assert: the builders are all checked, and the list is checked
	/// against them by name.
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

		let built: [(&str, Result<ChainSpec, String>); 5] = [
			(sp_genesis_builder::DEV_RUNTIME_PRESET, development_chain_spec()),
			(HEISENBERG_RUNTIME_PRESET, heisenberg_chain_spec()),
			(PLANCK_RUNTIME_PRESET, planck_chain_spec()),
			(MAINNET_RUNTIME_PRESET, mainnet_chain_spec()),
			(QNERO_TESTNET_RUNTIME_PRESET, qnero_testnet_chain_spec()),
		];

		for listed in qnero_runtime::genesis_config_presets::preset_names() {
			assert!(
				built.iter().any(|(name, _)| *name == listed),
				"the runtime lists the preset {listed:?} and this file has no builder for \
				 it, so its chain properties are checked by nothing"
			);
		}

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
