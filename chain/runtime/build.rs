/// The token symbol and decimals committed into the metadata hash.
///
/// `CheckMetadataHash` binds this, and it is what an offline or a hardware
/// signer displays when it decodes a call, so it has to be the symbol every
/// chain spec names: `QNR`, 12 decimals, the same pair `qnero_properties` in
/// `node/src/chain_spec.rs` writes. It said `UNIT`, the Substrate template's
/// placeholder, which would have shown a signing device one unit while every
/// spec file said another. The feature is on only under
/// `on-chain-release-build`, so the drift was invisible in a development
/// build and would have shipped in a release one.
#[cfg(all(feature = "std", feature = "metadata-hash"))]
fn main() {
	substrate_wasm_builder::WasmBuilder::init_with_defaults()
		.enable_metadata_hash("QNR", 12)
		.build();
}

#[cfg(all(feature = "std", not(feature = "metadata-hash")))]
fn main() {
	substrate_wasm_builder::WasmBuilder::build_using_defaults();
}

/// The wasm builder is deactivated when compiling
/// this crate for wasm to speed up the compilation.
#[cfg(not(feature = "std"))]
fn main() {}
