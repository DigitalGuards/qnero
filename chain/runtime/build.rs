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
	runtime_builder().enable_metadata_hash("QNR", 12).build();
}

#[cfg(all(feature = "std", not(feature = "metadata-hash")))]
fn main() {
	runtime_builder().build();
}

/// The wasm builder is deactivated when compiling
/// this crate for wasm to speed up the compilation.
#[cfg(not(feature = "std"))]
fn main() {}

/// Keep nested resolution pinned and source locations portable in published WASM.
#[cfg(feature = "std")]
fn runtime_builder() -> substrate_wasm_builder::WasmBuilder {
	use std::{env, path::PathBuf};

	let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
	let workspace = manifest.parent().expect("runtime belongs to the chain workspace");
	let source = workspace.parent().expect("chain belongs to the Qnero checkout");
	assert!(workspace.join("Cargo.lock").is_file(), "chain workspace lockfile is required");
	// The upstream builder searches from OUT_DIR unless this hint is supplied.
	env::set_var("WASM_BUILD_WORKSPACE_HINT", workspace);
	println!("cargo:rerun-if-changed={}", workspace.join("Cargo.lock").display());
	for name in ["CARGO_HOME", "HOME", "USERPROFILE"] {
		println!("cargo:rerun-if-env-changed={name}");
	}
	let cargo_home = env::var_os("CARGO_HOME")
		.map(PathBuf::from)
		.or_else(|| {
			env::var_os("HOME")
				.or_else(|| env::var_os("USERPROFILE"))
				.map(|home| PathBuf::from(home).join(".cargo"))
		})
		.expect("CARGO_HOME or a user home is required for portable runtime paths");
	let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
	// Cargo layout: target/profile/build/package-hash/out. This also covers
	// generated files when the target directory is outside the source tree.
	let target = output.ancestors().nth(4).expect("Cargo target directory exists");
	let mut builder = substrate_wasm_builder::WasmBuilder::init_with_defaults();
	for (path, alias) in [(source, "/qnero"), (cargo_home.as_path(), "/cargo"), (target, "/target")]
	{
		let resolved = path.canonicalize().expect("runtime source directory exists");
		for prefix in [path, resolved.as_path()] {
			let prefix = prefix.to_str().expect("runtime build paths must be UTF-8");
			assert!(
				!prefix.chars().any(char::is_whitespace),
				"WASM builder flags require build paths without whitespace"
			);
			builder = builder.append_to_rust_flags(format!("--remap-path-prefix={prefix}={alias}"));
		}
	}
	// The standard library's own sources. With the `rust-src` component
	// installed, rustc resolves the library's virtual `/rustc/<commit>` paths to
	// the local copy under the toolchain's sysroot, and those real paths reach
	// panic locations in the wasm: a runner's `/home/runner/.rustup/...` did.
	// Mapping them back to the virtual form makes the runtime the same bytes
	// with or without the component.
	if let Some((sysroot, commit)) = toolchain_sources() {
		let library = sysroot.join("lib/rustlib/src/rust");
		let prefix = library.to_str().expect("toolchain paths must be UTF-8");
		assert!(
			!prefix.chars().any(char::is_whitespace),
			"WASM builder flags require build paths without whitespace"
		);
		builder =
			builder.append_to_rust_flags(format!("--remap-path-prefix={prefix}=/rustc/{commit}"));
	}
	builder
}

/// The active toolchain's sysroot and the commit its library paths are
/// virtualised under, read from the compiler cargo runs for this build.
#[cfg(feature = "std")]
fn toolchain_sources() -> Option<(std::path::PathBuf, String)> {
	use std::process::Command;

	let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
	let sysroot = Command::new(&rustc).args(["--print", "sysroot"]).output().ok()?;
	let version = Command::new(&rustc).arg("-vV").output().ok()?;
	let sysroot = String::from_utf8(sysroot.stdout).ok()?.trim().to_owned();
	let commit = String::from_utf8(version.stdout)
		.ok()?
		.lines()
		.find_map(|line| line.strip_prefix("commit-hash: "))?
		.trim()
		.to_owned();
	Some((sysroot.into(), commit))
}
