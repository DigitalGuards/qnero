#[cfg(feature = "runtime-benchmarks")]
use crate::benchmarking::{inherent_benchmark_data, RemarkBuilder, TransferKeepAliveBuilder};
use crate::{
	chain_spec,
	cli::{Cli, QuantusAddressType, QuantusKeySubcommand, Subcommand},
	service,
};
#[cfg(feature = "runtime-benchmarks")]
use frame_benchmarking_cli::{BenchmarkCmd, ExtrinsicFactory, SUBSTRATE_REFERENCE_HARDWARE};
use qnero_runtime::Block;
#[cfg(feature = "runtime-benchmarks")]
use qnero_runtime::EXISTENTIAL_DEPOSIT;
use qp_dilithium_crypto::{traits::WormholeAddress, Dilithium87Pair};
use qp_rusty_crystals_hdwallet::{
	derive_key_from_mnemonic, derive_wormhole_from_mnemonic, generate_mnemonic, mnemonic_to_seed,
	wormhole::WormholePair, SensitiveBytes32, SensitiveBytes64, QUANTUS_DILITHIUM_CHAIN_ID,
	QUANTUS_WORMHOLE_CHAIN_ID,
};
use rand::Rng;
use sc_cli::SubstrateCli;
use sc_network::config::{NodeKeyConfig, Secret};
use sc_service::{BlocksPruning, PartialComponents, PruningMode};
use sp_core::{
	crypto::{AccountId32, Ss58AddressFormat, Ss58Codec},
	Pair, H256,
};
#[cfg(feature = "runtime-benchmarks")]
use sp_keyring::Sr25519Keyring;
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, PartialEq)]
pub struct QuantusKeyDetails {
	pub address: String,
	pub raw_address: String,
	pub public_key_hex: String, // Full public key, hex encoded with "0x" prefix
	pub secret_key_hex: String, // Secret key, hex encoded with "0x" prefix
	pub seed_hex: String,       // Derived seed, hex encoded with "0x" prefix
	pub secret_phrase: Option<String>, // Newly generated mnemonic; None when caller supplied it
	pub inner_hash: Option<String>, // If wormhole key, this is first hash
}

impl Drop for QuantusKeyDetails {
	fn drop(&mut self) {
		self.secret_key_hex.zeroize();
		self.seed_hex.zeroize();
		if let Some(ref mut phrase) = self.secret_phrase {
			phrase.zeroize();
		}
	}
}

/// Trim a secret `String`, returning a `Zeroizing` copy and scrubbing the source
/// (including any leading/trailing whitespace that `trim()` would otherwise leave
/// in a discarded allocation).
fn take_trimmed_secret(mut value: String) -> Option<Zeroizing<String>> {
	let trimmed = value.trim();
	if trimmed.is_empty() {
		value.zeroize();
		return None;
	}
	let secret = Zeroizing::new(trimmed.to_string());
	value.zeroize();
	Some(secret)
}

/// Read a secret from stdin rather than argv, so it never appears in
/// `/proc/<pid>/cmdline`, shell history, or process-accounting/audit logs.
/// Prompts without echo on a terminal; otherwise reads one line (piped input).
/// The returned value is zeroized on drop; the untrimmed stdin buffer is scrubbed
/// before this returns.
#[allow(clippy::result_large_err)]
fn read_secret_from_stdin(prompt: &str) -> Result<Zeroizing<String>, sc_cli::Error> {
	use std::io::{BufRead, IsTerminal};
	let stdin = std::io::stdin();
	let value = if stdin.is_terminal() {
		rpassword::prompt_password(prompt)
			.map_err(|e| sc_cli::Error::Input(format!("failed to read secret: {e}")))?
	} else {
		let mut line = String::new();
		stdin
			.lock()
			.read_line(&mut line)
			.map_err(|e| sc_cli::Error::Input(format!("failed to read secret from stdin: {e}")))?;
		line
	};
	take_trimmed_secret(value)
		.ok_or_else(|| sc_cli::Error::Input("no secret provided on stdin".into()))
}

#[allow(clippy::result_large_err)]
pub fn generate_quantus_key(
	scheme: QuantusAddressType,
	seed: Option<String>,
	words: Option<String>,
	wallet_index: u32,
	no_derivation: bool,
) -> Result<QuantusKeyDetails, sc_cli::Error> {
	// Scrub caller-supplied secrets on every exit path (including early returns).
	let seed = seed.map(Zeroizing::new);
	let mut words = words.map(Zeroizing::new);

	match scheme {
		QuantusAddressType::Standard => {
			let mut words_to_print: Option<String> = None;
			let seed_for_pair: Zeroizing<Vec<u8>>;

			// Build the derivation path (all components must be hardened for lattice-based crypto)
			let path =
				format!("m/44'/{QUANTUS_DILITHIUM_CHAIN_ID}/{index}'/0'/0'", index = wallet_index);

			if let Some(ref words_phrase) = words {
				// Use provided mnemonic. The caller already knows it, so it is
				// deliberately NOT placed in `secret_phrase` for echoing back.
				if no_derivation {
					// Get raw seed from mnemonic (writes into `seed64`, which zeroizes on drop).
					let mut seed64 = SensitiveBytes64::zeroed();
					mnemonic_to_seed(words_phrase.to_string(), None, &mut seed64).map_err(|e| {
						eprintln!("Error processing provided words: {:?}", e);
						sc_cli::Error::Input("Failed to process provided words".into())
					})?;
					seed_for_pair = Zeroizing::new(seed64.as_bytes().to_vec());
				} else {
					println!("Deriving HD path: {}", path);
					let keypair =
						derive_key_from_mnemonic(words_phrase, None, &path).map_err(|e| {
							eprintln!("Error deriving from mnemonic: {:?}", e);
							sc_cli::Error::Input("Failed to derive from mnemonic".into())
						})?;
					let dilithium_pair = Dilithium87Pair::from_keypair(keypair);
					let account_id = AccountId32::from(dilithium_pair.public());
					return Ok(QuantusKeyDetails {
						address: account_id
							.to_ss58check_with_version(Ss58AddressFormat::custom(189)),
						raw_address: format!("0x{}", hex::encode(account_id)),
						public_key_hex: format!("0x{}", hex::encode(dilithium_pair.public())),
						secret_key_hex: format!("0x{}", hex::encode(dilithium_pair.secret_bytes())),
						seed_hex: "N/A (derived from mnemonic)".to_string(),
						secret_phrase: words_to_print,
						inner_hash: None,
					});
				}
			} else if let Some(ref hex_seed_str) = seed {
				// Slice off an optional 0x prefix without reallocating a second secret String.
				let hex = hex_seed_str.strip_prefix("0x").unwrap_or(hex_seed_str.as_str());

				if hex.len() != 128 {
					eprintln!(
						"Error: --seed must be a 128-character hex string (for a 64-byte seed)."
					);
					return Err("Invalid hex seed length".into());
				}
				let mut decoded_seed_bytes = hex::decode(hex).map_err(|_| {
					eprintln!("Error: --seed must be a valid hex string (0-9, a-f).");
					sc_cli::Error::Input("Invalid hex seed format".into())
				})?;
				if decoded_seed_bytes.len() != 64 {
					decoded_seed_bytes.zeroize();
					eprintln!("Error: Decoded hex seed must be exactly 64 bytes.");
					return Err("Invalid decoded hex seed length".into());
				}
				seed_for_pair = Zeroizing::new(std::mem::take(&mut decoded_seed_bytes));
			} else {
				// Generate new mnemonic from random entropy
				let mut entropy = [0u8; 32];
				rand::thread_rng().fill(&mut entropy);
				let sensitive_entropy = SensitiveBytes32::from(&mut entropy);
				let new_words = generate_mnemonic(sensitive_entropy).map_err(|e| {
					eprintln!("Error generating new words: {:?}", e);
					sc_cli::Error::Input("Failed to generate new words".into())
				})?;
				words_to_print = Some(new_words.to_string());

				if no_derivation {
					// Get raw seed from mnemonic (writes into `seed64`, which zeroizes on drop).
					let mut seed64 = SensitiveBytes64::zeroed();
					mnemonic_to_seed(new_words.to_string(), None, &mut seed64).map_err(|e| {
						eprintln!("Error converting mnemonic to seed: {:?}", e);
						sc_cli::Error::Input("Failed to convert mnemonic to seed".into())
					})?;
					seed_for_pair = Zeroizing::new(seed64.as_bytes().to_vec());
				} else {
					println!("Deriving HD path: {}", path);
					let keypair =
						derive_key_from_mnemonic(&new_words, None, &path).map_err(|e| {
							eprintln!("Error deriving from mnemonic: {:?}", e);
							sc_cli::Error::Input("Failed to derive from mnemonic".into())
						})?;
					drop(new_words);
					let dilithium_pair = Dilithium87Pair::from_keypair(keypair);
					let account_id = AccountId32::from(dilithium_pair.public());
					return Ok(QuantusKeyDetails {
						address: account_id
							.to_ss58check_with_version(Ss58AddressFormat::custom(189)),
						raw_address: format!("0x{}", hex::encode(account_id)),
						public_key_hex: format!("0x{}", hex::encode(dilithium_pair.public())),
						secret_key_hex: format!("0x{}", hex::encode(dilithium_pair.secret_bytes())),
						seed_hex: "N/A (derived from mnemonic)".to_string(),
						secret_phrase: words_to_print,
						inner_hash: None,
					});
				}
			};

			let dilithium_pair = Dilithium87Pair::from_seed(&seed_for_pair).map_err(|e| {
				eprintln!("Error creating Dilithium87Pair: {:?}", e);
				sc_cli::Error::Input("Failed to create keypair".into())
			})?;

			let account_id = AccountId32::from(dilithium_pair.public());
			let seed_hex = format!("0x{}", hex::encode(&seed_for_pair));
			// `seed_for_pair` zeroizes here when dropped.
			drop(seed_for_pair);

			Ok(QuantusKeyDetails {
				address: account_id.to_ss58check_with_version(Ss58AddressFormat::custom(189)),
				raw_address: format!("0x{}", hex::encode(account_id)),
				public_key_hex: format!("0x{}", hex::encode(dilithium_pair.public())),
				secret_key_hex: format!("0x{}", hex::encode(dilithium_pair.secret_bytes())),
				seed_hex,
				secret_phrase: words_to_print,
				inner_hash: None,
			})
		},
		QuantusAddressType::Wormhole => {
			let path =
				format!("m/44'/{QUANTUS_WORMHOLE_CHAIN_ID}/{index}'/0'/0'", index = wallet_index);
			let words_to_print;
			let words_phrase: Zeroizing<String> = if let Some(w) = words.take() {
				// Caller-supplied mnemonic: not echoed back.
				words_to_print = None;
				w
			} else {
				let mut entropy = [0u8; 32];
				rand::thread_rng().fill(&mut entropy);
				let sensitive_entropy = SensitiveBytes32::from(&mut entropy);
				let new_words = generate_mnemonic(sensitive_entropy).map_err(|e| {
					eprintln!("Error generating new words: {:?}", e);
					sc_cli::Error::Input("Failed to generate new words".into())
				})?;
				words_to_print = Some(new_words.to_string());
				new_words
			};

			let wormhole_pair = if no_derivation {
				let mut seed64 = SensitiveBytes64::zeroed();
				mnemonic_to_seed(words_phrase.to_string(), None, &mut seed64).map_err(|e| {
					eprintln!("Error processing provided words: {:?}", e);
					sc_cli::Error::Input("Failed to process provided words".into())
				})?;
				let mut seed32 = [0u8; 32];
				seed32.copy_from_slice(&seed64.as_bytes()[..32]);
				let mut sensitive_seed = SensitiveBytes32::from(&mut seed32);
				WormholePair::generate_new(&mut sensitive_seed)
			} else {
				println!("Deriving wormhole HD path: {}", path);
				derive_wormhole_from_mnemonic(&words_phrase, None, &path).map_err(|e| {
					eprintln!("Error deriving wormhole from mnemonic: {:?}", e);
					sc_cli::Error::Input("Failed to derive wormhole from mnemonic".into())
				})?
			};
			// `words_phrase` zeroizes on drop here.

			let wormhole_address = WormholeAddress(H256::from(*wormhole_pair.address()));
			let account_id = wormhole_address.into_account();

			Ok(QuantusKeyDetails {
				address: account_id.to_ss58check(),
				raw_address: format!("0x{}", hex::encode(account_id)),
				public_key_hex: format!("0x{}", hex::encode(wormhole_pair.address())),
				secret_key_hex: format!("0x{}", hex::encode(wormhole_pair.secret().as_bytes())),
				seed_hex: "N/A (Wormhole)".to_string(),
				secret_phrase: words_to_print,
				inner_hash: Some(hex::encode(wormhole_pair.first_hash())),
			})
		},
	}
}

impl SubstrateCli for Cli {
	fn impl_name() -> String {
		"Qnero Node".into()
	}

	fn impl_version() -> String {
		env!("SUBSTRATE_CLI_IMPL_VERSION").into()
	}

	fn description() -> String {
		env!("CARGO_PKG_DESCRIPTION").into()
	}

	/// The startup banner's byline, and the one place an operator reads a
	/// maintainer at every start.
	///
	/// `CARGO_PKG_AUTHORS` would answer "Quantus Network Developers
	/// <hello@quantus.com>" here, which is the upstream workspace's
	/// attribution and stays in `chain/Cargo.toml` where the crate metadata
	/// belongs. A Qnero node that prints it names the wrong maintainer and
	/// sends an operator's bug report to the wrong address. Upstream's credit
	/// is in `chain/LICENSE`, in each crate's `NOTICE` and in the repository
	/// README, where the licence puts it.
	fn author() -> String {
		"DigitalGuards <https://github.com/DigitalGuards/qnero>".into()
	}

	/// Where a panicking node tells its operator to send the report.
	///
	/// `sc_cli` prints this as the last line of `--help` and hands it to
	/// `sp_panic_handler`, so it is the address every panic message names. The
	/// Substrate node template's default is `support.anonymous.an`, a domain
	/// nobody owns, which upstream carried and this fork inherited. A bug
	/// report is unanswerable for the same reason a second name for the binary
	/// makes it unanswerable, so the byline above and this line have to move
	/// together.
	fn support_url() -> String {
		"https://github.com/DigitalGuards/qnero/issues".into()
	}

	/// 2017 is the Substrate node template's own default, carried through
	/// upstream. This repository's first commit is 2026.
	fn copyright_start_year() -> i32 {
		2026
	}

	/// Every id here builds its genesis from a preset compiled into this
	/// binary, so every chain this node starts on its own runs this tree's
	/// runtime.
	///
	/// Three raw specs used to be embedded beside them, one of which the empty
	/// id resolved to, and all three were upstream Quantus networks: their
	/// genesis `:code` carried a `quantus-runtime` with no `pallet-shielded`,
	/// no coinbase inherent and no `QneroCallFilter`. A node started with no
	/// `--chain` therefore ran none of v1's mandatory-privacy rules, while the
	/// author-label seam still derived a fresh reward account every block from
	/// `H(cvk, parent_hash)` whose wormhole preimage nobody held. A raw spec
	/// belongs back here once one is generated from a Qnero preset against a
	/// live Qnero network, and `every_chain_id_this_node_accepts_is_a_qnero_chain`
	/// is what holds the line in the meantime.
	///
	/// The empty id is a refusal that names the chains, since `sc_cli` maps
	/// both a missing `--chain` and a missing `--dev` to it and a network is
	/// too large a thing to pick for an operator who named none.
	fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
		Ok(match id {
			// `--dev` resolves to this id, so it stays "dev" while the spec it
			// builds is Qnero's.
			"dev" | "qnero-dev" =>
				Box::new(chain_spec::development_chain_spec()?) as Box<dyn sc_service::ChainSpec>,
			"heisenberg" | "heisenberg_live_spec" =>
				Box::new(chain_spec::heisenberg_chain_spec()?) as Box<dyn sc_service::ChainSpec>,
			"planck" | "planck_live_spec" =>
				Box::new(chain_spec::planck_chain_spec()?) as Box<dyn sc_service::ChainSpec>,
			"mainnet" | "mainnet_live_spec" =>
				Box::new(chain_spec::mainnet_chain_spec()?) as Box<dyn sc_service::ChainSpec>,
			"" =>
				return Err("no chain was named. Pass --dev for a throwaway development chain, \
				            or --chain with one of dev, heisenberg, planck, mainnet, or the path \
				            to a chain spec file"
					.to_string()),
			path =>
				Box::new(chain_spec::ChainSpec::from_json_file(std::path::PathBuf::from(path))?)
					as Box<dyn sc_service::ChainSpec>,
		})
	}
}

/// The transparent entry's consensus rule, said where a key is minted.
///
/// `runtime/src/extrinsic.rs` refuses a signed extrinsic carrying the ML-DSA-65
/// variant of `DilithiumSignatureScheme` with `InvalidTransaction::BadSigner`.
/// The vendored `sc-cli` fork still offers `--scheme dilithium65` on its key
/// commands, minting material the entry refuses, and that tree stays as upstream
/// wrote it so the next subtree merge is clean. Qnero's own dispatch is where the
/// two meet. A level-3 key minted here carries an address that looks like any
/// other Qnero address, and the first sign that it cannot spend arrives at the
/// entry as `BadSigner`, a code that also means "the signature did not verify";
/// an operator reading it debugs the payload, the nonce and the genesis hash
/// long before suspecting the scheme. Say it at the point of minting instead.
#[allow(clippy::result_large_err)]
fn ensure_key_scheme_is_the_one_the_chain_admits(
	cmd: &sc_cli::KeySubcommand,
) -> sc_cli::Result<()> {
	let scheme = match cmd {
		sc_cli::KeySubcommand::Generate(cmd) => Some(cmd.crypto_scheme.scheme),
		sc_cli::KeySubcommand::Inspect(cmd) => Some(cmd.crypto_scheme.scheme),
		sc_cli::KeySubcommand::Insert(cmd) => Some(cmd.scheme),
		// Node keys are the p2p identity, one scheme wide, and carry no
		// `--scheme` flag of their own.
		sc_cli::KeySubcommand::GenerateNodeKey(_) | sc_cli::KeySubcommand::InspectNodeKey(_) =>
			None,
	};

	// What the entry refuses, this refuses at the point of minting.
	if matches!(scheme, Some(sc_cli::CryptoScheme::Dilithium65)) {
		return Err(sc_cli::Error::Input(
			"Qnero has one signature scheme at the transparent entry, ML-DSA-87. \
			 `--scheme dilithium65` mints a key this chain refuses: a signed extrinsic \
			 carrying the ML-DSA-65 variant is invalid and is answered with BadSigner \
			 before it is verified (runtime/src/extrinsic.rs), so the account could \
			 never spend what it holds. Use `--scheme dilithium87`, or \
			 `qnero-node key qnero` for a transparent address."
				.to_string(),
		));
	}

	Ok(())
}

/// Parse and run command line arguments
#[allow(clippy::result_large_err)]
pub fn run() -> sc_cli::Result<()> {
	sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));

	let cli = Cli::from_args();
	match &cli.subcommand {
		Some(Subcommand::Key(cmd)) => {
			match cmd {
				QuantusKeySubcommand::Sc(sc_cmd) => {
					ensure_key_scheme_is_the_one_the_chain_admits(sc_cmd)?;
					sc_cmd.run(&cli)
				},
				QuantusKeySubcommand::Quantus {
					scheme,
					seed,
					words,
					wallet_index,
					no_derivation,
					verbose,
				} => {
					// Secrets are read from stdin, never from argv (see cli.rs).
					// Move out of Zeroizing into generate_quantus_key, which immediately
					// re-wraps and zeroizes on every exit path.
					let seed_value = if *seed {
						Some(std::mem::take(&mut *read_secret_from_stdin(
							"Hex master seed (128 hex chars): ",
						)?))
					} else {
						None
					};
					let words_value = if *words {
						Some(std::mem::take(&mut *read_secret_from_stdin("BIP39 mnemonic: ")?))
					} else {
						None
					};
					match generate_quantus_key(
						scheme.clone(),
						seed_value,
						words_value,
						*wallet_index,
						*no_derivation,
					) {
						Ok(details) => {
							match scheme {
								QuantusAddressType::Standard => {
									println!("Generating Qnero Standard address...");
									if *seed {
										println!("Using provided hex seed...");
									} else if *words {
										println!("Using provided words phrase...");
									} else {
										println!(
                                            "No seed or words provided. Generating a new 24-word phrase..."
                                        );
									}

									if *no_derivation {
										println!("Derivation disabled (--no-derivation). Using master seed.");
									} else {
										println!(
											"Deriving child with index {} (path m/44'/{}/{}'/0'/0')",
											wallet_index, QUANTUS_DILITHIUM_CHAIN_ID, wallet_index
										);
									}

									println!(
										"XXXXXXXXXXXXXXXX Qnero Account Details XXXXXXXXXXXXXXXXXX"
									);
									if let Some(phrase) = &details.secret_phrase {
										println!("Secret phrase: {}", phrase);
									}
									// Include account index and derivation path in the output
									println!("Account index: {}", wallet_index);
									if *no_derivation {
										println!("Derivation path: master (no derivation)");
									} else {
										println!(
											"Derivation path: m/44'/{}/{}'/0'/0'",
											QUANTUS_DILITHIUM_CHAIN_ID, wallet_index
										);
									}
									println!("Address: {}", details.address);
									if *verbose {
										println!("Pub key: {}", details.public_key_hex);
									}
									println!(
                                        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    );
								},
								QuantusAddressType::Wormhole => {
									println!("Generating wormhole address...");
									println!(
                                        "XXXXXXXXXXXXXXXX Qnero Wormhole Details XXXXXXXXXXXXXXXXXX"
                                    );
									if let Some(phrase) = &details.secret_phrase {
										println!("Secret phrase: {}", phrase);
									}
									println!("Account index: {}", wallet_index);
									if *no_derivation {
										println!("Derivation path: master (no derivation)");
									} else {
										println!(
											"Derivation path: m/44'/{}/{}'/0'/0'",
											QUANTUS_WORMHOLE_CHAIN_ID, wallet_index
										);
									}
									println!("Address: {}", details.address);
									println!(
										"Inner Hash: 0x{}",
										details.inner_hash.as_deref().unwrap_or_default()
									);
									if *verbose {
										println!("Address hex: {}", details.public_key_hex);
									}
									println!(
                                        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                                    );
								},
							}
							Ok(())
						},
						Err(e) => Err(e),
					}
				},
			}
		},
		Some(Subcommand::BuildSpec(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.chain_spec, config.network))
		},
		Some(Subcommand::CheckBlock(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, import_queue, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		},
		Some(Subcommand::ExportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
				Ok((cmd.run(client, config.database), task_manager))
			})
		},
		Some(Subcommand::ExportState(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
				Ok((cmd.run(client, config.chain_spec), task_manager))
			})
		},
		Some(Subcommand::ImportBlocks(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, import_queue, .. } =
					service::new_partial(&config)?;
				Ok((cmd.run(client, import_queue), task_manager))
			})
		},
		Some(Subcommand::PurgeChain(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run(config.database))
		},
		Some(Subcommand::Revert(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.async_run(|config| {
				let PartialComponents { client, task_manager, backend, .. } =
					service::new_partial(&config)?;
				let aux_revert = Box::new(|_client, _, _blocks| {
					unimplemented!("TODO - g*randpa was removed.");
				});
				Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
			})
		},
		#[cfg(feature = "runtime-benchmarks")]
		Some(Subcommand::Benchmark(cmd)) => {
			let runner = cli.create_runner(cmd)?;

			runner.sync_run(|config| {
				// This switch needs to be in the client, since the client decides
				// which sub-commands it wants to support.
				match cmd {
					BenchmarkCmd::Pallet(cmd) => cmd
						.run_with_spec::<sp_runtime::traits::HashingFor<Block>, ()>(Some(
							config.chain_spec,
						)),
					BenchmarkCmd::Block(cmd) => {
						let PartialComponents { client, .. } = service::new_partial(&config)?;
						cmd.run(client)
					},
					BenchmarkCmd::Storage(cmd) => {
						let PartialComponents { client, backend, .. } =
							service::new_partial(&config)?;
						let db = backend.expose_db();
						let storage = backend.expose_storage();

						cmd.run(config, client, db, storage, None)
					},
					BenchmarkCmd::Overhead(cmd) => {
						let PartialComponents { client, .. } = service::new_partial(&config)?;
						let ext_builder = RemarkBuilder::new(client.clone());

						cmd.run(
							config.chain_spec.name().into(),
							client,
							inherent_benchmark_data()?,
							Vec::new(),
							&ext_builder,
							false,
						)
					},
					BenchmarkCmd::Extrinsic(cmd) => {
						let PartialComponents { client, .. } = service::new_partial(&config)?;
						// Register the *Remark* and *TKA* builders.
						let ext_factory = ExtrinsicFactory(vec![
							Box::new(RemarkBuilder::new(client.clone())),
							Box::new(TransferKeepAliveBuilder::new(
								client.clone(),
								Sr25519Keyring::Alice.to_account_id(),
								EXISTENTIAL_DEPOSIT,
							)),
						]);

						cmd.run(client, inherent_benchmark_data()?, Vec::new(), &ext_factory)
					},
					BenchmarkCmd::Machine(cmd) =>
						cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone()),
				}
			})
		},
		Some(Subcommand::ChainInfo(cmd)) => {
			let runner = cli.create_runner(cmd)?;
			runner.sync_run(|config| cmd.run::<Block>(&config))
		},
		None => {
			log::info!("Run until exit ....");
			let runner = cli.create_runner(&cli.run)?;
			runner.run_node_until_exit(|mut config| async move {
				//Obligatory configuration for all node holders
				config.blocks_pruning = BlocksPruning::KeepFinalized;
				config.state_pruning = Some(PruningMode::ArchiveCanonical);

				// Note: We parse node_key_file here to make a Dilithium keypair.
				// We then override the net config object parsed by sc_cli so we don't have to
				// fork sc_cli.
				let key_path =
					if let Some(path_str) = &cli.run.network_params.node_key_params.node_key_file {
						let path = std::path::Path::new(path_str);
						if path.is_absolute() {
							path.to_path_buf()
						} else {
							// This is a valid assumption because the node is run from the shell
							std::env::current_dir().unwrap().join(path)
						}
					} else {
						config.network.net_config_path.clone().unwrap().join("secret_dilithium")
					};

				log::debug!(target: "network", "node identity file: {:?}", key_path);

				config.network.node_key = NodeKeyConfig::Dilithium(Secret::File(key_path));

				// Network backend is set via --network-backend flag (handled by sc_cli)
				// Both libp2p and litep2p backends use Dilithium for node identity

				let rewards_account = match cli.rewards_inner_hash {
					Some(ref inner_hash) => {
						let hex_str = match inner_hash.strip_prefix("0x") {
							Some(s) => s,
							None => {
								eprintln!("Error: --rewards-inner-hash must start with '0x'.\n");
								eprintln!("To generate an inner hash, run:");
								eprintln!("  qnero-node key qnero --scheme wormhole\n");
								eprintln!(
									"Then pass the 'Inner Hash' value as --rewards-inner-hash."
								);
								return Err(sc_cli::Error::Input("Missing 0x prefix".into()));
							},
						};
						if hex_str.len() != 64 {
							eprintln!(
						"Error: --rewards-inner-hash must be a 0x-prefixed 32-byte hex string."
					);
							eprintln!("  Provided: {}", inner_hash);
							eprintln!("  Expected 66 characters, got {}.\n", inner_hash.len());
							eprintln!("To generate an inner hash, run:");
							eprintln!("  qnero-node key qnero --scheme wormhole\n");
							eprintln!("Then pass the 'Inner Hash' value as --rewards-inner-hash.");
							return Err(sc_cli::Error::Input("Invalid inner hash length".into()));
						}
						let bytes = hex::decode(hex_str).map_err(|_| {
							eprintln!(
								"Error: --rewards-inner-hash contains invalid hex characters.\n"
							);
							eprintln!("To generate an inner hash, run:");
							eprintln!("  qnero-node key qnero --scheme wormhole\n");
							eprintln!("Then pass the 'Inner Hash' value as --rewards-inner-hash.");
							sc_cli::Error::Input("Invalid hex characters".into())
						})?;
						let inner_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
							sc_cli::Error::Input("Failed to convert inner hash to account".into())
						})?;
						let wormhole_address = AccountId32::from(
							qp_wormhole::derive_wormhole_address(inner_bytes).map_err(|_| {
								eprintln!(
									"Error: --rewards-inner-hash is not a canonical Poseidon digest.\n"
								);
								eprintln!("To generate an inner hash, run:");
								eprintln!("  qnero-node key qnero --scheme wormhole\n");
								eprintln!(
									"Then pass the 'Inner Hash' value as --rewards-inner-hash."
								);
								sc_cli::Error::Input("Non-canonical inner hash".into())
							})?,
						);
						// Not the reward recipient. Under v1 no account is
						// paid: the block reward is a note, and the wallet
						// behind --rewards-miner-key is who it is for. This
						// value is the fallback author label for a node with
						// no miner key, which cannot author a valid block
						// anyway, and the derived address is logged only so an
						// operator can recognise the hash it pasted.
						log::info!(
							"⛏️ Consensus author fallback, paid nothing: {}",
							wormhole_address.to_ss58check()
						);
						AccountId32::new(inner_bytes)
					},
					None =>
						if cli.run.shared_params.is_dev() {
							let treasury_account = qnero_runtime::configs::TreasuryPalletId::get()
								.into_account_truncating();
							// Same reason as the branch above: v1 pays no
							// account, so this is only the fallback author
							// label a --dev node signs its blocks with.
							log::info!(
								"⛏️ Consensus author fallback, paid nothing: {:?}",
								treasury_account
							);
							treasury_account
						} else if config.role.is_authority() {
							eprintln!(
								"Error: --rewards-inner-hash is required when running with --validator.\n"
							);
							eprintln!("To generate an inner hash, run:");
							eprintln!("  qnero-node key qnero --scheme wormhole\n");
							eprintln!("Then pass the 'Inner Hash' value as --rewards-inner-hash.");
							return Err(sc_cli::Error::Input("Missing --rewards-inner-hash".into()));
						} else {
							// unused for non-validator nodes, use zero placeholder.
							AccountId32::new([0u8; 32])
						},
				};

				// The miner key every coinbase note this node mints is derived
				// from. An authority owes one: without it the node builds
				// blocks with no coinbase inherent, and every node refuses
				// those, its own import included, so the failure belongs at
				// startup.
				let miner_key = match cli.rewards_miner_key {
					Some(ref encoded) => {
						let key =
							qnero_note_core::MinerKey::decode(encoded.trim()).map_err(|error| {
								// The key itself is never printed: half of it
								// is a viewing-tier secret.
								eprintln!("Error: --rewards-miner-key is not a Qnero miner key: {error}\n");
								eprintln!("To get one, run:");
								eprintln!("  qnero-wallet miner-address\n");
								eprintln!(
									"Then pass the printed qnm1... string as --rewards-miner-key, \
									 or set QNERO_MINER_KEY."
								);
								sc_cli::Error::Input("Invalid miner key".into())
							})?;
						// The reward recipient, and the one value worth
						// checking against what `qnero-wallet miner-address`
						// printed. Both ends of the bech32m string, because a
						// mistyped or stale key mines correct blocks into
						// notes the operator's wallet cannot open, and the
						// only other symptom is a balance that never grows.
						let encoded_key = key.encode();
						log::info!(
							"⛏️ Coinbase notes are minted for miner key {}…{}",
							&encoded_key[..12],
							&encoded_key[encoded_key.len() - 8..]
						);
						Some(key)
					},
					None =>
						if config.role.is_authority() {
							eprintln!(
								"Error: --rewards-miner-key is required when running with --validator.\n"
							);
							eprintln!(
								"Every block mints its reward as one shielded note, so the node"
							);
							eprintln!("needs a key to mint it for. To get one, run:");
							eprintln!("  qnero-wallet miner-address\n");
							eprintln!(
								"Then pass it as --rewards-miner-key, or set QNERO_MINER_KEY."
							);
							return Err(sc_cli::Error::Input("Missing --rewards-miner-key".into()));
						} else {
							// A node that does not author mints nobody's note.
							None
						},
				};

				// Mining only runs on authorities; fail fast instead of
				// silently ignoring the flags (matches --rewards-inner-hash above).
				if cli.stratum_port.is_some() && !config.role.is_authority() {
					eprintln!("Error: --stratum-port requires running with --validator.\n");
					eprintln!("A node that does not author has no template to hand a rig, so the");
					eprintln!("endpoint would accept logins and never issue a job.");
					return Err(sc_cli::Error::Input("--stratum-port requires --validator".into()));
				}
				if cli.stratum_port.is_none() &&
					cli.stratum_share_difficulty != crate::cli::DEFAULT_SHARE_DIFFICULTY
				{
					eprintln!(
						"Error: --stratum-share-difficulty is only used with --stratum-port.\n"
					);
					return Err(sc_cli::Error::Input(
						"--stratum-share-difficulty requires --stratum-port".into(),
					));
				}
				if cli.stratum_port.is_none() &&
					cli.stratum_host != crate::cli::DEFAULT_STRATUM_HOST
				{
					eprintln!("Error: --stratum-host is only used with --stratum-port.\n");
					eprintln!("Without a port there is no listener to bind, so the address would");
					eprintln!("be accepted and never used.");
					return Err(sc_cli::Error::Input(
						"--stratum-host requires --stratum-port".into(),
					));
				}
				if cli.stratum_share_difficulty == 0 {
					eprintln!("Error: --stratum-share-difficulty must be at least 1.\n");
					return Err(sc_cli::Error::Input("--stratum-share-difficulty is zero".into()));
				}
				if cli.stratum_port.is_none() &&
					cli.stratum_max_connections_per_ip != crate::stratum::MAX_CONNECTIONS_PER_IP
				{
					eprintln!(
						"Error: --stratum-max-connections-per-ip is only used with \
						 --stratum-port.\n"
					);
					return Err(sc_cli::Error::Input(
						"--stratum-max-connections-per-ip requires --stratum-port".into(),
					));
				}
				if cli.stratum_port.is_none() && cli.stratum_share_timeout.is_some() {
					eprintln!("Error: --stratum-share-timeout is only used with --stratum-port.\n");
					return Err(sc_cli::Error::Input(
						"--stratum-share-timeout requires --stratum-port".into(),
					));
				}
				if cli.stratum_share_timeout == Some(0) {
					eprintln!("Error: --stratum-share-timeout must be at least 1.\n");
					eprintln!("Zero closes every session before a rig can submit anything, so");
					eprintln!("the endpoint would accept logins and disconnect them at once.");
					return Err(sc_cli::Error::Input("--stratum-share-timeout is zero".into()));
				}
				if cli.stratum_max_connections_per_ip == 0 {
					eprintln!("Error: --stratum-max-connections-per-ip must be at least 1.\n");
					eprintln!("Zero refuses every rig, including one on the node's own box.");
					return Err(sc_cli::Error::Input(
						"--stratum-max-connections-per-ip is zero".into(),
					));
				}
				if cli.mining_threads == 0 &&
					cli.stratum_port.is_none() &&
					config.role.is_authority()
				{
					eprintln!(
						"Error: --mining-threads 0 without --stratum-port leaves an authority \
						 with nothing mining.\n"
					);
					eprintln!("Either raise --mining-threads or open a stratum port for a rig.");
					return Err(sc_cli::Error::Input("no mining source configured".into()));
				}
				// And a ceiling, for the same reason there is a floor. Every thread
				// is a `spawn_blocking` on the pool rocksdb and block import share,
				// and a RandomX VM the pool then keeps idle: a mistyped
				// `--mining-threads 1000` starts without complaint and queues its own
				// hashing in front of its own import.
				let available = std::thread::available_parallelism()
					.map(std::num::NonZeroUsize::get)
					.unwrap_or(1);
				if cli.mining_threads > available {
					eprintln!(
						"Error: --mining-threads {} is above the {available} this machine has.\n",
						cli.mining_threads,
					);
					eprintln!("Mining threads run on the same blocking pool as block import, so");
					eprintln!(
						"oversubscribing them costs the node the work it needs to stay synced."
					);
					return Err(sc_cli::Error::Input(
						"--mining-threads above available parallelism".into(),
					));
				}

				let stratum_config = cli.stratum_port.map(|port| {
					// One flag sets both windows. The two clocks start on
					// different events, a login and an accepted share, and there
					// is no reason for the length to differ: the default already
					// covers the dataset a full-mode rig builds after login.
					let share_timeout = cli.stratum_share_timeout.map_or_else(
						|| crate::stratum::default_share_timeout(cli.stratum_share_difficulty),
						std::time::Duration::from_secs,
					);
					crate::stratum::StratumConfig {
						host: cli.stratum_host,
						port,
						share_difficulty: cli.stratum_share_difficulty,
						max_connections_per_ip: cli.stratum_max_connections_per_ip,
						first_share_timeout: share_timeout,
						share_timeout,
					}
				});

				// Allow mining without peers if --dev or --force-authoring is set
				let allow_mining_without_peers = config.force_authoring;

				log::info!("Using litep2p network backend (with Dilithium)");
				service::new_full::<sc_network::litep2p::Litep2pNetworkBackend>(
					config,
					rewards_account,
					miner_key,
					stratum_config,
					cli.mining_threads,
					cli.enable_peer_sharing,
					cli.sync_max_timeouts_before_drop,
					cli.sync_disable_major_sync_gating,
					cli.sync_block_request_timeout,
					allow_mining_without_peers,
					cli.max_tip_age,
				)
				.map_err(sc_cli::Error::Service)
			})
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		cli::QuantusAddressType,
		tests::data::quantus_key_test_data::{
			EXPECTED_PUBLIC_KEY_HEX, EXPECTED_SECRET_KEY_HEX, TEST_ADDRESS, TEST_ADDRESS_HD_0,
			TEST_ADDRESS_HD_1, TEST_MNEMONIC, TEST_SEED_HEX, TEST_WORMHOLE_ADDRESS,
			TEST_WORMHOLE_PREIMAGE,
		},
	};

	/// The startup banner names Qnero and its maintainer, and a panic names
	/// Qnero's issue tracker.
	///
	/// `sc_cli` prints `impl_name`, the version, then `by {author}` before any
	/// other line, and that banner is neither `--version` nor `--help`, so
	/// `tests/naming_guard.rs` cannot see it: it reads only what the binary
	/// writes for those two flags. This is the part of the rename guard that
	/// covers the banner. `support_url` is here too: `--help` carries it, so
	/// the guard would catch an upstream name there, and the guard cannot
	/// catch the Substrate template's placeholder, which names no project at
	/// all.
	#[test]
	fn the_startup_banner_names_qnero_and_no_upstream_maintainer() {
		use sc_cli::SubstrateCli;

		let name = <Cli as SubstrateCli>::impl_name();
		let author = <Cli as SubstrateCli>::author();
		let description = <Cli as SubstrateCli>::description();
		let support = <Cli as SubstrateCli>::support_url();

		assert_eq!(name, "Qnero Node");
		assert_eq!(
			support, "https://github.com/DigitalGuards/qnero/issues",
			"the address every panic message names is not Qnero's issue tracker"
		);
		assert!(
			!support.contains("anonymous.an"),
			"support_url is still the Substrate node template's placeholder: {support}"
		);
		for (what, line) in [
			("impl_name", &name),
			("author", &author),
			("description", &description),
			("support_url", &support),
		] {
			assert!(
				!line.to_ascii_lowercase().contains("quantus"),
				"the startup banner's {what} still says Quantus: {line}"
			);
		}
		assert!(
			description.contains("Qnero"),
			"the --help about line never says Qnero: {description}"
		);
	}

	/// Every `--chain` id this node accepts resolves to a Qnero chain.
	///
	/// Three foreign raw specs used to ship inside this binary, and the empty
	/// id `sc_cli` hands `load_spec` when an operator passes neither `--chain`
	/// nor `--dev` resolved to one of them. Their genesis `:code` was an
	/// upstream `quantus-runtime` with no `pallet-shielded`, no coinbase
	/// inherent and no `QneroCallFilter`, so the default network of the
	/// shipped binary had none of v1's mandatory-privacy rules: a transparent
	/// transfer succeeded there, nothing read the configured miner key, and
	/// the wormhole exit was live.
	///
	/// The chain properties are what this checks, because they separate the
	/// two families in a build with no runtime wasm. A spec built from a
	/// preset needs `WASM_BINARY` and fails without it, which is what
	/// `SKIP_WASM_BUILD=1` leaves; a raw spec carries its properties in its
	/// JSON and loads either way. So a spec that comes back at all carrying
	/// anything but the one Qnero properties map is a spec this tree's runtime
	/// did not build.
	#[test]
	fn every_chain_id_this_node_accepts_is_a_qnero_chain() {
		use clap::Parser;
		use sc_cli::SubstrateCli;

		let cli = crate::cli::Cli::try_parse_from(["qnero-node", "--validator"])
			.expect("parse a bare authority command line");

		for id in [
			"dev",
			"qnero-dev",
			"heisenberg",
			"heisenberg_live_spec",
			"planck",
			"planck_live_spec",
			"mainnet",
			"mainnet_live_spec",
		] {
			match cli.load_spec(id) {
				Ok(spec) => assert_eq!(
					spec.properties(),
					crate::chain_spec::qnero_properties(),
					"--chain {id} resolves to a spec this tree's runtime did not build"
				),
				Err(error) => assert!(
					error.contains("wasm not available"),
					"--chain {id} failed for a reason that is not a missing runtime wasm: {error}"
				),
			}
		}
	}

	/// A command line that names no chain gets an error naming the chains this
	/// node has.
	///
	/// `sc_cli` maps a missing `--chain` and a missing `--dev` to the id `""`,
	/// and that id used to load the embedded Heisenberg raw spec, so the
	/// shortest authority invocation in the runbook started a node on somebody
	/// else's network. An operator has to name the chain now.
	#[test]
	fn an_empty_chain_id_names_the_chains_this_node_has() {
		use clap::Parser;
		use sc_cli::SubstrateCli;

		let cli = crate::cli::Cli::try_parse_from(["qnero-node", "--validator"])
			.expect("parse a bare authority command line");

		let error = cli.load_spec("").expect_err("an empty chain id must not resolve to a chain");
		for id in ["dev", "heisenberg", "planck", "mainnet"] {
			assert!(
				error.contains(id),
				"the refusal does not name the {id} chain, so it does not tell an operator \
				 what to pass: {error}"
			);
		}
	}

	/// The per-address connection cap is a flag, and its default clears a real
	/// farm.
	///
	/// It was a hard-coded 4, which is a normal number of rigs behind one NAT
	/// gateway and a normal number of xmrig instances pinned per CCX on the
	/// node's own box. Past it the socket was dropped with nothing written and
	/// the only trace was a `debug` line, so neither end said why the fifth rig
	/// could not connect.
	#[test]
	fn the_per_address_connection_cap_is_a_flag() {
		use clap::Parser;

		let default = crate::cli::Cli::try_parse_from(["qnero-node", "--validator"])
			.expect("parse a bare authority command line");
		assert_eq!(default.stratum_max_connections_per_ip, crate::stratum::MAX_CONNECTIONS_PER_IP,);
		assert!(
			default.stratum_max_connections_per_ip >= 8,
			"the default has to clear a farm behind one address, and it is {}",
			default.stratum_max_connections_per_ip,
		);

		let raised = crate::cli::Cli::try_parse_from([
			"qnero-node",
			"--validator",
			"--stratum-port",
			"3333",
			"--stratum-max-connections-per-ip",
			"32",
		])
		.expect("parse --stratum-max-connections-per-ip");
		assert_eq!(raised.stratum_max_connections_per_ip, 32);
	}

	/// The session deadline is a flag, and its default is derived from the
	/// share difficulty.
	///
	/// It is the endpoint's whole liveness rule after login, so a deadline
	/// fixed in seconds while `--stratum-share-difficulty` moves is a bet on
	/// the rig's hash rate: raise the difficulty far enough and a healthy rig
	/// producing shares at exactly the rate it was asked for is disconnected
	/// between two of them.
	#[test]
	fn the_session_share_deadline_is_a_flag_defaulted_from_the_difficulty() {
		use clap::Parser;

		let default = crate::cli::Cli::try_parse_from(["qnero-node", "--validator"])
			.expect("parse a bare authority command line");
		assert_eq!(
			default.stratum_share_timeout, None,
			"an unset flag is what makes the default the derived one",
		);
		assert_eq!(
			crate::stratum::default_share_timeout(crate::cli::DEFAULT_SHARE_DIFFICULTY),
			std::time::Duration::from_secs(600),
			"the documented default is ten minutes at the default share difficulty",
		);
		assert!(
			crate::stratum::default_share_timeout(crate::cli::DEFAULT_SHARE_DIFFICULTY * 10) >
				crate::stratum::default_share_timeout(crate::cli::DEFAULT_SHARE_DIFFICULTY),
			"a raised share difficulty has to widen the window it is measured against",
		);

		let set = crate::cli::Cli::try_parse_from([
			"qnero-node",
			"--validator",
			"--stratum-port",
			"3333",
			"--stratum-share-timeout",
			"1200",
		])
		.expect("parse --stratum-share-timeout");
		assert_eq!(set.stratum_share_timeout, Some(1_200));
	}

	#[test]
	fn force_authoring_flag_is_parsed() {
		use clap::Parser;
		use sc_cli::CliConfiguration;

		let with_flag =
			crate::cli::Cli::try_parse_from(["qnero-node", "--validator", "--force-authoring"])
				.expect("parse --force-authoring");
		assert!(with_flag.run.force_authoring);
		assert!(with_flag.run.force_authoring().expect("force_authoring"));

		let without_flag = crate::cli::Cli::try_parse_from(["qnero-node", "--validator"])
			.expect("parse --validator");
		assert!(!without_flag.run.force_authoring);
		assert!(!without_flag.run.force_authoring().expect("force_authoring"));
	}

	#[test]
	fn dev_implies_force_authoring() {
		use clap::Parser;
		use sc_cli::CliConfiguration;

		let cli = crate::cli::Cli::try_parse_from(["qnero-node", "--dev"]).expect("parse --dev");
		assert!(cli.run.force_authoring().expect("force_authoring"));
	}

	#[test]
	fn take_trimmed_secret_returns_trimmed_and_rejects_whitespace_only() {
		let secret = take_trimmed_secret(String::from("  secret-phrase\n")).expect("non-empty");
		assert_eq!(secret.as_str(), "secret-phrase");
		assert!(take_trimmed_secret(String::from("   \n")).is_none());
	}

	/// Master secrets must never travel through argv: the argument vector is
	/// world-readable via /proc/<pid>/cmdline, recorded in shell history, and
	/// captured by process-accounting/audit logs.
	#[test]
	fn secrets_are_not_accepted_as_command_line_values() {
		use clap::Parser;
		assert!(
			crate::cli::Cli::try_parse_from([
				"qnero-node",
				"key",
				"qnero",
				"--seed",
				TEST_SEED_HEX,
			])
			.is_err(),
			"--seed must not accept an inline secret value"
		);
		assert!(
			crate::cli::Cli::try_parse_from([
				"qnero-node",
				"key",
				"qnero",
				"--words",
				TEST_MNEMONIC,
			])
			.is_err(),
			"--words must not accept an inline secret value"
		);
	}

	/// A caller-supplied mnemonic is already known to the caller; echoing it back
	/// into stdout needlessly persists it in terminal capture or redirected output.
	/// Only newly generated phrases (which would otherwise be lost) may be printed.
	#[test]
	fn provided_mnemonic_is_not_echoed_back() {
		let mnemonic = TEST_MNEMONIC.to_string();
		let standard = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			0,
			true,
		)
		.unwrap();
		assert!(
			standard.secret_phrase.is_none(),
			"caller-supplied mnemonic must not be echoed back (standard)"
		);

		let wormhole =
			generate_quantus_key(QuantusAddressType::Wormhole, None, Some(mnemonic), 0, false)
				.unwrap();
		assert!(
			wormhole.secret_phrase.is_none(),
			"caller-supplied mnemonic must not be echoed back (wormhole)"
		);
	}

	#[test]
	fn test_generate_quantus_key_standard_new_mnemonic() {
		// Test generating a standard address with a new mnemonic
		let result = generate_quantus_key(QuantusAddressType::Standard, None, None, 0, false);
		assert!(result.is_ok());
		assert!(result.unwrap().secret_phrase.is_some());
	}

	#[test]
	fn test_generate_quantus_key_standard_from_mnemonic() {
		// Test generating a standard address from a provided mnemonic
		let mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
                .to_string();
		let result = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			0,
			true,
		);
		assert!(result.is_ok());
		let details = result.unwrap();
		// Caller-supplied mnemonics are never echoed back.
		assert_eq!(details.secret_phrase, None);
	}

	#[test]
	fn test_generate_quantus_key_standard_from_seed() {
		// Test generating a standard address from a provided seed (0x prefixed and not)
		let seed_hex_no_prefix = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(); // 128 hex chars
		let seed_hex_with_prefix = format!("0x{}", seed_hex_no_prefix);

		let result_no_prefix = generate_quantus_key(
			QuantusAddressType::Standard,
			Some(seed_hex_no_prefix.clone()),
			None,
			0,
			true,
		);
		assert!(result_no_prefix.is_ok());
		let details_no_prefix = result_no_prefix.unwrap();
		assert_eq!(details_no_prefix.seed_hex, seed_hex_with_prefix); // Output is always 0x prefixed
		assert!(details_no_prefix.secret_phrase.is_none());

		let result_with_prefix = generate_quantus_key(
			QuantusAddressType::Standard,
			Some(seed_hex_with_prefix.clone()),
			None,
			0,
			true,
		);
		assert!(result_with_prefix.is_ok());
		let details_with_prefix = result_with_prefix.unwrap();
		assert_eq!(details_with_prefix.seed_hex, seed_hex_with_prefix);
		assert!(details_with_prefix.secret_phrase.is_none());
	}

	#[test]
	fn test_generate_quantus_key_wormhole() {
		// Test generating a wormhole address
		let result = generate_quantus_key(QuantusAddressType::Wormhole, None, None, 0, false);
		assert!(result.is_ok());
		let details = result.unwrap();
		assert!(details.public_key_hex.starts_with("0x"));
		assert!(details.secret_key_hex.starts_with("0x"));
		assert_eq!(details.seed_hex, "N/A (Wormhole)");
		assert!(details.secret_phrase.is_some());
		assert!(
			AccountId32::from_ss58check_with_version(&details.address).is_ok(),
			"Generated address should be valid SS58: {}",
			details.address
		);
	}

	#[test]
	fn test_generate_quantus_key_invalid_seed_length() {
		// Test error handling for invalid seed length
		let seed = Some("0123456789abcdef".to_string()); // Too short (16 chars, expected 128)
		let result = generate_quantus_key(QuantusAddressType::Standard, seed, None, 0, true);
		assert!(result.is_err());
		if let Err(e) = result {
			assert_eq!(format!("{:?}", e), "Input(\"Invalid hex seed length\")");
		}
	}

	#[test]
	fn test_generate_quantus_key_invalid_seed_format() {
		// Test error handling for invalid seed format (non-hex characters)
		// Ensure the string is 128 chars long but contains an invalid hex char.
		let seed = Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg0123456789abcdef".to_string()); // Contains 'g', now 128 chars
		let result = generate_quantus_key(QuantusAddressType::Standard, seed, None, 0, true);
		assert!(result.is_err());
		if let Err(e) = result {
			assert_eq!(format!("{:?}", e), "Input(\"Invalid hex seed format\")");
		}
	}

	#[test]
	fn test_generate_quantus_key_standard_known_values() {
		let mnemonic = TEST_MNEMONIC.to_string();
		let expected_seed_hex = TEST_SEED_HEX.to_string();
		let expected_address = TEST_ADDRESS.to_string();
		let expected_public_key_hex = EXPECTED_PUBLIC_KEY_HEX.to_string();
		let expected_secret_key_hex = EXPECTED_SECRET_KEY_HEX.to_string();

		let result = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			0,
			true,
		);
		assert!(result.is_ok());
		let details = result.unwrap();

		assert_eq!(details.secret_phrase, None);
		assert_eq!(details.seed_hex, expected_seed_hex.clone());
		assert_eq!(details.address, expected_address.clone());
		assert_eq!(details.public_key_hex, expected_public_key_hex.clone());
		assert_eq!(details.secret_key_hex, expected_secret_key_hex.clone());

		let result = generate_quantus_key(
			QuantusAddressType::Standard,
			Some(expected_seed_hex.clone()),
			None,
			0,
			true,
		);
		assert!(result.is_ok());
		let details = result.unwrap();

		assert_eq!(details.seed_hex, expected_seed_hex);
		assert_eq!(details.address, expected_address);
		assert_eq!(details.public_key_hex, expected_public_key_hex);
		assert_eq!(details.secret_key_hex, expected_secret_key_hex);
	}

	#[test]
	fn test_generate_quantus_key_standard_hd_derivation_changes_seed_and_key() {
		let mnemonic = TEST_MNEMONIC.to_string();
		// Master (no derivation)
		let master = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			0,
			true,
		)
		.unwrap();

		// Derived index 0
		let child0 = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			0,
			false,
		)
		.unwrap();

		// Derived index 1
		let child1 = generate_quantus_key(
			QuantusAddressType::Standard,
			None,
			Some(mnemonic.clone()),
			1,
			false,
		)
		.unwrap();

		assert_eq!(master.address, TEST_ADDRESS);
		assert_eq!(child0.address, TEST_ADDRESS_HD_0);
		assert_eq!(child1.address, TEST_ADDRESS_HD_1);
	}

	#[test]
	fn test_derive_wormhole_from_mnemonic_known_values() {
		let path = format!("m/44'/{QUANTUS_WORMHOLE_CHAIN_ID}/0'/0'/0'");
		let pair = derive_wormhole_from_mnemonic(TEST_MNEMONIC, None, &path).unwrap();

		let wormhole_address = WormholeAddress(H256::from(*pair.address()));
		let account_id = wormhole_address.into_account();

		assert_eq!(
			account_id.to_ss58check_with_version(Ss58AddressFormat::custom(189)),
			TEST_WORMHOLE_ADDRESS
		);
		assert_eq!(hex::encode(pair.first_hash()), TEST_WORMHOLE_PREIMAGE);
	}
}
