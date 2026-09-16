//! Offline exact-executor component qualification. See docs/WASM-BUDGET.md.
use std::{borrow::Cow, error::Error, path::PathBuf, time::Instant};

use codec::{Decode, Encode};
use frame_support::BoundedVec;
use qnero_runtime::{shielded_budget::*, Runtime, System};
use sc_executor::WasmExecutor;
use serde_json::{json, Value};
use sp_core::traits::{CallContext, CodeExecutor, RuntimeCode, WrappedRuntimeCode};
use sp_io::{SubstrateHostFunctions, TestExternalities};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Args {
	wasm: Option<PathBuf>,
	private_proof: PathBuf,
	public_proof: Option<PathBuf>,
	runs: usize,
}

fn args() -> Result<Args> {
	let mut wasm = None;
	let mut private_proof = None;
	let mut public_proof = None;
	let mut runs = 9;
	let mut args = std::env::args().skip(1);
	while let Some(flag) = args.next() {
		let value = args.next().ok_or("each argument requires a value")?;
		match flag.as_str() {
			"--wasm" => wasm = Some(PathBuf::from(value)),
			"--private-proof" => private_proof = Some(PathBuf::from(value)),
			"--public-proof" => public_proof = Some(PathBuf::from(value)),
			"--runs" => runs = value.parse()?,
			_ => return Err(format!("unknown argument {flag}").into()),
		}
	}
	if !(3..=31).contains(&runs) {
		return Err("--runs must be between 3 and 31".into());
	}
	Ok(Args {
		wasm,
		private_proof: private_proof.ok_or("--private-proof <valid proof file> is required")?,
		public_proof,
		runs,
	})
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Runner {
	wasm: Vec<u8>,
	executor: WasmExecutor<SubstrateHostFunctions>,
}

impl Runner {
	fn call(
		&self,
		ext: &mut TestExternalities,
		method: &str,
		data: &[u8],
	) -> Result<(Vec<u8>, u64)> {
		let fetcher = WrappedRuntimeCode(Cow::Borrowed(&self.wasm));
		let code = RuntimeCode {
			code_fetcher: &fetcher,
			heap_pages: None,
			hash: sp_core::hashing::blake2_256(&self.wasm).to_vec(),
		};
		let start = Instant::now();
		let (result, native) =
			self.executor.call(&mut ext.ext(), &code, method, data, CallContext::Onchain);
		let elapsed_ps =
			u64::try_from(start.elapsed().as_nanos().saturating_mul(1000)).unwrap_or(u64::MAX);
		if native {
			return Err("benchmark unexpectedly used native execution".into());
		}
		Ok((result.map_err(|error| format!("{method}: {error}"))?, elapsed_ps))
	}

	fn run(
		&self,
		operation: u8,
		input: &[u8],
		repetitions: u32,
		slots: u32,
	) -> Result<(u64, u64, u32)> {
		let mut ext = externalities(operation)?;
		let encoded = (operation, input.to_vec(), repetitions, slots).encode();
		let (answer, elapsed) = self.call(&mut ext, "ShieldedBudgetApi_run", &encoded)?;
		let result = std::result::Result::<(u64, u32), Vec<u8>>::decode(&mut &answer[..])?;
		let (declared, count) =
			result.map_err(|error| String::from_utf8_lossy(&error).into_owned())?;
		if operation == RETENTION_HOOK {
			let expected = <Runtime as pallet_shielded::Config>::MaxCiphertextPrunesPerBlock::get();
			if count != expected {
				return Err(format!("retention pruned {count}, expected {expected}").into());
			}
		}
		Ok((elapsed, declared, count))
	}
}

fn externalities(operation: u8) -> Result<TestExternalities> {
	let mut ext = TestExternalities::default();
	if operation == RETENTION_HOOK {
		ext.execute_with(|| -> Result<()> {
			let limit = <Runtime as pallet_shielded::Config>::MaxCiphertextPrunesPerBlock::get();
			let per_block = <Runtime as pallet_shielded::Config>::MaxCiphertextsPerBlock::get();
			let cap = <Runtime as pallet_shielded::Config>::MaxCiphertextBytes::get();
			let payload: BoundedVec<u8, <Runtime as pallet_shielded::Config>::MaxCiphertextBytes> =
				vec![0u8; cap as usize].try_into().map_err(|_| "invalid fixture payload cap")?;
			for index in 0..limit {
				let created = 1 + index / per_block;
				pallet_shielded::Ciphertexts::<Runtime>::insert(u64::from(index), &payload);
				pallet_shielded::CiphertextQueue::<Runtime>::insert(
					u64::from(index),
					(created, u64::from(index)),
				);
			}
			pallet_shielded::CiphertextQueueTail::<Runtime>::put(u64::from(limit));
			let now = <Runtime as pallet_shielded::Config>::CiphertextRetentionBlocks::get() +
				limit / per_block +
				2;
			System::set_block_number(now);
			Ok(())
		})?;
	}
	Ok(ext)
}

fn measure(
	runner: &Runner,
	label: &str,
	operation: u8,
	input: &[u8],
	repetitions: u32,
	slots: u32,
	runs: usize,
) -> Result<(Value, bool)> {
	let (first, declared, _) = runner.run(operation, input, repetitions, slots)?;
	let mut samples = Vec::with_capacity(runs);
	for _ in 0..runs {
		let (elapsed, repeated_budget, _) = runner.run(operation, input, repetitions, slots)?;
		if repeated_budget != declared {
			return Err("runtime budget changed between identical calls".into());
		}
		samples.push(elapsed);
	}
	let mut sorted = samples.clone();
	sorted.sort_unstable();
	let max = sorted[sorted.len() - 1];
	let p95 = sorted[(95 * sorted.len()).div_ceil(100) - 1];
	// The first call after module compilation still pays all runtime-local
	// loading. Include it in the conservative component gate.
	let measured = max.max(first);
	let pass = declared == 0 || measured <= declared;
	Ok((
		json!({
			"component": label, "repetitions_per_runtime_call": repetitions,
			"slots": slots, "input_bytes": input.len(),
			"first_call_ps": first, "cached_executor_samples_ps": samples,
			"median_ps": sorted[sorted.len()/2], "p95_ps": p95, "max_ps": measured,
			"declared_budget_ps": if declared == 0 { Value::Null } else { json!(declared) },
			"within_declared_budget": if declared == 0 { Value::Null } else { json!(pass) },
		}),
		pass,
	))
}

fn read_proof(path: &PathBuf) -> Result<Vec<u8>> {
	let bytes = std::fs::read(path)?;
	if bytes.len() > pallet_shielded::MAX_PROOF_BYTES {
		return Err("fixture proof exceeds the runtime proof limit".into());
	}
	Ok(bytes)
}

fn main() -> Result<()> {
	let args = args()?;
	let wasm = match args.wasm {
		Some(path) => std::fs::read(path)?,
		None => qnero_runtime::WASM_BINARY
			.ok_or("runtime WASM was skipped; supply --wasm")?
			.to_vec(),
	};
	let private = read_proof(&args.private_proof)?;
	let public = args.public_proof.as_ref().map(read_proof).transpose()?;
	let runner = Runner {
		wasm,
		executor: WasmExecutor::<SubstrateHostFunctions>::builder()
			.with_max_runtime_instances(1)
			.with_runtime_cache_size(1)
			.build(),
	};
	let (version, cold_compile_ps) =
		runner.call(&mut TestExternalities::default(), "Core_version", &[])?;
	let version = sp_version::RuntimeVersion::decode(&mut &version[..])?;
	let (profile, _) =
		runner.call(&mut TestExternalities::default(), "ShieldedBudgetApi_profile", &[])?;
	let profile = Vec::<u8>::decode(&mut &profile[..])?;
	if profile != pallet_shielded::circuit_config::PROTOCOL_PROFILE {
		return Err("benchmark host and WASM have different protocol profiles".into());
	}
	let mut rows = Vec::new();
	let mut all_pass = true;
	let mut add = |label, operation, input: &[u8], repetitions, slots| -> Result<()> {
		let (row, pass) = measure(&runner, label, operation, input, repetitions, slots, args.runs)?;
		all_pass &= pass;
		rows.push(row);
		Ok(())
	};
	add("private_artifact_load", LOAD_PRIVATE, &[], 1, 0)?;
	add("private_parse", PARSE_PRIVATE, &private, 1, 0)?;
	add("private_parse_and_verify_once", VERIFY_PRIVATE, &private, 1, 0)?;
	add("private_parse_and_verify_twice", VERIFY_PRIVATE, &private, 2, 0)?;
	add("public_artifact_load", LOAD_PUBLIC, &[], 1, 0)?;
	if let Some(proof) = &public {
		add("public_parse", PARSE_PUBLIC, proof, 1, 0)?;
		add("public_parse_and_verify_once", VERIFY_PUBLIC, proof, 1, 0)?;
		add("public_parse_and_verify_twice", VERIFY_PUBLIC, proof, 2, 0)?;
	}
	let max_slots = (pallet_shielded::circuit_config::NUM_LEAF_PROOFS *
		pallet_shielded::circuit_config::NUM_PRIVATE_BATCH_PROOFS) as u32;
	let cap = <Runtime as pallet_shielded::Config>::MaxCiphertextBytes::get();
	add("payload_digest_two_checks_one_slot", PAYLOAD_DIGEST, &vec![0u8; cap as usize], 1, 1)?;
	add(
		"payload_digest_two_checks_max_slots",
		PAYLOAD_DIGEST,
		&vec![0u8; cap as usize],
		1,
		max_slots,
	)?;
	add("bounded_retention_hook", RETENTION_HOOK, &[], 1, 0)?;
	let cpu = std::fs::read_to_string("/proc/cpuinfo")
		.unwrap_or_default()
		.lines()
		.find_map(|line| {
			line.strip_prefix("model name")
				.and_then(|line| line.split_once(':'))
				.map(|(_, value)| value.trim().to_owned())
		})
		.unwrap_or_default();
	let report = json!({
		"schema": "qnero-wasm-budget-v1", "engine": "sc-executor/wasmtime PoolingCopyOnWrite",
		"host_functions": "sp_io::SubstrateHostFunctions", "native_execution": false,
		"heap_strategy": "executor default", "runtime_feature": "shielded-budget-bench",
		"runtime_spec_version": version.spec_version,
		"runtime_wasm_blake2_256": hex(&sp_core::hashing::blake2_256(&runner.wasm)),
		"protocol_profile_hex": hex(&profile),
		"private_proof_blake2_256": hex(&sp_core::hashing::blake2_256(&private)),
		"public_proof_blake2_256": public.as_ref().map(|p| hex(&sp_core::hashing::blake2_256(p))),
		"cpu_model": cpu, "architecture": std::env::consts::ARCH,
		"available_cpus": std::thread::available_parallelism().map(|v| v.get()).unwrap_or(0),
		"cold_module_compile_and_core_version_ps": cold_compile_ps,
		"all_measured_components_within_declared_budget": all_pass,
		"public_verification_measured": public.is_some(),
		"unqualified": ["successful_full_settlement", "full_block_import", "disk_database_latency", "public_node_admission_capacity", "reference_hardware"],
		"components": rows,
	});
	println!("{}", serde_json::to_string_pretty(&report)?);
	if !all_pass {
		return Err("measured WASM component exceeded its declared weight budget".into());
	}
	Ok(())
}
