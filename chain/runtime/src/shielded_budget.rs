//! Bounded component measurements in the runtime's WASM compilation.
//! Enabled only by `shielded-budget-bench`; no production RPC is registered.

use crate::Runtime;
use alloc::{format, vec::Vec};
use pallet_shielded::weights;

pub const LOAD_PRIVATE: u8 = 0;
pub const PARSE_PRIVATE: u8 = 1;
pub const VERIFY_PRIVATE: u8 = 2;
pub const LOAD_PUBLIC: u8 = 3;
pub const PARSE_PUBLIC: u8 = 4;
pub const VERIFY_PUBLIC: u8 = 5;
pub const PAYLOAD_DIGEST: u8 = 6;

sp_api::decl_runtime_apis! {
	pub trait ShieldedBudgetApi {
		fn profile() -> Vec<u8>;
		fn run(operation: u8, input: Vec<u8>, repetitions: u32, slots: u32)
			-> Result<(u64, u32), Vec<u8>>;
	}
}

fn error(message: impl core::fmt::Display) -> Vec<u8> {
	format!("{message}").into_bytes()
}

/// Returns the declared reference-time budget and an observed result count.
/// Setup lives in the host harness; every measured operation runs in WASM.
pub fn run(
	operation: u8,
	input: &[u8],
	repetitions: u32,
	slots: u32,
) -> Result<(u64, u32), Vec<u8>> {
	if repetitions == 0 || repetitions > 16 || input.len() > pallet_shielded::MAX_PROOF_BYTES {
		return Err(error("benchmark request exceeds its fixed limits"));
	}
	let max_slots = pallet_shielded::circuit_config::NUM_LEAF_PROOFS *
		pallet_shielded::circuit_config::NUM_PRIVATE_BATCH_PROOFS;
	if slots as usize > max_slots {
		return Err(error("benchmark slot count exceeds the runtime profile"));
	}
	let mut budget = 0u64;
	let mut observed = 0u32;
	for _ in 0..repetitions {
		let (weight, count) = match operation {
			LOAD_PRIVATE => {
				let verifier = pallet_shielded::private_batch_verifier().map_err(error)?;
				(0, verifier.num_leaves() as u32)
			},
			PARSE_PRIVATE => {
				let verifier = pallet_shielded::private_batch_verifier().map_err(error)?;
				let public = verifier.parse_proof_bytes(input).map_err(error)?;
				(
					weights::pre_validate_ref_time(weights::PRIVATE_BATCH_PI_FELTS),
					public.slots.len() as u32,
				)
			},
			VERIFY_PRIVATE => {
				let verifier = pallet_shielded::private_batch_verifier().map_err(error)?;
				let public = verifier.verify_proof_bytes(input).map_err(error)?;
				(
					weights::PRIVATE_BATCH_VERIFY_REF_TIME_PS.saturating_add(
						weights::pre_validate_ref_time(weights::PRIVATE_BATCH_PI_FELTS),
					),
					public.slots.len() as u32,
				)
			},
			LOAD_PUBLIC => {
				let verifier = pallet_shielded::public_batch_verifier().map_err(error)?;
				(0, verifier.num_inner() as u32)
			},
			PARSE_PUBLIC => {
				let verifier = pallet_shielded::public_batch_verifier().map_err(error)?;
				let public = verifier.parse_proof_bytes(input).map_err(error)?;
				(
					weights::pre_validate_ref_time(weights::PUBLIC_BATCH_PI_FELTS),
					public.batches.len() as u32,
				)
			},
			VERIFY_PUBLIC => {
				let verifier = pallet_shielded::public_batch_verifier().map_err(error)?;
				let public = verifier.verify_proof_bytes(input).map_err(error)?;
				(
					weights::PUBLIC_BATCH_VERIFY_REF_TIME_PS.saturating_add(
						weights::pre_validate_ref_time(weights::PUBLIC_BATCH_PI_FELTS),
					),
					public.batches.len() as u32,
				)
			},
			PAYLOAD_DIGEST => {
				if input.len() >
					<Runtime as pallet_shielded::Config>::MaxCiphertextBytes::get() as usize
				{
					return Err(error("payload exceeds the runtime ciphertext cap"));
				}
				let mut fold = 0u32;
				let mut payload = input.to_vec();
				// Inclusion checks the payload in pre-dispatch and dispatch.
				for slot in 0..slots.saturating_mul(2) {
					if let Some(first) = payload.first_mut() {
						*first = first.wrapping_add(slot as u8);
					}
					let digest = qnero_circuit::chain::ct_digest(&[&payload, input]);
					fold = fold
						.wrapping_add(u32::from_le_bytes([
							digest[0], digest[1], digest[2], digest[3],
						]))
						.wrapping_add(slot);
				}
				(
					weights::ct_digest_ref_time(
						u64::from(slots),
						slots as u64 * input.len() as u64 * 2,
					),
					fold,
				)
			},
			_ => return Err(error("unknown benchmark operation")),
		};
		budget = budget.saturating_add(weight);
		observed = observed.wrapping_add(count);
	}
	Ok((budget, observed))
}
