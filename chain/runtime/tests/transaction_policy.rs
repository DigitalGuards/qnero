//! The public Executive rejects unsupported calls before pool admission or
//! block inclusion. These tests use the production extrinsic wrapper and keep
//! the admission policy separate from lower-layer fee and quota coverage.

#[allow(dead_code)]
mod common;

use codec::Encode;
use common::TestCommons;
use frame_support::traits::Currency;
use qnero_runtime::{
	extrinsic::UpstreamUncheckedExtrinsic, AccountId, Balances, Executive, Runtime, RuntimeCall,
	System, UncheckedExtrinsic, UNIT,
};
use qp_dilithium_crypto::Dilithium87Pair;
use sp_core::{Pair, H256};
use sp_runtime::{
	generic::{DigestItem, Preamble},
	traits::{Checkable, IdentifyAccount},
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	BuildStorage, MultiAddress,
};

const INVALID_CALL: TransactionValidityError =
	TransactionValidityError::Invalid(InvalidTransaction::Call);

fn pair() -> Dilithium87Pair {
	Dilithium87Pair::from_seed_slice(&[43; 32]).expect("valid test seed")
}

fn sender() -> AccountId {
	pair().public().into_account()
}

fn recipient() -> AccountId {
	AccountId::new([9; 32])
}

fn test_ext() -> sp_io::TestExternalities {
	let storage = frame_system::GenesisConfig::<Runtime>::default()
		.build_storage()
		.expect("valid system genesis");
	let mut ext = sp_io::TestExternalities::new(storage);
	ext.execute_with(|| {
		System::set_block_number(1);
		Balances::make_free_balance_be(&sender(), 1000 * UNIT);
	});
	ext
}

fn signed(call: RuntimeCall) -> UncheckedExtrinsic {
	TestCommons::signed_extrinsic(&pair(), sender(), call, 0, 0)
}

fn transfer() -> RuntimeCall {
	RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
		dest: MultiAddress::Id(recipient()),
		value: UNIT,
	})
}

/// A `Multisig::propose` carrying `payload` as its opaque inner call.
fn propose(payload: Vec<u8>) -> RuntimeCall {
	RuntimeCall::Multisig(pallet_multisig::Call::propose {
		multisig_address: AccountId::new([8; 32]),
		call: payload.try_into().expect("the payload fits MaxCallSize"),
		expiry: 100,
	})
}

/// Valid call bytes with one byte after them.
///
/// `decode` does not have to consume its whole input, so this passes a bare
/// decode and is still permanently unexecutable: `execute` requires the
/// executor's typed call to re-encode byte-equal to the stored payload, and no
/// typed call encodes trailing bytes. The pallet refuses it at propose time
/// and so does the filter.
fn non_canonical() -> Vec<u8> {
	let mut bytes =
		RuntimeCall::System(frame_system::Call::remark { remark: b"payload".to_vec() }).encode();
	bytes.push(0x00);
	bytes
}

/// Both bare encodings, the signed encoding, and the general preamble all
/// reach the same call policy before their own authorization checks.
fn formats(call: RuntimeCall) -> [UncheckedExtrinsic; 4] {
	let signed = signed(call.clone());
	let Preamble::Signed(_, _, tx_ext) = &signed.0.preamble else {
		panic!("test helper must produce a signed extrinsic");
	};
	let general = UncheckedExtrinsic(UpstreamUncheckedExtrinsic::new_transaction(
		call.clone(),
		tx_ext.clone(),
	));
	[
		signed,
		UncheckedExtrinsic::new_bare(call.clone()),
		UncheckedExtrinsic(UpstreamUncheckedExtrinsic::new_bare_legacy(call)),
		general,
	]
}

fn forbidden_calls() -> Vec<RuntimeCall> {
	vec![
		transfer(),
		RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
			dest: MultiAddress::Id(recipient()),
			value: UNIT,
		}),
		RuntimeCall::Balances(pallet_balances::Call::transfer_all {
			dest: MultiAddress::Id(recipient()),
			keep_alive: true,
		}),
		RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![RuntimeCall::Multisig(pallet_multisig::Call::execute {
				multisig_address: AccountId::new([8; 32]),
				proposal_id: 0,
				call: Box::new(transfer()),
			})],
		}),
		// `propose` carries its inner call as opaque bytes and dispatches
		// nothing, so the three shapes here are what the filter has to decode:
		// a transfer, a wrapper carrying one, and a payload that can never
		// execute at all.
		propose(transfer().encode()),
		propose(
			RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![transfer()] })
				.encode(),
		),
		propose(non_canonical()),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::schedule_transfer {
			dest: MultiAddress::Id(recipient()),
			amount: UNIT,
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::set_high_security {
			delay: qp_scheduler::BlockNumberOrTimestamp::BlockNumber(10),
			guardian: recipient(),
		}),
		RuntimeCall::Vesting(pallet_vesting::Call::create_schedule {
			beneficiary: recipient(),
			start: 0,
			cliff: 0,
			end: 10,
			total: UNIT,
		}),
	]
}

#[test]
fn forbidden_calls_are_invalid_for_pool_admission_in_every_format() {
	for call in forbidden_calls() {
		test_ext().execute_with(|| {
			for xt in formats(call.clone()) {
				assert_eq!(
					Executive::validate_transaction(
						TransactionSource::External,
						xt,
						H256::default(),
					),
					Err(INVALID_CALL),
					"unsupported call must be rejected before admission: {call:?}"
				);
			}
		});
	}
}

#[test]
fn forbidden_calls_are_invalid_before_block_recording_fees_or_nonce_changes() {
	let empty = extrinsics_root_of_a_block_nothing_was_offered_to();
	for call in forbidden_calls() {
		test_ext().execute_with(|| {
			let account_before = System::account(sender());
			let recipient_before = System::account(recipient());
			let events_before = System::events();
			let index_before = System::extrinsic_index();
			for xt in formats(call.clone()) {
				assert_eq!(Executive::apply_extrinsic(xt), Err(INVALID_CALL));
				assert_eq!(System::account(sender()), account_before);
				assert_eq!(System::account(recipient()), recipient_before);
				assert_eq!(System::events(), events_before);
				assert_eq!(System::extrinsic_index(), index_before);
				assert!(System::extrinsic_data(0).is_empty());
			}
			// The header half of the same property. `extrinsic_data` is the
			// storage the body is built from, and `extrinsics_root` is what
			// the header commits to, so a block offered four refused
			// extrinsics has to hash to the block nobody offered anything to.
			assert_eq!(
				System::finalize().extrinsics_root,
				empty,
				"a refused call must leave the header it was offered to unchanged: {call:?}"
			);
		});
	}
}

/// The `extrinsics_root` of the same block, finalized without the attempt.
fn extrinsics_root_of_a_block_nothing_was_offered_to() -> H256 {
	test_ext().execute_with(|| System::finalize().extrinsics_root)
}

#[test]
fn call_policy_precedes_signature_verification() {
	test_ext().execute_with(|| {
		let mut xt = signed(transfer());
		let Preamble::Signed(address, _, _) = &mut xt.0.preamble else {
			panic!("test helper must produce a signed extrinsic");
		};
		*address = MultiAddress::Id(recipient());
		assert_eq!(Executive::apply_extrinsic(xt), Err(INVALID_CALL));
	});
}

#[test]
fn an_allowed_signed_batch_and_pool_entry_still_validate_and_dispatch() {
	let shield = RuntimeCall::Shielded(pallet_shielded::Call::shield {
		value: UNIT,
		inner: [0; 32],
		ciphertext: Vec::new(),
	});
	for call in [
		shield,
		RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![RuntimeCall::System(frame_system::Call::remark {
				remark: b"allowed batch".to_vec(),
			})],
		}),
	] {
		test_ext().execute_with(|| {
			assert!(Executive::validate_transaction(
				TransactionSource::External,
				signed(call.clone()),
				H256::default(),
			)
			.is_ok());
		});
		test_ext().execute_with(|| {
			Executive::apply_extrinsic(signed(call.clone()))
				.expect("supported signed call is valid")
				.expect("supported signed call dispatches");
			assert_eq!(System::account_nonce(sender()), 1);
			if matches!(call, RuntimeCall::Shielded(..)) {
				assert_eq!(pallet_shielded::PoolValue::<Runtime>::get(), UNIT);
				assert_eq!(pallet_zk_tree::LeafCount::<Runtime>::get(), 1);
			}
		});
	}
}

#[test]
fn unsigned_settlements_continue_to_their_own_validity_checks() {
	for call in [
		RuntimeCall::Shielded(pallet_shielded::Call::submit_private_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::submit_public_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
	] {
		test_ext().execute_with(|| {
			let xt = UncheckedExtrinsic::new_bare(call);
			assert!(xt.clone().check(&frame_system::ChainContext::<Runtime>::default()).is_ok());
			let result =
				Executive::validate_transaction(TransactionSource::External, xt, H256::default());
			assert!(result.is_err(), "an empty proof must still fail settlement validation");
		});
	}
}

/// A settlement carrying a wrong-length ciphertext is a permanent refusal, so
/// the real runtime answers `InvalidTransaction::Call` and never
/// `ExhaustsResources`.
///
/// The two answers mean opposite things to a block builder. `ExhaustsResources`
/// is "block full": the transaction is skipped and offered again for the next
/// block. `Call` is "invalid": it is dropped. The ciphertext-cap deferral added
/// the only `ExhaustsResources` arm this pallet has, for the one condition that
/// really is temporary, and `CiphertextLengthMismatch` and `UnknownCryptoSuite`
/// must not join it: a permanent failure answered as a full block would be
/// re-skipped once a block until its longevity ran out.
///
/// What this pins is the answer the whole runtime gives, through the production
/// extrinsic wrapper. Which check fires first is pinned in the pallet, over a
/// real proof, by `a_wrong_length_payload_is_a_permanent_call_refusal`: this
/// crate links no prover, so the proof here is empty and the parse refuses
/// ahead of the length rule.
#[test]
fn a_wrong_length_settlement_payload_is_never_answered_as_a_full_block() {
	// One byte short of `qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES`. The
	// literal is written out because this crate links `qnero-circuit` only
	// behind an optional benchmark feature, and the pallet's own tests hold the
	// number to the constant.
	let short = vec![7u8; 1_791];
	let outputs = vec![pallet_shielded::ShieldedOutput::<Runtime> {
		ct_1: short.clone().try_into().expect("under MaxCiphertextBytes"),
		ct_2: short.try_into().expect("under MaxCiphertextBytes"),
	}];
	for call in [
		RuntimeCall::Shielded(pallet_shielded::Call::submit_private_batch {
			proof: Vec::new(),
			outputs: outputs.clone(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::submit_public_batch {
			proof: Vec::new(),
			outputs: outputs.clone(),
		}),
	] {
		test_ext().execute_with(|| {
			let xt = UncheckedExtrinsic::new_bare(call);
			assert_eq!(
				Executive::validate_transaction(
					TransactionSource::External,
					xt.clone(),
					H256::default(),
				),
				Err(INVALID_CALL),
			);
			assert_eq!(Executive::apply_extrinsic(xt), Err(INVALID_CALL));
		});
	}
}

/// Both errors the exact-length rule raises exist in the runtime's own
/// `pallet-shielded` instance, so a wallet reading the metadata can name them
/// and the rule is not a pallet-only build.
#[test]
fn the_runtime_carries_the_exact_length_errors() {
	let names = [
		pallet_shielded::Error::<Runtime>::CiphertextLengthMismatch,
		pallet_shielded::Error::<Runtime>::UnknownCryptoSuite,
	];
	for error in names {
		let dispatch: sp_runtime::DispatchError = error.into();
		assert!(matches!(dispatch, sp_runtime::DispatchError::Module(_)));
	}
}

#[test]
fn timestamp_and_coinbase_inherents_still_apply() {
	for call in [
		RuntimeCall::Timestamp(pallet_timestamp::Call::set { now: 120_000 }),
		RuntimeCall::Shielded(pallet_shielded::Call::coinbase {
			inner: [0; 32],
			ciphertext: Vec::new(),
		}),
	] {
		test_ext().execute_with(|| {
			let mut author = [0; 32];
			author[..8].copy_from_slice(&1u64.to_le_bytes());
			System::deposit_log(DigestItem::PreRuntime(
				qp_wormhole::POW_ENGINE_ID,
				author.to_vec(),
			));
			Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(call))
				.expect("supported inherent is valid")
				.expect("supported inherent dispatches");
		});
	}
}

#[cfg(feature = "try-runtime")]
#[test]
fn replay_keeps_the_call_policy_for_every_format() {
	test_ext().execute_with(|| {
		for xt in formats(transfer()) {
			assert_eq!(
				xt.unchecked_into_checked_i_know_what_i_am_doing(&frame_system::ChainContext::<
					Runtime,
				>::default(),)
					.map(|_| ()),
				Err(INVALID_CALL)
			);
		}
	});
}
