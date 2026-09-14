//! Guard for the consensus rule in `runtime/src/extrinsic.rs`: the transparent
//! entry admits ML-DSA-87 and refuses ML-DSA-65.
//!
//! Both halves are here. An ML-DSA-65 signature is refused with
//! `InvalidTransaction::BadSigner` on both consensus paths, the one
//! `Executive::validate_transaction` takes and the one
//! `Executive::apply_extrinsic` takes, and on the one call the pool depends on,
//! `Shielded::shield`. An otherwise identical ML-DSA-87 extrinsic is admitted
//! and dispatches.
//!
//! Before this rule an ML-DSA-65 extrinsic passed every check and entered the
//! block, refused only later at dispatch by v1's call filter. That history is
//! what makes this a consensus break, and it is why the tests below assert the
//! refusal happens at the entry.

use crate::common::TestCommons;
use frame_support::traits::Currency;
use qnero_runtime::{
	Balances, BalancesCall, Executive, Runtime, RuntimeCall, Signature, System, UncheckedExtrinsic,
	UNIT,
};
use qp_dilithium_crypto::{Dilithium65Pair, Dilithium87Pair};
use sp_core::{Pair, H256};
use sp_runtime::{
	traits::IdentifyAccount,
	transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
	AccountId32, MultiAddress,
};

const BAD_SIGNER: TransactionValidityError =
	TransactionValidityError::Invalid(InvalidTransaction::BadSigner);

fn ml_dsa_87_pair() -> Dilithium87Pair {
	Dilithium87Pair::from_seed_slice(&[42u8; 32]).expect("valid seed")
}

fn ml_dsa_65_pair() -> Dilithium65Pair {
	Dilithium65Pair::from_seed_slice(&[42u8; 32]).expect("valid seed")
}

/// Fund both signers. The two schemes hash to different accounts, and each test
/// below builds the same call under both, so both have to be able to pay.
fn test_ext() -> sp_io::TestExternalities {
	use qnero_runtime::BuildStorage;

	let t = frame_system::GenesisConfig::<Runtime>::default()
		.build_storage()
		.expect("storage");
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		Balances::make_free_balance_be(&ml_dsa_87_account(), 1000 * UNIT);
		Balances::make_free_balance_be(&ml_dsa_65_account(), 1000 * UNIT);
		System::set_block_number(1);
	});
	ext
}

fn ml_dsa_87_account() -> AccountId32 {
	ml_dsa_87_pair().public().into_account()
}

fn ml_dsa_65_account() -> AccountId32 {
	ml_dsa_65_pair().public().into_account()
}

/// The extrinsic the rule refuses: the production extension pipeline, signed
/// with the ML-DSA-65 variant.
fn ml_dsa_65_signed(call: RuntimeCall, nonce: u32) -> UncheckedExtrinsic {
	let pair = ml_dsa_65_pair();
	TestCommons::signed_extrinsic_signed_with(
		|payload| Signature::Dilithium65(pair.sign(payload)),
		ml_dsa_65_account(),
		call,
		nonce,
		0,
	)
}

/// The same extrinsic under the scheme the chain admits.
fn ml_dsa_87_signed(call: RuntimeCall, nonce: u32) -> UncheckedExtrinsic {
	TestCommons::signed_extrinsic(&ml_dsa_87_pair(), ml_dsa_87_account(), call, nonce, 0)
}

fn transfer(dest: &AccountId32) -> RuntimeCall {
	BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest.clone()), value: 10 * UNIT }
		.into()
}

fn remark() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark { remark: b"ml-dsa-87".to_vec() })
}

fn shield() -> RuntimeCall {
	RuntimeCall::Shielded(pallet_shielded::Call::shield {
		value: UNIT,
		inner: [0u8; 32],
		ciphertext: Vec::new(),
	})
}

fn validate(xt: UncheckedExtrinsic) -> Result<(), TransactionValidityError> {
	Executive::validate_transaction(TransactionSource::External, xt, H256::default()).map(|_| ())
}

#[test]
fn validate_transaction_refuses_an_ml_dsa_65_signature_with_bad_signer() {
	test_ext().execute_with(|| {
		let dest = AccountId32::new([9u8; 32]);
		assert_eq!(
			validate(ml_dsa_65_signed(transfer(&dest), 0)),
			Err(BAD_SIGNER),
			"an ML-DSA-65 signature must never reach the transaction pool"
		);
	});
}

#[test]
fn apply_extrinsic_refuses_an_ml_dsa_65_signature_with_bad_signer() {
	test_ext().execute_with(|| {
		let dest = AccountId32::new([9u8; 32]);
		assert_eq!(
			Executive::apply_extrinsic(ml_dsa_65_signed(transfer(&dest), 0)),
			Err(BAD_SIGNER),
			"an ML-DSA-65 signature must never be included in a block"
		);
		assert_eq!(Balances::free_balance(&dest), 0, "no value moved");
	});
}

/// The rule is at the extrinsic, so it covers every signed call without naming
/// one. `Shielded::shield` is the case worth pinning: it is the only door into
/// the pool, the call filter allows it, and a rule written per call would be
/// the easiest one to forget here.
#[test]
fn the_rule_covers_shield_the_one_door_into_the_pool() {
	test_ext().execute_with(|| {
		assert_eq!(validate(ml_dsa_65_signed(shield(), 0)), Err(BAD_SIGNER));
		assert_eq!(Executive::apply_extrinsic(ml_dsa_65_signed(shield(), 0)), Err(BAD_SIGNER));
	});
}

/// The refusal runs ahead of signature verification. An ML-DSA-65
/// extrinsic whose signature is also wrong answers `BadSigner`, which is the
/// rule speaking; `BadProof` here would mean the verifier ran first and the
/// rule is decoration on top of it.
#[test]
fn the_refusal_precedes_signature_verification() {
	test_ext().execute_with(|| {
		let impostor = ml_dsa_65_pair();
		let xt = TestCommons::signed_extrinsic_signed_with(
			|payload| Signature::Dilithium65(impostor.sign(payload)),
			AccountId32::new([7u8; 32]),
			remark(),
			0,
			0,
		);
		assert_eq!(Executive::apply_extrinsic(xt), Err(BAD_SIGNER));
	});
}

/// The other half of the rule: the scheme the chain does admit still settles,
/// through the same pipeline, the same extensions and the same two entry
/// points.
#[test]
fn an_identical_ml_dsa_87_extrinsic_is_admitted_and_dispatches() {
	test_ext().execute_with(|| {
		assert!(
			validate(ml_dsa_87_signed(remark(), 0)).is_ok(),
			"ML-DSA-87 is the scheme the transparent entry admits"
		);
		Executive::apply_extrinsic(ml_dsa_87_signed(remark(), 0))
			.expect("admitted")
			.expect("dispatched");
	});
}

/// The signed transfer that v1 refuses at dispatch is still admitted when it
/// carries an ML-DSA-87 signature, which is what separates this rule from the
/// call filter: one decides who may sign, the other decides what may run.
#[test]
fn an_ml_dsa_87_signed_transfer_is_admitted_and_refused_by_the_call_filter() {
	test_ext().execute_with(|| {
		let dest = AccountId32::new([9u8; 32]);
		let outcome = Executive::apply_extrinsic(ml_dsa_87_signed(transfer(&dest), 0))
			.expect("ML-DSA-87 passes the entry");
		assert_eq!(
			outcome.expect_err("v1 refuses a transparent transfer"),
			sp_runtime::DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
		);
		assert_eq!(Balances::free_balance(&dest), 0, "no value moved");
	});
}
