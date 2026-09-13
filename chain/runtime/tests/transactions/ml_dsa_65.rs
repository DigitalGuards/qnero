//! End-to-end tests: extrinsics signed with ML-DSA-65 through the full runtime
//! transaction pipeline (`Executive::apply_extrinsic` with all `TxExtension`s).

use crate::common::TestCommons;
use frame_support::traits::Currency;
use qnero_runtime::{
	Balances, BalancesCall, Executive, Runtime, RuntimeCall, System, UncheckedExtrinsic, UNIT,
};
use qp_dilithium_crypto::Dilithium65Pair;
use sp_core::Pair;
use sp_runtime::{traits::IdentifyAccount, AccountId32, MultiAddress};

fn test_ext(account: &AccountId32) -> sp_io::TestExternalities {
	use qnero_runtime::BuildStorage;

	let t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		Balances::make_free_balance_be(account, 1000 * UNIT);
		System::set_block_number(1);
	});
	ext
}

/// Build a `transfer_keep_alive` extrinsic signed by `pair`, claiming `sender`
/// as the transaction origin.
fn signed_transfer(
	pair: &Dilithium65Pair,
	sender: AccountId32,
	dest: AccountId32,
	value: u128,
	nonce: u32,
) -> UncheckedExtrinsic {
	let call: RuntimeCall =
		BalancesCall::transfer_keep_alive { dest: MultiAddress::Id(dest), value }.into();
	TestCommons::signed_extrinsic(pair, sender, call, nonce, 0)
}

/// An ML-DSA-65 signature carries an extrinsic through the whole pipeline, and
/// v1's call filter refuses the call at the end of it.
///
/// Both halves matter. The signature, the nonce, the era, the fee and every
/// transaction extension are checked and pass, which is what this test was
/// written for; the dispatch is then refused with `CallFiltered`, because a
/// transparent transfer is what v1 removed. The extrinsic is admitted and
/// included either way, and no value moves.
#[test]
fn an_ml_dsa_65_signed_transfer_passes_validation_and_is_refused_at_dispatch() {
	let pair = Dilithium65Pair::from_seed_slice(&[42u8; 32]).expect("valid seed");
	let account = pair.public().into_account();
	let mut ext = test_ext(&account);

	ext.execute_with(|| {
		let dest = AccountId32::new([9u8; 32]);
		let xt = signed_transfer(&pair, account.clone(), dest.clone(), 10 * UNIT, 0);

		let outcome = Executive::apply_extrinsic(xt)
			.expect("ML-DSA-65 signed extrinsic should pass validation");
		assert_eq!(
			outcome.expect_err("v1 refuses a transparent transfer"),
			sp_runtime::DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
		);
		assert_eq!(Balances::free_balance(&dest), 0, "no value moved");
	});
}

#[test]
fn test_ml_dsa_65_extrinsic_wrong_signer_rejected() {
	let pair = Dilithium65Pair::from_seed_slice(&[42u8; 32]).expect("valid seed");
	let account = pair.public().into_account();
	let mut ext = test_ext(&account);

	ext.execute_with(|| {
		// The payload is signed by `pair`, but the extrinsic claims a different sender.
		let impostor = AccountId32::new([7u8; 32]);
		let dest = AccountId32::new([9u8; 32]);
		let xt = signed_transfer(&pair, impostor, dest, 10 * UNIT, 0);

		assert!(
			Executive::apply_extrinsic(xt).is_err(),
			"extrinsic with mismatched signer must be rejected"
		);
	});
}
