//! The treasury config pallet, and the one call it no longer has.

#[cfg(test)]
mod tests {
	use crate::common::call_names;
	use qnero_runtime::{configs::TreasuryPalletId, AccountId, Runtime, System, TreasuryPallet, UNIT};
	use sp_runtime::{traits::AccountIdConversion, BuildStorage};

	fn treasury_account_id() -> AccountId {
		TreasuryPalletId::get().into_account_truncating()
	}

	fn new_test_ext() -> sp_io::TestExternalities {
		let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();

		pallet_balances::GenesisConfig::<Runtime> {
			balances: vec![(treasury_account_id(), 1000 * UNIT)],
			dev_accounts: None,
		}
		.assimilate_storage(&mut t)
		.unwrap();

		pallet_treasury::GenesisConfig::<Runtime> { treasury_account: Some(treasury_account_id()) }
			.assimilate_storage(&mut t)
			.unwrap();

		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| System::set_block_number(1));
		ext
	}

	#[test]
	fn genesis_sets_treasury_config() {
		new_test_ext().execute_with(|| {
			assert_eq!(TreasuryPallet::account_id(), treasury_account_id());
		});
	}

	/// The account a chain's genesis names is the only one it will ever have.
	///
	/// `set_treasury_account_works` and `set_treasury_account_requires_root`
	/// were here and are gone with the origin they exercised. The pallet's one
	/// extrinsic is `ensure_root` inside the pallet, and this runtime has no
	/// origin that can produce Root, so `TreasuryPallet` takes
	/// `#[runtime::disable_call]` and the call has no `RuntimeCall` variant at
	/// all. That is the stronger statement, and it is the one asserted here:
	/// not that the call refuses every caller, but that there is no call.
	#[test]
	fn the_treasury_account_cannot_be_changed_after_genesis() {
		assert!(
			!call_names::<qnero_runtime::RuntimeCall>().iter().any(|name| name == "TreasuryPallet"),
			"TreasuryPallet is dispatchable again; `set_treasury_account` is `ensure_root` \
			 inside the pallet and this runtime must have no way to reach it"
		);
	}
}
