//! Custom signed extensions for the runtime.
extern crate alloc;
use crate::*;
use codec::{Decode, DecodeWithMemTracking, Encode};
use core::marker::PhantomData;
use frame_support::pallet_prelude::{
	InvalidTransaction, TransactionValidityError, ValidTransaction,
};
use qp_high_security::HighSecurityInspector;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_runtime::{
	traits::{
		AsSystemOriginSigner, DispatchInfoOf, PostDispatchInfoOf, TransactionExtension, Zero,
	},
	DispatchResult, Weight,
};

/// `InvalidTransaction::Custom` code for a high-security signer attaching a tip.
/// Distinct from the whitelist rejection (`Custom(1)`).
pub const HIGH_SECURITY_TIP_FORBIDDEN: u8 = 2;

/// `InvalidTransaction::Custom` code when a high-security signer has already
/// included `MaxHighSecurityTxsPerWindow` extrinsics in the rolling window.
pub const HIGH_SECURITY_TX_QUOTA_EXCEEDED: u8 = 3;

/// `InvalidTransaction::Custom` code when a high-security signer's extrinsic
/// exceeds `MAX_HIGH_SECURITY_EXTRINSIC_LEN` encoded bytes.
pub const HIGH_SECURITY_EXTRINSIC_TOO_LARGE: u8 = 4;

/// `InvalidTransaction::Custom` code when a high-security signer's extrinsic
/// would cost more than `MAX_HIGH_SECURITY_INCLUSION_FEE` at zero tip.
pub const HIGH_SECURITY_FEE_LIMIT_EXCEEDED: u8 = 5;

/// Transaction extension for reversible accounts
///
/// This extension is used to intercept delayed transactions for users that opted in
/// for reversible transactions. Based on the policy set by the user, the transaction
/// will either be denied or intercepted and delayed.
#[derive(Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo, Debug, DecodeWithMemTracking)]
#[scale_info(skip_type_params(T))]
pub struct ReversibleTransactionExtension<T: pallet_reversible_transfers::Config>(PhantomData<T>);

impl<T: pallet_reversible_transfers::Config + Send + Sync> ReversibleTransactionExtension<T> {
	/// Creates new `TransactionExtension` to check genesis hash.
	pub fn new() -> Self {
		Self(core::marker::PhantomData)
	}
}

impl<T: pallet_reversible_transfers::Config + Send + Sync + alloc::fmt::Debug>
	TransactionExtension<RuntimeCall> for ReversibleTransactionExtension<T>
{
	/// Whether the signer is high-security, decided once in `validate` and
	/// carried forward: `prepare` records the quota only on the high-security
	/// path, and `post_dispatch_details` refunds the unused quota weight on
	/// every other path.
	type Pre = bool;
	type Val = bool;
	type Implicit = ();

	const IDENTIFIER: &'static str = "ReversibleTransactionExtension";

	fn weight(&self, _call: &RuntimeCall) -> Weight {
		// Worst case — a high-security signer, four reads and one write:
		//   1r `HighSecurityAccounts` classification        (validate)
		//   1r `NextFeeMultiplier` for the fee ceiling      (validate)
		//   1r `HighSecurityTxQuota` ring, admission check  (validate)
		//   1r+1w `HighSecurityTxQuota` ring, recording     (prepare)
		// The pallet helpers (`hs_quota_has_room` / `record_hs_quota`) do
		// not re-read `HighSecurityAccounts`, so it is read exactly once.
		// All other traffic
		// performs only the classification read; the surplus is returned in
		// `post_dispatch_details`. Walking `batch_all` children in
		// `is_whitelisted` is in-memory only. Proof size is deliberately not
		// modeled: this is a solo PoW chain (no PoV), matching `DbWeight`
		// usage across the runtime.
		T::DbWeight::get().reads_writes(4, 1)
	}

	fn prepare(
		self,
		val: Self::Val,
		origin: &sp_runtime::traits::DispatchOriginOf<RuntimeCall>,
		_call: &RuntimeCall,
		_info: &sp_runtime::traits::DispatchInfoOf<RuntimeCall>,
		_len: usize,
	) -> Result<Self::Pre, TransactionValidityError> {
		// `val` is fresh: during block execution `validate` runs immediately
		// before `prepare` on the same state, so the whitelist and length
		// gates in `validate` are consensus-enforced without a re-check here.
		if !val {
			return Ok(false);
		}
		let who = origin
			.as_system_origin_signer()
			.ok_or(TransactionValidityError::Invalid(InvalidTransaction::BadSigner))?;
		// Record here rather than in `validate`: mempool validation is not
		// sequenced with other same-account extrinsics in this block, so the
		// ring mutation must happen at inclusion time. `hs_ring_record`
		// re-checks ring admission; the high-security classification itself is
		// taken from `val` (fresh: `validate` ran just before on this state).
		pallet_reversible_transfers::Pallet::<Runtime>::record_hs_quota(who).map_err(|_| {
			TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_TX_QUOTA_EXCEEDED,
			))
		})?;
		Ok(true)
	}

	fn validate(
		&self,
		origin: sp_runtime::traits::DispatchOriginOf<RuntimeCall>,
		call: &RuntimeCall,
		info: &sp_runtime::traits::DispatchInfoOf<RuntimeCall>,
		len: usize,
		_self_implicit: Self::Implicit,
		_inherited_implication: &impl sp_runtime::traits::Implication,
		_source: frame_support::pallet_prelude::TransactionSource,
	) -> sp_runtime::traits::ValidateResult<Self::Val, RuntimeCall> {
		let Some(who) = origin.as_system_origin_signer() else {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::BadSigner));
		};

		// The one `HighSecurityAccounts` classification read, shared by the
		// whitelist check below, the quota check, the recording in `prepare`
		// and the weight refund in `post_dispatch_details`.
		let is_high_security = crate::configs::HighSecurityConfig::is_high_security(who);

		// Enforce the high-security whitelist on the top-level signer.
		// `is_whitelisted` walks `batch_all` children so a mixed batch is rejected here.
		// Origin-rewriting wrappers (multisig execution) re-check the whitelist at the
		// effective origin inside their own pallets at dispatch time.
		if !crate::configs::HighSecurityConfig::is_call_allowed_given(is_high_security, call) {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(1)));
		}

		// Cap the encoded length: the length fee is charged on the full
		// extrinsic pre-dispatch and never refunded, so a stolen key must not
		// be able to pad a future variable-length field and grind free
		// balance out to a colluding block author.
		if is_high_security && len as u32 > crate::configs::MAX_HIGH_SECURITY_EXTRINSIC_LEN {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_EXTRINSIC_TOO_LARGE,
			)));
		}

		// Bound the zero-tip inclusion fee itself, not just its inputs: a
		// future whitelisted call with an unforeseen length or weight surface
		// (the fee input the length cap above cannot see) cannot reopen the
		// fee-drain channel. Deterministic because `FeeMultiplierUpdate` is a
		// constant one.
		if is_high_security &&
			pallet_transaction_payment::Pallet::<Runtime>::compute_fee(len as u32, info, 0) >
				crate::configs::MAX_HIGH_SECURITY_INCLUSION_FEE
		{
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_FEE_LIMIT_EXCEEDED,
			)));
		}

		if is_high_security &&
			!pallet_reversible_transfers::Pallet::<Runtime>::hs_quota_has_room(who)
		{
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_TX_QUOTA_EXCEEDED,
			)));
		}

		Ok((ValidTransaction::default(), is_high_security, origin))
	}

	fn post_dispatch_details(
		pre: Self::Pre,
		_info: &sp_runtime::traits::DispatchInfoOf<RuntimeCall>,
		_post_info: &PostDispatchInfoOf<RuntimeCall>,
		_len: usize,
		_result: &DispatchResult,
	) -> Result<Weight, TransactionValidityError> {
		if pre {
			// High-security path: the full declared weight was used.
			return Ok(Weight::zero());
		}
		// Everyone else only did the classification read; return the fee
		// ceiling's multiplier read and the quota ring reads/write reserved
		// by `weight()`. This extension precedes the payment extension in
		// `TxExtension`, so the refund reaches the payer's fee, not just
		// block capacity.
		Ok(T::DbWeight::get().reads_writes(3, 1))
	}
}

/// The fee adapter that actually moves funds; [`HighSecurityFungibleAdapter`]
/// only vets the tip before delegating.
type InnerFeeAdapter = pallet_transaction_payment::FungibleAdapter<
	Balances,
	pallet_mining_rewards::TransactionFeesCollector<Runtime>,
>;

/// `OnChargeTransaction` adapter that forbids tips from high-security signers.
///
/// The call whitelist cannot see the tip: it lives on the payment extension,
/// not on `RuntimeCall`. Enforcing it in a wrapper extension proved fragile —
/// the wrapper had to impersonate the stock `ChargeTransactionPayment`
/// `IDENTIFIER`, so a refactor back to the unwrapped extension would have
/// compiled with byte-identical metadata while silently reopening the tip
/// channel. This adapter sees both `who` and `tip` on every fee path —
/// `can_withdraw_fee` on the (mempool and consensus) validation path and
/// `withdraw_fee` at inclusion — so the policy survives any change to the
/// extension tuple.
///
/// High-security accounts are delayed by design and do not need priority
/// bidding; a non-zero tip is rejected with `Custom(HIGH_SECURITY_TIP_FORBIDDEN)`
/// before anything is withdrawn.
///
/// Weight note: the `HighSecurityAccounts` read happens only on the
/// tip-carrying path (`can_withdraw_fee` during validation, `withdraw_fee` at
/// inclusion). The stock benchmarked payment weight cannot see this branch,
/// so [`PaymentWeightsWithTipPolicy`] — the configured payment `WeightInfo` —
/// declares both reads unconditionally.
pub struct HighSecurityFungibleAdapter;

/// `pallet_transaction_payment` weights adjusted for Quantus-owned work the
/// stock kitchensink benchmark never measures:
///
/// * two `HighSecurityAccounts` reads from the tip policy in [`HighSecurityFungibleAdapter`]
///   (`can_withdraw_fee` then `withdraw_fee` on a tipped transaction). Many distinct tipped signers
///   can appear in one block, so these are not warm-cache hits.
/// * one unique-key `CollectedFees` read and write from
///   [`pallet_mining_rewards::TransactionFeesCollector`] on every nonzero corrected fee. The
///   follow-on `get` for the event is same-key.
///
/// The high-security reads are charged unconditionally: the payment extension
/// has no tip-keyed refund hook, so zero-tip traffic overpays those two reads
/// (~50µs ref_time) — an error in the safe direction. The collector access
/// runs on every paid extrinsic, so it is not an overcharge.
pub struct PaymentWeightsWithTipPolicy;

impl pallet_transaction_payment::WeightInfo for PaymentWeightsWithTipPolicy {
	fn charge_transaction_payment() -> Weight {
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		pallet_transaction_payment::weights::SubstrateWeight::<Runtime>::charge_transaction_payment(
		)
		.saturating_add(db.reads(2))
		.saturating_add(db.reads_writes(1, 1))
	}
}

impl HighSecurityFungibleAdapter {
	fn reject_high_security_tip(
		who: &AccountId,
		tip: Balance,
	) -> Result<(), TransactionValidityError> {
		// Tip compared first so the storage read is skipped on the zero-tip path.
		if !tip.is_zero() && crate::configs::HighSecurityConfig::is_high_security(who) {
			return Err(TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_TIP_FORBIDDEN,
			)));
		}
		Ok(())
	}
}

impl pallet_transaction_payment::TxCreditHold<Runtime> for HighSecurityFungibleAdapter {
	type Credit = <InnerFeeAdapter as pallet_transaction_payment::TxCreditHold<Runtime>>::Credit;
}

impl pallet_transaction_payment::OnChargeTransaction<Runtime> for HighSecurityFungibleAdapter {
	type Balance = Balance;
	type LiquidityInfo = <InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<
		Runtime,
	>>::LiquidityInfo;

	fn withdraw_fee(
		who: &AccountId,
		call: &RuntimeCall,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		fee_with_tip: Self::Balance,
		tip: Self::Balance,
	) -> Result<Self::LiquidityInfo, TransactionValidityError> {
		Self::reject_high_security_tip(who, tip)?;
		<InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<Runtime>>::withdraw_fee(
			who,
			call,
			dispatch_info,
			fee_with_tip,
			tip,
		)
	}

	fn can_withdraw_fee(
		who: &AccountId,
		call: &RuntimeCall,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		fee_with_tip: Self::Balance,
		tip: Self::Balance,
	) -> Result<(), TransactionValidityError> {
		Self::reject_high_security_tip(who, tip)?;
		<InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<Runtime>>::can_withdraw_fee(
			who,
			call,
			dispatch_info,
			fee_with_tip,
			tip,
		)
	}

	fn correct_and_deposit_fee(
		who: &AccountId,
		dispatch_info: &DispatchInfoOf<RuntimeCall>,
		post_info: &PostDispatchInfoOf<RuntimeCall>,
		corrected_fee_with_tip: Self::Balance,
		tip: Self::Balance,
		liquidity_info: Self::LiquidityInfo,
	) -> Result<(), TransactionValidityError> {
		// No tip re-check: a high-security tip never gets past
		// `can_withdraw_fee` / `withdraw_fee`, so `tip` is zero here.
		<InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<Runtime>>::correct_and_deposit_fee(
			who,
			dispatch_info,
			post_info,
			corrected_fee_with_tip,
			tip,
			liquidity_info,
		)
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn endow_account(who: &AccountId, amount: Self::Balance) {
		<InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<Runtime>>::endow_account(
			who, amount,
		)
	}

	#[cfg(feature = "runtime-benchmarks")]
	fn minimum_balance() -> Self::Balance {
		<InnerFeeAdapter as pallet_transaction_payment::OnChargeTransaction<Runtime>>::minimum_balance()
	}
}

// `WormholeProofRecorderExtension` lived here until M6.
//
// It scanned a signed call's balance events and wrote a wormhole transfer leaf
// for every credit that landed on a keyless account, which is what made a
// transparent credit spendable through the ZK exit. Qnero v1 removed the exit
// with `pallet-wormhole` and removed the transfers with the call filter, so
// there is nothing left for it to scan: the block reward and the author's
// share of a settled fee are notes now, minted by `pallet-shielded` from the
// coinbase inherent, and `docs/DESIGN.md` section 7 lists what a signed call
// may still do. Dropping it from `TxExtension` changed the signed extrinsic
// encoding, which is what `transaction_version` 7 records.

#[cfg(test)]
mod tests {
	// The crate denies these at the top of `lib.rs`, which is the right default
	// for a runtime: a panic in a dispatch is a dead block. A test that cannot
	// build its own genesis has nothing to assert, so the deny is lifted here
	// and nowhere else.
	#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

	use super::*;
	use frame_support::{assert_ok, pallet_prelude::TransactionValidityError};
	use pallet_transaction_payment::WeightInfo;
	use sp_runtime::{traits::TxBaseImplication, AccountId32};
	fn alice() -> AccountId {
		AccountId32::from([1; 32])
	}

	fn bob() -> AccountId {
		AccountId32::from([2; 32])
	}
	fn charlie() -> AccountId {
		AccountId32::from([3; 32])
	}

	// Build genesis storage according to the mock runtime.
	pub fn new_test_ext() -> sp_io::TestExternalities {
		let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();

		pallet_balances::GenesisConfig::<Runtime> {
			balances: vec![
				(alice(), EXISTENTIAL_DEPOSIT * 10000),
				(bob(), EXISTENTIAL_DEPOSIT * 2),
				(charlie(), EXISTENTIAL_DEPOSIT * 100),
			],
			dev_accounts: None,
		}
		.assimilate_storage(&mut t)
		.unwrap();

		// high security account is charlie
		// guardian is alice
		pallet_reversible_transfers::GenesisConfig::<Runtime> {
			initial_high_security_accounts: vec![(charlie(), alice(), 10)],
		}
		.assimilate_storage(&mut t)
		.unwrap();

		// Treasury account is required for mining-reward fallback credits. It
		// must be explicit: the genesis default no longer configures anything (the old
		// default account was the keyless `[1u8; 32]` minting sentinel).
		pallet_treasury::GenesisConfig::<Runtime> {
			treasury_account: Some(AccountId32::from([9u8; 32])),
		}
		.assimilate_storage(&mut t)
		.unwrap();

		sp_io::TestExternalities::new(t)
	}

	#[test]
	fn test_reversible_transaction_extension() {
		new_test_ext().execute_with(|| {
			// Other calls should not be intercepted
			let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![1, 2, 3] });

			let origin = RuntimeOrigin::signed(alice());
			let ext = ReversibleTransactionExtension::<Runtime>::new();

			let result = ext.validate(
				origin,
				&call,
				&Default::default(),
				0,
				(),
				&TxBaseImplication::<()>(()),
				frame_support::pallet_prelude::TransactionSource::External,
			);

			// we should not fail here
			assert_ok!(result);

			// Test that non-high-security accounts can make balance transfers
			let ext = ReversibleTransactionExtension::<Runtime>::new();
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
				dest: MultiAddress::Id(bob()),
				value: 10 * EXISTENTIAL_DEPOSIT,
			});
			let origin = RuntimeOrigin::signed(alice());

			// Full lifecycle: validate decides the high-security status once and
			// prepare consumes it. Alice is not high-security, so this succeeds
			// and prepare reports the refundable (non-HS) path.
			let (_, val, _) = ext
				.clone()
				.validate(
					origin.clone(),
					&call,
					&Default::default(),
					0,
					(),
					&TxBaseImplication::<()>(()),
					frame_support::pallet_prelude::TransactionSource::External,
				)
				.expect("alice is not high-security");
			assert!(!val, "alice must be classified as non-high-security");
			let pre = ext.prepare(val, &origin, &call, &Default::default(), 0).unwrap();
			assert!(!pre);

			// Charlie is already configured as high-security from genesis
			// Verify Charlie is high-security
			assert!(ReversibleTransfers::is_high_security(&charlie()).is_some());

			// High-security accounts can call schedule_transfer
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(bob()),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);

			// Test the validate method
			let result = check_call(call);
			assert_ok!(result);

			// High-security accounts can call cancel
			let call =
				RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
					tx_id: sp_core::H256::default(),
				});
			let result = check_call(call);
			assert_ok!(result);

			// All other calls are disallowed for high-security accounts
			// (use transfer_keep_alive - not in whitelist for prod or runtime-benchmarks)
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
				dest: MultiAddress::Id(bob()),
				value: 10 * EXISTENTIAL_DEPOSIT,
			});
			let result = check_call(call);
			assert_eq!(
				result.unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	// Run the reversible transaction extension's `validate` for `call` signed by `signer`.

	// As `validate_with`, but with an explicit encoded length so the length gate can
	// be exercised without building a multi-KiB extrinsic.
	fn validate_with_len(
		signer: AccountId,
		call: &RuntimeCall,
		len: usize,
	) -> Result<(), TransactionValidityError> {
		ReversibleTransactionExtension::<Runtime>::new()
			.validate(
				RuntimeOrigin::signed(signer),
				call,
				&Default::default(),
				len,
				(),
				&TxBaseImplication::<()>(()),
				frame_support::pallet_prelude::TransactionSource::External,
			)
			.map(|_| ())
	}

	// As `validate_with`, but with an explicit `DispatchInfo` so the fee ceiling
	// can be exercised against a hypothetical heavy-weight call.
	fn validate_with_info(
		signer: AccountId,
		call: &RuntimeCall,
		info: &frame_support::dispatch::DispatchInfo,
	) -> Result<(), TransactionValidityError> {
		ReversibleTransactionExtension::<Runtime>::new()
			.validate(
				RuntimeOrigin::signed(signer),
				call,
				info,
				0,
				(),
				&TxBaseImplication::<()>(()),
				frame_support::pallet_prelude::TransactionSource::External,
			)
			.map(|_| ())
	}

	fn check_call(call: RuntimeCall) -> Result<(), TransactionValidityError> {
		// Verify Charlie is high-security
		assert!(ReversibleTransfers::is_high_security(&charlie()).is_some());

		let origin = RuntimeOrigin::signed(charlie());
		let ext = ReversibleTransactionExtension::<Runtime>::new();

		// Full lifecycle: validate classifies the signer, prepare records the quota.
		let (_, val, _) = ext.clone().validate(
			origin.clone(),
			&call,
			&Default::default(),
			0,
			(),
			&TxBaseImplication::<()>(()),
			frame_support::pallet_prelude::TransactionSource::External,
		)?;
		assert!(val, "charlie must be classified as high-security");
		ext.prepare(val, &origin, &call, &Default::default(), 0).map(|_| ())
	}

	#[test]
	fn test_high_security_transfer_keep_alive() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
				dest: MultiAddress::Id(bob()),
				value: 10 * EXISTENTIAL_DEPOSIT,
			});
			let result = check_call(call);

			// High-security accounts cannot make balance transfers
			assert_eq!(
				result.unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_transfer_allow_death() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
				dest: MultiAddress::Id(bob()),
				value: 10 * EXISTENTIAL_DEPOSIT,
			});
			let result = check_call(call);

			// High-security accounts cannot make balance transfers
			assert_eq!(
				result.unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_transfer_all() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_all {
				dest: MultiAddress::Id(bob()),
				keep_alive: true,
			});
			let result = check_call(call);

			// High-security accounts cannot make balance transfers
			assert_eq!(
				result.unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_schedule_transfer_allowed() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(bob()),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);
			// High-security accounts can call schedule_transfer
			assert_ok!(check_call(call));
		});
	}

	#[test]
	fn test_high_security_schedule_transfer_raw_dest_rejected() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Raw(vec![0u8; 1024]),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_schedule_transfer_address32_dest_rejected() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Address32([2u8; 32]),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_cancel_allowed() {
		new_test_ext().execute_with(|| {
			let call =
				RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
					tx_id: sp_core::H256::default(),
				});
			assert_ok!(check_call(call));
		});
	}

	// A call that clears the whitelist is still rejected for a high-security signer
	// once the encoded extrinsic exceeds the length cap. The gate lives in
	// `validate` only, which is consensus-enforced: `dispatch_transaction` runs
	// it immediately before `prepare` during block execution.
	#[test]
	fn test_high_security_oversized_extrinsic_rejected() {
		new_test_ext().execute_with(|| {
			let cap = crate::configs::MAX_HIGH_SECURITY_EXTRINSIC_LEN as usize;
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(bob()),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);
			let too_large = TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_EXTRINSIC_TOO_LARGE,
			));
			assert_eq!(validate_with_len(charlie(), &call, cap + 1).unwrap_err(), too_large);
		});
	}

	// The cap is inclusive: an extrinsic exactly at the limit is accepted, so a
	// legitimate worst-case `batch_all` is never rejected for length.
	#[test]
	fn test_high_security_extrinsic_at_cap_allowed() {
		new_test_ext().execute_with(|| {
			let cap = crate::configs::MAX_HIGH_SECURITY_EXTRINSIC_LEN as usize;
			let call = RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(bob()),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			);
			assert_ok!(validate_with_len(charlie(), &call, cap));
		});
	}

	// Weight is the fee input the length cap cannot see: a whitelisted call
	// with a huge (e.g. future mis-benchmarked) weight must not reopen the
	// fee-drain channel for a high-security signer.
	#[test]
	fn test_high_security_overweight_extrinsic_rejected() {
		new_test_ext().execute_with(|| {
			let call =
				RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
					tx_id: sp_core::H256::default(),
				});
			// ~2 UNIT of weight fee at IdentityFee — double the ceiling.
			let info = frame_support::dispatch::DispatchInfo {
				call_weight: Weight::from_parts(2_000_000_000_000, 0),
				..Default::default()
			};
			assert_eq!(
				validate_with_info(charlie(), &call, &info).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(
					HIGH_SECURITY_FEE_LIMIT_EXCEEDED
				))
			);
			// Normal signers are not fee-capped.
			assert_ok!(validate_with_info(alice(), &call, &info));
		});
	}

	/// Pins the declared storage weights to the executed footprint (enumerated
	/// in the `weight()` comment), so an edit to either side trips this test
	/// instead of silently under-declaring database work.
	#[test]
	fn weight_declarations_match_the_executed_storage_footprint() {
		let db = <Runtime as frame_system::Config>::DbWeight::get();
		let ext = ReversibleTransactionExtension::<Runtime>::new();
		let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });

		// High-security worst case: classification + `NextFeeMultiplier` +
		// quota-ring admission read in `validate`, ring read/write in
		// `prepare`. The quota helpers do not re-read
		// `HighSecurityAccounts`, so it is read exactly once.
		assert_eq!(
			<ReversibleTransactionExtension<Runtime> as TransactionExtension<RuntimeCall>>::weight(
				&ext, &call
			),
			db.reads_writes(4, 1)
		);

		// Non-high-security traffic executes only the classification read;
		// everything else is refunded.
		let refund = <ReversibleTransactionExtension<Runtime> as TransactionExtension<
			RuntimeCall,
		>>::post_dispatch_details(
			false, &Default::default(), &Default::default(), 0, &Ok(())
		)
		.unwrap();
		assert_eq!(refund, db.reads_writes(3, 1));

		// A tipped transaction additionally reads `HighSecurityAccounts` in
		// both `can_withdraw_fee` and `withdraw_fee` of the fee adapter.
		// Every paid extrinsic also mutates `CollectedFees` in the collector
		// (one unique-key read + write; the follow-on get is same-key).
		assert_eq!(
			<PaymentWeightsWithTipPolicy as pallet_transaction_payment::WeightInfo>::charge_transaction_payment(),
			pallet_transaction_payment::weights::SubstrateWeight::<Runtime>::charge_transaction_payment()
				.saturating_add(db.reads(2))
				.saturating_add(db.reads_writes(1, 1))
		);
	}

	// The zero-tip policy lives in the fee adapter, so it fires on every fee
	// path (mempool and consensus validation, and inclusion-time withdrawal)
	// regardless of how the extension tuple is composed.
	#[test]
	fn test_high_security_fee_adapter_rejects_tip() {
		use pallet_transaction_payment::OnChargeTransaction;
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
			let info = Default::default();
			let forbidden = TransactionValidityError::Invalid(InvalidTransaction::Custom(
				HIGH_SECURITY_TIP_FORBIDDEN,
			));

			// Charlie is high-security from genesis: any non-zero tip is refused
			// before funds move, on both the check and the withdrawal paths.
			assert_eq!(
				<HighSecurityFungibleAdapter as OnChargeTransaction<Runtime>>::can_withdraw_fee(
					&charlie(),
					&call,
					&info,
					10,
					10
				)
				.unwrap_err(),
				forbidden
			);
			assert_eq!(
				<HighSecurityFungibleAdapter as OnChargeTransaction<Runtime>>::withdraw_fee(
					&charlie(),
					&call,
					&info,
					10,
					10
				)
				.unwrap_err(),
				forbidden
			);

			// Zero tip from a high-security signer and any tip from a normal
			// signer both pass through to the inner adapter.
			assert_ok!(
				<HighSecurityFungibleAdapter as OnChargeTransaction<Runtime>>::can_withdraw_fee(
					&charlie(),
					&call,
					&info,
					10,
					0
				)
			);
			assert_ok!(
				<HighSecurityFungibleAdapter as OnChargeTransaction<Runtime>>::can_withdraw_fee(
					&alice(),
					&call,
					&info,
					10,
					5
				)
			);
		});
	}

	// Normal accounts are not length-capped: only high-security signers are.
	#[test]
	fn test_non_high_security_large_extrinsic_allowed() {
		new_test_ext().execute_with(|| {
			let cap = crate::configs::MAX_HIGH_SECURITY_EXTRINSIC_LEN as usize;
			let call = RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
				dest: MultiAddress::Id(bob()),
				value: 10 * EXISTENTIAL_DEPOSIT,
			});
			assert_ok!(validate_with_len(alice(), &call, cap * 4));
		});
	}

	#[test]
	fn test_high_security_batch_all_of_whitelisted_calls_is_allowed() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all {
				calls: vec![
					RuntimeCall::ReversibleTransfers(
						pallet_reversible_transfers::Call::schedule_transfer {
							dest: MultiAddress::Id(bob()),
							amount: 10 * EXISTENTIAL_DEPOSIT,
						},
					),
					RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
						tx_id: Default::default(),
					}),
				],
			});
			assert_ok!(check_call(call));
		});
	}

	#[test]
	fn test_high_security_empty_batch_all_is_rejected() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![] });
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_nested_batch_all_is_rejected() {
		new_test_ext().execute_with(|| {
			let inner = RuntimeCall::Utility(pallet_utility::Call::batch_all {
				calls: vec![RuntimeCall::ReversibleTransfers(
					pallet_reversible_transfers::Call::cancel { tx_id: Default::default() },
				)],
			});
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![inner] });
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_batch_all_rejects_more_than_max_batch_len_children() {
		new_test_ext().execute_with(|| {
			let max = crate::configs::MaxHighSecurityBatchLen::get() as usize;
			let child =
				RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
					tx_id: Default::default(),
				});
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all {
				calls: vec![child; max + 1],
			});
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_batch_all_rejects_raw_dest_child() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all {
				calls: vec![RuntimeCall::ReversibleTransfers(
					pallet_reversible_transfers::Call::schedule_transfer {
						dest: MultiAddress::Raw(vec![0u8; 1024]),
						amount: 10 * EXISTENTIAL_DEPOSIT,
					},
				)],
			});
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_vesting_claim_is_rejected() {
		new_test_ext().execute_with(|| {
			// Deliberately not whitelisted: `claim` is permissionless, so a third
			// party can claim on the HS beneficiary's behalf; on the HS signer it
			// was only another no-op fee path.
			let call = RuntimeCall::Vesting(pallet_vesting::Call::claim { schedule_id: 0 });
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	#[test]
	fn test_high_security_batch_all_rejects_non_whitelisted_child() {
		new_test_ext().execute_with(|| {
			let call = RuntimeCall::Utility(pallet_utility::Call::batch_all {
				calls: vec![
					RuntimeCall::ReversibleTransfers(
						pallet_reversible_transfers::Call::schedule_transfer {
							dest: MultiAddress::Id(bob()),
							amount: 10 * EXISTENTIAL_DEPOSIT,
						},
					),
					RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
						dest: MultiAddress::Id(bob()),
						value: 10 * EXISTENTIAL_DEPOSIT,
					}),
				],
			});
			assert_eq!(
				check_call(call).unwrap_err(),
				TransactionValidityError::Invalid(InvalidTransaction::Custom(1))
			);
		});
	}

	/// The high-security whitelist still admits a `batch_all` of scheduled
	/// transfers, and v1's call filter refuses the same batch one layer above
	/// it.
	///
	/// Both halves are the point. The whitelist is what a high-security account
	/// is allowed to submit at all, and it is unchanged; the filter is what any
	/// account may dispatch, and under v1 nothing that moves transparent value
	/// may. `Utility::batch_all` dispatches its children through the same
	/// filter as the batch itself, so the refusal lands on the children.
	#[test]
	fn a_batch_all_of_schedule_transfers_passes_the_whitelist_and_fails_the_filter() {
		new_test_ext().execute_with(|| {
			let children = vec![
				RuntimeCall::ReversibleTransfers(
					pallet_reversible_transfers::Call::schedule_transfer {
						dest: MultiAddress::Id(bob()),
						amount: 10 * EXISTENTIAL_DEPOSIT,
					},
				),
				RuntimeCall::ReversibleTransfers(
					pallet_reversible_transfers::Call::schedule_transfer {
						dest: MultiAddress::Id(bob()),
						amount: 11 * EXISTENTIAL_DEPOSIT,
					},
				),
			];
			let batch =
				RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: children.clone() });
			assert_ok!(check_call(batch));

			// `assert_noop!` compares the post-dispatch weight too, and
			// `batch_all` reports what it consumed before the refusal.
			let refused = Utility::batch_all(RuntimeOrigin::signed(charlie()), children)
				.expect_err("the children move transparent value");
			assert_eq!(refused.error, frame_system::Error::<Runtime>::CallFiltered.into());
			assert_eq!(ReversibleTransfers::next_transaction_id(), 0);
		});
	}

	/// The single-copy event reader decodes exactly what the streaming reader
	/// would.
	///
	/// It exists to make a scan linear: one `storage::get` in place of per-2-KiB
	/// refills that each re-materialize the whole overlay value. What it reads is
	/// the same. The scan it was built for went with
	/// `WormholeProofRecorderExtension` at M6 and the reader is still the
	/// runtime's, so this is what pins its behaviour.
	#[test]
	fn single_copy_event_reader_matches_the_streaming_reader() {
		new_test_ext().execute_with(|| {
			System::set_block_number(1);

			// A mixed stream: small records, a transfer, and an oversized record.
			assert_ok!(System::remark_with_event(RuntimeOrigin::signed(alice()), vec![1]));
			assert_ok!(Balances::transfer_keep_alive(
				RuntimeOrigin::signed(alice()),
				MultiAddress::Id(bob()),
				EXISTENTIAL_DEPOSIT * 50,
			));
			System::deposit_event(RuntimeEvent::Multisig(
				pallet_multisig::Event::ProposalExecuted {
					multisig_address: alice(),
					proposal_id: 0,
					proposer: alice(),
					call: vec![0u8; 10_240],
					approvers: vec![alice(); 100],
					result: Ok(()),
				},
			));

			let streamed: alloc::vec::Vec<_> =
				frame_system::Pallet::<Runtime>::read_events_no_consensus()
					.map(|boxed| *boxed)
					.collect();
			let (bytes, single_copy) =
				frame_system::Pallet::<Runtime>::read_events_no_consensus_single_copy();
			let single_copy: alloc::vec::Vec<_> = single_copy.collect();

			assert!(!streamed.is_empty(), "the fixture must have produced events");
			assert_eq!(
				streamed, single_copy,
				"the single-copy reader must decode the identical records"
			);
			assert_eq!(
				bytes,
				frame_system::Pallet::<Runtime>::event_bytes(),
				"the returned size must be the encoded length of the Events value"
			);
		});
	}
}
