//! The v1 call filter, at the runtime level.
//!
//! `docs/DESIGN.md` section 7 is the allowlist. What is asserted here is the
//! property the whole milestone rests on: after M6 no signed call moves
//! transparent value from one account to another, the pool's own entry still
//! works, and a wrapper is not a way around the first of those.
//!
//! Dispatched directly against `RuntimeOrigin::signed`, which is where the
//! filter lives: `RuntimeCall::dispatch` asks the origin, and the origin's
//! filter is `frame_system::Config::BaseCallFilter`. A signed extrinsic
//! reaches exactly this call.

use frame_support::{
	dispatch::GetDispatchInfo,
	traits::{Contains, Currency},
};
use quantus_runtime::{
	configs::QneroCallFilter, AccountId, Balances, Runtime, RuntimeCall, RuntimeOrigin, System,
	UNIT,
};
use sp_core::crypto::AccountId32;
use sp_runtime::{traits::Dispatchable, BuildStorage, DispatchError, MultiAddress};

fn account(id: u8) -> AccountId {
	let mut bytes = [0u8; 32];
	bytes[0] = id;
	AccountId32::new(bytes)
}

fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		System::set_block_number(1);
		Balances::make_free_balance_be(&account(1), 1_000 * UNIT);
		Balances::make_free_balance_be(&account(2), 1_000 * UNIT);
	});
	ext
}

fn transfer(value: u128) -> RuntimeCall {
	RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
		dest: MultiAddress::Id(account(2)),
		value,
	})
}

/// Every dispatch this milestone closes, refused by the one error that says so.
#[test]
fn a_transparent_transfer_is_refused_with_call_filtered() {
	new_test_ext().execute_with(|| {
		let before = Balances::free_balance(account(2));
		for call in [
			transfer(10 * UNIT),
			RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
				dest: MultiAddress::Id(account(2)),
				value: 10 * UNIT,
			}),
			RuntimeCall::Balances(pallet_balances::Call::transfer_all {
				dest: MultiAddress::Id(account(2)),
				keep_alive: true,
			}),
		] {
			assert_eq!(
				call.dispatch(RuntimeOrigin::signed(account(1))).unwrap_err().error,
				DispatchError::from(frame_system::Error::<Runtime>::CallFiltered),
			);
		}
		assert_eq!(Balances::free_balance(account(2)), before, "no value moved");
		assert_eq!(Balances::free_balance(account(1)), 1_000 * UNIT);
	});
}

/// A filter that stops a call and not the wrapper carrying it is decoration.
/// `batch_all` folds over its inner calls and `Multisig::execute` resubmits the
/// stored call verbatim, so both are right here in the extrinsic.
#[test]
fn a_wrapper_cannot_carry_a_transfer_past_the_filter() {
	new_test_ext().execute_with(|| {
		let batch = RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![
				RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() }),
				transfer(10 * UNIT),
			],
		});
		assert!(!QneroCallFilter::contains(&batch));
		assert_eq!(
			batch.dispatch(RuntimeOrigin::signed(account(1))).unwrap_err().error,
			DispatchError::from(frame_system::Error::<Runtime>::CallFiltered),
		);

		let execute = RuntimeCall::Multisig(pallet_multisig::Call::execute {
			multisig_address: account(3),
			proposal_id: 0,
			call: Box::new(transfer(10 * UNIT)),
		});
		assert!(!QneroCallFilter::contains(&execute));

		// A batch of allowed calls is still a batch of allowed calls.
		let harmless = RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() })],
		});
		assert!(QneroCallFilter::contains(&harmless));
	});
}

/// The delayed and scheduled ways of moving transparent value go with the
/// direct one.
#[test]
fn the_reversible_vesting_and_scheduled_transfer_paths_are_refused() {
	new_test_ext().execute_with(|| {
		let calls: Vec<RuntimeCall> = vec![
			RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(account(2)),
					amount: UNIT,
				},
			),
			RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
				tx_id: sp_core::H256::zero(),
			}),
			RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::recover_funds {
				account: account(2),
			}),
			RuntimeCall::Vesting(pallet_vesting::Call::create_schedule {
				beneficiary: account(2),
				start: 0,
				cliff: 0,
				end: 1,
				total: UNIT,
			}),
		];
		for call in calls {
			assert!(!QneroCallFilter::contains(&call), "{call:?} must be filtered");
			assert_eq!(
				call.dispatch(RuntimeOrigin::signed(account(1))).unwrap_err().error,
				DispatchError::from(frame_system::Error::<Runtime>::CallFiltered),
			);
		}
	});
}

/// Enrolling in high security is a one-way door into a feature v1 refuses.
///
/// The pallet has no call that undoes `set_high_security` and refuses a second
/// one with `AccountAlreadyHighSecurity`. Once an account is in, every call on
/// `HighSecurityConfig`'s whitelist that moves value is refused at dispatch by
/// this filter, and every call off that whitelist is refused at validation by
/// `ReversibleTransactionExtension`, before it can reach a block at all. What
/// the account keeps is `shield` and `burn`, which the whitelist carries for
/// the accounts already enrolled. Refusing the enrolment is what keeps a new
/// account out of that state until a milestone gives the feature something to
/// guard.
#[test]
fn enrolling_in_high_security_is_refused() {
	new_test_ext().execute_with(|| {
		let enrol = RuntimeCall::ReversibleTransfers(
			pallet_reversible_transfers::Call::set_high_security {
				delay: qp_scheduler::BlockNumberOrTimestamp::BlockNumber(10),
				guardian: account(2),
			},
		);
		assert!(!QneroCallFilter::contains(&enrol));
		assert_eq!(
			enrol.clone().dispatch(RuntimeOrigin::signed(account(1))).unwrap_err().error,
			DispatchError::from(frame_system::Error::<Runtime>::CallFiltered),
		);
		assert!(
			!pallet_reversible_transfers::Pallet::<Runtime>::is_high_security_account(&account(1)),
			"the enrolment must not have taken effect"
		);

		// And not through a wrapper either.
		let wrapped = RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![enrol] });
		assert!(!QneroCallFilter::contains(&wrapped));
	});
}

/// An account that is already in high security can still reach the pool.
///
/// The whitelist is checked at validation, before the filter, so a high
/// security account can only sign what is on it. `shield` and `burn` are on it
/// for that reason: without them the accounts enrolled before v1, and the
/// benchmark genesis one, could sign nothing at all and their balance would be
/// frozen forever.
#[test]
fn a_high_security_account_can_still_shield_and_burn() {
	use frame_support::traits::Contains as _;
	use qp_high_security::HighSecurityInspector;

	for call in [
		RuntimeCall::Shielded(pallet_shielded::Call::shield {
			value: UNIT,
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
		RuntimeCall::Balances(pallet_balances::Call::burn { value: UNIT, keep_alive: true }),
	] {
		assert!(
			quantus_runtime::configs::HighSecurityConfig::is_whitelisted(&call),
			"{call:?} must pass the high-security whitelist at validation"
		);
		assert!(
			QneroCallFilter::contains(&call),
			"{call:?} must also pass the base call filter at dispatch"
		);
	}
}

/// The pool's own door stays open, and so does everything a chain needs to run.
///
/// `shield` is the only entry into the pool and it burns the caller's own
/// balance, so it moves value out of the transparent layer rather than between
/// accounts. Blocking it would lock every genesis balance out of the chain's
/// own pool with no way in. The two settlement calls are unsigned and the
/// coinbase is an inherent; a filter that caught the coinbase would be a
/// mandatory dispatch failure, which is a dead block.
#[test]
fn the_pool_entry_the_settlements_and_the_coinbase_are_allowed() {
	let allowed: Vec<RuntimeCall> = vec![
		RuntimeCall::Shielded(pallet_shielded::Call::shield {
			value: UNIT,
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::submit_private_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::submit_public_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::coinbase {
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
		RuntimeCall::Timestamp(pallet_timestamp::Call::set { now: 0 }),
		RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() }),
		RuntimeCall::Balances(pallet_balances::Call::burn { value: UNIT, keep_alive: true }),
		// The genesis distribution channel. The pot is keyless and funded only
		// at genesis, `create_schedule` is refused so no new schedule can
		// appear, and a claim pays a beneficiary fixed at genesis an amount
		// fixed at genesis. Refusing it would strand every genesis allocation
		// in an account with no key.
		RuntimeCall::Vesting(pallet_vesting::Call::claim { schedule_id: 0 }),
	];
	for call in allowed {
		assert!(QneroCallFilter::contains(&call), "{call:?} must stay dispatchable");
	}
}

/// The coinbase is a mandatory dispatch, which is what makes a block that fails
/// to mint its reward an invalid block rather than a block that quietly pays
/// nobody.
#[test]
fn the_coinbase_is_a_mandatory_dispatch() {
	let call = RuntimeCall::Shielded(pallet_shielded::Call::coinbase {
		inner: [0u8; 32],
		ciphertext: Vec::new(),
	});
	assert_eq!(call.get_dispatch_info().class, frame_support::dispatch::DispatchClass::Mandatory);
}

/// The filter is an enumeration, so a call added later is not caught by
/// anything. This is the reminder: if a new call moves transparent value
/// between accounts, it belongs in `moves_transparent_value` and in
/// `docs/DESIGN.md` section 7.
///
/// Read off the call enum's own type information, which is what the runtime
/// metadata is built from, so a variant added anywhere in the list fails here
/// rather than quietly becoming a dispatchable transfer.
#[test]
fn a_new_balance_moving_call_is_matched_here() {
	fn call_names<T: scale_info::TypeInfo + 'static>() -> Vec<String> {
		let mut registry = scale_info::Registry::new();
		let symbol = registry.register_type(&scale_info::meta_type::<T>());
		let portable: scale_info::PortableRegistry = registry.into();
		let scale_info::TypeDef::Variant(variants) =
			&portable.resolve(symbol.id).expect("just registered").type_def
		else {
			panic!("a pallet Call is a variant type");
		};
		variants.variants.iter().map(|variant| variant.name.to_string()).collect()
	}

	assert_eq!(
		call_names::<pallet_balances::Call<Runtime>>(),
		["transfer_allow_death", "transfer_keep_alive", "transfer_all", "burn"],
		"pallet-balances grew or lost a call; decide whether it moves transparent \
		 value and update the filter and docs/DESIGN.md section 7"
	);
	assert_eq!(
		call_names::<pallet_shielded::Call<Runtime>>(),
		["submit_private_batch", "submit_public_batch", "shield", "coinbase"],
		"the shielded pool grew or lost a call; every one of them must stay \
		 dispatchable, and a new inherent must be claimed by `is_inherent`"
	);

	// The three pallets the filter enumerates beside `Balances`. Two of them
	// move value through `T::Currency` directly rather than by dispatching a
	// `Balances` call, so the enumeration here is the only thing standing
	// between a new payout call and a transparent transfer on a v1 chain.
	assert_eq!(
		call_names::<pallet_vesting::Call<Runtime>>(),
		["claim", "create_schedule", "end_schedule", "retarget_schedule"],
		"pallet-vesting grew or lost a call; decide whether it moves transparent \
		 value and update the filter and docs/DESIGN.md section 7"
	);
	assert_eq!(
		call_names::<pallet_reversible_transfers::Call<Runtime>>(),
		[
			"set_high_security",
			"cancel",
			"execute_transfer",
			"schedule_transfer",
			"schedule_transfer_with_delay",
			"recover_funds",
		],
		"pallet-reversible-transfers grew or lost a call; decide whether it moves \
		 transparent value and update the filter and docs/DESIGN.md section 7"
	);
	assert_eq!(
		call_names::<pallet_treasury::Call<Runtime>>(),
		["set_treasury_account"],
		"pallet-treasury grew or lost a call; decide whether it moves transparent \
		 value and update the filter and docs/DESIGN.md section 7"
	);

	// The wrappers. A wrapper the filter does not unwrap is a way around every
	// arm above, so a new one has to be added to `refused_under_v1`.
	assert_eq!(
		call_names::<pallet_utility::Call<Runtime>>(),
		["batch_all"],
		"pallet-utility grew a wrapper; `refused_under_v1` must unwrap it or the \
		 filter is decoration"
	);
	assert_eq!(
		call_names::<pallet_multisig::Call<Runtime>>(),
		[
			"create_multisig",
			"propose",
			"approve",
			"cancel",
			"remove_expired",
			"claim_deposits",
			"execute",
		],
		"pallet-multisig grew a call; `execute` is the one that dispatches an inner \
		 call and `refused_under_v1` must unwrap every one that does"
	);

	// The runtime's own pallet list. A pallet added to `construct_runtime` with
	// a transfer dispatchable is caught by nothing above, so the list itself is
	// the tripwire. Pallets with no dispatchables of their own are absent:
	// `QPoW`, `MiningRewards`, `ZkTree`, `TransactionPayment` and `Origins`
	// have no calls, and `Scheduler` is `#[runtime::disable_call]`.
	assert_eq!(
		call_names::<RuntimeCall>(),
		[
			"System",
			"Timestamp",
			"Balances",
			"Preimage",
			"Utility",
			"ReversibleTransfers",
			"TechCollective",
			"TechReferenda",
			"TreasuryPallet",
			"Multisig",
			"Vesting",
			"Shielded",
		],
		"the runtime gained or lost a pallet with calls; decide whether any of them \
		 moves transparent value and update the filter and docs/DESIGN.md section 7"
	);
}
