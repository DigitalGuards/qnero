//! Integration tests for the vesting pallet's runtime couplings that pallet unit tests
//! cannot see: the admin calls answering `BadOrigin` and `CallFiltered` at the
//! runtime's own door, and a genesis schedule paying out through `claim`.
//!
//! The admin origin used to be `EnsureRoot` or `EnsureTreasury`, and the tests
//! here drove it through the real treasury multisig. It is `NeverEnsureOrigin`
//! now, so `create_schedule`, `end_schedule` and `retarget_schedule` are
//! unreachable twice over: the call filter refuses all three, and the origin
//! accepts nobody. The genesis table is the whole set of schedules any Qnero
//! chain will ever hold, which is why every test below that needs one builds it
//! at genesis.

#[cfg(test)]
mod tests {
	use crate::common::TestCommons;
	use frame_support::{assert_noop, assert_ok, traits::Currency};
	use qnero_runtime::{
		configs::{VestingMinClaimInterval, VestingPayoutQuantum},
		AccountId, Balance, Balances, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, System,
		Vesting, ZkTree, EXISTENTIAL_DEPOSIT, UNIT,
	};
	use sp_core::crypto::AccountId32;
	use sp_runtime::{BuildStorage, DispatchError};

	const END_MS: u64 = 1_000_000;
	const GRANT: Balance = 100 * UNIT;

	/// `(beneficiary, start_ms, cliff_ms, end_ms, total)`, the genesis shape.
	type GenesisSchedule = (AccountId, u64, u64, u64, u128);

	fn account(id: u8) -> AccountId32 {
		TestCommons::account_id(id)
	}

	fn signers() -> Vec<AccountId> {
		vec![account(1), account(2), account(3)]
	}

	fn treasury_multisig() -> AccountId {
		pallet_multisig::Pallet::<Runtime>::derive_multisig_address(&signers(), 2, 0)
	}

	fn new_test_ext(treasury: Option<AccountId>) -> sp_io::TestExternalities {
		new_test_ext_with_schedules(treasury, Vec::new())
	}

	/// A chain whose vesting table is fixed at genesis, which is the only kind
	/// this runtime can produce.
	///
	/// The pot is endowed through the balances genesis rather than afterwards,
	/// because `pallet_vesting`'s genesis build asserts that the pot holds
	/// exactly the sum of the schedule totals plus its own existential deposit.
	fn new_test_ext_with_schedules(
		treasury: Option<AccountId>,
		schedules: Vec<GenesisSchedule>,
	) -> sp_io::TestExternalities {
		let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();

		let pot_total: u128 = schedules.iter().map(|(_, _, _, _, total)| *total).sum();
		let mut balances: Vec<(AccountId, u128)> =
			signers().into_iter().map(|who| (who, 1000 * UNIT)).collect();
		balances.push((Vesting::pot_account_id(), pot_total + EXISTENTIAL_DEPOSIT));
		pallet_balances::GenesisConfig::<Runtime> { balances, dev_accounts: None }
			.assimilate_storage(&mut t)
			.unwrap();

		pallet_treasury::GenesisConfig::<Runtime> { treasury_account: treasury }
			.assimilate_storage(&mut t)
			.unwrap();

		pallet_vesting::GenesisConfig::<Runtime> {
			schedules: schedules.try_into().expect("test table fits MAX_GENESIS_SCHEDULES"),
			anchor_to_first_timestamp: false,
		}
		.assimilate_storage(&mut t)
		.unwrap();

		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {
			System::set_block_number(1);
		});
		ext
	}

	/// A beneficiary's own claim, dispatched the way a user makes it: a signed
	/// origin through the v1 call filter.
	///
	/// `Vesting::claim` is the one vesting call v1 leaves dispatchable. The pot
	/// is keyless and funded at genesis, no origin can create a schedule after
	/// genesis, and a claim pays a beneficiary fixed at genesis an amount fixed
	/// at genesis. Refusing it would strand every genesis allocation in an
	/// account with no key.
	fn claim_as(who: AccountId, schedule_id: u64) -> sp_runtime::DispatchResult {
		use sp_runtime::traits::Dispatchable;
		RuntimeCall::Vesting(pallet_vesting::Call::claim { schedule_id })
			.dispatch(RuntimeOrigin::signed(who))
			.map(|_| ())
			.map_err(|error| error.error)
	}

	fn set_time(now_ms: u64) {
		pallet_timestamp::Now::<Runtime>::put(now_ms);
	}

	/// Leaves in the commitment tree.
	///
	/// A vesting payout used to record one, which is what made a credit to a
	/// keyless beneficiary spendable through the wormhole exit. v1 removed the
	/// exit, so a payout records none and this is zero throughout: the only
	/// leaves on a v1 chain are note commitments.
	fn recorded_leaves() -> u64 {
		ZkTree::leaf_count()
	}

	/// The treasury multisig path into vesting is closed under v1, at both
	/// layers. A beneficiary's own claim is not.
	///
	/// This replaces `treasury_multisig_creates_and_ends_schedules`, which
	/// covered the flow when it worked. The inner call of a
	/// `Multisig::execute` is dispatched with the multisig's own signed origin,
	/// so it meets the filter on the way in whatever the outer call did, and
	/// creating a vesting grant moves transparent value into the pot. There is
	/// no origin behind the filter either, which
	/// `the_vesting_admin_calls_are_unreachable` covers. `claim` stays
	/// dispatchable because it is the only way the keyless pot ever pays
	/// anybody.
	#[test]
	fn the_treasury_multisig_path_into_vesting_is_refused() {
		use sp_runtime::traits::Dispatchable;
		new_test_ext(Some(treasury_multisig())).execute_with(|| {
			let grant = RuntimeCall::Vesting(pallet_vesting::Call::create_schedule {
				beneficiary: account(7),
				start: 0,
				cliff: 0,
				end: END_MS,
				total: GRANT,
			});
			let execute = RuntimeCall::Multisig(pallet_multisig::Call::execute {
				multisig_address: treasury_multisig(),
				proposal_id: 0,
				call: Box::new(grant.clone()),
			});
			assert_eq!(
				execute
					.dispatch(RuntimeOrigin::signed(account(3)))
					.expect_err("a vesting grant moves transparent value")
					.error,
				DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
			);
			// The inner call on its own, which is what the multisig would have
			// dispatched with its own signed origin.
			assert_eq!(
				grant
					.dispatch(RuntimeOrigin::signed(treasury_multisig()))
					.expect_err("the same call, one layer down")
					.error,
				DispatchError::from(frame_system::Error::<Runtime>::CallFiltered)
			);
			// A beneficiary's own claim is the call a user makes, and it goes
			// through. There is no schedule 0 here, so the pallet's own error
			// is what comes back, which is the proof that the filter was not
			// what stopped it.
			let claim = RuntimeCall::Vesting(pallet_vesting::Call::claim { schedule_id: 0 });
			assert_eq!(
				claim
					.dispatch(RuntimeOrigin::signed(account(7)))
					.expect_err("there is no schedule to claim")
					.error,
				DispatchError::from(pallet_vesting::Error::<Runtime>::NoSchedule)
			);
		});
	}

	/// The three admin calls answer nobody, at both layers.
	///
	/// This replaces `non_treasury_origins_are_rejected` and
	/// `unconfigured_treasury_fails_loudly`, which asserted that a signed origin
	/// was refused while Root and the treasury were accepted. `AdminOrigin` is
	/// `NeverEnsureOrigin` now, so the pallet answers `BadOrigin` to every
	/// caller including Root, and a chain that configures a treasury is no
	/// different from one that does not. A dispatch never gets that far: the
	/// call filter answers `CallFiltered` first.
	#[test]
	fn the_vesting_admin_calls_are_unreachable() {
		use sp_runtime::traits::Dispatchable;

		for treasury in [Some(treasury_multisig()), None] {
			new_test_ext(treasury).execute_with(|| {
				let origins = [
					RuntimeOrigin::root(),
					RuntimeOrigin::signed(account(1)),
					RuntimeOrigin::signed(treasury_multisig()),
				];
				for origin in origins {
					assert_noop!(
						Vesting::create_schedule(origin.clone(), account(7), 0, 0, END_MS, GRANT,),
						DispatchError::BadOrigin
					);
					assert_noop!(
						Vesting::end_schedule(origin.clone(), 0),
						DispatchError::BadOrigin
					);
					assert_noop!(
						Vesting::retarget_schedule(origin, 0, account(8)),
						DispatchError::BadOrigin
					);
				}

				// The same three as dispatches, which is the layer a signed
				// extrinsic actually meets.
				for call in [
					RuntimeCall::Vesting(pallet_vesting::Call::create_schedule {
						beneficiary: account(7),
						start: 0,
						cliff: 0,
						end: END_MS,
						total: GRANT,
					}),
					RuntimeCall::Vesting(pallet_vesting::Call::end_schedule { schedule_id: 0 }),
					RuntimeCall::Vesting(pallet_vesting::Call::retarget_schedule {
						schedule_id: 0,
						new_beneficiary: account(8),
					}),
				] {
					assert_eq!(
						call.clone()
							.dispatch(RuntimeOrigin::signed(account(1)))
							.expect_err("every vesting admin call moves transparent value")
							.error,
						DispatchError::from(frame_system::Error::<Runtime>::CallFiltered),
						"{call:?} reached the pallet"
					);
				}
			});
		}
	}

	/// The payout quantum still has to clear the existential deposit and the
	/// claim interval is still a day. The third clause was the wormhole exit's
	/// volume fee dividing evenly into a non-final payout, and there is no
	/// exit to price any more.
	#[test]
	fn payout_policy_covers_the_account_minimum() {
		let quantum = VestingPayoutQuantum::get();
		assert!(quantum > EXISTENTIAL_DEPOSIT);
		assert_eq!(VestingMinClaimInterval::get(), 24 * 60 * 60 * 1000);
		assert_eq!(quantum * pallet_vesting::NON_FINAL_PAYOUT_QUANTA, 25 * UNIT);
	}

	/// A genesis schedule of exactly one quantum pays once and then nothing.
	///
	/// The beneficiary never signs anything, which is the shape a genesis
	/// allocation to a cold address has: anybody may dispatch the `claim`, and
	/// the schedule pays the beneficiary it was written with. The schedule is
	/// built at genesis because no origin can create one afterwards; the
	/// pallet's own unit tests cover the validity rules a rejected schedule
	/// would trip.
	#[test]
	fn one_quantum_schedule_claims_exactly_once_and_records_no_leaf() {
		let quantum = VestingPayoutQuantum::get();
		let beneficiary = account(9);
		let schedule = (beneficiary.clone(), 0u64, 0u64, END_MS, quantum);

		new_test_ext_with_schedules(Some(account(4)), vec![schedule]).execute_with(|| {
			let pot = Vesting::pot_account_id();
			set_time(END_MS - 1);
			assert_noop!(claim_as(account(1), 0), pallet_vesting::Error::<Runtime>::NothingToClaim);
			set_time(END_MS);
			System::reset_events();
			let count_before = recorded_leaves();
			assert_ok!(claim_as(account(1), 0));

			// The payout used to record a ZK-tree leaf, which is what let a
			// keyless beneficiary exit the funds through the wormhole. v1
			// removed the exit, so a payout is an ordinary transparent transfer
			// with no ZK side at all.
			assert_eq!(recorded_leaves(), count_before, "v1 records no transfer leaf");

			let payout = System::events()
				.into_iter()
				.find_map(|record| match record.event {
					RuntimeEvent::Balances(pallet_balances::Event::Transfer {
						from,
						to,
						amount,
					}) if from == pot && to == beneficiary => Some(amount),
					_ => None,
				})
				.expect("claim must emit a plain Transfer event from the pot");
			assert_eq!(payout, quantum);
			assert_eq!(Balances::total_balance(&beneficiary), quantum);
			assert_eq!(Balances::total_balance(&pot), EXISTENTIAL_DEPOSIT);
			let schedule = pallet_vesting::Schedules::<Runtime>::get(0).unwrap();
			assert_eq!(schedule.total, quantum);
			assert_eq!(schedule.claimed, quantum);
			assert_noop!(claim_as(account(1), 0), pallet_vesting::Error::<Runtime>::NothingToClaim);
		});
	}

	/// Claiming daily and claiming once pay the same total and record the same
	/// number of leaves, which is zero either way.
	#[test]
	fn non_final_alignment_stops_daily_fragmentation_from_reducing_exit_value() {
		const DAY: u64 = 24 * 60 * 60 * 1000;
		const DAYS: u64 = 365;
		const TOTAL: Balance = DAYS as Balance * UNIT;
		let beneficiary = account(9);
		let schedule = (beneficiary.clone(), 0u64, 0u64, DAYS * DAY, TOTAL);

		let periodic_leaves = new_test_ext_with_schedules(Some(account(4)), vec![schedule.clone()])
			.execute_with(|| {
				set_time(DAY);
				assert_noop!(
					claim_as(account(8), 0),
					pallet_vesting::Error::<Runtime>::NothingToClaim
				);
				for day in 1..=DAYS {
					set_time(day * DAY);
					let _ = claim_as(account(8), 0);
				}
				assert_eq!(pallet_vesting::Schedules::<Runtime>::get(0).unwrap().claimed, TOTAL);
				recorded_leaves()
			});

		let single_leaves = new_test_ext_with_schedules(Some(account(4)), vec![schedule])
			.execute_with(|| {
				set_time(DAYS * DAY);
				assert_ok!(claim_as(account(8), 0));
				recorded_leaves()
			});

		// Both shapes record nothing: the exit those leaves fed is gone, and a
		// payout is an ordinary transparent transfer with no ZK side at all.
		assert_eq!(single_leaves, 0);
		assert_eq!(periodic_leaves, 0);
	}
}
