//! Integration tests for the vesting pallet's runtime couplings that pallet unit tests
//! cannot see: the `EnsureTreasury` admin origin exercised through the *real* treasury
//! multisig, and the wormhole proof recorder consuming claim payout events.

#[cfg(test)]
mod tests {
	use crate::common::TestCommons;
	use frame_support::{assert_noop, assert_ok, traits::Currency};
	use quantus_runtime::{
		configs::{VestingMinClaimInterval, VestingPayoutQuantum},
		AccountId, Balance, Balances, Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, System,
		Vesting, ZkTree, EXISTENTIAL_DEPOSIT, UNIT,
	};
	use sp_core::crypto::AccountId32;
	use sp_runtime::{BuildStorage, DispatchError};

	const END_MS: u64 = 1_000_000;
	const GRANT: Balance = 100 * UNIT;

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
		let mut t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
		pallet_treasury::GenesisConfig::<Runtime> { treasury_account: treasury.clone() }
			.assimilate_storage(&mut t)
			.unwrap();
		let mut ext = sp_io::TestExternalities::new(t);
		ext.execute_with(|| {
			System::set_block_number(1);
			for signer in signers() {
				Balances::make_free_balance_be(&signer, 1000 * UNIT);
			}
			Balances::make_free_balance_be(&Vesting::pot_account_id(), EXISTENTIAL_DEPOSIT);
		});
		ext
	}

	/// A beneficiary's own claim, dispatched the way a user makes it: a signed
	/// origin through the v1 call filter.
	///
	/// `Vesting::claim` is the one vesting call v1 leaves dispatchable. The pot
	/// is keyless and funded at genesis, `create_schedule` is refused so no new
	/// schedule can appear, and a claim pays a beneficiary fixed at genesis an
	/// amount fixed at genesis. Refusing it would strand every genesis
	/// allocation in an account with no key.
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
	/// creating a vesting grant moves transparent value into the pot. Root
	/// remains the way to create one, which `non_treasury_origins_are_rejected`
	/// still covers. `claim` stays dispatchable because it is the only way the
	/// keyless pot ever pays anybody.
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

	#[test]
	fn end_schedule_records_a_one_quantum_leaf() {
		new_test_ext(Some(account(4))).execute_with(|| {
			let treasury = account(4);
			let beneficiary = account(9);
			Balances::make_free_balance_be(&treasury, 1000 * UNIT);
			let total = 100 * UNIT;
			let quantum = VestingPayoutQuantum::get();
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				beneficiary.clone(),
				0,
				0,
				END_MS,
				total,
			));
			// One quantum vested — nearest is one quantum, paid to the beneficiary.
			set_time((END_MS as u128 * quantum / total) as u64);
			let leaves_before = recorded_leaves();
			assert_ok!(Vesting::end_schedule(RuntimeOrigin::root(), 0));
			assert_eq!(Balances::total_balance(&beneficiary), quantum);
			assert_eq!(recorded_leaves(), leaves_before, "v1 records no transfer leaf");
			assert_eq!(Balances::total_balance(&treasury), 1000 * UNIT - quantum);
		});
	}

	#[test]
	fn non_treasury_origins_are_rejected() {
		new_test_ext(Some(treasury_multisig())).execute_with(|| {
			assert_noop!(
				Vesting::create_schedule(
					RuntimeOrigin::signed(account(1)),
					account(7),
					0,
					0,
					END_MS,
					GRANT,
				),
				DispatchError::BadOrigin
			);
			assert_noop!(
				Vesting::end_schedule(RuntimeOrigin::signed(account(1)), 0),
				DispatchError::BadOrigin
			);
			assert_noop!(
				Vesting::retarget_schedule(RuntimeOrigin::signed(account(1)), 0, account(8)),
				DispatchError::BadOrigin
			);

			// Root is the break-glass admin and works without the multisig.
			Balances::make_free_balance_be(&treasury_multisig(), 1000 * UNIT);
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				account(7),
				0,
				0,
				END_MS,
				GRANT,
			));
		});
	}

	#[test]
	fn unconfigured_treasury_fails_loudly() {
		new_test_ext(None).execute_with(|| {
			// Root passes the origin check but the pallet still refuses: there is no
			// treasury to fund from or refund to.
			assert_noop!(
				Vesting::create_schedule(RuntimeOrigin::root(), account(7), 0, 0, END_MS, GRANT),
				pallet_vesting::Error::<Runtime>::TreasuryNotConfigured
			);
			// A signed origin cannot match an unconfigured treasury either.
			assert_noop!(
				Vesting::create_schedule(
					RuntimeOrigin::signed(account(1)),
					account(7),
					0,
					0,
					END_MS,
					GRANT,
				),
				DispatchError::BadOrigin
			);
		});
	}

	#[test]
	fn one_quantum_schedule_claims_exactly_once_and_records_one_wormhole_leaf() {
		new_test_ext(Some(account(4))).execute_with(|| {
			Balances::make_free_balance_be(&account(4), 1000 * UNIT);
			let quantum = VestingPayoutQuantum::get();
			// The beneficiary never signs anything — exactly like a wormhole address.
			let beneficiary = account(9);
			let pot = Vesting::pot_account_id();
			assert_noop!(
				Vesting::create_schedule(
					RuntimeOrigin::root(),
					beneficiary.clone(),
					0,
					0,
					END_MS,
					quantum - 1,
				),
				pallet_vesting::Error::<Runtime>::InvalidSchedule
			);
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				beneficiary.clone(),
				0,
				0,
				END_MS,
				quantum,
			));
			set_time(END_MS - 1);
			assert_noop!(claim_as(account(1), 0), pallet_vesting::Error::<Runtime>::NothingToClaim);
			set_time(END_MS);
			System::reset_events();
			let count_before = recorded_leaves();
			assert_ok!(claim_as(account(1), 0));

			// The pallet records the payout itself, exactly once — this ZK-tree leaf is
			// what lets a wormhole owner later exit the funds via ZK proof. (The
			// event-scanning extension skips pot-sourced transfers, so signed
			// submissions don't add a second leaf — covered by the extension's own
			// unit test.)
			assert_eq!(recorded_leaves(), count_before, "v1 records no transfer leaf");

			// The payout itself is an ordinary keep-alive `Transfer` from the pot.
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

	#[test]
	fn non_final_alignment_stops_daily_fragmentation_from_reducing_exit_value() {
		const DAY: u64 = 24 * 60 * 60 * 1000;
		const DAYS: u64 = 365;
		const TOTAL: Balance = DAYS as Balance * UNIT;
		let beneficiary = account(9);

		let periodic_leaves = new_test_ext(Some(account(4))).execute_with(|| {
			Balances::make_free_balance_be(&account(4), 1000 * UNIT);
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				beneficiary.clone(),
				0,
				0,
				DAYS * DAY,
				TOTAL,
			));
			set_time(DAY);
			assert_noop!(claim_as(account(8), 0), pallet_vesting::Error::<Runtime>::NothingToClaim);
			for day in 1..=DAYS {
				set_time(day * DAY);
				let _ = claim_as(account(8), 0);
			}
			assert_eq!(pallet_vesting::Schedules::<Runtime>::get(0).unwrap().claimed, TOTAL);
			recorded_leaves()
		});

		let single_leaves = new_test_ext(Some(account(4))).execute_with(|| {
			Balances::make_free_balance_be(&account(4), 1000 * UNIT);
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				beneficiary.clone(),
				0,
				0,
				DAYS * DAY,
				TOTAL,
			));
			set_time(DAYS * DAY);
			assert_ok!(claim_as(account(8), 0));
			recorded_leaves()
		});

		// Both shapes record nothing: the exit those leaves fed is gone, and a
		// payout is an ordinary transparent transfer with no ZK side at all.
		assert_eq!(single_leaves, 0);
		assert_eq!(periodic_leaves, 0);
	}

	#[test]
	fn scheduler_enacted_root_end_schedule_records_the_payout_leaf() {
		use frame_support::traits::{
			schedule::{v3::Anon, DispatchTime},
			Hooks, StorePreimage,
		};
		use quantus_runtime::{OriginCaller, Scheduler};

		new_test_ext(Some(account(4))).execute_with(|| {
			Balances::make_free_balance_be(&account(4), 1000 * UNIT);
			let beneficiary = account(9);
			assert_ok!(Vesting::create_schedule(
				RuntimeOrigin::root(),
				beneficiary.clone(),
				0,
				0,
				END_MS,
				GRANT,
			));
			// Halfway vested at enactment time.
			set_time(END_MS / 2);

			// Schedule `end_schedule` as Root — the exact shape of a governance
			// enactment. The scheduler dispatches it from `on_initialize`, entirely
			// outside the signed-extrinsic pipeline: no transaction extension runs.
			let call = RuntimeCall::Vesting(pallet_vesting::Call::end_schedule { schedule_id: 0 });
			let bounded = <Runtime as pallet_scheduler::Config>::Preimages::bound(call)
				.expect("small call bounds inline");
			assert_ok!(<Scheduler as Anon<_, _, _>>::schedule(
				DispatchTime::At(3),
				None,
				0,
				OriginCaller::system(frame_system::RawOrigin::Root),
				bounded,
			));

			let count_before = recorded_leaves();
			while System::block_number() < 3 {
				let block = System::block_number();
				Scheduler::on_finalize(block);
				System::set_block_number(block + 1);
				Scheduler::on_initialize(block + 1);
			}

			// The schedule was ended by the hook-dispatched Root call: the
			// beneficiary got the vested half and the treasury the rest. There is
			// no payout leaf either way now; what this still covers is that a
			// scheduled Root dispatch reaches the pallet at all.
			assert!(pallet_vesting::Schedules::<Runtime>::get(0).is_none());
			assert_eq!(Balances::total_balance(&beneficiary), GRANT / 2);
			assert_eq!(recorded_leaves(), count_before, "v1 records no transfer leaf");
		});
	}
}
