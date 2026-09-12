//! Reversible transfers through the real runtime, under v1 mandatory privacy.
//!
//! This file used to walk the whole guardian flow end to end: a high-security
//! account schedules a transfer, the guardian cancels it and seizes the hold,
//! a chained guardian recovers a drained account. None of that is reachable on
//! a v1 chain. Every one of those calls moves transparent value between
//! accounts, so `BaseCallFilter` refuses them, and the refusal does not stop at
//! the entry point: the pallet executes and sweeps by dispatching
//! `Balances::transfer_*` with the account's own signed origin, which meets the
//! same filter. `docs/DESIGN.md` section 7.2 is the policy.
//!
//! What is asserted here is exactly that, plus the one call that survives
//! because it moves nothing. The pallet's own logic is covered by its 48 unit
//! tests in `pallets/reversible-transfers/src/tests`, whose mock runs an
//! unfiltered runtime, so nothing was lost with the flows above: what changed
//! is which origins can reach them on this chain.

use crate::common::TestCommons;
use frame_support::{assert_ok, traits::Currency};
use quantus_runtime::{
	Balances, ReversibleTransfers, Runtime, RuntimeCall, RuntimeOrigin, System, EXISTENTIAL_DEPOSIT,
};
use sp_runtime::{traits::Dispatchable, DispatchError, MultiAddress};

fn acc(n: u8) -> sp_core::crypto::AccountId32 {
	TestCommons::account_id(n)
}

fn call_filtered() -> DispatchError {
	frame_system::Error::<Runtime>::CallFiltered.into()
}

fn refusal(call: RuntimeCall, who: sp_core::crypto::AccountId32) -> DispatchError {
	call.dispatch(RuntimeOrigin::signed(who))
		.expect_err("the call moves transparent value")
		.error
}

/// Declaring an account high security moves no value, so it is still a call a
/// user can make. It is also the whole of what the pallet can still do.
#[test]
fn high_security_can_still_be_declared() {
	TestCommons::new_test_ext().execute_with(|| {
		System::set_block_number(1);
		let _ = Balances::deposit_creating(&acc(1), 1_000 * EXISTENTIAL_DEPOSIT);
		let _ = Balances::deposit_creating(&acc(2), 1_000 * EXISTENTIAL_DEPOSIT);

		let declare = RuntimeCall::ReversibleTransfers(
			pallet_reversible_transfers::Call::set_high_security {
				delay: qp_scheduler::BlockNumberOrTimestamp::BlockNumber(10),
				guardian: acc(2),
			},
		);
		assert_ok!(declare.dispatch(RuntimeOrigin::signed(acc(1))));
		assert_eq!(
			ReversibleTransfers::is_high_security(&acc(1)).map(|data| data.guardian),
			Some(acc(2))
		);
	});
}

/// Every path that moves value, refused at the door.
#[test]
fn every_value_moving_reversible_call_is_refused() {
	TestCommons::new_test_ext().execute_with(|| {
		System::set_block_number(1);
		let _ = Balances::deposit_creating(&acc(1), 1_000 * EXISTENTIAL_DEPOSIT);
		let before = Balances::free_balance(acc(3));

		let calls = [
			RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer {
					dest: MultiAddress::Id(acc(3)),
					amount: 10 * EXISTENTIAL_DEPOSIT,
				},
			),
			RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer_with_delay {
					dest: MultiAddress::Id(acc(3)),
					amount: 10 * EXISTENTIAL_DEPOSIT,
					delay: qp_scheduler::BlockNumberOrTimestamp::BlockNumber(10),
				},
			),
			RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::execute_transfer {
				tx_id: sp_core::H256::zero(),
			}),
			RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
				tx_id: sp_core::H256::zero(),
			}),
			RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::recover_funds {
				account: acc(1),
			}),
		];
		for call in calls {
			assert_eq!(refusal(call, acc(1)), call_filtered());
		}
		assert_eq!(Balances::free_balance(acc(3)), before, "nothing moved");
	});
}

/// The refusal reaches the pallet's own dispatches too, which is what makes a
/// guardian recovery inert rather than half-completed.
///
/// `recover_funds` seizes pending holds and then sweeps the account with a
/// dispatched `transfer_all` under the account's own signed origin. That inner
/// dispatch meets the filter like any other, so even an origin that got past
/// the outer call would move nothing.
#[test]
fn the_inner_sweep_of_a_recovery_is_refused_as_well() {
	TestCommons::new_test_ext().execute_with(|| {
		System::set_block_number(1);
		let _ = Balances::deposit_creating(&acc(1), 1_000 * EXISTENTIAL_DEPOSIT);
		let sweep = RuntimeCall::Balances(pallet_balances::Call::transfer_all {
			dest: MultiAddress::Id(acc(2)),
			keep_alive: false,
		});
		assert_eq!(refusal(sweep, acc(1)), call_filtered());
		assert!(Balances::free_balance(acc(1)) > 0, "the account was not drained");
	});
}
