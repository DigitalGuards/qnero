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
//! What is asserted here is exactly that, including the enrolment call, which
//! moves nothing and is refused anyway: it is one way, and an account that
//! took it would be held to a whitelist whose every value-moving call this
//! filter refuses. The pallet's own logic is covered by its 48 unit tests in
//! `pallets/reversible-transfers/src/tests`, whose mock runs an unfiltered
//! runtime, so nothing was lost with the flows above: what changed is which
//! origins can reach them on this chain.

use crate::common::TestCommons;
use frame_support::traits::Currency;
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

/// Declaring an account high security moves no value and is refused anyway.
///
/// The call has no inverse: the pallet has nothing that clears the flag and
/// refuses a second enrolment with `AccountAlreadyHighSecurity`. An account
/// that got in would be held to `HighSecurityConfig`'s whitelist at
/// validation, and this filter refuses every value-moving call on that
/// whitelist at dispatch, so the enrolment is a door into a room with no
/// exits. It is closed until a milestone gives the feature something to guard.
#[test]
fn enrolling_in_high_security_is_refused() {
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
		assert_eq!(refusal(declare, acc(1)), call_filtered());
		assert!(ReversibleTransfers::is_high_security(&acc(1)).is_none());
	});
}

/// A stolen high-security key cannot reach an immediate, irreversible drain.
///
/// The whitelist runs at validation, before the filter, so an enrolled account
/// can sign only what is on it, and everything on it is delayed: the owner's
/// `cancel` and the guardian's `recover_funds` both beat the delay. Adding
/// `Shielded::shield` or `Balances::burn` to unfreeze an account enrolled
/// before v1 would put an undelayed, unrecoverable call on that list, which is
/// the drain the feature exists to stop. A `shield` commits to a `pk` the
/// thief chose and settles next block; `recover_funds` walks
/// `PendingTransfersBySender` and releases holds, so there would be nothing
/// left for the guardian to find. The enrolment itself is refused under v1
/// (`enrolling_in_high_security_is_refused`), so no chain reaches
/// the freeze this would have been paying for.
#[test]
fn the_whitelist_refuses_the_undelayed_drain() {
	use qp_high_security::HighSecurityInspector;

	for call in [
		RuntimeCall::Shielded(pallet_shielded::Call::shield {
			value: EXISTENTIAL_DEPOSIT,
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
		RuntimeCall::Balances(pallet_balances::Call::burn {
			value: EXISTENTIAL_DEPOSIT,
			keep_alive: true,
		}),
	] {
		assert!(
			!quantus_runtime::configs::HighSecurityConfig::is_whitelisted(&call),
			"{call:?} is immediate and outside recover_funds, so it must not be whitelisted"
		);
	}
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
