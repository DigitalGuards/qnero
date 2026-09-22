//! The v1 call filter, at the runtime level.
//!
//! `docs/DESIGN.md` section 7 is the allowlist. What is asserted here is the
//! property the whole milestone rests on: after M6 no signed call moves
//! transparent value from one account to another, the pool's own entry still
//! works, and a wrapper is not a way around the first of those.
//!
//! Dispatched directly against `RuntimeOrigin::signed`, which is the filter's
//! second line: `RuntimeCall::dispatch` asks the origin, and the origin's
//! filter is `frame_system::Config::BaseCallFilter`. A submitted extrinsic is
//! refused a layer earlier, in `Checkable::check`
//! (`runtime/tests/transaction_policy.rs`), so what only this line reaches is a
//! call no extrinsic carried: a due scheduler task
//! (`runtime/tests/transactions/reversible_integration.rs`) and a `batch_all`
//! child re-dispatched under the caller's origin. Both layers consult the same
//! `Contains`, which is what these tests pin.

use codec::Encode;
use frame_support::{
	dispatch::GetDispatchInfo,
	traits::{Contains, Currency},
};
use qnero_runtime::{
	configs::QneroCallFilter, AccountId, Balances, Runtime, RuntimeCall, RuntimeOrigin, System,
	UNIT,
};
use sp_core::crypto::AccountId32;
use sp_runtime::{traits::Dispatchable, BuildStorage, DispatchError, MultiAddress};

// Every `.rs` directly under `tests/` is its own integration target, so the
// shared helper is pulled in by path rather than by `use crate::common`.
#[path = "common.rs"]
#[allow(dead_code)]
mod common;
use common::call_names;

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

fn remark() -> RuntimeCall {
	RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() })
}

fn propose(payload: Vec<u8>) -> RuntimeCall {
	propose_to(account(3), payload)
}

fn propose_to(multisig_address: AccountId, payload: Vec<u8>) -> RuntimeCall {
	RuntimeCall::Multisig(pallet_multisig::Call::propose {
		multisig_address,
		call: payload.try_into().expect("the payload fits MaxCallSize"),
		expiry: 100,
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

/// `Multisig::propose` is the wrapper whose payload is not a typed call, and
/// the filter unwraps it anyway.
///
/// The payload is opaque `BoundedVec<u8, MaxCallSize>` bytes. Left alone, a
/// proposal carrying a transfer is an ordinary valid extrinsic: it enters a
/// block with the sender, the recipient and the amount in its body, pays a fee
/// and a deposit, and only the later `execute` is refused. The arm decodes it
/// and holds it to the same rule.
#[test]
fn a_multisig_proposal_carrying_a_transfer_is_not_contained() {
	new_test_ext().execute_with(|| {
		assert!(!QneroCallFilter::contains(&propose(transfer(10 * UNIT).encode())));

		let batched = RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![transfer(10 * UNIT)],
		});
		assert!(!QneroCallFilter::contains(&propose(batched.encode())));

		// One level is unwrapped, so a payload carrying a proposal of its own
		// is refused without a second decode.
		let nested = propose(transfer(10 * UNIT).encode());
		assert!(!QneroCallFilter::contains(&propose(nested.encode())));
		let nested_in_a_batch =
			RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![nested] });
		assert!(!QneroCallFilter::contains(&propose(nested_in_a_batch.encode())));

		// A payload that can never execute is refused for that reason alone.
		assert!(!QneroCallFilter::contains(&propose(vec![0xff, 0xff, 0xff])));
		let mut trailing = remark().encode();
		trailing.push(0x00);
		assert!(!QneroCallFilter::contains(&propose(trailing)));

		// And a proposal of a call v1 allows is still a proposal v1 allows.
		assert!(QneroCallFilter::contains(&propose(remark().encode())));
	});
}

/// The filter's verdict and the pallet's own phase-3 verdict on the same
/// payload.
///
/// The two malformed shapes are the pallet's checks, mirrored: a decode at
/// `MAX_MULTISIG_CALL_DEPTH` and a canonical re-encode. If the two layers ever
/// disagreed there, the failure would be a proposal whose bytes were published
/// for a dispatch that could never run. The well-formed transfer is the other
/// half of the agreement, and the leak this arm closes: the pallet accepts it,
/// so the filter is the only thing that stops the payload reaching a block.
#[test]
fn the_filter_and_the_pallet_read_a_proposal_payload_the_same_way() {
	new_test_ext().execute_with(|| {
		let signers = vec![account(1), account(2)];
		let multisig = pallet_multisig::Pallet::<Runtime>::derive_multisig_address(&signers, 2, 0);
		RuntimeCall::Multisig(pallet_multisig::Call::create_multisig {
			signers,
			threshold: 2,
			nonce: 0,
		})
		.dispatch(RuntimeOrigin::signed(account(1)))
		.expect("creating a multisig is allowed under v1");

		let mut trailing = remark().encode();
		trailing.push(0x00);
		for payload in [vec![0xff, 0xff, 0xff], trailing] {
			assert!(
				!QneroCallFilter::contains(&propose_to(multisig.clone(), payload.clone())),
				"the filter refuses a payload that can never execute"
			);
			assert_eq!(
				pallet_multisig::Pallet::<Runtime>::propose(
					RuntimeOrigin::signed(account(1)),
					multisig.clone(),
					payload.try_into().expect("the payload fits MaxCallSize"),
					100,
				)
				.unwrap_err()
				.error,
				DispatchError::from(pallet_multisig::Error::<Runtime>::InvalidCall),
				"and the pallet refuses it for the same two reasons"
			);
		}

		// The pallet has no opinion about a well-formed transfer, which is why
		// the filter has to.
		let payload = transfer(10 * UNIT).encode();
		assert!(!QneroCallFilter::contains(&propose_to(multisig.clone(), payload.clone())));
		assert!(
			pallet_multisig::Pallet::<Runtime>::propose(
				RuntimeOrigin::signed(account(1)),
				multisig,
				payload.try_into().expect("the payload fits MaxCallSize"),
				100,
			)
			.is_ok(),
			"the pallet stores a transfer proposal, so only the filter keeps its \
			 arguments out of a block"
		);
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
/// `ReversibleTransactionExtension`, before it can reach a block at all, so the
/// account can sign nothing. Refusing the enrolment is what keeps any account
/// from reaching that state, and it is the reason the whitelist stays as it is:
/// widening it with an immediate call would unfreeze the account by voiding the
/// guarantee the feature exists for
/// (`the_high_security_whitelist_admits_only_reversible_calls`).
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

/// The high-security whitelist admits delayed, reversible calls and nothing
/// else.
///
/// This is the guarantee the feature sells: a stolen key can only schedule a
/// transfer, and the owner's `cancel` or the guardian's `recover_funds` beats
/// it to the delay. `Shielded::shield` and `Balances::burn` are the two calls
/// that would break it, because both are immediate, both are irreversible and
/// neither is reachable by `recover_funds`, which walks
/// `PendingTransfersBySender` and releases holds. A `shield` whose `inner`
/// commits to a `pk` only the thief holds settles in the next block and the
/// value is a note in the pool with nothing to cancel; a `burn` is the same
/// shape with total loss. Admitting them to unfreeze an account enrolled
/// before v1 would trade the guarantee against a freeze no v1-genesis chain
/// can reach, since the enrolment itself is refused
/// (`enrolling_in_high_security_is_refused`).
#[test]
fn the_high_security_whitelist_admits_only_reversible_calls() {
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
			!qnero_runtime::configs::HighSecurityConfig::is_whitelisted(&call),
			"{call:?} is immediate and irreversible, so a stolen high-security key must not \
			 be able to sign it"
		);
		// And not smuggled in through the one wrapper the whitelist admits.
		let wrapped =
			RuntimeCall::Utility(pallet_utility::Call::batch_all { calls: vec![call.clone()] });
		assert!(
			!qnero_runtime::configs::HighSecurityConfig::is_whitelisted(&wrapped),
			"a batch_all carrying {call:?} must be refused the same way"
		);
		// The base filter is a different question and still allows both: this
		// is a high-security restriction, and an ordinary account keeps its
		// door into the pool.
		assert!(
			QneroCallFilter::contains(&call),
			"{call:?} must still pass the base call filter for an ordinary account"
		);
	}

	// What stays on the list is the delayed path and the two ways out of it.
	for call in [
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::schedule_transfer {
			dest: MultiAddress::Id(account(2)),
			amount: UNIT,
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
			tx_id: sp_core::H256::zero(),
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::recover_funds {
			account: account(2),
		}),
	] {
		assert!(
			qnero_runtime::configs::HighSecurityConfig::is_whitelisted(&call),
			"{call:?} is the delayed path the guarantee is built on and must stay whitelisted"
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

	// The two pallets the filter enumerates beside `Balances`. Both move value
	// through `T::Currency` directly rather than by dispatching a `Balances`
	// call, so the enumeration here is the only thing standing between a new
	// payout call and a transparent transfer on a v1 chain. `pallet-treasury`
	// was a third until its calls were disabled: `set_treasury_account` has no
	// `RuntimeCall` variant any more, which `no_admin_keys.rs` pins.
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
		"pallet-multisig grew a call; `execute` dispatches an inner call and \
		 `propose` publishes one as opaque bytes, and `refused_under_v1` unwraps \
		 both, so a new call carrying an inner call has to join them"
	);

	// The runtime's own pallet list. A pallet added to `construct_runtime` with
	// a transfer dispatchable is caught by nothing above, so the list itself is
	// the tripwire. Pallets with no dispatchables of their own are absent:
	// `QPoW`, `MiningRewards`, `ZkTree` and `TransactionPayment` have no calls,
	// and `Scheduler`, `Preimage` and `TreasuryPallet` are all
	// `#[runtime::disable_call]`.
	assert_eq!(
		call_names::<RuntimeCall>(),
		[
			"System",
			"Timestamp",
			"Balances",
			"Utility",
			"ReversibleTransfers",
			"Multisig",
			"Vesting",
			"Shielded",
		],
		"the runtime gained or lost a pallet with calls; decide whether any of them \
		 moves transparent value and update the filter and docs/DESIGN.md section 7"
	);
}

/// The runtime's identity, pinned so a metadata change cannot ship under an
/// unchanged `spec_version`.
///
/// Every client that caches metadata keys the cache on `spec_version`:
/// polkadot-js, subxt, every indexer. A pass that changes an event layout, adds
/// an error variant or moves a storage item, and leaves the version alone,
/// hands those clients a stale shape that still decodes. A `bool` where a
/// `Vec<u8>` was decodes as a compact length and renders as empty; an event
/// that lost a leading `AccountId` decodes the next field's bytes as an
/// account and over-runs. Both succeed, and nothing reports either.
///
/// So this test fails on purpose whenever the pair moves. Read the rule at the
/// top of `runtime/src/lib.rs` before updating it: `spec_version` moves for any
/// metadata change, and `transaction_version` moves only when the signed
/// extrinsic encoding does.
#[test]
fn the_runtime_identity_is_pinned() {
	let version = qnero_runtime::VERSION;
	assert_eq!(version.spec_name, "qnero", "the chain's own name, set at M6");
	assert_eq!(version.impl_name, "qnero-node");
	assert_eq!(
		pallet_qpow::Pallet::<Runtime>::get_max_reorg_depth(),
		u32::MAX,
		"legacy depth consumers must preserve reversible PoW throughout the u32 height range"
	);
	assert_eq!(
		(version.spec_version, version.transaction_version),
		(106, 7),
		"runtime metadata or the signed extrinsic encoding moved; see the rule above \
		 `VERSION` in runtime/src/lib.rs and bump the half that changed"
	);
}
