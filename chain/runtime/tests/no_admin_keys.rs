//! "No admin keys" as an assertion rather than a claim.
//!
//! The chain ships with no privileged origin. The tech collective, the referenda
//! instance it voted in and the custom origin its fast-upgrade track dispatched
//! are gone; every `frame-system` dispatchable that could write `:code`,
//! `:heappages` or a raw storage key is deleted from the fork; and `Root`
//! survives as a type that nothing in the runtime can produce. `docs/DESIGN.md`
//! section 7.6 carries the decision and its cost.
//!
//! Five tests carry the claim, and each one fails for a different edit:
//! restoring a `frame-system` call, adding a pallet that mints an origin,
//! relaxing one of the `NeverEnsureOrigin` config items, shipping a spec that
//! still seeds a collective, or adding a dispatchable that writes the code key.

use frame_support::traits::{EnsureOrigin, UnfilteredDispatchable};
use qnero_runtime::{
	AccountId, Runtime, RuntimeCall, RuntimeGenesisConfig, RuntimeOrigin, UNIT,
};
use sp_core::crypto::AccountId32;
use sp_runtime::MultiAddress;

// Every `.rs` directly under `tests/` is its own integration target, so the
// shared helper is pulled in by path rather than by `use crate::common`.
#[path = "common.rs"]
#[allow(dead_code)]
mod common;
use common::call_names;

/// The two well-known keys that hold the chain's rules.
const CODE: &[u8] = b":code";
const HEAP_PAGES: &[u8] = b":heappages";

fn account(id: u8) -> AccountId {
	let mut bytes = [0u8; 32];
	bytes[0] = id;
	AccountId32::new(bytes)
}

/// Every leaf call the runtime still dispatches, one instance of each.
///
/// Built by hand, because a `RuntimeCall` cannot be enumerated from its type
/// information: the names are readable, the arguments are not. The count is
/// checked against `call_names` for every pallet below, so a call added
/// anywhere fails `no_dispatchable_can_replace_the_runtime_code` rather than
/// quietly going untested.
fn every_leaf_call() -> Vec<RuntimeCall> {
	use qp_scheduler::BlockNumberOrTimestamp;

	let dest = MultiAddress::Id(account(2));
	vec![
		// System (2)
		RuntimeCall::System(frame_system::Call::remark { remark: Vec::new() }),
		RuntimeCall::System(frame_system::Call::remark_with_event { remark: Vec::new() }),
		// Timestamp (1)
		RuntimeCall::Timestamp(pallet_timestamp::Call::set { now: 1 }),
		// Balances (4)
		RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death {
			dest: dest.clone(),
			value: UNIT,
		}),
		RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive {
			dest: dest.clone(),
			value: UNIT,
		}),
		RuntimeCall::Balances(pallet_balances::Call::transfer_all {
			dest: dest.clone(),
			keep_alive: true,
		}),
		RuntimeCall::Balances(pallet_balances::Call::burn { value: UNIT, keep_alive: true }),
		// Utility (1). The inner call is a `remark`, so what this dispatches is
		// the wrapper itself rather than a second copy of something above.
		RuntimeCall::Utility(pallet_utility::Call::batch_all {
			calls: vec![RuntimeCall::System(frame_system::Call::remark {
				remark: Vec::new(),
			})],
		}),
		// ReversibleTransfers (6)
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::set_high_security {
			delay: BlockNumberOrTimestamp::BlockNumber(10),
			guardian: account(3),
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::cancel {
			tx_id: sp_core::H256::zero(),
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::execute_transfer {
			tx_id: sp_core::H256::zero(),
		}),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::schedule_transfer {
			dest: dest.clone(),
			amount: UNIT,
		}),
		RuntimeCall::ReversibleTransfers(
			pallet_reversible_transfers::Call::schedule_transfer_with_delay {
				dest: dest.clone(),
				amount: UNIT,
				delay: BlockNumberOrTimestamp::BlockNumber(10),
			},
		),
		RuntimeCall::ReversibleTransfers(pallet_reversible_transfers::Call::recover_funds {
			account: account(2),
		}),
		// Multisig (7)
		RuntimeCall::Multisig(pallet_multisig::Call::create_multisig {
			signers: vec![account(1), account(2)],
			threshold: 2,
			nonce: 0,
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::propose {
			multisig_address: account(9),
			call: Default::default(),
			expiry: 100,
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::approve {
			multisig_address: account(9),
			proposal_id: 0,
			call: Default::default(),
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::cancel {
			multisig_address: account(9),
			proposal_id: 0,
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::remove_expired {
			multisig_address: account(9),
			proposal_id: 0,
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::claim_deposits {
			multisig_address: account(9),
		}),
		RuntimeCall::Multisig(pallet_multisig::Call::execute {
			multisig_address: account(9),
			proposal_id: 0,
			call: Box::new(RuntimeCall::System(frame_system::Call::remark {
				remark: Vec::new(),
			})),
		}),
		// Vesting (4)
		RuntimeCall::Vesting(pallet_vesting::Call::claim { schedule_id: 0 }),
		RuntimeCall::Vesting(pallet_vesting::Call::create_schedule {
			beneficiary: account(4),
			start: 0,
			cliff: 0,
			end: 1_000_000,
			total: 100 * UNIT,
		}),
		RuntimeCall::Vesting(pallet_vesting::Call::end_schedule { schedule_id: 0 }),
		RuntimeCall::Vesting(pallet_vesting::Call::retarget_schedule {
			schedule_id: 0,
			new_beneficiary: account(5),
		}),
		// Shielded (4)
		RuntimeCall::Shielded(pallet_shielded::Call::submit_private_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::submit_public_batch {
			proof: Vec::new(),
			outputs: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::shield {
			value: UNIT,
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
		RuntimeCall::Shielded(pallet_shielded::Call::coinbase {
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}),
	]
}

fn new_test_ext() -> sp_io::TestExternalities {
	use frame_support::traits::Currency;
	use sp_runtime::BuildStorage;

	let t = frame_system::GenesisConfig::<Runtime>::default().build_storage().unwrap();
	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| {
		qnero_runtime::System::set_block_number(1);
		for id in 1..=5u8 {
			qnero_runtime::Balances::make_free_balance_be(&account(id), 1_000 * UNIT);
		}
	});
	ext
}

/// No dispatchable can replace the runtime code.
///
/// Every leaf call above is dispatched with
/// `UnfilteredDispatchable::dispatch_bypass_filter` under `RawOrigin::Root`,
/// the strongest origin the type system can express and one this chain cannot
/// actually produce, so the test is stronger than the chain. The two well-known
/// keys are seeded with sentinel bytes first and compared byte for byte
/// afterwards. Dispatch results are ignored: the assertion is about the two
/// keys alone.
#[test]
fn no_dispatchable_can_replace_the_runtime_code() {
	// The pallets with calls, and how many each has. Read off the call enums
	// themselves, so a call added to any of them fails the count below before
	// it can go untested.
	let declared: usize = [
		call_names::<frame_system::Call<Runtime>>().len(),
		call_names::<pallet_timestamp::Call<Runtime>>().len(),
		call_names::<pallet_balances::Call<Runtime>>().len(),
		call_names::<pallet_utility::Call<Runtime>>().len(),
		call_names::<pallet_reversible_transfers::Call<Runtime>>().len(),
		call_names::<pallet_multisig::Call<Runtime>>().len(),
		call_names::<pallet_vesting::Call<Runtime>>().len(),
		call_names::<pallet_shielded::Call<Runtime>>().len(),
	]
	.iter()
	.sum();

	let calls = every_leaf_call();
	assert_eq!(
		calls.len(),
		declared,
		"a pallet gained or lost a call; add it to `every_leaf_call` so the code key \
		 is still checked against every dispatch this chain can execute"
	);
	assert_eq!(
		call_names::<RuntimeCall>().len(),
		8,
		"the runtime gained or lost a pallet with calls; `every_leaf_call` enumerates \
		 eight of them"
	);

	// Sentinel bytes rather than the real wasm: what is asserted is that the
	// bytes under these keys do not move, and a value nothing else writes makes
	// a write visible however small it is.
	let code = b"qnero: the rules of this chain".to_vec();
	let heap_pages = 64u64.to_le_bytes().to_vec();

	new_test_ext().execute_with(|| {
		sp_io::storage::set(CODE, &code);
		sp_io::storage::set(HEAP_PAGES, &heap_pages);

		for call in every_leaf_call() {
			// The result is deliberately discarded. Most of these fail, for
			// reasons that belong to their own pallets; what matters is what
			// they leave behind.
			let _ = call.clone().dispatch_bypass_filter(RuntimeOrigin::root());

			assert_eq!(
				sp_io::storage::get(CODE).map(|bytes| bytes.to_vec()),
				Some(code.clone()),
				"{call:?} moved `:code` under a Root dispatch"
			);
			assert_eq!(
				sp_io::storage::get(HEAP_PAGES).map(|bytes| bytes.to_vec()),
				Some(heap_pages.clone()),
				"{call:?} moved `:heappages` under a Root dispatch"
			);
		}
	});
}

/// `frame-system` dispatches remarks and nothing else.
///
/// Read off the call enum's own type information, which is what the runtime
/// metadata is built from, so a subtree merge that restores `set_code`,
/// `set_storage` or `authorize_upgrade` fails here rather than shipping a chain
/// whose rules a dispatch can rewrite.
#[test]
fn frame_system_dispatchables_are_remark_only() {
	assert_eq!(
		call_names::<frame_system::Call<Runtime>>(),
		["remark", "remark_with_event"],
		"frame-system grew a dispatchable. The nine that could write `:code`, \
		 `:heappages` or a raw storage key were deleted from the fork on purpose: \
		 set_heap_pages, set_code, set_code_without_checks, set_storage, \
		 kill_storage, kill_prefix, authorize_upgrade, \
		 authorize_upgrade_without_checks and apply_authorized_upgrade. See the \
		 removal note at the top of pallets/frame-system/src/lib.rs"
	);
}

/// No pallet can mint a privileged origin.
///
/// `OriginCaller` is the whole set of origins this runtime can construct, and
/// after the removal it is `frame-system`'s own and nothing else. There is no
/// second variant for a track, a collective or a body to dispatch from, so the
/// only origins that exist are `Root`, `Signed(who)` and `None`, and `Root` has
/// no producer.
#[test]
fn the_runtime_declares_no_custom_origin() {
	assert_eq!(
		call_names::<qnero_runtime::OriginCaller>(),
		["system"],
		"a pallet declared a custom origin. `Origins` (index 23) held one, \
		 `FastUpgrade`, and it was removed with the governance lane"
	);
}

/// Defence in depth: even a Root that could be produced reaches nothing.
///
/// The three config items that used to take Root are `NeverEnsureOrigin`, so a
/// change that reopened a Root dispatch would still not schedule a task, pin a
/// preimage or create a vesting schedule.
#[test]
fn the_root_gated_config_origins_never_succeed() {
	new_test_ext().execute_with(|| {
		assert!(
			<<Runtime as pallet_scheduler::Config>::ScheduleOrigin as EnsureOrigin<
				RuntimeOrigin,
			>>::try_origin(RuntimeOrigin::root())
			.is_err(),
			"Root can schedule a task"
		);
		assert!(
			<<Runtime as pallet_preimage::Config>::ManagerOrigin as EnsureOrigin<
				RuntimeOrigin,
			>>::try_origin(RuntimeOrigin::root())
			.is_err(),
			"Root can manage preimages"
		);
		assert!(
			<<Runtime as pallet_vesting::Config>::AdminOrigin as EnsureOrigin<
				RuntimeOrigin,
			>>::try_origin(RuntimeOrigin::root())
			.is_err(),
			"Root can administer a vesting schedule"
		);
	});
}

/// A chain spec that still seeds a collective is refused rather than ignored.
///
/// `GenesisBuilder::build_state` went back to the plain helper when the seed
/// channel was deleted, and `RuntimeGenesisConfig` carries
/// `#[serde(deny_unknown_fields)]`. So an operator who launches an old spec
/// against this binary gets a failed build rather than a chain that silently
/// dropped the field it thought it was configuring.
#[test]
fn a_stale_collective_seed_is_refused_at_genesis() {
	use frame_support::genesis_builder_helper::build_state;
	use sp_genesis_builder::PresetId;

	let raw = qnero_runtime::genesis_config_presets::get_preset(&PresetId::from("qnero-testnet"))
		.expect("the testnet preset resolves");
	let mut value: serde_json::Value =
		serde_json::from_slice(&raw).expect("a preset is a JSON object");

	sp_io::TestExternalities::default().execute_with(|| {
		build_state::<RuntimeGenesisConfig>(serde_json::to_vec(&value).expect("serializes"))
			.expect("the shipped preset builds");
	});

	value
		.as_object_mut()
		.expect("a preset is a JSON object")
		.insert("tech_collective_seed_members".into(), serde_json::Value::Array(Vec::new()));

	sp_io::TestExternalities::default().execute_with(|| {
		assert!(
			build_state::<RuntimeGenesisConfig>(
				serde_json::to_vec(&value).expect("serializes")
			)
			.is_err(),
			"a genesis still carrying tech_collective_seed_members was accepted"
		);
	});
}
