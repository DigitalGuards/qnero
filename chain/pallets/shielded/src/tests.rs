//! Tests for `pallet-shielded`.
//!
//! Two layers. The settlement algebra is exercised against synthetic public
//! inputs, because the rules that matter most are the ones no circuit enforces
//! and several of them cannot be reached through a valid proof at all: the
//! private-batch circuit constrains all `2N` of a batch's nullifiers pairwise
//! distinct, so an in-batch duplicate is unprovable and only a hand-built
//! bundle can test that the chain refuses one. Above that, a smaller number of
//! tests build a real private batch with `qnero-prover` and put it through the
//! whole extrinsic.
//!
//! The proving tests are slow by nature: building the private-batch circuit is
//! seconds and proving one is tens of seconds single threaded. Rayon is
//! deliberately off in this crate's dev-dependencies so a test run cannot
//! saturate the machine it is on, and the prover is built once for the whole
//! binary.

use std::{
	collections::BTreeMap,
	sync::{Mutex, OnceLock},
};

#[test]
fn protocol_profile_is_committed_at_genesis_and_refreshed_on_upgrade() {
	use frame_support::traits::{BuildGenesisConfig, Hooks};
	new_test_ext().execute_with(|| {
		crate::GenesisConfig::<Test>::default().build();
		assert_eq!(
			crate::ActiveProtocolProfile::<Test>::get(),
			Some(crate::circuit_config::PROTOCOL_PROFILE)
		);
		crate::ActiveProtocolProfile::<Test>::put([0u8; qnero_circuit::profile::PROFILE_LEN]);
		<Shielded as Hooks<u64>>::on_runtime_upgrade();
		assert_eq!(
			crate::ActiveProtocolProfile::<Test>::get(),
			Some(crate::circuit_config::PROTOCOL_PROFILE)
		);
	});
}

#[test]
fn protocol_profile_metadata_contract_matches_authenticated_storage() {
	use frame_support::traits::BuildGenesisConfig;
	new_test_ext().execute_with(|| {
		crate::GenesisConfig::<Test>::default().build();
		// Inspect the generated metadata used by the runtime API. Calling the
		// Rust getter directly would miss an incompatible exported name.
		let constants = Shielded::pallet_constants_metadata();
		let profiles: Vec<_> =
			constants.iter().filter(|constant| constant.name == "ProtocolProfile").collect();
		assert_eq!(profiles.len(), 1, "wallets require exactly one ProtocolProfile constant");
		assert!(constants.iter().all(|constant| constant.name != "protocol_profile"));
		let exported = &profiles[0].value;
		assert_eq!(exported.len(), qnero_circuit::profile::PROFILE_LEN);
		assert_eq!(exported.as_slice(), crate::circuit_config::PROTOCOL_PROFILE.as_slice());
		let stored = crate::ActiveProtocolProfile::<Test>::get().expect("genesis profile");
		assert_eq!(exported.as_slice(), stored.as_slice());
		let raw = sp_io::storage::get(&crate::ActiveProtocolProfile::<Test>::hashed_key())
			.expect("authenticated profile storage bytes");
		assert_eq!(exported.as_slice(), &raw[..], "metadata and trie bytes must match exactly");
	});
}

/// A budget of two output notes per block, so a single settlement or a pair of
/// shields fills a block. The production value is restored even if a test
/// assertion fails.
fn with_output_budget(test: impl FnOnce()) {
	struct Restore(u32);
	impl Drop for Restore {
		fn drop(&mut self) {
			MaxOutputsPerBlock::set(self.0);
		}
	}
	let _restore = Restore(MaxOutputsPerBlock::get());
	MaxOutputsPerBlock::set(2);
	test();
}

/// One shield, which is one output note against the block's budget.
fn budget_test_shield() -> sp_runtime::DispatchResult {
	Shielded::shield(RuntimeOrigin::signed(alice()), POOL_STEP, [0; 32], b"note".to_vec())
}

#[test]
fn the_output_cap_refuses_a_shield_before_burning_and_resets_for_next_block() {
	with_output_budget(|| {
		new_test_ext_with_endowments(vec![(alice(), 100 * UNIT)]).execute_with(|| {
			assert_ok!(budget_test_shield());
			assert_ok!(budget_test_shield());
			assert_noop!(budget_test_shield(), Error::<Test>::TooManyOutputsInBlock);
			assert_eq!(ZkTree::leaf_count(), 2);
			// Transaction-pool validation initializes the next block's system
			// context without executing pallet hooks. The stamped counter must
			// admit that context as well.
			System::set_block_number(2);
			assert_ok!(budget_test_shield());
			assert_eq!(crate::OutputsWrittenThisBlock::<Test>::get(), (2, 1));
		});
	});
}

#[test]
fn the_output_cap_applies_to_complete_settlements_before_nullifiers_change() {
	with_output_budget(|| {
		new_test_ext().execute_with(|| {
			fund_pool(100);
			let ct_1 = suite_ciphertext(0xc1);
			let ct_2 = suite_ciphertext(0xc2);
			let first = one_segment(10, vec![slot("budget-first", &ct_1, &ct_2, 9)]);
			assert_ok!(Shielded::settle(first, vec![output(&ct_1, &ct_2)]));
			let second = one_segment(10, vec![slot("budget-second", &ct_1, &ct_2, 9)]);
			assert_noop!(
				Shielded::settle(second, vec![output(&ct_1, &ct_2)]),
				Error::<Test>::TooManyOutputsInBlock
			);
			assert_eq!(crate::OutputsWrittenThisBlock::<Test>::get().1, 2);
			assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 2);
		});
	});
}

/// Nothing lives under the key a pre-bundle wallet would read.
///
/// The map is gone from the pallet, so its prefix is spelled out here rather
/// than taken from a storage type. What this asserts is the thing a wallet
/// cares about: the chain writes no value at that address, so a wallet that
/// still asked for one would be reading a hole and finding no payment. The
/// profile byte is what refuses such a wallet before it gets that far.
fn no_ciphertext_key_exists() -> bool {
	let mut prefix = sp_io::hashing::twox_128(b"Shielded").to_vec();
	prefix.extend_from_slice(&sp_io::hashing::twox_128(b"Ciphertexts"));
	match sp_io::storage::next_key(&prefix) {
		Some(key) => !key.starts_with(&prefix),
		None => true,
	}
}

/// A settling slot appends two commitment leaves and stamps two `LeafBlocks`
/// entries, and that is every per-leaf key it writes. The payload rides in the
/// extrinsic that carried it, which the header's extrinsics root
/// authenticates, and `SLOT_DB_OPS` is the declared half of the same
/// statement: it lost the two ciphertext writes with the map.
#[test]
fn a_settled_slot_writes_no_ciphertext_to_state() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let ct_1 = suite_ciphertext(0xd1);
		let ct_2 = suite_ciphertext(0xd2);
		let bundle = one_segment(10, vec![slot("no-state", &ct_1, &ct_2, 9)]);
		assert_ok!(Shielded::settle(bundle, vec![output(&ct_1, &ct_2)]));

		assert_eq!(ZkTree::leaf_count(), 2);
		assert_eq!(Shielded::leaf_block(0), Some(System::block_number()));
		assert_eq!(Shielded::leaf_block(1), Some(System::block_number()));
		assert!(no_ciphertext_key_exists(), "a settlement wrote a ciphertext into state");
		assert_eq!(weights::SLOT_DB_OPS, (4, 4));
	});
}

/// The retention window is zero and the hook that drained it is gone, so
/// `on_initialize` reserves the coinbase mint and nothing else, at any height.
///
/// The constant stays in the pallet's metadata at zero on purpose: it is how a
/// wallet reading the metadata is told where the payload lives, and
/// `integrity_test` refuses any other value.
#[test]
fn the_retention_constant_is_zero_and_the_prune_is_gone() {
	use crate::weights::WeightInfo as _;
	use frame_support::traits::Hooks;

	new_test_ext().execute_with(|| {
		assert_eq!(CiphertextRetentionBlocks::get(), 0);
		let reservation = <() as crate::weights::WeightInfo>::mint_coinbase(
			MaxCiphertextBytes::get(),
		)
		.saturating_add(<Test as frame_system::Config>::DbWeight::get().writes(1));
		for height in [1u64, 2, 65, 1_000_000] {
			System::set_block_number(height);
			assert_eq!(<Shielded as Hooks<u64>>::on_initialize(height), reservation);
		}
	});
}

/// The counter regression. `store_ciphertext` was the only writer of the
/// per-block output counter, and it went with the map; `record_outputs` is
/// what replaced it. Without a writer the cap compares every submission
/// against zero, `TooManyOutputsInBlock` never fires, and the deferral gate
/// below it becomes unreachable code that nothing would have caught.
///
/// This checks the plan, which is what the gate calls, rather than the
/// dispatch: a cap that only bound at dispatch would let the block builder
/// spend a full verify on a settlement it cannot include.
#[test]
fn a_second_submission_in_a_full_block_still_returns_too_many_outputs_in_block() {
	with_output_budget(|| {
		new_test_ext().execute_with(|| {
			fund_pool(100);
			let ct_1 = suite_ciphertext(0xe1);
			let ct_2 = suite_ciphertext(0xe2);
			let outputs = vec![output(&ct_1, &ct_2)];

			let first = one_segment(10, vec![slot("budget-first", &ct_1, &ct_2, 9)]);
			assert_ok!(plan(&first, &outputs));
			assert_ok!(Shielded::settle(first, outputs.clone()));
			assert_eq!(crate::OutputsWrittenThisBlock::<Test>::get().1, 2);

			// The block is full. A fresh submission, no nullifier of which this
			// chain has seen, is refused by the budget and by nothing else.
			let second = one_segment(10, vec![slot("budget-second", &ct_1, &ct_2, 9)]);
			assert_noop!(plan(&second, &outputs), Error::<Test>::TooManyOutputsInBlock);
			assert_noop!(check(&second, &outputs), Error::<Test>::TooManyOutputsInBlock);

			// The counter is stamped with its block, so the next block admits
			// the same submission with no hook run in between.
			System::set_block_number(11);
			assert_ok!(plan(&second, &outputs));
		});
	});
}

use frame_support::{assert_noop, assert_ok, traits::fungible::Inspect, BoundedVec};
use qnero_circuit::{
	batch_layout::{
		private_batch_pi_len, public_batch_inner_start, public_batch_pi_len, slot_commitment_index,
		slot_ct_digest_index, slot_fee_index, slot_nullifier_index, AGGREGATOR_ADDRESS_START,
		BLOCK_HASH_START, BLOCK_NUMBER_INDEX,
	},
	chain::ct_digest,
	header::{HeaderInputs, DIGEST_LOGS_SIZE},
	merkle::MerklePath,
	witness::{InputNote, OutputNote, SpendWitness},
};
use qnero_note_core::{derive_pk, entry_rho, note_inner, DerivedKeys, Digest, Note};
use qnero_prover::WalletProver;
use qnero_verifier::{
	parse_private_batch_public_input_felts, parse_public_batch_public_input_felts,
};
use qp_plonky2_verifier::{field::types::Field, F};
use sp_core::H256;
use sp_runtime::{
	traits::ValidateUnsigned,
	transaction_validity::{InvalidTransaction, TransactionSource},
};

use crate::{
	circuit_config, mock::*, padding_block_hash, weights, Error, Event, Hash256, RealSlot, Segment,
	SettlementBundle, ShieldedOutput, POOL_STEP,
};

// ===========================================================================
// Synthetic bundles: the settlement algebra
// ===========================================================================

fn digest_bytes_of(tag: &str) -> Hash256 {
	qp_poseidon_core::hash_bytes(tag.as_bytes())
}

/// Write a 32-byte digest into a public-input vector at `start`, the way the
/// batch wrapper registers one: four canonical limbs, little endian per limb.
fn write_digest(felts: &mut [F], start: usize, digest: &Hash256) {
	for (index, limb) in digest.chunks_exact(8).enumerate() {
		felts[start + index] =
			F::from_canonical_u64(u64::from_le_bytes(limb.try_into().expect("8 bytes")));
	}
}

/// The one length a settlement position may carry per field, as a `u64` for
/// the byte arithmetic these tests do. Two of them, 3584 bytes, is the only
/// payload a carried position can publish, and it is exactly seven 512-byte fee
/// steps.
const SUITE_CIPHERTEXT_BYTES: u64 = qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES as u64;

/// A blob consensus reads as a settlement ciphertext: exactly
/// `SUITE_1_CIPHERTEXT_BYTES`, headed by the address version byte and the
/// little-endian suite id, `[1, 1, 0]`.
///
/// The chain reads those three header bytes and the length and parses nothing
/// else, so this is a ciphertext as far as settlement is concerned. The filler
/// behind the header is what makes two seeds hash to different `ct_digest`s,
/// and it is deliberately not a real `NoteCiphertext`: the rule fixes how many
/// bytes a settlement publishes, and nothing here authenticates a note.
fn suite_ciphertext(seed: u8) -> Vec<u8> {
	let mut bytes = vec![0u8; qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES];
	bytes[0] = 1;
	bytes[1..3].copy_from_slice(&qnero_circuit::chain::CRYPTO_SUITE_ML_KEM_1024.to_le_bytes());
	for (index, byte) in bytes[3..].iter_mut().enumerate() {
		*byte = seed ^ (index as u8);
	}
	bytes
}

/// A blob padded to `MaxCiphertextBytes` behind a valid suite-1 header.
///
/// The header matters: filler bytes at offsets 1..3 declare whatever suite id
/// they happen to spell, and a padded pair refused for an unknown suite would
/// not be testing the length rule. This is the shape the payload fee term was
/// sized against, and it is the shape the rule now refuses.
fn capped_ciphertext(seed: u8) -> Vec<u8> {
	let cap = <Test as crate::Config>::MaxCiphertextBytes::get() as usize;
	let mut bytes = vec![seed; cap];
	bytes[0] = 1;
	bytes[1..3].copy_from_slice(&qnero_circuit::chain::CRYPTO_SUITE_ML_KEM_1024.to_le_bytes());
	bytes
}

fn output(a: &[u8], b: &[u8]) -> ShieldedOutput<Test> {
	ShieldedOutput {
		ct_1: BoundedVec::try_from(a.to_vec()).expect("under MaxCiphertextBytes"),
		ct_2: BoundedVec::try_from(b.to_vec()).expect("under MaxCiphertextBytes"),
	}
}

/// `check_settlement` with its error widened to `DispatchError`, which is what
/// `assert_noop!` compares against.
fn check(
	bundle: &SettlementBundle,
	outputs: &[ShieldedOutput<Test>],
) -> Result<crate::PlannedSettlement, sp_runtime::DispatchError> {
	Shielded::check_settlement(bundle, outputs).map_err(Into::into)
}

/// The cheap half of `check_settlement`: everything but the payload binding.
fn plan(
	bundle: &SettlementBundle,
	outputs: &[ShieldedOutput<Test>],
) -> Result<crate::PlannedSettlement, sp_runtime::DispatchError> {
	Shielded::plan_settlement(bundle, outputs).map_err(Into::into)
}

/// The payload half: the one term linear in the submitted bytes.
fn bind(
	bundle: &SettlementBundle,
	outputs: &[ShieldedOutput<Test>],
) -> Result<(), sp_runtime::DispatchError> {
	Shielded::bind_payload(bundle, outputs).map_err(Into::into)
}

/// A real slot whose `ct_digest` matches `output(a, b)`.
fn slot(tag: &str, a: &[u8], b: &[u8], fee: u64) -> RealSlot {
	RealSlot {
		nullifiers: [
			digest_bytes_of(&format!("{tag}-nf1")),
			digest_bytes_of(&format!("{tag}-nf2")),
		],
		commitments: [
			digest_bytes_of(&format!("{tag}-cm1")),
			digest_bytes_of(&format!("{tag}-cm2")),
		],
		fee,
		ct_digest: ct_digest(&[a, b]),
	}
}

/// Anchor a synthetic segment at a height whose block hash the test controls.
fn anchor(block_number: u32) -> Hash256 {
	let hash = digest_bytes_of(&format!("block-{block_number}"));
	frame_system::BlockHash::<Test>::insert(u64::from(block_number), H256::from(hash));
	System::set_block_number(u64::from(block_number) + 1);
	hash
}

fn one_segment(block_number: u32, slots: Vec<RealSlot>) -> SettlementBundle {
	SettlementBundle {
		segments: vec![Segment { block_hash: anchor(block_number), block_number, slots }],
	}
}

/// Stand `steps` of pool value behind a synthetic settlement.
///
/// A settled fee leaves the pool, and the pallet refuses a fee larger than the
/// pool is holding, and refuses the settlement when it is not.
/// The end-to-end tests shield for real; these hand-built bundles have no
/// entry, so they seed the counter directly.
fn fund_pool(steps: u128) {
	crate::PoolValue::<Test>::put(steps * POOL_STEP);
}

#[test]
fn a_bundle_with_no_settleable_segment_is_refused() {
	new_test_ext().execute_with(|| {
		// This is what a standalone all-padding private batch parses to.
		// `prove_padding_batch` returns a proof that verifies against the
		// published verifier while its prover holds no note, and settlement
		// extrinsics are fee free, so accepting one as a no-op would let
		// anyone write into permanent state for nothing.
		let empty = SettlementBundle::default();
		assert_noop!(check(&empty, &[]), Error::<Test>::NothingToSettle);
	});
}

#[test]
fn a_valid_single_segment_bundle_passes_and_counts_its_fee() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		// Nine steps against a per-slot floor of eight: the flat minimum plus
		// the seven the one reachable payload costs.
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		let plan = check(&bundle, &outputs).expect("valid");
		assert_eq!(plan.fee_steps, 9);
		assert_eq!(plan.slots, 1);
	});
}

#[test]
fn a_nullifier_already_settled_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		assert_ok!(check(&bundle, &outputs));

		// One of the two nullifiers is settled. The segment is skipped, and
		// with nothing else in the submission there is nothing left to settle,
		// so the submission is refused.
		crate::UsedNullifiers::<Test>::insert(bundle.segments[0].slots[0].nullifiers[1], ());
		assert_noop!(check(&bundle, &outputs), Error::<Test>::NullifierAlreadyUsed);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::NullifierAlreadyUsed);
		assert_eq!(ZkTree::leaf_count(), 0);
	});
}

/// The second nullifier of a slot is the one a mechanical port of upstream's
/// wrapper drops. A note spent from input slot 1 is marked used only if slot
/// 1's nullifier is settled, so both have to be in the set the chain checks
/// and writes.
#[test]
fn both_nullifiers_of_a_slot_are_checked_and_settled() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		assert_ok!(Shielded::settle(bundle.clone(), outputs.clone()));

		for nullifier in bundle.segments[0].slots[0].nullifiers {
			assert!(crate::UsedNullifiers::<Test>::contains_key(nullifier));
		}
		// And the whole submission is a replay now: every segment is already
		// settled, so there is nothing left to settle and it is refused.
		assert_noop!(check(&bundle, &outputs), Error::<Test>::NullifierAlreadyUsed);
	});
}

/// The private-batch circuit forbids a repeat inside one batch, so this is
/// unreachable through a valid private batch. It is reachable through a public
/// batch: nothing in that circuit compares the nullifiers of two different
/// inner proofs, which is `n * 2N` digests and not affordable in circuit.
///
/// The later segment is skipped and the earlier one settles. Refusing the
/// submission instead would let one participant kill an aggregator's batch by
/// handing it two inners that spend one note.
#[test]
fn a_nullifier_repeated_across_two_segments_skips_the_later_one() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		// Sixteen steps: two carried slots at the flat minimum, plus the
		// fourteen the two carried payloads cost, the skipped segment's
		// included.
		let shared = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 16);
		let mut second = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		second.nullifiers[0] = shared.nullifiers[1];

		let bundle = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![shared.clone()] },
				Segment { block_hash, block_number: 10, slots: vec![second.clone()] },
			],
		};
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];

		let plan = check(&bundle, &outputs).expect("the first segment settles");
		assert_eq!(plan.settles, vec![true, false]);
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.fee_steps, 16);

		assert_ok!(Shielded::settle(bundle, outputs));
		// The first segment's leaves are there and the second's are not, and
		// the second segment's own fresh nullifier was never marked, so the
		// note behind it is still spendable in another batch.
		assert_eq!(ZkTree::leaf_count(), 2);
		assert!(crate::UsedNullifiers::<Test>::contains_key(shared.nullifiers[0]));
		assert!(!crate::UsedNullifiers::<Test>::contains_key(second.nullifiers[1]));
	});
}

#[test]
fn a_duplicate_nullifier_inside_one_segment_is_refused() {
	new_test_ext().execute_with(|| {
		let mut only = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		only.nullifiers[1] = only.nullifiers[0];
		let bundle = one_segment(10, vec![only]);
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::DuplicateNullifier
		);
	});
}

#[test]
fn the_zero_nullifier_never_enters_the_set() {
	new_test_ext().execute_with(|| {
		let mut only = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		only.nullifiers[0] = [0u8; 32];
		let bundle = one_segment(10, vec![only]);
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::ZeroNullifier
		);
	});
}

#[test]
fn a_segment_anchored_at_the_wrong_block_hash_is_refused() {
	new_test_ext().execute_with(|| {
		let mut bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3)]);
		bundle.segments[0].block_hash = digest_bytes_of("some other block");
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::BlockHashMismatch
		);
	});
}

#[test]
fn a_segment_anchored_at_a_height_with_no_block_is_refused() {
	new_test_ext().execute_with(|| {
		anchor(10);
		let bundle = SettlementBundle {
			segments: vec![Segment {
				block_hash: digest_bytes_of("block-9"),
				block_number: 9,
				slots: vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3)],
			}],
		};
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::BlockNotFound
		);
	});
}

#[test]
fn a_segment_outside_the_window_is_refused() {
	new_test_ext().execute_with(|| {
		let hash = digest_bytes_of("block-1");
		frame_system::BlockHash::<Test>::insert(1u64, H256::from(hash));
		// `BlockHashWindow` is 64 in the mock.
		System::set_block_number(200);
		let bundle = SettlementBundle {
			segments: vec![Segment {
				block_hash: hash,
				block_number: 1,
				slots: vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3)],
			}],
		};
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::BlockOutsideWindow
		);
	});
}

/// A segment anchored at the block being built has no hash yet and would be a
/// proof about a tree root that is not final.
#[test]
fn a_segment_anchored_at_the_current_block_is_refused() {
	new_test_ext().execute_with(|| {
		anchor(10);
		let bundle = SettlementBundle {
			segments: vec![Segment {
				block_hash: digest_bytes_of("block-11"),
				block_number: 11,
				slots: vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3)],
			}],
		};
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::BlockOutsideWindow
		);
	});
}

/// The circuit leaves `ct_digest` a free public input, so this comparison is
/// the whole binding between a proof and the ciphertexts submitted with it.
#[test]
fn a_ciphertext_that_does_not_hash_to_the_slots_digest_is_refused() {
	new_test_ext().execute_with(|| {
		// The binding runs behind the cheap pass, so the pool has to stand
		// behind the fee for the submission to reach it at all.
		fund_pool(100);
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xff))]),
			Error::<Test>::CiphertextDigestMismatch
		);
		// Swapping the two is a different digest as well, which is what binds
		// `ct_1` to `cm_1`.
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa2), &suite_ciphertext(0xa1))]),
			Error::<Test>::CiphertextDigestMismatch
		);
	});
}

#[test]
fn the_output_count_must_equal_the_real_slot_count() {
	new_test_ext().execute_with(|| {
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_noop!(check(&bundle, &[]), Error::<Test>::CiphertextCountMismatch);
		assert_noop!(
			check(
				&bundle,
				&[
					output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
					output(&suite_ciphertext(0xee), &suite_ciphertext(0xee)),
				]
			),
			Error::<Test>::CiphertextCountMismatch
		);
	});
}

/// The anti-spam mechanism. One note of any value, zero included, spent with a
/// dummy in the other slot mints two spendable notes, so nothing else bounds
/// how many leaves a prover can produce.
#[test]
fn a_slot_below_the_minimum_fee_is_refused() {
	new_test_ext().execute_with(|| {
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 0)]);
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]),
			Error::<Test>::FeeBelowMinimum
		);
	});
}

#[test]
fn settling_appends_two_leaves_per_slot_and_keeps_no_payload() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle = one_segment(
			10,
			vec![
				slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 8),
				slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 8),
			],
		);
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];
		assert_ok!(Shielded::settle(bundle.clone(), outputs));

		assert_eq!(ZkTree::leaf_count(), 4);
		for (index, slot) in bundle.segments[0].slots.iter().enumerate() {
			let first = index as u64 * 2;
			// leaf_hash = cm, with nothing recomputed.
			assert_eq!(ZkTree::leaf(first), Some(slot.commitments[0]));
			assert_eq!(ZkTree::leaf(first + 1), Some(slot.commitments[1]));
			assert_eq!(Shielded::leaf_block(first), Some(System::block_number()));
		}
		assert_eq!(crate::OutputsWrittenThisBlock::<Test>::get().1, 4);

		// Two slots at their per-slot floor of eight. Half of the sixteen-step
		// fee burns and half goes to the author, who is absent here, so the
		// whole fee simply leaves the pool.
		System::assert_has_event(
			Event::BatchSettled { segments: 1, slots: 2, fee: 16 * POOL_STEP }.into(),
		);
	});
}

#[test]
fn the_block_author_fee_share_is_held_for_the_blocks_coinbase_note() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		let preimage = [7u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);
		assert_eq!(Balances::balance(&author), 0);

		// Shield first, so the fee the settlement pays out is value the pool
		// actually holds. Asserting the author's credit against an empty pool
		// would assert that the underflow guard is a no-op.
		assert_ok!(Shielded::shield(
			RuntimeOrigin::signed(alice()),
			100 * POOL_STEP,
			note_inner(&shielder_keys().pk(), &entry_rho(1, 0), &Digest::hash_bytes(&[b"r"]))
				.to_bytes(),
			b"ct".to_vec(),
		));
		let issuance_before = Balances::total_issuance();

		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_ok!(Shielded::settle(
			bundle,
			vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]
		));

		// Nine steps, burn rounds up against the author: five burned, four
		// held for the coinbase note. The author's transparent account is not
		// touched at all, which is the whole of what v1 changed here.
		assert_eq!(Balances::balance(&author), 0);
		assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);
		System::assert_has_event(Event::AuthorFeeAccrued { amount: 4 * POOL_STEP }.into());
		// The whole fee left the pool. The burned half is gone; the author's
		// half is in flight, which is why the supply measure counts both books.
		assert_eq!(Shielded::pool_value(), 91 * POOL_STEP);
		assert_eq!(Balances::total_issuance(), issuance_before);
		assert_eq!(
			<crate::ShieldedSupply<Test> as frame_support::traits::Get<u128>>::get(),
			91 * POOL_STEP + 4 * POOL_STEP
		);
	});
}

/// `PoolValue` is the pallet's record of the issuance the pool stands in for.
/// A fee above it means the circuit's balance equation was broken or an entry
/// point forgot to credit the pool, and the response has to be a refusal:
/// a saturating subtraction would mint the author a share of a fee nothing
/// backs and zero the books on the way past, with nothing on chain to say so.
#[test]
fn a_fee_larger_than_the_pool_is_refused_with_nothing_written() {
	new_test_ext().execute_with(|| {
		fund_pool(2);
		// Nine steps clears the per-slot floor of eight and the submission
		// floor, so what is left to refuse it is the pool holding two.
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PoolUnderflow);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::PoolUnderflow);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
		assert_eq!(Shielded::pool_value(), 2 * POOL_STEP);
	});
}

/// A settled fee moves no transparent balance at all.
///
/// Under v1 the author's share becomes part of a note, so nothing in the fee
/// path mints, transfers or touches an account, and no `pallet_balances` event
/// can come out of a settlement. The rule this replaces was narrower and had
/// the same root: the runtime's wormhole recorder scanned `Minted` and
/// `Transfer` events and turned them into a second spend path for one credit.
/// There is no transparent credit to double now.
#[test]
fn a_settled_fee_moves_no_transparent_balance() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let preimage = [13u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);

		System::reset_events();
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_ok!(Shielded::settle(
			bundle,
			vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]
		));
		assert_eq!(Balances::balance(&author), 0, "the author holds no transparent balance");
		assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP, "the credit did happen");

		for record in System::events() {
			assert!(
				!matches!(record.event, RuntimeEvent::Balances(_)),
				"a settlement emitted a balance event: {:?}",
				record.event
			);
		}
	});
}

/// A padding slot's commitments are zero and its two nullifiers are hashes of
/// randomness drawn for that proving run. It settles nothing, and the parse is
/// where that is decided, so a settleable segment never carries one.
#[test]
fn a_padding_slot_is_dropped_at_the_parse() {
	let sentinel = padding_block_hash();
	assert_ne!(sentinel, [0u8; 32]);
	// The sentinel is what the chain recognises padding by, and it is not a
	// hash any chain can produce.
	assert_eq!(
		hex::encode(sentinel),
		"34b4e468a910702ae5c6124a10a5ed2e2eea369e90faa8bb5244e83015939269"
	);

	// Two slots, the second one padding: commitments zeroed, nullifiers still
	// carrying the prover's randomness, fee and `ct_digest` zeroed.
	let mut felts = vec![F::ZERO; private_batch_pi_len(2)];
	let block_hash = digest_bytes_of("a real block");
	write_digest(&mut felts, BLOCK_HASH_START, &block_hash);
	felts[BLOCK_NUMBER_INDEX] = F::from_canonical_u64(10);
	write_digest(&mut felts, slot_nullifier_index(0, 0), &digest_bytes_of("real-nf1"));
	write_digest(&mut felts, slot_nullifier_index(0, 1), &digest_bytes_of("real-nf2"));
	write_digest(&mut felts, slot_commitment_index(0, 0), &digest_bytes_of("real-cm1"));
	write_digest(&mut felts, slot_commitment_index(0, 1), &digest_bytes_of("real-cm2"));
	felts[slot_fee_index(0)] = F::from_canonical_u64(3);
	write_digest(
		&mut felts,
		slot_ct_digest_index(0),
		&ct_digest(&[&suite_ciphertext(0x01), &suite_ciphertext(0x02)]),
	);
	write_digest(&mut felts, slot_nullifier_index(1, 0), &digest_bytes_of("padding-nf1"));
	write_digest(&mut felts, slot_nullifier_index(1, 1), &digest_bytes_of("padding-nf2"));

	let inputs = parse_private_batch_public_input_felts(&felts, 2).expect("the layout parses");
	let bundle = SettlementBundle::from_private_batch(&inputs);
	assert_eq!(bundle.segments.len(), 1);
	let segment = &bundle.segments[0];
	assert_eq!(segment.block_hash, block_hash);
	assert_eq!(segment.block_number, 10);
	// Only the real slot survives, and the padding slot's two nullifiers never
	// reach the chain's nullifier set.
	assert_eq!(segment.slots.len(), 1);
	assert_eq!(segment.slots[0].nullifiers[0], digest_bytes_of("real-nf1"));
	assert_eq!(segment.slots[0].nullifiers[1], digest_bytes_of("real-nf2"));
	assert_eq!(segment.slots[0].fee, 3);
}

/// The public-batch twin. A padding inner keeps the sentinel header with its
/// whole slot region zeroed, so settling it would insert the all-zero
/// nullifier and make the chain refuse its own next batch as a double spend.
#[test]
fn a_padding_inner_is_dropped_at_the_parse() {
	let mut felts = vec![F::ZERO; public_batch_pi_len(2, 1)];
	write_digest(&mut felts, AGGREGATOR_ADDRESS_START, &digest_bytes_of("an aggregator"));

	// Inner 0 is real.
	let real = public_batch_inner_start(0, 1);
	let block_hash = digest_bytes_of("a real block");
	write_digest(&mut felts, real + BLOCK_HASH_START, &block_hash);
	felts[real + BLOCK_NUMBER_INDEX] = F::from_canonical_u64(7);
	write_digest(&mut felts, real + slot_nullifier_index(0, 0), &digest_bytes_of("nf1"));
	write_digest(&mut felts, real + slot_nullifier_index(0, 1), &digest_bytes_of("nf2"));
	write_digest(&mut felts, real + slot_commitment_index(0, 0), &digest_bytes_of("cm1"));
	write_digest(&mut felts, real + slot_commitment_index(0, 1), &digest_bytes_of("cm2"));
	felts[real + slot_fee_index(0)] = F::from_canonical_u64(1);

	// Inner 1 is padding: the sentinel header over a zeroed slot region.
	let padding = public_batch_inner_start(1, 1);
	write_digest(&mut felts, padding + BLOCK_HASH_START, &padding_block_hash());

	let inputs = parse_public_batch_public_input_felts(&felts, 2, 1).expect("the layout parses");
	let bundle = SettlementBundle::from_public_batch(&inputs);
	assert_eq!(bundle.segments.len(), 1, "the padding inner settles nothing");
	assert_eq!(bundle.segments[0].block_hash, block_hash);
	assert_eq!(bundle.segments[0].slots.len(), 1);
}

/// `block_number` arrives as a field element, which is wider than the `u32` the
/// chain compares against. The cast saturates: a truncating one would let an
/// out-of-range claim alias a real height, leaving
/// the block-hash comparison as the only thing between it and a settlement
/// anchored at a block the prover never saw.
#[test]
fn an_out_of_range_block_number_saturates_and_is_then_refused() {
	let mut felts = vec![F::ZERO; private_batch_pi_len(1)];
	write_digest(&mut felts, BLOCK_HASH_START, &digest_bytes_of("a block"));
	felts[BLOCK_NUMBER_INDEX] = F::from_canonical_u64(1u64 << 32);
	write_digest(&mut felts, slot_nullifier_index(0, 0), &digest_bytes_of("nf1"));
	write_digest(&mut felts, slot_nullifier_index(0, 1), &digest_bytes_of("nf2"));
	write_digest(&mut felts, slot_commitment_index(0, 0), &digest_bytes_of("cm1"));
	write_digest(&mut felts, slot_commitment_index(0, 1), &digest_bytes_of("cm2"));
	felts[slot_fee_index(0)] = F::from_canonical_u64(1);
	write_digest(
		&mut felts,
		slot_ct_digest_index(0),
		&ct_digest(&[&suite_ciphertext(0x01), &suite_ciphertext(0x02)]),
	);

	let inputs = parse_private_batch_public_input_felts(&felts, 1).expect("the layout parses");
	let bundle = SettlementBundle::from_private_batch(&inputs);
	assert_eq!(bundle.segments[0].block_number, u32::MAX);

	new_test_ext().execute_with(|| {
		fund_pool(100);
		System::set_block_number(20);
		assert_noop!(
			check(&bundle, &[output(&suite_ciphertext(0x01), &suite_ciphertext(0x02))]),
			Error::<Test>::BlockOutsideWindow
		);
	});
}

/// An aggregator's public batch wraps proofs that are each, on their own,
/// exactly what `submit_private_batch` accepts. A participant can therefore
/// settle its own inner directly before the batch lands. If that made the whole
/// public batch fatal, one participant could strand the other fifty-two
/// transfers and waste the aggregator's recursive proving run, for free and as
/// often as it liked. The already-settled segment is skipped.
#[test]
fn a_segment_settled_by_an_earlier_submission_is_skipped_not_fatal() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		// The first segment settles on its own at its per-slot floor of eight.
		// The batch below carries both positions, so the segment that settles
		// there owes the submission floor over both: two flat minimums and the
		// fourteen steps the two payloads cost.
		let first = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 8);
		let second = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];

		// The first segment settles on its own.
		assert_ok!(Shielded::settle(
			SettlementBundle {
				segments: vec![Segment {
					block_hash,
					block_number: 10,
					slots: vec![first.clone()],
				}],
			},
			vec![outputs[0].clone()],
		));
		assert_eq!(ZkTree::leaf_count(), 2);

		// Now the batch that wraps it arrives. The settled segment contributes
		// no leaves and no fee; the other one settles.
		let batch = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![first.clone()] },
				Segment { block_hash, block_number: 10, slots: vec![second.clone()] },
			],
		};
		let plan = check(&batch, &outputs).expect("the batch settles what is left");
		assert_eq!(plan.settles, vec![false, true]);
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.fee_steps, 16);

		assert_ok!(Shielded::settle(batch.clone(), outputs.clone()));
		assert_eq!(ZkTree::leaf_count(), 4);
		assert_eq!(ZkTree::leaf(2), Some(second.commitments[0]));
		// The skipped segment appended nothing over the earlier settlement's
		// leaves, and the second segment's commitments landed against their
		// own leaf indices.
		assert_eq!(ZkTree::leaf(3), Some(second.commitments[1]));

		// Re-submitting the whole thing now settles nothing at all, which is a
		// replay and is refused.
		assert_noop!(check(&batch, &outputs), Error::<Test>::NullifierAlreadyUsed);
	});
}

/// A segment that is only *partly* settled is skipped too, and this is the
/// case that matters. A note's nullifier is a function of the note alone, so a
/// participant that hands an aggregator an inner and then spends one of those
/// notes in a differently composed batch of its own leaves the aggregator's
/// inner partly settled: one nullifier used, the rest fresh. Under an
/// all-or-nothing rule that one participant strands the other fifty-two
/// transfers in the batch and wastes the recursive proving run, for free and
/// as often as it likes, and the aggregator cannot defend against it because
/// the conflict is created after its batch is fixed. An honest wallet that
/// gives up waiting and re-spends produces the same shape.
#[test]
fn a_partly_settled_segment_does_not_strand_the_rest_of_the_batch() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		// Twelve steps each: three carried slots at the flat minimum plus the
		// twenty-one the three carried payloads cost is a submission floor of
		// twenty-four, and the two settling slots owe all of it.
		let griefed = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		let bystander = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 12);
		let other = slot("c", &suite_ciphertext(0xc1), &suite_ciphertext(0xc2), 12);

		// One of the first segment's twelve nullifiers is spent elsewhere.
		crate::UsedNullifiers::<Test>::insert(griefed.nullifiers[0], ());

		let batch = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![griefed.clone()] },
				Segment { block_hash, block_number: 10, slots: vec![bystander.clone()] },
				Segment { block_hash, block_number: 10, slots: vec![other.clone()] },
			],
		};
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
			output(&suite_ciphertext(0xc1), &suite_ciphertext(0xc2)),
		];

		let plan = check(&batch, &outputs).expect("the unaffected segments settle");
		assert_eq!(plan.settles, vec![false, true, true]);
		assert_eq!(plan.slots, 2);
		assert_eq!(plan.fee_steps, 24);

		assert_ok!(Shielded::settle(batch, outputs));
		// Four leaves, two per bystander segment. The skipped segment
		// appended none.
		assert_eq!(ZkTree::leaf_count(), 4);
		assert_eq!(ZkTree::leaf(0), Some(bystander.commitments[0]));
		assert_eq!(ZkTree::leaf(2), Some(other.commitments[0]));
		// Nothing of the skipped segment was written, so its unspent nullifier
		// is still free and the note behind it can settle in another batch.
		assert!(!crate::UsedNullifiers::<Test>::contains_key(griefed.nullifiers[1]));
	});
}

/// Every real slot's ciphertexts are bound to the `ct_digest` its proof
/// publishes, whether or not this submission settles that slot. The count rule
/// requires an `outputs` entry per real slot, so a position left unchecked
/// would be a place to carry bytes no proof commits to, on an unsigned and fee
/// free extrinsic the block then has to carry.
#[test]
fn the_ciphertexts_of_a_skipped_segment_are_still_bound_to_the_proof() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		let settled = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		// Sixteen steps, because the skipped position here carries 3584 bytes
		// and the submission floor makes the settling slot pay for them. That
		// rule is the subject of `a_submission_pays_for_every_byte_it_carries`;
		// what this test is about is what happens to those bytes once they are
		// paid for, which is that they are still bound to the proof.
		let fresh = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		crate::UsedNullifiers::<Test>::insert(settled.nullifiers[0], ());

		let batch = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![settled] },
				Segment { block_hash, block_number: 10, slots: vec![fresh] },
			],
		};
		// The skipped segment's position carries the wrong bytes at the right
		// length, so the length rule passes it through to the binding, which is
		// what this test is about.
		let wrong = vec![
			output(&suite_ciphertext(0x3a), &suite_ciphertext(0x3b)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];
		assert_noop!(check(&batch, &wrong), Error::<Test>::CiphertextDigestMismatch);

		// The same position padded to the ciphertext cap does not reach the
		// binding at all now: the length rule refuses it in front.
		let padded = vec![
			output(&capped_ciphertext(9), &capped_ciphertext(9)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];
		assert_noop!(check(&batch, &padded), Error::<Test>::CiphertextLengthMismatch);

		let honest = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];
		assert_ok!(check(&batch, &honest));
	});
}

/// A segment whose block anchor no longer resolves is skipped, exactly the way
/// a nullifier conflict is skipped, and the rest of the submission settles.
///
/// This is the half of the griefing an aggregator cannot defend against at
/// all. A nullifier conflict it can at least pre-check its inners for; an
/// anchor goes stale after the batch is fixed. One reorg between the recursive
/// proving run, about 21 seconds, and inclusion is enough to orphan an inner's
/// anchoring block, and a participant can force the same shape deliberately by
/// handing over an inner anchored near the edge of `BlockHashWindow`. Under the
/// `ensure!` this replaces, that one inner refused the whole submission and
/// stranded the other fifty-two transfers.
#[test]
fn a_segment_whose_anchor_no_longer_resolves_is_skipped_not_fatal() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		let orphaned = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		// Sixteen steps: both positions carry their payload, and the settling
		// slot owes the submission floor over both.
		let fresh = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];

		// The first segment is anchored at height 10 on a hash that is no
		// longer the canonical one there, which is what a one-block reorg
		// leaves behind.
		let batch = SettlementBundle {
			segments: vec![
				Segment {
					block_hash: digest_bytes_of("the orphaned block at 10"),
					block_number: 10,
					slots: vec![orphaned.clone()],
				},
				Segment { block_hash, block_number: 10, slots: vec![fresh.clone()] },
			],
		};

		let plan = check(&batch, &outputs).expect("the segment with a live anchor settles");
		assert_eq!(plan.settles, vec![false, true]);
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.skipped_slots, 1);
		assert_eq!(plan.fee_steps, 16);

		assert_ok!(Shielded::settle(batch, outputs));
		// Two leaves, both the surviving segment's, and nothing of the
		// orphaned one was written, so the notes behind it can settle in a
		// batch anchored at a block that still resolves.
		assert_eq!(ZkTree::leaf_count(), 2);
		assert_eq!(ZkTree::leaf(0), Some(fresh.commitments[0]));
		for nullifier in orphaned.nullifiers {
			assert!(!crate::UsedNullifiers::<Test>::contains_key(nullifier));
		}
	});
}

/// A submission whose every segment has a stale anchor settles nothing and is
/// refused, and the anchor rule is what names the refusal, so the error is the
/// anchor's own.
///
/// A private batch carries exactly one segment, so skipping and refusing are
/// the same outcome there and the wallet is owed the reason its proof did not
/// land. Each of the four anchor failures keeps its own error through the skip.
#[test]
fn a_submission_with_no_live_anchor_is_refused_by_the_anchor_rule() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];

		let wrong_hash = SettlementBundle {
			segments: vec![Segment {
				block_hash: digest_bytes_of("not the block at 10"),
				block_number: 10,
				slots: vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3)],
			}],
		};
		anchor(10);
		assert_noop!(check(&wrong_hash, &outputs), Error::<Test>::BlockHashMismatch);

		// And in a two-segment submission where the other segment is a replay,
		// the anchor is still what the refusal names: reporting the nullifier
		// conflict would send an aggregator looking for a double spend that is
		// not the reason its batch settled nothing.
		let settled = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 3);
		for nullifier in settled.nullifiers {
			crate::UsedNullifiers::<Test>::insert(nullifier, ());
		}
		let mixed = SettlementBundle {
			segments: vec![
				wrong_hash.segments[0].clone(),
				Segment {
					block_hash: digest_bytes_of("block-10"),
					block_number: 10,
					slots: vec![settled],
				},
			],
		};
		assert_noop!(
			check(
				&mixed,
				&[outputs[0].clone(), output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2))]
			),
			Error::<Test>::BlockHashMismatch
		);
	});
}

/// Every byte a submission carries is paid for by the slots it settles.
///
/// A skipped segment pays no fee of its own, because it writes no permanent
/// state, and its ciphertexts still sit in the block and are still sponged into
/// a `ct_digest` by every node that sees the submission. So the settling slots
/// owe `(settling slots + skipped slots) * MinLeafFee + ceil(carried bytes /
/// 512)` over the whole submission, and the carried bytes are every byte in
/// `outputs`.
///
/// This test is the payload half of that floor, and it is the half a slot count
/// could never price on its own. The submitter picks how many slots it skips
/// independently of how many it settles, so three skipped slots carrying a full
/// payload each ride on one settling slot while the slot counts stay inside any
/// ratio a runtime would pick: 10752 bytes of never-pruned payload for the one
/// settling slot's eight steps. Pricing the bytes is what makes that free ride
/// impossible to construct, because a byte costs the same wherever it is
/// carried. The exact-length rule bounds how large the shape can be, since a
/// carried position is 3584 bytes or nothing; it does not price it.
/// `a_carried_slot_is_paid_for_even_when_its_outputs_are_emptied` is the other
/// half, where the bytes are gone and the slots remain.
#[test]
fn a_submission_pays_for_every_byte_it_carries() {
	new_test_ext().execute_with(|| {
		fund_pool(1_000);
		let block_hash = anchor(10);
		let carried_1 = suite_ciphertext(0x77);
		let carried_2 = suite_ciphertext(0x88);

		// One segment that settles, carrying its 3584-byte pair, and `skipped`
		// segments already spent on this chain, each carrying one too.
		let build = |skipped: usize, fee: u64| {
			let mut segments = vec![Segment {
				block_hash,
				block_number: 10,
				slots: vec![slot("live", &suite_ciphertext(0x11), &suite_ciphertext(0x12), fee)],
			}];
			let mut outputs = vec![output(&suite_ciphertext(0x11), &suite_ciphertext(0x12))];
			for index in 0..skipped {
				let tag = format!("spent-{index}");
				let conflicting = slot(&tag, &carried_1, &carried_2, 9);
				crate::UsedNullifiers::<Test>::insert(conflicting.nullifiers[0], ());
				segments.push(Segment { block_hash, block_number: 10, slots: vec![conflicting] });
				outputs.push(output(&carried_1, &carried_2));
			}
			(SettlementBundle { segments }, outputs)
		};

		// Three skipped slots carrying a payload each: 10752 bytes beside the
		// settling slot's 3584, which is 28 started steps, plus a flat minimum
		// for each of the four slots the submission carries. The settling
		// slot's own per-slot floor is eight, and paying exactly that is not
		// enough.
		let (bundle, outputs) = build(3, 8);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);
		let (bundle, outputs) = build(3, 31);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);

		// Paid for, and it settles.
		let (bundle, outputs) = build(3, 32);
		let plan = check(&bundle, &outputs).expect("the settling fee covers every carried byte");
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.skipped_slots, 3);
		assert_eq!(plan.carried_bytes, 4 * 2 * SUITE_CIPHERTEXT_BYTES);
		assert_ok!(Shielded::settle(bundle, outputs));
		assert_eq!(ZkTree::leaf_count(), 2);
	});
}

/// The byte price counts a skipped segment however it came to be skipped. A
/// stale anchor is the cheaper of the two shapes to produce in bulk: it needs
/// no nullifier of the attacker's to be spent first, only an inner anchored at
/// a block that has aged out of `BlockHashWindow`, and such an inner stays
/// skippable forever.
#[test]
fn a_segment_skipped_for_a_stale_anchor_is_priced_like_any_other() {
	new_test_ext().execute_with(|| {
		fund_pool(1_000);
		let block_hash = anchor(10);
		let carried_1 = suite_ciphertext(0x77);
		let carried_2 = suite_ciphertext(0x88);

		let build = |fee: u64| {
			let mut segments = vec![Segment {
				block_hash,
				block_number: 10,
				slots: vec![slot("live", &suite_ciphertext(0x11), &suite_ciphertext(0x12), fee)],
			}];
			let mut outputs = vec![output(&suite_ciphertext(0x11), &suite_ciphertext(0x12))];
			for index in 0..8 {
				let tag = format!("stale-{index}");
				segments.push(Segment {
					block_hash: digest_bytes_of(&format!("orphan-{index}")),
					block_number: 10,
					slots: vec![slot(&tag, &carried_1, &carried_2, 9)],
				});
				outputs.push(output(&carried_1, &carried_2));
			}
			(SettlementBundle { segments }, outputs)
		};

		// Eight orphaned segments carrying a payload each: 28672 bytes beside
		// the settling slot's 3584, 63 started steps, plus a flat minimum for
		// each of the nine slots the submission carries.
		let (bundle, outputs) = build(8);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::PayloadUnderpaid);
		assert_eq!(ZkTree::leaf_count(), 0);

		let (bundle, outputs) = build(72);
		let plan = check(&bundle, &outputs).expect("the settling fee covers the orphaned bytes");
		assert_eq!(plan.skipped_slots, 8);
		assert_eq!(plan.carried_bytes, 9 * 2 * SUITE_CIPHERTEXT_BYTES);

		// Emptying them is the aggregator's move here too, and it removes the
		// payload term alone: the nine carried slots still owe their flat
		// minimums, which is sixteen steps with the settling slot's seven
		// payload steps.
		let (bundle, mut outputs) = build(15);
		for position in outputs.iter_mut().skip(1) {
			*position = output(b"", b"");
		}
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);

		let (bundle, mut outputs) = build(16);
		for position in outputs.iter_mut().skip(1) {
			*position = output(b"", b"");
		}
		assert_ok!(Shielded::settle(bundle, outputs));
		assert_eq!(ZkTree::leaf_count(), 2);
	});
}

/// A slot the submission carries is paid for whether or not it settles, and
/// emptying its ciphertexts does not make it free.
///
/// This is the slot half of the submission floor, and it is what the byte term
/// alone could not price. Emptying a skipped position removes its bytes, and
/// the slot behind it still costs every node the admission walk over it, two
/// `UsedNullifiers` probes, a position in `outputs` and the weight the
/// extrinsic declares for it, and an unsigned settlement pays nothing else for
/// any of that. Without a per-slot term one settling slot commands the whole
/// walk and the whole declared weight of a full public batch, 318 real slots,
/// for one step.
///
/// That is the 52-of-53 grief shape at its limit: participants hand an
/// aggregator inners that re-spend a note another inner settles, which the
/// public-batch circuit permits as long as the shared note sits anywhere but
/// slot 0 input 0. The aggregator keeps two remedies, and both are priced. Pay
/// the floor, which its settling fees often already cover. Or recompose a fresh
/// public batch without the conflicted inners, which costs one public-batch
/// proof. What it may not do is hand a block 318 slots of work on credit.
///
/// How the skipped slots are spread over segments does not matter: nothing in
/// the rule reads a segment count, so one real slot per skipped segment is the
/// clearest way to write the 318 real slots a full public batch carries.
#[test]
fn a_carried_slot_is_paid_for_even_when_its_outputs_are_emptied() {
	new_test_ext().execute_with(|| {
		fund_pool(10_000);
		let block_hash = anchor(10);

		let build = |fee: u64| {
			let mut segments = vec![Segment {
				block_hash,
				block_number: 10,
				slots: vec![slot("live", &suite_ciphertext(0x11), &suite_ciphertext(0x12), fee)],
			}];
			let mut outputs = vec![output(&suite_ciphertext(0x11), &suite_ciphertext(0x12))];
			for index in 0..317 {
				let tag = format!("spent-{index}");
				let conflicting = slot(&tag, &suite_ciphertext(0x51), &suite_ciphertext(0x52), 9);
				crate::UsedNullifiers::<Test>::insert(conflicting.nullifiers[0], ());
				segments.push(Segment { block_hash, block_number: 10, slots: vec![conflicting] });
				// The aggregator's resubmission: the position stays, the bytes
				// go.
				outputs.push(output(b"", b""));
			}
			(SettlementBundle { segments }, outputs)
		};

		// 318 carried slots at one step each, plus the seven started steps the
		// settling slot's 3584 bytes cost. The settling slot's own per-slot
		// floor is eight, and that is all it paid before this term existed.
		let (bundle, outputs) = build(8);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::PayloadUnderpaid);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 317);

		let (bundle, outputs) = build(324);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PayloadUnderpaid);

		// Paid for, and the batch settles: one griefed segment is never fatal.
		let (bundle, outputs) = build(325);
		let plan = check(&bundle, &outputs).expect("every carried slot is paid for");
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.skipped_slots, 317);
		// Only the settling slot's own ciphertexts are carried.
		assert_eq!(plan.carried_bytes, 2 * SUITE_CIPHERTEXT_BYTES);
		assert_eq!(plan.fee_steps, 325);

		assert_ok!(Shielded::settle(bundle, outputs));
		assert_eq!(ZkTree::leaf_count(), 2);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 317 + 2);
	});
}

/// A submission that settles everything it carries pays its per-slot floors and
/// nothing more, which is every private batch and every public batch that is
/// not being griefed.
///
/// The submission floor is `(settling + skipped) * MinLeafFee + ceil(sum b_i /
/// q)` and the per-slot floors sum to `settling * MinLeafFee + sum(ceil(b_i /
/// q))`. With nothing skipped the flat terms are equal and
/// `sum(ceil(b_i / q))` is at least `ceil(sum(b_i) / q)`, so the submission
/// floor can never be the binding one. Three slots carrying the one payload
/// settlement admits are the case where the two rounding terms are equal as
/// well, 21 steps either way, so the floors coincide exactly and a submission
/// paying the per-slot minimum to the step still passes. Under the exact-length
/// rule that is no longer a coincidence: 3584 divides into 512-byte steps with
/// nothing left over, so neither term ever rounds.
#[test]
fn a_single_segment_submission_pays_only_its_per_slot_floors() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		// 1792 bytes is the length settlement requires of a suite-1
		// ciphertext, so a slot carries 3584 bytes: exactly seven steps over
		// the flat minimum, a per-slot floor of eight.
		let real_1 = suite_ciphertext(0x21);
		let real_2 = suite_ciphertext(0x22);
		let outputs =
			vec![output(&real_1, &real_2), output(&real_1, &real_2), output(&real_1, &real_2)];

		let exact = one_segment(
			10,
			vec![
				slot("a", &real_1, &real_2, 8),
				slot("b", &real_1, &real_2, 8),
				slot("c", &real_1, &real_2, 8),
			],
		);
		let plan = check(&exact, &outputs).expect("the per-slot floors are the whole floor");
		assert_eq!(plan.slots, 3);
		assert_eq!(plan.skipped_slots, 0);
		assert_eq!(plan.fee_steps, 24);
		// 3 * 1 flat plus 10752 / 512 = 21, which is the sum of the three
		// per-slot floors exactly.
		assert_eq!(plan.carried_bytes, 3 * 2 * SUITE_CIPHERTEXT_BYTES);

		// One step less on any slot is refused by the per-slot floor, which
		// is the binding one here.
		let cheap = one_segment(
			11,
			vec![
				slot("a", &real_1, &real_2, 8),
				slot("b", &real_1, &real_2, 8),
				slot("c", &real_1, &real_2, 7),
			],
		);
		assert_noop!(check(&cheap, &outputs), Error::<Test>::FeeBelowMinimum);
	});
}

/// A settling slot has to carry both of its ciphertexts.
///
/// The emptied position is an exemption for a segment that settles nothing:
/// `bind_payload` evaluates no `ct_digest` for one, because there are no bytes
/// there to bind. Taken by a slot that settles, it would append two commitments
/// and store two empty ciphertexts behind a digest nothing checked, leaving an
/// output note its recipient can never find. The refusal lives in
/// `plan_settlement`, which runs ahead of the binding on every path, and this
/// pins that pairing: the binding alone accepts the emptied position.
#[test]
fn a_settling_slot_may_not_empty_its_ciphertexts() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);

		let emptied = vec![output(b"", b"")];
		assert_ok!(bind(&bundle, &emptied));
		assert_noop!(plan(&bundle, &emptied), Error::<Test>::EmptyCiphertext);
		assert_noop!(check(&bundle, &emptied), Error::<Test>::EmptyCiphertext);
		assert_noop!(Shielded::settle(bundle.clone(), emptied), Error::<Test>::EmptyCiphertext);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);

		// One empty field is refused too, and now it is the length rule that
		// refuses it, in front of the per-slot check above: the zero-length
		// exemption is a whole pair or nothing, and a half-emptied position is
		// a ciphertext that is not the length its suite fixes. That is the
		// better error of the two, because it says which field is wrong rather
		// than which slot.
		let half = vec![output(b"", &suite_ciphertext(0xa2))];
		assert_noop!(plan(&bundle, &half), Error::<Test>::CiphertextLengthMismatch);
		assert_noop!(check(&bundle, &half), Error::<Test>::CiphertextLengthMismatch);
	});
}

/// A skipped position that still carries its ciphertexts is bound to the
/// proof's `ct_digest`, and an emptied one is exempt. The count rule holds
/// either way, so neither shape is a place to carry bytes no proof commits to.
#[test]
fn an_emptied_position_is_exempt_from_the_binding_and_a_carried_one_is_not() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		let settled = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		// Sixteen steps while the skipped position carries its payload, which
		// is what the junk case below needs to reach the binding at all.
		let fresh = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		crate::UsedNullifiers::<Test>::insert(settled.nullifiers[0], ());

		let bundle = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![settled] },
				Segment { block_hash, block_number: 10, slots: vec![fresh] },
			],
		};

		// Junk at the skipped position is still refused: it carries bytes, and
		// these are the right length, so the binding is what refuses them.
		let junk = vec![
			output(&suite_ciphertext(0x0a), &suite_ciphertext(0x0b)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];
		assert_noop!(check(&bundle, &junk), Error::<Test>::CiphertextDigestMismatch);

		// Emptied, it settles, and the position itself is still required.
		let emptied =
			vec![output(b"", b""), output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2))];
		let plan = check(&bundle, &emptied).expect("an emptied skipped position");
		assert_eq!(plan.carried_bytes, 2 * SUITE_CIPHERTEXT_BYTES);
		assert_noop!(check(&bundle, &emptied[1..]), Error::<Test>::CiphertextCountMismatch);
	});
}

/// A segment anchored above the current height is skipped like any other
/// anchor failure, and the rest of the submission settles.
///
/// This is the one anchor condition of the four that is not permanent: the
/// height it names arrives later. It is a skip all the same, because a refusal
/// would hand an aggregator's participants the cheapest grief of the lot, an
/// inner anchored in the future being one line of a hand-built witness. What
/// the skip promises is that the segment does not settle at this height, which
/// is what a plan for this block needs.
#[test]
fn a_segment_anchored_above_the_current_height_is_skipped_not_fatal() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		let ahead = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		// Sixteen steps: both positions carry their payload, so the settling
		// slot owes the submission floor over both.
		let fresh = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		let outputs = vec![
			output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)),
			output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2)),
		];

		let bundle = SettlementBundle {
			segments: vec![
				Segment {
					block_hash: digest_bytes_of("block-99"),
					block_number: 99,
					slots: vec![ahead.clone()],
				},
				Segment { block_hash, block_number: 10, slots: vec![fresh] },
			],
		};

		let plan = check(&bundle, &outputs).expect("the anchored segment settles");
		assert_eq!(plan.settles, vec![false, true]);
		assert_eq!(plan.slots, 1);
		assert_ok!(Shielded::settle(bundle, outputs));
		assert_eq!(ZkTree::leaf_count(), 2);
		// Nothing of the skipped segment was written, so the same proof can
		// settle in a later submission if that height ever resolves to the hash
		// it named.
		assert!(!crate::UsedNullifiers::<Test>::contains_key(ahead.nullifiers[0]));
	});
}

/// `shield` writes its ciphertext into the same bounded live `Ciphertexts` map
/// a settled slot writes two of, so it carries the same proof-size term. The
/// runtime leaves `proof_size` uncapped today, so this is a declaration and
/// nothing is metered against it yet. The day it is capped, an under-declared
/// `shield` is PoV nothing accounts for.
#[test]
fn the_shield_weight_carries_the_ciphertext_it_writes() {
	use crate::weights::WeightInfo as _;

	let empty = weights::SubstrateWeight::<Test>::shield(0);
	let full = weights::SubstrateWeight::<Test>::shield(2_048);
	assert_eq!(full.proof_size(), empty.proof_size() + 2_048);
	assert_eq!(full.ref_time(), empty.ref_time());
}

/// The fee floor is linear in the payload, and under the exact-length rule the
/// settlement path has exactly one payload per carried position, so the line
/// has one point on it: 3584 bytes, seven steps, a per-slot floor of eight.
///
/// What the endpoints used to pin was that a pair padded to
/// `MaxCiphertextBytes` cost strictly more than a real pair, because the chain
/// did not parse the bytes and nothing held a submission to a real ciphertext
/// shape. That is now `a_pair_padded_to_the_cap_is_refused_not_priced`: the
/// grind the divisor was sized against is refused rather than priced. What
/// stays pinned here is that the one reachable payload is priced at all, and
/// that a position emptied whole is priced at nothing.
#[test]
fn a_slot_pays_for_the_ciphertext_bytes_it_publishes() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		// The one reachable pair: 3584 bytes, exactly seven 512-byte units
		// over the flat minimum of one step.
		let real_1 = suite_ciphertext(0x31);
		let real_2 = suite_ciphertext(0x32);
		let outputs = vec![output(&real_1, &real_2)];

		let cheap = one_segment(10, vec![slot("a", &real_1, &real_2, 7)]);
		assert_noop!(check(&cheap, &outputs), Error::<Test>::FeeBelowMinimum);

		let paid = one_segment(11, vec![slot("a", &real_1, &real_2, 8)]);
		let plan = check(&paid, &outputs).expect("the per-slot floor is eight steps");
		assert_eq!(plan.carried_bytes, 2 * SUITE_CIPHERTEXT_BYTES);

		// A position emptied whole carries nothing, so it is priced at
		// nothing: the flat minimum is the whole floor of the slot behind it.
		// That is the only other shape a settlement may publish.
		let block_hash = anchor(12);
		let skipped = slot("b", &real_1, &real_2, 9);
		crate::UsedNullifiers::<Test>::insert(skipped.nullifiers[0], ());
		let settling = slot("c", &real_1, &real_2, 9);
		let mixed = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 12, slots: vec![skipped] },
				Segment { block_hash, block_number: 12, slots: vec![settling] },
			],
		};
		let plan = check(&mixed, &[output(b"", b""), output(&real_1, &real_2)])
			.expect("an emptied position costs its slot's flat minimum and no bytes");
		assert_eq!(plan.carried_bytes, 2 * SUITE_CIPHERTEXT_BYTES);
		assert_eq!(plan.skipped_slots, 1);
	});
}

/// Every ciphertext a settling slot carries is exactly the length its declared
/// suite fixes. One byte either way is refused, through the plan, through the
/// check and through the dispatch alike, because all three run the same pass.
///
/// This is the rule itself. What it buys is that `MaxCiphertextBytes` is
/// unreachable on the settlement path, so the padding grind the payload fee
/// term was sized against is foreclosed rather than priced, and what it does
/// not buy is any claim about the bytes: a blob of the exact length behind a
/// valid header still settles whatever it contains.
#[test]
fn a_settling_slot_carries_exact_suite_length_ciphertexts() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let exact = suite_ciphertext(0x41);
		let short = exact[..exact.len() - 1].to_vec();
		let long = {
			let mut bytes = exact.clone();
			bytes.push(0);
			bytes
		};
		assert_eq!(short.len(), qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES - 1);
		assert_eq!(long.len(), qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES + 1);

		for wrong in [short, long] {
			let bundle = one_segment(10, vec![slot("a", &wrong, &wrong, 9)]);
			let outputs = vec![output(&wrong, &wrong)];
			assert_noop!(plan(&bundle, &outputs), Error::<Test>::CiphertextLengthMismatch);
			assert_noop!(check(&bundle, &outputs), Error::<Test>::CiphertextLengthMismatch);
			assert_noop!(
				Shielded::settle(bundle, outputs),
				Error::<Test>::CiphertextLengthMismatch
			);
			assert_eq!(ZkTree::leaf_count(), 0);
		}

		// The exact length, behind a `[1, 1, 0]` header, settles.
		let bundle = one_segment(11, vec![slot("a", &exact, &exact, 9)]);
		assert_eq!(&exact[..3], &[1u8, 1, 0]);
		assert_ok!(Shielded::settle(bundle, vec![output(&exact, &exact)]));
		assert_eq!(ZkTree::leaf_count(), 2);
	});
}

/// A position belonging to a skipped segment is exact or empty, with nothing
/// in between.
///
/// The zero-length pair is the exemption a griefed aggregator resubmits with,
/// and `bind_payload` evaluates no digest for one. A pair that carries bytes is
/// bound, and now it is also measured, so a skipped position is no longer a
/// place to park an arbitrary blob behind a digest the proof already fixed.
#[test]
fn a_carried_skipped_position_is_exact_or_empty() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let block_hash = anchor(10);
		let settled = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		let fresh = slot("b", &suite_ciphertext(0xb1), &suite_ciphertext(0xb2), 16);
		crate::UsedNullifiers::<Test>::insert(settled.nullifiers[0], ());

		let bundle = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![settled] },
				Segment { block_hash, block_number: 10, slots: vec![fresh] },
			],
		};
		let carried = output(&suite_ciphertext(0xb1), &suite_ciphertext(0xb2));

		// Emptied whole: exempt from the length rule and from the binding.
		let emptied = vec![output(b"", b""), carried.clone()];
		assert_ok!(check(&bundle, &emptied));

		// Exact and matching the proof's digest: bound, and it settles.
		let exact = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2)), carried.clone()];
		assert_ok!(check(&bundle, &exact));

		// Short: refused by length, ahead of `bind_payload`, which never
		// evaluates a digest for it.
		let short = vec![output(b"ct", b"ct"), carried];
		assert_noop!(plan(&bundle, &short), Error::<Test>::CiphertextLengthMismatch);
		assert_noop!(check(&bundle, &short), Error::<Test>::CiphertextLengthMismatch);
	});
}

/// A ciphertext declaring a suite this release has no length for is refused by
/// name.
///
/// It is the answer a wallet one release ahead of the runtime is owed. Folded
/// into `CiphertextLengthMismatch` it would tell such a wallet its bytes were
/// the wrong length, when its bytes are right and this chain is the one that
/// has not caught up. The blob here is suite-1 sized on purpose: what refuses
/// it is the id and not the length.
#[test]
fn a_ciphertext_declaring_an_unknown_suite_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let mut ahead = suite_ciphertext(0x61);
		ahead[1..3].copy_from_slice(&2u16.to_le_bytes());
		assert_eq!(ahead.len(), qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES);

		let bundle = one_segment(10, vec![slot("a", &ahead, &ahead, 9)]);
		let outputs = vec![output(&ahead, &ahead)];
		assert_noop!(plan(&bundle, &outputs), Error::<Test>::UnknownCryptoSuite);
		assert_noop!(check(&bundle, &outputs), Error::<Test>::UnknownCryptoSuite);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::UnknownCryptoSuite);
		assert_eq!(ZkTree::leaf_count(), 0);
	});
}

/// A blob too short to carry a suite id at all is refused, at a settling
/// position and at a skipped one.
///
/// This is the `None` arm of `declared_crypto_suite`, and it is the one path
/// where a length rule keyed on a header panics if it is written with a slice
/// index. One byte and two bytes are the interesting lengths: a zero-length
/// field is the emptied-position exemption when its partner is empty too, and a
/// refusal when its partner is not.
#[test]
fn a_ciphertext_shorter_than_its_header_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let exact = suite_ciphertext(0x41);

		for length in [0usize, 1, 2] {
			let stub = vec![1u8; length];
			let bundle = one_segment(10, vec![slot("a", &stub, &stub, 9)]);
			let outputs = vec![output(&stub, &stub)];
			if length == 0 {
				// Both fields empty is the exemption, so this one reaches the
				// per-slot check that a settling slot may not take it.
				assert_noop!(check(&bundle, &outputs), Error::<Test>::EmptyCiphertext);
			} else {
				assert_noop!(plan(&bundle, &outputs), Error::<Test>::CiphertextLengthMismatch);
				assert_noop!(check(&bundle, &outputs), Error::<Test>::CiphertextLengthMismatch);
			}

			// The same stub at a skipped position, beside a settling slot that
			// carries its payload.
			let block_hash = anchor(20);
			let settled = slot("s", &stub, &stub, 3);
			let settled_nullifier = settled.nullifiers[0];
			crate::UsedNullifiers::<Test>::insert(settled_nullifier, ());
			let skipped_bundle = SettlementBundle {
				segments: vec![
					Segment { block_hash, block_number: 20, slots: vec![settled] },
					Segment {
						block_hash,
						block_number: 20,
						slots: vec![slot("t", &exact, &exact, 16)],
					},
				],
			};
			let mixed = vec![output(&stub, &stub), output(&exact, &exact)];
			if length == 0 {
				assert_ok!(check(&skipped_bundle, &mixed));
			} else {
				assert_noop!(
					check(&skipped_bundle, &mixed),
					Error::<Test>::CiphertextLengthMismatch
				);
			}
			crate::UsedNullifiers::<Test>::remove(settled_nullifier);
		}
	});
}

/// `carried_bytes` has one reachable value per position: 3584 bytes, or zero
/// for a position emptied whole.
///
/// It kept its arithmetic and lost its range. The payload term is still linear,
/// because it still prices a skipped position's bytes and because a second
/// suite would publish a second length, and the submission floor is now the
/// slot count times `MinLeafFee` plus seven steps per carried position.
#[test]
fn the_reachable_carried_bytes_are_one_value_per_position() {
	new_test_ext().execute_with(|| {
		fund_pool(1_000);
		let ct_1 = suite_ciphertext(0x91);
		let ct_2 = suite_ciphertext(0x92);

		// A private batch: one segment, every position carried.
		let private = one_segment(10, vec![slot("a", &ct_1, &ct_2, 8), slot("b", &ct_1, &ct_2, 8)]);
		let outputs = vec![output(&ct_1, &ct_2), output(&ct_1, &ct_2)];
		let plan = check(&private, &outputs).expect("two carried positions");
		assert_eq!(plan.carried_bytes, 2 * 2 * SUITE_CIPHERTEXT_BYTES);

		// A multi-segment public batch with one position emptied, which is the
		// only other value the term can take.
		let block_hash = anchor(11);
		let settled = slot("c", &ct_1, &ct_2, 3);
		crate::UsedNullifiers::<Test>::insert(settled.nullifiers[0], ());
		let public = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 11, slots: vec![settled] },
				Segment {
					block_hash,
					block_number: 11,
					slots: vec![slot("d", &ct_1, &ct_2, 9), slot("e", &ct_1, &ct_2, 8)],
				},
			],
		};
		let mixed = vec![output(b"", b""), output(&ct_1, &ct_2), output(&ct_1, &ct_2)];
		let plan = check(&public, &mixed).expect("one emptied position and two carried");
		assert_eq!(plan.carried_bytes, 2 * 2 * SUITE_CIPHERTEXT_BYTES);
		assert_eq!(plan.skipped_slots, 1);
		assert_eq!(plan.slots, 2);
		// Three carried slots at the flat minimum plus fourteen payload steps
		// is a submission floor of seventeen, and the two settling slots pay it
		// exactly.
		assert_eq!(plan.fee_steps, 17);
	});
}

/// The grind the payload fee term was sized against is refused outright now,
/// and this is the test that states what the rule bought.
///
/// `CiphertextBytesPerFeeQuantum` was tuned so that a pair padded to
/// `MaxCiphertextBytes` landed a fee bucket above the pair a wallet really
/// sends, because the chain never parsed these bytes and a settler could fill
/// both fields with anything it liked. The exact-length rule takes the shape
/// away: 4096 bytes at a settling position is not priced at nine steps, it is
/// not priced at all.
#[test]
fn a_pair_padded_to_the_cap_is_refused_not_priced() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let padded_1 = capped_ciphertext(5);
		let padded_2 = capped_ciphertext(6);
		let padded_outputs = vec![output(&padded_1, &padded_2)];

		// Nine steps is what the old per-slot floor asked of a capped pair,
		// and the fee is no longer the thing in the way.
		let padded = one_segment(15, vec![slot("d", &padded_1, &padded_2, 9)]);
		assert_noop!(plan(&padded, &padded_outputs), Error::<Test>::CiphertextLengthMismatch);
		assert_noop!(check(&padded, &padded_outputs), Error::<Test>::CiphertextLengthMismatch);
		assert_noop!(
			Shielded::settle(padded, padded_outputs),
			Error::<Test>::CiphertextLengthMismatch
		);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
	});
}

// ===========================================================================
// Shield: the only entry into the pool at v0
// ===========================================================================

fn alice() -> AccountId {
	qp_wormhole::account_id(1)
}

/// The spend credential the tests shield to and spend from.
fn shielder_keys() -> DerivedKeys {
	DerivedKeys {
		ask: Digest::hash_bytes(&[b"qnero-test/ask"]),
		nk: Digest::hash_bytes(&[b"qnero-test/nk"]),
	}
}

/// A note for `pk` worth `steps`, with its `rho` derived by the entry rule.
fn entry_note(pk: Digest, steps: u64, block_number: u32, entry_index: u64) -> Note {
	let rho = entry_rho(block_number, entry_index);
	let r = Digest::hash_bytes(&[b"qnero-test/entry-r", &entry_index.to_le_bytes()]);
	Note::new(pk, steps, rho, r).expect("value under the 62-bit bound")
}

#[test]
fn shield_burns_the_value_and_appends_the_commitment() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		let issuance_before = Balances::total_issuance();
		let keys = shielder_keys();
		let note = entry_note(keys.pk(), 100, 1, 0);
		let inner = note_inner(&keys.pk(), &note.rho, &note.r);

		assert_ok!(Shielded::shield(
			RuntimeOrigin::signed(alice()),
			100 * POOL_STEP,
			inner.to_bytes(),
			b"a note ciphertext".to_vec(),
		));

		// The chain computed `cm = H(CM, inner, value)` and it is the note's
		// own commitment.
		assert_eq!(ZkTree::leaf(0), Some(note.commitment().to_bytes()));
		assert_eq!(Shielded::pool_value(), 100 * POOL_STEP);
		assert_eq!(Shielded::entry_count(), 1);
		assert_eq!(Balances::total_issuance(), issuance_before - 100 * POOL_STEP);

		// The event carries everything a recipient needs: the ciphertext to
		// decrypt, and the `entry_index` half of the identifier its `rho` is
		// derived from. The other half is the block this event is in.
		System::assert_has_event(
			Event::Shielded {
				who: alice(),
				value: 100 * POOL_STEP,
				commitment: note.commitment().to_bytes(),
				leaf_index: 0,
				entry_index: 0,
				ciphertext: b"a note ciphertext".to_vec(),
			}
			.into(),
		);
	});
}

#[test]
fn shield_refuses_a_value_that_is_not_a_whole_step() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		assert_noop!(
			Shielded::shield(
				RuntimeOrigin::signed(alice()),
				POOL_STEP + 1,
				[1u8; 32],
				b"ct".to_vec()
			),
			Error::<Test>::ValueNotQuantized
		);
		assert_noop!(
			Shielded::shield(RuntimeOrigin::signed(alice()), 0, [1u8; 32], b"ct".to_vec()),
			Error::<Test>::ValueNotQuantized
		);
	});
}

/// The 62-bit range check. Every value entering the pool outside a spend has to
/// carry it, or the no-wrap argument behind the circuit's balance equation does
/// not hold for the notes created this way.
#[test]
fn shield_range_checks_the_value_to_62_bits() {
	new_test_ext_with_endowments(vec![(alice(), u128::MAX / 2)]).execute_with(|| {
		let over = (u128::from(qnero_circuit::chain::MAX_VALUE) + 1) * POOL_STEP;
		assert_noop!(
			Shielded::shield(RuntimeOrigin::signed(alice()), over, [1u8; 32], b"ct".to_vec()),
			Error::<Test>::ValueOutOfRange
		);
	});
}

#[test]
fn shield_refuses_a_non_canonical_inner() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		let mut alias = [0u8; 32];
		alias[..8].copy_from_slice(&pallet_zk_tree::tree::GOLDILOCKS_P.to_le_bytes());
		assert_noop!(
			Shielded::shield(RuntimeOrigin::signed(alice()), POOL_STEP, alias, b"ct".to_vec()),
			Error::<Test>::NonCanonicalInner
		);
	});
}

/// A different `entry_index` is a different `rho` is a different nullifier, so
/// two shields of the same value to the same key are two spendable notes rather
/// than one note and one stranded duplicate.
#[test]
fn two_shields_of_the_same_value_produce_different_commitments() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		let keys = shielder_keys();
		for entry_index in 0..2u64 {
			let note = entry_note(keys.pk(), 100, 1, entry_index);
			let inner = note_inner(&keys.pk(), &note.rho, &note.r);
			assert_ok!(Shielded::shield(
				RuntimeOrigin::signed(alice()),
				100 * POOL_STEP,
				inner.to_bytes(),
				b"ct".to_vec(),
			));
		}
		assert_ne!(ZkTree::leaf(0), ZkTree::leaf(1));
		assert_eq!(Shielded::entry_count(), 2);
	});
}

// ===========================================================================
// End to end: a real private batch proof through the extrinsic
// ===========================================================================

/// One `WalletProver` for the whole test binary. Building it is seconds and
/// proving with it is tens of seconds, so nothing here constructs a second.
fn wallet() -> &'static WalletProver {
	static WALLET: OnceLock<WalletProver> = OnceLock::new();
	WALLET.get_or_init(|| {
		WalletProver::new(circuit_config::NUM_LEAF_PROOFS).expect("the circuits build")
	})
}

/// Memoized proof bytes, keyed on everything a proof depends on: the height it
/// anchors at, its fee, and the tree root its input note's path reaches.
type ProofCache = BTreeMap<(u32, u64, [u8; 32]), Vec<u8>>;

/// A shielded note, the chain state that holds it, and a proof spending it.
struct Spend {
	proof: Vec<u8>,
	outputs: Vec<ShieldedOutput<Test>>,
}

/// Shield one note, settle the tree, publish a header at `anchored_at` whose
/// `zk_tree_root` is the settled root, and prove a spend of that note.
///
/// This is the whole chain the circuit's security rests on, assembled the way
/// a wallet assembles it: the public `block_hash` commits to a header, the
/// header carries the tree root, and the note's Merkle path reaches that root.
fn shield_and_prove(anchored_at: u32, fee: u64) -> Spend {
	let keys = shielder_keys();
	let note = entry_note(keys.pk(), 1_000, 1, 0);
	let inner = note_inner(&keys.pk(), &note.rho, &note.r);

	assert_ok!(Shielded::shield(
		RuntimeOrigin::signed(alice()),
		1_000 * POOL_STEP,
		inner.to_bytes(),
		b"the shielded note".to_vec(),
	));
	// A leaf appended this block is provable only after the block's fold, so a
	// note cannot be minted and spent in the same block.
	ZkTree::process_pending_leaves();

	let chain_proof = ZkTree::get_merkle_proof(0).expect("the settled leaf is provable");
	let siblings: Vec<[Digest; 3]> = chain_proof
		.siblings
		.iter()
		.map(|level| {
			[
				Digest::from_bytes(&level[0]).expect("canonical"),
				Digest::from_bytes(&level[1]).expect("canonical"),
				Digest::from_bytes(&level[2]).expect("canonical"),
			]
		})
		.collect();
	// The chain returns siblings in child-index order with no position; the
	// circuit wants them sorted plus the slot the running hash occupies.
	let path = MerklePath::from_unsorted(&siblings, note.commitment()).expect("path converts");
	let root = Digest::from_bytes(&ZkTree::root()).expect("canonical root");

	let header = HeaderInputs::new(
		Digest::hash_bytes(&[b"qnero-test/parent"]),
		anchored_at,
		[0u8; 32],
		[0u8; 32],
		root,
		&[0u8; DIGEST_LOGS_SIZE],
	)
	.expect("header digest logs are the documented length");
	frame_system::BlockHash::<Test>::insert(
		u64::from(anchored_at),
		H256::from(header.block_hash().to_bytes()),
	);
	System::set_block_number(u64::from(anchored_at) + 1);

	// Exact-length settlement ciphertexts, which is what the rule at the head
	// of `plan_settlement` requires. They are hashed into the witness's
	// `ct_digest` below, so these bytes are a proof input and not a literal the
	// fixtures can swap.
	let ct_1 = suite_ciphertext(0x01);
	let ct_2 = suite_ciphertext(0x02);
	let recipient = derive_pk(
		&Digest::hash_bytes(&[b"qnero-test/recipient-ask"]),
		&Digest::hash_bytes(&[b"qnero-test/recipient-nk"]),
	);
	let witness = SpendWitness {
		header,
		depth: path.depth(),
		inputs: [
			InputNote::real(&keys, &note, path).expect("a real input"),
			InputNote::dummy(
				&keys,
				Digest::hash_bytes(&[b"qnero-test/dummy-rho"]),
				Digest::hash_bytes(&[b"qnero-test/dummy-r"]),
				chain_proof.siblings.len(),
			),
		],
		outputs: [
			OutputNote::new(recipient, 600, Digest::hash_bytes(&[b"qnero-test/r-out"])),
			OutputNote::new(keys.pk(), 400 - fee, Digest::hash_bytes(&[b"qnero-test/r-change"])),
		],
		fee,
		ct_digest: Digest::from_bytes(&ct_digest(&[&ct_1, &ct_2])).expect("canonical"),
	};

	// Proving is the expensive part and the tests reuse a handful of identical
	// witnesses, so the bytes are memoized on everything the proof depends on.
	// The lock also keeps two provings from running at once: the harness runs
	// tests on as many threads as the machine has cores, and a private batch
	// peaks around a gigabyte.
	static PROOFS: Mutex<ProofCache> = Mutex::new(BTreeMap::new());
	let key = (anchored_at, fee, ZkTree::root());
	let mut proofs = PROOFS.lock().expect("no test panics while holding this");
	let proof = proofs
		.entry(key)
		.or_insert_with(|| {
			wallet().prove_submission_bytes(vec![witness]).expect("the batch proves")
		})
		.clone();
	drop(proofs);

	Spend { proof, outputs: vec![output(&ct_1, &ct_2)] }
}

#[test]
fn a_real_private_batch_settles_end_to_end() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		let root_before = ZkTree::root();

		// The size gate is a real bound and this is the proof kind a test
		// covers: `MAX_PROOF_BYTES` is applied before the blob is copied or
		// parsed, so a circuit change that pushed a private batch past it
		// would refuse every settlement. The public batch is measured at
		// `n = 53` (237544 bytes, M5) and verified through the embedded
		// verifier by `a_real_public_batch_verifies_through_the_embedded_verifier`,
		// but producing one costs a minute of CPU and about ten gigabytes, so
		// no default test holds it to the cap. That is the open half, recorded
		// at the constant and in `docs/BENCH.md`.
		assert!(
			spend.proof.len() <= crate::MAX_PROOF_BYTES,
			"a private batch serializes to {} bytes against a {} byte cap",
			spend.proof.len(),
			crate::MAX_PROOF_BYTES,
		);

		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof.clone(),
			spend.outputs.clone(),
		));

		// One real slot: two nullifiers settled, two commitments appended
		// after the shielded note's own leaf.
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 2);
		assert_eq!(ZkTree::leaf_count(), 3);

		// The tree root advances once the block's leaves are folded, and the
		// new leaves become provable then and not before.
		assert!(ZkTree::get_merkle_proof(1).is_err());
		ZkTree::process_pending_leaves();
		assert_ne!(ZkTree::root(), root_before);
		let proof = ZkTree::get_merkle_proof(1).expect("the new leaf is provable now");
		assert!(ZkTree::verify_proof(ZkTree::leaf(1).expect("leaf 1"), &proof));

		// The payload is in the extrinsic that carried it and nowhere else.
		assert!(no_ciphertext_key_exists(), "a settlement wrote a ciphertext into state");
	});
}

#[test]
fn a_settled_batch_cannot_be_replayed() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof.clone(),
			spend.outputs.clone(),
		));
		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof, spend.outputs),
			Error::<Test>::NullifierAlreadyUsed
		);
	});
}

/// Pool admission verifies. Nothing short of the verify establishes that a
/// proof's public inputs are a proof's: they are a plain vector in the
/// serialized blob, so a body-tampered clone of a genuine proof carries the
/// victim's nullifiers, passes the canonical-encoding round trip and the whole
/// settlement check, and would be admitted and re-gossiped by every node if
/// admission stopped short of the verify. It would also take the victim's
/// `provides` tag, which is derived from those same nullifiers, and under a
/// constant priority whichever arrived first would hold the pool slot.
///
/// The canonical-encoding round trip does not close this: it rejects other
/// encodings of one decoded proof and says nothing about a mutated proof
/// object, which is what the tamper below is. What verifying at admission buys
/// is that the blob stops at the first node it reaches. Without it the blob
/// travels the whole network and every node pays a settlement walk for it.
#[test]
fn an_unverifiable_proof_is_refused_at_pool_admission() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);

		// A byte in the proof body, well clear of the public-input tail, so the
		// settlement check sees exactly the values the genuine proof carries.
		let mut tampered = spend.proof.clone();
		tampered[spend.proof.len() / 3] ^= 0x01;
		assert_ne!(tampered, spend.proof);

		let genuine = crate::Call::submit_private_batch {
			proof: spend.proof.clone(),
			outputs: spend.outputs.clone(),
		};
		let forged =
			crate::Call::submit_private_batch { proof: tampered, outputs: spend.outputs.clone() };

		// The forgery and the genuine transaction are the same settlement as
		// far as every check short of the verify is concerned: same tag.
		let bundle = Shielded::pre_validate_private_batch(match &forged {
			crate::Call::submit_private_batch { proof, .. } => proof,
			_ => unreachable!(),
		})
		.expect("the public inputs still parse");
		assert_eq!(
			Shielded::settlement_provides_tag(&bundle),
			Shielded::settlement_provides_tag(
				&Shielded::pre_validate_private_batch(&spend.proof).expect("parses")
			),
			"the forgery would occupy the genuine settlement's pool slot"
		);
		assert_ok!(Shielded::check_settlement(&bundle, &spend.outputs));

		// Admission refuses it anyway, so it never enters a pool and is never
		// re-gossiped.
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&forged
		)
		.is_err());
		assert!(<Shielded as ValidateUnsigned>::pre_dispatch(&forged).is_err());
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&genuine
		)
		.is_ok());
	});
}

/// Pool admission decides what a submission settles before it verifies, and
/// binds the payload only after.
///
/// A settlement proof is public by construction: the extrinsic carrying it is
/// gossiped and old ones sit in finalized blocks. An attacker keeps the proof
/// byte identical, flips one byte of `outputs`, and has a transaction with a
/// new hash that no node has seen, so every node validates it fresh. There is
/// no proving work and no fee behind that, and it can be repeated as fast as
/// the blobs can be pushed.
///
/// For a settled proof, which is the variant that costs an attacker nothing at
/// all, every segment conflicts and `plan_settlement` refuses it on
/// `UsedNullifiers` reads alone: no FRI verification and not one byte of the
/// payload hashed, whatever the `outputs` carry. The payload binding is the one
/// term linear in the submitted bytes, and at the runtime's dimensions it is
/// the larger of it and the verify, so it runs behind the verify where a blob
/// that cannot settle never reaches it.
#[test]
fn a_replay_is_refused_before_the_verify_and_before_any_hashing() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);

		// A ciphertext variant of an unsettled proof. The cheap pass has
		// nothing to object to, because it does not look at the bytes.
		let mut variant = spend.outputs.clone();
		let mut bytes = variant[0].ct_1.to_vec();
		bytes[0] ^= 0x01;
		variant[0].ct_1 = BoundedVec::try_from(bytes).expect("the length did not change");

		let parsed = Shielded::pre_validate_private_batch(&spend.proof).expect("parses");
		assert_ok!(plan(&parsed, &variant));
		// The binding is what refuses it, and admission runs that after the
		// verify.
		assert_noop!(check(&parsed, &variant), Error::<Test>::CiphertextDigestMismatch);
		let call =
			crate::Call::submit_private_batch { proof: spend.proof.clone(), outputs: variant };
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&call
		)
		.is_err());

		// A settled proof is the free variant: the blob is in a finalized
		// block for anyone to copy, and its `outputs` can be anything at all.
		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof.clone(),
			spend.outputs.clone(),
		));
		let replayed = Shielded::pre_validate_private_batch(&spend.proof).expect("parses");

		// Junk `outputs` at the length settlement requires, and the refusal
		// still comes from the nullifier scan. Nothing here hashed the
		// payload: had the binding run first, this would be
		// `CiphertextDigestMismatch`. The exact-length rule sits in front of
		// the scan and reads three header bytes and a length, which is not a
		// sponge and is not what this test is about.
		let junk = vec![output(&suite_ciphertext(0x5a), &suite_ciphertext(0x5b))];
		assert_noop!(plan(&replayed, &junk), Error::<Test>::NullifierAlreadyUsed);
		assert_noop!(check(&replayed, &junk), Error::<Test>::NullifierAlreadyUsed);
		assert_noop!(check(&replayed, &spend.outputs), Error::<Test>::NullifierAlreadyUsed);

		// Junk padded to the ciphertext cap dies one step earlier, on the
		// length rule, which is cheaper still: it reads no storage at all.
		let over_long = vec![output(&capped_ciphertext(9), &capped_ciphertext(9))];
		assert_noop!(plan(&replayed, &over_long), Error::<Test>::CiphertextLengthMismatch);

		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&crate::Call::submit_private_batch { proof: spend.proof, outputs: junk }
		)
		.is_err());
	});
}

/// The cheap pass and the payload pass are genuinely split: `plan_settlement`
/// decides the whole submission without touching a ciphertext byte, and
/// `bind_payload` is what the bytes have to survive.
///
/// This is the ordering pool admission relies on. If the payload sponge crept
/// back into the cheap pass, a replay would pay it before the nullifier scan
/// could refuse it, and by the pallet's own weight constants that sponge is
/// larger than the verify the ordering exists to defer.
#[test]
fn the_cheap_pass_decides_a_settlement_without_hashing_the_payload() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);

		// Ciphertexts of the right lengths and the wrong bytes. The cheap pass
		// reads the lengths, for the fee floor and for the exact-length rule,
		// and the three header bytes that name the suite. It reads no more of
		// the payload than that and it sponges none of it.
		let wrong = vec![output(&suite_ciphertext(0x71), &suite_ciphertext(0x72))];
		let planned = plan(&bundle, &wrong).expect("the cheap pass passes");
		assert_eq!(planned.slots, 1);
		assert_eq!(planned.fee_steps, 9);
		assert_noop!(bind(&bundle, &wrong), Error::<Test>::CiphertextDigestMismatch);
		assert_noop!(check(&bundle, &wrong), Error::<Test>::CiphertextDigestMismatch);

		let right = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		assert_ok!(bind(&bundle, &right));
		assert_ok!(check(&bundle, &right));
	});
}

/// The dispatch body verifies, and this is the call that proves it: it reaches
/// the body directly, the way a general-format extrinsic does.
///
/// `ensure_none` is satisfied by any dispatch with no origin, and
/// `ExtrinsicFormat::General` reaches a call with `None` as its origin without
/// `ValidateUnsigned` running at all. That path is closed in the runtime today
/// by one transaction extension refusing a non-signed origin, which is a tuple
/// entry a future runtime may reorder or relax. What it would open, if the
/// body only parsed, is a settlement whose public inputs were rewritten
/// wholesale: attacker-chosen commitments appended as tree leaves with no
/// proof behind them.
#[test]
fn the_dispatch_body_refuses_a_proof_that_does_not_verify() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);

		// A byte in the proof body, clear of the public-input tail, so the
		// bundle the body builds is the genuine one and only the verify can
		// refuse it.
		let mut tampered = spend.proof.clone();
		tampered[spend.proof.len() / 3] ^= 0x01;
		assert_ok!(Shielded::pre_validate_private_batch(&tampered));

		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), tampered, spend.outputs.clone()),
			Error::<Test>::ProofVerificationFailed
		);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
		// The shielded note's own leaf and nothing else.
		assert_eq!(ZkTree::leaf_count(), 1);

		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof,
			spend.outputs,
		));
	});
}

/// The per-slot `ct_digest` is a byte sponge over kilobytes of note
/// ciphertext, and the weight has to charge for the bytes it actually absorbs.
/// This pins the weight's model against the encoding the real hasher uses: four
/// bytes per field element plus a terminator, eight field elements absorbed per
/// permutation.
#[test]
fn ciphertext_digest_permutations_match_the_hashed_bytes() {
	assert_eq!(weights::SPONGE_RATE as usize, qp_poseidon_core::SPONGE_RATE);

	// The middle pair is the only one settlement admits. The last is still
	// what the model has to be total over: the weight is declared from the
	// submitted vector, before the exact-length rule refuses it, and
	// `MaxCiphertextBytes` is what bounds that vector, since a larger
	// ciphertext fails the extrinsic's SCALE decode and never reaches the
	// weight path at all.
	let cap = <Test as crate::Config>::MaxCiphertextBytes::get() as usize;
	for (ct_1, ct_2) in [
		(vec![0u8; 0], vec![0u8; 0]),
		(
			vec![0u8; qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES],
			vec![0u8; qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES],
		),
		(vec![7u8; cap], vec![7u8; cap]),
	] {
		// The preimage `qnero_circuit::chain::ct_digest` builds.
		let mut preimage = Vec::new();
		preimage.extend_from_slice(b"qnero/ct");
		preimage.extend_from_slice(&2u32.to_le_bytes());
		for ct in [&ct_1, &ct_2] {
			preimage.extend_from_slice(&(ct.len() as u32).to_le_bytes());
			preimage.extend_from_slice(ct);
		}
		assert_eq!(
			preimage.len() as u64,
			weights::CT_DIGEST_FRAMING_BYTES + (ct_1.len() + ct_2.len()) as u64,
			"the weight's framing does not match the preimage"
		);

		let felts = qp_poseidon_core::serialization::bytes_to_felts(&preimage).len() as u64;
		let permutations = felts.div_ceil(weights::SPONGE_RATE);
		assert_eq!(
			weights::ct_digest_permutations((ct_1.len() + ct_2.len()) as u64),
			permutations,
			"charged permutations do not match the sponge over {} bytes",
			preimage.len()
		);
		// The digest itself has to be computable over these bytes, which is
		// what makes the count a real cost.
		let _ = ct_digest(&[&ct_1, &ct_2]);
	}
}

/// The chain's header hash and the circuit's must agree, or every settlement
/// fails `BlockHashMismatch` on the first real chain with nothing to say which
/// side moved.
///
/// The end-to-end test writes the circuit's own value into
/// `frame_system::BlockHash`, so it compares that encoding against itself. This
/// is the one place the two implementations meet.
#[test]
fn the_chain_header_hash_matches_the_circuits() {
	use codec::Encode;

	assert_eq!(qp_header::DIGEST_LOGS_SIZE, DIGEST_LOGS_SIZE);

	let parent = qp_poseidon_core::hash_bytes(b"qnero-test/parent-header");
	let zk_tree_root = qp_poseidon_core::hash_bytes(b"qnero-test/zk-tree-root");
	// Blake2 outputs, which need not be canonical field elements; both sides
	// reduce them through the same lossy decode.
	let state_root = [0xABu8; 32];
	let extrinsics_root = [0xCDu8; 32];

	let mut digest = sp_runtime::Digest::default();
	digest.push(sp_runtime::DigestItem::PreRuntime(qp_wormhole::POW_ENGINE_ID, vec![5u8; 32]));

	let header = qp_header::Header::<u64, sp_runtime::traits::BlakeTwo256>::new_with_zk_root(
		42,
		H256::from(extrinsics_root),
		H256::from(state_root),
		H256::from(parent),
		H256::from(zk_tree_root),
		digest.clone(),
	);

	// The chain pads the SCALE-encoded digest to the fixed window before
	// hashing it, and bytes past the window are not committed at all, which is
	// why the import path refuses a longer one.
	let encoded = digest.encode();
	assert!(encoded.len() <= DIGEST_LOGS_SIZE);
	let mut padded = [0u8; DIGEST_LOGS_SIZE];
	padded[..encoded.len()].copy_from_slice(&encoded);

	let circuit = HeaderInputs::new(
		Digest::from_bytes(&parent).expect("canonical"),
		42,
		state_root,
		extrinsics_root,
		Digest::from_bytes(&zk_tree_root).expect("canonical"),
		&padded,
	)
	.expect("the digest window is the documented length");

	assert_eq!(header.hash().as_bytes(), circuit.block_hash().to_bytes());
}

/// A tampered proof passes neither gate, and a byte variant of a genuine one is
/// a different transaction identity the canonical-encoding round trip refuses.
#[test]
fn a_tampered_proof_is_refused() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);

		let mut tampered = spend.proof.clone();
		let last = tampered.len() - 1;
		tampered[last] ^= 0x01;
		let call =
			crate::Call::submit_private_batch { proof: tampered, outputs: spend.outputs.clone() };
		assert!(<Shielded as ValidateUnsigned>::pre_dispatch(&call).is_err());

		// Trailing bytes are a different transaction identity for the same
		// proof, and plonky2's reader would accept them. The pallet names that
		// failure, which is the point of declaring it: an operator debugging a
		// rejected settlement can tell a byte-mangled proof from a genuine
		// public-input layout mismatch and from a proof built for other circuit
		// dimensions.
		let mut padded = spend.proof.clone();
		padded.push(0);
		assert!(matches!(
			Shielded::pre_validate_private_batch(&padded),
			Err(Error::<Test>::NonCanonicalProofEncoding)
		));
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&crate::Call::submit_private_batch { proof: padded, outputs: spend.outputs.clone() }
		)
		.is_err());

		// A truncated proof does not deserialize at all, which is also what a
		// proof built at another `N` looks like.
		let truncated = spend.proof[..spend.proof.len() / 2].to_vec();
		assert!(matches!(
			Shielded::pre_validate_private_batch(&truncated),
			Err(Error::<Test>::ProofDeserializationFailed)
		));

		// The genuine proof passes both.
		let good = crate::Call::submit_private_batch { proof: spend.proof, outputs: spend.outputs };
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&good
		)
		.is_ok());
		assert!(<Shielded as ValidateUnsigned>::pre_dispatch(&good).is_ok());
	});
}

/// A wrong-length payload is a permanent refusal, so it answers
/// `InvalidTransaction::Call` at both unsigned gates and never the
/// `ExhaustsResources` the ciphertext-cap deferral added.
///
/// The two answers mean opposite things to a block builder.
/// `ExhaustsResources` is "block full": the transaction is skipped and offered
/// again for the next block. `Call` is "invalid": it is dropped. A permanent
/// failure answered as a full block would have the builder re-skip a dead
/// transaction once a block until its longevity ran out, which is the mirror
/// image of the regression `a_full_block_defers_a_settlement_instead_of_dropping_it`
/// pins. This runs over a real proof, so what refuses the call is the length
/// rule and not the parse in front of it.
#[test]
fn a_wrong_length_payload_is_a_permanent_call_refusal() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		let exact = suite_ciphertext(0x41);
		let short = exact[..exact.len() - 1].to_vec();
		let mut unknown_suite = exact.clone();
		unknown_suite[1..3].copy_from_slice(&2u16.to_le_bytes());

		for (wrong, expected) in [
			(short, Error::<Test>::CiphertextLengthMismatch),
			(unknown_suite, Error::<Test>::UnknownCryptoSuite),
		] {
			let outputs = vec![output(&wrong, &wrong)];
			let call = crate::Call::submit_private_batch {
				proof: spend.proof.clone(),
				outputs: outputs.clone(),
			};
			assert_eq!(
				<Shielded as ValidateUnsigned>::pre_dispatch(&call),
				Err(InvalidTransaction::Call.into())
			);
			assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
				TransactionSource::External,
				&call
			)
			.is_err());
			// The dispatch body names the error the unsigned gates flatten.
			assert_noop!(
				Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof.clone(), outputs,),
				expected
			);
			assert_eq!(ZkTree::leaf_count(), 1);
		}

		// The genuine payload passes both gates, so what refused the two above
		// is the payload and not the proof.
		let good = crate::Call::submit_private_batch {
			proof: spend.proof.clone(),
			outputs: spend.outputs.clone(),
		};
		assert_ok!(<Shielded as ValidateUnsigned>::pre_dispatch(&good));
	});
}

/// A block already at its ciphertext cap defers a settlement and keeps it in
/// the pool.
///
/// The regression this pins: the capacity check used to run only inside
/// `check_settlement`, behind the ZK verify, and its failure was reported as
/// `InvalidTransaction::Call`. `sc-basic-authorship` reads a `Call` failure as
/// "this transaction is invalid" and drops it from the pool, so the first
/// settlement offered to a full block was destroyed with no event and never
/// retried. The gate now runs ahead of the verify and answers
/// `ExhaustsResources`, which the block builder reads as "block full": the
/// transaction is skipped and survives for the next block.
///
/// One single-slot settlement writes two ciphertexts
/// (`slots.saturating_mul(2)`), so at a cap of 2 the settlement fills a block
/// on its own. The two shields below are what make the block full ahead of it.
#[test]
fn a_full_block_defers_a_settlement_instead_of_dropping_it() {
	with_output_budget(|| {
		new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
			// Shields at block 1, publishes the anchor header at block 4 and
			// leaves the chain at block 5, whose ciphertext counter reads 0.
			let spend = shield_and_prove(4, 8);
			let call = crate::Call::submit_private_batch {
				proof: spend.proof.clone(),
				outputs: spend.outputs.clone(),
			};

			// Block 5 is empty, so the settlement's two ciphertexts fit.
			assert_ok!(<Shielded as ValidateUnsigned>::pre_dispatch(&call));

			// Two shields fill block 5 to the cap of 2.
			assert_ok!(budget_test_shield());
			assert_ok!(budget_test_shield());
			assert_eq!(crate::OutputsWrittenThisBlock::<Test>::get(), (5, 2));

			// The same settlement is now deferred, and the answer says so:
			// `ExhaustsResources` keeps it in the pool for the next block.
			assert_eq!(
				<Shielded as ValidateUnsigned>::pre_dispatch(&call),
				Err(InvalidTransaction::ExhaustsResources.into())
			);

			// The dispatch backstop is unchanged: a settlement that reaches
			// `settle` in a full block still fails on the pallet error, with
			// nothing written.
			assert_noop!(
				Shielded::submit_private_batch(
					RuntimeOrigin::none(),
					spend.proof.clone(),
					spend.outputs.clone(),
				),
				Error::<Test>::TooManyOutputsInBlock
			);

			// Next block, empty counter, same transaction. The anchor at block
			// 4 is still inside `BlockHashWindow` and `BlockHash(4)` is still
			// present, so nothing about the proof has gone stale.
			System::set_block_number(6);
			assert_ok!(<Shielded as ValidateUnsigned>::validate_unsigned(
				TransactionSource::External,
				&call
			));
			assert_ok!(<Shielded as ValidateUnsigned>::pre_dispatch(&call));
		});
	});
}

#[test]
fn a_real_batch_anchored_at_the_wrong_block_hash_is_refused() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		// Rewrite the block the proof anchors at. The proof still verifies;
		// what fails is the chain's binding of `block_hash` to the block at
		// `block_number`, which is what ties the tree root the proof used to a
		// root this chain actually published.
		frame_system::BlockHash::<Test>::insert(4u64, H256::from([9u8; 32]));
		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof, spend.outputs),
			Error::<Test>::BlockHashMismatch
		);
	});
}

#[test]
fn a_real_batch_with_swapped_ciphertexts_is_refused() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		// Two distinct exact-length blobs, so what the swap tests is still the
		// order binding and not the length rule in front of it.
		let swapped = vec![output(&suite_ciphertext(0x02), &suite_ciphertext(0x01))];
		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof, swapped),
			Error::<Test>::CiphertextDigestMismatch
		);
	});
}

#[test]
fn a_real_batch_below_the_minimum_fee_is_refused() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		MinLeafFee::set(5);
		let spend = shield_and_prove(4, 8);
		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof, spend.outputs),
			Error::<Test>::FeeBelowMinimum
		);
		MinLeafFee::set(1);
	});
}

/// The whole v1 fee path, over a real proof: the author's share of a settled
/// fee leaves the pool, waits, and comes back as part of the block's coinbase
/// note. No account balance moves anywhere along it.
#[test]
fn a_real_batch_pays_the_block_author_in_a_coinbase_note() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		let preimage = [11u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);
		let inner = record_coinbase(System::block_number() as u32);

		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof,
			spend.outputs,
		));
		// Eight steps: four burned, four held for this block's coinbase.
		assert_eq!(Balances::balance(&author), 0);
		assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);

		// The emission the miner would have been paid transparently, plus that
		// share, is the value of one note.
		assert_ok!(deposit_coinbase(2 * POOL_STEP));
		let leaf = ZkTree::leaf_count() - 1;
		assert_eq!(Shielded::coinbase_value(leaf), Some(6));
		assert_eq!(
			pallet_zk_tree::Leaves::<Test>::get(leaf),
			qnero_circuit::chain::commitment(&inner, 6)
		);
		assert_eq!(Balances::balance(&author), 0);
	});
}

/// `BatchLeafSlot::is_padding` asks whether *both* commitments are zero, so a
/// slot with one zero and one real commitment survives the padding filter. No
/// valid proof produces one, and the point of the check is that the append
/// fails before anything is written. A check reached halfway through the write
/// would leave the rollback to the dispatch layer.
#[test]
fn a_slot_with_one_zero_commitment_is_refused_before_any_write() {
	new_test_ext().execute_with(|| {
		let mut only = slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 3);
		only.commitments[1] = [0u8; 32];
		let bundle = one_segment(10, vec![only]);
		let outputs = vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))];
		assert_noop!(check(&bundle, &outputs), Error::<Test>::ZeroCommitment);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::ZeroCommitment);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
	});
}

// ===========================================================================
// The public batch at the chain default, through the embedded verifier
// ===========================================================================

/// Time `validate_public_batch` over a real `n = 53` proof.
///
/// Ignored, and it needs a proof: producing one is a full recursive run over
/// fifty-three inner private batches, which is a minute of CPU and about ten
/// gigabytes of peak memory, so it is not a thing a `cargo test` run should
/// do. `crates/qnero-wallet/tests/public_batch_bench.rs` produces one against
/// a dev chain and writes it to `target/qnero-public-batch-53.bin`; point
/// `QNERO_PUBLIC_BATCH_PROOF` somewhere else to use another.
///
/// What this measures is everything the chain pays before it settles
/// anything: the size gate, the deserialization against the embedded
/// verifier's circuit data, the canonical-encoding round trip, the ZK verify
/// and the public-input parse. The figure is native. A wasm runtime pays a
/// multiple of it, which is why the declared weight for a public-batch verify
/// is a ceiling chosen to be wrong in the safe direction (`weights.rs`).
///
/// It is also the first check that a proof produced at these dimensions is one
/// this runtime's embedded verifier accepts at all. The two are built from the
/// same circuit code and the same `N`, and nothing had ever tested that.
#[test]
#[ignore]
fn a_real_public_batch_verifies_through_the_embedded_verifier() {
	use std::time::Instant;

	let path = std::env::var("QNERO_PUBLIC_BATCH_PROOF").unwrap_or_else(|_| {
		format!("{}/../../../target/qnero-public-batch-53.bin", env!("CARGO_MANIFEST_DIR"))
	});
	// A missing artifact fails the test. This test is `#[ignore]`d
	// and only runs when someone asked for it by name, and it is the only
	// check that a proof produced at these dimensions is one the runtime's
	// embedded verifier accepts. Returning early printed `ok` on any tree
	// where the file is absent, which is every fresh clone and everything
	// after a `cargo clean`, since the artifact lives under `target/`.
	let proof = std::fs::read(&path).unwrap_or_else(|error| {
		panic!(
			"no public-batch proof at {path}: {error}\nProduce one with:\n  \
			 QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
			 -j 2 --release -p qnero-wallet --features parallel --test public_batch_bench -- \
			 --ignored --nocapture\nor point QNERO_PUBLIC_BATCH_PROOF at one."
		)
	});

	new_test_ext().execute_with(|| {
		assert!(
			proof.len() <= crate::MAX_PROOF_BYTES,
			"a public batch serializes to {} bytes against a {} byte cap",
			proof.len(),
			crate::MAX_PROOF_BYTES,
		);

		let started = Instant::now();
		let bundle = Shielded::validate_public_batch(&proof).expect("the public batch verifies");
		let elapsed = started.elapsed();

		println!("public batch proof            {} bytes", proof.len());
		println!("validate_public_batch native  {elapsed:.2?}");
		println!("settleable segments           {}", bundle.segments.len());
		println!(
			"real slots                    {}",
			bundle.segments.iter().map(|segment| segment.slots.len()).sum::<usize>()
		);

		// One real inner beside fifty-two padding ones: the padding segments
		// are dropped at the parse, so what survives is the one segment that
		// settles anything.
		assert_eq!(bundle.segments.len(), 1);
	});
}

// ===========================================================================
// The coinbase: the only way value is created at v1, genesis aside
// ===========================================================================

/// A coinbase note for the test's own key, as a block author's node builds one:
/// `rho` from the block number under the coinbase tag, `r` fresh, `inner` over
/// both. The value is not in `inner`, which is the property the whole design
/// rests on: the chain supplies the value and hashes `cm = H(CM, inner, value)`
/// itself.
fn coinbase_payload(block_number: u32) -> (Hash256, Digest, Digest) {
	let pk = shielder_keys().pk();
	let rho = qnero_note_core::coinbase_rho(block_number);
	let r = Digest::hash_bytes(&[b"qnero-test/coinbase-r", &block_number.to_le_bytes()]);
	(note_inner(&pk, &rho, &r).to_bytes(), rho, r)
}

/// Record a coinbase payload the way an inherent does, at the current block.
///
/// No ciphertext, which is what a Qnero node publishes: the note is derived
/// from the miner key the operator configured, so there is nothing to send.
fn record_coinbase(block_number: u32) -> Hash256 {
	let (inner, _, _) = coinbase_payload(block_number);
	assert_ok!(Shielded::coinbase(RuntimeOrigin::none(), inner, Vec::new()));
	inner
}

/// The sink call `pallet-mining-rewards` makes from its `on_finalize`.
fn deposit_coinbase(amount: u128) -> Result<(), u128> {
	<Shielded as qp_coinbase::CoinbaseSink<u128>>::deposit_coinbase(amount)
}

#[test]
fn a_block_mints_one_coinbase_note_worth_the_reward() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		let block = System::block_number() as u32;
		let inner = record_coinbase(block);

		assert_ok!(deposit_coinbase(7 * POOL_STEP));

		// The leaf the chain appended is the commitment over the author's
		// opaque `inner` and the value the chain decided.
		let expected = qnero_circuit::chain::commitment(&inner, 7).expect("canonical inner");
		assert_eq!(ZkTree::leaf_count(), 1);
		assert_eq!(pallet_zk_tree::Leaves::<Test>::get(0), Some(expected));
		assert_eq!(Shielded::coinbase_value(0), Some(7));
		assert_eq!(Shielded::leaf_block(0), Some(System::block_number()));
		assert_eq!(Shielded::pool_value(), 7 * POOL_STEP);
		System::assert_has_event(
			Event::CoinbaseMinted {
				block_number: System::block_number(),
				leaf_index: 0,
				inner,
				value: 7 * POOL_STEP,
				has_ciphertext: false,
			}
			.into(),
		);
		// Nothing transparent happened.
		assert_eq!(Balances::total_issuance(), 0);
	});
}

/// The value in the leaf is the chain's arithmetic over both books: the reward
/// the emission schedule handed over plus the author's share of every fee the
/// block settled.
#[test]
fn the_coinbase_note_carries_the_block_reward_and_the_author_fee_share() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		set_author_preimage([5u8; 32]);
		let block = System::block_number() as u32;
		let inner = record_coinbase(block);

		// Nine steps of fee: five burned, four to the author.
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_ok!(Shielded::settle(
			bundle,
			vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]
		));
		assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);

		assert_ok!(deposit_coinbase(7 * POOL_STEP));

		let leaf = ZkTree::leaf_count() - 1;
		assert_eq!(Shielded::coinbase_value(leaf), Some(11));
		let expected = qnero_circuit::chain::commitment(&inner, 11).expect("canonical inner");
		assert_eq!(pallet_zk_tree::Leaves::<Test>::get(leaf), Some(expected));
		assert_eq!(Shielded::pending_coinbase_fee(), 0);
		// The pool lost the whole fee and gained the coinbase note: 100 - 9 + 11.
		assert_eq!(Shielded::pool_value(), 102 * POOL_STEP);
	});
}

/// A zero credit still mints, when what the pool owes the author is already
/// inside it.
///
/// This is the end state the emission curve is heading for: supply reaches
/// `MaxSupply`, the block reward rounds to zero, and a block whose only traffic
/// is settlements collects no transaction fees either, because a settlement is
/// `Pays::No`. What that block does have is the author's share of the fees it
/// settled, waiting in `PendingCoinbaseFee`. It has to become a note here or it
/// never does: it left `PoolValue` on the way, `ShieldedSupply` counts it, and
/// nothing else drains it.
#[test]
fn a_zero_reward_still_mints_the_author_fee_already_in_the_pool() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		set_author_preimage([5u8; 32]);
		let block = System::block_number() as u32;
		let inner = record_coinbase(block);

		// Nine steps of fee: five burned, four to the author.
		let bundle =
			one_segment(10, vec![slot("a", &suite_ciphertext(0xa1), &suite_ciphertext(0xa2), 9)]);
		assert_ok!(Shielded::settle(
			bundle,
			vec![output(&suite_ciphertext(0xa1), &suite_ciphertext(0xa2))]
		));
		assert_eq!(Shielded::pending_coinbase_fee(), 4 * POOL_STEP);

		// No emission and no collected fees: exactly what a late-life block
		// hands over.
		assert_ok!(deposit_coinbase(0));

		let leaf = ZkTree::leaf_count() - 1;
		assert_eq!(Shielded::coinbase_value(leaf), Some(4), "the author's share is the note");
		assert_eq!(
			pallet_zk_tree::Leaves::<Test>::get(leaf),
			qnero_circuit::chain::commitment(&inner, 4)
		);
		assert_eq!(Shielded::pending_coinbase_fee(), 0);
		// 100 in, 9 of fee out, 4 back as the note.
		assert_eq!(Shielded::pool_value(), 95 * POOL_STEP);
	});
}

/// Two coinbase notes in one block would be two notes on one `rho`, because the
/// block number is the whole identifier the rule hashes. The refusal is a
/// mandatory dispatch failure, which is a dead block.
#[test]
fn a_second_coinbase_in_one_block_is_refused() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		let block = System::block_number() as u32;
		record_coinbase(block);
		let (inner, _, _) = coinbase_payload(block + 1);
		assert_noop!(
			Shielded::coinbase(RuntimeOrigin::none(), inner, Vec::new()),
			Error::<Test>::CoinbaseAlreadySet
		);
	});
}

/// A block with no author has nobody to pay.
#[test]
fn a_coinbase_without_a_block_author_is_refused() {
	new_test_ext().execute_with(|| {
		let (inner, _, _) = coinbase_payload(1);
		assert_noop!(
			Shielded::coinbase(RuntimeOrigin::none(), inner, b"ct".to_vec()),
			Error::<Test>::NoBlockAuthor
		);
	});
}

/// `on_finalize` cannot refuse anything, so the one field it hashes is checked
/// where a refusal is still possible.
#[test]
fn a_coinbase_inner_that_is_not_four_canonical_limbs_is_refused() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		assert_noop!(
			Shielded::coinbase(RuntimeOrigin::none(), [0xffu8; 32], Vec::new()),
			Error::<Test>::NonCanonicalInner
		);
		// An empty ciphertext is the ordinary case: a derived coinbase carries
		// no payload at all.
		assert_ok!(Shielded::coinbase(RuntimeOrigin::none(), coinbase_payload(1).0, Vec::new()));
	});
}

/// No inherent, no note. The credit goes back to the caller, which holds it for
/// the next block rather than minting it into nothing.
#[test]
fn a_block_with_no_coinbase_inherent_hands_the_reward_back() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		assert_eq!(deposit_coinbase(7 * POOL_STEP), Err(7 * POOL_STEP));
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(Shielded::pool_value(), 0);
		System::assert_has_event(Event::CoinbaseDeferred { amount: 7 * POOL_STEP }.into());
	});
}

/// A payload never outlives its block. If it did, the next block's inherent
/// would hit `CoinbaseAlreadySet` and die on a mandatory dispatch.
#[test]
fn the_previous_blocks_payload_is_cleared_before_the_next_inherent() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		record_coinbase(1);
		assert!(Shielded::pending_coinbase().is_some());

		<Shielded as frame_support::traits::Hooks<u64>>::on_initialize(2);
		assert!(Shielded::pending_coinbase().is_none());
		// And the block after can record its own.
		assert_ok!(Shielded::coinbase(RuntimeOrigin::none(), coinbase_payload(2).0, Vec::new()));
	});
}

/// Sub-step change cannot vanish: a note's value is a whole number of pool
/// steps and the remainder waits for the next block.
#[test]
fn sub_step_change_stays_for_the_next_coinbase() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		record_coinbase(1);
		assert_ok!(deposit_coinbase(7 * POOL_STEP + 3));
		assert_eq!(Shielded::coinbase_value(0), Some(7));
		assert_eq!(Shielded::pending_coinbase_fee(), 3);
		assert_eq!(Shielded::pool_value(), 7 * POOL_STEP);
	});
}

/// The inherent contract itself: every block owes one, the coinbase call is the
/// only inherent this pallet claims, and a settlement is not one.
#[test]
fn the_coinbase_is_a_required_inherent_and_the_settlements_are_not() {
	use frame_support::inherent::ProvideInherent;
	new_test_ext().execute_with(|| {
		let data = sp_inherents::InherentData::new();
		assert_eq!(
			<Shielded as ProvideInherent>::is_inherent_required(&data),
			Ok(Some(qp_coinbase::InherentError::Missing))
		);
		assert!(<Shielded as ProvideInherent>::is_inherent(&crate::Call::coinbase {
			inner: [0u8; 32],
			ciphertext: Vec::new(),
		}));
		assert!(!<Shielded as ProvideInherent>::is_inherent(&crate::Call::submit_private_batch {
			proof: Vec::new(),
			outputs: Vec::new()
		}));
		assert!(!<Shielded as ProvideInherent>::is_inherent(&crate::Call::submit_public_batch {
			proof: Vec::new(),
			outputs: Vec::new()
		}));
		// A node that supplied no payload builds no coinbase call, and the
		// block it builds is the one `is_inherent_required` refuses.
		assert!(<Shielded as ProvideInherent>::create_inherent(&data).is_none());
	});
}

/// The payload round-trips from inherent data to the call the author's node
/// puts in the block.
///
/// The ciphertext field survives on the wire, so the path is one `ensure!`
/// away when a builder exists, and the dispatch refuses what the mapping
/// carries: v1 accepts the empty field and nothing else.
#[test]
fn the_inherent_data_becomes_the_coinbase_call() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		let (inner, _, _) = coinbase_payload(4);
		let mut data = sp_inherents::InherentData::new();
		data.put_data(
			qp_coinbase::INHERENT_IDENTIFIER,
			&qp_coinbase::CoinbaseInherentData { inner, ciphertext: b"ct".to_vec() },
		)
		.expect("fresh inherent data");
		assert_eq!(
			<Shielded as frame_support::inherent::ProvideInherent>::create_inherent(&data),
			Some(crate::Call::coinbase { inner, ciphertext: b"ct".to_vec() })
		);
		assert_noop!(
			Shielded::coinbase(RuntimeOrigin::none(), inner, b"ct".to_vec()),
			Error::<Test>::CoinbasePayloadNotSupported
		);
	});
}

/// The other coinbase shape, an author paying an address whose coinbase
/// viewing key it does not hold, has no builder yet, so v1 refuses the field
/// it would ride in.
///
/// An inherent pays no fee and a mandatory dispatch does not compete for block
/// weight, so an accepted payload would be permanent state at no cost: the
/// settlement path charges `MinLeafFee + ceil(bytes / q)` for the same map,
/// and an author writing the cap on every block it wins would pay nothing for
/// bytes every full node keeps forever. One byte is as refused as the cap.
#[test]
fn a_coinbase_payload_has_no_builder_and_is_refused() {
	new_test_ext().execute_with(|| {
		set_author_preimage([3u8; 32]);
		let (inner, _, _) = coinbase_payload(System::block_number() as u32);
		for payload in [
			b"x".to_vec(),
			vec![0u8; MaxCiphertextBytes::get() as usize],
			vec![0u8; (MaxCiphertextBytes::get() + 1) as usize],
		] {
			assert_noop!(
				Shielded::coinbase(RuntimeOrigin::none(), inner, payload),
				Error::<Test>::CoinbasePayloadNotSupported
			);
		}

		// The empty field is the one a node publishes, and it still works.
		assert_ok!(Shielded::coinbase(RuntimeOrigin::none(), inner, Vec::new()));
		assert_ok!(deposit_coinbase(3 * POOL_STEP));
		assert_eq!(Shielded::coinbase_value(0), Some(3));
		System::assert_has_event(
			Event::CoinbaseMinted {
				block_number: System::block_number(),
				leaf_index: 0,
				inner,
				value: 3 * POOL_STEP,
				has_ciphertext: false,
			}
			.into(),
		);
	});
}

/// The coinbase is an inherent, so it has to pass the gate every bare
/// extrinsic passes on its way into a block, and it must not pass the one that
/// admits a transaction into a pool.
///
/// The regression this pins cost a chain: `pre_dispatch` refused every call
/// that was not a settlement, the block builder dropped the inherent it had
/// just created, and every block it then proposed was refused by its own
/// import with "the block carries no coinbase inherent". The node mined
/// nothing at all.
#[test]
fn the_coinbase_passes_pre_dispatch_and_never_enters_the_pool() {
	new_test_ext().execute_with(|| {
		let call = crate::Call::<Test>::coinbase { inner: [0u8; 32], ciphertext: Vec::new() };
		assert_ok!(<Shielded as ValidateUnsigned>::pre_dispatch(&call));
		assert_eq!(
			<Shielded as ValidateUnsigned>::validate_unsigned(TransactionSource::External, &call),
			Err(InvalidTransaction::Call.into()),
			"a coinbase belongs to the block its author is building"
		);
	});
}
