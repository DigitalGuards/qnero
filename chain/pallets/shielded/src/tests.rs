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
use sp_runtime::{traits::ValidateUnsigned, transaction_validity::TransactionSource};

use crate::{
	circuit_config, mock::*, padding_block_hash, weights, Error, Event, Hash256, RealSlot, Segment,
	SettlementBundle, ShieldedOutput, POOL_QUANTUM,
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

/// Stand `quanta` of pool value behind a synthetic settlement.
///
/// A settled fee leaves the pool, and the pallet refuses a fee larger than the
/// pool is holding, and refuses the settlement when it is not.
/// The end-to-end tests shield for real; these hand-built bundles have no
/// entry, so they seed the counter directly.
fn fund_pool(quanta: u128) {
	crate::PoolValue::<Test>::put(quanta * POOL_QUANTUM);
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
		let plan = check(&bundle, &outputs).expect("valid");
		assert_eq!(plan.fee_quanta, 3);
		assert_eq!(plan.slots, 1);
	});
}

#[test]
fn a_nullifier_already_settled_is_refused() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
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
		let shared = slot("a", b"ct-a1", b"ct-a2", 3);
		let mut second = slot("b", b"ct-b1", b"ct-b2", 3);
		second.nullifiers[0] = shared.nullifiers[1];

		let bundle = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![shared.clone()] },
				Segment { block_hash, block_number: 10, slots: vec![second.clone()] },
			],
		};
		let outputs = vec![output(b"ct-a1", b"ct-a2"), output(b"ct-b1", b"ct-b2")];

		let plan = check(&bundle, &outputs).expect("the first segment settles");
		assert_eq!(plan.settles, vec![true, false]);
		assert_eq!(plan.slots, 1);
		assert_eq!(plan.fee_quanta, 3);

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
		let mut only = slot("a", b"ct-a1", b"ct-a2", 3);
		only.nullifiers[1] = only.nullifiers[0];
		let bundle = one_segment(10, vec![only]);
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"ct-a2")]),
			Error::<Test>::DuplicateNullifier
		);
	});
}

#[test]
fn the_zero_nullifier_never_enters_the_set() {
	new_test_ext().execute_with(|| {
		let mut only = slot("a", b"ct-a1", b"ct-a2", 3);
		only.nullifiers[0] = [0u8; 32];
		let bundle = one_segment(10, vec![only]);
		assert_noop!(check(&bundle, &[output(b"ct-a1", b"ct-a2")]), Error::<Test>::ZeroNullifier);
	});
}

#[test]
fn a_segment_anchored_at_the_wrong_block_hash_is_refused() {
	new_test_ext().execute_with(|| {
		let mut bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		bundle.segments[0].block_hash = digest_bytes_of("some other block");
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"ct-a2")]),
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
				slots: vec![slot("a", b"ct-a1", b"ct-a2", 3)],
			}],
		};
		assert_noop!(check(&bundle, &[output(b"ct-a1", b"ct-a2")]), Error::<Test>::BlockNotFound);
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
				slots: vec![slot("a", b"ct-a1", b"ct-a2", 3)],
			}],
		};
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"ct-a2")]),
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
				slots: vec![slot("a", b"ct-a1", b"ct-a2", 3)],
			}],
		};
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"ct-a2")]),
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"tampered")]),
			Error::<Test>::CiphertextDigestMismatch
		);
		// Swapping the two is a different digest as well, which is what binds
		// `ct_1` to `cm_1`.
		assert_noop!(
			check(&bundle, &[output(b"ct-a2", b"ct-a1")]),
			Error::<Test>::CiphertextDigestMismatch
		);
	});
}

#[test]
fn the_output_count_must_equal_the_real_slot_count() {
	new_test_ext().execute_with(|| {
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		assert_noop!(check(&bundle, &[]), Error::<Test>::CiphertextCountMismatch);
		assert_noop!(
			check(&bundle, &[output(b"ct-a1", b"ct-a2"), output(b"extra", b"extra")]),
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 0)]);
		assert_noop!(check(&bundle, &[output(b"ct-a1", b"ct-a2")]), Error::<Test>::FeeBelowMinimum);
	});
}

#[test]
fn settling_appends_two_leaves_per_slot_and_stores_their_ciphertexts() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let bundle = one_segment(
			10,
			vec![slot("a", b"ct-a1", b"ct-a2", 3), slot("b", b"ct-b1", b"ct-b2", 5)],
		);
		let outputs = vec![output(b"ct-a1", b"ct-a2"), output(b"ct-b1", b"ct-b2")];
		assert_ok!(Shielded::settle(bundle.clone(), outputs));

		assert_eq!(ZkTree::leaf_count(), 4);
		for (index, slot) in bundle.segments[0].slots.iter().enumerate() {
			let first = index as u64 * 2;
			// leaf_hash = cm, with nothing recomputed.
			assert_eq!(ZkTree::leaf(first), Some(slot.commitments[0]));
			assert_eq!(ZkTree::leaf(first + 1), Some(slot.commitments[1]));
			assert_eq!(Shielded::leaf_block(first), Some(System::block_number()));
		}
		assert_eq!(Shielded::ciphertext(0).map(|c| c.to_vec()), Some(b"ct-a1".to_vec()));
		assert_eq!(Shielded::ciphertext(3).map(|c| c.to_vec()), Some(b"ct-b2".to_vec()));

		// Half of the eight-quantum fee burns and half goes to the author,
		// who is absent here, so the whole fee simply leaves the pool.
		System::assert_has_event(
			Event::BatchSettled { segments: 1, slots: 2, fee: 8 * POOL_QUANTUM }.into(),
		);
	});
}

#[test]
fn the_block_author_is_paid_its_share_of_a_settled_fee() {
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
			100 * POOL_QUANTUM,
			note_inner(&shielder_keys().pk(), &entry_rho(1, 0), &Digest::hash_bytes(&[b"r"]))
				.to_bytes(),
			b"ct".to_vec(),
		));
		let issuance_before = Balances::total_issuance();

		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 9)]);
		assert_ok!(Shielded::settle(bundle, vec![output(b"ct-a1", b"ct-a2")]));

		// Nine quanta, burn rounds up against the author: five burned, four
		// credited.
		assert_eq!(Balances::balance(&author), 4 * POOL_QUANTUM);
		System::assert_has_event(Event::AuthorFeePaid { author, amount: 4 * POOL_QUANTUM }.into());
		// The whole fee left the pool and only the author's share came back
		// into issuance; the burned half is the issuance the shield removed and
		// never restored.
		assert_eq!(Shielded::pool_value(), 91 * POOL_QUANTUM);
		assert_eq!(Balances::total_issuance(), issuance_before + 4 * POOL_QUANTUM);
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
		assert_noop!(check(&bundle, &outputs), Error::<Test>::PoolUnderflow);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::PoolUnderflow);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
		assert_eq!(Shielded::pool_value(), 2 * POOL_QUANTUM);
	});
}

/// The author's fee share must not emit an event the runtime's
/// `WormholeProofRecorderExtension` scans for.
///
/// That extension turns a `Balances::Minted` (and a `Transfer`) into a wormhole
/// transfer leaf of its own, and this pallet records the author's leaf itself,
/// so `Mutate::mint_into` here would credit one balance against two independent
/// leaves and let the author exit twice what it was paid. `pallet-wormhole`
/// carries the same rule and the same test.
#[test]
fn the_author_fee_credit_emits_no_scannable_balance_event() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		let preimage = [13u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);

		System::reset_events();
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 9)]);
		assert_ok!(Shielded::settle(bundle, vec![output(b"ct-a1", b"ct-a2")]));
		assert_eq!(Balances::balance(&author), 4 * POOL_QUANTUM, "the credit did happen");

		for record in System::events() {
			assert!(
				!matches!(
					record.event,
					RuntimeEvent::Balances(pallet_balances::Event::Minted { .. }) |
						RuntimeEvent::Balances(pallet_balances::Event::Transfer { .. })
				),
				"a settlement emitted a balance event the wormhole recorder scans for: {:?}",
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
	write_digest(&mut felts, slot_ct_digest_index(0), &ct_digest(&[b"ct-1", b"ct-2"]));
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
	write_digest(&mut felts, slot_ct_digest_index(0), &ct_digest(&[b"ct-1", b"ct-2"]));

	let inputs = parse_private_batch_public_input_felts(&felts, 1).expect("the layout parses");
	let bundle = SettlementBundle::from_private_batch(&inputs);
	assert_eq!(bundle.segments[0].block_number, u32::MAX);

	new_test_ext().execute_with(|| {
		fund_pool(100);
		System::set_block_number(20);
		assert_noop!(
			check(&bundle, &[output(b"ct-1", b"ct-2")]),
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
		let first = slot("a", b"ct-a1", b"ct-a2", 3);
		let second = slot("b", b"ct-b1", b"ct-b2", 5);
		let outputs = vec![output(b"ct-a1", b"ct-a2"), output(b"ct-b1", b"ct-b2")];

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
		assert_eq!(plan.fee_quanta, 5);

		assert_ok!(Shielded::settle(batch.clone(), outputs.clone()));
		assert_eq!(ZkTree::leaf_count(), 4);
		assert_eq!(ZkTree::leaf(2), Some(second.commitments[0]));
		// The skipped segment's ciphertexts were not rewritten over the
		// earlier settlement's leaves, and the second segment's ciphertexts
		// landed against their own leaf indices.
		assert_eq!(Shielded::ciphertext(2).map(|c| c.to_vec()), Some(b"ct-b1".to_vec()));
		assert_eq!(Shielded::ciphertext(0).map(|c| c.to_vec()), Some(b"ct-a1".to_vec()));

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
		let griefed = slot("a", b"ct-a1", b"ct-a2", 3);
		let bystander = slot("b", b"ct-b1", b"ct-b2", 5);
		let other = slot("c", b"ct-c1", b"ct-c2", 7);

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
			output(b"ct-a1", b"ct-a2"),
			output(b"ct-b1", b"ct-b2"),
			output(b"ct-c1", b"ct-c2"),
		];

		let plan = check(&batch, &outputs).expect("the unaffected segments settle");
		assert_eq!(plan.settles, vec![false, true, true]);
		assert_eq!(plan.slots, 2);
		assert_eq!(plan.fee_quanta, 12);

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
		let settled = slot("a", b"ct-a1", b"ct-a2", 3);
		let fresh = slot("b", b"ct-b1", b"ct-b2", 5);
		crate::UsedNullifiers::<Test>::insert(settled.nullifiers[0], ());

		let batch = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![settled] },
				Segment { block_hash, block_number: 10, slots: vec![fresh] },
			],
		};
		// The skipped segment's position carries junk where the proof
		// committed to real ciphertexts.
		let padded = vec![output(&[9u8; 2_048], &[9u8; 2_048]), output(b"ct-b1", b"ct-b2")];
		assert_noop!(check(&batch, &padded), Error::<Test>::CiphertextDigestMismatch);

		let honest = vec![output(b"ct-a1", b"ct-a2"), output(b"ct-b1", b"ct-b2")];
		assert_ok!(check(&batch, &honest));
	});
}

/// The fee floor is linear in the payload, because the payload is what the
/// settlement writes into permanent state. The chain never parses these bytes
/// and `Ciphertexts` is never pruned, so a flat floor would buy as much state
/// as the ciphertext cap allows for one quantum.
///
/// The endpoints are what matter and they are pinned here: a pair at the
/// ciphertext cap has to cost strictly more than a pair at the real
/// `NoteCiphertext` size, or the divisor is wide enough that the term prices
/// none of the slack it exists to price and a settler pads to the cap for free.
#[test]
fn a_slot_pays_for_the_ciphertext_bytes_it_publishes() {
	new_test_ext().execute_with(|| {
		fund_pool(100);
		// Two 1500-byte ciphertexts: 3000 bytes, six started 512-byte units
		// over the flat minimum of one quantum.
		let big_1 = vec![1u8; 1_500];
		let big_2 = vec![2u8; 1_500];
		let outputs = vec![output(&big_1, &big_2)];

		let cheap = one_segment(10, vec![slot("a", &big_1, &big_2, 6)]);
		assert_noop!(check(&cheap, &outputs), Error::<Test>::FeeBelowMinimum);

		let paid = one_segment(11, vec![slot("a", &big_1, &big_2, 7)]);
		assert_ok!(check(&paid, &outputs));

		// A slot carrying almost nothing still pays the flat floor and no more.
		let small = one_segment(12, vec![slot("b", b"ct-b1", b"ct-b2", 2)]);
		assert_ok!(check(&small, &[output(b"ct-b1", b"ct-b2")]));

		// The two endpoints of the reachable band. A `NoteCiphertext` at the
		// chain's parameter set with an empty memo is 1731 bytes, pinned by
		// `an_empty_memo_ciphertext_serializes_to_1731_bytes` in
		// `qnero-pqcrypto`; the cap is read from the pallet's own config so
		// the two cannot drift apart.
		let cap = <Test as crate::Config>::MaxCiphertextBytes::get() as usize;
		let real_1 = vec![3u8; 1_731];
		let real_2 = vec![4u8; 1_731];
		let real_outputs = vec![output(&real_1, &real_2)];
		let padded_1 = vec![5u8; cap];
		let padded_2 = vec![6u8; cap];
		let padded_outputs = vec![output(&padded_1, &padded_2)];

		// A real pair settles at eight quanta.
		let real = one_segment(13, vec![slot("c", &real_1, &real_2, 8)]);
		assert_ok!(check(&real, &real_outputs));

		// A pair padded to the cap does not: the same fee is below its floor.
		let padded_cheap = one_segment(14, vec![slot("d", &padded_1, &padded_2, 8)]);
		assert_noop!(check(&padded_cheap, &padded_outputs), Error::<Test>::FeeBelowMinimum);

		let padded = one_segment(15, vec![slot("d", &padded_1, &padded_2, 9)]);
		assert_ok!(check(&padded, &padded_outputs));
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

/// A note for `pk` worth `quanta`, with its `rho` derived by the entry rule.
fn entry_note(pk: Digest, quanta: u64, block_number: u32, entry_index: u64) -> Note {
	let rho = entry_rho(block_number, entry_index);
	let r = Digest::hash_bytes(&[b"qnero-test/entry-r", &entry_index.to_le_bytes()]);
	Note::new(pk, quanta, rho, r).expect("value under the 62-bit bound")
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
			100 * POOL_QUANTUM,
			inner.to_bytes(),
			b"a note ciphertext".to_vec(),
		));

		// The chain computed `cm = H(CM, inner, value)` and it is the note's
		// own commitment.
		assert_eq!(ZkTree::leaf(0), Some(note.commitment().to_bytes()));
		assert_eq!(Shielded::pool_value(), 100 * POOL_QUANTUM);
		assert_eq!(Shielded::entry_count(), 1);
		assert_eq!(Balances::total_issuance(), issuance_before - 100 * POOL_QUANTUM);
		assert_eq!(
			Shielded::ciphertext(0).map(|c| c.to_vec()),
			Some(b"a note ciphertext".to_vec())
		);

		// The event carries everything a recipient needs: the ciphertext to
		// decrypt, and the `entry_index` half of the identifier its `rho` is
		// derived from. The other half is the block this event is in.
		System::assert_has_event(
			Event::Shielded {
				who: alice(),
				value: 100 * POOL_QUANTUM,
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
fn shield_refuses_a_value_that_is_not_a_whole_quantum() {
	new_test_ext_with_endowments(vec![(alice(), 1_000 * UNIT)]).execute_with(|| {
		assert_noop!(
			Shielded::shield(
				RuntimeOrigin::signed(alice()),
				POOL_QUANTUM + 1,
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
		let over = (u128::from(qnero_circuit::chain::MAX_VALUE) + 1) * POOL_QUANTUM;
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
			Shielded::shield(RuntimeOrigin::signed(alice()), POOL_QUANTUM, alias, b"ct".to_vec()),
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
				100 * POOL_QUANTUM,
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
		1_000 * POOL_QUANTUM,
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

	let ct_1 = b"output one ciphertext".to_vec();
	let ct_2 = b"output two ciphertext".to_vec();
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
		let spend = shield_and_prove(4, 2);
		let root_before = ZkTree::root();

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

		// Both output ciphertexts are stored against their own leaf index.
		assert_eq!(
			Shielded::ciphertext(1).map(|c| c.to_vec()),
			Some(b"output one ciphertext".to_vec())
		);
		assert_eq!(
			Shielded::ciphertext(2).map(|c| c.to_vec()),
			Some(b"output two ciphertext".to_vec())
		);
	});
}

#[test]
fn a_settled_batch_cannot_be_replayed() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 2);
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
		let spend = shield_and_prove(4, 2);

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
		let spend = shield_and_prove(4, 2);

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
		let junk = vec![output(&[9u8; 2_048], &[9u8; 2_048])];
		// Junk `outputs`, and the refusal still comes from the nullifier scan.
		// Nothing here hashed the payload: had the binding run first, this
		// would be `CiphertextDigestMismatch`.
		assert_noop!(plan(&replayed, &junk), Error::<Test>::NullifierAlreadyUsed);
		assert_noop!(check(&replayed, &junk), Error::<Test>::NullifierAlreadyUsed);
		assert_noop!(check(&replayed, &spend.outputs), Error::<Test>::NullifierAlreadyUsed);
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);

		// Ciphertexts of the right lengths and the wrong bytes. The cheap pass
		// reads the lengths, for the fee floor, and nothing else.
		let wrong = vec![output(b"ct-x1", b"ct-x2")];
		let planned = plan(&bundle, &wrong).expect("the cheap pass passes");
		assert_eq!(planned.slots, 1);
		assert_eq!(planned.fee_quanta, 3);
		assert_noop!(bind(&bundle, &wrong), Error::<Test>::CiphertextDigestMismatch);
		assert_noop!(check(&bundle, &wrong), Error::<Test>::CiphertextDigestMismatch);

		let right = vec![output(b"ct-a1", b"ct-a2")];
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
		let spend = shield_and_prove(4, 2);

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

	// The last pair is the reachable worst case: `MaxCiphertextBytes` bounds
	// each ciphertext on its own, so a larger one fails the extrinsic's SCALE
	// decode and never reaches the weight path.
	let cap = <Test as crate::Config>::MaxCiphertextBytes::get() as usize;
	for (ct_1, ct_2) in [
		(vec![0u8; 0], vec![0u8; 0]),
		(vec![0u8; 1_731], vec![0u8; 1_731]),
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
		let spend = shield_and_prove(4, 2);

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

#[test]
fn a_real_batch_anchored_at_the_wrong_block_hash_is_refused() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 2);
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
		let spend = shield_and_prove(4, 2);
		let swapped = vec![output(b"output two ciphertext", b"output one ciphertext")];
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
		let spend = shield_and_prove(4, 2);
		assert_noop!(
			Shielded::submit_private_batch(RuntimeOrigin::none(), spend.proof, spend.outputs),
			Error::<Test>::FeeBelowMinimum
		);
		MinLeafFee::set(1);
	});
}

#[test]
fn a_real_batch_pays_the_block_author() {
	new_test_ext_with_endowments(vec![(alice(), 10_000 * UNIT)]).execute_with(|| {
		let spend = shield_and_prove(4, 8);
		let preimage = [11u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);

		assert_ok!(Shielded::submit_private_batch(
			RuntimeOrigin::none(),
			spend.proof,
			spend.outputs,
		));
		// Eight quanta: four burned, four to the author.
		assert_eq!(Balances::balance(&author), 4 * POOL_QUANTUM);
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
		let mut only = slot("a", b"ct-a1", b"ct-a2", 3);
		only.commitments[1] = [0u8; 32];
		let bundle = one_segment(10, vec![only]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
		assert_noop!(check(&bundle, &outputs), Error::<Test>::ZeroCommitment);
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::ZeroCommitment);
		assert_eq!(ZkTree::leaf_count(), 0);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
	});
}
