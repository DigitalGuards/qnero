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
	chain::ct_digest,
	header::{HeaderInputs, DIGEST_LOGS_SIZE},
	merkle::MerklePath,
	witness::{InputNote, OutputNote, SpendWitness},
};
use qnero_note_core::{derive_pk, entry_rho, note_inner, DerivedKeys, Digest, Note};
use qnero_prover::WalletProver;
use sp_core::H256;
use sp_runtime::{traits::ValidateUnsigned, transaction_validity::TransactionSource};

use crate::{
	circuit_config, mock::*, padding_block_hash, Error, Event, Hash256, RealSlot, Segment,
	SettlementBundle, ShieldedOutput, POOL_QUANTUM,
};

// ===========================================================================
// Synthetic bundles: the settlement algebra
// ===========================================================================

fn digest_bytes_of(tag: &str) -> Hash256 {
	qp_poseidon_core::hash_bytes(tag.as_bytes())
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
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
		assert_ok!(check(&bundle, &outputs));

		crate::UsedNullifiers::<Test>::insert(bundle.segments[0].slots[0].nullifiers[1], ());
		assert_noop!(check(&bundle, &outputs), Error::<Test>::NullifierAlreadyUsed);
	});
}

/// The second nullifier of a slot is the one a mechanical port of upstream's
/// wrapper drops. A note spent from input slot 1 is marked used only if slot
/// 1's nullifier is settled, so both have to be in the set the chain checks
/// and writes.
#[test]
fn both_nullifiers_of_a_slot_are_checked_and_settled() {
	new_test_ext().execute_with(|| {
		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 3)]);
		let outputs = vec![output(b"ct-a1", b"ct-a2")];
		assert_ok!(Shielded::settle(bundle.clone(), outputs.clone()));

		for nullifier in bundle.segments[0].slots[0].nullifiers {
			assert!(crate::UsedNullifiers::<Test>::contains_key(nullifier));
		}
		// And the whole submission is a replay now.
		assert_noop!(check(&bundle, &outputs), Error::<Test>::NullifierAlreadyUsed);
	});
}

/// The private-batch circuit forbids a repeat inside one batch, so this is
/// unreachable through a valid private batch. It is reachable through a public
/// batch: nothing in that circuit compares the nullifiers of two different
/// inner proofs, which is `n * 2N` digests and not affordable in circuit.
#[test]
fn a_nullifier_repeated_across_two_segments_aborts_the_submission() {
	new_test_ext().execute_with(|| {
		let block_hash = anchor(10);
		let shared = slot("a", b"ct-a1", b"ct-a2", 3);
		let mut second = slot("b", b"ct-b1", b"ct-b2", 3);
		second.nullifiers[0] = shared.nullifiers[1];

		let bundle = SettlementBundle {
			segments: vec![
				Segment { block_hash, block_number: 10, slots: vec![shared] },
				Segment { block_hash, block_number: 10, slots: vec![second] },
			],
		};
		let outputs = vec![output(b"ct-a1", b"ct-a2"), output(b"ct-b1", b"ct-b2")];

		assert_noop!(check(&bundle, &outputs), Error::<Test>::DuplicateNullifier);
		// Nothing was written: the whole submission is refused before any
		// state changes, so the first segment's nullifiers are still free.
		assert_noop!(Shielded::settle(bundle, outputs), Error::<Test>::DuplicateNullifier);
		assert_eq!(crate::UsedNullifiers::<Test>::iter().count(), 0);
		assert_eq!(ZkTree::leaf_count(), 0);
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
	new_test_ext().execute_with(|| {
		let preimage = [7u8; 32];
		let author = author_of(preimage);
		set_author_preimage(preimage);
		assert_eq!(Balances::balance(&author), 0);

		let bundle = one_segment(10, vec![slot("a", b"ct-a1", b"ct-a2", 9)]);
		assert_ok!(Shielded::settle(bundle, vec![output(b"ct-a1", b"ct-a2")]));

		// Nine quanta, burn rounds up against the author: five burned, four
		// minted.
		assert_eq!(Balances::balance(&author), 4 * POOL_QUANTUM);
		System::assert_has_event(Event::AuthorFeePaid { author, amount: 4 * POOL_QUANTUM }.into());
	});
}

/// A padding slot's commitments are zero and its two nullifiers are hashes of
/// randomness drawn for that proving run. It settles nothing, and the parse is
/// where that is decided, so a settleable segment never carries one.
#[test]
fn a_padding_slot_is_dropped_at_the_parse() {
	new_test_ext().execute_with(|| {
		let sentinel = padding_block_hash();
		assert_ne!(sentinel, [0u8; 32]);
		// The sentinel is what the chain recognises padding by, and it is not
		// a hash any chain can produce.
		assert_eq!(
			hex::encode(sentinel),
			"34b4e468a910702ae5c6124a10a5ed2e2eea369e90faa8bb5244e83015939269"
		);
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

/// Pool admission does the cheap work; `pre_dispatch` is the block-inclusion
/// gate that runs the ZK verify. A tampered proof passes neither, and the
/// difference between them is what stops fee-free gossip forcing a verify per
/// byte variant.
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
		// proof, and plonky2's reader would accept them.
		let mut padded = spend.proof.clone();
		padded.push(0);
		assert!(<Shielded as ValidateUnsigned>::validate_unsigned(
			TransactionSource::External,
			&crate::Call::submit_private_batch { proof: padded, outputs: spend.outputs.clone() }
		)
		.is_err());

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
