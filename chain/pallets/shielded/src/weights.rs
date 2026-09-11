//! Weights for `pallet-shielded`.
//!
//! **TODO(M5): these are calibrated constants. No benchmark has produced
//! them.** What is here is built the way `pallet-wormhole`'s weights are
//! built, from measured proof-verification times and from the storage
//! operations a settlement performs, so a runtime has a defensible ceiling to
//! meter against before the benchmarks land. Two figures carry real
//! uncertainty and are marked below: the public-batch verify, which has never
//! been measured at the chain's dimensions, and the per-slot storage cost,
//! which is derived arithmetic over a table of database operations.
//!
//! The private-batch verify is measured: 4.2 ms at `N = 7` on the development
//! workstation (`docs/BENCH.md`), and verification is flat in `N`, which is the
//! property that makes the recursion worth its proving cost.

use core::marker::PhantomData;

use frame_support::{traits::Get, weights::Weight};

/// Reference time of one private-batch proof verification, in picoseconds.
///
/// Measured (`docs/BENCH.md`, M3): 4.1 to 4.2 ms, single threaded and with
/// rayon, over a batch of six or seven leaf slots. Rounded up to 5 ms.
pub const PRIVATE_BATCH_VERIFY_REF_TIME_PS: u64 = 5_000_000_000;

/// Reference time of one public-batch proof verification, in picoseconds.
///
/// **Not measured.** The public batch has never been built or timed at the
/// chain default of 53 inner proofs; M3 exercised it at two. Upstream's
/// comparable circuit verifies in about 11 ms at eight inner proofs and its
/// pallet meters 21 ms, and the Qnero public batch is the same shape with a
/// wider forwarded public-input region, whose parse is linear in `n * N`. 30 ms
/// is a ceiling chosen to be wrong in the safe direction. Re-measure before a
/// public network.
pub const PUBLIC_BATCH_VERIFY_REF_TIME_PS: u64 = 30_000_000_000;

/// Reference time of the cheap pre-validation that runs in the dispatch body
/// after `pre_dispatch` has already verified: deserialize, canonical-encoding
/// round trip, public-input parse. Roughly a fifth of a verify.
pub const PRE_VALIDATE_REF_TIME_PS: u64 = 1_000_000_000;

/// Reference time of one Poseidon2 permutation, matching `pallet-zk-tree`.
pub const POSEIDON_EVAL_REF_TIME_PS: u64 = pallet_zk_tree::POSEIDON_EVAL_REF_TIME_PS;

/// Proof-of-validity size charged per storage key touched, matching
/// `pallet-zk-tree`'s figure for a tree key.
pub const KEY_POV: u64 = pallet_zk_tree::TREE_KEY_POV;

/// Storage operations one real leaf slot performs, beyond the tree's own.
///
/// Reads: two `UsedNullifiers` probes. Writes: two `UsedNullifiers`, two
/// `Ciphertexts`, two `LeafBlocks`.
const SLOT_DB_OPS: (u64, u64) = (2, 6);

/// Poseidon2 permutations one real leaf slot costs outside the tree: the
/// ciphertext digest over two note ciphertexts, which the byte sponge absorbs
/// at a rate of eight felts.
const SLOT_POSEIDON_EVALS: u64 = 6;

pub trait WeightInfo {
	/// `slots` is the number of real leaf slots, which is the number of
	/// `ShieldedOutput`s the call carries.
	fn submit_private_batch(slots: u32) -> Weight;
	fn submit_public_batch(slots: u32) -> Weight;
	fn shield() -> Weight;
}

/// Weight of settling `slots` real leaf slots, excluding the proof
/// verification.
fn settlement_weight<T: frame_system::Config>(slots: u32) -> Weight {
	let slots = u64::from(slots);
	// Two tree leaves per slot, plus at most one wormhole leaf for the block
	// author's fee share.
	let leaves = slots.saturating_mul(2).saturating_add(1);
	let (tree_reads, tree_writes) = pallet_zk_tree::INSERT_LEAF_DB_OPS;
	let (slot_reads, slot_writes) = SLOT_DB_OPS;

	let reads = leaves
		.saturating_mul(tree_reads)
		.saturating_add(slots.saturating_mul(slot_reads))
		// `PoolValue`, `EntryCount`, the digest logs for the author lookup.
		.saturating_add(3);
	let writes = leaves
		.saturating_mul(tree_writes)
		.saturating_add(slots.saturating_mul(slot_writes))
		// `PoolValue`, and the author's balance.
		.saturating_add(2);

	let hashing = leaves
		.saturating_mul(pallet_zk_tree::INSERT_LEAF_POSEIDON_EVALS)
		.saturating_add(slots.saturating_mul(SLOT_POSEIDON_EVALS))
		.saturating_mul(POSEIDON_EVAL_REF_TIME_PS);

	<T as frame_system::Config>::DbWeight::get()
		.reads_writes(reads, writes)
		.saturating_add(Weight::from_parts(hashing, reads.saturating_mul(KEY_POV)))
}

pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn submit_private_batch(slots: u32) -> Weight {
		Weight::from_parts(
			PRIVATE_BATCH_VERIFY_REF_TIME_PS.saturating_add(PRE_VALIDATE_REF_TIME_PS),
			0,
		)
		.saturating_add(settlement_weight::<T>(slots))
	}

	fn submit_public_batch(slots: u32) -> Weight {
		Weight::from_parts(
			PUBLIC_BATCH_VERIFY_REF_TIME_PS.saturating_add(PRE_VALIDATE_REF_TIME_PS),
			0,
		)
		.saturating_add(settlement_weight::<T>(slots))
	}

	fn shield() -> Weight {
		let (tree_reads, tree_writes) = pallet_zk_tree::INSERT_LEAF_DB_OPS;
		// Reads: the signer's account, `EntryCount`, `PoolValue`, plus the
		// tree's. Writes: the signer's account, `EntryCount`, `PoolValue`,
		// `Ciphertexts`, `LeafBlocks`, plus the tree's.
		let reads = tree_reads.saturating_add(3);
		let writes = tree_writes.saturating_add(5);
		let hashing = pallet_zk_tree::INSERT_LEAF_POSEIDON_EVALS
			.saturating_add(1)
			.saturating_mul(POSEIDON_EVAL_REF_TIME_PS);
		<T as frame_system::Config>::DbWeight::get()
			.reads_writes(reads, writes)
			.saturating_add(Weight::from_parts(hashing, reads.saturating_mul(KEY_POV)))
	}
}

/// Marginal cost of one real leaf slot in the `()` impl, in picoseconds.
///
/// Two nullifier writes, two tree appends with their Poseidon2 work, two
/// ciphertext writes and a digest over two ciphertexts. Well under a
/// millisecond in practice; 200 microseconds is the placeholder, and it is
/// deliberately far below a proof verification, which is the shape the real
/// numbers have to keep.
const SLOT_REF_TIME_PS: u64 = 200_000_000;

/// For mocks and for a runtime that has not wired its own.
impl WeightInfo for () {
	fn submit_private_batch(slots: u32) -> Weight {
		Weight::from_parts(
			PRIVATE_BATCH_VERIFY_REF_TIME_PS
				.saturating_add(PRE_VALIDATE_REF_TIME_PS)
				.saturating_add(u64::from(slots).saturating_mul(SLOT_REF_TIME_PS)),
			0,
		)
	}

	fn submit_public_batch(slots: u32) -> Weight {
		Weight::from_parts(
			PUBLIC_BATCH_VERIFY_REF_TIME_PS
				.saturating_add(PRE_VALIDATE_REF_TIME_PS)
				.saturating_add(u64::from(slots).saturating_mul(SLOT_REF_TIME_PS)),
			0,
		)
	}

	fn shield() -> Weight {
		Weight::from_parts(SLOT_REF_TIME_PS, 0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Whatever the numbers turn out to be, the shape has to hold: settling
	/// more slots costs more, and a public batch costs at least what a private
	/// batch of the same slot count does, because it verifies a larger proof
	/// over the same settlement work.
	#[test]
	fn settlement_weight_is_monotonic_in_the_slot_count() {
		for slots in 0u32..8 {
			let private = <() as WeightInfo>::submit_private_batch(slots);
			let public = <() as WeightInfo>::submit_public_batch(slots);
			assert!(public.ref_time() >= private.ref_time());
			if slots > 0 {
				assert!(
					private.ref_time() >
						<() as WeightInfo>::submit_private_batch(slots - 1).ref_time()
				);
			}
		}
	}

	/// The verify dominates a full batch. This is the shape the real
	/// benchmarks have to keep: if a settlement's storage work ever outgrew
	/// the proof verification, a fixed verify cost per call would stop being
	/// the right way to meter one.
	#[test]
	fn the_proof_verification_dominates_a_full_batch() {
		let full = <() as WeightInfo>::submit_private_batch(6).ref_time();
		let settlement = full - PRIVATE_BATCH_VERIFY_REF_TIME_PS - PRE_VALIDATE_REF_TIME_PS;
		assert!(
			settlement < PRIVATE_BATCH_VERIFY_REF_TIME_PS,
			"settling six slots costs {settlement} ps against a {PRIVATE_BATCH_VERIFY_REF_TIME_PS} ps verify"
		);
	}
}
