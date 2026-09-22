//! Weights for `pallet-shielded`.
//!
//! These declarations require executor qualification on release hardware.
//! `docs/WASM-BUDGET.md` describes the offline WASM component gate. What is here is built the way
//! `pallet-wormhole`'s weights are built, from proof-verification times and from the storage
//! operations a settlement performs. `docs/BENCH.md` records the measured component costs;
//! full-block execution and admission capacity still require qualification.
//!
//! The constants retain their conservative estimates. Component measurements
//! on one workstation do not establish the complete release-hardware budget.

use core::marker::PhantomData;

use frame_support::{traits::Get, weights::Weight};

/// Factor between a native verify and the same verify inside the wasm runtime.
///
/// The node builds a `WasmExecutor` and nothing else, so the verification a
/// block import actually pays is plonky2 FRI over Goldilocks running under
/// wasmtime, without the native build's 64-bit multiply and SIMD paths. Weight
/// is what bounds block execution time, so a native figure under-declares the
/// dominant cost of every settlement by roughly this factor, and settlements
/// are `Pays::No`, so nobody pays the difference.
///
/// Five remains a conservative estimate. The runtime-WASM component harness
/// measures private and public verification at `N = 6` / `n = 53`; its record
/// is in `docs/BENCH.md`. Qualify full settlement and block execution on the
/// designated reference hardware before changing these declarations.
///
/// **Open issue, M5.** The same measurement owes an answer on the cost a
/// transaction pool absorbs that no weight bounds: admission pays one cheap
/// settlement walk plus one verify for every distinct gossiped settlement blob,
/// unpaid and unrate-limited, because nothing short of a verify establishes
/// that a proof's public inputs are a proof's. The walk is `plan_settlement`,
/// which is storage reads and integer comparisons and hashes nothing; the
/// payload sponge sits behind the verify, where a blob that fails the verify
/// never reaches it. `docs/CIRCUIT.md` section 9.11 carries the analysis. A
/// rejection cache keyed on the proof hash bounds the repeat case; it does not
/// bound distinct blobs.
pub const WASM_VERIFY_FACTOR: u64 = 5;

/// Reference time of one private-batch proof verification, in picoseconds.
///
/// Measured natively (`docs/BENCH.md`, M3): 4.1 to 4.2 ms, single threaded and
/// with rayon, over a batch of six or seven leaf slots. Rounded up to 5 ms and
/// multiplied by [`WASM_VERIFY_FACTOR`].
pub const PRIVATE_BATCH_VERIFY_REF_TIME_PS: u64 = 5_000_000_000 * WASM_VERIFY_FACTOR;

/// Reference time of one public-batch proof verification, in picoseconds.
///
/// Public verifier artifacts at 53 inner proofs are generated and pinned by
/// the release builder. The WASM budget harness also measures a valid public
/// proof; `docs/BENCH.md` records the artifact identities and observed costs.
/// Upstream's comparable circuit verifies in about 11 ms at eight inner proofs
/// and its pallet meters 21 ms, and the Qnero public batch is the same shape
/// with a wider forwarded public-input region, whose parse is linear in
/// `n * N`. 30 ms is a native ceiling chosen to be wrong in the safe direction,
/// multiplied by [`WASM_VERIFY_FACTOR`] like the private batch. Re-measure
/// before a public network.
pub const PUBLIC_BATCH_VERIFY_REF_TIME_PS: u64 = 30_000_000_000 * WASM_VERIFY_FACTOR;

/// Reference time of one proof parse: deserialize, canonical-encoding round
/// trip, public-input parse, and no cryptography. Roughly a fifth of a native
/// private-batch verify.
///
/// Two terms, because the parse of a public batch is not the parse of a
/// private batch. The blob round trip is the fixed part: a recursive proof is
/// about the same size whatever it wraps. What grows is the public-input
/// vector, which the round trip writes back and the layout parse walks:
/// `private_batch_pi_len(6)` is 131 felts against `public_batch_pi_len(53, 6)`
/// at 6947, and the parse allocates a slot per forwarded leaf. Charging one
/// flat constant for both under-declares the public batch; charging the flat
/// constant scaled by the felt ratio would over-declare it by a factor of
/// fifty, because the blob round trip does not scale with the public inputs.
///
/// These terms remain estimates. The WASM component harness checks their sum
/// at both release proof shapes. The per-felt estimate includes margin above
/// the native cost of copying and checking a field element.
pub const PRE_VALIDATE_BASE_REF_TIME_PS: u64 = 1_000_000_000 * WASM_VERIFY_FACTOR;

/// Reference time the parse spends per public-input field element. See
/// [`PRE_VALIDATE_BASE_REF_TIME_PS`].
pub const PRE_VALIDATE_PER_FELT_REF_TIME_PS: u64 = 100_000 * WASM_VERIFY_FACTOR;

/// Reference time of one proof parse over `pi_felts` public inputs.
pub const fn pre_validate_ref_time(pi_felts: u64) -> u64 {
	PRE_VALIDATE_BASE_REF_TIME_PS
		.saturating_add(pi_felts.saturating_mul(PRE_VALIDATE_PER_FELT_REF_TIME_PS))
}

/// Public inputs one private-batch proof carries, at this runtime's dimensions.
pub const PRIVATE_BATCH_PI_FELTS: u64 =
	qnero_circuit::batch_layout::private_batch_pi_len(crate::circuit_config::NUM_LEAF_PROOFS)
		as u64;

/// Public inputs one public-batch proof carries, at this runtime's dimensions.
pub const PUBLIC_BATCH_PI_FELTS: u64 = qnero_circuit::batch_layout::public_batch_pi_len(
	crate::circuit_config::NUM_PRIVATE_BATCH_PROOFS,
	crate::circuit_config::NUM_LEAF_PROOFS,
) as u64;

/// What one included settlement pays for verification and parsing.
///
/// Both happen twice. `ValidateUnsigned::pre_dispatch` parses and verifies as
/// the block-inclusion gate, and the dispatch body parses and verifies again,
/// because `ensure_none` alone does not establish that `ValidateUnsigned` ran:
/// a general-format extrinsic reaches a dispatch with no origin and no
/// `pre_dispatch`. See `Pallet::submit_private_batch`.
const fn verify_ref_time(verify: u64, pi_felts: u64) -> u64 {
	verify.saturating_add(pre_validate_ref_time(pi_felts)).saturating_mul(2)
}

/// Reference time of one Poseidon2 permutation, matching `pallet-zk-tree`.
pub const POSEIDON_EVAL_REF_TIME_PS: u64 = pallet_zk_tree::POSEIDON_EVAL_REF_TIME_PS;

/// Proof-of-validity size charged per storage key touched, matching
/// `pallet-zk-tree`'s figure for a tree key.
pub const KEY_POV: u64 = pallet_zk_tree::TREE_KEY_POV;

/// Field elements the byte sponge absorbs per Poseidon2 permutation
/// (`qp_poseidon_core::SPONGE_RATE`).
pub const SPONGE_RATE: u64 = 8;

/// Bytes the injective byte encoding packs into one field element
/// (`qp_poseidon_core::serialization::bytes_to_felts`, 4 bytes per felt plus a
/// one-byte terminator over the whole input).
pub const BYTES_PER_FELT: u64 = 4;

/// Fixed bytes of one slot's `ct_digest` preimage, outside the ciphertexts:
/// the eight-byte `"qnero/ct"` prefix, a `u32` count, and a `u32` length per
/// ciphertext. `ciphertext_digest_permutations_match_the_hashed_bytes` in the
/// pallet's tests pins this against what `qnero_circuit::chain::ct_digest`
/// actually builds.
pub const CT_DIGEST_FRAMING_BYTES: u64 = 8 + 4 + 4 + 4;

/// Storage operations one settling leaf slot performs, beyond the tree's own.
///
/// Reads: two `UsedNullifiers` probes, and the settlement check runs twice per
/// included extrinsic, once in `pre_dispatch` and once in the dispatch body's
/// `settle`, so the reads are charged twice. Writes happen once: two
/// `UsedNullifiers` and two `LeafBlocks`. The two ciphertext writes went with
/// the state copy of the payload, which now rides in the extrinsic alone.
pub const SLOT_DB_OPS: (u64, u64) = (4, 4);

/// Permutations the `ct_digest` of one slot costs, given the bytes of its two
/// ciphertexts.
///
/// The sponge absorbs [`SPONGE_RATE`] field elements per permutation and the
/// encoding packs [`BYTES_PER_FELT`] bytes into each, so this is linear in the
/// payload and independent of the slot count. Charging a constant here is what
/// under-priced a settlement by a factor of eighteen to forty-three: a slot
/// carries kilobytes of ML-KEM and AEAD ciphertext.
pub const fn ct_digest_permutations(ciphertext_bytes: u64) -> u64 {
	let bytes = CT_DIGEST_FRAMING_BYTES.saturating_add(ciphertext_bytes);
	// `+ 1` is the encoding's terminator byte.
	let felts = bytes.saturating_add(1).div_ceil(BYTES_PER_FELT);
	felts.div_ceil(SPONGE_RATE)
}

/// Poseidon2 reference time a settlement's ciphertext digests cost.
///
/// `ciphertext_bytes` is the whole submission's payload and `slots` its slot
/// count, so the framing is charged per slot and the payload once. One extra
/// permutation per slot covers the per-slot rounding, which cannot be shared
/// because every slot's sponge is finalized on its own; that makes this an
/// upper bound on the sum of [`ct_digest_permutations`] over the slots,
/// whatever the payload split between them. Doubled: an included settlement
/// binds its payload twice, once in `pre_dispatch` and once in the dispatch
/// body, and both recompute every digest.
pub const fn ct_digest_ref_time(slots: u64, ciphertext_bytes: u64) -> u64 {
	let per_slot_framing = slots.saturating_mul(CT_DIGEST_FRAMING_BYTES.saturating_add(1));
	let felts = per_slot_framing.saturating_add(ciphertext_bytes).div_ceil(BYTES_PER_FELT);
	felts
		.div_ceil(SPONGE_RATE)
		.saturating_add(slots)
		.saturating_mul(POSEIDON_EVAL_REF_TIME_PS)
		.saturating_mul(2)
}

pub trait WeightInfo {
	/// `slots` is the number of real leaf slots, which is the number of
	/// `ShieldedOutput`s the call carries, and `ciphertext_bytes` their total
	/// payload. The payload is a weight term of its own: the per-slot
	/// `ct_digest` is a byte sponge over it, and the bytes remain in the
	/// archived block body, which is now the only copy.
	fn submit_private_batch(slots: u32, ciphertext_bytes: u32) -> Weight;
	fn submit_public_batch(slots: u32, ciphertext_bytes: u32) -> Weight;
	/// `ciphertext_bytes` is the one ciphertext a shield carries in its own
	/// extrinsic, so it carries the same proof-size term a settlement's does.
	fn shield(ciphertext_bytes: u32) -> Weight;
	/// Recording the block's coinbase payload: one bounded write and the
	/// author lookup over the block's digest logs. No tree work and no value
	/// moves; see `mint_coinbase` for that half.
	fn coinbase(ciphertext_bytes: u32) -> Weight;
	/// Minting the coinbase note in `on_finalize`: one tree append, the
	/// leaf-block and value maps, and the pool update. Reserved by this
	/// pallet's `on_initialize` at the largest ciphertext the runtime accepts,
	/// because the author's payload is already in `PendingCoinbase` by then
	/// and the reservation has to be made before it is read.
	fn mint_coinbase(ciphertext_bytes: u32) -> Weight;
}

/// Storage the coinbase mint performs beyond the tree's own: reads of
/// `PendingCoinbase`, `PendingCoinbaseFee` and `PoolValue`; writes of
/// `PendingCoinbase` (taken), `PendingCoinbaseFee`, `PoolValue`, `LeafBlocks`
/// and `CoinbaseValues`.
pub const MINT_COINBASE_DB_OPS: (u64, u64) = (3, 5);

/// Weight of minting one coinbase note, shared by both `WeightInfo` impls
/// because the work does not depend on the runtime's own storage weights
/// beyond `DbWeight`.
fn mint_coinbase_weight<T: frame_system::Config>(ciphertext_bytes: u32) -> Weight {
	let ciphertext_bytes = u64::from(ciphertext_bytes);
	let (tree_reads, tree_writes) = pallet_zk_tree::INSERT_LEAF_DB_OPS;
	let (mint_reads, mint_writes) = MINT_COINBASE_DB_OPS;
	let reads = tree_reads.saturating_add(mint_reads);
	let writes = tree_writes.saturating_add(mint_writes);
	// The tree append's own hashing, plus the one Poseidon2 evaluation that
	// turns `(inner, value)` into the commitment.
	let hashing = pallet_zk_tree::INSERT_LEAF_POSEIDON_EVALS
		.saturating_add(1)
		.saturating_mul(POSEIDON_EVAL_REF_TIME_PS);
	<T as frame_system::Config>::DbWeight::get()
		.reads_writes(reads, writes)
		.saturating_add(Weight::from_parts(
			hashing,
			reads.saturating_mul(KEY_POV).saturating_add(ciphertext_bytes),
		))
}

/// Weight of settling `slots` real leaf slots carrying `ciphertext_bytes` of
/// payload, excluding the proof verification.
fn settlement_weight<T: frame_system::Config>(slots: u32, ciphertext_bytes: u32) -> Weight {
	let slots = u64::from(slots);
	let ciphertext_bytes = u64::from(ciphertext_bytes);
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
		.saturating_mul(POSEIDON_EVAL_REF_TIME_PS)
		.saturating_add(ct_digest_ref_time(slots, ciphertext_bytes));

	<T as frame_system::Config>::DbWeight::get()
		.reads_writes(reads, writes)
		.saturating_add(Weight::from_parts(
			hashing,
			reads.saturating_mul(KEY_POV).saturating_add(ciphertext_bytes),
		))
}

pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn submit_private_batch(slots: u32, ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(
			verify_ref_time(PRIVATE_BATCH_VERIFY_REF_TIME_PS, PRIVATE_BATCH_PI_FELTS),
			0,
		)
		.saturating_add(settlement_weight::<T>(slots, ciphertext_bytes))
	}

	fn submit_public_batch(slots: u32, ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(
			verify_ref_time(PUBLIC_BATCH_VERIFY_REF_TIME_PS, PUBLIC_BATCH_PI_FELTS),
			0,
		)
		.saturating_add(settlement_weight::<T>(slots, ciphertext_bytes))
	}

	fn coinbase(ciphertext_bytes: u32) -> Weight {
		// One read of `PendingCoinbase`, one of the digest logs for the author
		// lookup, one write of the payload.
		<T as frame_system::Config>::DbWeight::get().reads_writes(2, 1).saturating_add(
			Weight::from_parts(
				POSEIDON_EVAL_REF_TIME_PS,
				2u64.saturating_mul(KEY_POV).saturating_add(u64::from(ciphertext_bytes)),
			),
		)
	}

	fn mint_coinbase(ciphertext_bytes: u32) -> Weight {
		mint_coinbase_weight::<T>(ciphertext_bytes)
	}

	fn shield(ciphertext_bytes: u32) -> Weight {
		let (tree_reads, tree_writes) = pallet_zk_tree::INSERT_LEAF_DB_OPS;
		// Reads: the signer's account, `EntryCount`, `PoolValue`, plus the
		// tree's. Writes: the signer's account, `EntryCount`, `PoolValue`,
		// `LeafBlocks`, plus the tree's.
		let reads = tree_reads.saturating_add(3);
		let writes = tree_writes.saturating_add(4);
		let hashing = pallet_zk_tree::INSERT_LEAF_POSEIDON_EVALS
			.saturating_add(1)
			.saturating_mul(POSEIDON_EVAL_REF_TIME_PS);
		<T as frame_system::Config>::DbWeight::get()
			.reads_writes(reads, writes)
			// The ciphertext is in the proof size for the same reason
			// `settlement_weight` puts one there: the bytes ride in the
			// extrinsic and every validator reads them. The runtime leaves
			// `proof_size` uncapped today, so nothing is metered against this
			// yet; the term is here so that the declaration is an upper bound
			// on the day it is.
			.saturating_add(Weight::from_parts(
				hashing,
				reads.saturating_mul(KEY_POV).saturating_add(u64::from(ciphertext_bytes)),
			))
	}
}

/// Marginal cost of one real leaf slot in the `()` impl, in picoseconds.
///
/// Two nullifier writes, two tree appends with their Poseidon2 work and a
/// digest over two ciphertexts. 200 microseconds is the placeholder for the
/// fixed part; the payload term below is the one that dominates a real slot.
const SLOT_REF_TIME_PS: u64 = 200_000_000;

/// For mocks and for a runtime that has not wired its own.
impl WeightInfo for () {
	fn submit_private_batch(slots: u32, ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(
			verify_ref_time(PRIVATE_BATCH_VERIFY_REF_TIME_PS, PRIVATE_BATCH_PI_FELTS)
				.saturating_add(u64::from(slots).saturating_mul(SLOT_REF_TIME_PS))
				.saturating_add(ct_digest_ref_time(u64::from(slots), u64::from(ciphertext_bytes))),
			0,
		)
	}

	fn submit_public_batch(slots: u32, ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(
			verify_ref_time(PUBLIC_BATCH_VERIFY_REF_TIME_PS, PUBLIC_BATCH_PI_FELTS)
				.saturating_add(u64::from(slots).saturating_mul(SLOT_REF_TIME_PS))
				.saturating_add(ct_digest_ref_time(u64::from(slots), u64::from(ciphertext_bytes))),
			0,
		)
	}

	fn shield(ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(SLOT_REF_TIME_PS, u64::from(ciphertext_bytes))
	}

	fn coinbase(ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(POSEIDON_EVAL_REF_TIME_PS, u64::from(ciphertext_bytes))
	}

	fn mint_coinbase(ciphertext_bytes: u32) -> Weight {
		Weight::from_parts(SLOT_REF_TIME_PS, u64::from(ciphertext_bytes))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Whatever the numbers turn out to be, the shape has to hold: settling
	/// more slots costs more, carrying more ciphertext costs more, and a public
	/// batch costs at least what a private batch of the same shape does,
	/// because it verifies a larger proof over the same settlement work.
	#[test]
	fn settlement_weight_is_monotonic_in_the_slot_count_and_the_payload() {
		for slots in 0u32..8 {
			let private = <() as WeightInfo>::submit_private_batch(slots, slots * 3_500);
			let public = <() as WeightInfo>::submit_public_batch(slots, slots * 3_500);
			assert!(public.ref_time() >= private.ref_time());
			if slots > 0 {
				assert!(
					private.ref_time() >
						<() as WeightInfo>::submit_private_batch(slots - 1, (slots - 1) * 3_500)
							.ref_time()
				);
			}
			assert!(
				<() as WeightInfo>::submit_private_batch(slots, 8_192).ref_time() >=
					<() as WeightInfo>::submit_private_batch(slots, 0).ref_time()
			);
		}
	}

	/// The ciphertext digest is a real cost. One slot absorbs two
	/// kilobyte-scale ciphertexts, and the old flat charge of six permutations
	/// was wrong by more than an order of magnitude. This pins the order of magnitude;
	/// `ciphertext_digest_permutations_match_the_hashed_bytes` in the pallet's
	/// tests pins the exact number against the real hasher's encoding.
	#[test]
	fn the_ciphertext_digest_is_priced_per_byte() {
		// Two ciphertexts at the reachable cap of 2048 bytes each: 4116 bytes
		// of preimage, 1030 felts, 129 permutations. The cap is per
		// ciphertext, so this pair is one slot's worst case.
		assert_eq!(ct_digest_permutations(2 * 2_048), 129);
		// An empty pair is the framing alone.
		assert_eq!(ct_digest_permutations(0), 1);
		// Two ciphertexts at the real ML-KEM-1024 size with no memo.
		assert_eq!(ct_digest_permutations(2 * 1_731), 109);

		// The aggregate charge is an upper bound on the per-slot sum, whatever
		// the split. Six slots of two maximum ciphertexts each:
		let per_slot: u64 = 6 * ct_digest_permutations(2 * 2_048);
		let charged = ct_digest_ref_time(6, 6 * 2 * 2_048) / POSEIDON_EVAL_REF_TIME_PS / 2;
		assert!(charged >= per_slot, "charged {charged} permutations against {per_slot} real");
	}

	/// The verify dominates a settlement at a realistic payload, which is the
	/// shape a fixed verify cost per call assumes. It stops dominating at the
	/// maximum ciphertext size, which is why the payload is a weight term and
	/// why the cap is set where it is.
	#[test]
	fn the_proof_verification_dominates_a_full_batch_at_a_realistic_payload() {
		let realistic = 6 * 2 * 1_731;
		let full = <() as WeightInfo>::submit_private_batch(6, realistic).ref_time();
		let settlement =
			full - verify_ref_time(PRIVATE_BATCH_VERIFY_REF_TIME_PS, PRIVATE_BATCH_PI_FELTS);
		assert!(
			settlement < PRIVATE_BATCH_VERIFY_REF_TIME_PS,
			"settling six slots costs {settlement} ps against a {PRIVATE_BATCH_VERIFY_REF_TIME_PS} ps verify"
		);
	}

	/// Both gates are charged. `pre_dispatch` parses and verifies, and the
	/// dispatch body parses and verifies again, because a general-format
	/// extrinsic reaches a dispatch without `ValidateUnsigned` running.
	#[test]
	fn the_verify_and_the_parse_are_each_charged_twice() {
		let private = <() as WeightInfo>::submit_private_batch(0, 0).ref_time();
		assert_eq!(
			private,
			2 * (PRIVATE_BATCH_VERIFY_REF_TIME_PS +
				PRE_VALIDATE_BASE_REF_TIME_PS +
				PRIVATE_BATCH_PI_FELTS * PRE_VALIDATE_PER_FELT_REF_TIME_PS)
		);
	}

	/// A public batch's public-input vector is `n` times a private batch's, and
	/// the parse walks all of it, so the two cannot share one flat constant.
	#[test]
	fn the_public_batch_parse_costs_more_than_the_private_batch_parse() {
		const { assert!(PUBLIC_BATCH_PI_FELTS > PRIVATE_BATCH_PI_FELTS * 10) };
		assert!(
			pre_validate_ref_time(PUBLIC_BATCH_PI_FELTS) >
				pre_validate_ref_time(PRIVATE_BATCH_PI_FELTS)
		);
		// The blob round trip does not scale with the public inputs, so the
		// public batch's parse stays within an order of magnitude of the
		// private batch's. The felt ratio alone would be a factor of fifty.
		assert!(
			pre_validate_ref_time(PUBLIC_BATCH_PI_FELTS) <
				pre_validate_ref_time(PRIVATE_BATCH_PI_FELTS) * 10
		);
	}
}
