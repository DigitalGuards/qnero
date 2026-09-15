//! # Qnero shielded pool
//!
//! Every transfer in Qnero is shielded. A wallet proves a batch of spends with
//! `qnero-prover` and submits one private-batch proof; an aggregator may wrap
//! several of those into a public batch. This pallet is what settles either:
//! it checks the block each segment is anchored at, refuses a nullifier it has
//! already seen or one repeated inside the submission, appends the note
//! commitments to `pallet-zk-tree` as raw leaves, binds the submitted
//! ciphertexts to the proof, and accounts the fee.
//!
//! `docs/CIRCUIT.md` section 8.6 in the Qnero repository is the settlement
//! contract, and section 4 is the leaf rule. The properties that are this
//! pallet's alone, because no circuit enforces them:
//!
//! - **A padding segment settles nothing.** A segment whose `block_hash` is `PADDING_BLOCK_HASH` is
//!   skipped whole, and a submission with no other segment is refused.
//!   `qnero_aggregator::prove_padding_batch` is a public API returning a proof that verifies
//!   against the published verifier while its prover holds no note, and settlement extrinsics are
//!   fee free, so a standalone padding batch would write nullifier entries into permanent state for
//!   nothing. A padding inner of a public batch additionally has its whole slot region zeroed, so
//!   settling it would insert the all-zero nullifier and make the chain reject its own next batch
//!   as a double spend.
//! - **Cross-segment nullifier dedupe.** The public-batch circuit refuses a repeated inner proof;
//!   it does not compare nullifiers between two different inners, because that is `n * 2N` digests.
//!   The chain does it. A segment holding a nullifier this chain already settled, or one an earlier
//!   segment of the same submission claimed, is skipped whole and the rest settles; a submission
//!   that settles nothing is refused. Aborting the whole submission instead would let one
//!   participant destroy an aggregator's batch by settling a note of its own inner first. A segment
//!   whose block anchor no longer resolves is skipped on the same argument: it can never settle,
//!   and one reorg between an aggregator's proving run and inclusion would otherwise destroy the
//!   whole batch.
//! - **Every slot and every byte a submission carries is paid for by the slots it settles.** A
//!   skipped segment pays no fee, because it writes no permanent state, and it still costs every
//!   node the admission walk over its slots, the weight the submission declares for them, and a
//!   `ct_digest` sponge over whatever bytes they carry. So the settling slots owe `MinLeafFee` for
//!   every slot the submission walks, settling and skipped alike, and `ceil(carried bytes /
//!   CiphertextBytesPerFeeQuantum)` over the whole submission, where the carried bytes are every
//!   ciphertext in the extrinsic, a skipped segment's included. Emptying a skipped position to a
//!   zero-length pair removes its bytes from the payload term; the slot itself is still charged the
//!   flat minimum, because the walk and the weight it costs are the same either way. A griefed
//!   aggregator either pays that floor or recomposes a batch without the conflicted inners.
//! - **`ct_digest`.** The circuit leaves it a free public input. The chain recomputes it over the
//!   ciphertexts in the extrinsic, in output order, and rejects the slot when it differs.
//! - **A minimum fee per real slot.** The leaf circuit's "at least one real input" constraint does
//!   not bound how many leaves a prover can produce: one note of any value, zero included, spent
//!   with a dummy in the other slot yields two spendable notes and can be repeated every block. The
//!   fee floor is the anti-spam mechanism, and it is the only one.
//! - **A 62-bit range check on every value entering the pool outside a spend.** The no-wrap
//!   argument behind the circuit's balance equation holds only while every value is below `2^62`.
//! - **The depth the circuit can prove.** A settlement that would take the tree past
//!   `capacity_at_depth(CIRCUIT_MAX_TREE_DEPTH)` is refused whole.
//!
//! Forked from `pallet-wormhole` in Quantus-Network/chain (MIT-0); see README.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};

use lazy_static::lazy_static;
pub use pallet::*;
use qnero_circuit::padding::PADDING_BLOCK_HASH;
use qnero_verifier::{
	PrivateBatchPublicInputs, PublicBatchPublicInputs, QneroPrivateBatchVerifier,
	QneroPublicBatchVerifier,
};
use qp_plonky2_verifier::{field::types::PrimeField64, F};

pub mod weights;
pub use weights::WeightInfo;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

/// A 32-byte digest: four canonical Goldilocks limbs, little endian per limb.
/// The same encoding `pallet-zk-tree` hashes and the chain's own block hash
/// uses, so a conversion between the two is lossless.
pub type Hash256 = [u8; 32];

/// Fixed transaction-pool priority for unsigned settlement submissions.
///
/// Must not be derived from the public inputs. Combined with the
/// nullifier-derived `provides` tag, an amount-derived priority would let one
/// submission usurp a victim's same-tag settlement, because the pool replaces
/// on strictly higher priority, and the public inputs a priority would read
/// are the prover's own claim. A constant makes first seen win.
pub const UNSIGNED_SETTLEMENT_PRIORITY: u64 = 1;

/// Hard upper bound on a serialized settlement proof, applied before the blob
/// is copied or parsed.
///
/// Settlement extrinsics are unsigned and fee free and pre-validation runs for
/// every gossiped candidate, so without this the only bound on the bytes every
/// node copies and feeds to the plonky2 parser is the block length limit. Proof
/// sizes are fixed by the compiled dimensions: a private batch serializes to
/// 150908 bytes at the chain default, and a public batch is the same shape with
/// a wider forwarded region, 237544 bytes at `n = 53`. Both are measurements,
/// taken at M5 on the development workstation, and the margin against this cap
/// is 2.2x for the larger of the two. `docs/BENCH.md` carries both, and
/// `crates/qnero-wallet/tests/public_batch_bench.rs` is where the public-batch
/// figure comes from.
///
/// **Only one of the two proof kinds is covered by a test that runs by
/// default**, and that is still the thing to watch.
/// `a_real_private_batch_settles_end_to_end` proves a private batch at the
/// chain's `N` and asserts its serialized length against this cap, so a circuit
/// change that pushed the private batch past it fails there. Producing a public
/// batch is a minute of CPU and about ten gigabytes of peak memory, so its
/// measurement is an ignored test and a circuit change that grew a public batch
/// past this cap would refuse every public-batch settlement with
/// `ProofTooLarge` on a live chain with no default test saying so first.
pub const MAX_PROOF_BYTES: usize = 512 * 1024;

/// One pool step in planck: value in the pool moves in steps of 0.01 QNR.
///
/// A note commits its value as a single field element, and the chain's balance
/// is `u128` planck at twelve decimals, so the two are related by a fixed
/// step. It is `pallet-zk-tree`'s own `AMOUNT_SCALE_DOWN_FACTOR`, which is
/// what lets one tree hold a shielded note and a wormhole leaf without two
/// notions of "one unit"; the assertion below is what holds them together.
pub const POOL_STEP: u128 = 10_000_000_000;

const _: () = assert!(POOL_STEP == pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR);

/// The depth the tree may grow to and the depth the circuit can prove are one
/// number, and it is held here because the two crates that carry it never see
/// each other: `pallet-zk-tree` links no prover stack, and `qnero-circuit`'s
/// Merkle gadget is behind the `circuit` feature this pallet does not enable.
/// Raising one without the other is silent either way. A circuit that proves
/// deeper than the tree grows caps the pool early; a tree that grows deeper
/// than the circuit proves needs a longer path for every note already in it,
/// and the whole pool becomes unspendable with no error from the chain.
const _: () = assert!(
	pallet_zk_tree::CIRCUIT_MAX_TREE_DEPTH as usize == qnero_circuit::chain::MAX_TREE_DEPTH
);

/// Circuit sizing constants, written by `build.rs` from `QNERO_NUM_*`.
pub mod circuit_config {
	include!(concat!(env!("OUT_DIR"), "/qnero-artifacts/qnero_circuit_config.rs"));
}

/// The leaf verifier this runtime's batch verifiers were built against.
///
/// Bytes only, deliberately. A leaf proof does not blind and is not a
/// transaction: it is an input to a wallet's own aggregator. `qnero-verifier`
/// keeps its leaf entry points behind a non-default feature so a runtime cannot
/// name a leaf verifier at all, and this constant exists so a wallet can
/// compare the artifact it loads against the one the chain settles under.
pub const LEAF_VERIFIER_ARTIFACT: &[u8] =
	include_bytes!(concat!(env!("OUT_DIR"), "/qnero-artifacts/leaf_verifier.bin"));

/// The private-batch verifier artifact embedded in this runtime.
pub const PRIVATE_BATCH_VERIFIER_ARTIFACT: &[u8] =
	include_bytes!(concat!(env!("OUT_DIR"), "/qnero-artifacts/private_batch_verifier.bin"));

/// The public-batch verifier artifact embedded in this runtime, dimension
/// header included.
pub const PUBLIC_BATCH_VERIFIER_ARTIFACT: &[u8] =
	include_bytes!(concat!(env!("OUT_DIR"), "/qnero-artifacts/public_batch_verifier.bin"));

lazy_static! {
	static ref PRIVATE_BATCH_VERIFIER: Option<QneroPrivateBatchVerifier> =
		QneroPrivateBatchVerifier::from_artifact_bytes(
			PRIVATE_BATCH_VERIFIER_ARTIFACT,
			circuit_config::NUM_LEAF_PROOFS,
		)
		.ok();
	static ref PUBLIC_BATCH_VERIFIER: Option<QneroPublicBatchVerifier> =
		QneroPublicBatchVerifier::from_artifact_bytes(
			PUBLIC_BATCH_VERIFIER_ARTIFACT,
			circuit_config::NUM_PRIVATE_BATCH_PROOFS,
			circuit_config::NUM_LEAF_PROOFS,
		)
		.ok();
}

/// The private-batch verifier, or an error if the embedded artifact did not
/// pass its profile.
pub fn private_batch_verifier() -> Result<&'static QneroPrivateBatchVerifier, &'static str> {
	PRIVATE_BATCH_VERIFIER
		.as_ref()
		.ok_or("the private-batch verifier artifact is not loadable")
}

/// The public-batch verifier, or an error if the embedded artifact did not pass
/// its dimension header and profile.
pub fn public_batch_verifier() -> Result<&'static QneroPublicBatchVerifier, &'static str> {
	PUBLIC_BATCH_VERIFIER
		.as_ref()
		.ok_or("the public-batch verifier artifact is not loadable")
}

/// One canonical Goldilocks limb quadruple as the 32 bytes the chain stores.
fn digest_bytes(digest: &[F; 4]) -> Hash256 {
	let mut out = [0u8; 32];
	for (chunk, limb) in out.chunks_exact_mut(8).zip(digest.iter()) {
		chunk.copy_from_slice(&limb.to_canonical_u64().to_le_bytes());
	}
	out
}

/// One field element as the integer it encodes.
fn felt_u64(felt: F) -> u64 {
	felt.to_canonical_u64()
}

/// One real leaf slot of a settleable segment, read off the public inputs.
///
/// "Real" means not padding: the batch wrapper zeroes a padding slot's
/// commitment pair, and a real slot's commitments are Poseidon2 outputs, so the
/// two are told apart by the commitments alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealSlot {
	/// Both nullifiers the slot publishes. A dummy input's nullifier is among
	/// them and is indistinguishable from a real one by design, so both are
	/// settled: a note spent from input slot 1 is marked used only if slot 1's
	/// nullifier is settled.
	pub nullifiers: [Hash256; 2],
	/// Both output note commitments, which become two tree leaves.
	pub commitments: [Hash256; 2],
	/// The slot's fee, in pool steps.
	pub fee: u64,
	/// The digest the chain recomputes from the submitted ciphertexts.
	pub ct_digest: Hash256,
}

/// One settleable segment: a private batch, or one non-padding inner of a
/// public batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
	pub block_hash: Hash256,
	pub block_number: u32,
	/// Only the real slots. A padding slot settles nothing: its commitments are
	/// zero, so there is nothing to append, and its two nullifiers are hashes of
	/// randomness drawn for that proving run, so settling them writes inert
	/// entries into permanent state forever. At `N = 6` a one-transfer batch
	/// would otherwise carry ten of them.
	pub slots: Vec<RealSlot>,
}

/// What a settlement extrinsic settles, read off one proof's public inputs.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SettlementBundle {
	pub segments: Vec<Segment>,
}

impl SettlementBundle {
	/// Read a private batch's public inputs. An all-padding batch yields no
	/// segment, which the caller refuses.
	pub fn from_private_batch(inputs: &PrivateBatchPublicInputs) -> Self {
		let segments = if inputs.is_padding() { vec![] } else { vec![Segment::from(inputs)] };
		Self { segments }
	}

	/// Read a public batch's public inputs, skipping every padding inner.
	pub fn from_public_batch(inputs: &PublicBatchPublicInputs) -> Self {
		Self { segments: inputs.settleable_batches().map(Segment::from).collect() }
	}

	/// Every real slot of every segment, in settlement order.
	///
	/// This is the one statement of the order the `outputs` argument of a
	/// settlement extrinsic follows, and it is the walk `Pallet::bind_payload`
	/// makes: position `i` of `outputs` carries the two ciphertexts of the
	/// `i`th real slot, skipped segments included. A position whose segment
	/// this submission skips may instead be a pair of zero-length ciphertexts,
	/// which carries no bytes and binds nothing; the position itself stays,
	/// because the mapping from slot to position cannot depend on which
	/// segments were settled by someone else in the meantime.
	/// `Pallet::plan_settlement` and `Pallet::settle` walk the segments
	/// themselves, because they need the per-segment skip flag, and they count
	/// positions the same way.
	pub fn real_slots(&self) -> impl Iterator<Item = &RealSlot> {
		self.segments.iter().flat_map(|segment| segment.slots.iter())
	}
}

impl From<&PrivateBatchPublicInputs> for Segment {
	fn from(inputs: &PrivateBatchPublicInputs) -> Self {
		let slots = inputs
			.slots
			.iter()
			.filter(|slot| !slot.is_padding())
			.map(|slot| RealSlot {
				nullifiers: [digest_bytes(&slot.nullifiers[0]), digest_bytes(&slot.nullifiers[1])],
				commitments: [
					digest_bytes(&slot.commitments[0]),
					digest_bytes(&slot.commitments[1]),
				],
				fee: felt_u64(slot.fee),
				ct_digest: digest_bytes(&slot.ct_digest),
			})
			.collect();
		Self {
			block_hash: digest_bytes(&inputs.block_hash),
			// Saturating. A truncating cast is the trap here: the leaf
			// circuit range checks
			// `block_number` below `2^32`, and truncation would let an
			// out-of-range claim alias a real height, leaving the block-hash
			// comparison as the only thing between it and a settlement
			// anchored at a block the prover never saw.
			block_number: u32::try_from(felt_u64(inputs.block_number)).unwrap_or(u32::MAX),
			slots,
		}
	}
}

/// The padding sentinel in the 32-byte form the chain compares against.
pub fn padding_block_hash() -> Hash256 {
	let mut out = [0u8; 32];
	for (chunk, limb) in out.chunks_exact_mut(8).zip(PADDING_BLOCK_HASH.iter()) {
		chunk.copy_from_slice(&limb.to_le_bytes());
	}
	out
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::{
		dispatch::{DispatchClass, DispatchResultWithPostInfo, Pays},
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate},
			tokens::{Fortitude, Precision, Preservation},
			FindAuthor,
		},
		BoundedVec,
	};
	use frame_system::pallet_prelude::*;
	use pallet_zk_tree::ZkCommitmentRecorder;
	use qp_coinbase::CoinbaseSink;
	use sp_inherents::{InherentData, InherentIdentifier};
	use sp_runtime::{
		traits::{CheckedSub, Saturating, Zero},
		transaction_validity::{
			InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
			ValidTransaction,
		},
		DispatchError, Permill,
	};

	pub type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

	/// A fresh pallet with no predecessor state and no migrations.
	pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::pallet]
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	/// The two note ciphertexts of one real leaf slot, in output order: `ct_1`
	/// belongs to `cm_1`.
	///
	/// `qnero_circuit::chain::ct_digest` over these two, in this order, is what
	/// the slot's `ct_digest` public input must equal. The bytes are
	/// `qnero_pqcrypto::note_encryption::NoteCiphertext::to_bytes`: an ML-KEM
	/// ciphertext plus two AEAD payloads. The chain never parses them.
	#[derive(
		Encode,
		Decode,
		DecodeWithMemTracking,
		CloneNoBound,
		PartialEqNoBound,
		EqNoBound,
		RuntimeDebugNoBound,
		TypeInfo,
		MaxEncodedLen,
	)]
	#[scale_info(skip_type_params(T))]
	pub struct ShieldedOutput<T: Config> {
		pub ct_1: BoundedVec<u8, T::MaxCiphertextBytes>,
		pub ct_2: BoundedVec<u8, T::MaxCiphertextBytes>,
	}

	/// One block's coinbase payload, as its author supplied it.
	///
	/// `inner = H(NOTE, pk, rho, r)` of the note the author is minting to
	/// itself, and a ciphertext when the recipient needs one. The chain checks
	/// that `inner` is four canonical Goldilocks limbs, because it hashes it,
	/// and checks nothing else: both fields are the author's own and an author
	/// that malforms them can only strand its own reward.
	#[derive(
		Encode,
		Decode,
		DecodeWithMemTracking,
		CloneNoBound,
		PartialEqNoBound,
		EqNoBound,
		RuntimeDebugNoBound,
		TypeInfo,
		MaxEncodedLen,
	)]
	#[scale_info(skip_type_params(T))]
	pub struct CoinbasePayload<T: Config> {
		pub inner: Hash256,
		pub ciphertext: BoundedVec<u8, T::MaxCiphertextBytes>,
	}

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// The native currency. A shield burns from it and a settled fee mints
		/// back into it; see the module docs on pool accounting.
		type Currency: Mutate<Self::AccountId> + Inspect<Self::AccountId>;

		/// The commitment tree. Shielded leaves and wormhole transfer leaves
		/// share one instance, because the circuit's `zk_tree_root` is the one
		/// root the block header carries.
		type ZkTree: ZkCommitmentRecorder;

		/// The block author, as one seam.
		///
		/// The pallet reads the author in exactly one place, the coinbase
		/// inherent, and it reads it through this. A block's coinbase belongs
		/// to whoever authored the block, so a block with no author has no
		/// coinbase to mint and is refused. Routing it through `FindAuthor` is
		/// what keeps the proof of work out of the pallet: today the runtime's
		/// implementation reads the QPoW pre-runtime digest, and a later engine
		/// swaps that one implementation without touching this pallet,
		/// `pallet-mining-rewards`, or the shape of a block. `docs/OPS-DEV.md`
		/// carries the seam.
		type FindAuthor: FindAuthor<Self::AccountId>;

		/// How far back a settlement may anchor.
		///
		/// A proof binds the header of one block, and the chain resolves that
		/// hash from `frame_system::BlockHash`, which is pruned. The window is
		/// the smaller of the two bounds and is what stops a wallet submitting
		/// a proof built against a block so old that the anonymity set it saw
		/// is a small prefix of the current tree.
		#[pallet::constant]
		type BlockHashWindow: Get<BlockNumberFor<Self>>;

		/// Minimum fee, in pool steps, that every real leaf slot must carry.
		///
		/// The anti-spam mechanism. One note of any value spent with a dummy in
		/// the other slot mints two spendable notes, so nothing else bounds how
		/// many leaves a prover can produce, and each one writes two nullifier
		/// entries and two tree slots into permanent state.
		///
		/// Two floors read it, and they answer two questions. The per-slot
		/// floor asks whether a settling slot pays for the permanent state it
		/// writes. The submission floor in [`Pallet::plan_settlement`] asks
		/// whether the settling fees of the whole submission cover every real
		/// leaf slot it carries and every byte it carries, its skipped
		/// segments included: a skipped slot writes nothing permanent and it
		/// still costs every node the admission walk over it and the weight the
		/// submission declares, so it is charged this same minimum. A
		/// submission that settles everything it carries passes the second
		/// whenever it passes the first, because each slot already paid this
		/// minimum once and `sum(ceil(b_i / q))` is at least
		/// `ceil(sum(b_i) / q)`.
		#[pallet::constant]
		type MinLeafFee: Get<u64>;

		/// Bytes of note ciphertext one step of fee buys, on top of
		/// [`Config::MinLeafFee`].
		///
		/// A flat per-slot floor prices a slot's permanent state at whatever
		/// the ciphertext cap allows. The chain never parses these bytes, so a
		/// settler is not held to a real `NoteCiphertext`: it commits its proof
		/// to two fields of arbitrary bytes up to
		/// [`Config::MaxCiphertextBytes`], and `Ciphertexts` is never pruned
		/// and carries no storage deposit. This makes the floor linear in the
		/// payload, so the state a settlement adds is paid for in proportion.
		///
		/// A runtime owes one property when it picks a value: the divisor has
		/// to sit below the slack between a real `NoteCiphertext` and
		/// [`Config::MaxCiphertextBytes`], or both round to the same number of
		/// steps and padding to the cap is free, which is the whole of what
		/// this term exists to price.
		///
		/// The same divisor prices the submission as a whole. The settling fees
		/// must cover `ceil(carried bytes / CiphertextBytesPerFeeQuantum)` over
		/// every ciphertext in the extrinsic, so one byte costs the same
		/// whether the slot that published it settles or is skipped, beside
		/// [`Config::MinLeafFee`] for every carried slot.
		///
		/// A wallet can compute the floor before it proves: the fee is a public
		/// input and the ciphertext sizes are known by the time the proof is
		/// built. Zero is refused by `integrity_test`.
		#[pallet::constant]
		type CiphertextBytesPerFeeQuantum: Get<u32>;

		/// Share of a settled fee that is burned. The rest is minted to the
		/// block author.
		#[pallet::constant]
		type FeeBurnRate: Get<Permill>;

		/// Size cap on one note ciphertext.
		#[pallet::constant]
		type MaxCiphertextBytes: Get<u32>;

		/// Weights.
		type WeightInfo: WeightInfo;
	}

	/// Nullifiers this chain has settled. Presence is the only thing stored.
	///
	/// Hashed with `Blake2_128Concat`. A real nullifier is a Poseidon2 output
	/// nobody controls, so `Identity` would be safe for those; a padding
	/// slot's nullifiers are hashes of prover-chosen randomness, and a prover
	/// can grind keys that share a prefix and deepen one trie branch. The map
	/// takes both kinds, so it takes the hasher the second kind needs.
	#[pallet::storage]
	#[pallet::getter(fn used_nullifiers)]
	pub type UsedNullifiers<T: Config> = StorageMap<_, Blake2_128Concat, Hash256, (), OptionQuery>;

	/// The note ciphertext stored against the leaf index of its commitment.
	///
	/// A recipient finds its notes by trial decryption, so it needs every
	/// ciphertext. They are emitted in an event as well; this map is what lets a
	/// wallet that was offline catch up from state.
	#[pallet::storage]
	#[pallet::getter(fn ciphertext)]
	pub type Ciphertexts<T: Config> =
		StorageMap<_, Identity, u64, BoundedVec<u8, T::MaxCiphertextBytes>, OptionQuery>;

	/// The block a leaf was appended in, by leaf index. A wallet syncing from a
	/// height resolves which leaves are new without walking every block.
	#[pallet::storage]
	#[pallet::getter(fn leaf_block)]
	pub type LeafBlocks<T: Config> = StorageMap<_, Identity, u64, BlockNumberFor<T>, OptionQuery>;

	/// Notes created outside a spend proof, counted chain wide.
	///
	/// The identifier half of the entry `rho` rule: a recipient recomputes
	/// `rho = H(RHO_ENTRY, block_number, entry_index)` from the pair this
	/// counter and the block number make, so no two entry notes share a
	/// nullifier seed. `qnero_notes::entry_rho` is the rule, and the chain
	/// publishes the identifier it hashes without hashing it itself.
	#[pallet::storage]
	#[pallet::getter(fn entry_count)]
	pub type EntryCount<T: Config> = StorageValue<_, u64, ValueQuery>;

	/// Value held by the pool, in planck.
	///
	/// Shielding burns from the shielder and adds here; a settled fee subtracts
	/// here and mints the author's share back. Nothing else moves it, so this is
	/// the amount of issuance the pool is standing in for, and it is what an
	/// unshield path would have to draw from at v1.
	#[pallet::storage]
	#[pallet::getter(fn pool_value)]
	pub type PoolValue<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// The coinbase payload the author of the block being executed supplied,
	/// held from the inherent until `on_finalize` knows what the note is worth.
	///
	/// Killed at the start of every block, so a payload can never outlive the
	/// block it was supplied for, and taken when the note is minted. Its
	/// presence is also the one-per-block rule: a second coinbase inherent
	/// finds it set and fails, and a mandatory dispatch that fails takes the
	/// block with it.
	#[pallet::storage]
	#[pallet::getter(fn pending_coinbase)]
	pub type PendingCoinbase<T: Config> = StorageValue<_, CoinbasePayload<T>, OptionQuery>;

	/// The block author's share of the fees settled so far, waiting for the
	/// coinbase note that pays it.
	///
	/// A settled fee leaves [`PoolValue`] whole; the burned share is gone and
	/// this is the rest. It is planck, always a whole number of pool steps,
	/// and it is value the pool still stands behind, so [`ShieldedSupply`]
	/// counts it. A block that mints no coinbase leaves it here for the next
	/// one.
	#[pallet::storage]
	#[pallet::getter(fn pending_coinbase_fee)]
	pub type PendingCoinbaseFee<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// Value of the coinbase note at a leaf index, in pool steps.
	///
	/// A coinbase note's value is public, which is what lets the chain compute
	/// `cm = H(CM, inner, value)` from an opaque `inner` it never checks. The
	/// map is how a wallet reads that value: the note carries no ciphertext at
	/// all when its recipient can derive it, so the scan takes the amount from
	/// here and rebuilds the commitment against the leaf. Presence is also what
	/// marks a leaf a coinbase.
	#[pallet::storage]
	#[pallet::getter(fn coinbase_value)]
	pub type CoinbaseValues<T: Config> = StorageMap<_, Identity, u64, u64, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A note was created from transparent value. `entry_index` and the
		/// block this event is in are what the recipient derives the note's
		/// `rho` from, and the ciphertext is what it decrypts.
		Shielded {
			who: T::AccountId,
			value: BalanceOf<T>,
			commitment: Hash256,
			leaf_index: u64,
			entry_index: u64,
			ciphertext: Vec<u8>,
		},
		/// One real leaf slot settled: two nullifiers spent, two notes created.
		/// The ciphertexts are in output order, so `ciphertexts.0` belongs to
		/// the note at `leaf_indices.0`.
		SlotSettled {
			nullifiers: [Hash256; 2],
			commitments: [Hash256; 2],
			leaf_indices: (u64, u64),
			ciphertexts: (Vec<u8>, Vec<u8>),
		},
		/// A settlement was accepted. `slots` counts the real leaf slots and
		/// `fee` is their summed fee in planck.
		BatchSettled { segments: u32, slots: u32, fee: BalanceOf<T> },
		/// The block author's share of a settled fee, held for this block's
		/// coinbase note. It is not a transparent credit and no account was
		/// touched.
		AuthorFeeAccrued { amount: BalanceOf<T> },
		/// The block's coinbase note. `value` is public and is what the chain
		/// hashed with `inner` to get the commitment it appended.
		///
		/// `has_ciphertext` is a flag rather than the payload: the bytes are
		/// already in `Ciphertexts` under the leaf index, and a block that
		/// republished them would put every author's payload in two places
		/// forever. v1 refuses a non-empty payload outright, so the flag is
		/// false on every block this runtime builds.
		CoinbaseMinted {
			block_number: BlockNumberFor<T>,
			leaf_index: u64,
			inner: Hash256,
			value: BalanceOf<T>,
			has_ciphertext: bool,
		},
		/// The block reward could not be minted into a note and stays with
		/// `pallet-mining-rewards` for the next block. The one reachable cause
		/// is a block whose author supplied no coinbase inherent, which the
		/// inherent check refuses on import.
		CoinbaseDeferred { amount: BalanceOf<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The proof is larger than `MAX_PROOF_BYTES`.
		ProofTooLarge,
		/// The proof did not deserialize against the embedded verifier's circuit
		/// data.
		ProofDeserializationFailed,
		/// The bytes are not the canonical encoding of the proof they decode to.
		/// Plonky2's reader ignores trailing bytes and accepts non-canonical
		/// field limbs, so without this one proof has unlimited distinct
		/// transaction identities.
		NonCanonicalProofEncoding,
		/// The embedded verifier artifact did not load.
		VerifierNotAvailable,
		/// The proof failed verification.
		ProofVerificationFailed,
		/// The public inputs did not parse at the documented indices.
		InvalidPublicInputs,
		/// Every segment of the submission is padding, so it settles nothing.
		/// A padding batch proof verifies while its prover holds no note.
		NothingToSettle,
		/// No block at that height, or its hash has been pruned.
		BlockNotFound,
		/// The anchoring block is outside `BlockHashWindow`, or is not yet a
		/// finished block.
		BlockOutsideWindow,
		/// The `block_hash` public input is not the hash of the block at
		/// `block_number`.
		BlockHashMismatch,
		/// A nullifier has already been settled.
		NullifierAlreadyUsed,
		/// A nullifier appears twice in this submission. The private-batch
		/// circuit forbids a repeat inside one batch; nothing in the
		/// public-batch circuit compares two different inners.
		DuplicateNullifier,
		/// A settleable slot published the all-zero nullifier, which is not a
		/// settleable value.
		ZeroNullifier,
		/// A settleable slot published the all-zero commitment, which is the
		/// commitment tree's absence sentinel and cannot be stored as a leaf.
		ZeroCommitment,
		/// The fee of a real leaf slot is below `MinLeafFee`.
		FeeBelowMinimum,
		/// A value entering the pool is at or above `2^62`, or a fee sum
		/// overflowed.
		ValueOutOfRange,
		/// The settled fee is larger than the value the pool is standing in
		/// for. Unreachable while the circuit's balance equation holds and
		/// `shield` is the only entry, which is exactly why it fails closed:
		/// the alternative is minting the block author a share of a fee that
		/// nothing backs, and zeroing the pool's own books on the way past.
		PoolUnderflow,
		/// The number of `ShieldedOutput`s does not match the number of real
		/// leaf slots.
		CiphertextCountMismatch,
		/// The recomputed ciphertext digest differs from the slot's `ct_digest`.
		CiphertextDigestMismatch,
		/// A ciphertext is longer than `MaxCiphertextBytes`.
		CiphertextTooLarge,
		/// A slot this submission settles carries an empty ciphertext.
		///
		/// A zero-length pair is the exemption a skipped position may take: it
		/// carries no bytes, so nothing prices it and `bind_payload` has
		/// nothing to bind. A settling slot appends two commitments and stores
		/// two ciphertexts, so an empty field there would write an output note
		/// its recipient can never find, behind a `ct_digest` nothing
		/// evaluated.
		EmptyCiphertext,
		/// The settling fees do not cover the slots and the bytes the
		/// submission carries.
		///
		/// The floor is `(settling slots + skipped slots) * MinLeafFee +
		/// ceil(carried bytes / CiphertextBytesPerFeeQuantum)`, over every real
		/// leaf slot of the submission and every ciphertext in the extrinsic, a
		/// skipped segment's included. A skipped segment pays no fee of its
		/// own and still costs every node the admission walk over its slots and
		/// the weight the submission declares, so this is what keeps a
		/// submitter that picks how many of its own segments conflict from
		/// spending a block's work and space on credit.
		PayloadUnderpaid,
		/// The settlement would take the tree past the depth the circuit can
		/// prove.
		TreeFull,
		/// A shielded value is not a positive whole number of pool steps.
		ValueNotQuantized,
		/// The `inner` of a shield or a coinbase is not four canonical
		/// Goldilocks limbs.
		NonCanonicalInner,
		/// The block already carries a coinbase inherent. One block mints one
		/// coinbase note, and the block number is the whole identifier its
		/// `rho` is derived from, so a second one would be a second note on one
		/// nullifier seed.
		CoinbaseAlreadySet,
		/// The block has no author, so there is nobody the coinbase belongs to.
		NoBlockAuthor,
		/// The coinbase inherent carried an encrypted payload. v1 has no
		/// builder for one and charges nothing for the bytes, so the field is
		/// refused until both exist.
		CoinbasePayloadNotSupported,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Clear the previous block's coinbase payload and reserve what minting
		/// this block's costs.
		///
		/// The kill is what makes [`PendingCoinbase`]'s presence mean "this
		/// block already has one": a payload that survived its block would
		/// refuse the next block's inherent, and a mandatory dispatch that
		/// fails is a dead block. The reservation covers the work
		/// `deposit_coinbase` does in `pallet-mining-rewards`' `on_finalize`,
		/// which is one tree append, three map writes and the pool update, at
		/// the largest ciphertext this runtime accepts. Nothing else in the
		/// pallet runs from a hook.
		fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
			PendingCoinbase::<T>::kill();
			T::WeightInfo::mint_coinbase(T::MaxCiphertextBytes::get())
				.saturating_add(<T as frame_system::Config>::DbWeight::get().writes(1))
		}

		/// Both embedded verifier artifacts have to load.
		///
		/// They are loaded lazily, on the first settlement, and a failure there
		/// surfaces as a `VerifierNotAvailable` on one transaction, which no
		/// node operator is watching. This fails at runtime construction, which
		/// is where a mismatched or corrupted artifact belongs.
		fn integrity_test() {
			assert!(
				private_batch_verifier().is_ok(),
				"the embedded private-batch verifier artifact did not pass its profile"
			);
			assert!(
				public_batch_verifier().is_ok(),
				"the embedded public-batch verifier artifact did not pass its dimension header or its profile"
			);
			assert!(
				T::CiphertextBytesPerFeeQuantum::get() > 0,
				"CiphertextBytesPerFeeQuantum is the divisor of the per-byte fee floor and cannot be zero"
			);
			assert!(
				T::MinLeafFee::get() > 0,
				"MinLeafFee is the only price of a carried slot; zero reopens the free-carry denial of service"
			);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Settle one private batch: the transaction a wallet submits.
		///
		/// `outputs` carries the two note ciphertexts of every real leaf slot,
		/// in slot order, skipped segments included. A position belonging to a
		/// segment this submission skips may be emptied, and a submitter whose
		/// segments went stale after it proved does exactly that: the settling
		/// fees have to cover every byte the submission carries.
		///
		/// The body verifies the proof itself, and so does
		/// `ValidateUnsigned::pre_dispatch` before it. The declared weight
		/// prices both passes. The repetition is not redundancy for its own
		/// sake: `ensure_none` is satisfied by any dispatch with no origin, and
		/// a general-format extrinsic (`sp_runtime`'s
		/// `ExtrinsicFormat::General`) reaches a call with `None` as its origin
		/// without `ValidateUnsigned` running at all, because the checked
		/// extrinsic dispatches that format without calling `pre_dispatch`.
		/// Today the runtime's `ReversibleTransactionExtension` refuses a
		/// non-signed origin and closes that path, but that is one extension in
		/// a tuple a future runtime may reorder or relax, and what it would
		/// open is a settlement whose public inputs were rewritten wholesale:
		/// a parse alone is not cryptography, so the commitments appended would
		/// be attacker chosen and the pool would inflate without a proof.
		/// The verify here is what makes that structural.
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::submit_private_batch(
			outputs.len() as u32,
			Pallet::<T>::ciphertext_bytes(outputs),
		))]
		pub fn submit_private_batch(
			origin: OriginFor<T>,
			proof: Vec<u8>,
			outputs: Vec<ShieldedOutput<T>>,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			let bundle = Self::validate_private_batch(&proof)?;
			Self::settle(bundle, outputs)
		}

		/// Settle one public batch: an aggregator's bundle of private batches.
		///
		/// The whole submission is validated before any of it is written. The
		/// circuit stops the same inner appearing twice and says nothing about
		/// one nullifier appearing in two different inners, so the chain does
		/// that itself: a segment whose nullifiers collide with something
		/// already settled, or with an earlier segment of this submission, is
		/// skipped whole and the rest still settles. See
		/// [`PlannedSettlement::settles`] for what refusing the whole submission
		/// would cost an aggregator and everyone else in its batch.
		///
		/// The body verifies, for the reason
		/// [`Pallet::submit_private_batch`] gives.
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::submit_public_batch(
			outputs.len() as u32,
			Pallet::<T>::ciphertext_bytes(outputs),
		))]
		pub fn submit_public_batch(
			origin: OriginFor<T>,
			proof: Vec<u8>,
			outputs: Vec<ShieldedOutput<T>>,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			let bundle = Self::validate_public_batch(&proof)?;
			Self::settle(bundle, outputs)
		}

		/// Move transparent value into the pool as one note.
		///
		/// This is the only entry into the pool at v0, and there is no exit:
		/// value that goes in can only move between notes. `inner` is
		/// `H(NOTE, pk, rho, r)` and stays opaque, so the recipient and the
		/// note's randomness are private while its value is public; the chain
		/// computes `cm = H(CM, inner, value)` and appends it.
		///
		/// The shielder owes the `rho` rule: the spend circuit derives an
		/// output's `rho` from the nullifiers its leaf publishes, and an entry
		/// has no spent nullifier to derive from, so `rho` must be
		/// `H(RHO_ENTRY, block_number, entry_index)` over the pair this call
		/// publishes in its event. The chain cannot check it, because `inner` is
		/// opaque by construction; what it owes is the identifier, and a
		/// shielder who ignores the rule can only strand its own note.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::shield(ciphertext.len() as u32))]
		pub fn shield(
			origin: OriginFor<T>,
			value: BalanceOf<T>,
			inner: Hash256,
			ciphertext: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let value_u128: u128 = value.try_into().map_err(|_| Error::<T>::ValueOutOfRange)?;
			ensure!(
				value_u128 > 0 && value_u128.is_multiple_of(POOL_STEP),
				Error::<T>::ValueNotQuantized
			);
			// The 62-bit range check. Every value that enters the pool outside a
			// spend proof has to carry it, or the no-wrap argument behind the
			// circuit's balance equation does not hold for the notes created
			// this way.
			let steps = u64::try_from(value_u128 / POOL_STEP)
				.map_err(|_| Error::<T>::ValueOutOfRange)?;
			ensure!(steps <= qnero_circuit::chain::MAX_VALUE, Error::<T>::ValueOutOfRange);

			let commitment = qnero_circuit::chain::commitment(&inner, steps)
				.ok_or(Error::<T>::NonCanonicalInner)?;
			let stored: BoundedVec<u8, T::MaxCiphertextBytes> =
				ciphertext.clone().try_into().map_err(|_| Error::<T>::CiphertextTooLarge)?;

			ensure!(T::ZkTree::remaining_capacity() >= 1, Error::<T>::TreeFull);

			// Burning is the simpler of the two entries the design left open.
			// Value inside the pool is accounted by `PoolValue` and moves only
			// through proofs, so an account balance standing in for it would be
			// a second book to keep in step, and there is no exit at v0 to draw
			// from it. A settled fee mints the author's share back.
			// `Expendable`: a shielder moving its whole balance into the pool is
			// the ordinary case on a chain whose policy is that value lives in
			// the pool, and refusing to let the last step leave would make
			// the transparent account a permanent dust holder.
			T::Currency::burn_from(
				&who,
				value,
				Preservation::Expendable,
				Precision::Exact,
				Fortitude::Polite,
			)?;

			let entry_index = EntryCount::<T>::get();
			EntryCount::<T>::put(entry_index.saturating_add(1));
			let leaf_index = T::ZkTree::insert_commitment(commitment)?;
			Ciphertexts::<T>::insert(leaf_index, &stored);
			LeafBlocks::<T>::insert(leaf_index, frame_system::Pallet::<T>::block_number());
			PoolValue::<T>::mutate(|pool| *pool = pool.saturating_add(value));

			Self::deposit_event(Event::Shielded {
				who,
				value,
				commitment,
				leaf_index,
				entry_index,
				ciphertext,
			});
			Ok(())
		}

		/// Record this block's coinbase payload. The block author's node is the
		/// only caller.
		///
		/// This writes no value and creates no note. It carries the fields the
		/// chain cannot compute for itself from the author's node to
		/// `on_finalize`, which is the first moment the note's value is known:
		/// the value is the block reward plus the author's share of every fee
		/// the block settled, and the block's settlements have not run yet when
		/// an inherent does.
		///
		/// `inner = H(NOTE, pk, rho, r)` is the note with its value left out,
		/// and it is opaque: the chain hashes it and never opens it. The
		/// ciphertext is what carries `(rho, r)` to a recipient who cannot
		/// derive them, and **it is usually empty**. A Qnero node cannot build
		/// one, because it cannot link an ML-KEM implementation beside the one
		/// its own post-quantum transport pins, so it derives the note from a
		/// miner key its operator configured instead
		/// (`qnero_note_core::coinbase_r`). An empty field is therefore the
		/// ordinary case here, unlike a settling slot, where it would mean a
		/// note nobody can find behind a `ct_digest` nothing evaluated.
		///
		/// Mandatory, like every inherent. The failure modes are a second
		/// coinbase in one block, a block with no author, and a payload the
		/// chain cannot hash, and all three make the block invalid rather than
		/// dropping the reward: an author must not be able to mint two notes
		/// for one block, and a block that pays its reward nowhere is a block
		/// that mints value into nothing.
		///
		/// It is not in [`ValidateUnsigned`], so it cannot enter a transaction
		/// pool at all. An author puts it in the block it is building, which is
		/// the only place it belongs, and every other node sees it as an
		/// inherent because [`ProvideInherent::is_inherent`] says so.
		#[pallet::call_index(3)]
		#[pallet::weight((T::WeightInfo::coinbase(ciphertext.len() as u32), DispatchClass::Mandatory))]
		pub fn coinbase(
			origin: OriginFor<T>,
			inner: Hash256,
			ciphertext: Vec<u8>,
		) -> DispatchResult {
			ensure_none(origin)?;
			ensure!(!PendingCoinbase::<T>::exists(), Error::<T>::CoinbaseAlreadySet);
			ensure!(Self::block_author().is_some(), Error::<T>::NoBlockAuthor);

			// Nothing builds one yet, so nothing may publish one. An inherent
			// pays no fee and a mandatory dispatch does not compete for block
			// weight, so these bytes would be the one place on the chain where
			// permanent state is free: the settlement path charges
			// `MinLeafFee + ceil(bytes / CiphertextBytesPerFeeQuantum)` for
			// exactly the same map, and an author writing
			// `MaxCiphertextBytes` of anything every block it wins would pay
			// nothing for state every full node keeps forever. A non-empty
			// payload would also mark its own leaf, since a derived coinbase
			// publishes none. When a builder for a third-party coinbase lands
			// (`docs/CIRCUIT.md` section 10.6), this is where its bytes get
			// priced against the author's own credit.
			ensure!(ciphertext.is_empty(), Error::<T>::CoinbasePayloadNotSupported);
			let stored: BoundedVec<u8, T::MaxCiphertextBytes> =
				ciphertext.try_into().map_err(|_| Error::<T>::CiphertextTooLarge)?;
			// The one property of the payload the chain does check, because it
			// is the one it needs: `on_finalize` hashes `inner` and cannot
			// refuse anything. A non-canonical limb reaching the hasher there
			// would be a block that fails to finalize.
			ensure!(
				qnero_circuit::chain::commitment(&inner, 0).is_some(),
				Error::<T>::NonCanonicalInner
			);

			PendingCoinbase::<T>::put(CoinbasePayload::<T> { inner, ciphertext: stored });
			Ok(())
		}
	}

	#[pallet::inherent]
	impl<T: Config> ProvideInherent for Pallet<T> {
		type Call = Call<T>;
		type Error = qp_coinbase::InherentError;
		const INHERENT_IDENTIFIER: InherentIdentifier = qp_coinbase::INHERENT_IDENTIFIER;

		fn create_inherent(data: &InherentData) -> Option<Self::Call> {
			let payload: qp_coinbase::CoinbaseInherentData =
				data.get_data(&Self::INHERENT_IDENTIFIER).ok().flatten()?;
			Some(Call::coinbase { inner: payload.inner, ciphertext: payload.ciphertext })
		}

		/// Nothing to check. The payload is the author's own: a `pk` the chain
		/// cannot see inside an `inner` it cannot open, and a ciphertext it
		/// never parses. An importing node has no second opinion about either,
		/// and the value the note carries is the chain's own arithmetic rather
		/// than the author's claim. What is checked is that the inherent is
		/// there at all, and [`Self::is_inherent_required`] is where that is
		/// stated.
		fn check_inherent(_call: &Self::Call, _data: &InherentData) -> Result<(), Self::Error> {
			Ok(())
		}

		/// Every block carries one.
		///
		/// Unconditional, so it does not depend on the importing node having
		/// built coinbase inherent data of its own: a node that is not
		/// authoring has no miner key and no payload, and it still has to
		/// reject a block that mints its reward nowhere. The error is fatal, so
		/// the block is refused rather than imported.
		fn is_inherent_required(_data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
			Ok(Some(qp_coinbase::InherentError::Missing))
		}

		/// Only the coinbase. The two settlement calls are unsigned and go
		/// through [`ValidateUnsigned`]; classifying them as inherents here
		/// would let a block author put settlements in a block without the pool
		/// ever validating them.
		fn is_inherent(call: &Self::Call) -> bool {
			matches!(call, Call::coinbase { .. })
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// Three stages, in cost order, and admission runs all three.
			//
			// First the parse and the cheap half of the settlement check: the
			// size gate before anything is copied, deserialization, the
			// canonical-encoding round trip, the public-input parse, and then
			// `plan_settlement`, a bounded walk over the segments against chain
			// state. That walk is storage reads and integer comparisons, at most
			// two `UsedNullifiers` probes per slot, and it hashes nothing. It has
			// to come first because it is what the cheapest forgery dies on. A
			// settlement proof is public by construction: the extrinsic carrying
			// it is gossiped and old ones sit in finalized blocks, so anyone can
			// take a settled proof, keep the blob byte identical, change one byte
			// of `outputs`, and have a transaction no node has seen. Every
			// segment of a settled proof conflicts, so every one of those dies
			// here on `NullifierAlreadyUsed`, on a few hundred storage reads.
			//
			// Then the ZK verify, and admission cannot skip it. Nothing in the
			// parse is cryptography: a proof carries its public inputs as a plain
			// vector, so anyone can take a genuine proof, rewrite its public
			// inputs to claim any nullifiers, commitments, fee and block anchor,
			// re-serialize canonically, and produce a blob that passes every
			// check short of the verify. The canonical round trip does not close
			// that: it rejects other encodings of one decoded proof, and says
			// nothing about a mutated proof object. Admitting such a blob would
			// hand it the victim's nullifier-derived `provides` tag, and under a
			// constant priority whichever arrived first would hold the pool slot.
			// Verifying here also cuts propagation at the first hop, so one junk
			// blob costs one node one verify.
			//
			// Last the payload binding, `bind_payload`, which is the one term
			// linear in the submitted bytes: a Poseidon2 sponge over both
			// ciphertexts of every real slot. It runs behind the verify because
			// at the runtime's dimensions it is the larger of the two. A full
			// public batch carries 318 real slots, and by this pallet's own
			// weight constants that sponge is about 2.2 times one verify plus
			// parse at the real ciphertext size and about 2.6 times it at the
			// cap. Putting it in front of the verify would make a fabricated blob
			// cost a node the walk and the verify where it used to cost the
			// verify alone.
			//
			// The residual cost is one unpaid verify plus one unpaid cheap walk
			// per distinct gossiped proof, unrated-limited. It is an open issue,
			// recorded next to `WASM_VERIFY_FACTOR` in `weights.rs` and in
			// `docs/CIRCUIT.md` section 9.11.
			let (bundle, prefix) = match call {
				Call::submit_private_batch { proof, outputs } => {
					let parsed = Self::pre_validate_private_batch(proof)
						.map_err(|_| InvalidTransaction::Call)?;
					Self::plan_settlement(&parsed, outputs)
						.map_err(|_| InvalidTransaction::Call)?;
					let verified = Self::validate_private_batch(proof)
						.map_err(|_| InvalidTransaction::Call)?;
					Self::bind_payload(&verified, outputs).map_err(|_| InvalidTransaction::Call)?;
					(verified, "QneroPrivateBatch")
				},
				Call::submit_public_batch { proof, outputs } => {
					let parsed = Self::pre_validate_public_batch(proof)
						.map_err(|_| InvalidTransaction::Call)?;
					Self::plan_settlement(&parsed, outputs)
						.map_err(|_| InvalidTransaction::Call)?;
					let verified =
						Self::validate_public_batch(proof).map_err(|_| InvalidTransaction::Call)?;
					Self::bind_payload(&verified, outputs).map_err(|_| InvalidTransaction::Call)?;
					(verified, "QneroPublicBatch")
				},
				_ => return InvalidTransaction::Call.into(),
			};

			ValidTransaction::with_tag_prefix(prefix)
				.and_provides(Self::settlement_provides_tag(&bundle))
				.priority(UNSIGNED_SETTLEMENT_PRIORITY)
				.longevity(5)
				.propagate(true)
				.build()
		}

		fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
			// The block-inclusion gate: the full validation including the ZK
			// verify. Returning `Err` here excludes the transaction from the
			// block being built and makes a block that includes an unverifiable
			// proof invalid on import.
			//
			// It is also the gate every *inherent* passes, which is why the
			// coinbase is named here and refused in `validate_unsigned` above.
			// A bare extrinsic reaches `I::pre_dispatch` on its way into a block
			// and `I::validate_unsigned` on its way into a pool
			// (`sp_runtime`'s `CheckedExtrinsic::apply` and `validate`), so the
			// two answers are what keep the coinbase to the block its author is
			// building: the block builder may include one, and nobody can
			// gossip one. Its own checks are in the dispatch, where a failure
			// is a mandatory-dispatch failure and the block dies with it.
			match call {
				Call::coinbase { .. } => Ok(()),
				Call::submit_private_batch { proof, outputs } => {
					let bundle = Self::validate_private_batch(proof)
						.map_err(|_| InvalidTransaction::Call)?;
					Self::check_settlement(&bundle, outputs)
						.map_err(|_| InvalidTransaction::Call)?;
					Ok(())
				},
				Call::submit_public_batch { proof, outputs } => {
					let bundle =
						Self::validate_public_batch(proof).map_err(|_| InvalidTransaction::Call)?;
					Self::check_settlement(&bundle, outputs)
						.map_err(|_| InvalidTransaction::Call)?;
					Ok(())
				},
				_ => Err(InvalidTransaction::Call.into()),
			}
		}
	}

	/// What a validated settlement will do, carried from the check to the write
	/// so the two cannot disagree.
	#[derive(Clone, Debug, PartialEq, Eq)]
	pub struct PlannedSettlement {
		/// Summed fee of every slot that will settle, in pool steps. A skipped
		/// segment contributes nothing.
		pub fee_steps: u128,
		/// Real leaf slots that will settle.
		pub slots: u32,
		/// Real leaf slots of the segments this submission skips.
		///
		/// They settle nothing and pay no fee of their own, and they still hold
		/// their positions in `outputs`. Such a position may be emptied, and
		/// then it carries no bytes at all; one that still carries its
		/// ciphertexts is bound by [`Pallet::bind_payload`] and its bytes are
		/// priced through [`PlannedSettlement::carried_bytes`].
		///
		/// The slot itself is priced either way. It costs every node the
		/// admission walk and the weight the submission declares whether or not
		/// it settles, so the submission floor charges the settling fees
		/// [`Config::MinLeafFee`] for it, the same as for a slot that settles.
		pub skipped_slots: u32,
		/// Ciphertext bytes the whole submission carries: every byte of every
		/// `ShieldedOutput`, whether the slot it belongs to settles or is
		/// skipped.
		///
		/// This is what the settling fees have to cover, at
		/// [`Config::CiphertextBytesPerFeeQuantum`] bytes per step, on top
		/// of [`Config::MinLeafFee`] for every real slot the submission
		/// carries, [`PlannedSettlement::skipped_slots`] included. The bound
		/// reads bytes and slots, so it holds however a submitter splits its
		/// payload between segments and however many slots it puts in each:
		/// both of those are the submitter's to choose, and both are charged
		/// what a settling submission is charged for them.
		pub carried_bytes: u64,
		/// One flag per segment of the bundle, in order: whether this
		/// submission settles it.
		///
		/// A segment is skipped for either of two reasons, and neither is fatal
		/// to the submission. Any nullifier it publishes is already in
		/// `UsedNullifiers`, or was claimed by an earlier segment of this same
		/// submission. Or its block anchor no longer resolves: outside
		/// `BlockHashWindow`, pruned from `frame_system::BlockHash`, or holding
		/// a hash that is no longer the canonical one at that height. Both are
		/// conditions the segment cannot recover from under any ordering, and
		/// both are conditions a participant can inflict on an aggregator after
		/// its batch is fixed: the anchor case needs only a one-block reorg
		/// between the recursive proving run and inclusion, or an inner handed
		/// over already near the edge of the window.
		///
		/// Refusing the whole submission instead is what lets one
		/// participant destroy an aggregator's batch: every inner of a public
		/// batch is exactly the artifact `submit_private_batch` accepts, so a
		/// participant can settle a note of its own inner directly, in its own
		/// differently composed batch, and leave that inner partly settled by
		/// the time the aggregator's proof lands. Under an all-or-nothing rule
		/// that strands the other fifty-two transfers and wastes the
		/// aggregator's recursive proving run, for free and as often as it
		/// likes. An honest wallet that gives up waiting and re-spends produces
		/// the same shape.
		///
		/// Skipping is sound because a skipped segment could not have settled
		/// anyway: the leaf circuit's constraint 9 makes at least one input of
		/// every real slot a real note, and one of that segment's published
		/// nullifiers is already spent, so the segment is a double spend by
		/// construction. Refusing it and skipping it are the same outcome for
		/// it; they differ only for the segments around it. The same argument
		/// covers the anchor: a segment whose block anchor does not resolve is
		/// refused at every height from here on, because the window only moves
		/// forward and a pruned or orphaned hash never comes back. Nothing of a
		/// skipped segment is written: no commitment appended, no nullifier
		/// marked, no fee counted, so its own fresh nullifiers stay unspent.
		/// Which of two conflicting segments wins is the order they appear in
		/// the proof, which is fixed, so every node decides the same way, and
		/// the anchor rule reads chain state that every node agrees on at that
		/// height.
		pub settles: Vec<bool>,
	}

	impl<T: Config> Pallet<T> {
		// ------------------------------------------------------------------
		// Verification pipeline
		// ------------------------------------------------------------------

		/// Why the verifier refused a proof, as this pallet's own error.
		///
		/// Each layer that can refuse a proof gets its own error, so a rejected
		/// settlement says where it died. One flat error would leave an
		/// operator guessing. The split stops at deserialization: a truncated
		/// upload and a proof built at other circuit dimensions both fail
		/// `from_bytes` and land in the same variant, and separating them would
		/// mean carrying plonky2's own message into a `no_std` runtime. The log
		/// line names the dimensions this runtime was built for, which is the
		/// half of that question the chain can answer.
		fn proof_error(rejection: qnero_verifier::ProofRejection) -> Error<T> {
			use qnero_verifier::ProofRejection;
			match rejection {
				ProofRejection::TooLarge => Error::<T>::ProofTooLarge,
				ProofRejection::Deserialization => {
					log::debug!(
						target: "runtime::shielded",
						"a settlement proof did not deserialize; this runtime embeds verifiers for \
						 {} leaf slots per private batch and {} private batches per public batch",
						circuit_config::NUM_LEAF_PROOFS,
						circuit_config::NUM_PRIVATE_BATCH_PROOFS,
					);
					Error::<T>::ProofDeserializationFailed
				},
				ProofRejection::NonCanonicalEncoding => Error::<T>::NonCanonicalProofEncoding,
				ProofRejection::PublicInputLayout => Error::<T>::InvalidPublicInputs,
				ProofRejection::Verification => Error::<T>::ProofVerificationFailed,
			}
		}

		/// Everything short of the ZK verify, for a private batch.
		///
		/// This is the first half of pool admission: the parse, run ahead of
		/// the verify so a blob that cannot settle dies without one. See
		/// `ValidateUnsigned::validate_unsigned`. Nothing in it establishes
		/// that the public inputs are a proof's: only a verify does that.
		pub(crate) fn pre_validate_private_batch(
			proof: &[u8],
		) -> Result<SettlementBundle, Error<T>> {
			// The size gate comes before anything copies or parses the blob.
			ensure!(proof.len() <= MAX_PROOF_BYTES, Error::<T>::ProofTooLarge);
			let verifier =
				private_batch_verifier().map_err(|_| Error::<T>::VerifierNotAvailable)?;
			let inputs = verifier.parse_proof_bytes(proof).map_err(Self::proof_error)?;
			Ok(SettlementBundle::from_private_batch(&inputs))
		}

		/// Pre-validation plus the ZK verify.
		pub(crate) fn validate_private_batch(proof: &[u8]) -> Result<SettlementBundle, Error<T>> {
			ensure!(proof.len() <= MAX_PROOF_BYTES, Error::<T>::ProofTooLarge);
			let verifier =
				private_batch_verifier().map_err(|_| Error::<T>::VerifierNotAvailable)?;
			let inputs = verifier.verify_proof_bytes(proof).map_err(Self::proof_error)?;
			Ok(SettlementBundle::from_private_batch(&inputs))
		}

		/// Everything short of the ZK verify, for a public batch.
		pub(crate) fn pre_validate_public_batch(
			proof: &[u8],
		) -> Result<SettlementBundle, Error<T>> {
			ensure!(proof.len() <= MAX_PROOF_BYTES, Error::<T>::ProofTooLarge);
			let verifier = public_batch_verifier().map_err(|_| Error::<T>::VerifierNotAvailable)?;
			let inputs = verifier.parse_proof_bytes(proof).map_err(Self::proof_error)?;
			Ok(SettlementBundle::from_public_batch(&inputs))
		}

		/// Pre-validation plus the ZK verify.
		pub(crate) fn validate_public_batch(proof: &[u8]) -> Result<SettlementBundle, Error<T>> {
			ensure!(proof.len() <= MAX_PROOF_BYTES, Error::<T>::ProofTooLarge);
			let verifier = public_batch_verifier().map_err(|_| Error::<T>::VerifierNotAvailable)?;
			let inputs = verifier.verify_proof_bytes(proof).map_err(Self::proof_error)?;
			Ok(SettlementBundle::from_public_batch(&inputs))
		}

		/// Ciphertext bytes one settlement carries, for the declared weight.
		///
		/// The per-slot `ct_digest` is a byte sponge over both ciphertexts of
		/// the slot, so the hashing a settlement costs is linear in this, where
		/// the slot count alone says little. Saturating: an `outputs` vector
		/// large enough
		/// to overflow is refused by the block length limit long before it
		/// reaches a dispatch.
		pub fn ciphertext_bytes(outputs: &[ShieldedOutput<T>]) -> u32 {
			outputs.iter().fold(0u32, |total, output| {
				total
					.saturating_add(output.ct_1.len() as u32)
					.saturating_add(output.ct_2.len() as u32)
			})
		}

		// ------------------------------------------------------------------
		// Settlement
		// ------------------------------------------------------------------

		/// Every rule a settlement has to pass, with nothing written.
		///
		/// Two passes, split by cost. [`Pallet::plan_settlement`] is the cheap
		/// one: storage reads and integer comparisons over the segments, no
		/// hashing. [`Pallet::bind_payload`] is the one term linear in the
		/// submitted bytes. Pool admission runs them on either side of the ZK
		/// verify; a dispatch runs both, here, in full before `settle` touches
		/// state, so the whole submission is decided before any of it is
		/// written. The dispatch layer's storage rollback is the second line
		/// under that.
		pub(crate) fn check_settlement(
			bundle: &SettlementBundle,
			outputs: &[ShieldedOutput<T>],
		) -> Result<PlannedSettlement, Error<T>> {
			let plan = Self::plan_settlement(bundle, outputs)?;
			Self::bind_payload(bundle, outputs)?;
			Ok(plan)
		}

		/// Every settlement rule except the payload binding: what a submission
		/// settles, and whether it is allowed to.
		///
		/// This is the cheap half, and it is cheap on purpose. It reads
		/// `UsedNullifiers` twice per slot, looks up one block hash per segment,
		/// compares integers, and hashes nothing at all. The fee floors are
		/// evaluated here because they need only the slot counts and the
		/// lengths of the submitted ciphertexts, where the binding needs their
		/// bytes.
		///
		/// Pool admission runs this before the ZK verify, so the free forgery
		/// (a settled proof copied out of a finalized block with one byte of
		/// `outputs` changed) dies on a bounded storage walk. See
		/// `ValidateUnsigned::validate_unsigned` for why the other half runs
		/// behind the verify.
		pub(crate) fn plan_settlement(
			bundle: &SettlementBundle,
			outputs: &[ShieldedOutput<T>],
		) -> Result<PlannedSettlement, Error<T>> {
			// A submission whose every segment is padding settles nothing at
			// all, and `prove_padding_batch` produces one without holding a
			// note. Accepting one as a no-op would let anyone spend a block's
			// admission work for free.
			ensure!(!bundle.segments.is_empty(), Error::<T>::NothingToSettle);

			let current = frame_system::Pallet::<T>::block_number();
			let window = T::BlockHashWindow::get();
			let min_fee = T::MinLeafFee::get();

			let mut claimed = alloc::collections::BTreeSet::new();
			let mut fee_steps: u128 = 0;
			let mut slots: u32 = 0;
			let mut skipped_slots: u32 = 0;
			// The first anchor failure of the walk, kept so that a submission
			// settling nothing says why. An anchor that does not resolve is a
			// skip like a nullifier conflict, and a private batch has exactly
			// one segment, so without this a wallet whose proof named a block
			// this chain cannot resolve would be told its nullifiers were
			// already used.
			let mut stale_anchor: Option<Error<T>> = None;
			let mut settles = Vec::with_capacity(bundle.segments.len());
			// Walks every real slot of every segment, settling or not.
			// `outputs` covers all of them: a submitter cannot know which
			// segments were settled by someone else in the meantime, so the
			// positional mapping from slot to ciphertext pair has to stay
			// independent of that. [`SettlementBundle::real_slots`] is that
			// order, and `bind_payload` walks it.
			let mut real_slots: usize = 0;

			for segment in &bundle.segments {
				// A segment that reached this far is not padding, so it must
				// name a real block. The padding sentinel is filtered before
				// the block lookup on purpose: it carries block number 0 and
				// would otherwise be refused as a missing block by accident
				// where the rule is what should refuse it.
				debug_assert_ne!(segment.block_hash, padding_block_hash());
				ensure!(!segment.slots.is_empty(), Error::<T>::NothingToSettle);

				// A segment that conflicts with a nullifier already settled, or
				// with one an earlier segment of this submission claimed, is
				// skipped whole and the rest of the submission stands: see
				// `PlannedSettlement::settles` for what refusing the whole
				// submission would cost an aggregator's participants. The scan
				// runs before anything else about the segment, so a conflicting
				// segment's anchor and fee are not evaluated at all and a
				// parameter change between two settlements cannot make an
				// already-settled segment fatal on its second appearance. It is
				// also the whole of what a replay has to touch, which is what
				// makes this pass the right one to run first.
				let conflicts = segment.slots.iter().any(|slot| {
					slot.nullifiers.iter().any(|nullifier| {
						UsedNullifiers::<T>::contains_key(nullifier) || claimed.contains(nullifier)
					})
				});
				// A segment whose block anchor does not resolve is skipped on
				// the same argument; `Self::anchor_failure` carries what each
				// of the four conditions promises. Refusing the submission over
				// it would hand an aggregator's participants the griefing the
				// skip rule exists to close, and this half of it is the one an
				// aggregator cannot defend against at all: one reorg between
				// the recursive proving run and inclusion is enough, and a
				// participant can force it by handing over an inner anchored
				// near the edge of the window.
				//
				// The check is written per segment and it decides whole
				// submissions for the batches the circuits produce. The
				// public-batch circuit constrains every non-padding inner to
				// one block hash and one block number, so a verified public
				// batch has a single anchor and its segments stand or fall
				// together, and a private batch has one segment to begin with.
				// Per segment is still the shape this walk needs: it also runs
				// at pool admission over a parsed bundle no verifier has
				// touched, where that agreement is a claim, and the skip is
				// what keeps the walk total there.
				let skipped = if conflicts {
					true
				} else if let Some(error) = Self::anchor_failure(segment, current, window) {
					stale_anchor.get_or_insert(error);
					true
				} else {
					false
				};
				if skipped {
					settles.push(false);
					// The slots of a skipped segment still hold their positions
					// in `outputs`, and a position that carries bytes is still
					// bound by `bind_payload`: every real slot needs an entry,
					// so a position left unchecked is a place to carry bytes
					// nothing commits to on an unsigned, fee-free extrinsic. A
					// position emptied to a zero-length pair is the one
					// exemption, and it has nothing there to bind.
					//
					// No fee of the slot's own is evaluated, because a skipped
					// segment writes no nullifier, appends no leaf and stores no
					// ciphertext, so there is no permanent state for a fee to
					// price. The slot still costs every node the admission walk
					// over it and the weight the submission declares, so the
					// submission floor below charges it the same flat minimum a
					// settling slot pays, beside the bytes it carries.
					skipped_slots = u32::try_from(segment.slots.len())
						.ok()
						.and_then(|count| skipped_slots.checked_add(count))
						.ok_or(Error::<T>::ValueOutOfRange)?;
					real_slots = real_slots
						.checked_add(segment.slots.len())
						.ok_or(Error::<T>::ValueOutOfRange)?;
					continue;
				}
				settles.push(true);

				for slot in &segment.slots {
					ensure!(
						slot.fee <= qnero_circuit::chain::MAX_VALUE,
						Error::<T>::ValueOutOfRange
					);

					// `is_padding` asks whether *both* commitments are zero, so
					// a slot with one zero and one real commitment is not
					// padding and reaches here. No valid proof produces one,
					// since a commitment is a Poseidon2 output, but the append
					// would otherwise fail halfway through the write.
					for commitment in &slot.commitments {
						ensure!(*commitment != [0u8; 32], Error::<T>::ZeroCommitment);
					}

					for nullifier in &slot.nullifiers {
						ensure!(*nullifier != [0u8; 32], Error::<T>::ZeroNullifier);
						// The scan above already refused a nullifier this chain
						// or an earlier segment holds, so a failure here is a
						// repeat inside this segment. The private-batch circuit
						// forbids that, which leaves a hand-built bundle and a
						// future circuit change as the paths that reach it.
						ensure!(claimed.insert(*nullifier), Error::<T>::DuplicateNullifier);
					}

					let output =
						outputs.get(real_slots).ok_or(Error::<T>::CiphertextCountMismatch)?;

					// A settling slot has to carry both of its ciphertexts. An
					// emptied position is the exemption a skipped position may
					// take, and `bind_payload` evaluates no `ct_digest` for
					// one, so taking it here would store an output note no
					// recipient can find behind a digest nothing checked. A
					// real `NoteCiphertext` is 1731 bytes at the chain's
					// parameter set, so nothing legitimate is refused.
					ensure!(
						!output.ct_1.is_empty() && !output.ct_2.is_empty(),
						Error::<T>::EmptyCiphertext
					);

					// The fee floor is the flat minimum plus the payload the
					// slot writes into permanent state. Only the lengths are
					// needed here; the bytes themselves are bound in
					// `bind_payload`.
					ensure!(
						slot.fee >= Self::fee_floor(min_fee, Self::output_bytes(output)),
						Error::<T>::FeeBelowMinimum
					);

					fee_steps = fee_steps
						.checked_add(slot.fee as u128)
						.ok_or(Error::<T>::ValueOutOfRange)?;
					slots = slots.checked_add(1).ok_or(Error::<T>::ValueOutOfRange)?;
					real_slots = real_slots.checked_add(1).ok_or(Error::<T>::ValueOutOfRange)?;
				}
			}

			// Every segment was skipped: the whole submission settles nothing,
			// which is what a replay looks like, and accepting it as a no-op
			// would let anyone spend a block's admission work for free. This is
			// the refusal the free forgery lands on, and it is reached without
			// hashing a byte of the payload. An anchor failure is reported in
			// preference to the replay error, because a private batch has one
			// segment and a wallet whose proof named a block this chain cannot
			// resolve is owed the reason it cannot.
			if slots == 0 {
				return Err(stale_anchor.unwrap_or(Error::<T>::NullifierAlreadyUsed));
			}

			// Exactly one `ShieldedOutput` per real slot, skipped segments
			// included. A trailing extra would otherwise ride along unbound by
			// any proof.
			ensure!(outputs.len() == real_slots, Error::<T>::CiphertextCountMismatch);

			// The submission floor. The slots that settle pay
			// [`Config::MinLeafFee`] for every real slot the submission
			// carries, settling and skipped alike, plus one step per started
			// [`Config::CiphertextBytesPerFeeQuantum`] bytes of payload, the
			// bytes of its skipped segments included.
			//
			// It prices slots as well as bytes. Every real slot the submission
			// carries costs every node the admission walk over it, two
			// `UsedNullifiers` probes, a position in `outputs` and the weight
			// the extrinsic declares for it, whether or not it settles, and an
			// unsigned settlement pays nothing else. So a carried slot is
			// charged the flat minimum a settling slot is charged, and a
			// carried byte is charged what a settling byte is charged. Reading
			// both is what makes the floor hold in every shape: the payload per
			// slot and the slot count per segment are the submitter's to choose
			// independently, so a rule reading one of them alone would price a
			// number the submitter moves for free.
			//
			// It costs an honest submission nothing. A submission that settles
			// everything it carries passes this the moment it passes the
			// per-slot floors, because `sum(ceil(b_i / q))` is at least
			// `ceil(sum(b_i) / q)` and each slot already paid its own flat
			// minimum. An aggregator griefed between submission and inclusion
			// cannot raise a fee after proving (every fee is a public input
			// fixed by the leaf circuit), so its remedy is to recompose a
			// fresh public batch without the conflicted inners, which costs
			// one public-batch proof. The floor prices the declared weight
			// and the settlement walk a carried slot costs at pre_dispatch
			// and dispatch; it cannot price the admission walk of a blob
			// that never reaches dispatch, which is the pool-level open
			// issue recorded in docs/CIRCUIT.md 9.10. What a submission may
			// not do is hand a block 317 slots of walk and weight for the
			// price of one, which is what emptying the outputs alone bought.
			let carried_bytes = Self::carried_bytes(outputs);
			let payload_steps = carried_bytes.div_ceil(Self::bytes_per_fee_quantum());
			let submission_floor = u128::from(slots)
				.checked_add(u128::from(skipped_slots))
				.and_then(|carried| carried.checked_mul(u128::from(min_fee)))
				.and_then(|flat| flat.checked_add(u128::from(payload_steps)))
				.ok_or(Error::<T>::ValueOutOfRange)?;
			ensure!(fee_steps >= submission_floor, Error::<T>::PayloadUnderpaid);

			// Two commitments per slot, plus at most one wormhole leaf for the
			// author's fee share.
			let appends = u64::from(slots).saturating_mul(2).saturating_add(1);
			ensure!(appends <= T::ZkTree::remaining_capacity(), Error::<T>::TreeFull);

			// The fee leaves the pool, so the pool has to hold it. A fee above
			// `PoolValue` means the circuit's balance equation was broken or an
			// entry point forgot to credit the pool, and the settlement is
			// refused before anything is written. A saturating subtraction here
			// would mint the author a share of a fee nothing backs and zero the
			// pallet's own books on the way past, with nothing on chain to say
			// the two stopped agreeing.
			ensure!(
				PoolValue::<T>::get() >= Self::fee_planck(fee_steps)?,
				Error::<T>::PoolUnderflow
			);

			Ok(PlannedSettlement { fee_steps, slots, skipped_slots, carried_bytes, settles })
		}

		/// Why a segment's block anchor does not resolve, or `None` when it
		/// does.
		///
		/// A settleable segment must name a block that is already finished,
		/// inside [`Config::BlockHashWindow`], present in
		/// `frame_system::BlockHash`, and whose hash equals the segment's
		/// `block_hash` public input. The public input arrives as four
		/// canonical Goldilocks limbs and the chain's header hash is a
		/// Poseidon2 output stored in the same 32-byte little-endian-per-limb
		/// form, so the comparison is lossless.
		///
		/// Failing any of the four skips the segment and leaves the rest of
		/// the submission standing: see [`PlannedSettlement::settles`].
		///
		/// Three of the four are permanent. The window only moves forward, a
		/// pruned hash does not come back, and an orphaned one never becomes
		/// canonical again, so a segment that fails one of those cannot settle
		/// at this height or at any later one, and refusing it and skipping it
		/// are the same outcome for it.
		///
		/// The fourth, an anchor at or above the current height, is a claim
		/// about a block this chain has not finished, and that height does
		/// arrive later. It is a skip all the same, deliberately. A refusal
		/// would hand an aggregator's participants exactly the grief the skip
		/// rule exists to close, and an inner anchored in the future is one
		/// line of a hand-built witness, which makes it the cheapest shape to
		/// inflict. What the skip promises is narrower and is all a plan for
		/// this block needs: the segment does not settle here. A skipped
		/// segment writes nothing, so the same proof can settle in a later
		/// submission if that height ever resolves to the hash it named, and
		/// that takes predicting a future header hash.
		fn anchor_failure(
			segment: &Segment,
			current: BlockNumberFor<T>,
			window: BlockNumberFor<T>,
		) -> Option<Error<T>> {
			let anchored_at = BlockNumberFor::<T>::from(segment.block_number);
			// The block being built has no hash yet, and a height above it is
			// a claim about a block this chain has not produced. Skipped, for
			// the reason in the doc above; it is the one condition of the four
			// that is not permanent.
			if anchored_at >= current {
				return Some(Error::<T>::BlockOutsideWindow);
			}
			if current.saturating_sub(anchored_at) > window {
				return Some(Error::<T>::BlockOutsideWindow);
			}
			let on_chain = frame_system::Pallet::<T>::block_hash(anchored_at);
			// `BlockHash` returns the default hash for a height outside the
			// pruning window, which is also the all-zero sentinel.
			if on_chain == <T as frame_system::Config>::Hash::default() {
				return Some(Error::<T>::BlockNotFound);
			}
			if on_chain.as_ref() != segment.block_hash.as_slice() {
				return Some(Error::<T>::BlockHashMismatch);
			}
			None
		}

		/// Bind every real slot's ciphertexts to the `ct_digest` its proof
		/// publishes.
		///
		/// This is the whole of the settlement check that is linear in the
		/// submitted bytes: one Poseidon2 byte sponge per slot, over both of its
		/// ciphertexts. Every real slot is bound, whether or not this submission
		/// settles it. The circuit leaves `ct_digest` a free public input, so
		/// this comparison is the whole binding between a proof and the bytes
		/// submitted with it, and a slot position left unbound is a place to put
		/// bytes no proof commits to.
		///
		/// One position is exempt: a pair of zero-length ciphertexts. It carries
		/// no bytes, so there is nothing there to bind and nothing to price,
		/// and it is what lets an aggregator whose segments went stale between
		/// submission and inclusion resubmit the batch with those segments'
		/// outputs emptied. The exemption is safe because
		/// [`Pallet::plan_settlement`] refuses an emptied position in a segment
		/// that settles, and it runs ahead of this on every path that reaches
		/// here, so an emptied position belongs to a skipped segment.
		///
		/// It walks [`SettlementBundle::real_slots`], which is the order
		/// `outputs` follows and the order `settle` writes in.
		pub(crate) fn bind_payload(
			bundle: &SettlementBundle,
			outputs: &[ShieldedOutput<T>],
		) -> Result<(), Error<T>> {
			for (index, slot) in bundle.real_slots().enumerate() {
				let output = outputs.get(index).ok_or(Error::<T>::CiphertextCountMismatch)?;
				if output.ct_1.is_empty() && output.ct_2.is_empty() {
					continue;
				}
				let recomputed = qnero_circuit::chain::ct_digest(&[
					output.ct_1.as_slice(),
					output.ct_2.as_slice(),
				]);
				ensure!(recomputed == slot.ct_digest, Error::<T>::CiphertextDigestMismatch);
			}
			Ok(())
		}

		/// Ciphertext bytes one settlement output carries.
		fn output_bytes(output: &ShieldedOutput<T>) -> u64 {
			(output.ct_1.len() as u64).saturating_add(output.ct_2.len() as u64)
		}

		/// Ciphertext bytes the whole submission carries, settling and skipped
		/// positions alike. This is the payload term of the submission fee
		/// floor, beside the flat minimum every carried slot pays, and an
		/// emptied position contributes zero to it.
		///
		/// Saturating: `outputs` is bounded by the block length limit long
		/// before a `u64` of bytes is reachable.
		fn carried_bytes(outputs: &[ShieldedOutput<T>]) -> u64 {
			outputs
				.iter()
				.fold(0u64, |total, output| total.saturating_add(Self::output_bytes(output)))
		}

		/// Bytes of ciphertext one step of fee buys.
		///
		/// `integrity_test` refuses a zero divisor; the clamp keeps a
		/// misconfigured runtime from dividing by zero on a live block. Both
		/// fee floors read it here, so the per-slot floor and the submission
		/// floor cannot disagree about the price of a byte.
		fn bytes_per_fee_quantum() -> u64 {
			u64::from(T::CiphertextBytesPerFeeQuantum::get().max(1))
		}

		/// The fee one real leaf slot must carry, in pool steps: the flat
		/// floor plus one step per started
		/// [`Config::CiphertextBytesPerFeeQuantum`] bytes of ciphertext.
		///
		/// The payload term is what prices the permanent state a slot adds.
		/// `Ciphertexts` is never pruned, the chain never parses these bytes,
		/// and a settler can fill both fields to
		/// [`Config::MaxCiphertextBytes`] with anything it likes, so a flat
		/// floor buys as much state as the cap allows for one step.
		fn fee_floor(min_fee: u64, ciphertext_bytes: u64) -> u64 {
			min_fee.saturating_add(ciphertext_bytes.div_ceil(Self::bytes_per_fee_quantum()))
		}

		/// A fee in pool steps as a balance in planck.
		fn fee_planck(fee_steps: u128) -> Result<BalanceOf<T>, Error<T>> {
			fee_steps
				.checked_mul(POOL_STEP)
				.ok_or(Error::<T>::ValueOutOfRange)?
				.try_into()
				.map_err(|_| Error::<T>::ValueOutOfRange)
		}

		/// Check everything, then write.
		pub(crate) fn settle(
			bundle: SettlementBundle,
			outputs: Vec<ShieldedOutput<T>>,
		) -> DispatchResultWithPostInfo {
			let plan = Self::check_settlement(&bundle, &outputs)?;

			let block_number = frame_system::Pallet::<T>::block_number();
			let mut output_index = 0usize;
			for (segment, settles) in bundle.segments.iter().zip(plan.settles.iter()) {
				// A segment this submission does not settle is skipped whole.
				// Its slots still occupy their positions in `outputs`, so the
				// index walks past them. A position that carries bytes was
				// bound to the segment's own `ct_digest` by `check_settlement`;
				// one emptied to a zero-length pair binds nothing, which is the
				// exemption `bind_payload` states and the one shape here that
				// was not checked against a digest.
				if !settles {
					output_index = output_index.saturating_add(segment.slots.len());
					continue;
				}
				for slot in &segment.slots {
					for nullifier in &slot.nullifiers {
						UsedNullifiers::<T>::insert(nullifier, ());
					}

					let output = &outputs[output_index];
					output_index += 1;

					// Both commitments are Poseidon2 outputs of a verified
					// proof and neither is zero, so neither append can fail.
					// The `?` is what keeps that an assertion.
					let first = T::ZkTree::insert_commitment(slot.commitments[0])?;
					let second = T::ZkTree::insert_commitment(slot.commitments[1])?;
					Ciphertexts::<T>::insert(first, &output.ct_1);
					Ciphertexts::<T>::insert(second, &output.ct_2);
					LeafBlocks::<T>::insert(first, block_number);
					LeafBlocks::<T>::insert(second, block_number);

					Self::deposit_event(Event::SlotSettled {
						nullifiers: slot.nullifiers,
						commitments: slot.commitments,
						leaf_indices: (first, second),
						ciphertexts: (output.ct_1.to_vec(), output.ct_2.to_vec()),
					});
				}
			}

			let fee = Self::account_fee(plan.fee_steps)?;
			Self::deposit_event(Event::BatchSettled {
				segments: plan.settles.iter().filter(|settles| **settles).count() as u32,
				slots: plan.slots,
				fee,
			});

			Ok(Pays::No.into())
		}

		/// Split a settled fee between the burn and the block author, and take
		/// it out of the pool.
		///
		/// The whole fee leaves the pool. The burn share simply stops existing:
		/// it is value the pool was standing behind and now stands behind
		/// nothing, which is what makes it a burn. The author's share is held
		/// in [`PendingCoinbaseFee`] until `on_finalize`, where it becomes part
		/// of the block's coinbase note. It is never a transparent credit, so
		/// no account and no issuance moves here at all: under v1 mandatory
		/// privacy the author is paid in notes like everyone else, and the only
		/// thing that knows who the author is is the payload its own node
		/// supplied.
		fn account_fee(fee_steps: u128) -> Result<BalanceOf<T>, DispatchError> {
			if fee_steps == 0 {
				return Ok(Zero::zero());
			}
			let fee = Self::fee_planck(fee_steps)?;

			// `check_settlement` already refused a fee above the pool, so this
			// subtraction cannot fail. It is checked so that a future entry
			// point which forgets to credit `PoolValue` fails the settlement,
			// where a saturating subtraction would mint the difference.
			let pool = PoolValue::<T>::get().checked_sub(&fee).ok_or(Error::<T>::PoolUnderflow)?;
			PoolValue::<T>::put(pool);

			// Rounds against the author.
			let burn_steps = T::FeeBurnRate::get().mul_ceil(fee_steps);
			let author_steps = fee_steps.saturating_sub(burn_steps);
			if author_steps == 0 {
				return Ok(fee);
			}
			let author_amount = Self::fee_planck(author_steps)?;
			PendingCoinbaseFee::<T>::mutate(|pending| {
				*pending = pending.saturating_add(author_amount)
			});
			Self::deposit_event(Event::AuthorFeeAccrued { amount: author_amount });

			Ok(fee)
		}

		/// The block author, through the one seam this pallet reads consensus
		/// through. See [`Config::FindAuthor`].
		pub fn block_author() -> Option<T::AccountId> {
			T::FindAuthor::find_author(
				frame_system::Pallet::<T>::digest()
					.logs
					.iter()
					.filter_map(|log| log.as_pre_runtime()),
			)
		}

		/// Mint this block's coinbase note.
		///
		/// `minted` is the emission `pallet-mining-rewards` computed plus the
		/// transaction fees it collected, which is value that is not in
		/// `Balances::total_issuance()`: fees were burned when their imbalance
		/// dropped and emission has not been created yet. Adding it to
		/// [`PoolValue`] is what creates it, in the pool, as a note. The
		/// author's share of this block's settled fees comes with it.
		///
		/// Returns the credit when there is no note to mint it into, and the
		/// caller holds it for the next block. Sub-step change stays in
		/// [`PendingCoinbaseFee`] for the same reason: a note's value is a
		/// whole number of pool steps, and nothing is allowed to vanish
		/// between the two books.
		fn mint_coinbase(minted: BalanceOf<T>) -> Result<(), BalanceOf<T>> {
			let Some(payload) = PendingCoinbase::<T>::take() else {
				// No coinbase inherent in this block. The inherent check
				// refuses such a block on import, so this is reachable only in
				// a runtime test or a block built by something that is not a
				// Qnero node.
				if !minted.is_zero() {
					Self::deposit_event(Event::CoinbaseDeferred { amount: minted });
				}
				return Err(minted);
			};

			let pending_fee = PendingCoinbaseFee::<T>::get();
			let total = minted.saturating_add(pending_fee);
			let Ok(total_planck) = TryInto::<u128>::try_into(total) else {
				return Err(minted);
			};
			let steps_u128 = total_planck / POOL_STEP;
			let change = total_planck % POOL_STEP;
			let Ok(steps) = u64::try_from(steps_u128) else {
				return Err(minted);
			};
			// The 62-bit cap, on this creation path like every other. The
			// emission cannot reach it at any supply this chain has, and the
			// check is here because what it protects is the argument behind the
			// circuit's balance equation.
			if steps == 0 || steps > qnero_circuit::chain::MAX_VALUE {
				return Err(minted);
			}
			let Some(commitment) = qnero_circuit::chain::commitment(&payload.inner, steps) else {
				// Refused at the inherent, so unreachable here.
				return Err(minted);
			};
			let Ok(leaf_index) = T::ZkTree::insert_commitment(commitment) else {
				return Err(minted);
			};
			let Ok(value) =
				TryInto::<BalanceOf<T>>::try_into(steps_u128.saturating_mul(POOL_STEP))
			else {
				return Err(minted);
			};
			let Ok(change) = TryInto::<BalanceOf<T>>::try_into(change) else {
				return Err(minted);
			};

			let block_number = frame_system::Pallet::<T>::block_number();
			// Only when there is one, which under v1 is never: the inherent
			// refuses a non-empty payload, and a derived coinbase carries none
			// anyway. The branch is where a priced third-party payload would
			// land, and an empty entry would be a key the wallet reads for
			// nothing.
			if !payload.ciphertext.is_empty() {
				Ciphertexts::<T>::insert(leaf_index, &payload.ciphertext);
			}
			LeafBlocks::<T>::insert(leaf_index, block_number);
			CoinbaseValues::<T>::insert(leaf_index, steps);
			PoolValue::<T>::mutate(|pool| *pool = pool.saturating_add(value));
			PendingCoinbaseFee::<T>::put(change);

			Self::deposit_event(Event::CoinbaseMinted {
				block_number,
				leaf_index,
				inner: payload.inner,
				value,
				has_ciphertext: !payload.ciphertext.is_empty(),
			});
			Ok(())
		}

		/// Transaction-pool dedup tag: a hash of the submission's nullifiers,
		/// sorted within each segment.
		///
		/// Sorting within a segment keeps two proofs that publish the same
		/// multiset in different privately chosen orders on one tag, while the
		/// segment boundaries stay part of the preimage.
		///
		/// What the tag excludes is byte-different rebroadcasts of one
		/// submission: they hash to one tag, hold one pool slot, and under a
		/// constant priority the first seen keeps it. That is sound only
		/// because admission verifies, since a forged blob carrying a victim's
		/// nullifiers would otherwise take the victim's slot.
		///
		/// It is deliberately not cross-submission double-spend exclusion. The
		/// preimage carries the submission's segmentation, so a private batch
		/// and the public batch that wraps it as one inner spend the same notes
		/// and hash to different tags; both are admitted and both can reach one
		/// block. What excludes a double spend is `UsedNullifiers` inside
		/// `check_settlement`, and the segment-skip rule in
		/// [`PlannedSettlement::settles`] is what lets that pair settle once
		/// between them.
		pub(crate) fn settlement_provides_tag(bundle: &SettlementBundle) -> Hash256 {
			let mut preimage = Vec::new();
			preimage.extend_from_slice(&(bundle.segments.len() as u32).to_le_bytes());
			for segment in &bundle.segments {
				preimage.extend_from_slice(&(segment.slots.len() as u32).to_le_bytes());
				let mut nullifiers: Vec<Hash256> =
					segment.slots.iter().flat_map(|slot| slot.nullifiers).collect();
				nullifiers.sort_unstable();
				for nullifier in nullifiers {
					preimage.extend_from_slice(&nullifier);
				}
			}
			sp_io::hashing::blake2_256(&preimage)
		}
	}

	/// Where `pallet-mining-rewards` pays the block reward.
	///
	/// The reward does not reach an account. It becomes the value of this
	/// block's coinbase note, beside the author's share of the fees the block
	/// settled, and the pool stands behind both.
	impl<T: Config> CoinbaseSink<BalanceOf<T>> for Pallet<T> {
		fn deposit_coinbase(amount: BalanceOf<T>) -> Result<(), BalanceOf<T>> {
			Self::mint_coinbase(amount)
		}
	}

	/// Value the pool holds, for a supply measure that has to cover both books.
	///
	/// `Balances::total_issuance()` counts transparent balances and nothing
	/// else: shielding burns from the shielder and credits [`PoolValue`], so
	/// the planck that moved into the pool left issuance behind. Under v1 that
	/// is where nearly every planck ends up, so an emission schedule that
	/// measured supply by issuance alone would see supply fall as the pool
	/// filled and mint faster forever. `pallet-mining-rewards` adds this to the
	/// issuance it reads, and the sum is the whole supply.
	///
	/// [`PendingCoinbaseFee`] is in it because that value is inside the pool
	/// too: it left [`PoolValue`] on its way to a note that has not been minted
	/// yet, and it is minted into one in the same block unless the block has no
	/// coinbase at all.
	pub struct ShieldedSupply<T>(core::marker::PhantomData<T>);

	impl<T: Config> Get<BalanceOf<T>> for ShieldedSupply<T> {
		fn get() -> BalanceOf<T> {
			PoolValue::<T>::get().saturating_add(PendingCoinbaseFee::<T>::get())
		}
	}
}
