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
//!   The chain does it, and a repeat aborts the whole submission before any state changes.
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
/// about 157 KB at the chain default, and a public batch is the same shape with
/// a wider forwarded region. If a circuit change ever pushes a real proof past
/// this cap, every settlement test fails at the same time as the size gate.
pub const MAX_PROOF_BYTES: usize = 512 * 1024;

/// One pool quantum in planck: the unit a note value is counted in.
///
/// A note commits its value as a single field element, and the chain's balance
/// is `u128` planck at twelve decimals, so the two are related by a fixed
/// quantum. It is the same quantum `pallet-zk-tree` uses for a wormhole leaf's
/// amount, which is what lets one tree hold both without two notions of "one
/// unit"; `SHIELDED_QUANTUM_MATCHES_ZK_TREE` asserts that.
pub const POOL_QUANTUM: u128 = 10_000_000_000;

const _: () = assert!(POOL_QUANTUM == pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR);

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
	/// The slot's fee, in pool quanta.
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

	/// Every real slot of every segment, in settlement order. This is the order
	/// the `outputs` argument of a settlement extrinsic follows.
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
		dispatch::{DispatchResultWithPostInfo, Pays},
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate, Unbalanced},
			tokens::{Fortitude, Precision, Preservation},
		},
		BoundedVec,
	};
	use frame_system::pallet_prelude::*;
	use pallet_zk_tree::ZkCommitmentRecorder;
	use qp_wormhole::TransferProofRecorder;
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

	#[pallet::config]
	pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
		/// The native currency. A shield burns from it and a settled fee mints
		/// back into it; see the module docs on pool accounting.
		type Currency: Mutate<Self::AccountId> + Inspect<Self::AccountId>;

		/// The commitment tree. Shielded leaves and wormhole transfer leaves
		/// share one instance, because the circuit's `zk_tree_root` is the one
		/// root the block header carries.
		type ZkTree: ZkCommitmentRecorder;

		/// Records a transparent credit as a wormhole leaf.
		///
		/// The block author's fee share is minted to the QPoW-derived author
		/// account, which has no signing key: a wormhole leaf is its only spend
		/// path, so a credit without one is frozen forever. This is the same
		/// seam `pallet-mining-rewards` uses for the block reward.
		type ProofRecorder: qp_wormhole::TransferProofRecorder<
			Self::AccountId,
			u32,
			BalanceOf<Self>,
		>;

		/// The nominal sender of a minted fee credit, as it appears in the
		/// wormhole leaf. Shared with `pallet-mining-rewards`.
		#[pallet::constant]
		type MintingAccount: Get<Self::AccountId>;

		/// How far back a settlement may anchor.
		///
		/// A proof binds the header of one block, and the chain resolves that
		/// hash from `frame_system::BlockHash`, which is pruned. The window is
		/// the smaller of the two bounds and is what stops a wallet submitting
		/// a proof built against a block so old that the anonymity set it saw
		/// is a small prefix of the current tree.
		#[pallet::constant]
		type BlockHashWindow: Get<BlockNumberFor<Self>>;

		/// Minimum fee, in pool quanta, that every real leaf slot must carry.
		///
		/// The anti-spam mechanism. One note of any value spent with a dummy in
		/// the other slot mints two spendable notes, so nothing else bounds how
		/// many leaves a prover can produce, and each one writes two nullifier
		/// entries and two tree slots into permanent state.
		#[pallet::constant]
		type MinLeafFee: Get<u64>;

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
		/// The block author's share of a settled fee.
		AuthorFeePaid { author: T::AccountId, amount: BalanceOf<T> },
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
		/// The settlement would take the tree past the depth the circuit can
		/// prove.
		TreeFull,
		/// A shielded value is not a positive whole number of pool quanta.
		ValueNotQuantized,
		/// The `inner` of a shield is not four canonical Goldilocks limbs.
		NonCanonicalInner,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
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
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Settle one private batch: the transaction a wallet submits.
		///
		/// `outputs` carries the two note ciphertexts of every real leaf slot,
		/// in slot order, skipped segments included. The body deliberately
		/// re-runs only the cheap pre-validation: the ZK verify already ran in
		/// `ValidateUnsigned::pre_dispatch`, which is the block-inclusion gate,
		/// and repeating it here would double the verify cost. The settlement
		/// check does run twice, once there and once in `settle`, and the
		/// declared weight prices both passes: the second is the only guard on
		/// a path that reaches a dispatch without `ValidateUnsigned`, which a
		/// root-scheduled `dispatch_as` would be.
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
			let bundle = Self::pre_validate_private_batch(&proof)?;
			Self::settle(bundle, outputs)
		}

		/// Settle one public batch: an aggregator's bundle of private batches.
		///
		/// All or nothing. The circuit stops the same inner appearing twice and
		/// says nothing about one nullifier appearing in two different inners,
		/// so the whole submission is validated before any of it is written.
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
			let bundle = Self::pre_validate_public_batch(&proof)?;
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
		#[pallet::weight(T::WeightInfo::shield())]
		pub fn shield(
			origin: OriginFor<T>,
			value: BalanceOf<T>,
			inner: Hash256,
			ciphertext: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let value_u128: u128 = value.try_into().map_err(|_| Error::<T>::ValueOutOfRange)?;
			ensure!(
				value_u128 > 0 && value_u128.is_multiple_of(POOL_QUANTUM),
				Error::<T>::ValueNotQuantized
			);
			// The 62-bit range check. Every value that enters the pool outside a
			// spend proof has to carry it, or the no-wrap argument behind the
			// circuit's balance equation does not hold for the notes created
			// this way.
			let quanta = u64::try_from(value_u128 / POOL_QUANTUM)
				.map_err(|_| Error::<T>::ValueOutOfRange)?;
			ensure!(quanta <= qnero_circuit::chain::MAX_VALUE, Error::<T>::ValueOutOfRange);

			let commitment = qnero_circuit::chain::commitment(&inner, quanta)
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
			// the pool, and refusing to let the last quantum leave would make
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
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// Pool admission verifies the proof, in this order: the size gate
			// before anything is copied, deserialization, the canonical-encoding
			// round trip, the public-input parse, the ZK verify, and only then
			// the settlement check.
			//
			// The verify belongs at admission, and `pre_dispatch` repeats it
			// for block import. That is what makes a settlement expensive to
			// forge. Nothing in the parse is
			// cryptography: a proof carries its public inputs as a plain
			// vector, so anyone can take a genuine proof, rewrite its public
			// inputs to claim any nullifiers, commitments, fee and block
			// anchor, re-serialize canonically, and produce a blob that passes
			// every check short of the verify. Admitting that blob costs each
			// node the whole per-slot settlement walk, which at a full public
			// batch is far more work than the verify it was deferring, and
			// `propagate(true)` hands it to the next node. It reaches a block
			// author, fails `pre_dispatch`, and is charged nothing: settlement
			// extrinsics are unsigned and `Pays::No`.
			//
			// What the split was written to prevent, one proof's byte variants
			// each forcing a verify, is closed by the canonical-encoding round
			// trip: one proof has exactly one encoding, so a distinct admitted
			// proof needs real proving work.
			let (bundle, prefix) = match call {
				Call::submit_private_batch { proof, outputs } => (
					Self::validate_private_batch(proof)
						.and_then(|bundle| {
							Self::check_settlement(&bundle, outputs)?;
							Ok(bundle)
						})
						.map_err(|_| InvalidTransaction::Call)?,
					"QneroPrivateBatch",
				),
				Call::submit_public_batch { proof, outputs } => (
					Self::validate_public_batch(proof)
						.and_then(|bundle| {
							Self::check_settlement(&bundle, outputs)?;
							Ok(bundle)
						})
						.map_err(|_| InvalidTransaction::Call)?,
					"QneroPublicBatch",
				),
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
			match call {
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
		/// Summed fee of every slot that will settle, in pool quanta. A segment
		/// that settled before contributes nothing: its fee was accounted then.
		pub fee_quanta: u128,
		/// Real leaf slots that will settle.
		pub slots: u32,
		/// One flag per segment of the bundle, in order: whether this
		/// submission settles it.
		///
		/// A segment every one of whose nullifiers is already in
		/// `UsedNullifiers` settled before and is skipped whole. That case is
		/// reachable for free: every inner of an aggregator's public batch is
		/// exactly the artifact `submit_private_batch` accepts, so a
		/// participant can settle its own inner directly and, if a repeat were
		/// fatal, strand the other fifty-two transfers in the batch and waste
		/// the aggregator's recursive proving run. Skipping is value neutral,
		/// because that segment's commitments were appended and its fee
		/// accounted by the settlement that got there first.
		pub settles: Vec<bool>,
	}

	impl<T: Config> Pallet<T> {
		// ------------------------------------------------------------------
		// Verification pipeline
		// ------------------------------------------------------------------

		/// Why the verifier refused a proof, as this pallet's own error.
		///
		/// The four kinds are four different operator problems and the pallet
		/// declares an error for each. A deserialization failure is also what a
		/// proof built at other circuit dimensions looks like, which is the
		/// realistic version of it: a wallet whose artifact set was generated
		/// with a different `QNERO_NUM_LEAF_PROOFS` produces proofs this
		/// runtime cannot read, so the log line names the dimensions the
		/// runtime was built for.
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
		/// This is the dispatch body's path, after `pre_dispatch` has already
		/// verified. Nothing in it establishes that the public inputs are a
		/// proof's: only a verify does that.
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
		/// This runs in full before `settle` touches state, so a submission is
		/// all or nothing by construction. The dispatch layer's storage
		/// rollback is the second line under it.
		pub(crate) fn check_settlement(
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
			let mut fee_quanta: u128 = 0;
			let mut slots: u32 = 0;
			let mut settles = Vec::with_capacity(bundle.segments.len());
			// Walks every real slot of every segment, settling or not.
			// `outputs` covers all of them: a submitter cannot know which
			// segments were settled by someone else in the meantime, so the
			// positional mapping from slot to ciphertext pair has to stay
			// independent of that.
			let mut real_slots: u32 = 0;

			for segment in &bundle.segments {
				// A segment that reached this far is not padding, so it must
				// name a real block. The padding sentinel is filtered before
				// the block lookup on purpose: it carries block number 0 and
				// would otherwise be refused as a missing block by accident
				// where the rule is what should refuse it.
				debug_assert_ne!(segment.block_hash, padding_block_hash());
				ensure!(!segment.slots.is_empty(), Error::<T>::NothingToSettle);
				let segment_slots =
					u32::try_from(segment.slots.len()).map_err(|_| Error::<T>::ValueOutOfRange)?;

				// A segment whose every nullifier is already settled was
				// settled before, commitments, fee and all. Skip it whole and
				// let the submission stand: see
				// `PlannedSettlement::settles`. A segment that is only partly
				// settled is not this case and falls through to the per-slot
				// check, which refuses it with `NullifierAlreadyUsed`.
				let settled_before = segment
					.slots
					.iter()
					.all(|slot| slot.nullifiers.iter().all(UsedNullifiers::<T>::contains_key));
				if settled_before {
					settles.push(false);
					real_slots =
						real_slots.checked_add(segment_slots).ok_or(Error::<T>::ValueOutOfRange)?;
					continue;
				}
				settles.push(true);

				let anchored_at = BlockNumberFor::<T>::from(segment.block_number);
				ensure!(anchored_at < current, Error::<T>::BlockOutsideWindow);
				ensure!(
					current.saturating_sub(anchored_at) <= window,
					Error::<T>::BlockOutsideWindow
				);
				let on_chain = frame_system::Pallet::<T>::block_hash(anchored_at);
				// `BlockHash` returns the default hash for a height outside the
				// pruning window, which is also the all-zero sentinel.
				ensure!(
					on_chain != <T as frame_system::Config>::Hash::default(),
					Error::<T>::BlockNotFound
				);
				ensure!(
					on_chain.as_ref() == segment.block_hash.as_slice(),
					Error::<T>::BlockHashMismatch
				);

				for slot in &segment.slots {
					ensure!(slot.fee >= min_fee, Error::<T>::FeeBelowMinimum);
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
						ensure!(
							!UsedNullifiers::<T>::contains_key(nullifier),
							Error::<T>::NullifierAlreadyUsed
						);
						ensure!(claimed.insert(*nullifier), Error::<T>::DuplicateNullifier);
					}

					let output = outputs
						.get(real_slots as usize)
						.ok_or(Error::<T>::CiphertextCountMismatch)?;
					let recomputed = qnero_circuit::chain::ct_digest(&[
						output.ct_1.as_slice(),
						output.ct_2.as_slice(),
					]);
					ensure!(recomputed == slot.ct_digest, Error::<T>::CiphertextDigestMismatch);

					fee_quanta = fee_quanta
						.checked_add(slot.fee as u128)
						.ok_or(Error::<T>::ValueOutOfRange)?;
					slots = slots.checked_add(1).ok_or(Error::<T>::ValueOutOfRange)?;
					real_slots = real_slots.checked_add(1).ok_or(Error::<T>::ValueOutOfRange)?;
				}
			}

			// Every segment was settled before: the whole submission is a
			// replay, and accepting it as a no-op would let anyone spend a
			// block's admission work for free.
			ensure!(slots > 0, Error::<T>::NullifierAlreadyUsed);

			// Exactly one `ShieldedOutput` per real slot, skipped segments
			// included. A trailing extra would otherwise ride along unbound by
			// any proof.
			ensure!(outputs.len() == real_slots as usize, Error::<T>::CiphertextCountMismatch);

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
				PoolValue::<T>::get() >= Self::fee_planck(fee_quanta)?,
				Error::<T>::PoolUnderflow
			);

			Ok(PlannedSettlement { fee_quanta, slots, settles })
		}

		/// A fee in pool quanta as a balance in planck.
		fn fee_planck(fee_quanta: u128) -> Result<BalanceOf<T>, Error<T>> {
			fee_quanta
				.checked_mul(POOL_QUANTUM)
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
				// A segment settled by an earlier submission is skipped whole.
				// Its ciphertexts still occupy their positions in `outputs`, so
				// the index walks past them.
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

			let fee = Self::account_fee(plan.fee_quanta)?;
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
		/// The whole fee leaves the pool. The burn share simply is not minted
		/// back, which is what makes it a burn: the value was removed from
		/// issuance when it was shielded. The author's share is minted and
		/// recorded as a wormhole leaf, the same path a block reward takes, so
		/// the author can actually spend it.
		fn account_fee(fee_quanta: u128) -> Result<BalanceOf<T>, DispatchError> {
			if fee_quanta == 0 {
				return Ok(Zero::zero());
			}
			let fee = Self::fee_planck(fee_quanta)?;

			// `check_settlement` already refused a fee above the pool, so this
			// subtraction cannot fail. It is checked so that a future entry
			// point which forgets to credit `PoolValue` fails the settlement,
			// where a saturating subtraction would mint the difference.
			let pool = PoolValue::<T>::get().checked_sub(&fee).ok_or(Error::<T>::PoolUnderflow)?;
			PoolValue::<T>::put(pool);

			// Rounds against the author.
			let burn_quanta = T::FeeBurnRate::get().mul_ceil(fee_quanta);
			let author_quanta = fee_quanta.saturating_sub(burn_quanta);
			if author_quanta == 0 {
				return Ok(fee);
			}
			let author_planck = author_quanta.saturating_mul(POOL_QUANTUM);
			let author_amount: BalanceOf<T> =
				author_planck.try_into().map_err(|_| Error::<T>::ValueOutOfRange)?;

			let Some(author) = qp_wormhole::extract_author_from_digest::<T::AccountId, _>(
				frame_system::Pallet::<T>::digest().logs.iter(),
			) else {
				// No author in the digest, which is the shape of a test block or
				// a non-mined block. The share stays unminted, which is the
				// same outcome as burning it.
				return Ok(fee);
			};

			// The credit is `increase_balance`. `Mutate::mint_into` deposits
			// `pallet_balances::Event::Minted`, which the runtime's
			// `WormholeProofRecorderExtension` scans for and turns into a
			// wormhole leaf of its own; this pallet records that leaf itself,
			// just below, so the pair would credit one balance against two
			// independent leaves and leave the author able to exit twice what
			// it was paid. `pallet-wormhole` states the same rule at its
			// `credit_and_record`. Today the scan does not reach a bare
			// extrinsic, which is an accident of one default method and not a
			// property to lean on.
			//
			// `increase_balance` leaves total issuance alone, so the issuance
			// the value lost when it was shielded is put back here explicitly.
			// That is the half of the fee that is not burned.
			match <T::Currency as Unbalanced<_>>::increase_balance(
				&author,
				author_amount,
				Precision::Exact,
			) {
				Ok(credited) => {
					let issuance = <T::Currency as Inspect<_>>::total_issuance();
					<T::Currency as Unbalanced<_>>::set_total_issuance(
						issuance.saturating_add(credited),
					);
					// Without the leaf the credit is frozen: a QPoW-derived
					// author account has no signing key and a wormhole leaf is
					// its only spend path.
					T::ProofRecorder::record_transfer_proof(
						None,
						T::MintingAccount::get(),
						author.clone(),
						credited,
					);
					Self::deposit_event(Event::AuthorFeePaid { author, amount: credited });
				},
				Err(error) => {
					// A mint below the existential deposit is the realistic
					// failure. The share stays unminted; failing every
					// settlement in the batch over one small credit would be
					// the worse outcome.
					log::debug!(
						target: "runtime::shielded",
						"author fee mint failed: {error:?}"
					);
				},
			}

			Ok(fee)
		}

		/// Transaction-pool dedup tag: a hash of the submission's nullifiers,
		/// sorted within each segment.
		///
		/// Sorting within a segment keeps two proofs that publish the same
		/// multiset in different privately chosen orders on one tag, while the
		/// segment boundaries stay part of the preimage.
		///
		/// The tag commits to the nullifiers and to nothing else, so two
		/// submissions spending the same notes are mutually exclusive in the
		/// pool, which is the double-spend exclusion the tag exists for. That
		/// is sound only because admission verifies: a forged blob carrying a
		/// victim's nullifiers would otherwise take the victim's pool slot, and
		/// under a constant priority whichever arrived first would hold it.
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
}
