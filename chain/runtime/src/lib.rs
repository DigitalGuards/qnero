#![cfg_attr(not(feature = "std"), no_std)]
#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

pub mod apis;
#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
pub mod configs;

pub use qp_dilithium_crypto::{
	Dilithium65Pair, Dilithium65Public, Dilithium65Signature, Dilithium65SignatureWithPublic,
	Dilithium87Public, Dilithium87Signature, DilithiumSignatureScheme,
};

use alloc::vec::Vec;
use sp_core::U512;
use sp_runtime::{
	generic, impl_opaque_keys,
	traits::{BlakeTwo256, IdentifyAccount, Verify},
	MultiAddress,
};
use sp_version::RuntimeVersion;

pub use frame_system::Call as SystemCall;
pub use pallet_balances::Call as BalancesCall;
pub use pallet_reversible_transfers as ReversibleTransfersCall;
pub use pallet_timestamp::Call as TimestampCall;

#[cfg(any(feature = "std", test))]
pub use sp_runtime::BuildStorage;

pub mod genesis_config_presets;
pub mod governance;
pub mod transaction_extensions;

pub use governance::origins::pallet_custom_origins;

/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
	use super::*;
	use sp_runtime::generic;

	pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

	// Block header with Poseidon block hash and BlakeTwo256 for state trie
	pub type Header = qp_header::Header<BlockNumber, BlakeTwo256>;

	// Opaque block type.
	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	// Opaque block identifier type.
	pub type BlockId = generic::BlockId<Block>;

	// Opaque block hash type (H256).
	pub type Hash = sp_core::H256;
}

impl_opaque_keys! {
	pub struct SessionKeys {
		// pub a*ura: A*ura,
		// pub g*randpa: G*randpa,
	}
}

// Runtime versioning: https://docs.substrate.io/main-docs/build/upgrade#runtime-versioning
//
// Qnero is its own chain, and M6 is where it says so. The fork carried the
// upstream identity `quantus-runtime` at `spec_version` 152 while already
// storing a `pallet-zk-tree` leaf no upstream node can read: leaves are raw
// note commitments here and typed wormhole preimages there. A node that
// matched on that name and version would have substituted native execution for
// a wasm runtime with different state rules. The name is the chain's, the
// version restarts at 100, and both move together from here. The crate that
// builds this runtime is `qnero-runtime`, renamed after M6 along with the
// node package, so the wasm blob it emits is `qnero_runtime.wasm`.
//
// Bump `transaction_version` only when the signed extrinsic encoding changes
// (TxExtension set or payload layout), not for verifier-rule changes. M6
// dropped `WormholeProofRecorderExtension` from `TxExtension`, which is such a
// change, and the wallet's own list of known extensions moved with it.
//
// Bump `spec_version` whenever the metadata moves, which is a wider rule than
// "whenever consensus moves". Every client that caches metadata keys that
// cache on `spec_version`: polkadot-js, subxt, every indexer. A changed event
// layout under an unchanged version decodes with the stale shape, succeeds and
// is silently wrong, and nothing in the node reports it. 101 is the M6 review
// pass, which added a `pallet-shielded` error variant and changed three event
// layouts across `pallet-shielded` and `pallet-mining-rewards`.
// `the_runtime_identity_is_pinned` in `tests/call_filter.rs` is the tripwire.
//
// Bump `impl_version` when the emitted wasm changes under an unchanged
// specification. Renaming the crate to `qnero-runtime` changed the blob: the
// panic paths carry the crate name, so the pre-rename and post-rename wasm
// differ byte for byte while implementing the same runtime. Two blobs that
// answer the same version triple are two blobs a `set_code` preflight, an
// srtool reproducible-build comparison and `try-runtime
// --disable-spec-version-check` all accept interchangeably, so the field that
// exists for exactly this moved to 2. `impl_version` sits outside the metadata
// hash, which covers `spec_name`, `spec_version`, the extrinsic version, the
// SS58 prefix, decimals and symbol (RFC-0078), so transaction validity,
// metadata and consensus are untouched by the bump.
#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
	spec_name: alloc::borrow::Cow::Borrowed("qnero"),
	impl_name: alloc::borrow::Cow::Borrowed("qnero-node"),
	authoring_version: 1,
	spec_version: 102,
	impl_version: 2,
	apis: apis::RUNTIME_API_VERSIONS,
	transaction_version: 7,
	system_version: 1,
};

// Time is measured by number of blocks.
pub const TARGET_BLOCK_TIME_MS: u64 = 12_000;

/// Derived time units expressed in number of blocks (e.g. 60s / 12s = 5 blocks per minute)
pub const MINUTES: BlockNumber = (60_000u64 / TARGET_BLOCK_TIME_MS) as BlockNumber;
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;

// Unit = the base number of indivisible units for balances
pub const UNIT: Balance = 1_000_000_000_000;
pub const MILLI_UNIT: Balance = 1_000_000_000;
pub const MICRO_UNIT: Balance = 1_000_000;

/// Existential deposit.
pub const EXISTENTIAL_DEPOSIT: Balance = MILLI_UNIT;

/// Hard cap on total issuance; mining emissions stop here.
pub const MAX_SUPPLY: Balance = 21_000_000 * UNIT;

/// Central fee dial. Every absolute-QNR price in the runtime, weight and length
/// fees, multisig fees and deposit, preimage and referendum deposits, and the
/// high-security inclusion-fee cap, is derived through [`scale_fee`], so editing
/// this one ratio (plus a runtime upgrade) repositions the whole price level.
/// Percentage rates (wormhole bps, reversal/step factors), the existential
/// deposit, and the 0.01-QNR circuit quanta are deliberately not scaled.
pub const FEE_SCALE_NUM: Balance = 1;
pub const FEE_SCALE_DEN: Balance = 1;

pub const fn scale_fee(base: Balance) -> Balance {
	base * FEE_SCALE_NUM / FEE_SCALE_DEN
}

/// Wall-clock day in milliseconds — the unit vesting schedules and claim cadence are
/// expressed in (`pallet_timestamp` moments, not block numbers).
pub const MILLIS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
// pub type Signature = MultiSignature;
pub type Signature = DilithiumSignatureScheme;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// Balance of an account.
pub type Balance = u128;

/// Id type for assets
pub type AssetId = u32;

/// Index of a transaction in the chain.
pub type Nonce = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// An index to a block.
pub type BlockNumber = u32;

/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;

/// Block header type as expected by this runtime.
/// Uses Poseidon for block hash and BlakeTwo256 for state trie / extrinsics root.
pub type Header = qp_header::Header<BlockNumber, BlakeTwo256>;

/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;

/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;

/// Type of the difficulty
pub type Difficulty = U512;

/// The SignedExtension to the basic transaction logic.
pub type TxExtension = (
	frame_system::CheckNonZeroSender<Runtime>,
	frame_system::CheckSpecVersion<Runtime>,
	frame_system::CheckTxVersion<Runtime>,
	frame_system::CheckGenesis<Runtime>,
	frame_system::CheckEra<Runtime>,
	frame_system::CheckNonce<Runtime>,
	frame_system::CheckWeight<Runtime>,
	transaction_extensions::ReversibleTransactionExtension<Runtime>,
	// `WormholeProofRecorderExtension` was here at M5 and is gone at M6. It
	// scanned a signed call's balance events and wrote a wormhole transfer leaf
	// for each one, which is what made a transparent credit to a keyless
	// account spendable. There are no transparent transfers to scan any more:
	// the call filter refuses every one of them, and the block reward and the
	// author's fee share are notes. Removing it changes the signed extrinsic
	// encoding, which is what `transaction_version` 7 is.
	// The high-security zero-tip policy is NOT enforced here: it lives in
	// `transaction_extensions::HighSecurityFungibleAdapter` (the configured
	// `OnChargeTransaction`), which every fee path of this extension goes
	// through, so no refactor of this tuple can silently reopen the tip channel.
	pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
	frame_metadata_hash_extension::CheckMetadataHash<Runtime>,
	// Must stay last: re-runs the block-weight reclaim so that refunds made by the
	// extensions above (e.g. the wormhole recorder returning statically over-charged
	// per-transfer weight) are returned to block capacity. `CheckWeight`'s own reclaim
	// runs before those refunds exist; `reclaim_weight` is idempotent via
	// `ExtrinsicWeightReclaimed`, so running it twice never double-counts.
	frame_system::WeightReclaim<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

/// The payload being signed in transactions.
pub type SignedPayload = generic::SignedPayload<RuntimeCall, TxExtension>;

/// All storage migrations to run on runtime upgrade.
pub type Migrations = (
	// v0 -> v1: no-op version bump (TreasuryPortion is no longer written).
	pallet_treasury::migrations::MigrateV0ToV1<Runtime>,
	// v1 -> v2: kill leftover TreasuryPortion; treasury is not paid from emission.
	pallet_treasury::migrations::MigrateV1ToV2<Runtime>,
);

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
	Runtime,
	Block,
	frame_system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	Migrations,
>;

// Create the runtime by composing the FRAME pallets that were previously configured.
#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(
		RuntimeCall,
		RuntimeEvent,
		RuntimeError,
		RuntimeOrigin,
		RuntimeFreezeReason,
		RuntimeHoldReason,
		RuntimeSlashReason,
		RuntimeLockId,
		RuntimeTask
	)]
	pub struct Runtime;

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Timestamp = pallet_timestamp;

	#[runtime::pallet_index(2)]
	pub type Balances = pallet_balances;

	#[runtime::pallet_index(3)]
	pub type TransactionPayment = pallet_transaction_payment;

	// Index 4 was `pallet_sudo` (removed). Kept vacant so downstream pallet indices stay stable.

	#[runtime::pallet_index(5)]
	pub type QPoW = pallet_qpow;

	#[runtime::pallet_index(6)]
	pub type MiningRewards = pallet_mining_rewards;

	#[runtime::pallet_index(7)]
	pub type Preimage = pallet_preimage;

	// The scheduler is used internally for reversible transfers and governance via the
	// `Scheduler`/`ScheduleNamed` trait. Its extrinsics are disabled so users cannot place
	// arbitrary transactions onto the scheduler.
	#[runtime::pallet_index(8)]
	#[runtime::disable_call]
	pub type Scheduler = pallet_scheduler;

	#[runtime::pallet_index(9)]
	pub type Utility = pallet_utility;

	// Index 10 was the community `Referenda` instance (removed with the public/token-weighted
	// governance lane). Kept vacant so downstream pallet indices stay stable.

	#[runtime::pallet_index(11)]
	pub type ReversibleTransfers = pallet_reversible_transfers;

	// Index 12 was `ConvictionVoting` (removed with the community lane). Kept vacant.

	#[runtime::pallet_index(13)]
	pub type TechCollective = pallet_ranked_collective;

	#[runtime::pallet_index(14)]
	pub type TechReferenda = pallet_referenda::Pallet<Runtime, Instance1>;

	#[runtime::pallet_index(15)]
	pub type TreasuryPallet = pallet_treasury;

	// Index 16 was `pallet_recovery` (removed). Kept vacant so downstream pallet indices stay
	// stable.

	// Index 17 was `pallet_assets` (removed). Kept vacant so downstream pallet indices stay stable.

	// Index 18 was `pallet_assets_holder` (removed with assets). Kept vacant.

	#[runtime::pallet_index(19)]
	pub type Multisig = pallet_multisig;

	// Index 20 was `pallet_wormhole` (removed at M6 with the transparent exit
	// path). Kept vacant so downstream pallet indices stay stable. `qp-wormhole`,
	// the primitives crate, stays: the QPoW author derivation lives there and the
	// runtime's one author seam calls it.

	#[runtime::pallet_index(21)]
	pub type ZkTree = pallet_zk_tree;

	#[runtime::pallet_index(22)]
	pub type Vesting = pallet_vesting;

	// Custom governance origins (no calls, no storage): dispatch origins for the
	// non-Root tech-referenda tracks, e.g. `FastUpgrade`.
	#[runtime::pallet_index(23)]
	pub type Origins = pallet_custom_origins;

	// The Qnero shielded pool, and at M6 the only place value is created. It
	// appends to the `ZkTree` instance the whole chain shares, because the leaf
	// circuit anchors at `zk_tree_root` and the header carries exactly one of
	// those.
	//
	// It appends from two places and neither is one of its own hooks. Ordinary
	// settlements and the `shield` entry append during extrinsic execution. The
	// coinbase note is appended inside `CoinbaseSink::deposit_coinbase`, which
	// `pallet-mining-rewards` calls from its `on_finalize` at index 6, so the
	// append happens well before `ZkTree` folds the block's leaves at index 21.
	// That ordering is the reason the coinbase is paid through the sink rather
	// than from an `on_finalize` here: this pallet is declared after `ZkTree`,
	// hooks run in pallet-index order, and a leaf appended after the fold would
	// miss the root this block's header carries.
	#[runtime::pallet_index(24)]
	pub type Shielded = pallet_shielded;
}
