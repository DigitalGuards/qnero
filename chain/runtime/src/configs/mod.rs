// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org>

// Substrate and Polkadot dependencies
use crate::{
	governance::{
		definitions::{
			EnsureRootRemoveKeepsMemberFloor, GlobalMaxMembers, MinRankOfClassConverter,
			PreimageDeposit, RootOrMemberForTechReferendaOrigin, TechCollectiveTracksInfo,
		},
		origins::FastUpgrade,
	},
	pallet_custom_origins, MILLI_UNIT,
};
use frame_support::{
	derive_impl, parameter_types,
	traits::{
		ConstU128, ConstU16, ConstU32, ConstU8, EitherOfDiverse, EnsureOrigin, Get,
		NeverEnsureOrigin, VariantCountOf,
	},
	weights::{
		constants::{RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND},
		Weight, WeightToFeeCoefficient, WeightToFeeCoefficients, WeightToFeePolynomial,
	},
	PalletId,
};
use frame_system::{
	limits::{BlockLength, BlockWeights},
	EnsureRoot, EnsureRootWithSuccess,
};
use pallet_ranked_collective::Linear;
use pallet_transaction_payment::{ConstFeeMultiplier, Multiplier};
use smallvec::smallvec;

use qp_scheduler::BlockNumberOrTimestamp;
use sp_runtime::{
	traits::{BlakeTwo256, One},
	MultiAddress, Perbill, Permill,
};
use sp_version::RuntimeVersion;

// Local module imports
use super::{
	scale_fee, AccountId, AssetId, Balance, Balances, Block, BlockNumber, Hash, Nonce,
	OriginCaller, PalletInfo, Preimage, Runtime, RuntimeCall, RuntimeEvent, RuntimeFreezeReason,
	RuntimeHoldReason, RuntimeOrigin, RuntimeTask, Scheduler, Shielded, System, Timestamp, Vesting,
	ZkTree, DAYS, EXISTENTIAL_DEPOSIT, FEE_SCALE_DEN, FEE_SCALE_NUM, MAX_SUPPLY, MILLIS_PER_DAY,
	TARGET_BLOCK_TIME_MS, UNIT, VERSION,
};
use sp_core::U512;

const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

parameter_types! {
	pub const BlockHashCount: BlockNumber = 4096;
	pub const Version: RuntimeVersion = VERSION;

	/// Block weight limits for the runtime.
	///
	/// - `ref_time`: 6 seconds of compute (with 12 second block time, this leaves headroom)
	/// - `proof_size`: Set to u64::MAX (uncapped) - this is intentional for a solo PoW chain
	///   where stateless validation and PoV limits don't apply.
	///
	/// See "Proof Size Design Rationale" in the Transaction Fee Structure section below
	/// for detailed explanation of why proof_size is uncapped and when to revisit this.
	pub RuntimeBlockWeights: BlockWeights = BlockWeights::with_sensible_defaults(
		Weight::from_parts(6u64 * WEIGHT_REF_TIME_PER_SECOND, u64::MAX),
		NORMAL_DISPATCH_RATIO,
	);
	/// Maximum block length (5 MB).
	///
	/// Estimated network transfer times:
	/// - Download: 100 Mbps link ~600ms, 1 Gbps link ~200ms
	/// - Upload: 10 Mbps link ~4.1s, 100 Mbps link ~500ms
	pub RuntimeBlockLength: BlockLength = BlockLength::max_with_normal_ratio(5 * 1024 * 1024, NORMAL_DISPATCH_RATIO);
	pub const SS58Prefix: u8 = 189;
}

/// The one place this runtime reads the block author from consensus.
///
/// `pallet-mining-rewards` and `pallet-shielded` both need to know whether a
/// block has an author and who it is, and both read it through
/// `frame_support::traits::FindAuthor` rather than through the proof of work.
/// This implementation is the whole of the coupling: QPoW puts the miner's
/// 32-byte inner hash in a `PreRuntime` digest item, and the account is the
/// wormhole address derived from it, which is the derivation
/// `--rewards-inner-hash` names on the command line.
///
/// Swapping the engine, which `docs/DESIGN.md` section 10 keeps open for
/// RandomX so Monero rigs can mine Qnero, changes the consensus client and this
/// impl. No pallet, no storage item and no block shape moves with it.
/// `docs/OPS-DEV.md` carries the seam.
pub struct QpowAuthor;

impl frame_support::traits::FindAuthor<AccountId> for QpowAuthor {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (sp_runtime::ConsensusEngineId, &'a [u8])>,
	{
		for (engine, data) in digests {
			if engine != sp_consensus_qpow::POW_ENGINE_ID {
				continue;
			}
			// Exactly 32 bytes. A malformed item is not an author, and both
			// callers treat "no author" as a block that pays nobody rather
			// than as an error.
			let preimage: [u8; 32] = data.try_into().ok()?;
			return qp_wormhole::derive_wormhole_address(preimage).ok().map(AccountId::new);
		}
		None
	}
}

/// A transfer-proof recorder that records nothing and says so successfully.
///
/// `pallet-vesting` treats a dropped credit as fatal and rolls the payout back:
/// a keyless beneficiary's only spend path used to be the wormhole leaf the
/// recorder wrote, so a payout without one was value frozen forever. v1 removed
/// the exit, so there is no leaf to write and nothing for its absence to mean.
/// The `()` implementation reports `false`, which the pallet reads as the old
/// failure and which would make every vesting payout fail closed, so the
/// runtime says what is true here instead: nothing was recorded, and nothing
/// needed to be.
///
/// The tree holds note commitments and nothing else under v1, which is what
/// makes "every unit of value that enters circulation is a shielded note" a
/// property of the tree rather than a claim about it.
pub struct NoTransferProofNeeded;

impl qp_wormhole::TransferProofRecorder<AccountId, AssetId, Balance> for NoTransferProofNeeded {
	fn record_transfer_proof(
		_asset_id: Option<AssetId>,
		_from: AccountId,
		_to: AccountId,
		_amount: Balance,
	) -> bool {
		true
	}
}

/// Qnero v1: no call may move transparent value from one account to another.
///
/// `docs/DESIGN.md` section 7 is the allowlist and the argument. The shape of
/// the check is the one `transaction_extensions::count_transfers` already uses,
/// including the recursion through the two wrappers, because a filter that
/// stops `Balances::transfer_allow_death` and lets
/// `Utility::batch_all([transfer_allow_death])` through is decoration.
///
/// Four things it deliberately does not do:
///
/// - It does not stop `Vesting::claim`. The pot is keyless, it is funded at genesis, and with
///   `create_schedule` refused no schedule can appear after genesis, so a claim pays a beneficiary
///   fixed at genesis an amount fixed at genesis. Refusing it would strand the whole genesis
///   allocation in an account with no key. `docs/DESIGN.md` section 7.2 carries the decision.
/// - It does not stop `Shielded::shield`, which is the only door into the pool. A shield burns the
///   caller's own balance, so it moves value out of the transparent layer rather than between
///   accounts, and blocking it would lock every genesis balance out of the chain's own pool with no
///   way in.
/// - It does not stop a fee. `ChargeTransactionPayment` is a transaction extension and never
///   reaches a `Contains` check, which is what lets a filtered runtime still charge for the calls
///   it allows.
/// - It does not reach a Root dispatch. `frame_system`'s `filter_call` exempts the Root origin and
///   nothing else, so a tech referendum enacting a call under Root can still move transparent
///   value, and that is a governance decision rather than an oversight: the calls exist, the
///   collective can enact them, and the filter is what keeps them out of ordinary use. The
///   scheduler is not an exemption. It dispatches a due task with the origin the task carries, and
///   every origin but Root meets this filter, which is why a reversible transfer's own enactment is
///   refused (`runtime/tests/transactions/reversible_integration.rs`).
pub struct QneroCallFilter;

impl frame_support::traits::Contains<RuntimeCall> for QneroCallFilter {
	fn contains(call: &RuntimeCall) -> bool {
		!refused_under_v1(call)
	}
}

/// Everything v1 refuses, wrappers included.
///
/// Two reasons a call is refused, and the recursion is here rather than in
/// either of them so a wrapper carrying either one is caught: it moves
/// transparent value between accounts, or it enrols an account in a feature
/// whose every call v1 refuses.
fn refused_under_v1(call: &RuntimeCall) -> bool {
	match call {
		// The wrappers. Both carry the inner call in the submitted extrinsic,
		// so the recursion is over data that is right here.
		RuntimeCall::Utility(pallet_utility::Call::batch_all { calls }) =>
			calls.iter().any(refused_under_v1),
		// `execute` is the one that dispatches, and the executor resubmits the
		// stored call there, verified byte-equal, so the inner call is in the
		// extrinsic. `propose` carries its call as opaque bytes and dispatches
		// nothing, so there is nothing to decode and nothing to stop.
		RuntimeCall::Multisig(pallet_multisig::Call::execute { call, .. }) =>
			refused_under_v1(call),
		_ => moves_transparent_value(call) || enrols_in_a_feature_v1_refuses(call),
	}
}

/// A call that is not a transfer and that v1 still has to refuse, because it
/// puts an account somewhere v1 gives it nothing to do.
///
/// `set_high_security` is the whole list. It is one way: the pallet has no
/// call that undoes it and refuses a second one with
/// `AccountAlreadyHighSecurity`. From the block it succeeds in, the account's
/// every call goes through `HighSecurityConfig::is_whitelisted`, which is a
/// reversible-transfers list, and v1 refuses every call on that list. The
/// account would keep `shield` and `burn`, which
/// [`HighSecurityConfig::is_whitelisted_leaf`] carries for the accounts
/// already enrolled, and it would gain nothing else until a milestone gives
/// the feature something to guard. Refusing the enrolment is what keeps the
/// answer to "what can this account still do" from depending on a block
/// number.
fn enrols_in_a_feature_v1_refuses(call: &RuntimeCall) -> bool {
	matches!(
		call,
		RuntimeCall::ReversibleTransfers(
			pallet_reversible_transfers::Call::set_high_security { .. }
		)
	)
}

/// Whether a call moves transparent value between accounts.
///
/// Leaves only: [`refused_under_v1`] is where the wrappers are unwrapped.
///
/// Enumerated rather than derived: a new pallet with a transfer call is not
/// caught by anything here, and `a_new_balance_moving_call_is_matched_here`
/// in `tests/call_filter.rs` is the reminder.
fn moves_transparent_value(call: &RuntimeCall) -> bool {
	match call {
		// The transparent transfers themselves. `burn` is deliberately absent:
		// it destroys the caller's own balance and moves nothing to anyone,
		// which is the same direction `shield` goes.
		RuntimeCall::Balances(pallet_balances::Call::transfer_allow_death { .. }) |
		RuntimeCall::Balances(pallet_balances::Call::transfer_keep_alive { .. }) |
		RuntimeCall::Balances(pallet_balances::Call::transfer_all { .. }) => true,

		// Reversible transfers are transfers with a delay. `cancel` seizes a
		// pending hold to the guardian, `recover_funds` sweeps an account to
		// one, and the other three schedule or execute a transfer.
		RuntimeCall::ReversibleTransfers(
			pallet_reversible_transfers::Call::schedule_transfer { .. } |
			pallet_reversible_transfers::Call::schedule_transfer_with_delay { .. } |
			pallet_reversible_transfers::Call::execute_transfer { .. } |
			pallet_reversible_transfers::Call::cancel { .. } |
			pallet_reversible_transfers::Call::recover_funds { .. },
		) => true,

		// Vesting moves the pot around: `create_schedule` funds it from the
		// treasury, `end_schedule` and `retarget_schedule` move a schedule's
		// unpaid remainder. `count_transfers` leaves the pallet out because it
		// records its own proofs, which is a different question.
		//
		// `claim` is deliberately absent, and `docs/DESIGN.md` section 7.2
		// carries the decision. It is the genesis distribution channel rather
		// than a transfer: every preset endows a keyless pot that cannot sign,
		// against schedules written at genesis, and with `create_schedule`
		// refused no new one can appear. A claim pays a beneficiary fixed at
		// genesis an amount fixed at genesis, and that beneficiary can then
		// only shield or burn it. Refusing it would strand the whole genesis
		// allocation in an account with no key, permanently inside
		// `total_issuance`, where the emission schedule counts it as supply
		// forever.
		RuntimeCall::Vesting(
			pallet_vesting::Call::create_schedule { .. } |
			pallet_vesting::Call::end_schedule { .. } |
			pallet_vesting::Call::retarget_schedule { .. },
		) => true,

		_ => false,
	}
}

/// The default types are being injected by [`derive_impl`](`frame_support::derive_impl`) from
/// [`SoloChainDefaultConfig`](`struct@frame_system::config_preludes::SolochainDefaultConfig`),
/// but overridden as needed.
#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
	/// v1 mandatory privacy: no signed call moves transparent value between
	/// accounts. See [`QneroCallFilter`].
	type BaseCallFilter = QneroCallFilter;
	/// The block type for the runtime.
	type Block = Block;
	/// Block & extrinsics weights: base values and limits.
	type BlockWeights = RuntimeBlockWeights;
	/// The maximum length of a block (in bytes).
	type BlockLength = RuntimeBlockLength;
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;

	type Lookup = sp_runtime::traits::AccountIdLookup<Self::AccountId, ()>;
	/// The type for storing how many extrinsics an account has signed.
	type Nonce = Nonce;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used for state trie and extrinsics root.
	/// This matches the `StateHash` parameter in qp_header::Header.
	type Hashing = BlakeTwo256;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// The weight of database operations that the runtime can invoke.
	type DbWeight = RocksDbWeight;
	/// Version of the runtime.
	type Version = Version;
	/// The data to be stored in an account.
	type AccountData = pallet_balances::AccountData<Balance>;
	/// This is used as an identifier of the chain. 42 is the generic substrate prefix.
	type SS58Prefix = SS58Prefix;
	type MaxConsumers = ConstU32<16>;
	/// `authorize_upgrade` accepts Root (the normal tech-referenda track) or the
	/// fast-upgrade track's `FastUpgrade` origin. `set_code` and
	/// `authorize_upgrade_without_checks` remain Root-only.
	type AuthorizeUpgradeOrigin = EitherOfDiverse<EnsureRoot<AccountId>, FastUpgrade>;
}

impl pallet_custom_origins::Config for Runtime {}

parameter_types! {
	pub const MiningUnit: Balance = UNIT;
}

impl pallet_mining_rewards::Config for Runtime {
	type Currency = Balances;
	/// The block reward becomes the value of the block's coinbase note. No
	/// account is credited: under v1 mandatory privacy there is no transparent
	/// payee, and the note's recipient is inside an `inner` the chain cannot
	/// open.
	type CoinbaseSink = Shielded;
	/// Emission measures supply across both books. Nearly every planck ends up
	/// in the pool, where `Balances::total_issuance()` does not count it.
	type ShieldedSupply = pallet_shielded::ShieldedSupply<Runtime>;
	type FindAuthor = QpowAuthor;
	type WeightInfo = pallet_mining_rewards::weights::SubstrateWeight<Runtime>;
	type MaxSupply = ConstU128<{ MAX_SUPPLY }>;
	type EmissionDivisor = ConstU128<50_000_000>;
	type Unit = MiningUnit;
}

parameter_types! {
	/// Target block time ms
	pub const TargetBlockTime: u64 = TARGET_BLOCK_TIME_MS;
	pub const TimestampBucketSize: u64 = 2 * TARGET_BLOCK_TIME_MS; // Nyquist frequency
	/// Initial mining difficulty
	pub const QPoWInitialDifficulty: U512 = U512([99_999_999_999, 0, 0, 0, 0, 0, 0, 0]);
}

impl pallet_qpow::Config for Runtime {
	type InitialDifficulty = QPoWInitialDifficulty;
	type TargetBlockTime = TargetBlockTime;
	type MaxReorgDepth = ConstU32<100>;
	type WeightInfo = pallet_qpow::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	/// Canonical minting account for native token operations (mining rewards, wormhole exits).
	/// Used as the `from` address in TransferProofs when native tokens are minted.
	/// This is a well-known sentinel address, not a real account.
	pub const MintingAccount: AccountId = AccountId::new([1u8; 32]);
}

type Moment = u64;

parameter_types! {
	pub const MinimumPeriod: u64 = 100;
}

impl pallet_timestamp::Config for Runtime {
	/// A timestamp: milliseconds since the unix epoch.
	type Moment = Moment;
	type OnTimestampSet = Vesting;
	type MinimumPeriod = MinimumPeriod;
	type WeightInfo = pallet_timestamp::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub const ExistentialDeposit: Balance = EXISTENTIAL_DEPOSIT;
}

impl pallet_balances::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	type RuntimeHoldReason = RuntimeHoldReason;
	type RuntimeFreezeReason = RuntimeFreezeReason;
	type WeightInfo = pallet_balances::weights::SubstrateWeight<Runtime>;
	/// The type for recording an account's balance.
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = RuntimeFreezeReason;
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ();
	type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
	type DoneSlashHandler = ();
}

impl pallet_preimage::Config for Runtime {
	type WeightInfo = pallet_preimage::weights::SubstrateWeight<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	type Currency = Balances;
	type ManagerOrigin = EnsureRoot<AccountId>;
	type Consideration = PreimageDeposit;
}

parameter_types! {
	// Maximum number of referenda queued for deciding on a single track (`MaxQueued`).
	pub const ReferendumMaxProposals: u32 = 100;
	// Global cap on `Ongoing` referenda, enforced at submission. `MaxQueued` only bounds the
	// per-track deciding queue: without this cap, submissions that never receive a decision
	// deposit would accumulate without limit until the 45-day undeciding timeout, each one
	// consuming referendum storage and a scheduler agenda slot for its timeout alarm. Must be
	// at least `MaxQueued` + total `max_deciding` + 1 (checked by the pallet's
	// `integrity_test`; benchmarks fill a track's queue and deciding slots completely).
	pub const MaxActiveReferenda: u32 = 128;
	// Per-account bound on ongoing referenda. `MaxActiveReferenda` is a shared resource and
	// `SubmitOrigin` is members-only, so without this cap a single member could fill all
	// 128 slots with refundable-deposit referenda and freeze the chain's only governance
	// lane — including the referendum needed to remove them — for the 45-day
	// `UndecidingTimeout`, renewably. With at most `MaxMemberCount` (13) members at 8 slots
	// each (104 < 128), the global bound is unreachable even if every member colludes, and
	// 8 concurrent proposals per member is ample headroom for real use.
	pub const MaxActiveReferendaPerAccount: u32 = 8;
	// Max encoded length of a Lookup proposal. `submit` requests the preimage so `unnote`
	// cannot delete it before enactment — which also lets the noter reclaim the preimage
	// deposit while the bytes stay pinned. Cap the blob so that (a) `MaxActive` × size
	// cannot approach hundreds of MiB of deposit-free state, and (b) the preimage deposit
	// for a max-sized blob (0.1 UNIT + 0.0001 UNIT/byte ≈ 0.51 UNIT) stays under the
	// 1 UNIT submission deposit, so the held bytes remain collateralized even after
	// `unnote`. 4 KiB is ample for any tech-collective call (a runtime-upgrade
	// authorization is a few dozen bytes); together with the decision deposit it keeps a
	// tech referendum affordable from the 3 UNIT mainnet genesis seed.
	pub const MaxReferendaProposalSize: u32 = 4 * 1024;
	// Submission deposit for referenda
	pub const ReferendumSubmissionDeposit: Balance = scale_fee(UNIT);
	// Undeciding timeout (45 days): a submitted referendum that is NOT in the track queue —
	// e.g. one that never received a decision deposit — is rejected as TimedOut after this
	// long. Referenda that ARE queued for deciding are exempt: the timeout check
	// (pallets/referenda/src/lib.rs, `service_referendum`) is gated on `!status.in_queue`,
	// so a queued referendum that simply never gets a free deciding slot is NOT timed out.
	pub const UndecidingTimeout: BlockNumber = 45 * DAYS;
	pub const AlarmInterval: BlockNumber = 1;
}

parameter_types! {
	pub const MinRankOfClassDelta: u16 = 0;
	pub const MaxMemberCount: u32 = 13;
}
impl pallet_ranked_collective::Config for Runtime {
	type WeightInfo = pallet_ranked_collective::weights::SubstrateWeight<Runtime>;
	type RuntimeEvent = RuntimeEvent;
	// #91267: membership changes go through Root only (i.e. a passed TechReferenda vote), so no
	// single member can unilaterally add/remove others or stuff the collective. Root operates at
	// rank 0, matching the flat collective. Removals are additionally gated on the
	// MIN_TECH_COLLECTIVE_MEMBERS floor: shrinking below it would collapse the tech-referenda
	// vote thresholds or (at zero members) deadlock the lane entirely.
	type AddOrigin = EnsureRootWithSuccess<AccountId, ConstU16<0>>;
	type RemoveOrigin = EnsureRootRemoveKeepsMemberFloor;
	type PromoteOrigin = NeverEnsureOrigin<u16>;
	type DemoteOrigin = NeverEnsureOrigin<u16>;
	type ExchangeOrigin = NeverEnsureOrigin<u16>;
	type Polls = pallet_referenda::Pallet<Runtime, TechReferendaInstance>;
	type MinRankOfClass = MinRankOfClassConverter<MinRankOfClassDelta>;
	type MemberSwappedHandler = ();
	type VoteWeight = Linear;
	type MaxMemberCount = GlobalMaxMembers<MaxMemberCount>;

	#[cfg(feature = "runtime-benchmarks")]
	type BenchmarkSetup = ();
}

pub type TechReferendaInstance = pallet_referenda::Instance1;

impl pallet_referenda::Config<TechReferendaInstance> for Runtime {
	/// The type of call dispatched by referenda upon approval and execution.
	type RuntimeCall = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	/// Provides weights for the pallet operations to properly charge transaction fees.
	type WeightInfo = pallet_referenda::weights::SubstrateWeight<Runtime>;
	/// The scheduler pallet used to delay execution of successful referenda.
	type Scheduler = Scheduler;
	/// The currency mechanism used for handling deposits and voting.
	type Currency = Balances;
	/// The origin allowed to submit referenda - in this case any signed account.
	type SubmitOrigin = RootOrMemberForTechReferendaOrigin;
	/// The privileged origin allowed to cancel an ongoing referendum - only root can do this.
	type CancelOrigin = EnsureRoot<AccountId>;
	/// The privileged origin allowed to kill a referendum that's not passing - only root can do
	/// this.
	type KillOrigin = EnsureRoot<AccountId>;
	/// Destination for slashed deposits when a referendum is cancelled or killed.
	/// Leaving () here, will burn all slashed deposits. It's possible to use here the same idea
	/// as we have for TransactionFees (OnUnbalanced) - with this it should be possible to
	/// do something more sophisticated with this.
	type Slash = (); // Will discard any slashed deposits
	/// The voting mechanism used to collect votes and determine how they're counted.
	/// Connected to the conviction voting pallet to allow conviction-weighted votes.
	type Votes = pallet_ranked_collective::Votes;
	/// The method to tally votes and determine referendum outcome.
	/// Uses conviction voting's tally system with a maximum turnout threshold.
	type Tally = pallet_ranked_collective::TallyOf<Runtime>;
	/// The deposit required to submit a referendum proposal.
	type SubmissionDeposit = ReferendumSubmissionDeposit;
	/// Maximum number of referenda that can be queued for deciding on the track.
	type MaxQueued = ReferendumMaxProposals;
	/// Global admission bound on `Ongoing` referenda, enforced in `submit`.
	type MaxActive = MaxActiveReferenda;
	/// Per-submitter admission bound, so no member coalition can exhaust `MaxActive`.
	type MaxActivePerAccount = MaxActiveReferendaPerAccount;
	/// Max Lookup proposal size; keeps requested-but-unnoted preimages collateralized.
	type MaxProposalSize = MaxReferendaProposalSize;
	/// Time period after which an undecided referendum will be automatically rejected.
	type UndecidingTimeout = UndecidingTimeout;
	/// The frequency at which the pallet checks for expired or ready-to-timeout referenda.
	type AlarmInterval = AlarmInterval;
	/// Defines the different referendum tracks (categories with distinct parameters).
	type Tracks = TechCollectiveTracksInfo;
	/// The pallet used to store preimages (detailed proposal content) for referenda.
	type Preimages = Preimage;
	/// Blocknumber provider
	type BlockNumberProvider = System;
}

parameter_types! {
	// Maximum weight for scheduled calls (80% of the block's maximum weight)
	pub MaximumSchedulerWeight: Weight = Perbill::from_percent(80) * RuntimeBlockWeights::get().max_block;
	// Maximum number of scheduled calls per block
	pub const MaxScheduledPerBlock: u32 = 50;
}

impl pallet_scheduler::Config for Runtime {
	type RuntimeOrigin = RuntimeOrigin;
	type PalletsOrigin = OriginCaller;
	type RuntimeCall = RuntimeCall;
	type MaximumWeight = MaximumSchedulerWeight;
	type ScheduleOrigin = EnsureRoot<AccountId>;
	type MaxScheduledPerBlock = MaxScheduledPerBlock;
	type WeightInfo = pallet_scheduler::weights::SubstrateWeight<Runtime>;
	type OriginPrivilegeCmp = frame_support::traits::EqualPrivilegeOnly;
	type Preimages = Preimage;
	type TimeProvider = Timestamp;
	type Moment = u64;
	type TimestampBucketSize = TimestampBucketSize;
}

// ============================================================================
// Transaction Fee Structure
// ============================================================================
//
// This is a solo Proof of Work chain (not a parachain), so Proof of Validity (PoV)
// size limits do not apply - we don't submit proofs to any relay chain.
//
// Fee Structure:
// - **Compute (ref_time):** 1 balance unit per unit of ref_time
//   - 1 second of compute ≈ 1 UNIT (since WEIGHT_REF_TIME_PER_SECOND = 10^12)
//   - Uses `ScaledIdentityFee`: direct 1:1 mapping × `FEE_SCALE`
//
// - **Extrinsic Length:** 1 UNIT per megabyte (LENGTH_FEE_MULTIPLIER = 10^6)
//   - This brings storage/bandwidth costs in line with compute costs
//   - A 5 MB block (max size) costs ~5 UNIT in length fees
//   - A typical 500-byte transfer costs ~0.0005 UNIT in length fees
//   - Uses `LengthToFeeMultiplier` with 10^6 coefficient
//
// - **Proof Size:** Not enforced or charged
//   - Block weight limit uses u64::MAX for proof_size component
//   - WeightToFee only considers ref_time, not proof_size
//
// Fee Destination:
// - 100% of transaction fees go to the block miner
// - Block rewards go 100% to the miner (quantized to the wormhole leaf quantum; any sub-quantum
//   remainder stays in CollectedFees for the next miner)
//
// Spam Prevention:
// - Existential deposit: 0.001 UNIT
// - Various pallet-specific deposits (multisig, governance, etc.)
// - Miners can reject transactions below their minimum fee threshold
//
// ============================================================================
// Proof Size Design Rationale
// ============================================================================
//
// **Why proof_size is set to u64::MAX and not priced:**
//
// In Substrate's two-dimensional weight system, `proof_size` represents the amount of
// state witness data required for stateless validation. This is critical for parachains
// where validators must re-execute blocks using only the PoV (Proof of Validity) blob,
// which has strict size limits imposed by the relay chain.
//
// For this solo PoW chain, proof_size constraints are intentionally disabled because:
//
// 1. **No relay chain constraints:** Unlike parachains, solo chains have no external entity
//    imposing PoV size limits. Validators have full state access.
//
// 2. **Full nodes validate blocks:** All validators maintain complete state, so they don't need
//    witnesses to re-execute transactions.
//
// 3. **ref_time provides sufficient protection:** Compute-bound benchmarking (ref_time) naturally
//    correlates with state access patterns. Heavy state reads/writes increase ref_time, providing
//    indirect protection against state-heavy transactions.
//
// 4. **Block length limits storage abuse:** The 5 MB block size limit caps the amount of data that
//    can be included per block, preventing bandwidth-based attacks.
//
// **When to revisit this decision:**
//
// This design should be reconsidered if the chain adopts features where proof/witness
// size becomes a meaningful resource constraint:
//
// - **Light client support:** Light clients verify blocks using state proofs. Large witnesses
//   increase sync times and bandwidth requirements for light clients.
//
// - **Cross-chain bridges:** Bridge protocols often require merkle proofs of state. Unbounded proof
//   sizes could make bridge operations expensive or impractical.
//
// - **Stateless validation:** If the chain moves toward stateless block validation (validators
//   don't keep full state), witness size becomes a critical resource.
//
// - **ZK proof generation:** If state proofs are used as inputs to ZK circuits, proof size directly
//   impacts prover time and memory requirements.
//
// To enable proof_size enforcement in the future:
// 1. Set a concrete proof_size limit in RuntimeBlockWeights (instead of u64::MAX)
// 2. Update WeightToFee to price both ref_time and proof_size dimensions
// 3. Ensure all pallet benchmarks accurately measure proof_size

/// Multiplier for converting extrinsic length (bytes) to fee.
/// At 10^6, this means 1 MB of data costs approximately 1 UNIT in fees,
/// bringing storage costs roughly in line with compute costs.
pub const LENGTH_FEE_MULTIPLIER: Balance = 1_000_000;

/// Converts extrinsic length to fee with a multiplier.
///
/// This implementation applies [`LENGTH_FEE_MULTIPLIER`] to the extrinsic length,
/// making 1 MB of extrinsic data cost approximately 1 UNIT in fees.
///
/// Fee comparison at different transaction sizes:
/// - 500 bytes (simple transfer): ~0.0005 UNIT
/// - 10 KB (complex call): ~0.01 UNIT
/// - 100 KB (batch operation): ~0.1 UNIT
/// - 1 MB (large payload): ~1 UNIT
/// - 5 MB (full block): ~5 UNIT
pub struct LengthToFeeMultiplier;

impl WeightToFeePolynomial for LengthToFeeMultiplier {
	type Balance = Balance;

	fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
		smallvec![fee_scaled_coeff(LENGTH_FEE_MULTIPLIER)]
	}
}

/// Degree-1 coefficient of `base × FEE_SCALE`, split into integer and fractional
/// parts so fractional scales (`FEE_SCALE_DEN > 1`) keep precision.
// modulo_one/identity_op fire only while FEE_SCALE is 1/1, where `% DEN` and
// `/ DEN` constant-fold to no-ops; the split is load-bearing for any other DEN.
#[allow(clippy::modulo_one, clippy::identity_op)]
fn fee_scaled_coeff(base: Balance) -> WeightToFeeCoefficient<Balance> {
	let num = base * FEE_SCALE_NUM;
	WeightToFeeCoefficient {
		degree: 1,
		negative: false,
		coeff_integer: num / FEE_SCALE_DEN,
		coeff_frac: Perbill::from_rational(num % FEE_SCALE_DEN, FEE_SCALE_DEN),
	}
}

/// `IdentityFee` (1 planck per ps of ref_time) scaled by `FEE_SCALE`. Applied by
/// `pallet_transaction_payment` to both the base fee and the weight fee, so the
/// dial moves them together.
pub struct ScaledIdentityFee;

impl WeightToFeePolynomial for ScaledIdentityFee {
	type Balance = Balance;

	fn polynomial() -> WeightToFeeCoefficients<Self::Balance> {
		smallvec![fee_scaled_coeff(1)]
	}
}

parameter_types! {
	pub FeeMultiplier: Multiplier = Multiplier::one();
}

impl pallet_transaction_payment::Config for Runtime {
	type RuntimeEvent = RuntimeEvent;
	// Wraps `FungibleAdapter<Balances, TransactionFeesCollector>` and rejects
	// any non-zero tip from a high-security signer. Enforced here rather than
	// in the extension tuple so no `TxExtension` refactor can silently reopen
	// the tip channel.
	type OnChargeTransaction = crate::transaction_extensions::HighSecurityFungibleAdapter;
	/// Converts compute weight (ref_time) to fee. Identity (1:1) mapping scaled
	/// by `FEE_SCALE`, so 1 second of compute costs approximately `FEE_SCALE` UNIT.
	type WeightToFee = ScaledIdentityFee;
	/// Converts extrinsic length to fee. Uses 10^6 multiplier so 1 MB costs ~1 UNIT,
	/// bringing storage/bandwidth costs in line with compute costs.
	type LengthToFee = LengthToFeeMultiplier;
	type FeeMultiplierUpdate = ConstFeeMultiplier<FeeMultiplier>;
	type OperationalFeeMultiplier = ConstU8<5>;
	// Stock weights plus the two `HighSecurityAccounts` reads from the tip
	// policy and the `CollectedFees` read/write from `TransactionFeesCollector`.
	type WeightInfo = crate::transaction_extensions::PaymentWeightsWithTipPolicy;
}

impl pallet_utility::Config for Runtime {
	type RuntimeCall = RuntimeCall;
	type RuntimeEvent = RuntimeEvent;
	type WeightInfo = pallet_utility::weights::SubstrateWeight<Runtime>;
	type HighSecurity = HighSecurityConfig;
}

parameter_types! {
	pub const ReversibleTransfersPalletIdValue: PalletId = PalletId(*b"rtpallet");
	pub const DefaultDelay: BlockNumberOrTimestamp<BlockNumber, Moment> = BlockNumberOrTimestamp::BlockNumber(DAYS);
	pub const MinDelayPeriodBlocks: BlockNumber = 2;
	pub const MaxPendingPerAccount: u32 = 16;
	/// Maximum leaf calls in a high-security `batch_all`. Deliberately its own
	/// constant rather than reusing `MaxPendingPerAccount`: a future bump of
	/// pending-transfer capacity must not silently widen the maximum fee
	/// surface of a single high-security extrinsic.
	pub const MaxHighSecurityBatchLen: u32 = 16;
	/// Rolling 24h cap on signed extrinsics from a high-security account.
	pub const MaxHighSecurityTxsPerWindow: u32 = 16;
	pub const HighSecurityTxWindowBlocks: BlockNumber = DAYS;
	/// Volume fee for reversed transactions from high-security accounts only (1% fee is burned)
	pub const HighSecurityVolumeFee: Permill = Permill::from_percent(1);
}

/// Max encoded bytes of a high-security signer's extrinsic; larger ones are rejected
/// before any fee is withdrawn, capping the length fee.
///
/// The largest legitimate one is a flat `batch_all` of [`MaxHighSecurityBatchLen`]
/// `schedule_transfer`s (~7.2 KiB Dilithium sig+pubkey + ~0.8 KiB call ≈ 8.1 KiB).
/// 10 KiB leaves headroom; revisit if that ceiling grows.
pub const MAX_HIGH_SECURITY_EXTRINSIC_LEN: u32 = 10 * 1024;

/// Max zero-tip inclusion fee of a high-security signer's extrinsic; costlier
/// ones are rejected before any fee is withdrawn.
///
/// Unlike the per-call shape rules (Id-only dest, flat batch, arity, the
/// length cap above), this bounds the fee itself, so a future whitelisted
/// call with an unforeseen length or weight surface cannot reopen the
/// fee-drain channel. The costliest legitimate extrinsic today is
/// `recover_funds` at ~0.098 UNIT (17 statically charged wormhole proof
/// reservations); a 16-leaf `batch_all` of `schedule_transfer`s is
/// ~0.021 UNIT. 1 UNIT gives ~10x headroom for re-benchmarking drift and
/// caps the worst-case drain at `MaxHighSecurityTxsPerWindow` UNIT per
/// rolling day. Deterministic: `FeeMultiplierUpdate` is a constant one.
/// Scaled by `FEE_SCALE` in lockstep with the fees it bounds, so the headroom
/// is scale-invariant.
pub const MAX_HIGH_SECURITY_INCLUSION_FEE: Balance = scale_fee(UNIT);

impl pallet_reversible_transfers::Config for Runtime {
	type AssetId = AssetId;
	type SchedulerOrigin = OriginCaller;
	type Scheduler = Scheduler;
	type BlockNumberProvider = System;
	type DefaultDelay = DefaultDelay;
	type MinDelayPeriodBlocks = MinDelayPeriodBlocks;
	type MinDelayPeriodMoment = TargetBlockTime;
	type PalletId = ReversibleTransfersPalletIdValue;
	type Preimages = Preimage;
	type WeightInfo = pallet_reversible_transfers::weights::SubstrateWeight<Runtime>;
	type RuntimeHoldReason = RuntimeHoldReason;
	type Moment = Moment;
	type TimeProvider = Timestamp;
	type MaxPendingPerAccount = MaxPendingPerAccount;
	type MaxHighSecurityTxsPerWindow = MaxHighSecurityTxsPerWindow;
	type HighSecurityTxWindowBlocks = HighSecurityTxWindowBlocks;
	type VolumeFee = HighSecurityVolumeFee;
	// Nothing to record. Every call this pallet can schedule or execute moves
	// transparent value between accounts, and the call filter refuses all of
	// them under v1; the exit path those leaves existed for is gone with
	// `pallet-wormhole`.
	type ProofRecorder = ();
}

parameter_types! {
	pub const TreasuryPalletId: PalletId = PalletId(*b"py/trsry");
}

impl pallet_treasury::Config for Runtime {
	type WeightInfo = pallet_treasury::weights::SubstrateWeight<Runtime>;
}

parameter_types! {
	pub const VestingPalletId: PalletId = PalletId(*b"qvesting");
	/// Vesting payouts are rounded down to multiples of the tree's leaf quantum:
	/// a sub-quantum transfer would be committed as a zero-value leaf,
	/// stranding funds paid to keyless beneficiaries.
	pub const VestingPayoutQuantum: Balance = pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR;
	pub const VestingMinClaimInterval: u64 = MILLIS_PER_DAY;
}

/// The value that decides whether a leaf is non-zero is the ZK tree's quantum,
/// which is the pool's: `pallet-shielded` asserts the two are one number.
const _: () = assert!(
	VestingPayoutQuantum::get() == pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR,
	"vesting payout quantum must match the ZK tree's leaf amount scale factor"
);

/// A ZK leaf commits `amount / AMOUNT_SCALE_DOWN_FACTOR` as a `u32`, saturating at
/// `u32::MAX`. A payout past that ceiling would move real funds while committing a
/// clamped leaf, leaving the excess unexitable for a keyless beneficiary. Nothing in
/// the runtime bounds a single vesting payout below the ceiling — total issuance does:
/// no payout can exceed the maximum supply.
const _: () = assert!(
	MAX_SUPPLY < (u32::MAX as Balance) * pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR,
	"a single payout could exceed the ZK leaf's u32 amount ceiling"
);

/// The configured treasury account as an `Option` — unlike
/// `pallet_treasury::Pallet::account_id()`, this never panics on a chain whose
/// genesis omitted the treasury; vesting admin calls fail with an explicit error instead.
pub struct TreasuryAccountOption;
impl Get<Option<AccountId>> for TreasuryAccountOption {
	fn get() -> Option<AccountId> {
		pallet_treasury::Pallet::<Runtime>::treasury_account()
	}
}

/// `Signed(who)` where `who` is the configured treasury account.
///
/// The treasury is a multisig in real deployments; the multisig pallet dispatches
/// approved proposals as `RawOrigin::Signed(multisig_address)`, so a plain
/// signed-origin check covers it.
pub struct EnsureTreasury;
impl EnsureOrigin<RuntimeOrigin> for EnsureTreasury {
	type Success = AccountId;
	fn try_origin(o: RuntimeOrigin) -> Result<Self::Success, RuntimeOrigin> {
		match (o.clone().into(), pallet_treasury::Pallet::<Runtime>::treasury_account()) {
			(Ok(frame_system::RawOrigin::Signed(who)), Some(treasury)) if who == treasury =>
				Ok(who),
			_ => Err(o),
		}
	}
	#[cfg(feature = "runtime-benchmarks")]
	fn try_successful_origin() -> Result<RuntimeOrigin, ()> {
		pallet_treasury::Pallet::<Runtime>::treasury_account()
			.map(RuntimeOrigin::signed)
			.ok_or(())
	}
}

impl pallet_vesting::Config for Runtime {
	type Currency = Balances;
	type TimeProvider = Timestamp;
	type PalletId = VestingPalletId;
	type AdminOrigin = EitherOfDiverse<EnsureRoot<AccountId>, EnsureTreasury>;
	type TreasuryAccount = TreasuryAccountOption;
	type AssetId = AssetId;
	// Nothing to record: a vesting payout is a transparent transfer, the call
	// filter refuses `claim` and `create_schedule` under v1, and there is no
	// exit path a leaf could feed. The pallet rolls a payout back when the
	// recorder reports a dropped credit, so this one reports success; see
	// [`NoTransferProofNeeded`].
	type ProofRecorder = NoTransferProofNeeded;
	type PayoutQuantum = VestingPayoutQuantum;
	type MinClaimInterval = VestingMinClaimInterval;
	type WeightInfo = pallet_vesting::weights::SubstrateWeight<Runtime>;
}

// Multisig configuration
parameter_types! {
	pub const MultisigPalletId: PalletId = PalletId(*b"py/mltsg");
	pub const MaxSigners: u32 = 100;
	pub const MaxTotalProposalsInStorage: u32 = 200; // Max Active + Approved proposals per multisig
	pub const MaxCallSize: u32 = 10240; // 10KB
	pub const MultisigFee: Balance = scale_fee(30 * MILLI_UNIT); // 0.03 UNIT (non-refundable, burned)
	pub const ProposalDeposit: Balance = scale_fee(10 * MILLI_UNIT); // 0.01 UNIT (locked until cleanup)
	pub const ProposalFee: Balance = scale_fee(50 * MILLI_UNIT); // 0.05 UNIT (non-refundable)
	pub const SignerStepFactorParam: Permill = Permill::from_percent(1);
	pub const MaxExpiryDuration: BlockNumber = 100_800; // ~2 weeks at 12s blocks (14 days * 24h * 60m * 60s / 12s)
	// Maximum weight for inner calls executed via multisig: 1s of ref_time (a sixth
	// of the 6s block budget, leaving room for multisig bookkeeping and other
	// extrinsics) and 2.5 MiB of proof_size (uncharged today — the block's
	// proof_size limit is uncapped — but bounded here so a future switch to metered
	// proof_size cannot be saturated through multisig dispatch).
	pub MaxInnerCallWeight: Weight = Weight::from_parts(1_000_000_000_000, 2_621_440);
}

/// High-Security configuration wrapper for Runtime
///
/// This type alias delegates to `ReversibleTransfers` pallet for high-security checks
/// and adds RuntimeCall-specific whitelist validation.
///
/// Used by:
/// - Multisig pallet: validates calls in `propose()` extrinsic
/// - Transaction extensions: validates calls for high-security EOAs
///
/// Whitelist: the delayed, reversible operations, plus the two calls that move
/// the signer's own balance out of the transparent layer.
/// - `schedule_transfer`: delayed native transfer; dest must be `MultiAddress::Id` so a stolen key
///   cannot pad `MultiAddress::Raw` and exfiltrate via the length fee
/// - `cancel`: Cancel pending delayed transfer
/// - `recover_funds`: Guardian-initiated recovery
/// - `Shielded::shield` and `Balances::burn`: v1 refuses the three above at dispatch, so without
///   these an enrolled account could put nothing at all in a block. Neither names another account.
/// - `Utility::batch_all`: a flat, non-empty batch of at most [`MaxHighSecurityBatchLen`] leaf
///   calls, each of which must itself be whitelisted. Nested `batch_all` is rejected so a packed
///   wrapper cannot inflate the inclusion fee. The pallet still re-checks each child at dispatch so
///   a same-tx enrollment cannot smuggle a later drain.
///
/// v1 also refuses `set_high_security` itself ([`QneroCallFilter`]), so this
/// list is what the accounts already enrolled keep rather than a feature a new
/// account can opt into.
///
/// `Vesting::claim` is not listed: it is permissionless, so a third party can
/// claim on behalf of a high-security beneficiary. The HS signer does not need
/// it, and leaving it on the list was only another no-op fee path.
///
/// The tip is not part of `RuntimeCall`. High-security signers are forced to a
/// zero tip by `transaction_extensions::HighSecurityFungibleAdapter` inside
/// `OnChargeTransaction`, which every fee path goes through.
/// Signed extrinsics from a high-security account are also capped at 16 per
/// rolling day by `ReversibleTransactionExtension` (see `HighSecurityTxQuota`),
/// and at [`MAX_HIGH_SECURITY_EXTRINSIC_LEN`] encoded bytes so the length fee
/// cannot be inflated through any variable-length field.
///
/// The quota keys on the outer signer, so a *single-key* high-security
/// guardian shares it with its own traffic and can be quota-locked out of
/// `cancel`/`recover_funds` for up to a day. Documented limitation: an
/// exemption for live guardian interventions would be farmable (enrollment
/// needs no guardian consent), and the recommended multisig guardian is
/// immune — its derived address never signs an extrinsic, so the quota never
/// applies to it, even when the multisig is itself high-security.
pub struct HighSecurityConfig;

impl HighSecurityConfig {
	/// Leaf whitelist: the reversible-transfer calls, plus the two ways an
	/// account moves its own balance out of the transparent layer. `batch_all`
	/// is a wrapper and is never a valid child, so nesting cannot pad fees.
	/// `schedule_transfer` dest must be `MultiAddress::Id` so a stolen key
	/// cannot pad `Raw` and inflate the length fee.
	///
	/// `Shielded::shield` and `Balances::burn` are on the list because v1
	/// refuses every reversible-transfer call above
	/// ([`QneroCallFilter`]), and this list is checked at validation, before
	/// the filter is reached. Without them an account already enrolled in high
	/// security could not put a single extrinsic in a block: the three
	/// whitelisted calls die at dispatch on the filter, and everything else
	/// dies at validation on this list. Both move the account's own balance
	/// and neither can name another account, so a stolen key gains nothing it
	/// did not already have from `schedule_transfer`. `shield`'s ciphertext is
	/// variable length, which the [`MAX_HIGH_SECURITY_EXTRINSIC_LEN`] and
	/// [`MAX_HIGH_SECURITY_INCLUSION_FEE`] caps already bound.
	fn is_whitelisted_leaf(call: &RuntimeCall) -> bool {
		match call {
			RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::schedule_transfer { dest, .. },
			) => matches!(dest, MultiAddress::Id(_)),
			RuntimeCall::ReversibleTransfers(
				pallet_reversible_transfers::Call::cancel { .. } |
				pallet_reversible_transfers::Call::recover_funds { .. },
			) => true,
			RuntimeCall::Shielded(pallet_shielded::Call::shield { .. }) |
			RuntimeCall::Balances(pallet_balances::Call::burn { .. }) => true,
			_ => false,
		}
	}
}

impl qp_high_security::HighSecurityInspector<AccountId, RuntimeCall> for HighSecurityConfig {
	fn is_high_security(who: &AccountId) -> bool {
		// Delegate to reversible-transfers pallet
		pallet_reversible_transfers::Pallet::<Runtime>::is_high_security_account(who)
	}

	fn is_whitelisted(call: &RuntimeCall) -> bool {
		match call {
			RuntimeCall::Utility(pallet_utility::Call::batch_all { calls }) => {
				let n = calls.len() as u32;
				n > 0 &&
					n <= MaxHighSecurityBatchLen::get() &&
					calls.iter().all(Self::is_whitelisted_leaf)
			},
			_ => Self::is_whitelisted_leaf(call),
		}
	}

	fn guardian(who: &AccountId) -> Option<AccountId> {
		// Delegate to reversible-transfers pallet
		pallet_reversible_transfers::Pallet::<Runtime>::get_guardian(who)
	}
}

impl pallet_multisig::Config for Runtime {
	type RuntimeCall = RuntimeCall;
	type Currency = Balances;
	type MaxSigners = MaxSigners;
	type MaxTotalProposalsInStorage = MaxTotalProposalsInStorage;
	type MaxCallSize = MaxCallSize;
	type MultisigFee = MultisigFee;
	type ProposalDeposit = ProposalDeposit;
	type ProposalFee = ProposalFee;
	type SignerStepFactor = SignerStepFactorParam;
	type MaxExpiryDuration = MaxExpiryDuration;
	type MaxInnerCallWeight = MaxInnerCallWeight;
	type PalletId = MultisigPalletId;
	type WeightInfo = pallet_multisig::weights::SubstrateWeight<Runtime>;
	type HighSecurity = HighSecurityConfig;
}

impl TryFrom<RuntimeCall> for pallet_balances::Call<Runtime> {
	type Error = ();
	fn try_from(call: RuntimeCall) -> Result<Self, Self::Error> {
		match call {
			RuntimeCall::Balances(c) => Ok(c),
			_ => Err(()),
		}
	}
}

impl pallet_zk_tree::Config for Runtime {
	type AssetId = AssetId;
	type Balance = Balance;
}

parameter_types! {
	/// How far back a shielded settlement may anchor: 256 blocks, about 51
	/// minutes at a 12 second target.
	///
	/// Two bounds meet here. A proof names the header of one block and the
	/// chain resolves that hash from `frame_system::BlockHash`, which keeps
	/// `BlockHashCount` (4096) entries, so this is the tighter of the two on
	/// purpose: a proof built against a much older block saw a smaller
	/// commitment tree, and settling it would tell an observer roughly how old
	/// the anonymity set the prover used was. It also has to be wide enough
	/// that a wallet can finish proving: about 20 seconds single threaded at
	/// `N = 6`, plus propagation.
	pub const ShieldedBlockHashWindow: BlockNumber = 256;
	/// Minimum fee per real leaf slot, in pool quanta: one quantum, 0.01 QTC.
	///
	/// The anti-spam mechanism, and the only one. The leaf circuit requires a
	/// real input, which does not bound how many leaves a prover can produce:
	/// one note of any value spent with a dummy in the other slot mints two
	/// spendable notes and can be repeated every block, each repetition writing
	/// two nullifier entries and two tree slots into permanent state. Settlement
	/// extrinsics are unsigned and fee free, so the leaf's own fee is the only
	/// cost there is.
	///
	/// The submission floor charges it once per real leaf slot the submission
	/// carries, a slot the chain skips included. A skipped slot writes no
	/// permanent state and it still costs every node the admission walk over it
	/// and the weight the extrinsic declares, and nothing else is charged for
	/// that, so a submission that carries 318 slots and settles one pays 318
	/// minimums.
	pub const ShieldedMinLeafFee: u64 = 1;
	/// Bytes of note ciphertext one quantum of fee buys: 512 bytes.
	///
	/// A real slot carries two ciphertexts whose fixed part is 1731 bytes
	/// each, plus whatever memo pad the wallet writing them uses; the v0
	/// wallet pads to 61, so the pair it publishes is 3584 bytes and pays
	/// seven quanta of payload on top of `ShieldedMinLeafFee`. A slot padded
	/// to the cap (two ciphertexts of `ShieldedMaxCiphertextBytes`, 4096 bytes
	/// in total) pays eight. The flat floor alone would price either at one
	/// quantum. The chain never parses these bytes and `Ciphertexts` is never
	/// pruned, so the whole cap is usable by a settler and the payload is what
	/// has to be priced.
	///
	/// The divisor has to sit below the slack between the real ciphertext size
	/// and the cap, or the term prices nothing it was added to price: at one
	/// kilobyte both 3584 and 4096 bytes round to four quanta, so a settler
	/// could pad both ciphertexts to the cap and add 512 bytes of permanent,
	/// never-pruned, never-parsed state for no extra fee.
	/// `a_slot_pays_for_the_ciphertext_bytes_it_publishes` in the pallet's
	/// tests pins the two endpoints apart, and the real endpoint it pins is
	/// the padded pair a wallet actually sends. The memo pad eats the same
	/// slack: a pad of 256 would put a real pair at 3974 bytes,
	/// in the cap's own bucket, and the separation would be gone for every
	/// spend on the chain while both test suites stayed green.
	///
	/// It prices the submission as well as the slot. A segment the chain skips,
	/// because a nullifier it publishes is already spent or because its block
	/// anchor no longer resolves, pays no fee of its own: it writes no
	/// permanent state, and charging it the fee it paid when it first settled
	/// would drift `PoolValue` from the sum of the notes behind it. Its
	/// ciphertexts are in the block all the same and every node sponges them
	/// into a `ct_digest`, so the settling slots of a submission owe
	/// `(settling slots + skipped slots) * ShieldedMinLeafFee` plus one quantum
	/// per started 512 bytes the submission carries, a skipped segment's bytes
	/// included. A skipped position may instead be emptied, which is what a
	/// griefed aggregator resubmits: that removes the position from the payload
	/// term, and the slot behind it is still charged the flat minimum, because
	/// the walk and the weight it costs a block do not depend on its bytes.
	pub const ShieldedCiphertextBytesPerFeeQuantum: u32 = 512;
	/// Half of a settled fee is burned, half becomes part of the block's
	/// coinbase note. The same split the wormhole applied to its volume fee.
	pub const ShieldedFeeBurnRate: Permill = Permill::from_percent(50);
	/// Size cap on one note ciphertext: 2048 bytes.
	///
	/// A `NoteCiphertext` at the chain's parameter set serializes to 1731 bytes
	/// with an empty memo: 19 bytes of framing (a version byte, a two-byte
	/// crypto suite, a four-byte diversifier index, and a `u32` length before
	/// each of the three payloads), an ML-KEM-1024 encapsulation (1568), the
	/// 112-byte note payload under a ChaCha20-Poly1305 tag (128), and the
	/// memo's own tag (16). `an_empty_memo_ciphertext_serializes_to_1731_bytes`
	/// in `qnero-pqcrypto` pins that total against the serializer. The cap
	/// leaves 317 bytes of memo.
	///
	/// The slack is deliberately small, and the whole cap is what a settler can
	/// use: the chain never parses these bytes, so nothing holds a submission
	/// to a real `NoteCiphertext` shape, and `Ciphertexts` is never pruned.
	/// `ShieldedCiphertextBytesPerFeeQuantum` is what prices the payload; this
	/// cap is what bounds one slot's worst case. A wallet reads this bound from
	/// the pallet's metadata, where a hardcoded copy would drift: exceeding it
	/// fails the extrinsic's SCALE decode after the proof that committed to
	/// those exact bytes has already been built.
	pub const ShieldedMaxCiphertextBytes: u32 = 2048;
}

impl pallet_shielded::Config for Runtime {
	type Currency = Balances;
	/// The same tree instance the wormhole appends to. There is one
	/// `zk_tree_root` in the header, and that root is what every shielded spend
	/// proof anchors at, so a second instance would be a root no proof could
	/// reach. The two leaf kinds cannot be confused: a wormhole leaf hashes an
	/// 8-felt typed preimage and a shielded leaf is a note commitment, a
	/// Poseidon2 output over a 6-felt preimage led by the `CM` domain tag, so
	/// passing one off as the other is a preimage attack on Poseidon2.
	type ZkTree = ZkTree;
	type FindAuthor = QpowAuthor;
	type BlockHashWindow = ShieldedBlockHashWindow;
	type MinLeafFee = ShieldedMinLeafFee;
	type CiphertextBytesPerFeeQuantum = ShieldedCiphertextBytesPerFeeQuantum;
	type FeeBurnRate = ShieldedFeeBurnRate;
	type MaxCiphertextBytes = ShieldedMaxCiphertextBytes;
	type WeightInfo = pallet_shielded::weights::SubstrateWeight<Runtime>;
}
