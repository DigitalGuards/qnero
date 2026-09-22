//! The target block time, and everything the runtime derives from it.
//!
//! The public chain targets 120 000 ms, Monero's interval. `docs/DESIGN.md`
//! carries the decision and the rationale; what this file carries is every
//! number that moved with it, so a future edit to `TARGET_BLOCK_TIME_MS` cannot
//! silently change what a governance period, a reversal window or a quota
//! window means.
//!
//! Two kinds of constant live here and they are audited differently:
//!
//! - Derived durations keep their meaning and change their block count. `DAYS` is one day at any
//!   target.
//! - Block counts keep their count and change their meaning. 256 blocks of shielded anchor validity
//!   is 8.5 hours at 120 s where it was 51 minutes at 12 s, and that was the point of leaving it
//!   alone.

use frame_support::traits::Get;
use qnero_runtime::{
	configs::{
		ChainTargetBlockTime, DefaultDelay, HighSecurityTxWindowBlocks, MaxExpiryDuration,
		MinDelayPeriodBlocks, ShieldedBlockHashWindow, TargetBlockTime, TimestampBucketSize,
		UndecidingTimeout,
	},
	DAYS, HOURS, MINUTES, TARGET_BLOCK_TIME_MS,
};
use qp_scheduler::BlockNumberOrTimestamp;

/// Monero's interval, and the runtime's public default.
#[test]
fn the_public_target_is_two_minutes() {
	assert_eq!(TARGET_BLOCK_TIME_MS, 120_000);
	assert_eq!(TargetBlockTime::get(), TARGET_BLOCK_TIME_MS);
}

/// Each unit is derived from milliseconds on its own. Chaining `HOURS` off
/// `MINUTES` would make both zero at a target longer than a minute, and every
/// governance period denominated in them would collapse to the next block with
/// nothing to say so.
#[test]
fn the_time_units_are_derived_from_milliseconds() {
	assert_eq!(MINUTES, 1, "one block, the shortest period a block count can express: 2 minutes");
	assert_eq!(HOURS, 30, "3_600_000 / 120_000, still exactly one hour");
	assert_eq!(DAYS, 720, "86_400_000 / 120_000, still exactly one day");
	assert_ne!(HOURS, MINUTES * 60, "chaining would make this two hours");
	assert_eq!(DAYS, HOURS * 24);
}

/// Every constant whose block count is a duration. The count changes, the
/// duration does not.
#[test]
fn duration_denominated_constants_keep_their_durations() {
	assert_eq!(UndecidingTimeout::get(), 45 * DAYS);
	assert_eq!(UndecidingTimeout::get(), 32_400, "still 45 days");
	assert_eq!(
		DefaultDelay::get(),
		BlockNumberOrTimestamp::BlockNumber(DAYS),
		"the default reversible delay is still 24 hours"
	);
	assert_eq!(HighSecurityTxWindowBlocks::get(), DAYS);
	assert_eq!(HighSecurityTxWindowBlocks::get(), 720, "the 16-tx quota window is still 24 hours");
	assert_eq!(MaxExpiryDuration::get(), 14 * DAYS);
	assert_eq!(
		MaxExpiryDuration::get(),
		10_080,
		"a multisig proposal still expires after two weeks; the old bare 100_800 would have \
		 made it 140 days"
	);
}

/// Every constant whose block count is a count. The duration changes, and this
/// is where the new duration is written down.
#[test]
fn count_denominated_constants_keep_their_counts() {
	assert_eq!(
		ShieldedBlockHashWindow::get(),
		256,
		"256 blocks of anchor validity: 8.5 hours at 120 s, which suits a phone prover"
	);
	assert_eq!(
		MinDelayPeriodBlocks::get(),
		2,
		"two confirmations is the guarantee; at 120 s that is 4 minutes of wall clock"
	);
}

/// The scheduler's timestamp granularity follows the chain's configured target
/// rather than the runtime constant, so a 12 s dev chain keeps 24 s buckets.
/// With no genesis storage written it falls back to the constant, which is the
/// path benchmarks, mocks and any pre-104 chain take.
#[test]
fn the_timestamp_bucket_follows_the_chain_target() {
	sp_io::TestExternalities::default().execute_with(|| {
		assert_eq!(ChainTargetBlockTime::get(), TARGET_BLOCK_TIME_MS);
		assert_eq!(TimestampBucketSize::get(), 2 * TARGET_BLOCK_TIME_MS);
		assert_eq!(TimestampBucketSize::get(), 240_000, "4 minutes, up from 24 s at a 12 s target");

		pallet_qpow::TargetBlockTimeMs::<qnero_runtime::Runtime>::put(12_000u64);
		assert_eq!(ChainTargetBlockTime::get(), 12_000);
		assert_eq!(TimestampBucketSize::get(), 24_000, "a dev chain keeps its 24 s buckets");
	});
}

/// How far the storage target reaches, said as a test because the reach is
/// partial and the partial half is easy to read as a whole one.
///
/// The genesis-configured target is what the retarget aims at, what
/// [`TimestampBucketSize`] doubles and what `MinDelayPeriodMoment` equals. It is
/// not what `MINUTES`, `HOURS` and `DAYS` derive from: those come from
/// `TARGET_BLOCK_TIME_MS`, the compile-time constant, so every window
/// denominated in them keeps the public chain's block count on a chain running
/// at another cadence. On the 12 s `dev` chain that makes each of them mean a
/// tenth of the wall clock its name claims, and the emission divisor is the
/// same kind of constant for the same reason. All three are metadata: a client
/// reads a governance period and a supply schedule out of metadata, and a value
/// that changed with a storage read is a value no metadata could state.
/// `docs/DESIGN.md` 7.4 and `docs/OPS-DEV.md` carry the same sentence.
#[test]
fn the_storage_target_does_not_reach_the_day_denominated_windows() {
	sp_io::TestExternalities::default().execute_with(|| {
		pallet_qpow::TargetBlockTimeMs::<qnero_runtime::Runtime>::put(12_000u64);

		assert_eq!(ChainTargetBlockTime::get(), 12_000, "the chain runs at the dev cadence");
		assert_eq!(
			HighSecurityTxWindowBlocks::get(),
			720,
			"the quota window keeps the public chain's block count, which at 12 s is 2.4 hours"
		);
		assert_eq!(DefaultDelay::get(), BlockNumberOrTimestamp::BlockNumber(720));
		assert_eq!(UndecidingTimeout::get(), 32_400);
		assert_eq!(MaxExpiryDuration::get(), 10_080);
		assert_eq!(DAYS, 720, "`DAYS` is the compile-time constant's day, on every chain");
	});
}

/// The RandomX seed schedule, in the block counts the runtime ships and the
/// wall clock those counts mean at the public target.
///
/// `chain/pallets/qpow/src/tests.rs` asserts the pallet's mock, so without
/// this test the values the chain actually ships are pinned only by the byte
/// comparison against the committed chain spec. The schedule belongs to this
/// file for the same reason the anchor window does: the block count is fixed
/// and the wall clock it means comes from `TARGET_BLOCK_TIME_MS`.
///
/// 2048 blocks is 245 760 000 ms, 2.84 days, Monero's own rotation interval.
/// 128 blocks is 15 360 000 ms, 4.3 hours, the distance between the block that
/// supplies a seed and the first block that hashes under it, and the notice a
/// full-mode rig gets on its next dataset build. `docs/DESIGN.md` 7.4 and
/// open question 3 carry the decision.
#[test]
fn the_seed_schedule_is_the_one_the_chain_ships() {
	// `ConstU32` answers `Get<u32>` and `Get<Option<u32>>` both, so the
	// binding names the one this file means.
	let epoch: u32 = <qnero_runtime::Runtime as pallet_qpow::Config>::SeedEpochBlocks::get();
	let lag: u32 = <qnero_runtime::Runtime as pallet_qpow::Config>::SeedEpochLag::get();

	assert_eq!(epoch, 2_048, "Monero's epoch, kept because the target is Monero's 120 s");
	assert_eq!(lag, 128, "twice Monero's lag, decided in the pre-genesis bundle");

	let epoch = u64::from(epoch);
	let lag = u64::from(lag);

	assert_eq!(epoch * TARGET_BLOCK_TIME_MS, 245_760_000, "2048 blocks at 120 s is 2.84 days");
	assert_eq!(lag * TARGET_BLOCK_TIME_MS, 15_360_000, "128 blocks at 120 s is 4.3 hours");

	// The two numbers the consensus client derives from the pair. Below
	// `epoch + lag` every block seeds from genesis, so the first rotation on a
	// fresh genesis is at 2177, and the seed walk is bounded by `epoch + lag`
	// (`chain/client/consensus/randomx/src/lib.rs`, `max_walk`).
	assert_eq!(epoch + lag, 2_176, "the seed-walk bound");
	assert_eq!(epoch + lag + 1, 2_177, "the first height with a seed other than genesis");
}
