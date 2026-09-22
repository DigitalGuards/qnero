use crate::{mock::*, Config, CurrentDifficulty};
use frame_support::{pallet_prelude::TypedGet, traits::Hooks};
use primitive_types::U512;
use sp_runtime::BuildStorage;

#[test]
fn test_difficulty_bounds() {
	new_test_ext().execute_with(|| {
		let min_difficulty = QPow::get_min_difficulty();
		let max_difficulty = QPow::get_max_difficulty();
		let initial_difficulty = QPow::initial_difficulty();

		assert_eq!(min_difficulty, U512::from(128u64));
		assert!(max_difficulty > initial_difficulty);
		assert!(initial_difficulty > min_difficulty);
	});
}

fn run_to_block(n: u64) {
	while System::block_number() < n {
		if System::block_number() > 1 {
			QPow::on_finalize(System::block_number());
			System::on_finalize(System::block_number());
		}
		System::set_block_number(System::block_number() + 1);
		System::on_initialize(System::block_number());
		QPow::on_initialize(System::block_number());
	}
}

fn run_block(block_num: u64, timestamp: u64) {
	System::set_block_number(block_num);
	pallet_timestamp::Pallet::<Test>::set_timestamp(timestamp);
	QPow::on_finalize(block_num);
}

#[test]
fn test_difficulty_adjustment() {
	new_test_ext().execute_with(|| {
		// Get initial difficulty
		let initial_difficulty = QPow::get_difficulty();
		assert!(initial_difficulty > U512::zero());

		// Run a few blocks
		run_to_block(3);

		// Difficulty should be tracked
		let current_difficulty = QPow::get_difficulty();
		assert!(current_difficulty > U512::zero());
	});
}

#[test]
fn test_difficulty_storage_and_retrieval() {
	new_test_ext().execute_with(|| {
		// 1. Test genesis block difficulty
		let genesis_difficulty = QPow::initial_difficulty();
		let initial_difficulty = <Test as Config>::InitialDifficulty::get();

		assert_eq!(
			genesis_difficulty, initial_difficulty,
			"Genesis block should have initial difficulty"
		);

		// 2. Simulate block production
		run_to_block(1);

		// 3. Check difficulty for block 1
		let block_1_difficulty = QPow::get_difficulty();
		assert_eq!(
			block_1_difficulty, initial_difficulty,
			"Block 1 should have same difficulty as initial"
		);

		// 4. Simulate adjustment period
		run_to_block(2);
	});
}

#[test]
fn test_difficulty_calculation() {
	new_test_ext().execute_with(|| {
		let current_difficulty = U512::from(1000u64);
		let observed_time = 2000u64; // 2x target
		let target_time = 1000u64;

		// When blocks are slow, difficulty should decrease
		let new_difficulty =
			QPow::calculate_difficulty(current_difficulty, observed_time, target_time);

		// Should be bounded by min/max
		let min_difficulty = QPow::get_min_difficulty();
		let max_difficulty = QPow::get_max_difficulty();
		assert!(new_difficulty >= min_difficulty);
		assert!(new_difficulty <= max_difficulty);
	});
}

#[test]
fn test_difficulty_recovers_after_sleep() {
	new_test_ext().execute_with(|| {
		let target = QPow::target_block_time();

		for i in 1u64..=10 {
			run_block(i, i * target);
		}

		let pre_sleep = QPow::get_difficulty();
		assert_eq!(pre_sleep, U512::from(1_000_000u64));

		// Simulate laptop sleep: 1-hour gap between blocks
		run_block(11, 10 * target + 3_600_000);

		// 20 normal blocks after waking
		for i in 12u64..=31 {
			run_block(i, 10 * target + 3_600_000 + (i - 11) * target);
		}

		let recovered = QPow::get_difficulty();
		// Ethereum-style adjustment decreases difficulty by up to 99/2048 per block during sleep,
		// then increases slowly during recovery. 20 normal blocks bring difficulty back partially.
		assert!(
			recovered > pre_sleep / 10,
			"Difficulty should stay above 10% after sleep. Pre: {}, Post: {}",
			pre_sleep.low_u64(),
			recovered.low_u64()
		);
	});
}

/// V12 audit fix (181313): genesis difficulty outside the operational bounds
/// (here: zero) must fail early during genesis build.
#[test]
#[should_panic(expected = "Genesis initial difficulty must be within")]
fn test_genesis_rejects_out_of_range_difficulty() {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	crate::GenesisConfig::<Test> {
		initial_difficulty: U512::zero(),
		target_block_time: <Test as Config>::TargetBlockTime::get(),
		_phantom: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();
}

/// V12 audit fix (181438): the retarget floors the author-controlled block time,
/// so an implausibly small timestamp delta cannot steer difficulty. The floor
/// stays below the divisor at the production-scale target, so genuinely fast
/// blocks still raise difficulty (the floor is a no-op there).
#[test]
fn test_retarget_floors_small_block_time() {
	new_test_ext().execute_with(|| {
		let difficulty = U512::from(1_000_000u64);

		// target 600ms -> divisor 500ms, equal to the 500ms floor: a sub-floor
		// delta is clamped to the floor and yields no increase.
		let target = 600u64;
		let floored = QPow::calculate_difficulty(difficulty, 1, target);
		let at_floor = QPow::calculate_difficulty(difficulty, 500, target);
		assert_eq!(floored, at_floor, "sub-floor block time must be clamped to the floor");
		assert_eq!(floored, difficulty, "floored delta must not raise difficulty");

		// production-scale target: floor stays below the divisor, so fast blocks
		// still increase difficulty.
		let fast = QPow::calculate_difficulty(difficulty, 100, PUBLIC_TARGET);
		assert!(
			fast > difficulty,
			"fast blocks must still increase difficulty at production target"
		);
	});
}

#[test]
fn test_zero_observed_block_time() {
	new_test_ext().execute_with(|| {
		let difficulty = U512::from(1_000_000u64);
		let result = QPow::calculate_difficulty(difficulty, 0, 1000);
		let min = QPow::get_min_difficulty();
		let max = QPow::get_max_difficulty();
		assert!(result >= min);
		assert!(result <= max);
	});
}

#[test]
fn test_min_difficulty_derived_from_clamp() {
	new_test_ext().execute_with(|| {
		assert_eq!(QPow::get_min_difficulty(), U512::from(128u64));
	});
}

#[test]
fn test_min_difficulty_can_increase() {
	new_test_ext().execute_with(|| {
		let min_diff = QPow::get_min_difficulty();
		// Fast blocks → positive adjustment → difficulty increases by 1/2048
		let result = QPow::calculate_difficulty(min_diff, 1, 1000);
		assert!(
			result > min_diff,
			"Min difficulty must be able to increase: {} should be > {}",
			result.low_u64(),
			min_diff.low_u64()
		);
	});
}

#[test]
fn test_min_difficulty_floors_on_slow_blocks() {
	new_test_ext().execute_with(|| {
		let min_diff = QPow::get_min_difficulty();
		// Slow blocks → negative adjustment, but clips to min difficulty
		let result = QPow::calculate_difficulty(min_diff, 100_000, 1000);
		assert_eq!(result, min_diff);
	});
}

#[test]
fn test_difficulty_below_min_clips_up() {
	new_test_ext().execute_with(|| {
		let min_diff = QPow::get_min_difficulty();
		// Starting at 1 (below min), any result clips to min_difficulty
		let result_fast = QPow::calculate_difficulty(U512::from(1u64), 1, 1000);
		let result_slow = QPow::calculate_difficulty(U512::from(1u64), 100_000, 1000);
		assert_eq!(result_fast, min_diff);
		assert_eq!(result_slow, min_diff);
	});
}

/// Regression test for V12 audit fix #2: adjust_difficulty must use get_difficulty()
/// (which falls back to InitialDifficulty) rather than reading raw storage (which
/// would return zero if unset, causing difficulty to collapse to min_difficulty).
#[test]
fn test_adjust_difficulty_with_zero_storage_uses_initial_difficulty() {
	new_test_ext().execute_with(|| {
		let initial_difficulty = <Test as Config>::InitialDifficulty::get();
		let target_time = QPow::target_block_time();

		// Clear the CurrentDifficulty storage to simulate unset state.
		// This could happen if genesis wasn't properly initialized or storage was corrupted.
		CurrentDifficulty::<Test>::kill();

		// Verify storage is indeed zero
		assert_eq!(CurrentDifficulty::<Test>::get(), U512::zero());

		// But get_difficulty() should return InitialDifficulty, not zero
		assert_eq!(QPow::get_difficulty(), initial_difficulty);

		// Set up timestamp for block 1
		pallet_timestamp::Pallet::<Test>::set_timestamp(target_time);
		System::set_block_number(1);

		// Run on_finalize which calls adjust_difficulty
		QPow::on_finalize(1);

		// The new difficulty should be based on InitialDifficulty, not zero.
		// With target_time == observed_time, difficulty should remain close to initial.
		let new_difficulty = QPow::get_difficulty();

		// Key assertion: difficulty should NOT have collapsed to min_difficulty.
		// If the bug existed (using raw storage zero), we'd get min_difficulty.
		let min_difficulty = QPow::get_min_difficulty();
		assert!(
			new_difficulty > min_difficulty,
			"Difficulty collapsed to min! Bug: adjust_difficulty used raw zero storage. \
			 Expected near {}, got {} (min={})",
			initial_difficulty.low_u64(),
			new_difficulty.low_u64(),
			min_difficulty.low_u64()
		);

		// Difficulty should be close to initial (within adjustment bounds)
		// Ethereum-style adjustment is at most ±1/2048 per block
		let max_change = initial_difficulty / 2048;
		assert!(
			new_difficulty >= initial_difficulty.saturating_sub(max_change) &&
				new_difficulty <= initial_difficulty.saturating_add(max_change),
			"Difficulty {} not within ±1/2048 of initial {}",
			new_difficulty.low_u64(),
			initial_difficulty.low_u64()
		);
	});
}

/// A max-legal future timestamp plus the honest catch-up blocks
/// `create_inherent` is forced to produce must not leave a permanent deficit
/// versus the same wall clock of honest blocks at the target.
///
/// The drift allowance is an absolute number of seconds and the retarget's
/// buckets scale with the target, so moving the public target from 12 s to
/// 120 s made this strictly safer: a 15 s inflate used to push a 12 s wait into
/// the next 10 s bucket and cost a single -1, and at a 100 s divisor it does not
/// leave the neutral band at all. Both targets are checked, because the dev
/// chain still runs at 12 s.
#[test]
fn max_timestamp_drift_does_not_bias_difficulty_down() {
	new_test_ext().execute_with(|| {
		let start = U512::from(4_000_000u64);
		let run = |target: u64, mut d: U512, deltas: &[u64]| {
			for &t in deltas {
				d = QPow::calculate_difficulty(d, t, target);
			}
			d
		};

		// Dev target: 12s wait + 15s future, then last+100ms, then the wall
		// clock catches up.
		let honest = run(DEV_TARGET, start, &[12_000, 12_000, 12_000]);
		let attacked = run(DEV_TARGET, start, &[27_000, 100, 8_900]);
		assert_eq!(honest, start, "honest 12s blocks leave difficulty unchanged");
		assert!(
			attacked >= honest,
			"max-drift cycle must not book a deficit at the dev target: honest {honest}, attacked {attacked}"
		);

		// Public target: the same 15s inflate after a 120s wait.
		let honest = run(PUBLIC_TARGET, start, &[120_000, 120_000, 120_000]);
		let attacked = run(PUBLIC_TARGET, start, &[135_000, 100, 104_900]);
		assert_eq!(honest, start, "honest 120s blocks leave difficulty unchanged");
		assert!(
			attacked >= honest,
			"max-drift cycle must not book a deficit at the public target: honest {honest}, attacked {attacked}"
		);
	});
}

/// The public chain's target and the `dev` preset's, as the retarget sees them.
const PUBLIC_TARGET: u64 = 120_000;
const DEV_TARGET: u64 = 12_000;

/// One rig of a fixed hash rate, driven to wherever the retarget takes it.
///
/// Difficulty is expected hashes per block, so the observed block time is
/// `difficulty / hash_rate`, and the retarget is fed that. Returns the blocks
/// it took to settle, the difficulty it settled on, the block time there and
/// the wall clock the run covered.
fn settle(start: U512, hash_rate: u64, target: u64, max_blocks: u32) -> (u32, U512, u64, u64) {
	let mut difficulty = start;
	let mut blocks = 0u32;
	let mut block_time_ms = 0u64;
	let mut wall_clock_ms = 0u64;
	while blocks < max_blocks {
		block_time_ms = (difficulty.low_u64().saturating_mul(1_000) / hash_rate).max(1);
		let next = QPow::calculate_difficulty(difficulty, block_time_ms, target);
		blocks += 1;
		wall_clock_ms = wall_clock_ms.saturating_add(block_time_ms);
		if next == difficulty {
			break;
		}
		difficulty = next;
	}
	(blocks, difficulty, block_time_ms, wall_clock_ms)
}

/// A chain that starts at the difficulty floor has to climb to a live
/// difficulty on the retarget alone, and a chain that loses hash rate has to
/// come back down the same way. This pins both, and the second half is where
/// the band is not symmetric with intuition.
///
/// The Homestead band is one to two divisors wide, so at a 120 s target (a 100 s
/// divisor) it is 100 s to 200 s and it is dead in both directions. A chain
/// climbing into it stops at the bottom, at 100 s blocks; a chain falling into
/// it stops at the top, at 200 s blocks, and stays there. Both are inside the
/// band by construction, and the target itself is the middle of it. `chain/MINING.md` says the same
/// thing to an operator.
///
/// The climb's cost is worth stating in both units, because one of them is not
/// ten times the 12 s figure. At 120 s it is 13 628 blocks and 2.40 days; at
/// 12 s it is 8 857 blocks and 0.25 days. The block count grows by half because
/// the settle difficulty is ten times higher and every step is a fixed 1/2048
/// fraction. The wall clock grows by ten for the same reason, the difficulty:
/// the whole climb runs far below the target, so multiplying the block count by
/// 120 s would overstate it by a factor of eight.
#[test]
fn a_chain_at_the_floor_converges_to_the_target_band() {
	new_test_ext().execute_with(|| {
		/// A small testnet rig: about two modern cores in full mode.
		const HASH_RATE: u64 = 3_500;
		/// Measured: 13_628 blocks and 2.40 days of wall clock.
		const MAX_BLOCKS: u32 = 14_000;
		let band = PUBLIC_TARGET * 10 / 12..PUBLIC_TARGET * 20 / 12;

		let (blocks, difficulty, block_time_ms, wall_clock_ms) =
			settle(QPow::get_min_difficulty(), HASH_RATE, PUBLIC_TARGET, MAX_BLOCKS);

		assert!(
			(13_000..MAX_BLOCKS).contains(&blocks),
			"climb from the floor took {blocks} blocks, expected about 13_628"
		);
		let days = wall_clock_ms / (24 * 60 * 60 * 1_000);
		assert_eq!(days, 2, "the climb covers about 2.4 days: it runs far below the target");
		assert!(
			band.contains(&block_time_ms),
			"settled block time {block_time_ms}ms is outside the retarget's neutral band"
		);
		// The band's lower edge is `hash_rate * divisor`, and the climb stops on
		// the first step that lands inside it.
		assert!(difficulty >= U512::from(HASH_RATE * (PUBLIC_TARGET * 10 / 12) / 1_000));

		// The same climb at the `dev` preset's target, for the comparison the
		// docs quote: fewer blocks, because the settle difficulty is ten times
		// lower and each step is the same fraction of it.
		let (dev_blocks, _, dev_block_time_ms, _) =
			settle(QPow::get_min_difficulty(), HASH_RATE, DEV_TARGET, MAX_BLOCKS);
		assert!(
			(8_500..9_500).contains(&dev_blocks),
			"the 12 s climb took {dev_blocks} blocks, expected about 8_857"
		);
		assert!((DEV_TARGET * 10 / 12..DEV_TARGET * 20 / 12).contains(&dev_block_time_ms));
		assert!(dev_blocks < blocks, "a ten times higher settle difficulty costs more steps");

		// Now take nine tenths of the hash rate away. The chain falls through
		// the band from above and stops at its top edge, so a network that lost
		// its miners holds 200 s blocks for good, with no drift back toward 120.
		// Monotonic all the way down: no oscillation, no overshoot.
		let mut falling = difficulty;
		let mut steps = 0u32;
		let mut fell_to = 0u64;
		while steps < 2_000 {
			let observed = (falling.low_u64().saturating_mul(1_000) / (HASH_RATE / 10)).max(1);
			let next = QPow::calculate_difficulty(falling, observed, PUBLIC_TARGET);
			steps += 1;
			fell_to = observed;
			if next == falling {
				break;
			}
			assert!(next < falling, "the fall must be monotonic, {next} is not below {falling}");
			falling = next;
		}
		assert!(
			(1_000..2_000).contains(&steps),
			"the fall took {steps} blocks, expected about 1_555"
		);
		assert!(band.contains(&fell_to), "settled at {fell_to}ms, outside the band");
		assert!(
			fell_to > PUBLIC_TARGET,
			"a chain falling into the band settles at its top edge, about 200 s"
		);
	});
}

/// The target is chain state, so one binary serves a 120 s public chain and a
/// 12 s dev chain. The accessor falls back to the runtime constant when storage
/// is unset, which is what an already-running chain reads.
#[test]
fn the_target_block_time_comes_from_genesis_storage() {
	new_test_ext().execute_with(|| {
		assert_eq!(QPow::target_block_time(), <Test as Config>::TargetBlockTime::get());
		crate::TargetBlockTimeMs::<Test>::put(PUBLIC_TARGET);
		assert_eq!(QPow::target_block_time(), PUBLIC_TARGET);
		crate::TargetBlockTimeMs::<Test>::kill();
		assert_eq!(
			QPow::target_block_time(),
			<Test as Config>::TargetBlockTime::get(),
			"an unset target must fall back to the runtime constant"
		);
	});
}

/// A zero target would divide by zero in the retarget, so genesis refuses it.
#[test]
#[should_panic(expected = "Genesis target block time must be non-zero")]
fn test_genesis_rejects_zero_target_block_time() {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	crate::GenesisConfig::<Test> {
		initial_difficulty: <Test as Config>::InitialDifficulty::get(),
		target_block_time: 0,
		_phantom: Default::default(),
	}
	.assimilate_storage(&mut t)
	.unwrap();
}

/// The seed schedule is chain state, so the consensus client can read it
/// instead of carrying Monero's constants as a literal.
#[test]
fn the_seed_schedule_is_readable_from_the_runtime() {
	new_test_ext().execute_with(|| {
		assert_eq!(QPow::get_seed_epoch_blocks(), 2048);
		assert_eq!(QPow::get_seed_epoch_lag(), 128);
	});
}

/// The retarget reads block times and nothing else. Feeding it the same times
/// twice gives the same answer, whatever hash produced those blocks, which is
/// the property that let the RandomX swap keep this pallet.
#[test]
fn the_retarget_is_a_function_of_block_times_alone() {
	let parent = U512::from(1_000_000u64);
	let target = 1_000u64;
	let fast = QPow::calculate_difficulty(parent, 100, target);
	let on_time = QPow::calculate_difficulty(parent, target, target);
	let slow = QPow::calculate_difficulty(parent, 10_000, target);

	assert_eq!(fast, QPow::calculate_difficulty(parent, 100, target));
	assert!(fast > on_time, "a fast block must raise difficulty");
	assert!(slow < on_time, "a slow block must lower difficulty");
}

/// The floor moved for RandomX, and the `dev` preset starts there, so a value
/// below it would stop a dev chain from building genesis at all.
#[test]
fn the_floor_is_reachable_by_one_light_mode_thread() {
	new_test_ext().execute_with(|| {
		let floor = QPow::get_min_difficulty();
		assert_eq!(floor, U512::from(128u64));
		// About four seconds at the ~33 H/s one light-mode thread manages,
		// which is what makes a single-machine devnet produce blocks.
		assert!(floor < U512::from(1_000u64));
	});
}

/// A chain that reaches the floor must be able to leave it. Below 2048 the
/// `parent / 2048` increment is zero by integer division, so without the floor
/// on the increment itself a chain at the RandomX difficulty floor would sit
/// there for ever however fast its blocks came.
#[test]
fn a_chain_at_the_floor_can_climb_out_of_it() {
	new_test_ext().execute_with(|| {
		let mut difficulty = QPow::get_min_difficulty();
		for _ in 0..8 {
			let next = QPow::calculate_difficulty(difficulty, 1, 1000);
			assert!(next > difficulty, "{next} must exceed {difficulty}");
			difficulty = next;
		}
		assert_eq!(difficulty, QPow::get_min_difficulty() + U512::from(8u64));
	});
}

/// And the step is one only where the division would round to zero: above
/// 2048 the retarget is exactly what it was before M7.
#[test]
fn the_increment_is_unchanged_above_the_rounding_boundary() {
	let parent = U512::from(4_096_000u64);
	let expected = parent + parent / U512::from(2048u64);
	assert_eq!(QPow::calculate_difficulty(parent, 1, 1000), expected);
}
