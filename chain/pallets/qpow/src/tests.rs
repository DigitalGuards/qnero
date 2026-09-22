use crate::{
	mock::*, retarget_divisor, Config, CurrentDifficulty, MAX_RETARGET_DECREASE_UNITS,
	RETARGET_INCREMENT_DIVISOR,
};
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

		// The floor is 500 ms and the divisor is `target * ln 2`, so the two are
		// equal at a 722 ms target (500 / ln 2 = 721.3 ms) and the floor is the
		// wider of the pair below that. At the 600 ms target here the divisor is
		// 415 ms, so a sub-floor delta is clamped to 500 ms, still lands in the
		// first bucket and yields no increase.
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
/// The cycle is three gaps: a wait at the target inflated by the full 15 s of
/// legal drift, the `last + 100 ms` block the inherent is then forced to
/// produce, and the compressed follow-up that brings the claimed clock back to
/// the honest wall clock. Three honest gaps at the target book nothing, so the
/// condition for the cycle to book nothing either is
///
///     floor((T + drift) / d) + floor((2T - drift - 100) / d) <= 3
///
/// with `d = retarget_divisor(T)`. At the public target that is `1 + 2 = 3` and
/// the cycle books exactly zero, the same as the old `target * 10 / 12`
/// divisor did.
///
/// **Safety is not monotone in the target**, so the invariant is asserted at
/// the public target alone. Both floors above land on 2 for every target from
/// about 24.5 s to about 38.8 s, and the 12 s `dev` target books one unit of
/// deficit for the same reason: 15 s is 1.8 divisors there, where the whole
/// concentration budget is one. That arm is pinned below as a documented
/// exception. A dev chain is a test harness with no adversarial miners, and it
/// cleared the old rule by coincidence rather than by margin, its third gap of
/// 8.9 s happening to fall under the old 10 s divisor.
#[test]
fn max_timestamp_drift_does_not_bias_difficulty_down() {
	new_test_ext().execute_with(|| {
		// At a parent of exactly one increment divisor the step the retarget
		// takes *is* the adjustment in units, so the comparison below is free
		// of the increment's own integer rounding.
		let units = |target: u64, gap: u64| -> i64 {
			let parent = U512::from(RETARGET_INCREMENT_DIVISOR);
			let next = QPow::calculate_difficulty(parent, gap, target);
			if next >= parent {
				(next - parent).low_u64() as i64
			} else {
				-((parent - next).low_u64() as i64)
			}
		};
		let cycle =
			|target: u64, gaps: &[u64]| -> i64 { gaps.iter().map(|&gap| units(target, gap)).sum() };

		// Public target: a 120 s wait inflated by the full 15 s, the forced
		// 100 ms block, then the catch-up. 135_000 + 100 + 224_900 is 360_000,
		// the same wall clock as three honest 120 s blocks.
		assert_eq!(
			cycle(PUBLIC_TARGET, &[120_000, 120_000, 120_000]),
			0,
			"honest 120s blocks leave difficulty unchanged"
		);
		assert_eq!(
			cycle(PUBLIC_TARGET, &[135_000, 100, 224_900]),
			0,
			"the max-drift cycle must not book a deficit at the public target"
		);

		// The dev chain is the documented exception, pinned so a future target
		// change cannot cross the band unnoticed. 27_000 + 100 + 8_900 is
		// 36_000, three honest 12 s blocks.
		assert_eq!(
			cycle(DEV_TARGET, &[12_000, 12_000, 12_000]),
			0,
			"honest 12s blocks leave difficulty unchanged"
		);
		assert_eq!(
			cycle(DEV_TARGET, &[27_000, 100, 8_900]),
			-1,
			"the dev target books one unit per max-drift cycle: 15s is 1.8 divisors there"
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
/// The Homestead band is one divisor wide, so at a 120 s target (an 83.177 s
/// divisor) it is 83.2 s to 166.4 s and it is dead in both directions. A chain
/// climbing into it stops at the bottom, at 83 s blocks; a chain falling into
/// it stops at the top, at 166 s blocks, and stays there. The target sits
/// inside the band at 1.4427 divisors, which is where the stationary mean is.
/// `chain/MINING.md` says the same thing to an operator.
///
/// The climb's cost is worth stating in both units, because one of them is not
/// ten times the 12 s figure. At 120 s it is 13 250 blocks and 2.00 days; at
/// 12 s it is 8 466 blocks and 5.096 hours. The block count grows by half
/// because the settle difficulty is ten times higher and every step is a fixed
/// 1/2048 fraction. The wall clock grows by ten for the same reason, the
/// difficulty: the whole climb runs far below the target, so multiplying the
/// block count by 120 s would overstate it by a factor of eight.
#[test]
fn a_chain_at_the_floor_converges_to_the_target_band() {
	new_test_ext().execute_with(|| {
		/// A small testnet rig: about two modern cores in full mode.
		const HASH_RATE: u64 = 3_500;
		/// Measured: 13_250 blocks and 48.1 hours of wall clock.
		const MAX_BLOCKS: u32 = 14_000;
		let band = retarget_divisor(PUBLIC_TARGET)..2 * retarget_divisor(PUBLIC_TARGET);

		// Measured on the first run under the new divisor: 13 250 blocks,
		// difficulty 291 239, block time 83 211 ms, 48.112 hours. The same
		// replay reproduces the old rule's committed 13 628 and 57.7 hours
		// exactly, so these are measurements rather than estimates.
		let (blocks, difficulty, block_time_ms, wall_clock_ms) =
			settle(QPow::get_min_difficulty(), HASH_RATE, PUBLIC_TARGET, MAX_BLOCKS);

		assert!(
			(13_000..MAX_BLOCKS).contains(&blocks),
			"climb from the floor took {blocks} blocks, expected about 13_250"
		);
		// 48.1 hours, so the integer day count is 2 with about seven minutes to
		// spare out of forty-eight hours, a margin of 0.2%. Any later move to
		// the seed hash rate, the difficulty floor or the ln 2 precision can
		// flip this to 1, so read a failure here as a changed input rather than
		// as a broken retarget.
		let days = wall_clock_ms / (24 * 60 * 60 * 1_000);
		assert_eq!(days, 2, "the climb covers about 2.00 days: it runs far below the target");
		assert!(
			band.contains(&block_time_ms),
			"settled block time {block_time_ms}ms is outside the retarget's neutral band"
		);
		// The band's lower edge is `hash_rate * divisor`, and the climb stops on
		// the first step that lands inside it.
		assert!(difficulty >= U512::from(HASH_RATE * retarget_divisor(PUBLIC_TARGET) / 1_000));

		// The same climb at the `dev` preset's target, for the comparison the
		// docs quote: fewer blocks, because the settle difficulty is ten times
		// lower and each step is the same fraction of it.
		let (dev_blocks, _, dev_block_time_ms, _) =
			settle(QPow::get_min_difficulty(), HASH_RATE, DEV_TARGET, MAX_BLOCKS);
		assert!(
			(8_100..8_900).contains(&dev_blocks),
			"the 12 s climb took {dev_blocks} blocks, expected about 8_466"
		);
		assert!((retarget_divisor(DEV_TARGET)..2 * retarget_divisor(DEV_TARGET))
			.contains(&dev_block_time_ms));
		assert!(dev_blocks < blocks, "a ten times higher settle difficulty costs more steps");

		// Now take nine tenths of the hash rate away. The chain falls through
		// the band from above and stops at its top edge, so a network that lost
		// its miners holds 166 s blocks for good, with no drift back toward 120.
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
		// Measured: 1 558 steps settling at 166 305 ms, which is 1.386 times
		// the target. Both endpoints scale with the divisor, so the ratio of
		// 5.0 and the step count are what they were under the old rule.
		assert!(
			(1_000..2_000).contains(&steps),
			"the fall took {steps} blocks, expected about 1_558"
		);
		assert!(band.contains(&fell_to), "settled at {fell_to}ms, outside the band");
		assert!(
			fell_to > PUBLIC_TARGET,
			"a chain falling into the band settles at its top edge, about 166 s"
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

/// The divisor is the one constant that decides where the chain settles, so it
/// is pinned by value at every target the tree uses. `target * ln 2` in
/// millionths, floored at one so a sub-millisecond target cannot divide by
/// zero.
#[test]
fn the_divisor_is_the_target_times_ln_two() {
	assert_eq!(retarget_divisor(PUBLIC_TARGET), 83_177);
	assert_eq!(retarget_divisor(DEV_TARGET), 8_317);
	assert_eq!(retarget_divisor(1_000), 693);
	assert_eq!(retarget_divisor(600), 415);
	assert_eq!(retarget_divisor(1), 1, "the floor keeps the divisor non-zero");

	let mut previous = 0u64;
	for target_ms in (0..600_000).step_by(97) {
		let divisor = retarget_divisor(target_ms);
		assert!(divisor >= previous, "the divisor fell from {previous} at target {target_ms}ms");
		previous = divisor;
	}
}

/// The structural property that makes the rule sane at any target: the neutral
/// band is `[divisor, 2 * divisor)`, the stationary mean is `1 / ln 2 = 1.4427`
/// divisors, and 1.4427 lies inside `[1, 2)`. So a chain that has settled on
/// the interval it declares feels no retarget pressure there, and that stays
/// true whatever the target is rather than being a coincidence of 120 s.
#[test]
fn the_target_sits_inside_the_neutral_band() {
	for target_ms in (600..600_000).step_by(89) {
		let divisor = retarget_divisor(target_ms);
		assert!(divisor <= target_ms, "target {target_ms}ms is below its own band");
		assert!(2 * divisor > target_ms, "target {target_ms}ms is above its own band");
	}
}

/// SplitMix64, pinned so the simulations below are the same run every time.
///
/// `f64` lives here and nowhere else: the retarget itself is integer, and this
/// is a `#[cfg(test)]` sampler feeding it.
struct Rng(u64);

impl Rng {
	fn next_u64(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
		z ^ (z >> 31)
	}

	/// Uniform on `(0, 1]`, never zero so the logarithm below is finite.
	fn uniform(&mut self) -> f64 {
		((self.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64
	}

	/// An exponential draw, which is the inter-arrival time of a Poisson
	/// process and therefore what a constant hash rate produces.
	fn exponential_ms(&mut self, mean_ms: f64) -> u64 {
		(-mean_ms * self.uniform().ln()) as u64
	}
}

/// The seed every simulation below starts from.
const POISSON_SEED: u64 = 0x5165_726F_5F31_3230;

/// Drive the real `calculate_difficulty` with Poisson block times at a constant
/// hash rate and report the mean block time over the measured tail.
///
/// Difficulty is expected hashes per block, so the mean inter-arrival time is
/// `difficulty / hash_rate` and the sampler draws around it.
fn poisson_run(
	hash_rate: u64,
	start: U512,
	target_ms: u64,
	measured_blocks: u32,
	warmup_blocks: u32,
) -> (f64, U512) {
	let mut rng = Rng(POISSON_SEED);
	let mut difficulty = start;
	let mut measured_total_ms = 0u128;
	for block in 0..(warmup_blocks + measured_blocks) {
		let mean_ms = difficulty.low_u64() as f64 * 1_000.0 / hash_rate as f64;
		let block_time_ms = rng.exponential_ms(mean_ms);
		if block >= warmup_blocks {
			measured_total_ms += block_time_ms as u128;
		}
		difficulty = QPow::calculate_difficulty(difficulty, block_time_ms, target_ms);
	}
	(measured_total_ms as f64 / measured_blocks as f64, difficulty)
}

/// A small testnet rig, for the simulations.
const SIM_HASH_RATE: u64 = 3_500;
/// Blocks discarded before measuring, about three autocorrelation times of the
/// difficulty's own wander at a 1/2048 unit.
const SIM_WARMUP_BLOCKS: u32 = 5_000;
/// Blocks measured. The sample mean's relative standard deviation here is
/// about 0.9%, so the 3% band below is better than three sigma.
const SIM_MEASURED_BLOCKS: u32 = 20_000;

/// The whole point of the divisor: a chain at a constant hash rate averages the
/// interval it declares.
///
/// Under the old `target * 10 / 12` divisor this simulation produced 144 s at a
/// 120 s target, which is what the public testnet measured for its whole life.
///
/// Measured on the first run, with the analytic `divisor / ln 2` beside it:
/// 119 907 ms against 119 999 at the public target (-0.08%), and 11 988 ms
/// against 11 999 at the dev target (-0.10%). Both gaps are inside the sample
/// mean's own 0.9% standard deviation, so the band below is a tolerance rather
/// than a pinned value: the sampler is `f64`, and a last-ulp difference across
/// platforms can move a bucket boundary.
#[test]
fn a_poisson_chain_at_constant_hashrate_averages_the_target() {
	new_test_ext().execute_with(|| {
		for target_ms in [PUBLIC_TARGET, DEV_TARGET] {
			// The equilibrium difficulty is `hash_rate * target_seconds`.
			let start = U512::from(SIM_HASH_RATE * target_ms / 1_000);
			let (mean_ms, _) = poisson_run(
				SIM_HASH_RATE,
				start,
				target_ms,
				SIM_MEASURED_BLOCKS,
				SIM_WARMUP_BLOCKS,
			);
			let error = (mean_ms - target_ms as f64).abs() / target_ms as f64;
			assert!(
				error < 0.03,
				"mean block time {mean_ms:.0}ms is {:.2}% off a {target_ms}ms target",
				error * 100.0
			);
		}
	});
}

/// The tripwire that makes the change falsifiable.
///
/// A 144 270 ms target has a new-rule divisor of 100 000 ms, which is exactly
/// what `target * 10 / 12` gave at a 120 s target. So this arm reproduces the
/// live testnet's measured 137 to 150 s from the old constant, and it fails if
/// anyone restores the old ratio: under `10 / 12` the same run would settle at
/// about 173 s instead.
///
/// Measured on the first run: 144 160 ms against the analytic 144 269 (-0.08%).
#[test]
fn the_old_divisor_explains_the_measured_144_s() {
	new_test_ext().execute_with(|| {
		const OLD_RULE_TARGET: u64 = 144_270;
		assert_eq!(retarget_divisor(OLD_RULE_TARGET), 100_000, "this is the old 120 s divisor");

		let start = U512::from(SIM_HASH_RATE * OLD_RULE_TARGET / 1_000);
		let (mean_ms, _) = poisson_run(
			SIM_HASH_RATE,
			start,
			OLD_RULE_TARGET,
			SIM_MEASURED_BLOCKS,
			SIM_WARMUP_BLOCKS,
		);
		let error = (mean_ms - OLD_RULE_TARGET as f64).abs() / OLD_RULE_TARGET as f64;
		assert!(
			error < 0.03,
			"mean block time {mean_ms:.0}ms is {:.2}% off the old rule's 144 270ms",
			error * 100.0
		);
	});
}

/// The two caps, by name and by the claimed gap each one needs.
///
/// The asymmetry is the decision: one unit up per block against ninety-nine
/// down, which is why a difficulty overshoot decays in hours where a hash rate
/// arrival is absorbed over days.
#[test]
fn the_maximum_per_block_moves_are_the_named_units() {
	let parent = U512::from(4_096_000u64);
	let unit = parent / U512::from(RETARGET_INCREMENT_DIVISOR);
	let divisor = retarget_divisor(PUBLIC_TARGET);

	assert_eq!(
		QPow::calculate_difficulty(parent, 1, PUBLIC_TARGET),
		parent + unit,
		"the fastest possible block adds exactly one unit"
	);

	// The full decrease needs a claimed gap of exactly 100 divisors: at one
	// millisecond less the retarget is still a unit short of the clamp.
	let full_decrease_gap = 100 * divisor;
	assert_eq!(
		QPow::calculate_difficulty(parent, full_decrease_gap, PUBLIC_TARGET),
		parent - unit * U512::from(MAX_RETARGET_DECREASE_UNITS as u64),
		"100 divisors of claimed gap reaches the clamp"
	);
	assert_eq!(
		QPow::calculate_difficulty(parent, full_decrease_gap - 1, PUBLIC_TARGET),
		parent - unit * U512::from(98u64),
		"one millisecond short of 100 divisors is one unit short of the clamp"
	);
	assert_eq!(
		QPow::calculate_difficulty(parent, full_decrease_gap * 10, PUBLIC_TARGET),
		parent - unit * U512::from(MAX_RETARGET_DECREASE_UNITS as u64),
		"the clamp holds however long the claimed gap is"
	);
	assert_eq!(full_decrease_gap, 8_317_700, "8 317.7 s at the public target");
}

/// `chain/client/consensus/randomx/src/admission.rs` admits a side-branch block
/// for free while its difficulty is within an eighth of the tip's, on the
/// ground that an eighth takes about 42 consecutive maximum decreases and each
/// of those needs a claimed gap of 100 divisors. Both halves of that sentence
/// are arithmetic in this pallet's constants, so the count is asserted here,
/// where the constants live, rather than behind a dependency edge from the
/// client crate to a runtime pallet.
///
/// The free line itself does not move with the divisor: what it prices is the
/// equilibrium difficulty ratio `p / (1 - p)` a partition holding a fraction
/// `p` of the hash settles at, and neither the divisor nor the unit touches
/// that ratio. Only the wall clock to arrive there moves.
#[test]
fn the_free_line_is_reached_in_the_documented_number_of_max_decrease_steps() {
	new_test_ext().execute_with(|| {
		/// `admission::SIDE_BRANCH_DIFFICULTY_FRACTION`.
		const FRACTION: u64 = 8;
		let tip = U512::from(4_096_000u64);
		let divisor = retarget_divisor(PUBLIC_TARGET);
		let full_decrease_gap = 100 * divisor;

		let mut branch = tip;
		let mut steps = 0u32;
		// `admission::is_difficulty_admissible`: free while `branch * 8 >= tip`.
		while branch * U512::from(FRACTION) >= tip {
			branch = QPow::calculate_difficulty(branch, full_decrease_gap, PUBLIC_TARGET);
			steps += 1;
			assert!(steps < 1_000, "the fall to the free line must terminate");
		}
		// 43 measured here against a continuous estimate of 42.0
		// (`0.95166^42 = 0.1248`). The extra step is the integer floor on
		// `parent / 2048`, which makes every decrease a shade smaller than the
		// fraction; at a tip of 10^9 the same walk takes the estimated 42. That
		// is the difficulty-dependence `admission.rs` names.
		assert_eq!(steps, 43, "43 maximum decreases take a 4 096 000 tip past an eighth");

		// And the claimed wall clock those steps need, which is the number the
		// module comment quotes to an operator.
		let claimed_ms = steps as u64 * full_decrease_gap;
		let claimed_days = claimed_ms as f64 / (24.0 * 60.0 * 60.0 * 1_000.0);
		assert!(
			(4.0..4.3).contains(&claimed_days),
			"the fall claims {claimed_days:.2} days, expected about 4.1"
		);
	});
}
