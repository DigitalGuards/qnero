use crate::{mock::*, weights::WeightInfo, Event};
use frame_support::traits::Hooks;
use qp_wormhole::derive_wormhole_address;
use sp_runtime::testing::Digest;

/// Block reward `on_finalize` will compute from the current supply: the
/// transparent issuance, the collected fees the pallet treats as
/// already-burned supply, and the value the shielded pool holds.
fn expected_block_reward(tx_fees: Balance) -> Balance {
	let current_supply = Balances::total_issuance()
		.saturating_add(tx_fees)
		.saturating_add(ShieldedSupply::get());
	(MaxSupply::get() - current_supply) / EmissionDivisor::get()
}

fn leaf_quantum() -> Balance {
	pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR
}

fn quantize(amount: Balance) -> (Balance, Balance) {
	let quantum = leaf_quantum();
	let dust = amount % quantum;
	(amount - dust, dust)
}

/// What `on_finalize` actually pays into the block's coinbase note: fees plus
/// emission, floored to the pool quantum.
fn miner_payout(tx_fees: Balance) -> (Balance, Balance) {
	quantize(expected_block_reward(tx_fees) + tx_fees)
}

#[test]
fn the_block_reward_goes_to_the_coinbase_and_not_to_an_account() {
	new_test_ext().execute_with(|| {
		let initial_balance = Balances::free_balance(MINER_1.account_id());
		set_miner_preimage_digest(MINER_1.preimage());

		let (miner_reward, _) = miner_payout(0);

		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::credits(), vec![miner_reward]);
		assert_eq!(
			Balances::free_balance(MINER_1.account_id()),
			initial_balance,
			"v1 mints nothing to a transparent account"
		);
		assert_eq!(Balances::total_issuance(), initial_balance * 2);
		System::assert_has_event(Event::CoinbaseCredited { amount: miner_reward }.into());
	});
}

#[test]
fn transaction_fees_ride_into_the_coinbase_with_the_reward() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());

		let fees: Balance = 25;
		MiningRewards::collect_transaction_fees(fees);
		System::assert_has_event(Event::FeesCollected { amount: 25, total: 25 }.into());

		let (miner_reward, _) = miner_payout(fees);

		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::credits(), vec![miner_reward]);
		System::assert_has_event(Event::CoinbaseCredited { amount: miner_reward }.into());
	});
}

#[test]
fn on_unbalanced_collects_fees() {
	new_test_ext().execute_with(|| {
		MiningRewards::collect_transaction_fees(30);
		assert_eq!(MiningRewards::collected_fees(), 30);

		let (miner_reward, _) = miner_payout(30);
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::total(), miner_reward);
	});
}

#[test]
fn multiple_blocks_accumulate_rewards() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::collect_transaction_fees(10);
		let (block_1_reward, _) = miner_payout(10);
		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::total(), block_1_reward);

		// A credit that reached the pool is supply the next block's emission
		// has to see, and the pool is where it is.
		ShieldedSupply::set(MockCoinbaseSink::total());
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::collect_transaction_fees(15);
		let (block_2_reward, _) = miner_payout(15);
		MiningRewards::on_finalize(2);

		assert_eq!(MockCoinbaseSink::total(), block_1_reward + block_2_reward);
		assert!(block_2_reward < block_1_reward, "supply in the pool still decays the emission");
	});
}

/// Each block's credit is attributed to that block's author, and the value
/// itself goes to whichever payload that author's node supplied.
#[test]
fn each_block_credits_its_own_author() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::collect_transaction_fees(10);
		let (block_1_reward, _) = miner_payout(10);
		MiningRewards::on_finalize(1);

		System::assert_has_event(Event::CoinbaseCredited { amount: block_1_reward }.into());

		let block_1 = System::finalize();
		System::initialize(&2, &block_1.hash(), &Digest { logs: vec![] });
		set_miner_preimage_digest(MINER_2.preimage());
		MiningRewards::collect_transaction_fees(20);
		let (block_2_reward, _) = miner_payout(20);
		MiningRewards::on_finalize(2);

		System::assert_has_event(Event::CoinbaseCredited { amount: block_2_reward }.into());
		assert_eq!(MockCoinbaseSink::credits(), vec![block_1_reward, block_2_reward]);
		assert_eq!(Balances::free_balance(MINER_1.account_id()), ExistentialDeposit::get());
		assert_eq!(Balances::free_balance(MINER_2.account_id()), ExistentialDeposit::get());
	});
}

#[test]
fn transaction_fees_collector_works() {
	new_test_ext().execute_with(|| {
		MiningRewards::collect_transaction_fees(10);
		MiningRewards::collect_transaction_fees(15);
		MiningRewards::collect_transaction_fees(5);
		assert_eq!(MiningRewards::collected_fees(), 30);

		let (miner_reward, _) = miner_payout(30);
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::total(), miner_reward);
	});
}

#[test]
fn on_initialize_returns_correct_weight() {
	new_test_ext().execute_with(|| {
		let weight = MiningRewards::on_initialize(1);
		assert_eq!(weight, <()>::on_finalize_rewarded_miner());
	});
}

#[test]
fn test_run_to_block_helper() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		MiningRewards::collect_transaction_fees(10);
		let initial_supply = Balances::total_issuance();

		run_to_block(3);

		assert_eq!(System::block_number(), 3);
		assert!(MockCoinbaseSink::total() > 0, "the pool should have taken the rewards");
		assert_eq!(
			Balances::total_issuance(),
			initial_supply,
			"transparent issuance does not move any more"
		);
	});
}

#[test]
fn rewards_are_deferred_when_no_miner() {
	new_test_ext().execute_with(|| {
		let issuance_before = Balances::total_issuance();
		let miner_before = Balances::free_balance(MINER_1.account_id());
		let total_reward = expected_block_reward(0);

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(
			Balances::total_issuance(),
			issuance_before,
			"nothing is minted without a miner"
		);
		assert_eq!(Balances::free_balance(MINER_1.account_id()), miner_before);
		assert_eq!(MiningRewards::collected_fees(), total_reward);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward }.into());
	});
}

/// EQ-QNT-MINING-R-02: transaction fees stay with the miner credit when no miner is present.
#[test]
fn fees_are_deferred_when_no_miner() {
	new_test_ext().execute_with(|| {
		let issuance_before = Balances::total_issuance();
		let tx_fees: u128 = 500;
		let total_reward = expected_block_reward(tx_fees);
		MiningRewards::collect_transaction_fees(tx_fees);

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(Balances::total_issuance(), issuance_before);
		assert_eq!(MiningRewards::collected_fees(), total_reward + tx_fees);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward + tx_fees }.into());
	});
}

/// A block whose author supplied no coinbase inherent: the pool refuses the
/// credit, the pallet keeps it, and the next block pays it out. The inherent
/// check refuses such a block on import, so this is the belt under that belt.
#[test]
fn a_refused_coinbase_is_retained_and_recovered() {
	new_test_ext().execute_with(|| {
		let miner = MINER_1.account_id();
		let miner_before = Balances::free_balance(&miner);
		let issuance_before = Balances::total_issuance();

		let tx_fees: Balance = 1_000 * Unit::get();
		MiningRewards::collect_transaction_fees(tx_fees);
		set_miner_preimage_digest(MINER_1.preimage());

		let lost = expected_block_reward(tx_fees) + tx_fees;
		MockCoinbaseSink::set_refusing(true);
		MiningRewards::on_finalize(1);

		assert_eq!(Balances::free_balance(&miner), miner_before);
		assert_eq!(Balances::total_issuance(), issuance_before);
		assert_eq!(MockCoinbaseSink::total(), 0);
		System::assert_has_event(Event::CoinbaseRejected { amount: quantize(lost).0 }.into());
		assert_eq!(
			MiningRewards::collected_fees(),
			lost,
			"quantized credit plus dust must both be retained for retry"
		);

		MockCoinbaseSink::set_refusing(false);
		set_miner_preimage_digest(MINER_1.preimage());
		let (paid, dust) = quantize(lost + expected_block_reward(lost));
		MiningRewards::on_finalize(2);

		assert_eq!(MockCoinbaseSink::total(), paid);
		assert_eq!(MiningRewards::collected_fees(), dust);
	});
}

#[test]
fn unminted_rewards_accumulate_across_consecutive_blocks_without_a_miner() {
	new_test_ext().execute_with(|| {
		MiningRewards::on_finalize(1);
		let retained_after_1 = MiningRewards::collected_fees();
		assert!(retained_after_1 > 0, "a miner-less block must retain its rewards");

		MiningRewards::on_finalize(2);
		let retained_after_2 = MiningRewards::collected_fees();
		assert!(
			retained_after_2 > retained_after_1,
			"a second miner-less block must add its own rewards to the retained pool"
		);

		set_miner_preimage_digest(MINER_1.preimage());
		let (paid, dust) = quantize(retained_after_2 + expected_block_reward(retained_after_2));
		MiningRewards::on_finalize(3);

		assert_eq!(MockCoinbaseSink::total(), paid);
		assert_eq!(MiningRewards::collected_fees(), dust);
	});
}

#[test]
fn retried_rewards_follow_fee_destination_to_next_miner() {
	new_test_ext().execute_with(|| {
		MiningRewards::on_finalize(1);
		let retained = MiningRewards::collected_fees();
		assert!(retained > 0);

		set_miner_preimage_digest(MINER_1.preimage());
		let (paid, dust) = quantize(retained + expected_block_reward(retained));
		MiningRewards::on_finalize(2);

		assert_eq!(MiningRewards::collected_fees(), dust);
		assert_eq!(
			MockCoinbaseSink::total(),
			paid,
			"deferred rewards must reach the next block's coinbase via the fee path"
		);
	});
}

// =========================================================================
// EQ-QNT-WORMHOLE-F-03: Tests for extract_author_from_digest edge cases
// =========================================================================

#[test]
fn incorrect_engine_id_ignored() {
	new_test_ext().execute_with(|| {
		let total_reward = expected_block_reward(0);

		let wrong_engine_id: [u8; 4] = *b"FAKE";
		set_digest_with_engine_id(wrong_engine_id, MINER_1.preimage().to_vec());

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(MiningRewards::collected_fees(), total_reward);
		assert_eq!(
			MockCoinbaseSink::total(),
			0,
			"no coinbase is credited when the engine ID is not the chain's"
		);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward }.into());
	});
}

#[test]
fn malformed_preimage_data_ignored() {
	new_test_ext().execute_with(|| {
		use sp_consensus_qpow::POW_ENGINE_ID;

		let total_reward = expected_block_reward(0);

		let short_data: Vec<u8> = vec![1, 2, 3, 4, 5];
		set_digest_with_engine_id(POW_ENGINE_ID, short_data);

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(MiningRewards::collected_fees(), total_reward);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward }.into());
	});
}

#[test]
fn empty_digest_defers_payout() {
	new_test_ext().execute_with(|| {
		let total_reward = expected_block_reward(0);

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(MiningRewards::collected_fees(), total_reward);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward }.into());
	});
}

#[test]
fn oversized_preimage_data_ignored() {
	new_test_ext().execute_with(|| {
		use sp_consensus_qpow::POW_ENGINE_ID;

		let total_reward = expected_block_reward(0);

		let long_data: Vec<u8> = vec![42u8; 64];
		set_digest_with_engine_id(POW_ENGINE_ID, long_data);

		System::set_block_number(1);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(MiningRewards::collected_fees(), total_reward);
		System::assert_has_event(Event::PayoutDeferred { amount: total_reward }.into());
	});
}

#[test]
fn the_authors_derived_address_is_paid_nothing_and_named_nowhere() {
	new_test_ext().execute_with(|| {
		let test_preimage = [42u8; 32];
		let miner_wormhole_address = sp_core::crypto::AccountId32::from(
			derive_wormhole_address(test_preimage).expect("test preimage limbs are canonical"),
		);

		let tx_fees = 100;
		MiningRewards::collect_transaction_fees(tx_fees);
		let (miner_reward, _) = miner_payout(tx_fees);

		System::set_block_number(1);
		set_miner_preimage_digest(test_preimage);
		MiningRewards::on_finalize(System::block_number());

		assert_eq!(MockCoinbaseSink::credits(), vec![miner_reward]);
		assert_eq!(
			Balances::free_balance(&miner_wormhole_address),
			0,
			"the derived address is paid nothing, and no event names it"
		);
		System::assert_has_event(Event::CoinbaseCredited { amount: miner_reward }.into());
	});
}

#[test]
fn the_coinbase_credit_is_quantized_and_dust_is_held() {
	new_test_ext().execute_with(|| {
		let quantum = leaf_quantum();
		set_miner_preimage_digest(MINER_1.preimage());

		let fees: Balance = 25;
		MiningRewards::collect_transaction_fees(fees);
		let (quantized, dust) = miner_payout(fees);
		assert!(dust > 0, "test setup must produce a sub-quantum remainder");
		assert_eq!(quantized % quantum, 0);

		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::credits(), vec![quantized]);
		assert_eq!(MiningRewards::collected_fees(), dust);
		System::assert_has_event(Event::CoinbaseCredited { amount: quantized }.into());
	});
}

#[test]
fn combined_fee_and_reward_can_recover_a_quantum() {
	new_test_ext().execute_with(|| {
		let quantum = leaf_quantum();
		set_miner_preimage_digest(MINER_1.preimage());

		// Fee remainder is quantum-1, so any non-zero reward remainder crosses a quantum.
		let fees = quantum - 1;
		MiningRewards::collect_transaction_fees(fees);

		let reward = expected_block_reward(fees);
		assert!(!reward.is_multiple_of(quantum), "block reward must not already be aligned");
		let (combined, _dust) = quantize(reward + fees);
		let (reward_only, _) = quantize(reward);
		let (fee_only, _) = quantize(fees);
		assert!(
			combined > reward_only + fee_only,
			"summing before the floor must recover a quantum that two floors would drop"
		);

		MiningRewards::on_finalize(1);
		assert_eq!(MockCoinbaseSink::total(), combined);
	});
}

#[test]
fn sub_quantum_credit_does_not_mint_a_note() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());

		let fees: Balance = 25;
		MiningRewards::collect_transaction_fees(fees);
		let (quantized, dust) = miner_payout(fees);
		assert!(dust > 0 && dust < leaf_quantum());

		MiningRewards::on_finalize(1);

		let credits = MockCoinbaseSink::credits();
		assert_eq!(credits, vec![quantized], "held dust must not reach the pool");
		assert_eq!(credits[0] % leaf_quantum(), 0);
		assert_eq!(MiningRewards::collected_fees(), dust);
	});
}

#[test]
#[ignore] // This test takes a very long time (~13M blocks simulation), run manually with --ignored
fn test_emission_simulation_13m_blocks() {
	new_test_ext().execute_with(|| {
		println!("=== Mining Rewards Emission Simulation ===");
		println!("Max Supply: {:.0} tokens", MaxSupply::get() as f64 / UNIT as f64);
		println!("Emission Divisor: {:?}", EmissionDivisor::get());
		println!();

		/// Block counts at the public 120 s target: a tenth of what they were
		/// at 12 s, so each one covers the same wall clock.
		const TARGET_BLOCK_TIME_SECONDS: f64 = 120.0;
		const MAX_BLOCKS: u64 = 13_000_000;
		const REPORT_INTERVAL: u64 = 100_000;
		const UNIT: u128 = 1_000_000_000_000;
		const FOUR_YEARS_BLOCKS: u64 = 1_051_920;
		const HALF_LIFE_BLOCKS: u64 = 3_465_736;

		let initial_supply = Balances::total_issuance();
		let mut current_supply = initial_supply;
		let mut total_miner_rewards = 0u128;
		let mut block = 0u64;
		let mut four_year_stats: Option<(u128, u128)> = None;
		let mut half_life_stats: Option<(u128, u128)> = None;

		println!("Block       Supply        %MaxSupply  BlockReward   Remaining");
		println!("{}", "-".repeat(70));

		let remaining = MaxSupply::get() - current_supply;
		let block_reward = if remaining > 0 { remaining / EmissionDivisor::get() } else { 0 };
		println!(
			"{:<11} {:<13} {:<11.2}% {:<13.6} {:<13}",
			block,
			current_supply / UNIT,
			(current_supply as f64 / MaxSupply::get() as f64) * 100.0,
			block_reward as f64 / UNIT as f64,
			remaining / UNIT
		);

		set_miner_preimage_digest(MINER_1.preimage());

		loop {
			let remaining_supply = MaxSupply::get().saturating_sub(current_supply);
			let block_reward = remaining_supply / EmissionDivisor::get();
			if block_reward == 0 || block >= MAX_BLOCKS {
				break;
			}

			current_supply += block_reward;
			total_miner_rewards += block_reward;
			block += 1;

			if block == FOUR_YEARS_BLOCKS {
				four_year_stats = Some((current_supply, total_miner_rewards));
			}
			if block == HALF_LIFE_BLOCKS {
				half_life_stats = Some((current_supply, total_miner_rewards));
			}

			if block.is_multiple_of(REPORT_INTERVAL) {
				let remaining = MaxSupply::get().saturating_sub(current_supply);
				let next_block_reward =
					if remaining > 0 { remaining / EmissionDivisor::get() } else { 0 };
				println!(
					"{:<11} {:<13} {:<11.2}% {:<13.6} {:<13}",
					block,
					current_supply / UNIT,
					(current_supply as f64 / MaxSupply::get() as f64) * 100.0,
					next_block_reward as f64 / UNIT as f64,
					remaining / UNIT
				);
			}
		}

		let remaining = MaxSupply::get().saturating_sub(current_supply);
		let next_block_reward = if remaining > 0 { remaining / EmissionDivisor::get() } else { 0 };
		println!(
			"{:<11} {:<13} {:<11.2}% {:<13.6} {:<13} (final)",
			block,
			current_supply / UNIT,
			(current_supply as f64 / MaxSupply::get() as f64) * 100.0,
			next_block_reward as f64 / UNIT as f64,
			remaining / UNIT
		);

		println!("{}", "-".repeat(70));
		println!();
		println!("=== Final Summary ===");
		println!("Total Blocks Processed: {}", block);
		println!("Final Supply: {:.6} tokens", current_supply as f64 / UNIT as f64);
		println!(
			"Percentage of Max Supply: {:.4}%",
			(current_supply as f64 / MaxSupply::get() as f64) * 100.0
		);
		println!(
			"Remaining Supply: {:.6} tokens",
			(MaxSupply::get() - current_supply) as f64 / UNIT as f64
		);
		println!();
		println!("Total Miner Rewards: {:.6} tokens", total_miner_rewards as f64 / UNIT as f64);

		let total_seconds = block as f64 * TARGET_BLOCK_TIME_SECONDS;
		let days = total_seconds / (24.0 * 3600.0);
		let years = days / 365.25;
		println!();
		println!("=== Time Estimates ({TARGET_BLOCK_TIME_SECONDS:.0}s blocks) ===");
		println!("Total Time: {:.1} days ({:.1} years)", days, years);

		let (supply_4y, miner_4y) =
			four_year_stats.expect("simulation must run past the 4-year mark");
		let mineable_supply = MaxSupply::get() - initial_supply;
		let emitted_4y = supply_4y - initial_supply;
		let emitted_pct_4y = (emitted_4y as f64 / mineable_supply as f64) * 100.0;
		let miner_pct_4y = (miner_4y as f64 / mineable_supply as f64) * 100.0;

		println!();
		println!("=== 4-Year Checkpoint (block {}) ===", FOUR_YEARS_BLOCKS);
		println!(
			"Emitted: {:.6} tokens ({:.2}% of mineable supply)",
			emitted_4y as f64 / UNIT as f64,
			emitted_pct_4y
		);
		println!(
			"To Miners: {:.6} tokens ({:.2}% of mineable supply)",
			miner_4y as f64 / UNIT as f64,
			miner_pct_4y
		);

		assert!(
			(18.5..=19.5).contains(&emitted_pct_4y),
			"~19% of mineable supply should be emitted after 4 years, got {:.2}%",
			emitted_pct_4y
		);
		assert!(
			(18.5..=19.5).contains(&miner_pct_4y),
			"~19% of mineable supply should have gone to miners after 4 years, got {:.2}%",
			miner_pct_4y
		);

		let (supply_half, miner_half) =
			half_life_stats.expect("simulation must run past the half-life mark");
		let emitted_half = supply_half - initial_supply;
		let emitted_pct_half = (emitted_half as f64 / mineable_supply as f64) * 100.0;
		let miner_pct_half = (miner_half as f64 / mineable_supply as f64) * 100.0;
		println!();
		println!("=== Half-life Checkpoint (block {}) ===", HALF_LIFE_BLOCKS);
		println!(
			"Emitted: {:.6} tokens ({:.2}% of mineable supply)",
			emitted_half as f64 / UNIT as f64,
			emitted_pct_half
		);
		assert!(
			(49.0..=51.0).contains(&emitted_pct_half),
			"~50% of mineable supply should be emitted at the ~13.2-year half-life, got {:.2}%",
			emitted_pct_half
		);
		assert!(
			(49.0..=51.0).contains(&miner_pct_half),
			"~50% of mineable supply should have gone to miners at half-life, got {:.2}%",
			miner_pct_half
		);

		assert!(current_supply >= initial_supply, "Supply should have increased");
		assert!(current_supply <= MaxSupply::get(), "Supply should not exceed max supply");

		let emitted_tokens = current_supply - initial_supply;
		let emission_percentage =
			(emitted_tokens as f64 / (MaxSupply::get() - initial_supply) as f64) * 100.0;
		assert!(
			emission_percentage > 90.0,
			"Should have emitted >90% of available supply, got {:.2}%",
			emission_percentage
		);

		assert!(total_miner_rewards > 0, "Miners should have received rewards");
		assert_eq!(
			total_miner_rewards, emitted_tokens,
			"Total miner rewards should equal emitted tokens"
		);

		let remaining_percentage =
			((MaxSupply::get() - current_supply) as f64 / MaxSupply::get() as f64) * 100.0;
		assert!(
			remaining_percentage < 10.0,
			"Should have <10% supply remaining, got {:.2}%",
			remaining_percentage
		);
		assert!(
			remaining_percentage > 0.0,
			"Should still have some supply remaining for future emission"
		);

		println!();
		println!("✅ All emission validation checks passed!");
		println!("✅ Emission simulation completed successfully!");
	});
}

// =========================================================================
// What reaches the shielded pool
// =========================================================================

/// One credit per block, and it is the whole of what the block emits.
#[test]
fn a_block_pays_one_coinbase_credit() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		assert_eq!(MockCoinbaseSink::credits().len(), 0);

		MiningRewards::on_finalize(1);

		let credits = MockCoinbaseSink::credits();
		assert_eq!(credits.len(), 1, "one combined credit, no split");
		assert!(credits[0] > 0);
	});
}

/// Fees and the block reward are one credit, which is what lets a block recover
/// a quantum two separate floors would drop, and what leaves the author holding
/// one note instead of two.
#[test]
fn fees_and_the_block_reward_are_one_credit() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());

		let fees: Balance = 100;
		MiningRewards::collect_transaction_fees(fees);
		let (expected, _) = miner_payout(fees);

		MiningRewards::on_finalize(1);

		assert_eq!(MockCoinbaseSink::credits(), vec![expected]);
	});
}

/// A block with no author pays nothing into the pool and keeps the credit.
#[test]
fn no_author_defers_the_payout_without_minting_a_note() {
	new_test_ext().execute_with(|| {
		let gross = expected_block_reward(0);

		MiningRewards::on_finalize(1);

		assert!(MockCoinbaseSink::credits().is_empty(), "a deferred payout mints no note");
		assert_eq!(MiningRewards::collected_fees(), gross);
		System::assert_has_event(Event::PayoutDeferred { amount: gross }.into());
	});
}

/// Value in the shielded pool is supply. Without that term the emission would
/// see supply fall as the pool filled and mint faster forever, which is the one
/// thing v1 could have broken about the schedule.
#[test]
fn the_emission_measures_the_shielded_pool_as_supply() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		let empty_pool = expected_block_reward(0);

		ShieldedSupply::set(MaxSupply::get() / 2);
		let half_supply_in_the_pool = expected_block_reward(0);

		assert!(
			half_supply_in_the_pool < empty_pool / 2 + 1,
			"a pool holding half the supply must halve the emission"
		);

		MiningRewards::on_finalize(1);
		assert_eq!(MockCoinbaseSink::credits(), vec![quantize(half_supply_in_the_pool).0]);
	});
}

/// A block with nothing of its own to mint still gives the pool its turn.
///
/// The pool holds the author's share of every fee the block's settlements
/// paid, and a mint is the only thing that drains it. Once the emission rounds
/// to zero, which is where `MaxSupply` sends this chain, a block whose only
/// traffic is settlements has no reward and no collected fees, because a
/// settlement is `Pays::No`. If this pallet returned early on a zero credit,
/// that block would never mint, the author's share would sit in the pool
/// counted as supply and backed by no note, and the next block would repeat
/// it. So the sink is called either way, and it decides.
#[test]
fn a_block_with_no_emission_still_reaches_the_pool() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest(MINER_1.preimage());
		// Every planck is already supply, so the emission is zero. The pallet
		// subtracts saturating; the helper above does not, which is why the
		// measure is taken here rather than read off it.
		ShieldedSupply::set(MaxSupply::get());
		assert_eq!(
			MaxSupply::get()
				.saturating_sub(Balances::total_issuance().saturating_add(ShieldedSupply::get())),
			0,
			"no supply left to emit"
		);
		assert_eq!(MiningRewards::collected_fees(), 0);

		MiningRewards::on_finalize(1);

		assert_eq!(
			MockCoinbaseSink::credits(),
			vec![0],
			"the pool is asked even when this pallet has nothing to add, because \
			 what it owes the author may already be inside it"
		);
	});
}

/// The author seam decides whether a block pays at all, and nothing else.
///
/// The digest is read through `Config::FindAuthor`, so the engine swap keeps
/// this pallet untouched. What the seam answers is a yes or a no: with an
/// author the credit goes to the pool, without one it waits for the next
/// block. The account it derives is never published, because an account beside
/// every block's credit is a mining identity attached to every coinbase note.
#[test]
fn the_author_seam_decides_whether_the_block_pays() {
	new_test_ext().execute_with(|| {
		set_miner_preimage_digest([42u8; 32]);
		MiningRewards::on_finalize(1);

		let amount = MockCoinbaseSink::total();
		assert!(amount > 0);
		System::assert_has_event(Event::CoinbaseCredited { amount }.into());
		assert!(
			!System::events().iter().any(|record| matches!(
				record.event,
				RuntimeEvent::MiningRewards(Event::PayoutDeferred { .. })
			)),
			"a block with an author pays"
		);
	});

	// The same block without the digest item pays nobody and holds the credit.
	new_test_ext().execute_with(|| {
		MiningRewards::on_finalize(1);
		assert_eq!(MockCoinbaseSink::total(), 0);
		assert!(
			System::events().iter().any(|record| matches!(
				record.event,
				RuntimeEvent::MiningRewards(Event::PayoutDeferred { .. })
			)),
			"a block with no author holds its credit for the next one"
		);
	});
}
