// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// this module is used by the client, so it's ok to panic/unwrap here
#![allow(clippy::expect_used, clippy::panic)]

pub(crate) mod mainnet_vesting;

use crate::{
	AccountId, BalancesConfig, RuntimeGenesisConfig, EXISTENTIAL_DEPOSIT, MILLIS_PER_DAY,
	TARGET_BLOCK_TIME_MS, UNIT,
};
use alloc::{vec, vec::Vec};
use pallet_multisig::Pallet as Multisig;
use qp_dilithium_crypto::pair::{crystal_alice, crystal_charlie, dilithium_bob};
// Key derivation from a raw seed is a test concern now: the two accounts a
// preset derived that way padded the tech collective, and both went with it.
#[cfg(test)]
use qp_dilithium_crypto::Dilithium87Pair;
use serde_json::Value;
#[cfg(test)]
use sp_core::Pair;
use sp_core::{crypto::Ss58Codec, U512};
use sp_genesis_builder::{self, PresetId};
use sp_runtime::traits::IdentifyAccount;

// The dev preset used to endow a keyless wormhole test address so a developer
// could exercise the ZK spend path against it. v1 removed `pallet-wormhole`
// and with it every way an account that cannot sign reaches its balance, so
// the endowment became 100_000 UNIT of genesis supply nobody can shield,
// burn or spend, counted against `MaxSupply` forever. The secret and the
// address went with it.

/// Milliseconds since the unix epoch, the time basis of vesting schedules.
type VestingMoment = u64;

/// One vesting genesis entry: `(beneficiary, start_ms, cliff_ms, end_ms, total)`.
type VestingScheduleTuple = (AccountId, VestingMoment, VestingMoment, VestingMoment, u128);

const fn days_ms(days: u64) -> VestingMoment {
	days * MILLIS_PER_DAY
}

/// Midnight UTC of a Gregorian date (year >= 1970) as milliseconds since the Unix
/// epoch, so every vesting epoch below is written as the date it documents and
/// cannot drift from it. Days-from-civil, per Howard Hinnant's `chrono` algorithm.
const fn utc_midnight_ms(year: u64, month: u64, day: u64) -> VestingMoment {
	let y = if month <= 2 { year - 1 } else { year };
	let era = y / 400;
	let yoe = y - era * 400;
	let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	(era * 146_097 + doe - 719_468) * MILLIS_PER_DAY
}

/// Genesis vesting starts at this wall-clock time: **2026-08-05 00:00:00 UTC**.
/// Re-derive this (midnight UTC of the intended start date) before any real launch.
const GENESIS_VESTING_START_MS: VestingMoment = utc_midnight_ms(2026, 8, 5);
/// Testnet example cliff: 90 days after start.
const GENESIS_VESTING_CLIFF_MS: VestingMoment = GENESIS_VESTING_START_MS + days_ms(90);
/// Testnet example vesting end: 1 year after start.
const GENESIS_VESTING_END_MS: VestingMoment = GENESIS_VESTING_START_MS + days_ms(365);
/// Testnet example grant size.
const GENESIS_VESTING_TOTAL: u128 = 10_000 * UNIT;

/// Identifier for the heisenberg runtime preset.
///
/// Heisenberg is the internal integration testnet. Its genesis deliberately
/// reuses `dilithium_default_accounts` (well-known public keys) — see that
/// helper for why that is acceptable here and must not be copied onto a
/// mainnet / value-bearing chain.
pub const HEISENBERG_RUNTIME_PRESET: &str = "heisenberg";

/// Identifier for the planck runtime preset.
pub const PLANCK_RUNTIME_PRESET: &str = "planck";

/// Identifier for the mainnet runtime preset.
///
/// Genesis requires finalized allocations and a qualified proof-system profile.
/// The allocation table lives in `mainnet_vesting` so it can be audited
/// without the rest of the preset machinery.
pub const MAINNET_RUNTIME_PRESET: &str = "mainnet";

/// Mainnet requires an independently assessed proof-system composition. The
/// protocol profile remains experimental until that review and any resulting
/// circuit migration have been completed. See `docs/CRYPTOGRAPHY.md`.
fn mainnet_security_qualified() -> bool {
	!pallet_shielded::EXPERIMENTAL_PROOF_SYSTEM
}

/// Identifier for the Qnero public testnet preset.
///
/// The first Qnero chain with a genesis of its own. Its whole allocation is
/// one endowed account, the faucet, and nothing else: no vesting table, no
/// treasury and no placeholder. See
/// [`qnero_testnet_config_genesis`] for what each of those absences costs and
/// why the cost is the right one on a testnet.
pub const QNERO_TESTNET_RUNTIME_PRESET: &str = "qnero-testnet";

/// SS58 address format used by all Quantus chains.
fn ss58_version() -> sp_core::crypto::Ss58AddressFormat {
	sp_core::crypto::Ss58AddressFormat::custom(189)
}

/// Well-known Dilithium accounts used by the `dev` and `heisenberg` presets
/// (`crystal_alice` / `dilithium_bob` / `crystal_charlie`, derived from the
/// public seeds `[0u8; 32]` / `[1u8; 32]` / `[2u8; 32]`).
///
/// These keys are intentionally public. That is fine for local development
/// (`dev`) and for Heisenberg, which is an **integration testnet** with no
/// monetary value, where CI and integrators need reproducible endowed accounts
/// and treasury signers without secret distribution. It would **not** be
/// acceptable for a mainnet or any chain whose tokens have real-world value:
/// those must use unique, privately held keys (as Planck does for its live
/// treasury signers).
fn dilithium_default_accounts() -> Vec<AccountId> {
	vec![
		crystal_alice().into_account(),
		dilithium_bob().into_account(),
		crystal_charlie().into_account(),
	]
}

/// Treasury as 2-of-3 multisig from Alice, Bob, Charlie (`dilithium_default_accounts`), nonce 0.
fn development_treasury_account() -> AccountId {
	let signers = dilithium_default_accounts();
	Multisig::<crate::Runtime>::derive_multisig_address(&signers, 2, 0)
}

/// Multisig nonce for Heisenberg treasury: same three well-known signers as
/// `dev` (acceptable because Heisenberg is an integration testnet — see
/// `dilithium_default_accounts`), different on-chain address from development
/// (different nonce) so presets are distinguishable.
const HEISENBERG_TREASURY_MULTISIG_NONCE: u64 = 1;

fn heisenberg_treasury_signers() -> Vec<AccountId> {
	dilithium_default_accounts()
}

/// Treasury as 2-of-3 multisig (Alice, Bob, Charlie) with nonce
/// [`HEISENBERG_TREASURY_MULTISIG_NONCE`].
fn heisenberg_treasury_account() -> AccountId {
	Multisig::<crate::Runtime>::derive_multisig_address(
		&heisenberg_treasury_signers(),
		2,
		HEISENBERG_TREASURY_MULTISIG_NONCE,
	)
}

/// Treasury genesis params per profile. The account is configured here; any
/// balance comes from the ordinary genesis endowment list, and never from
/// mining.
///
/// `None` is a chain with no treasury, which is a state the runtime already
/// supports rather than one this widening invented:
/// `pallet_treasury`'s genesis build returns early on `None`
/// (`pallets/treasury/src/lib.rs`), `TreasuryAccountOption` answers `None`
/// (`runtime/src/configs/mod.rs`), and the only reader left is
/// `pallet_vesting`'s end-of-schedule remainder, which no origin can reach.
/// Nothing in the runtime calls the panicking `Pallet::account_id()`. The
/// alternative was to point the field at some account the preset already names,
/// which on a chain with no treasury means writing a treasury address into
/// genesis that means nothing.
#[derive(Clone)]
struct TreasuryGenesis {
	account: Option<AccountId>,
}

/// Returns the genesis config populated with given parameters. Treasury is per-profile.
///
/// Every genesis balance is transparent and stays that way until its holder
/// shields it. v1 removed `pallet-wormhole`, so nothing derives a spendable
/// leaf from a genesis balance any more and an account that cannot sign cannot
/// reach the pool. That is why an endowment goes to an account with a key, and
/// why the vesting pot holds only what its schedules pay out:
/// `every_genesis_planck_is_reachable_under_the_call_filter` is the test.
fn genesis_template(
	endowed_accounts: Vec<AccountId>,
	treasury: TreasuryGenesis,
	extra_balances: Vec<(AccountId, u128)>,
	vesting_schedules: Vec<VestingScheduleTuple>,
	anchor_vesting_to_first_timestamp: bool,
	consensus: ConsensusGenesis,
) -> Value {
	const ENDOWED_BALANCE_UNITS: u128 = 100_000;
	let mut balances = endowed_accounts
		.iter()
		.cloned()
		.map(|k| (k, ENDOWED_BALANCE_UNITS.saturating_mul(UNIT)))
		.collect::<Vec<_>>();
	balances.extend(extra_balances);

	// The pot must hold exactly the sum of all schedule totals plus its existential-
	// deposit buffer (asserted by the vesting pallet's genesis build). It is endowed
	// with at least the ED even when no schedules exist, so a later milestone can
	// create schedules. The pot cannot sign, so `Vesting::claim` is the only way its
	// balance moves, which is why v1's call filter leaves that one call dispatchable.
	// The ED itself never moves: it is the pot's own floor, one MILLI_UNIT.
	let mut vesting_total: u128 = 0;
	for (_, _, _, _, total) in &vesting_schedules {
		vesting_total = vesting_total
			.checked_add(*total)
			.expect("vesting genesis allocation overflows u128");
	}
	let pot_account = pallet_vesting::Pallet::<crate::Runtime>::pot_account_id();
	balances.push((
		pot_account,
		vesting_total
			.checked_add(EXISTENTIAL_DEPOSIT)
			.expect("vesting pot endowment overflows u128"),
	));

	let config = RuntimeGenesisConfig {
		balances: BalancesConfig { balances, dev_accounts: None },
		q_po_w: pallet_qpow::GenesisConfig {
			initial_difficulty: consensus
				.initial_difficulty
				.unwrap_or_else(pallet_qpow::Pallet::<crate::Runtime>::initial_difficulty),
			target_block_time: consensus.target_block_time.unwrap_or(TARGET_BLOCK_TIME_MS),
			..Default::default()
		},
		treasury_pallet: pallet_treasury::GenesisConfig::<crate::Runtime> {
			treasury_account: treasury.account,
		},
		vesting: pallet_vesting::GenesisConfig::<crate::Runtime> {
			schedules: vesting_schedules
				.try_into()
				.expect("genesis vesting table exceeds pallet_vesting::MAX_GENESIS_SCHEDULES"),
			anchor_to_first_timestamp: anchor_vesting_to_first_timestamp,
		},
		..Default::default()
	};

	// Every field here is a `RuntimeGenesisConfig` field. The builder used to add
	// one that was not, `tech_collective_seed_members`, which the runtime API had
	// to strip before deserializing; there is no collective to seed any more, and
	// `#[serde(deny_unknown_fields)]` now refuses a spec that still carries it.
	serde_json::to_value(config).expect("Could not build genesis config.")
}

/// Testnet vesting table for `dev` and `heisenberg`: Bob holds two schedules
/// (exercises multi-schedule-per-account), Charlie one.
fn testnet_vesting_schedules() -> Vec<VestingScheduleTuple> {
	let accounts = dilithium_default_accounts();
	vec![
		(
			accounts[1].clone(),
			GENESIS_VESTING_START_MS,
			GENESIS_VESTING_CLIFF_MS,
			GENESIS_VESTING_END_MS,
			GENESIS_VESTING_TOTAL,
		),
		(
			accounts[1].clone(),
			GENESIS_VESTING_START_MS,
			GENESIS_VESTING_CLIFF_MS,
			GENESIS_VESTING_END_MS,
			GENESIS_VESTING_TOTAL,
		),
		(
			accounts[2].clone(),
			GENESIS_VESTING_START_MS,
			GENESIS_VESTING_CLIFF_MS,
			GENESIS_VESTING_END_MS,
			GENESIS_VESTING_TOTAL,
		),
	]
}

fn log_vesting_schedules(preset: &str, schedules: &[VestingScheduleTuple]) {
	let ss58 = ss58_version();
	let pot = pallet_vesting::Pallet::<crate::Runtime>::pot_account_id();
	log::info!("[{preset}] 🪙 Vesting pot: {:?}", pot.to_ss58check_with_version(ss58));
	for (beneficiary, start, cliff, end, total) in schedules {
		log::info!(
			"[{preset}] 🪙 Vesting: {:?} total={total} start={start} cliff={cliff} end={end}",
			beneficiary.to_ss58check_with_version(ss58),
		);
	}
}

fn log_genesis_accounts(
	preset: &str,
	endowed: &[AccountId],
	treasury_account: Option<&AccountId>,
	treasury_signers: &[AccountId],
) {
	let ss58 = ss58_version();
	for account in endowed {
		log::info!("[{preset}] 💰 Endowed: {:?}", account.to_ss58check_with_version(ss58));
	}
	match treasury_account {
		Some(account) =>
			log::info!("[{preset}] 🏦 Treasury: {:?}", account.to_ss58check_with_version(ss58)),
		None => log::info!(
			"[{preset}] 🏦 Treasury: none. Nothing reads the account on this chain except \
			 the vesting pallet's end-of-schedule remainder, which no origin can reach"
		),
	}
	for signer in treasury_signers {
		log::info!("[{preset}] 🔑 Treasury signer: {:?}", signer.to_ss58check_with_version(ss58));
	}
}

/// Initial difficulty for the `dev` preset: the qpow pallet's operational floor, so
/// a single dev machine finds blocks immediately instead of grinding against the
/// mainnet-scale `QPoWInitialDifficulty`. The retarget raises it if the machine
/// sustains faster-than-target blocks.
fn dev_initial_difficulty() -> U512 {
	pallet_qpow::Pallet::<crate::Runtime>::get_min_difficulty()
}

/// What a preset says about consensus at genesis.
///
/// `None` in either field means "the runtime's own default": the public chains
/// take it, and the `dev` preset overrides both.
pub struct ConsensusGenesis {
	/// Starting mining difficulty, defaulting to `QPoWInitialDifficulty`.
	pub initial_difficulty: Option<U512>,
	/// Target block time in milliseconds, defaulting to [`TARGET_BLOCK_TIME_MS`].
	pub target_block_time: Option<u64>,
}

impl ConsensusGenesis {
	/// The public chains: mainnet-scale difficulty, 120 s blocks.
	fn public() -> Self {
		Self { initial_difficulty: None, target_block_time: None }
	}

	/// The `dev` preset: the difficulty floor and the fast block time.
	fn dev() -> Self {
		Self {
			initial_difficulty: Some(dev_initial_difficulty()),
			target_block_time: Some(DEV_TARGET_BLOCK_TIME_MS),
		}
	}

	/// The Qnero public testnet: the 120 s target, and a difficulty sized for
	/// the hash rate that chain is certain to have on its first day.
	fn qnero_testnet() -> Self {
		Self {
			initial_difficulty: Some(U512::from(QNERO_TESTNET_INITIAL_DIFFICULTY)),
			target_block_time: Some(TARGET_BLOCK_TIME_MS),
		}
	}
}

/// Genesis mining difficulty for the Qnero public testnet.
///
/// Difficulty is expected hashes per block, so the number that matters is the
/// hash rate the chain actually has, and the retarget's equilibrium is the
/// *divisor* rather than the target: `divisor = target * 10 / 12` is 100 000 ms
/// at a 120 s target, and the neutral band is one to two divisors wide
/// (`pallets/qpow/src/lib.rs`). A chain settles at roughly `100 * H` to
/// `200 * H` for a hash rate of `H` hashes a second.
///
/// The hash rate this chain is certain of is its own node's: one in-process
/// RandomX light-mode thread, measured at 32.9 H/s (`docs/BENCH.md`). That
/// puts the neutral band at 3 300 to 6 600 and its middle at 5 000, which is
/// one block every 152 seconds on the node alone, inside the band and needing
/// no retarget at all. A rig is 450 H/s per thread in full mode, so the first
/// one to point xmrig at the stratum port takes the chain far under the target
/// until the retarget climbs.
///
/// **The asymmetry is the whole argument for choosing low.** The retarget is
/// Homestead's, one 2048th of the difficulty per step, and it is slow in both
/// directions: climbing is linear at `H / 2048` per second, and falling is
/// exponential with a time constant of `100 * 2048` seconds, which is 57
/// hours per e-fold whatever the numbers are. A difficulty set above the
/// available hash rate is therefore days of a chain that looks dead, while one
/// set below it is hours of fast blocks that fix themselves. Inheriting
/// `QPoWInitialDifficulty` (1 000 000, sized for about 8 300 H/s) would be the
/// first of those: 8.4 hours to the first block on the node alone, and a week
/// to converge.
///
/// There is no floor field to set beside this. `get_min_difficulty()` is a
/// hard-coded 128 (`pallets/qpow/src/lib.rs`); genesis validates against it
/// and cannot move it.
pub const QNERO_TESTNET_INITIAL_DIFFICULTY: u64 = 5_000;

/// Target block time for the `dev` preset, in milliseconds.
///
/// The public chain targets 120 s. Every e2e suite and every local test drives a
/// dev chain and would otherwise wait ten times as long for each block, so the
/// `dev` preset writes this into `pallet_qpow::TargetBlockTimeMs` at genesis.
/// One binary, two cadences, and no feature flag: the target is chain state.
/// `the_dev_preset_keeps_the_fast_block_time` is the tripwire, so a future edit
/// cannot slow the suites down without a failing test.
pub const DEV_TARGET_BLOCK_TIME_MS: u64 = 12_000;

/// Return the development genesis config.
pub fn development_config_genesis() -> Value {
	let endowed_accounts = dilithium_default_accounts();
	let treasury_account = development_treasury_account();
	log_genesis_accounts(
		"dev",
		&endowed_accounts,
		Some(&treasury_account),
		&dilithium_default_accounts(),
	);
	// The same table `heisenberg` ships. Dev used to add a fourth schedule for
	// the keyless test wormhole address, whose only spend path was the block-1
	// wormhole leaf; v1 removed that, so a payout to an account that cannot
	// sign is value nobody can shield and nobody can move.
	let vesting_schedules = testnet_vesting_schedules();
	log_vesting_schedules("dev", &vesting_schedules);

	#[cfg(feature = "runtime-benchmarks")]
	{
		use crate::Runtime;
		use frame_benchmarking::v2::{account, whitelisted_caller};
		use pallet_multisig::Pallet as Multisig;

		const SEED: u32 = 0;
		let caller = whitelisted_caller::<AccountId>();
		let signer1 = account::<AccountId>("signer1", 0, SEED);
		let signer2 = account::<AccountId>("signer2", 1, SEED);
		let mut signers = vec![caller, signer1, signer2];
		signers.sort();
		let multisig_address = Multisig::<Runtime>::derive_multisig_address(&signers, 2, 0);
		let guardian = crystal_alice().into_account();
		let delay = 10u32;

		let rt_genesis = pallet_reversible_transfers::GenesisConfig::<Runtime> {
			initial_high_security_accounts: vec![(multisig_address, guardian, delay)],
		};

		let treasury = TreasuryGenesis { account: Some(treasury_account) };
		let template_value = genesis_template(
			endowed_accounts,
			treasury,
			vec![],
			vesting_schedules,
			false,
			ConsensusGenesis::dev(),
		);
		// Every field `genesis_template` writes is a `RuntimeGenesisConfig` field
		// now, so this is a plain round trip through the config type.
		let mut config: RuntimeGenesisConfig =
			serde_json::from_value(template_value).expect("genesis_template returns valid config");
		config.reversible_transfers = rt_genesis;
		return serde_json::to_value(config).expect("Could not build genesis config.");
	}

	#[cfg(not(feature = "runtime-benchmarks"))]
	{
		let treasury = TreasuryGenesis { account: Some(treasury_account) };
		genesis_template(
			endowed_accounts,
			treasury,
			vec![],
			vesting_schedules,
			false,
			ConsensusGenesis::dev(),
		)
	}
}

pub fn heisenberg_config_genesis() -> Value {
	let endowed_accounts = dilithium_default_accounts();
	let treasury_signers = heisenberg_treasury_signers();
	let treasury_account = heisenberg_treasury_account();
	log_genesis_accounts(
		"heisenberg",
		&endowed_accounts,
		Some(&treasury_account),
		&treasury_signers,
	);
	let vesting_schedules = testnet_vesting_schedules();
	log_vesting_schedules("heisenberg", &vesting_schedules);
	let treasury = TreasuryGenesis { account: Some(treasury_account) };
	genesis_template(
		endowed_accounts,
		treasury,
		vec![],
		vesting_schedules,
		false,
		ConsensusGenesis::public(),
	)
}

/// ML-DSA-87, as every Planck literal must be ([`account_from_ss58`]).
fn planck_faucet_account() -> AccountId {
	account_from_ss58("qzka7DZXAT7GnzgXQfxiSwrPKRWgW6m6G89QRsQiLThThZ6Cw")
}

/// ML-DSA-87, as every Planck literal must be ([`account_from_ss58`]). These
/// three carry the 2-of-3 treasury, so a wrong scheme here freezes the treasury
/// itself.
fn planck_treasury_signers() -> Vec<AccountId> {
	vec![
		account_from_ss58("qzoRRfx5bUSdq2YWSXBXrmFFSwe24bNSUoMu3Vhz5hrtPri7D"),
		account_from_ss58("qzkscJp9ofGZzQbhAdySSNx3pmfKBDq9vqdfT8ZHNjp4GiwFq"),
		account_from_ss58("qzjxqVV6hzauZkBPBvvMxVv1o7ifp2XZj1J1qLTnze3yh7uhu"),
	]
}

fn planck_treasury_account() -> AccountId {
	Multisig::<crate::Runtime>::derive_multisig_address(&planck_treasury_signers(), 2, 0)
}

/// Balance each Planck treasury signer is seeded with: one multisig creation plus
/// the first proposal at the configured (`FEE_SCALE`-scaled) prices — `MultisigFee`
/// and the proposal fee burned, `ProposalDeposit` reserved — plus the transient
/// `MaxInnerCallWeight` inclusion-fee prepay `propose` declares (refunded
/// post-dispatch, but free balance must cover it at inclusion), the existential
/// deposit, and scaled headroom for base/length fees. Derived so turning the fee
/// dial cannot strand treasury bootstrap.
pub fn treasury_signer_seed(signers_count: u32) -> crate::Balance {
	use crate::configs::{MaxInnerCallWeight, MultisigFee, ProposalDeposit, ScaledIdentityFee};
	use frame_support::weights::WeightToFee;
	MultisigFee::get() +
		Multisig::<crate::Runtime>::proposal_fee(signers_count) +
		ProposalDeposit::get() +
		ScaledIdentityFee::weight_to_fee(&MaxInnerCallWeight::get()) +
		EXISTENTIAL_DEPOSIT +
		crate::scale_fee(100 * crate::MILLI_UNIT)
}

pub fn planck_config_genesis() -> Value {
	let treasury_signers = planck_treasury_signers();
	let treasury_account = planck_treasury_account();
	let endowed_accounts = vec![planck_faucet_account()];
	let seed = treasury_signer_seed(treasury_signers.len() as u32);
	let signer_fee_seed: Vec<_> = treasury_signers.iter().cloned().map(|a| (a, seed)).collect();
	log_genesis_accounts("planck", &endowed_accounts, Some(&treasury_account), &treasury_signers);
	// No vesting allocations on Planck; the pot still receives its ED buffer so
	// `create_schedule` works post-genesis.
	log_vesting_schedules("planck", &[]);
	let treasury = TreasuryGenesis { account: Some(treasury_account) };
	genesis_template(
		endowed_accounts,
		treasury,
		signer_fee_seed,
		vec![],
		false,
		ConsensusGenesis::public(),
	)
}

/// Mainnet genesis: the 2% placeholder TGE mint from `mainnet_vesting`, which is its one vesting
/// row, the `SEED` endowments for the treasurers, and the treasury multisig
/// derived from the treasurers. Requires a qualified proof-system
/// profile and `mainnet_vesting::FINALIZED`, which remains false while the
/// allocation contains a placeholder address.
pub fn mainnet_config_genesis() -> Value {
	assert!(
		mainnet_security_qualified(),
		"mainnet genesis is disabled: the Qnero proof-system profile is experimental; \
		 complete independent cryptographic qualification before enabling this preset"
	);
	let treasury_signers = mainnet_vesting::treasurers();
	let treasury_account = mainnet_vesting::treasury_account();
	let extra_balances = mainnet_vesting::seed_balances();
	let seeded: Vec<AccountId> = extra_balances.iter().map(|(who, _)| who.clone()).collect();
	log_genesis_accounts(
		MAINNET_RUNTIME_PRESET,
		&seeded,
		Some(&treasury_account),
		&treasury_signers,
	);
	let vesting_schedules = mainnet_vesting::schedules();
	log_vesting_schedules(MAINNET_RUNTIME_PRESET, &vesting_schedules);
	let treasury = TreasuryGenesis { account: Some(treasury_account) };
	genesis_template(
		vec![],
		treasury,
		extra_balances,
		vesting_schedules,
		true,
		ConsensusGenesis::public(),
	)
}

/// The Qnero public testnet's faucet: the one account its genesis endows.
///
/// ML-DSA-87, as every literal in this file must be ([`account_from_ss58`]).
/// Minted with `qnero-faucet keygen`, which is
/// `TransparentKey::from_seed(32 bytes from the operating system)` and
/// therefore the same derivation as `Dilithium87Pair::from_seed`; the node's
/// own `key qnero --scheme standard --no-derivation --seed` answers this
/// address for the same seed, which is the confirmation `docs/TESTNET.md`
/// asks for before genesis is cut. The seed lives in the operator's secret
/// store and nowhere else, and this address is all the chain spec carries.
fn qnero_testnet_faucet_account() -> AccountId {
	account_from_ss58("qzjpnqS6zVnCLeXgqAPn85dquWQNbSVr3ba54YivjzdYLKieZ")
}

/// The Qnero public testnet genesis: one endowed faucet account, and nothing
/// else.
///
/// Every absence here is deliberate, and each one costs something worth
/// naming:
///
/// - **No vesting table.** `GENESIS_VESTING_*` and `testnet_vesting_schedules` are the dev and
///   Heisenberg example table; a public chain that shipped them would vest real supply to the three
///   well-known public keys. The pot still receives its existential deposit from
///   `genesis_template`, which is what lets a schedule be created later.
/// - **No mainnet placeholder.** `mainnet_vesting::PLACEHOLDER` pays 2% of the supply to an address
///   nobody holds a key for. It reaches a chain only through [`mainnet_config_genesis`], so not
///   calling that is the whole defence, and `FINALIZED` is the backstop.
/// - **No treasury.** There is nothing for one to hold and nothing to spend from it, so the field
///   is `None` rather than an account picked to fill it in. See `TreasuryGenesis`.
/// - **No collective exists to seed.** The tech collective, its referenda instance and the
///   fast-upgrade origin were removed from the runtime itself, so this is a property of the binary
///   rather than of the preset. No chain this binary launches has an origin that can change its own
///   rules; the recovery for a consensus bug is a relaunch. `docs/DESIGN.md` section 7.6 carries
///   the decision.
/// - **No sudo.** There is no sudo pallet in this runtime and nothing should add one back.
///
/// What the faucet account does receive is `ENDOWED_BALANCE_UNITS`, 100 000
/// QNR of the 21 000 000 `MaxSupply`, all of it transparent. Under v1 that
/// balance can go exactly one place: into the pool, through a `shield` the
/// faucet signs for itself. It cannot be transferred to anybody, which is why
/// the faucet is a shielded-payment server and not a transfer script.
pub fn qnero_testnet_config_genesis() -> Value {
	let faucet = qnero_testnet_faucet_account();
	let endowed_accounts = vec![faucet];
	log_genesis_accounts(QNERO_TESTNET_RUNTIME_PRESET, &endowed_accounts, None, &[]);
	log_vesting_schedules(QNERO_TESTNET_RUNTIME_PRESET, &[]);
	let treasury = TreasuryGenesis { account: None };
	genesis_template(
		endowed_accounts,
		treasury,
		Vec::new(),
		Vec::new(),
		false,
		ConsensusGenesis::qnero_testnet(),
	)
}

/// Provides the JSON representation of predefined genesis config for given `id`.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
	let patch = match id.as_ref() {
		sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
		HEISENBERG_RUNTIME_PRESET => heisenberg_config_genesis(),
		PLANCK_RUNTIME_PRESET => planck_config_genesis(),
		MAINNET_RUNTIME_PRESET => mainnet_config_genesis(),
		QNERO_TESTNET_RUNTIME_PRESET => qnero_testnet_config_genesis(),
		_ => return None,
	};
	Some(
		serde_json::to_string(&patch)
			.expect("serialization to json is expected to work. qed.")
			.into_bytes(),
	)
}

/// Decode a preset account from its SS58 literal.
///
/// An address is `hash_bytes(public_key)`, and both variants of
/// `DilithiumSignatureScheme` hash into the same 32 bytes, so a literal carries
/// no trace of the scheme its key belongs to. No test can assert one, and the
/// consequence of getting it wrong is permanent: the transparent entry refuses
/// an ML-DSA-65 signature (`runtime/src/extrinsic.rs`), so a level-3 account
/// among these literals can never sign. Its vesting claim, its treasury
/// approval and its faucet drip all answer `BadSigner`, and its balance is
/// stranded for good.
///
/// Provenance is therefore a procedure, standing in for an assertion nothing
/// here can make. Every address passed here must be an ML-DSA-87 account: mint
/// one with `qnero-node key qnero` at its default `--scheme standard`, which
/// builds an ML-DSA-87 pair. Its other scheme, `wormhole`, derives an
/// unspendable wormhole address from a mnemonic and mints no signing key, so a
/// wormhole address is never a preset account. The node refuses
/// `key generate --scheme dilithium65` for the same reason
/// (`node/src/command.rs`), and `docs/DESIGN.md` section 7.3 carries the
/// pre-mainnet check that every literal has been confirmed before genesis.
fn account_from_ss58(ss58: &str) -> AccountId {
	AccountId::from_ss58check_with_version(ss58)
		.expect("Failed to decode SS58 address")
		.0
}

/// List of supported presets.
pub fn preset_names() -> Vec<PresetId> {
	let mut names = vec![
		PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
		PresetId::from(HEISENBERG_RUNTIME_PRESET),
		PresetId::from(PLANCK_RUNTIME_PRESET),
		PresetId::from(QNERO_TESTNET_RUNTIME_PRESET),
	];
	if mainnet_vesting::FINALIZED && mainnet_security_qualified() {
		names.push(PresetId::from(MAINNET_RUNTIME_PRESET));
	}
	names
}

#[cfg(test)]
mod tests {
	use super::{mainnet_vesting, *};
	use sp_runtime::BuildStorage;

	/// Every account a preset derives from a key is an ML-DSA-87 account, which
	/// is the one scheme the transparent entry admits (`runtime/src/extrinsic.rs`).
	/// A helper moved to the other variant of `DilithiumSignatureScheme` would
	/// hash to a different `AccountId32`, so pinning each derivation to the
	/// ML-DSA-87 pair for its public seed is what catches it.
	///
	/// What this cannot cover, said plainly so the coverage is not read wider
	/// than it is: the Planck and mainnet accounts are SS58 literals decoded by
	/// `account_from_ss58`, and both variants hash into the same 32-byte
	/// account, so a literal carries no variant to assert on. Only a
	/// key-derived account can carry one. A level-3 account among those
	/// literals would be stranded for good, since the entry refuses its
	/// signature; `account_from_ss58` carries the procedure that stands in for
	/// the assertion, and `docs/DESIGN.md` section 7.3 the pre-mainnet check.
	#[test]
	fn every_key_derived_preset_account_is_ml_dsa_87() {
		let ml_dsa_87 = |seed: [u8; 32]| -> AccountId {
			Dilithium87Pair::from_seed_slice(&seed)
				.expect("static seed is valid")
				.into_account()
		};
		// The three public seeds every dev and Heisenberg account comes from. Seeds
		// `[3u8; 32]` and `[4u8; 32]` went with the collective they padded.
		let known: Vec<AccountId> = (0u8..3).map(|i| ml_dsa_87([i; 32])).collect();

		for account in dilithium_default_accounts().into_iter().chain(heisenberg_treasury_signers())
		{
			assert!(
				known.contains(&account),
				"a preset derived {account:?} from a key that is not the ML-DSA-87 pair for one \
				 of the public seeds [0u8; 32]..[2u8; 32]"
			);
		}

		// Both development treasuries are multisigs over the first three of
		// those signers, so pinning the signer set pins the treasury address.
		assert_eq!(
			development_treasury_account(),
			Multisig::<crate::Runtime>::derive_multisig_address(&known, 2, 0)
		);
		assert_eq!(
			heisenberg_treasury_account(),
			Multisig::<crate::Runtime>::derive_multisig_address(
				&known,
				2,
				HEISENBERG_TREASURY_MULTISIG_NONCE
			)
		);
	}

	/// 2020-01-01 and 2100-01-01 UTC, sanity bounds for genesis vesting dates.
	const YEAR_2020_MS: u64 = 1_577_836_800_000;
	const YEAR_2100_MS: u64 = 4_102_444_800_000;

	#[test]
	fn days_ms_is_exact() {
		assert_eq!(days_ms(1), 86_400_000);
		assert_eq!(days_ms(365), 31_536_000_000);
	}

	#[test]
	fn utc_midnight_ms_matches_known_epochs() {
		assert_eq!(utc_midnight_ms(1970, 1, 1), 0);
		assert_eq!(utc_midnight_ms(2000, 3, 1), 951_868_800_000);
		assert_eq!(utc_midnight_ms(2024, 2, 29), 1_709_164_800_000);
		// Each documented vesting epoch, pinned to its independently derived value.
		assert_eq!(GENESIS_VESTING_START_MS, 1_785_888_000_000); // 2026-08-05 UTC
	}

	/// Every one of these is decidable at compile time, so they are asserted
	/// there: a const block fails the build rather than a test run.
	#[test]
	fn genesis_vesting_times_are_sane() {
		assert_eq!(GENESIS_VESTING_START_MS % MILLIS_PER_DAY, 0, "start must be midnight UTC");
		const { assert!(GENESIS_VESTING_START_MS > YEAR_2020_MS) };
		const { assert!(GENESIS_VESTING_START_MS < YEAR_2100_MS) };
		const { assert!(GENESIS_VESTING_START_MS <= GENESIS_VESTING_CLIFF_MS) };
		const { assert!(GENESIS_VESTING_CLIFF_MS <= GENESIS_VESTING_END_MS) };
		const { assert!(GENESIS_VESTING_START_MS < GENESIS_VESTING_END_MS) };
	}

	/// Every shipped preset must build genesis storage, including the vesting
	/// pallet's pot-balance assertions. Nothing derives a transfer proof from a
	/// genesis balance any more: v1 removed the exit those leaves fed.
	#[test]
	fn all_presets_build_genesis_storage() {
		for id in preset_names() {
			let bytes = get_preset(&id).expect("listed preset must resolve");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&bytes)
				.unwrap_or_else(|e| panic!("preset {:?} must deserialize: {e}", id));
			config
				.build_storage()
				.unwrap_or_else(|e| panic!("preset {:?} must build genesis storage: {e:?}", id));
		}
	}

	/// Each preset starts at the difficulty its own chain needs.
	///
	/// `dev` starts at the qpow floor so a single machine mines immediately.
	/// `heisenberg` and `planck` keep the mainnet-scale runtime constant. The
	/// public testnet sets its own, an order of magnitude below that constant,
	/// because it is the one of the four with a real hash rate to be sized
	/// against and a retarget too slow to correct a bad guess.
	#[test]
	fn each_preset_starts_at_the_difficulty_its_chain_needs() {
		let difficulty_of = |name: &str| {
			let raw = get_preset(&PresetId::from(name)).expect("listed preset must resolve");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
			config.q_po_w.initial_difficulty
		};
		assert_eq!(difficulty_of(sp_genesis_builder::DEV_RUNTIME_PRESET), dev_initial_difficulty());
		for preset in [HEISENBERG_RUNTIME_PRESET, PLANCK_RUNTIME_PRESET] {
			assert_eq!(difficulty_of(preset), crate::configs::QPoWInitialDifficulty::get());
		}

		// The public testnet sets its own, and the value is the one thing in
		// its spec that cannot be corrected without a new genesis: the
		// retarget moves by a 2048th of the difficulty per step, which is 57
		// hours per e-fold downwards, so a number set above the hash rate that
		// chain actually has is days of a chain that looks dead. It is pinned
		// here by value, and below the inherited constant by an order of
		// magnitude, because both halves are the point.
		let testnet = difficulty_of(QNERO_TESTNET_RUNTIME_PRESET);
		assert_eq!(testnet, U512::from(QNERO_TESTNET_INITIAL_DIFFICULTY));
		assert_eq!(QNERO_TESTNET_INITIAL_DIFFICULTY, 5_000);
		assert!(
			testnet < crate::configs::QPoWInitialDifficulty::get(),
			"the public testnet must not inherit the mainnet-scale initial difficulty"
		);
		assert!(
			testnet >= pallet_qpow::Pallet::<crate::Runtime>::get_min_difficulty(),
			"genesis validates the initial difficulty against the pallet's floor"
		);
	}

	/// The public chain targets 120 s and the `dev` preset overrides it to 12 s,
	/// which is what keeps every e2e suite at its old cadence under a binary
	/// built for the public chain. Without this assertion an edit that dropped
	/// the override would make the suites ten times slower and nothing would
	/// say so; without the other half, a preset that silently kept 12 s would
	/// ship a public chain at the wrong cadence.
	#[test]
	fn the_dev_preset_keeps_the_fast_block_time() {
		let target_of = |name: &str| {
			let raw = get_preset(&PresetId::from(name)).expect("listed preset must resolve");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
			config.q_po_w.target_block_time
		};
		assert_eq!(
			target_of(sp_genesis_builder::DEV_RUNTIME_PRESET),
			DEV_TARGET_BLOCK_TIME_MS,
			"the dev preset must keep the fast block time the test suites are sized for"
		);
		assert_eq!(DEV_TARGET_BLOCK_TIME_MS, 12_000);
		assert_eq!(crate::TARGET_BLOCK_TIME_MS, 120_000);
		for preset in
			[HEISENBERG_RUNTIME_PRESET, PLANCK_RUNTIME_PRESET, QNERO_TESTNET_RUNTIME_PRESET]
		{
			assert_eq!(target_of(preset), crate::TARGET_BLOCK_TIME_MS);
		}
	}

	/// Every planck a preset endows can still reach the pool under v1's call
	/// filter.
	///
	/// v1 refuses every transfer between accounts and removed the wormhole exit
	/// that used to give a keyless account a spend path, so a genesis balance is
	/// reachable only if its holder can sign a `shield`, and a vesting
	/// allocation is deliverable only if `Vesting::claim` stays dispatchable and
	/// pays an account that can sign. A preset that endows a keyless account, or
	/// vests to one, mints supply that nobody can ever move and that the
	/// emission schedule counts against `MaxSupply` forever, which is what the
	/// dev preset did with its wormhole test address until v1.
	///
	/// The two keyless accounts a preset can name are the vesting pot and the
	/// treasury. The pot is allowed to hold exactly the schedule table plus its
	/// own existential deposit, and nothing else, because `claim` is the one
	/// call that moves it. The treasury is a multisig, so its signers reach it
	/// through `Multisig::execute`, whose inner call meets the filter like any
	/// other and may be a `shield`.
	///
	/// Every preset is checked, and each one's endowed set is compared against
	/// the tables that preset builds it from: the well-known signers for `dev`
	/// and `heisenberg`, the treasury signers plus the faucet for `planck`, the
	/// seeded treasurers for `mainnet`, and the pot everywhere.
	/// A non-zero check is what this used to do, and it would have passed the
	/// bug it exists to catch, since the keyless wormhole address was endowed
	/// with plenty.
	///
	/// What it cannot check is whether a key exists behind an address a human
	/// supplied: `mainnet`'s grant rows are external SS58 strings and the
	/// runtime has no way to tell a live address from a typo. The guard is
	/// that the endowment list is closed and every row on it has to be
	/// attributed here before it ships.
	#[test]
	fn every_genesis_planck_is_reachable_under_the_call_filter() {
		use crate::configs::QneroCallFilter;
		use frame_support::traits::Contains;

		assert!(
			QneroCallFilter::contains(&crate::RuntimeCall::Vesting(pallet_vesting::Call::claim {
				schedule_id: 0
			})),
			"a genesis vesting allocation is deliverable only while `claim` is dispatchable"
		);
		assert!(
			QneroCallFilter::contains(&crate::RuntimeCall::Shielded(
				pallet_shielded::Call::shield {
					value: crate::UNIT,
					inner: [0u8; 32],
					ciphertext: alloc::vec::Vec::new(),
				}
			)),
			"a genesis balance reaches the pool through `shield` and nowhere else"
		);

		let pot = pallet_vesting::Pallet::<crate::Runtime>::pot_account_id();

		// Every preset's endowed set, compared against the tables that preset
		// builds it from. `amount > 0` is not the property: the address that
		// shipped the bug was endowed with plenty and could sign for none of
		// it. What makes an endowment reachable is that it came off a list of
		// signers a human holds keys for, so the list is what this compares
		// against.
		//
		// How much that catches differs by preset, and the difference is worth
		// being exact about. `dev` and `heisenberg` endow through
		// `genesis_template`'s `extra_balances`, which is a separate channel
		// from the table named here, so for those two the equality is a real
		// attribution: a row added anywhere else fails it. `planck` and
		// `mainnet` build their balances from the very functions this reads,
		// so for them both sides move together and what the equality catches
		// is only a row `genesis_template` adds beyond the preset's own table.
		// Those two rest on the SS58 tables themselves, which is where a new
		// signer has to be justified.
		let declared_endowed = |id: &PresetId| -> Vec<AccountId> {
			let mut accounts = match id.as_ref() {
				sp_genesis_builder::DEV_RUNTIME_PRESET | HEISENBERG_RUNTIME_PRESET =>
					dilithium_default_accounts(),
				PLANCK_RUNTIME_PRESET => {
					let mut planck = planck_treasury_signers();
					planck.push(planck_faucet_account());
					planck
				},
				// The public testnet's whole allocation: one faucet account,
				// whose key the operator holds and whose seed the runbook says
				// is confirmed against this address before genesis.
				QNERO_TESTNET_RUNTIME_PRESET => vec![qnero_testnet_faucet_account()],
				MAINNET_RUNTIME_PRESET =>
					mainnet_vesting::seed_balances().into_iter().map(|(who, _)| who).collect(),
				other => panic!(
					"preset {other:?} has no declared account table here; add one before \
					 shipping it, or the endowment check below is only a non-zero test"
				),
			};
			accounts.push(pot.clone());
			accounts.sort();
			accounts.dedup();
			accounts
		};

		// The vesting half of the same property, and the half the wormhole
		// regression had: `dev` used to carry a fourth schedule paying the
		// keyless test wormhole address, whose only spend path was the block-1
		// wormhole leaf v1 removed. A schedule pays its stored beneficiary and
		// nobody else, so a row naming an account with no key mints supply
		// nobody can claim exactly as an endowment to one does, and the
		// endowment check above says nothing about it: the pot's amount covers
		// the schedule table whoever it pays.
		//
		// `planck` vests to nobody. `mainnet`'s payees are its own allocation
		// table, which is the circularity noted above: what it pins there is
		// that `genesis_template` adds no schedule of its own. The treasury
		// multisig holds no schedule since the 2% placeholder replaced the
		// inherited table.
		let declared_vested = |id: &PresetId| -> Vec<AccountId> {
			match id.as_ref() {
				sp_genesis_builder::DEV_RUNTIME_PRESET | HEISENBERG_RUNTIME_PRESET =>
					dilithium_default_accounts(),
				// Neither Planck nor the public testnet vests to anybody, so
				// what the equality below pins for both is that
				// `genesis_template` adds no schedule of its own.
				PLANCK_RUNTIME_PRESET | QNERO_TESTNET_RUNTIME_PRESET => Vec::new(),
				MAINNET_RUNTIME_PRESET => {
					mainnet_vesting::schedules().into_iter().map(|(who, ..)| who).collect()
				},
				other => panic!(
					"preset {other:?} has no declared beneficiary table here; add one before 					 shipping it, or a schedule paying an account with no key ships unchecked"
				),
			}
		};

		for id in preset_names() {
			let raw = get_preset(&id).expect("listed preset must resolve");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
			let schedule_sum: u128 =
				config.vesting.schedules.iter().map(|(_, _, _, _, total)| *total).sum();

			for (who, amount) in &config.balances.balances {
				if *who == pot {
					assert_eq!(
						*amount,
						schedule_sum + EXISTENTIAL_DEPOSIT,
						"preset {id:?}: the keyless vesting pot may hold only its schedule \
						 table and its own existential deposit"
					);
					continue;
				}
				assert!(*amount > 0, "preset {id:?}: {who:?} is endowed with nothing");
			}

			let mut endowed: Vec<AccountId> =
				config.balances.balances.iter().map(|(who, _)| who.clone()).collect();
			endowed.sort();
			endowed.dedup();
			assert_eq!(
				endowed,
				declared_endowed(&id),
				"preset {id:?}: an endowed account is not on any list this preset declares, \
				 so nothing here says a key exists for it"
			);

			let vested = declared_vested(&id);
			for (who, _, _, _, _) in &config.vesting.schedules {
				assert_ne!(*who, pot, "preset {id:?}: the pot cannot vest to itself");
				assert!(
					vested.contains(who),
					"preset {id:?}: {who:?} is vested to and is on no list this preset 					 declares, so nothing here says a key exists for it"
				);
			}
		}

		// The dev preset, pinned account by account: it is the one that shipped
		// an endowment to an address with no key, and a list is what catches
		// the next one.
		let raw = get_preset(&PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET))
			.expect("dev preset exists");
		let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
		let mut endowed: Vec<AccountId> =
			config.balances.balances.iter().map(|(who, _)| who.clone()).collect();
		endowed.sort();
		let mut expected = dilithium_default_accounts();
		expected.push(pot.clone());
		expected.sort();
		assert_eq!(
			endowed, expected,
			"the dev preset endows the three well-known signers and the vesting pot, and \
			 every one of them can reach the pool"
		);
	}

	/// The vesting pot's genesis endowment must exactly cover the schedule table.
	#[test]
	fn preset_pot_endowment_matches_schedules() {
		let raw = get_preset(&PresetId::from(HEISENBERG_RUNTIME_PRESET)).expect("preset exists");
		let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
		let pot = pallet_vesting::Pallet::<crate::Runtime>::pot_account_id();
		let pot_balance = config
			.balances
			.balances
			.iter()
			.find(|(who, _)| *who == pot)
			.map(|(_, amount)| *amount)
			.expect("pot must be endowed");
		let schedule_sum: u128 =
			config.vesting.schedules.iter().map(|(_, _, _, _, total)| *total).sum();
		assert_eq!(pot_balance, schedule_sum + EXISTENTIAL_DEPOSIT);
	}

	/// Pin the known testnet/dev vesting tables (and their schedule counts) to the
	/// published cliff constants. Regression: Bob's second schedule shipped with the
	/// start timestamp in its cliff field, so it accrued linearly from day 0 in both
	/// `dev` and `heisenberg` instead of honoring the 90-day lock.
	///
	/// Counts are exact per preset: a `>= 3` floor would let a heisenberg drop slip
	/// through. The 90-day pin applies only to schedules that use
	/// [`GENESIS_VESTING_START_MS`]; a future allocation table that ships a
	/// different start/cliff pair is checked only for structural validity
	/// (`start <= cliff < end`).
	#[test]
	fn preset_vesting_schedules_enforce_the_published_cliff() {
		let mut expected: Vec<(&str, usize)> = vec![
			(sp_genesis_builder::DEV_RUNTIME_PRESET, 3),
			(HEISENBERG_RUNTIME_PRESET, 3),
			(PLANCK_RUNTIME_PRESET, 0),
			(QNERO_TESTNET_RUNTIME_PRESET, 0),
		];
		if mainnet_vesting::FINALIZED && mainnet_security_qualified() {
			expected.push((MAINNET_RUNTIME_PRESET, mainnet_vesting::schedules().len()));
		}
		let mut total = 0usize;
		for &(name, expected_count) in &expected {
			let id = PresetId::from(name);
			let raw = get_preset(&id).expect("listed preset must resolve");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
			assert_eq!(
				config.vesting.schedules.len(),
				expected_count,
				"preset {id:?}: unexpected vesting schedule count"
			);
			for (who, start, cliff, end, _) in &config.vesting.schedules {
				assert!(
					start <= cliff,
					"preset {id:?}: schedule for {who:?} must not cliff before it starts"
				);
				assert!(cliff < end, "preset {id:?}: cliff must precede the vesting end");
				if *start == GENESIS_VESTING_START_MS {
					assert_eq!(
						*cliff, GENESIS_VESTING_CLIFF_MS,
						"preset {id:?}: schedule for {who:?} using the published start \
						 must lock until GENESIS_VESTING_CLIFF_MS (start + 90 days)"
					);
				}
			}
			total += config.vesting.schedules.len();
		}
		let expected_total: usize = expected.iter().map(|(_, count)| count).sum();
		assert_eq!(
			total, expected_total,
			"per-preset vesting schedule counts must sum to the pinned total"
		);
	}

	/// The public testnet's genesis, field by field.
	///
	/// This is the first Qnero chain with a genesis of its own, and the whole
	/// of what it mints is one endowed faucet account. Every other preset here
	/// carries something the testnet deliberately does not, so each absence is
	/// asserted rather than left to the reader of the builder: a vesting row
	/// would pay the public dev keys, a treasury would write an address into
	/// genesis that means nothing here, and the mainnet placeholder is 2% of the
	/// supply paid to an address nobody can sign for.
	#[test]
	fn the_public_testnet_endows_one_faucet_and_nothing_else() {
		let id = PresetId::from(QNERO_TESTNET_RUNTIME_PRESET);
		let raw = get_preset(&id).expect("the testnet preset resolves");
		let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");

		let pot = pallet_vesting::Pallet::<crate::Runtime>::pot_account_id();
		let faucet = qnero_testnet_faucet_account();

		let mut endowed: Vec<(AccountId, u128)> = config.balances.balances.clone();
		endowed.sort();
		assert_eq!(endowed.len(), 2, "the testnet genesis has two balance rows and no more");
		let faucet_row =
			endowed.iter().find(|(who, _)| *who == faucet).expect("the faucet is endowed");
		assert_eq!(faucet_row.1, 100_000 * UNIT);
		let pot_row = endowed.iter().find(|(who, _)| *who == pot).expect("the pot is endowed");
		assert_eq!(
			pot_row.1, EXISTENTIAL_DEPOSIT,
			"with no schedules the pot holds exactly its own existential deposit"
		);

		assert!(config.vesting.schedules.is_empty(), "the testnet vests to nobody");
		assert!(!config.vesting.anchor_to_first_timestamp);
		assert!(
			config.treasury_pallet.treasury_account.is_none(),
			"the testnet configures no treasury, and nothing on this chain needs one"
		);
		// The placeholder, by address rather than by absence of a row: it is
		// the one allocation in this file that would be invisible in a diff
		// and permanent in a genesis.
		let placeholder = mainnet_vesting::PLACEHOLDER;
		assert!(
			config
				.balances
				.balances
				.iter()
				.all(|(who, _)| { who.to_ss58check_with_version(ss58_version()) != placeholder }),
			"the mainnet placeholder allocation reached the testnet genesis"
		);

		assert_eq!(config.q_po_w.target_block_time, crate::TARGET_BLOCK_TIME_MS);
		assert_eq!(config.q_po_w.target_block_time, 120_000);
		assert_eq!(config.q_po_w.initial_difficulty, U512::from(5_000u64));

		// It has to build, treasury-free genesis included.
		config.build_storage().expect("the testnet genesis builds");
	}

	#[test]
	fn mainnet_preset_requires_final_allocations_and_security_qualification() {
		let minted_total = mainnet_vesting::GENESIS_ALLOCATION + EXISTENTIAL_DEPOSIT;
		if mainnet_vesting::FINALIZED && mainnet_security_qualified() {
			let raw = get_preset(&PresetId::from(MAINNET_RUNTIME_PRESET)).expect("preset exists");
			let config: RuntimeGenesisConfig = serde_json::from_slice(&raw).expect("deserializes");
			let treasury = config.treasury_pallet.treasury_account.clone().expect("treasury");
			assert_eq!(treasury, mainnet_vesting::treasury_account());
			assert!(
				config.balances.balances.iter().all(|(who, _)| *who != treasury),
				"treasury holds no liquid genesis balance"
			);
			for who in mainnet_vesting::treasurers().iter() {
				let seed = config
					.balances
					.balances
					.iter()
					.find(|(account, _)| account == who)
					.map(|(_, amount)| *amount)
					.expect("seeded account must have a genesis balance");
				assert_eq!(seed, mainnet_vesting::SEED);
			}
			assert_eq!(config.vesting.schedules.len(), mainnet_vesting::schedules().len());
			assert_eq!(
				config.vesting.schedules.iter().filter(|(who, ..)| *who == treasury).count(),
				0,
				"the treasury holds no vesting schedule under the 2% placeholder allocation"
			);
			assert!(config.vesting.anchor_to_first_timestamp);
			let minted: u128 = config.balances.balances.iter().map(|(_, amount)| *amount).sum();
			assert_eq!(minted, minted_total);
			let storage = config.build_storage().expect("finalized mainnet genesis must build");
			sp_io::TestExternalities::new(storage).execute_with(|| {
				assert_eq!(pallet_balances::TotalIssuance::<crate::Runtime>::get(), minted_total);
			});
		} else {
			assert!(preset_names()
				.iter()
				.all(|id| AsRef::<str>::as_ref(id) != MAINNET_RUNTIME_PRESET));
			assert!(std::panic::catch_unwind(mainnet_config_genesis).is_err());
		}
	}
}
