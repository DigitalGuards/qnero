//! Mainnet genesis allocation — the audit surface for the 2% placeholder mint.
//!
//! How to audit this file:
//! 1. [`GENESIS_ALLOCATION`] is 2% of [`MAX_SUPPLY`] (420 000 QNR). Every coin of it is either the
//!    single [`VESTING`] row or a [`SEED`] endowment: `sum(VESTING) + SEEDED_ACCOUNTS * SEED ==
//!    GENESIS_ALLOCATION` is asserted at compile time.
//! 2. [`VESTING`] is one row, `(account, amount, unlock start day, unlock end day)`. Days count
//!    from TGE, the first non-zero block timestamp (the genesis block's `Now` is 0 and is not TGE).
//!    It vests linearly with `cliff == start`, so nothing unlocks as a lump: locked for
//!    [`GRANT_UNLOCK_DELAY_DAYS`] (1 year), then vesting over [`GRANT_UNLOCK_PERIOD_DAYS`] (3
//!    years) to [`GRANT_END_DAYS`].
//! 3. That row pays [`PLACEHOLDER`], and [`PLACEHOLDER`] is a placeholder. It is one ML-DSA-87
//!    address generated with `qnero-node key qnero`, standing in for whatever allocation this
//!    project decides on. Replace it or delete the whole allocation before mainnet genesis; there
//!    is no launch that should ship this address. `docs/DESIGN.md` section 7.3 carries the
//!    pre-mainnet check.
//! 4. Each of [`TREASURERS`] and [`TECH_COLLECTIVE`] (distinct sets) is endowed with [`SEED`] as
//!    free balance so they can pay fees and deposits from block 1. They hold no vesting schedule.
//!    The vesting pot additionally receives its existential deposit from `genesis_template`, the
//!    only issuance outside the 2%.
//! 5. The treasury multisig is derived from [`TREASURERS`] and holds no genesis balance at all.
//! 6. Accounts are SS58 addresses only — no personal names.
//! 7. Every address below must be an ML-DSA-87 account, minted with `qnero-node key qnero`. An SS58
//!    literal carries no trace of its scheme, so nothing here can assert it; the entry refuses an
//!    ML-DSA-65 signature, which would strand such an account and everything vested to it for good.
//!    `super::account_from_ss58` states the procedure and `docs/DESIGN.md` section 7.3 the
//!    pre-mainnet check.
//!
//! History: this table inherited a 27% allocation and 48 vesting rows from the upstream project
//! this chain forked. Every one of those rows was removed on 2026-09-14. 27% of the supply minted
//! to addresses this project has no relationship with is not an allocation it can defend, so the
//! placeholder is 2% and the open question is whether it survives at all.
//!
//! Flip [`FINALIZED`] only after every `REPLACE_WITH_` placeholder is filled. Until then the
//! `mainnet` preset refuses to build.

use super::{account_from_ss58, days_ms, Multisig, VestingScheduleTuple};
use crate::{AccountId, MAX_SUPPLY, UNIT};
use alloc::vec::Vec;

/// 2% of [`MAX_SUPPLY`] minted at genesis, as a placeholder. See the module docs: this number is a
/// position to argue from, not a commitment, and zero is a live option.
pub const GENESIS_ALLOCATION: u128 = 2 * MAX_SUPPLY / 100;
/// Delay before unlock starts, in days from TGE.
pub const GRANT_UNLOCK_DELAY_DAYS: u64 = 365;
/// Linear unlock after the delay, in days.
pub const GRANT_UNLOCK_PERIOD_DAYS: u64 = 3 * 365;
/// Finish of the delayed schedule, in days from TGE.
pub const GRANT_END_DAYS: u64 = GRANT_UNLOCK_DELAY_DAYS + GRANT_UNLOCK_PERIOD_DAYS;
/// Free balance endowed to each treasurer and tech collective member at genesis.
pub const SEED: u128 = 3 * UNIT;
/// Number of [`SEED`] endowments: [`TREASURERS`] plus [`TECH_COLLECTIVE`].
pub const SEEDED_ACCOUNTS: u128 = (TREASURERS.len() + TECH_COLLECTIVE.len()) as u128;
/// Approvals required on the treasury multisig.
pub const TREASURY_THRESHOLD: u32 = 6;
const TREASURY_NONCE: u64 = 0;
/// Whatever of the 2% the seed endowments do not take, vesting to [`PLACEHOLDER`].
pub const PLACEHOLDER_AMOUNT: u128 = GENESIS_ALLOCATION - SEEDED_ACCOUNTS * SEED;

/// Flip to `true` only when every placeholder below is a launch address.
pub const FINALIZED: bool = true;

/// Treasury multisig signers.
pub const TREASURERS: [&str; 10] = [
	"qzkmmtHL1XZ94LnDc43hTuUUW6o2jkjQBSgwSYF7Dm2JErapB",
	"qzmFVMW5f48c1cBNXTzNjAn9YbLhCfohXqEgofeCn3UhJUaMw",
	"qzkBP7kRB9wh1dKozJK83Y4e6GqSFgWEhf69WEggay7wt5Ls7",
	"qzmtKfCXKHvhg5agvp1XKgx8ymuShQzNhJ8ZrpKCqy4Y5z6HW",
	"qzk42WAmPUAbirA9SdAfpu9qr5UdTwU2PnLoifRFtX7GJLf5P",
	"qznYp4bk4YdA77tXqfokbwLcrzbDMLuKdNKTQs4s9EjLbx2rq",
	"qzjeW1DVYmPUqYCiosKnr3Ssh8DVTjmXmYV6JHibiVQKiBveD",
	"qzm2TcoDAyqycAmMuS91bXhPwWqEgaKcYGh5nQ3wqBqCzc9d5",
	"qzjuYZSefPGu3DFgBfXDRgGXJ3YvdFwXBNTSbE8Fa7dk3aV8u",
	"qzmHuteJKcKmyNdLrgS9WivKrsSv6AvwDC56ETf21YhastHXm",
];

/// Tech collective members, distinct from [`TREASURERS`].
pub const TECH_COLLECTIVE: [&str; 10] = [
	"qzpfF7tvw4nhTzhhAjifFGPRKqKTBfCk68dgvM5DwnDCSyXYJ",
	"qzjpLEi51md3q9FpECBTxRuLQsP31N5NmT9CF3ovVXY2RVKWE",
	"qzomCRTgMZHtdDWBBAqm5WLG8FwLKuYCJHgrAMznkKEhWG8qJ",
	"qzmQoa5gvngjmTafLJqCBnmmmNKFCuaVvZiZcdairrGWVCBjA",
	"qzosrX14BSUfTsGYB3NmakBWBvJgLGwqboJCQAvL2V1Tm64UA",
	"qznivf7i8HDSqqb4uCSzeAypCPpKAHZASC2QPQa4D1zzYGsZu",
	"qzmyhjrbKk9Nhtcq3gnNpX5p9CR8HnM92SUGBC2cVW6FpAzd2",
	"qzneDSjVt2Lbf2nq3UZFGG3cutFfkk5ktffaeJRamAb134obQ",
	"qzmdJBPzYdtBGLaJYjtT7FutNd47q79rjr63qhJTeQNzvBb9c",
	"qzoijuSKGJAgAbPChRc1LxxxjeZRpWGLBooHDUYzhPJ6ooTvw",
];

/// The one account the placeholder allocation vests to.
///
/// An ML-DSA-87 address from `qnero-node key qnero`, held by nobody who matters: it exists so the
/// allocation machinery has something to point at while the allocation itself is undecided. A
/// mainnet launch replaces this address or removes [`VESTING`] entirely.
pub const PLACEHOLDER: &str = "qzmgtTEBgy7i7vBLRMq7qscR1h4mqHV8sdxx8Wyqo6vpEco6p";

/// One schedule: `(account, amount, unlock start day, unlock end day)`; `cliff == start`.
type Row = (&'static str, u128, u64, u64);

#[rustfmt::skip]
const VESTING: &[Row] = &[
	//  account                                                                amount  start                    end
	(PLACEHOLDER,                                                  PLACEHOLDER_AMOUNT,  GRANT_UNLOCK_DELAY_DAYS, GRANT_END_DAYS),
];

const fn vesting_total() -> u128 {
	let mut sum = 0u128;
	let mut i = 0;
	while i < VESTING.len() {
		sum += VESTING[i].1;
		i += 1;
	}
	sum
}

const _: () = assert!(GENESIS_ALLOCATION == 420_000 * UNIT);
const _: () = assert!(SEEDED_ACCOUNTS * SEED == 60 * UNIT);
const _: () = assert!(PLACEHOLDER_AMOUNT == 419_940 * UNIT);
const _: () = assert!(GRANT_UNLOCK_PERIOD_DAYS == 3 * 365);
const _: () = assert!(GRANT_END_DAYS == 4 * 365);
const _: () = assert!(GRANT_UNLOCK_DELAY_DAYS < GRANT_END_DAYS);
const _: () = assert!(VESTING.len() == 1);
const _: () = assert!(VESTING.len() <= pallet_vesting::MAX_GENESIS_SCHEDULES as usize);
const _: () = assert!(vesting_total() == PLACEHOLDER_AMOUNT);
const _: () = assert!(vesting_total() + SEEDED_ACCOUNTS * SEED == GENESIS_ALLOCATION);

fn require_finalized() {
	if !FINALIZED {
		panic!(
			"mainnet allocation is not finalized — fill every REPLACE_WITH_ placeholder in \
			 genesis_config_presets/mainnet_vesting.rs and flip FINALIZED before building this \
			 chain spec"
		);
	}
}

fn accounts(ss58s: &[&str], what: &str) -> Vec<AccountId> {
	let out: Vec<AccountId> = ss58s.iter().map(|s| account_from_ss58(s)).collect();
	let mut deduped = out.clone();
	deduped.sort();
	deduped.dedup();
	assert_eq!(deduped.len(), out.len(), "mainnet {what} must be distinct");
	out
}

/// Treasury multisig signers.
pub fn treasurers() -> Vec<AccountId> {
	require_finalized();
	accounts(&TREASURERS, "treasurers")
}

/// Tech collective members; must not overlap the treasurers.
pub fn tech_collective() -> Vec<AccountId> {
	let treasurers = treasurers();
	let members = accounts(&TECH_COLLECTIVE, "tech collective members");
	assert!(
		members.iter().all(|m| !treasurers.contains(m)),
		"mainnet tech collective members must differ from the treasurers"
	);
	members
}

/// The [`TREASURY_THRESHOLD`]-of-10 multisig of [`TREASURERS`].
pub fn treasury_account() -> AccountId {
	Multisig::<crate::Runtime>::derive_multisig_address(
		&treasurers(),
		TREASURY_THRESHOLD,
		TREASURY_NONCE,
	)
}

/// [`SEED`] free balance for every treasurer and tech collective member.
pub fn seed_balances() -> Vec<(AccountId, u128)> {
	treasurers()
		.into_iter()
		.chain(tech_collective())
		.map(|who| (who, SEED))
		.collect()
}

/// [`VESTING`] in row order (ids from 0). Times are offsets from the first non-zero timestamp.
pub fn schedules() -> Vec<VestingScheduleTuple> {
	require_finalized();
	VESTING
		.iter()
		.map(|(who, amount, start, end)| {
			(account_from_ss58(who), days_ms(*start), days_ms(*start), days_ms(*end), *amount)
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::configs::VestingPayoutQuantum;

	#[test]
	fn every_coin_of_the_2_percent_is_accounted_for() {
		assert_eq!(GENESIS_ALLOCATION, 2 * MAX_SUPPLY / 100);
		assert_eq!(GENESIS_ALLOCATION, 420_000 * UNIT);
		assert_eq!(SEED, 3 * UNIT);
		assert_eq!(TREASURERS.len(), 10);
		assert_eq!(TECH_COLLECTIVE.len(), 10);
		let vested: u128 = VESTING.iter().map(|(_, amount, _, _)| *amount).sum();
		assert_eq!(vested, PLACEHOLDER_AMOUNT);
		assert_eq!(vested + SEEDED_ACCOUNTS * SEED, GENESIS_ALLOCATION);
	}

	/// The whole allocation is one row to one address, and that is the point:
	/// there is one thing to delete when the allocation question is settled.
	#[test]
	fn the_allocation_is_one_placeholder_row() {
		assert_eq!(VESTING.len(), 1);
		let (who, amount, start, end) = VESTING[0];
		assert_eq!(who, PLACEHOLDER);
		assert_eq!(amount, PLACEHOLDER_AMOUNT);
		assert_eq!((start, end), (GRANT_UNLOCK_DELAY_DAYS, GRANT_END_DAYS));
		assert_eq!(GRANT_UNLOCK_DELAY_DAYS, 365);
		assert_eq!(GRANT_UNLOCK_PERIOD_DAYS, 3 * 365);
		let placeholder = account_from_ss58(PLACEHOLDER);
		assert!(treasurers().iter().all(|who| *who != placeholder));
		assert!(tech_collective().iter().all(|who| *who != placeholder));
		assert_ne!(placeholder, treasury_account());
	}

	#[test]
	fn rows_are_valid_distinct_schedules() {
		for (who, amount, start, end) in VESTING {
			assert!(start < end, "{who}");
			assert!(*amount >= VestingPayoutQuantum::get(), "{who}");
			assert_eq!(amount % VestingPayoutQuantum::get(), 0, "{who}");
		}
		let mut accounts: Vec<&str> = VESTING.iter().map(|(who, ..)| *who).collect();
		accounts.extend(TREASURERS);
		accounts.extend(TECH_COLLECTIVE);
		let total = accounts.len();
		accounts.sort_unstable();
		accounts.dedup();
		assert_eq!(
			accounts.len(),
			total,
			"allocation, treasurer and tech collective addresses must be distinct"
		);
	}

	#[test]
	fn seeds_cover_bootstrap_costs() {
		use super::super::{tech_referendum_cost, treasury_signer_seed};
		assert!(treasury_signer_seed(TREASURERS.len() as u32) <= SEED);
		assert!(tech_referendum_cost() <= SEED);
	}

	#[test]
	fn refuses_to_build_until_finalized() {
		if FINALIZED {
			let placeholders = VESTING
				.iter()
				.map(|(who, ..)| *who)
				.chain(TREASURERS)
				.chain(TECH_COLLECTIVE)
				.filter(|s| s.starts_with("REPLACE_WITH_"))
				.count();
			assert_eq!(placeholders, 0);
			let treasury = treasury_account();
			let rows = schedules();
			assert_eq!(rows.len(), VESTING.len());
			assert_eq!(rows.iter().filter(|(who, ..)| *who == treasury).count(), 0);
			assert!(rows.iter().all(|(_, start, cliff, _, _)| start == cliff));
			let seeds = seed_balances();
			assert_eq!(seeds.len(), SEEDED_ACCOUNTS as usize);
			assert!(seeds.iter().all(|(who, amount)| {
				*amount == SEED && *who != treasury && rows.iter().all(|(b, ..)| b != who)
			}));
		} else {
			assert!(std::panic::catch_unwind(treasurers).is_err());
			assert!(std::panic::catch_unwind(tech_collective).is_err());
			assert!(std::panic::catch_unwind(treasury_account).is_err());
			assert!(std::panic::catch_unwind(seed_balances).is_err());
			assert!(std::panic::catch_unwind(schedules).is_err());
		}
	}
}
