//! Side-branch admission: what a node lets a peer make it execute.
//!
//! Qnero keeps genesis as its only irreversible block and chooses the chain
//! by cumulative work, so a node imports, executes and archives every valid
//! block it is offered, on every branch, at any depth. That is the property
//! that lets a heavier chain win after a long partition, and it is also the
//! cheapest thing an attacker can make every node do: a side branch retargets
//! from its own timestamps, the retarget falls at most 99/2048 per block but
//! it keeps falling, and after enough wall-clock time the branch mines blocks
//! at a small fraction of what the tip costs. Every one of those blocks is a
//! RandomX hash, a runtime execution and a permanent archive entry.
//!
//! No per-block verdict separates that branch from an honest one. A minority
//! partition's chain and an attacker's chain are the same object block by
//! block: a low-hashrate chain whose difficulty decayed. What separates them
//! is cumulative work at the tip, which is invisible until the whole branch is
//! in. A depth floor or a hard difficulty threshold therefore refuses the
//! honest case too, and refuses it permanently, because the sync layer offers
//! the same branch again from the same fork point for ever. Both were
//! considered and rejected on 2026-09-21 for that reason.
//!
//! So this module budgets instead of refusing. A block whose parent is the
//! tip is free. A block on another parent whose difficulty is within
//! [`SIDE_BRANCH_DIFFICULTY_FRACTION`] of the tip's is free too, because an
//! honest short fork or competing tip differs from the tip by a few retarget
//! steps at most. Everything cheaper draws one token from a bucket that
//! refills at a fixed rate, and it draws it once its seal has met the branch
//! difficulty, so a header carrying a junk seal drains nothing. When the
//! bucket is empty the block is refused through the ordinary
//! verification-failed path: sync drops the peer, and offers the branch again
//! later, when the bucket has refilled. An honest heavier chain is admitted at
//! the budget's rate and can never be refused for good; a spammer gets the
//! bucket's burst and then the refill rate, each token costing a real seal.
//!
//! The same shape bounds the other thing a peer can make the node do: fill a
//! 256 MiB RandomX cache. A block extending the tip fills for free (initial
//! sync, a restart on a prefix, the first block of a new epoch), and so does a
//! block under one of the two pinned identities, whose fill the node makes
//! anyway. Any other block whose seed is neither pinned nor resident draws
//! from a second bucket, before the fill, because the fill is the cost.
//!
//! Both budgets are charged in the import queue's verifier only. The
//! re-verification inside `import_block` and the node's own blocks see no
//! budget, so the two runs of `verify_pow` can never disagree about a block.

use parking_lot::Mutex;
use primitive_types::{H256, U512};
use prometheus_endpoint::{register, Counter, PrometheusError, Registry, U64};
use std::time::{Duration, Instant};

/// A side-branch block whose difficulty is at least the tip's divided by this
/// is admitted without charge.
///
/// The retarget moves at most 99/2048 (4.8%) down and 1/2048 up per block, so
/// a branch needs about 42 consecutive maximum-decrease steps (the integer
/// retarget makes the exact count difficulty-dependent), each of which needs
/// a claimed gap of 100 retarget divisors, to fall to an eighth of the tip.
/// The divisor is `target * ln 2` (`pallet-qpow`), 83 177 ms at the public
/// 120 s target, so the gap is 8 318 s and the fall is a branch starved of
/// hashrate for about four days. `pallet-qpow`'s own tests pin the step count
/// and that wall clock, because both are arithmetic in its constants and this
/// crate reads the chain through the runtime API rather than through the
/// pallet. Honest short forks never get near it. Above the line the number is
/// the amplification a spammer gets for free: up to eight executed side-branch
/// blocks per honest block's worth of hashing.
pub const SIDE_BRANCH_DIFFICULTY_FRACTION: u64 = 8;

/// Cheap side-branch blocks admitted in one burst before the refill rate
/// applies. About 22 MB of archive at 22 KB a block, and more than the cheap
/// prefix an honest migrated chain carries before its difficulty climbs back.
pub const SIDE_BRANCH_BUDGET_CAPACITY: u32 = 1024;

/// Default sustained rate of cheap side-branch blocks: one per four seconds,
/// 900 an hour, about 475 MB of archive a day against tens of thousands of
/// blocks an hour unbounded.
pub const DEFAULT_SIDE_BRANCH_BLOCKS_PER_HOUR: u32 = 900;

/// Cache fills for non-resident seeds admitted in one burst: two historical
/// canonical seeds and two branch seeds at once.
pub const SEED_FILL_BUDGET_CAPACITY: u32 = 4;

/// Default sustained rate of budgeted cache fills: one per 150 s. An honest
/// deep branch needs one fill per 2048 blocks and never exhausts this; a
/// junk-seal flood gets four fills and then one every two and a half minutes,
/// each costing the sender its peer slot.
pub const DEFAULT_SEED_FILLS_PER_HOUR: u32 = 24;

/// `d_branch * fraction >= d_ref`, saturating. A zero reference admits
/// everything, and the comparison never panics.
pub fn is_difficulty_admissible(d_branch: U512, d_ref: U512, fraction: u64) -> bool {
	d_branch.saturating_mul(U512::from(fraction)) >= d_ref
}

/// The two questions the classifier asks of the chain, as a trait so the
/// rule is unit-testable against a fake (the same shape as `seed::ChainView`).
pub trait TipView {
	/// The best block's hash and number.
	fn tip(&self) -> (H256, u64);
	/// The difficulty required for the child of `hash`.
	fn difficulty_after(&self, hash: H256) -> Result<U512, String>;
}

/// Where a block sits relative to the tip, for charging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideBranchClass {
	/// Its parent is the tip. Free.
	ExtendsTip,
	/// Another parent, but its difficulty is within the fraction of the
	/// tip's. Free.
	WithinFraction { tip_difficulty: U512 },
	/// Another parent and cheaper than the fraction allows. Charged.
	Cheap { tip_difficulty: U512 },
}

/// Classify a block by its parent and the difficulty it had to beat.
pub fn classify_side_branch<V: TipView + ?Sized>(
	view: &V,
	parent_hash: H256,
	difficulty: U512,
	fraction: u64,
) -> Result<SideBranchClass, String> {
	let (tip_hash, _) = view.tip();
	if parent_hash == tip_hash {
		return Ok(SideBranchClass::ExtendsTip);
	}
	let tip_difficulty = view.difficulty_after(tip_hash)?;
	Ok(if is_difficulty_admissible(difficulty, tip_difficulty, fraction) {
		SideBranchClass::WithinFraction { tip_difficulty }
	} else {
		SideBranchClass::Cheap { tip_difficulty }
	})
}

/// A token bucket with an injected clock, so tests never sleep.
#[derive(Debug, Clone)]
pub struct TokenBucket {
	capacity: u32,
	refill_every: Duration,
	tokens: u32,
	last_refill: Option<Instant>,
}

impl TokenBucket {
	/// A full bucket of `capacity` tokens that gains one every
	/// `refill_every`.
	pub fn new(capacity: u32, refill_every: Duration) -> Self {
		Self { capacity: capacity.max(1), refill_every, tokens: capacity.max(1), last_refill: None }
	}

	fn refill(&mut self, now: Instant) {
		let Some(last) = self.last_refill else {
			self.last_refill = Some(now);
			return;
		};
		if self.refill_every.is_zero() {
			self.tokens = self.capacity;
			self.last_refill = Some(now);
			return;
		}
		let elapsed = now.saturating_duration_since(last);
		let gained = (elapsed.as_nanos() / self.refill_every.as_nanos().max(1)) as u64;
		if gained == 0 {
			return;
		}
		self.tokens = self
			.tokens
			.saturating_add(gained.min(u64::from(u32::MAX)) as u32)
			.min(self.capacity);
		// Keep the remainder, so a steady trickle of requests does not lose
		// the fraction of an interval every time.
		let consumed = self.refill_every.saturating_mul(gained.min(u64::from(u32::MAX)) as u32);
		self.last_refill = Some(last + consumed);
	}

	/// Take one token: `Ok(tokens left)`, or `Err(time until the next one)`.
	pub fn try_take(&mut self, now: Instant) -> Result<u32, Duration> {
		self.refill(now);
		if self.tokens > 0 {
			self.tokens -= 1;
			return Ok(self.tokens);
		}
		let last = self.last_refill.unwrap_or(now);
		Err(self.refill_every.saturating_sub(now.saturating_duration_since(last)))
	}

	/// Tokens available right now, after accounting for the refill.
	pub fn tokens(&mut self, now: Instant) -> u32 {
		self.refill(now);
		self.tokens
	}
}

/// Which of the two budgets a refusal came from, for logging and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
	SideBranch,
	SeedFill,
}

/// Prometheus counters for the two budgets, registered when the node has a
/// registry.
struct Metrics {
	side_branch_charged: Counter<U64>,
	side_branch_refused: Counter<U64>,
	seed_fill_charged: Counter<U64>,
	seed_fill_refused: Counter<U64>,
}

impl Metrics {
	fn register(registry: &Registry) -> Result<Self, PrometheusError> {
		Ok(Self {
			side_branch_charged: register(
				Counter::new(
					"qnero_pow_side_branch_charged_total",
					"Cheap side-branch blocks admitted against the side-branch budget",
				)?,
				registry,
			)?,
			side_branch_refused: register(
				Counter::new(
					"qnero_pow_side_branch_refused_total",
					"Side-branch blocks refused because the side-branch budget was spent",
				)?,
				registry,
			)?,
			seed_fill_charged: register(
				Counter::new(
					"qnero_pow_seed_fill_charged_total",
					"RandomX cache fills admitted against the seed-fill budget",
				)?,
				registry,
			)?,
			seed_fill_refused: register(
				Counter::new(
					"qnero_pow_seed_fill_refused_total",
					"Blocks refused because they needed a cache fill and the seed-fill budget was spent",
				)?,
				registry,
			)?,
		})
	}
}

/// One warning line per budget per minute, with the count of what it hid.
#[derive(Default)]
struct Throttle {
	window_started: Option<Instant>,
	suppressed: u64,
}

const WARN_WINDOW: Duration = Duration::from_secs(60);

/// The two budgets, the cached tip difficulty and the log throttles.
///
/// `None` in either bucket means unlimited, which is what an operator asks
/// for with a budget of 0 blocks or fills per hour. The capacities are fixed;
/// the operator sets only the refill rate.
pub struct AdmissionBudgets {
	side_branch: Mutex<Option<TokenBucket>>,
	seed_fill: Mutex<Option<TokenBucket>>,
	tip_difficulty: Mutex<Option<(H256, U512)>>,
	throttles: Mutex<[Throttle; 2]>,
	metrics: Option<Metrics>,
}

impl AdmissionBudgets {
	/// Budgets at the defaults, with counters on `registry` when there is one.
	pub fn new(registry: Option<&Registry>) -> std::sync::Arc<Self> {
		let metrics = registry.and_then(|registry| match Metrics::register(registry) {
			Ok(metrics) => Some(metrics),
			Err(error) => {
				log::warn!(
					target: crate::LOG_TARGET,
					"Admission budget metrics not registered: {error}"
				);
				None
			},
		});
		let budgets = Self {
			side_branch: Mutex::new(None),
			seed_fill: Mutex::new(None),
			tip_difficulty: Mutex::new(None),
			throttles: Mutex::new([Throttle::default(), Throttle::default()]),
			metrics,
		};
		budgets.configure(DEFAULT_SIDE_BRANCH_BLOCKS_PER_HOUR, DEFAULT_SEED_FILLS_PER_HOUR);
		std::sync::Arc::new(budgets)
	}

	/// Set both refill rates. Zero means unlimited.
	pub fn configure(&self, side_branch_blocks_per_hour: u32, seed_fills_per_hour: u32) {
		*self.side_branch.lock() = bucket(SIDE_BRANCH_BUDGET_CAPACITY, side_branch_blocks_per_hour);
		*self.seed_fill.lock() = bucket(SEED_FILL_BUDGET_CAPACITY, seed_fills_per_hour);
	}

	/// Classify a block, reading the tip's difficulty at most once per tip.
	pub fn classify<V: TipView + ?Sized>(
		&self,
		view: &V,
		parent_hash: H256,
		difficulty: U512,
	) -> Result<SideBranchClass, String> {
		let cached = CachedTip { inner: view, cache: &self.tip_difficulty };
		classify_side_branch(&cached, parent_hash, difficulty, SIDE_BRANCH_DIFFICULTY_FRACTION)
	}

	/// Charge the side-branch budget for a block of this class.
	///
	/// `Ok(None)` is a free block, `Ok(Some(n))` a charged one with `n` tokens
	/// left, `Err(d)` a refusal with `d` until the next token.
	pub fn charge_side_branch(
		&self,
		class: &SideBranchClass,
		now: Instant,
	) -> Result<Option<u32>, Duration> {
		if !matches!(class, SideBranchClass::Cheap { .. }) {
			return Ok(None);
		}
		let mut guard = self.side_branch.lock();
		let Some(bucket) = guard.as_mut() else { return Ok(None) };
		match bucket.try_take(now) {
			Ok(left) => {
				if let Some(metrics) = &self.metrics {
					metrics.side_branch_charged.inc();
				}
				Ok(Some(left))
			},
			Err(retry) => {
				if let Some(metrics) = &self.metrics {
					metrics.side_branch_refused.inc();
				}
				Err(retry)
			},
		}
	}

	/// Charge the seed-fill budget for one fill of a non-resident seed.
	pub fn charge_seed_fill(&self, now: Instant) -> Result<Option<u32>, Duration> {
		let mut guard = self.seed_fill.lock();
		let Some(bucket) = guard.as_mut() else { return Ok(None) };
		match bucket.try_take(now) {
			Ok(left) => {
				if let Some(metrics) = &self.metrics {
					metrics.seed_fill_charged.inc();
				}
				Ok(Some(left))
			},
			Err(retry) => {
				if let Some(metrics) = &self.metrics {
					metrics.seed_fill_refused.inc();
				}
				Err(retry)
			},
		}
	}

	/// Whether a refusal from `budget` should be logged now, and how many were
	/// suppressed since the last line. One line per budget per minute.
	pub fn should_warn(&self, budget: Budget, now: Instant) -> Option<u64> {
		let mut throttles = self.throttles.lock();
		let throttle = &mut throttles[match budget {
			Budget::SideBranch => 0,
			Budget::SeedFill => 1,
		}];
		match throttle.window_started {
			Some(started) if now.saturating_duration_since(started) < WARN_WINDOW => {
				throttle.suppressed += 1;
				None
			},
			_ => {
				let suppressed = std::mem::take(&mut throttle.suppressed);
				throttle.window_started = Some(now);
				Some(suppressed)
			},
		}
	}
}

fn bucket(capacity: u32, per_hour: u32) -> Option<TokenBucket> {
	if per_hour == 0 {
		return None;
	}
	let refill_every = Duration::from_secs(3600) / per_hour;
	Some(TokenBucket::new(capacity, refill_every))
}

/// A view that remembers the tip's difficulty for as long as the tip stays.
struct CachedTip<'a, V: TipView + ?Sized> {
	inner: &'a V,
	cache: &'a Mutex<Option<(H256, U512)>>,
}

impl<V: TipView + ?Sized> TipView for CachedTip<'_, V> {
	fn tip(&self) -> (H256, u64) {
		self.inner.tip()
	}

	fn difficulty_after(&self, hash: H256) -> Result<U512, String> {
		if let Some((cached_hash, difficulty)) = *self.cache.lock() {
			if cached_hash == hash {
				return Ok(difficulty);
			}
		}
		let difficulty = self.inner.difficulty_after(hash)?;
		*self.cache.lock() = Some((hash, difficulty));
		Ok(difficulty)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{cell::Cell, collections::HashMap};

	struct FakeTip {
		tip: (H256, u64),
		difficulties: HashMap<H256, U512>,
		calls: Cell<usize>,
	}

	impl FakeTip {
		fn new(tip: H256, tip_difficulty: u64) -> Self {
			let mut difficulties = HashMap::new();
			difficulties.insert(tip, U512::from(tip_difficulty));
			Self { tip: (tip, 10_000), difficulties, calls: Cell::new(0) }
		}
	}

	impl TipView for FakeTip {
		fn tip(&self) -> (H256, u64) {
			self.tip
		}

		fn difficulty_after(&self, hash: H256) -> Result<U512, String> {
			self.calls.set(self.calls.get() + 1);
			self.difficulties
				.get(&hash)
				.copied()
				.ok_or_else(|| format!("no difficulty for {hash:?}"))
		}
	}

	const TIP: H256 = H256([0x11u8; 32]);
	const OTHER: H256 = H256([0x22u8; 32]);

	fn d(value: u64) -> U512 {
		U512::from(value)
	}

	#[test]
	fn the_fraction_rule_is_a_pure_comparison() {
		assert!(is_difficulty_admissible(d(5000), d(5000), 8));
		// The boundary admits: 625 * 8 == 5000.
		assert!(is_difficulty_admissible(d(625), d(5000), 8));
		assert!(!is_difficulty_admissible(d(624), d(5000), 8));
		assert!(!is_difficulty_admissible(d(0), d(5000), 8));
		// The 128 floor against a small canonical.
		assert!(is_difficulty_admissible(d(128), d(1024), 8));
		assert!(!is_difficulty_admissible(d(128), d(1025), 8));
		// Saturating, never a panic.
		assert!(is_difficulty_admissible(U512::MAX, d(1), 8));
		// A zero reference admits everything.
		assert!(is_difficulty_admissible(d(1), d(0), 8));
		// Asymmetry: a branch at or above the reference is admissible at every
		// fraction of one or more.
		for fraction in 1..=64u64 {
			assert!(is_difficulty_admissible(d(5000), d(5000), fraction));
			assert!(is_difficulty_admissible(d(5001), d(5000), fraction));
		}
	}

	#[test]
	fn a_token_bucket_bursts_then_refuses_then_refills() {
		let t0 = Instant::now();
		let mut bucket = TokenBucket::new(2, Duration::from_secs(4));
		assert_eq!(bucket.try_take(t0), Ok(1));
		assert_eq!(bucket.try_take(t0), Ok(0));
		assert_eq!(bucket.try_take(t0), Err(Duration::from_secs(4)));
		assert_eq!(bucket.try_take(t0 + Duration::from_secs(4)), Ok(0));
		assert_eq!(bucket.try_take(t0 + Duration::from_secs(5)), Err(Duration::from_secs(3)));
		// A long idle refills to capacity and no further.
		assert_eq!(bucket.tokens(t0 + Duration::from_secs(1000)), 2);
	}

	#[test]
	fn classification_reads_the_tip_difficulty_only_off_the_tip_path() {
		let view = FakeTip::new(TIP, 5000);
		assert_eq!(classify_side_branch(&view, TIP, d(1), 8), Ok(SideBranchClass::ExtendsTip));
		assert_eq!(view.calls.get(), 0, "a block on the tip costs no runtime call");

		assert_eq!(
			classify_side_branch(&view, OTHER, d(625), 8),
			Ok(SideBranchClass::WithinFraction { tip_difficulty: d(5000) })
		);
		assert_eq!(
			classify_side_branch(&view, OTHER, d(624), 8),
			Ok(SideBranchClass::Cheap { tip_difficulty: d(5000) })
		);
		// A branch above the tip's difficulty is within the fraction too.
		assert_eq!(
			classify_side_branch(&view, OTHER, d(9000), 8),
			Ok(SideBranchClass::WithinFraction { tip_difficulty: d(5000) })
		);
	}

	#[test]
	fn the_budgets_cache_the_tip_difficulty_per_tip() {
		let budgets = AdmissionBudgets::new(None);
		let view = FakeTip::new(TIP, 5000);
		for _ in 0..5 {
			budgets.classify(&view, OTHER, d(100)).expect("classified");
		}
		assert_eq!(view.calls.get(), 1, "one runtime call per tip, whatever the block count");
	}

	#[test]
	fn a_cheap_side_branch_block_is_charged_and_refused_when_the_budget_is_spent() {
		let budgets = AdmissionBudgets::new(None);
		*budgets.side_branch.lock() = Some(TokenBucket::new(2, Duration::from_secs(4)));
		let now = Instant::now();
		let cheap = SideBranchClass::Cheap { tip_difficulty: d(5000) };
		assert_eq!(budgets.charge_side_branch(&cheap, now), Ok(Some(1)));
		assert_eq!(budgets.charge_side_branch(&cheap, now), Ok(Some(0)));
		assert!(budgets.charge_side_branch(&cheap, now).is_err());
		// Free classes are never charged, spent bucket or not.
		let within = SideBranchClass::WithinFraction { tip_difficulty: d(5000) };
		assert_eq!(budgets.charge_side_branch(&within, now), Ok(None));
		assert_eq!(budgets.charge_side_branch(&SideBranchClass::ExtendsTip, now), Ok(None));
		// And the refill admits again.
		assert_eq!(budgets.charge_side_branch(&cheap, now + Duration::from_secs(4)), Ok(Some(0)));
	}

	#[test]
	fn a_budget_of_zero_per_hour_is_unlimited() {
		let budgets = AdmissionBudgets::new(None);
		budgets.configure(0, 0);
		let now = Instant::now();
		let cheap = SideBranchClass::Cheap { tip_difficulty: d(5000) };
		for _ in 0..10_000 {
			assert_eq!(budgets.charge_side_branch(&cheap, now), Ok(None));
			assert_eq!(budgets.charge_seed_fill(now), Ok(None));
		}
	}

	#[test]
	fn the_defaults_are_the_documented_rates() {
		let budgets = AdmissionBudgets::new(None);
		let now = Instant::now();
		let side = budgets.side_branch.lock().clone().expect("a side-branch bucket");
		assert_eq!(side.capacity, SIDE_BRANCH_BUDGET_CAPACITY);
		assert_eq!(side.refill_every, Duration::from_secs(4));
		let fills = budgets.seed_fill.lock().clone().expect("a seed-fill bucket");
		assert_eq!(fills.capacity, SEED_FILL_BUDGET_CAPACITY);
		assert_eq!(fills.refill_every, Duration::from_secs(150));
		// Four fills in a burst, then a wait.
		for left in (0..4).rev() {
			assert_eq!(budgets.charge_seed_fill(now), Ok(Some(left)));
		}
		assert!(budgets.charge_seed_fill(now).is_err());
	}

	/// The honest migration case the rule was shaped around: a chain whose
	/// hashrate left and came back carries a prefix of cheap blocks. They are
	/// charged, and admitted while tokens remain; none is refused outright.
	#[test]
	fn a_migrated_chains_cheap_prefix_is_charged_and_admitted() {
		let budgets = AdmissionBudgets::new(None);
		let view = FakeTip::new(TIP, 5000);
		let now = Instant::now();
		let mut charged = 0;
		for difficulty in [4010u64, 2030, 600, 128] {
			let class = budgets.classify(&view, OTHER, d(difficulty)).expect("classified");
			match budgets.charge_side_branch(&class, now) {
				Ok(None) => {
					assert!(difficulty * 8 >= 5000, "{difficulty} should have been charged")
				},
				Ok(Some(_)) => {
					assert!(difficulty * 8 < 5000, "{difficulty} should have been free");
					charged += 1;
				},
				Err(_) => panic!("nothing is refused while the bucket has tokens"),
			}
		}
		assert_eq!(charged, 2);
	}

	#[test]
	fn a_refusal_is_logged_once_a_minute_per_budget() {
		let budgets = AdmissionBudgets::new(None);
		let t0 = Instant::now();
		assert_eq!(budgets.should_warn(Budget::SideBranch, t0), Some(0));
		assert_eq!(budgets.should_warn(Budget::SideBranch, t0 + Duration::from_secs(1)), None);
		assert_eq!(budgets.should_warn(Budget::SideBranch, t0 + Duration::from_secs(2)), None);
		// The other budget has its own window.
		assert_eq!(budgets.should_warn(Budget::SeedFill, t0 + Duration::from_secs(2)), Some(0));
		assert_eq!(budgets.should_warn(Budget::SideBranch, t0 + Duration::from_secs(61)), Some(2));
	}
}
