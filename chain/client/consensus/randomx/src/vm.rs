//! RandomX itself: caches, VMs, and the one function that turns a blob into a
//! hash.
//!
//! Everything here is **light mode**. The node allocates a 256 MiB Argon2d
//! cache per seed and no 2 GiB dataset, because it hashes once per block it
//! verifies and once per share it is offered, and a dataset would cost more
//! memory than the rest of the node. A rig does the opposite: xmrig builds the
//! dataset and runs an order of magnitude faster. Neither choice changes the
//! hash, only the speed of producing it.
//!
//! The bindings are `randomx-rs` (Tari), which vendors tevador's `librandomx`
//! and builds it with cmake. The vendored tree carries stock
//! `configuration.h`, which is what makes these hashes `rx/0`: bit-identical to
//! what a stock xmrig computes. There is no production-grade pure-Rust
//! RandomX to use instead, and the reason is structural rather than one of
//! effort: the VM sets the hardware floating-point rounding mode per program
//! (the `CFROUND` instruction writes MXCSR or FPCR) and Rust has no stable way
//! to do that. Cuprate, the Rust Monero node, binds to the same C library.

use parking_lot::Mutex;
use randomx_rs::{RandomXCache, RandomXError, RandomXFlag, RandomXVM};
use std::{
	collections::VecDeque,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
};

/// Length of a RandomX hash.
pub const RANDOMX_HASH_LEN: usize = 32;

/// Default number of unpinned seed caches held at once.
///
/// The engine keeps two kinds of cache. Two **pinned** slots hold the seed the
/// node hashes under now and the one the next epoch will use; they are named
/// by [`RandomxEngine::pin_seeds`], never evicted, and they are what the miner,
/// the stratum server and every block extending the tip hash under. Beside
/// them an LRU of this many entries holds historical and side-branch seeds: a
/// block from the previous epoch arriving late, or a branch that carries its
/// own block at a seed height and therefore its own seed hash.
///
/// Each cache is 256 MiB, so the lookup bound is `(2 + DEFAULT_MAX_CACHES) *
/// 256 MiB`, 1 GiB at these defaults. Resident memory can exceed that bound:
/// an idle or leased VM keeps an `Arc` to the cache it was last keyed to, so a
/// VM pointing at an evicted seed holds that cache alive until it is re-keyed.
/// The practical worst case on the seed node is about 1.25 to 1.5 GiB with
/// `max_idle_vms` at the mining thread count plus four.
///
/// Before the pinned slots existed, a peer naming a header on any old epoch
/// could push the live mining seed out of a two-entry LRU and make the miner
/// pay the 256 MiB Argon2d fill again on its next template. Pinning closes
/// that; the fills a peer can still force land in the LRU and are budgeted by
/// the verifier (`AdmissionBudgets` in the crate root).
pub const DEFAULT_MAX_CACHES: usize = 2;

/// A RandomX cache, shareable across threads.
///
/// # Safety
///
/// `randomx_init_cache` runs once, in `RandomXCache::new`, before the value is
/// ever published. After that the cache is read-only for the C library: many
/// VMs on many threads share one cache, which is what `randomx_create_vm`
/// exists to do and what every miner does. Nothing here hands out a `&mut` to
/// the inner pointer, so there is no interior mutation to race on.
struct SharedCache(RandomXCache);

// SAFETY: see the type's documentation. The cache is immutable after
// construction and the C library documents concurrent read access.
unsafe impl Send for SharedCache {}
// SAFETY: as above.
unsafe impl Sync for SharedCache {}

/// A RandomX VM, movable between threads.
///
/// # Safety
///
/// A VM owns a private scratchpad and holds no thread-local state, so it may be
/// moved from one thread to another; every stratum miner does exactly this when
/// it hands a VM to a worker. What it may not do is run on two threads at once,
/// and that is what the `Mutex` around each pooled VM prevents: a VM is only
/// ever reachable through a lease that owns it exclusively.
struct OwnedVm(RandomXVM);

// SAFETY: see the type's documentation. Exclusive ownership is enforced by the
// pool: a VM is either idle inside the pool or owned by exactly one lease.
unsafe impl Send for OwnedVm {}

/// What went wrong.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EngineError {
	#[error("RandomX error: {0}")]
	RandomX(String),
	#[error("RandomX returned a {0}-byte hash, expected {RANDOMX_HASH_LEN}")]
	HashLength(usize),
}

impl From<RandomXError> for EngineError {
	fn from(error: RandomXError) -> Self {
		Self::RandomX(error.to_string())
	}
}

struct PooledVm {
	vm: OwnedVm,
	seed: [u8; 32],
}

/// One of the two identities the node hashes under: the slot is named before
/// it is filled, so a pin never costs a fill, and a fill for a pinned identity
/// lands in its slot, never in the LRU.
struct PinnedSlot {
	seed: [u8; 32],
	cache: Option<Arc<SharedCache>>,
}

/// Every cache the engine can look up, under one lock so a pin and a fill
/// cannot race each other.
#[derive(Default)]
struct CacheTable {
	pinned: [Option<PinnedSlot>; 2],
	/// Most recently used at the back; the front is what an eviction takes.
	lru: VecDeque<([u8; 32], Arc<SharedCache>)>,
}

impl CacheTable {
	fn pinned_lookup(&self, seed: &[u8; 32]) -> Option<Arc<SharedCache>> {
		self.pinned
			.iter()
			.flatten()
			.find(|slot| &slot.seed == seed)
			.and_then(|slot| slot.cache.clone())
	}

	fn is_pinned_identity(&self, seed: &[u8; 32]) -> bool {
		self.pinned.iter().flatten().any(|slot| &slot.seed == seed)
	}

	/// Take the LRU entry for `seed` out of the queue, if it is there.
	fn take_from_lru(&mut self, seed: &[u8; 32]) -> Option<Arc<SharedCache>> {
		let index = self.lru.iter().position(|(key, _)| key == seed)?;
		self.lru.remove(index).map(|(_, cache)| cache)
	}

	fn touch_lru(&mut self, seed: &[u8; 32]) -> Option<Arc<SharedCache>> {
		let cache = self.take_from_lru(seed)?;
		self.lru.push_back((*seed, cache.clone()));
		Some(cache)
	}

	fn push_lru(&mut self, seed: [u8; 32], cache: Arc<SharedCache>, max_caches: usize) {
		self.lru.push_back((seed, cache));
		while self.lru.len() > max_caches {
			self.lru.pop_front();
		}
	}

	fn resident(&self) -> usize {
		self.pinned.iter().flatten().filter(|slot| slot.cache.is_some()).count() + self.lru.len()
	}
}

/// The node's RandomX instance: seed caches, a VM pool, and the hash.
pub struct RandomxEngine {
	flags: RandomXFlag,
	caches: Mutex<CacheTable>,
	cache_build: Mutex<()>,
	idle: Mutex<Vec<PooledVm>>,
	max_caches: usize,
	max_idle_vms: AtomicUsize,
	cache_initialisations: AtomicUsize,
	fill_counter: Mutex<Option<prometheus_endpoint::Counter<prometheus_endpoint::U64>>>,
}

impl RandomxEngine {
	/// A light-mode engine holding at most `max_idle_vms` VMs between uses.
	pub fn light(max_idle_vms: usize) -> Arc<Self> {
		Self::with_settings(max_idle_vms, DEFAULT_MAX_CACHES)
	}

	/// A light-mode engine with both pool sizes named. `max_caches` is the
	/// depth of the unpinned LRU; the two pinned slots come on top of it.
	pub fn with_settings(max_idle_vms: usize, max_caches: usize) -> Arc<Self> {
		// `get_recommended_flags` detects hardware AES, the JIT and the Argon2
		// variants, and deliberately never returns FULL_MEM: that is the
		// dataset flag, and this engine is light mode. None of these flags
		// change the hash.
		let flags = RandomXFlag::get_recommended_flags();
		Arc::new(Self {
			flags,
			caches: Mutex::new(CacheTable::default()),
			cache_build: Mutex::new(()),
			idle: Mutex::new(Vec::new()),
			max_caches: max_caches.max(1),
			max_idle_vms: AtomicUsize::new(max_idle_vms.max(1)),
			cache_initialisations: AtomicUsize::new(0),
			fill_counter: Mutex::new(None),
		})
	}

	/// The flags this engine runs with, for logging.
	pub fn flags(&self) -> RandomXFlag {
		self.flags
	}

	/// Make sure the pool keeps at least `at_least` VMs between uses.
	///
	/// The pool exists to stop VM churn: every VM it cannot hold is a
	/// `randomx_create_vm` (a 2 MiB scratchpad, and with the JIT a fresh
	/// executable code buffer) and a `randomx_destroy_vm` on every round. A node
	/// mining on more threads than the pool holds pays that on every batch, so
	/// the caller that knows the thread count raises the floor.
	pub fn reserve_idle_vms(&self, at_least: usize) {
		self.max_idle_vms.fetch_max(at_least.max(1), Ordering::Relaxed);
	}

	/// How many VMs the pool keeps between uses.
	pub fn max_idle_vms(&self) -> usize {
		self.max_idle_vms.load(Ordering::Relaxed)
	}

	/// How many VMs are idle in the pool right now.
	pub fn idle_vms(&self) -> usize {
		self.idle.lock().len()
	}

	/// How many Argon2d cache fills have happened, which is how many times a
	/// seed this engine did not hold was asked for.
	pub fn cache_initialisations(&self) -> usize {
		self.cache_initialisations.load(Ordering::Relaxed)
	}

	/// Count every cache fill on this Prometheus counter as well.
	pub fn set_fill_counter(
		&self,
		counter: prometheus_endpoint::Counter<prometheus_endpoint::U64>,
	) {
		*self.fill_counter.lock() = Some(counter);
	}

	/// Name the two seeds the node hashes under now and next.
	///
	/// This is O(1) and never fills: a slot can be named before its cache
	/// exists, and the fill happens on the first hash under it (or on
	/// [`Self::warm`]) and lands in the slot. A cache already resident in the
	/// LRU under one of these seeds moves into its slot; a previously pinned
	/// cache that is neither `live` nor `next` is demoted to the back of the
	/// LRU, evicting the LRU's oldest past `max_caches`, because at an epoch
	/// turn the old live seed is exactly the one late blocks still arrive
	/// under. `live == next` holds one slot.
	pub fn pin_seeds(&self, live: [u8; 32], next: [u8; 32]) {
		let wanted: Vec<[u8; 32]> = if live == next { vec![live] } else { vec![live, next] };
		let mut table = self.caches.lock();
		let already =
			[table.pinned[0].as_ref().map(|s| s.seed), table.pinned[1].as_ref().map(|s| s.seed)];
		if already.iter().flatten().count() == wanted.len() &&
			wanted.iter().all(|seed| already.contains(&Some(*seed)))
		{
			return;
		}

		let mut slots = std::mem::take(&mut table.pinned);
		// Keep what is still wanted, set aside what is not.
		let mut kept: Vec<PinnedSlot> = Vec::with_capacity(2);
		let mut demoted: Vec<PinnedSlot> = Vec::with_capacity(2);
		for slot in slots.iter_mut().filter_map(Option::take) {
			if wanted.contains(&slot.seed) {
				kept.push(slot);
			} else {
				demoted.push(slot);
			}
		}
		// Promote first: a wanted seed already resident in the LRU moves into
		// its slot before the demotions below can push it out of a full LRU.
		let mut next_slots: [Option<PinnedSlot>; 2] = [None, None];
		for (index, seed) in wanted.iter().enumerate() {
			let slot = match kept.iter().position(|slot| &slot.seed == seed) {
				Some(position) => kept.swap_remove(position),
				None => PinnedSlot { seed: *seed, cache: table.take_from_lru(seed) },
			};
			next_slots[index] = Some(slot);
		}
		table.pinned = next_slots;
		// Then demote: the old live seed lands at the back of the LRU, where
		// the late blocks still arriving under it will find it.
		let max = self.max_caches;
		for slot in demoted {
			if let Some(cache) = slot.cache {
				table.push_lru(slot.seed, cache, max);
			}
		}
		log::debug!(
			target: crate::LOG_TARGET,
			"RandomX: pinned seeds live {} next {} ({} cache(s) resident)",
			hex::encode(live),
			hex::encode(next),
			table.resident(),
		);
	}

	/// Fill the cache for `seed` now if it is absent, so a later hash under it
	/// pays nothing. Blocks for the Argon2d fill; call it off the critical
	/// path.
	pub fn warm(&self, seed: [u8; 32]) -> Result<(), EngineError> {
		self.cache_for(&seed).map(|_| ())
	}

	/// Whether `seed` is one of the two pinned identities, filled or not.
	pub fn is_pinned(&self, seed: &[u8; 32]) -> bool {
		self.caches.lock().is_pinned_identity(seed)
	}

	/// Whether a hash under `seed` would find its cache already built.
	pub fn is_resident(&self, seed: &[u8; 32]) -> bool {
		let table = self.caches.lock();
		table.pinned_lookup(seed).is_some() || table.lru.iter().any(|(key, _)| key == seed)
	}

	/// The two pinned identities, filled or not.
	pub fn pinned_seeds(&self) -> [Option<[u8; 32]>; 2] {
		let table = self.caches.lock();
		[table.pinned[0].as_ref().map(|s| s.seed), table.pinned[1].as_ref().map(|s| s.seed)]
	}

	/// How many caches are resident right now: filled pinned slots plus the
	/// LRU. Never more than `2 + max_caches`.
	pub fn resident_caches(&self) -> usize {
		self.caches.lock().resident()
	}

	fn cache_for(&self, seed: &[u8; 32]) -> Result<Arc<SharedCache>, EngineError> {
		{
			let mut table = self.caches.lock();
			if let Some(cache) = table.pinned_lookup(seed) {
				return Ok(cache);
			}
			if let Some(cache) = table.touch_lru(seed) {
				return Ok(cache);
			}
		}

		// Serialize cold-cache construction and check again after waiting. A
		// historical branch may use an older seed, and concurrent requests for
		// it must share one 256 MiB fill. Cached seeds remain available while
		// this lock is held because the cache lookup uses its own short lock.
		let _build = self.cache_build.lock();
		let pinned_identity = {
			let mut table = self.caches.lock();
			if let Some(cache) = table.pinned_lookup(seed) {
				return Ok(cache);
			}
			if let Some(cache) = table.touch_lru(seed) {
				return Ok(cache);
			}
			table.is_pinned_identity(seed)
		};
		log::info!(
			target: crate::LOG_TARGET,
			"⛏️ RandomX: initialising the seed cache for {} (light mode, 256 MiB, {})",
			hex::encode(seed),
			if pinned_identity { "pinned" } else { "historical" },
		);
		let cache = Arc::new(SharedCache(RandomXCache::new(self.flags, &seed[..])?));
		self.cache_initialisations.fetch_add(1, Ordering::Relaxed);
		if let Some(counter) = self.fill_counter.lock().as_ref() {
			counter.inc();
		}

		let mut table = self.caches.lock();
		// The identity may have been pinned or unpinned while the fill ran, so
		// the slot is chosen from the table as it is now.
		if let Some(slot) = table.pinned.iter_mut().flatten().find(|slot| &slot.seed == seed) {
			slot.cache = Some(cache.clone());
		} else {
			let max = self.max_caches;
			table.push_lru(*seed, cache.clone(), max);
		}
		Ok(cache)
	}

	/// Take a VM keyed to `seed`, building or re-keying one as needed.
	///
	/// The lease owns the VM until it is dropped, which is what keeps a VM off
	/// two threads at once.
	pub fn acquire(self: &Arc<Self>, seed: [u8; 32]) -> Result<VmLease, EngineError> {
		let pooled = self.idle.lock().pop();
		let vm = match pooled {
			Some(pooled) if pooled.seed == seed => pooled.vm,
			Some(mut pooled) => {
				let cache = self.cache_for(&seed)?;
				// `reinit_cache` re-points an existing VM at another seed,
				// which is cheaper than building a VM from scratch.
				pooled.vm.0.reinit_cache(cache.0.clone())?;
				pooled.vm
			},
			None => {
				let cache = self.cache_for(&seed)?;
				OwnedVm(RandomXVM::new(self.flags, Some(cache.0.clone()), None)?)
			},
		};
		Ok(VmLease { engine: self.clone(), vm: Some(vm), seed })
	}

	/// Hash one input under one seed, taking and returning a pooled VM.
	pub fn hash(
		self: &Arc<Self>,
		seed: [u8; 32],
		input: &[u8],
	) -> Result<[u8; RANDOMX_HASH_LEN], EngineError> {
		self.acquire(seed)?.hash(input)
	}

	fn release(&self, vm: OwnedVm, seed: [u8; 32]) {
		let mut idle = self.idle.lock();
		if idle.len() < self.max_idle_vms() {
			idle.push(PooledVm { vm, seed });
		}
	}
}

/// A VM checked out of the pool. Returned on drop.
pub struct VmLease {
	engine: Arc<RandomxEngine>,
	vm: Option<OwnedVm>,
	seed: [u8; 32],
}

impl VmLease {
	/// The seed this VM is keyed to.
	pub fn seed(&self) -> [u8; 32] {
		self.seed
	}

	/// Hash one input.
	pub fn hash(&self, input: &[u8]) -> Result<[u8; RANDOMX_HASH_LEN], EngineError> {
		let vm = self.vm.as_ref().expect("the VM is only taken in Drop; qed");
		let hash = vm.0.calculate_hash(input)?;
		let len = hash.len();
		hash.try_into().map_err(|_| EngineError::HashLength(len))
	}
}

impl Drop for VmLease {
	fn drop(&mut self) {
		if let Some(vm) = self.vm.take() {
			self.engine.release(vm, self.seed);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The known-answer vectors from `librandomx`'s own `src/tests/tests.cpp`.
	/// They are what "this is `rx/0`" means: a stock xmrig computes these, so a
	/// node that computes these accepts a stock xmrig's shares.
	const KNOWN_ANSWERS: &[(&[u8], &[u8], &str)] = &[
		(
			b"test key 000",
			b"This is a test",
			"639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
		),
		(
			b"test key 000",
			b"Lorem ipsum dolor sit amet",
			"300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
		),
		(
			b"test key 000",
			b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
			"c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
		),
		(
			b"test key 001",
			b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
			"e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
		),
	];

	fn seed_from(key: &[u8]) -> [u8; 32] {
		let mut seed = [0u8; 32];
		seed[..key.len()].copy_from_slice(key);
		seed
	}

	/// One engine, one cache per key, four hashes. Light mode throughout, which
	/// is what keeps this test a second rather than a minute.
	#[test]
	fn it_computes_the_librandomx_known_answers() {
		let engine = RandomxEngine::light(2);
		for (key, input, expected) in KNOWN_ANSWERS {
			// The cache key here is the raw librandomx test key, because that is
			// what the published vectors are defined over. A RandomX key is
			// variable length, so padding one of these to 32 bytes builds a
			// different cache and moves every answer below. The 32-byte seed a
			// block hash occupies, which is the only thing the node ever keys a
			// cache with, is what `the_engine_passes_the_seed_to_randomx_unchanged`
			// covers.
			let cache = RandomXCache::new(engine.flags(), key).expect("cache");
			let vm = RandomXVM::new(engine.flags(), Some(cache), None).expect("vm");
			let hash = vm.calculate_hash(input).expect("hash");
			assert_eq!(hex::encode(hash), *expected, "key {:?}", String::from_utf8_lossy(key));
		}
	}

	/// The vectors above go through the raw bindings; the node never does. This
	/// crosses the boundary: the same 32-byte seed and the same input, once
	/// through `RandomXCache::new` directly and once through `engine.hash`, must
	/// be the same bytes.
	///
	/// Without it, a change inside `cache_for` that domain-separated, truncated
	/// or byte-swapped the seed would leave every vector green and every
	/// engine-against-itself test green, while the node quietly stopped computing
	/// what a stock xmrig computes. That is a chain split with no failing test.
	#[test]
	fn the_engine_passes_the_seed_to_randomx_unchanged() {
		let engine = RandomxEngine::light(1);
		let seed = seed_from(b"qnero seed a");
		let input = b"the blob the node hashes";

		let cache = RandomXCache::new(engine.flags(), &seed[..]).expect("cache");
		let vm = RandomXVM::new(engine.flags(), Some(cache), None).expect("vm");
		let direct = vm.calculate_hash(input).expect("hash");

		assert_eq!(engine.hash(seed, input).expect("engine hash").to_vec(), direct);
	}

	#[test]
	fn the_same_seed_and_input_hash_the_same_through_the_pool() {
		let engine = RandomxEngine::light(2);
		let seed = seed_from(b"qnero seed a");
		let first = engine.hash(seed, b"blob").expect("first");
		let second = engine.hash(seed, b"blob").expect("second");
		assert_eq!(first, second);
		// One cache, whatever the pool did with VMs.
		assert_eq!(engine.cache_initialisations(), 1);
	}

	#[test]
	fn a_different_seed_is_a_different_hash_and_a_second_cache() {
		let engine = RandomxEngine::light(1);
		let a = engine.hash(seed_from(b"qnero seed a"), b"blob").expect("a");
		let b = engine.hash(seed_from(b"qnero seed b"), b"blob").expect("b");
		assert_ne!(a, b);
		assert_eq!(engine.cache_initialisations(), 2);
	}

	#[test]
	fn a_lease_hashes_many_inputs_without_rebuilding_the_cache() {
		let engine = RandomxEngine::light(1);
		let seed = seed_from(b"qnero seed a");
		let lease = engine.acquire(seed).expect("lease");
		assert_eq!(lease.seed(), seed);
		let mut seen = std::collections::HashSet::new();
		for nonce in 0u32..4 {
			seen.insert(lease.hash(&nonce.to_le_bytes()).expect("hash"));
		}
		assert_eq!(seen.len(), 4);
		assert_eq!(engine.cache_initialisations(), 1);
	}

	/// The pool has to be at least as deep as the number of threads leasing from
	/// it, or every round past the pool's depth creates and destroys a VM.
	#[test]
	fn the_pool_depth_can_be_raised_to_the_thread_count() {
		let engine = RandomxEngine::light(8);
		assert_eq!(engine.max_idle_vms(), 8);
		engine.reserve_idle_vms(20);
		assert_eq!(engine.max_idle_vms(), 20);
		// It is a floor, so a smaller reservation never shrinks the pool.
		engine.reserve_idle_vms(4);
		assert_eq!(engine.max_idle_vms(), 20);

		// And the depth is what `release` honours: ten leases returned at once
		// all stay pooled.
		let seed = seed_from(b"qnero seed a");
		let leases: Vec<_> = (0..10).map(|_| engine.acquire(seed).expect("lease")).collect();
		drop(leases);
		assert_eq!(engine.idle_vms(), 10);
	}

	#[test]
	fn returning_to_the_epoch_before_last_does_not_refill_the_cache() {
		let engine = RandomxEngine::with_settings(1, 2);
		let old = seed_from(b"epoch n-1");
		let new = seed_from(b"epoch n");
		engine.hash(old, b"blob").expect("old");
		engine.hash(new, b"blob").expect("new");
		// Both caches are still held, so a block that straddles the boundary
		// verifies without paying for Argon2d again.
		engine.hash(old, b"blob").expect("old again");
		assert_eq!(engine.cache_initialisations(), 2);
	}

	/// Naming the two seeds costs nothing: no fill, no resident cache.
	#[test]
	fn pin_seeds_does_not_initialise_a_cache() {
		let engine = RandomxEngine::with_settings(1, 2);
		let live = seed_from(b"live");
		let next = seed_from(b"next");
		engine.pin_seeds(live, next);
		assert_eq!(engine.cache_initialisations(), 0);
		assert_eq!(engine.resident_caches(), 0);
		assert_eq!(engine.pinned_seeds(), [Some(live), Some(next)]);
		assert!(!engine.is_resident(&live));
	}

	/// The point of the slots: however many historical seeds a peer names,
	/// the miner's two are never refilled.
	#[test]
	fn pinned_seeds_survive_historical_fills() {
		let engine = RandomxEngine::with_settings(1, 2);
		let live = seed_from(b"live");
		let next = seed_from(b"next");
		engine.pin_seeds(live, next);
		engine.hash(live, b"blob").expect("live");
		engine.hash(next, b"blob").expect("next");
		assert_eq!(engine.cache_initialisations(), 2);
		for index in 0..5u8 {
			engine.hash(seed_from(&[b'h', index]), b"blob").expect("historical");
		}
		assert_eq!(engine.cache_initialisations(), 7);
		engine.hash(live, b"blob").expect("live again");
		engine.hash(next, b"blob").expect("next again");
		assert_eq!(engine.cache_initialisations(), 7, "the pinned seeds were never refilled");
		assert!(engine.resident_caches() <= 4);
		assert!(engine.is_resident(&live) && engine.is_resident(&next));
	}

	/// A cache already in the LRU moves into its slot when its seed is
	/// pinned; nothing is rebuilt.
	#[test]
	fn pinning_a_resident_seed_moves_it_without_a_fill() {
		let engine = RandomxEngine::with_settings(1, 2);
		let x = seed_from(b"x");
		let y = seed_from(b"y");
		engine.hash(x, b"blob").expect("x");
		engine.pin_seeds(x, y);
		engine.hash(x, b"blob").expect("x again");
		assert_eq!(engine.cache_initialisations(), 1);
		assert_eq!(engine.resident_caches(), 1);
	}

	/// Inside an epoch the next seed is the current one, and that is one slot
	/// and one cache.
	#[test]
	fn pinning_the_same_seed_twice_holds_one_cache() {
		let engine = RandomxEngine::with_settings(1, 2);
		let a = seed_from(b"a");
		engine.pin_seeds(a, a);
		assert_eq!(engine.pinned_seeds(), [Some(a), None]);
		engine.hash(a, b"blob").expect("a");
		assert_eq!(engine.cache_initialisations(), 1);
		assert_eq!(engine.resident_caches(), 1);
	}

	/// At an epoch turn the old live seed is exactly the one late blocks still
	/// arrive under, so it is demoted into the LRU and kept.
	#[test]
	fn re_pinning_demotes_the_old_live_into_the_lru() {
		let engine = RandomxEngine::with_settings(1, 2);
		let a = seed_from(b"a");
		let b = seed_from(b"b");
		let c = seed_from(b"c");
		engine.pin_seeds(a, b);
		engine.hash(a, b"blob").expect("a");
		engine.hash(b, b"blob").expect("b");
		engine.pin_seeds(b, c);
		assert_eq!(engine.pinned_seeds(), [Some(b), Some(c)]);
		engine.hash(a, b"blob").expect("a from the LRU");
		assert_eq!(engine.cache_initialisations(), 2, "a came back from the LRU");
		assert!(engine.is_resident(&a));
		engine.hash(c, b"blob").expect("c");
		assert_eq!(engine.cache_initialisations(), 3);
		assert!(engine.resident_caches() <= 4);
	}

	/// The residual the verifier's fill budget exists for: three unpinned
	/// seeds through an LRU of two refill on every hash. The pinned seeds are
	/// untouched by it.
	#[test]
	fn three_unpinned_seeds_through_an_lru_of_two_refill_on_every_hash() {
		let engine = RandomxEngine::with_settings(1, 2);
		let a = seed_from(b"a");
		let b = seed_from(b"b");
		engine.pin_seeds(a, b);
		let x = seed_from(b"x");
		let y = seed_from(b"y");
		let z = seed_from(b"z");
		for seed in [x, y, z, x, y, z] {
			engine.hash(seed, b"blob").expect("unpinned");
		}
		assert_eq!(engine.cache_initialisations(), 6);
		engine.hash(a, b"blob").expect("a");
		assert_eq!(engine.cache_initialisations(), 7);
		assert!(engine.is_resident(&a));
		for seed in [x, y, z] {
			engine.hash(seed, b"blob").expect("unpinned");
		}
		assert!(engine.is_resident(&a), "the pinned seed outlives the churn");
	}

	/// The seed about to be pinned may already sit in the LRU, and the old
	/// pinned caches are demoted into that same LRU: promotion has to come
	/// first, or the demotions evict the very cache the pin is for.
	#[test]
	fn pinning_promotes_from_the_lru_before_demoting_into_it() {
		let engine = RandomxEngine::with_settings(1, 2);
		let a = seed_from(b"a");
		let b = seed_from(b"b");
		let c = seed_from(b"c");
		engine.pin_seeds(a, b);
		engine.hash(a, b"blob").expect("a");
		engine.hash(b, b"blob").expect("b");
		engine.hash(c, b"blob").expect("c into the LRU");
		assert_eq!(engine.cache_initialisations(), 3);
		engine.pin_seeds(c, c);
		assert_eq!(engine.pinned_seeds(), [Some(c), None]);
		assert!(engine.is_resident(&c), "c moved into its slot, the demotions did not evict it");
		engine.hash(c, b"blob").expect("c again");
		assert_eq!(engine.cache_initialisations(), 3);
		assert!(engine.resident_caches() <= 4);
	}

	#[test]
	fn a_pinned_identity_is_pinned_before_it_is_filled() {
		let engine = RandomxEngine::with_settings(1, 2);
		let live = seed_from(b"live");
		engine.pin_seeds(live, live);
		assert!(engine.is_pinned(&live));
		assert!(!engine.is_resident(&live));
		assert!(!engine.is_pinned(&seed_from(b"other")));
	}

	#[test]
	fn resident_caches_never_exceed_pinned_plus_lru() {
		let engine = RandomxEngine::with_settings(1, 2);
		let a = seed_from(b"a");
		let b = seed_from(b"b");
		engine.pin_seeds(a, b);
		for key in [b"a", b"b", b"c", b"d", b"e", b"f"] {
			engine.hash(seed_from(key), b"blob").expect("hash");
			assert!(engine.resident_caches() <= 4, "after {}", String::from_utf8_lossy(key));
		}
	}

	/// A fill for a pinned identity lands in its slot even when the identity
	/// was pinned cold, and a warm is that fill ahead of time.
	#[test]
	fn a_warm_fills_a_pinned_slot_ahead_of_the_first_hash() {
		let engine = RandomxEngine::with_settings(1, 2);
		let live = seed_from(b"live");
		let next = seed_from(b"next");
		engine.pin_seeds(live, next);
		engine.warm(next).expect("warm");
		assert_eq!(engine.cache_initialisations(), 1);
		assert!(engine.is_resident(&next));
		assert_eq!(engine.resident_caches(), 1);
		// The LRU is still empty: the fill went to the slot.
		engine.hash(seed_from(b"h1"), b"blob").expect("h1");
		engine.hash(seed_from(b"h2"), b"blob").expect("h2");
		engine.hash(seed_from(b"h3"), b"blob").expect("h3");
		assert!(engine.is_resident(&next), "three historical fills did not evict the pinned next");
		engine.hash(next, b"blob").expect("next");
		assert_eq!(engine.cache_initialisations(), 4);
	}

	#[test]
	fn concurrent_requests_share_one_cold_cache() {
		let engine = RandomxEngine::with_settings(4, 2);
		let ready = std::sync::Arc::new(std::sync::Barrier::new(4));
		let seed = seed_from(b"shared cold seed");
		let threads: Vec<_> = (0..4)
			.map(|_| {
				let engine = engine.clone();
				let ready = ready.clone();
				std::thread::spawn(move || {
					ready.wait();
					engine.hash(seed, b"same block").expect("valid hash")
				})
			})
			.collect();
		let hashes: Vec<_> = threads.into_iter().map(|thread| thread.join().unwrap()).collect();
		assert!(hashes.iter().all(|hash| hash == &hashes[0]));
		assert_eq!(engine.cache_initialisations(), 1);
	}
}
