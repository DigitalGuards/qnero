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

/// Default number of seed caches held at once.
///
/// Two lookup entries retain the usual current and previous epoch seeds.
/// Historical forks can request older seeds and rebuild their caches. Each
/// cache is 256 MiB; idle and leased VMs can retain additional cache references,
/// so this is a lookup bound rather than a total resident-memory bound.
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

/// The node's RandomX instance: seed caches, a VM pool, and the hash.
pub struct RandomxEngine {
	flags: RandomXFlag,
	caches: Mutex<VecDeque<([u8; 32], Arc<SharedCache>)>>,
	cache_build: Mutex<()>,
	idle: Mutex<Vec<PooledVm>>,
	max_caches: usize,
	max_idle_vms: AtomicUsize,
	cache_initialisations: AtomicUsize,
}

impl RandomxEngine {
	/// A light-mode engine holding at most `max_idle_vms` VMs between uses.
	pub fn light(max_idle_vms: usize) -> Arc<Self> {
		Self::with_settings(max_idle_vms, DEFAULT_MAX_CACHES)
	}

	/// A light-mode engine with both pool sizes named.
	pub fn with_settings(max_idle_vms: usize, max_caches: usize) -> Arc<Self> {
		// `get_recommended_flags` detects hardware AES, the JIT and the Argon2
		// variants, and deliberately never returns FULL_MEM: that is the
		// dataset flag, and this engine is light mode. None of these flags
		// change the hash.
		let flags = RandomXFlag::get_recommended_flags();
		Arc::new(Self {
			flags,
			caches: Mutex::new(VecDeque::new()),
			cache_build: Mutex::new(()),
			idle: Mutex::new(Vec::new()),
			max_caches: max_caches.max(1),
			max_idle_vms: AtomicUsize::new(max_idle_vms.max(1)),
			cache_initialisations: AtomicUsize::new(0),
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

	/// How many Argon2d cache fills have happened, which is how many times the
	/// seed moved under this process.
	pub fn cache_initialisations(&self) -> usize {
		self.cache_initialisations.load(Ordering::Relaxed)
	}

	fn cache_for(&self, seed: &[u8; 32]) -> Result<Arc<SharedCache>, EngineError> {
		{
			let mut caches = self.caches.lock();
			if let Some(index) = caches.iter().position(|(key, _)| key == seed) {
				// Most recently used goes to the back, so the front is what an
				// eviction takes.
				let entry = caches.remove(index).expect("index came from position; qed");
				let cache = entry.1.clone();
				caches.push_back(entry);
				return Ok(cache);
			}
		}

		// Serialize cold-cache construction and check again after waiting. A
		// historical branch may use an older seed, and concurrent requests for
		// it must share one 256 MiB fill. Cached seeds remain available while
		// this lock is held because the cache lookup uses its own short lock.
		let _build = self.cache_build.lock();
		{
			let caches = self.caches.lock();
			if let Some((_, cache)) = caches.iter().find(|(key, _)| key == seed) {
				return Ok(cache.clone());
			}
		}
		log::info!(
			target: crate::LOG_TARGET,
			"⛏️ RandomX: initialising the seed cache for {} (light mode, 256 MiB)",
			hex::encode(seed),
		);
		let cache = Arc::new(SharedCache(RandomXCache::new(self.flags, &seed[..])?));
		self.cache_initialisations.fetch_add(1, Ordering::Relaxed);

		let mut caches = self.caches.lock();
		caches.push_back((*seed, cache.clone()));
		while caches.len() > self.max_caches {
			caches.pop_front();
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
