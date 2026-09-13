#![cfg_attr(not(feature = "std"), no_std)]

//! Mining difficulty: what it is now, and how it moves.
//!
//! This pallet is the chain's difficulty, and since M7 that is all it is. It
//! used to verify the proof of work as well, when the hash was Poseidon and a
//! wasm runtime could compute it. RandomX cannot run in a wasm runtime, so
//! verification moved to the consensus client and what is left here is the part
//! that never depended on the hash in the first place.
//!
//! The retarget is a pure function of the parent difficulty, the observed block
//! time and the target block time, in Ethereum's Homestead shape. Nothing in it
//! reads a nonce, a hash or an engine id, which is why the RandomX swap keeps
//! it rather than forking it into a new pallet: a Monero-style LWMA would be
//! another tuning of the same inputs. The storage,
//! the genesis override and the `DifficultyAdjusted` event are unchanged, so
//! the swap moved no storage item.
//!
//! The seed schedule is here for the same reason: it is two numbers the client
//! reads out of chain state, so a chain can pick its own epoch length without a
//! client release.

extern crate alloc;

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;
use weights::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use core::ops::Shr;
	use frame_support::{
		pallet_prelude::*,
		sp_runtime::{traits::One, SaturatedConversion},
		traits::{BuildGenesisConfig, Time},
	};
	use frame_system::pallet_prelude::BlockNumberFor;
	use sp_core::U512;

	pub type Difficulty = U512;
	pub type WorkValue = U512;
	pub type Timestamp = u64;
	pub type BlockDuration = u64;

	/// Lower bound (ms) on the author-controlled block time fed into the difficulty
	/// retarget. Flooring can only lower the adjustment, so it can never stall the chain.
	const MIN_RETARGET_BLOCK_TIME_MS: u64 = 500;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	pub type LastBlockTime<T: Config> = StorageValue<_, Timestamp, ValueQuery>;

	#[pallet::storage]
	pub type LastBlockDuration<T: Config> = StorageValue<_, BlockDuration, ValueQuery>;

	#[pallet::storage]
	pub type CurrentDifficulty<T: Config> = StorageValue<_, Difficulty, ValueQuery>;

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_timestamp::Config {
		#[pallet::constant]
		type InitialDifficulty: Get<U512>;

		#[pallet::constant]
		type TargetBlockTime: Get<BlockDuration>;

		#[pallet::constant]
		type MaxReorgDepth: Get<u32>;

		/// Blocks per RandomX seed epoch.
		///
		/// The consensus client reads this rather than hard-coding Monero's
		/// 2048, because Monero's epoch was chosen against a 120 s block time
		/// and this chain's is 12 s. A power of two keeps the rule identical
		/// to Monero's masked form.
		#[pallet::constant]
		type SeedEpochBlocks: Get<u32>;

		/// Blocks between an epoch boundary and the block whose hash seeds it.
		///
		/// The lag is what gives every node the seed block well before the
		/// first block that hashes under it.
		#[pallet::constant]
		type SeedEpochLag: Get<u32>;

		type WeightInfo: WeightInfo;
	}

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub initial_difficulty: Difficulty,
		#[serde(skip)]
		pub _phantom: PhantomData<T>,
	}

	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { initial_difficulty: T::InitialDifficulty::get(), _phantom: PhantomData }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			// Fail early on an out-of-range genesis difficulty (this also rejects
			// zero, since the floor is non-zero) before it can drive first-block
			// consensus. Reuse the operational difficulty bounds.
			assert!(
				self.initial_difficulty >= Pallet::<T>::get_min_difficulty() &&
					self.initial_difficulty < Pallet::<T>::get_max_difficulty(),
				"Genesis initial difficulty must be within [get_min_difficulty, get_max_difficulty)"
			);
			// Use the genesis config value, not the runtime constant.
			// This allows chain-spec overrides of initial difficulty.
			<CurrentDifficulty<T>>::put(self.initial_difficulty);

			log::info!(target: "qpow", "Genesis: Set initial difficulty to {:x}",
				self.initial_difficulty.low_u64());
		}
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		DifficultyAdjusted {
			old_difficulty: Difficulty,
			new_difficulty: Difficulty,
			observed_block_time: BlockDuration,
		},
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
			<T as crate::Config>::WeightInfo::on_finalize()
		}

		/// Called at the end of each block to adjust mining difficulty.
		fn on_finalize(block_number: BlockNumberFor<T>) {
			let current_difficulty = Self::get_difficulty();
			log::debug!(target: "qpow",
				"📢 QPoW: before submit at block {:?}, current_difficulty={:?}",
				block_number,
				current_difficulty.low_u64()
			);

			Self::adjust_difficulty();
		}
	}

	impl<T: Config> Pallet<T> {
		fn percentage_change(big_a: U512, big_b: U512) -> (U512, bool) {
			let a = big_a.shr(10);
			let b = big_b.shr(10);

			let abs_diff = a.abs_diff(b);
			let change = abs_diff
				.saturating_mul(U512::from(100u64))
				.checked_div(a)
				.unwrap_or(U512::zero());

			(change, b >= a)
		}

		fn adjust_difficulty() {
			let now = pallet_timestamp::Pallet::<T>::now().saturated_into::<u64>();
			let last_time = <LastBlockTime<T>>::get();
			// Use get_difficulty() to handle zero/missing storage consistently with verification.
			// This ensures we use InitialDifficulty as the base when storage is unset,
			// rather than computing from zero which would clamp to min_difficulty.
			let current_difficulty = Self::get_difficulty();
			let current_block_number = <frame_system::Pallet<T>>::block_number();

			// Calculate block time (use target for genesis block)
			let block_time = if current_block_number > One::one() {
				let duration = now.saturating_sub(last_time);

				log::debug!(target: "qpow",
					"Time calculation: now={}, last_time={}, diff={}ms",
					now,
					last_time,
					duration
				);

				<LastBlockDuration<T>>::put(duration);

				duration
			} else {
				T::TargetBlockTime::get()
			};

			<LastBlockTime<T>>::put(now);

			let target_time = T::TargetBlockTime::get();
			let new_difficulty =
				Self::calculate_difficulty(current_difficulty, block_time, target_time);

			<CurrentDifficulty<T>>::put(new_difficulty);

			log::debug!(target: "qpow", "Stored new difficulty: {}",
				new_difficulty.low_u128());

			Self::deposit_event(Event::DifficultyAdjusted {
				old_difficulty: current_difficulty,
				new_difficulty,
				observed_block_time: block_time,
			});

			let (pct_change, is_positive) =
				Self::percentage_change(current_difficulty, new_difficulty);

			log::debug!(target: "qpow",
				"🟢 Adjusted mining difficulty {}{}%: {:x} -> {:x} (block time: {}ms, target: {}ms) ",
				if is_positive {"+"} else {"-"},
				pct_change,
				current_difficulty.low_u64(),
				new_difficulty.low_u64(),
				block_time,
				target_time
			);
		}

		/// Calculate new difficulty based on block time.
		/// Uses the same formula as Ethereum PoW:
		/// diff = parent_diff + (parent_diff / 2048) * max(1 - block_time / divisor, -99)
		///
		/// Homestead used 10s buckets (`Δt // 10`) with Geth's 15s future slack.
		/// Scaling 10/12 keeps those buckets at a 12s target so a max-drift inflate
		/// is a single -1 that forced +1 catch-up blocks repay (or overshoot).
		/// Zones at a 12s target (10s divisor):
		/// - < 10s: difficulty increases by 1/2048 (~0.05%)
		/// - 10s to 20s: no change
		/// - 20s to 30s: difficulty decreases by 1/2048
		/// - etc, up to max decrease of 99/2048 (~4.8%)
		pub fn calculate_difficulty(
			parent_difficulty: U512,
			block_time_ms: u64,
			target_time_ms: u64,
		) -> U512 {
			log::debug!(target: "qpow", "📊 Calculating new difficulty ---------------------------------------------");

			// Floor the author-controlled block time so an implausibly small timestamp
			// delta cannot steer the retarget.
			let block_time_ms = block_time_ms.max(MIN_RETARGET_BLOCK_TIME_MS);

			// Homestead divisor was 10s on a ~12-15s target. Keep that ratio:
			// divisor = target * 10 / 12.
			let divisor_ms = (target_time_ms * 10 / 12).max(1);
			let time_factor = (block_time_ms / divisor_ms) as i64;
			let adjustment = core::cmp::max(1i64 - time_factor, -99i64);

			log::debug!(target: "qpow", "Block time: {}ms, divisor: {}ms, time_factor: {}, adjustment: {}", 
				block_time_ms, divisor_ms, time_factor, adjustment);

			// Difficulty increment = parent_diff / 2048, and never zero.
			//
			// The floor on the increment is what M7 added, and it is the
			// difference between a floor a chain can leave and one it cannot.
			// Integer division makes the increment zero for any difficulty
			// below 2048, so a chain that fell to the RandomX floor of 128
			// would sit there for ever: fast blocks would compute an
			// adjustment and add nothing. One is the smallest step that keeps
			// the retarget monotonic at every difficulty, and it changes
			// nothing above 2048, where the division already dominates.
			let increment = (parent_difficulty / U512::from(2048u64)).max(U512::one());

			// Calculate new difficulty
			let new_difficulty = if adjustment >= 0 {
				parent_difficulty
					.saturating_add(increment.saturating_mul(U512::from(adjustment as u64)))
			} else {
				let decrease = increment.saturating_mul(U512::from((-adjustment) as u64));
				parent_difficulty.saturating_sub(decrease)
			};

			// Apply min/max bounds
			let min_difficulty = Self::get_min_difficulty();
			let max_difficulty = Self::get_max_difficulty();

			let bounded = if new_difficulty < min_difficulty {
				log::warn!("Min difficulty achieved, clipping to: {:x}", min_difficulty.low_u64());
				min_difficulty
			} else if new_difficulty > max_difficulty {
				log::warn!("Max difficulty achieved, clipping to: {:x}", max_difficulty.low_u64());
				max_difficulty
			} else {
				new_difficulty
			};

			log::debug!(target: "qpow",
				"🟢 Current Difficulty: {:x}",
				parent_difficulty.low_u64()
			);
			log::debug!(target: "qpow", "🟢 Next Difficulty:    {:x}", bounded.low_u64());
			log::debug!(target: "qpow", "🕒 Block Time: {}ms", block_time_ms);

			bounded
		}
	}

	impl<T: Config> Pallet<T> {
		pub fn initial_difficulty() -> Difficulty {
			T::InitialDifficulty::get()
		}

		pub fn get_difficulty() -> Difficulty {
			let stored = <CurrentDifficulty<T>>::get();
			let initial = Self::initial_difficulty();

			if stored == U512::zero() {
				log::warn!(target: "qpow", "Stored difficulty is zero, using initial: {:x}", initial.low_u64());
				return initial;
			}
			stored
		}

		pub fn get_min_difficulty() -> Difficulty {
			// The floor is sized for RandomX now. It used to be
			// Ethereum's 2^17, which at the 500 to 2000 H/s a RandomX core
			// manages would be 65 to 260 core-seconds per block against a 12 s
			// target: a one-machine devnet would never produce a block. 128 is
			// about four seconds on one light-mode thread, which is what the
			// `dev` preset starts at.
			U512::from(128u64)
		}

		pub fn get_max_difficulty() -> Difficulty {
			U512::MAX
		}

		pub fn get_last_block_time() -> Timestamp {
			<LastBlockTime<T>>::get()
		}

		pub fn get_last_block_duration() -> BlockDuration {
			<LastBlockDuration<T>>::get()
		}

		pub fn get_max_reorg_depth() -> u32 {
			T::MaxReorgDepth::get()
		}

		pub fn get_seed_epoch_blocks() -> u32 {
			T::SeedEpochBlocks::get()
		}

		pub fn get_seed_epoch_lag() -> u32 {
			T::SeedEpochLag::get()
		}
	}
}
