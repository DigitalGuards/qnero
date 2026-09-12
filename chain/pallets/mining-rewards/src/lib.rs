#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
pub use weights::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use core::marker::PhantomData;
	use frame_support::{
		pallet_prelude::*,
		traits::{
			fungible::{Inspect, Mutate},
			FindAuthor, Get, Imbalance, OnUnbalanced,
		},
	};
	use frame_system::pallet_prelude::*;
	use qp_coinbase::CoinbaseSink;
	use sp_runtime::traits::Saturating;

	pub(crate) type BalanceOf<T> =
		<<T as Config>::Currency as Inspect<<T as frame_system::Config>::AccountId>>::Balance;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	/// Fees and failed-mint retries awaiting distribution by `on_finalize`.
	#[pallet::storage]
	#[pallet::getter(fn collected_fees)]
	pub(super) type CollectedFees<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;

		/// Currency type. Read for the transparent half of the supply
		/// measure; this pallet mints nothing into it.
		type Currency: Mutate<Self::AccountId>;

		/// Where the block reward goes.
		///
		/// Under v1 mandatory privacy nothing is minted to an account: the
		/// reward and the transaction fees become the value of the block's
		/// coinbase note in the shielded pool. The sink hands back what it
		/// could not take, which this pallet holds for the next block.
		type CoinbaseSink: CoinbaseSink<BalanceOf<Self>>;

		/// Value held by the shielded pool.
		///
		/// The emission schedule measures supply against [`Config::MaxSupply`],
		/// and under v1 nearly every planck lives in the pool, where
		/// `total_issuance` does not count it: shielding burns from the
		/// shielder. Without this term supply would appear to fall as the pool
		/// filled and the schedule would mint faster forever.
		type ShieldedSupply: Get<BalanceOf<Self>>;

		/// The block author, as one seam. The runtime implements it over
		/// whatever consensus is in place; this pallet never reads a digest
		/// itself. `docs/OPS-DEV.md` carries the seam.
		type FindAuthor: FindAuthor<Self::AccountId>;

		/// The maximum total supply of tokens
		#[pallet::constant]
		type MaxSupply: Get<BalanceOf<Self>>;

		/// The divisor used to calculate block rewards from remaining supply
		#[pallet::constant]
		type EmissionDivisor: Get<BalanceOf<Self>>;

		/// The base unit for token amounts (e.g., 1e12 for 12 decimals)
		#[pallet::constant]
		type Unit: Get<BalanceOf<Self>>;
	}

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// The block reward and the fees became the value of this block's
		/// coinbase note. No account was credited.
		///
		/// The author is deliberately absent. Nothing reads it: both pallets
		/// ask only whether a block has an author, and who the note belongs to
		/// is inside an `inner` the chain cannot open. Publishing an account
		/// beside every coinbase value would label each note's block with a
		/// mining identity and hand an observer exactly the partition a
		/// shielded coinbase exists to deny.
		CoinbaseCredited {
			/// Quantized credit (block reward + fees, aligned to the pool
			/// quantum). The note can be worth more: the pool folds in the
			/// author's share of the fees this block's settlements paid, which
			/// never passes through this pallet.
			amount: BalanceOf<T>,
		},
		/// Transaction fees were collected for later distribution
		FeesCollected {
			/// The amount collected
			amount: BalanceOf<T>,
			/// Total fees waiting for distribution
			total: BalanceOf<T>,
		},
		/// No miner in the digest; the credit stays in `CollectedFees` for the next block.
		PayoutDeferred {
			/// Amount held for the next miner
			amount: BalanceOf<T>,
		},
		/// The pool could not take the credit, so it stays in `CollectedFees`
		/// for the next block. The one reachable cause is a block whose author
		/// supplied no coinbase inherent, and the inherent check refuses such a
		/// block on import.
		CoinbaseRejected {
			/// The credit retained.
			amount: BalanceOf<T>,
		},
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn integrity_test() {
			assert!(!T::EmissionDivisor::get().is_zero(), "EmissionDivisor must be non-zero");
			assert!(!T::MaxSupply::get().is_zero(), "MaxSupply must be non-zero");
			assert!(
				Self::leaf_quantum() > BalanceOf::<T>::zero(),
				"ZK-tree amount scale factor must fit in Balance and be non-zero"
			);
		}

		fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
			// Return weight consumed for on finalize hook
			<T as crate::pallet::Config>::WeightInfo::on_finalize_rewarded_miner()
		}

		fn on_finalize(_block_number: BlockNumberFor<T>) {
			// Take collected fees first - needed for accurate supply calculation below.
			// This also picks up any reward whose mint failed on an earlier finalize:
			let tx_fees = <CollectedFees<T>>::take();

			// Calculate dynamic block reward based on remaining supply.
			// Note: Transaction fees were burned when the NegativeImbalance was dropped
			// (during transaction execution), so we add them back to get the true
			// current supply before re-minting them to the miner. This prevents the
			// block reward calculation from being slightly inflated by the burned fees.
			// Retried unminted rewards inside `tx_fees` are likewise already-scheduled
			// supply (they were budgeted from the remaining supply of their own block),
			// so this line covers them too.
			// Both books. `total_issuance` is the transparent one; the pool
			// holds the rest and `ShieldedSupply` is what makes the emission
			// schedule see it. See `Config::ShieldedSupply`.
			let max_supply = T::MaxSupply::get();
			let current_supply = T::Currency::total_issuance()
				.saturating_add(tx_fees)
				.saturating_add(T::ShieldedSupply::get());
			let emission_divisor = T::EmissionDivisor::get();

			let remaining_supply = max_supply.saturating_sub(current_supply);

			if remaining_supply == BalanceOf::<T>::zero() {
				log::warn!(
					"💰 Emission completed: current supply has reached the configured maximum, \
					 no further block rewards will be minted."
				);
			}

			let total_reward = remaining_supply
				.checked_div(&emission_divisor)
				.unwrap_or_else(BalanceOf::<T>::zero);

			// Whether this block has an author, through the one seam this
			// pallet reads consensus through. Who it is decides nothing here:
			// the coinbase inherent carries the payee, inside an `inner` the
			// chain cannot open, and an account published beside every block's
			// credit would label each coinbase note with a mining identity.
			let has_author = Self::extract_miner_from_digest().is_some();

			// Fees and the block reward are one credit. Combining before
			// quantizing can recover a quantum that two independent floors would
			// drop, and the author holds one note rather than two.
			let miner_gross = tx_fees.saturating_add(total_reward);

			// Log readable amounts (convert to tokens by dividing by unit)
			if let (Ok(total), Ok(gross), Ok(current), Ok(fees), Ok(unit)) = (
				TryInto::<u128>::try_into(total_reward),
				TryInto::<u128>::try_into(miner_gross),
				TryInto::<u128>::try_into(current_supply),
				TryInto::<u128>::try_into(tx_fees),
				TryInto::<u128>::try_into(T::Unit::get()),
			) {
				let remaining: u128 =
					TryInto::<u128>::try_into(max_supply.saturating_sub(current_supply))
						.unwrap_or(0);
				let unit_f64 = unit as f64;
				log::debug!(
					target: "mining-rewards",
					"💰 Rewards: block={:.6}, fees={:.6}, miner_gross={:.6}, supply={:.2}, remaining={:.2}",
					total as f64 / unit_f64,
					fees as f64 / unit_f64,
					gross as f64 / unit_f64,
					current as f64 / unit_f64,
					remaining as f64 / unit_f64
				);
			}

			if !has_author {
				// A valid QPoW block always carries an author preimage, but extraction
				// is fallible (malformed digest). Do not panic in a hook and do not
				// divert miner credits to treasury: hold them for the next author.
				Self::retain_unminted(miner_gross);
				if !miner_gross.is_zero() {
					Self::deposit_event(Event::PayoutDeferred { amount: miner_gross });
				}
				return;
			}

			let (quantized, dust) = Self::quantize(miner_gross);
			Self::pay_coinbase(quantized);
			// Remainder stays unminted so a later block can form a full quantum.
			Self::retain_unminted(dust);
		}
	}

	impl<T: Config> Pallet<T> {
		/// The block author, through the one seam this pallet reads consensus
		/// through. See [`Config::FindAuthor`].
		fn extract_miner_from_digest() -> Option<T::AccountId> {
			T::FindAuthor::find_author(
				<frame_system::Pallet<T>>::digest()
					.logs
					.iter()
					.filter_map(|log| log.as_pre_runtime()),
			)
		}

		pub fn collect_transaction_fees(fees: BalanceOf<T>) {
			<CollectedFees<T>>::mutate(|total_fees| {
				*total_fees = total_fees.saturating_add(fees);
			});
			Self::deposit_event(Event::FeesCollected {
				amount: fees,
				total: <CollectedFees<T>>::get(),
			});
		}

		/// The amount quantum a note commits: `pallet-zk-tree` stores a
		/// wormhole leaf's amount divided by this, and `pallet-shielded`
		/// asserts its own pool quantum is the same number. A credit that is
		/// not a multiple of it cannot be the value of a note at all, so the
		/// remainder waits here for a block that completes it.
		fn leaf_quantum() -> BalanceOf<T> {
			pallet_zk_tree::tree::AMOUNT_SCALE_DOWN_FACTOR
				.try_into()
				.unwrap_or_else(|_| BalanceOf::<T>::zero())
		}

		/// Round down to a multiple of the leaf quantum. Returns `(aligned, remainder)`.
		fn quantize(amount: BalanceOf<T>) -> (BalanceOf<T>, BalanceOf<T>) {
			let remainder = amount % Self::leaf_quantum();
			(amount.saturating_sub(remainder), remainder)
		}

		/// Hand the credit to the shielded pool, which turns it into this
		/// block's coinbase note.
		///
		/// Nothing is minted into an account. The credit is value that is not
		/// in `total_issuance` yet, emission that has not been created and fees
		/// that were burned when their imbalance dropped, and the pool creates
		/// it by standing behind a note worth exactly this much.
		///
		/// A zero credit still goes to the sink. The pool holds the author's
		/// share of the fees this block's settlements paid, and only a mint
		/// drains it. Returning early on a zero credit would strand that share
		/// the moment the emission rounds to zero, which is the steady state
		/// this chain is heading for: supply approaches `MaxSupply`, settled
		/// fees keep accruing an author share, and every one of them would be
		/// subtracted from the pool, counted as supply, and never minted into
		/// a note again. The sink answers with what it could not take, so a
		/// block with nothing at all to mint costs one call that changes
		/// nothing.
		fn pay_coinbase(amount: BalanceOf<T>) {
			debug_assert!(
				(amount % Self::leaf_quantum()).is_zero(),
				"a coinbase credit must be pool-quantum aligned"
			);

			match T::CoinbaseSink::deposit_coinbase(amount) {
				Ok(()) => {
					Self::deposit_event(Event::CoinbaseCredited { amount });
				},
				Err(returned) if returned.is_zero() => {
					// Nothing was handed over and nothing came back: a block
					// with no emission and no pending fee mints no note.
				},
				Err(returned) => {
					log::warn!(
						target: "mining-rewards",
						"the shielded pool refused a coinbase credit of {:?}, retaining for retry",
						returned
					);
					Self::retain_unminted(returned);
					Self::deposit_event(Event::CoinbaseRejected { amount: returned });
				},
			}
		}

		/// Roll a failed mint back into `CollectedFees` for the next finalize.
		fn retain_unminted(reward: BalanceOf<T>) {
			<CollectedFees<T>>::mutate(|pending| {
				*pending = pending.saturating_add(reward);
			});
		}
	}

	pub struct TransactionFeesCollector<T>(PhantomData<T>);

	impl<T, I> OnUnbalanced<I> for TransactionFeesCollector<T>
	where
		T: Config,
		I: Imbalance<BalanceOf<T>>,
	{
		fn on_nonzero_unbalanced(amount: I) {
			Pallet::<T>::collect_transaction_fees(amount.peek());
		}
	}
}
