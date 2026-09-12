//! Benchmarking setup for pallet-mining-rewards

extern crate alloc;

use super::*;
use crate::Pallet as MiningRewards;
use frame_benchmarking::v2::*;
use frame_system::{pallet_prelude::BlockNumberFor, Pallet as SystemPallet};
use sp_consensus_qpow::POW_ENGINE_ID;
use sp_runtime::generic::{Digest, DigestItem};

#[benchmarks]
mod benchmarks {
	use super::*;
	use frame_support::traits::OnFinalize;

	#[benchmark]
	fn on_finalize_rewarded_miner() -> Result<(), BenchmarkError> {
		let block_number: BlockNumberFor<T> = 1u32.into();
		let fees_collected: BalanceOf<T> = 1000u32.into();

		CollectedFees::<T>::put(fees_collected);

		// The digest carries the author's 32-byte preimage, which the runtime's
		// author seam hashes into an account. Nothing is minted to that
		// account under v1, so the benchmark neither derives nor funds it.
		let miner_preimage: [u8; 32] = [42u8; 32];

		let miner_digest_item = DigestItem::PreRuntime(POW_ENGINE_ID, miner_preimage.to_vec());

		SystemPallet::<T>::initialize(
			&block_number,
			&SystemPallet::<T>::parent_hash(),
			&Digest { logs: alloc::vec![miner_digest_item] },
		);

		// The block carries no coinbase inherent, so the sink hands the credit
		// back and this measures the path without the note. The coinbase
		// append, the ciphertext and the maps behind it are reserved by
		// `pallet-shielded`'s own `on_initialize`; see `MAX_LEAF_INSERTS`.
		#[block]
		{
			MiningRewards::<T>::on_finalize(block_number);
		}
		Ok(())
	}
}
