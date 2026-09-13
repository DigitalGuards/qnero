#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
use alloc::vec::Vec;
use primitive_types::U512;
use sp_runtime::ConsensusEngineId;

/// The engine id in the header's `PreRuntime` and `Seal` digest items.
///
/// It stayed `pow_` across the M7 engine swap on purpose. The runtime derives a
/// block's author from the item under this id, through one `FindAuthor`
/// implementation, and a new id would have meant editing that implementation
/// for nothing: which hash function decided the seal is not something the
/// runtime knows or needs to know.
pub const POW_ENGINE_ID: ConsensusEngineId = [b'p', b'o', b'w', b'_'];

pub type Seal = Vec<u8>;

sp_api::decl_runtime_apis! {
	/// What the consensus client asks the runtime about proof of work.
	///
	/// Since M7 this is difficulty and schedule only. The runtime does not
	/// verify a nonce any more, because RandomX cannot run inside a wasm
	/// runtime: the Argon2d cache alone is 256 MiB against a 128 MiB runtime
	/// heap, there is no JIT, and the VM needs a floating-point rounding mode
	/// wasm has no way to set. Verification is the client's, in
	/// `sc-consensus-randomx`, and the runtime is the oracle it asks for the
	/// difficulty and the seed schedule.
	pub trait QPoWApi {
		/// Get the max possible reorg depth
		fn get_max_reorg_depth() -> u32;

		/// Get the max possible difficulty for work calculation
		fn get_max_difficulty() -> U512;

		/// Get the current mining difficulty
		fn get_difficulty() -> U512;

		/// Get last block timestamp
		fn get_last_block_time() -> u64;

		/// Get last block mining time
		fn get_last_block_duration() -> u64;

		fn get_chain_height() -> u32;

		/// Blocks per RandomX seed epoch: how long a seed, and therefore a
		/// miner's dataset, stays put.
		fn get_seed_epoch_blocks() -> u32;

		/// Blocks between an epoch boundary and the block whose hash seeds it.
		fn get_seed_epoch_lag() -> u32;
	}
}
