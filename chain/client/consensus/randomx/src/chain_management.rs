use codec::{Decode, Encode};
use primitive_types::U512;
use sc_client_api::AuxStore;
use sp_blockchain::HeaderBackend;
use sp_runtime::traits::{Block as BlockT, Zero};

const ACHIEVED_WORK_PREFIX: &[u8] = b"QPow:AchievedWork:";

/// Refuse a database carrying irreversible checkpoints from the legacy client.
///
/// Qnero chooses cumulative work and keeps confirmations reversible. A local
/// finalized prefix cannot be undone by importing a heavier chain. Operators
/// must replay into a separate archive database when adopting this policy.
pub fn ensure_pow_database<B: BlockT, C: HeaderBackend<B>>(
	client: &C,
) -> Result<(), sp_blockchain::Error> {
	let info = client.info();
	if !info.finalized_number.is_zero() || info.finalized_hash != info.genesis_hash {
		return Err(sp_blockchain::Error::Backend(format!(
			"Qnero requires reversible proof-of-work confirmations; this database has \
             a finalized checkpoint at {:?}. Preserve it and replay the chain into a \
             separate archive database before starting this client.",
			info.finalized_number,
		)));
	}
	Ok(())
}

/// Store cumulative achieved work for a block in auxiliary storage.
/// This is used for chain selection based on achieved difficulty.
pub fn store_cumulative_achieved_work<B: BlockT, C: AuxStore>(
	client: &C,
	block_hash: B::Hash,
	cumulative_work: U512,
) -> Result<(), sp_blockchain::Error> {
	let key = [ACHIEVED_WORK_PREFIX, block_hash.as_ref()].concat();
	client.insert_aux(&[(&key[..], &cumulative_work.encode()[..])], &[])?;
	log::debug!(
		target: "qpow",
		"Stored cumulative achieved work {} for block {:?}",
		cumulative_work,
		block_hash
	);
	Ok(())
}

/// Get cumulative achieved work for a block from auxiliary storage.
/// Returns U512::zero() if not found (e.g., for genesis block before initialization).
pub fn get_cumulative_achieved_work<B: BlockT, C: AuxStore>(
	client: &C,
	block_hash: B::Hash,
) -> Result<U512, sp_blockchain::Error> {
	let key = [ACHIEVED_WORK_PREFIX, block_hash.as_ref()].concat();
	match client.get_aux(&key)? {
		Some(bytes) => {
			let work = U512::decode(&mut &bytes[..]).map_err(|e| {
				sp_blockchain::Error::Backend(format!(
					"Failed to decode cumulative work for {:?}: {:?}",
					block_hash, e
				))
			})?;
			Ok(work)
		},
		None => {
			log::trace!(
				target: "qpow",
				"No cumulative achieved work found for block {:?}, returning zero",
				block_hash
			);
			Ok(U512::zero())
		},
	}
}

/// Delete cumulative achieved work for a block from auxiliary storage.
/// Used to roll back auxiliary work when a block import fails.
pub fn delete_cumulative_achieved_work<B: BlockT, C: AuxStore>(
	client: &C,
	block_hash: B::Hash,
) -> Result<(), sp_blockchain::Error> {
	let key = [ACHIEVED_WORK_PREFIX, block_hash.as_ref()].concat();
	client.insert_aux(&[], &[&key[..]])?;
	log::trace!(
		target: "qpow",
		"Deleted cumulative achieved work for block {:?}",
		block_hash
	);
	Ok(())
}

/// Initialize the genesis block's achieved work if not already set.
/// Genesis block has achieved work = 1 (no mining, but represents the start of the chain).
/// This should be called during node startup.
pub fn initialize_genesis_achieved_work<B: BlockT, C: AuxStore + HeaderBackend<B>>(
	client: &C,
) -> Result<(), sp_blockchain::Error> {
	// Get genesis hash
	let genesis_hash = client
		.hash(Zero::zero())?
		.ok_or_else(|| sp_blockchain::Error::Backend("Genesis block not found".to_string()))?;

	// Check if already initialized
	let existing = get_cumulative_achieved_work::<B, C>(client, genesis_hash)?;
	if existing != U512::zero() {
		log::debug!(
			target: "qpow",
			"Genesis achieved work already initialized to {}",
			existing
		);
		return Ok(());
	}

	// Initialize genesis achieved work to 1
	let genesis_work = U512::one();
	store_cumulative_achieved_work::<B, C>(client, genesis_hash, genesis_work)?;
	log::info!(
		target: "qpow",
		"Initialized genesis block {:?} achieved work to {}",
		genesis_hash,
		genesis_work
	);

	Ok(())
}

/// Get chain work using achieved difficulty from auxiliary storage.
/// This is the new chain selection metric based on actual work done.
pub fn get_chain_work<B, C>(client: &C, at_hash: B::Hash) -> Result<U512, sp_consensus::Error>
where
	B: BlockT,
	C: AuxStore,
{
	get_cumulative_achieved_work::<B, C>(client, at_hash).map_err(|e| {
		sp_consensus::Error::Other(
			format!("Failed to get cumulative achieved work: {:?}", e).into(),
		)
	})
}

pub fn is_heavier<N: PartialOrd>(
	candidate_work: U512,
	candidate_number: N,
	current_work: U512,
	current_number: N,
) -> bool {
	candidate_work > current_work ||
		(candidate_work == current_work && candidate_number > current_number)
}
