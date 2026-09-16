//! RandomX proof of work for Qnero.
//!
//! This crate is the consensus client: it seals blocks, verifies seals and
//! decides fork choice. It replaces the Poseidon-hash QPoW engine and keeps
//! everything M6 built around it, byte for byte.
//!
//! **What is the same.** The header shape: one `PreRuntime` item of 32 bytes
//! under [`POW_ENGINE_ID`] and one 64-byte `Seal`, filling the header's
//! 110-byte digest commitment window exactly. The author label: the node still
//! publishes `H(cvk, parent_hash)` and the runtime still derives the block's
//! author from it through one `FindAuthor` implementation. The coinbase: still
//! an inherent, still minted from the node's own miner key, and it reads
//! nothing about the proof of work. Fork choice: still cumulative work in the
//! aux store, still `parent_work + difficulty`. The difficulty pallet: still
//! `pallet-qpow`, whose retarget is a function of block times and knows nothing
//! about the hash.
//!
//! **What is different.** The hash is RandomX (`rx/0`), so a Monero rig mines
//! Qnero with a config change. The proof is a 4-byte nonce plus a 4-byte extra
//! nonce over a 76-byte blob ([`blob`]), packed into the 64-byte seal
//! ([`seal`]). The comparison is Monero's, little-endian and 256-bit
//! ([`target`]). And verification is **client side**: RandomX cannot run in a
//! wasm runtime (a 256 MiB Argon2d cache, no JIT, and a floating-point
//! rounding mode wasm cannot set), so the runtime no longer verifies a nonce.
//! It answers what the difficulty is and the client does the rest.

mod chain_management;
mod worker;

pub mod blob;
pub mod seal;
pub mod seed;
pub mod target;
pub mod vm;

pub use chain_management::{
	delete_cumulative_achieved_work, ensure_pow_database, get_chain_work,
	get_cumulative_achieved_work, initialize_genesis_achieved_work, is_heavier,
	store_cumulative_achieved_work,
};
pub use seal::{Seal, SealError, SEAL_LEN};
pub use vm::{EngineError, RandomxEngine, VmLease};

use primitive_types::{H256, U512};
use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_consensus_qpow::{QPoWApi, Seal as RawSeal};
use sp_runtime::traits::{Block as BlockT, NumberFor, UniqueSaturatedFrom};
use std::{marker::PhantomData, sync::Arc, time::Duration};

use qp_header::{check_digest_commitment_window, DIGEST_LOGS_SIZE};

use crate::worker::UntilImportedOrTransaction;
pub use crate::worker::{MiningBuild, MiningHandle, MiningMetadata, RebuildTrigger};

/// What an authoring node publishes in the `PreRuntime` digest item of the
/// block it proposes, given the parent it is building on.
///
/// One item per block, 32 bytes, and the header commits to exactly that item
/// and the seal. The runtime derives the block's author account from it and
/// reads nothing else out of it, so what it must not be is a constant: a value
/// that is the same in every block one operator wins labels each of those
/// blocks, which on Qnero means labelling the coinbase note in it. The node
/// supplies a function rather than a value for that reason. It must return
/// four canonical Goldilocks limbs, because the runtime treats an item it
/// cannot derive an account from as a block with no author.
///
/// The engine swap does not touch this. RandomX decides what a valid seal is
/// and nothing else.
pub type AuthorLabel = Arc<dyn Fn(H256) -> [u8; 32] + Send + Sync>;

use futures::{Future, Stream, StreamExt};
use log::*;
use prometheus_endpoint::Registry;
use sc_client_api::{self, backend::AuxStore, BlockOf, BlockchainEvents};
use sc_consensus::{
	BasicQueue, BlockCheckParams, BlockImport, BlockImportParams, BoxBlockImport,
	BoxJustificationImport, ForkChoiceStrategy, ImportResult, JustificationSyncLink, Verifier,
};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::{Environment, Error as ConsensusError, Proposer};
use sp_consensus_qpow::POW_ENGINE_ID;

use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::{
	generic::{Digest, DigestItem},
	traits::Header as HeaderT,
};

pub(crate) const LOG_TARGET: &str = "randomx";

/// The stratum algorithm name a job advertises. Stock RandomX, stock
/// constants, so this is the same algorithm Monero mines.
pub const ALGO: &str = "rx/0";

#[derive(Debug, thiserror::Error)]
pub enum Error<B: BlockT> {
	#[error("Header uses the wrong engine {0:?}")]
	WrongEngine([u8; 4]),
	#[error("Header {0:?} is unsealed")]
	HeaderUnsealed(B::Hash),
	#[error("PoW validation error: invalid seal")]
	InvalidSeal,
	#[error("PoW validation error: malformed seal: {0}")]
	MalformedSeal(SealError),
	#[error("PoW validation error: preliminary verification failed")]
	FailedPreliminaryVerify,
	#[error("Rejecting block too far in future")]
	TooFarInFuture,
	#[error("Fetching best header failed: {0}")]
	BestHeader(sp_blockchain::Error),
	#[error("Best header does not exist")]
	NoBestHeader,
	#[error("Block proposing error: {0}")]
	BlockProposingError(String),
	#[error("Error with block built on {0:?}: {1}")]
	BlockBuiltError(B::Hash, ConsensusError),
	#[error("Creating inherents failed: {0}")]
	CreateInherents(sp_inherents::Error),
	#[error("Checking inherents failed: {0}")]
	CheckInherents(sp_inherents::Error),
	#[error(
		"Checking inherents unknown error for identifier: {}",
		String::from_utf8_lossy(.0)
	)]
	CheckInherentsUnknownError(sp_inherents::InherentIdentifier),
	#[error("Multiple pre-runtime digests")]
	MultiplePreRuntimeDigests,
	#[error("Header has an encoded digest of {0} bytes; expected {1}-byte commitment window")]
	DigestWindowMismatch(usize, usize),
	#[error("Seed block #{0} is not reachable from the block being verified")]
	SeedUnreachable(u64),
	#[error("Parent {0:?} is unknown")]
	UnknownParent(B::Hash),
	#[error("Block claims height {height}, but its parent is #{parent_number}")]
	HeightMismatch { height: u64, parent_number: u64 },
	#[error("Block #{height} is at or below the finalized height #{finalized}")]
	BelowFinalized { height: u64, finalized: u64 },
	#[error("RandomX engine error: {0}")]
	Engine(EngineError),
	#[error(transparent)]
	Client(sp_blockchain::Error),
	#[error(transparent)]
	Codec(codec::Error),
	#[error("{0}")]
	Environment(String),
	#[error("{0}")]
	Runtime(String),
	#[error("{0}")]
	Other(String),
}

impl<B: BlockT> From<Error<B>> for String {
	fn from(error: Error<B>) -> String {
		error.to_string()
	}
}

impl<B: BlockT> From<Error<B>> for ConsensusError {
	fn from(error: Error<B>) -> ConsensusError {
		ConsensusError::ClientImport(error.to_string())
	}
}

/// The seed a block at `height` hashes under, the seed the next epoch will use,
/// and the height the first of those came from.
///
/// Resolved along the candidate's **own ancestry**, never by canonical height
/// alone: a fork candidate has to use the seed block that is its own ancestor,
/// which is what Monero does for alt chains. The fast path is one hash lookup,
/// because a parent that is on the canonical chain shares its ancestry with it.
pub fn seed_hashes<B, C>(
	client: &C,
	parent_hash: B::Hash,
	height: u64,
) -> Result<(H256, H256, u64), Error<B>>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B> + HeaderBackend<B>,
	C::Api: QPoWApi<B>,
{
	let api = client.runtime_api();
	let epoch = api
		.get_seed_epoch_blocks(parent_hash)
		.map_err(|e| Error::Runtime(format!("seed epoch length: {e:?}")))? as u64;
	let lag = api
		.get_seed_epoch_lag(parent_hash)
		.map_err(|e| Error::Runtime(format!("seed epoch lag: {e:?}")))? as u64;

	let seed_height = seed::seed_height(height, epoch, lag);
	let next_seed_height = seed::next_seed_height(height, epoch, lag);

	let seed = hash_at_ancestor::<B, C>(client, parent_hash, height, seed_height, epoch + lag)?;
	let next = if next_seed_height == seed_height {
		seed
	} else {
		hash_at_ancestor::<B, C>(client, parent_hash, height, next_seed_height, epoch + lag)?
	};
	Ok((seed, next, seed_height))
}

/// The client, seen as the two questions the seed walk asks it.
struct BackendView<'a, B, C> {
	client: &'a C,
	_block: PhantomData<B>,
}

impl<B, C> seed::ChainView for BackendView<'_, B, C>
where
	B: BlockT<Hash = H256>,
	C: HeaderBackend<B>,
{
	fn canonical_hash(&self, number: u64) -> Result<Option<H256>, String> {
		let number: NumberFor<B> = UniqueSaturatedFrom::unique_saturated_from(number);
		self.client.hash(number).map_err(|e| e.to_string())
	}

	fn parent_of(&self, hash: H256) -> Result<Option<H256>, String> {
		Ok(self.client.header(hash).map_err(|e| e.to_string())?.map(|h| *h.parent_hash()))
	}
}

/// The hash of the block at `target_height` on the branch that ends at
/// `parent_hash`.
fn hash_at_ancestor<B, C>(
	client: &C,
	parent_hash: B::Hash,
	height: u64,
	target_height: u64,
	max_walk: u64,
) -> Result<H256, Error<B>>
where
	B: BlockT<Hash = H256>,
	C: HeaderBackend<B>,
{
	let view = BackendView::<B, C> { client, _block: PhantomData };
	seed::resolve_on_branch(&view, parent_hash, height, target_height, max_walk)
		.map_err(Error::Other)?
		.ok_or(Error::SeedUnreachable(target_height))
}

/// Where a header sits: its height must be its parent's plus one, and it must
/// be somewhere the chain could still accept it.
///
/// The height is attacker-supplied and it is load bearing twice over: it picks
/// the RandomX seed epoch, and it is hashed into the mining blob. The runtime
/// does catch a mismatch in `frame_executive::initial_checks`, but only once
/// the body executes, which is several expensive stages later. Checking it
/// here, before the seed walk and before any hash, is what keeps a header that
/// lies about its height from buying an ancestry walk the length of a whole
/// seed epoch plus a RandomX hash for a few hundred bytes of input.
///
/// Existing finalized database boundaries are respected by this check. New
/// Qnero databases retain genesis as their only finalized block, allowing an
/// old valid branch to compete by cumulative work. Startup refuses legacy
/// databases that already advanced irreversible finality.
pub fn check_header_position<B, C>(
	client: &C,
	parent_hash: B::Hash,
	height: u64,
	block_hash: B::Hash,
) -> Result<(), Error<B>>
where
	B: BlockT<Hash = H256>,
	C: HeaderBackend<B>,
{
	let parent_number: u64 = client
		.number(parent_hash)
		.map_err(Error::Client)?
		.ok_or(Error::UnknownParent(parent_hash))?
		.try_into()
		.unwrap_or(u64::MAX);
	if height != parent_number.saturating_add(1) {
		return Err(Error::HeightMismatch { height, parent_number });
	}

	let info = client.info();
	let finalized: u64 = info.finalized_number.try_into().unwrap_or(u64::MAX);
	if height > finalized {
		return Ok(());
	}

	// Below the floor, and only here, the two exemptions are worth a lookup
	// each: the gap left by warp or fast sync, and a block the node already
	// has, which is what `check-block` and `import-blocks` hand back to the
	// import queue by design. A peer's junk header is neither, so it still
	// costs one read and no hash.
	let fills_the_sync_gap = info
		.block_gap
		.is_some_and(|gap| TryInto::<u64>::try_into(gap.start).unwrap_or(u64::MAX) == height);
	let already_imported =
		matches!(client.status(block_hash), Ok(sp_blockchain::BlockStatus::InChain));
	if fills_the_sync_gap || already_imported {
		return Ok(());
	}
	Err(Error::BelowFinalized { height, finalized })
}

/// Verify one block's proof of work, and return the work it contributes.
///
/// This is the single implementation of the rule. The import queue's verifier
/// calls it so a bad seal is `VerificationFailed` and the peer can be
/// penalised, and `import_block` calls it so nothing reaches the database
/// unverified, including blocks this node mined itself. There is no second
/// copy of the comparison anywhere: the miner in `MiningHandle::submit` and the
/// stratum server both go through [`check_seal`] below, which is what this
/// function calls once it has resolved the seed and the difficulty.
pub fn verify_pow<B, C>(
	client: &C,
	engine: &Arc<RandomxEngine>,
	parent_hash: B::Hash,
	height: u64,
	pre_hash: B::Hash,
	block_hash: B::Hash,
	seal_bytes: &[u8],
) -> Result<U512, Error<B>>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B> + HeaderBackend<B>,
	C::Api: QPoWApi<B>,
{
	// Shape first, before anything is hashed: a seal that is not exactly 64
	// bytes with the pinned padding is refused whatever it hashes to.
	let seal = Seal::decode(seal_bytes).map_err(Error::MalformedSeal)?;

	// Then the position: the seed epoch and the blob both come off this height,
	// so it has to agree with where the block actually sits, and the block has
	// to sit somewhere the chain could still accept it.
	check_header_position::<B, C>(client, parent_hash, height, block_hash)?;

	let difficulty = client
		.runtime_api()
		.get_difficulty(parent_hash)
		.map_err(|e| Error::Runtime(format!("difficulty: {e:?}")))?;

	let (seed, _next_seed, seed_height) = seed_hashes::<B, C>(client, parent_hash, height)?;

	check_seal::<B>(engine, pre_hash, height, seed, seal, difficulty)?;

	log::trace!(
		target: LOG_TARGET,
		"verified rx/0 seal for #{height} (seed #{seed_height} {}, difficulty {difficulty})",
		hex::encode(seed),
	);

	// The block's work is the difficulty it had to beat. Every block at one
	// difficulty then contributes the same deterministic amount, which is
	// Bitcoin's and Ethereum's rule and is what makes cumulative work track
	// expended hash power; the difficulty a block happened to achieve would
	// make one lucky hash dominate the sum.
	Ok(difficulty)
}

/// The proof-of-work comparison itself, given everything already resolved.
///
/// Separated out so that authoring, which already knows the seed and the
/// difficulty for the template it built, checks exactly the same rule the
/// importer will apply, without re-walking the chain.
pub fn check_seal<B>(
	engine: &Arc<RandomxEngine>,
	pre_hash: B::Hash,
	height: u64,
	seed: H256,
	seal: Seal,
	difficulty: U512,
) -> Result<[u8; 32], Error<B>>
where
	B: BlockT<Hash = H256>,
{
	let blob = blob::build_blob(&pre_hash.0, height, seal.extra_nonce, seal.nonce);
	let hash = engine.hash(seed.0, &blob).map_err(Error::Engine)?;
	if !target::meets_difficulty(&hash, difficulty) {
		return Err(Error::InvalidSeal);
	}
	Ok(hash)
}

/// A block importer for RandomX proof of work.
pub struct PowBlockImport<B: BlockT<Hash = H256>, I, C, CIDP, BE, const LOGGING_FREQUENCY: u64> {
	inner: I,
	client: Arc<C>,
	engine: Arc<RandomxEngine>,
	create_inherent_data_providers: Arc<CIDP>,
	check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
	// Serializes the best-work read, fork-choice decision and inner import so
	// concurrent imports cannot race on a stale best. Shared across clones.
	import_lock: Arc<futures::lock::Mutex<()>>,
	_backend: PhantomData<BE>,
}

impl<
		B: BlockT<Hash = H256>,
		I: Clone,
		C: ProvideRuntimeApi<B>,
		CIDP,
		BE,
		const LOGGING_FREQUENCY: u64,
	> Clone for PowBlockImport<B, I, C, CIDP, BE, LOGGING_FREQUENCY>
{
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
			client: self.client.clone(),
			engine: self.engine.clone(),
			create_inherent_data_providers: self.create_inherent_data_providers.clone(),
			check_inherents_after: self.check_inherents_after,
			import_lock: self.import_lock.clone(),
			_backend: PhantomData,
		}
	}
}

impl<B, I, C, CIDP, BE, const LOGGING_FREQUENCY: u64>
	PowBlockImport<B, I, C, CIDP, BE, LOGGING_FREQUENCY>
where
	B: BlockT<Hash = H256>,
	I: BlockImport<B> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B>
		+ BlockBackend<B>
		+ Send
		+ Sync
		+ HeaderBackend<B>
		+ AuxStore
		+ BlockOf
		+ 'static,
	C::Api: QPoWApi<B>,
	C::Api: BlockBuilderApi<B>,
	CIDP: CreateInherentDataProviders<B, ()>,
	BE: sc_client_api::Backend<B>,
{
	/// Create a new block import suitable to be used in PoW
	pub fn new(
		inner: I,
		client: Arc<C>,
		engine: Arc<RandomxEngine>,
		check_inherents_after: <<B as BlockT>::Header as HeaderT>::Number,
		create_inherent_data_providers: CIDP,
	) -> Self {
		Self {
			inner,
			client,
			engine,
			check_inherents_after,
			create_inherent_data_providers: Arc::new(create_inherent_data_providers),
			import_lock: Arc::new(futures::lock::Mutex::new(())),
			_backend: PhantomData,
		}
	}

	async fn check_inherents(
		&self,
		block: B,
		at_hash: B::Hash,
		inherent_data_providers: CIDP::InherentDataProviders,
	) -> Result<(), Error<B>> {
		if *block.header().number() < self.check_inherents_after {
			return Ok(());
		}

		let inherent_data = inherent_data_providers
			.create_inherent_data()
			.await
			.map_err(|e| Error::CreateInherents(e))?;

		let inherent_res = self
			.client
			.runtime_api()
			.check_inherents(at_hash, block.into(), inherent_data)
			.map_err(|e| Error::Client(e.into()))?;

		if !inherent_res.ok() {
			for (identifier, error) in inherent_res.into_errors() {
				match inherent_data_providers.try_handle_error(&identifier, &error).await {
					Some(res) => res.map_err(Error::CheckInherents)?,
					None => return Err(Error::CheckInherentsUnknownError(identifier)),
				}
			}
		}

		Ok(())
	}
}

#[async_trait::async_trait]
impl<B, I, C, CIDP, BE, const LOGGING_FREQUENCY: u64> BlockImport<B>
	for PowBlockImport<B, I, C, CIDP, BE, LOGGING_FREQUENCY>
where
	B: BlockT<Hash = H256>,
	I: BlockImport<B> + Send + Sync,
	I::Error: Into<ConsensusError>,
	C: ProvideRuntimeApi<B>
		+ BlockBackend<B>
		+ Send
		+ Sync
		+ HeaderBackend<B>
		+ AuxStore
		+ BlockOf
		+ 'static,
	C::Api: BlockBuilderApi<B> + QPoWApi<B>,
	CIDP: CreateInherentDataProviders<B, ()> + Send + Sync,
	BE: sc_client_api::Backend<B> + 'static,
{
	type Error = ConsensusError;

	async fn check_block(&self, block: BlockCheckParams<B>) -> Result<ImportResult, Self::Error> {
		self.inner.check_block(block).await.map_err(Into::into)
	}

	async fn import_block(
		&self,
		mut block_import_params: BlockImportParams<B>,
	) -> Result<ImportResult, Self::Error> {
		// The canonical post-seal digest must encode to exactly the window
		// committed by `Header::hash()`, except for the one-byte
		// `RuntimeEnvironmentUpdated` leftover on historical runtime-upgrade
		// blocks at or below `LEGACY_DIGEST_CUTOFF` (see
		// `check_digest_commitment_window`). Short encodings are zero-padded
		// and long encodings are truncated, so either mismatch would let two
		// distinct sealed headers collide. Fail closed before *any* `hash()`
		// call on this header, and without embedding a hash of the malformed
		// header in the error. The pre-seal digest is a prefix of the
		// post-seal one, so this bound also covers the pre-seal
		// `header.hash()` calls below.
		let post_header = block_import_params.post_header();
		let number = (*block_import_params.header.number()).try_into().unwrap_or(u64::MAX);
		if let Err(encoded_digest_len) =
			check_digest_commitment_window(post_header.digest(), number)
		{
			return Err(
				Error::<B>::DigestWindowMismatch(encoded_digest_len, DIGEST_LOGS_SIZE).into()
			);
		}

		let parent_hash = *block_import_params.header.parent_hash();

		if let Some(inner_body) = block_import_params.body.take() {
			let check_block = B::new(block_import_params.header.clone(), inner_body);

			if !block_import_params.state_action.skip_execution_checks() {
				self.check_inherents(
					check_block.clone(),
					parent_hash,
					self.create_inherent_data_providers
						.create_inherent_data_providers(parent_hash, ())
						.await?,
				)
				.await?;
			}

			block_import_params.body = Some(check_block.deconstruct().1);
		}

		let inner_seal = fetch_seal::<B>(
			block_import_params.post_digests.last(),
			block_import_params.header.hash(),
		)?;

		let pre_hash = block_import_params.header.hash();

		// The same rule the import queue's verifier applied, applied again:
		// blocks this node mined itself reach `import_block` without passing
		// through the verifier at all.
		let achieved_difficulty = verify_pow::<B, _>(
			&*self.client,
			&self.engine,
			parent_hash,
			number,
			pre_hash,
			post_header.hash(),
			&inner_seal,
		)
		.map_err(|error| {
			log::error!(
				target: LOG_TARGET,
				"Invalid seal for block #{number} on parent {parent_hash:?}: {error}"
			);
			error
		})?;

		// Get parent's cumulative achieved work from aux storage. A backend/decode
		// failure must fail the import: seeding fork choice with zero would be
		// silent corruption.
		let parent_work = get_chain_work::<B, C>(&*self.client, parent_hash)?;

		// Calculate new cumulative achieved work
		let new_work = parent_work.saturating_add(achieved_difficulty);

		// Serialize the best-work read, fork-choice decision and inner import so a
		// concurrent import cannot commit a new best between our read and our commit
		// and let a weaker block win fork choice. Held until the end of the import.
		let _import_guard = self.import_lock.lock().await;

		let info = self.client.info();
		let current_best_work = get_chain_work::<B, C>(&*self.client, info.best_hash)?;

		let is_best = is_heavier(
			new_work,
			*block_import_params.header.number(),
			current_best_work,
			info.best_number,
		);
		block_import_params.fork_choice = Some(ForkChoiceStrategy::Custom(is_best));

		// Get block hash (with seal) for achieved work storage.
		// Must use the post-seal hash because that's how blocks are referenced:
		// - parent_hash in child blocks references the post-seal hash
		// - client.info().best_hash is the post-seal hash
		let block_hash = block_import_params.post_header().hash();

		// Log block import progress every LOGGING_FREQUENCY blocks
		let block_number = block_import_params.header.number();
		let block_number_u64: u64 = (*block_number).try_into().unwrap_or(0);
		if block_number_u64.is_multiple_of(LOGGING_FREQUENCY) {
			log::info!(
				"⛏️ Imported blocks #{}-{}: {:?} - extrinsics_root={:?}, state_root={:?}",
				block_number_u64.saturating_sub(LOGGING_FREQUENCY),
				block_number,
				block_import_params.header.hash(),
				block_import_params.header.extrinsics_root(),
				block_import_params.header.state_root()
			);
		} else {
			log::debug!(
				target: LOG_TARGET,
				"⛏️ Importing block #{}: {:?} - extrinsics_root={:?}, state_root={:?}",
				block_number,
				block_import_params.header.hash(),
				block_import_params.header.extrinsics_root(),
				block_import_params.header.state_root()
			);
		}

		// Store cumulative achieved work BEFORE inner import, because inner import
		// triggers notifications that call best_chain which needs this data.
		store_cumulative_achieved_work::<B, C>(&*self.client, block_hash, new_work).map_err(
			|e| {
				ConsensusError::ClientImport(format!(
					"Failed to store cumulative achieved work for {:?}: {:?}",
					block_hash, e
				))
			},
		)?;

		// Import the block. If import fails, clean up the achieved work entry we just stored
		// to prevent stale aux data accumulation from repeated invalid submissions.
		let result = match self.inner.import_block(block_import_params).await {
			Ok(result) => result,
			Err(e) => {
				// Rollback: remove the achieved work entry for the failed import
				if let Err(cleanup_err) =
					delete_cumulative_achieved_work::<B, C>(&*self.client, block_hash)
				{
					log::warn!(
						target: LOG_TARGET,
						"Failed to clean up achieved work after failed import for {:?}: {:?}",
						block_hash,
						cleanup_err
					);
				}
				return Err(e.into());
			},
		};

		// Confirmations remain reversible. Retain work for every imported block
		// so an older branch can become canonical when its cumulative work wins.

		let info = self.client.info();
		log::debug!(target: LOG_TARGET, "📦 Canonical tip: #{} ({:?})", info.best_number, info.best_hash);

		Ok(result)
	}
}

/// Extract the PoW seal from header into post_digests for later verification.
async fn extract_pow_seal<B>(
	mut block: BlockImportParams<B>,
) -> Result<BlockImportParams<B>, String>
where
	B: BlockT<Hash = H256>,
{
	// This is the first point in the import pipeline that hashes a
	// network-supplied header. `Header::hash()` pads short encodings and
	// truncates long ones, so reject anything that is not a permitted
	// commitment-window shape before any `hash()` call. The authoritative
	// check lives in `import_block`; this one only keeps the hashing below
	// panic-free in debug builds.
	let number = (*block.header.number()).try_into().unwrap_or(u64::MAX);
	if let Err(encoded_digest_len) = check_digest_commitment_window(block.header.digest(), number) {
		return Err(format!(
			"Header has an encoded digest of {encoded_digest_len} bytes; expected {DIGEST_LOGS_SIZE}-byte commitment window"
		));
	}

	let hash = block.header.hash();
	let header = &mut block.header;
	let block_hash = hash;
	let seal_item = match header.digest_mut().pop() {
		Some(DigestItem::Seal(id, seal)) => {
			if id == POW_ENGINE_ID {
				// The shape of the seal is a property of the header, so it is
				// checked here, where the header is taken apart, and again
				// inside `verify_pow`. A seal with unpinned padding is a
				// grinding attempt.
				Seal::decode(&seal).map_err(|e| Error::<B>::MalformedSeal(e).to_string())?;
				DigestItem::Seal(id, seal)
			} else {
				return Err(Error::<B>::WrongEngine(id).into());
			}
		},
		_ => return Err(Error::<B>::HeaderUnsealed(block_hash).into()),
	};

	block.post_digests.push(seal_item);
	Ok(block)
}

/// The PoW import queue type.
pub type PowImportQueue<B> = BasicQueue<B>;

/// Verifier that extracts the PoW seal from the header and checks the
/// proof-of-work before the block reaches `import_block`.
///
/// The check lives here, in the `Verifier` the import queue calls, so that a
/// bad seal surfaces as `BlockImportError::VerificationFailed`, the variant
/// that carries the peer id and lets the sync layer penalise and drop the
/// sending peer. It also runs before the expensive `check_inherents` call in
/// `import_block`, so a junk block is discarded for one RandomX hash instead
/// of a full-body inherent check.
struct PowVerifier<C> {
	client: Arc<C>,
	engine: Arc<RandomxEngine>,
}

impl<C> PowVerifier<C> {
	fn new(client: Arc<C>, engine: Arc<RandomxEngine>) -> Self {
		Self { client, engine }
	}
}

#[async_trait::async_trait]
impl<B, C> Verifier<B> for PowVerifier<C>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync,
	C::Api: QPoWApi<B>,
{
	async fn verify(&self, block: BlockImportParams<B>) -> Result<BlockImportParams<B>, String> {
		// Pop the seal into `post_digests` and reject a digest that is not a
		// permitted commitment-window shape. After this the header is the
		// pre-seal header, so `hash()` yields the pre-hash the nonce was mined
		// against.
		let block = extract_pow_seal::<B>(block).await?;

		let parent_hash = *block.header.parent_hash();
		let number = (*block.header.number()).try_into().unwrap_or(u64::MAX);
		let pre_hash = block.header.hash();
		// With the seal back on the header: the block's own hash, which is what
		// the position check needs to recognise a block the node already has.
		let block_hash = block.post_hash();
		let inner_seal = fetch_seal::<B>(block.post_digests.last(), pre_hash)?;

		verify_pow::<B, _>(
			&*self.client,
			&self.engine,
			parent_hash,
			number,
			pre_hash,
			block_hash,
			&inner_seal,
		)
		.map_err(|error| {
			log::error!(
				target: LOG_TARGET,
				"Invalid seal for block #{number} on parent {parent_hash:?}: {error}"
			);
			String::from(error)
		})?;

		Ok(block)
	}
}

/// Import queue for the RandomX engine.
pub fn import_queue<B, C>(
	block_import: BoxBlockImport<B>,
	justification_import: Option<BoxJustificationImport<B>>,
	client: Arc<C>,
	engine: Arc<RandomxEngine>,
	spawner: &impl sp_core::traits::SpawnEssentialNamed,
	registry: Option<&Registry>,
) -> Result<PowImportQueue<B>, sp_consensus::Error>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B> + BlockBackend<B> + HeaderBackend<B> + Send + Sync + 'static,
	C::Api: QPoWApi<B>,
{
	let verifier = PowVerifier::new(client, engine);
	Ok(BasicQueue::new(verifier, block_import, justification_import, spawner, registry))
}

/// Minimum interval between transaction-triggered rebuilds.
/// Set high enough to prevent the "rebuild loop" under high tx load where block construction
/// time dominates and effective mining time approaches zero, causing block times to spike.
const MIN_INTERVAL_BETWEEN_TX_REBUILDS: Duration = Duration::from_secs(2);

/// Start the mining worker. This function provides the necessary helper functions that can
/// be used to implement a miner. However, it does not do the CPU-intensive mining itself.
///
/// Two values are returned -- a worker, which contains functions that allows querying the current
/// mining metadata and submitting mined blocks, and a future, which must be polled to fill in
/// information in the worker.
///
/// Authoring starts disabled. The caller must enable it through
/// [`MiningHandle::set_authoring_enabled`] after its authoring policy passes.
///
/// The worker will rebuild blocks when:
/// - A new block is imported from the network
/// - New transactions arrive (rate limited to MIN_INTERVAL_BETWEEN_TX_REBUILDS)
///
/// This allows transactions to be included faster since we don't wait for the next block import
/// to rebuild. Mining on a new block vs the old block has the same probability of success per
/// nonce, so the only cost is the overhead of rebuilding (which is minimal compared to mining
/// time).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub fn start_mining_worker<Block, C, E, L, CIDP, TxHash, TxStream>(
	block_import: BoxBlockImport<Block>,
	client: Arc<C>,
	engine: Arc<RandomxEngine>,
	mut env: E,
	justification_sync_link: L,
	author_label: AuthorLabel,
	create_inherent_data_providers: CIDP,
	tx_notifications: TxStream,
	build_time: Duration,
) -> (MiningHandle<Block, C, L, <E::Proposer as Proposer<Block>>::Proof>, impl Future<Output = ()>)
where
	Block: BlockT<Hash = H256>,
	C: BlockchainEvents<Block>
		+ ProvideRuntimeApi<Block>
		+ BlockBackend<Block>
		+ HeaderBackend<Block>
		+ Send
		+ Sync
		+ 'static,
	C::Api: QPoWApi<Block>,
	E: Environment<Block> + Send + Sync + 'static,
	E::Error: std::fmt::Debug,
	E::Proposer: Proposer<Block>,
	L: JustificationSyncLink<Block>,
	CIDP: CreateInherentDataProviders<Block, ()>,
	TxHash: Send + 'static,
	TxStream: Stream<Item = TxHash> + Send + Unpin + 'static,
{
	let mut trigger_stream = UntilImportedOrTransaction::new(
		client.import_notification_stream(),
		tx_notifications,
		MIN_INTERVAL_BETWEEN_TX_REBUILDS,
	);
	// Latest build request - overwrites previous if builder is slow.
	// Uses a Mutex<Option> for the value + a channel for wake notification.
	let pending_build: Arc<parking_lot::Mutex<Option<Block::Hash>>> =
		Arc::new(parking_lot::Mutex::new(None));
	let (notify_tx, mut notify_rx) = futures::channel::mpsc::channel::<()>(1);

	let worker = MiningHandle::new(
		client.clone(),
		engine.clone(),
		block_import,
		justification_sync_link,
		pending_build.clone(),
		notify_tx.clone(),
	);
	let worker_ret = worker.clone();

	// Task 1: Convert triggers into build requests
	let trigger_task = {
		let client = client.clone();
		let worker = worker.clone();
		let pending_build = pending_build.clone();
		let mut notify_tx = notify_tx;
		async move {
			while let Some(trigger) = trigger_stream.next().await {
				if !worker.is_authoring_enabled() {
					continue;
				}
				let best_hash = client.info().best_hash;

				// Optimization, skip if we already imported this block
				if trigger == RebuildTrigger::BlockImported && worker.best_hash() == Some(best_hash)
				{
					continue;
				}

				// Set the latest build request (overwrites any previous)
				*pending_build.lock() = Some(best_hash);
				let _ = notify_tx.try_send(()); // Err is ok: Full (wake queued) or Disconnected (will exit)
			}
		}
	};

	// Task 2: Process build requests and update worker
	let build_task = async move {
		while notify_rx.next().await.is_some() {
			// Take the latest request (may have been overwritten multiple times)
			let Some(target_hash) = pending_build.lock().take() else {
				continue;
			};
			if !worker.is_authoring_enabled() {
				continue;
			}

			// Build the block
			if let Some(build) = create_proposal(
				&client,
				&mut env,
				&create_inherent_data_providers,
				target_hash,
				&author_label,
				build_time,
			)
			.await
			{
				worker.on_build(build);
			}
		}
	};

	let task = async move {
		futures::join!(trigger_task, build_task);
	};

	(worker_ret, task)
}

/// Create a block proposal. Returns None if any step fails (errors are logged).
async fn create_proposal<Block, C, E, CIDP>(
	client: &Arc<C>,
	env: &mut E,
	create_inherent_data_providers: &CIDP,
	best_hash: Block::Hash,
	author_label: &AuthorLabel,
	build_time: Duration,
) -> Option<MiningBuild<Block, <E::Proposer as Proposer<Block>>::Proof>>
where
	Block: BlockT<Hash = H256>,
	C: HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
	C::Api: QPoWApi<Block>,
	E: Environment<Block>,
	E::Error: std::fmt::Debug,
	E::Proposer: Proposer<Block>,
	CIDP: CreateInherentDataProviders<Block, ()>,
{
	let best_header = match client.header(best_hash) {
		Ok(Some(h)) => h,
		Ok(None) => {
			warn!(target: LOG_TARGET, "Best header not found for hash: {:?}", best_hash);
			return None;
		},
		Err(e) => {
			warn!(target: LOG_TARGET, "Header lookup error: {}", e);
			return None;
		},
	};

	let difficulty = match get_difficulty::<Block, C>(&**client, best_hash) {
		Ok(d) => d,
		Err(e) => {
			warn!(target: LOG_TARGET, "Fetch difficulty failed: {}", e);
			return None;
		},
	};

	let parent_number: u64 = (*best_header.number()).try_into().unwrap_or(u64::MAX);
	let height = parent_number.saturating_add(1);

	// The seed is resolved on the branch this candidate extends, so a candidate
	// on a fork hashes under its own ancestry's seed.
	let (seed_hash, next_seed_hash, seed_height) =
		match seed_hashes::<Block, C>(&**client, best_hash, height) {
			Ok(seeds) => seeds,
			Err(e) => {
				warn!(target: LOG_TARGET, "Resolving the RandomX seed failed: {}", e);
				return None;
			},
		};

	let inherent_data_providers = match create_inherent_data_providers
		.create_inherent_data_providers(best_hash, ())
		.await
	{
		Ok(p) => p,
		Err(e) => {
			warn!(target: LOG_TARGET, "Creating inherent data providers failed: {}", e);
			return None;
		},
	};

	let inherent_data = match inherent_data_providers.create_inherent_data().await {
		Ok(d) => d,
		Err(e) => {
			warn!(target: LOG_TARGET, "Creating inherent data failed: {}", e);
			return None;
		},
	};

	let proposer = match env.init(&best_header).await {
		Ok(p) => p,
		Err(e) => {
			warn!(target: LOG_TARGET, "Creating proposer failed: {:?}", e);
			return None;
		},
	};

	// One item per block, and this block's own. See [`AuthorLabel`]: a label
	// that did not change from block to block would name every block this
	// operator wins.
	let author_label = author_label(best_hash);
	let mut inherent_digest = Digest::default();
	inherent_digest.push(DigestItem::PreRuntime(POW_ENGINE_ID, author_label.to_vec()));

	let proposal = match proposer.propose(inherent_data, inherent_digest, build_time, None).await {
		Ok(p) => p,
		Err(e) => {
			warn!(target: LOG_TARGET, "Creating proposal failed: {}", e);
			return None;
		},
	};

	// Check if best_hash changed during building
	if client.info().best_hash != best_hash {
		info!(target: LOG_TARGET, "Best hash changed during block building, discarding proposal");
		return None;
	}

	Some(MiningBuild {
		metadata: MiningMetadata {
			best_hash,
			pre_hash: proposal.block.header().hash(),
			author_label,
			difficulty,
			height,
			seed_hash,
			next_seed_hash,
			seed_height,
		},
		proposal,
	})
}

/// Fetch the seal from the given digest, if present and valid.
fn fetch_seal<B: BlockT>(digest: Option<&DigestItem>, hash: B::Hash) -> Result<RawSeal, Error<B>> {
	match digest {
		Some(DigestItem::Seal(id, seal)) if *id == POW_ENGINE_ID => Ok(seal.clone()),
		Some(DigestItem::Seal(id, _)) => Err(Error::<B>::WrongEngine(*id)),
		_ => Err(Error::<B>::HeaderUnsealed(hash)),
	}
}

/// The difficulty a block built on `parent` must beat, from the chain state at
/// that parent.
pub fn get_difficulty<B, C>(client: &C, parent: B::Hash) -> Result<U512, Error<B>>
where
	B: BlockT<Hash = H256>,
	C: ProvideRuntimeApi<B>,
	C::Api: QPoWApi<B>,
{
	client
		.runtime_api()
		.get_difficulty(parent)
		.map_err(|_| Error::Runtime("Failed to fetch difficulty".into()))
}

#[cfg(test)]
mod tests;
