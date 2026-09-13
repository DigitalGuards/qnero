//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.
//!
//! This module provides the main service setup for a Qnero node, including:
//! - Network configuration and setup
//! - Transaction pool management
//! - Mining infrastructure (local and external miner support)
//! - RPC endpoint configuration

use futures::FutureExt;
#[cfg(feature = "tx-logging")]
use futures::StreamExt;
use qnero_runtime::{self, apis::RuntimeApi, opaque::Block};
use sc_client_api::Backend;
use sc_consensus_randomx::{blob, target, MiningHandle, MiningMetadata, RandomxEngine, Seal};
use sc_service::{error::Error as ServiceError, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
#[cfg(feature = "tx-logging")]
use sc_transaction_pool_api::InPoolTransaction;
use sc_transaction_pool_api::{OffchainTransactionPoolFactory, TransactionPool};
use sp_inherents::CreateInherentDataProviders;
use tokio_util::sync::CancellationToken;

use crate::{coinbase, prometheus::BusinessMetrics, stratum};
use jsonrpsee::tokio;
use sc_basic_authorship::ProposerFactory;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_qpow::QPoWApi;
use sp_core::{crypto::AccountId32, U512};
use std::{sync::Arc, time::Duration};

/// Frequency of block import logging. Every 1000 blocks.
const LOG_FREQUENCY: u64 = 1000;

/// Default tip-age limit for the initial-sync authoring guard: 24 hours,
/// matching Bitcoin's `DEFAULT_MAX_TIP_AGE`. Deliberately wall-clock scale
/// rather than a small multiple of the block interval: the guard only needs to
/// distinguish "way behind, still syncing" from "roughly current", and a tight
/// window would let a chain stall outlast it, deadlocking recovery if all
/// miners restart during the stall (nobody authors the block that would
/// freshen the tip). Tunable via `--max-tip-age`.
pub const DEFAULT_MAX_TIP_AGE_SECS: u64 = 24 * 60 * 60;

fn tip_is_stale(now_ms: u64, tip_timestamp_ms: u64, max_tip_age_ms: u64) -> bool {
	now_ms.saturating_sub(tip_timestamp_ms) > max_tip_age_ms
}

/// Whether the stale-tip freshness gate applies before authoring.
fn freshness_gate_applies(allow_mining_without_peers: bool, tip_has_been_fresh: bool) -> bool {
	!allow_mining_without_peers && !tip_has_been_fresh
}
// ============================================================================
// Mining
// ============================================================================

/// Nonces one in-process mining round tries per thread before it looks up to
/// see whether the template moved.
///
/// Sixteen is about half a second on one light-mode thread at the ~33 H/s this
/// workstation manages, which keeps a `--dev` node responsive without making
/// the version check the dominant cost.
const LOCAL_MINING_BATCH: u32 = 16;

/// How long the loop waits on a stratum share when nothing else is running.
///
/// With in-process mining on, the wait is the round itself: the two producers
/// are raced against each other, so a rig's seal is taken as it lands and not
/// at the next batch boundary.
const STRATUM_POLL_IDLE: Duration = Duration::from_millis(500);

/// Idle RandomX VMs the pool holds before the mining thread count is known:
/// enough for the verifier, the importer and one share check.
const DEFAULT_IDLE_VMS: usize = 8;

/// Idle VMs the pool holds beyond the mining threads, for the same three.
const IDLE_VMS_BESIDE_MINING: usize = 4;

/// The job a template becomes, for whoever is mining it.
fn job_from_metadata(
	job_id: String,
	metadata: &MiningMetadata<sp_core::H256, U512>,
) -> stratum::MiningJob {
	stratum::MiningJob {
		job_id,
		pre_hash: metadata.pre_hash,
		height: metadata.height,
		difficulty: metadata.difficulty,
		seed_hash: metadata.seed_hash,
		next_seed_hash: metadata.next_seed_hash,
	}
}

/// One round of in-process mining: `LOCAL_MINING_BATCH` nonces per thread,
/// each thread on its own RandomX VM, all of them light mode.
///
/// This is what keeps a `--dev` node producing blocks with no rig attached. It
/// is not meant to be competitive: a light-mode VM is an order of magnitude
/// slower than the full-mode dataset a real miner builds, which is the whole
/// reason the stratum endpoint exists.
async fn local_mining_round(
	engine: Arc<RandomxEngine>,
	metadata: MiningMetadata<sp_core::H256, U512>,
	threads: usize,
	start_nonce: u32,
	extra_nonce: u32,
) -> Option<Seal> {
	let (pre_hash, height, seed, difficulty) =
		(metadata.pre_hash, metadata.height, metadata.seed_hash, metadata.difficulty);
	// Dropping this future detaches its workers: a `spawn_blocking` task cannot
	// be aborted, so without a flag they each run their whole batch on the pool
	// that also carries rocksdb reads and block import. The round is dropped
	// every time a rig wins the template, which on a busy endpoint is several
	// times a second.
	let stop = StopFlag::new();
	let mut workers = Vec::with_capacity(threads);
	for thread in 0..threads {
		let engine = engine.clone();
		let stop = stop.handle();
		workers.push(tokio::task::spawn_blocking(move || {
			let lease = match engine.acquire(seed.0) {
				Ok(lease) => lease,
				Err(error) => {
					log::error!("⛏️ RandomX could not start: {error}");
					return None;
				},
			};
			for step in 0..LOCAL_MINING_BATCH {
				if stop.load(std::sync::atomic::Ordering::Relaxed) {
					return None;
				}
				// Threads interleave rather than take disjoint ranges, so a
				// short round still spreads over the space.
				let nonce = start_nonce
					.wrapping_add(step.wrapping_mul(threads as u32))
					.wrapping_add(thread as u32);
				let blob = blob::build_blob(&pre_hash.0, height, extra_nonce, nonce);
				match lease.hash(&blob) {
					Ok(hash) if target::meets_difficulty(&hash, difficulty) =>
						return Some(Seal { nonce, extra_nonce }),
					Ok(_) => {},
					Err(error) => {
						log::error!("⛏️ RandomX hashing failed: {error}");
						return None;
					},
				}
			}
			None
		}));
	}

	let mut found = None;
	for worker in workers {
		if let Ok(Some(seal)) = worker.await {
			// The template is won; the rest of the round is wasted hashing.
			stop.stop();
			found = found.or(Some(seal));
		}
	}
	found
}

/// A stop flag the blocking workers poll, set when the round ends however it
/// ends.
///
/// The `Drop` is the point: the round is a future in a `select!`, and the arm
/// that loses is dropped where it stands.
struct StopFlag(Arc<std::sync::atomic::AtomicBool>);

impl StopFlag {
	fn new() -> Self {
		Self(Arc::new(std::sync::atomic::AtomicBool::new(false)))
	}

	fn handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
		self.0.clone()
	}

	fn stop(&self) {
		self.0.store(true, std::sync::atomic::Ordering::Relaxed);
	}
}

impl Drop for StopFlag {
	fn drop(&mut self) {
		self.stop();
	}
}

/// Which producer won the template.
#[derive(Debug)]
enum Won {
	/// The node's own light-mode miner.
	Local(Seal),
	/// A rig on the stratum endpoint.
	Stratum(stratum::MinedSeal),
}

/// Take whichever producer finishes first, the rig ahead of the local round.
///
/// A share a rig has already found must not wait out a batch of hashing that
/// has not. Polling the seal channel only between batches put up to a full
/// batch of latency in front of every rig seal, and a seal that aged past its
/// template that way was then dropped as superseded: 17 of 65 block-worthy
/// shares in one measured session, each one acknowledged to the miner and then
/// thrown away. Both futures are cancel safe, so a seal the select does not
/// take is still on the channel.
async fn first_producer<L, S>(local: L, stratum: S) -> Option<Won>
where
	L: std::future::Future<Output = Option<Seal>>,
	S: std::future::Future<Output = stratum::MinedSeal>,
{
	tokio::select! {
		biased;
		mined = stratum => Some(Won::Stratum(mined)),
		found = local => found.map(Won::Local),
	}
}

/// Submit a mined seal to the worker handle.
///
/// Returns `true` if submission was successful, `false` otherwise.
async fn submit_mined_block(
	worker_handle: &MiningHandle<
		Block,
		FullClient,
		Arc<sc_network_sync::SyncingService<Block>>,
		(),
	>,
	seal: Vec<u8>,
	mining_start_time: &mut std::time::Instant,
	source: &str,
) -> bool {
	if worker_handle.submit(seal).await {
		let mining_time = mining_start_time.elapsed().as_secs();
		log::info!(
			"🥇 Successfully mined and submitted a new block{} (mining time: {}s)",
			source,
			mining_time
		);
		*mining_start_time = std::time::Instant::now();
		true
	} else {
		log::warn!("⛏️ Failed to submit mined block{}", source);
		false
	}
}

/// Pause proposal building and drop the stratum server's current job on the
/// enabled-to-disabled edge. Stratum has no cancel message, so a miner that is
/// already connected keeps grinding the last job it was pushed;
/// `clear_current_job` only stops *new* logins from being handed stale work.
/// Repeated pauses while already disabled are no-ops so the 5s retry loop does
/// not log a clear every iteration.
async fn pause_authoring(
	worker_handle: &MiningHandle<
		Block,
		FullClient,
		Arc<sc_network_sync::SyncingService<Block>>,
		(),
	>,
	stratum_server: &Option<Arc<stratum::StratumServer>>,
) {
	let was_enabled = worker_handle.is_authoring_enabled();
	worker_handle.set_authoring_enabled(false);
	if was_enabled {
		if let Some(server) = stratum_server {
			server.clear_current_job().await;
		}
	}
}

/// Mine one template, until it is won or superseded.
///
/// Both producers run against the same template: the in-process miner for a
/// devnet with no rig attached, and the stratum server for the rigs that are.
/// Either one's seal goes through `MiningHandle::submit`, which re-checks it
/// under the build lock before it consumes the build.
async fn mine_one_template(
	worker_handle: &MiningHandle<
		Block,
		FullClient,
		Arc<sc_network_sync::SyncingService<Block>>,
		(),
	>,
	stratum_server: &Option<Arc<stratum::StratumServer>>,
	cancellation_token: &CancellationToken,
	job_counter: &mut u64,
	mining_start_time: &mut std::time::Instant,
	mining_threads: usize,
) {
	let job_version = worker_handle.version();
	let Some(metadata) = worker_handle.metadata() else {
		return;
	};

	*job_counter += 1;
	let job_id = job_counter.to_string();
	log::info!(
		"⛏️ Mining #{} with {}: pre_hash={}, difficulty={}, seed #{} {}",
		metadata.height,
		sc_consensus_randomx::ALGO,
		hex::encode(metadata.pre_hash.as_bytes()),
		metadata.difficulty,
		metadata.seed_height,
		hex::encode(metadata.seed_hash.as_bytes()),
	);

	if let Some(server) = stratum_server {
		let stats = server.stats();
		// Shares that met the block difficulty and blocks are separate numbers
		// on purpose: the loop takes one seal per template and drops the rest,
		// so reporting candidates as blocks overstated a rig's output by more
		// than a factor of two.
		log::info!(
			"⛏️ Stratum so far: {} shares accepted, {} rejected, {} at the block difficulty, \
			 {} sealed, {} too late",
			stats.accepted,
			stats.rejected,
			stats.block_candidates,
			stats.sealed,
			stats.superseded,
		);
		server.broadcast_job(job_from_metadata(job_id.clone(), &metadata)).await;
	}

	// Any rebuild, sync-clear, or consumed build bumps the worker version,
	// superseding this template. `submit` re-verifies against the current
	// build under its own lock, so a stale seal can never be imported; these
	// checks only avoid wasted hashing and misleading logs.
	let superseded = || cancellation_token.is_cancelled() || worker_handle.version() != job_version;

	let engine = worker_handle.engine();
	// A fresh extra nonce per template, so a node restarting on the same
	// template does not re-walk the nonces it already tried.
	let extra_nonce: u32 = rand::random();
	let mut nonce_cursor: u32 = rand::random();

	// One batch of in-process hashing, and the cursor moved past it.
	let round = |cursor: &mut u32| {
		let round = local_mining_round(
			engine.clone(),
			metadata.clone(),
			mining_threads,
			*cursor,
			extra_nonce,
		);
		*cursor = cursor.wrapping_add(LOCAL_MINING_BATCH.wrapping_mul(mining_threads as u32));
		round
	};

	while !superseded() {
		let won = match (mining_threads > 0, stratum_server) {
			// Both producers on one template, raced against each other, so a
			// rig's seal is taken the moment it lands.
			(true, Some(server)) =>
				first_producer(round(&mut nonce_cursor), server.recv_seal()).await,
			(true, None) => round(&mut nonce_cursor).await.map(Won::Local),
			(false, Some(server)) =>
				server.recv_seal_timeout(STRATUM_POLL_IDLE).await.map(Won::Stratum),
			(false, None) => {
				// Neither producer is configured: nothing to do but wait for
				// the operator to fix it.
				tokio::time::sleep(STRATUM_POLL_IDLE).await;
				None
			},
		};

		let (seal, source, from_a_rig) = match won {
			Some(Won::Local(seal)) => (seal.encode().to_vec(), " in process".to_string(), false),
			Some(Won::Stratum(mined)) => {
				if mined.job_id != job_id {
					if let Some(server) = stratum_server {
						server.note_seal_superseded();
					}
					log::debug!(target: "stratum", "dropping a seal for the superseded job {}", mined.job_id);
					continue;
				}
				(mined.seal, format!(" by stratum miner {:?}", mined.worker), true)
			},
			None => {
				tokio::task::yield_now().await;
				continue;
			},
		};

		if superseded() {
			if from_a_rig {
				if let Some(server) = stratum_server {
					server.note_seal_superseded();
				}
			}
			return;
		}
		let submitted = submit_mined_block(worker_handle, seal, mining_start_time, &source).await;
		if from_a_rig {
			if let Some(server) = stratum_server {
				if submitted {
					server.note_block_sealed();
				} else {
					server.note_seal_superseded();
				}
			}
		}
		return;
	}
}

/// The main mining loop.
///
/// This function runs continuously until the cancellation token is triggered.
/// It handles:
/// - Waiting for the initial tip to become fresh
/// - Publishing each template to connected rigs, and mining it in process
#[allow(clippy::too_many_arguments)]
async fn mining_loop(
	client: Arc<FullClient>,
	worker_handle: MiningHandle<Block, FullClient, Arc<sc_network_sync::SyncingService<Block>>, ()>,
	sync_service: Arc<sc_network_sync::SyncingService<Block>>,
	stratum_server: Option<Arc<stratum::StratumServer>>,
	cancellation_token: CancellationToken,
	allow_mining_without_peers: bool,
	max_tip_age_ms: u64,
	mining_threads: usize,
) {
	log::info!(
		"⛏️ RandomX mining task spawned ({}, {} in-process thread(s), flags {:?})",
		sc_consensus_randomx::ALGO,
		mining_threads,
		worker_handle.engine().flags(),
	);

	let mut mining_start_time = std::time::Instant::now();
	let mut job_counter: u64 = 0;

	// Track when we first detected offline status for grace period
	let mut offline_since: Option<std::time::Instant> = None;
	const OFFLINE_GRACE_PERIOD: Duration = Duration::from_secs(30);
	let mut tip_has_been_fresh = false;
	let mut logged_stale_tip = false;
	let mut logged_tip_error = false;

	loop {
		if cancellation_token.is_cancelled() {
			pause_authoring(&worker_handle, &stratum_server).await;
			log::info!("⛏️ RandomX mining task shutting down gracefully");
			break;
		}

		// Bitcoin-style IBD gate: authoring never depends on network sync state
		// (which peers could influence). Until the tip has been observed fresh
		// once, refuse to mine on a stale tip; after that, briefly falling
		// behind is tolerated because a stale candidate simply loses the
		// fork-choice race.
		let chain_info = client.info();
		if freshness_gate_applies(allow_mining_without_peers, tip_has_been_fresh) {
			let best_hash = chain_info.best_hash;
			// The freshness comparison needs the wall clock; if it is
			// unreadable, fail closed like the runtime-API error below
			// rather than treating the tip as fresh.
			let now_ms = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.ok()
				.and_then(|duration| u64::try_from(duration.as_millis()).ok());
			match now_ms.ok_or_else(|| "system wall clock is unreadable".to_string()).and_then(
				|now_ms| {
					client
						.runtime_api()
						.get_last_block_time(best_hash)
						.map(|tip_timestamp_ms| (now_ms, tip_timestamp_ms))
						.map_err(|error| error.to_string())
				},
			) {
				Ok((now_ms, tip_timestamp_ms)) => {
					logged_tip_error = false;
					if tip_is_stale(now_ms, tip_timestamp_ms, max_tip_age_ms) {
						pause_authoring(&worker_handle, &stratum_server).await;
						if !logged_stale_tip {
							log::info!(
								"⛏️ Mining paused: best block timestamp is {}s old (limit {}s); waiting to catch up with the network",
								now_ms.saturating_sub(tip_timestamp_ms) / 1000,
								max_tip_age_ms / 1000,
							);
							logged_stale_tip = true;
						} else {
							log::debug!(target: "randomx", "Mining paused: tip is stale");
						}
						tokio::select! {
							_ = tokio::time::sleep(Duration::from_secs(5)) => {}
							_ = cancellation_token.cancelled() => continue
						}
						continue;
					}
					if logged_stale_tip {
						log::info!("⛏️ Tip is fresh again, resuming mining");
					}
					tip_has_been_fresh = true;
				},
				Err(error) => {
					pause_authoring(&worker_handle, &stratum_server).await;
					// Fail closed: this is the only freshness gate for
					// authoring, so an unreadable clock or tip timestamp
					// pauses mining just like a stale one
					// (--force-authoring bypasses).
					if !logged_tip_error {
						log::warn!("⛏️ Mining paused: could not check tip freshness: {error}");
						logged_tip_error = true;
					}
					tokio::select! {
						_ = tokio::time::sleep(Duration::from_secs(5)) => {}
						_ = cancellation_token.cancelled() => continue
					}
					continue;
				},
			}
		}

		// Don't mine if we have no peers (unless --dev or --force-authoring)
		// Use a grace period to handle brief network hiccups
		if !allow_mining_without_peers && sync_service.is_offline() {
			let now = std::time::Instant::now();
			match offline_since {
				None => {
					// First time detecting offline, start grace period
					offline_since = Some(now);
					log::debug!(target: "randomx", "No peers detected, starting {}s grace period before pausing mining", OFFLINE_GRACE_PERIOD.as_secs());
				},
				Some(since) if now.duration_since(since) >= OFFLINE_GRACE_PERIOD => {
					// Grace period exceeded, pause mining
					pause_authoring(&worker_handle, &stratum_server).await;
					log::warn!(target: "randomx", "Mining paused: no connected peers for {}s (node is offline)", OFFLINE_GRACE_PERIOD.as_secs());
					tokio::select! {
						_ = tokio::time::sleep(Duration::from_secs(5)) => {}
						_ = cancellation_token.cancelled() => continue
					}
					continue;
				},
				Some(_) => {
					// Still within grace period, continue mining but log
					log::debug!(target: "randomx", "No peers but still within grace period, continuing mining");
				},
			}
		} else {
			// We have peers (or are in dev mode), reset offline tracking
			if offline_since.is_some() {
				log::info!(target: "randomx", "Peers reconnected, resuming normal mining");
			}
			offline_since = None;
		}

		worker_handle.set_authoring_enabled(true);

		// Wait for mining metadata to be available. If there is no candidate
		// (e.g. it was cleared during an import burst, or a submitted block
		// failed to import) request a rebuild so mining resumes without
		// waiting for an external block/tx trigger.
		if worker_handle.metadata().is_none() {
			log::debug!(target: "randomx", "No mining metadata available, requesting rebuild");
			worker_handle.request_rebuild();
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_millis(250)) => {}
				_ = cancellation_token.cancelled() => continue
			}
			continue;
		}

		mine_one_template(
			&worker_handle,
			&stratum_server,
			&cancellation_token,
			&mut job_counter,
			&mut mining_start_time,
			mining_threads,
		)
		.await;

		// Yield to let other async tasks run
		tokio::task::yield_now().await;
	}

	log::info!("⛏️ RandomX mining task terminated");
}

/// Spawn the transaction logger task.
///
/// This task logs transactions as they are added to the pool.
/// Only available when the `tx-logging` feature is enabled.
#[cfg(feature = "tx-logging")]
fn spawn_transaction_logger(
	task_manager: &TaskManager,
	transaction_pool: Arc<sc_transaction_pool::TransactionPoolHandle<Block, FullClient>>,
	tx_stream: impl futures::Stream<Item = sp_core::H256> + Send + 'static,
) {
	task_manager.spawn_handle().spawn("tx-logger", None, async move {
		let tx_stream = tx_stream;
		futures::pin_mut!(tx_stream);
		while let Some(tx_hash) = tx_stream.next().await {
			if let Some(tx) = transaction_pool.ready_transaction(&tx_hash) {
				log::trace!(target: "miner", "New transaction: Hash = {:?}", tx_hash);
				let extrinsic = tx.data();
				log::trace!(target: "miner", "Payload: {:?}", extrinsic);
			} else {
				log::warn!("⛏️ Transaction {:?} not found in pool", tx_hash);
			}
		}
	});
}

/// Spawn all authority-related tasks (mining, metrics, transaction logging).
///
/// This is only called when the node is running as an authority (block producer).
#[allow(clippy::too_many_arguments)]
fn spawn_authority_tasks(
	task_manager: &mut TaskManager,
	client: Arc<FullClient>,
	transaction_pool: Arc<sc_transaction_pool::TransactionPoolHandle<Block, FullClient>>,
	pow_block_import: PowBlockImport,
	engine: Arc<RandomxEngine>,
	sync_service: Arc<sc_network_sync::SyncingService<Block>>,
	prometheus_registry: Option<prometheus::Registry>,
	rewards_address: AccountId32,
	miner_key: Option<qnero_note_core::MinerKey>,
	stratum_config: Option<stratum::StratumConfig>,
	mining_threads: usize,
	tx_stream_for_worker: impl futures::Stream<Item = sp_core::H256> + Send + Unpin + 'static,
	#[cfg(feature = "tx-logging")] tx_stream_for_logger: impl futures::Stream<Item = sp_core::H256>
		+ Send
		+ 'static,
	allow_mining_without_peers: bool,
	max_tip_age_ms: u64,
) {
	// Create block proposer factory
	let proposer = ProposerFactory::new(
		task_manager.spawn_handle(),
		client.clone(),
		transaction_pool.clone(),
		prometheus_registry.as_ref(),
		None,
	);

	// Create inherent data providers.
	//
	// Two now. The coinbase one is what makes a block's reward a note: it
	// derives this block's note from the operator's miner key and the height,
	// and the runtime hashes the value it decided into the commitment. A node
	// authoring without a miner key supplies no payload and builds a block its
	// own import refuses, which is why `--rewards-miner-key` is required of an
	// authority.
	let coinbase_client = client.clone();
	let label_key = miner_key.clone();
	let inherent_data_providers = Box::new(move |parent, _| {
		let client = coinbase_client.clone();
		let miner_key = miner_key.clone();
		async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
			let coinbase = coinbase::CoinbaseInherentDataProvider::for_child_of::<Block, _>(
				&client,
				parent,
				miner_key.as_ref(),
			)?;
			Ok((timestamp, coinbase))
		}
	})
		as Box<
			dyn CreateInherentDataProviders<
				Block,
				(),
				InherentDataProviders = (
					sp_timestamp::InherentDataProvider,
					coinbase::CoinbaseInherentDataProvider,
				),
			>,
		>;

	// Start the mining worker (block building task).
	//
	// The author label is this block's, not this operator's. `--rewards-inner-hash`
	// is the fallback for a node with no miner key, which cannot author a
	// valid block anyway: a block it built would carry no coinbase inherent
	// and its own import would refuse it. With a miner key the label is
	// `H(cvk, parent)`, so the 32 bytes in the header change every block and
	// nothing groups a miner's blocks, or the coinbase notes in them, for an
	// observer. See `sc_consensus_randomx::AuthorLabel`.
	let fallback_label: [u8; 32] = rewards_address.into();
	let author_label: sc_consensus_randomx::AuthorLabel =
		Arc::new(move |parent: sp_core::H256| match label_key.as_ref() {
			Some(key) => key.author_label(parent.as_ref()).to_bytes(),
			None => fallback_label,
		});
	let (worker_handle, worker_task) = sc_consensus_randomx::start_mining_worker(
		Box::new(pow_block_import),
		client.clone(),
		engine.clone(),
		proposer,
		sync_service.clone(),
		author_label,
		inherent_data_providers,
		tx_stream_for_worker,
		Duration::from_secs(10),
	);

	task_manager
		.spawn_essential_handle()
		.spawn_blocking("block-producer", None, worker_task);

	// Start Prometheus business metrics monitoring
	BusinessMetrics::start_monitoring_task(client.clone(), prometheus_registry, task_manager);

	// Setup graceful shutdown for mining
	let mining_cancellation_token = CancellationToken::new();
	let mining_token_clone = mining_cancellation_token.clone();

	task_manager.spawn_handle().spawn("mining-shutdown-listener", None, async move {
		tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
		log::info!("🛑 Received Ctrl+C signal, shutting down the mining worker");
		mining_token_clone.cancel();
	});

	// Spawn the main mining loop
	task_manager.spawn_essential_handle().spawn("randomx-mining", None, async move {
		// Start the stratum server if a port was given. Failure must abort this
		// essential task (and thus the node) rather than quietly leaving the
		// operator with in-process mining only: they asked for a rig endpoint.
		let stratum_server: Option<Arc<stratum::StratumServer>> =
			if let Some(config) = stratum_config {
				let endpoint = (config.host, config.port);
				match stratum::StratumServer::start(config, engine).await {
					Ok(server) => {
						log::info!(
							"⛏️ Point a rig at {}: xmrig --algo {} -o {} -u <label>",
							server.local_addr(),
							sc_consensus_randomx::ALGO,
							server.local_addr(),
						);
						Some(server)
					},
					Err(error) => {
						log::error!(
							"⛏️ Failed to start the stratum server on {}:{}: {error}",
							endpoint.0,
							endpoint.1,
						);
						return;
					},
				}
			} else {
				if mining_threads == 0 {
					log::error!(
						"⛏️ Neither --stratum-port nor --mining-threads is set to anything \
						 that mines: this authority will never author a block."
					);
				} else {
					log::info!(
						"⛏️ No --stratum-port given: mining in process on {mining_threads} \
						 thread(s), light mode."
					);
				}
				None
			};

		mining_loop(
			client,
			worker_handle,
			sync_service,
			stratum_server,
			mining_cancellation_token,
			allow_mining_without_peers,
			max_tip_age_ms,
			mining_threads,
		)
		.await;
	});

	// Spawn transaction logger (only when tx-logging feature is enabled)
	#[cfg(feature = "tx-logging")]
	spawn_transaction_logger(task_manager, transaction_pool, tx_stream_for_logger);

	log::info!(target: "randomx", "⛏️  Miner spawned");
}

// ============================================================================
// Type Definitions
// ============================================================================

/// WASM host functions. The `runtime-benchmarks` build adds `ext_benchmarking_*`.
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = sp_io::SubstrateHostFunctions;

#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions =
	(sp_io::SubstrateHostFunctions, frame_benchmarking::benchmarking::HostFunctions);

pub(crate) type FullClient =
	sc_service::TFullClient<Block, RuntimeApi, sc_executor::WasmExecutor<HostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
pub type PowBlockImport = sc_consensus_randomx::PowBlockImport<
	Block,
	Arc<FullClient>,
	FullClient,
	Box<
		dyn sp_inherents::CreateInherentDataProviders<
			Block,
			(),
			InherentDataProviders = (
				sp_timestamp::InherentDataProvider,
				coinbase::CoinbaseInherentDataProvider,
			),
		>,
	>,
	FullBackend,
	LOG_FREQUENCY,
>;

pub type Service = sc_service::PartialComponents<
	FullClient,
	FullBackend,
	(),
	sc_consensus::DefaultImportQueue<Block>,
	sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
	(PowBlockImport, Option<Telemetry>, Arc<RandomxEngine>),
>;

#[allow(clippy::result_large_err)]
pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = sc_service::new_wasm_executor::<HostFunctions>(&config.executor);
	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	// Initialize genesis block's achieved work if not already set.
	// Genesis has achieved work = 1 (represents the start of the chain).
	if let Err(e) = sc_consensus_randomx::initialize_genesis_achieved_work::<Block, _>(&*client) {
		log::warn!(target: "randomx", "Failed to initialize genesis achieved work: {:?}", e);
	}

	// One RandomX engine per node, shared by the verifier, the importer, the
	// in-process miner and the stratum server, so they share seed caches: a
	// cache is 256 MiB and an Argon2d fill, and nothing here should pay for it
	// twice. Eight idle VMs to start with, which is a 2 MiB scratchpad each and
	// covers a verifier, an importer and a share check. `new_full` raises the
	// floor to the mining thread count, because a VM the pool cannot hold is a
	// create and a destroy on every mining round.
	let engine = RandomxEngine::light(DEFAULT_IDLE_VMS);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	// Pool type/limits come from CLI (`--pool-type`, `--pool-limit`, `--pool-kbytes`, …)
	// via `Configuration::transaction_pool`. Builder logs the selected type at create time.
	let transaction_pool = Arc::from(
		sc_transaction_pool::Builder::new(
			task_manager.spawn_essential_handle(),
			client.clone(),
			config.role.is_authority().into(),
		)
		.with_options(config.transaction_pool.clone())
		.with_prometheus(config.prometheus_registry())
		.build(),
	);

	// The import-side providers. The coinbase one carries no payload here: an
	// importing node has no reward address and builds nobody's note. It is in
	// the tuple so that the identifier is claimed, because
	// `PowBlockImport::check_inherents` turns an inherent error whose
	// identifier no provider knows into `CheckInherentsUnknownError`, and a
	// block missing its coinbase deserves the refusal that says so.
	let inherent_data_providers = Box::new(move |_, _| async move {
		let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
		Ok((timestamp, coinbase::CoinbaseInherentDataProvider::checking()))
	})
		as Box<
			dyn CreateInherentDataProviders<
				Block,
				(),
				InherentDataProviders = (
					sp_timestamp::InherentDataProvider,
					coinbase::CoinbaseInherentDataProvider,
				),
			>,
		>;

	let pow_block_import = sc_consensus_randomx::PowBlockImport::new(
		Arc::clone(&client),
		Arc::clone(&client),
		Arc::clone(&engine),
		0, // check inherents starting at block 0
		inherent_data_providers,
	);

	let import_queue = sc_consensus_randomx::import_queue::<Block, FullClient>(
		Box::new(pow_block_import.clone()),
		None,
		Arc::clone(&client),
		Arc::clone(&engine),
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
	)?;

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore_container,
		select_chain: (),
		transaction_pool,
		other: (pow_block_import, telemetry, engine),
	})
}

/// Builds a new service for a full client.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
pub fn new_full<
	N: sc_network::NetworkBackend<Block, <Block as sp_runtime::traits::Block>::Hash>,
>(
	config: Configuration,
	rewards_address: AccountId32,
	miner_key: Option<qnero_note_core::MinerKey>,
	stratum_config: Option<stratum::StratumConfig>,
	mining_threads: usize,
	enable_peer_sharing: bool,
	sync_max_timeouts_before_drop: u32,
	sync_disable_major_sync_gating: bool,
	sync_block_request_timeout: u64,
	allow_mining_without_peers: bool,
	max_tip_age_secs: u64,
) -> Result<TaskManager, ServiceError> {
	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain: _,
		transaction_pool,
		other: (pow_block_import, mut telemetry, engine),
	} = new_partial(&config)?;

	// The pool has to be at least as deep as the number of threads leasing from
	// it, or every mining round past its depth creates and destroys a VM: a
	// 2 MiB scratchpad and, with the JIT on, an executable code buffer, twice a
	// second per thread.
	engine.reserve_idle_vms(mining_threads.saturating_add(IDLE_VMS_BESIDE_MINING));

	let tx_stream_for_worker = transaction_pool.clone().import_notification_stream();
	#[cfg(feature = "tx-logging")]
	let tx_stream_for_logger = transaction_pool.clone().import_notification_stream();

	let timeout = std::time::Duration::from_secs(sync_block_request_timeout);
	sc_network_sync::set_block_request_timeout(timeout);
	sc_network::set_transport_timeout(timeout);

	let net_config = sc_network::config::FullNetworkConfiguration::<
		Block,
		<Block as sp_runtime::traits::Block>::Hash,
		N,
	>::new(&config.network, config.prometheus_registry().cloned());
	let metrics = N::register_notification_metrics(config.prometheus_registry());

	let (network, system_rpc_tx, tx_handler_controller, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_config: None,
			block_relay: None,
			metrics,
		})?;

	sync_service.set_max_timeouts_before_drop(sync_max_timeouts_before_drop);
	sync_service.set_disable_major_sync_gating(sync_disable_major_sync_gating);
	log::debug!(
		"Applied CLI sync flags: max_timeouts_before_drop={}, disable_major_sync_gating={}",
		sync_max_timeouts_before_drop,
		sync_disable_major_sync_gating
	);

	if config.offchain_worker.enabled {
		let offchain_workers =
			sc_offchain::OffchainWorkers::new(sc_offchain::OffchainWorkerOptions {
				runtime_api_provider: client.clone(),
				is_validator: config.role.is_authority(),
				keystore: Some(keystore_container.keystore()),
				offchain_db: backend.offchain_storage(),
				transaction_pool: Some(OffchainTransactionPoolFactory::new(
					transaction_pool.clone(),
				)),
				network_provider: Arc::new(network.clone()),
				enable_http_requests: true,
				custom_extensions: |_| vec![],
			})?;
		task_manager.spawn_handle().spawn(
			"offchain-workers-runner",
			"offchain-worker",
			offchain_workers.run(client.clone(), task_manager.spawn_handle()).boxed(),
		);
	}

	let role = config.role;
	let prometheus_registry = config.prometheus_registry().cloned();
	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();
		let network_for_rpc = if enable_peer_sharing { Some(network.clone()) } else { None };

		Box::new(move |_| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				network: network_for_rpc.clone(),
			};
			crate::rpc::create_full(deps).map_err(Into::into)
		})
	};

	log::info!("🧹 Blocks pruning mode: {:?}", config.blocks_pruning);
	log::info!("📦 State pruning mode: {:?}", config.state_pruning);

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		network: network.clone(),
		client: client.clone(),
		keystore: keystore_container.keystore(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		rpc_builder: rpc_extensions_builder,
		backend,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		config,
		telemetry: telemetry.as_mut(),
		tracing_execute_block: None,
	})?;

	if role.is_authority() {
		#[cfg(feature = "tx-logging")]
		spawn_authority_tasks(
			&mut task_manager,
			client,
			transaction_pool,
			pow_block_import,
			engine,
			sync_service,
			prometheus_registry,
			rewards_address,
			miner_key,
			stratum_config,
			mining_threads,
			tx_stream_for_worker,
			tx_stream_for_logger,
			allow_mining_without_peers,
			max_tip_age_secs.saturating_mul(1000),
		);
		#[cfg(not(feature = "tx-logging"))]
		spawn_authority_tasks(
			&mut task_manager,
			client,
			transaction_pool,
			pow_block_import,
			engine,
			sync_service,
			prometheus_registry,
			rewards_address,
			miner_key,
			stratum_config,
			mining_threads,
			tx_stream_for_worker,
			allow_mining_without_peers,
			max_tip_age_secs.saturating_mul(1000),
		);
	}

	// Note: Finalization is now handled synchronously in import_block,
	// so we don't need a separate finalization task.

	Ok(task_manager)
}

#[cfg(test)]
mod tests {
	use super::{
		first_producer, freshness_gate_applies, stratum, tip_is_stale, Seal, StopFlag, Won,
		DEFAULT_MAX_TIP_AGE_SECS,
	};
	use jsonrpsee::tokio;
	use std::time::{Duration, Instant};

	const NOW_MS: u64 = 1_755_000_000_000;
	const MAX_TIP_AGE_MS: u64 = DEFAULT_MAX_TIP_AGE_SECS * 1000;

	#[test]
	fn fresh_tip_is_not_stale() {
		assert!(!tip_is_stale(NOW_MS, NOW_MS, MAX_TIP_AGE_MS));
		assert!(!tip_is_stale(NOW_MS, NOW_MS - MAX_TIP_AGE_MS, MAX_TIP_AGE_MS));
	}

	#[test]
	fn old_tip_is_stale() {
		assert!(tip_is_stale(NOW_MS, NOW_MS - MAX_TIP_AGE_MS - 1, MAX_TIP_AGE_MS));
	}

	#[test]
	fn genesis_tip_is_stale() {
		assert!(tip_is_stale(NOW_MS, 0, MAX_TIP_AGE_MS));
	}

	#[test]
	fn future_tip_is_not_stale() {
		assert!(!tip_is_stale(NOW_MS, NOW_MS + MAX_TIP_AGE_MS, MAX_TIP_AGE_MS));
	}

	#[test]
	fn gate_applies_until_tip_has_been_fresh() {
		assert!(freshness_gate_applies(false, false));
		assert!(!freshness_gate_applies(false, true));
	}

	#[test]
	fn force_authoring_bypasses_gate() {
		assert!(!freshness_gate_applies(true, false));
	}

	fn rig_seal() -> stratum::MinedSeal {
		stratum::MinedSeal { job_id: "1".to_string(), worker: "rig".to_string(), seal: vec![7; 64] }
	}

	/// A rig's seal must not wait out a batch of in-process hashing.
	///
	/// The loop used to hash a whole batch and then poll the seal channel for a
	/// millisecond, so a block-worthy share sat in the queue for up to half a
	/// second and was dropped as superseded if the template moved first: 17 of
	/// 65 in one measured session, every one of them acknowledged to the miner.
	#[tokio::test]
	async fn a_rig_seal_is_taken_while_the_local_round_is_still_hashing() {
		let local = async {
			tokio::time::sleep(Duration::from_secs(30)).await;
			Some(Seal { nonce: 1, extra_nonce: 2 })
		};
		let started = Instant::now();
		let won = first_producer(local, std::future::ready(rig_seal())).await;

		match won {
			Some(Won::Stratum(mined)) => assert_eq!(mined.job_id, "1"),
			other =>
				panic!("the rig's seal must win a round it did not have to wait for: {other:?}"),
		}
		assert!(
			started.elapsed() < Duration::from_secs(1),
			"the seal waited on the local batch: {:?}",
			started.elapsed(),
		);
	}

	/// And with no rig attached the local round still wins the template.
	#[tokio::test]
	async fn the_local_round_wins_when_no_share_arrives() {
		let won = first_producer(
			std::future::ready(Some(Seal { nonce: 9, extra_nonce: 3 })),
			std::future::pending::<stratum::MinedSeal>(),
		)
		.await;
		match won {
			Some(Won::Local(seal)) => assert_eq!(seal.nonce, 9),
			other => panic!("expected the local seal: {other:?}"),
		}
	}

	/// Dropping a round has to stop its hashing.
	///
	/// The round's workers are `spawn_blocking` tasks, and a blocking task
	/// cannot be aborted: dropping the round detaches them and they run their
	/// whole batch on the pool that also carries rocksdb and block import. The
	/// select drops the round every time a rig wins the template, so on a busy
	/// endpoint that is several abandoned batches a second on top of the ones
	/// the next round starts.
	#[test]
	fn dropping_a_round_stops_its_workers() {
		let flag = StopFlag::new();
		let handle = flag.handle();
		assert!(!handle.load(std::sync::atomic::Ordering::Relaxed));
		drop(flag);
		assert!(
			handle.load(std::sync::atomic::Ordering::Relaxed),
			"a dropped round leaves its workers hashing a template nobody wants",
		);
	}

	/// And a round that wins stops the threads that have not finished.
	#[test]
	fn a_won_round_stops_the_rest_of_its_workers() {
		let flag = StopFlag::new();
		let handle = flag.handle();
		flag.stop();
		assert!(handle.load(std::sync::atomic::Ordering::Relaxed));
	}

	/// A round that finds nothing is a round, and the loop goes again.
	#[tokio::test]
	async fn a_round_that_finds_nothing_wins_nothing() {
		let won =
			first_producer(std::future::ready(None), std::future::pending::<stratum::MinedSeal>())
				.await;
		assert!(won.is_none(), "expected no winner: {won:?}");
	}
}
