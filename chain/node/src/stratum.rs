//! The stratum server xmrig talks to.
//!
//! This is the Monero dialect of stratum, and it is deliberately exact. The
//! Bitcoin family shares the name and nothing else. A stock
//! `xmrig --algo rx/0 -o <node>:<port> -u <name>` must work with no patched
//! miner and no custom build. Line-delimited JSON over plain TCP, one object
//! per line:
//!
//! ```text
//! miner -> node  {"id":1,"method":"login","params":{"login":…,"pass":…,"agent":…}}
//! node  -> miner {"id":1,"result":{"id":<session>,"job":{…},"status":"OK","extensions":[…]}}
//! node  -> miner {"method":"job","params":{"blob":…,"job_id":…,"target":…,"height":…,
//!                                          "seed_hash":…,"next_seed_hash":…,"algo":"rx/0"}}
//! miner -> node  {"id":2,"method":"submit","params":{"id":…,"job_id":…,"nonce":…,"result":…}}
//! node  -> miner {"id":2,"result":{"status":"OK"}}
//! miner -> node  {"id":3,"method":"keepalived","params":{"id":…}}
//! node  -> miner {"id":3,"result":{"status":"KEEPALIVED"}}
//! ```
//!
//! **What the login means here.** Nothing is paid to it. Qnero's block reward
//! is a shielded note minted for the miner key the node itself is configured
//! with (`--rewards-miner-key`), and that key is secret-bearing: it carries the
//! coinbase viewing key, so it is exactly the thing not to send over a plain
//! TCP login line. So this is a solo-mining endpoint: the login string is a
//! worker label, it is logged and otherwise ignored, and whoever runs the node
//! is who the coinbase belongs to. A pool that paid many miners would need a
//! payout ledger and a share accounting scheme, which is a different product.
//!
//! **What is trusted.** Nothing the miner sends. A submitted share is re-hashed
//! here, with the node's own RandomX cache, over a blob the node rebuilds from
//! the job it issued plus the submitted nonce. The `result` field a miner sends
//! is compared against that and never used in its place.

use jsonrpsee::tokio;
use sc_consensus_randomx::{blob, seal::Seal, target, RandomxEngine, ALGO};
use serde_json::{json, Value};
use sp_core::{H256, U512};
use std::{
	collections::{HashMap, HashSet},
	net::{IpAddr, SocketAddr},
	sync::{
		atomic::{AtomicU64, Ordering},
		Arc,
	},
	time::Duration,
};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	net::{TcpListener, TcpStream},
	sync::{mpsc, RwLock},
};

const LOG_TARGET: &str = "stratum";

/// Longest line a miner may send. A login with a long agent string is a few
/// hundred bytes; anything past this is not a miner.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Outgoing queue depth per connection. A miner that will not read its socket
/// is disconnected rather than allowed to consume memory.
const WRITE_QUEUE_DEPTH: usize = 32;

/// How long a connection may stay silent before it is dropped. xmrig sends a
/// keepalive about once a minute when the pool advertises `keepalive`.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// What the node hands miners to work on.
#[derive(Clone, Debug)]
pub struct MiningJob {
	/// Opaque job identifier, echoed in every submit.
	pub job_id: String,
	/// The pre-seal header hash the blob commits to.
	pub pre_hash: H256,
	/// Height of the block being mined.
	pub height: u64,
	/// The difficulty a share has to beat to be a block.
	pub difficulty: U512,
	/// The RandomX seed for this height.
	pub seed_hash: H256,
	/// The seed the next epoch will use.
	pub next_seed_hash: H256,
}

/// A share that was good enough to be a block.
#[derive(Clone, Debug)]
pub struct MinedSeal {
	/// The job it was mined against.
	pub job_id: String,
	/// The worker label from the login, for the log line.
	pub worker: String,
	/// The 64 bytes that go into the header.
	pub seal: Vec<u8>,
}

/// Configuration for the stratum listener.
#[derive(Clone, Debug)]
pub struct StratumConfig {
	/// Address to bind.
	pub host: IpAddr,
	/// Port to bind.
	pub port: u16,
	/// Share difficulty handed to a connection, clamped per job to the block
	/// difficulty so a share is never harder to find than a block.
	pub share_difficulty: u64,
}

struct Session {
	worker: String,
	extra_nonce: u32,
	out: mpsc::Sender<String>,
}

#[derive(Default)]
struct Counters {
	accepted: AtomicU64,
	rejected: AtomicU64,
	blocks: AtomicU64,
}

/// The listener, the sessions, and the share check.
pub struct StratumServer {
	engine: Arc<RandomxEngine>,
	config: StratumConfig,
	current_job: RwLock<Option<MiningJob>>,
	sessions: RwLock<HashMap<u64, Session>>,
	/// (job id, session id, nonce) already seen, cleared when the job changes.
	seen_shares: RwLock<HashSet<(u64, u32)>>,
	next_session_id: AtomicU64,
	seal_tx: mpsc::Sender<MinedSeal>,
	seal_rx: tokio::sync::Mutex<mpsc::Receiver<MinedSeal>>,
	counters: Counters,
	bound: SocketAddr,
}

impl StratumServer {
	/// Bind the listener and start accepting miners.
	pub async fn start(
		config: StratumConfig,
		engine: Arc<RandomxEngine>,
	) -> Result<Arc<Self>, String> {
		let addr = SocketAddr::new(config.host, config.port);
		let listener = TcpListener::bind(addr)
			.await
			.map_err(|e| format!("stratum: cannot bind {addr}: {e}"))?;
		let bound = listener.local_addr().map_err(|e| e.to_string())?;

		let (seal_tx, seal_rx) = mpsc::channel(16);
		let server = Arc::new(Self {
			engine,
			config,
			current_job: RwLock::new(None),
			sessions: RwLock::new(HashMap::new()),
			seen_shares: RwLock::new(HashSet::new()),
			next_session_id: AtomicU64::new(1),
			seal_tx,
			seal_rx: tokio::sync::Mutex::new(seal_rx),
			counters: Counters::default(),
			bound,
		});

		log::info!(
			target: LOG_TARGET,
			"⛏️ Stratum listening on {bound} (algo {ALGO}, share difficulty {})",
			server.config.share_difficulty,
		);

		let accept_server = server.clone();
		tokio::spawn(async move {
			loop {
				match listener.accept().await {
					Ok((stream, peer)) => {
						let server = accept_server.clone();
						tokio::spawn(async move {
							if let Err(error) = server.serve(stream, peer).await {
								log::debug!(target: LOG_TARGET, "miner {peer} disconnected: {error}");
							}
						});
					},
					Err(error) => {
						log::warn!(target: LOG_TARGET, "accept failed: {error}");
						tokio::time::sleep(Duration::from_millis(200)).await;
					},
				}
			}
		});

		Ok(server)
	}

	/// The address the listener actually bound. Port 0 resolves here, which is
	/// what the protocol tests bind.
	pub fn local_addr(&self) -> SocketAddr {
		self.bound
	}

	/// Publish a job and push it to every connected miner. Supersedes the
	/// previous one: stratum has no cancel and needs none.
	pub async fn broadcast_job(&self, job: MiningJob) {
		let notification = json!({
			"jsonrpc": "2.0",
			"method": "job",
			"params": Value::Null,
		});
		*self.current_job.write().await = Some(job.clone());
		self.seen_shares.write().await.clear();

		let sessions = self.sessions.read().await;
		for (id, session) in sessions.iter() {
			let mut notification = notification.clone();
			notification["params"] = self.job_payload(&job, session.extra_nonce);
			// A miner that is not draining its queue is not mining; dropping
			// the push is enough, the connection's own writer will close it.
			if session.out.try_send(notification.to_string()).is_err() {
				log::debug!(target: LOG_TARGET, "session {id} is not keeping up with jobs");
			}
		}
	}

	/// Forget the current job, so a miner that connects next is not handed
	/// stale work.
	pub async fn clear_current_job(&self) {
		*self.current_job.write().await = None;
	}

	/// Wait for a share that was good enough to be a block.
	pub async fn recv_seal_timeout(&self, timeout: Duration) -> Option<MinedSeal> {
		let mut rx = self.seal_rx.lock().await;
		tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
	}

	/// Accepted shares, rejected shares, and shares that were blocks.
	pub fn stats(&self) -> (u64, u64, u64) {
		(
			self.counters.accepted.load(Ordering::Relaxed),
			self.counters.rejected.load(Ordering::Relaxed),
			self.counters.blocks.load(Ordering::Relaxed),
		)
	}

	/// The share difficulty for a job: the configured one, never above the
	/// block difficulty. On a dev chain whose difficulty is below the
	/// configured share difficulty this makes every share a block, which is
	/// what a one-machine devnet wants.
	fn job_share_difficulty(&self, job: &MiningJob) -> u64 {
		self.config
			.share_difficulty
			.min(target::difficulty_as_u64(job.difficulty))
			.max(1)
	}

	fn job_payload(&self, job: &MiningJob, extra_nonce: u32) -> Value {
		let blob = blob::build_blob(&job.pre_hash.0, job.height, extra_nonce, 0);
		json!({
			"blob": hex::encode(blob),
			"job_id": job.job_id,
			"target": target::stratum_target_hex(self.job_share_difficulty(job)),
			"algo": ALGO,
			"height": job.height,
			"seed_hash": hex::encode(job.seed_hash.0),
			"next_seed_hash": hex::encode(job.next_seed_hash.0),
		})
	}

	async fn serve(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) -> Result<(), String> {
		// Nagle would hold a submit back behind the 40 ms coalescing timer,
		// which on a fast chain is a measurable share of a block interval.
		let _ = stream.set_nodelay(true);
		let (read_half, mut write_half) = stream.into_split();
		let (out_tx, mut out_rx) = mpsc::channel::<String>(WRITE_QUEUE_DEPTH);

		let writer = tokio::spawn(async move {
			while let Some(line) = out_rx.recv().await {
				if write_half.write_all(line.as_bytes()).await.is_err() {
					break;
				}
				if write_half.write_all(b"\n").await.is_err() {
					break;
				}
			}
		});

		let mut session_id: Option<u64> = None;
		let mut reader = BufReader::new(read_half);
		let mut line = String::new();
		let result = loop {
			line.clear();
			let read = tokio::time::timeout(IDLE_TIMEOUT, reader.read_line(&mut line)).await;
			let read = match read {
				Ok(read) => read,
				Err(_) => break Err("idle timeout".to_string()),
			};
			match read {
				Ok(0) => break Ok(()),
				Ok(bytes) if bytes > MAX_LINE_BYTES => break Err("line too long".to_string()),
				Ok(_) => {},
				Err(error) => break Err(error.to_string()),
			}
			let trimmed = line.trim();
			if trimmed.is_empty() {
				continue;
			}
			let request: Value = match serde_json::from_str(trimmed) {
				Ok(value) => value,
				Err(error) => {
					let _ =
						out_tx.send(error_response(&Value::Null, -32700, &error.to_string())).await;
					continue;
				},
			};
			let response = self.handle(&request, &out_tx, &mut session_id, peer).await;
			if let Some(response) = response {
				if out_tx.send(response).await.is_err() {
					break Ok(());
				}
			}
		};

		if let Some(id) = session_id {
			self.sessions.write().await.remove(&id);
		}
		drop(out_tx);
		let _ = writer.await;
		result
	}

	async fn handle(
		&self,
		request: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		peer: SocketAddr,
	) -> Option<String> {
		let id = request.get("id").cloned().unwrap_or(Value::Null);
		let method = request.get("method").and_then(Value::as_str).unwrap_or("");
		let params = request.get("params").cloned().unwrap_or(Value::Null);

		match method {
			"login" => Some(self.handle_login(&id, &params, out_tx, session_id, peer).await),
			"submit" => Some(self.handle_submit(&id, &params, session_id).await),
			"keepalived" => Some(ok_response(&id, json!({"status": "KEEPALIVED"}))),
			"" => Some(error_response(&id, -32600, "Missing method")),
			other => Some(error_response(&id, -32601, &format!("Unknown method {other}"))),
		}
	}

	async fn handle_login(
		&self,
		id: &Value,
		params: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		peer: SocketAddr,
	) -> String {
		let Some(job) = self.current_job.read().await.clone() else {
			// Authoring has not produced a template yet. xmrig retries the
			// connection, which is the right behaviour while a node is still
			// syncing or paused.
			return error_response(id, -1, "No job available yet");
		};

		let worker = params
			.get("login")
			.and_then(Value::as_str)
			.unwrap_or("anonymous")
			.chars()
			.take(64)
			.collect::<String>();
		let agent = params.get("agent").and_then(Value::as_str).unwrap_or("unknown");

		let new_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
		// Every connection gets its own extra nonce, so two rigs on one
		// template never grind the same 4-byte nonce space.
		let extra_nonce = rand::random::<u32>();
		if let Some(old) = session_id.replace(new_id) {
			self.sessions.write().await.remove(&old);
		}
		self.sessions
			.write()
			.await
			.insert(new_id, Session { worker: worker.clone(), extra_nonce, out: out_tx.clone() });

		log::info!(
			target: LOG_TARGET,
			"⛏️ Miner {peer} logged in as {worker:?} ({agent}), extra nonce {extra_nonce:#010x}",
		);

		ok_response(
			id,
			json!({
				"id": new_id.to_string(),
				"job": self.job_payload(&job, extra_nonce),
				"status": "OK",
				// `algo` so the per-job algorithm field is honoured, `keepalive`
				// so xmrig sends keepalives instead of reconnecting on its idle
				// timer. Deliberately not `nicehash`: that would take the top
				// nonce byte away from the miner and the space is small enough
				// already.
				"extensions": ["algo", "keepalive"],
			}),
		)
	}

	async fn handle_submit(&self, id: &Value, params: &Value, session_id: &Option<u64>) -> String {
		let Some(session_id) = *session_id else {
			return self.reject(id, "Unauthenticated");
		};
		let Some((worker, extra_nonce)) = self
			.sessions
			.read()
			.await
			.get(&session_id)
			.map(|session| (session.worker.clone(), session.extra_nonce))
		else {
			return self.reject(id, "Unauthenticated");
		};

		let Some(job) = self.current_job.read().await.clone() else {
			return self.reject(id, "Block expired");
		};
		let submitted_job = params.get("job_id").and_then(Value::as_str).unwrap_or_default();
		if submitted_job != job.job_id {
			return self.reject(id, "Invalid job id");
		}

		let nonce = match params.get("nonce").and_then(Value::as_str).map(decode_nonce) {
			Some(Ok(nonce)) => nonce,
			_ => return self.reject(id, "Malformed nonce"),
		};

		if !self.seen_shares.write().await.insert((session_id, nonce)) {
			return self.reject(id, "Duplicate share");
		}

		// Re-hash, over a blob this node rebuilds. The miner's own `result` is
		// only ever compared against this, never substituted for it.
		let blob = blob::build_blob(&job.pre_hash.0, job.height, extra_nonce, nonce);
		let hash = match self.engine.hash(job.seed_hash.0, &blob) {
			Ok(hash) => hash,
			Err(error) => {
				log::error!(target: LOG_TARGET, "RandomX failed while checking a share: {error}");
				return self.reject(id, "Internal error");
			},
		};

		if let Some(claimed) = params.get("result").and_then(Value::as_str) {
			if !claimed.eq_ignore_ascii_case(&hex::encode(hash)) {
				log::warn!(
					target: LOG_TARGET,
					"Share from {worker:?} claims a hash the node does not compute; \
					 the miner is on a different blob or a different algorithm",
				);
				return self.reject(id, "Invalid result");
			}
		}

		let share_target = target::share_target_u64(self.job_share_difficulty(&job));
		if !target::meets_share_target(&hash, share_target) {
			return self.reject(id, "Low difficulty share");
		}

		self.counters.accepted.fetch_add(1, Ordering::Relaxed);

		if target::meets_difficulty(&hash, job.difficulty) {
			self.counters.blocks.fetch_add(1, Ordering::Relaxed);
			log::info!(
				target: LOG_TARGET,
				"🥇 Share from {worker:?} meets the block difficulty {} at height {}",
				job.difficulty,
				job.height,
			);
			let seal = Seal { nonce, extra_nonce }.encode().to_vec();
			if self
				.seal_tx
				.send(MinedSeal { job_id: job.job_id.clone(), worker, seal })
				.await
				.is_err()
			{
				log::warn!(target: LOG_TARGET, "nobody is listening for mined seals");
			}
		} else {
			log::debug!(target: LOG_TARGET, "share from {worker:?} accepted at height {}", job.height);
		}

		ok_response(id, json!({"status": "OK"}))
	}

	fn reject(&self, id: &Value, message: &str) -> String {
		self.counters.rejected.fetch_add(1, Ordering::Relaxed);
		log::debug!(target: LOG_TARGET, "share rejected: {message}");
		error_response(id, -1, message)
	}
}

fn decode_nonce(value: &str) -> Result<u32, ()> {
	let bytes = hex::decode(value).map_err(|_| ())?;
	let bytes: [u8; 4] = bytes.try_into().map_err(|_| ())?;
	// The hex is the four blob bytes in order, and the blob stores the nonce
	// little-endian, so this is the same read the miner did.
	Ok(u32::from_le_bytes(bytes))
}

fn ok_response(id: &Value, result: Value) -> String {
	json!({"id": id, "jsonrpc": "2.0", "error": Value::Null, "result": result}).to_string()
}

fn error_response(id: &Value, code: i64, message: &str) -> String {
	json!({
		"id": id,
		"jsonrpc": "2.0",
		"error": {"code": code, "message": message},
		"result": Value::Null,
	})
	.to_string()
}

#[cfg(test)]
mod tests;
