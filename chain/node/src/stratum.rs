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
//! is compared against that and never used in its place. Every byte a miner
//! sends is bounded before it is buffered, every share is hashed on the
//! blocking pool under a semaphore so a peer cannot take the async runtime
//! away from consensus, and every miner-supplied string is truncated and
//! escaped before it reaches a log line.
//!
//! **Lock order.** `jobs`, then `sessions` or `seen_shares`, always in that
//! order, and no `sessions` guard is ever held across an `await` on `jobs`. Login and
//! `broadcast_job` both hold the `jobs` guard across their session work, so a rig that logs in
//! while a template rolls is handed one job or the other and never the old one after the new one.

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
	time::{Duration, Instant},
};
use tokio::{
	io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
	net::{TcpListener, TcpStream},
	sync::{mpsc, RwLock, Semaphore},
};

const LOG_TARGET: &str = "stratum";

/// Longest line a miner may send. A login with a long agent string is a few
/// hundred bytes; anything past this is not a miner.
///
/// The bound lives on the reader itself. `read_line` left to its own devices
/// buffers until it finds a newline, so a peer that never sends one would be
/// free to allocate as fast as it can write, and a length check afterwards runs
/// only once that allocation has already happened.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Connections accepted at once. One rig needs one; the cap is what stops an
/// unauthenticated peer from multiplying the per-connection allowance across
/// sockets.
const MAX_CONNECTIONS: usize = 64;

/// Share verifications hashing at once.
///
/// A light-mode RandomX hash is tens of milliseconds of pure CPU, and it runs
/// on the blocking pool. This bounds how much of that pool the endpoint can
/// take, so a flood of submits cannot starve the blocking work the node itself
/// depends on.
const MAX_CONCURRENT_SHARE_CHECKS: usize = 4;

/// Longest agent string kept from a login, in characters. Truncated and
/// escaped before it is logged: it is attacker-controlled text heading for the
/// operator's log file.
const MAX_AGENT_CHARS: usize = 64;

/// Submits a connection may burst, and the rate it refills at.
///
/// A 4 kH/s rig at the default share difficulty submits well under one share a
/// second; these bounds are far above any miner and far below what it takes to
/// keep the hashing pool saturated.
const SUBMIT_BURST: f64 = 64.0;
const SUBMIT_REFILL_PER_SECOND: f64 = 32.0;

/// Outgoing queue depth per connection. A miner that will not read its socket
/// is disconnected, so the memory one peer can claim stays bounded.
const WRITE_QUEUE_DEPTH: usize = 32;

/// How long one write to a miner may take before the connection is given up.
///
/// A peer that stops reading its socket shuts its receive window, and an
/// undeadlined `write_all` then parks the writer task for as long as the peer
/// likes. The connection task waits on that writer, so without this the
/// connection never ends and the slot it holds never comes back.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a connection may go without logging in.
///
/// The share-scaled deadline below is a rig's allowance, and a peer earns it by
/// logging in. Until then the connection is one line away from useful and is
/// holding one of the endpoint's slots, so it gets a short window.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections one address may hold at once. The global cap alone lets a single
/// host take the whole endpoint; this bounds what one address can claim of it.
const MAX_CONNECTIONS_PER_IP: usize = 4;

/// Entries the duplicate-share set may hold.
///
/// Eviction is driven by the template rolling, and a chain whose template has
/// stalled does not roll one, so the set would otherwise grow at the
/// share-check rate for as long as the stall lasts. Clearing at the ceiling
/// costs at most one re-credited duplicate.
const MAX_SEEN_SHARES: usize = 100_000;

/// Floor and ceiling on how long a connection may stay silent.
///
/// xmrig resets its keepalive timer on every line it *receives*, so a healthy
/// rig that is taking job pushes and has not found a share sends nothing at
/// all. The deadline therefore has to outlast the time it takes that rig to
/// find one share. One keepalive interval is far short of that.
const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(7_200);

/// The hash rate the idle deadline assumes of the slowest plausible rig, and
/// how many expected share intervals it waits for.
const SLOW_RIG_HASHES_PER_SECOND: u64 = 100;
const IDLE_SHARE_INTERVALS: u64 = 20;

/// Error strings xmrig treats as critical: it closes the socket, drops the
/// pool and sits out its retry pause.
///
/// These are **prefixes**, matched case-insensitively. `Client::isCriticalError`
/// in xmrig compares the pool's message with `strncasecmp` over the length of
/// each string, so `"invalid job id: 42"` is as fatal as `"Invalid job id"`. A
/// share-level rejection must never be one of them: a stale share is the normal
/// outcome of a template roll, and answering it with a critical string costs
/// the rig a reconnect every time the chain moves.
pub(crate) const XMRIG_CRITICAL_ERRORS: [&str; 4] =
	["Unauthenticated", "your IP is banned", "IP Address currently banned", "Invalid job id"];

/// Whether xmrig would treat this message as critical and drop the pool.
/// Matched the way xmrig matches it: on the prefix, ignoring case.
pub(crate) fn is_xmrig_critical(message: &str) -> bool {
	XMRIG_CRITICAL_ERRORS.iter().any(|critical| {
		message
			.get(..critical.len())
			.is_some_and(|head| head.eq_ignore_ascii_case(critical))
	})
}

/// How long a silent connection is given, for a share difficulty.
fn idle_timeout(share_difficulty: u64) -> Duration {
	let seconds = share_difficulty
		.saturating_mul(IDLE_SHARE_INTERVALS)
		.saturating_div(SLOW_RIG_HASHES_PER_SECOND);
	Duration::from_secs(seconds).clamp(MIN_IDLE_TIMEOUT, MAX_IDLE_TIMEOUT)
}

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

/// The bounds one connection is served under.
///
/// Constants in production. The protocol tests set their own, so a cap can be
/// reached without opening hundreds of sockets or waiting out a deadline
/// measured in minutes.
#[derive(Clone, Copy, Debug)]
struct Limits {
	/// How long a connection may go without logging in.
	login_timeout: Duration,
	/// How long one write to a miner may take.
	write_timeout: Duration,
	/// Connections open at once across the endpoint.
	max_connections: usize,
	/// Connections open at once from one address.
	max_connections_per_ip: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			login_timeout: LOGIN_TIMEOUT,
			write_timeout: WRITE_TIMEOUT,
			max_connections: MAX_CONNECTIONS,
			max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
		}
	}
}

/// The template being mined, and the one before it.
///
/// Keeping the previous template is what makes a template roll cost a rig
/// nothing: a share submitted against the job the miner was holding when the
/// push went out was genuinely earned, so it is hashed, checked and credited.
/// It cannot become a block, because the build it belongs to is gone.
#[derive(Default)]
struct Jobs {
	current: Option<MiningJob>,
	previous: Option<MiningJob>,
}

impl Jobs {
	/// The job a submit names, and whether it is the current template.
	fn lookup(&self, job_id: &str) -> Option<(MiningJob, bool)> {
		if let Some(job) = self.current.as_ref().filter(|job| job.job_id == job_id) {
			return Some((job.clone(), true));
		}
		self.previous
			.as_ref()
			.filter(|job| job.job_id == job_id)
			.map(|job| (job.clone(), false))
	}

	fn is_live(&self, job_id: &str) -> bool {
		[self.current.as_ref(), self.previous.as_ref()]
			.into_iter()
			.flatten()
			.any(|job| job.job_id == job_id)
	}
}

/// A connection's submit budget: a token bucket, so an unauthenticated peer
/// cannot queue unbounded RandomX work by sending 100-byte lines.
struct SubmitBudget {
	tokens: f64,
	last: Instant,
}

impl SubmitBudget {
	fn new() -> Self {
		Self { tokens: SUBMIT_BURST, last: Instant::now() }
	}

	fn take(&mut self) -> bool {
		let now = Instant::now();
		let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
		self.last = now;
		self.tokens = (self.tokens + elapsed * SUBMIT_REFILL_PER_SECOND).min(SUBMIT_BURST);
		if self.tokens < 1.0 {
			return false;
		}
		self.tokens -= 1.0;
		true
	}
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
	jobs: RwLock<Jobs>,
	sessions: RwLock<HashMap<u64, Session>>,
	/// `(job id, session id, nonce)` already seen. Entries for jobs that are no
	/// longer live are evicted by `broadcast_job`; the job id is in the key
	/// because two jobs are live at once, and a fresh template does not change
	/// a session's extra nonce, so the same nonce is legitimately submittable
	/// against both.
	seen_shares: RwLock<HashSet<(String, u64, u32)>>,
	next_session_id: AtomicU64,
	/// Bounds how many share hashes are on the blocking pool at once.
	hash_slots: Semaphore,
	/// Bounds how many sockets are open at once.
	connection_slots: Arc<Semaphore>,
	/// Sockets open per address, so one host cannot take every slot.
	connections_per_ip: std::sync::Mutex<HashMap<IpAddr, usize>>,
	limits: Limits,
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
		Self::start_with_limits(config, engine, Limits::default()).await
	}

	/// Bind under explicit bounds. The protocol tests use this to reach a cap
	/// without opening hundreds of sockets.
	async fn start_with_limits(
		config: StratumConfig,
		engine: Arc<RandomxEngine>,
		limits: Limits,
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
			jobs: RwLock::new(Jobs::default()),
			sessions: RwLock::new(HashMap::new()),
			seen_shares: RwLock::new(HashSet::new()),
			next_session_id: AtomicU64::new(1),
			hash_slots: Semaphore::new(MAX_CONCURRENT_SHARE_CHECKS),
			connection_slots: Arc::new(Semaphore::new(limits.max_connections)),
			connections_per_ip: std::sync::Mutex::new(HashMap::new()),
			limits,
			seal_tx,
			seal_rx: tokio::sync::Mutex::new(seal_rx),
			counters: Counters::default(),
			bound,
		});

		log::info!(
			target: LOG_TARGET,
			"⛏️ Stratum listening on {bound} (algo {ALGO}, share difficulty {}, idle timeout {}s)",
			server.config.share_difficulty,
			idle_timeout(server.config.share_difficulty).as_secs(),
		);

		let accept_server = server.clone();
		tokio::spawn(async move {
			loop {
				match listener.accept().await {
					Ok((stream, peer)) => {
						// A connection holds a slot for its lifetime. Refusing here
						// keeps the accept loop answering and bounds the memory one
						// peer can claim.
						let Ok(slot) = accept_server.connection_slots.clone().try_acquire_owned()
						else {
							log::debug!(
								target: LOG_TARGET,
								"refusing {peer}: {} connections already open",
								accept_server.limits.max_connections,
							);
							drop(stream);
							continue;
						};
						// And a second claim, on the address's own budget: the global
						// cap alone lets one host hold every slot and lock the
						// operator's rigs out.
						let Some(ip_slot) = IpSlot::claim(&accept_server, peer.ip()) else {
							log::debug!(
								target: LOG_TARGET,
								"refusing {peer}: that address already holds {} connections",
								accept_server.limits.max_connections_per_ip,
							);
							drop(stream);
							continue;
						};
						let server = accept_server.clone();
						tokio::spawn(async move {
							if let Err(error) = server.serve(stream, peer).await {
								log::debug!(target: LOG_TARGET, "miner {peer} disconnected: {error}");
							}
							drop(ip_slot);
							drop(slot);
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
	/// previous one: stratum has no cancel and needs none. The superseded job
	/// stays creditable for one generation, because a rig is always mid-nonce
	/// when a template rolls.
	pub async fn broadcast_job(&self, job: MiningJob) {
		let notification = json!({
			"jsonrpc": "2.0",
			"method": "job",
			"params": Value::Null,
		});

		// The write guard is held across the push loop, so a login either
		// completes entirely before this or reads the new job. Releasing it
		// first would let a fresh session miss the push and then be handed the
		// superseded job by its own login reply.
		let mut jobs = self.jobs.write().await;
		jobs.previous = jobs.current.take();
		jobs.current = Some(job.clone());
		self.seen_shares.write().await.retain(|(job_id, _, _)| jobs.is_live(job_id));

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

	/// Stop handing the current template out, so a miner that logs in next is
	/// not given work the node has stopped building on.
	///
	/// The template moves to the grace slot, so a rig that was mid-nonce when
	/// authoring paused is still credited for what it finds. Dropping both slots
	/// answers every submit `Block expired` for the length of the pause, which on
	/// a long initial sync is hours of a rig burning power at a visible 0/N.
	pub async fn clear_current_job(&self) {
		let mut jobs = self.jobs.write().await;
		jobs.previous = jobs.current.take();
		self.seen_shares.write().await.retain(|(job_id, _, _)| jobs.is_live(job_id));
	}

	/// Wait for a share that was good enough to be a block.
	pub async fn recv_seal_timeout(&self, timeout: Duration) -> Option<MinedSeal> {
		let mut rx = self.seal_rx.lock().await;
		tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
	}

	/// Wait for such a share, with no deadline and no other outcome.
	///
	/// Cancel safe, which is what lets the mining loop race this against a round
	/// of in-process hashing: dropping the future takes nothing off the channel.
	/// A closed channel parks for good: the sender lives on this server, so the
	/// case is unreachable, and a `None` returned into a `select!` would spin the
	/// loop.
	pub async fn recv_seal(&self) -> MinedSeal {
		let mut rx = self.seal_rx.lock().await;
		match rx.recv().await {
			Some(seal) => seal,
			None => std::future::pending().await,
		}
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

		// Milliseconds since `opened` at the last write that landed. xmrig
		// re-arms its keepalive timer on every line it *receives*, so a job push
		// proves the connection is alive exactly as an inbound line does, and the
		// deadline below counts from whichever came last.
		let opened = Instant::now();
		let last_write = Arc::new(AtomicU64::new(0));

		let write_timeout = self.limits.write_timeout;
		let writer_activity = last_write.clone();
		let mut writer = tokio::spawn(async move {
			while let Some(line) = out_rx.recv().await {
				// Deadlined: a peer that stops reading shuts its receive window,
				// and an undeadlined `write_all` then parks this task, the
				// connection behind it, and the slot the connection holds.
				let write = async {
					write_half.write_all(line.as_bytes()).await?;
					write_half.write_all(b"\n").await
				};
				if !matches!(tokio::time::timeout(write_timeout, write).await, Ok(Ok(()))) {
					break;
				}
				writer_activity.store(opened.elapsed().as_millis() as u64, Ordering::Relaxed);
			}
		});

		let authenticated_deadline = idle_timeout(self.config.share_difficulty);
		let mut session_id: Option<u64> = None;
		let mut budget = SubmitBudget::new();
		let mut reader = BufReader::new(read_half);
		let mut line = String::new();
		let mut last_read = Instant::now();
		let result = loop {
			// A rig earns the long share-scaled window by logging in. Until then
			// the connection is one line away from useful and is holding a slot,
			// so it gets the short one.
			let deadline = if session_id.is_some() {
				authenticated_deadline
			} else {
				self.limits.login_timeout
			};
			let since_write = opened
				.elapsed()
				.saturating_sub(Duration::from_millis(last_write.load(Ordering::Relaxed)));
			let Some(remaining) = deadline.checked_sub(last_read.elapsed().min(since_write)) else {
				break Err("idle timeout".to_string());
			};

			line.clear();
			// One byte past the limit, so an over-long line is caught by the
			// reader stopping, before the length is measured on a buffer that
			// has already grown. This is the bound: without it a peer that never
			// sends a newline can allocate for as long as the deadline allows.
			let mut limited = (&mut reader).take(MAX_LINE_BYTES as u64 + 1);
			let read = tokio::time::timeout(remaining, limited.read_line(&mut line)).await;
			let read = match read {
				Ok(read) => read,
				// A job push written while this waited counts as activity, so the
				// deadline is recomputed before the connection is given up.
				Err(_) => continue,
			};
			last_read = Instant::now();
			match read {
				Ok(0) => break Ok(()),
				// The unread tail is still queued, so there is nothing to
				// resynchronise to: drop the connection.
				Ok(bytes) if bytes > MAX_LINE_BYTES => break Err("line too long".to_string()),
				Ok(_) => {},
				Err(error) => break Err(error.to_string()),
			}
			let trimmed = line.trim();
			if trimmed.is_empty() {
				continue;
			}
			let reply = match serde_json::from_str::<Value>(trimmed) {
				Ok(request) =>
					self.handle(&request, &out_tx, &mut session_id, &mut budget, peer).await,
				Err(error) => Reply::open(error_response(&Value::Null, -32700, &error.to_string())),
			};
			if let Some(body) = reply.body {
				// `try_send`, never `send().await`: waiting for queue capacity is
				// waiting on a peer that may never read again, and this task
				// holds one of the endpoint's connection slots while it waits.
				if out_tx.try_send(body).is_err() {
					break Err("not reading its socket".to_string());
				}
			}
			if reply.close {
				break Ok(());
			}
		};

		if let Some(id) = session_id {
			self.sessions.write().await.remove(&id);
		}
		// Dropping the sender ends the writer once the queue has drained, so a
		// refusal queued just above still reaches the miner. Deadlined for the
		// reason every write is: a wedged socket must not keep the slot.
		drop(out_tx);
		if tokio::time::timeout(write_timeout, &mut writer).await.is_err() {
			writer.abort();
			log::debug!(target: LOG_TARGET, "miner {peer} stopped reading; dropping the connection");
		}
		result
	}

	async fn handle(
		&self,
		request: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		budget: &mut SubmitBudget,
		peer: SocketAddr,
	) -> Reply {
		let id = request.get("id").cloned().unwrap_or(Value::Null);
		let method = request.get("method").and_then(Value::as_str).unwrap_or("");
		let params = request.get("params").cloned().unwrap_or(Value::Null);

		match method {
			"login" => self.handle_login(&id, &params, out_tx, session_id, peer).await,
			"submit" => Reply::open(self.handle_submit(&id, &params, session_id, budget).await),
			"keepalived" => Reply::open(ok_response(&id, json!({"status": "KEEPALIVED"}))),
			"" => Reply::open(error_response(&id, -32600, "Missing method")),
			other => Reply::open(error_response(&id, -32601, &format!("Unknown method {other}"))),
		}
	}

	/// Log in, register the session and queue the reply, all under one read of
	/// `jobs`, so a `broadcast_job` racing this cannot leave the new session
	/// holding a superseded job.
	async fn handle_login(
		&self,
		id: &Value,
		params: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		peer: SocketAddr,
	) -> Reply {
		let jobs = self.jobs.read().await;
		let Some(job) = jobs.current.clone() else {
			// Authoring has not produced a template yet, which is where a node
			// still syncing or paused sits. The socket closes with the refusal:
			// xmrig clears its own timers on any line it receives and arms the
			// keepalive only on a *successful* login, so a rig left holding an
			// open socket here sits at zero hash rate with both timers at zero
			// until the node's idle deadline fires. EOF is what makes it count a
			// failure and reconnect.
			return Reply::closing(error_response(id, -1, "No job available yet"));
		};

		let worker = truncate(params.get("login").and_then(Value::as_str).unwrap_or("anonymous"));
		// Attacker-controlled text heading for a log file: bounded like the
		// worker label, and printed with `{:?}` so a newline cannot forge a
		// log line and an escape sequence cannot rewrite a terminal.
		let agent = truncate(params.get("agent").and_then(Value::as_str).unwrap_or("unknown"));

		let new_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
		// Every connection gets its own extra nonce, so two rigs on one
		// template never grind the same 4-byte nonce space.
		let extra_nonce = rand::random::<u32>();
		{
			let mut sessions = self.sessions.write().await;
			if let Some(old) = session_id.replace(new_id) {
				sessions.remove(&old);
			}
			sessions.insert(
				new_id,
				Session { worker: worker.clone(), extra_nonce, out: out_tx.clone() },
			);
		}

		let reply = ok_response(
			id,
			json!({
				"id": new_id.to_string(),
				"job": self.job_payload(&job, extra_nonce),
				"status": "OK",
				// `algo` so the per-job algorithm field is honoured, `keepalive`
				// so xmrig answers its idle timer with a keepalive and keeps
				// the connection. Deliberately not `nicehash`: that takes the top
				// nonce byte away from the miner and the space is small enough
				// already.
				"extensions": ["algo", "keepalive"],
			}),
		);
		// Never `send().await` under the `jobs` guard: a peer that stops
		// reading its socket would then hold up every template.
		if out_tx.try_send(reply).is_err() {
			return Reply::closing(error_response(id, -1, "Busy"));
		}
		drop(jobs);

		log::info!(
			target: LOG_TARGET,
			"⛏️ Miner {peer} logged in as {worker:?} ({agent:?}), extra nonce {extra_nonce:#010x}",
		);
		Reply::silent()
	}

	async fn handle_submit(
		&self,
		id: &Value,
		params: &Value,
		session_id: &Option<u64>,
		budget: &mut SubmitBudget,
	) -> String {
		let Some(session_id) = *session_id else {
			return self.reject_fatal(id, "Unauthenticated");
		};

		let submitted_job =
			params.get("job_id").and_then(Value::as_str).unwrap_or_default().to_string();
		// The `jobs` guard is taken first and dropped before `sessions`, which
		// is the lock order the whole file keeps.
		let found = self.jobs.read().await.lookup(&submitted_job);
		let Some((job, is_current)) = found else {
			// Never "Invalid job id": xmrig treats that string as critical and
			// drops the pool. A stale share is ordinary.
			return self.reject_share(id, "Block expired");
		};

		let Some((worker, extra_nonce)) = self
			.sessions
			.read()
			.await
			.get(&session_id)
			.map(|session| (session.worker.clone(), session.extra_nonce))
		else {
			return self.reject_fatal(id, "Unauthenticated");
		};

		let nonce = match params.get("nonce").and_then(Value::as_str).map(decode_nonce) {
			Some(Ok(nonce)) => nonce,
			_ => return self.reject_share(id, "Malformed nonce"),
		};

		// Everything above is cheap. The hash is not, so the budget is spent
		// here, before any RandomX work is queued.
		if !budget.take() {
			return self.reject_share(id, "Too many shares");
		}

		let mut seen = self.seen_shares.write().await;
		let fresh =
			insert_seen(&mut seen, (job.job_id.clone(), session_id, nonce), MAX_SEEN_SHARES);
		drop(seen);
		if !fresh {
			return self.reject_share(id, "Duplicate share");
		}

		// Re-hash, over a blob this node rebuilds. The miner's own `result` is
		// only ever compared against this, never substituted for it. The hash
		// goes to the blocking pool under a semaphore: it is tens of
		// milliseconds of C, and the runtime this task is on also carries
		// networking, block import and the job pushes these miners depend on.
		let blob = blob::build_blob(&job.pre_hash.0, job.height, extra_nonce, nonce);
		let engine = self.engine.clone();
		let seed = job.seed_hash.0;
		let hashed = {
			let Ok(_slot) = self.hash_slots.acquire().await else {
				return self.reject_share(id, "Internal error");
			};
			tokio::task::spawn_blocking(move || engine.hash(seed, &blob)).await
		};
		let hash = match hashed {
			Ok(Ok(hash)) => hash,
			Ok(Err(error)) => {
				log::error!(target: LOG_TARGET, "RandomX failed while checking a share: {error}");
				return self.reject_share(id, "Internal error");
			},
			Err(error) => {
				log::error!(target: LOG_TARGET, "the share hashing task failed: {error}");
				return self.reject_share(id, "Internal error");
			},
		};

		if let Some(claimed) = params.get("result").and_then(Value::as_str) {
			if !claimed.eq_ignore_ascii_case(&hex::encode(hash)) {
				log::warn!(
					target: LOG_TARGET,
					"Share from {worker:?} claims a hash the node does not compute; \
					 the miner is on a different blob or a different algorithm",
				);
				return self.reject_share(id, "Invalid result");
			}
		}

		// The block rule is evaluated first and is sufficient on its own. The
		// two rules agree everywhere except at one boundary value, where a hash
		// can satisfy `hash_le * difficulty <= 2^256 - 1` and still fail the
		// top-64-bit share test at the same difficulty; the node must never
		// throw away a block it was handed.
		let is_block = target::meets_difficulty(&hash, job.difficulty);
		let share_target = target::share_target_u64(self.job_share_difficulty(&job));
		if !is_block && !target::meets_share_target(&hash, share_target) {
			return self.reject_share(id, "Low difficulty share");
		}

		self.counters.accepted.fetch_add(1, Ordering::Relaxed);

		match (is_block, is_current) {
			(true, true) => {
				self.counters.blocks.fetch_add(1, Ordering::Relaxed);
				log::info!(
					target: LOG_TARGET,
					"🥇 Share from {worker:?} meets the block difficulty {} at height {}",
					job.difficulty,
					job.height,
				);
				let seal = Seal { nonce, extra_nonce }.encode().to_vec();
				// `try_send`: the mining loop drains this once per template, a
				// second block-level share for the same template is worthless,
				// and blocking here would stall this connection's reads and
				// widen the stale-share window.
				if self
					.seal_tx
					.try_send(MinedSeal { job_id: job.job_id.clone(), worker, seal })
					.is_err()
				{
					log::debug!(
						target: LOG_TARGET,
						"a seal for job {} was dropped: nobody is waiting for one",
						job.job_id,
					);
				}
			},
			(true, false) => log::debug!(
				target: LOG_TARGET,
				"a block-worthy share arrived for the superseded job {}; credited, and the build it belongs to is gone",
				job.job_id,
			),
			(false, _) =>
				log::debug!(target: LOG_TARGET, "share from {worker:?} accepted at height {}", job.height),
		}

		ok_response(id, json!({"status": "OK"}))
	}

	/// Refuse one share. The message must not be one xmrig treats as critical,
	/// prefix and case included, because that is how xmrig compares it.
	fn reject_share(&self, id: &Value, message: &str) -> String {
		debug_assert!(
			!is_xmrig_critical(message),
			"{message:?} makes xmrig drop the pool; it is not a share-level rejection",
		);
		self.reject_fatal(id, message)
	}

	/// Refuse, and mean it: the miner is expected to close.
	fn reject_fatal(&self, id: &Value, message: &str) -> String {
		self.counters.rejected.fetch_add(1, Ordering::Relaxed);
		log::debug!(target: LOG_TARGET, "share rejected: {message}");
		error_response(id, -1, message)
	}
}

/// What one request produced: the line to answer with, and whether the
/// connection is finished.
struct Reply {
	body: Option<String>,
	close: bool,
}

impl Reply {
	/// Answer and keep serving.
	fn open(body: String) -> Self {
		Self { body: Some(body), close: false }
	}

	/// Answer already queued elsewhere, and keep serving.
	fn silent() -> Self {
		Self { body: None, close: false }
	}

	/// Answer, then close. A refusal a miner cannot act on has to arrive as an
	/// EOF too, or xmrig holds the socket and stops its own retry timers.
	fn closing(body: String) -> Self {
		Self { body: Some(body), close: true }
	}
}

/// One connection's claim on its address's budget, released when the
/// connection ends however it ends.
struct IpSlot {
	server: Arc<StratumServer>,
	ip: IpAddr,
}

impl IpSlot {
	fn claim(server: &Arc<StratumServer>, ip: IpAddr) -> Option<Self> {
		let mut open = server.connections_per_ip.lock().unwrap_or_else(|e| e.into_inner());
		let count = open.entry(ip).or_insert(0);
		if *count >= server.limits.max_connections_per_ip {
			// Nothing was added: the entry only exists because it is already at
			// the cap.
			return None;
		}
		*count += 1;
		drop(open);
		Some(Self { server: server.clone(), ip })
	}
}

impl Drop for IpSlot {
	fn drop(&mut self) {
		let mut open = self.server.connections_per_ip.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(count) = open.get_mut(&self.ip) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				open.remove(&self.ip);
			}
		}
	}
}

/// Record a share against the duplicate set, and say whether it is new.
///
/// The ceiling is what keeps the set finite when the template does not roll:
/// eviction is driven by `broadcast_job`, and a stalled chain broadcasts
/// nothing. Clearing costs at most one re-credited duplicate, which is cheaper
/// than a set that grows for as long as the stall lasts.
fn insert_seen(
	seen: &mut HashSet<(String, u64, u32)>,
	share: (String, u64, u32),
	ceiling: usize,
) -> bool {
	if seen.len() >= ceiling {
		seen.clear();
	}
	seen.insert(share)
}

/// Bound a miner-supplied string before it is kept or logged.
fn truncate(value: &str) -> String {
	value.chars().take(MAX_AGENT_CHARS).collect()
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
