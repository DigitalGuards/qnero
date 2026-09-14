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
//! **What keeps a session alive.** One rule: an accepted share, never a block.
//! The deadline is sized in expected share intervals, so it is independent of
//! the chain's target block time: a rig on a 120 s chain and a rig on a 12 s
//! dev chain are held to the same ten minutes. A logged-in
//! connection has `first_share_timeout` to produce its first share at or above
//! the job's share target, and `share_timeout` between accepted shares after
//! that. Nothing else refreshes that clock. A blank line does not, a
//! `keepalived` does not, a malformed line does not, a rejected share does
//! not, and neither does anything the node writes to the connection. Both
//! windows come from [`default_share_timeout`], which sizes them from the
//! configured share difficulty for a rig slower than any real one, and
//! `--stratum-share-timeout` sets them outright. Before login a connection is
//! on a separate window, [`LOGIN_TIMEOUT`], measured from the moment it was
//! accepted.
//!
//! An inbound-silence ceiling used to be the liveness signal, and it is gone,
//! so the endpoint has one rule to explain and one deadline to tune. Every
//! completed line refreshed that ceiling, a blank line and a `keepalived`
//! included, so a peer that logged in and then sent one byte a window held a
//! connection slot for the life of the process while producing nothing at all.
//! Sixteen of those took the endpoint away from the operator's own rigs, and on
//! the documented rig-only deployment, `--mining-threads 0` with a stratum
//! port, that is a node that stops authoring.
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
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	net::{TcpListener, TcpStream},
	sync::{mpsc, RwLock, Semaphore},
};

const LOG_TARGET: &str = "stratum";

/// Longest line a miner may send. A login with a long agent string is a few
/// hundred bytes; anything past this is not a miner.
///
/// The bound is counted as the line is accumulated, in [`read_one_line`]. A
/// reader left to its own devices buffers until it finds a newline, so a peer
/// that never sends one would be free to allocate as fast as it can write, and
/// a length check afterwards runs only once that allocation has already
/// happened.
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

/// The refill a job gets when every share it can produce is also a block.
///
/// The share difficulty is clamped per job to the block difficulty, so on a
/// chain whose difficulty sits below the configured share difficulty the two
/// rules are the same rule. A new chain sits at the difficulty floor and so
/// does one recovering from a hashrate collapse, and there a 10 kH/s rig finds
/// about 78 shares a second, every one of them a block. A 120 s target settles
/// at ten times the difficulty a 12 s one did, so the clamp bites for fewer
/// blocks after a launch, but the burst it has to survive while it does is
/// unchanged. Refusing those for
/// budget throws blocks away before they are ever hashed. The concurrency cap
/// on the hashing itself is what bounds the work, and it is unchanged: a
/// connection has at most one submit in flight, because it is served from its
/// own read loop.
const SUBMIT_REFILL_WHEN_EVERY_SHARE_IS_A_BLOCK: f64 = 256.0;

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

/// How long a connection has to log in, measured from the moment it opened.
///
/// The share deadline above is a rig's allowance, and a peer earns it by
/// logging in. Until then the connection is one line away from useful and is
/// holding one of the endpoint's slots, so it gets a short window. This one is
/// a lifetime and no inbound line refreshes it, because a peer that has nothing
/// to say to the endpoint can say it as often as it likes.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections one address may hold at once, by default. The global cap alone
/// lets a single host take the whole endpoint; this bounds what one address can
/// claim of it.
///
/// A farm behind one NAT gateway, and several xmrig instances pinned per CCX on
/// the node's own box, both arrive from a single address, so the default has to
/// clear a real deployment: `--stratum-max-connections-per-ip` moves it and the
/// global cap is the bound that matters.
pub(crate) const MAX_CONNECTIONS_PER_IP: usize = 16;

/// Refusals being written at once, and how long one may take.
///
/// A refusal is one short line on a socket that is about to be dropped. The
/// bound is what keeps a flood of connections from becoming a flood of tasks;
/// past it the socket closes with nothing said, which is what every refusal did
/// before.
const MAX_REFUSAL_WRITES: usize = 16;
const REFUSAL_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a refusal is logged. Every refusal past one inside the window is
/// counted and reported with the next one.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// What a refused connection is told.
///
/// Not one of the four strings xmrig treats as critical: a cap is a transient
/// condition and the rig should keep retrying, and it should print the reason
/// while it does.
pub(crate) const REFUSED_MESSAGE: &str = "Too many connections";

/// Entries the duplicate-share set may hold.
///
/// Eviction is driven by the template rolling, and a chain whose template has
/// stalled does not roll one, so the set would otherwise grow at the
/// share-check rate for as long as the stall lasts. What clearing at the
/// ceiling costs is written out at `insert_seen`.
const MAX_SEEN_SHARES: usize = 100_000;

/// Floor and ceiling on how long a session may go without an accepted share.
///
/// The floor is the deadline at the default share difficulty, and it is what
/// `--stratum-share-timeout` moves. Ten minutes is generous for any real rig
/// there: a 900 H/s box finds a 5000-difficulty share every six seconds, so
/// the window is a hundred expected shares wide, and it also covers the minute
/// a full-mode rig spends building its dataset after login, before it hashes
/// anything at all.
///
/// The ceiling bounds what one unproductive session can cost when the share
/// difficulty is raised far enough for the estimate below to run away.
///
/// Neither number is denominated in block intervals and neither moved when the
/// chain's target went from 12 s to 120 s. What the rule counts is accepted
/// shares, and a share is found against the *share* difficulty, which the block
/// interval does not enter. In block intervals the floor is now five and the
/// ceiling sixty, where they used to be fifty and six hundred, so a rig that
/// has genuinely stopped hashing is still cut loose inside ten minutes and one
/// that is working is never close to either. Longer blocks make the endpoint
/// quieter in one respect: a job is rolled on each new template, so a rig now
/// holds a job about 120 s instead of 12 s and meets a tenth as many stale
/// shares across a template roll.
const DEFAULT_SHARE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_SHARE_TIMEOUT: Duration = Duration::from_secs(7_200);

/// The hash rate the share deadline assumes of the slowest plausible rig, and
/// how many expected share intervals it waits for.
///
/// Finding shares is a Poisson process, so the window is stated in expected
/// intervals and converted to seconds here: twelve of them leave a rig at
/// exactly that hash rate a 6 in a million chance of a spurious disconnect per
/// window, and a real rig is an order of magnitude faster than the one assumed
/// here.
const SLOW_RIG_HASHES_PER_SECOND: u64 = 100;
const SHARE_TIMEOUT_INTERVALS: u64 = 12;

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

/// What a rig is told when authoring pauses under it.
///
/// Deliberately not one of the four above: the node expects the rig back as
/// soon as it is authoring again, so this must leave xmrig's own retry timer
/// running.
pub(crate) const PAUSED_MESSAGE: &str = "Node is not authoring";

/// What a session is told when it is closed for producing no accepted share.
///
/// Deliberately not one of the four above either. A rig whose deadline ran out
/// is one the endpoint wants back: the usual cause is a rig that was pointed at
/// the wrong algorithm or that stopped hashing, and both are conditions the
/// operator fixes on the rig while xmrig keeps retrying on its own timer.
pub(crate) const NO_SHARES_MESSAGE: &str = "No accepted shares";

/// Whether xmrig would treat this message as critical and drop the pool.
/// Matched the way xmrig matches it: on the prefix, ignoring case.
pub(crate) fn is_xmrig_critical(message: &str) -> bool {
	XMRIG_CRITICAL_ERRORS.iter().any(|critical| {
		message
			.get(..critical.len())
			.is_some_and(|head| head.eq_ignore_ascii_case(critical))
	})
}

/// How long a session is given to produce an accepted share, for a share
/// difficulty. This is the default both windows take, and what
/// `--stratum-share-timeout` replaces.
///
/// The estimate is what a rig of [`SLOW_RIG_HASHES_PER_SECOND`] takes to find
/// [`SHARE_TIMEOUT_INTERVALS`] shares at that difficulty, floored at
/// [`DEFAULT_SHARE_TIMEOUT`] and capped at [`MAX_SHARE_TIMEOUT`].
///
/// It is computed from the *configured* share difficulty, and a job's share
/// difficulty is that value clamped down to the block difficulty, so the
/// estimate is never shorter than the time a share actually takes to find. A
/// chain sitting at the difficulty floor hands out shares far easier than the
/// configuration asks for, and the deadline stays sized for the harder one.
pub(crate) fn default_share_timeout(share_difficulty: u64) -> Duration {
	let seconds = share_difficulty
		.saturating_mul(SHARE_TIMEOUT_INTERVALS)
		.saturating_div(SLOW_RIG_HASHES_PER_SECOND);
	Duration::from_secs(seconds).clamp(DEFAULT_SHARE_TIMEOUT, MAX_SHARE_TIMEOUT)
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
///
/// The two deadlines are the whole liveness rule: a logged-in session is closed
/// unless it keeps producing accepted shares. They are separate fields because
/// the clocks start on different events, a login and a share, and both default
/// to [`default_share_timeout`] of `share_difficulty`.
#[derive(Clone, Debug)]
pub struct StratumConfig {
	/// Address to bind.
	pub host: IpAddr,
	/// Port to bind.
	pub port: u16,
	/// Share difficulty handed to a connection, clamped per job to the block
	/// difficulty so a share is never harder to find than a block.
	pub share_difficulty: u64,
	/// Connections one address may hold at once.
	pub max_connections_per_ip: usize,
	/// How long a session has, from its login, to produce its first accepted
	/// share.
	pub first_share_timeout: Duration,
	/// How long a session that has produced one has to produce the next.
	pub share_timeout: Duration,
}

/// The bounds one connection is served under.
///
/// Constants in production. The protocol tests set their own, so a cap can be
/// reached without opening hundreds of sockets or waiting out a deadline
/// measured in minutes.
#[derive(Clone, Copy, Debug)]
struct Limits {
	/// How long a connection has to log in, counted from when it opened.
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

/// A refusal log that a flood cannot turn into a log flood.
///
/// The refusals themselves were logged at `debug`, which is off at the default
/// `RUST_LOG=info`, so a farm whose connections were being refused had no
/// diagnostic on either end: the rig saw a connect and an immediate EOF, and
/// the node said nothing at all. They are worth a `warn` and are not worth one
/// per socket.
struct RefusalLog {
	started: Instant,
	/// Milliseconds since `started` at the last line printed, or `u64::MAX`
	/// when none has been.
	last: AtomicU64,
	suppressed: AtomicU64,
}

impl RefusalLog {
	fn new() -> Self {
		Self::since(Instant::now())
	}

	/// The same, dated. The unit test builds one whose clock already reads an
	/// hour, so it can move the window without waiting out a minute.
	fn since(started: Instant) -> Self {
		Self { started, last: AtomicU64::new(u64::MAX), suppressed: AtomicU64::new(0) }
	}

	/// Whether to print now, and how many refusals went unprinted since the
	/// last time it said yes.
	fn due(&self) -> Option<u64> {
		let now = self.started.elapsed().as_millis() as u64;
		let last = self.last.load(Ordering::Relaxed);
		if last != u64::MAX && now.saturating_sub(last) < REFUSAL_LOG_INTERVAL.as_millis() as u64 {
			self.suppressed.fetch_add(1, Ordering::Relaxed);
			return None;
		}
		self.last.store(now, Ordering::Relaxed);
		Some(self.suppressed.swap(0, Ordering::Relaxed))
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

	fn take(&mut self, refill_per_second: f64) -> bool {
		self.take_at(Instant::now(), refill_per_second)
	}

	/// The same, at a stated time, so the unit test does not race the clock.
	fn take_at(&mut self, now: Instant, refill_per_second: f64) -> bool {
		let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
		self.last = now;
		self.tokens = (self.tokens + elapsed * refill_per_second).min(SUBMIT_BURST);
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
	/// Ends this connection's read loop. Dropping the server's copy of `out`
	/// is not enough: the loop holds its own sender, so the writer stays alive
	/// and the socket stays open.
	close: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct Counters {
	accepted: AtomicU64,
	rejected: AtomicU64,
	block_candidates: AtomicU64,
	sealed: AtomicU64,
	superseded: AtomicU64,
}

/// What the endpoint has done so far, for the operator's line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StratumStats {
	/// Shares hashed and credited.
	pub accepted: u64,
	/// Shares refused, for any reason.
	pub rejected: u64,
	/// Accepted shares that met the block difficulty.
	pub block_candidates: u64,
	/// Those that became a block.
	pub sealed: u64,
	/// Those that arrived after the template they belonged to had moved on.
	pub superseded: u64,
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
	/// Bounds how many refusals are being written at once.
	refusal_slots: Arc<Semaphore>,
	/// Bounds how often a refusal is logged.
	refusal_log: RefusalLog,
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
		let limits =
			Limits { max_connections_per_ip: config.max_connections_per_ip, ..Limits::default() };
		Self::start_with_limits(config, engine, limits).await
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
			refusal_slots: Arc::new(Semaphore::new(MAX_REFUSAL_WRITES)),
			refusal_log: RefusalLog::new(),
			limits,
			seal_tx,
			seal_rx: tokio::sync::Mutex::new(seal_rx),
			counters: Counters::default(),
			bound,
		});

		log::info!(
			target: LOG_TARGET,
			"⛏️ Stratum listening on {bound} (algo {ALGO}, share difficulty {}, first share \
			 within {}s, a share every {}s after that)",
			server.config.share_difficulty,
			server.config.first_share_timeout.as_secs(),
			server.config.share_timeout.as_secs(),
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
							if let Some(suppressed) = accept_server.refusal_log.due() {
								log::warn!(
									target: LOG_TARGET,
									"refusing {peer}: all {} connections are open{}",
									accept_server.limits.max_connections,
									suppressed_tail(suppressed),
								);
							}
							accept_server.refuse(stream);
							continue;
						};
						// And a second claim, on the address's own budget: the global
						// cap alone lets one host hold every slot and lock the
						// operator's rigs out.
						let Some(ip_slot) = IpSlot::claim(&accept_server, peer.ip()) else {
							if let Some(suppressed) = accept_server.refusal_log.due() {
								log::warn!(
									target: LOG_TARGET,
									"refusing {peer}: that address already holds {} connections, \
									 which is --stratum-max-connections-per-ip{}",
									accept_server.limits.max_connections_per_ip,
									suppressed_tail(suppressed),
								);
							}
							accept_server.refuse(stream);
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

	/// Tell a refused peer why, then drop the socket.
	///
	/// Without the line the rig sees a connect followed immediately by an EOF
	/// and logs only "connection closed", so neither end says which cap was
	/// reached. The write is deadlined, and bounded in number, because it is
	/// being made to a peer the endpoint has already decided it cannot serve.
	fn refuse(&self, mut stream: TcpStream) {
		let Ok(slot) = self.refusal_slots.clone().try_acquire_owned() else {
			return;
		};
		let line = error_response(&Value::Null, -1, REFUSED_MESSAGE);
		tokio::spawn(async move {
			let write = async {
				stream.write_all(line.as_bytes()).await?;
				stream.write_all(b"\n").await
			};
			let _ = tokio::time::timeout(REFUSAL_WRITE_TIMEOUT, write).await;
			drop(slot);
		});
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

	/// Stop handing the current template out, and disconnect the rigs that are
	/// holding it.
	///
	/// Authoring pauses on a stale tip, on no peers, and for the length of an
	/// initial sync, and it is the enabled-to-disabled edge that calls this, so
	/// nothing rolls the template out of the grace slot until authoring comes
	/// back. A rig that stayed connected through that was answered `OK` for
	/// every share it found, for hours, against a template with no build behind
	/// it: a 100% accept rate on work that could never become a block, while a
	/// rig that connected during the same pause was told `No job available yet`
	/// and closed. The two paths disagreed about whether the endpoint was open
	/// and the one that looked healthy was the one that was lying.
	///
	/// So the pause reaches the connections too: a reason, then the same EOF a
	/// fresh login gets, so xmrig counts a failure and retries on its own timer
	/// and the operator sees it in the rig's log. The grace slot stays for what
	/// it was built for, a genuine template roll, which `broadcast_job` drives.
	pub async fn clear_current_job(&self) {
		let mut jobs = self.jobs.write().await;
		jobs.previous = jobs.current.take();
		self.seen_shares.write().await.retain(|(job_id, _, _)| jobs.is_live(job_id));
		// The file's lock order: `jobs` first, then `sessions`.
		let line = error_response(&Value::Null, -1, PAUSED_MESSAGE);
		let mut sessions = self.sessions.write().await;
		for (id, session) in sessions.drain() {
			// The reason is queued before the close, so the writer drains it on
			// its way out. A miner that is not reading gets the EOF alone.
			let _ = session.out.try_send(line.clone());
			session.close.notify_one();
			log::debug!(target: LOG_TARGET, "session {id} closed: the node stopped authoring");
		}
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

	/// What the endpoint has done so far.
	pub fn stats(&self) -> StratumStats {
		StratumStats {
			accepted: self.counters.accepted.load(Ordering::Relaxed),
			rejected: self.counters.rejected.load(Ordering::Relaxed),
			block_candidates: self.counters.block_candidates.load(Ordering::Relaxed),
			sealed: self.counters.sealed.load(Ordering::Relaxed),
			superseded: self.counters.superseded.load(Ordering::Relaxed),
		}
	}

	/// A seal this endpoint produced went into a block.
	///
	/// Counted where the seal is consumed, because the mining loop takes one
	/// seal per template and drops the rest: counting block-worthy shares as
	/// blocks overstated a rig's output by more than a factor of two in a
	/// measured session.
	pub fn note_block_sealed(&self) {
		self.counters.sealed.fetch_add(1, Ordering::Relaxed);
	}

	/// A seal this endpoint produced arrived too late to be used.
	pub fn note_seal_superseded(&self) {
		self.counters.superseded.fetch_add(1, Ordering::Relaxed);
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

		// The connection's own age. The pre-login window runs from here and
		// nothing the peer sends moves it.
		let opened = Instant::now();

		let write_timeout = self.limits.write_timeout;
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
			}
		});

		// Handed to the session at login, so the server can end this loop.
		let closed = Arc::new(tokio::sync::Notify::new());
		let mut session_id: Option<u64> = None;
		let mut budget = SubmitBudget::new();
		let mut reader = BufReader::new(read_half);
		// Survives the loop iteration on purpose: a line split across two waits
		// is resumed here, and the reader below is the only thing that clears
		// it.
		let mut line: Vec<u8> = Vec::new();
		// The instant of the first successful login, which never moves
		// afterwards: a second login line is as cheap to send as a newline, so
		// letting one restart the clock would be the hole this rule closes.
		let mut logged_in_at: Option<Instant> = None;
		// The last share this connection had accepted, which is the only thing
		// that refreshes the deadline.
		let mut last_accepted: Option<Instant> = None;
		let result = loop {
			// Exactly one deadline is live at a time, and it is folded into the
			// read's own timeout rather than checked only on re-entry: a bound
			// that no inbound line ever takes the loop past would otherwise
			// never be checked again.
			let remaining = match logged_in_at {
				// Before login the connection is one line away from useful and
				// is holding one of the endpoint's slots, so it gets the short
				// window, and that one is the connection's whole life. Measured
				// from the last line it would be no bound at all: a blank line
				// is a complete line, and `keepalived` is answered without a
				// session, so one byte a window would buy a peer that never
				// intends to log in the slot it holds for the life of the
				// process.
				None => {
					let Some(left) = self.limits.login_timeout.checked_sub(opened.elapsed()) else {
						break Err("did not log in".to_string());
					};
					left
				},
				// After login there is one rule, and it is what the endpoint
				// exists for: an accepted share. A rig that is hashing and has
				// found nothing is covered by the window's width, which is sized
				// for a rig slower than any real one at the configured share
				// difficulty. A peer that will never produce one is closed
				// whatever it sends and whatever the node writes to it.
				Some(login) => {
					let (clock, deadline) = match last_accepted {
						Some(accepted) => (accepted, self.config.share_timeout),
						None => (login, self.config.first_share_timeout),
					};
					let Some(left) = deadline.checked_sub(clock.elapsed()) else {
						// Queued before the close, so the writer drains it on its
						// way out: the rig prints the reason and retries on its
						// own timer, and the operator has something to act on.
						let reason = error_response(&Value::Null, -1, NO_SHARES_MESSAGE);
						let _ = out_tx.try_send(reason);
						break Err("no accepted share".to_string());
					};
					left
				},
			};

			let read = tokio::select! {
				biased;
				// A close the server asked for wins over anything still
				// buffered: the template it belongs to is gone.
				_ = closed.notified() => break Err("the node stopped authoring".to_string()),
				read = tokio::time::timeout(remaining, read_one_line(&mut reader, &mut line)) =>
					read,
			};
			let read = match read {
				Ok(read) => read,
				// The deadline this wait was sized for has run out. The loop
				// re-checks it above and ends there, so one place decides what
				// closes a connection and why. What the reader has already taken
				// off the socket is still in `line`, which is why it has to be
				// cancel safe to be re-entered here.
				Err(_) => continue,
			};
			match read {
				Ok(Line::Complete) => {},
				Ok(Line::Eof) => break Ok(()),
				// The unread tail is still queued, so there is nothing to
				// resynchronise to: drop the connection.
				Ok(Line::TooLong) => break Err("line too long".to_string()),
				Err(error) => break Err(error.to_string()),
			}
			let request = serde_json::from_slice::<Value>(trim_ascii(&line));
			let blank = trim_ascii(&line).is_empty();
			line.clear();
			if blank {
				continue;
			}
			let reply = match request {
				Ok(request) =>
					self.handle(&request, &out_tx, &mut session_id, &mut budget, &closed, peer)
						.await,
				Err(error) => Reply::open(error_response(&Value::Null, -32700, &error.to_string())),
			};
			if logged_in_at.is_none() && session_id.is_some() {
				logged_in_at = Some(Instant::now());
			}
			if reply.accepted_share {
				// Stamped where the answer was produced: the hash behind it runs
				// on the blocking pool and can queue behind other connections'
				// shares, so the submit's own arrival is the earlier instant.
				last_accepted = Some(Instant::now());
			}
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

	#[allow(clippy::too_many_arguments)]
	async fn handle(
		&self,
		request: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		budget: &mut SubmitBudget,
		closed: &Arc<tokio::sync::Notify>,
		peer: SocketAddr,
	) -> Reply {
		let id = request.get("id").cloned().unwrap_or(Value::Null);
		let method = request.get("method").and_then(Value::as_str).unwrap_or("");
		let params = request.get("params").cloned().unwrap_or(Value::Null);

		match method {
			"login" => self.handle_login(&id, &params, out_tx, session_id, closed, peer).await,
			"submit" => self.handle_submit(&id, &params, session_id, budget).await,
			// Answered because xmrig expects an answer, and inert otherwise: it
			// is one line any peer can send and it says nothing about whether
			// the peer is mining. See the liveness rule in the module doc.
			"keepalived" => Reply::open(ok_response(&id, json!({"status": "KEEPALIVED"}))),
			"" => Reply::open(error_response(&id, -32600, "Missing method")),
			other => Reply::open(error_response(&id, -32601, &format!("Unknown method {other}"))),
		}
	}

	/// Log in, register the session and queue the reply, all under one read of
	/// `jobs`, so a `broadcast_job` racing this cannot leave the new session
	/// holding a superseded job.
	#[allow(clippy::too_many_arguments)]
	async fn handle_login(
		&self,
		id: &Value,
		params: &Value,
		out_tx: &mpsc::Sender<String>,
		session_id: &mut Option<u64>,
		closed: &Arc<tokio::sync::Notify>,
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
				Session {
					worker: worker.clone(),
					extra_nonce,
					out: out_tx.clone(),
					close: closed.clone(),
				},
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
	) -> Reply {
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
		// here, before any RandomX work is queued. What a share is worth
		// decides the rate: when the job's share target is the block target,
		// every share refused for budget is a block thrown away unhashed.
		let block_difficulty = target::difficulty_as_u64(job.difficulty);
		let refill = if self.job_share_difficulty(&job) >= block_difficulty {
			SUBMIT_REFILL_WHEN_EVERY_SHARE_IS_A_BLOCK
		} else {
			SUBMIT_REFILL_PER_SECOND
		};
		if !budget.take(refill) {
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
				self.counters.block_candidates.fetch_add(1, Ordering::Relaxed);
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
			(true, false) => {
				self.counters.block_candidates.fetch_add(1, Ordering::Relaxed);
				self.counters.superseded.fetch_add(1, Ordering::Relaxed);
				log::debug!(
					target: LOG_TARGET,
					"a block-worthy share arrived for the superseded job {}; credited, and the build it belongs to is gone",
					job.job_id,
				);
			},
			(false, _) =>
				log::debug!(target: LOG_TARGET, "share from {worker:?} accepted at height {}", job.height),
		}

		// The one line that refreshes this session's deadline.
		Reply::accepted(ok_response(id, json!({"status": "OK"})))
	}

	/// Refuse one share. The message must not be one xmrig treats as critical,
	/// prefix and case included, because that is how xmrig compares it.
	fn reject_share(&self, id: &Value, message: &str) -> Reply {
		debug_assert!(
			!is_xmrig_critical(message),
			"{message:?} makes xmrig drop the pool; it is not a share-level rejection",
		);
		self.reject_fatal(id, message)
	}

	/// Refuse, and mean it: the miner is expected to close.
	///
	/// A refusal returns [`Reply::open`], which leaves the session's liveness
	/// clock where it was: a peer that could refresh its deadline with a
	/// rejected share is a peer that never has to mine.
	fn reject_fatal(&self, id: &Value, message: &str) -> Reply {
		self.counters.rejected.fetch_add(1, Ordering::Relaxed);
		log::debug!(target: LOG_TARGET, "share rejected: {message}");
		Reply::open(error_response(id, -1, message))
	}
}

/// What one request produced: the line to answer with, whether the connection
/// is finished, and whether this was the one thing that proves the peer is
/// mining.
struct Reply {
	body: Option<String>,
	close: bool,
	/// Whether the line was a share the endpoint accepted. The only thing that
	/// refreshes a session's liveness clock, which is why it is carried out of
	/// here rather than inferred from the answer's text.
	accepted_share: bool,
}

impl Reply {
	/// Answer and keep serving.
	fn open(body: String) -> Self {
		Self { body: Some(body), close: false, accepted_share: false }
	}

	/// Answer an accepted share, and keep serving.
	fn accepted(body: String) -> Self {
		Self { accepted_share: true, ..Self::open(body) }
	}

	/// Answer already queued elsewhere, and keep serving.
	fn silent() -> Self {
		Self { body: None, close: false, accepted_share: false }
	}

	/// Answer, then close. A refusal a miner cannot act on has to arrive as an
	/// EOF too, or xmrig holds the socket and stops its own retry timers.
	fn closing(body: String) -> Self {
		Self { close: true, ..Self::open(body) }
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
/// nothing.
///
/// Reaching it clears the whole set, and that re-opens every share recorded
/// against a job that is still live, so a nonce already credited can be sent
/// again, hashed again and counted again. Every submitted nonce counts toward
/// the ceiling whether or not it was valid, and the set is shared by every
/// session, so a full endpoint spending its ordinary refill reaches 100 000
/// inside a minute and the dedup stops saving hashing for as long as the load
/// lasts. `accepted` and `block_candidates` in the operator's line can
/// over-report by the duplicates that buys.
///
/// Both costs are bounded by the submit budget and by the hashing semaphore,
/// and neither is a consensus question: a duplicate seal cannot produce a
/// second block, because `MiningHandle::submit` verifies and consumes the
/// build under one lock. A per-job map would not remove the clear, because the
/// case the ceiling exists for is a chain whose one live job never rolls.
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

/// What one read produced.
enum Line {
	/// A newline was reached; `line` holds it.
	Complete,
	/// The peer closed.
	Eof,
	/// The peer sent more than `MAX_LINE_BYTES` without a newline.
	TooLong,
}

/// Read one line into `line`, cancel safe.
///
/// `AsyncBufReadExt::read_line` is documented as **not** cancel safe: the bytes
/// it has taken off the socket live in the future's own buffer and are dropped
/// with it. That was harmless while a timeout ended the connection, and it is
/// not harmless now that a timeout re-enters the read, because the resumed call
/// would start in the middle of the peer's line: a submit split across two TCP
/// segments would come back as a parse error and the share in it would be lost
/// without either end knowing which.
///
/// `fill_buf` is cancel safe (cancelling it consumes nothing) and `line` is the
/// caller's, so a line split across two waits is resumed whole.
/// The bound is counted on `line` itself, which is the same bound the `take`
/// this replaced provided: a peer that never sends a newline cannot make the
/// node buffer for it.
async fn read_one_line<R>(reader: &mut R, line: &mut Vec<u8>) -> std::io::Result<Line>
where
	R: tokio::io::AsyncBufRead + Unpin,
{
	loop {
		let available = reader.fill_buf().await?;
		if available.is_empty() {
			return Ok(Line::Eof);
		}
		let (taken, complete) = match available.iter().position(|byte| *byte == b'\n') {
			Some(end) => (end + 1, true),
			None => (available.len(), false),
		};
		line.extend_from_slice(&available[..taken]);
		reader.consume(taken);
		if complete {
			// The newline itself is not part of the line.
			return Ok(if line.len().saturating_sub(1) > MAX_LINE_BYTES {
				Line::TooLong
			} else {
				Line::Complete
			});
		}
		if line.len() > MAX_LINE_BYTES {
			return Ok(Line::TooLong);
		}
	}
}

/// The line without its surrounding whitespace.
fn trim_ascii(line: &[u8]) -> &[u8] {
	let start = line.iter().position(|byte| !byte.is_ascii_whitespace());
	let Some(start) = start else { return &[] };
	let end = line.iter().rposition(|byte| !byte.is_ascii_whitespace()).unwrap_or(start);
	&line[start..=end]
}

/// What to append to a refusal line when others went unprinted.
fn suppressed_tail(suppressed: u64) -> String {
	match suppressed {
		0 => String::new(),
		n => format!(" ({n} more refusals since the last of these)"),
	}
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
