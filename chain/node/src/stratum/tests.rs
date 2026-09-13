//! Protocol tests with a fake miner that speaks xmrig's messages.
//!
//! The point of these is compatibility, so the client here sends exactly what
//! xmrig sends, in the same shapes, and reads the fields xmrig reads. The share
//! it submits is precomputed the way a miner computes it: take the blob out of
//! the job, write a nonce at offset 39, hash it with RandomX under the job's
//! seed, and send the nonce and the hash back.

use super::*;
use sc_consensus_randomx::seal::Seal;
use tokio::io::AsyncBufReadExt;

/// A line-delimited JSON client, which is all a stratum miner is.
struct FakeMiner {
	reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
	writer: tokio::net::tcp::OwnedWriteHalf,
	session: String,
	next_id: u64,
}

impl FakeMiner {
	async fn connect(addr: SocketAddr) -> Self {
		let stream = TcpStream::connect(addr).await.expect("connect");
		let (read, write) = stream.into_split();
		Self { reader: BufReader::new(read), writer: write, session: String::new(), next_id: 1 }
	}

	async fn send(&mut self, method: &str, params: Value) -> u64 {
		let id = self.next_id;
		self.next_id += 1;
		let line =
			json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params}).to_string();
		self.writer.write_all(line.as_bytes()).await.expect("write");
		self.writer.write_all(b"\n").await.expect("newline");
		id
	}

	async fn recv(&mut self) -> Value {
		let mut line = String::new();
		tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
			.await
			.expect("a reply within ten seconds")
			.expect("read");
		serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON: {line:?}: {e}"))
	}

	/// xmrig's login, agent string and all.
	async fn login(&mut self, user: &str) -> Value {
		self.send(
			"login",
			json!({
				"login": user,
				"pass": "x",
				"agent": "XMRig/6.21.0 (Linux x86_64) libuv/1.44.2 gcc/12",
				"algo": ["rx/0", "rx/wow", "cn/r"],
			}),
		)
		.await;
		let response = self.recv().await;
		if let Some(session) = response["result"]["id"].as_str() {
			self.session = session.to_string();
		}
		response
	}

	/// A login that tolerates a socket the server has already closed, for the
	/// tests that poll until a connection slot comes back.
	async fn try_login(&mut self, user: &str) -> Option<Value> {
		let line = json!({
			"id": 1,
			"jsonrpc": "2.0",
			"method": "login",
			"params": {"login": user, "pass": "x", "agent": "XMRig/6.21.0"},
		})
		.to_string();
		self.writer.write_all(line.as_bytes()).await.ok()?;
		self.writer.write_all(b"\n").await.ok()?;
		let mut reply = String::new();
		let read = tokio::time::timeout(Duration::from_secs(2), self.reader.read_line(&mut reply))
			.await
			.ok()?
			.ok()?;
		if read == 0 {
			return None;
		}
		serde_json::from_str(&reply).ok()
	}

	async fn submit(&mut self, job_id: &str, nonce: u32, result: Option<&str>) -> Value {
		let mut params = json!({
			"id": self.session,
			"job_id": job_id,
			"nonce": hex::encode(nonce.to_le_bytes()),
			"algo": "rx/0",
		});
		if let Some(result) = result {
			params["result"] = json!(result);
		}
		self.send("submit", params).await;
		self.recv().await
	}
}

fn test_job(difficulty: u64) -> MiningJob {
	MiningJob {
		job_id: "1".to_string(),
		pre_hash: H256([0x42u8; 32]),
		height: 7,
		difficulty: U512::from(difficulty),
		seed_hash: H256([0x24u8; 32]),
		next_seed_hash: H256([0x24u8; 32]),
	}
}

async fn server_with_job(
	difficulty: u64,
	share_difficulty: u64,
) -> (Arc<StratumServer>, Arc<RandomxEngine>) {
	server_with_limits(difficulty, share_difficulty, Limits::default()).await
}

/// The same, under bounds a test can reach: a cap of 64 connections and a
/// deadline of half an hour are production numbers, and reaching either one
/// honestly in a test would take hundreds of sockets or minutes of waiting.
async fn server_with_limits(
	difficulty: u64,
	share_difficulty: u64,
	limits: Limits,
) -> (Arc<StratumServer>, Arc<RandomxEngine>) {
	let engine = RandomxEngine::light(2);
	let server = StratumServer::start_with_limits(
		StratumConfig {
			host: IpAddr::from([127, 0, 0, 1]),
			port: 0,
			share_difficulty,
			max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
		},
		engine.clone(),
		limits,
	)
	.await
	.expect("bind");
	server.broadcast_job(test_job(difficulty)).await;
	(server, engine)
}

/// Whether the server has closed this connection, within a few seconds.
async fn is_closed(miner: &mut FakeMiner, within: Duration) -> bool {
	let mut line = String::new();
	matches!(
		tokio::time::timeout(within, miner.reader.read_line(&mut line)).await,
		Ok(Ok(0)) | Ok(Err(_)),
	)
}

/// Take the job apart the way a miner does, find a nonce that clears the
/// target the job carried, and return it with the hash.
fn mine_from_job(engine: &Arc<RandomxEngine>, job: &Value) -> (u32, String) {
	let blob = hex::decode(job["blob"].as_str().expect("blob")).expect("blob hex");
	assert!(blob.len() >= 76, "xmrig refuses a blob under 76 bytes, got {}", blob.len());
	let seed: [u8; 32] = hex::decode(job["seed_hash"].as_str().expect("seed_hash"))
		.expect("seed hex")
		.try_into()
		.expect("32 bytes");
	let target_bytes: [u8; 8] = hex::decode(job["target"].as_str().expect("target"))
		.expect("target hex")
		.try_into()
		.expect("8 bytes");
	let target_value = u64::from_le_bytes(target_bytes);

	let lease = engine.acquire(seed).expect("lease");
	let mut blob: [u8; 76] = blob[..76].try_into().expect("76 bytes");
	for nonce in 0..8_192u32 {
		// Exactly what a miner does: overwrite four bytes at offset 39.
		blob[39..43].copy_from_slice(&nonce.to_le_bytes());
		let hash = lease.hash(&blob).expect("hash");
		if target::meets_share_target(&hash, target_value) {
			return (nonce, hex::encode(hash));
		}
	}
	panic!("no share found in 8192 nonces");
}

#[tokio::test]
async fn a_stock_miner_logs_in_and_gets_a_job_with_every_field_it_needs() {
	let (server, _engine) = server_with_job(1_000, 100).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let response = miner.login("qnero-worker").await;

	assert!(response["error"].is_null(), "login must not error: {response}");
	assert_eq!(response["result"]["status"], "OK");
	assert!(response["result"]["id"].is_string(), "a session id is what submit echoes");

	let job = &response["result"]["job"];
	assert_eq!(job["algo"], ALGO);
	assert_eq!(job["job_id"], "1");
	assert_eq!(job["height"], 7);
	assert_eq!(job["seed_hash"].as_str().expect("seed_hash").len(), 64);
	assert_eq!(job["next_seed_hash"].as_str().expect("next_seed_hash").len(), 64);
	// 16 hex characters: the u64 form, because a share difficulty above 2^32
	// cannot be said in the short one.
	assert_eq!(job["target"].as_str().expect("target").len(), 16);
	assert_eq!(hex::decode(job["blob"].as_str().expect("blob")).expect("hex").len(), 76);

	// The extensions a Monero pool advertises, and not `nicehash`, which would
	// cost the miner a nonce byte.
	let extensions = response["result"]["extensions"].as_array().expect("extensions");
	assert!(extensions.iter().any(|e| e == "algo"));
	assert!(extensions.iter().any(|e| e == "keepalive"));
	assert!(!extensions.iter().any(|e| e == "nicehash"));
}

#[tokio::test]
async fn a_valid_share_above_the_block_difficulty_becomes_a_seal() {
	// Block difficulty 8 and share difficulty 8: on a chain this easy every
	// share is a block, which is what a devnet looks like.
	let (server, engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let job = login["result"]["job"].clone();

	let (nonce, result) = mine_from_job(&engine, &job);
	let response = miner.submit("1", nonce, Some(&result)).await;
	assert!(response["error"].is_null(), "share must be accepted: {response}");
	assert_eq!(response["result"]["status"], "OK");

	let seal = server
		.recv_seal_timeout(Duration::from_secs(5))
		.await
		.expect("a share at the block difficulty is a seal");
	assert_eq!(seal.job_id, "1");
	assert_eq!(seal.worker, "qnero-worker");
	let decoded = Seal::decode(&seal.seal).expect("the seal is well formed");
	assert_eq!(decoded.nonce, nonce);

	let (accepted, _rejected, blocks) = server.stats();
	assert_eq!((accepted, blocks), (1, 1));
}

/// A share that clears the easy per-connection target but not the block
/// difficulty is counted and acknowledged, and produces no block.
#[tokio::test]
async fn a_share_below_the_block_difficulty_is_counted_and_acknowledged() {
	let (server, engine) = server_with_job(u64::MAX, 1).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let job = login["result"]["job"].clone();
	// Share difficulty 1 means the first nonce is a share.
	assert_eq!(job["target"].as_str().expect("target"), "ffffffffffffffff");

	let (nonce, result) = mine_from_job(&engine, &job);
	let response = miner.submit("1", nonce, Some(&result)).await;
	assert!(response["error"].is_null(), "share must be accepted: {response}");

	let (accepted, rejected, blocks) = server.stats();
	assert_eq!((accepted, rejected, blocks), (1, 0, 0));
	assert!(server.recv_seal_timeout(Duration::from_millis(200)).await.is_none());
}

/// A share that was in flight when the template rolled was still earned: it is
/// hashed, credited and acknowledged. It cannot become a block, because the
/// build it belongs to is gone.
#[tokio::test]
async fn a_share_for_the_job_that_just_moved_on_is_credited_and_seals_nothing() {
	let (server, engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let job = login["result"]["job"].clone();
	let (nonce, result) = mine_from_job(&engine, &job);

	let mut next = test_job(8);
	next.job_id = "2".to_string();
	server.broadcast_job(next).await;
	// The push for the new job arrives on the same connection, which is how a
	// miner learns the template moved.
	let pushed = miner.recv().await;
	assert_eq!(pushed["method"], "job");
	assert_eq!(pushed["params"]["job_id"], "2");

	let response = miner.submit("1", nonce, Some(&result)).await;
	assert!(response["error"].is_null(), "the grace job must be credited: {response}");
	assert_eq!(response["result"]["status"], "OK");

	let (accepted, rejected, blocks) = server.stats();
	assert_eq!((accepted, rejected, blocks), (1, 0, 0));
	assert!(
		server.recv_seal_timeout(Duration::from_millis(200)).await.is_none(),
		"a superseded template has no build left to seal",
	);
}

/// One generation of grace, and no more. A job two templates back is gone, and
/// saying so must not cost the rig its connection.
#[tokio::test]
async fn a_share_two_templates_back_is_expired_and_not_a_critical_error() {
	let (server, engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let (nonce, result) = mine_from_job(&engine, &login["result"]["job"]);

	for id in ["2", "3"] {
		let mut next = test_job(8);
		next.job_id = id.to_string();
		server.broadcast_job(next).await;
		assert_eq!(miner.recv().await["params"]["job_id"], id);
	}

	let response = miner.submit("1", nonce, Some(&result)).await;
	let message = response["error"]["message"].as_str().expect("a rejection message");
	assert_eq!(message, "Block expired");
	assert!(
		!XMRIG_CRITICAL_ERRORS.contains(&message),
		"{message:?} makes xmrig close the socket and drop the pool",
	);
}

/// xmrig closes the connection on exactly four error strings. A stale share is
/// the ordinary outcome of a template roll, so none of the share-level
/// rejections may be one of them: the measured cost of getting this wrong was
/// six reconnects in 69 s, about half the wall time at zero hash rate.
#[tokio::test]
async fn no_share_level_rejection_is_a_string_xmrig_treats_as_critical() {
	// Difficulty and share difficulty both at the ceiling, so no nonce clears
	// either rule and the low-difficulty path is reachable.
	let (server, _engine) = server_with_job(u64::MAX, u64::MAX).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	miner.login("qnero-worker").await;

	let mut messages = Vec::new();
	// A job the node has never issued.
	messages.push(miner.submit("no-such-job", 1, None).await);
	// A nonce that is not four bytes of hex.
	miner
		.send("submit", json!({"id": miner.session, "job_id": "1", "nonce": "zz"}))
		.await;
	messages.push(miner.recv().await);
	// A hash the node does not compute.
	messages.push(miner.submit("1", 2, Some(&"00".repeat(32))).await);
	// A share that clears nothing, then the same nonce again.
	messages.push(miner.submit("1", 3, None).await);
	messages.push(miner.submit("1", 3, None).await);

	let messages: Vec<String> = messages
		.iter()
		.map(|response| {
			response["error"]["message"]
				.as_str()
				.unwrap_or_else(|| panic!("expected a rejection, got {response}"))
				.to_string()
		})
		.collect();
	assert!(
		messages.iter().any(|m| m == "Low difficulty share") &&
			messages.iter().any(|m| m == "Duplicate share"),
		"the test must actually reach those paths: {messages:?}",
	);
	for message in &messages {
		assert!(
			!is_xmrig_critical(message),
			"{message:?} makes xmrig close the socket and drop the pool",
		);
	}
}

/// xmrig compares those four strings with `strncasecmp`, so they are
/// case-insensitive prefixes. A guard that tested whole-string equality would
/// have passed `"Invalid job id (expired)"` and reinstated the reconnect loop
/// this pass was written to remove.
#[test]
fn the_critical_error_guard_matches_the_way_xmrig_matches() {
	for critical in XMRIG_CRITICAL_ERRORS {
		assert!(is_xmrig_critical(critical));
		assert!(is_xmrig_critical(&critical.to_ascii_lowercase()));
		assert!(is_xmrig_critical(&critical.to_ascii_uppercase()));
		assert!(is_xmrig_critical(&format!("{critical} (expired)")));
	}
	assert!(is_xmrig_critical("invalid job id: 42"));
	assert!(!is_xmrig_critical("Block expired"));
	assert!(!is_xmrig_critical("Low difficulty share"));
	assert!(!is_xmrig_critical("Invalid"));
	// A multi-byte character where the prefix would end must not panic.
	assert!(!is_xmrig_critical("Unauthenticat€d"));
}

/// The duplicate set is evicted when the template rolls, and a stalled chain
/// does not roll one. The ceiling is what keeps it finite regardless.
#[test]
fn the_duplicate_set_stops_growing_at_its_ceiling() {
	let mut seen = HashSet::new();
	for nonce in 0..1_000u32 {
		assert!(insert_seen(&mut seen, ("1".to_string(), 1, nonce), 8));
		assert!(seen.len() <= 8, "the set grew past its ceiling: {}", seen.len());
	}
	// And inside the ceiling it still catches a repeat.
	let mut seen = HashSet::new();
	assert!(insert_seen(&mut seen, ("1".to_string(), 1, 7), 8));
	assert!(!insert_seen(&mut seen, ("1".to_string(), 1, 7), 8));
}

/// A flood of refusals must not become a flood of log lines, and the count of
/// what went unprinted has to survive to the next one that is printed.
#[test]
fn refusals_are_logged_once_and_then_counted() {
	// A clock that already reads an hour, so the window can be moved without
	// waiting out a minute.
	let log = RefusalLog::since(Instant::now() - Duration::from_secs(3_600));
	assert_eq!(log.due(), Some(0), "the first refusal is always printed");
	for _ in 0..10 {
		assert_eq!(log.due(), None, "the rest are inside the window");
	}
	// Put the last printed line an hour back, which is past the window.
	log.last.store(0, Ordering::Relaxed);
	assert_eq!(log.due(), Some(10), "the suppressed refusals are reported with the next line");
	assert_eq!(log.due(), None);
}

/// The line bound has to be on the reader. `read_line` on its own appends until
/// it sees a newline, so a peer that never sends one could allocate for as long
/// as the idle deadline allowed: tens of gigabytes on a fast link, times as
/// many sockets as it opened.
#[tokio::test]
async fn a_line_that_never_ends_is_bounded_and_drops_the_connection() {
	let (server, _engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let flood = vec![b'a'; MAX_LINE_BYTES + 1];
	let _ = miner.writer.write_all(&flood).await;

	let mut line = String::new();
	let read = tokio::time::timeout(Duration::from_secs(10), miner.reader.read_line(&mut line))
		.await
		.expect("the server must close the connection and stop buffering");
	assert!(
		matches!(read, Ok(0) | Err(_)),
		"the connection must be closed, got {read:?} with {line:?}",
	);
}

/// The cap is what stops one peer from multiplying whatever per-connection
/// allowance is left across sockets.
#[tokio::test]
async fn the_listener_stops_accepting_past_the_connection_cap() {
	let cap = 4;
	let (server, _engine) = server_with_limits(
		8,
		8,
		Limits { max_connections: cap, max_connections_per_ip: cap, ..Limits::default() },
	)
	.await;
	let mut held = Vec::new();
	for _ in 0..cap {
		held.push(FakeMiner::connect(server.local_addr()).await);
	}
	// Let the accept loop drain the backlog, so the refusal comes from the cap
	// and not from the listen queue.
	tokio::time::sleep(Duration::from_millis(300)).await;
	// The listen backlog still completes the handshake, so the refusal shows up
	// on the socket: a reason, then an EOF.
	let mut extra = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(extra.recv().await["error"]["message"], REFUSED_MESSAGE);
	assert!(is_closed(&mut extra, Duration::from_secs(10)).await, "expected a closed socket");

	// Freeing one lets the next connection in.
	drop(held.pop());
	tokio::time::sleep(Duration::from_millis(200)).await;
	let mut next = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(next.login("qnero-worker").await["result"]["status"], "OK");
}

/// A peer that stops reading its socket must not keep the slot it holds.
///
/// The reply path used to be `send().await`, which waits for queue capacity,
/// and the writer behind it had no deadline. A peer that filled its receive
/// window then parked the connection task forever: with a connection cap in
/// front of it, that is a handful of unauthenticated sockets taking the whole
/// endpoint until the node is restarted.
#[tokio::test]
async fn a_peer_that_stops_reading_gives_its_slot_back() {
	let (server, _engine) = server_with_limits(
		8,
		8,
		Limits {
			max_connections: 1,
			max_connections_per_ip: 1,
			write_timeout: Duration::from_millis(200),
			..Limits::default()
		},
	)
	.await;

	// One socket, never read from, fed lines that each earn a reply. The
	// server's queue fills, then the kernel buffers, and the writer wedges.
	let mut wedged = FakeMiner::connect(server.local_addr()).await;
	let line = json!({"id": 1, "method": "keepalived", "params": {}}).to_string() + "\n";
	let flood = async {
		let mut sent = 0usize;
		while sent < 64 * 1024 * 1024 {
			if wedged.writer.write_all(line.as_bytes()).await.is_err() {
				break;
			}
			sent += line.len();
		}
		sent
	};
	// The flood ends when the server closes on us. Deadlined anyway, so a
	// regression shows up as a failed assertion and not as a hung test.
	let sent = tokio::time::timeout(Duration::from_secs(30), flood).await.unwrap_or_default();

	// The slot comes back, which is the whole of the claim: a fresh connection
	// is accepted and served.
	let mut served = false;
	for _ in 0..50 {
		tokio::time::sleep(Duration::from_millis(100)).await;
		let mut candidate = FakeMiner::connect(server.local_addr()).await;
		if let Some(login) = candidate.try_login("qnero-worker").await {
			if login["result"]["status"] == "OK" {
				served = true;
				break;
			}
		}
	}
	assert!(served, "the wedged connection never released its slot after {sent} bytes");
}

/// A connection that never logs in holds a slot, so it gets the short deadline
/// and not the share-scaled one a rig earns by logging in.
#[tokio::test]
async fn a_connection_that_never_logs_in_gives_its_slot_back() {
	let (server, _engine) = server_with_limits(
		8,
		// A share difficulty this high puts the authenticated deadline at its
		// two-hour ceiling, so the short pre-login window is what is measured.
		u64::MAX,
		Limits {
			max_connections: 1,
			max_connections_per_ip: 1,
			login_timeout: Duration::from_millis(400),
			..Limits::default()
		},
	)
	.await;

	let mut silent = FakeMiner::connect(server.local_addr()).await;
	assert!(
		is_closed(&mut silent, Duration::from_secs(5)).await,
		"a peer that never logs in must not hold a slot for the rig's deadline",
	);

	tokio::time::sleep(Duration::from_millis(200)).await;
	let mut next = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(next.login("qnero-worker").await["result"]["status"], "OK");
}

/// A session that logs in and then never says anything again must not live on
/// the node's own job pushes.
///
/// The share-scaled deadline counts a job push as proof of life, which is
/// right for a rig that is hashing and has found nothing. On its own it is also
/// a session that never has to send another byte: the node pushes a job every
/// block interval and the deadline's floor is 25 of those, so a peer that sends
/// one login line and then drains forever held a connection slot until the node
/// restarted. With 64 slots on the endpoint and four to an address, sixteen
/// addresses sending one line each took the whole thing away from the
/// operator's own rigs.
#[tokio::test]
async fn a_session_that_goes_silent_is_dropped_even_while_jobs_are_pushed() {
	let (server, _engine) = server_with_limits(
		8,
		// The authenticated deadline at its two-hour ceiling, so the only rule
		// that can close this connection is the inbound one.
		u64::MAX,
		Limits { max_idle: Duration::from_millis(600), ..Limits::default() },
	)
	.await;

	let mut silent = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(silent.login("qnero-worker").await["result"]["status"], "OK");

	// Exactly what used to hold the connection open: the node writing to it.
	let pushing = tokio::spawn({
		let server = server.clone();
		async move {
			for id in 2..40u64 {
				let mut job = test_job(8);
				job.job_id = id.to_string();
				server.broadcast_job(job).await;
				tokio::time::sleep(Duration::from_millis(100)).await;
			}
		}
	});

	// Drain the pushes without answering any of them, until the server closes.
	let closed = tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			let mut line = String::new();
			match silent.reader.read_line(&mut line).await {
				Ok(0) | Err(_) => break,
				Ok(_) => {},
			}
		}
	})
	.await;
	pushing.abort();
	assert!(
		closed.is_ok(),
		"a logged-in peer that sends nothing held its slot for as long as the node kept \
		 writing to it",
	);
}

/// One address must not be able to take every slot on the endpoint.
#[tokio::test]
async fn one_address_cannot_take_every_connection_slot() {
	let (server, _engine) = server_with_limits(
		8,
		8,
		Limits { max_connections: 8, max_connections_per_ip: 2, ..Limits::default() },
	)
	.await;

	let mut held = Vec::new();
	for _ in 0..2 {
		let mut miner = FakeMiner::connect(server.local_addr()).await;
		assert_eq!(miner.login("qnero-worker").await["result"]["status"], "OK");
		held.push(miner);
	}
	tokio::time::sleep(Duration::from_millis(200)).await;

	// Six global slots are still free, and this address has used its two.
	let mut extra = FakeMiner::connect(server.local_addr()).await;
	// And the refusal says so. Without a line the rig sees a connect and an
	// immediate EOF, logs "connection closed", and retries every five seconds
	// forever with neither end saying which cap it hit.
	let refusal = extra.recv().await;
	assert_eq!(refusal["error"]["message"], REFUSED_MESSAGE);
	assert!(
		!is_xmrig_critical(REFUSED_MESSAGE),
		"{REFUSED_MESSAGE:?} makes xmrig drop the pool instead of retrying",
	);
	assert!(
		is_closed(&mut extra, Duration::from_secs(5)).await,
		"the per-address budget must refuse this while the endpoint still has room",
	);

	drop(held.pop());
	tokio::time::sleep(Duration::from_millis(200)).await;
	let mut next = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(next.login("qnero-worker").await["result"]["status"], "OK");
}

#[tokio::test]
async fn the_same_nonce_twice_is_a_duplicate() {
	let (server, engine) = server_with_job(u64::MAX, 1).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let (nonce, result) = mine_from_job(&engine, &login["result"]["job"]);

	assert!(miner.submit("1", nonce, Some(&result)).await["error"].is_null());
	let second = miner.submit("1", nonce, Some(&result)).await;
	assert_eq!(second["error"]["message"], "Duplicate share");
}

/// The node never takes the miner's word for the hash. A miner that sends a
/// plausible nonce with a made-up result is refused on the node's own hash.
#[tokio::test]
async fn a_claimed_hash_the_node_does_not_compute_is_refused() {
	let (server, _engine) = server_with_job(u64::MAX, 1).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	miner.login("qnero-worker").await;

	let response = miner.submit("1", 1, Some(&"00".repeat(32))).await;
	assert_eq!(response["error"]["message"], "Invalid result");
	let (accepted, rejected, blocks) = server.stats();
	assert_eq!((accepted, rejected, blocks), (0, 1, 0));
}

/// A miner that sends no `result` at all is still checked, because the node
/// computes the hash either way.
#[tokio::test]
async fn a_submit_without_a_result_field_is_still_checked() {
	let (server, engine) = server_with_job(u64::MAX, 1).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let login = miner.login("qnero-worker").await;
	let (nonce, _) = mine_from_job(&engine, &login["result"]["job"]);
	assert!(miner.submit("1", nonce, None).await["error"].is_null());
}

#[tokio::test]
async fn a_submit_before_login_is_unauthenticated() {
	let (server, _engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	miner
		.send("submit", json!({"id": "1", "job_id": "1", "nonce": "00000000"}))
		.await;
	let response = miner.recv().await;
	assert_eq!(response["error"]["message"], "Unauthenticated");
}

#[tokio::test]
async fn keepalived_is_answered_so_the_miner_does_not_reconnect() {
	let (server, _engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	miner.login("qnero-worker").await;
	miner.send("keepalived", json!({"id": miner.session})).await;
	let response = miner.recv().await;
	assert_eq!(response["result"]["status"], "KEEPALIVED");
}

/// A login the node cannot serve is answered and then the socket closes.
///
/// The answer alone is not enough. xmrig clears its expiry timer on every line
/// it receives and arms its keepalive only inside a *successful* login, so a
/// rig refused on an open socket sits with both timers at zero: measured
/// against xmrig 6.21.3, one log line and then 75 s of nothing. The EOF is what
/// makes it count a failure and reconnect.
#[tokio::test]
async fn a_login_before_the_first_template_is_refused_and_the_socket_closes() {
	let engine = RandomxEngine::light(1);
	let server = StratumServer::start(
		StratumConfig {
			host: IpAddr::from([127, 0, 0, 1]),
			port: 0,
			share_difficulty: 100,
			max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
		},
		engine,
	)
	.await
	.expect("bind");
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let response = miner.login("qnero-worker").await;
	assert_eq!(response["error"]["message"], "No job available yet");
	assert!(
		is_closed(&mut miner, Duration::from_secs(5)).await,
		"the refusal has to arrive as an EOF too, or the rig never retries",
	);
}

/// A pause has to reach the rigs that are already connected.
///
/// Authoring pauses on a stale tip, on no peers, and for the length of an
/// initial sync, and nothing rolls the template out of the grace slot until it
/// comes back. A connected rig was answered `OK` for every share it found, for
/// as long as that lasted, against a template with no build behind it, while a
/// rig connecting during the same pause was refused and closed. The healthy
/// looking path was the lying one.
#[tokio::test]
async fn a_pause_disconnects_the_rigs_it_can_no_longer_serve() {
	let (server, _engine) = server_with_job(u64::MAX, 1).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(miner.login("qnero-worker").await["result"]["status"], "OK");

	// What `pause_authoring` does on the enabled-to-disabled edge.
	server.clear_current_job().await;

	// The reason first, and it must not be one xmrig treats as critical: the
	// node wants this rig back as soon as it is authoring again.
	let reason = miner.recv().await;
	assert_eq!(reason["error"]["message"], PAUSED_MESSAGE);
	assert!(
		!is_xmrig_critical(PAUSED_MESSAGE),
		"{PAUSED_MESSAGE:?} makes xmrig drop the pool instead of retrying",
	);
	// Then the same EOF a fresh login gets, which is what makes the rig count a
	// failure and stop hashing a template that cannot become a block.
	assert!(
		is_closed(&mut miner, Duration::from_secs(5)).await,
		"a paused endpoint must close the connections it can no longer serve",
	);

	// And a fresh login is still refused, because there is no template to hand
	// it.
	let mut fresh = FakeMiner::connect(server.local_addr()).await;
	assert_eq!(fresh.login("qnero-worker").await["error"]["message"], "No job available yet");
}

#[tokio::test]
async fn garbage_does_not_take_the_connection_down() {
	let (server, _engine) = server_with_job(8, 8).await;
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	miner.writer.write_all(b"not json at all\n").await.expect("write");
	let response = miner.recv().await;
	assert_eq!(response["error"]["code"], -32700);
	// Still usable afterwards.
	let login = miner.login("qnero-worker").await;
	assert_eq!(login["result"]["status"], "OK");
}

/// The read has to be cancel safe, because the idle deadline now re-enters it.
///
/// `read_line` is documented as not cancel safe: what it has taken off the
/// socket is dropped with the future. A submit split across two TCP segments
/// with the deadline firing between them would come back as a parse error, and
/// the share in it would be lost without either end knowing which.
#[tokio::test]
async fn a_line_split_by_a_cancelled_read_is_resumed_and_not_lost() {
	let (mut client, server) = tokio::io::duplex(64);
	let mut reader = BufReader::new(server);
	let mut line: Vec<u8> = Vec::new();

	// The first half arrives, then nothing: the read is cancelled by the
	// deadline, exactly as the serve loop cancels it.
	client.write_all(br#"{"id":1,"meth"#).await.expect("first segment");
	assert!(
		tokio::time::timeout(Duration::from_millis(200), read_one_line(&mut reader, &mut line))
			.await
			.is_err(),
		"the read must still be waiting for the rest of the line",
	);

	// The tail arrives and the resumed read completes the same line.
	client.write_all(b"od\":\"keepalived\"}\n").await.expect("second segment");
	let outcome =
		tokio::time::timeout(Duration::from_secs(5), read_one_line(&mut reader, &mut line))
			.await
			.expect("a line within five seconds")
			.expect("read");
	assert!(matches!(outcome, Line::Complete), "expected a complete line");
	let parsed: Value = serde_json::from_slice(trim_ascii(&line)).expect("the whole line parses");
	assert_eq!(parsed["method"], "keepalived");
}

/// The line bound is counted as the line accumulates, so a peer that never
/// sends a newline cannot allocate past it across resumed reads either.
#[tokio::test]
async fn an_unterminated_line_is_refused_at_the_bound() {
	let (mut client, server) = tokio::io::duplex(4096);
	let writing = tokio::spawn(async move {
		let chunk = vec![b'a'; 4096];
		while client.write_all(&chunk).await.is_ok() {}
	});
	let mut reader = BufReader::new(server);
	let mut line: Vec<u8> = Vec::new();
	let outcome =
		tokio::time::timeout(Duration::from_secs(5), read_one_line(&mut reader, &mut line))
			.await
			.expect("the bound must be reached within five seconds")
			.expect("read");
	writing.abort();
	assert!(matches!(outcome, Line::TooLong), "expected the line to be refused");
	// The bound plus at most one `fill_buf` chunk, which is the reader's own
	// 8 KiB buffer.
	assert!(
		line.len() <= MAX_LINE_BYTES + 8 * 1024,
		"the buffer grew past the bound: {}",
		line.len(),
	);
}

/// Two connections must not be handed the same blob, or they grind the same
/// nonce space and duplicate each other's work.
#[tokio::test]
async fn two_miners_get_different_blobs() {
	let (server, _engine) = server_with_job(8, 8).await;
	let mut first = FakeMiner::connect(server.local_addr()).await;
	let mut second = FakeMiner::connect(server.local_addr()).await;
	let a = first.login("a").await;
	let b = second.login("b").await;
	assert_ne!(a["result"]["job"]["blob"], b["result"]["job"]["blob"]);
	// And the difference is confined to the extra nonce: bytes 0..39, the
	// domain tag and the pre-hash the header commits to, are identical.
	let blob_a = hex::decode(a["result"]["job"]["blob"].as_str().expect("blob")).expect("hex");
	let blob_b = hex::decode(b["result"]["job"]["blob"].as_str().expect("blob")).expect("hex");
	assert_eq!(blob_a[..39], blob_b[..39]);
}
