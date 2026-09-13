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
	let engine = RandomxEngine::light(2);
	let server = StratumServer::start(
		StratumConfig { host: IpAddr::from([127, 0, 0, 1]), port: 0, share_difficulty },
		engine.clone(),
	)
	.await
	.expect("bind");
	server.broadcast_job(test_job(difficulty)).await;
	(server, engine)
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

#[tokio::test]
async fn a_share_for_a_job_that_moved_on_is_refused() {
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
	assert_eq!(response["error"]["message"], "Invalid job id");
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

#[tokio::test]
async fn a_login_before_the_first_template_is_refused_rather_than_answered_with_no_job() {
	let engine = RandomxEngine::light(1);
	let server = StratumServer::start(
		StratumConfig { host: IpAddr::from([127, 0, 0, 1]), port: 0, share_difficulty: 100 },
		engine,
	)
	.await
	.expect("bind");
	let mut miner = FakeMiner::connect(server.local_addr()).await;
	let response = miner.login("qnero-worker").await;
	assert_eq!(response["error"]["message"], "No job available yet");
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
