//! A scriptable JSON-RPC node, and the request log it keeps.
//!
//! The wallet's privacy properties are properties of what it *asks*, and no
//! assertion over return values can see them: a wallet that probes
//! `UsedNullifiers` with its own nullifiers and one that pages the whole map
//! reach exactly the same balance. So the tests that cover those properties
//! run the wallet against a node that records every request body, and assert
//! over the log.
//!
//! Deliberately small. It answers the handful of methods the wallet calls, in
//! the shapes a real node answers them in, and nothing else.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use codec::Encode;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::TreeFrontier;
use qnero_notes::{Digest, MinerKey};
use qnero_wallet::extrinsic::ShieldedOutput;
use qnero_wallet::metadata::{
    ChainMetadata, StorageItem, KNOWN_SIGNED_EXTENSIONS, REQUIRED_STORAGE,
};
use serde_json::{json, Value};

/// What the node answers with, and what it has been asked.
#[derive(Default)]
pub struct NodeState {
    /// `0x`-hex storage key to raw value.
    pub storage: BTreeMap<String, Vec<u8>>,
    /// Best block number. `author_submitExtrinsic` advances it.
    pub head_number: u32,
    /// Block number to the hex of every extrinsic in it.
    pub blocks: BTreeMap<u32, Vec<String>>,
    /// Leaf index to a `zkTree_getMerkleProof` result.
    pub merkle_proofs: BTreeMap<u64, Value>,
    /// Every request body, in order.
    pub requests: Vec<String>,
    /// Set when a submission should be included in the next block.
    pub include_submissions: bool,
    /// Omit nodes while retaining the genuine selected header for integrity tests.
    pub missing_proof_nodes: bool,
    /// Raw nodes from a different fixture state, used to check root binding.
    pub proof_node_override: Option<Vec<Vec<u8>>>,
    /// Hide a public key from enumeration while preserving the underlying trie.
    pub hidden_listing_keys: BTreeSet<String>,
    /// Which branch this node is on.
    ///
    /// Mixed into the hash of every block at or above `fork_from`, so bumping
    /// it makes `chain_getBlockHash` answer a different hash from that height
    /// up and the same hash below it: a reorg, as a wallet sees one. The block
    /// number stays in the first four bytes, so a hash still names its height.
    pub fork_tag: u8,
    /// The lowest height `fork_tag` applies to.
    pub fork_from: u32,
    /// Leaf indices `ZkTree::Leaves` answers nothing for, whatever the count
    /// says.
    ///
    /// Below the count that is a node withholding an answer, which the sync
    /// refuses by name: the map has no gaps below its own count, so reading
    /// one as "no leaf here" steps over whatever was on that leaf and then
    /// writes a watermark above it. Every other index below the count is
    /// filled by [`storage_at`], because a fixture with a hole in it is a
    /// chain no node can serve.
    pub withheld_leaves: BTreeSet<u64>,
    /// Blocks `chain_getBlock` answers nothing for, whatever its header says.
    ///
    /// The one way a node can hide a payload now that the payload is in the
    /// body: the body roots as a whole, so there is no single extrinsic to
    /// withhold, and a node that will not serve the block at all is what is
    /// left. The wallet refuses the pass by name and commits no watermark.
    pub withheld_bodies: BTreeSet<u32>,
    /// Blocks whose body `chain_getBlock` serves with one byte changed.
    ///
    /// Changed on the way out, after the header was built, so the header still
    /// carries the root of the body this node actually holds and the body it
    /// serves roots elsewhere. That is the whole of the authentication.
    pub tampered_bodies: BTreeSet<u32>,
    /// The same hook for `Shielded::LeafBlocks`.
    pub withheld_leaf_blocks: BTreeSet<u64>,
    /// The same hook for `Shielded::CoinbaseValues`, which is the one key of
    /// the four a leaf is allowed not to have: presence marks a coinbase.
    pub withheld_coinbase_values: BTreeSet<u64>,
    /// Blocks this node has already dated a leaf to, once and for good.
    ///
    /// Filled in by [`seal_leaves`] on the first request after a leaf appears,
    /// which is what keeps a fixture's history stable: a leaf that shows up
    /// when the head is block twenty is dated there, and raising the count
    /// again later cannot move it back into a block the wallet has already
    /// checkpointed.
    pub sealed: BTreeMap<u64, u32>,
    /// What `ZkTree::LeafCount` answers, where the chain this node's headers
    /// describe is longer.
    ///
    /// A node serving a head it has not finished executing is on this wallet's
    /// chain and answers a short count, and its history is unchanged: the
    /// blocks it already published still carry the roots they carried. Writing
    /// a shorter count into storage instead would rewrite every root and every
    /// hash above it, which is a different branch and not lag at all.
    pub short_leaf_count: Option<u64>,
    /// The miner key whose author label the blocks in [`NodeState::authored`]
    /// carry.
    ///
    /// A wallet decides which blocks it mined by recomputing
    /// `H("qnero/author-label", cvk, parent_hash)` and comparing it against
    /// the pre-runtime digest item in the header, so a fixture that wants a
    /// block to be the wallet's own hands over the wallet's own miner key and
    /// names the heights.
    pub miner_key: Option<MinerKey>,
    /// Heights whose author label is [`NodeState::miner_key`]'s. Every other
    /// height carries a label no key in the test produces.
    pub authored: BTreeSet<u32>,
    /// Leaves this node answers a `Shielded::LeafBlocks` for that is not the
    /// block its own headers put them in.
    ///
    /// The map is advisory: it proposes a block's leaf range and the root in
    /// that block's header settles it, so a node that moves a leaf between
    /// blocks is what this models. Which block a leaf is in is what decides
    /// where a coinbase sits.
    pub misdated_leaves: BTreeMap<u64, u32>,
    /// Heights whose header this node serves with a field changed after the
    /// hash was fixed, so the header no longer hashes to the name it was
    /// asked for.
    pub lying_headers: BTreeSet<u32>,
    /// Heights `chain_getBlockHash` answers `null` for, whatever the head is.
    ///
    /// A node that has a head and no block at a lower height: pruned, or
    /// serving a head it has not filled in behind. It is not a fork, and a
    /// wallet that treats it as one rewinds its watermark on a node that
    /// cannot answer for the range it rewinds into.
    pub missing_hashes: BTreeSet<u32>,
    /// Heights whose header carries no pre-runtime digest item at all, so a
    /// wallet reads no author label there.
    ///
    /// A node above the newest checkpoint chooses every header field, the
    /// label included, and omitting it is the cheapest way to try: no rule of
    /// either wallet may rest on a label being present.
    pub unlabelled: BTreeSet<u32>,
    /// Heights whose header is built with a block number that is not the
    /// height it sits at.
    ///
    /// The header still hashes to its own name, so this is not a header served
    /// with a field changed afterwards: it is a real header of one height
    /// answered for another, which is the lie a walk that fetches by height
    /// rather than by parent link has to catch for itself.
    pub renumbered_headers: BTreeMap<u32, u32>,
    /// Heights whose header is built naming a parent that is not the block
    /// below it.
    ///
    /// The header hashes to its own name and carries the number it sits at, so
    /// every check but one passes: what it is, is a block out of a second
    /// chain spliced into this one. The descending walk could not be shown
    /// this at all, because it fetched each header by the hash its child
    /// named; the pipelined walk fetches by height and checks the parent
    /// links instead.
    pub spliced_parents: BTreeSet<u32>,
    /// Set when this node answers a JSON-RPC batch array with an error rather
    /// than a list of answers.
    ///
    /// The header walk sends its `chain_getHeader` calls as a batch, and a node
    /// that will not take one is an ordinary answer rather than a refusal to
    /// report: the wallet falls back to one request per call. This is what
    /// drives that path.
    pub refuse_batches: bool,
    /// Set when this node answers `chain_getBlockHash` over a list of numbers
    /// with a single hash rather than a list.
    ///
    /// The same shape of fallback for the other half of the walk. An older
    /// node answers the first number and nothing else, which is a list this
    /// wallet cannot read as one and is not a lie about any height.
    pub refuse_hash_lists: bool,
    /// Set when this node answers `chain_getBlockHash` over a list of numbers
    /// with a JSON-RPC error rather than with a hash.
    ///
    /// The other shape of the same older node, and the likelier one: an
    /// implementation whose parameter is a single number fails to deserialize
    /// an array and answers `-32602 Invalid params`. The wallet has to read
    /// that as a parameter this node does not implement rather than as a
    /// refusal, or every walk against such a node is refused outright.
    pub error_hash_lists: bool,
    /// Set when this node answers a JSON-RPC batch array with HTTP 429.
    ///
    /// A rate limiter refusing for now, which says nothing about whether this
    /// node takes batch arrays. The live testnet's front end does exactly this
    /// after about eighty requests in a window, and a wallet that read it as
    /// "no batches" would send the next chunk as a thousand single requests
    /// into the limiter that had just refused one.
    pub rate_limited_batches: bool,
    /// The chain this node's storage implies, kept until that storage moves.
    ///
    /// [`ChainView::build`] folds the tree and hashes a header per block, and
    /// `dispatch` needs one for nearly every request, so a fixture whose head
    /// is thousands of blocks up paid that per request. The key is a digest of
    /// everything `build` reads, so a test that reaches into any of those
    /// fields between syncs still gets a fresh chain.
    pub chain_cache: std::cell::RefCell<Option<(u64, Arc<ChainView>)>>,
    /// Immutable historical state used to build genuine RPC read proofs.
    pub trie_history: std::cell::RefCell<BTreeMap<(u8, u32), Vec<qnero_state_proof::StorageEntry>>>,
}

impl NodeState {
    /// Complete raw proof for this small fixture's selected state.
    pub fn complete_state_proof(&self) -> Vec<Vec<u8>> {
        let entries = trie_entries(self, self.head_number);
        let keys = entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        qnero_state_proof::fixtures::proof(&entries, &keys).1
    }

    /// Whether any request carried this substring. The privacy assertions are
    /// all of this shape.
    pub fn asked_about(&self, needle: &str) -> bool {
        self.requests.iter().any(|body| body.contains(needle))
    }

    /// How many calls of this method the wallet has made.
    ///
    /// Counted per call and not per request body, because a request body may
    /// be a JSON-RPC batch array carrying many of them: the header walk sends
    /// sixty-four `chain_getHeader` calls in one.
    pub fn calls(&self, method: &str) -> usize {
        let needle = format!("\"method\":\"{method}\"");
        self.requests
            .iter()
            .map(|body| body.matches(needle.as_str()).count())
            .sum()
    }

    /// How many HTTP requests the wallet has made, batch arrays counting once.
    pub fn round_trips(&self) -> usize {
        self.requests.len()
    }

    pub fn put_storage(&mut self, key: &[u8], value: &[u8]) {
        self.storage
            .insert(format!("0x{}", hex::encode(key)), value.to_vec());
    }

    pub fn remove_storage(&mut self, key: &[u8]) {
        self.storage.remove(&format!("0x{}", hex::encode(key)));
    }

    /// The hash this node answers at a height, on whichever branch it is on.
    ///
    /// A real header hash: the Poseidon2 hash of the preimage the chain
    /// hashes, over this node's own answers. A wallet fetches every header of
    /// a scanned range by the hash its child names and rehashes it, so a
    /// fixture whose hashes were not its headers' hashes would be a node that
    /// cannot serve a header at all.
    pub fn hash_at(&self, number: u32) -> [u8; 32] {
        self.chain().hash_at(number)
    }

    /// The genesis this node serves, which is what a wallet binds its store to
    /// and what a coinbase note is derived against.
    ///
    /// Block zero's header carries no leaves, so this is fixed before any
    /// fixture writes one and a test can derive a coinbase note from it.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.hash_at(0)
    }

    /// Every header this node would serve, built from its own storage.
    pub fn chain(&self) -> Arc<ChainView> {
        let key = self.chain_key();
        if let Some((cached, view)) = self.chain_cache.borrow().as_ref() {
            if *cached == key {
                return Arc::clone(view);
            }
        }
        let view = Arc::new(ChainView::build(self));
        *self.chain_cache.borrow_mut() = Some((key, Arc::clone(&view)));
        view
    }

    /// A digest of everything [`ChainView::build`] reads.
    fn chain_key(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.head_number.hash(&mut hasher);
        self.fork_tag.hash(&mut hasher);
        self.fork_from.hash(&mut hasher);
        self.short_leaf_count.hash(&mut hasher);
        self.storage.hash(&mut hasher);
        // The bodies reach `build` through the `extrinsicsRoot` it puts in
        // every header, so a fixture that appends an extrinsic gets a fresh
        // chain.
        self.blocks.hash(&mut hasher);
        self.sealed.hash(&mut hasher);
        self.misdated_leaves.hash(&mut hasher);
        self.authored.hash(&mut hasher);
        self.unlabelled.hash(&mut hasher);
        // The withheld sets reach `build` too, through the `storage_at` it
        // folds the tree out of, so a test that clears one between syncs has
        // to get a fresh chain.
        self.withheld_leaves.hash(&mut hasher);
        self.withheld_leaf_blocks.hash(&mut hasher);
        self.withheld_coinbase_values.hash(&mut hasher);
        self.lying_headers.hash(&mut hasher);
        self.missing_hashes.hash(&mut hasher);
        match &self.miner_key {
            Some(key) => key.author_label(&[0u8; 32]).to_bytes().hash(&mut hasher),
            None => 0u8.hash(&mut hasher),
        }
        hasher.finish()
    }
}

/// The header chain a [`NodeState`] implies, block by block.
///
/// Built from the same storage the node answers reads out of, so the
/// `zkTreeRoot` in each header is the root of exactly the leaves this node
/// dates to that block and a wallet's per-block check passes on an honest
/// fixture. A fixture that wants to be caught moves a leaf, a block or a key
/// and the check fails where the wallet says it does.
pub struct ChainView {
    hashes: Vec<[u8; 32]>,
    headers: Vec<Value>,
}

impl ChainView {
    fn build(state: &NodeState) -> Self {
        let declared = node_leaf_count(state);
        let leaf_count = if declared <= MAX_FIXTURE_LEAVES {
            declared
        } else {
            0
        };
        let dates = leaf_blocks(state);
        let leaves: Vec<(Digest, u32)> = (0..leaf_count)
            .map(|index| {
                let bytes = storage_at(
                    state,
                    &format!(
                        "0x{}",
                        hex::encode(qnero_wallet::scale::identity_map_key(
                            "ZkTree", "Leaves", index
                        ))
                    ),
                )
                .unwrap_or_else(|| filler_leaf(index));
                let commitment = <[u8; 32]>::try_from(bytes.as_slice())
                    .ok()
                    .and_then(|bytes| Digest::from_bytes(&bytes).ok())
                    .unwrap_or_else(|| {
                        Digest::hash_bytes(&[b"fixture leaf", &index.to_le_bytes()])
                    });
                (commitment, dates[index as usize])
            })
            .collect();

        let mut frontier = TreeFrontier::new();
        let mut cursor = 0usize;
        let mut parent = [0u8; 32];
        let mut hashes = Vec::with_capacity(state.head_number as usize + 1);
        let mut headers = Vec::with_capacity(state.head_number as usize + 1);
        for number in 0..=state.head_number {
            while cursor < leaves.len() && leaves[cursor].1 == number {
                frontier.push(leaves[cursor].0);
                cursor += 1;
            }
            let root = frontier.root().expect("a fixture tree roots");
            let label = match (&state.miner_key, state.authored.contains(&number)) {
                (Some(key), true) => key.author_label(&parent).to_bytes(),
                _ => qnero_wallet::scale::blake2_256(
                    &[b"somebody else", &number.to_le_bytes()[..]].concat(),
                ),
            };
            let entries = trie_entries(state, number);
            let (state_root, _) = qnero_state_proof::fixtures::proof(&entries, &[]);
            // The header's own commitment to this block's body, built the way
            // `frame_system` builds it. A fixture whose headers carried a
            // constant here would be a node no wallet could read a payload
            // off, because the body check is what authenticates every note
            // ciphertext on the chain.
            let extrinsics_root = qnero_state_proof::extrinsics_root(&body_at(state, number))
                .expect("a fixture body roots");
            let logs = if state.unlabelled.contains(&number) {
                Vec::new()
            } else {
                vec![format!("0x{}", hex::encode(pre_runtime_item(&label)))]
            };
            // Two splices, each applied before the header is hashed, so the
            // header still hashes to its own name and the lie is in what it
            // says rather than in the bytes.
            if state.spliced_parents.contains(&number) {
                parent = qnero_wallet::scale::blake2_256(
                    &[b"a second chain", &number.to_le_bytes()[..]].concat(),
                );
            }
            let claimed = state
                .renumbered_headers
                .get(&number)
                .copied()
                .unwrap_or(number);
            let header = HeaderInputs::new(
                Digest::from_bytes(&parent).expect("a canonical parent"),
                claimed,
                state_root,
                extrinsics_root,
                root,
                &digest_window(&logs),
            )
            .expect("a header");
            let hash = header.block_hash().to_bytes();
            headers.push(json!({
                "parentHash": format!("0x{}", hex::encode(parent)),
                "number": format!("0x{claimed:x}"),
                "stateRoot": format!("0x{}", hex::encode(state_root)),
                "extrinsicsRoot": format!("0x{}", hex::encode(extrinsics_root)),
                "zkTreeRoot": format!("0x{}", root.to_hex()),
                "digest": {"logs": logs},
            }));
            hashes.push(hash);
            parent = hash;
        }
        Self { hashes, headers }
    }

    pub fn hash_at(&self, number: u32) -> [u8; 32] {
        self.hashes
            .get(number as usize)
            .copied()
            .unwrap_or([0u8; 32])
    }

    pub fn number_of(&self, hash: &str) -> Option<u32> {
        let wanted = hash.trim_start_matches("0x").to_ascii_lowercase();
        self.hashes
            .iter()
            .position(|candidate| hex::encode(candidate) == wanted)
            .map(|index| index as u32)
    }

    fn header(&self, number: u32) -> Option<Value> {
        self.headers.get(number as usize).cloned()
    }
}

/// `DigestItem::PreRuntime(POW_ENGINE_ID, label)`, SCALE encoded.
fn pre_runtime_item(label: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![6u8];
    out.extend_from_slice(b"pow_");
    // A `Vec<u8>` of 32 bytes: compact(32) is one byte, `32 << 2`.
    out.push(32u8 << 2);
    out.extend_from_slice(label);
    out
}

/// The 110-byte window the chain hashes the digest through.
fn digest_window(logs: &[String]) -> [u8; DIGEST_LOGS_SIZE] {
    let mut encoded = qnero_wallet::scale::compact_len(logs.len());
    for log in logs {
        encoded.extend_from_slice(&hex::decode(log.trim_start_matches("0x")).expect("hex"));
    }
    let mut padded = [0u8; DIGEST_LOGS_SIZE];
    let taken = encoded.len().min(DIGEST_LOGS_SIZE);
    padded[..taken].copy_from_slice(&encoded[..taken]);
    padded
}

pub struct FakeNode {
    pub url: String,
    pub state: Arc<Mutex<NodeState>>,
}

impl FakeNode {
    /// Start a node on a loopback port of the operating system's choosing.
    pub fn start(state: NodeState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("an address"));
        let state = Arc::new(Mutex::new(state));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = serve(stream, shared);
                });
            }
        });
        Self { url, state }
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, NodeState> {
        self.state.lock().expect("the node state is not poisoned")
    }
}

fn serve(mut stream: TcpStream, state: Arc<Mutex<NodeState>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body).into_owned();

    let request: Value = serde_json::from_str(&body).expect("the wallet sends JSON");

    let rate_limited = {
        let mut state = state.lock().expect("the node state is not poisoned");
        state.requests.push(body.clone());
        request.as_array().is_some() && state.rate_limited_batches
    };
    if rate_limited {
        // A refusal to serve rather than an answer about batching. What a
        // front end that will not take an array body sends is a 4xx this
        // client reads as "no batches"; what this is, is the endpoint refusing
        // everything for the next minute, and the wallet has to tell them
        // apart.
        let page = "<html>\r\n<head><title>429 Too Many Requests</title></head>\r\n</html>";
        write!(
            stream,
            "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
            page.len()
        )?;
        return stream.flush();
    }

    let response = {
        let mut state = state.lock().expect("the node state is not poisoned");
        match request.as_array() {
            // A JSON-RPC batch array. Answered as an array, in the order it
            // arrived, which is one of the two orders a real node may answer
            // in: the wallet matches answers to calls by id and not by
            // position, so `answer_batch` reverses the list to keep it honest.
            Some(calls) if !state.refuse_batches => {
                let mut answers: Vec<Value> = calls
                    .iter()
                    .map(|call| {
                        let method = call["method"].as_str().unwrap_or_default().to_string();
                        let params = call["params"].clone();
                        let id = call["id"].clone();
                        match dispatch(&mut state, &method, &params) {
                            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                            Err(message) => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {"code": -32000, "message": message},
                            }),
                        }
                    })
                    .collect();
                answers.reverse();
                Value::Array(answers)
            }
            // A node that does not take batch arrays. This is what one
            // answers: one error object, no id, and no list.
            Some(_) => json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32600, "message": "batch requests are not supported"},
            }),
            None => {
                let method = request["method"].as_str().unwrap_or_default().to_string();
                let params = request["params"].clone();
                let id = request["id"].clone();
                match dispatch(&mut state, &method, &params) {
                    Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    Err(message) => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": message},
                    }),
                }
            }
        }
    };
    let encoded = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        encoded.len(),
        encoded
    )?;
    stream.flush()
}

fn dispatch(state: &mut NodeState, method: &str, params: &Value) -> Result<Value, String> {
    seal_leaves(state);
    match method {
        "chain_getHeader" => {
            let chain = state.chain();
            let number = match params.get(0).and_then(Value::as_str) {
                Some(hash) => chain
                    .number_of(hash)
                    .ok_or_else(|| format!("no block at {hash}"))?,
                None => state.head_number,
            };
            let mut header = chain
                .header(number)
                .ok_or_else(|| format!("no header at {number}"))?;
            if state.lying_headers.contains(&number) {
                // One field changed after the hash was fixed. A wallet
                // rehashes every header it is handed, so this is what a node
                // serving a header it did not build looks like.
                header["stateRoot"] = json!(format!("0x{}", "ee".repeat(32)));
            }
            Ok(header)
        }
        "chain_getBlockHash" => {
            let one = |state: &NodeState, number: u32| -> Value {
                if number > state.head_number || state.missing_hashes.contains(&number) {
                    Value::Null
                } else {
                    json!(format!("0x{}", hex::encode(state.hash_at(number))))
                }
            };
            // A list of numbers is answered with a list of hashes, which is
            // what Substrate does and what the header walk pages at 256. A
            // node with `refuse_hash_lists` answers the first number alone,
            // which is what an implementation that reads the parameter as one
            // number does, and the wallet then asks one height at a time.
            if let Some(numbers) = params.get(0).and_then(Value::as_array) {
                let heights: Vec<u32> = numbers
                    .iter()
                    .filter_map(Value::as_u64)
                    .map(|number| number as u32)
                    .collect();
                if state.error_hash_lists {
                    return Err(
                        "Invalid params: expected a block number, got a sequence".to_string()
                    );
                }
                if state.refuse_hash_lists {
                    let first = heights.first().copied().unwrap_or(state.head_number);
                    return Ok(one(state, first));
                }
                return Ok(Value::Array(
                    heights.iter().map(|number| one(state, *number)).collect(),
                ));
            }
            let number = params
                .get(0)
                .and_then(Value::as_u64)
                .unwrap_or(u64::from(state.head_number)) as u32;
            Ok(one(state, number))
        }
        "chain_getBlock" => {
            let chain = state.chain();
            let number = params
                .get(0)
                .and_then(Value::as_str)
                .and_then(|hash| chain.number_of(hash))
                .unwrap_or(state.head_number);
            if state.withheld_bodies.contains(&number) {
                // What a node that will not serve a block answers: a result
                // with no block in it, which is not an error and which a
                // wallet must not read as a block that carried nothing.
                return Ok(Value::Null);
            }
            let mut extrinsics = state.blocks.get(&number).cloned().unwrap_or_default();
            if state.tampered_bodies.contains(&number) {
                // One byte, in the last extrinsic, after the header was built.
                let last = extrinsics
                    .last_mut()
                    .expect("a tampered body has an extrinsic to tamper with");
                let mut bytes = hex::decode(last.trim_start_matches("0x")).expect("hex");
                let end = bytes.len() - 1;
                bytes[end] ^= 0x01;
                *last = format!("0x{}", hex::encode(bytes));
            }
            Ok(json!({"block": {"extrinsics": extrinsics}}))
        }
        "state_getRuntimeVersion" => Ok(json!({"specVersion": 152, "transactionVersion": 6})),
        "state_getReadProof" => {
            let at = params
                .get(1)
                .and_then(Value::as_str)
                .ok_or("a read proof must be pinned")?;
            let number = state.chain().number_of(at).ok_or("unknown proof block")?;
            let keys = params
                .get(0)
                .and_then(Value::as_array)
                .ok_or("missing proof keys")?
                .iter()
                .map(|key| hex::decode(key.as_str().unwrap_or("").trim_start_matches("0x")))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            let (_, mut proof) =
                qnero_state_proof::fixtures::proof(&trie_entries(state, number), &keys);
            if let Some(nodes) = &state.proof_node_override {
                proof = nodes.clone();
            }
            if state.missing_proof_nodes {
                proof.clear();
            }
            Ok(json!({"at": at, "proof": proof.iter().map(|node|
                format!("0x{}", hex::encode(node))).collect::<Vec<_>>()}))
        }
        "state_getStorage" => {
            let key = params.get(0).and_then(Value::as_str).unwrap_or_default();
            // `ZkTree::LeafCount` is answered as of the block asked about,
            // which is the one piece of history this node keeps. A wallet
            // recording a birthday reads the count at the epoch block it is
            // starting from, and a fixture that answered the head's count
            // there would hand it a watermark above leaves that block never
            // held. Every other key is answered as it stands: the maps this
            // fixture serves only grow, and no test reads one as of an older
            // block.
            let count_key = format!(
                "0x{}",
                hex::encode(qnero_wallet::scale::storage_prefix("ZkTree", "LeafCount"))
            );
            if key == count_key && state.short_leaf_count.is_none() {
                if let Some(at) = params.get(1).and_then(Value::as_str) {
                    if let Some(number) = state.chain().number_of(at) {
                        if number < state.head_number {
                            let dates = leaf_blocks(state);
                            let count =
                                dates.iter().filter(|block| **block <= number).count() as u64;
                            return Ok(json!(format!("0x{}", hex::encode(count.to_le_bytes()))));
                        }
                    }
                }
            }
            Ok(match storage_at(state, key) {
                Some(value) => json!(format!("0x{}", hex::encode(value))),
                None => Value::Null,
            })
        }
        "state_queryStorageAt" => {
            let keys = params
                .get(0)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let changes: Vec<Value> = keys
                .iter()
                .filter_map(Value::as_str)
                .filter_map(|key| {
                    storage_at(state, key)
                        .map(|value| json!([key, format!("0x{}", hex::encode(value))]))
                })
                .collect();
            Ok(
                json!([{"block": format!("0x{}", hex::encode(state.hash_at(state.head_number))), "changes": changes}]),
            )
        }
        "state_getKeysPaged" => {
            let prefix = params.get(0).and_then(Value::as_str).unwrap_or_default();
            let count = params.get(1).and_then(Value::as_u64).unwrap_or(100) as usize;
            let start = params.get(2).and_then(Value::as_str);
            let keys: Vec<Value> = state
                .storage
                .keys()
                .filter(|key| key.starts_with(prefix) && !state.hidden_listing_keys.contains(*key))
                .filter(|key| match start {
                    Some(cursor) => key.as_str() > cursor,
                    None => true,
                })
                .take(count)
                .map(|key| json!(key))
                .collect();
            Ok(Value::Array(keys))
        }
        "zkTree_getMerkleProof" => {
            let index = params.get(0).and_then(Value::as_u64).unwrap_or_default();
            Ok(state
                .merkle_proofs
                .get(&index)
                .cloned()
                .unwrap_or(Value::Null))
        }
        "author_submitExtrinsic" => {
            let encoded = params
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if state.include_submissions {
                let next = state.head_number + 1;
                state.blocks.entry(next).or_default().push(encoded.clone());
                state.head_number = next;
            }
            Ok(json!(format!(
                "0x{}",
                hex::encode(qnero_wallet::scale::blake2_256(encoded.as_bytes()))
            )))
        }
        "state_getMetadata" => Err("this fake node serves no metadata blob".into()),
        other => Err(format!("{other} is not served by this fake node")),
    }
}

/// One storage value, with every per-leaf map filled in below its own count.
///
/// `pallet-zk-tree` appends a leaf and raises `LeafCount` in one call and
/// nothing ever removes one, and `pallet-shielded` writes `LeafBlocks` in that
/// same call, plus `CoinbaseValues` where the leaf is the coinbase. So a real
/// chain carries a commitment and a block at every index below its count, and
/// the wallet refuses an absent one there by name: below the count, no answer
/// is an answer withheld, and scanning past it hides a payment behind a
/// watermark written above it (`Chain::leaves` and `Wallet::sync_with`). A
/// fixture that writes one leaf and a count of six is describing a chain no
/// node can serve, so the gaps are filled here rather than in every test: what
/// a fixture sets is what the wallet reads, and the rest is a leaf that
/// belongs to nobody. The note ciphertexts are not filled in at all: they live
/// in block bodies, a body with no payload in it is a chain any node can
/// serve, and [`put_payload`] is how a fixture puts one there.
///
/// The same argument reaches `CoinbaseValues` now that a wallet requires one
/// at every coinbase position. A block's coinbase is the last leaf it
/// appended and `pallet-shielded` writes the value in the call that appends
/// it, so on a real chain every block's last leaf carries one and no leaf
/// below it does. That is filled in here from the block ranges rather than
/// from a fixture's intent, so a fixture that writes one leaf and a count of
/// six still describes a chain some node could serve.
///
/// A fixture overrides it in either direction and both are used: writing the
/// key sets the value, and [`NodeState::withheld_coinbase_values`] is the node
/// answering nothing for a key the chain wrote, which is the shape the refusal
/// tests drive.
fn storage_at(state: &NodeState, key: &str) -> Option<Vec<u8>> {
    if let Some(short) = state.short_leaf_count {
        let count_key = format!(
            "0x{}",
            hex::encode(qnero_wallet::scale::storage_prefix("ZkTree", "LeafCount"))
        );
        if key == count_key {
            return Some(short.to_le_bytes().to_vec());
        }
    }
    let Some((item, index)) = leaf_key(key) else {
        return state.storage.get(key).cloned();
    };
    let withheld = match item {
        LeafKey::Leaves => &state.withheld_leaves,
        LeafKey::LeafBlocks => &state.withheld_leaf_blocks,
        LeafKey::CoinbaseValues => &state.withheld_coinbase_values,
    };
    if withheld.contains(&index) {
        return None;
    }
    if item == LeafKey::LeafBlocks {
        if let Some(block) = state.misdated_leaves.get(&index) {
            return Some(codec::Encode::encode(block));
        }
    }
    if let Some(value) = state.storage.get(key) {
        return Some(value.clone());
    }
    if index >= node_leaf_count(state) {
        return None;
    }
    if item == LeafKey::Leaves {
        return Some(filler_leaf(index));
    }
    let mints_here = ends_its_block(state, index);
    match item {
        LeafKey::Leaves => Some(filler_leaf(index)),
        LeafKey::LeafBlocks => leaf_blocks(state)
            .get(index as usize)
            .map(codec::Encode::encode),
        LeafKey::CoinbaseValues if mints_here => {
            Some(codec::Encode::encode(&filler_coinbase_value(index)))
        }
        LeafKey::CoinbaseValues => None,
    }
}

/// Whether a leaf is the last one its block appended, which is the one index
/// of that block a coinbase can occupy.
fn ends_its_block(state: &NodeState, index: u64) -> bool {
    let blocks = leaf_blocks(state);
    let Some(block) = blocks.get(index as usize) else {
        return false;
    };
    match blocks.get(index as usize + 1) {
        Some(next) => next != block,
        None => true,
    }
}

/// The three maps a scan reads per leaf.
///
/// The note ciphertexts are not among them: the chain publishes them in block
/// bodies, so a fixture puts one in a body with [`put_payload`] and this node
/// serves it through `chain_getBlock`, under a header whose `extrinsicsRoot`
/// is the root of that body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafKey {
    Leaves,
    LeafBlocks,
    CoinbaseValues,
}

/// Which per-leaf map a storage key names, and at which index.
fn leaf_key(key: &str) -> Option<(LeafKey, u64)> {
    for (item, pallet, name) in [
        (LeafKey::Leaves, "ZkTree", "Leaves"),
        (LeafKey::LeafBlocks, "Shielded", "LeafBlocks"),
        (LeafKey::CoinbaseValues, "Shielded", "CoinbaseValues"),
    ] {
        let prefix = format!(
            "0x{}",
            hex::encode(qnero_wallet::scale::storage_prefix(pallet, name))
        );
        if let Some(index) = key.strip_prefix(&prefix) {
            let bytes: [u8; 8] = hex::decode(index).ok()?.try_into().ok()?;
            return Some((item, u64::from_le_bytes(bytes)));
        }
    }
    None
}

/// Whether a fixture wrote one per-leaf key itself.
fn has_storage(state: &NodeState, pallet: &str, name: &str, index: u64) -> bool {
    let key = format!(
        "0x{}",
        hex::encode(qnero_wallet::scale::identity_map_key(pallet, name, index))
    );
    state.storage.contains_key(&key)
}

fn node_leaf_count(state: &NodeState) -> u64 {
    let key = format!(
        "0x{}",
        hex::encode(qnero_wallet::scale::storage_prefix("ZkTree", "LeafCount"))
    );
    state
        .storage
        .get(&key)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

/// The block a filled-in leaf is dated at when nothing else decides.
const FILLER_BLOCK: u32 = 1;

/// How many leaves this node will build a chain over.
///
/// A fixture that writes an absurd `ZkTree::LeafCount` is testing the wallet's
/// bound on that number, and the node must not try to fold four billion filler
/// leaves to answer it. Every real fixture is far below this.
const MAX_FIXTURE_LEAVES: u64 = 4096;

/// The block every leaf below the count is dated at.
///
/// Three sources in order: what the fixture wrote, what this node has already
/// sealed, and a derivation for a leaf nobody has dated yet. The derivation is
/// the head at the moment the leaf first appeared, held below the next leaf a
/// fixture did date and above the last one, because leaves are appended in
/// block order and a wallet now checks exactly that against the root in each
/// header.
fn leaf_blocks(state: &NodeState) -> Vec<u32> {
    let declared = node_leaf_count(state);
    let count = if declared <= MAX_FIXTURE_LEAVES {
        declared
    } else {
        0
    };
    let mut out = Vec::with_capacity(count as usize);
    let mut floor = 0u32;
    for index in 0..count {
        let block = if let Some(block) = explicit_leaf_block(state, index) {
            block
        } else if let Some(block) = state.sealed.get(&index).copied() {
            block
        } else {
            let ceiling = (index + 1..count)
                .find_map(|above| explicit_leaf_block(state, above))
                .unwrap_or(u32::MAX);
            state.head_number.min(ceiling).max(floor).max(FILLER_BLOCK)
        };
        floor = block;
        out.push(block);
    }
    out
}

/// Date every leaf this node has not dated yet, at the head it has now.
fn seal_leaves(state: &mut NodeState) {
    let blocks = leaf_blocks(state);
    for (index, block) in blocks.into_iter().enumerate() {
        let index = index as u64;
        if explicit_leaf_block(state, index).is_none() {
            state.sealed.insert(index, block);
        }
    }
}

/// What a fixture wrote at `Shielded::LeafBlocks(index)`, if anything.
fn explicit_leaf_block(state: &NodeState, index: u64) -> Option<u32> {
    let key = format!(
        "0x{}",
        hex::encode(qnero_wallet::scale::identity_map_key(
            "Shielded",
            "LeafBlocks",
            index
        ))
    );
    state
        .storage
        .get(&key)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
        .map(u32::from_le_bytes)
}

/// A coinbase value that is nobody's: the leaf beside it is a filler, so no
/// value rebuilds this wallet's own coinbase note over it.
fn filler_coinbase_value(index: u64) -> u64 {
    index + 1
}

/// A leaf that is nobody's: 32 bytes derived from the index, opened by no
/// payload any body carries.
fn filler_leaf(index: u64) -> Vec<u8> {
    qnero_wallet::scale::blake2_256(&index.to_le_bytes()).to_vec()
}

/// The extrinsics of one block, decoded, in the order `chain_getBlock` serves
/// them.
fn body_at(state: &NodeState, number: u32) -> Vec<Vec<u8>> {
    state
        .blocks
        .get(&number)
        .map(|extrinsics| {
            extrinsics
                .iter()
                .map(|extrinsic| {
                    hex::decode(extrinsic.trim_start_matches("0x")).expect("a fixture body is hex")
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Put one note ciphertext into a block's body, the way a settlement carries
/// it.
///
/// A bare `submit_private_batch` with one output slot: the payload as `ct_1`
/// and an empty `ct_2`, which is the shape a settling slot that emptied its
/// second position publishes. The header's `extrinsicsRoot` follows
/// automatically, because [`ChainView::build`] roots whatever is in
/// `NodeState::blocks`.
pub fn put_payload(state: &mut NodeState, block: u32, ciphertext: &[u8]) {
    let extrinsic = settlement_extrinsic(&[ciphertext.to_vec(), Vec::new()]);
    state
        .blocks
        .entry(block)
        .or_default()
        .push(format!("0x{}", hex::encode(extrinsic)));
}

/// A bare `submit_private_batch(proof, outputs)` carrying these payloads, two
/// to a slot.
///
/// Built through the wallet's own encoder, so the walk the scan makes is
/// reading back exactly what the wallet writes and a change to either side
/// fails here rather than in production.
pub fn settlement_extrinsic(payloads: &[Vec<u8>]) -> Vec<u8> {
    let outputs: Vec<ShieldedOutput> = payloads
        .chunks(2)
        .map(|pair| ShieldedOutput {
            ct_1: pair[0].clone(),
            ct_2: pair.get(1).cloned().unwrap_or_default(),
        })
        .collect();
    qnero_wallet::extrinsic::encode_submit_private_batch(&test_metadata(), b"a proof", &outputs)
        .expect("the fixture settlement encodes")
}

/// A signed `shield(value, inner, ciphertext)`, as a dev account submits one.
///
/// The one signed shape the walk has to handle: past `MultiAddress::Id`, past
/// the ML-DSA-87 signature and public key, past the four extensions that
/// encode anything, and only then the call and its arguments.
pub fn shield_extrinsic(value_planck: u128, inner: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    let metadata = test_metadata();
    let key = qnero_wallet::dev_account::TransparentKey::dev("alice").expect("a dev key");
    let call =
        qnero_wallet::extrinsic::encode_shield_call(&metadata, value_planck, inner, ciphertext);
    qnero_wallet::extrinsic::encode_signed(
        &metadata,
        &key,
        &call,
        &qnero_wallet::extrinsic::SigningContext {
            spec_version: 152,
            transaction_version: 6,
            genesis_hash: [0x11; 32],
            nonce: 0,
            tip: 0,
        },
    )
    .expect("the fixture shield signs")
}

/// An opaque 32 bytes to pin a read to.
///
/// This fake node answers every storage read out of one map whatever block
/// hash it is handed, so a test that only needs *a* hash for an `at`
/// parameter uses this. It is **not** the hash this node serves at that
/// height: that is [`NodeState::hash_at`], a real header hash, and a test
/// comparing hashes or deriving a coinbase note has to use that one.
pub fn block_hash(number: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&number.to_le_bytes());
    hash
}

/// A `ChainMetadata` shaped like the dev runtime's, without a blob to parse.
///
/// The storage list is exactly what the wallet requires, so
/// `ensure_known_storage` passes and a test that wants a drift can edit one
/// entry.
pub fn test_metadata() -> ChainMetadata {
    ChainMetadata {
        protocol_profile: qnero_circuit::profile::SUPPORTED_PROFILE,
        shielded_pallet_index: 24,
        submit_private_batch: 0,
        submit_public_batch: 1,
        shield: 2,
        block_hash_window: 256,
        min_leaf_fee: 1,
        ciphertext_bytes_per_fee_quantum: 512,
        max_ciphertext_bytes: 2048,
        signed_extensions: KNOWN_SIGNED_EXTENSIONS
            .iter()
            .map(|name| name.to_string())
            .collect(),
        extrinsic_version: 4,
        storage: REQUIRED_STORAGE
            .iter()
            .map(|(pallet, name, hasher)| StorageItem {
                pallet: (*pallet).to_string(),
                prefix: (*pallet).to_string(),
                name: (*name).to_string(),
                hasher: hasher.map(str::to_string),
            })
            .collect(),
    }
}

/// SCALE for the storage values the wallet decodes.
pub fn encode_u64(value: u64) -> Vec<u8> {
    value.encode()
}

pub fn encode_u8(value: u8) -> Vec<u8> {
    value.encode()
}

pub fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("qnero-fake-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// A small state trie at one fixture height. Published historical snapshots
/// remain stable when the fixture appends a new block.
fn trie_entries(state: &NodeState, number: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
    let tag = if number >= state.fork_from {
        state.fork_tag
    } else {
        0
    };
    let cache_key = (tag, number);
    if number < state.head_number {
        if let Some(entries) = state.trie_history.borrow().get(&cache_key) {
            return entries.clone();
        }
    }
    let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = state
        .storage
        .iter()
        .filter(|(key, _)| leaf_key(key).is_none())
        .map(|(key, value)| {
            (
                hex::decode(key.trim_start_matches("0x")).unwrap(),
                value.clone(),
            )
        })
        .collect();
    entries.insert(
        qnero_wallet::scale::storage_prefix("Shielded", "ActiveProtocolProfile"),
        qnero_circuit::profile::SUPPORTED_PROFILE.to_vec(),
    );
    let dates = leaf_blocks(state);
    let count = dates.iter().filter(|date| **date <= number).count() as u64;
    let count_key = qnero_wallet::scale::storage_prefix("ZkTree", "LeafCount");
    if number < state.head_number {
        entries.insert(count_key, count.to_le_bytes().to_vec());
    } else if let Some(short) = state.short_leaf_count {
        entries.insert(count_key, short.to_le_bytes().to_vec());
    }
    for index in 0..count.min(MAX_FIXTURE_LEAVES) {
        let mints_here = dates.get(index as usize + 1) != dates.get(index as usize);
        for (pallet, item, withheld) in [
            ("ZkTree", "Leaves", &state.withheld_leaves),
            ("Shielded", "LeafBlocks", &state.withheld_leaf_blocks),
            (
                "Shielded",
                "CoinbaseValues",
                &state.withheld_coinbase_values,
            ),
        ] {
            if withheld.contains(&index) {
                continue;
            }
            let key = qnero_wallet::scale::identity_map_key(pallet, item, index);
            let hex_key = format!("0x{}", hex::encode(&key));
            let value = if item == "LeafBlocks" && state.misdated_leaves.contains_key(&index) {
                state.misdated_leaves.get(&index).map(codec::Encode::encode)
            } else if let Some(value) = state.storage.get(&hex_key) {
                Some(value.clone())
            } else {
                match item {
                    "Leaves" => Some(filler_leaf(index)),
                    "LeafBlocks" => dates.get(index as usize).map(codec::Encode::encode),
                    "CoinbaseValues" if mints_here => {
                        Some(codec::Encode::encode(&filler_coinbase_value(index)))
                    }
                    _ => None,
                }
            };
            if let Some(value) = value {
                entries.insert(key, value);
            }
        }
    }
    // A harmless key distinguishes explicit fixture fork tags in the state.
    entries.insert(b"fixture/branch".to_vec(), vec![tag]);
    let entries: Vec<_> = entries.into_iter().collect();
    state
        .trie_history
        .borrow_mut()
        .insert(cache_key, entries.clone());
    entries
}
