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
    /// The same hook for `Shielded::Ciphertexts`.
    ///
    /// One hook per key rather than one for all four. `pallet-shielded` writes
    /// each of these in the same call that appends the leaf and removes none
    /// of them, so each is its own withheld answer with its own way of hiding
    /// the leaf, and a test that can only take the commitment away cannot
    /// cover the other three.
    pub withheld_ciphertexts: BTreeSet<u64>,
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
    /// The chain this node's storage implies, kept until that storage moves.
    ///
    /// [`ChainView::build`] folds the tree and hashes a header per block, and
    /// `dispatch` needs one for nearly every request, so a fixture whose head
    /// is thousands of blocks up paid that per request. The key is a digest of
    /// everything `build` reads, so a test that reaches into any of those
    /// fields between syncs still gets a fresh chain.
    pub chain_cache: std::cell::RefCell<Option<(u64, Arc<ChainView>)>>,
}

impl NodeState {
    /// Whether any request carried this substring. The privacy assertions are
    /// all of this shape.
    pub fn asked_about(&self, needle: &str) -> bool {
        self.requests.iter().any(|body| body.contains(needle))
    }

    pub fn calls(&self, method: &str) -> usize {
        self.requests
            .iter()
            .filter(|body| body.contains(&format!("\"method\":\"{method}\"")))
            .count()
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
        self.sealed.hash(&mut hasher);
        self.misdated_leaves.hash(&mut hasher);
        self.authored.hash(&mut hasher);
        self.unlabelled.hash(&mut hasher);
        // The withheld sets reach `build` too, through the `storage_at` it
        // folds the tree out of, so a test that clears one between syncs has
        // to get a fresh chain.
        self.withheld_leaves.hash(&mut hasher);
        self.withheld_ciphertexts.hash(&mut hasher);
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
        let leaf_count = node_leaf_count(state).min(MAX_FIXTURE_LEAVES);
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
            let mut state_root = [0x11u8; 32];
            state_root[0] = if number >= state.fork_from {
                state.fork_tag
            } else {
                0
            };
            let logs = if state.unlabelled.contains(&number) {
                Vec::new()
            } else {
                vec![format!("0x{}", hex::encode(pre_runtime_item(&label)))]
            };
            let header = HeaderInputs::new(
                Digest::from_bytes(&parent).expect("a canonical parent"),
                number,
                state_root,
                [0x22u8; 32],
                root,
                &digest_window(&logs),
            )
            .expect("a header");
            let hash = header.block_hash().to_bytes();
            headers.push(json!({
                "parentHash": format!("0x{}", hex::encode(parent)),
                "number": format!("0x{number:x}"),
                "stateRoot": format!("0x{}", hex::encode(state_root)),
                "extrinsicsRoot": format!("0x{}", hex::encode([0x22u8; 32])),
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

    fn number_of(&self, hash: &str) -> Option<u32> {
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
    let method = request["method"].as_str().unwrap_or_default().to_string();
    let params = request["params"].clone();
    let id = request["id"].clone();

    let response = {
        let mut state = state.lock().expect("the node state is not poisoned");
        state.requests.push(body.clone());
        match dispatch(&mut state, &method, &params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(message) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": message}})
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
            let number = params
                .get(0)
                .and_then(Value::as_u64)
                .unwrap_or(u64::from(state.head_number)) as u32;
            if number > state.head_number || state.missing_hashes.contains(&number) {
                return Ok(Value::Null);
            }
            Ok(json!(format!("0x{}", hex::encode(state.hash_at(number)))))
        }
        "chain_getBlock" => {
            let chain = state.chain();
            let number = params
                .get(0)
                .and_then(Value::as_str)
                .and_then(|hash| chain.number_of(hash))
                .unwrap_or(state.head_number);
            let extrinsics = state.blocks.get(&number).cloned().unwrap_or_default();
            Ok(json!({"block": {"extrinsics": extrinsics}}))
        }
        "state_getRuntimeVersion" => Ok(json!({"specVersion": 152, "transactionVersion": 6})),
        "state_getStorage" => {
            let key = params.get(0).and_then(Value::as_str).unwrap_or_default();
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
                .filter(|key| key.starts_with(prefix))
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
/// nothing ever removes one, and `pallet-shielded` writes the leaf's other
/// keys in that same call: a shield and a settled output write `Ciphertexts`
/// and `LeafBlocks`, and a coinbase writes `LeafBlocks` and `CoinbaseValues`.
/// So a real chain carries a commitment, a block and, where the leaf is not a
/// coinbase, a ciphertext at every index below its count, and the wallet
/// refuses an absent one there by name: below the count, no answer is an
/// answer withheld, and scanning past it hides a payment behind a watermark
/// written above it (`Chain::leaves` and `Wallet::sync_with`). A fixture that
/// writes one leaf and a count of six is describing a chain no node can serve,
/// so the gaps are filled here rather than in every test: what a fixture sets
/// is what the wallet reads, and the rest is a leaf that belongs to nobody.
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
        LeafKey::Ciphertexts => &state.withheld_ciphertexts,
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
    let wrote_value = has_storage(state, "Shielded", "CoinbaseValues", index);
    let mints_here = ends_its_block(state, index);
    match item {
        LeafKey::Leaves => Some(filler_leaf(index)),
        LeafKey::LeafBlocks => leaf_blocks(state)
            .get(index as usize)
            .map(codec::Encode::encode),
        // Not for a coinbase leaf: under v1 the inherent refuses a payload, so
        // a coinbase leaf carries no ciphertext, and a fixture whose coinbase
        // was handed a filler would be exercising the payload branch by
        // accident.
        LeafKey::Ciphertexts if !wrote_value && !mints_here => {
            Some(codec::Encode::encode(&filler_ciphertext(index)))
        }
        LeafKey::CoinbaseValues if mints_here => {
            Some(codec::Encode::encode(&filler_coinbase_value(index)))
        }
        LeafKey::Ciphertexts | LeafKey::CoinbaseValues => None,
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

/// The four maps a scan reads per leaf.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafKey {
    Leaves,
    Ciphertexts,
    LeafBlocks,
    CoinbaseValues,
}

/// Which per-leaf map a storage key names, and at which index.
fn leaf_key(key: &str) -> Option<(LeafKey, u64)> {
    for (item, pallet, name) in [
        (LeafKey::Leaves, "ZkTree", "Leaves"),
        (LeafKey::Ciphertexts, "Shielded", "Ciphertexts"),
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
    let count = node_leaf_count(state).min(MAX_FIXTURE_LEAVES);
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

/// A ciphertext that is nobody's: bytes derived from the index, which
/// `NoteCiphertext::from_bytes` refuses at its length before any key is tried.
fn filler_ciphertext(index: u64) -> Vec<u8> {
    qnero_wallet::scale::blake2_256(&index.to_le_bytes()).to_vec()
}

/// A coinbase value that is nobody's: the leaf beside it is a filler, so no
/// value rebuilds this wallet's own coinbase note over it.
fn filler_coinbase_value(index: u64) -> u64 {
    index + 1
}

/// A leaf that is nobody's: 32 bytes derived from the index, with a filler
/// ciphertext beside it that decrypts for no one.
fn filler_leaf(index: u64) -> Vec<u8> {
    qnero_wallet::scale::blake2_256(&index.to_le_bytes()).to_vec()
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
