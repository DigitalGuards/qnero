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
    /// Heights `chain_getBlockHash` answers `null` for, whatever the head is.
    ///
    /// A node that has a head and no block at a lower height: pruned, or
    /// serving a head it has not filled in behind. It is not a fork, and a
    /// wallet that treats it as one rewinds its watermark on a node that
    /// cannot answer for the range it rewinds into.
    pub missing_hashes: BTreeSet<u32>,
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
    pub fn hash_at(&self, number: u32) -> [u8; 32] {
        let tag = if number >= self.fork_from {
            self.fork_tag
        } else {
            0
        };
        forked_block_hash(number, tag)
    }
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
    match method {
        "chain_getHeader" => {
            let number = match params.get(0).and_then(Value::as_str) {
                Some(hash) => block_number_of(hash),
                None => state.head_number,
            };
            Ok(header_json(number, state.hash_at(number.saturating_sub(1))))
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
            let number = params
                .get(0)
                .and_then(Value::as_str)
                .map(block_number_of)
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

/// One storage value, with the leaf map filled in below its own count.
///
/// `pallet-zk-tree` appends a leaf and raises `LeafCount` in one call and
/// nothing ever removes one, so a real chain carries a commitment at every
/// index below its count, and the wallet refuses an absent one there by name:
/// below the count, no answer is an answer withheld, and scanning past it
/// hides a payment behind a watermark written above it
/// (`Wallet::sync_with`). A fixture that writes one leaf and a count of six is
/// describing a chain no node can serve, so the gaps are filled here rather
/// than in every test: what a fixture sets is what the wallet reads, and the
/// rest is a leaf that belongs to nobody and carries no ciphertext.
fn storage_at(state: &NodeState, key: &str) -> Option<Vec<u8>> {
    if let Some(index) = leaf_index(key) {
        if state.withheld_leaves.contains(&index) {
            return None;
        }
    }
    if let Some(value) = state.storage.get(key) {
        return Some(value.clone());
    }
    unset_leaf_index(state, key).map(filler_leaf)
}

/// The leaf index of a `ZkTree::Leaves` key below this node's own leaf count.
fn unset_leaf_index(state: &NodeState, key: &str) -> Option<u64> {
    leaf_index(key).filter(|index| *index < node_leaf_count(state))
}

/// The leaf index a `ZkTree::Leaves` key names, whatever the count says.
fn leaf_index(key: &str) -> Option<u64> {
    let prefix = format!(
        "0x{}",
        hex::encode(qnero_wallet::scale::storage_prefix("ZkTree", "Leaves"))
    );
    let index = key.strip_prefix(&prefix)?;
    let bytes: [u8; 8] = hex::decode(index).ok()?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
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

/// A leaf that is nobody's: 32 bytes derived from the index, with no
/// ciphertext beside it, which is what a wormhole or reward leaf looks like.
fn filler_leaf(index: u64) -> Vec<u8> {
    qnero_wallet::scale::blake2_256(&index.to_le_bytes()).to_vec()
}

/// Block hashes are the block number, repeated. The wallet treats them as
/// opaque keys, and a readable one makes a failing assertion legible.
pub fn block_hash(number: u32) -> [u8; 32] {
    forked_block_hash(number, 0)
}

/// The same, on a named branch. Two branches answer different hashes at one
/// height, which is what a wallet's fork check reads.
pub fn forked_block_hash(number: u32, fork_tag: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&number.to_le_bytes());
    hash[4] = fork_tag;
    hash
}

fn block_number_of(hash: &str) -> u32 {
    let bytes = hex::decode(hash.trim_start_matches("0x")).unwrap_or_default();
    let mut number = [0u8; 4];
    number.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(number)
}

fn header_json(number: u32, parent_hash: [u8; 32]) -> Value {
    json!({
        "parentHash": format!("0x{}", hex::encode(parent_hash)),
        "number": format!("0x{number:x}"),
        "stateRoot": format!("0x{}", "11".repeat(32)),
        "extrinsicsRoot": format!("0x{}", "22".repeat(32)),
        "zkTreeRoot": format!("0x{}", "00".repeat(32)),
        "digest": {"logs": []},
    })
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
