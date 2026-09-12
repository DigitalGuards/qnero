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

use std::collections::BTreeMap;
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
            Ok(header_json(number))
        }
        "chain_getBlockHash" => {
            let number = params
                .get(0)
                .and_then(Value::as_u64)
                .unwrap_or(u64::from(state.head_number)) as u32;
            if number > state.head_number {
                return Ok(Value::Null);
            }
            Ok(json!(format!("0x{}", hex::encode(block_hash(number)))))
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
            Ok(match state.storage.get(key) {
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
                    state
                        .storage
                        .get(key)
                        .map(|value| json!([key, format!("0x{}", hex::encode(value))]))
                })
                .collect();
            Ok(
                json!([{"block": format!("0x{}", hex::encode(block_hash(state.head_number))), "changes": changes}]),
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

/// Block hashes are the block number, repeated. The wallet treats them as
/// opaque keys, and a readable one makes a failing assertion legible.
pub fn block_hash(number: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&number.to_le_bytes());
    hash
}

fn block_number_of(hash: &str) -> u32 {
    let bytes = hex::decode(hash.trim_start_matches("0x")).unwrap_or_default();
    let mut number = [0u8; 4];
    number.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(number)
}

fn header_json(number: u32) -> Value {
    json!({
        "parentHash": format!("0x{}", hex::encode(block_hash(number.saturating_sub(1)))),
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
