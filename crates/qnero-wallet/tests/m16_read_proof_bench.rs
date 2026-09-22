//! M16 measurement harness: `state_getReadProof` page sizes and verify time.
//!
//! Not part of the wallet's own test suite. It needs a running node, so it is
//! `#[ignore]`d in the style of the other measurement harnesses:
//!
//! ```text
//! QNERO_NODE=http://127.0.0.1:9944 QNERO_M16_OUT=/tmp/m16 \
//!   cargo test -p qnero-wallet --release --test m16_read_proof_bench -- \
//!   --ignored --nocapture
//! ```
//!
//! It records, for one block hash: the raw proof bytes, node count and bytes
//! per key for a page of 64 and a page of 16 leaf indices, separately for
//! `ZkTree::Leaves` and `Shielded::Ciphertexts`; and the native verify time
//! through `qnero_state_proof::read_values`. It writes each proof out as the
//! JSON request `readStateProof` takes, so the wasm twin measures the same
//! bytes.

use std::time::Instant;

use qnero_wallet::{
    rpc::{hex_0x, RpcClient},
    scale::identity_map_key,
};
use serde_json::json;

const SAMPLES: usize = 50;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let middle = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

#[test]
#[ignore]
fn m16_read_proof_pages() {
    let url = std::env::var("QNERO_NODE").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let out = std::env::var("QNERO_M16_OUT").unwrap_or_else(|_| "/tmp/m16".into());
    std::fs::create_dir_all(&out).expect("output directory");
    let rpc = RpcClient::new(&url);

    let head: String = rpc
        .call_as("chain_getBlockHash", json!([]))
        .expect("head hash");
    let root = rpc.state_root(&head).expect("state root");
    println!("node          : {url}");
    println!("block         : {head}");
    println!("state root    : {}", hex_0x(&root));

    // `LeafCount` is a plain value: twox128(pallet) ++ twox128(item).
    let leaf_count = {
        let key = {
            let mut key = qnero_wallet::scale::storage_prefix("ZkTree", "LeafCount");
            key.truncate(32);
            key
        };
        let raw: Option<String> = rpc
            .call_as("state_getStorage", json!([hex_0x(&key), head]))
            .expect("leaf count");
        let bytes =
            hex::decode(raw.expect("leaf count present").trim_start_matches("0x")).expect("hex");
        u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]))
    };
    println!("leaf count    : {leaf_count}");

    // The highest leaf index whose ciphertext is still inside the runtime's
    // 64-block retention window. A page ending here is the shape a wallet
    // scanning a settlement reads; a page at the tail of the tree on this
    // chain is coinbase leaves, whose ciphertext slot is empty.
    let mut settled_top = leaf_count.saturating_sub(1);
    for index in (0..leaf_count).rev() {
        let key = identity_map_key("Shielded", "Ciphertexts", index);
        let raw: Option<String> = rpc
            .call_as("state_getStorage", json!([hex_0x(&key), head]))
            .expect("ciphertext probe");
        if raw.is_some() {
            settled_top = index;
            break;
        }
    }
    println!("top live ct   : leaf {settled_top}");

    // Three windows per map: `head` is the first indices in the tree, which on
    // this dev chain are coinbase leaves with no ciphertext; `tail` is the last
    // indices in the tree; `settled` ends on the newest leaf whose ciphertext
    // is still live.
    for (pallet, item) in [("ZkTree", "Leaves"), ("Shielded", "Ciphertexts")] {
        for (window, page) in [
            ("head", 64usize),
            ("head", 16),
            ("tail", 64),
            ("tail", 16),
            ("settled", 64),
            ("settled", 16),
        ] {
            let first = match window {
                "head" => 0,
                "tail" => leaf_count.saturating_sub(page as u64),
                _ => (settled_top + 1).saturating_sub(page as u64),
            };
            let keys: Vec<Vec<u8>> = (first..first + page as u64)
                .map(|index| identity_map_key(pallet, item, index))
                .collect();
            let hex_keys: Vec<String> = keys.iter().map(|key| hex_0x(key)).collect();
            #[derive(serde::Deserialize)]
            struct ReadProof {
                at: String,
                proof: Vec<String>,
            }
            let answer: ReadProof = rpc
                .call_as("state_getReadProof", json!([hex_keys, head]))
                .expect("read proof");
            assert_eq!(answer.at, head, "proof is for another block");
            let hex_len: usize = answer.proof.iter().map(|node| node.len()).sum();
            let nodes: Vec<Vec<u8>> = answer
                .proof
                .iter()
                .map(|node| hex::decode(node.trim_start_matches("0x")).expect("hex node"))
                .collect();
            let bytes: usize = nodes.iter().map(|node| node.len()).sum();

            let values =
                qnero_state_proof::read_values(root, nodes.clone(), &keys).expect("proof verifies");
            let present = values.iter().filter(|value| value.is_some()).count();
            let value_bytes: usize = values
                .iter()
                .filter_map(|value| value.as_ref().map(|value| value.len()))
                .sum();

            let mut samples = Vec::with_capacity(SAMPLES);
            for _ in 0..SAMPLES {
                let start = Instant::now();
                let read = qnero_state_proof::read_values(root, nodes.clone(), &keys)
                    .expect("proof verifies");
                std::hint::black_box(&read);
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }

            println!("--- {pallet}::{item}, {window} page of {page}, from leaf {first} ---");
            println!("proof nodes          : {}", answer.proof.len());
            println!("proof bytes          : {bytes}");
            println!("proof hex chars      : {hex_len}");
            println!("bytes per key        : {:.1}", bytes as f64 / page as f64);
            println!("values present       : {present} of {page}");
            println!("value bytes          : {value_bytes}");
            println!(
                "native verify median : {:.3} ms over {SAMPLES} samples",
                median(samples.clone())
            );
            println!(
                "native verify min    : {:.3} ms",
                samples.iter().cloned().fold(f64::INFINITY, f64::min)
            );

            let request = json!({
                "root": hex_0x(&root),
                "nodes": answer.proof,
                "keys": hex_keys,
            });
            let path = format!(
                "{out}/{}_{}_{window}_{page}.json",
                pallet.to_lowercase(),
                item.to_lowercase()
            );
            std::fs::write(&path, serde_json::to_string(&request).unwrap()).expect("write request");
            println!("wasm request written : {path}");
        }
    }
}

/// The other half of the measurement: what one settled transfer writes into
/// state, and what its settlement extrinsic weighs on the wire.
#[test]
#[ignore]
fn m16_settlement_state_and_body() {
    use qnero_wallet::scale::{blake2_128_concat_map_key, storage_prefix};

    let url = std::env::var("QNERO_NODE").unwrap_or_else(|_| "http://127.0.0.1:9944".into());
    let rpc = RpcClient::new(&url);
    let head: String = rpc
        .call_as("chain_getBlockHash", json!([]))
        .expect("head hash");

    fn plain(rpc: &RpcClient, pallet: &str, item: &str, at: &str) -> Option<Vec<u8>> {
        let key = storage_prefix(pallet, item);
        let raw: Option<String> = rpc
            .call_as("state_getStorage", json!([hex_0x(&key), at]))
            .expect("plain value");
        raw.map(|value| hex::decode(value.trim_start_matches("0x")).expect("hex"))
    }
    let leaf_count = plain(&rpc, "ZkTree", "LeafCount", &head)
        .map(|bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        .expect("leaf count");
    let entry_count = plain(&rpc, "Shielded", "EntryCount", &head)
        .map(|bytes| u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        .unwrap_or_default();
    println!("block         : {head}");
    println!("leaf count    : {leaf_count}");
    println!("entry count   : {entry_count}");

    // Value bytes per leaf for the last 24 leaves, so a settlement pair and
    // the coinbase leaves around it can be told apart by what they store.
    println!("--- per-leaf stored value bytes (key bytes are 32 prefix + 8 index) ---");
    println!("leaf,leaves,ciphertexts,leafblocks,coinbasevalues");
    let first = leaf_count.saturating_sub(24);
    for index in first..leaf_count {
        let mut sizes = Vec::new();
        for (pallet, item) in [
            ("ZkTree", "Leaves"),
            ("Shielded", "Ciphertexts"),
            ("Shielded", "LeafBlocks"),
            ("Shielded", "CoinbaseValues"),
        ] {
            let key = identity_map_key(pallet, item, index);
            let raw: Option<String> = rpc
                .call_as("state_getStorage", json!([hex_0x(&key), head]))
                .expect("value");
            sizes.push(
                raw.map(|value| (value.trim_start_matches("0x").len()) / 2)
                    .unwrap_or(0),
            );
        }
        println!(
            "{index},{},{},{},{}",
            sizes[0], sizes[1], sizes[2], sizes[3]
        );
    }

    // The settled nullifier map: one entry per spent note, forever.
    let prefix = storage_prefix("Shielded", "UsedNullifiers");
    let keys: Vec<String> = rpc
        .call_as(
            "state_getKeysPaged",
            json!([hex_0x(&prefix), 1000, hex_0x(&prefix), head]),
        )
        .expect("nullifier keys");
    let key_bytes: usize = keys
        .iter()
        .map(|key| key.trim_start_matches("0x").len() / 2)
        .sum();
    println!("--- Shielded::UsedNullifiers ---");
    println!("entries       : {}", keys.len());
    println!("key bytes     : {key_bytes}");
    if let Some(key) = keys.first() {
        let raw: Option<String> = rpc
            .call_as("state_getStorage", json!([key, head]))
            .expect("nullifier value");
        println!(
            "value bytes   : {} per entry",
            raw.map(|value| value.trim_start_matches("0x").len() / 2)
                .unwrap_or(0)
        );
    }
    let _ = blake2_128_concat_map_key("Shielded", "UsedNullifiers", &[0u8; 32]);

    // Every block body from genesis to head, with each extrinsic's size, so a
    // settlement extrinsic's share of a block is explicit.
    println!("--- block bodies ---");
    println!("height,extrinsics,total_body_bytes,largest_extrinsic_bytes");
    let head_number = {
        #[derive(serde::Deserialize)]
        struct Header {
            number: String,
        }
        let header: Header = rpc
            .call_as("chain_getHeader", json!([head]))
            .expect("header");
        u64::from_str_radix(header.number.trim_start_matches("0x"), 16).expect("height")
    };
    for height in 0..=head_number {
        let hash: String = rpc
            .call_as("chain_getBlockHash", json!([height]))
            .expect("hash");
        #[derive(serde::Deserialize)]
        struct SignedBlock {
            block: Block,
        }
        #[derive(serde::Deserialize)]
        struct Block {
            extrinsics: Vec<String>,
        }
        let block: SignedBlock = rpc.call_as("chain_getBlock", json!([hash])).expect("block");
        let sizes: Vec<usize> = block
            .block
            .extrinsics
            .iter()
            .map(|extrinsic| extrinsic.trim_start_matches("0x").len() / 2)
            .collect();
        println!(
            "{height},{},{},{}",
            sizes.len(),
            sizes.iter().sum::<usize>(),
            sizes.iter().copied().max().unwrap_or(0)
        );
    }
}
