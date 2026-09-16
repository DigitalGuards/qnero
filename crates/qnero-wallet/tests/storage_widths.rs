//! Every integer this wallet reads out of storage, at the width the runtime
//! declares, and the leaf count bounded by what the circuit can prove over.
//!
//! `u64::decode` reads the first eight bytes of whatever it is handed and
//! ignores the rest, so a value of another width does not fail: it decodes to
//! a plausible number. That matters here because each of these numbers is one
//! a wallet turns into work or into a statement about somebody's money.
//! `ZkTree::LeafCount` decides how many leaves a scan reads, one window per 64
//! of it, so thirty-two bytes of `0xff` read as `u64::MAX` was a scan that
//! never ends. `Shielded::EntryCount` is hashed once per unit by the origin
//! walk. `Shielded::LeafBlocks` dates a leaf and is what a coinbase note is
//! rebuilt from, and `Shielded::CoinbaseValues` is that note's value.
//!
//! The bound is the second half of the leaf count. A 4-ary tree at the depth
//! the circuit can prove holds `4 ** MAX_TREE_DEPTH` leaves, which
//! `pallet-zk-tree` enforces on the way in as `capacity_at_depth`, so a count
//! above it is not a tree this chain carries whatever width it arrived at.
//!
//! `wallet-web/tests/chain.test.ts` is the same set of rules on the browser's
//! side, where `decodeInteger` and `readTreeShape` hold them.

mod support;

use qnero_notes::Digest;
use qnero_wallet::chain::Chain;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use support::{encode_u64, FakeNode, NodeState};

/// `4 ** MAX_TREE_DEPTH`, which is what `pallet-zk-tree::capacity_at_depth`
/// answers at `CIRCUIT_MAX_TREE_DEPTH` and what the tree can hold.
const TREE_CAPACITY: u64 = 4u64.pow(16);

fn node_with(state: NodeState) -> FakeNode {
    FakeNode::start(state)
}

#[test]
fn a_leaf_count_of_another_width_is_refused_by_name() {
    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    // Thirty-two bytes of 0xff, which `u64::decode` reads as `u64::MAX` and
    // leaves twenty-four bytes of it unread.
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &[0xff; 32]);
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = chain
        .leaf_count_at(&chain.head().expect("selected head").hash)
        .expect_err("a leaf count that is not eight bytes is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("ZkTree::LeafCount is 32 bytes"),
        "{message}"
    );
    assert!(message.contains("decodes it as 8"), "{message}");

    // The same node answering at the declared width is read.
    node.state()
        .put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    assert_eq!(
        chain
            .leaf_count_at(&chain.head().expect("selected head").hash)
            .expect("eight bytes read back"),
        7
    );
}

#[test]
fn a_leaf_count_above_the_trees_capacity_is_refused() {
    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    state.put_storage(
        &storage_prefix("ZkTree", "LeafCount"),
        &encode_u64(TREE_CAPACITY + 1),
    );
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = chain
        .leaf_count_at(&chain.head().expect("selected head").hash)
        .expect_err("a count above the tree's capacity is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("4 ** 16"), "{message}");
    assert!(
        message.contains(&TREE_CAPACITY.to_string()),
        "the refusal names the capacity: {message}"
    );

    // The capacity itself is a tree the chain can carry, so it is read.
    node.state().put_storage(
        &storage_prefix("ZkTree", "LeafCount"),
        &encode_u64(TREE_CAPACITY),
    );
    assert_eq!(
        chain
            .leaf_count_at(&chain.head().expect("selected head").hash)
            .expect("the capacity is a count this chain can reach"),
        TREE_CAPACITY
    );
}

#[test]
fn an_entry_count_of_another_width_is_refused_by_name() {
    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("Shielded", "EntryCount"), &[0xff; 32]);
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = chain
        .entry_count_at(&chain.head().expect("selected head").hash)
        .expect_err("an entry counter that is not eight bytes is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("Shielded::EntryCount is 32 bytes"),
        "{message}"
    );
}

#[test]
fn a_tree_depth_of_another_width_is_refused_by_name() {
    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    // Two bytes, which `u8::decode` reads as the first of them: a depth of 4
    // where the runtime declared 1024, and a local rebuild at the wrong depth
    // reaches a root the header does not carry.
    state.put_storage(&storage_prefix("ZkTree", "Depth"), &[0x04, 0x00]);
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = chain
        .tree_depth_at(&chain.head().expect("selected head").hash)
        .expect_err("a depth that is not one byte is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("ZkTree::Depth is 2 bytes"), "{message}");
}

#[test]
fn a_leaf_block_and_a_coinbase_value_of_another_width_are_refused_by_name() {
    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));
    state.put_storage(
        &identity_map_key("ZkTree", "Leaves", 0),
        &Digest::hash_bytes(&[b"a leaf"]).to_bytes(),
    );
    // Eight bytes where the runtime declares four: a height read off by a
    // factor of 2^32, and a coinbase note rebuilt from it belongs to nobody.
    state.put_storage(&identity_map_key("Shielded", "LeafBlocks", 0), &[0u8; 8]);
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = chain
        .leaves(0..1, &chain.head().expect("selected head").hash, 1)
        .expect_err("a block height that is not four bytes is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("Shielded::LeafBlocks(0) is 8 bytes"),
        "{message}"
    );

    {
        let mut state = node.state();
        state.put_storage(
            &identity_map_key("Shielded", "LeafBlocks", 0),
            &codec::Encode::encode(&3u32),
        );
        state.put_storage(
            &identity_map_key("Shielded", "CoinbaseValues", 0),
            &[0u8; 4],
        );
    }
    let refused = chain
        .leaves(0..1, &chain.head().expect("selected head").hash, 1)
        .expect_err("a coinbase value that is not eight bytes is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("Shielded::CoinbaseValues(0) is 4 bytes"),
        "{message}"
    );

    // Both at their declared widths, read back.
    node.state().put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", 0),
        &encode_u64(42),
    );
    let leaves = chain
        .leaves(0..1, &chain.head().expect("selected head").hash, 1)
        .expect("the row reads back at the declared widths");
    assert_eq!(leaves[0].block_number, Some(3));
    assert_eq!(leaves[0].coinbase_value, Some(42));
}
