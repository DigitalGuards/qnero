//! What the wallet asks a node, and what a node can learn from being asked.
//!
//! Both of these are regressions. The wallet used to answer "is this note
//! spent?" by probing `UsedNullifiers` with its own nullifiers as raw storage
//! keys, and "what is this leaf's Merkle path?" by asking
//! `zkTree_getMerkleProof` about the leaves it was spending. Both questions
//! reach the same answers as the reads that replaced them, so no assertion
//! over a balance can tell the two apart. These assert over the request log.

mod support;

use std::collections::BTreeSet;

use qnero_circuit::merkle::CommitmentTree;
use qnero_notes::Digest;
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{blake2_128_concat_map_key, identity_map_key, storage_prefix};
use qnero_wallet::store::{NoteOrigin, StoredNote};
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, encode_u8, test_metadata, FakeNode, NodeState};

/// A sync learns which of this wallet's notes are spent without naming one of
/// them to the node.
///
/// `UsedNullifiers` is `Blake2_128Concat`, so a probe of one key carries the
/// raw 32-byte nullifier in the clear. A node that logged those learned, per
/// client, the set of nullifiers this wallet would publish when it spent, and
/// could attribute any later settlement that published one of them with
/// certainty. The map is public: paging its keys asks the same question and
/// distinguishes nothing.
#[test]
fn a_sync_never_names_this_wallets_nullifiers_to_the_node() {
    let dir = support::scratch_dir("nullifiers");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");

    let mine = Digest::hash_bytes(&[b"a nullifier this wallet holds"]);
    let unspent = Digest::hash_bytes(&[b"a nullifier this wallet holds, unspent"]);
    let stranger = Digest::hash_bytes(&[b"somebody else's nullifier"]);
    wallet.store.notes.push(note(1_000, 4, mine));
    wallet.store.notes.push(note(250, 5, unspent));
    wallet.save().expect("the store writes");

    let mut state = NodeState {
        head_number: 12,
        ..Default::default()
    };
    // An empty tree, so the scan has nothing to read and the only thing left
    // is spent status.
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(0));
    for nullifier in [mine, stranger] {
        state.put_storage(
            &blake2_128_concat_map_key("Shielded", "UsedNullifiers", &nullifier.to_bytes()),
            &[],
        );
    }
    let node = FakeNode::start(state);

    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync completes");

    assert_eq!(report.newly_spent, 1);
    assert!(wallet.store.notes[0].spent, "the settled note is spent");
    assert!(!wallet.store.notes[1].spent, "the other note is not");
    assert_eq!(wallet.store.unspent_total(), 250);
    // The whole public set, cached for the next sync to decide against.
    assert_eq!(
        wallet.store.used_nullifiers,
        BTreeSet::from([mine.to_hex(), stranger.to_hex()])
    );

    let state = node.state();
    assert!(
        state.calls("state_getKeysPaged") > 0,
        "the settled set is paged, not probed"
    );
    assert!(!state.asked_about(&unspent.to_hex()), "an unpublished nullifier stays local");
    // Proof requests may echo the entire public page. They must include the
    // stranger's entry alongside our already published nullifier.
    for request in &state.requests {
        let request: serde_json::Value = serde_json::from_str(request).unwrap();
        if request["method"] == "state_getReadProof" {
            let keys = request["params"][0].to_string();
            if keys.contains(&mine.to_hex()) {
                assert!(keys.contains(&stranger.to_hex()), "public proof pages stay broad");
            }
        }
    }
}

/// A spend's Merkle paths come out of a locally rebuilt tree, so no request
/// singles out the leaf being spent.
///
/// `zkTree_getMerkleProof` is only ever asked about a leaf the caller is
/// spending, so every call identifies one of the caller's own leaves, and the
/// settlement that publishes the matching nullifier follows on the same
/// connection seconds later.
#[test]
fn a_rebuilt_tree_reaches_the_chains_root_without_asking_about_a_leaf() {
    let leaves: Vec<Digest> = (0..9u64)
        .map(|index| Digest::hash_bytes(&[b"leaf", &index.to_le_bytes()]))
        .collect();
    let depth = CommitmentTree::depth_for(leaves.len()).expect("a depth");
    let reference = CommitmentTree::new(&leaves, depth).expect("the reference tree builds");

    let mut state = NodeState {
        head_number: 7,
        ..Default::default()
    };
    state.put_storage(
        &storage_prefix("ZkTree", "LeafCount"),
        &encode_u64(leaves.len() as u64),
    );
    state.put_storage(&storage_prefix("ZkTree", "Depth"), &encode_u8(depth as u8));
    for (index, leaf) in leaves.iter().enumerate() {
        state.put_storage(
            &identity_map_key("ZkTree", "Leaves", index as u64),
            &leaf.to_bytes(),
        );
    }
    let node = FakeNode::start(state);

    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let at = chain.head().expect("selected head").hash;
    let tree = chain.rebuild_tree(&at).expect("the tree rebuilds");

    assert_eq!(tree.leaf_count(), leaves.len() as u64);
    assert_eq!(tree.depth(), depth);
    assert_eq!(tree.root(), reference.root());
    for index in 0..leaves.len() as u64 {
        assert_eq!(tree.leaf(index), Some(leaves[index as usize]));
        let path = tree.path(index).expect("a path");
        assert_eq!(
            path.root(leaves[index as usize]).expect("the path folds"),
            reference.root(),
            "the path for leaf {index} must reach the chain's root"
        );
    }

    let state = node.state();
    assert_eq!(
        state.calls("zkTree_getMerkleProof"),
        0,
        "a rebuild must not ask the node about any leaf"
    );
}

fn note(value: u64, leaf_index: u64, nullifier: Digest) -> StoredNote {
    StoredNote {
        leaf_index,
        block_number: Some(3),
        value,
        commitment: Digest::hash_bytes(&[b"cm", &leaf_index.to_le_bytes()]).to_hex(),
        nullifier: nullifier.to_hex().into(),
        rho: Digest::hash_bytes(&[b"rho", &leaf_index.to_le_bytes()])
            .to_hex()
            .into(),
        r: Digest::hash_bytes(&[b"r", &leaf_index.to_le_bytes()])
            .to_hex()
            .into(),
        memo: String::new(),
        origin: NoteOrigin::Spend,
        spent: false,
        spent_seen_at_block: None,
        on_chain: true,
    }
}
