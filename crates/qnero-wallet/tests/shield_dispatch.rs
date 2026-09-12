//! A shield that the runtime included and then refused must not be reported as
//! a success.
//!
//! The regression: `shield` waited for the extrinsic's bytes to appear in a
//! block and returned `Ok` at that point. An extrinsic in a block is not a
//! dispatch that succeeded, and a shield whose signer cannot pay, or whose
//! value is not a whole multiple of `POOL_QUANTUM`, is included and then fails
//! having appended no leaf. The command printed a commitment, an inclusion
//! block and an exit code of zero, and left a pending entry in the store that
//! nothing would ever clear.

mod support;

use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::{create_seed, store_path_for};
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::storage_prefix;
use qnero_wallet::store::WalletStore;
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, test_metadata, FakeNode, NodeState};

#[test]
fn a_shield_whose_dispatch_failed_is_an_error_and_leaves_no_pending_note() {
    let dir = support::scratch_dir("shield");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.store.address.clone();

    let mut state = NodeState {
        head_number: 10,
        include_submissions: true,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("Shielded", "EntryCount"), &encode_u64(3));
    // The tree does not move: the extrinsic is included and its dispatch
    // appends no leaf, which is exactly what a failed shield looks like from
    // outside.
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(20));
    let node = FakeNode::start(state);

    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let dev = TransparentKey::dev("alice").expect("a dev account");
    let error = wallet
        .shield(&chain, &test_metadata(), &dev, 1_000, "overdraft")
        .expect_err("an included extrinsic whose dispatch failed is not a success");

    let message = error.to_string();
    assert!(
        message.contains("dispatch failed"),
        "the error must say the dispatch failed: {message}"
    );
    assert!(
        message.contains("no note was created"),
        "the error must say no note exists: {message}"
    );

    // In memory and on disk: a pending entry that survives is a balance the
    // wallet reports forever and nothing ever clears.
    assert!(wallet.store.pending.is_empty());
    let reloaded =
        WalletStore::load_or_new(&store_path_for(&seed), &address).expect("the store reloads");
    assert!(
        reloaded.pending.is_empty(),
        "the pending note must be dropped on disk too"
    );
    assert_eq!(reloaded.pending_total(), 0);
}

/// A drifted storage layout must stop a shield before it is signed.
///
/// The regression: `shield` was the one command that read hand-built storage
/// keys without first checking the runtime's declaration, and `main` runs it
/// before any sync, so nothing else checked either. `ZkTree::Leaves` renamed or
/// moved makes the post-inclusion confirmation read an empty map, so no leaf in
/// the block carries the commitment, and the wallet reports "the dispatch
/// failed ... no note was created" for a shield that actually settled and
/// burned the value, dropping the pending entry holding that note's `r` as it
/// goes.
#[test]
fn a_shield_is_refused_when_the_runtime_storage_is_not_the_one_the_wallet_hashes() {
    let dir = support::scratch_dir("shield-drift");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");

    let state = NodeState {
        head_number: 10,
        include_submissions: true,
        ..Default::default()
    };
    let node = FakeNode::start(state);

    let mut drifted = test_metadata();
    for item in drifted.storage.iter_mut() {
        if item.pallet == "ZkTree" && item.name == "Leaves" {
            item.name = "LeafHashes".into();
        }
    }

    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let dev = TransparentKey::dev("alice").expect("a dev account");
    let error = wallet
        .shield(&chain, &drifted, &dev, 1_000, "drift")
        .expect_err("a layout the wallet does not hash is refused");

    let message = error.to_string();
    assert!(
        message.contains("declares no `Leaves`"),
        "the error must name the drifted item: {message}"
    );

    // Nothing was signed, nothing was sent, and no pending entry exists to be
    // dropped by a false failure report later.
    let state = node.state();
    assert_eq!(state.calls("author_submitExtrinsic"), 0);
    assert!(wallet.store.pending.is_empty());
    let reloaded = WalletStore::load_or_new(&store_path_for(&seed), &wallet.store.address)
        .expect("the store reloads");
    assert!(reloaded.pending.is_empty());
}
