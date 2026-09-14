//! What decides which rule opens a leaf, and what a node cannot do about it.
//!
//! A leaf is a coinbase or it is a transfer, and the two are opened by
//! different rules. Getting the kind wrong is silent: the wrong rule does not
//! open the leaf, the scan reads it as somebody else's, and the pass commits a
//! watermark above it, so nothing reads that leaf again without a rescan.
//!
//! The kind used to be decided by which per-leaf keys a node chose to answer,
//! and both directions of that were exploitable. Eight invented bytes at
//! `Shielded::CoinbaseValues` sent an incoming payment down the coinbase
//! rebuild, which cannot open it. An invented `Shielded::Ciphertexts` beside a
//! withheld coinbase value silenced the rule that was supposed to catch the
//! withholding, and hid a mined reward. Neither is a key the chain wrote.
//!
//! What decides now is what the headers commit to: the header chain itself,
//! the `zkTreeRoot` each block published, the fact that a block's coinbase is
//! the last leaf that block appended, and the author label that says whose
//! block it is. Every test here takes one of those away and watches the pass
//! refuse by name.

mod support;

use qnero_notes::{encrypt_note, Digest, MinerKey, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, test_metadata, FakeNode, NodeState};

fn note_for(pk: Digest, value: u64, tag: &str) -> Note {
    Note::new(
        pk,
        value,
        Digest::hash_bytes(&[b"rho", tag.as_bytes()]),
        Digest::hash_bytes(&[b"r", tag.as_bytes()]),
    )
    .expect("a note")
}

fn ct_for(address: &qnero_notes::Address, note: &Note, tag: u8) -> Vec<u8> {
    encrypt_note(&address.ek, note, &pad_memo("").expect("fits"), &[tag; 32])
        .expect("encrypts")
        .to_bytes()
}

fn put_leaf(state: &mut NodeState, index: u64, block: u32, cm: Digest, ct: &[u8]) {
    state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
    state.put_storage(
        &identity_map_key("Shielded", "Ciphertexts", index),
        &codec::Encode::encode(&ct.to_vec()),
    );
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", index),
        &codec::Encode::encode(&block),
    );
}

fn put_coinbase(state: &mut NodeState, index: u64, block: u32, cm: Digest, value: u64) {
    state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", index),
        &codec::Encode::encode(&block),
    );
    state.put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", index),
        &codec::Encode::encode(&value),
    );
}

/// A wallet, its store directory and a seed, in one line.
fn fresh(tag: &str) -> (std::path::PathBuf, Wallet) {
    let dir = support::scratch_dir(tag);
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let wallet = Wallet::open(&seed).expect("the wallet opens");
    (seed, wallet)
}

/// The control. A payment on one leaf, this wallet's own mined coinbase on
/// another, and both arrive.
#[test]
fn an_honest_node_pays_a_transfer_and_a_mined_coinbase() {
    let (_seed, mut wallet) = fresh("typing-control");
    let address = wallet.address();
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [8].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mine = note_for(address.pk, 1_000, "typing");
    let mined = miner_key.coinbase_note(&genesis, 8, 42).expect("a note");

    put_leaf(&mut state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut state,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    // Block 8's coinbase, minted in `on_finalize` and so its last leaf.
    put_coinbase(&mut state, 2, 8, mined.commitment(), 42);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.received, 2);
    assert_eq!(report.coinbase_leaves, 1);
    assert_eq!(report.coinbase_received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_042);
    assert_eq!(wallet.store.next_leaf, 3);
}

/// An invented `Shielded::CoinbaseValues` on an incoming payment.
///
/// The leaf is not the last one its block appended, so it cannot be a coinbase
/// whatever a node answers for it, and the pass refuses by name rather than
/// sending the payment down a rebuild that cannot open it. Take the
/// coinbase-position rule out of `qnero_wallet::typing` and this becomes a
/// silent skip with a watermark written above the hidden leaf, which is what
/// it was.
#[test]
fn an_invented_coinbase_value_below_a_blocks_last_leaf_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-invented-value");
    let address = wallet.address();

    let mine = note_for(address.pk, 1_000, "masked");
    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut state,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(&mut state, 2, 8, Digest::hash_bytes(&[b"leaf two"]), &[]);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    // The whole attack: eight bytes at a key the pallet never wrote for this
    // leaf. Nothing is removed, so every withheld-answer rule still passes.
    state.put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", 1),
        &encode_u64(1),
    );

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a coinbase value below a block's last leaf is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("Shielded::CoinbaseValues for leaf 1"),
        "{message}"
    );
    assert!(message.contains("last leaf block 8 appended"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");
    assert!(wallet.store.notes.is_empty());

    // The same node without the invented key pays the note.
    node.state()
        .remove_storage(&identity_map_key("Shielded", "CoinbaseValues", 1));
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest answer pays");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);
}

/// An invented coinbase value at the one position a coinbase can occupy, in
/// somebody else's block, with the payment's ciphertext still there.
///
/// Nothing authenticates another author's coinbase value, so the claim is not
/// refusable. What the rule does instead is refuse to let it decide: the
/// ciphertext beside it is tried anyway, so the payment arrives. Under v1 a
/// coinbase carries no ciphertext at all, so this costs nothing on an honest
/// chain.
#[test]
fn an_invented_coinbase_value_at_a_foreign_coinbase_position_still_pays() {
    let (_seed, mut wallet) = fresh("typing-foreign-position");
    let address = wallet.address();

    let mine = note_for(address.pk, 700, "last leaf");
    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    // The payment is the last leaf of block 8, which is where a coinbase would
    // sit if block 8 had minted one.
    put_leaf(
        &mut state,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
    state.put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", 1),
        &encode_u64(1),
    );

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");
    assert_eq!(report.received, 1, "the payment is not skipped");
    assert_eq!(wallet.store.unspent_total(), 700);
}

/// An invented ciphertext beside a withheld coinbase value, at the coinbase
/// position of a block this wallet mined.
///
/// This is the other direction, and it is the one the old rules documented as
/// covered. The ciphertext rule read presence, and presence is the node's to
/// write, so a junk ciphertext silenced it and the mined reward was stepped
/// over. The author label is what closes it: the header commits to
/// `H("qnero/author-label", cvk, parent_hash)`, no node can compute this
/// wallet's, and the coinbase value of a block this wallet mined is therefore
/// a key the node must answer.
#[test]
fn a_withheld_coinbase_value_on_this_wallets_own_block_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-masked-coinbase");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [7].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    state.put_storage(
        &identity_map_key("ZkTree", "Leaves", 0),
        &mined.commitment().to_bytes(),
    );
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", 0),
        &codec::Encode::encode(&7u32),
    );
    // `CoinbaseValues(0)` is withheld and a ciphertext nobody can open is
    // written in its place.
    state.put_storage(
        &identity_map_key("Shielded", "Ciphertexts", 0),
        &codec::Encode::encode(&vec![9u8; 64]),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a withheld coinbase value on this wallet's own block is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("own author label"), "{message}");
    assert!(
        message.contains("no Shielded::CoinbaseValues for leaf 0"),
        "{message}"
    );
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");

    // Answered for, the reward is this wallet's.
    node.state().put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", 0),
        &codec::Encode::encode(&42u64),
    );
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest answer pays the miner");
    assert_eq!(report.coinbase_received, 1);
    assert_eq!(wallet.store.unspent_total(), 42);
}

/// A wrong coinbase value on a block this wallet mined.
///
/// The value is the one field of a coinbase note the chain decides, and the
/// commitment is authenticated by the tree, so a value that rebuilds to
/// another commitment is a node answering something the chain did not write.
/// On somebody else's block the same shape is simply not this wallet's note:
/// `a_value_that_does_not_open_the_commitment_is_not_received` covers that.
#[test]
fn a_wrong_value_on_this_wallets_own_block_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-wrong-value");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 8,
        miner_key: Some(miner_key.clone()),
        authored: [7].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    put_coinbase(&mut state, 0, 7, mined.commitment(), 1_000);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a wrong value on this wallet's own block is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("own author label"), "{message}");
    assert!(message.contains("1000 quanta"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0);
}

/// A node that moves a leaf from one block to another.
///
/// `Shielded::LeafBlocks` proposes a block's leaf range and the `zkTreeRoot`
/// in that block's header settles it. Moving one leaf is what decides where a
/// coinbase sits, so the disagreement refuses the pass.
#[test]
fn a_leaf_dated_to_the_wrong_block_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-misdated");
    let address = wallet.address();

    let mine = note_for(address.pk, 500, "misdated");
    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 7, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut state,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(&mut state, 2, 8, Digest::hash_bytes(&[b"leaf two"]), &[]);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    // The node's headers put leaf 1 in block 8. It answers block 7, which
    // would make leaf 0 block 7's last leaf and leaf 1 nothing this wallet
    // decrypts.
    state.misdated_leaves.insert(1, 7);

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a leaf dated to the wrong block is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("zkTreeRoot"), "{message}");
    assert!(message.contains("block 7"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0);

    node.state().misdated_leaves.clear();
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest dating pays");
    assert_eq!(report.received, 1);
}

/// A node that answers a leaf count its own headers do not carry.
///
/// The count is what decides how much of the tree a pass reads, and the root
/// the head's header carries is what checks it. A short count leaves the
/// blocks the pass walked accounting for leaves the header does not.
#[test]
fn a_leaf_count_the_headers_do_not_carry_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-short-count");
    let address = wallet.address();

    let mine = note_for(address.pk, 500, "short count");
    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut state,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(&mut state, 2, 8, Digest::hash_bytes(&[b"leaf two"]), &[]);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    // Two leaves, says the node, on a chain whose headers carry three.
    state.short_leaf_count = Some(2);

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a leaf count the headers do not carry is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("zkTreeRoot"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0);
}

/// A header that does not hash to the name it was asked for.
///
/// Every header of a scanned range is fetched by the hash its child names and
/// rehashed from its own preimage. That recomputation is what authenticates
/// the `zkTreeRoot` a leaf range is checked against and the author label that
/// says whose block it is, so a header that fails it authenticates nothing and
/// the walk stops there.
#[test]
fn a_header_that_does_not_hash_to_its_own_name_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-bad-header");
    let address = wallet.address();

    let mine = note_for(address.pk, 500, "bad header");
    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(
        &mut state,
        0,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));
    state.lying_headers.insert(5);

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a header that does not hash to its own name is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("hashes to"), "{message}");
    assert!(message.contains("block 5"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0);

    node.state().lying_headers.clear();
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest chain pays");
    assert_eq!(report.received, 1);
}

/// The author label is a secret's output, so holding the address is not
/// holding the ability to claim a block.
#[test]
fn an_author_label_cannot_be_produced_from_the_address_alone() {
    let (_seed, wallet) = fresh("typing-author-label");
    let mine = wallet.miner_key();
    let same_address = MinerKey::new(mine.pk, Digest::hash_bytes(&[b"not my cvk"]));
    let parent = [7u8; 32];
    assert_ne!(
        mine.author_label(&parent),
        same_address.author_label(&parent),
        "the label is the coinbase viewing key's, and the address is not it"
    );
}
