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
//! What decides now is position, and position is what the headers commit to:
//! the header chain itself, the `zkTreeRoot` each block published, and the
//! fact that a block's coinbase is the last leaf that block appended. Every
//! test here takes one of those away and watches the pass refuse by name.
//!
//! **No rule rests on the author label.** These wallets verify no proof of
//! work, so above the newest checkpoint a node picks every header field, the
//! label included. So a coinbase value is required at every coinbase position
//! whatever the label says, this wallet's own coinbase note is rebuilt at
//! every coinbase position whatever the label says, and the label is a
//! cross-check: a label claiming this wallet's block over a rebuild that does
//! not match refuses the pass, and a rebuild that matches under another
//! author's label takes the reward and reports the disagreement.
//!
//! What no per-leaf rule can reach is a node that rebuilds the headers
//! themselves, and the bound that does hold is the checkpoint fork walk:
//! `a_rebuilt_chain_hides_two_notes_until_an_honest_node_answers` drives it.
//! `docs/WALLET.md` carries it under "What a lying node can and cannot do".

mod support;

use qnero_circuit::merkle::{hash_node, TreeFrontier};
use qnero_notes::{encrypt_note, Digest, MinerKey, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::wallet::{SyncOptions, Wallet, WARNED_LEAVES_PER_PASS};
use std::collections::BTreeSet;

use support::{encode_u64, test_metadata, FakeNode, NodeState};

/// The root the chain publishes over exactly these leaves, in this order.
///
/// `TreeFrontier` is the fold `pallet-zk-tree` runs in `on_finalize` and the
/// one `crate::typing` checks a block's leaf range with, so the premise tests
/// below are about the production fold and no model of it.
fn root_over(leaves: &[Digest]) -> Digest {
    let mut frontier = TreeFrontier::new();
    for leaf in leaves {
        frontier.push(*leaf);
    }
    frontier.root().expect("a root")
}

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

/// A withheld coinbase value at a coinbase position, under this wallet's own
/// author label.
///
/// The value is public and `pallet-shielded` writes it in the call that
/// appends the leaf, so an absent one there is an answer withheld, and a scan
/// that stepped over it would drop a mined reward behind a watermark.
#[test]
fn a_withheld_coinbase_value_under_this_wallets_own_label_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-masked-coinbase");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [7].into_iter().collect(),
        withheld_coinbase_values: [0].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    put_coinbase(&mut state, 0, 7, mined.commitment(), 42);
    // A ciphertext nobody can open, written where the chain wrote none. It is
    // what keeps the read layer's "neither key was answered" refusal off this
    // pass, so the rule under test is the one that fires.
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
        .expect_err("a withheld coinbase value at a coinbase position is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("no Shielded::CoinbaseValues for leaf 0"),
        "{message}"
    );
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");

    // Answered for, the reward is this wallet's.
    node.state().withheld_coinbase_values.clear();
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest answer pays the miner");
    assert_eq!(report.coinbase_received, 1);
    assert_eq!(report.coinbase_label_disagreed, 0);
    assert_eq!(wallet.store.unspent_total(), 42);
}

/// The same withholding with the block's author label rebuilt as somebody
/// else's, which is the shape the old rule could not see.
///
/// The requirement used to be gated on the label matching this wallet's, and
/// above the trusted anchor no proof of work pins any header field, so a node
/// that rebuilt the block under a label of its own reached the transfer arm,
/// found no ciphertext either, and the mined coinbase was skipped behind a
/// committed watermark. Take the required value off the coinbase position in
/// `qnero_wallet::typing` and this goes back to a silent skip with `next_leaf`
/// written above the hidden reward.
#[test]
fn a_withheld_coinbase_value_under_a_foreign_label_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-masked-foreign-label");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        // Nothing this node publishes says this wallet mined anything.
        authored: BTreeSet::new(),
        withheld_coinbase_values: [0].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    put_coinbase(&mut state, 0, 7, mined.commitment(), 42);
    // A ciphertext nobody can open, written where the chain wrote none. It is
    // what keeps the read layer's "neither key was answered" refusal off this
    // pass, so the rule under test is the one that fires.
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
        .expect_err("a withheld coinbase value is refused whatever the label says");
    let message = format!("{refused:#}");
    assert!(
        message.contains("no Shielded::CoinbaseValues for leaf 0"),
        "{message}"
    );
    assert!(
        message.contains("whatever the author label says"),
        "{message}"
    );
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");
    assert!(wallet.store.notes.is_empty());
}

/// And with no pre-runtime item at all, which is the cheapest of the three:
/// omit the field rather than invent one.
#[test]
fn a_withheld_coinbase_value_under_no_label_at_all_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-masked-no-label");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [7].into_iter().collect(),
        unlabelled: [7].into_iter().collect(),
        withheld_coinbase_values: [0].into_iter().collect(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    put_coinbase(&mut state, 0, 7, mined.commitment(), 42);
    // A ciphertext nobody can open, written where the chain wrote none. It is
    // what keeps the read layer's "neither key was answered" refusal off this
    // pass, so the rule under test is the one that fires.
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
        .expect_err("a withheld coinbase value is refused with no label to read");
    let message = format!("{refused:#}");
    assert!(
        message.contains("no Shielded::CoinbaseValues for leaf 0"),
        "{message}"
    );
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");
}

/// This wallet's own reward, found under a label that says another author's.
///
/// The rebuild runs at every coinbase position and it is what decides: only
/// the holder of `cvk` derives the `r` inside that commitment, so a leaf the
/// rebuild opens is this wallet's note whatever header sits beside it. Gate
/// the rebuild on the label the way the old rule did and the reward is skipped
/// with the watermark written above it. The disagreement is reported rather
/// than swallowed, because on a block a Qnero node built the label and the
/// note come out of one key.
#[test]
fn a_forged_foreign_label_does_not_hide_this_wallets_own_reward() {
    let (_seed, mut wallet) = fresh("typing-forged-foreign-label");
    let miner_key = wallet.miner_key();

    let mut state = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: BTreeSet::new(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    put_coinbase(&mut state, 0, 7, mined.commitment(), 42);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the reward is found whatever the label says");
    assert_eq!(report.coinbase_received, 1);
    assert_eq!(
        report.coinbase_label_disagreed, 1,
        "the disagreement between the rebuild and the label is reported"
    );
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
    assert!(message.contains("10.00 QNR"), "{message}");
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

/// Both wallets read one header the same way.
///
/// `RawHeader::author_label` and `wallet-web`'s `authorLabelFromHeader` are two
/// implementations of one rule, and a wallet that reads a header differently
/// from the other types a leaf differently from it. The Rust side used to
/// answer `None` for the whole header at the first pre-runtime item of the
/// right shape whose payload was not 32 bytes, where the browser skipped it and
/// carried on. `tests/fixtures/author_label_headers.json` is the one fixture,
/// and `wallet-web/tests/leaf-typing.test.ts` reads the same file.
#[test]
fn both_wallets_read_one_headers_author_label_the_same_way() {
    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        logs: Vec<String>,
        label: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct Fixture {
        cases: Vec<Case>,
    }

    let raw = include_str!("fixtures/author_label_headers.json");
    let fixture: Fixture = serde_json::from_str(raw).expect("the fixture parses");
    assert!(
        fixture.cases.len() >= 6,
        "the fixture covers every shape both wallets have to agree on"
    );
    for case in &fixture.cases {
        let header: qnero_wallet::chain::RawHeader = serde_json::from_value(serde_json::json!({
            "parentHash": format!("0x{}", "00".repeat(32)),
            "number": "0x1",
            "stateRoot": format!("0x{}", "11".repeat(32)),
            "extrinsicsRoot": format!("0x{}", "22".repeat(32)),
            "zkTreeRoot": format!("0x{}", "33".repeat(32)),
            "digest": {"logs": case.logs},
        }))
        .expect("the header parses");
        let read = header
            .author_label()
            .expect("the digest logs are hex")
            .map(hex::encode);
        assert_eq!(read, case.label, "{}", case.name);
    }
}

/// A pass that scans no leaf still walks the headers, so the checkpoint it
/// records names a head it authenticated.
///
/// The checkpoint is what the next pass's header walk stands on. A pass that
/// fetched no header authenticated nothing, and recording the node's claimed
/// head anyway planted a hash the next walk then chained down to and trusted.
/// Take the walk off the no-leaf path and this test goes green with a
/// checkpoint written for a header that never hashed to its own name.
#[test]
fn a_pass_that_scans_no_leaf_still_authenticates_the_head_it_checkpoints() {
    let (_seed, mut wallet) = fresh("typing-empty-pass");

    let state = NodeState {
        head_number: 9,
        lying_headers: [5].into_iter().collect(),
        ..Default::default()
    };
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("an empty pass over a header that does not hash to its own name is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("hashes to"), "{message}");
    assert!(message.contains("block 5"), "{message}");
    assert!(
        wallet.store.checkpoints.is_empty(),
        "a refused pass records no checkpoint"
    );

    node.state().lying_headers.clear();
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("an empty pass over an honest chain runs");
    assert_eq!(report.leaves_scanned, 0);
    let head_hash = hex::encode(node.state().hash_at(9));
    let checkpoint = wallet
        .store
        .newest_checkpoint()
        .cloned()
        .expect("an empty pass records a checkpoint for the head it walked");
    assert_eq!(checkpoint.block_number, 9);
    assert_eq!(checkpoint.block_hash, head_hash);
    assert_eq!(checkpoint.next_leaf, 0);
}

/// A node that rebuilt the headers above this wallet's newest checkpoint hides
/// a payment and a mined reward, and the first honest node undoes it.
///
/// This is the bound, and it is the one `docs/WALLET.md` states under "What a
/// lying node can and cannot do". No per-leaf rule reaches this: the wallet
/// verifies no proof of work, so above the newest checkpoint the node chooses
/// every header field, which means it chooses where each block's leaf range
/// ends, which leaf is a coinbase position and what label sits on each block.
/// Here it puts an incoming payment at a coinbase position and withholds the
/// ciphertext, and it publishes a wrong value under a foreign label over this
/// wallet's own coinbase. Both leaves are stepped over and the watermark goes
/// above them.
///
/// What it cannot do is make that branch survive contact with anyone else. The
/// forged head is recorded only as a checkpoint, and the next pass against an
/// honest node finds the hash at that height disagreeing, rewinds to the newest
/// checkpoint both nodes stand on, and rescans from that checkpoint's
/// watermark. Both hidden notes arrive. Drop the fork walk's rewind and this
/// test keeps the balance at zero for good.
#[test]
fn a_rebuilt_chain_hides_two_notes_until_an_honest_node_answers() {
    let (_seed, mut wallet) = fresh("typing-rebuilt-chain");
    let address = wallet.address();
    let miner_key = wallet.miner_key();

    // A chain both branches agree on, checkpointed before the fork.
    let state = NodeState {
        head_number: 5,
        miner_key: Some(miner_key.clone()),
        authored: BTreeSet::new(),
        ..Default::default()
    };
    let genesis = state.genesis_hash();
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    wallet
        .sync(&chain, &test_metadata())
        .expect("the agreed prefix syncs");
    let agreed = wallet
        .store
        .newest_checkpoint()
        .cloned()
        .expect("a checkpoint at the agreed head");
    assert_eq!(agreed.block_number, 5);

    let mine = note_for(address.pk, 1_000, "rebuilt");
    let mined = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    {
        let mut state = node.state();
        state.head_number = 9;
        // The payment, at what this node's headers make the last leaf of block
        // 6, with its ciphertext withheld. Under these headers the leaf is a
        // coinbase position, so no rule asks for a ciphertext there.
        put_leaf(
            &mut state,
            0,
            6,
            mine.commitment(),
            &ct_for(&address, &mine, 7),
        );
        state.withheld_ciphertexts.insert(0);
        // This wallet's own coinbase for block 7, under a foreign label and a
        // value that rebuilds to nothing.
        put_coinbase(&mut state, 1, 7, mined.commitment(), 999);
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
    }

    let hidden = wallet
        .sync(&chain, &test_metadata())
        .expect("the rebuilt branch is self-consistent, so the pass runs");
    assert_eq!(hidden.received, 0, "both notes are hidden");
    assert_eq!(wallet.store.unspent_total(), 0);
    assert_eq!(wallet.store.next_leaf, 2, "the watermark went above them");
    let forged = wallet
        .store
        .newest_checkpoint()
        .cloned()
        .expect("the forged head is recorded as a checkpoint");
    assert_eq!(forged.block_number, 9);

    // The honest node. It agrees with the branch below block 6 and disagrees
    // above it: block 7 carries this wallet's own author label, block 6's leaf
    // is an ordinary payment with its ciphertext answered for, and the coinbase
    // value is the one the chain wrote.
    {
        let mut state = node.state();
        state.authored = [7].into_iter().collect();
        state.withheld_ciphertexts.clear();
        state.put_storage(
            &identity_map_key("Shielded", "CoinbaseValues", 1),
            &encode_u64(42),
        );
    }
    let honest_head = hex::encode(node.state().hash_at(9));
    assert_ne!(
        honest_head, forged.block_hash,
        "the two branches name different blocks at the checkpointed height"
    );

    let recovered = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest node syncs");
    assert_eq!(
        recovered.forked_at_block,
        Some(agreed.block_number),
        "the walk rewinds to the newest checkpoint both nodes stand on"
    );
    assert_eq!(recovered.rewound_from, Some(2));
    assert_eq!(recovered.rewound_to, Some(0));
    assert_eq!(recovered.received, 2, "both hidden notes arrive");
    assert_eq!(recovered.coinbase_received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_042);
}

/// A chain three chunks ahead of the checkpoint syncs in one command, and
/// records a checkpoint per chunk.
///
/// The head is a number the node answers with and the walk holds one header
/// per block between the trusted anchor and it, so the range is climbed in
/// chunks of `HEADER_WALK_LIMIT`. Each chunk learns its top's hash from
/// `chain_getBlockHash` and then proves it by walking down to a hash already
/// trusted, so the bound costs a request per chunk and no guarantee. Remove
/// the chunking and the walk is one allocation the node sizes; bound it
/// without chunking and a chain this far ahead cannot be synced at all.
#[test]
fn a_chain_three_chunks_ahead_syncs_in_one_command() {
    let (_seed, mut wallet) = fresh("typing-chunked-walk");
    let address = wallet.address();

    let head = qnero_wallet::wallet::HEADER_WALK_LIMIT * 3;
    let mine = note_for(address.pk, 700, "chunked");
    let mut state = NodeState {
        head_number: head,
        ..Default::default()
    };
    put_leaf(
        &mut state,
        0,
        head - 1,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(
        &mut state,
        1,
        head - 1,
        Digest::hash_bytes(&[b"the block's coinbase"]),
        &[],
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("a chain three chunks ahead syncs in one pass");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 700);

    let heights: Vec<u32> = wallet
        .store
        .checkpoints
        .iter()
        .map(|checkpoint| checkpoint.block_number)
        .collect();
    assert_eq!(
        heights,
        vec![
            qnero_wallet::wallet::HEADER_WALK_LIMIT,
            qnero_wallet::wallet::HEADER_WALK_LIMIT * 2,
            head
        ],
        "one checkpoint per chunk, each at the top the chunk authenticated"
    );
    assert_eq!(
        wallet
            .store
            .newest_checkpoint()
            .expect("a checkpoint")
            .block_hash,
        hex::encode(node.state().hash_at(head))
    );
}

/// A complete proof from another state cannot authorize a scan under the
/// selected header. Each case also confirms the authentic proof still syncs.
fn assert_changed_state_refused(tag: &str, key: Vec<u8>, value: Vec<u8>) {
    let (seed, mut wallet) = fresh(tag);
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "authenticated payment");
    let mut selected = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(
        &mut selected,
        0,
        8,
        Digest::hash_bytes(&[b"other payment"]),
        &[],
    );
    put_leaf(
        &mut selected,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_coinbase(
        &mut selected,
        2,
        8,
        Digest::hash_bytes(&[b"other coinbase"]),
        42,
    );
    selected.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    selected.put_storage(&storage_prefix("ZkTree", "Depth"), &[1u8]);
    selected.put_storage(&storage_prefix("Shielded", "EntryCount"), &encode_u64(1));

    let mut changed = NodeState {
        head_number: selected.head_number,
        storage: selected.storage.clone(),
        ..Default::default()
    };
    changed.put_storage(&key, &value);
    assert_ne!(
        selected.hash_at(9),
        changed.hash_at(9),
        "storage changes the header state root"
    );
    selected.proof_node_override = Some(changed.complete_state_proof());
    let node = FakeNode::start(selected);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let store_path = qnero_wallet::keys::store_path_for(&seed);
    let saved_before = std::fs::read(&store_path).ok();

    let error = wallet
        .sync(&chain, &test_metadata())
        .expect_err("another state's proof is refused");
    assert!(
        format!("{error:#}").contains("state proof is invalid or incomplete"),
        "{error:#}"
    );
    assert_eq!(wallet.store.next_leaf, 0);
    assert!(wallet.store.notes.is_empty());
    assert!(wallet.store.checkpoints.is_empty());
    assert_eq!(std::fs::read(&store_path).ok(), saved_before);
    assert_eq!(node.state().calls("state_getStorage"), 0);

    node.state().proof_node_override = None;
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the selected state's proof syncs");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert_eq!(wallet.store.next_leaf, 3);
}

#[test]
fn a_changed_leaf_count_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_leaf_count_refuses_the_pass_under_the_selected_header",
        storage_prefix("ZkTree", "LeafCount"),
        encode_u64(4),
    );
}

#[test]
fn changed_ciphertext_bytes_refuse_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "changed_ciphertext_bytes_refuse_the_pass_under_the_selected_header",
        identity_map_key("Shielded", "Ciphertexts", 1),
        codec::Encode::encode(&vec![9u8; 48]),
    );
}

/// A pass that read leaves and took nothing out of them says so.
///
/// The one operator-visible signal for the bound above. It is the ordinary
/// case on most passes, because almost every leaf on the chain is somebody
/// else's, and it is also exactly what a substituted ciphertext looks like, so
/// the pass carries the sentence that names the recovery rather than leaving
/// an operator waiting for a payment with nothing to read.
#[test]
fn a_pass_that_receives_nothing_carries_the_ciphertext_hint() {
    let (_seed, mut wallet) = fresh("ct-hint");

    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(&mut state, 1, 8, Digest::hash_bytes(&[b"leaf one"]), &[]);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");
    assert_eq!(report.received, 0);
    assert!(report.leaves_scanned > 0);
    assert!(report.scanned_and_received_nothing);
    let hint = report.ciphertext_hint().expect("the hint is carried");
    assert!(
        hint.contains("authenticated to the selected headers"),
        "{hint}"
    );
    assert!(hint.contains("does not verify proof of work"), "{hint}");

    // A pass that scanned nothing at all does not raise it: there was no leaf
    // to read, so there is nothing a ciphertext could have been swapped at.
    let idle = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");
    assert_eq!(idle.leaves_scanned, 0);
    assert!(!idle.scanned_and_received_nothing);
    assert!(idle.ciphertext_hint().is_none());
}

/// The two answers above, on the read the spend path makes.
///
/// `Chain::leaf_hashes` is what `Chain::rebuild_tree` reads a whole leaf range
/// with, and it used to turn an absent answer into `empty_digest()` at every
/// index, below the reported count as well as above it. So a node that padded
/// under its own count on the spend path handed this wallet a tree rebuilt
/// over pads, and the browser wallet refused that same answer in `fetchLeaves`
/// and `fetchLeafHashes`: the two wallets disagreed about one lie. Below the
/// count the count is what gives an answer meaning, so both are refused by
/// name here too, and above it the padding stays the pallet's own rule.
#[test]
fn the_spend_paths_leaf_read_refuses_a_pad_and_a_withheld_leaf_below_the_count() {
    let leaves = [
        Digest::hash_bytes(&[b"leaf zero"]),
        Digest::hash_bytes(&[b"leaf one"]),
        Digest::hash_bytes(&[b"leaf two"]),
    ];
    let honest = || {
        let mut state = NodeState {
            head_number: 7,
            ..Default::default()
        };
        for (index, leaf) in leaves.iter().enumerate() {
            state.put_storage(
                &identity_map_key("ZkTree", "Leaves", index as u64),
                &leaf.to_bytes(),
            );
        }
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
        state.put_storage(&storage_prefix("ZkTree", "Depth"), &[1u8]);
        state
    };

    // The control: three real leaves, and the tree rebuilds.
    let node = FakeNode::start(honest());
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let tree = chain
        .rebuild_tree(&chain.head().expect("selected head").hash)
        .expect("the honest tree rebuilds");
    assert_eq!(tree.leaf_count(), 3);

    // Above the count an absent answer is the pallet's own padding, which is
    // what `tree::get_leaf_hash` substitutes for an unfilled slot.
    let window = chain
        .leaf_hashes(0..4, 3, &chain.head().expect("selected head").hash)
        .expect("a window past the end of the tree pads");
    assert_eq!(window.len(), 4);
    assert_eq!(window[3], qnero_circuit::merkle::empty_digest());

    // The pad, below the count.
    let mut padded = honest();
    padded.put_storage(
        &identity_map_key("ZkTree", "Leaves", 1),
        &qnero_circuit::merkle::empty_digest().to_bytes(),
    );
    let node = FakeNode::start(padded);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = chain
        .rebuild_tree(&chain.head().expect("selected head").hash)
        .expect_err("the tree's own pad is not a leaf below the count");
    let message = format!("{refused:#}");
    assert!(message.contains("ZkTree::Leaves(1)"), "{message}");
    assert!(message.contains("all-zero digest"), "{message}");

    // The withheld answer, below the count.
    let mut withheld = honest();
    withheld.withheld_leaves = [1u64].into_iter().collect();
    let node = FakeNode::start(withheld);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = chain
        .rebuild_tree(&chain.head().expect("selected head").hash)
        .expect_err("a leaf below the count is an answer withheld");
    let message = format!("{refused:#}");
    assert!(message.contains("no ZkTree::Leaves(1)"), "{message}");
}

/// The premise of the two tests below, at the layer it comes from.
///
/// `qnero_circuit::merkle::hash_node` sorts a node's four children before
/// hashing them, and `pallet-zk-tree`'s `tree::hash_node` does the same: it is
/// what lets a Merkle path carry siblings with no position beside them. The
/// consequence is that the parent of an aligned group of four leaves is a
/// function of the multiset alone, so two orderings of one group reach the
/// same root and a published `zkTreeRoot` commits to no order inside a group.
#[test]
fn a_swap_inside_one_group_of_four_moves_no_root() {
    let leaves: Vec<Digest> = (0..3u8)
        .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
        .collect();
    assert_eq!(
        root_over(&leaves),
        root_over(&[leaves[1], leaves[0], leaves[2]]),
        "sorted children make the fold permutation invariant inside a group"
    );
}

#[test]
fn a_changed_commitment_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_commitment_refuses_the_pass_under_the_selected_header",
        identity_map_key("ZkTree", "Leaves", 1),
        Digest::hash_bytes(&[b"different commitment"])
            .to_bytes()
            .to_vec(),
    );
}

/// The premise of the tests below, one level up: whole sibling **subtrees**
/// can be exchanged too.
///
/// `hash_node` sorts at every level, so the fold is invariant under the whole
/// automorphism group of the 4-ary tree: permute leaves inside an aligned
/// group of four, and permute sibling subtrees at any level above. Composed
/// inside one block's leaf range, which the per-block root does pin, that
/// moves a leaf across group boundaries and onto any position the range's
/// aligned subtrees allow.
#[test]
fn a_swap_between_two_groups_of_four_moves_no_root() {
    let leaves: Vec<Digest> = (0..8u8)
        .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
        .collect();

    // The two aligned groups exchanged, and inside the group that lands
    // second the leaf that was at index 1 is put last, at index 7: the
    // coinbase position.
    let permuted = [
        leaves[4], leaves[5], leaves[6], leaves[7], leaves[0], leaves[2], leaves[3], leaves[1],
    ];
    assert_eq!(
        root_over(&leaves),
        root_over(&permuted),
        "sorting at every level makes the fold permutation invariant across group boundaries too"
    );
    assert_ne!(
        leaves[1], permuted[1],
        "and the leaf really did move six positions"
    );
}

/// The other half of the bound: the fold carries no level tag, so a shorter
/// tree of internal node values reaches the same root as the leaves under it.
///
/// `hash_node` mixes in neither the level nor the child slot, and
/// `TreeFrontier::root` folds `m` leaves to `depth_for(m)` and pads the empty
/// slots with `empty_digest()`. So the fold of two level-1 node values at
/// depth 1 is the fold of the eight leaves under them at depth 2, and a
/// per-block root pins neither the leaf count nor the height inside a block.
#[test]
fn two_level_one_node_values_served_as_leaves_fold_to_the_same_root() {
    let leaves: Vec<Digest> = (0..8u8)
        .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
        .collect();
    let level_one = [
        hash_node(&[leaves[0], leaves[1], leaves[2], leaves[3]]),
        hash_node(&[leaves[4], leaves[5], leaves[6], leaves[7]]),
    ];
    assert_eq!(
        root_over(&leaves),
        root_over(&level_one),
        "with no level tag, two node values presented as two leaves fold to the same root"
    );
}

#[test]
fn a_changed_creation_block_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_creation_block_refuses_the_pass_under_the_selected_header",
        identity_map_key("Shielded", "LeafBlocks", 1),
        codec::Encode::encode(&7u32),
    );
}

/// How many leaves a pass writes one sentence about is a node's choice, so the
/// sentences are capped and the rest are counted.
///
/// Both detector warnings are per leaf, and a node answers the leaves: it can
/// put a commitment this wallet's payload does not open beside every
/// ciphertext it serves. Uncapped that is one `String` per leaf on
/// `SyncReport::warnings` and one printed line per leaf, out of an answer
/// nothing has checked. Past `WARNED_LEAVES_PER_PASS` the pass counts instead
/// and closes each kind with one sentence carrying the count, so the list is
/// bounded at eighteen entries whatever a node answers.
///
/// `wallet-web/tests/leaf-typing.test.ts` drives the same two overflows
/// against the browser wallet.
#[test]
fn the_per_leaf_warnings_are_capped_and_the_rest_are_counted() {
    let (_seed, mut wallet) = fresh("warning-cap");
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "capped-payment");
    let mine_ct = ct_for(&address, &mine, 7);
    // A second note of this wallet's, whose commitment the block never holds.
    let elsewhere = note_for(address.pk, 5, "capped-elsewhere");
    let elsewhere_ct = ct_for(&address, &elsewhere, 8);

    let overflow: u64 = 2;
    let each = WARNED_LEAVES_PER_PASS + overflow;
    let coinbase_index = each * 2;

    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    // The first `each` leaves carry this wallet's payment ciphertext beside a
    // stranger's commitment, and the block holds the payment's own commitment
    // at its coinbase position, so each of them is a move the pass recovers.
    for leaf in 0..each {
        let stranger = Digest::hash_bytes(&[b"moved", &leaf.to_le_bytes()]);
        put_leaf(&mut state, leaf, 8, stranger, &mine_ct);
    }
    // The next `each` carry a ciphertext of this wallet's whose commitment the
    // block holds nowhere, so each of those is skipped.
    for leaf in 0..each {
        let stranger = Digest::hash_bytes(&[b"unplaceable", &leaf.to_le_bytes()]);
        put_leaf(&mut state, each + leaf, 8, stranger, &elsewhere_ct);
    }
    put_coinbase(&mut state, coinbase_index, 8, mine.commitment(), 42);
    state.put_storage(
        &storage_prefix("ZkTree", "LeafCount"),
        &encode_u64(coinbase_index + 1),
    );

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("a capped pass still finishes");

    // The payment still arrives, at the index inside the block that holds the
    // commitment it opens. A cap on the sentences changes no decision.
    assert_eq!(report.received, 1, "the payment arrives");
    assert_eq!(
        wallet
            .store
            .notes
            .first()
            .expect("the note is stored")
            .leaf_index,
        coinbase_index
    );

    let moved: Vec<&String> = report
        .warnings
        .iter()
        .filter(|warning| warning.contains("tree entry answered beside it"))
        .collect();
    let skipped: Vec<&String> = report
        .warnings
        .iter()
        .filter(|warning| warning.contains("at none of the leaves it appended"))
        .collect();
    assert_eq!(moved.len() as u64, WARNED_LEAVES_PER_PASS, "{moved:?}");
    assert_eq!(skipped.len() as u64, WARNED_LEAVES_PER_PASS, "{skipped:?}");
    // The ones written out are the first of each kind, named by their leaf.
    assert!(moved[0].contains("leaf 0"), "{}", moved[0]);
    assert!(
        skipped[0].contains(&format!("leaf {each}")),
        "{}",
        skipped[0]
    );

    // And each kind closes with one sentence carrying what the cap held back.
    let moved_more: Vec<&String> = report
        .warnings
        .iter()
        .filter(|warning| {
            warning.starts_with(&format!("and {overflow} more leaves"))
                && warning.contains("each recorded")
        })
        .collect();
    let skipped_more: Vec<&String> = report
        .warnings
        .iter()
        .filter(|warning| {
            warning.starts_with(&format!("and {overflow} more leaves"))
                && warning.contains("each skipped")
        })
        .collect();
    assert_eq!(moved_more.len(), 1, "{:?}", report.warnings);
    assert_eq!(skipped_more.len(), 1, "{:?}", report.warnings);
    assert!(moved_more[0].contains("second node"), "{}", moved_more[0]);
    assert!(
        skipped_more[0].contains("second node"),
        "{}",
        skipped_more[0]
    );

    // Eighteen, whatever a node answers: two kinds of eight plus one closing
    // sentence each, and nothing else fired on this pass.
    assert_eq!(
        report.warnings.len() as u64,
        WARNED_LEAVES_PER_PASS * 2 + 2,
        "{:?}",
        report.warnings
    );
}

/// At the cap exactly, there is nothing left over to count.
#[test]
fn a_pass_at_the_warning_cap_writes_no_overflow_sentence() {
    let (_seed, mut wallet) = fresh("warning-cap-exact");
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "at-the-cap");
    let mine_ct = ct_for(&address, &mine, 7);

    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    for leaf in 0..WARNED_LEAVES_PER_PASS {
        let stranger = Digest::hash_bytes(&[b"moved", &leaf.to_le_bytes()]);
        put_leaf(&mut state, leaf, 8, stranger, &mine_ct);
    }
    put_coinbase(&mut state, WARNED_LEAVES_PER_PASS, 8, mine.commitment(), 42);
    state.put_storage(
        &storage_prefix("ZkTree", "LeafCount"),
        &encode_u64(WARNED_LEAVES_PER_PASS + 1),
    );

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("a pass at the cap finishes");
    assert_eq!(
        report.warnings.len() as u64,
        WARNED_LEAVES_PER_PASS,
        "{:?}",
        report.warnings
    );
    assert!(
        !report.warnings.iter().any(|w| w.starts_with("and ")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn a_changed_coinbase_value_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_coinbase_value_refuses_the_pass_under_the_selected_header",
        identity_map_key("Shielded", "CoinbaseValues", 2),
        encode_u64(43),
    );
}

#[test]
fn a_changed_entry_counter_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_entry_counter_refuses_the_pass_under_the_selected_header",
        storage_prefix("Shielded", "EntryCount"),
        encode_u64(2),
    );
}

#[test]
fn a_changed_tree_depth_refuses_the_pass_under_the_selected_header() {
    assert_changed_state_refused(
        "a_changed_tree_depth_refuses_the_pass_under_the_selected_header",
        storage_prefix("ZkTree", "Depth"),
        vec![2u8],
    );
}

/// A ciphertext of this wallet's beside a commitment the block holds nowhere:
/// warned, skipped, and the pass finishes.
///
/// The detector's other arm, and it is a warning deliberately. Two things
/// produce this reading and nothing local tells them apart: a node that moved
/// a ciphertext across blocks, and a sender who encrypted a payload opening a
/// commitment the sender never published. The circuit leaves `ct_digest`
/// unconstrained (`docs/CIRCUIT.md` section 1), so no rule on chain ties a
/// ciphertext's plaintext to the commitment beside it, and anyone holding this
/// wallet's address can write such a leaf for the price of one transaction.
/// Refusing the pass would hand that sender a permanent sync denial, because
/// the leaf is read again on every later pass and on a rescan as well.
#[test]
fn a_ciphertext_of_ours_beside_a_commitment_the_block_lacks_warns_and_keeps_scanning() {
    let (_seed, mut wallet) = fresh("mismatch-nowhere");
    let address = wallet.address();
    // The note this payload opens, whose commitment is at no leaf at all.
    let orphan = note_for(address.pk, 1_000, "opens nothing on chain");
    let orphan_ct = ct_for(&address, &orphan, 7);
    let mine = note_for(address.pk, 25, "a real payment");
    let mine_ct = ct_for(&address, &mine, 8);
    let stranger = Digest::hash_bytes(&[b"somebody else's leaf"]);
    let coinbase = Digest::hash_bytes(&[b"block 8 coinbase"]);

    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut state, 0, 8, stranger, &orphan_ct);
    put_leaf(&mut state, 1, 8, mine.commitment(), &mine_ct);
    put_coinbase(&mut state, 2, 8, coinbase, 42);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));

    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("one unbindable leaf does not stop a sync");
    assert_eq!(report.leaves_scanned, 3);
    assert_eq!(
        report.received, 1,
        "the leaf below it is read and the payment on it arrives"
    );
    assert_eq!(wallet.store.unspent_total(), 25);
    let warning = report
        .warnings
        .iter()
        .find(|warning| warning.contains("at none of the leaves it appended"))
        .expect("the unbindable leaf is warned about");
    assert!(warning.contains("leaf 0"), "{warning}");
    assert!(warning.contains("second node"), "{warning}");

    // And it is the same answer on every later pass, which is the point of
    // keeping it a warning: a sender cannot brick this wallet's sync.
    let again = wallet
        .sync_with(&chain, &test_metadata(), SyncOptions { rescan: true })
        .expect("a rescan reads the same leaf and does not refuse either");
    assert_eq!(again.received, 0, "the payment is already held");
    assert_eq!(wallet.store.unspent_total(), 25);
}
