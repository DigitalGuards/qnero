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

use qnero_notes::{encrypt_note, Digest, MinerKey, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::wallet::{SyncOptions, Wallet};
use std::collections::BTreeSet;

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

/// The tree's own pad, answered as a leaf below the count the node reports.
///
/// `TreeFrontier` fills the slots above the last leaf with `empty_digest()`,
/// so appending explicit all-zero leaves reaches the root a fold that stopped
/// short reaches, inside one depth. Both nodes here serve byte-identical
/// headers for blocks 0 to 9, which is bound A: the only difference is
/// `ZkTree::LeafCount` and one pad leaf. Without the pad rule every check in
/// `qnero_wallet::typing` passes, the pass commits `next_leaf` above indices
/// the chain has not filled, and the real leaves that later land there are
/// below the watermark and never read.
///
/// What makes the pad refusable is that no chain holds one:
/// `pallet-zk-tree::insert_commitment` refuses an append of the all-zero
/// digest by name (`ZeroCommitment`) and reads it as an unfilled slot
/// everywhere else. Take the rule out of `Chain::leaf_window` and
/// `typing::type_chunk` and this test goes green on a watermark four leaves up
/// a three-leaf chain.
#[test]
fn a_pad_leaf_below_the_reported_count_refuses_the_pass() {
    let (_seed, mut wallet) = fresh("typing-empty-pad");
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "pad-paid");

    // The lying node: three real leaves in block 8, plus one `empty_digest()`
    // leaf it also dates to block 8. The root of four leaves whose fourth is
    // the pad is the root of three, so block 8's header is the honest one.
    let mut liar = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut liar, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut liar,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(&mut liar, 2, 8, Digest::hash_bytes(&[b"leaf two"]), &[]);
    // The pad. Nothing on chain appended it, and no key beside it is written:
    // it sits where block 8's coinbase would, so the fixture answers a
    // coinbase value there the way a node serving this branch would.
    liar.put_storage(
        &identity_map_key("ZkTree", "Leaves", 3),
        &qnero_circuit::merkle::empty_digest().to_bytes(),
    );
    liar.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", 3),
        &codec::Encode::encode(&8u32),
    );
    liar.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));

    // The honest node, at the same height, with the same three leaves.
    let mut honest = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut honest, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
    put_leaf(
        &mut honest,
        1,
        8,
        mine.commitment(),
        &ct_for(&address, &mine, 7),
    );
    put_leaf(&mut honest, 2, 8, Digest::hash_bytes(&[b"leaf two"]), &[]);
    honest.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));

    // Same genesis, and the same hash at block 9: the pad moved no header.
    assert_eq!(liar.genesis_hash(), honest.genesis_hash());
    assert_eq!(
        liar.hash_at(9),
        honest.hash_at(9),
        "the pad leaf changes no header, so this is bound A: honest headers"
    );

    let node = FakeNode::start(liar);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a leaf equal to the tree's pad is refused below the count");
    let message = format!("{refused:#}");
    assert!(message.contains("ZkTree::Leaves(3)"), "{message}");
    assert!(message.contains("all-zero digest"), "{message}");
    assert_eq!(wallet.store.next_leaf, 0, "nothing has been changed");
    assert!(wallet.store.notes.is_empty());

    // The honest control still folds: the same three leaves, the count the
    // chain holds, and the payment arrives.
    let honest_node = FakeNode::start(honest);
    let rpc = RpcClient::new(&honest_node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest count folds");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert_eq!(wallet.store.next_leaf, 3);
}

/// A substituted ciphertext hides an incoming payment, and a rescan against a
/// second node is what brings it back.
///
/// This is a bound rather than a refusal, and it is open. `ct_digest` binds a
/// settlement's ciphertext bytes inside the extrinsic that settles them, at
/// inclusion, and `Shielded::Ciphertexts(i)` is a storage value nothing on
/// chain ties to leaf `i`: the commitment the tree authenticates carries no
/// ciphertext. So a node with honest headers can answer a stranger's bytes at
/// this wallet's payment, the AEAD does not open, and the leaf reads as
/// somebody else's, which is the ordinary answer for almost every leaf on the
/// chain. Every root, every position and every header still checks out.
///
/// The checkpoint fork walk does not reach it either: the headers agree, so a
/// later honest node confirms every checkpoint and the ordinary pass scans
/// nothing. `--rescan` is the recovery, and this test drives it end to end.
/// `docs/WALLET.md` states the bound under "What a lying node can and cannot
/// do" and `docs/DESIGN.md` records the closure as the next wallet milestone.
#[test]
fn a_substituted_ciphertext_hides_a_payment_until_a_rescan_reads_the_leaf_again() {
    let (_seed, mut wallet) = fresh("ct-substituted");
    let address = wallet.address();
    let miner_key = wallet.miner_key();

    let leaves = |state: &mut NodeState, ciphertext: &[u8], genesis: &[u8; 32]| {
        let mine = note_for(address.pk, 1_000, "ct-bound");
        let mined = miner_key.coinbase_note(genesis, 8, 42).expect("a note");
        put_leaf(state, 0, 8, Digest::hash_bytes(&[b"leaf zero"]), &[]);
        put_leaf(state, 1, 8, mine.commitment(), ciphertext);
        put_coinbase(state, 2, 8, mined.commitment(), 42);
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    };

    // A well-formed ciphertext of the right length, addressed to somebody
    // else. `try_transfer` parses it and the AEAD simply does not open.
    let (_stranger_seed, stranger) = fresh("ct-stranger");
    let stranger = stranger.address();
    let decoy = note_for(stranger.pk, 1_000, "decoy");
    let substituted = ct_for(&stranger, &decoy, 9);
    let honest_ct = {
        let mine = note_for(address.pk, 1_000, "ct-bound");
        ct_for(&address, &mine, 7)
    };

    let mut liar = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [8].into_iter().collect(),
        ..Default::default()
    };
    let genesis = liar.genesis_hash();
    leaves(&mut liar, &substituted, &genesis);

    let mut honest = NodeState {
        head_number: 9,
        miner_key: Some(miner_key.clone()),
        authored: [8].into_iter().collect(),
        ..Default::default()
    };
    leaves(&mut honest, &honest_ct, &genesis);
    assert_eq!(
        liar.hash_at(9),
        honest.hash_at(9),
        "the ciphertext is in no header, so this is bound A: honest headers"
    );

    let node = FakeNode::start(liar);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the substitution is not refused, which is the bound");
    assert_eq!(report.received, 1, "only the mined coinbase arrived");
    assert_eq!(wallet.store.unspent_total(), 42);
    assert_eq!(report.rejected, 0);
    assert_eq!(wallet.store.next_leaf, 3, "the watermark is above the leaf");

    // An ordinary pass against the honest node recovers nothing. Its headers
    // are the ones this wallet already checkpointed, so no fork is found, and
    // the scan starts above the leaf that was skipped.
    let honest_node = FakeNode::start(honest);
    let rpc = RpcClient::new(&honest_node.url);
    let chain = Chain::new(&rpc);
    let ordinary = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest node agrees with every checkpoint");
    assert_eq!(ordinary.received, 0);
    assert_eq!(wallet.store.unspent_total(), 42);

    // The recovery, end to end: a rescan reads the range again from leaf zero
    // against the honest node, and the payment arrives.
    let recovered = wallet
        .sync_with(&chain, &test_metadata(), SyncOptions { rescan: true })
        .expect("a rescan reads the range again");
    assert_eq!(recovered.received, 1, "the payment is back");
    assert_eq!(wallet.store.unspent_total(), 1_042);
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
    assert!(hint.contains("Shielded::Ciphertexts"), "{hint}");
    assert!(hint.contains("--rescan"), "{hint}");

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
    let at = support::block_hash(7);

    // The control: three real leaves, and the tree rebuilds.
    let node = FakeNode::start(honest());
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let tree = chain.rebuild_tree(&at).expect("the honest tree rebuilds");
    assert_eq!(tree.leaf_count(), 3);

    // Above the count an absent answer is the pallet's own padding, which is
    // what `tree::get_leaf_hash` substitutes for an unfilled slot.
    let window = chain
        .leaf_hashes(0..4, 3, &at)
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
        .rebuild_tree(&at)
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
        .rebuild_tree(&at)
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
    use qnero_circuit::merkle::TreeFrontier;

    let leaves: Vec<Digest> = (0..3u8)
        .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
        .collect();
    let mut straight = TreeFrontier::new();
    for leaf in &leaves {
        straight.push(*leaf);
    }
    let mut swapped = TreeFrontier::new();
    for leaf in [leaves[1], leaves[0], leaves[2]] {
        swapped.push(leaf);
    }
    assert_eq!(
        straight.root().expect("a root"),
        swapped.root().expect("a root"),
        "sorted children make the fold permutation invariant inside a group"
    );
}

/// A leaf moved inside its own group of four hides an incoming payment, and a
/// rescan against a second node is what brings it back.
///
/// This is a bound rather than a refusal, and it is open. It is the second
/// half of the one above it: the root a block's header carries commits to
/// which leaves that block appended and never to which index each one landed
/// at, because the node rule sorts. So a node with honest headers can exchange
/// this wallet's payment with the block's coinbase, keep every ciphertext the
/// chain published where it published it, and answer nothing at the coinbase
/// position. Every root, every position rule and every header still check out.
/// The payment is typed a coinbase, the rebuild does not open it, there is no
/// ciphertext to try, and the watermark commits above it.
///
/// The checkpoint fork walk does not reach it: the headers agree, so a later
/// honest node confirms every checkpoint and the ordinary pass scans nothing.
/// `--rescan` is the recovery, and this test drives it end to end.
/// `docs/WALLET.md` states the bound under "What bound A does not cover" and
/// `docs/DESIGN.md` section 9 carries both closures.
#[test]
fn a_within_group_swap_onto_the_coinbase_position_hides_a_payment_until_a_rescan() {
    let (_seed, mut wallet) = fresh("permuted-coinbase");
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "permuted-hidden");
    let mine_ct = ct_for(&address, &mine, 7);
    let stranger = Digest::hash_bytes(&[b"somebody else's leaf"]);
    let stranger_ct = vec![9u8; 32];
    let coinbase = Digest::hash_bytes(&[b"block 8 coinbase"]);

    // The chain: leaf 1 is the payment, leaf 2 is the block's coinbase.
    let mut honest = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut honest, 0, 8, stranger, &stranger_ct);
    put_leaf(&mut honest, 1, 8, mine.commitment(), &mine_ct);
    put_coinbase(&mut honest, 2, 8, coinbase, 42);
    honest.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));

    // The liar: the payment's commitment and the coinbase's are exchanged.
    // Every ciphertext is untouched, so `Shielded::Ciphertexts(1)` is still
    // exactly the bytes the chain published, and the coinbase position carries
    // no ciphertext because under v1 a coinbase never does.
    let mut liar = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut liar, 0, 8, stranger, &stranger_ct);
    put_leaf(&mut liar, 1, 8, coinbase, &mine_ct);
    put_coinbase(&mut liar, 2, 8, mine.commitment(), 42);
    liar.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));

    assert_eq!(liar.genesis_hash(), honest.genesis_hash());
    assert_eq!(
        liar.hash_at(9),
        honest.hash_at(9),
        "the swap moves no header, so this is bound A: honest headers"
    );

    let node = FakeNode::start(liar);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the permuted order is not refused, which is the bound");
    assert_eq!(report.received, 0, "the payment is gone");
    assert_eq!(report.rejected, 0, "and nothing is counted");
    assert_eq!(wallet.store.unspent_total(), 0);
    assert_eq!(wallet.store.next_leaf, 3, "the watermark is above it");

    // What the operator is given instead: the hint, which names the index
    // beside the ciphertext because one rescan is the recovery for either.
    assert!(report.scanned_and_received_nothing);
    let hint = report.ciphertext_hint().expect("the hint is carried");
    assert!(hint.contains("aligned group"), "{hint}");
    assert!(hint.contains("Shielded::Ciphertexts"), "{hint}");
    assert!(hint.contains("--rescan"), "{hint}");

    // An ordinary pass against the honest node recovers nothing: its headers
    // are the ones this wallet already checkpointed, so no fork is found and
    // the scan starts above the leaf that was skipped.
    let honest_node = FakeNode::start(honest);
    let rpc = RpcClient::new(&honest_node.url);
    let chain = Chain::new(&rpc);
    let ordinary = wallet
        .sync(&chain, &test_metadata())
        .expect("the honest node agrees with every checkpoint");
    assert_eq!(ordinary.received, 0);
    assert_eq!(wallet.store.unspent_total(), 0, "still hidden");

    // The recovery, end to end.
    let recovered = wallet
        .sync_with(&chain, &test_metadata(), SyncOptions { rescan: true })
        .expect("a rescan reads the range again");
    assert_eq!(recovered.received, 1, "the payment is back");
    assert_eq!(wallet.store.unspent_total(), 1_000);
}

/// The same swap between two ordinary leaves: the payment arrives, at an index
/// the chain does not hold it at, and the spend path is where that shows.
///
/// A note's leaf index is what a Merkle path is rebuilt for, so a note stored
/// at the wrong index reaches a root no header carries and cannot be spent.
/// Nothing refuses at scan time, because the root the pass folds is the root
/// the header published either way. A rescan is what moves the note to the
/// index the chain actually holds it at.
#[test]
fn a_within_group_swap_records_a_note_at_a_leaf_the_chain_does_not_hold() {
    let (_seed, mut wallet) = fresh("permuted-index");
    let address = wallet.address();
    let mine = note_for(address.pk, 1_000, "permuted");
    let mine_ct = ct_for(&address, &mine, 7);
    let stranger = Digest::hash_bytes(&[b"somebody else's leaf"]);
    let stranger_ct = vec![9u8; 32];
    let coinbase = Digest::hash_bytes(&[b"block 8 coinbase"]);

    let mut honest = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut honest, 0, 8, stranger, &stranger_ct);
    put_leaf(&mut honest, 1, 8, mine.commitment(), &mine_ct);
    put_coinbase(&mut honest, 2, 8, coinbase, 42);
    honest.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    // The depth the chain folded three leaves at, which a rebuild reads.
    honest.put_storage(&storage_prefix("ZkTree", "Depth"), &[1u8]);

    // Leaf 0 and leaf 1 exchanged, each keeping the ciphertext the chain
    // published beside it.
    let mut liar = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_leaf(&mut liar, 0, 8, mine.commitment(), &mine_ct);
    put_leaf(&mut liar, 1, 8, stranger, &stranger_ct);
    put_coinbase(&mut liar, 2, 8, coinbase, 42);
    liar.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
    liar.put_storage(&storage_prefix("ZkTree", "Depth"), &[1u8]);

    assert_eq!(
        liar.hash_at(9),
        honest.hash_at(9),
        "the swap moves no header, so this is bound A: honest headers"
    );

    let node = FakeNode::start(liar);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the permuted order is not refused");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert_eq!(
        wallet
            .store
            .notes
            .first()
            .expect("the note is stored")
            .leaf_index,
        0,
        "the index the lying node dictated"
    );

    // The honest node confirms every checkpoint, so nothing rewinds and the
    // wrong index stands.
    let honest_node = FakeNode::start(honest);
    let rpc = RpcClient::new(&honest_node.url);
    let chain = Chain::new(&rpc);
    let again = wallet
        .sync(&chain, &test_metadata())
        .expect("an honest pass");
    assert_eq!(again.received, 0);
    assert_eq!(
        wallet
            .store
            .notes
            .first()
            .expect("still one note")
            .leaf_index,
        0,
        "no ordinary pass revisits it"
    );

    // Where it shows: the spend path rebuilds the tree at the anchor, checks
    // its root against the header, and then reads the leaf at the note's own
    // index.
    let at = honest_node.state().hash_at(9);
    let tree = chain.rebuild_tree(&at).expect("the honest tree rebuilds");
    assert_eq!(
        tree.leaf(1).expect("a leaf"),
        mine.commitment(),
        "the chain holds the payment at leaf 1"
    );
    assert_ne!(
        tree.leaf(0).expect("a leaf"),
        mine.commitment(),
        "and not where this wallet recorded it"
    );
    let path = tree.path(0).expect("a path");
    assert_ne!(
        path.root(mine.commitment()).expect("a root"),
        tree.root(),
        "a path rebuilt at the recorded index reaches no root this chain published"
    );

    // The recovery: a rescan reads the range again and moves the note to the
    // leaf the chain holds it at.
    let recovered = wallet
        .sync_with(&chain, &test_metadata(), SyncOptions { rescan: true })
        .expect("a rescan reads the range again");
    assert_eq!(
        recovered.relocated, 1,
        "one note moved, and the store still holds one"
    );
    assert_eq!(
        wallet
            .store
            .notes
            .first()
            .expect("still one note")
            .leaf_index,
        1,
        "the index the chain actually holds it at"
    );
    assert_eq!(wallet.store.unspent_total(), 1_000);
}
