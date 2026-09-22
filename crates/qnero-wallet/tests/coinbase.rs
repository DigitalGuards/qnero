//! What a wallet does with the block rewards it mined.
//!
//! A coinbase note is the one note a wallet is not told about. Its value is
//! public, its randomness is derived from the miner key the operator gave the
//! node, and it carries no ciphertext at all: the coinbase inherent refuses a
//! non-empty payload by name, so no block body holds one. The scan therefore
//! reconstructs the note from its own key plus what the chain published and
//! proves the reconstruction against the leaf. These cover that rule and the
//! refusals that keep an author from writing a note into somebody else's
//! balance.

mod support;

use qnero_notes::{Digest, MinerKey};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::store::NoteOrigin;
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, test_metadata, FakeNode, NodeState};

/// Write one coinbase leaf the way `pallet-shielded` writes it: the
/// commitment, the block and the public value.
///
/// No payload. The coinbase inherent refuses a non-empty ciphertext by name,
/// so no block body carries one and the derived rebuild is the whole rule.
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

fn node_with(state: NodeState) -> FakeNode {
    FakeNode::start(state)
}

/// A node that names this wallet as the author of `blocks`.
///
/// A block's author label is `H("qnero/author-label", cvk, parent_hash)` in
/// its pre-runtime digest item, and the header hash commits to it, so a wallet
/// knows which blocks it mined without asking. What the wallet does with that
/// is ask for the coinbase value of its own blocks by name, so a fixture that
/// wants a block to be the wallet's own says so here.
fn node_authoring(miner_key: &MinerKey, head: u32, blocks: &[u32]) -> NodeState {
    NodeState {
        head_number: head,
        miner_key: Some(miner_key.clone()),
        authored: blocks.iter().copied().collect(),
        ..Default::default()
    }
}

/// The genesis of the chain a fake node serves. A derived coinbase note is
/// bound to it, so every note a test builds has to name the same chain the
/// wallet will sync against. Block zero carries no leaves, so this is fixed
/// before a fixture writes any.
fn genesis_of(state: &NodeState) -> [u8; 32] {
    state.genesis_hash()
}

/// The path every Qnero node takes: the node publishes `inner` alone, the
/// chain publishes the value, and the wallet rebuilds the note from its own
/// miner key.
#[test]
fn a_mined_block_becomes_a_spendable_note() {
    let dir = support::scratch_dir("coinbase-derived");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let miner_key = wallet.miner_key();

    // Two blocks this wallet authored, at two heights, worth different amounts.
    let mut state = node_authoring(&miner_key, 9, &[7, 8]);
    let genesis = genesis_of(&state);
    let first = miner_key.coinbase_note(&genesis, 7, 42).expect("a note");
    let second = miner_key.coinbase_note(&genesis, 8, 41).expect("a note");

    put_coinbase(&mut state, 0, 7, first.commitment(), 42);
    put_coinbase(&mut state, 1, 8, second.commitment(), 41);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.coinbase_leaves, 2);
    assert_eq!(report.coinbase_received, 2);
    assert_eq!(report.received, 2);
    assert_eq!(wallet.store.unspent_total(), 83);
    for note in &wallet.store.notes {
        assert_eq!(note.origin, NoteOrigin::Coinbase);
        assert!(!note.spent);
    }
    // Spendable like any other note: the nullifier is the ordinary rule over
    // the derived `rho` and `r`.
    assert_eq!(wallet.store.spendable().len(), 2);
}

/// A coinbase position with no value answered refuses the pass by name. The
/// fixture commits this state into its header; missing proof nodes against an
/// unchanged header are covered by state_proofs.
#[test]
fn a_coinbase_value_withheld_below_the_leaf_count_refuses_the_pass() {
    let dir = support::scratch_dir("coinbase-withheld-value");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let miner_key = wallet.miner_key();
    let mut state = node_authoring(&miner_key, 4, &[3]);
    state.withheld_coinbase_values = [0].into_iter().collect();
    let mined = miner_key
        .coinbase_note(&genesis_of(&state), 3, 25)
        .expect("a note");
    put_coinbase(&mut state, 0, 3, mined.commitment(), 25);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let refused = wallet
        .sync(&chain, &test_metadata())
        .expect_err("a coinbase position with no value is refused");
    let message = format!("{refused:#}");
    assert!(
        message.contains("no Shielded::CoinbaseValues for leaf 0") && message.contains("block 3"),
        "the one leaf of block 3 is its coinbase position and its value is withheld: {message}"
    );
    assert_eq!(wallet.store.next_leaf, 0);
    assert!(wallet.store.notes.is_empty());

    // The same node answering for the value pays the miner.
    node.state().withheld_coinbase_values.clear();
    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the pass runs once the value is answered for");
    assert_eq!(report.coinbase_received, 1);
    assert_eq!(wallet.store.unspent_total(), 25);
}

/// The commitment check is the whole of the trust model. A leaf whose value
/// does not open the commitment is not this wallet's note, however the payload
/// was built, and a block author cannot write a number into someone's balance
/// by publishing one.
#[test]
fn a_value_that_does_not_open_the_commitment_is_not_received() {
    let dir = support::scratch_dir("coinbase-mismatch");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let miner_key = wallet.miner_key();

    // The commitment of a 0.42 QNR note, published beside a claim of 10 QNR,
    // in a block whose author label is not this wallet's. A block this wallet
    // *did* author refuses the pass instead: see
    // `a_wrong_value_on_this_wallets_own_block_refuses_the_pass`.
    let mut state = NodeState {
        head_number: 8,
        ..Default::default()
    };
    let note = miner_key
        .coinbase_note(&genesis_of(&state), 7, 42)
        .expect("a note");
    put_coinbase(&mut state, 0, 7, note.commitment(), 1_000);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.coinbase_leaves, 1, "the leaf was read");
    assert_eq!(report.coinbase_received, 0, "and refused");
    assert_eq!(wallet.store.unspent_total(), 0);
}

/// Somebody else's block. Every block on the chain mints one of these, so the
/// scan walks far more coinbase leaves than it keeps, and the only thing
/// separating them is a key this wallet does not have.
#[test]
fn another_miners_coinbase_is_not_this_wallets_note() {
    let dir = support::scratch_dir("coinbase-theirs");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let mine = wallet.miner_key();

    let theirs = MinerKey::new(
        Digest::hash_bytes(&[b"their pk"]),
        Digest::hash_bytes(&[b"their cvk"]),
    );
    // Same address, different coinbase viewing key: holding the address is not
    // holding the coinbase view.
    let same_address = MinerKey::new(mine.pk, Digest::hash_bytes(&[b"not my cvk"]));

    let mut state = NodeState {
        head_number: 6,
        ..Default::default()
    };
    let genesis = genesis_of(&state);
    put_coinbase(
        &mut state,
        0,
        4,
        theirs
            .coinbase_note(&genesis, 4, 10)
            .expect("a note")
            .commitment(),
        10,
    );
    put_coinbase(
        &mut state,
        1,
        5,
        same_address
            .coinbase_note(&genesis, 5, 10)
            .expect("a note")
            .commitment(),
        10,
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.coinbase_leaves, 2);
    assert_eq!(report.coinbase_received, 0);
    assert_eq!(wallet.store.unspent_total(), 0);
}

/// The same miner key, mining another chain. A coinbase note is derived with
/// no randomness in it, so the genesis is what keeps one operator's notes on
/// two chains apart; without it, the notes would be byte identical at equal
/// heights and equality alone would carry an identification from one chain to
/// the other.
#[test]
fn a_coinbase_from_another_chain_is_not_this_wallets_note() {
    let dir = support::scratch_dir("coinbase-other-chain");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let miner_key = wallet.miner_key();

    // This wallet's own miner key at height 7, mined on a chain whose genesis
    // is not the one this node serves. On this chain block 7 belongs to
    // somebody else, which is what its author label says.
    let mut state = node_authoring(&miner_key, 9, &[8]);
    let elsewhere = miner_key.coinbase_note(&[0xAB; 32], 7, 42).expect("a note");
    // And the same key at the same height here, which must still be found.
    let here = miner_key
        .coinbase_note(&genesis_of(&state), 8, 5)
        .expect("a note");

    put_coinbase(&mut state, 0, 7, elsewhere.commitment(), 42);
    put_coinbase(&mut state, 1, 8, here.commitment(), 5);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.coinbase_leaves, 2);
    assert_eq!(
        report.coinbase_received, 1,
        "only the note minted on this chain is this wallet's"
    );
    assert_eq!(wallet.store.unspent_total(), 5);
}

/// The miner key is what an operator pastes into a node, and the two sides of
/// that paste have to agree on every byte.
#[test]
fn the_miner_key_round_trips_to_the_note_a_node_would_build() {
    let dir = support::scratch_dir("coinbase-minerkey");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let wallet = Wallet::open(&seed).expect("the wallet opens");

    let encoded = wallet.miner_key().encode();
    let decoded = MinerKey::decode(&encoded).expect("a miner key");
    assert_eq!(
        decoded.pk,
        wallet.address().pk,
        "the key names this wallet's address"
    );
    let chain = [0x5Au8; 32];
    assert_eq!(
        decoded
            .coinbase_note(&chain, 11, 5)
            .expect("a note")
            .commitment(),
        wallet
            .miner_key()
            .coinbase_note(&chain, 11, 5)
            .expect("a note")
            .commitment()
    );
}
