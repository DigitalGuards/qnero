//! What a wallet does with the block rewards it mined.
//!
//! A coinbase note is the one note a wallet is not told about. Its value is
//! public, its randomness is derived from the miner key the operator gave the
//! node, and there is usually no ciphertext at all, so the scan has to
//! reconstruct the note from its own key plus what the chain published and
//! prove the reconstruction against the leaf. These cover both ways in, the
//! derived one every Qnero node uses and the encrypted one the pallet still
//! accepts, and the refusals that keep an author from writing a note into
//! somebody else's balance.

mod support;

use qnero_notes::{encrypt_note, Digest, MinerKey, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::store::NoteOrigin;
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, test_metadata, FakeNode, NodeState};

/// Write one coinbase leaf the way `pallet-shielded` writes it: the
/// commitment, the block, the public value, and a ciphertext only when the
/// author encrypted one.
fn put_coinbase(
    state: &mut NodeState,
    index: u64,
    block: u32,
    cm: Digest,
    value: u64,
    ct: Option<&[u8]>,
) {
    state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", index),
        &codec::Encode::encode(&block),
    );
    state.put_storage(
        &identity_map_key("Shielded", "CoinbaseValues", index),
        &codec::Encode::encode(&value),
    );
    if let Some(ct) = ct {
        state.put_storage(
            &identity_map_key("Shielded", "Ciphertexts", index),
            &codec::Encode::encode(&ct.to_vec()),
        );
    }
}

fn node_with(state: NodeState) -> FakeNode {
    FakeNode::start(state)
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
    let first = miner_key.coinbase_note(7, 42).expect("a note");
    let second = miner_key.coinbase_note(8, 41).expect("a note");

    let mut state = NodeState {
        head_number: 9,
        ..Default::default()
    };
    put_coinbase(&mut state, 0, 7, first.commitment(), 42, None);
    put_coinbase(&mut state, 1, 8, second.commitment(), 41, None);
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

/// The other way in: an author that does not hold the recipient's coinbase
/// viewing key encrypts the payload instead. The value inside it is ignored
/// and the note is rebuilt against the chain's.
#[test]
fn an_encrypted_coinbase_payload_is_rebuilt_against_the_public_value() {
    let dir = support::scratch_dir("coinbase-encrypted");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    // A payload built by something that is not this wallet's own node: fresh
    // randomness, and a value of zero inside the ciphertext.
    let rho = Digest::hash_bytes(&[b"coinbase/rho", &[9u8]]);
    let r = Digest::hash_bytes(&[b"coinbase/r", &[9u8]]);
    let carrier = Note::new(address.pk, 0, rho, r).expect("a note");
    let ct = encrypt_note(&address.ek, &carrier, &[], &[3u8; 32])
        .expect("encrypts")
        .to_bytes();
    // The note the chain actually minted is the same one at the public value.
    let minted = Note::new(address.pk, 17, rho, r).expect("a note");

    let mut state = NodeState {
        head_number: 4,
        ..Default::default()
    };
    put_coinbase(&mut state, 0, 3, minted.commitment(), 17, Some(&ct));
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(1));
    let node = node_with(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the sync runs");

    assert_eq!(report.coinbase_received, 1);
    assert_eq!(
        wallet.store.unspent_total(),
        17,
        "the chain decides the amount"
    );
    assert_eq!(wallet.store.notes[0].origin, NoteOrigin::Coinbase);
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

    // The commitment of a 42-quantum note, published beside a claim of 1000.
    let note = miner_key.coinbase_note(7, 42).expect("a note");
    let mut state = NodeState {
        head_number: 8,
        ..Default::default()
    };
    put_coinbase(&mut state, 0, 7, note.commitment(), 1_000, None);
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
    put_coinbase(
        &mut state,
        0,
        4,
        theirs.coinbase_note(4, 10).expect("a note").commitment(),
        10,
        None,
    );
    put_coinbase(
        &mut state,
        1,
        5,
        same_address
            .coinbase_note(5, 10)
            .expect("a note")
            .commitment(),
        10,
        None,
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
    assert_eq!(
        decoded.coinbase_note(11, 5).expect("a note").commitment(),
        wallet
            .miner_key()
            .coinbase_note(11, 5)
            .expect("a note")
            .commitment()
    );
}
