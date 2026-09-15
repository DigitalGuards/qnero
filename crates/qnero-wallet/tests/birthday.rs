//! Where a wallet starts reading, and what it costs to start in the wrong
//! place.
//!
//! A wallet cannot have been paid into a leaf that existed before the wallet
//! did, so one that records the head it was created at never walks the headers
//! under that block and never trial-decrypts the ciphertexts under its leaf
//! count. On a chain a year deep that is the difference between a first sync
//! that finishes and one somebody watches.
//!
//! The birthday is a checkpoint and nothing more: the sync reads it exactly as
//! it reads a checkpoint an earlier pass wrote, so the fork walk rewinds
//! through it and the first sync folds the leaves under it against the
//! `zkTreeRoot` of the block it names. It is the node's claim, and a restore
//! height is the operator's claim on top of that. Both are recorded rounded
//! **down** to a multiple of `BIRTHDAY_EPOCH`, so what every later node is told
//! is a coarse public epoch and never the moment the wallet was made.

mod support;

use qnero_notes::{encrypt_note, Digest, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::{create_seed, import_seed};
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{identity_map_key, storage_prefix};
use qnero_wallet::store::{birthday_epoch_of, BIRTHDAY_EPOCH};
use qnero_wallet::wallet::Wallet;

use support::{encode_u64, test_metadata, FakeNode, NodeState};

fn fresh(tag: &str) -> (std::path::PathBuf, Wallet) {
    let dir = support::scratch_dir(tag);
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let wallet = Wallet::open(&seed).expect("the wallet opens");
    (seed, wallet)
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

fn put_leaf(state: &mut NodeState, index: u64, block: u32, cm: Digest, ct: &[u8]) {
    state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
    state.put_storage(
        &identity_map_key("Shielded", "Ciphertexts", index),
        &codec::Encode::encode(&ct.to_vec()),
    );
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", index),
        &block.to_le_bytes(),
    );
}

#[test]
fn an_epoch_is_the_height_rounded_down() {
    assert_eq!(birthday_epoch_of(0), 0);
    assert_eq!(birthday_epoch_of(BIRTHDAY_EPOCH - 1), 0);
    assert_eq!(birthday_epoch_of(BIRTHDAY_EPOCH), BIRTHDAY_EPOCH);
    assert_eq!(birthday_epoch_of(BIRTHDAY_EPOCH + 1), BIRTHDAY_EPOCH);
    assert_eq!(
        birthday_epoch_of(3 * BIRTHDAY_EPOCH - 1),
        2 * BIRTHDAY_EPOCH
    );
}

/// A chain with three leaves behind the wallet and one payment in front of it.
fn chain_with_a_payment(address: &qnero_notes::Address) -> (NodeState, Note) {
    let mut state = NodeState {
        head_number: 2 * BIRTHDAY_EPOCH + 50,
        ..Default::default()
    };
    // Three leaves, all in one block a long way under the birthday. A wallet
    // created at the head cannot own any of them.
    for index in 0..3u64 {
        put_leaf(
            &mut state,
            index,
            500,
            Digest::hash_bytes(&[b"somebody else", &index.to_le_bytes()]),
            &[0x11u8; 64],
        );
    }
    // The payment, in a block above the birthday epoch.
    let mine = note_for(address.pk, 1_000, "birthday");
    let ciphertext = encrypt_note(&address.ek, &mine, &pad_memo("").expect("fits"), &[7u8; 32])
        .expect("encrypts")
        .to_bytes();
    put_leaf(
        &mut state,
        3,
        2 * BIRTHDAY_EPOCH + 10,
        mine.commitment(),
        &ciphertext,
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    (state, mine)
}

#[test]
fn a_wallet_created_at_a_head_skips_the_history_under_it_and_is_paid_after_it() {
    let (seed, wallet) = fresh("birthday-created");
    let address = wallet.address();
    drop(wallet);
    let (state, mine) = chain_with_a_payment(&address);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let birthday = wallet
        .record_birthday(&chain, None)
        .expect("a head is a birthday");
    // Rounded down from the head, so the recorded block is the epoch below it
    // and never the moment the wallet was made.
    assert_eq!(birthday.block_number, 2 * BIRTHDAY_EPOCH);
    assert_eq!(birthday.next_leaf, 3);
    assert_eq!(wallet.store.next_leaf, 3);

    let report = wallet
        .sync(&chain, &test_metadata())
        .expect("the first sync starts at the birthday");
    assert_eq!(report.scanned_from, 3);
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.notes[0].commitment, mine.commitment().to_hex());

    let state = node.state();
    // Never asks for a leaf under the watermark. The ciphertext is the
    // expensive read and the one that says which leaves this wallet cared
    // about, and the three under the birthday are never named.
    for index in 0..3u64 {
        let key = hex::encode(identity_map_key("Shielded", "Ciphertexts", index));
        assert!(
            !state.asked_about(&key),
            "the pass asked for the ciphertext of leaf {index}, which is under its birthday"
        );
    }
    // And never walks a header under it either. The walk stands on the
    // birthday block, so the bottom of the range is that block and not zero.
    assert!(
        state.calls("chain_getHeader") <= 60,
        "the walk fetched {} headers for a 50-block range above the birthday",
        state.calls("chain_getHeader")
    );
}

#[test]
fn a_restore_height_is_recorded_at_the_epoch_below_it() {
    let (seed, wallet) = fresh("birthday-restored");
    let address = wallet.address();
    drop(wallet);
    let (state, _mine) = chain_with_a_payment(&address);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let birthday = wallet
        .record_birthday(&chain, Some(BIRTHDAY_EPOCH + 700))
        .expect("a restore height is a birthday");

    assert_eq!(birthday.block_number, BIRTHDAY_EPOCH);
    assert_eq!(wallet.store.last_synced_block, BIRTHDAY_EPOCH);
    // The store carries it, and it is also the store's one checkpoint, which
    // is what the header walk stands on.
    assert_eq!(wallet.store.birthday.as_ref(), Some(&birthday));
    assert_eq!(wallet.store.checkpoints, vec![birthday]);
}

#[test]
fn a_restore_height_above_the_head_is_refused_and_records_nothing() {
    let (seed, wallet) = fresh("birthday-too-high");
    let address = wallet.address();
    drop(wallet);
    let (state, _mine) = chain_with_a_payment(&address);
    let head = state.head_number;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let refused = wallet
        .record_birthday(&chain, Some(head + 1))
        .expect_err("a height above the head is refused");
    assert!(format!("{refused:#}").contains("names a block nobody has yet"));
    assert!(wallet.store.birthday.is_none());
    assert_eq!(wallet.store.next_leaf, 0);
}

#[test]
fn a_birthday_is_only_recorded_on_a_store_that_has_read_nothing() {
    let (seed, wallet) = fresh("birthday-twice");
    let address = wallet.address();
    drop(wallet);
    let (state, _mine) = chain_with_a_payment(&address);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);

    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    wallet
        .record_birthday(&chain, Some(BIRTHDAY_EPOCH))
        .expect("the first one is recorded");
    let refused = wallet
        .record_birthday(&chain, Some(0))
        .expect_err("a second birthday is refused");
    assert!(format!("{refused:#}").contains("has never read one"));
}

#[test]
fn a_restored_seed_is_the_same_wallet_and_a_malformed_one_writes_nothing() {
    let dir = support::scratch_dir("birthday-import");
    let original = dir.join("first.seed");
    create_seed(&original).expect("a fresh seed");
    let address = Wallet::open(&original).expect("opens").address().encode();
    let hex = std::fs::read_to_string(&original).expect("the seed reads");

    // The grouped spelling the browser wallet shows, with the whitespace it
    // shows it with.
    let grouped = hex
        .trim()
        .as_bytes()
        .chunks(8)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let restored = dir.join("second.seed");
    import_seed(&restored, &grouped).expect("the grouped spelling goes back in");
    assert_eq!(
        Wallet::open(&restored).expect("opens").address().encode(),
        address
    );

    let short = dir.join("third.seed");
    // `SpendingKey` has no `Debug`, deliberately, so the error comes out by
    // hand rather than through `expect_err`.
    let refused = match import_seed(&short, "abcdef") {
        Ok(_) => panic!("a short key was accepted"),
        Err(error) => format!("{error:#}"),
    };
    assert!(refused.contains("64 hex characters"), "{refused}");
    assert!(!short.exists(), "a refused import left a file behind");
}
