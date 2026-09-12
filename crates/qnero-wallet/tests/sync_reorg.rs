//! A note that moved leaf must be repaired, not skipped.
//!
//! The regression: a scan skipped any commitment the store already held. Every
//! read a sync makes is pinned to `chain_getHeader`, which on a proof-of-work
//! chain is the best block, and a best block can still be orphaned, so a
//! note's leaf index is provisional when it is first recorded. When the block a note settled
//! in is orphaned, the extrinsic is still in the pool, is re-included, and
//! appends the identical commitment at whatever index the replacement block has
//! room for. The rescan saw the commitment, skipped it, and left the store
//! pointing at a leaf that now holds somebody else's note: the balance read as
//! spendable and every spend failed on the path rebuild until the JSON was
//! edited by hand.

mod support;

use qnero_notes::{encrypt_note, Digest, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::create_seed;
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{blake2_128_concat_map_key, identity_map_key, storage_prefix};
use qnero_wallet::wallet::Wallet;
use support::{encode_u64, test_metadata, FakeNode, NodeState};

#[test]
fn a_note_re_included_at_another_leaf_is_moved_rather_than_skipped() {
    let dir = support::scratch_dir("reorg");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    // A note this wallet can decrypt, with the commitment the chain publishes
    // beside it.
    let note = Note::new(
        address.pk,
        1_000,
        Digest::hash_bytes(&[b"reorg rho"]),
        Digest::hash_bytes(&[b"reorg r"]),
    )
    .expect("a note");
    let ciphertext = encrypt_note(
        &address.ek,
        &note,
        &pad_memo("survives a reorg").expect("it fits"),
        &[5u8; 32],
    )
    .expect("it encrypts")
    .to_bytes();
    let commitment = note.commitment();

    let mut state = NodeState {
        head_number: 11,
        ..Default::default()
    };
    let place = |state: &mut NodeState, index: u64, block: u32| {
        state.put_storage(
            &identity_map_key("ZkTree", "Leaves", index),
            &commitment.to_bytes(),
        );
        state.put_storage(
            &identity_map_key("Shielded", "Ciphertexts", index),
            &codec::Encode::encode(&ciphertext),
        );
        state.put_storage(
            &identity_map_key("Shielded", "LeafBlocks", index),
            &codec::Encode::encode(&block),
        );
    };
    place(&mut state, 7, 11);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(8));
    let node = FakeNode::start(state);

    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    let report = wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(report.relocated, 0);
    assert_eq!(wallet.store.notes.len(), 1);
    assert_eq!(wallet.store.notes[0].leaf_index, 7);
    assert_eq!(wallet.store.notes[0].block_number, Some(11));
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert_eq!(wallet.store.notes[0].memo, "survives a reorg");

    // Block 11 is orphaned. Its leaves are gone, the extrinsic is re-included
    // in the replacement chain, and the same commitment lands one leaf further
    // along.
    {
        let mut state = node.state();
        for key in [
            identity_map_key("ZkTree", "Leaves", 7),
            identity_map_key("Shielded", "Ciphertexts", 7),
            identity_map_key("Shielded", "LeafBlocks", 7),
        ] {
            state.storage.remove(&format!("0x{}", hex::encode(key)));
        }
        place(&mut state, 8, 12);
        state.head_number = 13;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(9));
    }

    let report = wallet.sync(&chain, &metadata).expect("the rescan runs");
    assert_eq!(
        report.relocated, 1,
        "the note the chain moved must be moved in the store"
    );
    assert_eq!(report.received, 0, "the same note came back as one note");
    assert_eq!(wallet.store.notes.len(), 1);
    assert_eq!(wallet.store.notes[0].leaf_index, 8);
    assert_eq!(wallet.store.notes[0].block_number, Some(12));
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert!(wallet.store.rejected.is_empty());
}

/// The regression the commit above did not close: the repair only ran for
/// leaves at or above the store's watermark, and that is the direction a reorg
/// almost never produces.
///
/// A reorg happens because the replacement branch is heavier, so it normally
/// carries at least as many leaves as the branch it replaced and a re-included
/// commitment lands at or below where it was. The scan starts at the watermark
/// and the watermark only moves forward, so that leaf is never re-read: the
/// store kept an index that now holds somebody else's commitment, `balance`
/// went on calling the note spendable, and every spend that selected it failed
/// on the path rebuild until the JSON was edited by hand.
///
/// The fork is detected now, through the block hashes a sync records, and the
/// watermark is rewound to the newest block that is still canonical before the
/// range is computed.
#[test]
fn a_note_re_included_below_the_watermark_is_still_moved() {
    let dir = support::scratch_dir("reorg-below");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = Note::new(
        address.pk,
        1_000,
        Digest::hash_bytes(&[b"below rho"]),
        Digest::hash_bytes(&[b"below r"]),
    )
    .expect("a note");
    let ciphertext = encrypt_note(
        &address.ek,
        &note,
        &pad_memo("moved down").expect("it fits"),
        &[6u8; 32],
    )
    .expect("it encrypts")
    .to_bytes();
    let commitment = note.commitment();

    // A second note, appended by the replacement branch inside the rescanned
    // range. A note first seen by the rescan is on the chain by construction,
    // and it must not be counted among the notes the rescan failed to find.
    let fresh = Note::new(
        address.pk,
        250,
        Digest::hash_bytes(&[b"fresh rho"]),
        Digest::hash_bytes(&[b"fresh r"]),
    )
    .expect("a note");
    let fresh_ciphertext = encrypt_note(
        &address.ek,
        &fresh,
        &pad_memo("after the fork").expect("it fits"),
        &[7u8; 32],
    )
    .expect("it encrypts")
    .to_bytes();

    let put = |state: &mut NodeState, index: u64, block: u32, cm: Digest, ct: &[u8]| {
        state.put_storage(&identity_map_key("ZkTree", "Leaves", index), &cm.to_bytes());
        state.put_storage(
            &identity_map_key("Shielded", "Ciphertexts", index),
            &codec::Encode::encode(&ct.to_vec()),
        );
        state.put_storage(
            &identity_map_key("Shielded", "LeafBlocks", index),
            &codec::Encode::encode(&block),
        );
    };
    let place = move |state: &mut NodeState, index: u64, block: u32| {
        put(state, index, block, commitment, &ciphertext);
    };

    // A sync that finishes before the block the note lands in. Its checkpoint
    // is the ancestor the fork check will rewind to.
    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    let report = wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(report.received, 0);
    assert_eq!(wallet.store.next_leaf, 4);

    // Block 11 appends the note at leaf 7.
    {
        let mut state = node.state();
        place(&mut state, 7, 11);
        state.head_number = 11;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(8));
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.notes[0].leaf_index, 7);
    assert_eq!(wallet.store.next_leaf, 8);

    // Block 11 is orphaned. The replacement branch carries one fewer leaf
    // before it, so the re-included extrinsic appends the identical commitment
    // at leaf 5, below the watermark this wallet reached, and the chain then
    // grows past it. This is the ordinary shape of a reorg.
    {
        let mut state = node.state();
        for key in [
            identity_map_key("ZkTree", "Leaves", 7),
            identity_map_key("Shielded", "Ciphertexts", 7),
            identity_map_key("Shielded", "LeafBlocks", 7),
        ] {
            state.remove_storage(&key);
        }
        place(&mut state, 5, 11);
        put(&mut state, 6, 11, fresh.commitment(), &fresh_ciphertext);
        state.fork_from = 11;
        state.fork_tag = 1;
        state.head_number = 13;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(9));
    }

    let report = wallet.sync(&chain, &metadata).expect("the rescan runs");
    assert_eq!(
        report.rewound_from,
        Some(8),
        "the fork was not detected: the watermark never moved"
    );
    // Rewound to the watermark of block 10, the newest checkpoint whose hash
    // the chain still answers with.
    assert_eq!(report.rewound_to, Some(4));
    assert_eq!(report.forked_at_block, Some(10));
    assert_eq!(report.scanned_from, 4);
    assert_eq!(
        report.relocated, 1,
        "a commitment re-included below the watermark must still be moved"
    );
    assert_eq!(
        report.received, 1,
        "the note the replacement branch added is a new one"
    );
    assert_eq!(
        report.vanished, 0,
        "a note this rescan recorded for the first time is on the chain"
    );
    assert_eq!(wallet.store.notes.len(), 2);
    assert_eq!(wallet.store.notes[0].leaf_index, 5);
    assert_eq!(wallet.store.unspent_total(), 1_250);
    assert!(wallet.store.rejected.is_empty());
}

/// The regression: `spent` was a latch.
///
/// Every sync repages the whole `UsedNullifiers` map, so the store always
/// holds the chain's current answer, and then the flag was only ever set true.
/// A settlement whose block is orphaned and which does not re-land, because
/// the unsigned extrinsic left the pool after five blocks or its anchor fell
/// outside the window, leaves its nullifier permanently absent from the map.
/// The note it spent stayed `spent` forever: out of `unspent_total`, never
/// selected, and fully spendable on chain.
#[test]
fn a_settlement_that_is_orphaned_out_puts_the_note_back_in_the_balance() {
    let dir = support::scratch_dir("unspend");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = Note::new(
        address.pk,
        1_000,
        Digest::hash_bytes(&[b"unspend rho"]),
        Digest::hash_bytes(&[b"unspend r"]),
    )
    .expect("a note");
    let ciphertext = encrypt_note(
        &address.ek,
        &note,
        &pad_memo("").expect("it fits"),
        &[8u8; 32],
    )
    .expect("it encrypts")
    .to_bytes();
    let commitment = note.commitment();

    let mut state = NodeState {
        head_number: 11,
        ..Default::default()
    };
    state.put_storage(
        &identity_map_key("ZkTree", "Leaves", 7),
        &commitment.to_bytes(),
    );
    state.put_storage(
        &identity_map_key("Shielded", "Ciphertexts", 7),
        &codec::Encode::encode(&ciphertext),
    );
    state.put_storage(
        &identity_map_key("Shielded", "LeafBlocks", 7),
        &codec::Encode::encode(&11u32),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(8));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    let report = wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);

    // The nullifier of the wallet's own note, as the chain would publish it.
    // Only the nullifier key computes this at all, and the wallet computed it
    // on the sync above.
    let nullifier = hex::decode(&wallet.store.notes[0].nullifier).expect("hex");
    let key = blake2_128_concat_map_key("Shielded", "UsedNullifiers", &nullifier);

    // The spend settles.
    {
        let mut state = node.state();
        state.put_storage(&key, &[]);
        state.head_number = 12;
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(report.newly_spent, 1);
    assert_eq!(report.newly_unspent, 0);
    assert_eq!(wallet.store.unspent_total(), 0);
    assert_eq!(wallet.store.notes[0].spent_seen_at_block, Some(12));

    // Its block is orphaned and the settlement does not re-land.
    {
        let mut state = node.state();
        state.remove_storage(&key);
        state.head_number = 13;
    }
    let report = wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert_eq!(
        report.newly_unspent, 1,
        "a note whose settlement left the chain has to come back into the balance"
    );
    assert_eq!(report.newly_spent, 0);
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert!(!wallet.store.notes[0].spent);
    assert_eq!(wallet.store.notes[0].spent_seen_at_block, None);
}
