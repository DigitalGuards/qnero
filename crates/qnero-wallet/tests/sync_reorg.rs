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
use qnero_wallet::scale::{identity_map_key, storage_prefix};
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
    assert_eq!(report.received, 0, "it is the same note, not a second one");
    assert_eq!(wallet.store.notes.len(), 1);
    assert_eq!(wallet.store.notes[0].leaf_index, 8);
    assert_eq!(wallet.store.notes[0].block_number, Some(12));
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert!(wallet.store.rejected.is_empty());
}
