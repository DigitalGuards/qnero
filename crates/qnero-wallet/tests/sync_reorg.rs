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
use qnero_wallet::keys::{create_seed, load_seed};
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
    // The commitment goes in the tree and the payload goes in the body of the
    // block that appended it, which is where the chain puts both.
    let place = |state: &mut NodeState, index: u64, block: u32| {
        state.put_storage(
            &identity_map_key("ZkTree", "Leaves", index),
            &commitment.to_bytes(),
        );
        state.put_storage(
            &identity_map_key("Shielded", "LeafBlocks", index),
            &codec::Encode::encode(&block),
        );
        support::put_payload(state, block, &ciphertext);
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
            identity_map_key("Shielded", "LeafBlocks", 7),
        ] {
            state.storage.remove(&format!("0x{}", hex::encode(key)));
        }
        state.blocks.remove(&11);
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
            &identity_map_key("Shielded", "LeafBlocks", index),
            &codec::Encode::encode(&block),
        );
        support::put_payload(state, block, ct);
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
            identity_map_key("Shielded", "LeafBlocks", 7),
        ] {
            state.remove_storage(&key);
        }
        // The replacement branch is a different block 11, so its body is the
        // one the re-included extrinsic lands in and the old one goes.
        state.blocks.remove(&11);
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
        &identity_map_key("Shielded", "LeafBlocks", 7),
        &codec::Encode::encode(&11u32),
    );
    support::put_payload(&mut state, 11, &ciphertext);
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
    let nullifier = hex::decode(wallet.store.notes[0].nullifier.as_str()).expect("hex");
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

/// Helpers for the reorg cases below: a leaf is a commitment, a ciphertext and
/// the block it landed in, and an orphaned block takes all three away.
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
        &identity_map_key("Shielded", "LeafBlocks", index),
        &codec::Encode::encode(&block),
    );
    support::put_payload(state, block, ct);
}

/// Take a leaf off the tree, and the block's body with it.
///
/// Both, because a reorg takes the extrinsic out of the block as well as the
/// leaf out of the tree, and a body left behind would root to a header the
/// replacement branch never published.
fn drop_leaf(state: &mut NodeState, index: u64, block: u32) {
    for key in [
        identity_map_key("ZkTree", "Leaves", index),
        identity_map_key("Shielded", "LeafBlocks", index),
    ] {
        state.remove_storage(&key);
    }
    state.blocks.remove(&block);
}

fn nullifier_key(store: &qnero_wallet::store::WalletStore, commitment: &str) -> Vec<u8> {
    let note = store
        .notes
        .iter()
        .find(|note| note.commitment == commitment)
        .expect("the wallet holds that note");
    let raw = hex::decode(note.nullifier.as_str()).expect("hex");
    blake2_128_concat_map_key("Shielded", "UsedNullifiers", &raw)
}

/// The regression: a note the fork rescan proved is not on the chain stayed in
/// the balance.
///
/// The rescan already computed the fact and reported it as a count, and then
/// nothing was written down. The note kept `spent: false` in the store, so
/// `unspent_total` and the `balance` table reported value the chain does not
/// back, permanently and with no marker; `balance` does not sync, so the
/// one-off line the sync printed was never seen again. `select_notes` picks
/// largest first, so a phantom larger than every real note also made every
/// subsequent `send` fail on the path rebuild, with no documented remedy but
/// editing the JSON by hand.
#[test]
fn an_orphaned_settlement_leaves_the_balance_backed_by_the_chain() {
    let dir = support::scratch_dir("orphaned-settlement");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let input = note_for(address.pk, 1_000, "input");
    let input_ct = ct_for(&address, &input, 1);
    let change = note_for(address.pk, 692, "change");
    let change_ct = ct_for(&address, &change, 2);

    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    put_leaf(&mut state, 5, 10, input.commitment(), &input_ct);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    let report = wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(wallet.store.unspent_total(), 1_000);

    // Block 11 settles a spend of the input note and appends the change note.
    let used_key = nullifier_key(&wallet.store, &input.commitment().to_hex());
    {
        let mut state = node.state();
        put_leaf(&mut state, 6, 11, change.commitment(), &change_ct);
        state.put_storage(&used_key, &[]);
        state.head_number = 11;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(report.newly_spent, 1);
    assert_eq!(wallet.store.unspent_total(), 692);

    // Block 11 is orphaned and the settlement does not re-land. The chain
    // carries the input note at leaf 5 and nothing else.
    {
        let mut state = node.state();
        drop_leaf(&mut state, 6, 11);
        state.remove_storage(&used_key);
        state.fork_from = 11;
        state.fork_tag = 1;
        state.head_number = 13;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    }
    let report = wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert_eq!(report.rewound_from, Some(7), "the fork was detected");
    assert_eq!(report.rewound_to, Some(6));
    assert_eq!(report.newly_unspent, 1, "the input note came back");
    assert_eq!(report.vanished, 1, "the change note is not on the chain");

    assert_eq!(
        wallet.store.unspent_total(),
        1_000,
        "the chain backs 10 QNR and that is what the wallet may report"
    );
    assert_eq!(wallet.store.off_chain_total(), 692);
    let phantom = wallet
        .store
        .off_chain()
        .next()
        .expect("the change note is listed under its own heading");
    assert_eq!(phantom.commitment, change.commitment().to_hex());
    // Still held: its secrets are the only copy the wallet has, and the
    // extrinsic can still be re-included.
    assert_eq!(wallet.store.notes.len(), 2);
    // And a spend cannot select it, which is what stops a phantom larger than
    // every real note from failing every send on the path rebuild.
    assert!(!wallet
        .store
        .unspent()
        .any(|note| note.commitment == phantom.commitment));

    // `balance` does not sync, so the marker has to survive the file.
    wallet.save().expect("saved");
    let reopened = Wallet::open(&seed).expect("the store reopens");
    assert_eq!(reopened.store.unspent_total(), 1_000);
    assert_eq!(reopened.store.off_chain().count(), 1);

    // The settlement is re-included at a later block, one leaf further along.
    {
        let mut state = node.state();
        put_leaf(&mut state, 6, 14, change.commitment(), &change_ct);
        state.put_storage(&used_key, &[]);
        state.head_number = 14;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the fourth sync runs");
    assert_eq!(report.received, 0, "the same note came back as one note");
    assert_eq!(report.newly_spent, 1);
    assert_eq!(wallet.store.off_chain().count(), 0);
    assert_eq!(wallet.store.unspent_total(), 692);
}

/// The regression: `vanished` was counted before the spent flags were derived,
/// so it read the flags the reconciliation was about to flip.
///
/// A note that was spent and whose own creating leaf was orphaned in the same
/// reorg was skipped by the `!note.spent` filter, and four lines later
/// `reconcile_spent` flipped it to unspent and let it back into the balance as
/// a phantom nobody had been told about. The operator was told one note was
/// missing while two were. The ordering was an artifact of the fix pass: the
/// `vanished` block was written into the slot the old latching `newly_spent`
/// loop had occupied.
#[test]
fn a_spent_note_whose_own_leaf_was_orphaned_is_reported_too() {
    let dir = support::scratch_dir("orphaned-chain");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let first = note_for(address.pk, 1_000, "first");
    let first_ct = ct_for(&address, &first, 1);
    let second = note_for(address.pk, 692, "second");
    let second_ct = ct_for(&address, &second, 2);
    let third = note_for(address.pk, 400, "third");
    let third_ct = ct_for(&address, &third, 3);

    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    put_leaf(&mut state, 5, 10, first.commitment(), &first_ct);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    wallet.sync(&chain, &metadata).expect("the first sync runs");
    let first_key = nullifier_key(&wallet.store, &first.commitment().to_hex());

    // Block 11 settles a spend of `first`, with `second` as its change.
    {
        let mut state = node.state();
        put_leaf(&mut state, 6, 11, second.commitment(), &second_ct);
        state.put_storage(&first_key, &[]);
        state.head_number = 11;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    let second_key = nullifier_key(&wallet.store, &second.commitment().to_hex());

    // Block 12 settles a spend of `second`, with `third` as its change.
    {
        let mut state = node.state();
        put_leaf(&mut state, 7, 12, third.commitment(), &third_ct);
        state.put_storage(&second_key, &[]);
        state.head_number = 12;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(8));
    }
    let report = wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert_eq!(report.newly_spent, 1);
    assert_eq!(wallet.store.unspent_total(), 400);

    // Blocks 11 and 12 are orphaned together and neither settlement re-lands.
    // The chain is back to carrying `first` at leaf 5 and nothing else.
    {
        let mut state = node.state();
        drop_leaf(&mut state, 6, 11);
        drop_leaf(&mut state, 7, 12);
        state.remove_storage(&first_key);
        state.remove_storage(&second_key);
        state.fork_from = 11;
        state.fork_tag = 1;
        state.head_number = 15;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the fourth sync runs");
    assert_eq!(report.rewound_to, Some(6));
    assert_eq!(
        report.newly_unspent, 2,
        "both settlements left the chain, so both notes they spent come back"
    );
    assert_eq!(
        report.vanished, 2,
        "two held notes sit inside the rescanned range and the chain carries \
         neither, whatever their spent flag said before the reconciliation"
    );
    assert_eq!(
        wallet.store.unspent_total(),
        1_000,
        "the chain backs `first` alone"
    );
    assert_eq!(wallet.store.off_chain_total(), 692 + 400);
    assert_eq!(wallet.store.off_chain().count(), 2);
    // `first` is below the rewind point, so it was folded at or before a block
    // that is still canonical and cannot have moved.
    let held = wallet
        .store
        .unspent()
        .map(|note| note.commitment.clone())
        .collect::<Vec<_>>();
    assert_eq!(held, vec![first.commitment().to_hex()]);
}

/// The regression: a fork rescan appended a second identical `RejectedNote`
/// for every refused leaf inside the rewound range.
///
/// A refused note is never added to `store.notes`, so `has_commitment` does
/// not see it, the rescan decrypts it and refuses it again, and the refusal
/// branch did not ask whether `store.rejected` already held that commitment.
/// Each fork touching that range added another copy, and `balance` prints one
/// line per copy. It is new with the rewind: before it a leaf was never
/// scanned twice.
///
/// The second half is the refusal going away again. The one refusal left is a
/// nullifier the chain has already settled, and that is a statement about a
/// chain state a reorg can undo: the settlement is orphaned, the rescan walks
/// the same leaf, the nullifier is no longer settled and the note is held. The
/// refusal stayed in the file, so `balance` printed "its nullifier is already
/// settled on chain" beside a note it had just added to the balance.
#[test]
fn a_fork_rescan_records_one_refusal_per_refused_output_and_drops_it_when_held() {
    let dir = support::scratch_dir("refusal-dedupe");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    // A note whose nullifier the chain has already settled: whoever sent it
    // reused a `(rho, r)` pair that a spend of an earlier note published, so
    // this output can never be spent while that settlement stands.
    let held = note_for(address.pk, 1_000, "held");
    let held_ct = ct_for(&address, &held, 1);
    let settled = note_for(address.pk, 7, "settled");
    let settled_ct = ct_for(&address, &settled, 2);
    let nk = load_seed(&seed).expect("the seed loads").nk();
    let settled_key = blake2_128_concat_map_key(
        "Shielded",
        "UsedNullifiers",
        &settled.nullifier(&nk).to_bytes(),
    );

    // A sync that finishes before either leaf lands, so its checkpoint is the
    // ancestor the fork check rewinds to.
    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(5));
    state.put_storage(&settled_key, &[]);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();
    wallet.sync(&chain, &metadata).expect("the first sync runs");

    {
        let mut state = node.state();
        put_leaf(&mut state, 5, 11, held.commitment(), &held_ct);
        put_leaf(&mut state, 6, 11, settled.commitment(), &settled_ct);
        state.head_number = 11;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(report.received, 1);
    assert_eq!(report.rejected, 1);
    assert_eq!(wallet.store.rejected.len(), 1);
    assert_eq!(wallet.store.rejected[0].leaf_index, 6);

    // A fork below both leaves. The replacement branch carries the same two
    // outputs and the same settlement, so the rescan walks leaf 6 and refuses
    // the same output again.
    {
        let mut state = node.state();
        state.fork_from = 11;
        state.fork_tag = 1;
        state.head_number = 13;
    }
    let report = wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert_eq!(report.rewound_to, Some(5), "the fork was detected");
    assert_eq!(
        report.rejected, 0,
        "the rescan refused nothing the store had not already recorded"
    );
    assert_eq!(
        wallet.store.rejected.len(),
        1,
        "one output on chain is one refusal in the store, however many forks \
         walk past it"
    );
    assert_eq!(
        report.vanished, 0,
        "the held note came back at its own leaf"
    );
    assert_eq!(wallet.store.unspent_total(), 1_000);

    // A second fork over the same range: still one entry.
    {
        let mut state = node.state();
        state.fork_tag = 2;
        state.head_number = 15;
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the fourth sync runs");
    assert_eq!(wallet.store.rejected.len(), 1);

    // The settlement that claimed the nullifier is orphaned out. The next
    // rescan meets the same leaf, finds the nullifier unsettled and holds the
    // note, and the refusal has to go with it.
    {
        let mut state = node.state();
        state.remove_storage(&settled_key);
        state.fork_tag = 3;
        state.head_number = 17;
    }
    let report = wallet.sync(&chain, &metadata).expect("the fifth sync runs");
    assert_eq!(report.received, 1, "the output is held now");
    assert_eq!(
        report.rejected_cleared, 1,
        "a refusal for an output this wallet holds has to go"
    );
    assert!(
        wallet.store.rejected.is_empty(),
        "balance would print a refusal beside the note it names: {:?}",
        wallet.store.rejected
    );
    assert_eq!(wallet.store.unspent_total(), 1_007);
}
