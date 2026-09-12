//! What a sync refuses, and what it holds on to when the node is not the
//! authority it looks like.
//!
//! Every one of these is a case where a node's answer is less than what the
//! wallet already knows, and where the old code read that as a change. A store
//! is a set of statements about one chain at one height: which leaves exist,
//! which nullifiers are settled, which block hashes stand. A node behind the
//! wallet, a node with no block at a height it claims to have passed, and a
//! node serving a different chain entirely all answer those questions with
//! something that is not a correction.

mod support;

use qnero_notes::{encrypt_note, Digest, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::{create_seed, load_seed, store_path_for};
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{blake2_128_concat_map_key, identity_map_key, storage_prefix};
use qnero_wallet::select::select_notes;
use qnero_wallet::wallet::{ChainBinding, Wallet};
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

/// Rule 1. A node behind this wallet's own watermark is refused, and the sync
/// that refuses writes nothing.
///
/// The regression: nothing required the node's view to be at least as new as
/// the wallet's own last sync, and everything a sync derives is derived from
/// what that node answers. `reconcile_spent` derives spent in both directions
/// from the settled set, so a node that has not executed the block a
/// settlement landed in answers a map without that nullifier, and the note it
/// spent came straight back into the balance. The next `send` then selected an
/// input the chain had already consumed and paid a full proof to have the
/// settlement skipped. The same answer also moved the watermark: every
/// checkpoint above that node's head has no block at its height, which the
/// fork check read as a branch that is gone.
///
/// A node behind the wallet is an ordinary operational state, so it is named
/// rather than worked around: a second `--node`, a node resyncing, a load
/// balancer answering from a lagging replica.
#[test]
fn a_node_behind_this_wallet_is_refused_and_changes_nothing() {
    let dir = support::scratch_dir("node-behind");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = note_for(address.pk, 1_000, "behind");
    let ct = ct_for(&address, &note, 1);

    let mut state = NodeState {
        head_number: 20,
        ..Default::default()
    };
    put_leaf(&mut state, 5, 19, note.commitment(), &ct);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(wallet.store.unspent_total(), 1_000);

    // The spend settles at block 21 and `submit_spend` latches it there, which
    // is what every spend does between its inclusion and the next sync.
    let nk = load_seed(&seed).expect("the seed loads").nk();
    let used_key = blake2_128_concat_map_key(
        "Shielded",
        "UsedNullifiers",
        &note.nullifier(&nk).to_bytes(),
    );
    {
        let mut state = node.state();
        state.put_storage(&used_key, &[]);
        state.head_number = 21;
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert!(wallet.store.notes[0].spent);
    assert_eq!(wallet.store.unspent_total(), 0);
    assert_eq!(wallet.store.last_synced_block, 21);
    let before = serde_json::to_value(&wallet.store).expect("the store serializes");
    let checkpoints = wallet.store.checkpoints.clone();

    // A second node, or the same one resyncing: it is four blocks behind, it
    // has not executed the settlement, and its leaf count is smaller.
    {
        let mut state = node.state();
        state.remove_storage(&used_key);
        state.head_number = 17;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    }
    let refused = wallet
        .sync(&chain, &metadata)
        .expect_err("a node behind the wallet is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("head is block 17"), "{message}");
    assert!(message.contains("synced through block 21"), "{message}");

    // Nothing changed. The note stays spent, the watermark stays where it was,
    // and no checkpoint was popped.
    assert_eq!(
        serde_json::to_value(&wallet.store).expect("the store serializes"),
        before,
        "a refused sync must not have written anything"
    );
    assert!(wallet.store.notes[0].spent);
    assert_eq!(wallet.store.unspent_total(), 0);
    assert_eq!(wallet.store.checkpoints, checkpoints);

    // And the file on disk is the file the last good sync left.
    let reopened = Wallet::open(&seed).expect("the store reopens");
    assert_eq!(
        serde_json::to_value(&reopened.store).expect("the store serializes"),
        before
    );
}

/// Rule 1, second half. A node with no block at a checkpoint's height is
/// refused, and no checkpoint is popped.
///
/// The regression: the fork walk treated "no block at that height" and "a
/// different block at that height" as the same answer. Only the second is a
/// fork. The first is a node that does not reach that height, pruned or
/// serving a head it has not filled in behind, and rewinding on it rescans
/// leaves against a tree smaller than the one already recorded.
#[test]
fn a_missing_block_at_a_checkpoint_height_is_refused_rather_than_rewound() {
    let dir = support::scratch_dir("missing-block");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = note_for(address.pk, 1_000, "missing");
    let ct = ct_for(&address, &note, 2);

    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();
    wallet.sync(&chain, &metadata).expect("the first sync runs");

    {
        let mut state = node.state();
        put_leaf(&mut state, 5, 11, note.commitment(), &ct);
        state.head_number = 11;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.notes[0].leaf_index, 5);
    let before = serde_json::to_value(&wallet.store).expect("the store serializes");

    // The head moves on and the node stops answering for block 11, the newest
    // checkpoint's height. Its hash is not different: there is no block.
    {
        let mut state = node.state();
        state.head_number = 14;
        state.missing_hashes.insert(11);
    }
    let refused = wallet
        .sync(&chain, &metadata)
        .expect_err("a node with no block at a checkpoint height is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("no block at height 11"), "{message}");
    assert!(message.contains("it is not a fork"), "{message}");
    assert_eq!(
        serde_json::to_value(&wallet.store).expect("the store serializes"),
        before,
        "no checkpoint may be popped and no watermark moved"
    );

    // The node fills the gap in. Same hash, so there was never a fork, and the
    // sync runs with nothing rewound.
    {
        let mut state = node.state();
        state.missing_hashes.clear();
    }
    let report = wallet.sync(&chain, &metadata).expect("the sync runs again");
    assert_eq!(report.rewound_from, None, "the same hash is not a fork");
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.unspent_total(), 1_000);
}

/// Rule 3. A store carries the genesis of the chain it was built against, and
/// a node serving a different one is refused.
///
/// The regression: the store was bound to an address and to no chain at all.
/// A `--dev --tmp` node restarts on a fresh genesis with an empty tree, and
/// against one of those every leaf index, block number, checkpoint hash and
/// spent flag in the store is a statement about a chain that is gone. The
/// watermark sits above the new chain's leaf count, so the scan range is empty
/// and the wallet keeps reporting a balance this chain has never carried,
/// silently, for as long as the operator keeps syncing.
///
/// The escape archives rather than deletes: the file is the only copy of every
/// note's `rho` and `r`, and the reason it looks wrong may be an operator who
/// typed the wrong `--node`.
#[test]
fn a_store_refuses_a_node_serving_another_chain_and_the_escape_archives_it() {
    let dir = support::scratch_dir("other-chain");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let store_path = store_path_for(&seed);
    let metadata = test_metadata();

    let first = {
        let mut state = NodeState {
            head_number: 9,
            ..Default::default()
        };
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
        FakeNode::start(state)
    };
    let first_rpc = RpcClient::new(&first.url);
    let first_chain = Chain::new(&first_rpc);

    let (mut wallet, binding) =
        Wallet::open_on_chain(&seed, &first_chain, false).expect("the wallet opens");
    assert_eq!(
        binding,
        ChainBinding::Recorded,
        "a store with no chain recorded takes the one it first sees"
    );
    wallet
        .sync(&first_chain, &metadata)
        .expect("the first sync runs");
    assert_eq!(wallet.store.last_synced_block, 9);
    let bound = wallet
        .store
        .genesis_hash
        .clone()
        .expect("the genesis is recorded");

    // Opening again against the same chain is the ordinary case and says
    // nothing.
    let (_, binding) =
        Wallet::open_on_chain(&seed, &first_chain, false).expect("the wallet reopens");
    assert_eq!(binding, ChainBinding::Bound);

    // A different chain: a restarted `--dev --tmp` node, which is a fresh
    // genesis and an empty tree.
    let second = {
        let mut state = NodeState {
            head_number: 2,
            fork_from: 0,
            fork_tag: 7,
            ..Default::default()
        };
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(0));
        FakeNode::start(state)
    };
    let second_rpc = RpcClient::new(&second.url);
    let second_chain = Chain::new(&second_rpc);

    let refused = Wallet::open_on_chain(&seed, &second_chain, false)
        .expect_err("a store belonging to another chain is refused");
    let message = format!("{refused:#}");
    assert!(message.contains(&bound), "{message}");
    assert!(message.contains("--new-chain-store"), "{message}");

    // The sync path refuses on its own, so a caller that opened the wallet
    // without the binding cannot walk past it either.
    let mut opened = Wallet::open(&seed).expect("the wallet opens");
    let refused = opened
        .sync(&second_chain, &metadata)
        .expect_err("the sync refuses the other chain too");
    assert!(format!("{refused:#}").contains("--new-chain-store"));
    assert_eq!(
        opened.store.last_synced_block, 9,
        "the refused sync changed nothing"
    );

    // The escape. The old store moves aside with its note secrets intact and
    // the wallet starts fresh against the node in front of it.
    let (wallet, binding) =
        Wallet::open_on_chain(&seed, &second_chain, true).expect("the escape opens the wallet");
    let ChainBinding::Archived(archived) = binding else {
        panic!("the escape archives the old store");
    };
    assert!(archived.exists(), "the old store must be kept, not deleted");
    assert_ne!(archived, store_path);
    let kept: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&archived).expect("the archive reads"))
            .expect("the archive is a store");
    assert_eq!(kept["genesis_hash"], serde_json::Value::String(bound));
    assert_eq!(kept["last_synced_block"], 9);

    assert_eq!(wallet.store.last_synced_block, 0);
    assert_eq!(wallet.store.next_leaf, 0);
    assert!(wallet.store.checkpoints.is_empty());
    assert_eq!(
        wallet.store.genesis_hash.as_deref(),
        Some(hex::encode(second_chain.genesis_hash().expect("a genesis")).as_str())
    );
    assert_eq!(wallet.store.address, wallet.address().encode());
}

/// Rule 4. Two notes sharing a nullifier are a conflict set, not a permanent
/// refusal of whichever one arrived second.
///
/// The regression: a sender picks `rho` and `r` for a note it creates
/// (`docs/CIRCUIT.md` section 9.8), so a sender that repeats a pair hands over
/// two notes sharing one nullifier. At most one of them can ever settle, and
/// which one is decided by the recipient spending it, not by the order a scan
/// met them in. The scan refused the second one it saw, wrote that refusal
/// into the file and never revisited it, so a sender who put the large note
/// second had the wallet keep the small one with no way back: the refused
/// value was unreachable and `balance` explained why in a sentence that was
/// not true.
///
/// Both are held now. The selection treats the set as one candidate at its
/// largest member's value, and once one member settles the nullifier set marks
/// the whole set spent, which is what it was always going to do.
#[test]
fn a_conflict_set_spends_its_best_member_and_reports_the_rest_spent_after() {
    let dir = support::scratch_dir("conflict-set");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    // The small note lands first and the large one second, which is the order
    // that used to lose the large one.
    let small = Note::new(
        address.pk,
        40,
        Digest::hash_bytes(&[b"shared rho"]),
        Digest::hash_bytes(&[b"shared r"]),
    )
    .expect("a note");
    let large = Note::new(
        address.pk,
        1_000,
        Digest::hash_bytes(&[b"shared rho"]),
        Digest::hash_bytes(&[b"shared r"]),
    )
    .expect("a note sharing the nullifier");
    assert_ne!(small.commitment(), large.commitment());
    let plain = note_for(address.pk, 250, "plain");

    let mut state = NodeState {
        head_number: 11,
        ..Default::default()
    };
    put_leaf(
        &mut state,
        4,
        11,
        small.commitment(),
        &ct_for(&address, &small, 1),
    );
    put_leaf(
        &mut state,
        5,
        11,
        large.commitment(),
        &ct_for(&address, &large, 2),
    );
    put_leaf(
        &mut state,
        6,
        11,
        plain.commitment(),
        &ct_for(&address, &plain, 3),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    let report = wallet.sync(&chain, &metadata).expect("the sync runs");
    assert_eq!(
        report.received, 3,
        "every decryptable output is held, whatever its nullifier"
    );
    assert_eq!(
        report.rejected, 0,
        "a duplicate nullifier is not a refusal: {:?}",
        wallet.store.rejected
    );

    // One candidate for the set, at the larger member's value, plus the note
    // that shares nothing.
    let spendable = wallet.store.spendable();
    assert_eq!(spendable.len(), 2, "a conflict set is one candidate");
    let mut values: Vec<u64> = spendable.iter().map(|note| note.value).collect();
    values.sort_unstable();
    assert_eq!(values, vec![250, 1_000]);
    assert_eq!(
        wallet.store.unspent_total(),
        1_250,
        "the set counts once, at the value a spend would use"
    );

    // And a selection takes the large member, which is the one that used to be
    // written off.
    let chosen = select_notes(wallet.store.spendable(), 900).expect("the spend is fundable");
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].commitment, large.commitment().to_hex());

    // `balance` prints the set once and says so.
    let rows = wallet.store.rows();
    assert_eq!(rows.len(), 2, "one row per nullifier");
    let conflict = rows
        .iter()
        .find(|row| row.is_conflict())
        .expect("the set is marked");
    assert_eq!(conflict.members, 2);
    assert_eq!(conflict.note.commitment, large.commitment().to_hex());
    assert_eq!(wallet.store.conflicted().len(), 2);

    // The spend of the chosen member settles. The nullifier is shared, so the
    // whole set goes out of the balance together, which is the chain's own
    // answer and needs no rule of its own.
    let nk = load_seed(&seed).expect("the seed loads").nk();
    {
        let mut state = node.state();
        state.put_storage(
            &blake2_128_concat_map_key(
                "Shielded",
                "UsedNullifiers",
                &large.nullifier(&nk).to_bytes(),
            ),
            &[],
        );
        state.head_number = 12;
    }
    let report = wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    assert_eq!(report.newly_spent, 2, "both members of the set are spent");
    assert_eq!(wallet.store.unspent_total(), 250);
    assert!(wallet
        .store
        .notes
        .iter()
        .filter(|note| note.commitment != plain.commitment().to_hex())
        .all(|note| note.spent));
}
