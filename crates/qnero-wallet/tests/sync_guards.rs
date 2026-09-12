//! What a sync refuses, and what it holds on to when the node is not the
//! authority it looks like.
//!
//! Every one of these is a case where a node's answer is less than what the
//! wallet already knows, and where the old code read that as a change. A store
//! is a set of statements about one chain at one height: which leaves exist,
//! which nullifiers are settled, which block hashes stand. A node behind the
//! wallet, a node with no block at a height it claims to have passed, a node
//! whose tree is shorter than the leaves the wallet has read, and a node
//! serving a different chain entirely all answer those questions with
//! something that is not a correction.
//!
//! The one answer that **is** a correction is a different block at a height
//! this wallet checkpointed, and a node on a branch heavier and shorter than
//! the wallet's own is still that. So the walk is keyed on checkpoint hashes
//! and a fork is allowed to take `last_synced_block` down.

mod support;

use qnero_notes::{encrypt_note, Digest, Note};
use qnero_wallet::chain::Chain;
use qnero_wallet::keys::{create_seed, load_seed, store_path_for};
use qnero_wallet::memo::pad_memo;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::scale::{blake2_128_concat_map_key, identity_map_key, storage_prefix};
use qnero_wallet::select::select_notes;
use qnero_wallet::wallet::{ChainBinding, SyncOptions, Wallet};
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
        ChainBinding::Unrecorded,
        "a store with no chain recorded names none until something commits"
    );
    assert!(
        !store_path.exists(),
        "opening a wallet writes nothing, the binding included"
    );
    let report = wallet
        .sync(&first_chain, &metadata)
        .expect("the first sync runs");
    assert!(
        report.recorded_genesis,
        "the sync that commits is what records the chain"
    );
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
    let (mut wallet, binding) =
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
        wallet.store.genesis_hash, None,
        "the fresh store names a chain once it commits one, and the rename is all the escape \
         writes"
    );
    assert_eq!(wallet.store.address, wallet.address().encode());

    // And the sync against the new chain is what records it.
    let report = wallet
        .sync(&second_chain, &metadata)
        .expect("the fresh store syncs against the chain it was pointed at");
    assert!(report.recorded_genesis);
    assert_eq!(
        wallet.store.genesis_hash.as_deref(),
        Some(hex::encode(second_chain.genesis_hash().expect("a genesis")).as_str())
    );
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

/// Rule 1, decided on checkpoint hashes. A node on this wallet's own
/// chain that has not reached every block the wallet has is refused, and the
/// refusal survives the node still holding every leaf the wallet scanned.
///
/// The constraint this covers is the one skipped checkpoint. The walk goes
/// newest first and skips every checkpoint above the node's head, because a
/// height it cannot answer for says nothing on its own. What decides the case
/// is the first checkpoint it can answer for: the hash still stands, so the
/// node is on this wallet's chain, and the checkpoints above it are blocks
/// this node has not reached. Drop the count of what was skipped and this sync
/// runs: the leaf gate passes, because a lagging node's tree is the same size
/// here, and the sync writes a `last_synced_block` below the one it found and
/// pops the checkpoints above it, having read `UsedNullifiers` from a node
/// that has not executed the settlement.
#[test]
fn a_lagging_node_on_the_same_chain_is_refused_and_writes_nothing() {
    let dir = support::scratch_dir("lagging-same-chain");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = note_for(address.pk, 1_000, "lagging");
    let ct = ct_for(&address, &note, 4);

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
        put_leaf(&mut state, 5, 19, note.commitment(), &ct);
        state.head_number = 20;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");

    // The spend settles and `submit_spend` latches it, the way every spend
    // does between inclusion and the next sync.
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
    wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert!(wallet.store.notes[0].spent);
    assert_eq!(wallet.store.last_synced_block, 21);
    assert_eq!(
        wallet
            .store
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.block_number)
            .collect::<Vec<_>>(),
        vec![10, 20, 21]
    );
    let before = serde_json::to_value(&wallet.store).expect("the store serializes");

    // A replica four blocks behind. Same chain, same tree size, and it has not
    // executed the settlement. The checkpoint at block 10 is one it can answer
    // for and its hash still stands, so nothing about a fork is in question.
    {
        let mut state = node.state();
        state.remove_storage(&used_key);
        state.head_number = 15;
    }
    let refused = wallet
        .sync(&chain, &metadata)
        .expect_err("a node behind the wallet on its own chain is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("behind this wallet"), "{message}");
    assert!(message.contains("head is block 15"), "{message}");
    assert!(message.contains("synced through block 21"), "{message}");

    assert_eq!(
        serde_json::to_value(&wallet.store).expect("the store serializes"),
        before,
        "a refused sync must not have written anything"
    );
    assert!(wallet.store.notes[0].spent, "the settlement still stands");
    let reopened = Wallet::open(&seed).expect("the store reopens");
    assert_eq!(
        serde_json::to_value(&reopened.store).expect("the store serializes"),
        before
    );
}

/// Rule 2. A reorg onto a heavier but shorter branch is a fork, and the sync
/// runs: the watermark and the block height both follow the checkpoint that
/// survived, downwards.
///
/// The regression: the gate compared heights, so a head below
/// `last_synced_block` was refused whatever the hashes said. Heaviest-chain
/// rules do not order branches by length, so a shorter branch can win, and
/// against one of those the wallet refused every sync until the chain climbed
/// back past a height it had recorded on a branch that no longer existed. The
/// note that moved leaf in the reorg stayed at its old index for the whole of
/// that window, unspendable, with `balance` reporting it as spendable.
///
/// `last_synced_block` going down is the point. It is a statement about one
/// branch, and when that branch is gone the statement goes with it.
#[test]
fn a_heavier_shorter_branch_is_a_fork_and_syncs() {
    let dir = support::scratch_dir("shorter-branch");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let first = note_for(address.pk, 400, "before the fork");
    let moved = note_for(address.pk, 1_000, "across the fork");

    let mut state = NodeState {
        head_number: 5,
        ..Default::default()
    };
    put_leaf(
        &mut state,
        3,
        4,
        first.commitment(),
        &ct_for(&address, &first, 5),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(wallet.store.next_leaf, 4);

    // The second note lands at leaf 4 in block 10, above the height the fork
    // will later cut at.
    {
        let mut state = node.state();
        put_leaf(
            &mut state,
            4,
            10,
            moved.commitment(),
            &ct_for(&address, &moved, 6),
        );
        state.head_number = 12;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(5));
    }
    wallet
        .sync(&chain, &metadata)
        .expect("the second sync runs");
    {
        let mut state = node.state();
        state.head_number = 21;
    }
    wallet.sync(&chain, &metadata).expect("the third sync runs");
    assert_eq!(wallet.store.last_synced_block, 21);
    assert_eq!(wallet.store.unspent_total(), 1_400);

    // The reorg. Every block from 8 up is a different block, the new head is
    // block 17, which is below the wallet's own `last_synced_block`, and the
    // replacement branch re-included the second note at leaf 6.
    {
        let mut state = node.state();
        state.fork_from = 8;
        state.fork_tag = 3;
        state.head_number = 17;
        state.remove_storage(&identity_map_key("ZkTree", "Leaves", 4));
        state.remove_storage(&identity_map_key("Shielded", "Ciphertexts", 4));
        state.remove_storage(&identity_map_key("Shielded", "LeafBlocks", 4));
        put_leaf(
            &mut state,
            6,
            9,
            moved.commitment(),
            &ct_for(&address, &moved, 6),
        );
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(7));
    }

    let report = wallet
        .sync(&chain, &metadata)
        .expect("a shorter branch is a fork, and a fork syncs");
    assert_eq!(
        report.forked_at_block,
        Some(5),
        "the survivor is the newest checkpoint whose hash still stands"
    );
    assert_eq!(report.rewound_from, Some(5));
    assert_eq!(report.rewound_to, Some(4));
    assert_eq!(report.relocated, 1, "the moved note is repaired in place");
    assert_eq!(report.vanished, 0);
    assert_eq!(
        wallet.store.last_synced_block, 17,
        "the height follows the branch that survived, downwards"
    );
    assert_eq!(wallet.store.next_leaf, 7);
    let relocated = wallet
        .store
        .notes
        .iter()
        .find(|note| note.commitment == moved.commitment().to_hex())
        .expect("the note is still held");
    assert_eq!(relocated.leaf_index, 6);
    assert_eq!(relocated.block_number, Some(9));
    assert!(relocated.on_chain);
    assert_eq!(wallet.store.unspent_total(), 1_400);
    // The checkpoints of the branch that is gone went with it.
    assert_eq!(
        wallet
            .store
            .checkpoints
            .iter()
            .map(|checkpoint| checkpoint.block_number)
            .collect::<Vec<_>>(),
        vec![5, 17]
    );
}

/// Rule 1, third half. A tree smaller than the watermark this wallet already
/// reached is refused, and the watermark does not move.
///
/// The regression: the gates read block heights and checkpoint hashes and
/// never the leaf count. A node can be on this wallet's chain, at a head above
/// every checkpoint it kept, and still answer `ZkTree::LeafCount` with less
/// than the wallet has scanned: the count is a statement about the state that
/// node has executed, and a node serving a head it has not finished executing
/// answers a short tree. The scan range `start..leaf_count` is then empty, so
/// the scan is skipped and `mark_vanished` with it, and the watermark is
/// written back down to the node's count. The store then claims to have
/// scanned less than it has, and the notes above the new watermark keep their
/// leaf indices with nothing left to check them against.
///
/// A fork cannot reach this gate: the rewind above takes the watermark back to
/// a checkpoint the node's own branch carries, and that checkpoint was written
/// at a block whose tree was at least that large. So a short tree is lag.
#[test]
fn a_leaf_count_below_the_watermark_is_refused_without_a_fork() {
    let dir = support::scratch_dir("short-tree");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let note = note_for(address.pk, 1_000, "short tree");
    let ct = ct_for(&address, &note, 7);

    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    put_leaf(&mut state, 5, 9, note.commitment(), &ct);
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.unspent_total(), 1_000);
    let before = serde_json::to_value(&wallet.store).expect("the store serializes");

    // The head moves forward, every checkpoint hash still stands, and the tree
    // is two leaves shorter than the wallet has already read.
    {
        let mut state = node.state();
        state.head_number = 12;
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(4));
    }
    let refused = wallet
        .sync(&chain, &metadata)
        .expect_err("a tree shorter than the watermark is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("behind this wallet"), "{message}");
    assert!(message.contains("4 leaves"), "{message}");
    assert!(message.contains("leaf 6"), "{message}");

    assert_eq!(
        wallet.store.next_leaf, 6,
        "the watermark never regresses outside the fork path"
    );
    assert_eq!(
        serde_json::to_value(&wallet.store).expect("the store serializes"),
        before,
        "a refused sync must not have written anything"
    );
    let reopened = Wallet::open(&seed).expect("the store reopens");
    assert_eq!(
        serde_json::to_value(&reopened.store).expect("the store serializes"),
        before
    );

    // The node finishes executing and the sync runs with nothing rewound.
    {
        let mut state = node.state();
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    }
    let report = wallet.sync(&chain, &metadata).expect("the sync runs again");
    assert_eq!(report.rewound_from, None);
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.unspent_total(), 1_000);
}

/// Rule 3, the ordering half. A refused sync leaves a fresh store bound to no
/// chain at all.
///
/// The regression: opening a wallet on a chain recorded the genesis and saved
/// it, before any gate had run. A store with no genesis yet takes the chain of
/// whichever node it is first pointed at, so a wallet opened against a node
/// that the very next check refused was left naming that node's chain
/// permanently. Every later sync against the right node then refused with a
/// mismatch the operator never chose, and the only way out was
/// `--new-chain-store`, which archives the file and starts over.
///
/// The binding belongs to the save that commits a sync, a shield or a send:
/// the chain a store belongs to is the chain whose answers it actually kept.
#[test]
fn a_refused_sync_leaves_a_fresh_store_bound_to_no_chain() {
    let dir = support::scratch_dir("refused-binding");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let store_path = store_path_for(&seed);

    let wrong = {
        let mut state = NodeState {
            head_number: 6,
            ..Default::default()
        };
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(2));
        FakeNode::start(state)
    };
    let wrong_rpc = RpcClient::new(&wrong.url);
    let wrong_chain = Chain::new(&wrong_rpc);

    let (mut wallet, binding) =
        Wallet::open_on_chain(&seed, &wrong_chain, false).expect("the wallet opens");
    assert_eq!(binding, ChainBinding::Unrecorded);
    assert!(
        !store_path.exists(),
        "opening a wallet on a chain must write nothing"
    );

    // This node's runtime does not declare a storage item the wallet hashes
    // into every key it reads, so the sync refuses before it reads a leaf.
    let mut drifted = test_metadata();
    drifted
        .storage
        .retain(|item| !(item.pallet == "ZkTree" && item.name == "LeafCount"));
    let refused = wallet
        .sync(&wrong_chain, &drifted)
        .expect_err("a drifted storage layout is refused");
    assert!(format!("{refused:#}").contains("LeafCount"));
    assert!(
        !store_path.exists(),
        "a refused sync must not have written a store, and so must not have bound one"
    );
    assert_eq!(wallet.store.genesis_hash, None);

    // The node the operator meant. It serves a different chain, and the store
    // is free to take it.
    let right = {
        let mut state = NodeState {
            head_number: 9,
            fork_from: 0,
            fork_tag: 9,
            ..Default::default()
        };
        state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(3));
        FakeNode::start(state)
    };
    let right_rpc = RpcClient::new(&right.url);
    let right_chain = Chain::new(&right_rpc);
    let right_genesis = hex::encode(right_chain.genesis_hash().expect("a genesis"));
    assert_ne!(
        right_genesis,
        hex::encode(wrong_chain.genesis_hash().expect("a genesis"))
    );

    let report = wallet
        .sync(&right_chain, &test_metadata())
        .expect("the store belongs to no chain, so it takes this one");
    assert!(report.recorded_genesis);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&store_path).expect("the store reads"))
            .expect("the store is JSON");
    assert_eq!(
        written["genesis_hash"],
        serde_json::Value::String(right_genesis)
    );
}

/// `--rescan` walks the whole tree again and keeps every note.
///
/// Two things it has to do, and a store written by an older build needs both.
/// That build refused the second note it met that shared a nullifier with one
/// it already held: it wrote a `rejected` entry, kept no copy of the note's
/// `rho` and `r`, and left the leaf below the watermark, where no later sync
/// reads it again. Nothing in the store upgrade can bring those secrets back,
/// because they were never in the file. They are on chain, inside the
/// ciphertext beside the commitment, so a walk from leaf zero recovers them.
///
/// And the notes already held stay held, which is the difference from deleting
/// the store: a note whose leaf the current chain no longer carries would
/// otherwise lose the secrets that are the only handle on a settlement that
/// can still be re-included. It is marked off chain instead, by the same rule
/// a fork rescan uses.
#[test]
fn a_rescan_recovers_a_leaf_below_the_watermark_and_keeps_every_note() {
    let dir = support::scratch_dir("rescan");
    let seed = dir.join("wallet.seed");
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    let address = wallet.address();

    let held = note_for(address.pk, 400, "still there");
    let orphaned = note_for(address.pk, 250, "gone from the chain");
    // The note an older build refused: the same `rho` and `r` as `held`, so
    // the same nullifier, and a larger value.
    let twin = Note::new(
        address.pk,
        1_000,
        Digest::hash_bytes(&[b"rho", b"still there".as_slice()]),
        Digest::hash_bytes(&[b"r", b"still there".as_slice()]),
    )
    .expect("a note sharing the nullifier");

    let mut state = NodeState {
        head_number: 10,
        ..Default::default()
    };
    put_leaf(
        &mut state,
        1,
        9,
        held.commitment(),
        &ct_for(&address, &held, 8),
    );
    put_leaf(
        &mut state,
        3,
        9,
        orphaned.commitment(),
        &ct_for(&address, &orphaned, 9),
    );
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &encode_u64(6));
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let metadata = test_metadata();

    wallet.sync(&chain, &metadata).expect("the first sync runs");
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.unspent_total(), 650);

    // Leaf 2 was always there and this wallet never read it: an older build
    // decrypted it, refused it as a duplicate nullifier and moved on. Leaf 3
    // is gone, its block orphaned and its settlement never re-included.
    {
        let mut state = node.state();
        put_leaf(
            &mut state,
            2,
            9,
            twin.commitment(),
            &ct_for(&address, &twin, 10),
        );
        state.remove_storage(&identity_map_key("ZkTree", "Leaves", 3));
        state.remove_storage(&identity_map_key("Shielded", "Ciphertexts", 3));
        state.remove_storage(&identity_map_key("Shielded", "LeafBlocks", 3));
        state.head_number = 11;
    }

    // An ordinary sync sees none of it: both leaves are below the watermark.
    let report = wallet.sync(&chain, &metadata).expect("the plain sync runs");
    assert_eq!(report.received, 0);
    assert_eq!(report.vanished, 0);
    assert_eq!(wallet.store.unspent_total(), 650);

    let report = wallet
        .sync_with(&chain, &metadata, SyncOptions { rescan: true })
        .expect("the rescan runs");
    assert_eq!(report.rewound_from, Some(6));
    assert_eq!(report.rewound_to, Some(0));
    assert_eq!(
        report.forked_at_block, None,
        "a rescan the operator asked for is not a fork and must not report one"
    );
    assert_eq!(report.received, 1, "the leaf below the watermark is read");
    assert_eq!(report.vanished, 1, "the leaf the chain dropped is marked");
    assert_eq!(wallet.store.next_leaf, 6);
    assert_eq!(wallet.store.last_synced_block, 11);

    // Every note is still held, the recovered one included.
    assert_eq!(wallet.store.notes.len(), 3);
    let recovered = wallet
        .store
        .notes
        .iter()
        .find(|note| note.commitment == twin.commitment().to_hex())
        .expect("the recovered note is held");
    assert_eq!(recovered.leaf_index, 2);
    assert_eq!(recovered.value, 1_000);
    assert!(wallet
        .store
        .notes
        .iter()
        .any(|note| note.commitment == orphaned.commitment().to_hex() && !note.on_chain));

    // The conflict set counts once, at the member a spend would use, and the
    // note the chain no longer carries counts in neither total.
    assert_eq!(wallet.store.unspent_total(), 1_000);
    assert_eq!(wallet.store.off_chain_total(), 250);
    let chosen = select_notes(wallet.store.spendable(), 900).expect("the spend is fundable");
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].commitment, twin.commitment().to_hex());
}
