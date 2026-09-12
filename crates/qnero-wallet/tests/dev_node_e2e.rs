//! The whole wallet against a running dev node.
//!
//! Skipped unless `QNERO_DEV_NODE` points at one, because it shields real
//! value, proves two private batches and waits for them to settle. Start a
//! node with `nice -n 19 ./chain/target/release/quantus-node --dev --tmp` and
//! run:
//!
//! ```text
//! QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 \
//!   cargo test -j 2 --release -p qnero-wallet --features parallel \
//!   --test dev_node_e2e -- --nocapture
//! ```
//!
//! Without `--features parallel` a private batch is about 20 seconds where
//! with it a batch is about 6, and the whole test grows from under a minute to
//! a few.

use std::fs;
use std::path::PathBuf;

use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::create_seed;
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::wallet::{EntryRhoCheck, MerkleSource, Wallet, NUM_LEAF_PROOFS};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qnero-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join(name);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(qnero_wallet::keys::store_path_for(&path));
    path
}

/// Shield into A, pay B, pay back from B, and check both wallets' books at
/// every step.
///
/// The last leg is the one that matters most: it spends a note B received,
/// where every earlier leg spends a note its own wallet created. That is the
/// whole point of the `rho` the circuit derives and the ciphertext the sender
/// wrote.
#[test]
fn a_shield_a_payment_and_a_payment_back_settle_end_to_end() {
    let Ok(node) = std::env::var("QNERO_DEV_NODE") else {
        eprintln!("QNERO_DEV_NODE is not set; skipping the dev-chain end-to-end test");
        return;
    };

    let rpc = RpcClient::new(&node);
    let chain = Chain::new(&rpc);
    let metadata = ChainMetadata::fetch(&rpc).expect("the node answers state_getMetadata");
    metadata
        .ensure_known_signed_extensions()
        .expect("the runtime's extensions are the ones this wallet lays out");
    metadata
        .ensure_known_storage()
        .expect("the runtime's storage layout is the one this wallet hashes");

    let alice_seed = scratch("alice.seed");
    let bob_seed = scratch("bob.seed");
    create_seed(&alice_seed).expect("a fresh seed");
    create_seed(&bob_seed).expect("a fresh seed");
    let mut alice = Wallet::open(&alice_seed).expect("wallet A opens");
    let mut bob = Wallet::open(&bob_seed).expect("wallet B opens");
    let bob_address = bob.address();
    let alice_address = alice.address();

    // Both wallets start from the tree as it stands, so the scan cost does not
    // grow with how long the node has been up before the test.
    alice.sync(&chain, &metadata).expect("A syncs");
    bob.sync(&chain, &metadata).expect("B syncs");
    assert_eq!(alice.store.unspent_total(), 0);
    assert_eq!(bob.store.unspent_total(), 0);

    let dev = TransparentKey::dev("alice").expect("the dev chain endows alice");
    let shielded = alice
        .shield(&chain, &metadata, &dev, 1_000, "first shield")
        .expect("the shield settles");
    println!(
        "shield of 1000 quanta included at block {} ({:.2?}), leaf {}",
        shielded.included_at, shielded.inclusion, shielded.leaf_index
    );
    // The leaf index is the dispatch confirmation: an included extrinsic
    // whose dispatch failed appends no leaf. And on an otherwise idle dev
    // chain this is the only shield in its block, so both halves of the entry
    // rule are decidable.
    assert_eq!(
        shielded.entry_check,
        EntryRhoCheck::Confirmed,
        "the entry rho prediction should hold for the only shield in a block"
    );
    alice.sync(&chain, &metadata).expect("A syncs the shield");
    assert_eq!(alice.store.unspent_total(), 1_000);
    assert_eq!(alice.store.notes.len(), 1);
    assert_eq!(alice.store.notes[0].memo, "first shield");

    // One prover for the whole test: building the circuits is seconds and
    // proving with them is tens of seconds.
    let prover = WalletProver::new(NUM_LEAF_PROOFS).expect("the circuits build");

    // The floor, computed from the ciphertexts this submission carries: two
    // of 1731 bytes plus a memo cost `MinLeafFee` plus one quantum per started
    // 512 bytes, and the fee is a public input so it cannot be raised after
    // proving.
    let memo = "payment to B";
    let fee = alice
        .preflight(&metadata, &bob_address, 300, None, memo)
        .expect("the spend is fundable");
    let payment = alice
        .send(
            &chain,
            &metadata,
            &prover,
            &bob_address,
            300,
            Some(fee),
            memo,
            MerkleSource::Local,
        )
        .expect("the payment settles");
    println!(
        "300 quanta to B: proved in {:.2?}, {} proof bytes, included at block {}",
        payment.proving, payment.proof_bytes, payment.included_at
    );
    assert_eq!(payment.change, 1_000 - 300 - fee);

    bob.sync(&chain, &metadata).expect("B syncs");
    assert_eq!(bob.store.unspent_total(), 300);
    assert_eq!(bob.store.notes.len(), 1);
    assert_eq!(bob.store.notes[0].memo, memo);

    alice.sync(&chain, &metadata).expect("A syncs");
    assert_eq!(alice.store.unspent_total(), payment.change);
    assert_eq!(
        alice.store.notes.iter().filter(|note| note.spent).count(),
        1,
        "the spent input must be marked"
    );

    // A note B received, spent by B. The `rho` came out of the circuit and the
    // value and randomness out of a ciphertext A wrote.
    let back_memo = "back to A";
    let back_fee = bob
        .preflight(&metadata, &alice_address, 100, None, back_memo)
        .expect("B can fund the payment back");
    let back = bob
        .send(
            &chain,
            &metadata,
            &prover,
            &alice_address,
            100,
            Some(back_fee),
            back_memo,
            MerkleSource::Local,
        )
        .expect("the payment back settles");
    println!(
        "100 quanta back to A: proved in {:.2?}, included at block {}",
        back.proving, back.included_at
    );

    bob.sync(&chain, &metadata).expect("B syncs");
    assert_eq!(bob.store.unspent_total(), 300 - 100 - back_fee);
    alice.sync(&chain, &metadata).expect("A syncs");
    assert_eq!(alice.store.unspent_total(), payment.change + 100);
    assert!(alice
        .store
        .notes
        .iter()
        .any(|note| note.memo == back_memo && !note.spent));

    // Nothing was refused on either side: a duplicate nullifier would mean a
    // note this wallet cannot spend.
    assert!(alice.store.rejected.is_empty());
    assert!(bob.store.rejected.is_empty());
}
