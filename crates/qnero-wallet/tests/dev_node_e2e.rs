//! The whole wallet against a running dev node.
//!
//! Skipped unless `QNERO_DEV_NODE` points at one, because it shields real
//! value, proves two private batches and waits for them to settle. Start a
//! node with `nice -n 19 ./chain/target/release/qnero-node --dev --tmp` and
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

use codec::Encode;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::create_seed;
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::wallet::{EntryRhoCheck, MerkleSource, Wallet, NUM_LEAF_PROOFS};

/// `pallet-balances` and its first call. Stable indices in this runtime, and
/// `runtime/tests/call_filter.rs` is what fails if either moves.
const BALANCES_PALLET_INDEX: u8 = 2;
const TRANSFER_ALLOW_DEATH_CALL_INDEX: u8 = 0;
const REVERSIBLE_PALLET_INDEX: u8 = 11;
const SET_HIGH_SECURITY_CALL_INDEX: u8 = 0;
const VESTING_PALLET_INDEX: u8 = 22;
const CLAIM_CALL_INDEX: u8 = 0;

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

/// The v1 end state, against a running chain: the block author is paid in
/// notes, those notes spend like any other, and a transparent transfer is
/// refused by the call filter.
///
/// Needs a node started with this wallet's miner key, so the seed comes from
/// the environment rather than being made here:
///
/// ```text
/// qnero-wallet --file /tmp/qnero-m6/miner.seed keygen
/// QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6/miner.seed miner-address) \
///   nice -n 19 ./chain/target/release/qnero-node --dev --tmp
/// QNERO_DEV_NODE=http://127.0.0.1:9944 \
///   QNERO_MINER_SEED=/tmp/qnero-m6/miner.seed RAYON_NUM_THREADS=4 nice -n 19 \
///   cargo test -j 2 --release -p qnero-wallet --features parallel \
///   --test dev_node_e2e -- --nocapture
/// ```
#[test]
fn the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused() {
    let Ok(node) = std::env::var("QNERO_DEV_NODE") else {
        eprintln!("QNERO_DEV_NODE is not set; skipping the dev-chain end-to-end test");
        return;
    };
    let Ok(miner_seed) = std::env::var("QNERO_MINER_SEED") else {
        eprintln!("QNERO_MINER_SEED is not set; skipping the coinbase end-to-end test");
        return;
    };

    let rpc = RpcClient::new(&node);
    let chain = Chain::new(&rpc);
    let metadata = ChainMetadata::fetch(&rpc).expect("the node answers state_getMetadata");
    let mut miner =
        Wallet::open(std::path::Path::new(&miner_seed)).expect("the miner wallet opens");
    println!("miner address {}", miner.address().encode());

    // The coinbase notes of every block this node has authored so far.
    let report = miner.sync(&chain, &metadata).expect("the miner syncs");
    println!(
        "sync: {} leaves, {} coinbase leaves, {} of them this wallet's, {} quanta",
        report.leaves_scanned,
        report.coinbase_leaves,
        report.coinbase_received,
        miner.store.unspent_total()
    );
    assert!(
        report.coinbase_received > 0,
        "the node must be mining for this wallet"
    );
    assert_eq!(
        report.coinbase_received, report.coinbase_leaves,
        "every block on a one-miner dev chain is this wallet's"
    );
    for note in &miner.store.notes {
        assert_eq!(
            note.origin,
            qnero_wallet::store::NoteOrigin::Coinbase,
            "the only notes a miner holds before it spends are its coinbases"
        );
    }
    // The emission is flat over a few blocks, to within the one quantum the
    // sub-quantum carry adds: a block's credit is not a whole number of pool
    // quanta, so the remainder waits and occasionally completes one.
    let ordinary = |wallet: &Wallet, except: Option<u32>| -> (u64, u64) {
        let values: Vec<u64> = wallet
            .store
            .notes
            .iter()
            .filter(|note| {
                note.origin == qnero_wallet::store::NoteOrigin::Coinbase
                    && note.block_number != except
            })
            .map(|note| note.value)
            .collect();
        (
            *values.iter().min().expect("a coinbase note"),
            *values.iter().max().expect("a coinbase note"),
        )
    };
    let (low, high) = ordinary(&miner, None);
    assert!(
        high - low <= 1,
        "the emission moves by at most the carry: {low} to {high}"
    );

    // A payment out of a mined note, to a wallet that has never been paid.
    let recipient_seed = scratch("m6-recipient.seed");
    create_seed(&recipient_seed).expect("a fresh seed");
    let mut recipient = Wallet::open(&recipient_seed).expect("wallet B opens");
    let recipient_address = recipient.address();
    let prover = WalletProver::new(NUM_LEAF_PROOFS).expect("the circuits build");

    let memo = "mined and spent";
    let fee = miner
        .preflight(&metadata, &recipient_address, 5, None, memo)
        .expect("the spend is fundable");
    let payment = miner
        .send(
            &chain,
            &metadata,
            &prover,
            &recipient_address,
            5,
            Some(fee),
            memo,
            MerkleSource::Local,
        )
        .expect("the payment settles");
    println!(
        "5 quanta to B at fee {fee}: included at block {}, change {}",
        payment.included_at, payment.change
    );

    recipient.sync(&chain, &metadata).expect("B syncs");
    assert_eq!(recipient.store.unspent_total(), 5);
    assert_eq!(recipient.store.notes.len(), 1);
    assert_eq!(recipient.store.notes[0].memo, memo);

    // The author's share of that fee is in the coinbase note of the block that
    // settled it, and in no other.
    miner
        .sync(&chain, &metadata)
        .expect("the miner syncs the settlement");
    let author_share = fee - fee.div_ceil(2);
    let settling = miner
        .store
        .notes
        .iter()
        .find(|note| {
            note.origin == qnero_wallet::store::NoteOrigin::Coinbase
                && note.block_number == Some(payment.included_at)
        })
        .expect("the settling block minted a coinbase note");
    let (low, high) = ordinary(&miner, Some(payment.included_at));
    println!(
        "coinbase of block {}: {} quanta against {low} to {high} elsewhere, author share {}",
        payment.included_at, settling.value, author_share
    );
    assert!(
        settling.value >= low + author_share && settling.value <= high + author_share,
        "the settling block's coinbase carries the author's share of the fee: {} against \
         {low}..={high} plus {author_share}",
        settling.value
    );
    assert!(
        author_share > 1,
        "the fee must be large enough to tell from the carry"
    );

    // A transparent transfer between two dev accounts, signed properly and
    // refused by the runtime's call filter.
    let alice = TransparentKey::dev("alice").expect("the dev chain endows alice");
    let bob_account = TransparentKey::dev("bob")
        .expect("a dev account")
        .account_id();
    let mut call = vec![BALANCES_PALLET_INDEX, TRANSFER_ALLOW_DEATH_CALL_INDEX];
    call.push(0x00); // MultiAddress::Id
    call.extend_from_slice(&bob_account);
    call.extend_from_slice(&codec::Compact(1_000_000_000_000u128).encode());
    let sign = |call: &[u8], nonce: u32| {
        let context = qnero_wallet::extrinsic::SigningContext {
            spec_version: chain.runtime_version().expect("a version").0,
            transaction_version: chain.runtime_version().expect("a version").1,
            genesis_hash: chain.genesis_hash().expect("a genesis hash"),
            nonce,
            tip: 0,
        };
        qnero_wallet::extrinsic::encode_signed(&metadata, &alice, call, &context)
            .expect("the call encodes")
    };
    let nonce = chain.account_nonce(&alice.account_id()).expect("a nonce");
    let transfer = sign(&call, nonce);

    // `Ok(Err(DispatchError::Module { index: 0, error: [5, 0, 0, 0] }))`:
    // frame_system is pallet 0 and `CallFiltered` is its sixth error.
    const CALL_FILTERED: &str = "0x0001030005000000";
    let mut skipped_dry_run = false;
    match rpc.call_as::<String>(
        "system_dryRun",
        serde_json::json!([qnero_wallet::rpc::hex_0x(&transfer)]),
    ) {
        Ok(dry_run) => {
            println!("system_dryRun of a transparent transfer: {dry_run}");
            assert_eq!(
                dry_run, CALL_FILTERED,
                "a transparent transfer must be refused with CallFiltered"
            );
        }
        Err(error) => {
            // The node is serving safe RPC methods only. Submit it instead:
            // the filter refuses at dispatch, so the extrinsic is admitted and
            // included and the transfer does not happen.
            println!("system_dryRun unavailable ({error}); submitting instead");
            skipped_dry_run = true;
            let before = free_balance(&rpc, &bob_account);
            chain
                .submit_extrinsic(&transfer)
                .expect("the pool admits it");
            let head = chain.head().expect("a head").number;
            while chain.head().expect("a head").number < head + 3 {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            assert_eq!(
                free_balance(&rpc, &bob_account),
                before,
                "a transparent transfer must move nothing"
            );
        }
    }

    if skipped_dry_run {
        return;
    }

    // Enrolling in high security is refused too. The call moves nothing, and
    // it is one way: an account that took it would be held to a whitelist
    // whose every value-moving call this chain refuses, with no call that
    // undoes the enrolment.
    let mut enrol = vec![REVERSIBLE_PALLET_INDEX, SET_HIGH_SECURITY_CALL_INDEX];
    enrol.push(0x00); // BlockNumberOrTimestamp::BlockNumber
    enrol.extend_from_slice(&10u32.encode());
    enrol.extend_from_slice(&bob_account);
    let dry_run = rpc
        .call_as::<String>(
            "system_dryRun",
            serde_json::json!([qnero_wallet::rpc::hex_0x(&sign(&enrol, nonce))]),
        )
        .expect("the node dry-runs");
    println!("system_dryRun of set_high_security: {dry_run}");
    assert_eq!(
        dry_run, CALL_FILTERED,
        "enrolling in high security must be refused with CallFiltered"
    );

    // A vesting claim is not refused. It is the genesis distribution channel:
    // the pot cannot sign, no schedule can be created under v1, and a claim
    // pays a beneficiary fixed at genesis. What comes back is the vesting
    // pallet's own answer about this particular schedule, which is the proof
    // that the filter was not what stopped it.
    let mut claim = vec![VESTING_PALLET_INDEX, CLAIM_CALL_INDEX];
    claim.extend_from_slice(&0u64.encode());
    let dry_run = rpc
        .call_as::<String>(
            "system_dryRun",
            serde_json::json!([qnero_wallet::rpc::hex_0x(&sign(&claim, nonce))]),
        )
        .expect("the node dry-runs");
    println!("system_dryRun of a vesting claim: {dry_run}");
    // Decoded and pinned against the pallet index this test built the call
    // with. "anything but CallFiltered" would pass on a decode failure too,
    // which is exactly what a drifted `VESTING_PALLET_INDEX` or a moved call
    // index produces, and the test would go on reporting that the genesis
    // allocation is claimable while proving nothing.
    //
    // `system_dryRun` returns `Result<Result<(), DispatchError>, _>` in SCALE:
    // `00` for the outer Ok, then `00` for a successful dispatch or `01 03`
    // for `Err(DispatchError::Module)` followed by the module's own index and
    // its four-byte error. The dev chain's schedules are all inside their
    // 90-day cliff, so what comes back is pallet-vesting's own answer, which
    // is the proof that the filter was not what stopped it.
    let decoded = hex::decode(dry_run.trim_start_matches("0x")).expect("the node returns hex");
    match decoded.as_slice() {
        [0x00, 0x00] => println!("the claim dispatched: this signer has a claimable schedule"),
        [0x00, 0x01, 0x03, index, error @ ..] if error.len() >= 4 => {
            assert_eq!(
                *index, VESTING_PALLET_INDEX,
                "the claim came back from module {index} and this test built it for \
                 pallet {VESTING_PALLET_INDEX}: either the index drifted or the call \
                 never reached pallet-vesting ({dry_run})"
            );
            println!("pallet-vesting answered with error {}", error[0]);
        }
        _ => panic!(
            "a genesis vesting allocation must stay claimable, and this is neither a \
             dispatch nor a pallet-vesting error: {dry_run}"
        ),
    }
}

/// One account's free balance, straight out of `System::Account`.
fn free_balance(rpc: &RpcClient, account: &[u8; 32]) -> u128 {
    use codec::Decode;
    let key = qnero_wallet::scale::blake2_128_concat_map_key("System", "Account", account);
    let Some(bytes) = rpc.storage(&key, None).expect("the node answers") else {
        return 0;
    };
    // `AccountInfo`: nonce (u32), consumers, providers, sufficients (u32 each),
    // then `AccountData` whose first field is the free balance.
    let mut cursor = &bytes[16..];
    u128::decode(&mut cursor).expect("a balance")
}
