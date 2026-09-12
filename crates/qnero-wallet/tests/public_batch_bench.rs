//! The public batch at the chain default, `n = 53` over `N = 6`, measured
//! once against a live chain.
//!
//! M4 left this open: the public batch had been *built* at `n = 53`, which is
//! what a runtime embeds a verifier for, and never *proved* at that size. So
//! its proof length against the pallet's 512 KiB size gate was an estimate and
//! its proving cost was an extrapolation from upstream, and nothing said what
//! happens when one is actually submitted.
//!
//! Ignored, and it needs a dev node:
//!
//! ```text
//! QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 \
//!   cargo test -j 2 --release -p qnero-wallet --features parallel \
//!   --test public_batch_bench -- --ignored --nocapture
//! ```
//!
//! It writes the proof to `QNERO_PUBLIC_BATCH_PROOF` (default
//! `target/qnero-public-batch-53.bin`) so the pallet's own ignored test can
//! time the embedded verifier over the same bytes.
//!
//! The anchor window is the thing to watch. A segment must name a block inside
//! `BlockHashWindow`, 256 blocks, so everything between taking the anchor and
//! submitting has to fit inside it: the inner private batch's proving, the
//! public batch's proving, and the wait for inclusion. The circuit builds
//! happen before the anchor is taken, deliberately.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use qnero_aggregator::{Proof, PublicBatchInputs, QneroPublicBatchProver};
use qnero_circuit::config::qnero_public_batch_circuit_config;
use qnero_notes::Digest;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::extrinsic::encode_submit_public_batch;
use qnero_wallet::keys::create_seed;
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::{hex_0x, RpcClient};
use qnero_wallet::wallet::{MerkleSource, Wallet, NUM_LEAF_PROOFS};

/// The chain default: `chain/pallets/shielded/build.rs` reads it from the same
/// constant.
const NUM_INNER: usize = qnero_circuit_builder::DEFAULT_NUM_PRIVATE_BATCH_PROOFS;

#[test]
#[ignore]
fn public_batch_cost_at_the_chain_default() {
    let Ok(node) = std::env::var("QNERO_DEV_NODE") else {
        eprintln!("QNERO_DEV_NODE is not set; skipping the public-batch measurement");
        return;
    };
    println!(
        "measuring a public batch of n = {NUM_INNER} inner private batches of N = \
         {NUM_LEAF_PROOFS} leaf slots"
    );
    println!(
        "parallel feature: {}, RAYON_NUM_THREADS: {}",
        cfg!(feature = "parallel"),
        std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into())
    );

    let rpc = RpcClient::new(&node);
    let chain = Chain::new(&rpc);
    let metadata = ChainMetadata::fetch(&rpc).expect("the node answers state_getMetadata");

    // Every circuit build happens before the anchor is taken: the 256-block
    // window has to cover the proving and the inclusion, and nothing else.
    let started = Instant::now();
    let prover = WalletProver::new(NUM_LEAF_PROOFS).expect("the wallet circuits build");
    println!("leaf + private batch build   {:.2?}", started.elapsed());

    let started = Instant::now();
    let padding_batch = prover
        .padding_batch_proof()
        .expect("the all-padding private batch proves");
    println!("padding private batch prove  {:.2?}", started.elapsed());

    let private_verifier = prover.batch_verifier_data();
    let started = Instant::now();
    let public = QneroPublicBatchProver::new(
        qnero_public_batch_circuit_config(),
        private_verifier.common.clone(),
        &private_verifier.verifier_only,
        NUM_INNER,
        NUM_LEAF_PROOFS,
        padding_batch,
    )
    .expect("the public batch circuit builds");
    println!("public batch build           {:.3?}", started.elapsed());

    // One real inner: a genuine private batch spending a real note, anchored
    // at a real block, which is exactly what `submit_private_batch` would take
    // on its own. The other 52 slots are filled with the padding template by
    // `prove_batch`.
    let seed = std::env::temp_dir().join(format!("qnero-public-batch-{}.seed", std::process::id()));
    let _ = fs::remove_file(&seed);
    let _ = fs::remove_file(qnero_wallet::keys::store_path_for(&seed));
    create_seed(&seed).expect("a fresh seed");
    let mut wallet = Wallet::open(&seed).expect("the wallet opens");
    wallet.sync(&chain, &metadata).expect("the wallet syncs");
    let dev = TransparentKey::dev("alice").expect("the dev chain endows alice");
    wallet
        .shield(&chain, &metadata, &dev, 1_000, "public batch bench")
        .expect("the shield settles");
    wallet
        .sync(&chain, &metadata)
        .expect("the wallet syncs the shield");
    assert_eq!(wallet.store.unspent_total(), 1_000);

    let recipient = wallet.address();
    let prepared = wallet
        .prepare_spend(
            &chain,
            &metadata,
            &prover,
            &recipient,
            100,
            None,
            "inner",
            MerkleSource::Local,
        )
        .expect("the inner private batch proves");
    println!(
        "inner private batch prove    {:.2?} ({} bytes, anchored at block {})",
        prepared.proving,
        prepared.proof.len(),
        prepared.anchor_block
    );

    let inner = Proof::from_bytes(prepared.proof.clone(), &private_verifier.common)
        .expect("the inner proof deserializes");
    let aggregator_address = Digest::hash_bytes(&[b"qnero-wallet/bench-aggregator"]);

    let started = Instant::now();
    let batch = public
        .prove_batch(PublicBatchInputs {
            proofs: vec![inner],
            aggregator_address,
        })
        .expect("the public batch proves");
    let prove = started.elapsed();
    let bytes = batch.to_bytes();
    println!("public batch prove           {:.3?}", prove);
    println!("public batch proof           {} bytes", bytes.len());
    println!(
        "public inputs                {} felts",
        batch.public_inputs.len()
    );

    // Three verifies, because the first one in this process is not
    // representative: it runs against a heap holding the whole public-batch
    // circuit, and its first-touch cost is not what a node pays. The pallet's
    // own ignored test is the figure that matters; this one says how far the
    // two are apart and why.
    for sample in 0..3 {
        let started = Instant::now();
        public
            .verify(batch.clone(), &aggregator_address)
            .expect("the public batch verifies");
        println!(
            "public batch verify {sample}        {:.2?}",
            started.elapsed()
        );
    }

    let out = std::env::var("QNERO_PUBLIC_BATCH_PROOF")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/qnero-public-batch-53.bin")
        });
    fs::write(&out, &bytes).expect("the proof is written");
    println!("proof written to             {}", out.display());

    // The submission. One real slot in one real inner, so `outputs` carries
    // exactly one `ShieldedOutput`: every real leaf slot of every settleable
    // segment, and a padding segment settles nothing at all.
    let encoded = encode_submit_public_batch(&metadata, &bytes, &prepared.outputs)
        .expect("the runtime's extrinsic format version takes a bare preamble");
    println!("extrinsic                    {} bytes", encoded.len());
    let started = Instant::now();
    let head_before = chain.head().expect("a head").number;
    chain
        .submit_extrinsic(&encoded)
        .expect("the node admits the public batch");
    let included_at = wait_for(&chain, &hex_0x(&encoded), head_before);
    println!(
        "included                     block {included_at} after {:.2?}",
        started.elapsed()
    );

    let included_hash = chain.block_hash(included_at).expect("the inclusion block");
    let settled = chain
        .nullifiers_used(&prepared.nullifiers, &included_hash)
        .expect("the nullifier probe");
    assert!(
        settled[0] && settled[1],
        "the public batch was included and its segment settled nothing"
    );
    println!("settled                      both nullifiers of the real slot");

    let _ = fs::remove_file(&seed);
}

fn wait_for(chain: &Chain, extrinsic_hex: &str, from_block: u32) -> u32 {
    let deadline = Instant::now() + std::time::Duration::from_secs(180);
    let mut next = from_block + 1;
    loop {
        let head = chain.head().expect("a head").number;
        while next <= head {
            let hash = chain.block_hash(next).expect("a block hash");
            if chain
                .block_extrinsics(&hash)
                .expect("a block")
                .iter()
                .any(|encoded| encoded == extrinsic_hex)
            {
                return next;
            }
            next += 1;
        }
        assert!(
            Instant::now() < deadline,
            "the public batch was not included within 180 seconds"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
