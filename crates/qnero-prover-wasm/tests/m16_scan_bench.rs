//! M16 measurement harness: what one ciphertext costs a wallet scan, natively.
//!
//! This is the native twin of the browser's `decryptNote`, so the wasm column
//! measured in `www/run-scan.mjs` has something to be a ratio of, and it is
//! also where the two fixture ciphertexts that harness loops over are written.
//!
//! ```text
//! RAYON_NUM_THREADS=1 cargo test --release -p qnero-prover-wasm \
//!   --test m16_scan_bench -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Two shapes are timed, because they answer different questions.
//!
//! * The wallet's own per-leaf step, which is what `qnero-wallet` runs inside
//!   its scan loop (`wallet.rs::try_transfer`): parse the bytes, decapsulate,
//!   open the two AEAD payloads, rebuild the note and compare its commitment.
//!   The incoming viewing key is derived once, outside the clock, because a
//!   scan derives it once and then walks a chain.
//! * `scan::decrypt_note_json`, the body of the browser's `decryptNote`, which
//!   takes a seed rather than a key and therefore runs an ML-KEM key
//!   generation per ciphertext. That is the call the browser harness times, so
//!   it is the one the wasm ratio is computed against.
//!
//! Ignored by default: thousands of lattice operations do not belong in a
//! gate.

use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use qnero_notes::{decrypt_note, NoteCiphertext};
use qnero_prover_wasm::fixture::synthetic_transfer_request;
use qnero_prover_wasm::request::{spending_key_from_hex, TransferRequest};
use qnero_prover_wasm::scan::{decrypt_note_json, derive_account_json};

/// The wallet whose scan this measures. `www/worker.js` addresses its
/// synthetic transfer's first output to this seed.
const WALLET_SEED: &str = "32";
/// The sender of the ciphertext this wallet owns.
const SENDER_SEED: &str = "31";
/// A second pair, so the ciphertext that is not ours is genuinely addressed
/// elsewhere rather than being our own bytes read with the wrong key.
const STRANGER_SENDER_SEED: &str = "33";
const STRANGER_RECIPIENT_SEED: &str = "34";

const RUNS: usize = 5000;
const DERIVE_RUNS: usize = 2000;

fn seed(tag: &str) -> String {
    tag.repeat(32)
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a duration"));
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        values[middle]
    } else {
        (values[middle - 1] + values[middle]) / 2.0
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn stderr(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = mean(values);
    let variance = values
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / (values.len() - 1) as f64;
    (variance / values.len() as f64).sqrt()
}

fn percentile(mut values: Vec<f64>, fraction: f64) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a duration"));
    let index = ((values.len() - 1) as f64 * fraction).round() as usize;
    values[index]
}

fn line(label: &str, values: &[f64], total_micros: f64) {
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    println!(
        "{label}: n {}, mean {:.2} us (stderr {:.2}), median {:.2} us, p95 {:.2} us, \
         min {:.2} us, max {:.2} us, loop total/n {:.2} us, rate {:.0}/s",
        values.len(),
        mean(values),
        stderr(values),
        median(values.to_vec()),
        percentile(values.to_vec(), 0.95),
        min,
        max,
        total_micros,
        1_000_000.0 / total_micros,
    );
}

fn bench<T>(runs: usize, mut body: impl FnMut(usize) -> T) -> (Vec<f64>, f64) {
    for index in 0..8 {
        black_box(body(index));
    }
    let mut samples = Vec::with_capacity(runs);
    let whole = Instant::now();
    for index in 0..runs {
        let started = Instant::now();
        let value = body(index);
        samples.push(started.elapsed().as_secs_f64() * 1e6);
        black_box(value);
    }
    let total = whole.elapsed().as_secs_f64() * 1e6 / runs as f64;
    (samples, total)
}

/// One output ciphertext, addressed to `recipient`, from a synthetic transfer
/// `sender` builds. `outputs[0]` is the recipient's; `outputs[1]` is the
/// change note back to the sender.
fn ciphertext_to(sender: &str, recipient: &str) -> Vec<u8> {
    let json = synthetic_transfer_request(&seed(sender), &seed(recipient), 2)
        .expect("the fixture builds");
    let request: TransferRequest = serde_json::from_str(&json).expect("the fixture parses");
    let prepared = request.prepare().expect("the request prepares");
    let outputs = prepared.encrypt_outputs().expect("the outputs encrypt");
    outputs[0].ciphertext.clone()
}

#[test]
#[ignore = "thousands of decapsulations; this is the M16 measurement"]
fn one_ciphertext_through_a_wallet_scan() {
    println!("--- qnero-prover-wasm note scan, native, single threaded, M16 ---");

    let wallet_seed = seed(WALLET_SEED);
    let mine = ciphertext_to(SENDER_SEED, WALLET_SEED);
    let stranger = ciphertext_to(STRANGER_SENDER_SEED, STRANGER_RECIPIENT_SEED);

    let ivk = spending_key_from_hex(&wallet_seed)
        .expect("the seed parses")
        .incoming_viewing_key();

    // Both ciphertexts have to behave the way the labels claim before any
    // timing of them means anything.
    let parsed_mine = NoteCiphertext::from_bytes(&mine).expect("our ciphertext parses");
    let parsed_stranger =
        NoteCiphertext::from_bytes(&stranger).expect("the stranger's ciphertext parses");
    let received = decrypt_note(&ivk, &parsed_mine).expect("our ciphertext opens");
    assert!(
        decrypt_note(&ivk, &parsed_stranger).is_err(),
        "the stranger's ciphertext must not open under this key"
    );
    let commitment = received.commitment;
    println!(
        "ciphertexts: ours {} bytes, the stranger's {} bytes, note value {}",
        mine.len(),
        stranger.len(),
        received.note.value
    );

    // The wallet's per-leaf step, viewing key already derived.
    let (ours, ours_total) = bench(RUNS, |_| {
        let parsed = NoteCiphertext::from_bytes(black_box(&mine)).expect("parses");
        match decrypt_note(&ivk, &parsed) {
            Ok(received) => received.commitment == commitment,
            Err(_) => false,
        }
    });
    line(
        "wallet per-leaf step, ciphertext addressed to this wallet",
        &ours,
        ours_total,
    );

    let (theirs, theirs_total) = bench(RUNS, |_| {
        let parsed = NoteCiphertext::from_bytes(black_box(&stranger)).expect("parses");
        decrypt_note(&ivk, &parsed).is_ok()
    });
    line(
        "wallet per-leaf step, ciphertext addressed elsewhere",
        &theirs,
        theirs_total,
    );

    // The browser's call, which takes a seed and so derives the key per
    // ciphertext.
    let (json_ours, json_ours_total) = bench(RUNS, |_| {
        decrypt_note_json(black_box(&wallet_seed), black_box(&mine), "").expect("opens")
    });
    line(
        "decrypt_note_json (the decryptNote body), ours",
        &json_ours,
        json_ours_total,
    );

    let (json_theirs, json_theirs_total) = bench(RUNS, |_| {
        decrypt_note_json(black_box(&wallet_seed), black_box(&stranger), "").is_err()
    });
    line(
        "decrypt_note_json (the decryptNote body), the stranger's",
        &json_theirs,
        json_theirs_total,
    );

    // `deriveAccount`'s body, so the browser harness's third row has a twin
    // too. It is one ML-KEM key generation plus the note key tree plus the
    // encapsulation key the address carries, which is another parse of the
    // expanded secret key.
    let (account, account_total) = bench(DERIVE_RUNS, |_| {
        derive_account_json(black_box(&wallet_seed)).expect("derives")
    });
    line(
        "derive_account_json (the deriveAccount body)",
        &account,
        account_total,
    );

    // What the difference between those two pairs is made of: the key
    // derivation, which is an ML-KEM key generation plus the note key tree.
    let (derive, derive_total) = bench(DERIVE_RUNS, |_| {
        spending_key_from_hex(black_box(&wallet_seed))
            .expect("parses")
            .incoming_viewing_key()
    });
    line(
        "incoming viewing key derivation from a seed",
        &derive,
        derive_total,
    );

    write_browser_fixture(&wallet_seed, &mine, &stranger);
}

/// The two ciphertexts, where `www/scan-worker.js` can fetch them.
///
/// `www/results/` is gitignored, which is where every other measurement
/// artifact of this harness lands, and `server.mjs` serves the whole
/// directory, so the page reads it at `./results/m16-scan-ciphertexts.json`.
fn write_browser_fixture(wallet_seed: &str, mine: &[u8], stranger: &[u8]) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("www")
        .join("results");
    fs::create_dir_all(&directory).expect("the results directory");
    let path = directory.join("m16-scan-ciphertexts.json");
    let body = serde_json::json!({
        "generated_by": "crates/qnero-prover-wasm/tests/m16_scan_bench.rs",
        "wallet_seed": wallet_seed,
        "mine_hex": hex::encode(mine),
        "stranger_hex": hex::encode(stranger),
        "mine_bytes": mine.len(),
        "stranger_bytes": stranger.len(),
    });
    fs::write(&path, serde_json::to_vec_pretty(&body).expect("serializes"))
        .expect("the fixture is written");
    println!("wrote {}", path.display());
}
