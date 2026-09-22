//! M16 measurement harness: what one ML-KEM-1024 operation costs.
//!
//! `docs/BENCH.md` names the decapsulation unmeasured twice and every
//! wallet-scan figure in `docs/DESIGN.md` 12.6 is parametric on it. This file
//! is the native half of the answer, through the crate's own API, the one the
//! note channel calls.
//!
//! ```text
//! RAYON_NUM_THREADS=1 cargo test --release -p qnero-pqcrypto \
//!   --test m16_ml_kem_bench -- --ignored --nocapture --test-threads 1
//! ```
//!
//! Ignored by default: thousands of lattice operations do not belong in a
//! gate. Nothing below uses rayon; `RAYON_NUM_THREADS` is set only to say that
//! the figure is one thread's.
//!
//! Two decapsulation rows, because `MlKemSecretKey::decapsulate` parses the
//! 3168-byte expanded key on every call before it touches a lattice. A wallet
//! scanning a chain pays that parse per ciphertext today, so the wrapper row is
//! the one a scan budget is built from, and the raw row says how much of it is
//! the KEM itself.

use std::hint::black_box;
use std::time::Instant;

use qnero_pqcrypto::ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPublicKey, MlKemSecretKey};
use qnero_pqcrypto::traits::{KemKeyPair, KemPublicKey};

/// Five thousand, which is the floor this measurement was asked for. One
/// operation is hundreds of microseconds, so this is seconds of work per row
/// and the mean is pinned to well under a percent.
const RUNS: usize = 5000;

/// Key generation is the expensive one and it is here only for reference, so
/// it runs fewer times.
const KEYGEN_RUNS: usize = 1000;

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

/// One row, in microseconds. `total_micros` is the wall clock of the whole
/// loop divided by the run count, which carries no per-sample clock overhead
/// and is the figure a rate is computed from.
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

/// Run `runs` timed iterations of `body`, returning the per-call samples in
/// microseconds and the whole loop's wall clock divided by the run count.
fn bench<T>(runs: usize, mut body: impl FnMut(usize) -> T) -> (Vec<f64>, f64) {
    // A warm-up pass, so the first sample is not the one that faults the code
    // and the tables in.
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

#[test]
#[ignore = "thousands of lattice operations; this is the M16 measurement"]
fn ml_kem_1024_encapsulate_and_decapsulate() {
    println!("--- qnero-pqcrypto ML-KEM-1024, single threaded, M16 ---");

    let keypair = MlKemKeyPair::generate_deterministic(b"qnero/m16/ml-kem-1024-bench");
    let public: MlKemPublicKey = keypair.public_key();
    let secret: &MlKemSecretKey = keypair.secret_key();
    let (ciphertext, expected) = public.encapsulate(b"qnero/m16/encapsulation-randomness");

    // The answer has to be right before its cost means anything.
    let opened = secret.decapsulate(&ciphertext).expect("decapsulation");
    assert_eq!(opened.as_bytes(), expected.as_bytes());

    let (decapsulate, decapsulate_total) = bench(RUNS, |_| {
        secret
            .decapsulate(black_box(&ciphertext))
            .expect("decapsulation")
    });
    line(
        "decapsulate, crate API (expanded-key parse included)",
        &decapsulate,
        decapsulate_total,
    );

    let (encapsulate, encapsulate_total) = bench(RUNS, |index| {
        let seed = (index as u64).to_le_bytes();
        public.encapsulate(black_box(&seed))
    });
    line(
        "encapsulate, crate API (public-key parse included)",
        &encapsulate,
        encapsulate_total,
    );

    let (keygen, keygen_total) = bench(KEYGEN_RUNS, |index| {
        let seed = (index as u64).to_le_bytes();
        MlKemKeyPair::generate_deterministic(black_box(&seed))
    });
    line("keygen, crate API", &keygen, keygen_total);

    // The same ciphertext through the ml-kem crate directly, with the
    // decapsulation key parsed once outside the clock. The gap against the row
    // above is what the wrapper's per-call `from_expanded` costs.
    {
        use ml_kem::array::Array;
        use ml_kem::kem::Decapsulate;
        use ml_kem::{DecapsulationKey, MlKem1024};

        let mut seed_bytes = [0u8; 64];
        for (index, byte) in seed_bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let seed: ml_kem::Seed = Array::try_from(seed_bytes.as_slice()).expect("size");
        let raw_dk = DecapsulationKey::<MlKem1024>::from_seed(seed);
        let raw_ek = raw_dk.encapsulation_key();
        let message: Array<u8, _> = Array::try_from([7u8; 32].as_slice()).expect("size");
        let (raw_ct, _raw_ss) = raw_ek.encapsulate_deterministic(&message);

        let (raw, raw_total) = bench(RUNS, |_| raw_dk.decapsulate(black_box(&raw_ct)));
        line(
            "decapsulate, ml-kem 0.3.2 directly (key parsed once)",
            &raw,
            raw_total,
        );
    }

    println!(
        "sizes: ciphertext {} bytes, public key {} bytes, secret key {} bytes",
        ciphertext.as_bytes().len(),
        public.as_bytes().len(),
        secret.to_bytes().len(),
    );
    let _ = MlKemCiphertext::from_bytes(ciphertext.as_bytes()).expect("round trip");
}
