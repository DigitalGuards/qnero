//! The threading guard.
//!
//! rayon enters this crate's dependency tree the moment `qnero-prover/parallel`,
//! `qnero-aggregator/parallel` or `qp-plonky2/parallel` is set, and rayon-core
//! spawns `std::thread`, which on `wasm32-unknown-unknown` without the atomics
//! target feature fails at runtime. So the rule is that this crate declares no
//! feature that reaches one, and this test is what stops the rule from being
//! quietly relaxed in a manifest nobody re-reads.
//!
//! The other half of the guard runs at build time:
//! `scripts/build-wasm.sh` refuses to publish a module when
//! `cargo tree --target wasm32-unknown-unknown -p qnero-prover-wasm` mentions
//! rayon. It lives there rather than here because a test that shells out to
//! cargo deadlocks against the cargo that is running it.

const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn this_crate_declares_no_feature_that_reaches_rayon() {
    for line in MANIFEST.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        assert!(
            !line.contains("parallel"),
            "a `parallel` feature reaches rayon, which cannot spawn a thread in this target: {line}"
        );
    }
}
