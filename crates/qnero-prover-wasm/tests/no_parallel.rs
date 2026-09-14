//! The threading guard.
//!
//! rayon enters this crate's dependency tree the moment `qnero-prover/parallel`,
//! `qnero-aggregator/parallel` or `qp-plonky2/parallel` is set, and rayon-core
//! spawns `std::thread`, which on `wasm32-unknown-unknown` without the atomics
//! target feature fails at runtime.
//!
//! One feature is allowed to reach it, `threads`, and it is off by default. It
//! exists because a threaded module needs a `std` rebuilt with `+atomics` and
//! `+bulk-memory` and an origin that is cross-origin isolated, and none of
//! that is something a manifest edit can supply: see
//! `scripts/build-threaded-wasm.sh`. What this test asserts is that no *other*
//! feature reaches rayon, and in particular that `default` does not, so the
//! module a page falls back to cannot acquire a thread spawn by accident.
//!
//! The other half of the guard runs at build time:
//! `scripts/build-wasm.sh` refuses to publish a single-threaded module when
//! `cargo tree --target wasm32-unknown-unknown -p qnero-prover-wasm` mentions
//! rayon. It lives there rather than here because a test that shells out to
//! cargo deadlocks against the cargo that is running it.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// The one feature allowed to reach rayon, and the line that declares it.
const THREADS_FEATURE: &str = "threads = ";

#[test]
fn only_the_threads_feature_reaches_rayon() {
    for line in MANIFEST.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(THREADS_FEATURE) {
            continue;
        }
        assert!(
            !line.contains("parallel"),
            "a `parallel` feature other than `threads` reaches rayon, which cannot spawn a \
             thread in this target without a std rebuilt for it: {line}"
        );
    }
}

/// `default` is the module a page without cross-origin isolation falls back
/// to, and it must stay serial.
#[test]
fn the_default_feature_set_is_empty() {
    let default = MANIFEST
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("default = "))
        .expect("the manifest declares a default feature set");
    assert_eq!(default, "default = []", "{default}");
}
