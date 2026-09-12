//! `N` is resolved from the environment, the way the pallet's build script
//! resolves it.
//!
//! `chain/pallets/shielded/build.rs` reads `QNERO_NUM_LEAF_PROOFS` and falls
//! back to the builder default. The wallet reads the same variable through
//! `option_env!`, and this line is what makes Cargo rebuild the crate when it
//! changes: one environment then produces one `N` on both sides, and a wallet
//! cannot quietly prove at six against a runtime built at eight.
fn main() {
    println!("cargo:rerun-if-env-changed=QNERO_NUM_LEAF_PROOFS");
}
