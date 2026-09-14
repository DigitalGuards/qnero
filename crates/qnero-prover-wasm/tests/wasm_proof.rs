//! The acceptance gate: a proof the browser produced verifies natively.
//!
//! The circuits are deterministic and no floating point is involved, so a
//! wasm-produced private batch has to verify against the same artifact set a
//! runtime embeds. If it does not, something in the feature graph diverged, and
//! the likely culprits are the `zk` feature (a batch that does not blind is a
//! privacy failure that still proves) or a plonky2 version skew between the two
//! builds.
//!
//! ```text
//! cd crates/qnero-prover-wasm/www && node run.mjs --runs 1 --mode source --no-zk
//! QNERO_WASM_PROOF=www/results/private_batch-source-n6-nozk-x1.proof \
//! QNERO_ARTIFACT_DIR=www/artifacts \
//!   cargo test -p qnero-prover-wasm --release --test wasm_proof -- --ignored --nocapture
//! ```
//!
//! The runner writes one proof per invocation shape and no fixed name, and the
//! name carries the `N` it was proved at. That is deliberate: this test's only
//! failure message is that the proof did not verify, so a run at another `N`
//! leaving its proof under a name this test reads would report a slot-count
//! mismatch as a feature-graph divergence.
//!
//! Ignored rather than skipped-when-unset: a test that passes because its input
//! was missing is worse than no test.

use std::path::PathBuf;

use qnero_circuit::batch_layout::private_batch_pi_len;
use qnero_prover_wasm::CHAIN_NUM_LEAVES;
use qnero_verifier::QneroPrivateBatchVerifier;

/// `pallet-shielded` refuses a settlement blob above this before it is copied
/// or parsed.
const MAX_PROOF_BYTES: usize = 512 * 1024;

fn from_env(name: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} must name the file this test verifies")),
    )
}

#[test]
#[ignore = "needs a proof produced by the browser harness; see the module docs"]
fn a_browser_proof_verifies_against_the_runtime_artifact() {
    let proof = std::fs::read(from_env("QNERO_WASM_PROOF")).expect("the proof file reads");
    let artifacts = from_env("QNERO_ARTIFACT_DIR");
    let verifier_bytes =
        std::fs::read(artifacts.join("private_batch_verifier.bin")).expect("the verifier reads");

    println!("proof: {} bytes", proof.len());
    assert!(
        proof.len() <= MAX_PROOF_BYTES,
        "a settlement blob over MAX_PROOF_BYTES is refused before it is parsed"
    );

    let verifier =
        QneroPrivateBatchVerifier::from_artifact_bytes(&verifier_bytes, CHAIN_NUM_LEAVES)
            .expect("the runtime's own verifier loads");
    let public = verifier.verify_proof_bytes(&proof).unwrap_or_else(|error| {
        panic!(
            "a proof the browser produced does not verify natively at N = \
                 {CHAIN_NUM_LEAVES}: {error}. Either the two builds' feature graphs diverged, \
                 or this proof was produced at another slot count; \
                 QNERO_WASM_PROOF names the run it came from."
        )
    });

    assert_eq!(
        public.slots.len(),
        CHAIN_NUM_LEAVES,
        "every slot is published, padding included"
    );
    let real: Vec<_> = public
        .slots
        .iter()
        .filter(|slot| !slot.is_padding())
        .collect();
    assert_eq!(real.len(), 1, "the harness proves one transfer");
    println!(
        "verified: {} slots, {} real, {} public input felts",
        public.slots.len(),
        real.len(),
        private_batch_pi_len(CHAIN_NUM_LEAVES)
    );
}
