//! A Qnero wallet's proving path, compiled for a browser.
//!
//! This crate is the only `wasm-bindgen` surface in the workspace, and it is
//! the whole of what a browser wallet needs to move value: derive an address
//! from a seed, decrypt a ciphertext while scanning, and prove one private
//! batch. It is the M8 measurement subject, so the numbers in `docs/BENCH.md`
//! came out of exactly this module.
//!
//! ```text
//! entropy_self_check()                 draw from both entropy paths, once, at startup
//! derive_account(seed)                 address and the public half of the key tree
//! decrypt_note(seed, ct, commitment)   one scan step
//! WasmWalletProver.fromSource(n)       build both circuits from compiled code
//! WasmWalletProver.fromArtifacts(..)   build them, with the padding leaf supplied
//!   .proveTransfer(request)            one leaf, one private batch, one verify
//!   .verifyProof(bytes)
//! proveZkLeaf(request)                 the delegated-batcher shape, measured
//! linearMemoryBytes() / peakLinearMemoryBytes() / lastCallMemoryGrowthBytes()
//! ```
//!
//! # Threading
//!
//! Single threaded, by construction. No `parallel` feature is enabled anywhere
//! below this crate: rayon-core spawns `std::thread`, which on
//! `wasm32-unknown-unknown` without the atomics target feature fails at
//! runtime, and a useful rayon pool needs a SharedArrayBuffer, which needs
//! cross-origin isolation on whatever origin the wallet is served from.
//! `tests/no_parallel.rs` asserts the dependency tree stays rayon-free rather
//! than trusting nobody to flip a feature.
//!
//! # Run it in a Worker
//!
//! Proving a private batch is tens of seconds. On the main thread that is a
//! frozen tab, and a frozen tab on iOS is a tab the OS may reclaim. Build the
//! prover once per worker and keep it: every method takes `&self` for that
//! reason, and in wasm it matters more than it does natively, because linear
//! memory never shrinks and a second prover adds its gigabyte to a peak that is
//! already sticky for the life of the worker.
//!
//! # What zeroize buys here, and what it does not
//!
//! `SpendingKey`, `Secret` and the rest still zero their own storage on drop,
//! and that is all the guarantee there is. wasm linear memory is a JS
//! `ArrayBuffer` the host can read at any time; it is never paged to swap,
//! never core-dumped, and not unmapped when a `Vec` drops. A seed that arrives
//! as a JS string has already been copied into a heap this module does not
//! own. Treat the browser as the trust boundary, and the zeroizing as defence
//! against this module's own reuse of freed memory.
//!
//! # Errors
//!
//! Nothing from plonky2 reaches JS. A witness desync is routine for a wallet
//! (a stale path after a reorg, an index off by one) and plonky2 reports one by
//! naming the two conflicting field elements, which are a note's amount or the
//! limbs that place it in the tree; `qnero-prover` drops that error and this
//! crate never reconstructs it. What error strings here can quote is the
//! request's own fields, which the caller already holds. They are still not
//! safe to log: a console line outlives the call and a crash reporter uploads
//! it.

#![forbid(unsafe_code)]

pub mod clock;
pub mod fixture;
pub mod memory;
pub mod prove;
pub mod random;
pub mod request;
pub mod scan;

use wasm_bindgen::prelude::*;

pub use prove::CHAIN_NUM_LEAVES;

/// Turn an internal error into one JS can throw.
///
/// One funnel, so the redaction rule in the crate docs has one place to hold.
fn js_error(error: anyhow::Error) -> JsError {
    JsError::new(&error.to_string())
}

/// Draw from both entropy paths and refuse to go on if either is dead.
///
/// Call this once when the worker starts, before offering to prove anything.
/// See [`random::entropy_self_check`] for why a browser that cannot draw
/// randomness otherwise fails tens of seconds into a proof.
#[wasm_bindgen(js_name = entropySelfCheck)]
pub fn entropy_self_check() -> Result<(), JsError> {
    random::entropy_self_check().map_err(js_error)
}

/// The chain's leaf slots per private batch.
#[wasm_bindgen(js_name = chainNumLeaves)]
pub fn chain_num_leaves() -> usize {
    CHAIN_NUM_LEAVES
}

/// Linear memory this module currently holds, in bytes.
#[wasm_bindgen(js_name = linearMemoryBytes)]
pub fn linear_memory_bytes() -> f64 {
    memory::linear_memory_bytes() as f64
}

/// The largest linear memory this module has held since it was instantiated.
///
/// wasm linear memory never shrinks, so this is a high-water mark that stays
/// true for the life of the worker.
#[wasm_bindgen(js_name = peakLinearMemoryBytes)]
pub fn peak_linear_memory_bytes() -> f64 {
    memory::peak_bytes() as f64
}

/// How much linear memory the last proving call added to what it found.
///
/// There is no per-call peak to report: the mark is module-wide and linear
/// memory never shrinks, so a second call reads the first call's memory back.
/// This is the growth, which is a lower bound on what the same call needs in a
/// fresh worker. [`peak_linear_memory_bytes`] is the figure that sizes the
/// worker itself.
#[wasm_bindgen(js_name = lastCallMemoryGrowthBytes)]
pub fn last_call_memory_growth_bytes() -> f64 {
    memory::last_call_growth_bytes() as f64
}

/// The public half of a key tree, as JSON. See [`scan::derive_account_json`].
#[wasm_bindgen(js_name = deriveAccount)]
pub fn derive_account(seed_hex: &str) -> Result<String, JsError> {
    scan::derive_account_json(seed_hex).map_err(js_error)
}

/// One scan step: decrypt a ciphertext this seed might own.
///
/// Returns JSON carrying the note's value, `rho`, `r`, its commitment and the
/// memo with its padding stripped. That is the plaintext the ciphertext hides,
/// so it is exactly as sensitive as the note itself, and keeping it out of a
/// log is the caller's job. See [`scan::decrypt_note_json`].
#[wasm_bindgen(js_name = decryptNote)]
pub fn decrypt_note(
    seed_hex: &str,
    ciphertext: &[u8],
    expected_commitment_hex: &str,
) -> Result<String, JsError> {
    scan::decrypt_note_json(seed_hex, ciphertext, expected_commitment_hex).map_err(js_error)
}

/// What a browser wallet submits: one private-batch proof and the two output
/// ciphertexts that belong to it.
#[wasm_bindgen]
pub struct WasmSubmission {
    proof: Vec<u8>,
    ct_1: Vec<u8>,
    ct_2: Vec<u8>,
    report: String,
}

#[wasm_bindgen]
impl WasmSubmission {
    /// The private batch proof, plonky2's canonical encoding. This is the
    /// transaction.
    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Vec<u8> {
        self.proof.clone()
    }

    /// The ciphertext of output slot 1, which belongs to `cm_out_1`.
    #[wasm_bindgen(getter, js_name = ct1)]
    pub fn ct_1(&self) -> Vec<u8> {
        self.ct_1.clone()
    }

    /// The ciphertext of output slot 2.
    #[wasm_bindgen(getter, js_name = ct2)]
    pub fn ct_2(&self) -> Vec<u8> {
        self.ct_2.clone()
    }

    /// Public inputs, per-phase timings and linear memory, as JSON.
    #[wasm_bindgen(getter, js_name = reportJson)]
    pub fn report_json(&self) -> String {
        self.report.clone()
    }
}

/// Both circuits, built once and kept.
#[wasm_bindgen]
pub struct WasmWalletProver {
    inner: qnero_prover::WalletProver,
    build_report: String,
}

/// Redacting `Debug`, matching every other type that holds circuit data or
/// touches a spend credential.
impl core::fmt::Debug for WasmWalletProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WasmWalletProver")
            .field("num_leaves", &self.inner.num_leaves())
            .finish()
    }
}

#[wasm_bindgen]
impl WasmWalletProver {
    /// Build both circuits from the compiled code, reading nothing.
    ///
    /// This is the honest default for a browser: it removes the fetch, the
    /// cache invalidation and the pinning surface entirely. It costs one
    /// padding-leaf prove more than [`Self::from_artifacts`], which is noise
    /// against the circuit build.
    #[wasm_bindgen(js_name = fromSource)]
    pub fn from_source(num_leaves: usize) -> Result<WasmWalletProver, JsError> {
        let built = prove::build_from_source(num_leaves).map_err(js_error)?;
        Ok(Self {
            inner: built.prover,
            build_report: serde_json::to_string(&built.build).unwrap_or_else(|_| "{}".to_string()),
        })
    }

    /// Build from a published artifact set: `leaf_verifier.bin` and
    /// `padding_leaf_proof.bin`.
    ///
    /// Both are pinned to a canonical rebuild before either reaches the
    /// circuit, so a poisoned CDN copy is caught here rather than settled.
    #[wasm_bindgen(js_name = fromArtifacts)]
    pub fn from_artifacts(
        leaf_verifier: &[u8],
        padding_leaf_proof: &[u8],
        num_leaves: usize,
    ) -> Result<WasmWalletProver, JsError> {
        let built = prove::build_from_artifacts(leaf_verifier, padding_leaf_proof, num_leaves)
            .map_err(js_error)?;
        Ok(Self {
            inner: built.prover,
            build_report: serde_json::to_string(&built.build).unwrap_or_else(|_| "{}".to_string()),
        })
    }

    /// Leaf slots per batch.
    #[wasm_bindgen(getter, js_name = numLeaves)]
    pub fn num_leaves(&self) -> usize {
        self.inner.num_leaves()
    }

    /// What building the circuits cost, as JSON.
    #[wasm_bindgen(getter, js_name = buildReportJson)]
    pub fn build_report_json(&self) -> String {
        self.build_report.clone()
    }

    /// Prove one transfer and return what a wallet submits.
    ///
    /// `request_json` is [`request::TransferRequest`]. The leaf proof stays
    /// inside this call.
    #[wasm_bindgen(js_name = proveTransfer)]
    pub fn prove_transfer(&self, request_json: &str) -> Result<WasmSubmission, JsError> {
        let request: request::TransferRequest =
            serde_json::from_str(request_json).map_err(|error| {
                JsError::new(&format!("the transfer request does not parse: {error}"))
            })?;
        let submission = prove::prove_transfer(&self.inner, &request).map_err(js_error)?;
        let [ct_1, ct_2] = submission.ciphertexts;
        Ok(WasmSubmission {
            proof: submission.proof,
            ct_1,
            ct_2,
            report: serde_json::to_string(&submission.report).unwrap_or_else(|_| "{}".to_string()),
        })
    }

    /// Verify a private-batch proof against this prover's own circuit, and
    /// return what it cost in milliseconds.
    #[wasm_bindgen(js_name = verifyProof)]
    pub fn verify_proof(&self, proof: &[u8]) -> Result<f64, JsError> {
        prove::verify(&self.inner, proof).map_err(js_error)
    }
}

/// A synthetic transfer request, for the harness.
///
/// A browser cannot build one: a request names a Merkle path into a tree whose
/// root the header commits to, and both are Poseidon2 over Goldilocks. See
/// [`fixture`] for what the fixture is and is not.
#[wasm_bindgen(js_name = syntheticTransferRequest)]
pub fn synthetic_transfer_request(
    seed_hex: &str,
    recipient_seed_hex: &str,
    decoys: usize,
) -> Result<String, JsError> {
    fixture::synthetic_transfer_request(seed_hex, recipient_seed_hex, decoys).map_err(js_error)
}

/// Build a zero-knowledge leaf circuit and prove one transfer with it, for the
/// measurement only.
///
/// The proof is not returned. A ZK leaf is the artifact a phone could hand to
/// somebody else's batcher, and whether to build that path is a decision
/// `docs/DESIGN.md` section 8 argues, with its privacy cost stated. This
/// function answers what it would cost in time and memory, and nothing else.
#[wasm_bindgen(js_name = proveZkLeaf)]
pub fn prove_zk_leaf(request_json: &str) -> Result<String, JsError> {
    let request: request::TransferRequest = serde_json::from_str(request_json)
        .map_err(|error| JsError::new(&format!("the transfer request does not parse: {error}")))?;
    let report = prove::prove_zk_leaf(&request).map_err(js_error)?;
    serde_json::to_string(&report).map_err(|error| JsError::new(&error.to_string()))
}
