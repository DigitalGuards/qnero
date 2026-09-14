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
//! note_digests(seed, v, rho, r)        the commitment and the nullifier of a held note
//! coinbase_note(seed, genesis, block)  the miner-key derivation a scan rebuilds from
//! header_block_hash(anchor)            the anchor check, before a proof is paid for
//! tree_path(leaves, depth, index)      the local rebuild that names no leaf to the node
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
pub mod wallet;

use wasm_bindgen::prelude::*;

pub use prove::CHAIN_NUM_LEAVES;

/// `initThreadPool(threads)`, present only in the threaded module.
///
/// It spawns that many Web Workers over one `SharedArrayBuffer`-backed linear
/// memory and hands them to rayon. The page calls it once, after `init()` and
/// before anything is proved; a page that skips it gets a rayon pool of one,
/// which is the single-threaded module with extra steps.
///
/// Its absence is how a loader tells the two modules apart at runtime, which
/// is why it is re-exported here rather than left where the macro put it.
#[cfg(feature = "threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

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

/// The anchor header's own hash, recomputed from the preimage the chain
/// hashes.
///
/// A wallet checks this against `chain_getBlockHash` before it proves. See
/// [`wallet::header_block_hash_hex`].
#[wasm_bindgen(js_name = headerBlockHash)]
pub fn header_block_hash(anchor_json: &str) -> Result<String, JsError> {
    wallet::header_block_hash_hex(anchor_json).map_err(js_error)
}

/// Rebuild the commitment tree over a leaf range and take one leaf's path.
///
/// `leaf_hashes` is `32 * n` bytes, `ZkTree::Leaves` in index order read at
/// one block hash, and `depth` is `ZkTree::Depth` read at that same hash.
/// See [`wallet::tree_path_json`].
#[wasm_bindgen(js_name = treePath)]
pub fn tree_path(leaf_hashes: &[u8], depth: usize, leaf_index: usize) -> Result<String, JsError> {
    wallet::tree_path_json(leaf_hashes, depth, leaf_index).map_err(js_error)
}

/// The root a rebuild reaches, with no path taken: the gate against the
/// header's `zkTreeRoot`.
#[wasm_bindgen(js_name = treeRoot)]
pub fn tree_root(leaf_hashes: &[u8], depth: usize) -> Result<String, JsError> {
    wallet::tree_root_hex(leaf_hashes, depth).map_err(js_error)
}

/// The smallest tree depth that holds a leaf count.
#[wasm_bindgen(js_name = depthFor)]
pub fn depth_for(leaf_count: usize) -> Result<usize, JsError> {
    wallet::depth_for(leaf_count).map_err(js_error)
}

/// The adapter from `zkTree_getMerkleProof`'s shape to the circuit's.
///
/// Opt in only: fetching a proof names the leaf being spent to whoever runs
/// the node. See [`wallet::path_from_unsorted_json`].
#[wasm_bindgen(js_name = pathFromUnsorted)]
pub fn path_from_unsorted(unsorted_json: &str, leaf_hex: &str) -> Result<String, JsError> {
    wallet::path_from_unsorted_json(unsorted_json, leaf_hex).map_err(js_error)
}

/// The commitment and the nullifier of a note this seed owns.
///
/// The nullifier is as sensitive as the note: for an unspent note it has
/// appeared nowhere, so it must not reach a log, a URL or an error message.
/// See [`wallet::note_digests_json`].
#[wasm_bindgen(js_name = noteDigests)]
pub fn note_digests(
    seed_hex: &str,
    value: u64,
    rho_hex: &str,
    r_hex: &str,
) -> Result<String, JsError> {
    wallet::note_digests_json(seed_hex, value, rho_hex, r_hex).map_err(js_error)
}

/// The coinbase note this seed's miner key mints at one height on one chain.
#[wasm_bindgen(js_name = coinbaseNote)]
pub fn coinbase_note(
    seed_hex: &str,
    genesis_hash_hex: &str,
    block_number: u32,
    value: u64,
) -> Result<String, JsError> {
    wallet::coinbase_note_json(seed_hex, genesis_hash_hex, block_number, value).map_err(js_error)
}

/// `rho = H(RHO_ENTRY, block_number, entry_index)`, the shield rule.
#[wasm_bindgen(js_name = entryRho)]
pub fn entry_rho(block_number: u32, entry_index: u64) -> String {
    wallet::entry_rho_hex(block_number, entry_index)
}

/// The `qnm1...` a node is configured with. Secret bearing: it carries the
/// coinbase viewing key, so it is not the address and must be labelled.
#[wasm_bindgen(js_name = minerKey)]
pub fn miner_key(seed_hex: &str) -> Result<String, JsError> {
    wallet::miner_key_hex(seed_hex).map_err(js_error)
}

/// What a leaf's `ct_digest` public input commits to.
#[wasm_bindgen(js_name = ctDigest)]
pub fn ct_digest(ct_1: &[u8], ct_2: &[u8]) -> String {
    wallet::ct_digest_hex(ct_1, ct_2)
}

/// Whether a string decodes as an address of this chain.
#[wasm_bindgen(js_name = addressIsValid)]
pub fn address_is_valid(address: &str) -> bool {
    wallet::address_is_valid(address)
}

/// The constants a wallet must not keep a second copy of: the memo pad, the
/// fixed ciphertext size, the depth cap and the chain's leaf-slot count.
#[wasm_bindgen(js_name = walletLimits)]
pub fn wallet_limits() -> String {
    wallet::wallet_limits_json()
}

/// A memo's padded length, or a refusal naming the pad.
#[wasm_bindgen(js_name = memoFits)]
pub fn memo_fits(memo: &str) -> Result<usize, JsError> {
    wallet::memo_fits(memo).map_err(js_error)
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
