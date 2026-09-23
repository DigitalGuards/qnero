//! The JSON a browser hands the prover, and the witness it becomes.
//!
//! JSON rather than a `wasm-bindgen` object graph, because the alternative is
//! `serde-wasm-bindgen` or a hand-written `JsValue` walk for a request a
//! wallet builds once per payment. `serde_json` is already in the dependency
//! graph (`qnero_aggregator::config`), so this adds nothing to the module.
//!
//! Every digest is lowercase hex of 32 bytes, which is what `Digest::to_hex`
//! writes and what the chain's own JSON-RPC returns.
//!
//! # What this module deliberately does not accept
//!
//! `kem_randomness`. `qnero_notes::encrypt_note` takes it from the caller and enforces
//! nothing about it: two outputs encrypted under one seed share a
//! ChaCha20-Poly1305 key and nonce, which publishes the XOR of the two
//! plaintexts and the authentication key. A browser that drew it once and
//! reused it would be a silent privacy break with no error and a valid proof,
//! so it is drawn here, per output, and there is no way to pass one in.

use anyhow::{bail, ensure, Context, Result};
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::{MerklePath, SIBLINGS_PER_LEVEL};
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{Address, Digest, Note, SpendingKey};
use serde::{Deserialize, Serialize};

use crate::random::{random_digest, random_seed};

/// One transfer, as a browser wallet describes it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    /// The 32-byte spending seed, hex. Everything else derives from it.
    pub seed: String,
    /// The block this spend anchors to, as its preimage rather than its hash:
    /// the circuit recomputes `block_hash = Poseidon2(preimage)` and publishes
    /// the result, so a wallet that only had the hash could not prove.
    pub anchor: AnchorRequest,
    /// Depth of the commitment tree the anchor's `zk_tree_root` belongs to.
    pub tree_depth: usize,
    /// One or two notes to spend. One real note leaves the second slot to a
    /// freshly randomized dummy.
    pub inputs: Vec<InputRequest>,
    /// Exactly two, in slot order: `ct_1` belongs to `cm_out_1`.
    pub outputs: Vec<OutputRequest>,
    pub fee: u64,
}

/// A header preimage, field for field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorRequest {
    pub parent_hash: String,
    pub block_number: u32,
    /// Blake2-256, taken as raw bytes and reduced mod p by
    /// [`HeaderInputs::new`], which is what the chain does with it.
    pub state_root: String,
    /// Blake2-256, taken as raw bytes and reduced mod p by
    /// [`HeaderInputs::new`], which is what the chain does with it.
    pub extrinsics_root: String,
    pub zk_tree_root: String,
    /// The digest logs the chain encodes, hex, exactly
    /// [`DIGEST_LOGS_SIZE`] bytes.
    pub digest_logs: String,
}

/// One note being spent, with the path that proves it is in the tree.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRequest {
    pub value: u64,
    pub rho: String,
    pub r: String,
    pub path: PathRequest,
}

/// A Merkle path in the form the circuit consumes: siblings already sorted,
/// plus the slot the running hash occupies among them.
///
/// `MerklePath::from_unsorted` is the adapter from the shape
/// `pallet-zk-tree`'s `generate_proof` returns. A browser that fetched a proof
/// from a node runs it before filling this in.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRequest {
    pub siblings: Vec<Vec<String>>,
    pub positions: Vec<u8>,
}

/// One output note: who it pays, how much, and the memo that rides with it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    /// bech32m, `qn1...`. Carries both `pk` and the ML-KEM encapsulation key.
    pub address: String,
    pub value: u64,
    /// Optional, hex. Drawn from the browser's CSPRNG when absent, which is
    /// what a wallet should do; a fixed value is for a reproducible harness.
    #[serde(default)]
    pub r: Option<String>,
    /// Padded to `qnero_notes::MEMO_BYTES` before it is encrypted, so every
    /// ciphertext this crate writes is one length.
    #[serde(default)]
    pub memo: String,
}

/// What one output turned into: the ciphertext a submission carries for it.
pub struct PreparedOutput {
    pub ciphertext: Vec<u8>,
}

/// The public half of a submission, for the caller that has to build the
/// extrinsic around it.
#[derive(Debug, Serialize)]
pub struct SubmissionPublicInputs {
    pub block_hash: String,
    pub block_number: u32,
    pub nullifiers: [String; 2],
    pub commitments: [String; 2],
    pub fee: u64,
    pub ct_digest: String,
}

/// Parse 32 raw bytes from hex, with no rule about what they encode.
pub fn bytes32_from_hex(what: &str, value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .with_context(|| format!("{what} is not hex"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is not 32 bytes"))
}

/// Parse a 32-byte digest from hex.
pub fn digest_from_hex(what: &str, value: &str) -> Result<Digest> {
    let bytes = bytes32_from_hex(what, value)?;
    Digest::from_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("{what} is not four canonical Goldilocks limbs"))
}

/// Take the seed out of its hex, leaving nothing behind.
///
/// [`SpendingKey::take_from`] wipes the caller's buffer, so the only copy that
/// outlives this call is the one inside the key, which zeroes on drop. What no
/// Rust type can undo is the JS string the seed arrived in: a `String` in the
/// JS heap is the host's to keep, and wasm linear memory is a JS
/// `ArrayBuffer` the host can read at any time. The crate docs say so; this is
/// the boundary where it stops being avoidable.
pub fn spending_key_from_hex(seed_hex: &str) -> Result<SpendingKey> {
    let decoded = hex::decode(seed_hex.trim()).context("the seed is not hex")?;
    ensure!(decoded.len() == 32, "the seed must be 32 bytes");
    let mut bytes: [u8; 32] = decoded.try_into().expect("length checked");
    Ok(SpendingKey::take_from(&mut bytes))
}

impl AnchorRequest {
    /// The circuit's view of this header.
    ///
    /// `parent_hash` and `zk_tree_root` are Poseidon2 outputs, so they take
    /// the strict decode: four canonical Goldilocks limbs or a refusal.
    /// `state_root` and `extrinsics_root` are Blake2-256 outputs and go in as
    /// raw bytes, because the chain reduces them mod p and validates neither.
    /// A Blake2 output has an 8-byte little-endian limb at or above p about
    /// once every four billion blocks, and the strict decode used to refuse
    /// those headers: a browser wallet that could not anchor at all until the
    /// chain moved on, where the chain, the node and
    /// `crates/qnero-wallet/src/chain.rs` all hash them happily.
    pub fn to_header(&self) -> Result<HeaderInputs> {
        let digest_logs = hex::decode(&self.digest_logs).context("digest_logs is not hex")?;
        ensure!(
            digest_logs.len() == DIGEST_LOGS_SIZE,
            "digest_logs must be {DIGEST_LOGS_SIZE} bytes, got {}",
            digest_logs.len()
        );
        HeaderInputs::new(
            digest_from_hex("anchor.parent_hash", &self.parent_hash)?,
            self.block_number,
            bytes32_from_hex("anchor.state_root", &self.state_root)?,
            bytes32_from_hex("anchor.extrinsics_root", &self.extrinsics_root)?,
            digest_from_hex("anchor.zk_tree_root", &self.zk_tree_root)?,
            &digest_logs,
        )
    }
}

impl PathRequest {
    pub fn to_path(&self, index: usize) -> Result<MerklePath> {
        ensure!(
            self.siblings.len() == self.positions.len(),
            "input {index} path has {} sibling levels and {} positions",
            self.siblings.len(),
            self.positions.len()
        );
        let mut siblings = Vec::with_capacity(self.siblings.len());
        for (level, level_siblings) in self.siblings.iter().enumerate() {
            ensure!(
                level_siblings.len() == SIBLINGS_PER_LEVEL,
                "input {index} path level {level} has {} siblings, expected {SIBLINGS_PER_LEVEL}",
                level_siblings.len()
            );
            let mut sorted =
                [Digest::from_bytes(&[0u8; 32]).expect("zero is canonical"); SIBLINGS_PER_LEVEL];
            for (slot, sibling) in level_siblings.iter().enumerate() {
                sorted[slot] = digest_from_hex(
                    &format!("input {index} path level {level} sibling {slot}"),
                    sibling,
                )?;
            }
            siblings.push(sorted);
        }
        Ok(MerklePath {
            siblings,
            positions: self.positions.clone(),
        })
    }
}

/// A witness and the addresses its outputs were built for, so the caller can
/// encrypt to them once the outputs' `rho` values exist.
pub struct PreparedTransfer {
    pub witness: SpendWitness,
    pub output_addresses: [Address; 2],
    pub output_memos: [String; 2],
}

impl TransferRequest {
    /// Build the witness, with a placeholder `ct_digest`.
    ///
    /// The digest cannot be filled in yet: it covers ciphertexts that carry a
    /// `rho` the witness derives from its own nullifiers, so the witness has
    /// to exist before the ciphertexts do. Nothing is proved in between; see
    /// [`crate::prove::prove_transfer`].
    pub fn prepare(&self) -> Result<PreparedTransfer> {
        ensure!(
            (1..=2).contains(&self.inputs.len()),
            "a leaf spends one or two notes, got {}",
            self.inputs.len()
        );
        ensure!(
            self.outputs.len() == 2,
            "a leaf writes exactly two outputs, got {}",
            self.outputs.len()
        );

        let key = spending_key_from_hex(&self.seed)?;
        let derived = key.derived();
        let pk = key.pk();
        let header = self.anchor.to_header()?;

        let mut inputs = Vec::with_capacity(2);
        for (index, input) in self.inputs.iter().enumerate() {
            let note = Note::new(
                pk,
                input.value,
                digest_from_hex(&format!("input {index} rho"), &input.rho)?,
                digest_from_hex(&format!("input {index} r"), &input.r)?,
            )
            .map_err(|error| anyhow::anyhow!("input {index} is not a valid note: {error}"))?;
            let path = input.path.to_path(index)?;
            inputs.push(InputNote::real(&derived, &note, path)?);
        }
        if inputs.len() == 1 {
            // `dummy_random` draws `(rho, r)` from the CSPRNG. A repeated pair
            // publishes a nullifier the chain has already settled and the whole
            // submission is refused, naming a value no wallet can map to a note
            // it holds.
            inputs.push(InputNote::dummy_random(
                &mut crate::random::rng(),
                &derived,
                self.tree_depth,
            ));
        }
        let inputs: [InputNote; 2] = inputs
            .try_into()
            .map_err(|_| anyhow::anyhow!("a leaf has two input slots"))?;

        let mut addresses = Vec::with_capacity(2);
        let mut outputs = Vec::with_capacity(2);
        let mut memos = Vec::with_capacity(2);
        for (index, output) in self.outputs.iter().enumerate() {
            let address = Address::decode(output.address.trim())
                .map_err(|error| anyhow::anyhow!("output {index} address: {error}"))?;
            let r = match &output.r {
                Some(hex) => digest_from_hex(&format!("output {index} r"), hex)?,
                None => random_digest(b"qnero-wasm/out-r")?,
            };
            outputs.push(OutputNote::new(address.pk, output.value, r));
            memos.push(output.memo.clone());
            addresses.push(address);
        }
        let outputs: [OutputNote; 2] = outputs
            .try_into()
            .map_err(|_| anyhow::anyhow!("a leaf has two output slots"))?;
        let output_addresses: [Address; 2] = addresses
            .try_into()
            .map_err(|_| anyhow::anyhow!("a leaf has two output slots"))?;
        let output_memos: [String; 2] = memos
            .try_into()
            .map_err(|_| anyhow::anyhow!("a leaf has two output slots"))?;

        let witness = SpendWitness {
            header,
            depth: self.tree_depth,
            inputs,
            outputs,
            fee: self.fee,
            ct_digest: Digest::from_bytes(&[0u8; 32]).expect("zero is canonical"),
        };
        witness.validate()?;

        Ok(PreparedTransfer {
            witness,
            output_addresses,
            output_memos,
        })
    }
}

impl PreparedTransfer {
    /// Encrypt both outputs to their recipients.
    ///
    /// One fresh `kem_randomness` per output, drawn here. ML-KEM
    /// encapsulation in `qnero-pqcrypto` is deterministic in that seed, so
    /// this is the only ambient randomness note encryption needs.
    pub fn encrypt_outputs(&self) -> Result<[PreparedOutput; 2]> {
        let mut prepared = Vec::with_capacity(2);
        for index in 0..2 {
            let note = self.witness.output_note(index)?;
            let memo = qnero_notes::pad_memo(&self.output_memos[index])
                .map_err(|error| anyhow::anyhow!("output {index} memo: {error}"))?;
            let ciphertext = qnero_notes::encrypt_note(
                &self.output_addresses[index].ek,
                &note,
                &memo,
                &random_seed()?,
            )
            .map_err(|error| anyhow::anyhow!("output {index} does not encrypt: {error}"))?
            .to_bytes();
            prepared.push(PreparedOutput { ciphertext });
        }
        prepared
            .try_into()
            .map_err(|_| anyhow::anyhow!("a leaf has two output slots"))
    }

    /// The public inputs the finished witness publishes.
    pub fn public_inputs(&self) -> Result<SubmissionPublicInputs> {
        let witness = &self.witness;
        if witness.ct_digest == Digest::from_bytes(&[0u8; 32]).expect("zero is canonical") {
            bail!("public inputs were read before ct_digest was written");
        }
        Ok(SubmissionPublicInputs {
            block_hash: witness.header.block_hash().to_hex(),
            block_number: witness.header.block_number,
            nullifiers: [
                witness.inputs[0].nullifier().to_hex(),
                witness.inputs[1].nullifier().to_hex(),
            ],
            commitments: [
                witness.output_commitment(0).to_hex(),
                witness.output_commitment(1).to_hex(),
            ],
            fee: witness.fee,
            ct_digest: witness.ct_digest.to_hex(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Goldilocks modulus, `2^64 - 2^32 + 1`.
    const P: u64 = 0xffff_ffff_0000_0001;

    fn anchor(state_root: String) -> AnchorRequest {
        AnchorRequest {
            parent_hash: Digest::from_bytes(&[0u8; 32])
                .expect("zero is canonical")
                .to_hex(),
            block_number: 7,
            state_root,
            extrinsics_root: Digest::from_bytes(&[0u8; 32])
                .expect("zero is canonical")
                .to_hex(),
            zk_tree_root: Digest::from_bytes(&[1u8; 32])
                .expect("one is canonical")
                .to_hex(),
            digest_logs: hex::encode([0u8; DIGEST_LOGS_SIZE]),
        }
    }

    /// The parity vector `wallet-web/tests/anchor.test.ts` reduces in
    /// TypeScript, one limb per case the reduction has: `p + 1`, `u64::MAX`,
    /// `p - 1` and `p` itself.
    const NON_CANONICAL_VECTOR: &str =
        "02000000ffffffffffffffffffffffff00000000ffffffff01000000ffffffff";
    const REDUCED_VECTOR: &str = "0100000000000000feffffff0000000000000000ffffffff0000000000000000";

    /// A root whose first limb is `P + 1`, which the chain reduces to 1.
    fn non_canonical_root() -> String {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(P + 1).to_le_bytes());
        hex::encode(bytes)
    }

    /// The same root with that limb already reduced.
    fn reduced_root() -> String {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&1u64.to_le_bytes());
        hex::encode(bytes)
    }

    /// A Blake2-256 output is not four canonical Goldilocks limbs and does not
    /// have to be: `HeaderInputs::new` reduces `state_root` and
    /// `extrinsics_root` mod p, which is what the chain's own `Header::hash`
    /// does with them. The strict decode used to refuse such a header here, so
    /// a browser wallet could not anchor at a block the chain and
    /// `crates/qnero-wallet/src/chain.rs` both hash happily.
    #[test]
    fn a_state_root_limb_over_the_modulus_hashes_as_the_reduced_root() {
        let raw = anchor(non_canonical_root())
            .to_header()
            .expect("a Blake2 root is taken as raw bytes");
        let reduced = anchor(reduced_root())
            .to_header()
            .expect("the reduced root is canonical either way");
        assert_eq!(raw.block_hash(), reduced.block_hash());
    }

    /// The same for the second Blake2 field.
    #[test]
    fn an_extrinsics_root_limb_over_the_modulus_is_reduced_too() {
        let mut raw = anchor(reduced_root());
        raw.extrinsics_root = non_canonical_root();
        let mut reduced = anchor(reduced_root());
        reduced.extrinsics_root = reduced_root();
        assert_eq!(
            raw.to_header().expect("raw bytes").block_hash(),
            reduced.to_header().expect("reduced bytes").block_hash()
        );
    }

    /// The exact bytes the reduction produces, so the browser wallet and this
    /// module can be held to one answer. `wallet-web/tests/anchor.test.ts`
    /// asserts the same pair.
    #[test]
    fn the_reduction_matches_the_browser_wallets_parity_vector() {
        let mut request = anchor(NON_CANONICAL_VECTOR.to_string());
        request.extrinsics_root = NON_CANONICAL_VECTOR.to_string();
        let header = request.to_header().expect("raw Blake2 bytes are taken");
        assert_eq!(header.state_root.to_hex(), REDUCED_VECTOR);
        assert_eq!(header.extrinsics_root.to_hex(), REDUCED_VECTOR);
    }

    /// The two Poseidon2 fields keep the strict decode. Their values are
    /// circuit outputs, so a limb at or above p is a corrupt or invented
    /// header.
    #[test]
    fn a_poseidon_field_over_the_modulus_is_still_refused_by_name() {
        let mut request = anchor(reduced_root());
        request.parent_hash = non_canonical_root();
        let refused = request.to_header().expect_err("parent_hash is a digest");
        assert!(refused.to_string().contains("parent_hash"), "{refused}");

        let mut request = anchor(reduced_root());
        request.zk_tree_root = non_canonical_root();
        let refused = request.to_header().expect_err("zk_tree_root is a digest");
        assert!(refused.to_string().contains("zk_tree_root"), "{refused}");
    }
}
