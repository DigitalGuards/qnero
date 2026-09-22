//! Verification of Qnero batch proofs: the private batch a wallet submits and
//! the public batch an aggregator bundles.
//!
//! These are the two artifacts a runtime holds. Both loaders are fail closed:
//! an artifact that does not match the expected profile is refused, and the
//! caller gets no verifier at all. There is no path that hands back a
//! weakened one.
//!
//! # The profile
//!
//! A batch artifact cannot be pinned by hash. Its bytes are a function of the
//! batch dimensions, which travel beside it in `config.json` and are chosen at
//! build time, so there is no single canonical file to hash. What is pinned
//! instead:
//!
//! - the public-input count, exactly, against the layout for those dimensions;
//! - the whole [`CircuitConfig`], exactly. Both batch configs are fixed
//!   functions with no tunable knob, so anything else is not the circuit the
//!   prover was built from. This catches the substitutions a floor would let
//!   through, including a private-batch artifact whose `zero_knowledge` is
//!   false, which would verify every proof while quietly ending the privacy
//!   the layer exists for;
//! - the whole [`FriParams`](qp_plonky2_verifier::plonk::circuit_data), except
//!   its degree, recomputed from that config. This is what pins
//!   `reduction_arity_bits` and `leaf_hiding`, which live only in this second
//!   copy and which no config comparison reaches;
//! - the degree itself, to a ceiling, since it is the one value that must be
//!   free to grow with the batch size;
//! - the index structure of the artifact against its own gate list, so a
//!   corrupted selector range cannot turn verification into an unbounded loop
//!   (see `ensure_common_data_is_structurally_sound` in this crate's root).
//!
//! Requiring the recomputed `FriParams` to match is also what makes the
//! artifact's two copies of the FRI configuration agree. An artifact carries
//! one `FriConfig` inside `common.config` and a second inside
//! `common.fri_params`, deserialized independently from the same bytes, and
//! verification reads the second: the grinding bits it checks the
//! proof-of-work response against, the query count, and the rate that sizes
//! the LDE domain all come from `fri_params.config`. Plonky2 never compares
//! the two, so a check on `config.fri_config` alone would accept an artifact
//! whose `fri_params.config.proof_of_work_bits` is zero and verify proofs
//! under it with no grinding at all, while the canonical 16 stayed on display
//! in the copy that was checked.
//!
//! # Why the expected configs are restated here
//!
//! `qnero-circuit`'s own constructors return the same values, but they live
//! behind its circuit feature, which pulls in plonky2's prover and cannot be
//! compiled into a runtime. So the two configs are rebuilt from
//! `qnero_circuit::params` here, and `qnero-aggregator`, which sees both
//! sides, carries the test that they are equal. That duplication is forced by
//! the dependency structure; the test is what keeps it honest.

use alloc::vec::Vec;

use anyhow::{anyhow, ensure, Result};
use qnero_circuit::batch_layout::{
    private_batch_pi_len, public_batch_inner_start, public_batch_pi_len, slot_commitment_index,
    slot_ct_digest_index, slot_fee_index, slot_nullifier_index, validate_proof_count,
    AGGREGATOR_ADDRESS_START, BLOCK_HASH_START, BLOCK_NUMBER_INDEX, DIGEST_FELTS,
};
use qnero_circuit::layout::{NUM_INPUTS, NUM_OUTPUTS};
use qnero_circuit::padding::PADDING_BLOCK_HASH;
use qnero_circuit::params;
use qp_plonky2_verifier::field::types::PrimeField64;
use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use qp_plonky2_verifier::{
    CircuitConfig, CommonCircuitData, ProofWithPublicInputs, VerifierCircuitData, C, D, F,
};

use crate::{
    digest_at, ensure_common_data_is_structurally_sound, MAX_PROOF_BYTES,
    MAX_VERIFIER_ARTIFACT_BYTES,
};

/// One leaf slot of a private batch, as the chain reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLeafSlot {
    /// Both nullifiers the leaf published. A padding slot inside a real batch
    /// carries hashes of randomness the prover drew for this batch, and the
    /// circuit constrains all `2N` published nullifiers of a segment pairwise
    /// distinct, padding slots included, so no two slots of one segment carry
    /// the same value and a padding nullifier is outside the image of both
    /// leaf nullifier functions. Settling them is therefore inert, and the
    /// chain may settle every slot's nullifiers by one rule.
    ///
    /// **A padding slot is identifiable**, so that one rule buys no count
    /// hiding. The wrapper zeroes a padding slot's commitment pair and no real
    /// slot's can be zero ([`BatchLeafSlot::is_padding`]), so the number of
    /// real transfers in a submission and the positions they occupy are
    /// public. What the padding does buy is a fixed proof shape and a fixed
    /// public-input length. Whether the chain keeps settling a padding slot's
    /// two nullifiers or skips them the way it already skips a zero
    /// commitment is an M4 decision (`docs/CIRCUIT.md` section 8.6): skipping
    /// them saves `2 * (N - 1)` permanent entries on a one-transfer batch.
    ///
    /// Settling by one rule holds **inside a non-padding segment only**. A padding
    /// segment of a public batch has its whole slot region zeroed
    /// ([`PrivateBatchPublicInputs::is_padding`]), so its nullifiers are the
    /// all-zero digest and repeat across every padding segment of every batch.
    /// A chain that settled those would reject its own second batch as a
    /// double spend. Skip padding segments first;
    /// [`PublicBatchPublicInputs::settleable_batches`] is that filter, and a
    /// zero nullifier must never enter the nullifier set.
    pub nullifiers: [[F; DIGEST_FELTS]; NUM_INPUTS],
    /// Both output commitments. Zero in a padding slot.
    pub commitments: [[F; DIGEST_FELTS]; NUM_OUTPUTS],
    /// That leaf's fee. Zero in a padding slot. Fees are summed by the chain
    /// in native arithmetic: `N` 62-bit values overflow the field, so the
    /// circuit leaves the sum alone.
    pub fee: F,
    /// The digest of that leaf's output ciphertexts. Zero in a padding slot.
    pub ct_digest: [F; DIGEST_FELTS],
}

impl BatchLeafSlot {
    /// `true` when this slot is batch padding.
    ///
    /// Both commitments are the all-zero digest, which is what the wrapper
    /// masks a padding slot to and which no note commitment can be: a
    /// commitment is a Poseidon2 output, and the chain's commitment tree
    /// treats the zero digest as the absence sentinel. A chain appending this
    /// slot's commitments must skip it.
    pub fn is_padding(&self) -> bool {
        self.commitments
            .iter()
            .all(|commitment| commitment.iter().all(|limb| limb.to_canonical_u64() == 0))
    }
}

/// The public inputs of one private-batch proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBatchPublicInputs {
    /// The block every non-padding slot is anchored at.
    pub block_hash: [F; DIGEST_FELTS],
    pub block_number: F,
    pub slots: Vec<BatchLeafSlot>,
}

impl PrivateBatchPublicInputs {
    /// `true` when the whole batch is padding: it carries the padding sentinel
    /// as its block hash and settles nothing. The public batch fills its empty
    /// slots with exactly such a proof.
    ///
    /// **A padding batch settles nothing at all.** No nullifier of it enters
    /// the nullifier set, no commitment of it is appended, no fee of it is
    /// accounted. That holds for a segment inside a public batch, whose slot
    /// region is zeroed, and for a standalone submission, which a chain must
    /// refuse outright: `prove_padding_batch` is a public API, so anyone can
    /// produce a padding batch that verifies while holding no note.
    pub fn is_padding(&self) -> bool {
        block_hash_is_the_padding_sentinel(&self.block_hash)
    }
}

/// The public inputs of one public-batch proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBatchPublicInputs {
    /// Who may claim this batch's fees. A free witness in circuit, so a
    /// consumer that did not choose it must compare it against the aggregator
    /// it expects.
    pub aggregator_address: [F; DIGEST_FELTS],
    /// One segment per inner private batch, in slot order.
    pub batches: Vec<PrivateBatchPublicInputs>,
}

impl PublicBatchPublicInputs {
    /// The segments a chain settles: every inner batch that is not padding.
    ///
    /// This is the default settlement path, and it exists so a consumer gets
    /// the skip for free. A padding segment keeps its sentinel header and has its
    /// whole slot region zeroed, so iterating [`Self::batches`] directly and
    /// settling every published nullifier inserts the all-zero nullifier once
    /// per padding slot and fails on the second one. At the chain default of
    /// 53 inner slots a partly full batch is the normal case, so that is close
    /// to every batch after the first.
    pub fn settleable_batches(&self) -> impl Iterator<Item = &PrivateBatchPublicInputs> {
        self.batches.iter().filter(|batch| !batch.is_padding())
    }
}

fn block_hash_is_the_padding_sentinel(block_hash: &[F; DIGEST_FELTS]) -> bool {
    block_hash
        .iter()
        .zip(PADDING_BLOCK_HASH.iter())
        .all(|(limb, expected)| limb.to_canonical_u64() == *expected)
}

/// Read a private-batch public-input vector for `num_leaves` slots.
pub fn parse_private_batch_public_input_felts(
    public_inputs: &[F],
    num_leaves: usize,
) -> Result<PrivateBatchPublicInputs> {
    ensure!(
        validate_proof_count(num_leaves),
        "a private batch of {} leaves is outside the supported range",
        num_leaves
    );
    let expected = private_batch_pi_len(num_leaves);
    ensure!(
        public_inputs.len() == expected,
        "the private-batch proof has {} public inputs, expected {} for {} leaves",
        public_inputs.len(),
        expected,
        num_leaves
    );

    let slots = (0..num_leaves)
        .map(|slot| BatchLeafSlot {
            nullifiers: core::array::from_fn(|input| {
                digest_at(public_inputs, slot_nullifier_index(slot, input))
            }),
            commitments: core::array::from_fn(|note| {
                digest_at(public_inputs, slot_commitment_index(slot, note))
            }),
            fee: public_inputs[slot_fee_index(slot)],
            ct_digest: digest_at(public_inputs, slot_ct_digest_index(slot)),
        })
        .collect();

    Ok(PrivateBatchPublicInputs {
        block_hash: digest_at(public_inputs, BLOCK_HASH_START),
        block_number: public_inputs[BLOCK_NUMBER_INDEX],
        slots,
    })
}

/// Read a private-batch proof's public inputs.
pub fn parse_private_batch_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_leaves: usize,
) -> Result<PrivateBatchPublicInputs> {
    parse_private_batch_public_input_felts(&proof.public_inputs, num_leaves)
}

/// Read a public-batch public-input vector for `num_inner` private batches of
/// `num_leaves` slots each.
pub fn parse_public_batch_public_input_felts(
    public_inputs: &[F],
    num_inner: usize,
    num_leaves: usize,
) -> Result<PublicBatchPublicInputs> {
    ensure!(
        validate_proof_count(num_inner) && validate_proof_count(num_leaves),
        "a public batch of {} inner proofs over {} leaves is outside the supported range",
        num_inner,
        num_leaves
    );
    let expected = public_batch_pi_len(num_inner, num_leaves);
    ensure!(
        public_inputs.len() == expected,
        "the public-batch proof has {} public inputs, expected {} for {} inner proofs over {} \
         leaves",
        public_inputs.len(),
        expected,
        num_inner,
        num_leaves
    );

    let batches = (0..num_inner)
        .map(|inner| {
            let start = public_batch_inner_start(inner, num_leaves);
            let end = start + private_batch_pi_len(num_leaves);
            parse_private_batch_public_input_felts(&public_inputs[start..end], num_leaves)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(PublicBatchPublicInputs {
        aggregator_address: digest_at(public_inputs, AGGREGATOR_ADDRESS_START),
        batches,
    })
}

/// Read a public-batch proof's public inputs.
pub fn parse_public_batch_public_inputs(
    proof: &ProofWithPublicInputs<F, C, D>,
    num_inner: usize,
    num_leaves: usize,
) -> Result<PublicBatchPublicInputs> {
    parse_public_batch_public_input_felts(&proof.public_inputs, num_inner, num_leaves)
}

/// The config the private-batch circuit is built with.
///
/// Restated here, for the reason the module docs give.
pub fn expected_private_batch_config() -> CircuitConfig {
    CircuitConfig {
        num_wires: params::PRIVATE_BATCH_NUM_WIRES,
        num_routed_wires: params::PRIVATE_BATCH_NUM_ROUTED_WIRES,
        ..CircuitConfig::standard_recursion_zk_config()
    }
}

/// The config the public-batch circuit is built with.
pub fn expected_public_batch_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}

/// Hold an artifact to its layer's profile: public-input count, config, FRI
/// parameters, degree ceiling.
fn ensure_batch_profile(
    common: &CommonCircuitData<F, D>,
    expected_config: &CircuitConfig,
    expected_public_inputs: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        common.num_public_inputs == expected_public_inputs,
        "the {} artifact has {} public inputs, expected {}",
        label,
        common.num_public_inputs,
        expected_public_inputs
    );
    ensure!(
        &common.config == expected_config,
        "the {} artifact was built with a different circuit config than the canonical one",
        label
    );
    ensure_common_data_is_structurally_sound(common, label)?;
    ensure!(
        common.fri_params.degree_bits <= params::MAX_BATCH_DEGREE_BITS,
        "the {} artifact claims degree_bits {}, above the {} ceiling",
        label,
        common.fri_params.degree_bits,
        params::MAX_BATCH_DEGREE_BITS
    );

    // Recomputed from the config just checked, at the degree the artifact
    // claims. Equality pins the second FRI config copy, the reduction schedule
    // and the leaf-hiding flag together.
    let expected_fri_params = expected_config.fri_config.fri_params(
        common.fri_params.degree_bits,
        expected_config.zero_knowledge,
    );
    ensure!(
        common.fri_params == expected_fri_params,
        "the {} artifact's FRI parameters are not the ones its circuit config implies",
        label
    );

    Ok(())
}

/// Magic bytes of the dimension header a public-batch artifact carries.
pub const PUBLIC_BATCH_ARTIFACT_MAGIC: [u8; 8] = *b"QNROPBV1";

/// Length of that header: the magic, then `num_inner` and `num_leaves` as
/// little-endian `u32`.
pub const PUBLIC_BATCH_ARTIFACT_HEADER_LEN: usize = 16;

/// The header a public-batch artifact for these dimensions must carry.
///
/// The public-batch profile is otherwise **not injective** in
/// `(num_inner, num_leaves)`. Its only dimension-dependent check is the
/// public-input count, and `4 + n * (5 + 21 * N)` collides for supported
/// pairs: `public_batch_pi_len(34, 1)` and `public_batch_pi_len(13, 3)` are
/// both 888. The config is a fixed function of neither dimension, the FRI
/// parameters are recomputed at whatever degree the artifact claims, and the
/// degree itself is held only to a ceiling. So an artifact built for one pair
/// loads cleanly under the other, verifies genuine proofs, and the chain then
/// splits those proofs into segments at the wrong offsets: it would read one
/// inner's block hash as another's nullifier and write junk into the nullifier
/// set, with nothing anywhere refusing the artifact. Carrying the dimensions
/// beside the bytes closes that, and it costs sixteen bytes.
///
/// The private batch needs no such header: `5 + 21 * N` determines `N`
/// uniquely from a length, so its public-input check already binds it.
pub fn public_batch_artifact_header(
    num_inner: usize,
    num_leaves: usize,
) -> Result<[u8; PUBLIC_BATCH_ARTIFACT_HEADER_LEN]> {
    ensure!(
        validate_proof_count(num_inner) && validate_proof_count(num_leaves),
        "a public batch of {} inner proofs over {} leaves is outside the supported range",
        num_inner,
        num_leaves
    );
    let mut header = [0u8; PUBLIC_BATCH_ARTIFACT_HEADER_LEN];
    header[..8].copy_from_slice(&PUBLIC_BATCH_ARTIFACT_MAGIC);
    header[8..12].copy_from_slice(&(num_inner as u32).to_le_bytes());
    header[12..].copy_from_slice(&(num_leaves as u32).to_le_bytes());
    Ok(header)
}

/// Strip the dimension header, refusing an artifact built for another pair.
fn split_public_batch_artifact(bytes: &[u8], num_inner: usize, num_leaves: usize) -> Result<&[u8]> {
    let expected = public_batch_artifact_header(num_inner, num_leaves)?;
    ensure!(
        bytes.len() > PUBLIC_BATCH_ARTIFACT_HEADER_LEN,
        "the public-batch artifact is {} bytes, too short to carry its dimension header",
        bytes.len()
    );
    let (header, body) = bytes.split_at(PUBLIC_BATCH_ARTIFACT_HEADER_LEN);
    ensure!(
        header[..8] == PUBLIC_BATCH_ARTIFACT_MAGIC,
        "the public-batch artifact does not begin with its dimension header"
    );
    ensure!(
        header == expected,
        "the public-batch artifact was built for other dimensions than the {} inner proofs \
         over {} leaves it was loaded for",
        num_inner,
        num_leaves
    );
    Ok(body)
}

fn deserialize_verifier_data(bytes: &[u8], label: &str) -> Result<VerifierCircuitData<F, C, D>> {
    ensure!(
        bytes.len() <= MAX_VERIFIER_ARTIFACT_BYTES,
        "the {} artifact is {} bytes, above the {} byte limit",
        label,
        bytes.len(),
        MAX_VERIFIER_ARTIFACT_BYTES
    );
    VerifierCircuitData::<F, C, D>::from_bytes(bytes.to_vec(), &DefaultGateSerializer)
        .map_err(|e| anyhow!("failed to deserialize the {} artifact: {}", label, e))
}

/// Deserialize a proof and refuse anything but its canonical encoding.
///
/// Plonky2's reader stops when it has read a whole proof and never checks that
/// the buffer is exhausted, and it builds each public input with an unreduced
/// `u64` constructor whose range check is a debug assertion, while every
/// comparison on the resulting field element reduces. So `proof || padding`
/// and a proof whose serialized limbs each carry `+ p` both parse to the same
/// proof and verify. Value soundness is unaffected, but proof bytes are the
/// natural transaction identity on chain, and under those rules one batch has
/// unlimited distinct identities. Writing is deterministic and canonicalizing,
/// so one round trip rejects trailing bytes and non-canonical limbs together.
fn decode_canonical_proof(
    proof_bytes: &[u8],
    common: &CommonCircuitData<F, D>,
) -> core::result::Result<ProofWithPublicInputs<F, C, D>, ProofRejection> {
    if proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(ProofRejection::TooLarge);
    }
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.to_vec(), common)
        .map_err(|_| ProofRejection::Deserialization)?;
    if proof.to_bytes() != proof_bytes {
        return Err(ProofRejection::NonCanonicalEncoding);
    }
    Ok(proof)
}

/// Why a serialized batch proof was refused, in the order the checks run.
///
/// A chain settling these proofs declares an error per variant, so a rejected
/// settlement says which layer refused it: the byte cap, deserialization, the
/// canonical-encoding round trip, the public-input layout, or the verification
/// itself. That is as far as the split goes. It does not separate a truncated
/// blob from a proof of the same circuit built at other dimensions, because
/// both fail `from_bytes` and land in [`Self::Deserialization`]; an operator
/// looking at that variant has to check the wallet's artifact dimensions and
/// the upload separately. Carrying plonky2's own message here, behind `std`,
/// is what would separate them, and this enum deliberately carries no payload
/// so it stays `Copy` on a `no_std` runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRejection {
    /// Above [`MAX_PROOF_BYTES`]. Checked before anything is copied or parsed.
    TooLarge,
    /// The bytes did not deserialize against this verifier's circuit data. A
    /// proof built for other circuit dimensions lands here.
    Deserialization,
    /// The bytes are not the canonical encoding of the proof they decode to.
    /// `decode_canonical_proof` in this module re-encodes what it decoded and
    /// requires the two to be the same bytes, which is what closes the
    /// malleability this variant names.
    NonCanonicalEncoding,
    /// The public inputs did not parse at the documented indices.
    PublicInputLayout,
    /// The proof did not verify.
    Verification,
}

impl core::fmt::Display for ProofRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::TooLarge => "the proof is above the byte limit",
            Self::Deserialization => {
                "the proof did not deserialize against the verifier's circuit data, which is also \
                 what a proof built for other circuit dimensions looks like"
            }
            Self::NonCanonicalEncoding => {
                "the bytes are not the canonical encoding of the proof they decode to"
            }
            Self::PublicInputLayout => "the public inputs did not parse at the documented indices",
            Self::Verification => "the proof did not verify",
        };
        f.write_str(message)
    }
}

impl core::error::Error for ProofRejection {}

/// Verifier for private-batch proofs over one fixed slot count.
#[derive(Debug)]
pub struct QneroPrivateBatchVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
    num_leaves: usize,
}

impl QneroPrivateBatchVerifier {
    /// Wrap verifier data, holding it to the private-batch profile for
    /// `num_leaves`.
    pub fn new(circuit_data: VerifierCircuitData<F, C, D>, num_leaves: usize) -> Result<Self> {
        ensure!(
            validate_proof_count(num_leaves),
            "a private batch of {} leaves is outside the supported range",
            num_leaves
        );
        ensure_batch_profile(
            &circuit_data.common,
            &expected_private_batch_config(),
            private_batch_pi_len(num_leaves),
            "private-batch",
        )?;
        Ok(Self {
            circuit_data,
            num_leaves,
        })
    }

    /// Load verifier data from its serialized form.
    ///
    /// This is the shape a runtime uses: bytes that come out of a trusted
    /// build. There is deliberately no hash pin on them, because
    /// the bytes depend on `num_leaves`; the profile above stands in its
    /// place, and the caller owns provenance.
    pub fn from_artifact_bytes(bytes: &[u8], num_leaves: usize) -> Result<Self> {
        let circuit_data = deserialize_verifier_data(bytes, "private-batch")?;
        Self::new(circuit_data, num_leaves)
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Read a serialized proof's public inputs **without verifying it**.
    ///
    /// This is the size cap, the canonical-encoding round trip and the layout
    /// parse, and none of the recursive verification. It is for reading a
    /// proof whose verification happens somewhere else: a dispatch body behind
    /// a gate that already verified, a filter that discards obvious junk
    /// before the expensive work, an indexer reading a settlement out of a
    /// block that was already validated.
    ///
    /// A transaction pool admitting unsigned, fee-free settlements must call
    /// [`Self::verify_proof_bytes`] before it admits or re-gossips one.
    /// Admitting on this call alone is unsound: see `docs/CIRCUIT.md` section
    /// 9.10 in the Qnero repository. The public inputs are a plain vector in
    /// the serialized blob, so a body-tampered clone of a genuine proof parses
    /// to exactly the victim's nullifiers, takes the victim's nullifier-derived
    /// pool tag, and costs every node that relays it the whole settlement walk.
    ///
    /// What comes back is attacker controlled until a verify succeeds. Treat it
    /// as a claim about what the proof says, which only a verify establishes.
    pub fn parse_proof_bytes(
        &self,
        proof_bytes: &[u8],
    ) -> core::result::Result<PrivateBatchPublicInputs, ProofRejection> {
        let proof = decode_canonical_proof(proof_bytes, &self.circuit_data.common)?;
        parse_private_batch_public_inputs(&proof, self.num_leaves)
            .map_err(|_| ProofRejection::PublicInputLayout)
    }

    /// Verify a serialized proof and read its public inputs.
    pub fn verify_proof_bytes(
        &self,
        proof_bytes: &[u8],
    ) -> core::result::Result<PrivateBatchPublicInputs, ProofRejection> {
        let proof = decode_canonical_proof(proof_bytes, &self.circuit_data.common)?;
        let public = parse_private_batch_public_inputs(&proof, self.num_leaves)
            .map_err(|_| ProofRejection::PublicInputLayout)?;
        self.verify(proof)
            .map_err(|_| ProofRejection::Verification)?;
        Ok(public)
    }

    /// Verify and read the public inputs in one step.
    ///
    /// The public inputs are read first, from the proof this call owns, so the
    /// proof moves into `verify` without a copy.
    pub fn verify_and_parse(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<PrivateBatchPublicInputs> {
        let public = parse_private_batch_public_inputs(&proof, self.num_leaves)?;
        self.verify(proof)?;
        Ok(public)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.circuit_data
            .verify(proof)
            .map_err(|e| anyhow!("private-batch proof verification failed: {}", e))
    }
}

/// Verifier for public-batch proofs over one fixed pair of dimensions.
///
/// [`QneroPublicBatchVerifier::from_artifact_bytes`] is the only way to build
/// one, because it is the call that checks the sixteen-byte dimension header
/// before anything is deserialized. The profile a verifier is held to is not
/// injective in `(num_inner, num_leaves)`: `public_batch_pi_len(34, 1)` and
/// `public_batch_pi_len(13, 3)` are both 888 felts, so an artifact built for
/// one pair passes every profile check under the other, verifies genuine
/// proofs, and leaves a chain splitting them into segments at the wrong
/// offsets. The header is what closes that, so the constructor that skips it
/// is crate private:
///
/// ```compile_fail
/// use qnero_verifier::QneroPublicBatchVerifier;
/// // `new` takes already-deserialized verifier data, so it has no header to
/// // check. It is not callable from outside the crate.
/// let _ = QneroPublicBatchVerifier::new;
/// ```
///
/// The public door is reachable, and takes the dimensions it checks:
///
/// ```
/// use qnero_verifier::QneroPublicBatchVerifier;
/// let _ = QneroPublicBatchVerifier::from_artifact_bytes;
/// ```
#[derive(Debug)]
pub struct QneroPublicBatchVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
    num_inner: usize,
    num_leaves: usize,
}

impl QneroPublicBatchVerifier {
    /// Wrap verifier data, holding it to the public-batch profile for
    /// `(num_inner, num_leaves)`.
    ///
    /// Crate private on purpose: the profile does not pin the dimension pair,
    /// so every caller has to arrive through
    /// [`QneroPublicBatchVerifier::from_artifact_bytes`], which checks the
    /// header that does.
    pub(crate) fn new(
        circuit_data: VerifierCircuitData<F, C, D>,
        num_inner: usize,
        num_leaves: usize,
    ) -> Result<Self> {
        ensure!(
            validate_proof_count(num_inner) && validate_proof_count(num_leaves),
            "a public batch of {} inner proofs over {} leaves is outside the supported range",
            num_inner,
            num_leaves
        );
        ensure_batch_profile(
            &circuit_data.common,
            &expected_public_batch_config(),
            public_batch_pi_len(num_inner, num_leaves),
            "public-batch",
        )?;
        Ok(Self {
            circuit_data,
            num_inner,
            num_leaves,
        })
    }

    /// Load verifier data from its serialized form.
    ///
    /// The bytes carry a sixteen-byte dimension header, which is checked
    /// before anything is deserialized: see [`public_batch_artifact_header`]
    /// for what it closes.
    pub fn from_artifact_bytes(bytes: &[u8], num_inner: usize, num_leaves: usize) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_VERIFIER_ARTIFACT_BYTES,
            "the public-batch artifact is {} bytes, above the {} byte limit",
            bytes.len(),
            MAX_VERIFIER_ARTIFACT_BYTES
        );
        let body = split_public_batch_artifact(bytes, num_inner, num_leaves)?;
        let circuit_data = deserialize_verifier_data(body, "public-batch")?;
        Self::new(circuit_data, num_inner, num_leaves)
    }

    pub fn num_inner(&self) -> usize {
        self.num_inner
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Read a serialized proof's public inputs **without verifying it**. See
    /// [`QneroPrivateBatchVerifier::parse_proof_bytes`] for what that is for,
    /// what it does not establish, and why a transaction pool cannot admit on
    /// it alone.
    pub fn parse_proof_bytes(
        &self,
        proof_bytes: &[u8],
    ) -> core::result::Result<PublicBatchPublicInputs, ProofRejection> {
        let proof = decode_canonical_proof(proof_bytes, &self.circuit_data.common)?;
        parse_public_batch_public_inputs(&proof, self.num_inner, self.num_leaves)
            .map_err(|_| ProofRejection::PublicInputLayout)
    }

    pub fn verify_proof_bytes(
        &self,
        proof_bytes: &[u8],
    ) -> core::result::Result<PublicBatchPublicInputs, ProofRejection> {
        let proof = decode_canonical_proof(proof_bytes, &self.circuit_data.common)?;
        let public = parse_public_batch_public_inputs(&proof, self.num_inner, self.num_leaves)
            .map_err(|_| ProofRejection::PublicInputLayout)?;
        self.verify(proof)
            .map_err(|_| ProofRejection::Verification)?;
        Ok(public)
    }

    pub fn verify_and_parse(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<PublicBatchPublicInputs> {
        let public = parse_public_batch_public_inputs(&proof, self.num_inner, self.num_leaves)?;
        self.verify(proof)?;
        Ok(public)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.circuit_data
            .verify(proof)
            .map_err(|e| anyhow!("public-batch proof verification failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qp_plonky2_verifier::field::types::Field;

    #[test]
    fn a_private_batch_vector_of_the_wrong_length_is_rejected() {
        let felts = vec![F::ZERO; private_batch_pi_len(3)];
        assert!(parse_private_batch_public_input_felts(&felts, 3).is_ok());
        assert!(parse_private_batch_public_input_felts(&felts, 2).is_err());
        assert!(parse_private_batch_public_input_felts(&felts, 4).is_err());
        assert!(parse_private_batch_public_input_felts(&felts, 0).is_err());
    }

    #[test]
    fn private_batch_public_inputs_are_read_from_the_documented_indices() {
        let felts: Vec<F> = (0..private_batch_pi_len(2))
            .map(F::from_canonical_usize)
            .collect();
        let parsed = parse_private_batch_public_input_felts(&felts, 2).unwrap();

        assert_eq!(parsed.block_hash, [felts[0], felts[1], felts[2], felts[3]]);
        assert_eq!(parsed.block_number, felts[4]);
        assert_eq!(parsed.slots.len(), 2);
        assert_eq!(
            parsed.slots[0].nullifiers[0],
            [felts[5], felts[6], felts[7], felts[8]]
        );
        assert_eq!(
            parsed.slots[0].nullifiers[1],
            [felts[9], felts[10], felts[11], felts[12]]
        );
        assert_eq!(
            parsed.slots[0].commitments[0],
            [felts[13], felts[14], felts[15], felts[16]]
        );
        assert_eq!(
            parsed.slots[0].commitments[1],
            [felts[17], felts[18], felts[19], felts[20]]
        );
        assert_eq!(parsed.slots[0].fee, felts[21]);
        assert_eq!(
            parsed.slots[0].ct_digest,
            [felts[22], felts[23], felts[24], felts[25]]
        );
        // The second slot starts immediately after the first.
        assert_eq!(
            parsed.slots[1].nullifiers[0],
            [felts[26], felts[27], felts[28], felts[29]]
        );
        assert_eq!(parsed.slots[1].fee, felts[42]);
    }

    #[test]
    fn public_batch_public_inputs_split_into_inner_segments() {
        let felts: Vec<F> = (0..public_batch_pi_len(2, 1))
            .map(F::from_canonical_usize)
            .collect();
        let parsed = parse_public_batch_public_input_felts(&felts, 2, 1).unwrap();

        assert_eq!(
            parsed.aggregator_address,
            [felts[0], felts[1], felts[2], felts[3]]
        );
        assert_eq!(parsed.batches.len(), 2);
        assert_eq!(
            parsed.batches[0].block_hash,
            [felts[4], felts[5], felts[6], felts[7]]
        );
        assert_eq!(parsed.batches[0].block_number, felts[8]);
        // Second segment: 4 + 26 felts in.
        assert_eq!(
            parsed.batches[1].block_hash,
            [felts[30], felts[31], felts[32], felts[33]]
        );
    }

    /// A slot with zero commitments is padding, whatever its nullifiers say.
    /// The chain uses this to decide what to append to the commitment tree.
    #[test]
    fn a_slot_with_zero_commitments_reads_as_padding() {
        let mut felts = vec![F::ZERO; private_batch_pi_len(1)];
        // A padding slot still carries nullifiers, which the chain settles.
        felts[slot_nullifier_index(0, 0)] = F::from_canonical_u64(7);
        let parsed = parse_private_batch_public_input_felts(&felts, 1).unwrap();
        assert!(parsed.slots[0].is_padding());

        felts[slot_commitment_index(0, 1)] = F::from_canonical_u64(9);
        let parsed = parse_private_batch_public_input_felts(&felts, 1).unwrap();
        assert!(!parsed.slots[0].is_padding());
    }

    /// The sentinel is what a chain recognises an all-padding batch by, and it
    /// is not the all-zero digest.
    #[test]
    fn an_all_padding_batch_reads_as_padding() {
        let mut felts = vec![F::ZERO; private_batch_pi_len(1)];
        let parsed = parse_private_batch_public_input_felts(&felts, 1).unwrap();
        assert!(!parsed.is_padding());

        for (i, limb) in PADDING_BLOCK_HASH.iter().enumerate() {
            felts[BLOCK_HASH_START + i] = F::from_canonical_u64(*limb);
        }
        let parsed = parse_private_batch_public_input_felts(&felts, 1).unwrap();
        assert!(parsed.is_padding());
    }

    #[test]
    fn oversized_and_garbage_artifacts_are_refused() {
        let oversized = vec![0u8; MAX_VERIFIER_ARTIFACT_BYTES + 1];
        let error = QneroPrivateBatchVerifier::from_artifact_bytes(&oversized, 7).unwrap_err();
        assert!(error.to_string().contains("above the"));
        let error = QneroPublicBatchVerifier::from_artifact_bytes(&oversized, 2, 7).unwrap_err();
        assert!(error.to_string().contains("above the"));
        assert!(QneroPrivateBatchVerifier::from_artifact_bytes(&[0u8; 64], 7).is_err());
        assert!(QneroPublicBatchVerifier::from_artifact_bytes(&[0u8; 64], 2, 7).is_err());
    }

    /// A public-batch artifact is bound to the dimensions it was built for,
    /// which its public-input count alone cannot do.
    ///
    /// `4 + 34 * 26` and `4 + 13 * 68` are both 888, and every other check in
    /// the profile is blind to the dimensions, so without the header an
    /// artifact built for 34 inner proofs over 1 leaf would load as one built
    /// for 13 over 3 and every proof it verified would be split at the wrong
    /// offsets.
    #[test]
    fn a_public_batch_artifact_is_bound_to_its_dimensions() {
        assert_eq!(public_batch_pi_len(34, 1), public_batch_pi_len(13, 3));

        let mut artifact = public_batch_artifact_header(34, 1).unwrap().to_vec();
        artifact.extend_from_slice(&[0u8; 64]);

        let error = QneroPublicBatchVerifier::from_artifact_bytes(&artifact, 13, 3).unwrap_err();
        assert!(
            error.to_string().contains("other dimensions"),
            "got: {error}"
        );

        // Under its own dimensions the header passes and the body is what
        // fails, which is as far as a 64-byte stand-in can get.
        let error = QneroPublicBatchVerifier::from_artifact_bytes(&artifact, 34, 1).unwrap_err();
        assert!(error.to_string().contains("deserialize"), "got: {error}");
    }

    /// An artifact with no header at all is refused, so a set from before the
    /// header existed cannot be loaded as if it had one.
    #[test]
    fn a_public_batch_artifact_without_a_header_is_refused() {
        let unframed = vec![7u8; 128];
        let error = QneroPublicBatchVerifier::from_artifact_bytes(&unframed, 2, 7).unwrap_err();
        assert!(
            error.to_string().contains("dimension header"),
            "got: {error}"
        );
    }

    /// Only the non-padding segments of a public batch are settled.
    #[test]
    fn settleable_batches_skips_the_padding_segments() {
        let mut felts = vec![F::ZERO; public_batch_pi_len(2, 1)];
        // Segment 1 carries the sentinel; segment 0 does not.
        let padding_start = public_batch_inner_start(1, 1);
        for (i, limb) in PADDING_BLOCK_HASH.iter().enumerate() {
            felts[padding_start + BLOCK_HASH_START + i] = F::from_canonical_u64(*limb);
        }
        let parsed = parse_public_batch_public_input_felts(&felts, 2, 1).unwrap();

        assert_eq!(parsed.batches.len(), 2);
        assert_eq!(parsed.settleable_batches().count(), 1);
        assert!(parsed.settleable_batches().all(|batch| !batch.is_padding()));
    }

    /// The private batch is the layer that blinds. An artifact that is not
    /// zero knowledge is not that circuit.
    #[test]
    fn the_expected_private_batch_config_blinds_and_the_public_one_does_not() {
        assert!(expected_private_batch_config().zero_knowledge);
        assert!(!expected_public_batch_config().zero_knowledge);
        assert_eq!(
            expected_private_batch_config().num_wires,
            params::PRIVATE_BATCH_NUM_WIRES
        );
    }
}
