//! Verification of Qnero batch proofs: the private batch a wallet submits and
//! the public batch an aggregator bundles.
//!
//! These are the two artifacts a runtime holds. Both loaders are fail closed:
//! an artifact that does not match the expected profile is refused, and the
//! caller gets no verifier at all rather than a weak one.
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
//!   (see [`crate::ensure_common_data_is_structurally_sound`]).
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
    /// Both nullifiers the leaf published. A padding slot carries hashes of
    /// randomness the prover drew for this batch, so the chain settles every
    /// slot's nullifiers by one rule and never learns which slots were
    /// padding.
    pub nullifiers: [[F; DIGEST_FELTS]; NUM_INPUTS],
    /// Both output commitments. Zero in a padding slot.
    pub commitments: [[F; DIGEST_FELTS]; NUM_OUTPUTS],
    /// That leaf's fee. Zero in a padding slot. Fees are summed by the chain
    /// in native arithmetic, never in circuit: `N` 62-bit values overflow the
    /// field.
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
/// Restated here rather than imported: see the module docs.
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
    label: &str,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    ensure!(
        proof_bytes.len() <= MAX_PROOF_BYTES,
        "the {} proof is {} bytes, above the {} byte limit",
        label,
        proof_bytes.len(),
        MAX_PROOF_BYTES
    );
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.to_vec(), common)
        .map_err(|e| anyhow!("failed to deserialize the {} proof: {}", label, e))?;
    ensure!(
        proof.to_bytes() == proof_bytes,
        "the {} proof bytes are not the canonical encoding of the proof they decode to",
        label
    );
    Ok(proof)
}

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
    /// This is the shape a runtime uses: bytes produced by a trusted build,
    /// never by a prover. There is deliberately no hash pin on them, because
    /// the bytes depend on `num_leaves`; the profile above stands in its
    /// place, and the caller owns provenance.
    pub fn from_artifact_bytes(bytes: &[u8], num_leaves: usize) -> Result<Self> {
        let circuit_data = deserialize_verifier_data(bytes, "private-batch")?;
        Self::new(circuit_data, num_leaves)
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Verify a serialized proof and read its public inputs.
    pub fn verify_proof_bytes(&self, proof_bytes: &[u8]) -> Result<PrivateBatchPublicInputs> {
        let proof =
            decode_canonical_proof(proof_bytes, &self.circuit_data.common, "private-batch")?;
        self.verify_and_parse(proof)
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
#[derive(Debug)]
pub struct QneroPublicBatchVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
    num_inner: usize,
    num_leaves: usize,
}

impl QneroPublicBatchVerifier {
    pub fn new(
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

    pub fn from_artifact_bytes(bytes: &[u8], num_inner: usize, num_leaves: usize) -> Result<Self> {
        let circuit_data = deserialize_verifier_data(bytes, "public-batch")?;
        Self::new(circuit_data, num_inner, num_leaves)
    }

    pub fn num_inner(&self) -> usize {
        self.num_inner
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn verify_proof_bytes(&self, proof_bytes: &[u8]) -> Result<PublicBatchPublicInputs> {
        let proof = decode_canonical_proof(proof_bytes, &self.circuit_data.common, "public-batch")?;
        self.verify_and_parse(proof)
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
        assert!(QneroPrivateBatchVerifier::from_artifact_bytes(&[0u8; 64], 7).is_err());
        assert!(QneroPublicBatchVerifier::from_artifact_bytes(&[0u8; 64], 2, 7).is_err());
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
