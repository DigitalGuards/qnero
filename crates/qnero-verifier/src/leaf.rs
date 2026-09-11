//! Verification of a Qnero leaf proof.
//!
//! **A leaf proof is not the on-chain unit**, which is why this module is
//! behind the non-default `leaf` feature. The leaf is built with
//! `standard_recursion_config`, which does not blind, so its FRI openings leak
//! witness structure: note values, the Merkle path, the shape of the spend
//! credential. A leaf proof exists to be aggregated by the wallet that made
//! it. The unit a runtime verifies is the private batch, in
//! [`crate::batch`], and a runtime takes this crate without this feature so it
//! cannot reach a leaf entry point by accident.
//!
//! Public inputs are read by the constant indices in
//! [`qnero_circuit::layout`], which is the one place that layout is defined.

use anyhow::{anyhow, ensure, Result};
use qnero_circuit::layout::{
    commitment_index, nullifier_index, BLOCK_HASH_START, BLOCK_NUMBER_INDEX, CT_DIGEST_START,
    DIGEST_FELTS, FEE_INDEX, NUM_INPUTS, NUM_OUTPUTS, PUBLIC_INPUT_LEN,
};
use qnero_circuit::params;
use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use qp_plonky2_verifier::{CircuitConfig, ProofWithPublicInputs, VerifierCircuitData, C, D, F};

use crate::{
    digest_at, ensure_common_data_is_structurally_sound, MAX_PROOF_BYTES,
    MAX_VERIFIER_ARTIFACT_BYTES,
};

/// A leaf proof's public inputs, read positionally.
///
/// Field elements are kept as field elements: a nullifier and a commitment are
/// four Goldilocks limbs, which is exactly what the chain stores and compares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafPublicInputs {
    pub block_hash: [F; DIGEST_FELTS],
    pub block_number: F,
    pub nullifiers: [[F; DIGEST_FELTS]; NUM_INPUTS],
    pub commitments: [[F; DIGEST_FELTS]; NUM_OUTPUTS],
    pub fee: F,
    pub ct_digest: [F; DIGEST_FELTS],
}

/// Read the public inputs of a leaf proof.
pub fn parse_public_inputs(proof: &ProofWithPublicInputs<F, C, D>) -> Result<LeafPublicInputs> {
    parse_public_input_felts(&proof.public_inputs)
}

/// Read a bare public-input vector, for callers that already stripped the
/// proof (the batch layer forwards leaf public inputs verbatim).
pub fn parse_public_input_felts(public_inputs: &[F]) -> Result<LeafPublicInputs> {
    ensure!(
        public_inputs.len() == PUBLIC_INPUT_LEN,
        "leaf proof has {} public inputs, expected {}",
        public_inputs.len(),
        PUBLIC_INPUT_LEN
    );

    Ok(LeafPublicInputs {
        block_hash: digest_at(public_inputs, BLOCK_HASH_START),
        block_number: public_inputs[BLOCK_NUMBER_INDEX],
        nullifiers: core::array::from_fn(|i| digest_at(public_inputs, nullifier_index(i))),
        commitments: core::array::from_fn(|j| digest_at(public_inputs, commitment_index(j))),
        fee: public_inputs[FEE_INDEX],
        ct_digest: digest_at(public_inputs, CT_DIGEST_START),
    })
}

/// Verifier for Qnero leaf proofs.
#[derive(Debug)]
pub struct QneroVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
}

impl QneroVerifier {
    /// Wrap verifier data, checking that it is shaped like a leaf circuit and
    /// that its proof-system parameters are the canonical ones.
    ///
    /// The public-input count is the cheapest signal that the verifier and the
    /// prover were built from the same circuit. It does not catch a
    /// permutation of the layout at the same length, which is why both sides
    /// share one definition of the layout constants.
    ///
    /// The parameter floor is the second half. Public-input count alone says
    /// nothing about soundness: verifier data built over this exact layout
    /// with one FRI query round and no grinding deserializes cleanly, because
    /// plonky2's own check on deserialized config rejects only a zero
    /// challenge count, a zero constant count and fewer than three routed
    /// wires. Such an artifact verifies a forged proof with high probability,
    /// and this crate is what a runtime and the batch aggregator call. So the
    /// security-relevant parameters are pinned to [`qnero_circuit::params`],
    /// which the circuit crate tests against the config the prover builds
    /// with. It is a floor. Provenance is a separate question: the keccak pin
    /// on a tagged artifact is still to come, and until it lands the caller
    /// owns where the bytes came from.
    ///
    /// The floor covers both copies of the FRI configuration. An artifact
    /// carries one inside `common.config` and a second inside
    /// `common.fri_params`, verification reads the second, and plonky2 never
    /// compares them, so the two are required to agree before the floor is
    /// applied to the first.
    ///
    /// It also refuses an artifact whose index structure does not describe its
    /// own gate list, which is what keeps a corrupted selector range from
    /// turning verification into an unbounded loop; see
    /// [`crate::ensure_common_data_is_structurally_sound`].
    pub fn new(circuit_data: VerifierCircuitData<F, C, D>) -> Result<Self> {
        ensure!(
            circuit_data.common.num_public_inputs == PUBLIC_INPUT_LEN,
            "verifier data has {} public inputs, expected {} for a Qnero leaf",
            circuit_data.common.num_public_inputs,
            PUBLIC_INPUT_LEN
        );

        // The artifact carries the FRI configuration twice, and verification
        // reads the copy the table below does not. `read_common_circuit_data`
        // reads a `CircuitConfig`, whose `fri_config` is what the table holds
        // to the floor, and then reads a `FriParams` carrying a second full
        // `FriConfig` deserialized independently from the same bytes.
        // Plonky2 never relates the two: its structural check on a
        // deserialized artifact reads `common.config` plus
        // `fri_params.degree_bits`, while `verify_fri_proof` takes the
        // grinding bits, the query count and the rate from
        // `fri_params.config`. A floor over one copy alone is no floor: an
        // artifact whose `fri_params.config.proof_of_work_bits` is zero
        // presents the canonical 16 to every check that reads
        // `config.fri_config` and is verified with no grinding at all,
        // dropping those 16 bits out of the claimed security level. Requiring
        // the two to agree makes the checked copy govern both. A genuine
        // artifact always satisfies it, because `FriConfig::fri_params` clones
        // the config it is called on.
        ensure!(
            circuit_data.common.fri_params.config == circuit_data.common.config.fri_config,
            "verifier data carries two different FRI configurations: fri_params.config is {:?}, \
             config.fri_config is {:?}",
            circuit_data.common.fri_params.config,
            circuit_data.common.config.fri_config
        );

        ensure_common_data_is_structurally_sound(&circuit_data.common, "leaf")?;

        let config = &circuit_data.common.config;
        let fri = &config.fri_config;
        for (name, value, expected, exact) in [
            (
                "security_bits",
                config.security_bits,
                params::SECURITY_BITS,
                false,
            ),
            (
                "num_challenges",
                config.num_challenges,
                params::NUM_CHALLENGES,
                false,
            ),
            (
                "fri_config.num_query_rounds",
                fri.num_query_rounds,
                params::FRI_NUM_QUERY_ROUNDS,
                false,
            ),
            (
                "fri_config.proof_of_work_bits",
                fri.proof_of_work_bits as usize,
                params::FRI_PROOF_OF_WORK_BITS as usize,
                false,
            ),
            (
                "fri_config.rate_bits",
                fri.rate_bits,
                params::FRI_RATE_BITS,
                true,
            ),
            (
                "fri_config.cap_height",
                fri.cap_height,
                params::FRI_CAP_HEIGHT,
                true,
            ),
            (
                "fri_params.degree_bits",
                circuit_data.common.fri_params.degree_bits,
                params::LEAF_DEGREE_BITS,
                true,
            ),
        ] {
            if exact {
                ensure!(
                    value == expected,
                    "verifier data has {} = {}, the canonical Qnero leaf has {}",
                    name,
                    value,
                    expected
                );
            } else {
                ensure!(
                    value >= expected,
                    "verifier data has {} = {}, below the canonical Qnero leaf's {}",
                    name,
                    value,
                    expected
                );
            }
        }

        // Two values live only in the second FRI copy, and no floor entry
        // above reaches either: the folding schedule and the blinding flag.
        // The schedule decides how FRI reduces the codeword, and the flag
        // decides whether Merkle leaves are salted, so an artifact that
        // disagreed with the prover about either would be a verifier checking
        // a different protocol run. Both are recomputed from the canonical
        // config at the canonical degree, which the table above has already
        // pinned exactly. Nothing is lost by comparing the schedule exactly:
        // it is a function of the rate, the cap height, the degree and the
        // reduction strategy, and the first three are pinned exactly, so an
        // artifact that legitimately carried more query rounds still produces
        // this same schedule.
        let canonical_fri_params = CircuitConfig::standard_recursion_config()
            .fri_config
            .fri_params(params::LEAF_DEGREE_BITS, false);
        ensure!(
            circuit_data.common.fri_params.reduction_arity_bits
                == canonical_fri_params.reduction_arity_bits,
            "verifier data has FRI reduction arities {:?}, the canonical Qnero leaf has {:?}",
            circuit_data.common.fri_params.reduction_arity_bits,
            canonical_fri_params.reduction_arity_bits
        );
        ensure!(
            !circuit_data.common.fri_params.leaf_hiding,
            "verifier data claims hiding FRI leaves; the canonical Qnero leaf does not blind,              and privacy is applied at the private batch"
        );

        Ok(Self { circuit_data })
    }

    /// Load verifier data from its serialized form.
    ///
    /// This is the shape a runtime uses: it holds bytes produced by a trusted
    /// build, and a prover's output never reaches it. The bytes are capped,
    /// parsed, and then held to the parameter floor in
    /// [`QneroVerifier::new`]. There is deliberately no keccak pin on them
    /// yet, because Qnero has no tagged circuit release to pin; the pin lands
    /// with the first one, together with the batch verifier. Until then the
    /// caller owns artifact provenance.
    pub fn from_artifact_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_VERIFIER_ARTIFACT_BYTES,
            "verifier artifact is {} bytes, above the {} byte limit",
            bytes.len(),
            MAX_VERIFIER_ARTIFACT_BYTES
        );
        let circuit_data =
            VerifierCircuitData::<F, C, D>::from_bytes(bytes.to_vec(), &DefaultGateSerializer)
                .map_err(|e| anyhow!("failed to deserialize verifier data: {}", e))?;
        Self::new(circuit_data)
    }

    /// Verify a serialized proof and read its public inputs.
    ///
    /// Bytes are the real boundary: a proof reaches a verifier over the
    /// network or out of a block, never as a live struct.
    pub fn verify_proof_bytes(&self, proof_bytes: &[u8]) -> Result<LeafPublicInputs> {
        ensure!(
            proof_bytes.len() <= MAX_PROOF_BYTES,
            "proof is {} bytes, above the {} byte limit",
            proof_bytes.len(),
            MAX_PROOF_BYTES
        );
        let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
            proof_bytes.to_vec(),
            &self.circuit_data.common,
        )
        .map_err(|e| anyhow!("failed to deserialize the proof: {}", e))?;

        // One proof, one encoding. Plonky2's reader stops when it has read a
        // whole proof and never checks that the buffer is exhausted, and it
        // builds each public input with an unreduced `u64` constructor whose
        // range check is a debug assertion, while every comparison on the
        // resulting field element reduces. So `proof || padding` and a proof
        // whose serialized limbs each carry `+ p` both parse to this same
        // proof and verify. Value soundness is unaffected, but proof bytes are
        // the natural mempool key and transaction identity at M4, and under
        // those rules one leaf has unlimited distinct identities. Writing is
        // deterministic and canonicalizing, so one round trip rejects trailing
        // bytes and non-canonical limbs together.
        ensure!(
            proof.to_bytes() == proof_bytes,
            "proof bytes are not the canonical encoding of the proof they decode to"
        );

        self.verify_and_parse(proof)
    }

    /// Verify a proof this caller only holds a reference to.
    ///
    /// `VerifierCircuitData::verify` consumes its proof, so this clones about
    /// 100 kB of FRI openings and Merkle caps. Callers that own the proof
    /// should use [`QneroVerifier::verify`] or
    /// [`QneroVerifier::verify_and_parse`] instead.
    pub fn verify_ref(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.verify(proof.clone())
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.circuit_data
            .verify(proof)
            .map_err(|e| anyhow!("leaf proof verification failed: {}", e))
    }

    /// Verify and read the public inputs in one step.
    ///
    /// The public inputs are read first, from the proof this call owns, so the
    /// proof can be moved into `verify` without a copy.
    pub fn verify_and_parse(
        &self,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<LeafPublicInputs> {
        let public = parse_public_input_felts(&proof.public_inputs)?;
        self.verify(proof)?;
        Ok(public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qp_plonky2_verifier::field::types::Field;

    #[test]
    fn a_public_input_vector_of_the_wrong_length_is_rejected() {
        assert!(parse_public_input_felts(&[]).is_err());
        assert!(parse_public_input_felts(&[F::ZERO; PUBLIC_INPUT_LEN - 1]).is_err());
        assert!(parse_public_input_felts(&[F::ZERO; PUBLIC_INPUT_LEN + 1]).is_err());
    }

    #[test]
    fn public_inputs_are_read_from_the_documented_indices() {
        let felts: Vec<F> = (0..PUBLIC_INPUT_LEN).map(F::from_canonical_usize).collect();
        let parsed = parse_public_input_felts(&felts).unwrap();

        assert_eq!(parsed.block_hash, [felts[0], felts[1], felts[2], felts[3]]);
        assert_eq!(parsed.block_number, felts[4]);
        assert_eq!(
            parsed.nullifiers[0],
            [felts[5], felts[6], felts[7], felts[8]]
        );
        assert_eq!(
            parsed.nullifiers[1],
            [felts[9], felts[10], felts[11], felts[12]]
        );
        assert_eq!(
            parsed.commitments[0],
            [felts[13], felts[14], felts[15], felts[16]]
        );
        assert_eq!(
            parsed.commitments[1],
            [felts[17], felts[18], felts[19], felts[20]]
        );
        assert_eq!(parsed.fee, felts[21]);
        assert_eq!(
            parsed.ct_digest,
            [felts[22], felts[23], felts[24], felts[25]]
        );
    }

    #[test]
    fn oversized_artifacts_are_refused_before_parsing() {
        let oversized = vec![0u8; MAX_VERIFIER_ARTIFACT_BYTES + 1];
        let error = QneroVerifier::from_artifact_bytes(&oversized).unwrap_err();
        assert!(error.to_string().contains("above the"));
    }

    #[test]
    fn a_garbage_artifact_is_refused() {
        assert!(QneroVerifier::from_artifact_bytes(&[0u8; 64]).is_err());
    }
}
