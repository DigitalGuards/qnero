//! The aggregator-side public-batch prover.
//!
//! One circuit build per process. At production sizes that build takes tens of
//! seconds, so it must never sit on the per-batch path, and
//! [`QneroPublicBatchProver::prove_batch`] takes `&self`.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use plonky2::field::types::PrimeField64;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};

use qnero_circuit::batch_layout::{
    private_batch_pi_len, public_batch_pi_len, slot_commitment_index, slot_ct_digest_index,
    slot_fee_index, slot_nullifier_index, AGGREGATOR_ADDRESS_LEN, AGGREGATOR_ADDRESS_START,
    BLOCK_HASH_START, BLOCK_NUMBER_INDEX, DIGEST_FELTS,
};
use qnero_circuit::config::qnero_public_batch_circuit_config;
use qnero_circuit::convert::digest_to_felts;
use qnero_circuit::layout::{NUM_INPUTS, NUM_OUTPUTS};
use qnero_circuit::padding::{PADDING_BLOCK_HASH, PADDING_BLOCK_NUMBER};
use qnero_circuit::{C, D, F};
use qnero_notes::Digest;

use crate::artifacts::{
    ensure_proof_public_input_len, load_canonical_private_batch_verifier_data, read_artifact_file,
};
use crate::config::{validate_proof_count, CircuitBinsConfig};
use crate::public_batch::circuit::{PublicBatchTargets, QneroPublicBatchCircuit};
use crate::public_batch::witness::fill_public_batch_witness;
use crate::Proof;

/// What one public batch is proved from.
#[derive(Debug, Clone)]
pub struct PublicBatchInputs {
    pub proofs: Vec<Proof>,
    /// The address that may claim this batch's fees on chain.
    pub aggregator_address: Digest,
}

/// Proves public batches over one fixed pair of dimensions.
pub struct QneroPublicBatchProver {
    circuit_data: CircuitData<F, C, D>,
    targets: PublicBatchTargets,
    num_inner: usize,
    num_leaves: usize,
    padding_template: Proof,
    private_batch_verifier: VerifierCircuitData<F, C, D>,
}

impl core::fmt::Debug for QneroPublicBatchProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroPublicBatchProver")
            .field("num_inner", &self.num_inner)
            .field("num_leaves", &self.num_leaves)
            .field("circuit_data", &"[CircuitData]")
            .finish()
    }
}

impl QneroPublicBatchProver {
    /// Build over supplied private-batch verifier data.
    pub fn new(
        config: CircuitConfig,
        private_batch_common: CommonCircuitData<F, D>,
        private_batch_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_inner: usize,
        num_leaves: usize,
        padding_template: Proof,
    ) -> Result<Self> {
        let circuit = QneroPublicBatchCircuit::new(
            config,
            &private_batch_common,
            private_batch_verifier_only,
            num_inner,
            num_leaves,
        )?;
        let targets = circuit.targets();
        let circuit_data = circuit.build();

        let private_batch_verifier = VerifierCircuitData {
            verifier_only: private_batch_verifier_only.clone(),
            common: private_batch_common,
        };
        validate_padding_private_batch_template(
            &padding_template,
            &private_batch_verifier,
            num_leaves,
        )?;

        Ok(Self {
            circuit_data,
            targets,
            num_inner,
            num_leaves,
            padding_template,
            private_batch_verifier,
        })
    }

    /// Build from serialized artifacts.
    ///
    /// The private-batch artifacts are pinned to a canonical rebuild over the
    /// canonical leaf, so the verifier key baked into this circuit is a
    /// function of the compiled circuit code and `num_leaves` alone.
    pub fn new_from_artifact_bytes(
        private_batch_verifier_bytes: &[u8],
        padding_private_batch_proof_bytes: &[u8],
        num_leaves: usize,
        num_inner: usize,
    ) -> Result<Self> {
        validate_proof_count(num_leaves, "num_leaf_proofs")?;
        validate_proof_count(num_inner, "num_private_batch_proofs")?;

        let leaf = crate::artifacts::canonical_leaf_verifier_data();
        let private_batch = load_canonical_private_batch_verifier_data(
            private_batch_verifier_bytes,
            &leaf,
            num_leaves,
        )?;
        let padding_template = Proof::from_bytes(
            padding_private_batch_proof_bytes.to_vec(),
            &private_batch.common,
        )
        .map_err(|e| {
            anyhow!(
                "failed to deserialize the padding private-batch proof: {}",
                e
            )
        })?;

        Self::new(
            qnero_public_batch_circuit_config(),
            private_batch.common,
            &private_batch.verifier_only,
            num_inner,
            num_leaves,
            padding_template,
        )
    }

    /// Build from an artifact directory: `config.json`,
    /// `private_batch_verifier.bin`, `padding_private_batch_proof.bin`.
    pub fn new_from_artifact_dir(bins_dir: &Path) -> Result<Self> {
        let config = CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("failed to load config.json from {}", bins_dir.display()))?;
        let Some(num_inner) = config.num_private_batch_proofs else {
            bail!(
                "{} holds a private-batch-only artifact set: it has no public-batch dimension",
                bins_dir.display()
            );
        };
        let verifier = read_artifact_file(&bins_dir.join("private_batch_verifier.bin"))?;
        let padding = read_artifact_file(&bins_dir.join("padding_private_batch_proof.bin"))?;
        Self::new_from_artifact_bytes(&verifier, &padding, config.num_leaf_proofs, num_inner)
    }

    pub fn num_inner(&self) -> usize {
        self.num_inner
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.circuit_data.verifier_data()
    }

    /// Prove one public batch, padding it to the circuit's slot count.
    pub fn prove_batch(&self, inputs: PublicBatchInputs) -> Result<Proof> {
        let PublicBatchInputs {
            mut proofs,
            aggregator_address,
        } = inputs;

        self.preflight(&proofs)?;

        // No shuffle: forwarding is order preserving so the chain can
        // attribute a segment to an inner proof.
        for _ in proofs.len()..self.num_inner {
            proofs.push(self.padding_template.clone());
        }

        let mut witness = PartialWitness::new();
        fill_public_batch_witness(&mut witness, &self.targets, &proofs, &aggregator_address)?;
        self.circuit_data
            .prove(witness)
            .map_err(|e| anyhow!("failed to prove the public batch: {}", e))
    }

    /// Verify a public-batch proof and check that it names this aggregator.
    ///
    /// The address check is not a circuit constraint and cannot be one: the
    /// address is a free witness, so anyone holding the inner proofs can
    /// produce the same batch under a different address. An aggregator that
    /// accepts a finished proof from elsewhere has to compare the exposed
    /// address against its own, here, or it will verify and settle batches
    /// whose fees are payable to someone else.
    pub fn verify(&self, proof: Proof, expected_address: &Digest) -> Result<()> {
        ensure_proof_public_input_len(
            &proof,
            public_batch_pi_len(self.num_inner, self.num_leaves),
            "public-batch proof",
        )?;
        let expected = digest_to_felts(expected_address);
        let exposed = &proof.public_inputs
            [AGGREGATOR_ADDRESS_START..AGGREGATOR_ADDRESS_START + AGGREGATOR_ADDRESS_LEN];
        if exposed != expected {
            bail!(
                "the public-batch proof names a different aggregator address than the one \
                 expected"
            );
        }
        self.verifier_data()
            .verify(proof)
            .map_err(|e| anyhow!("public-batch proof verification failed: {}", e))
    }

    /// Admission checks for a caller-supplied inner-proof vector.
    fn preflight(&self, proofs: &[Proof]) -> Result<()> {
        if proofs.is_empty() {
            bail!("no private-batch proofs to aggregate");
        }
        if proofs.len() > self.num_inner {
            bail!(
                "got {} private-batch proofs, but this batch has {} slots",
                proofs.len(),
                self.num_inner
            );
        }

        let expected_len = private_batch_pi_len(self.num_leaves);
        for (index, proof) in proofs.iter().enumerate() {
            ensure_proof_public_input_len(proof, expected_len, "private-batch proof")
                .with_context(|| format!("private-batch proof {index}"))?;
            self.private_batch_verifier
                .verify(proof.clone())
                .map_err(|e| {
                    anyhow!(
                        "private-batch proof {} failed verification against the pinned \
                         private-batch verifier: {}",
                        index,
                        e
                    )
                })?;
        }

        ensure_inner_batch_compatible(proofs, self.num_leaves)
    }
}

/// Admission rules for the inner proofs of one public batch.
///
/// Two of them mirror circuit constraints and exist here for failure latency:
/// every non-padding inner shares one block hash and one block number.
///
/// The third has no circuit counterpart and is the only thing enforcing it.
/// **The `2N` nullifiers of one inner proof must not repeat in another.** The
/// public batch forwards each segment verbatim with no cross-inner check, and
/// a full pairwise comparison in circuit would be `n * 2N` digests against
/// each other, which at the chain default of 53 inners over 7 leaves is 742
/// nullifiers and is not affordable. So a duplicated inner proves and verifies
/// as readily as a distinct one: the same 2N nullifiers, the same 2N
/// commitments and the same per-leaf fee are republished once per copy. The
/// chain's settled-nullifier set catches the second copy, and its whole
/// settlement extrinsic then reverts, so one attacker resubmitting a proof
/// somebody else already paid for destroys an aggregator's entire batch at no
/// cost. This check is where that is stopped.
///
/// A caller-supplied padding inner is refused outright for the same reason.
/// The padding template is a published artifact anybody can download, it
/// settles nothing, and padding is this prover's to append. Accepting one as
/// an input would let anyone burn an aggregator's slots with a file. That one
/// rule also covers a vector of nothing but padding, which is why no
/// all-padding check follows the loop: the first padding proof bails, whatever
/// position it sits in.
///
/// `docs/CIRCUIT.md` section 8.3 records which half of the distinctness rule
/// is a circuit constraint and which is an admission rule.
fn ensure_inner_batch_compatible(proofs: &[Proof], num_leaves: usize) -> Result<()> {
    let mut reference: Option<(usize, [u64; DIGEST_FELTS], u64)> = None;
    let mut seen: HashMap<[u64; DIGEST_FELTS], (usize, usize, usize)> = HashMap::new();

    for (index, proof) in proofs.iter().enumerate() {
        let block_hash: [u64; DIGEST_FELTS] =
            core::array::from_fn(|i| proof.public_inputs[BLOCK_HASH_START + i].to_canonical_u64());
        if block_hash == PADDING_BLOCK_HASH {
            bail!(
                "private-batch proof {} carries the padding sentinel. A padding batch settles \
                 nothing, and padding is this prover's to append, so every supplied proof has \
                 to be a real private batch",
                index
            );
        }

        let block_number = proof.public_inputs[BLOCK_NUMBER_INDEX].to_canonical_u64();
        match reference {
            None => reference = Some((index, block_hash, block_number)),
            Some((reference_index, reference_hash, reference_number)) => {
                if block_hash != reference_hash || block_number != reference_number {
                    bail!(
                        "private-batch proof {} is anchored at a different block than proof {}; \
                         every non-padding inner proof of a public batch must share one block",
                        index,
                        reference_index
                    );
                }
            }
        }

        for slot in 0..num_leaves {
            for input in 0..NUM_INPUTS {
                let nullifier: [u64; DIGEST_FELTS] = core::array::from_fn(|limb| {
                    proof.public_inputs[slot_nullifier_index(slot, input) + limb].to_canonical_u64()
                });
                if let Some((previous_index, previous_slot, previous_input)) =
                    seen.insert(nullifier, (index, slot, input))
                {
                    bail!(
                        "private-batch proof {} publishes the nullifier at slot {} input {} that \
                         proof {} already published at slot {} input {}; two inner proofs of one \
                         public batch may not settle the same note, and a repeated inner is the \
                         usual cause",
                        index,
                        slot,
                        input,
                        previous_index,
                        previous_slot,
                        previous_input
                    );
                }
            }
        }
    }

    Ok(())
}

/// Accept a proof as the all-padding private batch only if it carries the
/// sentinel, settles nothing, and verifies.
///
/// The sentinel is checked first and cheaply; both halves must pass. Unlike
/// the padding leaf, this template's public inputs are not fully determined:
/// its padding nullifiers are hashes of the randomness drawn when the artifact
/// was built. So every field that must be inert is checked one by one, and the
/// nullifiers are left alone.
pub fn validate_padding_private_batch_template(
    template: &Proof,
    private_batch_verifier: &VerifierCircuitData<F, C, D>,
    num_leaves: usize,
) -> Result<()> {
    let expected_len = private_batch_pi_len(num_leaves);
    ensure_proof_public_input_len(template, expected_len, "padding private-batch template")?;

    let public = &template.public_inputs;
    let block_hash: [u64; DIGEST_FELTS] =
        core::array::from_fn(|i| public[BLOCK_HASH_START + i].to_canonical_u64());
    if block_hash != PADDING_BLOCK_HASH {
        bail!(
            "the padding private-batch template does not carry the padding block hash; refusing \
             to use it as public-batch padding"
        );
    }
    if public[BLOCK_NUMBER_INDEX].to_canonical_u64() != u64::from(PADDING_BLOCK_NUMBER) {
        bail!("the padding private-batch template does not carry the padding block number");
    }

    for slot in 0..num_leaves {
        for note in 0..NUM_OUTPUTS {
            for limb in 0..DIGEST_FELTS {
                if public[slot_commitment_index(slot, note) + limb].to_canonical_u64() != 0 {
                    bail!(
                        "the padding private-batch template publishes a nonzero commitment at \
                         slot {}; a padding batch must append nothing to the commitment tree",
                        slot
                    );
                }
            }
        }
        if public[slot_fee_index(slot)].to_canonical_u64() != 0 {
            bail!(
                "the padding private-batch template publishes a nonzero fee at slot {}",
                slot
            );
        }
        for limb in 0..DIGEST_FELTS {
            if public[slot_ct_digest_index(slot) + limb].to_canonical_u64() != 0 {
                bail!(
                    "the padding private-batch template publishes a nonzero ct_digest at slot {}",
                    slot
                );
            }
        }
    }

    private_batch_verifier
        .verify(template.clone())
        .map_err(|e| {
            anyhow!(
                "the padding private-batch template failed verification: {}",
                e
            )
        })
}
