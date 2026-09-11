//! The wallet-side private-batch prover.
//!
//! One expensive circuit build per process, then any number of batches:
//! [`QneroPrivateBatchProver::aggregate`] takes `&self`.
//!
//! No prover artifact is ever read or written. `ProverOnlyCircuitData` carries
//! the target list that decides which witness values become public inputs, so
//! a poisoned one could publish the padding preimages, which say which slots
//! were padding. The circuit is rebuilt from source, which the prover has to
//! do anyway.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use plonky2::field::types::{Field as _, PrimeField64};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use rand::seq::SliceRandom;
use rand::RngCore;

use qnero_circuit::batch_layout::DIGEST_FELTS;
use qnero_circuit::config::qnero_private_batch_circuit_config;
use qnero_circuit::layout::{
    nullifier_index, BLOCK_HASH_START, BLOCK_NUMBER_INDEX, NUM_INPUTS, PUBLIC_INPUT_LEN,
};
use qnero_circuit::padding::PADDING_BLOCK_HASH;
use qnero_circuit::{C, D, F};

use crate::artifacts::{
    ensure_proof_public_input_len, load_canonical_leaf_verifier_data, read_artifact_file,
};
use crate::config::{validate_proof_count, CircuitBinsConfig};
use crate::padding_proof::{load_padding_leaf_proof, validate_padding_leaf_template};
use crate::private_batch::circuit::{PrivateBatchTargets, QneroPrivateBatchCircuit};
use crate::private_batch::witness::{fill_private_batch_witness, SlotPaddingPreimages};
use crate::Proof;

/// Dimensions of the built circuit, for the size report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBatchBuildMetrics {
    pub num_leaves: usize,
    pub leaf_degree_bits: usize,
    pub unpadded_gates: usize,
    pub degree_bits: usize,
    pub padded_gates: usize,
}

/// Proves private batches over one fixed slot count.
pub struct QneroPrivateBatchProver {
    /// Full circuit data rather than prover-only data: the few hundred
    /// kilobytes of verifier data it adds are what let a wallet verify its own
    /// batch before submitting it, and what the artifact builder pins the
    /// published verifier against.
    circuit_data: CircuitData<F, C, D>,
    targets: PrivateBatchTargets,
    num_leaves: usize,
    padding_template: Proof,
    /// Kept so each supplied leaf can be verified in milliseconds before the
    /// recursive proving run starts.
    leaf_verifier: VerifierCircuitData<F, C, D>,
}

/// Redacting `Debug`: the prover holds a padding template and circuit data,
/// neither of which belongs in a log line.
impl core::fmt::Debug for QneroPrivateBatchProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroPrivateBatchProver")
            .field("num_leaves", &self.num_leaves)
            .field("circuit_data", &"[CircuitData]")
            .finish()
    }
}

impl QneroPrivateBatchProver {
    /// Build over supplied leaf verifier data.
    pub fn new(
        config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_leaves: usize,
        padding_template: Proof,
    ) -> Result<Self> {
        Self::new_with_metrics(
            config,
            leaf_common,
            leaf_verifier_only,
            num_leaves,
            padding_template,
        )
        .map(|(prover, _)| prover)
    }

    /// Build, and report the finalized circuit's dimensions.
    pub fn new_with_metrics(
        config: CircuitConfig,
        leaf_common: CommonCircuitData<F, D>,
        leaf_verifier_only: &VerifierOnlyCircuitData<C, D>,
        num_leaves: usize,
        padding_template: Proof,
    ) -> Result<(Self, PrivateBatchBuildMetrics)> {
        let circuit =
            QneroPrivateBatchCircuit::new(config, &leaf_common, leaf_verifier_only, num_leaves)?;
        let unpadded_gates = circuit.num_gates();
        let leaf_degree_bits = leaf_common.degree_bits();
        let targets = circuit.targets();
        let circuit_data = circuit.build();
        let metrics = PrivateBatchBuildMetrics {
            num_leaves,
            leaf_degree_bits,
            unpadded_gates,
            degree_bits: circuit_data.common.degree_bits(),
            padded_gates: circuit_data.common.degree(),
        };

        let leaf_verifier = VerifierCircuitData {
            verifier_only: leaf_verifier_only.clone(),
            common: leaf_common,
        };
        // The same template invariant the byte-loading constructors enforce:
        // `aggregate` clones this proof into every empty slot.
        validate_padding_leaf_template(&padding_template, &leaf_verifier)?;

        Ok((
            Self {
                circuit_data,
                targets,
                num_leaves,
                padding_template,
                leaf_verifier,
            },
            metrics,
        ))
    }

    /// Build over the canonical leaf circuit, rebuilt from source.
    ///
    /// The shape a wallet uses when it has no artifact directory: everything
    /// but the padding proof is a function of the compiled circuit code.
    pub fn new_canonical(num_leaves: usize, padding_template: Proof) -> Result<Self> {
        let leaf = crate::artifacts::canonical_leaf_verifier_data();
        Self::new(
            qnero_private_batch_circuit_config(),
            leaf.common,
            &leaf.verifier_only,
            num_leaves,
            padding_template,
        )
    }

    /// Build from serialized artifacts.
    ///
    /// The leaf artifacts are pinned to a canonical rebuild by raw bytes, and
    /// the rebuild is what gets baked in as the constant verifier key, so a
    /// substituted or stale leaf artifact cannot reach the circuit. The batch
    /// circuit itself is rebuilt from source: no `*_prover.bin` exists to
    /// load.
    pub fn new_from_artifact_bytes(
        leaf_verifier_bytes: &[u8],
        padding_leaf_proof_bytes: &[u8],
        num_leaves: usize,
    ) -> Result<Self> {
        validate_proof_count(num_leaves, "num_leaf_proofs")?;
        let leaf = load_canonical_leaf_verifier_data(leaf_verifier_bytes)?;
        let padding_template =
            load_padding_leaf_proof(padding_leaf_proof_bytes.to_vec(), &leaf.common)?;
        Self::new(
            qnero_private_batch_circuit_config(),
            leaf.common,
            &leaf.verifier_only,
            num_leaves,
            padding_template,
        )
    }

    /// Build from an artifact directory: `config.json`, `leaf_verifier.bin`,
    /// `padding_leaf_proof.bin`.
    pub fn new_from_artifact_dir(bins_dir: &Path) -> Result<Self> {
        let config = CircuitBinsConfig::load(bins_dir)
            .with_context(|| format!("failed to load config.json from {}", bins_dir.display()))?;
        let leaf_verifier = read_artifact_file(&bins_dir.join("leaf_verifier.bin"))?;
        let padding = read_artifact_file(&bins_dir.join("padding_leaf_proof.bin"))?;
        Self::new_from_artifact_bytes(&leaf_verifier, &padding, config.num_leaf_proofs)
    }

    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }

    /// Verifier data for the batch circuit this prover was built from. Built
    /// from source, so it is canonical by construction.
    pub fn verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.circuit_data.verifier_data()
    }

    /// Aggregate `1..=N` leaf proofs into one private-batch proof.
    ///
    /// Non-consuming: the circuit build is paid once per process.
    pub fn aggregate(&self, proofs: Vec<Proof>) -> Result<Proof> {
        let witness = self.build_witness(proofs)?;
        self.circuit_data
            .prove(witness)
            .map_err(|e| anyhow!("failed to prove the private batch: {}", e))
    }

    /// Prove an all-padding private batch: the template a public batch fills
    /// its empty slots with.
    ///
    /// This is the one batch proved without the admission checks in
    /// [`Self::aggregate`], which refuse an all-padding batch on purpose. It
    /// is also the only proof the artifact builder produces at this layer, and
    /// it is what the public batch masks a padding inner down to.
    ///
    /// The padding template was validated at construction, so what reaches the
    /// circuit here is the canonical padding leaf in every slot.
    pub fn prove_padding_batch(&self) -> Result<Proof> {
        let proofs = vec![self.padding_template.clone(); self.num_leaves];
        let preimages = padding_nullifier_preimages_for_build(&mut rand::rng(), self.num_leaves);

        let mut witness = PartialWitness::new();
        fill_private_batch_witness(&mut witness, &self.targets, &proofs, &preimages)?;
        self.circuit_data
            .prove(witness)
            .map_err(|e| anyhow!("failed to prove the all-padding private batch: {}", e))
    }

    /// Admission checks, padding and shuffling, in that order.
    fn build_witness(&self, mut proofs: Vec<Proof>) -> Result<PartialWitness<F>> {
        if proofs.is_empty() {
            bail!("no leaf proofs to aggregate");
        }
        if proofs.len() > self.num_leaves {
            bail!(
                "got {} leaf proofs, but this batch has {} slots",
                proofs.len(),
                self.num_leaves
            );
        }

        for (index, proof) in proofs.iter().enumerate() {
            ensure_proof_public_input_len(proof, PUBLIC_INPUT_LEN, "leaf proof")
                .with_context(|| format!("leaf proof {index}"))?;
            self.leaf_verifier.verify(proof.clone()).map_err(|e| {
                anyhow!(
                    "leaf proof {} failed verification against the pinned leaf verifier: {}",
                    index,
                    e
                )
            })?;
        }
        ensure_batch_compatible(&proofs)?;

        for _ in proofs.len()..self.num_leaves {
            proofs.push(self.padding_template.clone());
        }

        let mut rng = rand::rng();
        // Uniform shuffle, which is what hides where the padding sits. The
        // circuit picks its block reference by prefix scan and forwards each
        // slot's values as one unit, so no slot position means anything and no
        // separate permutation of the emitted region is needed.
        proofs.shuffle(&mut rng);

        let preimages = padding_nullifier_preimages_for_build(&mut rng, self.num_leaves);

        let mut witness = PartialWitness::new();
        fill_private_batch_witness(&mut witness, &self.targets, &proofs, &preimages)?;
        Ok(witness)
    }
}

/// Draw the padding randomness: two preimages per slot, one per nullifier the
/// padded leaf publishes.
///
/// Fresh on every proving run, so two batches never publish the same padding
/// nullifier, and a padding slot is not recognisable by a repeated value.
/// Every limb is reduced into the field, so the preimage is a canonical field
/// element rather than a `u64` the witness would silently reduce.
pub(crate) fn padding_nullifier_preimages_for_build<R: RngCore>(
    rng: &mut R,
    slots: usize,
) -> Vec<SlotPaddingPreimages> {
    (0..slots)
        .map(|_| {
            core::array::from_fn(|_| {
                core::array::from_fn(|_| F::from_canonical_u64(rng.next_u64() >> 2))
            })
        })
        .collect()
}

/// Reject a leaf set the circuit could never prove, before the expensive run.
///
/// Mirrors the circuit's cross-slot constraints, and must be kept in lockstep
/// with them:
///
/// - every non-padding leaf shares one block hash and one block number,
/// - the `2k` nullifiers of non-padding leaves are pairwise distinct,
/// - at least one leaf is non-padding, since an all-padding batch settles
///   nothing and only burns a proving window. The artifact builder produces
///   exactly such a batch as the public batch's padding template, and it fills
///   the witness directly rather than coming through here.
///
/// The circuit remains the enforcer. This is about failure latency and error
/// quality.
fn ensure_batch_compatible(proofs: &[Proof]) -> Result<()> {
    struct LeafMeta {
        block_hash: [u64; DIGEST_FELTS],
        block_number: u64,
        nullifiers: [[u64; DIGEST_FELTS]; NUM_INPUTS],
    }

    let metas: Vec<LeafMeta> = proofs
        .iter()
        .map(|proof| LeafMeta {
            block_hash: core::array::from_fn(|i| {
                proof.public_inputs[BLOCK_HASH_START + i].to_canonical_u64()
            }),
            block_number: proof.public_inputs[BLOCK_NUMBER_INDEX].to_canonical_u64(),
            nullifiers: core::array::from_fn(|input| {
                core::array::from_fn(|i| {
                    proof.public_inputs[nullifier_index(input) + i].to_canonical_u64()
                })
            }),
        })
        .collect();

    let mut reference: Option<(usize, &LeafMeta)> = None;
    let mut seen: HashMap<[u64; DIGEST_FELTS], (usize, usize)> = HashMap::new();
    for (index, meta) in metas.iter().enumerate() {
        if meta.block_hash == PADDING_BLOCK_HASH {
            continue;
        }
        match reference {
            None => reference = Some((index, meta)),
            Some((reference_index, reference_meta)) => {
                if meta.block_hash != reference_meta.block_hash {
                    bail!(
                        "leaf proof {} is anchored at a different block than leaf proof {}; \
                         every non-padding leaf in a private batch must share one block hash",
                        index,
                        reference_index
                    );
                }
                if meta.block_number != reference_meta.block_number {
                    bail!(
                        "leaf proof {} publishes block number {}, but leaf proof {} publishes \
                         {}",
                        index,
                        meta.block_number,
                        reference_index,
                        reference_meta.block_number
                    );
                }
            }
        }
        for (input, nullifier) in meta.nullifiers.iter().enumerate() {
            if let Some((previous_index, previous_input)) = seen.insert(*nullifier, (index, input))
            {
                bail!(
                    "leaf proof {} publishes nullifier {} that leaf proof {} already published \
                     as its nullifier {}; the private batch constrains all 2N real nullifiers \
                     pairwise distinct, so this batch would only fail after the recursive \
                     proving run",
                    index,
                    input,
                    previous_index,
                    previous_input
                );
            }
        }
    }

    if reference.is_none() {
        bail!(
            "every supplied leaf proof is padding: such a batch settles nothing; supply at \
             least one real leaf proof"
        );
    }
    Ok(())
}
