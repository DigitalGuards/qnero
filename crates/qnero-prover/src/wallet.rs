//! The wallet's proving API: a leaf per transfer, a private batch per
//! submission.
//!
//! ```
//! # use qnero_circuit::witness::SpendWitness;
//! # use qnero_prover::WalletProver;
//! # const NUM_LEAVES: usize = 7;
//! # fn submit(witness: SpendWitness) -> anyhow::Result<()> {
//! let wallet = WalletProver::new(NUM_LEAVES)?;                // one build per process
//! let bytes = wallet.prove_submission_bytes(vec![witness])?;  // one transaction
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```
//!
//! Compiled, so a rename of either method breaks the build and these docs
//! cannot drift into describing an API that is gone. Nothing here runs:
//! building the circuits takes seconds.
//!
//! # What a wallet actually submits
//!
//! The private batch proof. A leaf is built with `standard_recursion_config`,
//! which does not blind, so its FRI openings leak the structure of the notes
//! it spends, and it exists only to be aggregated. Zero knowledge is applied
//! one layer up. [`WalletProver::prove_submission`] keeps its leaf proofs
//! inside the call and is the method a wallet should use;
//! [`WalletProver::prove_leaf`] is an advanced seam, and what it returns must
//! not cross a trust boundary.
//!
//! # Cost
//!
//! Building the private-batch circuit is seconds and proving one is tens of
//! seconds; building the leaf circuit is tens of milliseconds and proving one
//! is a fraction of a second. So this type builds both circuits once and keeps
//! them, and every method takes `&self`. Constructing one per transaction is
//! the mistake this API exists to prevent.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;
use qnero_aggregator::private_batch::QneroPrivateBatchProver;
use qnero_aggregator::{generate_padding_leaf_proof, Proof};
use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::config::{qnero_leaf_circuit_config, qnero_private_batch_circuit_config};
use qnero_circuit::witness::{fill_witness, SpendWitness};
use qnero_circuit::{C, D, F};

/// Builds leaf proofs and the private batch that carries them.
pub struct WalletProver {
    leaf_targets: SpendTargets,
    leaf_data: CircuitData<F, C, D>,
    batch: QneroPrivateBatchProver,
}

/// Redacting `Debug`: this type holds circuit data and a padding template, and
/// its methods touch spend credentials.
impl core::fmt::Debug for WalletProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletProver")
            .field("num_leaves", &self.batch.num_leaves())
            .finish()
    }
}

impl WalletProver {
    /// Build both circuits from source and prove the padding leaf.
    ///
    /// Nothing is read from disk. Every circuit here is a function of the
    /// compiled code, which is what makes a poisoned artifact a non-issue at
    /// this layer; see `qnero_aggregator::artifacts`.
    pub fn new(num_leaves: usize) -> Result<Self> {
        let circuit = QneroSpendCircuit::new(qnero_leaf_circuit_config())?;
        let leaf_targets = circuit.targets();
        let leaf_data = circuit.build();
        let padding_leaf = generate_padding_leaf_proof(&leaf_data, &leaf_targets)?;

        let leaf_verifier = leaf_data.verifier_data();
        let batch = QneroPrivateBatchProver::new(
            qnero_private_batch_circuit_config(),
            leaf_verifier.common,
            &leaf_verifier.verifier_only,
            num_leaves,
            padding_leaf,
        )?;

        Ok(Self {
            leaf_targets,
            leaf_data,
            batch,
        })
    }

    /// Build from a published artifact directory.
    ///
    /// The leaf circuit is still rebuilt from source; what the directory
    /// supplies is the slot count and the padding leaf proof, and the leaf
    /// verifier artifact beside them is pinned to the rebuild before either is
    /// used.
    pub fn from_artifact_dir(bins_dir: &Path) -> Result<Self> {
        let batch = QneroPrivateBatchProver::new_from_artifact_dir(bins_dir)
            .with_context(|| format!("failed to load artifacts from {}", bins_dir.display()))?;
        let circuit = QneroSpendCircuit::new(qnero_leaf_circuit_config())?;
        let leaf_targets = circuit.targets();
        let leaf_data = circuit.build();
        Ok(Self {
            leaf_targets,
            leaf_data,
            batch,
        })
    }

    /// Leaf slots per batch.
    pub fn num_leaves(&self) -> usize {
        self.batch.num_leaves()
    }

    /// Prove one transfer.
    ///
    /// The witness is built from `qnero-notes` types: a [`Note`] and the keys
    /// that spend it, a Merkle path from the chain, and the recipient's `pk`.
    /// See `qnero_circuit::witness::InputNote::real`.
    ///
    /// The error deliberately carries nothing from plonky2. A witness desync
    /// is routine for a wallet, a stale path after a reorg or an index off by
    /// one, and plonky2 reports an unsatisfied copy constraint by naming the
    /// two conflicting field elements: a note's amount, or the limbs that
    /// place it in the tree. Logging that would write the spent note's value
    /// next to the nullifier about to be published.
    ///
    /// The proof this returns is not zero knowledge and is not a
    /// transaction. It is an input to [`Self::aggregate`], and handing one to
    /// anything outside the wallet publishes the structure of the notes it
    /// spends. Callers that do not need the two steps apart should use
    /// [`Self::prove_submission`], which keeps them inside one call.
    ///
    /// [`Note`]: qnero_notes::Note
    pub fn prove_leaf(&self, witness: &SpendWitness) -> Result<Proof> {
        witness.validate()?;
        let mut pw = PartialWitness::<F>::new();
        fill_witness(&mut pw, witness, &self.leaf_targets)
            .map_err(|_| anyhow!("failed to fill the leaf witness"))?;
        self.leaf_data
            .prove(pw)
            .map_err(|_| anyhow!("failed to prove the leaf"))
    }

    /// Aggregate leaf proofs into one private batch, padding the empty slots.
    ///
    /// Takes `1..=num_leaves` proofs. Padding, shuffling and the admission
    /// checks are the aggregator's; see
    /// [`QneroPrivateBatchProver::aggregate`].
    pub fn aggregate(&self, leaf_proofs: Vec<Proof>) -> Result<Proof> {
        self.batch.aggregate(leaf_proofs)
    }

    /// Prove one transaction end to end: a leaf per transfer, then the batch.
    ///
    /// The leaf proofs stay inside this call. They are not zero knowledge and
    /// there is no reason for a caller to hold one.
    pub fn prove_submission(&self, transfers: Vec<SpendWitness>) -> Result<Proof> {
        if transfers.is_empty() {
            bail!("a submission needs at least one transfer");
        }
        if transfers.len() > self.num_leaves() {
            bail!(
                "got {} transfers, but a batch has {} slots",
                transfers.len(),
                self.num_leaves()
            );
        }
        let leaf_proofs = transfers
            .iter()
            .map(|witness| self.prove_leaf(witness))
            .collect::<Result<Vec<_>>>()?;
        self.aggregate(leaf_proofs)
    }

    /// [`Self::prove_submission`], serialized for the wire.
    ///
    /// This is what a wallet sends. The bytes are plonky2's canonical encoding
    /// of the proof, which is what the chain requires: its reader accepts
    /// trailing bytes and non-canonical limbs, so anything but the canonical
    /// encoding would give one transaction several identities.
    pub fn prove_submission_bytes(&self, transfers: Vec<SpendWitness>) -> Result<Vec<u8>> {
        Ok(self.prove_submission(transfers)?.to_bytes())
    }

    /// An all-padding private batch: the template a public batch fills its
    /// empty inner slots with.
    ///
    /// Not a wallet's business, and it is here because the wallet is what
    /// holds a canonical private-batch prover. An aggregator that wraps
    /// inners from wallets needs one padding inner of exactly this shape, and
    /// building a second private-batch circuit to produce it costs seconds
    /// and proves nothing the first one did not. It settles nothing: a
    /// submission whose every segment is padding is refused with
    /// `NothingToSettle`.
    pub fn padding_batch_proof(&self) -> Result<Proof> {
        self.batch.prove_padding_batch()
    }

    /// Verifier data for the batch circuit, so a wallet can check its own
    /// proof before sending it.
    pub fn batch_verifier_data(
        &self,
    ) -> plonky2::plonk::circuit_data::VerifierCircuitData<F, C, D> {
        self.batch.verifier_data()
    }
}
