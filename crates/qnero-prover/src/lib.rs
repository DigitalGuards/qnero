//! Proving side of the Qnero v0 spend leaf.
//!
//! The prover is built from source, every time. No prover artifact is ever
//! loaded from disk, and none is emitted: `ProverOnlyCircuitData` carries the
//! witness generators and the target list that decides which witness values
//! become public inputs, so a poisoned artifact could exfiltrate a spend key
//! through the victim's own proof or silently substitute a weaker circuit.
//! The same reasoning is written down in the upstream Wormhole prover; it
//! applies here with more force, because the witness holds `ask` and `nk`.
//!
//! Leaf proofs are non-ZK. They are inputs to the wallet's own private-batch
//! aggregator and must not leave it. [`wallet::WalletProver`] is the API a
//! wallet should use: it builds both circuits once, keeps the leaf proofs
//! inside, and hands back the private-batch proof that is the transaction.

#![forbid(unsafe_code)]

pub mod wallet;

pub use wallet::WalletProver;

use anyhow::{bail, Result};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitConfig, ProverCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qnero_circuit::circuit::{QneroSpendCircuit, SpendTargets};
use qnero_circuit::config::qnero_leaf_circuit_config;
use qnero_circuit::witness::{fill_witness, SpendWitness};
use qnero_circuit::{C, D, F};

/// One-shot prover: build, commit once, prove once.
pub struct QneroProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    /// Taken by `commit`, which is what makes committing twice an error.
    targets: Option<SpendTargets>,
}

/// Redacting `Debug`: after `commit` the partial witness holds `ask`, `nk` and
/// every note field, so it must never reach a log or an error context.
impl core::fmt::Debug for QneroProver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QneroProver")
            .field("circuit_data", &"[ProverCircuitData]")
            .field("partial_witness", &"[REDACTED]")
            .field("committed", &self.targets.is_none())
            .finish()
    }
}

/// Build a prover with the canonical non-ZK leaf config.
pub fn build_fresh() -> QneroProver {
    QneroProver::new(qnero_leaf_circuit_config()).expect("the canonical leaf config is valid")
}

impl QneroProver {
    /// Build the circuit and its prover data.
    ///
    /// The config is validated before plonky2 sees it; see
    /// `qnero_circuit::config::validate_circuit_config`.
    pub fn new(config: CircuitConfig) -> Result<Self> {
        let circuit = QneroSpendCircuit::new(config)?;
        let targets = Some(circuit.targets());
        let circuit_data = circuit.build_prover();

        Ok(Self {
            circuit_data,
            partial_witness: PartialWitness::new(),
            targets,
        })
    }

    /// Fill the witness. Consuming, so a prover cannot be committed twice.
    ///
    /// Structural problems (a path of the wrong depth, a position outside the
    /// arity) are reported verbatim: those messages carry lengths and indices,
    /// never note contents. Anything plonky2 reports from witness filling is
    /// replaced, because it names the conflicting field elements.
    pub fn commit(mut self, witness: &SpendWitness) -> Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already committed to a witness");
        };
        witness.validate()?;
        fill_witness(&mut self.partial_witness, witness, &targets)
            .map_err(|_| anyhow::anyhow!("failed to fill the leaf witness"))?;
        Ok(self)
    }

    /// Prove. Requires a prior [`QneroProver::commit`].
    ///
    /// The underlying error is deliberately dropped. Plonky2 reports an
    /// unsatisfied copy constraint as `Partition containing Wire(..) was set
    /// twice with different values: <a> != <b>`, and both values are witness
    /// material: a note's plaintext amount, or the limbs of a Merkle node that
    /// place the note in the tree. A witness desync is routine for a wallet (a
    /// stale path after a reorg, an index off by one), so the normal reflex of
    /// logging the error would write the spent note's amount and position next
    /// to the nullifier that is about to be published. Everything else in this
    /// crate redacts; this returns nothing to redact.
    pub fn prove(self) -> Result<ProofWithPublicInputs<F, C, D>> {
        if self.targets.is_some() {
            bail!("prover has not committed to a witness");
        }
        self.circuit_data
            .prove(self.partial_witness)
            .map_err(|_| anyhow::anyhow!("failed to prove the leaf"))
    }
}

/// Build, commit and prove in one call.
pub fn prove_leaf(
    config: CircuitConfig,
    witness: &SpendWitness,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    QneroProver::new(config)?.commit(witness)?.prove()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proving_without_committing_is_an_error() {
        let prover = build_fresh();
        assert!(prover.prove().is_err());
    }

    #[test]
    fn prover_debug_does_not_leak_the_witness() {
        let prover = build_fresh();
        let dump = format!("{prover:?}");
        assert!(dump.contains("REDACTED"));
        assert!(!dump.contains("PartialWitness { target_values"));
    }
}
