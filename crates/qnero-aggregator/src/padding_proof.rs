//! The padding leaf proof: how it is produced, and what a consumer must check
//! before treating one as padding.
//!
//! A private batch has a fixed number of slots, and every slot holds a proof
//! of the leaf circuit, because the leaf verifier key is baked into the
//! wrapper as constants. A wallet with fewer transfers than slots fills the
//! rest with this one proof.
//!
//! The padding leaf's witness is deterministic (`qnero_circuit::padding`), so
//! its proof is a reproducible artifact: build it once, publish it, clone it
//! into every empty slot. Nothing it publishes reaches the chain, because the
//! wrapper masks every value a padding slot carries.

use anyhow::{anyhow, bail, Result};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::{CircuitData, CommonCircuitData, VerifierCircuitData};

use qnero_circuit::circuit::SpendTargets;
use qnero_circuit::padding::padding_leaf_witness;
use qnero_circuit::witness::fill_witness;
use qnero_circuit::{C, D, F};

use crate::Proof;

/// The public inputs the canonical padding leaf publishes.
///
/// Every field is a function of the fixed padding witness, so this is the
/// exact 26-felt vector a genuine padding template carries. It is what
/// [`validate_padding_leaf_template`] compares against.
pub fn canonical_padding_leaf_public_inputs() -> Vec<F> {
    padding_leaf_witness().public_inputs()
}

/// Prove the padding leaf against an already built leaf circuit.
///
/// Takes the built `CircuitData` because the caller (the artifact builder) has
/// to build the leaf circuit anyway, and proving before consuming it into
/// verifier data saves a second build.
pub fn generate_padding_leaf_proof(
    circuit_data: &CircuitData<F, C, D>,
    targets: &SpendTargets,
) -> Result<Proof> {
    let witness = padding_leaf_witness();
    let mut pw = PartialWitness::<F>::new();
    fill_witness(&mut pw, &witness, targets)
        .map_err(|e| anyhow!("failed to fill the padding leaf witness: {}", e))?;
    circuit_data
        .prove(pw)
        .map_err(|e| anyhow!("failed to prove the padding leaf: {}", e))
}

/// Deserialize a padding leaf proof against the leaf's common data.
pub fn load_padding_leaf_proof(bytes: Vec<u8>, common: &CommonCircuitData<F, D>) -> Result<Proof> {
    Proof::from_bytes(bytes, common)
        .map_err(|e| anyhow!("failed to deserialize the padding leaf proof: {}", e))
}

/// Accept a proof as the padding template only if it is exactly the canonical
/// padding leaf, and only if it verifies.
///
/// Both halves are required, and the cheap one runs first.
///
/// The public-input comparison is exact, rather than a field-by-field sentinel
/// check, because the padding witness is fully determined: any deviation is a
/// template that is not the padding leaf. Upstream can only check a handful of
/// fields, because its dummy leaf carries prover-chosen values the sentinel
/// does not cover, and that gap is what forces its wrapper to re-mask exit
/// accounts.
///
/// What this stops: a real leaf proof planted where the padding template is
/// read from. The wrapper masks a padding slot's published values, so such a
/// template settles nothing even if it slips through, but it would be baked
/// into the published all-padding private batch, and a consumer would then be
/// padding public batches with a proof that is not what its name says.
pub fn validate_padding_leaf_template(
    template: &Proof,
    leaf_verifier: &VerifierCircuitData<F, C, D>,
) -> Result<()> {
    let expected = canonical_padding_leaf_public_inputs();
    if template.public_inputs != expected {
        bail!(
            "the padding leaf template does not carry the canonical padding leaf's public \
             inputs; refusing to use it as batch padding"
        );
    }
    leaf_verifier
        .verify(template.clone())
        .map_err(|e| anyhow!("the padding leaf template failed verification: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use qnero_circuit::batch_layout::DIGEST_FELTS;
    use qnero_circuit::layout::{BLOCK_HASH_START, FEE_INDEX};
    use qnero_circuit::padding::PADDING_BLOCK_HASH;

    use crate::test_fixtures::{leaf_circuit, leaf_proof};

    /// A proof of a circuit that is not the leaf, publishing exactly the
    /// public inputs it is handed.
    ///
    /// Its only constraint is that each public input equals a constant, so it
    /// can claim any public-input vector. What it cannot do is verify against
    /// the leaf's verifier data.
    fn proof_of_another_circuit(public_inputs: &[F]) -> Proof {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        for value in public_inputs {
            let target = builder.constant(*value);
            builder.register_public_input(target);
        }
        let data = builder.build::<C>();
        let proof = data
            .prove(plonky2::iop::witness::PartialWitness::new())
            .expect("the stand-in circuit proves");
        assert_eq!(proof.public_inputs, public_inputs);
        proof
    }

    #[test]
    fn the_canonical_padding_public_inputs_carry_the_sentinel_and_no_value() {
        let public = canonical_padding_leaf_public_inputs();
        assert_eq!(public.len(), qnero_circuit::layout::PUBLIC_INPUT_LEN);
        for i in 0..DIGEST_FELTS {
            assert_eq!(
                public[BLOCK_HASH_START + i].to_canonical_u64(),
                PADDING_BLOCK_HASH[i]
            );
        }
        assert_eq!(public[FEE_INDEX], F::ZERO);
    }

    /// A real leaf proof planted where the padding template is read from is
    /// refused.
    ///
    /// This is the substitution the validator exists to stop: such a template
    /// would be cloned into every empty slot and baked into the published
    /// all-padding private batch, so the artifact would not be what its name
    /// says. Without this test the comparison could be inverted or deleted and
    /// every gate would stay green.
    #[test]
    fn a_real_leaf_proof_is_not_the_padding_template() {
        let (_, leaf) = leaf_circuit();
        let verifier = leaf.verifier_data();
        let real = leaf_proof("not-padding");

        // The control: the genuine template passes.
        let (targets, data) = leaf_circuit();
        let padding = generate_padding_leaf_proof(data, targets).expect("the padding leaf proves");
        validate_padding_leaf_template(&padding, &verifier)
            .expect("the canonical padding leaf is the padding template");

        let error = validate_padding_leaf_template(&real, &verifier)
            .expect_err("a real leaf proof must not be accepted as padding");
        assert!(
            error.to_string().contains("canonical padding leaf"),
            "got: {error}"
        );
    }

    /// Matching public inputs are not enough: the proof must also be a proof
    /// of the leaf circuit.
    ///
    /// This pins the verification half. A template whose public inputs were
    /// copied from the canonical padding leaf passes the comparison and must
    /// still be refused, otherwise the check degrades to a string match on
    /// values an attacker chooses.
    #[test]
    fn canonical_public_inputs_alone_are_not_the_padding_template() {
        let (_, leaf) = leaf_circuit();
        let verifier = leaf.verifier_data();
        let impostor = proof_of_another_circuit(&canonical_padding_leaf_public_inputs());

        let error = validate_padding_leaf_template(&impostor, &verifier)
            .expect_err("a proof of another circuit must not be accepted as padding");
        assert!(
            error.to_string().contains("failed verification"),
            "got: {error}"
        );
    }
}
