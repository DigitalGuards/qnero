//! Recursive proof verification with the inner verifier key as constants.
//!
//! A recursive verifier needs the inner proof and the inner verifier key. The
//! key can enter the circuit two ways, and only one of them is sound:
//!
//! ```ignore
//! let key = builder.add_virtual_verifier_data(cap_height);  // WITNESSED: unsound
//! let key = builder.constant_verifier_data::<C>(&inner_vk); // CONSTANT: sound
//! ```
//!
//! A witnessed key lets the prover substitute the verifier key of a circuit of
//! their own with no constraints at all, prove anything they like in it, and
//! have the wrapper accept it. Baking the key in as constants means the
//! wrapper only ever accepts proofs of the one circuit it was built over, and
//! it costs nothing extra: the constants are folded into the circuit digest.

use anyhow::Result;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::config::validate_proof_count;
use qnero_circuit::{C, D, F};

/// Add `num_proofs` recursive verifications of one inner circuit, all against
/// the same constant verifier key, and return the proof targets.
///
/// The proof targets are the only witness this adds. `num_proofs` is bounded
/// here as well as in the batch constructors, because it drives both the
/// allocation and the per-slot circuit construction, and zero would produce a
/// wrapper with no inner-proof constraints at all.
pub fn add_recursive_verifiers(
    builder: &mut CircuitBuilder<F, D>,
    inner_common: &CommonCircuitData<F, D>,
    inner_verifier_only: &VerifierOnlyCircuitData<C, D>,
    num_proofs: usize,
) -> Result<Vec<ProofWithPublicInputsTarget<D>>> {
    validate_proof_count(num_proofs, "num_proofs")?;

    let verifier_data = builder.constant_verifier_data::<C>(inner_verifier_only);

    let mut proofs = Vec::with_capacity(num_proofs);
    for _ in 0..num_proofs {
        let proof = builder.add_virtual_proof_with_pis(inner_common);
        builder.verify_proof::<C>(&proof, &verifier_data, inner_common);
        proofs.push(proof);
    }

    Ok(proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;

    fn inner_circuit(constrained: bool) -> plonky2::plonk::circuit_data::CircuitData<F, C, D> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target = builder.add_virtual_target();
        builder.register_public_input(target);
        if constrained {
            builder.range_check(target, 16);
        }
        builder.build::<C>()
    }

    #[test]
    fn out_of_range_proof_counts_are_rejected() {
        let inner = inner_circuit(true);
        for count in [0, MAX_COUNT + 1] {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let error =
                add_recursive_verifiers(&mut builder, &inner.common, &inner.verifier_only, count)
                    .expect_err("an out-of-range proof count must be rejected");
            assert!(error.to_string().contains("num_proofs"), "got: {error}");
        }
    }

    const MAX_COUNT: usize = crate::config::MAX_PROOF_COUNT;

    /// The property the constant verifier key exists for: a proof of a
    /// different circuit, even one with the same public-input shape, cannot be
    /// aggregated. With a witnessed key this test passes the malicious proof.
    #[test]
    fn a_proof_of_another_circuit_is_refused() {
        let honest = inner_circuit(true);
        let malicious = inner_circuit(false);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets =
            add_recursive_verifiers(&mut builder, &honest.common, &honest.verifier_only, 1)
                .unwrap();
        builder.register_public_inputs(&targets[0].public_inputs);
        let outer = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(
            malicious.prover_only.public_inputs[0],
            F::from_canonical_u64(100),
        )
        .unwrap();
        let malicious_proof = malicious.prove(pw).expect("the malicious inner proof");

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&targets[0], &malicious_proof)
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| outer.prove(pw)));
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "a proof of a different circuit was aggregated"
        );
    }

    #[test]
    fn a_proof_of_the_baked_in_circuit_is_accepted() {
        let honest = inner_circuit(true);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets =
            add_recursive_verifiers(&mut builder, &honest.common, &honest.verifier_only, 1)
                .unwrap();
        builder.register_public_inputs(&targets[0].public_inputs);
        let outer = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_target(
            honest.prover_only.public_inputs[0],
            F::from_canonical_u64(100),
        )
        .unwrap();
        let inner_proof = honest.prove(pw).expect("the honest inner proof");

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&targets[0], &inner_proof)
            .unwrap();
        let proof = outer.prove(pw).expect("the wrapper proves");
        outer.verify(proof).expect("and verifies");
    }
}
