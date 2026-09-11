//! Circuit configuration and its structural validation.
//!
//! Forked from `qp-zk-circuits` `common/src/circuit.rs`. Every public circuit
//! constructor runs [`validate_circuit_config`] before the config reaches
//! `CircuitBuilder::new`: an unchecked config panics deep inside plonky2
//! mid-construction, or drives exponential allocation during the expensive
//! build. Validating first moves that failure to the API boundary.

use anyhow::ensure;
use plonky2::plonk::circuit_data::CircuitConfig;

/// The Poseidon gate needs 135 wire columns; a smaller `num_wires` panics
/// inside plonky2's gate compatibility check mid-build.
pub const MIN_NUM_WIRES: usize = 135;

/// The 16-point coset-interpolation gate routes `1 + 16*D + D + D = 37` wires.
/// Below a gate's width, slot-packed gates instantiate with zero operation
/// slots and the build dies on an unrelated assert much later.
pub const MIN_NUM_ROUTED_WIRES: usize = 37;

/// Poseidon constraints have degree 7.
pub const MIN_MAX_QUOTIENT_DEGREE_FACTOR: usize = 7;

/// FRI rate ceiling. The exponent drives `1 << (degree_bits + rate_bits)`
/// allocations per committed polynomial. Production is 3.
pub const MAX_RATE_BITS: usize = 8;

/// FRI cap ceiling. A Merkle cap is `1 << cap_height` hashes per oracle and
/// the recursive verifier allocates that many hash targets as public inputs.
pub const MAX_CAP_HEIGHT: usize = 8;

/// Wire columns of the private batch. Re-exported from [`crate::params`], next
/// to the rest of the numbers a verifier holds a batch artifact to.
pub use crate::params::{PRIVATE_BATCH_NUM_ROUTED_WIRES, PRIVATE_BATCH_NUM_WIRES};

/// Config for the Qnero leaf (spend) circuit: non-ZK.
///
/// A leaf proof is only ever seen by the wallet's own private-batch
/// aggregator, so zero knowledge at this layer buys nothing and costs proving
/// time. Privacy is applied one layer up, where the batch proof is the
/// on-chain transaction unit. Do not ship a flow where a raw leaf proof
/// crosses a trust boundary.
pub fn qnero_leaf_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config() // zero_knowledge: false
}

/// Config for a zero-knowledge leaf circuit.
///
/// Not used in production. It exists so the ZK plumbing stays exercised and a
/// leaf can be made ZK without touching the circuit, for example to prove a
/// leaf to a third party. Requires the `zk` feature; see
/// [`ensure_zk_supported`].
pub fn qnero_leaf_zk_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_zk_config()
}

/// Config for the private batch: zero knowledge, wider routing.
///
/// This is the only layer that blinds. Its witnesses are the wallet's own leaf
/// proofs, whose FRI openings leak the structure of the notes they spend, and
/// the batch proof is the artifact that goes on chain, so blinding here is
/// what makes a transfer private. `num_wires = 135` is the Poseidon gate
/// floor; `num_routed_wires = 60` is what the recursive verifier's routing
/// wants at these degrees, and both are what the Wormhole private batch uses.
///
/// Requires the `zk` feature. `qnero-aggregator` enables it unconditionally,
/// because a production batch that could not blind would be a privacy failure
/// that compiles.
pub fn qnero_private_batch_circuit_config() -> CircuitConfig {
    CircuitConfig {
        num_wires: PRIVATE_BATCH_NUM_WIRES,
        num_routed_wires: PRIVATE_BATCH_NUM_ROUTED_WIRES,
        ..CircuitConfig::standard_recursion_zk_config()
    }
}

/// Config for the public batch: not zero knowledge.
///
/// Its witnesses are private-batch proofs, which are already blinded, and it
/// forwards their public inputs verbatim. Blinding again would buy nothing and
/// cost proving time on the aggregator's critical path.
pub fn qnero_public_batch_circuit_config() -> CircuitConfig {
    CircuitConfig::standard_recursion_config()
}

/// Rejects a zero-knowledge config when plonky2's randomness is not compiled
/// in. Without it, `blind()` panics at circuit-build time with a message about
/// plonky2 internals, leaving the caller to guess that their config caused it.
pub fn ensure_zk_supported(config: &CircuitConfig) -> anyhow::Result<()> {
    ensure!(
        !config.zero_knowledge || cfg!(feature = "zk"),
        "circuit config requests zero_knowledge, which needs the qnero-circuit `zk` feature \
         (plonky2 row blinding is compiled out otherwise and panics during the build)"
    );
    Ok(())
}

/// `ceil(log2(n))` for `n >= 1`.
fn log2_ceil(n: usize) -> usize {
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Structural and resource-bound validation of a caller-supplied
/// [`CircuitConfig`].
///
/// This is a structural policy. It says nothing about canonicality: profiling
/// sweeps legitimately build variant configs, and the canonicality of a
/// production verifier is pinned at the artifact-load boundary.
pub fn validate_circuit_config(config: &CircuitConfig) -> anyhow::Result<()> {
    for (name, value) in [
        ("num_challenges", config.num_challenges),
        ("security_bits", config.security_bits),
        (
            "fri_config.num_query_rounds",
            config.fri_config.num_query_rounds,
        ),
    ] {
        ensure!(value > 0, "circuit config {} must be greater than 0", name);
    }

    ensure!(
        config.num_wires >= MIN_NUM_WIRES,
        "circuit config num_wires ({}) must be >= {} (Poseidon gate floor)",
        config.num_wires,
        MIN_NUM_WIRES,
    );
    ensure!(
        config.num_routed_wires >= MIN_NUM_ROUTED_WIRES,
        "circuit config num_routed_wires ({}) must be >= {} (recursion gate floor)",
        config.num_routed_wires,
        MIN_NUM_ROUTED_WIRES,
    );
    ensure!(
        config.num_routed_wires <= config.num_wires,
        "circuit config num_routed_wires ({}) must be <= num_wires ({})",
        config.num_routed_wires,
        config.num_wires,
    );
    ensure!(
        config.max_quotient_degree_factor >= MIN_MAX_QUOTIENT_DEGREE_FACTOR,
        "circuit config max_quotient_degree_factor ({}) must be >= {} (Poseidon constraint degree)",
        config.max_quotient_degree_factor,
        MIN_MAX_QUOTIENT_DEGREE_FACTOR,
    );
    ensure!(
        config.fri_config.rate_bits <= MAX_RATE_BITS,
        "circuit config fri_config.rate_bits ({}) must be <= {}",
        config.fri_config.rate_bits,
        MAX_RATE_BITS,
    );
    ensure!(
        config.fri_config.cap_height <= MAX_CAP_HEIGHT,
        "circuit config fri_config.cap_height ({}) must be <= {}",
        config.fri_config.cap_height,
        MAX_CAP_HEIGHT,
    );

    // Plonky2 asserts this pair only at proving time, after the full build.
    let quotient_degree_bits = log2_ceil(config.max_quotient_degree_factor);
    ensure!(
        config.fri_config.rate_bits >= quotient_degree_bits,
        "circuit config fri_config.rate_bits ({}) must be >= \
         ceil(log2(max_quotient_degree_factor = {})) = {}",
        config.fri_config.rate_bits,
        config.max_quotient_degree_factor,
        quotient_degree_bits,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    /// `qnero_circuit::params` is what `qnero-verifier` holds an artifact to,
    /// and it compiles without plonky2, so nothing but this test ties it to
    /// the config the prover actually builds with.
    #[test]
    fn the_canonical_config_matches_the_published_parameters() {
        let config = qnero_leaf_circuit_config();
        assert_eq!(config.security_bits, params::SECURITY_BITS);
        assert_eq!(config.num_challenges, params::NUM_CHALLENGES);
        assert_eq!(
            config.fri_config.num_query_rounds,
            params::FRI_NUM_QUERY_ROUNDS
        );
        assert_eq!(config.fri_config.rate_bits, params::FRI_RATE_BITS);
        assert_eq!(config.fri_config.cap_height, params::FRI_CAP_HEIGHT);
        assert_eq!(
            config.fri_config.proof_of_work_bits,
            params::FRI_PROOF_OF_WORK_BITS
        );
    }

    #[test]
    fn canonical_configs_pass() {
        validate_circuit_config(&qnero_leaf_circuit_config()).unwrap();
        validate_circuit_config(&qnero_leaf_zk_circuit_config()).unwrap();
        validate_circuit_config(&qnero_private_batch_circuit_config()).unwrap();
        validate_circuit_config(&qnero_public_batch_circuit_config()).unwrap();
    }

    /// The private batch is the layer that blinds, and the public batch is the
    /// layer that must not pay for blinding it does not need. Both halves are
    /// pinned, because a config flipped either way compiles and proves.
    #[test]
    fn only_the_private_batch_is_zero_knowledge() {
        assert!(qnero_private_batch_circuit_config().zero_knowledge);
        assert!(!qnero_public_batch_circuit_config().zero_knowledge);
        assert_eq!(
            qnero_private_batch_circuit_config().num_wires,
            params::PRIVATE_BATCH_NUM_WIRES
        );
        assert_eq!(
            qnero_private_batch_circuit_config().num_routed_wires,
            params::PRIVATE_BATCH_NUM_ROUTED_WIRES
        );
    }

    /// Every layer shares the leaf's FRI parameters, which is what lets one
    /// parameter floor cover all three artifacts.
    #[test]
    fn every_layer_shares_the_leafs_fri_parameters() {
        use crate::params;

        for config in [
            qnero_private_batch_circuit_config(),
            qnero_public_batch_circuit_config(),
        ] {
            assert_eq!(config.security_bits, params::SECURITY_BITS);
            assert_eq!(config.num_challenges, params::NUM_CHALLENGES);
            assert_eq!(
                config.fri_config.num_query_rounds,
                params::FRI_NUM_QUERY_ROUNDS
            );
            assert_eq!(config.fri_config.rate_bits, params::FRI_RATE_BITS);
            assert_eq!(config.fri_config.cap_height, params::FRI_CAP_HEIGHT);
            assert_eq!(
                config.fri_config.proof_of_work_bits,
                params::FRI_PROOF_OF_WORK_BITS
            );
        }
    }

    #[test]
    fn leaf_config_is_not_zero_knowledge() {
        assert!(!qnero_leaf_circuit_config().zero_knowledge);
        assert!(qnero_leaf_zk_circuit_config().zero_knowledge);
    }

    #[test]
    fn narrow_configs_are_rejected() {
        let mut config = qnero_leaf_circuit_config();
        config.num_wires = MIN_NUM_WIRES - 1;
        assert!(validate_circuit_config(&config).is_err());

        let mut config = qnero_leaf_circuit_config();
        config.num_routed_wires = MIN_NUM_ROUTED_WIRES - 1;
        assert!(validate_circuit_config(&config).is_err());

        let mut config = qnero_leaf_circuit_config();
        config.fri_config.rate_bits = MAX_RATE_BITS + 1;
        assert!(validate_circuit_config(&config).is_err());
    }

    #[test]
    fn zk_config_is_gated_by_the_feature() {
        let result = ensure_zk_supported(&qnero_leaf_zk_circuit_config());
        assert_eq!(result.is_ok(), cfg!(feature = "zk"));
        ensure_zk_supported(&qnero_leaf_circuit_config()).unwrap();
    }
}
