//! Proof-system parameters of the canonical Qnero leaf.
//!
//! These are the numbers a verifier has to insist on. They live here, next to
//! [`crate::layout`], because the verifier crate reads them without the
//! circuit feature and therefore without plonky2, while the circuit crate
//! asserts the built leaf against them.
//!
//! Every value below is what `CircuitConfig::standard_recursion_config`
//! produces, which is the config
//! [`crate::config::qnero_leaf_circuit_config`] returns. A test pins that
//! agreement, so these constants cannot drift from the config the prover
//! builds with.
//!
//! Why a verifier cares. Verifier data deserializes from bytes, and plonky2's
//! own structural check on it rejects almost nothing: a zero challenge count,
//! a zero constant count, fewer than three routed wires. Nothing there bounds
//! the FRI query count, the grinding bits or the claimed security level, so an
//! artifact built over this exact public-input layout with one query round and
//! no grinding deserializes cleanly and verifies forged proofs with high
//! probability. Checking these parameters is not a substitute for pinning the
//! artifact's hash, which is still to come; it is the floor that holds until
//! there is a tagged release to pin.

/// Claimed security level, in bits.
pub const SECURITY_BITS: usize = 100;

/// Independent challenge repetitions of the PLONK argument.
pub const NUM_CHALLENGES: usize = 2;

/// FRI query rounds. This is the parameter that decides how likely a forged
/// proof is to survive: soundness falls off as `rate^num_query_rounds`.
pub const FRI_NUM_QUERY_ROUNDS: usize = 28;

/// FRI blowup, as `rate = 2^-rate_bits`.
pub const FRI_RATE_BITS: usize = 3;

/// Height of the FRI Merkle caps.
pub const FRI_CAP_HEIGHT: usize = 4;

/// Grinding bits attached to the FRI challenge.
pub const FRI_PROOF_OF_WORK_BITS: u32 = 16;

/// Degree of the canonical leaf's committed polynomials, in bits: the leaf
/// pads to `2^9 = 512` rows.
///
/// Unlike the rest of this module, this one is a property of the constraint
/// system, so it moves when the circuit grows past 512 rows. A test on the
/// built circuit fails when it does, which is the signal to update it here and
/// to regenerate any verifier artifact. It describes the canonical non-ZK
/// leaf: the `zk` config blinds rows and is not a production artifact.
pub const LEAF_DEGREE_BITS: usize = 9;
