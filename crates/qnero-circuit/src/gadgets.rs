//! Comparison gadgets.
//!
//! Forked from `qp-zk-circuits` `common/src/gadgets.rs`, restricted to widths
//! below 64 bits and extended with a bit-sharing entry point.

use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::{D, F};

/// `a XOR b = a + b - 2ab`.
fn xor(builder: &mut CircuitBuilder<F, D>, a: BoolTarget, b: BoolTarget) -> BoolTarget {
    let a_plus_b = builder.add(a.target, b.target);
    let ab = builder.mul(a.target, b.target);
    let two_ab = builder.add(ab, ab);
    let result = builder.sub(a_plus_b, two_ab);
    // Safe: a, b are bits, so a + b - 2ab is 0 or 1.
    BoolTarget::new_unsafe(result)
}

fn assert_comparison_width(left: usize, n_log: usize) {
    assert!(n_log > 0, "comparison bit width must be greater than zero");
    // 2^n_log must be below the Goldilocks modulus for the little-endian
    // decomposition of a field element to be unique. At 64 bits both `x` and
    // `x + p` are valid bit patterns, so a prover could pick whichever flips
    // the comparison. Upstream handles 64 bits through a canonical half-split;
    // nothing here is wider than 62 bits, so that branch is left out.
    assert!(
        n_log <= 63,
        "comparison bit width {n_log} exceeds 63 bits (Goldilocks decomposition is not unique)"
    );
    assert!(
        left < (1usize << n_log),
        "left constant {left} does not fit in comparison width {n_log} bits"
    );
}

/// `left < right` for a constant `left` against the little-endian bits of
/// `right`, least significant first.
///
/// Callers that compare many constants against the same target split it once
/// and share the bits. Splitting is what range-constrains `right`, so the
/// caller owns that: the bits must come from `builder.split_le`.
pub fn const_less_than_bits(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    right_bits: &[BoolTarget],
) -> BoolTarget {
    let n_log = right_bits.len();
    assert_comparison_width(left, n_log);

    let mut lt = builder._false();
    let mut eq = builder._true();

    for i in (0..n_log).rev() {
        let a = builder.constant_bool((left >> i) & 1 != 0);
        let b = right_bits[i];

        let not_a = builder.not(a);
        let not_a_and_b = builder.and(not_a, b);
        let this_lt = builder.and(not_a_and_b, eq);
        lt = builder.or(lt, this_lt);

        let a_xor_b = xor(builder, a, b);
        let not_xor = builder.not(a_xor_b);
        eq = builder.and(eq, not_xor);
    }

    lt
}

/// `left < right` for a constant `left`. Also range-constrains `right` to
/// `n_log` bits.
pub fn is_const_less_than(
    builder: &mut CircuitBuilder<F, D>,
    left: usize,
    right: Target,
    n_log: usize,
) -> BoolTarget {
    assert_comparison_width(left, n_log);
    let right_bits = builder.split_le(right, n_log);
    const_less_than_bits(builder, left, &right_bits)
}

/// Enforce `target < upper_bound_exclusive`, and constrain `target` to
/// `n_log` bits.
pub fn enforce_target_less_than_const(
    builder: &mut CircuitBuilder<F, D>,
    target: Target,
    upper_bound_exclusive: usize,
    n_log: usize,
) {
    assert!(
        upper_bound_exclusive > 0,
        "exclusive upper bound must be greater than zero"
    );
    assert_comparison_width(upper_bound_exclusive - 1, n_log);

    let overflow = is_const_less_than(builder, upper_bound_exclusive - 1, target, n_log);
    let zero = builder.zero();
    builder.connect(overflow.target, zero);
}

/// `a == b` over two 4-felt digests.
pub fn digests_are_equal(
    builder: &mut CircuitBuilder<F, D>,
    a: [Target; 4],
    b: [Target; 4],
) -> BoolTarget {
    let mut all_equal = builder._true();
    for i in 0..4 {
        let limb_equal = builder.is_equal(a[i], b[i]);
        all_equal = builder.and(all_equal, limb_equal);
    }
    all_equal
}
