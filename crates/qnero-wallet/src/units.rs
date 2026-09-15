//! Amounts, as a person reads them.
//!
//! Every figure this wallet prints is QNR. Value in the pool moves in steps of
//! 0.01 QNR, so a pool amount has two decimal places and no more, and neither
//! function here touches floating point: both divide a `u64` count of steps by
//! a hundred and print the remainder as hundredths.
//!
//! The two differ only in what they do with a whole number of QNR, because a
//! column and a sentence want different things. [`qnr`] keeps the hundredths,
//! so a table of figures lines up on its decimal point; [`qnr_plain`] drops
//! them, because "10 QNR" is how a sentence says it.

/// Pool steps in one QNR. `POOL_STEP` planck is 0.01 QNR at twelve decimals.
const STEPS_PER_QNR: u64 = 100;

/// An amount in pool steps as QNR, always with its two decimal places.
pub fn qnr(steps: u64) -> String {
    format!("{}.{:02}", steps / STEPS_PER_QNR, steps % STEPS_PER_QNR)
}

/// The same amount with the hundredths dropped when they are zero.
pub fn qnr_plain(steps: u64) -> String {
    let hundredths = steps % STEPS_PER_QNR;
    if hundredths == 0 {
        format!("{}", steps / STEPS_PER_QNR)
    } else {
        qnr(steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::POOL_STEP;

    /// The step this module divides by is the step the chain moves value in.
    #[test]
    fn a_hundred_steps_is_one_qnr() {
        assert_eq!(u128::from(STEPS_PER_QNR) * POOL_STEP, 1_000_000_000_000);
    }

    #[test]
    fn a_column_keeps_its_hundredths() {
        assert_eq!(qnr(1_000), "10.00");
        assert_eq!(qnr(8), "0.08");
        assert_eq!(qnr(1_234), "12.34");
        assert_eq!(qnr(411), "4.11");
        assert_eq!(qnr(0), "0.00");
    }

    #[test]
    fn a_sentence_drops_them() {
        assert_eq!(qnr_plain(1_000), "10");
        assert_eq!(qnr_plain(1), "0.01");
        assert_eq!(qnr_plain(1_234), "12.34");
        assert_eq!(qnr_plain(0), "0");
    }
}
