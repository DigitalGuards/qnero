//! Amounts, as a person reads them.
//!
//! Every figure this wallet prints is QNR. Value in the pool moves in steps of
//! 0.01 QNR, so a pool amount has two decimal places and no more, and neither
//! function here touches floating point: both divide a `u64` count of steps by
//! a hundred and print the remainder as hundredths.
//!
//! The two differ only in what they do with a whole number of QNR. [`qnr`] is
//! the one to reach for: every figure this wallet prints goes through it, its
//! columns and its sentences alike, so a balance and the note it came from
//! carry the same two decimals and a table lines up on its decimal point.
//! [`qnr_plain`] drops hundredths that are zero and has one caller, the
//! faucet's page, where the drip is a headline that reads "10 QNR" and the
//! `...Qnr` fields beside it say the same thing to a probe.

/// Pool steps in one QNR. `POOL_STEP` planck is 0.01 QNR at twelve decimals.
const STEPS_PER_QNR: u64 = 100;

/// An amount in pool steps as QNR, always with its two decimal places.
pub fn qnr(steps: u64) -> String {
    format!("{}.{:02}", steps / STEPS_PER_QNR, steps % STEPS_PER_QNR)
}

/// The same amount with the hundredths dropped when they are zero.
///
/// The faucet page's form, and nothing else's. See the module doc.
pub fn qnr_plain(steps: u64) -> String {
    let hundredths = steps % STEPS_PER_QNR;
    if hundredths == 0 {
        format!("{}", steps / STEPS_PER_QNR)
    } else {
        qnr(steps)
    }
}

/// A count of pool steps out of the QNR amount somebody typed.
///
/// Amounts move in steps of 0.01 QNR, so two decimal places is the whole
/// precision the pool has: a note's value is a count of steps and the circuit
/// range-checks it, so accepting a third decimal here would build a proof for
/// an amount nobody asked for. `wallet-web/src/lib/format.ts` reads what a
/// person types by the same rule, zero included: a spend of nothing costs a
/// circuit build, a proof and the fee to settle it, and leaves the recipient a
/// note worth nothing, so it is refused here rather than proved.
pub fn steps_from_qnr(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let (whole, fraction) = trimmed.split_once('.').unwrap_or((trimmed, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) {
        return Err(format!(
            "{trimmed:?} is not an amount in QNR, such as 12.34"
        ));
    }
    if fraction.len() > 2 {
        return Err(
            "amounts move in steps of 0.01 QNR, so an amount has at most two decimals".to_string(),
        );
    }
    let hundredths: u64 = format!("{fraction:0<2}")
        .parse()
        .map_err(|_| format!("{trimmed:?} is not an amount in QNR, such as 12.34"))?;
    let steps = whole
        .parse::<u64>()
        .ok()
        .and_then(|qnr| qnr.checked_mul(STEPS_PER_QNR))
        .and_then(|steps| steps.checked_add(hundredths))
        .ok_or_else(|| format!("{trimmed} is more QNR than this chain can hold"))?;
    if steps == 0 {
        return Err("an amount has to be more than zero".to_string());
    }
    Ok(steps)
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
    fn a_typed_amount_reads_as_steps() {
        assert_eq!(steps_from_qnr("10"), Ok(1_000));
        assert_eq!(steps_from_qnr("12.34"), Ok(1_234));
        assert_eq!(steps_from_qnr("0.01"), Ok(1));
        assert_eq!(steps_from_qnr("0.5"), Ok(50));
        assert_eq!(steps_from_qnr("  4.11  "), Ok(411));
    }

    /// Zero is refused, because a spend of nothing still costs a circuit
    /// build, a proof and the fee that settles it. The browser wallet refuses
    /// it before the click and this refuses it before the value parser
    /// returns, which is the same answer at the same moment.
    #[test]
    fn nothing_is_not_an_amount() {
        assert!(steps_from_qnr("0").is_err());
        assert!(steps_from_qnr("0.0").is_err());
        assert!(steps_from_qnr("0.00").is_err());
        assert!(steps_from_qnr("00").is_err());
    }

    /// A third decimal has no representation in a note, so it is refused here
    /// rather than rounded into a proof for an amount nobody asked for.
    #[test]
    fn a_third_decimal_is_refused() {
        assert!(steps_from_qnr("0.001").is_err());
        assert!(steps_from_qnr("12.345").is_err());
        assert!(steps_from_qnr("ten").is_err());
        assert!(steps_from_qnr("-1").is_err());
        assert!(steps_from_qnr("").is_err());
        assert!(steps_from_qnr("1e3").is_err());
    }

    /// What the two wallets agree on, amount by amount: the same text in gives
    /// the same count of steps, and that count printed gives the text back.
    #[test]
    fn what_is_typed_and_what_is_printed_are_one_rule() {
        for (typed, steps) in [
            ("10", 1_000u64),
            ("12.34", 1_234),
            ("0.08", 8),
            ("4.11", 411),
            ("0.01", 1),
        ] {
            assert_eq!(steps_from_qnr(typed), Ok(steps));
            assert_eq!(steps_from_qnr(&qnr(steps)), Ok(steps));
        }
        // And the one amount both wallets refuse, printable and unreadable.
        assert_eq!(qnr(0), "0.00");
        assert!(steps_from_qnr("0.00").is_err());
    }

    #[test]
    fn a_sentence_drops_them() {
        assert_eq!(qnr_plain(1_000), "10");
        assert_eq!(qnr_plain(1), "0.01");
        assert_eq!(qnr_plain(1_234), "12.34");
        assert_eq!(qnr_plain(0), "0");
    }
}
