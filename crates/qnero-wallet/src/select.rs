//! Choosing which notes to spend.
//!
//! The leaf circuit has exactly two input slots, so a spend reaches at most
//! two notes and the rest of the balance is unreachable in one transaction.
//! Largest first, because it is the selection that reaches the largest payment
//! from a given wallet, and because it keeps the note count falling rather
//! than growing a tail of dust a two-input circuit can never sweep.

use anyhow::{bail, Result};

use crate::store::StoredNote;

/// Input slots in the leaf circuit.
pub const MAX_INPUTS: usize = 2;

/// Pick up to [`MAX_INPUTS`] unspent notes covering `target`, largest first.
///
/// `target` is the payment plus the fee: both leave the pool, and the balance
/// equation is `inputs = outputs + fee`.
pub fn select_notes<'a>(
    unspent: impl IntoIterator<Item = &'a StoredNote>,
    target: u64,
) -> Result<Vec<&'a StoredNote>> {
    let mut candidates: Vec<&StoredNote> = unspent.into_iter().collect();
    // Ties broken by leaf index so the choice is deterministic: two notes of
    // equal value are otherwise ordered by however the store was written, and
    // a wallet that picks differently on a retry proves a different leaf.
    candidates.sort_by(|a, b| {
        b.value
            .cmp(&a.value)
            .then_with(|| a.leaf_index.cmp(&b.leaf_index))
    });

    let mut chosen = Vec::new();
    let mut total = 0u64;
    for note in candidates.iter().take(MAX_INPUTS) {
        chosen.push(*note);
        total = total.saturating_add(note.value);
        if total >= target {
            return Ok(chosen);
        }
    }

    let reachable = total;
    let held: u64 = candidates.iter().map(|note| note.value).sum();
    if candidates.is_empty() {
        bail!("this wallet holds no unspent notes");
    }
    bail!(
        "need {target} quanta and the {} largest of {} unspent notes reach {reachable} \
         ({held} held in total). A spend has {MAX_INPUTS} input slots, so consolidate first: \
         send yourself the largest notes to merge them.",
        chosen.len(),
        candidates.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NoteOrigin;
    use qnero_notes::Digest;

    fn note(value: u64, leaf_index: u64) -> StoredNote {
        StoredNote {
            leaf_index,
            block_number: Some(1),
            value,
            commitment: Digest::hash_bytes(&[b"cm", &leaf_index.to_le_bytes()]).to_hex(),
            nullifier: Digest::hash_bytes(&[b"nf", &leaf_index.to_le_bytes()])
                .to_hex()
                .into(),
            rho: Digest::hash_bytes(&[b"rho", &leaf_index.to_le_bytes()])
                .to_hex()
                .into(),
            r: Digest::hash_bytes(&[b"r", &leaf_index.to_le_bytes()])
                .to_hex()
                .into(),
            memo: String::new(),
            origin: NoteOrigin::Shield,
            spent: false,
            spent_seen_at_block: None,
            on_chain: true,
        }
    }

    #[test]
    fn one_note_is_enough_when_it_covers_the_target() {
        let notes = [note(1_000, 0), note(400, 1)];
        let chosen = select_notes(notes.iter(), 300).unwrap();
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].value, 1_000);
    }

    #[test]
    fn a_second_note_is_added_only_when_the_first_falls_short() {
        let notes = [note(200, 0), note(400, 1), note(50, 2)];
        let chosen = select_notes(notes.iter(), 500).unwrap();
        assert_eq!(
            chosen.iter().map(|n| n.value).collect::<Vec<_>>(),
            vec![400, 200]
        );
    }

    /// The circuit has two input slots. A balance spread over three notes is
    /// not reachable in one spend, and the wallet has to say so. A witness
    /// built anyway carries a balance equation that cannot hold.
    #[test]
    fn a_balance_spread_over_three_notes_is_refused_with_the_reachable_total() {
        let notes = [note(100, 0), note(100, 1), note(100, 2)];
        let error = select_notes(notes.iter(), 250).unwrap_err().to_string();
        assert!(error.contains("reach 200"), "{error}");
        assert!(error.contains("300 held in total"), "{error}");
    }

    #[test]
    fn the_fee_is_part_of_the_target() {
        let notes = [note(300, 0)];
        assert!(select_notes(notes.iter(), 300).is_ok());
        assert!(select_notes(notes.iter(), 301).is_err());
    }

    /// Two notes of equal value must be picked in one fixed order: a retry
    /// that picked the other one would spend a different note.
    #[test]
    fn equal_values_break_ties_on_the_leaf_index() {
        let notes = [note(100, 7), note(100, 3)];
        let chosen = select_notes(notes.iter(), 100).unwrap();
        assert_eq!(chosen[0].leaf_index, 3);
    }

    #[test]
    fn an_empty_wallet_says_so() {
        let empty: Vec<StoredNote> = Vec::new();
        let error = select_notes(empty.iter(), 1).unwrap_err().to_string();
        assert!(error.contains("no unspent notes"), "{error}");
    }
}
