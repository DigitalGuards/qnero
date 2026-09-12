//! Memos: padded on the way out, unpadded on the way in, escaped on the way to
//! a terminal.
//!
//! A note ciphertext is a fixed 1731 bytes plus its memo, byte for byte
//! (`qnero_pqcrypto::note_encryption`: the memo rides in its own AEAD payload
//! and `to_bytes` length-prefixes it). The chain publishes those bytes in
//! full, in `Shielded::Ciphertexts` and in the `SlotSettled` event, so an
//! unpadded memo publishes its own exact length to every chain reader. Two
//! things follow from that, and both are why every memo this wallet writes is
//! padded to one size:
//!
//! - `len(ct_1) - len(ct_2)` is the memo's byte count. It correlates any two
//!   payments carrying the same memo string, with no key material at all.
//! - A spend writes a payment and a change note. The change memo is empty, so
//!   an unpadded pair splits the pool's outputs publicly into "went to a
//!   counterparty" and "came back to the sender", which is most of what the
//!   pool exists to hide.
//!
//! The fee is computed from the same total, so it republishes the length in
//! `CiphertextBytesPerFeeQuantum` buckets even when nobody reads the
//! ciphertexts.

use anyhow::{bail, Result};

/// Every memo this wallet encrypts is exactly this many bytes.
///
/// The budget is `MaxCiphertextBytes` (2048 in the M4 runtime) minus the 1731
/// bytes of a memoless `NoteCiphertext`, which is 317. This is the largest
/// round size inside it with headroom left, and it is a wallet-side constant:
/// the chain does not care what a memo is, only that the ciphertext fits
/// under its bound, which `fee::ensure_ciphertext_fits` checks against the
/// runtime's own value before anything is proved.
///
/// Zcash's 512-byte memo field is the precedent for padding at all. The size
/// differs because this ciphertext's fixed part is larger.
pub const MEMO_BYTES: usize = 256;

/// Columns of memo `balance` will print before it truncates.
pub const MEMO_DISPLAY_COLUMNS: usize = 64;

/// Pad a memo to [`MEMO_BYTES`] with trailing zeros.
pub fn pad_memo(memo: &str) -> Result<Vec<u8>> {
    let bytes = memo.as_bytes();
    if bytes.len() > MEMO_BYTES {
        bail!(
            "the memo is {} bytes and this wallet pads every memo to {MEMO_BYTES}. A longer one \
             would make this ciphertext a different length from every other note's, which is the \
             leak the padding exists to close.",
            bytes.len()
        );
    }
    let mut padded = vec![0u8; MEMO_BYTES];
    padded[..bytes.len()].copy_from_slice(bytes);
    Ok(padded)
}

/// Strip the padding a received memo carries.
///
/// Trailing zero bytes, the way the padding writes them. A memo from a sender
/// that does not pad passes through unchanged unless it ends in NUL, which a
/// text memo does not.
pub fn unpad_memo(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    &bytes[..end]
}

/// Render a memo for a terminal.
///
/// A memo is remote input: anyone holding this wallet's address can send it a
/// note, and the memo rides along. Printed byte for byte it is an escape
/// sequence injection into the operator's terminal. `\r\x1b[2K` erases the
/// line just written and lets the sender redraw the balance table with leaf
/// indices, values and spent flags of their choosing; `\x1b]52;c;...\x07`
/// writes the sender's own address into the clipboard the operator then pastes
/// into `send --to`. Bidi controls reorder a line without any escape at all.
///
/// So every control character and every bidi override is escaped, and the
/// result is truncated, so one note can never exceed one row. The store keeps
/// the raw memo: serde_json escapes control characters on the way to the file,
/// and a wallet that rewrote what it received could not show an operator what
/// was actually sent.
pub fn render_memo(memo: &str) -> String {
    let mut out = String::new();
    let mut columns = 0usize;
    for character in memo.chars() {
        let rendered = if needs_escaping(character) {
            format!("\\u{{{:02x}}}", character as u32)
        } else {
            character.to_string()
        };
        let width = rendered.chars().count();
        if columns + width > MEMO_DISPLAY_COLUMNS {
            out.push_str("...");
            return out;
        }
        columns += width;
        out.push_str(&rendered);
    }
    out
}

/// Whether a character may not reach a terminal as itself.
///
/// C0 and C1 controls, DEL, and the bidirectional formatting characters. The
/// first group moves the cursor and starts escape sequences; the second
/// reorders a line's visible text without one.
fn needs_escaping(character: char) -> bool {
    character.is_control()
        || matches!(character, '\u{7f}'..='\u{9f}')
        || matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the padding exists for: every memo this wallet writes
    /// produces a ciphertext of one length, so no observer reads a memo's size
    /// off the chain and no spend's change note is the shorter of the pair.
    #[test]
    fn every_padded_memo_is_the_same_length() {
        let lengths: Vec<usize> = ["", "x", "payment to B", &"m".repeat(MEMO_BYTES)]
            .iter()
            .map(|memo| pad_memo(memo).expect("it fits").len())
            .collect();
        assert!(lengths.iter().all(|len| *len == MEMO_BYTES), "{lengths:?}");
    }

    #[test]
    fn padding_round_trips_through_unpadding() {
        for memo in ["", "x", "payment to B", "a memo with spaces and 1234"] {
            let padded = pad_memo(memo).expect("it fits");
            assert_eq!(unpad_memo(&padded), memo.as_bytes(), "{memo}");
        }
        // Nothing but zeros is an empty memo, and an unpadded memo from
        // another wallet passes through.
        assert_eq!(unpad_memo(&[0u8; MEMO_BYTES]), b"");
        assert_eq!(unpad_memo(b"unpadded"), b"unpadded");
    }

    #[test]
    fn a_memo_longer_than_the_pad_is_refused() {
        let error = pad_memo(&"m".repeat(MEMO_BYTES + 1)).expect_err("it does not fit");
        assert!(error.to_string().contains("pads every memo"));
    }

    /// The regression: a memo is remote input and was printed byte for byte,
    /// so any sender could drive the operator's terminal through
    /// `qnero-wallet balance`.
    #[test]
    fn a_memo_cannot_carry_an_escape_sequence_to_the_terminal() {
        let hostile = "\r\x1b[2K       4          9000        3    unspent  attacker's row";
        let rendered = render_memo(hostile);
        assert!(
            !rendered.contains('\x1b'),
            "an ESC byte survived: {rendered}"
        );
        assert!(!rendered.contains('\r'), "a CR survived: {rendered}");
        assert!(rendered.contains("\\u{1b}"), "{rendered}");
        assert!(rendered.contains("\\u{0d}"), "{rendered}");

        // OSC 52 writes the sender's address into the operator's clipboard.
        let clipboard = render_memo("\x1b]52;c;cXExYWJj\x07");
        assert!(!clipboard.contains('\x1b'));
        assert!(!clipboard.contains('\u{7}'));

        // Bidi overrides reorder a line with no escape byte at all.
        let bidi = render_memo("paid \u{202e}0001 to bob");
        assert!(!bidi.contains('\u{202e}'), "{bidi}");
    }

    /// The regression, measured where it shows: on the wire. Two ciphertexts
    /// of different lengths, published side by side in `SlotSettled` and in
    /// `Shielded::Ciphertexts`, name which of a spend's outputs is the
    /// sender's change and how many bytes the payment's memo was.
    #[test]
    fn padded_memos_produce_ciphertexts_of_one_length() {
        let alice = qnero_notes::SpendingKey::from_bytes([7u8; 32]);
        let bob = qnero_notes::SpendingKey::from_bytes([9u8; 32]);
        let note = qnero_notes::Note::new(
            alice.pk(),
            1_000,
            qnero_notes::Digest::hash_bytes(&[b"rho"]),
            qnero_notes::Digest::hash_bytes(&[b"r"]),
        )
        .expect("a note");

        let measure = |key: &qnero_notes::SpendingKey, memo: &str| {
            qnero_notes::encrypt_note(
                &key.incoming_viewing_key().encapsulation_key(),
                &note,
                &pad_memo(memo).expect("it fits"),
                &[3u8; 32],
            )
            .expect("it encrypts")
            .to_bytes()
            .len()
        };

        // A payment to somebody else with a memo, and the sender's own change
        // note with none: the pair the chain publishes together.
        let payment = measure(&bob, "payment to B");
        let change = measure(&alice, "");
        assert_eq!(payment, change);
        assert_eq!(measure(&bob, &"m".repeat(MEMO_BYTES)), payment);
        assert_eq!(measure(&bob, "x"), payment);
    }

    /// One note is one row. A memo is up to `MEMO_BYTES`, and a table that
    /// wraps is a table a sender controls the shape of.
    #[test]
    fn a_long_memo_is_truncated_to_one_row() {
        let rendered = render_memo(&"m".repeat(MEMO_BYTES));
        assert!(
            rendered.chars().count() <= MEMO_DISPLAY_COLUMNS + 3,
            "{} chars",
            rendered.chars().count()
        );
        assert!(rendered.ends_with("..."));
        assert_eq!(render_memo("short"), "short");
        assert_eq!(render_memo(""), "");
    }
}
