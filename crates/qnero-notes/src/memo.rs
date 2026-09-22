//! Memo padding: one size for every memo this ecosystem encrypts.
//!
//! A note ciphertext is a fixed [`CIPHERTEXT_FIXED_BYTES`] plus its memo, byte
//! for byte (`qnero_pqcrypto::note_encryption`: the memo rides in its own AEAD
//! payload and `to_bytes` length-prefixes it). The chain publishes those bytes
//! in full, in `Shielded::Ciphertexts` and in the `SlotSettled` event, so an
//! unpadded memo publishes its own exact length to every chain reader. Two
//! things follow, and both are why every memo is padded to one size:
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
//!
//! This lives here, beside [`encrypt_note`](crate::encrypt_note), because the
//! CLI wallet is no longer the only thing that encrypts a note: the browser
//! prover (`qnero-prover-wasm`) encrypts its own outputs and cannot link
//! `qnero-wallet`. Two copies of a padding rule drift, and a drifted pad is a
//! ciphertext length that identifies which wallet wrote it.

use crate::error::NotesError;

/// What a `NoteCiphertext` serializes to with an empty memo.
///
/// Fixed by the crypto suite: 19 bytes of framing, an ML-KEM-1024
/// encapsulation (1568), the note payload under a ChaCha20-Poly1305 tag (128)
/// and the memo's own tag (16).
/// `an_empty_memo_ciphertext_serializes_to_1731_bytes` in `qnero-pqcrypto`
/// pins it against the serializer and `qnero-wallet`'s `tests/ct_digest.rs`
/// pins it against a real ciphertext. Every size below is derived from it.
pub const CIPHERTEXT_FIXED_BYTES: usize = 1731;

/// Every memo Qnero encrypts is exactly this many bytes.
///
/// It is a derived consensus value now, and the literal is what it derives to.
/// `qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES` (1792) minus
/// [`CIPHERTEXT_FIXED_BYTES`] (1731) is 61, and settlement requires exactly
/// 1792 bytes per suite-1 ciphertext, so a pad of any other size produces a
/// ciphertext the chain refuses. `the_pad_is_the_consensus_length_minus_the_
/// serializers_fixed_part` below holds the two together; the constant stays a
/// literal so this crate keeps compiling without an edge to `qnero-circuit`,
/// which is the same reason `qnero_circuit::chain` restates the `CM` tag.
///
/// The reasoning it replaces. The pad used to be decided by two bounds with
/// the tighter one winning. The loose bound was `MaxCiphertextBytes` (2048)
/// minus [`CIPHERTEXT_FIXED_BYTES`], which leaves 317 bytes; a pad over that
/// still fails the extrinsic's SCALE decode, after the proof committing to
/// those bytes exists. The tight bound was the fee: the runtime sized
/// `CiphertextBytesPerFeeQuantum` (512) so an honest pair and a pair padded to
/// the cap landed in different buckets, because the chain did not parse these
/// bytes and nothing held a submission to a real ciphertext shape, and 61 was
/// the largest pad that kept the separation. The exact-length rule refuses the
/// padded pair outright, so that bound now prices a state nobody can reach.
/// It also removes the coordination hazard the derivation carried: the pad is
/// no longer a number every wallet on the chain has to move together, because
/// the chain publishes it.
///
/// The number itself does not move, so no wallet changes what it sends.
///
/// Zcash's 512-byte memo field is the precedent for padding at all. The size
/// differs because this ciphertext's fixed part is larger and because the
/// chain prices payload bytes.
pub const MEMO_BYTES: usize = 61;

/// Pad a memo to [`MEMO_BYTES`] with trailing zeros.
pub fn pad_memo(memo: &str) -> Result<Vec<u8>, NotesError> {
    let bytes = memo.as_bytes();
    if bytes.len() > MEMO_BYTES {
        return Err(NotesError::MemoTooLong {
            len: bytes.len(),
            max: MEMO_BYTES,
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the padding exists for: every memo produces a ciphertext
    /// of one length, so no observer reads a memo's size off the chain and no
    /// spend's change note is the shorter of the pair.
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
        assert_eq!(unpad_memo(&[0u8; MEMO_BYTES]), b"");
        assert_eq!(unpad_memo(b"unpadded"), b"unpadded");
    }

    /// The pad is a derived consensus value, held to its derivation here
    /// rather than by a dependency edge: this crate compiles without
    /// `qnero-circuit`, which is the crate a runtime links, and the constant
    /// stays a literal for that reason. `qnero-circuit` is a dev-dependency,
    /// so the comparison is available exactly where it is needed.
    ///
    /// A `MEMO_BYTES` that drifted would make every ciphertext this wallet
    /// produces the wrong length for settlement, and the chain would answer a
    /// bare pool rejection naming nothing, after the proof was paid for.
    #[test]
    fn the_pad_is_the_consensus_length_minus_the_serializers_fixed_part() {
        assert_eq!(
            CIPHERTEXT_FIXED_BYTES + MEMO_BYTES,
            qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES
        );
        assert_eq!(MEMO_BYTES, 61);
    }

    #[test]
    fn a_memo_longer_than_the_pad_is_refused() {
        let error = pad_memo(&"m".repeat(MEMO_BYTES + 1)).expect_err("it does not fit");
        assert!(error.to_string().contains("pads every memo"), "{error}");
    }
}
