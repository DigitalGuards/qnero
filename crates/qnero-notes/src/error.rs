use thiserror::Error;

/// The wallet tier's errors: everything [`qnero_note_core::NoteError`] can
/// produce, plus what only address decoding and note encryption reach.
#[derive(Debug, Error)]
pub enum NotesError {
    #[error(transparent)]
    Note(#[from] qnero_note_core::NoteError),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] qnero_pqcrypto::CryptoError),
    #[error("note ciphertext does not decrypt for this viewing key")]
    NotOurs,
    /// The payload opened and the commitment beside it is a different one.
    ///
    /// Its own variant because a wallet acts on it. Opening is authenticated:
    /// the ML-KEM ciphertext decapsulated under this viewing key and the AEAD
    /// verified with this key's own `pk` as associated data, so the note
    /// inside is this wallet's note whatever sits beside it. That makes this
    /// the one reading a scan can tell apart from a stranger's leaf on its
    /// own, and [`NotesError::NotOurs`] is what a stranger's leaf gives.
    /// Collapsing the two threw away the only local detector for a node that
    /// moved a commitment away from the ciphertext the chain published beside
    /// it; `qnero_wallet::wallet` carries what it does with the difference.
    #[error("decrypted note does not match the on-chain commitment")]
    CommitmentMismatch,
    #[error(
        "the memo is {len} bytes and Qnero pads every memo to {max}. A longer one would make \
         this ciphertext a different length from every other note's, which is the leak the \
         padding exists to close."
    )]
    MemoTooLong { len: usize, max: usize },
}
