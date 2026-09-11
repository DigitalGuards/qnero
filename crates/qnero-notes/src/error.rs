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
    #[error("decrypted note does not match the on-chain commitment")]
    CommitmentMismatch,
}
