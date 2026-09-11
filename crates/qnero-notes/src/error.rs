use thiserror::Error;

#[derive(Debug, Error)]
pub enum NotesError {
    #[error("value {0} exceeds the {bits}-bit note value bound", bits = crate::note::VALUE_BITS)]
    ValueTooLarge(u64),
    #[error("digest limb is not a canonical Goldilocks element")]
    NonCanonicalDigest,
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] qnero_pqcrypto::CryptoError),
    #[error("note ciphertext does not decrypt for this viewing key")]
    NotOurs,
    #[error("decrypted note does not match the on-chain commitment")]
    CommitmentMismatch,
}
