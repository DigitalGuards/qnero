use thiserror::Error;

/// What can go wrong building a note or a digest.
///
/// The wallet tier's `qnero_notes::NotesError` wraps this and adds the errors
/// that only address decoding and note encryption can produce.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NoteError {
    #[error("value {0} exceeds the {bits}-bit note value bound", bits = crate::note::VALUE_BITS)]
    ValueTooLarge(u64),
    #[error("digest limb is not a canonical Goldilocks element")]
    NonCanonicalDigest,
}
