//! Qnero shielded note primitives.
//!
//! Everything that goes inside the spend circuit is Poseidon2 over Goldilocks
//! (`qp-poseidon-core`, the same hash and parameters the Quantus Wormhole
//! circuits use). Everything outside the circuit (note encryption, view keys)
//! is ML-KEM-1024 plus ChaCha20-Poly1305 from `qnero-pqcrypto`.
//!
//! Key and note layout follows `docs/DESIGN.md` sections 4 and 5:
//!
//! ```text
//! sk        : 32 random bytes
//! ask       = H_bytes("qnero/ask" || sk)        spend authorizing key
//! nk        = H_bytes("qnero/nk"  || sk)        nullifier key
//! ak        = H(AK, ask)                        public spend commitment
//! pk        = H(PK, ak, nk)                     note receiving key
//! (ek, dk)  = ML-KEM-1024.KeyGen(H_bytes("qnero/kem" || sk))
//!
//! inner     = H(NOTE, pk, rho, r)
//! cm        = H(CM, inner, v)
//! nf        = H(NF, nk, rho, r)
//! nf_dummy  = H(NF_DUMMY, nk, rho, r)           padding input slot
//! rho_out_j = H(RHO, nf_1, nf_2, j)             seed of output j of a spend
//! ```
//!
//! `H` is Poseidon2 over field elements with a one-felt domain tag; `H_bytes`
//! is Poseidon2 over bytes. Every 32-byte digest is four canonical Goldilocks
//! limbs, little endian, so it round-trips into the circuit without loss.

#![forbid(unsafe_code)]

pub mod address;
pub mod encrypt;
pub mod error;
pub mod keys;

/// The primitives that carry no lattice dependency, re-exported so a wallet
/// keeps one import. `qnero-circuit`, `qnero-aggregator` and
/// `pallet-shielded` take that crate directly: none of them encrypts
/// anything, and an unused edge to `ml-kem` is one a Cargo lock file still
/// resolves.
pub use qnero_note_core::{digest, error as note_error, note, NoteError};

pub use address::{Address, ADDRESS_HRP, ADDRESS_VERSION};
pub use encrypt::{
    decrypt_note, encrypt_note, try_receive, try_receive_coinbase, NoteCiphertext, ReceivedNote,
};
pub use error::NotesError;
pub use keys::{FullViewingKey, IncomingViewingKey, SpendingKey};
pub use qnero_note_core::{
    coinbase_r, coinbase_rho, commitment_from_inner, derive_ak, derive_pk, dummy_nullifier,
    entry_rho, note_inner, nullifier, output_rho, DerivedKeys, Digest, Felt, MinerKey, Note,
    MAX_VALUE, VALUE_BITS,
};
