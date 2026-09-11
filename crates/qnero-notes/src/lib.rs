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
pub mod digest;
pub mod encrypt;
pub mod error;
pub mod keys;
pub mod note;

pub use address::{Address, ADDRESS_HRP, ADDRESS_VERSION};
pub use digest::{Digest, Felt};
pub use encrypt::{
    ct_digest, decrypt_note, encrypt_note, try_receive, NoteCiphertext, ReceivedNote,
};
pub use error::NotesError;
pub use keys::{
    derive_ak, derive_pk, DerivedKeys, FullViewingKey, IncomingViewingKey, SpendingKey,
};
pub use note::{
    commitment_from_inner, dummy_nullifier, note_inner, nullifier, output_rho, Note, MAX_VALUE,
    VALUE_BITS,
};
