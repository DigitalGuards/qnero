//! Note encryption: ML-KEM-1024 encapsulation to the recipient's `ek`, then
//! ChaCha20-Poly1305 over `(value, rho, r, memo)`. The wire format and AEAD
//! construction are Hegemon's (`qnero_pqcrypto::note_encryption`), reused
//! unchanged; Qnero only fixes the header fields.

use qnero_pqcrypto::note_encryption::{NoteCiphertext as PqNoteCiphertext, NotePlaintext};

use crate::digest::Digest;
use crate::error::NotesError;
use crate::keys::IncomingViewingKey;
use crate::note::Note;

pub use qnero_pqcrypto::note_encryption::NoteCiphertext;

/// Header fields fixed for Qnero v0. `crypto_suite` 1 = ML-KEM-1024 +
/// ChaCha20-Poly1305 with the vendored KDF.
pub const CIPHERTEXT_VERSION: u8 = 1;
pub const CRYPTO_SUITE: u16 = 1;
const DIVERSIFIER_INDEX: u32 = 0;
const ASSET_ID: u64 = 0;

/// Encrypt `note` (and `memo`) to the address that owns `note.pk`.
/// `kem_randomness` must be fresh per output.
pub fn encrypt_note(
    ek: &qnero_pqcrypto::ml_kem::MlKemPublicKey,
    note: &Note,
    memo: &[u8],
    kem_randomness: &[u8; 32],
) -> Result<NoteCiphertext, NotesError> {
    let pt = NotePlaintext::new(
        note.value,
        ASSET_ID,
        note.rho.to_bytes(),
        note.r.to_bytes(),
        memo.to_vec(),
    );
    Ok(PqNoteCiphertext::encrypt(
        ek,
        note.pk.to_bytes(),
        CIPHERTEXT_VERSION,
        CRYPTO_SUITE,
        DIVERSIFIER_INDEX,
        &pt,
        kem_randomness,
    )?)
}

/// Domain prefix of the ciphertext digest. Byte-mode hashing uses an ASCII
/// prefix where field-mode hashing uses a one-felt tag; `ct_digest` is never
/// recomputed inside a circuit, so it stays on the byte-mode sponge.
const CT_DIGEST_PREFIX: &[u8] = b"qnero/ct";

/// `ct_digest`: the leaf public input that binds a spend proof to the
/// ciphertexts submitted with it.
///
/// ```text
/// ct_digest = H_bytes("qnero/ct" || u32_le(count)
///                     || u32_le(len_1) || ct_1 || ... || u32_le(len_n) || ct_n)
/// ```
///
/// The circuit treats `ct_digest` as a free public input: hashing kilobytes of
/// ML-KEM and AEAD ciphertext in circuit would dominate the proof, so the
/// chain recomputes this digest from the bytes it was handed and compares.
/// That comparison binds the ciphertexts only while the rule is unambiguous,
/// which is what the count and the per-ciphertext length prefixes are for. A
/// bare concatenation would let two different output pairs share a preimage,
/// and a relayer could then swap the ciphertexts attached to a settled leaf
/// for a colliding pair, leaving the recipient unable to decrypt a note whose
/// commitment is already in the tree.
///
/// Both sides call this function. A wallet computes it over the ciphertexts it
/// is about to submit, in output order; the chain recomputes it over the
/// ciphertexts in the extrinsic, in the same order.
pub fn ct_digest(ciphertexts: &[NoteCiphertext]) -> Digest {
    let mut buf = Vec::new();
    buf.extend_from_slice(CT_DIGEST_PREFIX);
    buf.extend_from_slice(&(ciphertexts.len() as u32).to_le_bytes());
    for ct in ciphertexts {
        let bytes = ct.to_bytes();
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&bytes);
    }
    Digest::hash_bytes(&[&buf])
}

/// A note this viewing key can read, with its memo and commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct ReceivedNote {
    pub note: Note,
    pub memo: Vec<u8>,
    pub commitment: Digest,
}

/// Redacting `Debug`: this is the decrypted note plus its memo, which is the
/// most linkable object a wallet holds. The commitment stays in the clear
/// because the chain published it.
impl core::fmt::Debug for ReceivedNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReceivedNote")
            .field("note", &self.note)
            .field("memo", &"[REDACTED]")
            .field("commitment", &self.commitment)
            .finish()
    }
}

/// Decrypt without checking against an on-chain commitment.
pub fn decrypt_note(
    ivk: &IncomingViewingKey,
    ct: &NoteCiphertext,
) -> Result<ReceivedNote, NotesError> {
    if ct.version != CIPHERTEXT_VERSION || ct.crypto_suite != CRYPTO_SUITE {
        return Err(NotesError::NotOurs);
    }
    let pt = ct
        .decrypt(
            ivk.decapsulation_key(),
            ivk.pk().to_bytes(),
            DIVERSIFIER_INDEX,
        )
        .map_err(|_| NotesError::NotOurs)?;
    if pt.asset_id != ASSET_ID {
        return Err(NotesError::NotOurs);
    }
    let rho = Digest::from_bytes(&pt.rho).map_err(|_| NotesError::NotOurs)?;
    let r = Digest::from_bytes(&pt.r).map_err(|_| NotesError::NotOurs)?;
    let note = Note::new(ivk.pk(), pt.value, rho, r).map_err(|_| NotesError::NotOurs)?;
    let commitment = note.commitment();
    Ok(ReceivedNote {
        note,
        memo: pt.memo,
        commitment,
    })
}

/// Wallet scan step: decrypt and check that the plaintext opens the
/// commitment the chain published next to it. A ciphertext that decrypts but
/// opens a different commitment is a malformed output and is rejected.
pub fn try_receive(
    ivk: &IncomingViewingKey,
    ct: &NoteCiphertext,
    on_chain_commitment: &Digest,
) -> Result<ReceivedNote, NotesError> {
    let received = decrypt_note(ivk, ct)?;
    if &received.commitment != on_chain_commitment {
        return Err(NotesError::CommitmentMismatch);
    }
    Ok(received)
}
