//! The miner key: what a block author's node is configured with.
//!
//! A node that authors blocks needs two things to build a coinbase note for
//! its operator, and neither of them is the wallet's seed: the note-receiving
//! key `pk`, and the coinbase viewing key `cvk` that the note's `r` is derived
//! from ([`crate::coinbase_r`]). This is both, in one short bech32m string, so
//! an operator pastes one value instead of two.
//!
//! **It is secret-bearing.** `cvk` lets whoever holds it recognise the miner's
//! coinbase notes in the tree, and `pk` is the address's own public half, so a
//! leaked miner key is a leaked coinbase view. It confers nothing else: it
//! cannot spend, and it says nothing about any other note the wallet holds.
//! Treat it the way a node's other key material is treated, and note that it
//! is deliberately not the address: an address is meant to be handed out.
//!
//! It is not an ML-KEM encapsulation key either, which is what keeps this type
//! in the crate with no lattice dependency: the node cannot link one. The
//! module documentation on this crate carries that constraint.

use bech32::{FromBase32, ToBase32, Variant};

use crate::digest::Digest;
use crate::error::NoteError;

/// Human-readable part. Deliberately not the address's `qn`: pasting one where
/// the other belongs should fail on the checksum, not halfway through a decode.
pub const MINER_KEY_HRP: &str = "qnm";
pub const MINER_KEY_VERSION: u8 = 1;
pub const MINER_KEY_LEN: usize = 1 + Digest::LEN + Digest::LEN;

/// `pk` and `cvk`, as a node is configured with them.
#[derive(Clone, PartialEq, Eq)]
pub struct MinerKey {
    pub version: u8,
    /// The note-receiving key every coinbase note is built for.
    pub pk: Digest,
    /// The coinbase viewing key the note's `r` is derived from.
    pub cvk: Digest,
}

/// Redacted: half of this value is a viewing-tier secret, and a log line
/// carrying it hands over the miner's coinbase view.
impl core::fmt::Debug for MinerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MinerKey")
            .field("version", &self.version)
            .field("pk", &self.pk)
            .field("cvk", &"[REDACTED]")
            .finish()
    }
}

impl MinerKey {
    pub fn new(pk: Digest, cvk: Digest) -> Self {
        Self {
            version: MINER_KEY_VERSION,
            pk,
            cvk,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MINER_KEY_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.pk.to_bytes());
        out.extend_from_slice(&self.cvk.to_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NoteError> {
        if bytes.len() != MINER_KEY_LEN {
            return Err(NoteError::InvalidMinerKey(format!(
                "expected {MINER_KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let version = bytes[0];
        if version != MINER_KEY_VERSION {
            return Err(NoteError::InvalidMinerKey(format!(
                "unsupported miner key version {version}"
            )));
        }
        let pk = Digest::from_slice(&bytes[1..1 + Digest::LEN])
            .map_err(|_| NoteError::InvalidMinerKey("pk is not a canonical digest".into()))?;
        let cvk = Digest::from_slice(&bytes[1 + Digest::LEN..])
            .map_err(|_| NoteError::InvalidMinerKey("cvk is not a canonical digest".into()))?;
        Ok(Self { version, pk, cvk })
    }

    pub fn encode(&self) -> String {
        bech32::encode(MINER_KEY_HRP, self.to_bytes().to_base32(), Variant::Bech32m)
            .expect("hrp is valid")
    }

    pub fn decode(s: &str) -> Result<Self, NoteError> {
        let (hrp, data, variant) =
            bech32::decode(s).map_err(|e| NoteError::InvalidMinerKey(e.to_string()))?;
        if hrp != MINER_KEY_HRP {
            return Err(NoteError::InvalidMinerKey(format!(
                "hrp {hrp} is not {MINER_KEY_HRP}"
            )));
        }
        if variant != Variant::Bech32m {
            return Err(NoteError::InvalidMinerKey("checksum is not bech32m".into()));
        }
        let bytes =
            Vec::<u8>::from_base32(&data).map_err(|e| NoteError::InvalidMinerKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// The coinbase note this key mints at `block_number`, worth `value` pool
    /// quanta.
    ///
    /// One function, called by three places that must agree: the node building
    /// the inherent payload, the wallet scanning for its own coinbase notes,
    /// and the tests that pin both. The chain is the fourth party and it sees
    /// only the commitment.
    pub fn coinbase_note(&self, block_number: u32, value: u64) -> Result<crate::Note, NoteError> {
        crate::Note::new(
            self.pk,
            value,
            crate::coinbase_rho(block_number),
            crate::coinbase_r(&self.cvk, block_number),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MinerKey {
        MinerKey::new(Digest::hash_bytes(&[b"pk"]), Digest::hash_bytes(&[b"cvk"]))
    }

    #[test]
    fn a_miner_key_round_trips_through_bech32m() {
        let encoded = key().encode();
        assert!(encoded.starts_with("qnm1"), "{encoded}");
        assert_eq!(MinerKey::decode(&encoded).unwrap(), key());
    }

    /// A one-character change fails the checksum rather than decoding to
    /// another key, which is what a copy-paste error has to do to a value that
    /// decides where every block's reward goes.
    #[test]
    fn a_corrupted_miner_key_is_refused() {
        let encoded = key().encode();
        let mut corrupted = encoded.clone();
        let last = corrupted.pop().expect("non-empty");
        corrupted.push(if last == 'q' { 'p' } else { 'q' });
        assert!(MinerKey::decode(&corrupted).is_err());
        assert!(
            MinerKey::decode("qn1qqqq").is_err(),
            "an address is not a miner key"
        );
    }

    /// The note the node builds and the note the wallet looks for are one
    /// function, and its value is the only thing the chain decides.
    #[test]
    fn a_coinbase_note_is_fixed_by_the_key_the_block_and_the_value() {
        let key = key();
        let note = key.coinbase_note(9, 11).unwrap();
        assert_eq!(note.rho, crate::coinbase_rho(9));
        assert_eq!(note.r, crate::coinbase_r(&key.cvk, 9));
        assert_eq!(note.inner(), key.coinbase_note(9, 42).unwrap().inner());
        assert_ne!(
            note.commitment(),
            key.coinbase_note(9, 42).unwrap().commitment()
        );
        assert_ne!(note.inner(), key.coinbase_note(10, 11).unwrap().inner());
    }
}
