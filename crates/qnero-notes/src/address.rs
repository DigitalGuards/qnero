//! Shielded address: `bech32m("qn", version || pk || ek)`.
//!
//! The ML-KEM-1024 encapsulation key dominates the size (1568 bytes), so an
//! encoded address is about 2.6k characters. Wallets exchange it as a QR
//! code or a copy-paste string; nobody types it.

use bech32::{FromBase32, ToBase32, Variant};
use qnero_pqcrypto::ml_kem::{MlKemPublicKey, ML_KEM_PUBLIC_KEY_LEN};
use qnero_pqcrypto::traits::KemPublicKey;

use crate::digest::Digest;
use crate::error::NotesError;

pub const ADDRESS_HRP: &str = "qn";
pub const ADDRESS_VERSION: u8 = 1;
pub const ADDRESS_LEN: usize = 1 + Digest::LEN + ML_KEM_PUBLIC_KEY_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub version: u8,
    pub pk: Digest,
    pub ek: MlKemPublicKey,
}

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADDRESS_LEN);
        out.push(self.version);
        out.extend_from_slice(&self.pk.to_bytes());
        out.extend_from_slice(self.ek.as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NotesError> {
        if bytes.len() != ADDRESS_LEN {
            return Err(NotesError::InvalidAddress(format!(
                "expected {ADDRESS_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let version = bytes[0];
        if version != ADDRESS_VERSION {
            return Err(NotesError::InvalidAddress(format!(
                "unsupported address version {version}"
            )));
        }
        let pk = Digest::from_slice(&bytes[1..1 + Digest::LEN])
            .map_err(|_| NotesError::InvalidAddress("pk is not a canonical digest".into()))?;
        let ek = MlKemPublicKey::from_bytes(&bytes[1 + Digest::LEN..])
            .map_err(|e| NotesError::InvalidAddress(format!("bad encapsulation key: {e}")))?;
        Ok(Self { version, pk, ek })
    }

    pub fn encode(&self) -> String {
        bech32::encode(ADDRESS_HRP, self.to_bytes().to_base32(), Variant::Bech32m)
            .expect("hrp is valid")
    }

    pub fn decode(s: &str) -> Result<Self, NotesError> {
        let (hrp, data, variant) =
            bech32::decode(s).map_err(|e| NotesError::InvalidAddress(e.to_string()))?;
        if hrp != ADDRESS_HRP {
            return Err(NotesError::InvalidAddress(format!(
                "hrp {hrp} is not {ADDRESS_HRP}"
            )));
        }
        if variant != Variant::Bech32m {
            return Err(NotesError::InvalidAddress("checksum is not bech32m".into()));
        }
        let bytes =
            Vec::<u8>::from_base32(&data).map_err(|e| NotesError::InvalidAddress(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}
