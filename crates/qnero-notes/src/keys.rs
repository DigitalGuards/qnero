//! Key hierarchy. See the crate docs for the derivation tree.

use qnero_pqcrypto::ml_kem::{MlKemKeyPair, MlKemPublicKey, MlKemSecretKey};
use qnero_pqcrypto::traits::KemKeyPair;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use qnero_note_core::keys::{derive_ak, derive_pk, DerivedKeys};
use qnero_note_core::Digest;

use crate::address::Address;

const DS_ASK: &[u8] = b"qnero/ask";
const DS_NK: &[u8] = b"qnero/nk";
const DS_KEM: &[u8] = b"qnero/kem";

/// The 32-byte seed. Everything else derives from it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey([u8; 32]);

impl SpendingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Take a seed out of a caller-owned buffer, wiping that buffer.
    ///
    /// [`SpendingKey`] is `ZeroizeOnDrop`, so the copy this type holds is
    /// wiped when it drops. A caller that decoded the seed into an ordinary
    /// array still holds a second copy whose storage is released with the seed
    /// still in it, where a core dump, a swap page or a later stack frame can
    /// reach it. This is the constructor that leaves nothing behind.
    pub fn take_from(bytes: &mut [u8; 32]) -> Self {
        let key = Self(*bytes);
        bytes.zeroize();
        key
    }

    pub fn random<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Spend authorizing key. Knowledge of its preimage is what the circuit
    /// proves.
    pub fn ask(&self) -> Digest {
        Digest::hash_bytes(&[DS_ASK, &self.0])
    }

    /// Nullifier key.
    pub fn nk(&self) -> Digest {
        Digest::hash_bytes(&[DS_NK, &self.0])
    }

    /// Public spend commitment `ak = H(AK, ask)`.
    pub fn ak(&self) -> Digest {
        derive_ak(&self.ask())
    }

    /// Note receiving key `pk = H(PK, ak, nk)`.
    pub fn pk(&self) -> Digest {
        derive_pk(&self.ask(), &self.nk())
    }

    /// The two keys a spend proof needs, bundled so they cannot be swapped.
    pub fn derived(&self) -> DerivedKeys {
        DerivedKeys {
            ask: self.ask(),
            nk: self.nk(),
        }
    }

    pub fn kem_keypair(&self) -> MlKemKeyPair {
        let seed = Zeroizing::new(Digest::hash_bytes(&[DS_KEM, &self.0]).to_bytes());
        MlKemKeyPair::generate_deterministic(seed.as_slice())
    }

    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey {
            ivk: IncomingViewingKey {
                pk: self.pk(),
                kem: self.kem_keypair(),
            },
            nk: self.nk(),
        }
    }

    pub fn incoming_viewing_key(&self) -> IncomingViewingKey {
        self.full_viewing_key().ivk
    }

    pub fn address(&self) -> Address {
        self.incoming_viewing_key().address()
    }
}

/// Detects and decrypts incoming notes. Cannot spend and cannot tell whether
/// a note has been spent.
pub struct IncomingViewingKey {
    pub(crate) pk: Digest,
    pub(crate) kem: MlKemKeyPair,
}

impl IncomingViewingKey {
    pub fn pk(&self) -> Digest {
        self.pk
    }

    pub fn encapsulation_key(&self) -> MlKemPublicKey {
        self.kem.public_key()
    }

    pub(crate) fn decapsulation_key(&self) -> &MlKemSecretKey {
        self.kem.secret_key()
    }

    pub fn address(&self) -> Address {
        Address {
            version: crate::address::ADDRESS_VERSION,
            pk: self.pk,
            ek: self.kem.public_key(),
        }
    }
}

/// Incoming viewing key plus the nullifier key, so spent status is visible.
pub struct FullViewingKey {
    pub(crate) ivk: IncomingViewingKey,
    pub(crate) nk: Digest,
}

impl FullViewingKey {
    pub fn incoming(&self) -> &IncomingViewingKey {
        &self.ivk
    }

    pub fn nk(&self) -> Digest {
        self.nk
    }

    pub fn pk(&self) -> Digest {
        self.ivk.pk
    }

    pub fn address(&self) -> Address {
        self.ivk.address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `take_from`: the caller's buffer is wiped, so the
    /// only copy of the seed left is the one `ZeroizeOnDrop` covers.
    #[test]
    fn take_from_wipes_the_buffer_it_took() {
        let mut buffer = [7u8; 32];
        let key = SpendingKey::take_from(&mut buffer);
        assert_eq!(buffer, [0u8; 32]);
        assert_eq!(key.expose_bytes(), &[7u8; 32]);
        assert_eq!(
            key.address().encode(),
            SpendingKey::from_bytes([7u8; 32]).address().encode()
        );
    }
}
