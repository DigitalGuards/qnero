//! Key hierarchy. See the crate docs for the derivation tree.

use qnero_pqcrypto::ml_kem::{MlKemKeyPair, MlKemPublicKey, MlKemSecretKey};
use qnero_pqcrypto::traits::KemKeyPair;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::address::Address;
use crate::digest::{domain, Digest};

const DS_ASK: &[u8] = b"qnero/ask";
const DS_NK: &[u8] = b"qnero/nk";
const DS_KEM: &[u8] = b"qnero/kem";

/// `ak = H(AK, ask)`. Split out from [`SpendingKey`] because the spend
/// circuit derives `pk` from `(ask, nk)` in circuit and its off-circuit mirror
/// must use this exact rule.
pub fn derive_ak(ask: &Digest) -> Digest {
    Digest::hash_felts(domain::AK, &[ask.felts()])
}

/// `pk = H(PK, H(AK, ask), nk)`.
pub fn derive_pk(ask: &Digest, nk: &Digest) -> Digest {
    let ak = derive_ak(ask);
    Digest::hash_felts(domain::PK, &[ak.felts(), nk.felts()])
}

/// The spend credential: the authorizing key and the nullifier key.
///
/// Redacting `Debug`: together these two spend every note that pays their
/// `pk`.
#[derive(Clone, Copy)]
pub struct DerivedKeys {
    pub ask: Digest,
    pub nk: Digest,
}

impl core::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("ask", &"[REDACTED]")
            .field("nk", &"[REDACTED]")
            .finish()
    }
}

impl DerivedKeys {
    /// The note receiving key these keys own.
    pub fn pk(&self) -> Digest {
        derive_pk(&self.ask, &self.nk)
    }
}

/// The 32-byte seed. Everything else derives from it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpendingKey([u8; 32]);

impl SpendingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
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
