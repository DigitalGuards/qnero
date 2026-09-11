//! The spend credential, and the two derivations the circuit mirrors.
//!
//! `SpendingKey`, the 32-byte seed everything else comes from, lives in
//! `qnero-notes`: it also derives an ML-KEM viewing key pair, which is the one
//! part of the key hierarchy that needs lattice cryptography.

use crate::digest::{domain, Digest};

/// `ak = H(AK, ask)`. Split out from the spending key because the spend
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
