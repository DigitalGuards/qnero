//! The well-known dev accounts, and the one signature a wallet makes.
//!
//! `shield` is the only signed call this wallet sends and v0 has no unshield,
//! so the transparent key exists purely to move value into the pool. On a
//! `--dev` chain the endowed accounts are `crystal_alice`, `dilithium_bob` and
//! `crystal_charlie`, derived from the public seeds `[0u8; 32]`, `[1u8; 32]`
//! and `[2u8; 32]` (`chain/runtime/src/genesis_config_presets`). Those keys
//! are public by design and are worth nothing outside a dev chain.
//!
//! The shielded spending key is an entirely separate secret. A wallet holds
//! both and neither derives from the other: a transparent key that could
//! derive the spending key would make every shield linkable to its notes by
//! anyone holding it.

use anyhow::{bail, Result};
use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, SecretKey};
use qp_rusty_crystals_dilithium::SensitiveBytes32;
use zeroize::Zeroizing;

/// FIPS 204 context every extrinsic signature is made under
/// (`chain/primitives/dilithium-crypto/src/signing_context.rs`). Contexts are
/// domain separated, so a contextless signature over the same payload is
/// refused as `Transaction has a bad signature` with no further hint.
pub const EXTRINSIC_CONTEXT: &[u8] = b"QUANTUS_EXTRINSIC";

/// ML-DSA-87 signature bytes.
pub const SIGNATURE_LEN: usize = 4627;
/// ML-DSA-87 public key bytes.
pub const PUBLIC_KEY_LEN: usize = 2592;

/// A transparent ML-DSA-87 key pair.
pub struct TransparentKey {
    public: [u8; PUBLIC_KEY_LEN],
    secret: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for TransparentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransparentKey")
            .field("account_id", &hex::encode(self.account_id()))
            .finish()
    }
}

impl TransparentKey {
    /// The derivation `Dilithium87Pair::from_seed` makes: ML-DSA-87 key
    /// generation seeded with the 32 bytes directly.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut entropy = seed;
        let mut sensitive = SensitiveBytes32::from(&mut entropy);
        let keypair = Keypair::generate(&mut sensitive);
        Self {
            public: keypair.public().to_bytes(),
            secret: Zeroizing::new(keypair.secret().to_bytes().to_vec()),
        }
    }

    /// One of the dev chain's endowed accounts.
    pub fn dev(name: &str) -> Result<Self> {
        let seed = match name.to_ascii_lowercase().as_str() {
            "alice" => 0u8,
            "bob" => 1,
            "charlie" => 2,
            other => bail!(
                "`{other}` is not a dev account. The dev chain endows alice, bob and charlie."
            ),
        };
        Ok(Self::from_seed([seed; 32]))
    }

    pub fn public_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// `AccountId32` is Poseidon2 of the public key
    /// (`chain/primitives/dilithium-crypto/src/scheme_macro.rs`). Any address
    /// derivation copied from generic Substrate tooling hashes with Blake2 and
    /// is wrong here.
    pub fn account_id(&self) -> [u8; 32] {
        qp_poseidon_core::hash_bytes(&self.public)
    }

    /// Sign under the extrinsic context.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let secret = SecretKey::from_bytes(&self.secret)
            .map_err(|e| anyhow::anyhow!("the dev secret key does not parse: {e:?}"))?;
        let signature = secret
            .sign(message, Some(EXTRINSIC_CONTEXT), None)
            .map_err(|e| anyhow::anyhow!("signing failed: {e:?}"))?;
        Ok(signature.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dev seeds are fixed, so the accounts they derive are fixed. A
    /// changed derivation shields from an account the genesis does not endow
    /// and the failure is an opaque balance error.
    #[test]
    fn the_dev_accounts_are_deterministic() {
        let alice = TransparentKey::dev("alice").unwrap();
        let again = TransparentKey::dev("Alice").unwrap();
        assert_eq!(alice.account_id(), again.account_id());
        let bob = TransparentKey::dev("bob").unwrap();
        assert_ne!(alice.account_id(), bob.account_id());
        assert!(TransparentKey::dev("mallory").is_err());
    }

    #[test]
    fn a_signature_is_the_documented_length() {
        let alice = TransparentKey::dev("alice").unwrap();
        assert_eq!(alice.public_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(alice.sign(b"payload").unwrap().len(), SIGNATURE_LEN);
    }
}
