//! The faucet's transparent key: the genesis-endowed account it shields from.
//!
//! Two secrets, and neither derives from the other. This file holds the
//! transparent one, the ML-DSA-87 key behind the SS58 literal in the testnet
//! preset, which signs `shield` and nothing else. The shielded spending key is
//! `qnero_wallet::keys` and lives in its own file beside its note store.
//!
//! The seed is 32 bytes of hex. `Dilithium87Pair::from_seed` takes the first
//! 32 bytes of whatever it is handed
//! (`chain/primitives/dilithium-crypto/src/scheme_macro.rs`), and
//! `TransparentKey::from_seed` is the same derivation on this side, so 32
//! bytes is the whole secret and a longer file would be 32 bytes of secret
//! with a tail nothing reads.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use qnero_wallet::dev_account::TransparentKey;
use rand::TryRngCore;
use zeroize::Zeroizing;

/// Refuse a seed file anything but its owner can read.
///
/// The same rule `qnero_wallet::keys::refuse_if_readable_beyond_owner` applies
/// to the spending key, for the same reason: this file is the whole of the
/// faucet's genesis endowment.
pub fn refuse_if_readable_beyond_owner(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("{}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {:o}, which lets somebody other than its owner read the faucet's \
             transparent seed. chmod 600 it",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

/// Create a seed file with 32 bytes from the operating system, mode 0600.
///
/// Refuses to overwrite: a faucet seed that is replaced is a genesis
/// endowment that is stranded, because the address in the chain spec cannot be
/// changed without a new genesis.
pub fn create_seed(path: &Path) -> Result<TransparentKey> {
    if path.exists() {
        bail!(
            "{} already exists. A faucet seed is the key behind an address written into a chain \
             spec's genesis, so replacing it strands that endowment for good; move the old file \
             aside deliberately if that is what you mean",
            path.display()
        );
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(seed.as_mut())
        .context("the operating system's RNG refused")?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("{}", path.display()))?;
    let hex = Zeroizing::new(hex::encode(&seed[..]));
    file.write_all(hex.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);

    Ok(TransparentKey::from_seed(*seed))
}

/// Load a seed file and derive the transparent key from it.
pub fn load_seed(path: &Path) -> Result<TransparentKey> {
    refuse_if_readable_beyond_owner(path)?;
    let raw =
        Zeroizing::new(fs::read_to_string(path).with_context(|| format!("{}", path.display()))?);
    let trimmed = raw.trim();
    let bytes = Zeroizing::new(hex::decode(trimmed).with_context(|| {
        format!(
            "{} is not hex. A faucet seed is 64 hex characters",
            path.display()
        )
    })?);
    if bytes.len() != 32 {
        bail!(
            "{} decodes to {} bytes and a faucet seed is 32",
            path.display(),
            bytes.len()
        );
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[..]);
    Ok(TransparentKey::from_seed(*seed))
}

/// The SS58 address a transparent key answers to.
pub fn address_of(key: &TransparentKey) -> String {
    crate::ss58::encode(&key.account_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derivation this file rests on, pinned to one pair.
    ///
    /// The seed is all zeroes, which is `crystal_alice`: the runtime derives
    /// that account from `Dilithium87Pair::from_seed_slice(&[0u8; 32])` and
    /// the dev preset endows it. The address below is the node's own answer
    /// for that seed, taken from
    /// `qnero-node key qnero --scheme standard --no-derivation --seed`, so
    /// this asserts that three independent things agree: this crate's
    /// derivation, its account hash, and its SS58 encoder against `sp_core`'s.
    /// If any of them moved, the faucet would sign for an account the chain
    /// spec does not name and every drip would fail at the transparent entry
    /// with nothing saying why.
    #[test]
    fn the_seed_derivation_is_the_chains_own() {
        let key = TransparentKey::from_seed([0u8; 32]);
        assert_eq!(
            address_of(&key),
            "qzk1Nxai3dZD9Cn5kwGcgL6mKxsfxwqdis7kDQJ52aJS2vSn7"
        );
    }
}
