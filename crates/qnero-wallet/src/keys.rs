//! The seed file.
//!
//! Dev-grade key storage, deliberately: the seed is 32 bytes of hex in a file
//! with mode 0600 and no passphrase, no KDF and no encryption at rest. Anyone
//! who can read the file can spend every note the wallet holds. That is stated
//! in `--help`, in `docs/WALLET.md` and here, and it is the first thing M6
//! owes.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use qnero_notes::SpendingKey;
use rand::TryRngCore;
use zeroize::Zeroizing;

/// Where a seed lives when `--file` is not given.
pub fn default_seed_path() -> PathBuf {
    PathBuf::from("qnero-wallet.seed")
}

/// Write a fresh 32-byte seed, refusing to overwrite one that exists.
pub fn create_seed(path: &Path) -> Result<SpendingKey> {
    if path.exists() {
        bail!(
            "{} already exists. Refusing to overwrite a seed: the notes behind it would be \
             unspendable.",
            path.display()
        );
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .context("the operating system's RNG refused")?;
    write_seed(path, &bytes)?;
    Ok(SpendingKey::from_bytes(*bytes))
}

fn write_seed(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    let encoded = Zeroizing::new(hex::encode(bytes));
    writeln!(file, "{}", encoded.as_str())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Read a seed, refusing one that is readable by anyone else.
pub fn load_seed(path: &Path) -> Result<SpendingKey> {
    let metadata = fs::metadata(path).with_context(|| {
        format!(
            "no seed at {}. Run `qnero-wallet keygen` first.",
            path.display()
        )
    })?;
    let mode = metadata.permissions().mode() & 0o077;
    if mode != 0 {
        bail!(
            "{} is readable or writable beyond its owner (mode {:o}). Fix it with `chmod 600 {}`.",
            path.display(),
            metadata.permissions().mode() & 0o777,
            path.display()
        );
    }
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?,
    );
    let decoded = Zeroizing::new(
        hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?,
    );
    let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{} is {} bytes, a seed is 32",
            path.display(),
            decoded.len()
        )
    })?;
    Ok(SpendingKey::from_bytes(bytes))
}

/// The store that belongs to a seed file.
pub fn store_path_for(seed: &Path) -> PathBuf {
    let mut name = seed.as_os_str().to_os_string();
    name.push(".store.json");
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("qnero-keys-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("round-trip.seed");
        let _ = fs::remove_file(&path);
        let created = create_seed(&path).unwrap();
        let loaded = load_seed(&path).unwrap();
        assert_eq!(created.expose_bytes(), loaded.expose_bytes());
        assert_eq!(created.address().encode(), loaded.address().encode());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_world_readable_seed_is_refused() {
        let dir = std::env::temp_dir().join(format!("qnero-keys-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("loose.seed");
        let _ = fs::remove_file(&path);
        create_seed(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_seed(&path).is_err());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_store_sits_beside_the_seed() {
        assert_eq!(
            store_path_for(Path::new("/tmp/a.seed")),
            PathBuf::from("/tmp/a.seed.store.json")
        );
    }
}
