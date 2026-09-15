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
///
/// Always under the user's data directory. The documented way to run this
/// binary is from a checkout, so a default that resolved relatively would drop
/// an unencrypted spending key and a store full of note secrets into whatever
/// repository the user happened to be standing in, one `git add -A` away from
/// a public history that no history rewrite fully recalls.
pub fn default_seed_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")));
    match base {
        Some(base) => base.join("qnero").join("qnero-wallet.seed"),
        // No HOME and no XDG_DATA_HOME. Falling back to the working directory
        // keeps the binary usable in a container, and the path is printed by
        // every command that writes one.
        None => PathBuf::from("qnero-wallet.seed"),
    }
}

/// Refuse a file holding secrets that anyone but its owner can read or write.
///
/// One implementation for the seed and for the store beside it. They carry the
/// same weight: the seed spends every note, and the store's `rho` and `r`
/// beside a published nullifier link every spend the wallet has made.
pub fn refuse_if_readable_beyond_owner(path: &Path) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} is readable or writable beyond its owner (mode {:o}). Fix it with `chmod 600 {}`.",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

/// Make a rename or a create durable by syncing the directory that carries the
/// name.
///
/// POSIX does not make a directory entry durable until the directory itself is
/// synced. A power loss between a store's rename and the next directory flush,
/// with the extrinsic already in the node's pool, leaves the note settled on
/// chain and the wallet with no `r` for it: the value is unspendable, which is
/// the exact outcome the temporary-file dance exists to prevent.
pub fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("failed to sync the directory {}", parent.display()))
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
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .context("the operating system's RNG refused")?;
    write_seed(path, &bytes)?;
    // `take_from` wipes the buffer it took, so nothing outside the
    // `ZeroizeOnDrop` key holds the seed after this line.
    Ok(SpendingKey::take_from(&mut bytes))
}

/// Write a seed somebody already holds, refusing to overwrite one that exists.
///
/// The hex is taken with whitespace anywhere in it, because the browser wallet
/// shows a spend key as eight groups of eight characters and somebody
/// restoring one has written it down that way.
pub fn import_seed(path: &Path, text: &str) -> Result<SpendingKey> {
    if path.exists() {
        bail!(
            "{} already exists. Refusing to overwrite a seed: the notes behind it would be \
             unspendable.",
            path.display()
        );
    }
    let packed = Zeroizing::new(
        text.chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase(),
    );
    if packed.len() != 64
        || !packed
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        bail!(
            "a spend key is 64 hex characters and this is {}. Nothing has been written.",
            packed.len()
        );
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(packed.as_str(), bytes.as_mut()).context("the spend key is not hex")?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    write_seed(path, &bytes)?;
    Ok(SpendingKey::take_from(&mut bytes))
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
    file.sync_all()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    drop(file);
    sync_parent_dir(path)
}

/// Read a seed, refusing one that is readable by anyone else.
pub fn load_seed(path: &Path) -> Result<SpendingKey> {
    if !path.exists() {
        bail!(
            "no seed at {}. Run `qnero-wallet keygen` first.",
            path.display()
        );
    }
    refuse_if_readable_beyond_owner(path)?;
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?,
    );
    let decoded = Zeroizing::new(
        hex::decode(text.trim()).with_context(|| format!("{} is not hex", path.display()))?,
    );
    if decoded.len() != 32 {
        bail!(
            "{} is {} bytes, a seed is 32",
            path.display(),
            decoded.len()
        );
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&decoded);
    Ok(SpendingKey::take_from(&mut bytes))
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

    /// The one check, applied to whatever holds secrets. The store uses it
    /// too, and a drift between the two is what left the store unchecked on
    /// load while the seed beside it was checked.
    #[test]
    fn the_permission_check_accepts_only_owner_access() {
        let dir = std::env::temp_dir().join(format!("qnero-keys-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("modes.seed");
        let _ = fs::remove_file(&path);
        create_seed(&path).unwrap();
        for mode in [0o600, 0o400, 0o200] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                refuse_if_readable_beyond_owner(&path).is_ok(),
                "mode {mode:o}"
            );
        }
        for mode in [0o640, 0o604, 0o660, 0o666, 0o601] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                refuse_if_readable_beyond_owner(&path).is_err(),
                "mode {mode:o}"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&path).unwrap();
    }

    /// A default that resolves relatively drops a spending key into whatever
    /// repository the user is standing in.
    #[test]
    fn the_default_seed_path_is_absolute_under_a_data_directory() {
        let path = default_seed_path();
        if std::env::var_os("HOME").is_some() || std::env::var_os("XDG_DATA_HOME").is_some() {
            assert!(path.is_absolute(), "{} is not absolute", path.display());
            assert!(path.to_string_lossy().contains("qnero"));
        }
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("qnero-wallet.seed")
        );
    }

    #[test]
    fn the_store_sits_beside_the_seed() {
        assert_eq!(
            store_path_for(Path::new("/tmp/a.seed")),
            PathBuf::from("/tmp/a.seed.store.json")
        );
    }
}
