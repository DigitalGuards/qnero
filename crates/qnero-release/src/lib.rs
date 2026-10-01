//! Authenticate release bytes with an independently trusted ML-DSA-87 key.
//!
//! A signature covers the exact manifest bytes, including the source revision,
//! paths, sizes, executable bits and SHA-512 digests. Verification authenticates
//! before parsing paths, and optional snapshot output copies the same bytes it
//! hashes. The caller supplies both its trusted key and its expected revision.

use anyhow::{bail, ensure, Context, Result};
use qp_rusty_crystals_dilithium::{
    ml_dsa_87::{Keypair, PublicKey, PUBLICKEYBYTES, SIGNBYTES},
    SensitiveBytes32,
};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const SIGNING_CONTEXT: &[u8] = b"QNERO_RELEASE_MANIFEST_V1";
pub const SCHEMA: &str = "qnero-release-v1";
pub const REPOSITORY: &str = "https://github.com/DigitalGuards/qnero";
const ALGORITHM: &str = "ML-DSA-87";
const PRIVATE_HEADER: &[u8] = b"QNERO_RELEASE_PRIVATE_V1\n";
const PUBLIC_HEADER: &[u8] = b"QNERO_RELEASE_PUBLIC_V1\n";
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_ENTRIES: usize = MAX_FILES * 4;
const MAX_PATH_BYTES: usize = 512;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub repository: String,
    pub algorithm: String,
    pub revision: String,
    pub public_key_sha512: String,
    pub files: Vec<Artifact>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub size: u64,
    pub sha512: String,
    pub executable: bool,
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system refused release randomness")?;
    Ok(bytes)
}

fn new_file(path: &Path, secret: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    options
        .open(path)
        .with_context(|| format!("refusing to overwrite or cannot create {}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut file = new_file(path, secret)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn regular_file(path: &Path) -> Result<File> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "{} must be a regular file, without a symlink",
        path.display()
    );
    File::open(path).with_context(|| format!("cannot read {}", path.display()))
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    regular_file(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} is too large",
        path.display()
    );
    Ok(bytes)
}

fn keypair_from_seed(mut seed: Zeroizing<[u8; 32]>) -> Keypair {
    Keypair::generate(&mut SensitiveBytes32::from(&mut *seed))
}

fn load_private(path: &Path) -> Result<Keypair> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            fs::symlink_metadata(path)?.permissions().mode() & 0o077 == 0,
            "private release key must have owner-only permissions"
        );
    }
    let bytes = Zeroizing::new(read_limited(path, (PRIVATE_HEADER.len() + 32) as u64)?);
    ensure!(
        bytes.len() == PRIVATE_HEADER.len() + 32 && bytes.starts_with(PRIVATE_HEADER),
        "invalid private release key format"
    );
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&bytes[PRIVATE_HEADER.len()..]);
    Ok(keypair_from_seed(seed))
}

fn public_bytes(keypair: &Keypair) -> Vec<u8> {
    [PUBLIC_HEADER, &keypair.public().to_bytes()].concat()
}

/// Generate a separate release seed. Existing files are never overwritten.
pub fn keygen(private: &Path, public: &Path) -> Result<String> {
    ensure!(
        fs::symlink_metadata(public).is_err(),
        "public key output already exists"
    );
    let seed = Zeroizing::new(random_bytes()?);
    let keypair = keypair_from_seed(Zeroizing::new(*seed));
    let mut encoded = Zeroizing::new(Vec::with_capacity(PRIVATE_HEADER.len() + 32));
    encoded.extend_from_slice(PRIVATE_HEADER);
    encoded.extend_from_slice(seed.as_ref());
    write_new(private, &encoded, true)?;
    write_new(public, &public_bytes(&keypair), false)?;
    Ok(hex::encode(Sha512::digest(keypair.public().to_bytes())))
}

/// Recover the public file from an existing private key without exposing it.
pub fn export_public(private: &Path, public: &Path) -> Result<()> {
    write_new(public, &public_bytes(&load_private(private)?), false)
}

fn load_public(path: &Path) -> Result<(PublicKey, String)> {
    let public = read_limited(path, (PUBLIC_HEADER.len() + PUBLICKEYBYTES) as u64)?;
    ensure!(
        public.len() == PUBLIC_HEADER.len() + PUBLICKEYBYTES && public.starts_with(PUBLIC_HEADER),
        "invalid public release key format"
    );
    let raw_public = &public[PUBLIC_HEADER.len()..];
    let key = PublicKey::from_bytes(raw_public)
        .map_err(|e| anyhow::anyhow!("invalid public release key: {e:?}"))?;
    Ok((key, hex::encode(Sha512::digest(raw_public))))
}

/// Return the public key fingerprint for comparison through a trusted channel.
pub fn fingerprint(public: &Path) -> Result<String> {
    Ok(load_public(public)?.1)
}

fn validate_revision(revision: &str) -> Result<()> {
    ensure!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected revision must be a full lowercase 40-character Git commit"
    );
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "invalid artifact path length"
    );
    for part in path.split('/') {
        ensure!(
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid artifact path {path}"
        );
        ensure!(!part.ends_with('.'), "invalid artifact path {path}");
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        ensure!(
            !["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "reserved artifact path {path}"
        );
    }
    Ok(())
}

fn checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_path(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        ensure!(
            !fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "symlink in artifact path {relative}"
        );
    }
    Ok(path)
}

fn collect(
    root: &Path,
    relative: &str,
    files: &mut BTreeSet<String>,
    visited: &mut usize,
) -> Result<()> {
    *visited += 1;
    ensure!(
        *visited <= MAX_ENTRIES,
        "too many artifact directory entries"
    );
    let path = checked_path(root, relative)?;
    let kind = fs::symlink_metadata(&path)?.file_type();
    if kind.is_dir() {
        for entry in fs::read_dir(path)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("artifact names must be ASCII"))?;
            collect(root, &format!("{relative}/{name}"), files, visited)?;
        }
    } else {
        ensure!(kind.is_file(), "artifact {relative} must be a regular file");
        files.insert(relative.to_string());
        ensure!(files.len() <= MAX_FILES, "too many artifacts");
    }
    Ok(())
}

fn executable(file: &File) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(file.metadata()?.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(false)
    }
}

fn hash_stream(reader: &mut impl Read, mut output: Option<&mut File>) -> Result<(u64, String)> {
    let mut hash = Sha512::new();
    let mut size = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .context("artifact size overflow")?;
        hash.update(&buffer[..read]);
        if let Some(writer) = output.as_mut() {
            writer.write_all(&buffer[..read])?;
        }
    }
    Ok((size, hex::encode(hash.finalize())))
}

/// Sign files or complete directory trees, using paths relative to `root`.
pub fn sign(
    root: &Path,
    private: &Path,
    revision: &str,
    paths: &[String],
    manifest: &Path,
    signature: &Path,
) -> Result<Manifest> {
    validate_revision(revision)?;
    let root = root.canonicalize()?;
    let keypair = load_private(private)?;
    let mut selected = BTreeSet::new();
    let mut visited = 0;
    for path in paths {
        collect(&root, path, &mut selected, &mut visited)?;
    }
    ensure!(!selected.is_empty(), "at least one artifact is required");
    let mut files = Vec::new();
    for path in selected {
        let mut input = regular_file(&checked_path(&root, &path)?)?;
        let executable = executable(&input)?;
        let (size, sha512) = hash_stream(&mut input, None)?;
        files.push(Artifact {
            path,
            size,
            sha512,
            executable,
        });
    }
    let manifest_data = Manifest {
        schema: SCHEMA.to_string(),
        repository: REPOSITORY.to_string(),
        algorithm: ALGORITHM.to_string(),
        revision: revision.to_string(),
        public_key_sha512: hex::encode(Sha512::digest(keypair.public().to_bytes())),
        files,
    };
    validate_manifest(&manifest_data, revision)?;
    let bytes = serde_json::to_vec_pretty(&manifest_data)?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "manifest is too large"
    );
    let mut hedge_bytes = Zeroizing::new(random_bytes()?);
    let hedge = SensitiveBytes32::from(&mut *hedge_bytes);
    let signed = keypair
        .sign(&bytes, Some(SIGNING_CONTEXT), Some(&hedge))
        .map_err(|e| anyhow::anyhow!("release signing failed: {e:?}"))?;
    ensure!(
        fs::symlink_metadata(signature).is_err(),
        "signature output already exists"
    );
    write_new(manifest, &bytes, false)?;
    write_new(signature, &signed, false)?;
    Ok(manifest_data)
}

fn validate_manifest(manifest: &Manifest, revision: &str) -> Result<()> {
    ensure!(
        manifest.schema == SCHEMA
            && manifest.repository == REPOSITORY
            && manifest.algorithm == ALGORITHM,
        "unsupported release manifest"
    );
    ensure!(
        manifest.revision == revision,
        "release revision does not match the expected commit"
    );
    ensure!(
        !manifest.files.is_empty() && manifest.files.len() <= MAX_FILES,
        "invalid artifact count"
    );
    let mut names = BTreeSet::new();
    for artifact in &manifest.files {
        validate_path(&artifact.path)?;
        ensure!(
            names.insert(artifact.path.to_ascii_lowercase()),
            "duplicate artifact path {}",
            artifact.path
        );
        ensure!(artifact.size < u64::MAX, "invalid artifact size");
        ensure!(
            artifact.sha512.len() == 128
                && artifact
                    .sha512
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid SHA-512 digest"
        );
    }
    Ok(())
}

struct Snapshot {
    path: PathBuf,
    published: bool,
}

impl Snapshot {
    fn create(destination: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(destination).is_err(),
            "snapshot output already exists"
        );
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        for _ in 0..8 {
            let path = parent.join(format!(".qnero-release-{}", hex::encode(random_bytes()?)));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        published: false,
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("cannot allocate a private verification snapshot")
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Authenticate first, check required coverage and all digests, then publish an
/// optional snapshot. Its file bytes come from the streams that were hashed.
pub fn verify(
    root: &Path,
    public: &Path,
    revision: &str,
    manifest: &Path,
    signature: &Path,
    required: &[String],
    output: Option<&Path>,
) -> Result<Manifest> {
    validate_revision(revision)?;
    let bytes = read_limited(manifest, MAX_MANIFEST_BYTES)?;
    let signed = read_limited(signature, SIGNBYTES as u64)?;
    let (key, fingerprint) = load_public(public)?;
    ensure!(
        key.verify(&bytes, &signed, Some(SIGNING_CONTEXT)),
        "release signature does not verify with the trusted key"
    );
    let manifest_data: Manifest =
        serde_json::from_slice(&bytes).context("invalid signed release manifest")?;
    validate_manifest(&manifest_data, revision)?;
    ensure!(
        manifest_data.public_key_sha512 == fingerprint,
        "release key fingerprint does not match"
    );
    let root = root.canonicalize()?;
    let covered: BTreeMap<_, _> = manifest_data
        .files
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();
    let mut needed = BTreeSet::new();
    let mut visited = 0;
    for path in required {
        collect(&root, path, &mut needed, &mut visited)?;
    }
    for path in needed {
        ensure!(
            covered.contains_key(path.as_str()),
            "signed manifest leaves out required file {path}"
        );
    }
    let mut snapshot = output.map(Snapshot::create).transpose()?;
    for entry in &manifest_data.files {
        let input = regular_file(&checked_path(&root, &entry.path)?)?;
        ensure!(
            input.metadata()?.len() == entry.size,
            "artifact {} does not match its signed size",
            entry.path
        );
        let mut writer = if let Some(snapshot) = &snapshot {
            let path = snapshot.path.join(&entry.path);
            fs::create_dir_all(path.parent().context("missing snapshot parent")?)?;
            Some(new_file(&path, false)?)
        } else {
            None
        };
        let (size, hash) = hash_stream(&mut input.take(entry.size + 1), writer.as_mut())?;
        ensure!(
            size == entry.size && hash == entry.sha512,
            "artifact {} does not match its signed SHA-512 digest",
            entry.path
        );
        if let Some(writer) = &mut writer {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                writer.set_permissions(fs::Permissions::from_mode(if entry.executable {
                    0o755
                } else {
                    0o644
                }))?;
            }
            writer.sync_all()?;
        }
    }
    if let (Some(snapshot), Some(output)) = (&mut snapshot, output) {
        ensure!(
            fs::symlink_metadata(output).is_err(),
            "snapshot output already exists"
        );
        fs::rename(&snapshot.path, output)?;
        snapshot.published = true;
    }
    Ok(manifest_data)
}
