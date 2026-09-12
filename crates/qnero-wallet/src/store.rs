//! The wallet store: one JSON file beside the seed.
//!
//! JSON, on purpose. Everything in it is small, a wallet reads it whole on
//! every command, and a note that a wallet cannot spend because its store is
//! opaque is worse than a slow scan. The format is
//! documented in `docs/WALLET.md` and versioned in the file, so a later
//! version can migrate.
//!
//! The file holds note secrets, `rho` and `r`, so it is written 0600 and is as
//! sensitive as the seed: `rho` and `r` plus the published nullifier are what
//! link a spend to its note.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{bail, Context, Result};
use qnero_notes::{Digest, Note};
use serde::{Deserialize, Serialize};

use crate::keys::{refuse_if_readable_beyond_owner, sync_parent_dir};

/// Bumped when the on-disk shape changes.
///
/// Version 2 added `used_nullifiers`, the local copy of the chain's settled
/// set. A version-1 store is refused; deleting it and re-syncing recovers
/// every unspent note, because every note's plaintext is on chain inside its
/// ciphertext.
pub const STORE_VERSION: u32 = 2;

#[derive(Clone, Serialize, Deserialize)]
pub struct WalletStore {
    pub version: u32,
    /// The address this store belongs to. A store opened with the wrong seed
    /// is refused, so two wallets' notes never merge.
    pub address: String,
    /// Highest block whose leaves are all accounted for.
    pub last_synced_block: u32,
    /// One past the last leaf index scanned.
    pub next_leaf: u64,
    pub notes: Vec<StoredNote>,
    /// Notes this wallet created and has not yet seen on chain.
    pub pending: Vec<PendingNote>,
    /// Ciphertexts that decrypted to this wallet and were refused. Kept so a
    /// wallet can say why a payment it was told about is not in its balance.
    pub rejected: Vec<RejectedNote>,
    /// Every nullifier the chain has settled, as of `last_synced_block`, in
    /// hex.
    ///
    /// This is a copy of a public map, and it is here so that spent status is
    /// decided locally. Asking the node whether one specific nullifier is
    /// settled hands it the nullifier of a note this wallet holds, which is
    /// the one value the pool's unlinkability rests on, before that value is
    /// published anywhere. See `docs/WALLET.md`.
    #[serde(default)]
    pub used_nullifiers: BTreeSet<String>,
}

/// The whole store, with every secret redacted.
///
/// Hand written, like every other type in this workspace that touches note
/// material. A derive would print `rho` and `r` for every note the moment
/// anyone added a `tracing::debug!` or an `anyhow` context that formats a
/// store, and those two values beside a published nullifier are what link a
/// settled spend to its note, its value and its recipient.
impl core::fmt::Debug for WalletStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WalletStore")
            .field("version", &self.version)
            .field("address", &self.address)
            .field("last_synced_block", &self.last_synced_block)
            .field("next_leaf", &self.next_leaf)
            .field("notes", &self.notes.len())
            .field("pending", &self.pending.len())
            .field("rejected", &self.rejected.len())
            .field("used_nullifiers", &self.used_nullifiers.len())
            .finish()
    }
}

/// Where a note came from. Recorded because a shield's `rho` follows the entry
/// rule and a spend output's follows the in-circuit rule, and the two are
/// checked differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteOrigin {
    /// Created by `shield`, with `rho = H(RHO_ENTRY, block_number, entry_index)`.
    Shield,
    /// An output of a spend, with `rho` derived in circuit from the two
    /// nullifiers its leaf published.
    Spend,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredNote {
    pub leaf_index: u64,
    pub block_number: Option<u32>,
    /// Pool quanta.
    pub value: u64,
    pub commitment: String,
    pub nullifier: String,
    pub rho: String,
    pub r: String,
    #[serde(default)]
    pub memo: String,
    pub origin: NoteOrigin,
    pub spent: bool,
    /// The block at which this wallet first saw the nullifier settled. Not the
    /// block that settled it: a wallet learns of a spend by probing
    /// `UsedNullifiers`, which carries no height.
    pub spent_seen_at_block: Option<u32>,
}

/// Redacted, for the reason `qnero_note_core::note::Note` gives: `rho` and
/// `r` beside a settled nullifier are the amount and the recipient key.
impl core::fmt::Debug for StoredNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredNote")
            .field("leaf_index", &self.leaf_index)
            .field("block_number", &self.block_number)
            .field("value", &self.value)
            .field("commitment", &self.commitment)
            .field("nullifier", &self.nullifier)
            .field("rho", &REDACTED)
            .field("r", &REDACTED)
            .field("memo", &REDACTED)
            .field("origin", &self.origin)
            .field("spent", &self.spent)
            .field("spent_seen_at_block", &self.spent_seen_at_block)
            .finish()
    }
}

/// What a redacted field prints as. A marker, so a log line says a secret was
/// there.
pub const REDACTED: &str = "[REDACTED]";

impl StoredNote {
    pub fn note(&self, pk: Digest) -> Result<Note> {
        Ok(Note::new(
            pk,
            self.value,
            parse_digest(&self.rho, "rho")?,
            parse_digest(&self.r, "r")?,
        )?)
    }
}

/// A note this wallet created and submitted, before the chain has it.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingNote {
    pub kind: PendingKind,
    pub commitment: String,
    pub value: u64,
    pub rho: String,
    pub r: String,
    #[serde(default)]
    pub memo: String,
    /// Height at the moment of submission, so a wallet can say how long a
    /// pending note has been waiting.
    pub submitted_at_block: u32,
    /// The extrinsic, hex encoded, for matching a block's extrinsics against
    /// this submission.
    pub extrinsic: String,
}

impl core::fmt::Debug for PendingNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingNote")
            .field("kind", &self.kind)
            .field("commitment", &self.commitment)
            .field("value", &self.value)
            .field("rho", &REDACTED)
            .field("r", &REDACTED)
            .field("memo", &REDACTED)
            .field("submitted_at_block", &self.submitted_at_block)
            .field("extrinsic", &self.extrinsic.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Shield,
    Change,
}

/// A decryptable output this wallet refused.
///
/// `docs/CIRCUIT.md` section 9.8: a sender chooses `rho` and `r` for a note it
/// creates, so a sender that repeats a pair creates two notes sharing a
/// nullifier, of which the recipient can spend exactly one. Accepting the
/// second silently would leave a balance that cannot be spent and no record of
/// why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedNote {
    pub leaf_index: u64,
    pub commitment: String,
    pub nullifier: String,
    pub value: u64,
    pub reason: String,
}

/// Distinguishes the temporary files of two saves in one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl WalletStore {
    pub fn new(address: String) -> Self {
        Self {
            version: STORE_VERSION,
            address,
            last_synced_block: 0,
            next_leaf: 0,
            notes: Vec::new(),
            pending: Vec::new(),
            rejected: Vec::new(),
            used_nullifiers: BTreeSet::new(),
        }
    }

    /// Load, or start a fresh store when the file does not exist.
    pub fn load_or_new(path: &Path, address: &str) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new(address.to_string()));
        }
        // The same check the seed one file over gets. The store holds every
        // note's `rho` and `r`, and a backup extracted without
        // `--preserve-permissions` or an `scp` under a permissive umask lands
        // it at 0644 where `save` would never put it.
        refuse_if_readable_beyond_owner(path)?;
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let store: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a wallet store", path.display()))?;
        if store.version != STORE_VERSION {
            bail!(
                "{} is store version {}, this wallet writes version {STORE_VERSION}",
                path.display(),
                store.version
            );
        }
        if store.address != address {
            bail!(
                "{} belongs to {} and the seed given derives {}",
                path.display(),
                store.address,
                address
            );
        }
        Ok(store)
    }

    /// Write atomically through a temporary file, so an interrupted write
    /// cannot truncate a store that holds the only copy of a note's `r`.
    pub fn save(&self, path: &Path) -> Result<()> {
        // A unique name opened with `create_new`, the discipline `write_seed`
        // already uses. `.mode()` is the `open(2)` mode argument and applies
        // only when the call actually creates the file, so a pre-existing
        // `.tmp` would take the note secrets at whatever mode it already
        // carried, and a symlink planted at that path would redirect the whole
        // store.
        let mut temp = path.as_os_str().to_os_string();
        temp.push(format!(
            ".tmp.{}.{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let temp = std::path::PathBuf::from(temp);
        if temp.exists() {
            fs::remove_file(&temp)
                .with_context(|| format!("failed to remove the stale {}", temp.display()))?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .with_context(|| format!("failed to create {}", temp.display()))?;
        let encoded = serde_json::to_string_pretty(self)?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        // Belt and braces: `create_new` already applied the mode.
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temp, path)
            .with_context(|| format!("failed to move {} into place", temp.display()))?;
        // The rename is the publication, and POSIX does not make it durable
        // until the directory carrying the name is synced. The store is the
        // only copy of a pending note's `r`.
        sync_parent_dir(path)
    }

    pub fn unspent(&self) -> impl Iterator<Item = &StoredNote> {
        self.notes.iter().filter(|note| !note.spent)
    }

    pub fn unspent_total(&self) -> u64 {
        self.unspent().map(|note| note.value).sum()
    }

    pub fn pending_total(&self) -> u64 {
        self.pending.iter().map(|note| note.value).sum()
    }

    /// Every nullifier this wallet already holds, spent or not.
    pub fn known_nullifiers(&self) -> BTreeSet<String> {
        self.notes
            .iter()
            .map(|note| note.nullifier.clone())
            .collect()
    }

    pub fn has_commitment(&self, commitment: &str) -> bool {
        self.notes.iter().any(|note| note.commitment == commitment)
    }

    /// Whether the chain had settled this nullifier as of the last sync.
    ///
    /// Answered from the local copy of `UsedNullifiers`. The node is asked
    /// for the whole map and the decision is made here.
    pub fn nullifier_settled(&self, nullifier: &str) -> bool {
        self.used_nullifiers.contains(nullifier)
    }

    pub fn mark_spent(&mut self, nullifier: &str, seen_at: u32) {
        for note in self.notes.iter_mut() {
            if note.nullifier == nullifier && !note.spent {
                note.spent = true;
                note.spent_seen_at_block = Some(seen_at);
            }
        }
    }
}

pub fn parse_digest(value: &str, what: &str) -> Result<Digest> {
    let bytes = hex::decode(value).with_context(|| format!("{what} is not hex"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is {} bytes, expected 32", bytes.len()))?;
    Digest::from_bytes(&bytes).map_err(|_| anyhow::anyhow!("{what} is not a canonical digest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_note(value: u64, tag: &str) -> StoredNote {
        let rho = Digest::hash_bytes(&[b"rho", tag.as_bytes()]);
        let r = Digest::hash_bytes(&[b"r", tag.as_bytes()]);
        StoredNote {
            leaf_index: value,
            block_number: Some(3),
            value,
            commitment: Digest::hash_bytes(&[b"cm", tag.as_bytes()]).to_hex(),
            nullifier: Digest::hash_bytes(&[b"nf", tag.as_bytes()]).to_hex(),
            rho: rho.to_hex(),
            r: r.to_hex(),
            memo: "a memo".into(),
            origin: NoteOrigin::Shield,
            spent: false,
            spent_seen_at_block: None,
        }
    }

    /// The store is the only copy of `r` a wallet has. A round trip that lost
    /// a field would leave a note in the tree that nothing can open.
    #[test]
    fn a_store_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("qnero-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("round-trip.store.json");
        let _ = fs::remove_file(&path);

        let mut store = WalletStore::new("qn1example".into());
        store.last_synced_block = 12;
        store.next_leaf = 31;
        store.notes.push(sample_note(1_000, "one"));
        store.notes.push(sample_note(400, "two"));
        store.pending.push(PendingNote {
            kind: PendingKind::Shield,
            commitment: "aa".repeat(32),
            value: 700,
            rho: Digest::hash_bytes(&[b"p-rho"]).to_hex(),
            r: Digest::hash_bytes(&[b"p-r"]).to_hex(),
            memo: String::new(),
            submitted_at_block: 9,
            extrinsic: "0x00".into(),
        });
        store.used_nullifiers.insert("dd".repeat(32));
        store.rejected.push(RejectedNote {
            leaf_index: 4,
            commitment: "bb".repeat(32),
            nullifier: "cc".repeat(32),
            value: 5,
            reason: "duplicate nullifier".into(),
        });
        store.save(&path).unwrap();

        let loaded = WalletStore::load_or_new(&path, "qn1example").unwrap();
        assert_eq!(
            serde_json::to_value(&store).unwrap(),
            serde_json::to_value(&loaded).unwrap()
        );
        assert_eq!(loaded.unspent_total(), 1_400);
        assert_eq!(loaded.pending_total(), 700);
        assert!(loaded.nullifier_settled(&"dd".repeat(32)));
        assert!(!loaded.nullifier_settled(&"ee".repeat(32)));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_file(&path).unwrap();
    }

    /// Opening a store with the wrong seed would merge two wallets' notes and
    /// then fail to spend any of them.
    #[test]
    fn a_store_refuses_a_seed_that_is_not_its_own() {
        let dir = std::env::temp_dir().join(format!("qnero-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wrong-seed.store.json");
        let _ = fs::remove_file(&path);
        WalletStore::new("qn1alice".into()).save(&path).unwrap();
        assert!(WalletStore::load_or_new(&path, "qn1bob").is_err());
        assert!(WalletStore::load_or_new(&path, "qn1alice").is_ok());
        fs::remove_file(&path).unwrap();
    }

    /// A store at a mode anyone else can read is refused on load, the way the
    /// seed beside it is. It holds every note's `rho` and `r`.
    #[test]
    fn a_world_readable_store_is_refused() {
        let dir = std::env::temp_dir().join(format!("qnero-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("loose.store.json");
        let _ = fs::remove_file(&path);
        WalletStore::new("qn1example".into()).save(&path).unwrap();
        assert!(WalletStore::load_or_new(&path, "qn1example").is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let refused = WalletStore::load_or_new(&path, "qn1example")
            .expect_err("a group or world readable store is refused");
        assert!(refused.to_string().contains("chmod 600"));
        fs::remove_file(&path).unwrap();
    }

    /// A derive would print `rho` and `r`. The first `tracing::debug!` or
    /// `dbg!` added later then writes every note's secrets into a log file at
    /// whatever mode that file happens to carry.
    #[test]
    fn debug_output_carries_no_note_secrets() {
        let note = sample_note(1_000, "one");
        let printed = format!("{note:?}");
        assert!(!printed.contains(&note.rho), "rho leaked: {printed}");
        assert!(!printed.contains(&note.r), "r leaked: {printed}");
        assert!(!printed.contains("a memo"), "the memo leaked: {printed}");
        assert!(printed.contains(&note.commitment));
        assert!(printed.contains(REDACTED));

        let pending = PendingNote {
            kind: PendingKind::Change,
            commitment: "aa".repeat(32),
            value: 7,
            rho: Digest::hash_bytes(&[b"p-rho"]).to_hex(),
            r: Digest::hash_bytes(&[b"p-r"]).to_hex(),
            memo: "secret memo".into(),
            submitted_at_block: 9,
            extrinsic: "0xdeadbeef".into(),
        };
        let printed = format!("{pending:?}");
        assert!(!printed.contains(&pending.rho));
        assert!(!printed.contains(&pending.r));
        assert!(!printed.contains("secret memo"));

        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(note);
        store.pending.push(pending);
        let printed = format!("{store:?}");
        assert!(!printed.contains(&store.notes[0].rho));
        assert!(!printed.contains(&store.pending[0].r));
        assert!(printed.contains("notes: 1"));
    }

    #[test]
    fn marking_a_nullifier_spent_moves_it_out_of_the_balance() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        let nullifier = store.notes[0].nullifier.clone();
        assert_eq!(store.unspent_total(), 1_000);
        store.mark_spent(&nullifier, 42);
        assert_eq!(store.unspent_total(), 0);
        assert_eq!(store.notes[0].spent_seen_at_block, Some(42));
    }
}
