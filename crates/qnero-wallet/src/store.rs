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
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{refuse_if_readable_beyond_owner, sync_parent_dir};

/// Bumped when the on-disk shape changes.
///
/// Version 2 added `used_nullifiers`, the local copy of the chain's settled
/// set. Version 3 added `checkpoints`, the block hashes a sync finished at,
/// which is how a fork is detected. A version-2 store is upgraded in place on
/// load, with an empty checkpoint list: the first sync after the upgrade
/// records one and has nothing older to compare against. A version-1 store is
/// refused; deleting it and re-syncing recovers every unspent note, because
/// every note's plaintext is on chain inside its ciphertext.
pub const STORE_VERSION: u32 = 3;

/// The oldest store shape this wallet still upgrades. Anything older is
/// refused.
const OLDEST_UPGRADABLE_VERSION: u32 = 2;

/// Sync checkpoints kept, newest last.
///
/// Each one costs a `chain_getBlockHash` on the sync that has to walk back
/// through it, and the walk stops at the first that still matches, so the
/// usual cost is one call. Sixteen on-demand syncs is a long way past any
/// reorg a proof-of-work chain settles in; deeper than that the watermark
/// rewinds to zero and the whole tree is rescanned, which is correct and slow.
const MAX_CHECKPOINTS: usize = 16;

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
    /// The blocks this wallet finished a sync at, and the leaf watermark each
    /// one left, oldest first.
    ///
    /// A leaf index is provisional: every read a sync makes is pinned to the
    /// best block, and a best block can be orphaned. The watermark alone
    /// cannot see that, because it only ever moves forward and a replacement
    /// branch is normally at least as long as the branch it replaces, so the
    /// leaf a note moved to is usually below the watermark and is never
    /// re-read. Comparing a stored block hash against
    /// `chain_getBlockHash(block_number)` sees the fork itself, and rewinding
    /// the watermark to the newest checkpoint that still matches puts every
    /// moved leaf back inside the next scan's range. See
    /// `Wallet::sync`.
    #[serde(default)]
    pub checkpoints: Vec<SyncCheckpoint>,
}

/// A block a sync finished at, and the watermark it left behind.
///
/// `block_hash` is what makes it a checkpoint. A height survives a reorg and
/// a hash does not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    pub block_number: u32,
    /// Hex, no `0x`.
    pub block_hash: String,
    /// The leaf watermark as of that block: one past the last leaf scanned.
    pub next_leaf: u64,
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
            .field("checkpoints", &self.checkpoints.len())
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

/// A note secret, held as hex and wiped when the last copy drops.
///
/// The store's JSON text is read and written inside `Zeroizing`, which covers
/// the two shortest-lived buffers the wallet owns. `serde_json::from_str`
/// allocates a fresh `String` for every `rho` and `r` it parses, and those are
/// the longest-lived copies: they sit in the `WalletStore` for the life of the
/// process, are cloned again by `prepare_spend`, and used to be dropped
/// without being wiped. A core dump, a swap page or a hibernation image from a
/// machine that merely ran `qnero-wallet balance` then still yielded every
/// note's `rho` and `r`, which beside a published nullifier is the whole link
/// from a settled spend to its note, its value and its recipient.
///
/// `#[serde(transparent)]`, so the file format is unchanged: a plain hex
/// string. What is not covered is a `String` that reallocates while growing,
/// which leaves the old allocation behind; these are built once from a fixed
/// 64-character hex and never grown.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretHex(String);

impl SecretHex {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretHex {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::ops::Deref for SecretHex {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretHex {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretHex {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

/// Redacted, like every other note secret in this workspace.
impl core::fmt::Debug for SecretHex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(REDACTED)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredNote {
    pub leaf_index: u64,
    pub block_number: Option<u32>,
    /// Pool quanta.
    pub value: u64,
    pub commitment: String,
    pub nullifier: String,
    pub rho: SecretHex,
    pub r: SecretHex,
    #[serde(default)]
    pub memo: String,
    pub origin: NoteOrigin,
    pub spent: bool,
    /// The block at which this wallet first saw the nullifier settled.
    ///
    /// Not the block that settled it. Spent status is decided locally against
    /// the paged copy of `UsedNullifiers`, and that map carries no height at
    /// all, so the best a wallet can record is the head its sync was pinned
    /// to.
    pub spent_seen_at_block: Option<u32>,
}

/// Redacted, for the reason `qnero_note_core::note::Note` gives: `rho` and
/// `r` beside a settled nullifier are the amount and the recipient key.
///
/// The nullifier is redacted too, and it is the one that matters most here.
/// For a note that has not been spent, its nullifier has never appeared
/// anywhere: it is exactly the value `Chain::used_nullifiers_at` pages a whole
/// public map for, and exactly what `PreparedSpend`'s `Debug` redacts on the
/// same grounds. A log line carrying it lets anyone who
/// later reads that file watch the chain and attribute the settlement that
/// publishes it to this wallet with certainty. `commitment` stays in the
/// clear: the chain published it beside the leaf.
///
/// `leaf_index` stays as well. It names a leaf this wallet owns, so it is not
/// nothing, and `SendReport` prints the input leaves of a settled spend
/// anyway; what it does not do is predict a value the wallet has yet to
/// publish. `docs/WALLET.md` says which fields are covered.
impl core::fmt::Debug for StoredNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoredNote")
            .field("leaf_index", &self.leaf_index)
            .field("block_number", &self.block_number)
            .field("value", &self.value)
            .field("commitment", &self.commitment)
            .field("nullifier", &REDACTED)
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
    pub rho: SecretHex,
    pub r: SecretHex,
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
#[derive(Clone, Serialize, Deserialize)]
pub struct RejectedNote {
    pub leaf_index: u64,
    pub commitment: String,
    pub nullifier: String,
    pub value: u64,
    pub reason: String,
}

/// Redacted for the reason `StoredNote`'s is. A refused note's nullifier is a
/// value this wallet computed and nobody published; one of the two refusals
/// that produce a `RejectedNote` is a nullifier that duplicates a note this
/// wallet still holds and still intends to spend, so printing it names the
/// value that spend will publish.
impl core::fmt::Debug for RejectedNote {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RejectedNote")
            .field("leaf_index", &self.leaf_index)
            .field("commitment", &self.commitment)
            .field("nullifier", &REDACTED)
            .field("value", &self.value)
            .field("reason", &self.reason)
            .finish()
    }
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
            checkpoints: Vec::new(),
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
        // Wiped on the way out. The buffer holds every note's `rho` and `r`,
        // which beside a published nullifier are the link from a settled spend
        // to its note, its value and its recipient; the seed one file over is
        // handled inside `Zeroizing` for the same reason. A core dump or a
        // swap page reaches a freed heap buffer just as well as a live one.
        let text = Zeroizing::new(
            fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        );
        let mut store: Self = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a wallet store", path.display()))?;
        if store.version > STORE_VERSION || store.version < OLDEST_UPGRADABLE_VERSION {
            bail!(
                "{} is store version {}, this wallet writes version {STORE_VERSION} and upgrades \
                 version {OLDEST_UPGRADABLE_VERSION}",
                path.display(),
                store.version
            );
        }
        if store.version < STORE_VERSION {
            // Version 2 to 3 adds `checkpoints`, which defaults to empty. The
            // first sync after the upgrade records one; until then there is no
            // stored hash to compare against, so a fork that happened before
            // the upgrade is invisible, which is what it already was.
            store.version = STORE_VERSION;
            store.checkpoints.clear();
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
        // Wiped on the way out, for the reason `load_or_new` gives. Every
        // command writes the store more than once: a `send` writes the pending
        // change note, again after settlement, and again after its sync.
        let encoded = Zeroizing::new(serde_json::to_string_pretty(self)?);
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

    /// Move a note this wallet already holds to the leaf it now occupies.
    ///
    /// A leaf index is provisional when a scan first records it. Every read a
    /// sync makes is pinned to `chain_getHeader`, which on a proof-of-work
    /// chain is the best block, and a best block can still be orphaned. When
    /// the block a note
    /// settled in is orphaned, the extrinsic is still in the pool and is
    /// re-included, and it appends the identical commitment (the same `pk`,
    /// `rho` and `r` open the same `inner`) at whatever index the replacement
    /// block has room for.
    ///
    /// The rescan sees that commitment again and must not skip it: a stored
    /// index that points at somebody else's leaf makes the note unspendable,
    /// because `local_paths` refuses a leaf whose commitment is not the note's
    /// and `--merkle-rpc` refuses the same way. The balance would read as
    /// spendable and every spend would fail until the JSON was edited by hand.
    ///
    /// Returns whether anything moved.
    pub fn relocate_note(
        &mut self,
        commitment: &str,
        leaf_index: u64,
        block_number: Option<u32>,
    ) -> bool {
        let mut moved = false;
        for note in self.notes.iter_mut() {
            if note.commitment != commitment {
                continue;
            }
            if note.leaf_index != leaf_index || note.block_number != block_number {
                note.leaf_index = leaf_index;
                note.block_number = block_number;
                moved = true;
            }
        }
        moved
    }

    /// Whether the chain had settled this nullifier as of the last sync.
    ///
    /// Answered from the local copy of `UsedNullifiers`. The node is asked
    /// for the whole map and the decision is made here.
    pub fn nullifier_settled(&self, nullifier: &str) -> bool {
        self.used_nullifiers.contains(nullifier)
    }

    /// Latch a note spent, ahead of the sync that would derive it.
    ///
    /// Used by `submit_spend`, which has confirmed both nullifiers are in
    /// `UsedNullifiers` at the inclusion block. Between that point and the
    /// next sync the store's copy of the settled set has not been repaged, so
    /// nothing would derive the flag and `send --no-sync` could select the
    /// same input twice.
    pub fn mark_spent(&mut self, nullifier: &str, seen_at: u32) {
        for note in self.notes.iter_mut() {
            if note.nullifier == nullifier && !note.spent {
                note.spent = true;
                note.spent_seen_at_block = Some(seen_at);
            }
        }
    }

    /// Put a note back in the balance.
    ///
    /// The inverse of [`WalletStore::mark_spent`], and the reason
    /// [`WalletStore::reconcile_spent`] can exist.
    pub fn mark_unspent(&mut self, nullifier: &str) {
        for note in self.notes.iter_mut() {
            if note.nullifier == nullifier && note.spent {
                note.spent = false;
                note.spent_seen_at_block = None;
            }
        }
    }

    /// Re-derive every note's spent flag from the settled set.
    ///
    /// Returns `(newly spent, newly unspent)`.
    ///
    /// The regression this closes: `spent` was a latch. A sync replaced the
    /// local copy of `UsedNullifiers` wholesale on every pass, so the store
    /// always held the chain's current answer, and then only ever set the flag
    /// true. When the block carrying a settlement was orphaned and the
    /// settlement did not re-land, because the unsigned extrinsic left the
    /// pool after five blocks or its anchor fell outside the window, the
    /// nullifier was permanently absent from the map and the note stayed
    /// spent forever: under-reported in the balance, passed over by every
    /// selection, and recoverable only by deleting the store.
    ///
    /// Safe against the latch above because this runs inside `Wallet::sync`,
    /// immediately after the set is repaged from the chain. A head that still
    /// contains the inclusion block re-derives exactly what `submit_spend`
    /// latched; a head that no longer contains it is the case this exists for.
    pub fn reconcile_spent(&mut self, seen_at: u32) -> (u64, u64) {
        // Taken out and put back so the notes can be walked mutably against
        // it. The set is the authority here, and it was read at `seen_at`.
        let settled = core::mem::take(&mut self.used_nullifiers);
        let mut newly_spent = 0;
        let mut newly_unspent = 0;
        for note in self.notes.iter_mut() {
            match (settled.contains(&note.nullifier), note.spent) {
                (true, false) => {
                    note.spent = true;
                    note.spent_seen_at_block = Some(seen_at);
                    newly_spent += 1;
                }
                (false, true) => {
                    note.spent = false;
                    note.spent_seen_at_block = None;
                    newly_unspent += 1;
                }
                _ => {}
            }
        }
        self.used_nullifiers = settled;
        (newly_spent, newly_unspent)
    }

    /// The newest checkpoint, if any.
    pub fn newest_checkpoint(&self) -> Option<&SyncCheckpoint> {
        self.checkpoints.last()
    }

    /// Record where this sync finished, dropping anything at or above it.
    ///
    /// Anything at or above the new height is either the same block, and so
    /// redundant, or a block this sync did not see, which after a fork is a
    /// checkpoint for a branch that is gone.
    pub fn record_checkpoint(&mut self, block_number: u32, block_hash: String, next_leaf: u64) {
        self.checkpoints
            .retain(|checkpoint| checkpoint.block_number < block_number);
        self.checkpoints.push(SyncCheckpoint {
            block_number,
            block_hash,
            next_leaf,
        });
        if self.checkpoints.len() > MAX_CHECKPOINTS {
            let excess = self.checkpoints.len() - MAX_CHECKPOINTS;
            self.checkpoints.drain(..excess);
        }
    }

    /// Rewind the scan watermark and drop every checkpoint above it.
    ///
    /// What a fork detection does. The leaves below `next_leaf` were folded at
    /// or before a block that is still canonical, so they cannot have moved;
    /// everything above is rescanned and `relocate_note` sees whatever the
    /// replacement branch did with it.
    pub fn rewind_to(&mut self, block_number: u32, next_leaf: u64) {
        self.next_leaf = next_leaf;
        self.last_synced_block = block_number;
        self.checkpoints
            .retain(|checkpoint| checkpoint.block_number <= block_number);
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
            rho: rho.to_hex().into(),
            r: r.to_hex().into(),
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
            rho: Digest::hash_bytes(&[b"p-rho"]).to_hex().into(),
            r: Digest::hash_bytes(&[b"p-r"]).to_hex().into(),
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
        assert!(
            !printed.contains(note.rho.as_str()),
            "rho leaked: {printed}"
        );
        assert!(!printed.contains(note.r.as_str()), "r leaked: {printed}");
        assert!(!printed.contains("a memo"), "the memo leaked: {printed}");
        // The regression: an unspent note's nullifier has never been
        // published, and a log line carrying it lets a later reader attribute
        // the settlement that publishes it to this wallet. It is the same
        // value `PreparedSpend` redacts and the same value
        // `used_nullifiers_at` pages a whole map to avoid naming.
        assert!(
            !printed.contains(&note.nullifier),
            "the nullifier leaked: {printed}"
        );
        assert!(printed.contains(&note.commitment));
        assert!(printed.contains(REDACTED));

        let rejected = RejectedNote {
            leaf_index: 4,
            commitment: "bb".repeat(32),
            nullifier: "cc".repeat(32),
            value: 5,
            reason: "duplicate nullifier".into(),
        };
        let printed = format!("{rejected:?}");
        assert!(
            !printed.contains(&rejected.nullifier),
            "a refused note's nullifier leaked: {printed}"
        );
        assert!(printed.contains("duplicate nullifier"), "{printed}");

        let pending = PendingNote {
            kind: PendingKind::Change,
            commitment: "aa".repeat(32),
            value: 7,
            rho: Digest::hash_bytes(&[b"p-rho"]).to_hex().into(),
            r: Digest::hash_bytes(&[b"p-r"]).to_hex().into(),
            memo: "secret memo".into(),
            submitted_at_block: 9,
            extrinsic: "0xdeadbeef".into(),
        };
        let printed = format!("{pending:?}");
        assert!(!printed.contains(pending.rho.as_str()));
        assert!(!printed.contains(pending.r.as_str()));
        assert!(!printed.contains("secret memo"));

        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(note);
        store.pending.push(pending);
        let printed = format!("{store:?}");
        assert!(!printed.contains(store.notes[0].rho.as_str()));
        assert!(!printed.contains(store.pending[0].r.as_str()));
        assert!(printed.contains("notes: 1"));
    }

    /// The regression: a rescan skipped any commitment the store already held,
    /// so a note whose block was orphaned and whose extrinsic was re-included
    /// at a different leaf kept the old index forever. `select_notes` picked
    /// it, the path rebuild refused the leaf as somebody else's, and the
    /// balance was unspendable until the JSON was edited by hand.
    #[test]
    fn a_note_that_moved_leaf_is_repaired_rather_than_skipped() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        let commitment = store.notes[0].commitment.clone();
        let original = store.notes[0].leaf_index;

        assert!(store.has_commitment(&commitment));
        assert!(
            !store.relocate_note(&commitment, original, Some(3)),
            "a note at the index it was recorded at does not move"
        );

        assert!(store.relocate_note(&commitment, original + 1, Some(4)));
        assert_eq!(store.notes[0].leaf_index, original + 1);
        assert_eq!(store.notes[0].block_number, Some(4));
        // The value, the secrets and the spent flag are untouched: only where
        // the note sits changed.
        assert_eq!(store.unspent_total(), 1_000);
        assert!(!store.notes[0].spent);

        assert!(!store.relocate_note(&"ff".repeat(32), 9, Some(9)));
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

    /// The regression: `spent` was a latch. The settled set is repaged whole
    /// on every sync, so the store always holds the chain's current answer,
    /// and a note whose settlement was orphaned out of the chain stayed spent
    /// forever: under-reported, passed over by every selection, recoverable
    /// only by deleting the store.
    #[test]
    fn spent_status_follows_the_settled_set_in_both_directions() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        store.notes.push(sample_note(400, "two"));
        let first = store.notes[0].nullifier.clone();

        store.used_nullifiers.insert(first.clone());
        assert_eq!(store.reconcile_spent(42), (1, 0));
        assert_eq!(store.unspent_total(), 400);
        assert_eq!(store.notes[0].spent_seen_at_block, Some(42));

        // Idempotent: the same set at a later head changes nothing.
        assert_eq!(store.reconcile_spent(43), (0, 0));
        assert_eq!(store.notes[0].spent_seen_at_block, Some(42));

        // The settlement is orphaned out and does not re-land.
        store.used_nullifiers.remove(&first);
        assert_eq!(store.reconcile_spent(44), (0, 1));
        assert_eq!(store.unspent_total(), 1_400);
        assert!(!store.notes[0].spent);
        assert_eq!(store.notes[0].spent_seen_at_block, None);

        store.mark_unspent(&first);
        assert_eq!(store.unspent_total(), 1_400);
    }

    /// Checkpoints are the fork detector's memory: one per sync, newest last,
    /// bounded, and a rewind drops every branch above the block it rewinds to.
    #[test]
    fn checkpoints_stay_ordered_bounded_and_truthful() {
        let mut store = WalletStore::new("qn1example".into());
        for block in 1..=(MAX_CHECKPOINTS as u32 + 4) {
            store.record_checkpoint(block, format!("{block:064x}"), u64::from(block) * 2);
        }
        assert_eq!(store.checkpoints.len(), MAX_CHECKPOINTS);
        assert_eq!(
            store.newest_checkpoint().map(|c| c.block_number),
            Some(MAX_CHECKPOINTS as u32 + 4)
        );
        assert!(store
            .checkpoints
            .windows(2)
            .all(|pair| pair[0].block_number < pair[1].block_number));

        // A sync that finishes at a height already recorded replaces it: after
        // a fork the old entry is a hash from a branch that is gone.
        let height = store.checkpoints[0].block_number;
        store.record_checkpoint(height, "ff".repeat(32), 7);
        assert_eq!(store.checkpoints.len(), 1);
        assert_eq!(store.checkpoints[0].next_leaf, 7);

        store.record_checkpoint(height + 1, "ee".repeat(32), 9);
        store.rewind_to(height, 7);
        assert_eq!(store.next_leaf, 7);
        assert_eq!(store.last_synced_block, height);
        assert_eq!(store.checkpoints.len(), 1);
    }

    /// A version-2 store upgrades in place: it holds every note secret and the
    /// only thing version 3 adds defaults to empty.
    #[test]
    fn a_version_two_store_upgrades_rather_than_being_refused() {
        let dir = std::env::temp_dir().join(format!("qnero-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v2.store.json");
        let _ = fs::remove_file(&path);

        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        store.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("\"version\": 3", "\"version\": 2")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let loaded = WalletStore::load_or_new(&path, "qn1example").expect("it upgrades");
        assert_eq!(loaded.version, STORE_VERSION);
        assert_eq!(loaded.unspent_total(), 1_000);
        assert!(loaded.checkpoints.is_empty());

        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("\"version\": 2", "\"version\": 1")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(WalletStore::load_or_new(&path, "qn1example").is_err());
        fs::remove_file(&path).unwrap();
    }
}
