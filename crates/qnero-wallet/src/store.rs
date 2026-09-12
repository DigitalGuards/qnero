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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
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
/// which is how a fork is detected. Version 4 added `on_chain`, which is what
/// a fork rescan writes down when it proves a held note is not on the chain
/// any more, and dropped `used_nullifiers` from the file. Version 5 added
/// `genesis_hash`, which binds the store to one chain.
///
/// Every older shape is upgraded in place on load. A version-2 store gets an
/// empty checkpoint list: the first sync after the upgrade records one and has
/// nothing older to compare against. A version-3 store's notes load as
/// `on_chain: true`, which is what every note in one is: the version that
/// wrote it had no way to mark a note otherwise. A version-4 store loads with
/// no genesis, and the first sync after the upgrade records the genesis of the
/// node it runs against. A version-1 store is refused;
/// deleting it and re-syncing recovers every unspent note, because every
/// note's plaintext is on chain inside its ciphertext.
pub const STORE_VERSION: u32 = 5;

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
    /// `chain_getBlockHash(0)` of the chain this store was built against, hex,
    /// no `0x`.
    ///
    /// An address binds the store to a seed and says nothing about which chain
    /// the leaf indices, the block numbers, the checkpoint hashes and the
    /// spent flags in it came from. A `--dev --tmp` node restarts on a fresh
    /// genesis with an empty tree, and against one of those every one of those
    /// values is wrong in a way no later sync repairs: the watermark sits
    /// above the new chain's leaf count so the scan range is empty, the
    /// checkpoint hashes belong to a chain that never existed here, and the
    /// settled set is somebody else's, so notes read spent or unspent at
    /// random.
    ///
    /// `None` in a store written before version 5, and in one that has never
    /// synced. The first sync against a node records that node's genesis, and
    /// every sync after it refuses a node that answers a different one. The
    /// escape is `--new-chain-store`, which archives the file rather than
    /// deleting it: the note secrets in it are the only copy this wallet has.
    #[serde(default)]
    pub genesis_hash: Option<String>,
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
    ///
    /// In memory only. `Wallet::sync` overwrites it wholesale from the chain
    /// before either of its two readers runs, the scan's `nullifier_settled`
    /// check and [`WalletStore::reconcile_spent`], and no other command reads
    /// it at all, so a persisted copy never produced a cache hit. What it did
    /// do is grow the file with the whole chain's activity instead of this
    /// wallet's, at about sixty-eight bytes an entry in pretty-printed JSON,
    /// and a single `send` writes the store three times.
    #[serde(skip)]
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
            // Public chain data: it is the hash of block zero.
            .field("genesis_hash", &self.genesis_hash)
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

/// What `on_chain` reads as in a store written before the field existed.
///
/// A version-3 store could not mark a note off chain at all, so every note in
/// one is on the chain as far as that version could tell.
fn on_chain_default() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredNote {
    pub leaf_index: u64,
    pub block_number: Option<u32>,
    /// Pool quanta.
    pub value: u64,
    pub commitment: String,
    /// Redacted in `Debug` and zeroized on drop, like `rho` and `r` beside it,
    /// and on a stronger argument than either: for a note that has not been
    /// spent this value has never appeared anywhere, so whoever reads a core
    /// dump or a swap page later can watch the chain and attribute the
    /// settlement that publishes it to this wallet with certainty.
    pub nullifier: SecretHex,
    pub rho: SecretHex,
    pub r: SecretHex,
    #[serde(default)]
    pub memo: String,
    pub origin: NoteOrigin,
    pub spent: bool,
    /// Whether the chain still carries this note's commitment.
    ///
    /// False for exactly the notes a fork rescan walked past without finding:
    /// their settlement was orphaned and has not been re-included, so the
    /// chain does not back their value. Such a note stays in the store,
    /// because its secrets are the only copy this wallet has and a later block
    /// can still re-include the extrinsic, and it stays out of
    /// [`WalletStore::unspent`], because `unspent_total`, `select_notes` and
    /// the `balance` table have to agree with the chain. A rescan that finds
    /// the commitment again puts it back
    /// ([`WalletStore::relocate_note`]).
    #[serde(default = "on_chain_default")]
    pub on_chain: bool,
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
            .field("on_chain", &self.on_chain)
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
    /// Redacted and zeroized for the reason [`StoredNote::nullifier`] is: one
    /// of the two refusals that produce a `RejectedNote` is a nullifier that
    /// duplicates a note this wallet still holds and still intends to spend.
    pub nullifier: SecretHex,
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

/// Which way a [`WalletStore::reconcile_spent`] pass may move a flag.
///
/// The two directions are not symmetric and never were: setting a flag takes a
/// nullifier the node carries, and clearing one takes a nullifier it does not,
/// which is only evidence when the node has been proved to be at or ahead of
/// everything the wallet has read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentDirection {
    /// Set and clear. What an ordinary sync runs, behind the node gates that
    /// make the absence of a nullifier mean something.
    BothWays,
    /// Set only. What `--rescan` runs, because it may have bypassed those
    /// gates.
    AddOnly,
}

/// What one pass of [`WalletStore::reconcile_spent`] changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpentReconciliation {
    /// Notes whose nullifier the refreshed set carries and which were not
    /// marked spent.
    pub newly_spent: u64,
    /// Notes whose nullifier left the set, at a head that has passed the
    /// height the spend was seen at: the settlement was orphaned.
    pub newly_unspent: u64,
    /// Notes whose nullifier is absent from the set and which were left spent
    /// anyway: the head has not reached the height the spend was seen at, or
    /// the pass ran [`SpentDirection::AddOnly`]. In both cases the absence is
    /// this node's view falling short of the wallet's, and an orphaned
    /// settlement is what it is not.
    pub held_spent: u64,
}

/// One row of the `balance` note table.
///
/// A conflict set is one row, because it is one value: at most one of its
/// members can ever settle, so listing each member as its own line reports a
/// balance the chain will never back. See [`WalletStore::spendable`].
#[derive(Debug, Clone, Copy)]
pub struct NoteRow<'a> {
    /// The member this row stands for: the one a spend would use.
    pub note: &'a StoredNote,
    /// How many held notes share this row's nullifier, this one included. One
    /// for an ordinary note, more for a conflict set.
    pub members: usize,
}

impl NoteRow<'_> {
    pub fn is_conflict(&self) -> bool {
        self.members > 1
    }
}

/// Which member of a conflict set a spend uses: the largest value, ties broken
/// by the lowest leaf index.
///
/// Ties are broken so the choice is deterministic. Two members of equal value
/// are otherwise ordered by however the store was written, and a wallet that
/// picked differently on a retry would prove a different leaf.
fn outranks(candidate: &StoredNote, held: &StoredNote) -> bool {
    (candidate.value, core::cmp::Reverse(candidate.leaf_index))
        > (held.value, core::cmp::Reverse(held.leaf_index))
}

/// The same order, for the table, where spent and off-chain members are in the
/// running too.
///
/// A member a spend could use wins over one it could not, so the value the
/// table prints is the value the balance counts.
fn outranks_for_display(candidate: &StoredNote, held: &StoredNote) -> bool {
    let usable = |note: &StoredNote| !note.spent && note.on_chain;
    match (usable(candidate), usable(held)) {
        (true, false) => true,
        (false, true) => false,
        _ => outranks(candidate, held),
    }
}

/// Collapse a note list to one row per nullifier, keeping the order the notes
/// were first met in.
fn collapse<'a>(notes: impl Iterator<Item = &'a StoredNote>) -> Vec<NoteRow<'a>> {
    let mut order: Vec<&'a str> = Vec::new();
    let mut groups: BTreeMap<&'a str, NoteRow<'a>> = BTreeMap::new();
    for note in notes {
        match groups.entry(note.nullifier.as_str()) {
            Entry::Vacant(slot) => {
                order.push(note.nullifier.as_str());
                slot.insert(NoteRow { note, members: 1 });
            }
            Entry::Occupied(mut slot) => {
                let row = slot.get_mut();
                row.members += 1;
                if outranks_for_display(note, row.note) {
                    row.note = note;
                }
            }
        }
    }
    order
        .into_iter()
        .map(|nullifier| groups[nullifier])
        .collect()
}

/// Write one note off the chain, and the one place that decides a note may be
/// written off at all.
///
/// A spent note is skipped: its value is gone whether or not its leaf is still
/// there, so the marker would buy nothing, and `off_chain` reads the pair of
/// flags as a claim the chain can still honour. A note already off chain is
/// skipped so the counts a sync reports are what that sync changed.
fn mark_off_chain(note: &mut StoredNote) -> bool {
    if note.spent || !note.on_chain {
        return false;
    }
    note.on_chain = false;
    true
}

/// Distinguishes the temporary files of two saves in one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl WalletStore {
    pub fn new(address: String) -> Self {
        Self {
            version: STORE_VERSION,
            address,
            genesis_hash: None,
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
            //
            // Version 3 to 4 adds `on_chain`, which serde defaults to true for
            // every note already in the file, and drops `used_nullifiers` from
            // the format: the field is `#[serde(skip)]` now, so a version-3
            // file's copy is ignored on load and the first sync repages it.
            //
            // Version 4 to 5 adds `genesis_hash`, which serde reads as `None`.
            // The first sync that commits records the genesis of the node it
            // runs against, which is the only chain such a store could have
            // come from that this wallet can still name.
            //
            // What no upgrade recovers is a note an older build refused as a
            // duplicate nullifier. That build wrote a `rejected` entry and
            // never kept the note's `rho` and `r`, and the leaf sits below the
            // watermark from then on, so no later sync decrypts it again. The
            // secrets are not in the file to restore. They are on chain,
            // inside the ciphertext beside the commitment, so `sync --rescan`
            // walks the tree from leaf zero and picks them up; the notes
            // already held are kept either way. `docs/WALLET.md` says so under
            // the store format.
            if store.version < 3 {
                store.checkpoints.clear();
            }
            store.version = STORE_VERSION;
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

    /// Whether this store was built against a chain other than this one.
    ///
    /// A store with no genesis recorded belongs to no chain yet and is not
    /// "other".
    pub fn is_other_chain(&self, genesis: &str) -> bool {
        self.genesis_hash
            .as_deref()
            .is_some_and(|bound| bound != genesis)
    }

    /// Bind this store to a chain, refusing one it does not belong to.
    ///
    /// Returns whether the genesis was newly recorded.
    ///
    /// The address check above binds the store to a seed. This binds it to a
    /// chain, and nothing else does: leaf indices, block numbers, checkpoint
    /// hashes and spent flags are all statements about one chain, and a
    /// `--dev --tmp` node that restarted answers a fresh genesis with an empty
    /// tree. Against one of those the watermark sits above the new leaf count,
    /// so the scan range is empty and the wallet reports the notes it holds as
    /// a balance the chain has never heard of, while the checkpoint hashes
    /// name blocks that do not exist and the settled set is somebody else's.
    ///
    /// Nothing is written when the answer is a refusal, so a wallet pointed at
    /// the wrong node by a typed URL leaves the file it holds untouched.
    pub fn bind_genesis(&mut self, genesis: &str) -> Result<bool> {
        self.ensure_genesis(genesis)?;
        if self.genesis_hash.is_some() {
            return Ok(false);
        }
        self.genesis_hash = Some(genesis.to_string());
        Ok(true)
    }

    /// Refuse a chain this store does not belong to, recording nothing.
    ///
    /// What a command that only reads the store calls, where
    /// [`WalletStore::bind_genesis`] is what a sync calls.
    pub fn ensure_genesis(&self, genesis: &str) -> Result<()> {
        if let Some(bound) = self.genesis_hash.as_deref() {
            if bound != genesis {
                bail!(
                    "this store was built against the chain whose genesis is {bound} and this \
                     node serves the chain whose genesis is {genesis}. Every leaf index, block \
                     number, checkpoint hash and spent flag in the store is a statement about \
                     the first chain and means nothing on the second, so syncing would report a \
                     balance this chain has never carried. A --dev --tmp node that restarted is \
                     the usual cause. Pass --new-chain-store to archive this store and start a \
                     fresh one against this chain; the archive keeps the note secrets, which are \
                     the only copy of them."
                );
            }
        }
        Ok(())
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

    /// Notes this wallet can spend: not settled, and still on the chain.
    ///
    /// The second half is what a fork rescan writes down. A note whose
    /// settlement was orphaned and never re-included is not backed by the
    /// chain, so counting it in `unspent_total` reports value that does not
    /// exist, and `select_notes` picks largest first, so a phantom larger than
    /// every real note also makes every subsequent `send` fail on the path
    /// rebuild. [`WalletStore::off_chain`] is where those notes are listed
    /// instead.
    pub fn unspent(&self) -> impl Iterator<Item = &StoredNote> {
        self.notes
            .iter()
            .filter(|note| !note.spent && note.on_chain)
    }

    /// Notes a fork rescan proved the chain no longer carries, and whose
    /// value is still theirs to lose.
    ///
    /// A settled nullifier is the end of a note whatever became of its leaf,
    /// so a spent note is never off chain in the sense this heading means. The
    /// two flags meet on a conflict set: `mark_vanished` writes `on_chain`
    /// only over an unspent note, and one member of a set settling marks every
    /// member spent, so a set with an off-chain member ends up carrying both
    /// flags. Without the spent filter `balance` then printed that member's
    /// value under "not on the current chain", saying a sync that meets the
    /// commitment again puts it back, while the table above it printed the
    /// same value once, as `spent`. The chain refuses a nullifier it has
    /// settled, so nothing puts it back.
    pub fn off_chain(&self) -> impl Iterator<Item = &StoredNote> {
        self.notes
            .iter()
            .filter(|note| !note.on_chain && !note.spent)
    }

    /// One spendable note per nullifier: a conflict set collapses to the
    /// member a spend would use.
    ///
    /// A sender picks `rho` and `r` for a note it creates
    /// (`docs/CIRCUIT.md` section 9.8), so a sender that repeats a pair hands
    /// over two notes sharing one nullifier. At most one of them can ever
    /// settle, because the chain refuses a nullifier it has already seen, and
    /// the recipient cannot tell in advance which one a settlement will
    /// consume: it is whichever one the recipient itself spends first.
    ///
    /// The regression this closes: the scan used to refuse the second note it
    /// met, permanently and by arrival order. A sender that put the large note
    /// second had the wallet keep the small one and write the large one off
    /// with no way back, and a rescan after a fork walked the same leaves and
    /// refused the same one again. Both notes are held now, and the choice is
    /// made here, on value, where it can be remade on every command.
    ///
    /// The two members can never be spent together either, and that is the
    /// other half of why this collapses: a private batch constrains all its
    /// nullifiers pairwise distinct (`docs/CIRCUIT.md` section 8), so a
    /// selection that put both members in one leaf would fail in circuit.
    pub fn spendable(&self) -> Vec<&StoredNote> {
        let mut best: BTreeMap<&str, &StoredNote> = BTreeMap::new();
        for note in self.unspent() {
            match best.entry(note.nullifier.as_str()) {
                Entry::Vacant(slot) => {
                    slot.insert(note);
                }
                Entry::Occupied(mut slot) => {
                    if outranks(note, slot.get()) {
                        slot.insert(note);
                    }
                }
            }
        }
        best.into_values().collect()
    }

    /// Held notes that share their nullifier with another held note.
    ///
    /// What `balance` counts to say how much of the wallet is in conflict
    /// sets. Every member is listed, the chosen one included.
    ///
    /// Keyed on borrowed nullifiers, like [`WalletStore::spendable`]. The
    /// duplicate check a scan used to run built a fresh owned set per received
    /// note, and every one of those copies dropped without being wiped, so a
    /// scan that received `k` notes left `k` unwiped copies of every held
    /// nullifier on the heap. That is the one value `SecretHex` and the
    /// `Debug` redactions exist for.
    pub fn conflicted(&self) -> Vec<&StoredNote> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for note in &self.notes {
            *counts.entry(note.nullifier.as_str()).or_default() += 1;
        }
        self.notes
            .iter()
            .filter(|note| counts[note.nullifier.as_str()] > 1)
            .collect()
    }

    /// The note list as `balance` prints it: one row per nullifier.
    pub fn rows(&self) -> Vec<NoteRow<'_>> {
        collapse(self.notes.iter())
    }

    /// The same, over the notes the chain no longer carries.
    pub fn off_chain_rows(&self) -> Vec<NoteRow<'_>> {
        collapse(self.off_chain())
    }

    pub fn unspent_total(&self) -> u64 {
        self.spendable().iter().map(|note| note.value).sum()
    }

    /// Value the chain does not back, held for the case its settlement
    /// re-lands.
    ///
    /// Collapsed on the nullifier, exactly as [`WalletStore::off_chain_rows`]
    /// is, so the heading `balance` prints is the sum of the table under it.
    /// Summing every member instead counted a conflict set once per note: at
    /// most one member of a set can ever settle, so a set of two off-chain
    /// notes of 692 quanta reported 1,384 above a table showing one row of
    /// 692, which is the same overcount `unspent_total` collapses to avoid.
    pub fn off_chain_total(&self) -> u64 {
        self.off_chain_rows().iter().map(|row| row.note.value).sum()
    }

    /// Mark every note inside a rescanned range that the rescan did not find.
    /// Returns how many changed.
    ///
    /// `seen` is the set of commitments the rescan walked, so a note above
    /// `from` whose commitment is not in it is one the current chain does not
    /// carry.
    ///
    /// A note the settled set says is spent is skipped, and the caller has to
    /// run [`WalletStore::reconcile_spent`] before this so that flag is the
    /// one derived from the set the sync just repaged. A spent note's value is
    /// gone whether or not its leaf is still there, so the marker would buy
    /// nothing; a note whose settlement was orphaned in the same reorg that
    /// took its leaf is exactly the case this has to catch, and it only reads
    /// as unspent once the reconciliation has run.
    pub fn mark_vanished(&mut self, from: u64, seen: &BTreeSet<String>) -> u64 {
        let mut marked = 0;
        for note in self.notes.iter_mut() {
            if note.leaf_index >= from && !seen.contains(&note.commitment) {
                marked += u64::from(mark_off_chain(note));
            }
        }
        marked
    }

    /// Mark one held note off chain by its commitment, the way
    /// [`WalletStore::mark_vanished`] marks a whole rescanned range.
    ///
    /// The second caller is the path rebuild a spend runs: a selected note
    /// whose leaf index is past the end of a tree whose root the anchor
    /// header confirms, recorded at a block that anchor has executed, is a
    /// note this chain does not carry, and reporting that as a same-block race
    /// left `send` advising a retry that can never succeed. One rule, one
    /// field, so a note written off by either route comes back by the one
    /// route that puts it back, [`WalletStore::relocate_note`].
    ///
    /// Returns whether this changed anything.
    pub fn mark_note_off_chain(&mut self, commitment: &str) -> bool {
        let mut marked = false;
        for note in self.notes.iter_mut() {
            if note.commitment == commitment {
                marked |= mark_off_chain(note);
            }
        }
        marked
    }

    pub fn pending_total(&self) -> u64 {
        self.pending.iter().map(|note| note.value).sum()
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
    /// Seeing the commitment at all is also what puts a note the previous
    /// rescan wrote off back into the balance: `on_chain` is set here, whether
    /// or not the leaf moved, because the chain is carrying the commitment
    /// again.
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
            note.on_chain = true;
            if note.leaf_index != leaf_index || note.block_number != block_number {
                note.leaf_index = leaf_index;
                note.block_number = block_number;
                moved = true;
            }
        }
        moved
    }

    /// Record a decryptable output this wallet refused, once per commitment.
    ///
    /// Returns whether this is a refusal the store had not already recorded.
    ///
    /// A refused note is never added to `notes`, so `has_commitment` does not
    /// see it and a rescan of the same range decrypts it, refuses it and
    /// reaches this line again. Before the fork rewind a leaf was never
    /// scanned twice; with it, every fork touching that range used to append
    /// another identical entry, and `balance` prints one line per entry, so an
    /// operator reading that list to answer "why is the payment someone says
    /// they sent not in my balance?" saw N refusals where the chain carried
    /// one output.
    pub fn record_rejected(&mut self, rejected: RejectedNote) -> bool {
        if let Some(existing) = self
            .rejected
            .iter_mut()
            .find(|entry| entry.commitment == rejected.commitment)
        {
            // The leaf a refused output sits at is provisional in exactly the
            // way a held note's is, and for the same reason, so the newest
            // position wins. `relocate_note` does this for notes the wallet
            // kept.
            existing.leaf_index = rejected.leaf_index;
            return false;
        }
        self.rejected.push(rejected);
        true
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
            if note.nullifier.as_str() == nullifier && !note.spent {
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
            if note.nullifier.as_str() == nullifier && note.spent {
                note.spent = false;
                note.spent_seen_at_block = None;
            }
        }
    }

    /// Re-derive every note's spent flag from the settled set.
    ///
    /// The regression this closed: `spent` was a latch. A sync replaced the
    /// local copy of `UsedNullifiers` wholesale on every pass, so the store
    /// always held the chain's current answer, and then only ever set the flag
    /// true. When the block carrying a settlement was orphaned and the
    /// settlement did not re-land, because the unsigned extrinsic left the
    /// pool after five blocks or its anchor fell outside the window, the
    /// nullifier was permanently absent from the map and the note stayed
    /// spent forever: under-reported in the balance, passed over by every
    /// selection, and recoverable only by deleting the store.
    ///
    /// Clearing the flag is the direction that can lose money, so it carries a
    /// condition the setting direction does not: `head_block` has to have
    /// reached the height the spend was seen at. A nullifier is absent from a
    /// node's map for two different reasons, and they are indistinguishable
    /// from the map alone. Either the settlement was orphaned, which is what
    /// this exists for, or the node has not reached the block that settled it.
    /// `Wallet::sync` refuses outright a node behind this wallet's own
    /// watermark, and this covers what that gate cannot see: a spend
    /// `submit_spend` latched at an inclusion block above the watermark, which
    /// is every spend made since the last sync. Un-spending such a note puts
    /// it back in the balance and lets the next `send` select an input the
    /// chain has already consumed, which is a submission refused after the
    /// full proving cost.
    ///
    /// A note marked spent with no height recorded is cleared, because there
    /// is nothing to compare against. Only a store written before the field
    /// carried meaning holds one.
    ///
    /// Safe against the latch above because this runs inside `Wallet::sync`,
    /// immediately after the set is repaged from the chain. A head that still
    /// contains the inclusion block re-derives exactly what `submit_spend`
    /// latched; a head that no longer contains it is the case this exists for.
    ///
    /// [`SpentDirection::AddOnly`] is the other half of the argument, and it
    /// is what `--rescan` passes. That override drops the gates whose whole
    /// job is to prove this node's settled set is not shorter than the
    /// wallet's own knowledge, so under it the absence of a nullifier is no
    /// evidence at all and clearing on it would un-spend notes the chain has
    /// consumed.
    pub fn reconcile_spent(
        &mut self,
        head_block: u32,
        direction: SpentDirection,
    ) -> SpentReconciliation {
        // Taken out and put back so the notes can be walked mutably against
        // it. The set is the authority here, and it was read at `head_block`.
        let settled = core::mem::take(&mut self.used_nullifiers);
        let mut counts = SpentReconciliation::default();
        for note in self.notes.iter_mut() {
            match (settled.contains(note.nullifier.as_str()), note.spent) {
                (true, false) => {
                    note.spent = true;
                    note.spent_seen_at_block = Some(head_block);
                    counts.newly_spent += 1;
                }
                (false, true) => {
                    // A note marked spent with no height recorded has nothing
                    // to compare against, so only a store written before the
                    // field carried meaning reaches the `None` arm.
                    let above_this_head = match note.spent_seen_at_block {
                        Some(seen) => head_block < seen,
                        None => false,
                    };
                    if direction == SpentDirection::AddOnly || above_this_head {
                        counts.held_spent += 1;
                    } else {
                        note.spent = false;
                        note.spent_seen_at_block = None;
                        counts.newly_unspent += 1;
                    }
                }
                _ => {}
            }
        }
        self.used_nullifiers = settled;
        counts
    }

    /// Drop every refusal for an output this wallet now holds.
    ///
    /// Returns how many went.
    ///
    /// A `RejectedNote` records an output that decrypted to this wallet and
    /// could not be kept. The one refusal left is a nullifier the chain has
    /// already settled, and that is a statement about a chain state that a
    /// reorg can undo: the settlement is orphaned, the rescan walks the same
    /// leaf, the nullifier is no longer settled and the note is held. Without
    /// this the refusal stayed in the file and `balance` went on printing
    /// "its nullifier is already settled on chain" beside the note it had just
    /// added to the balance.
    pub fn prune_rejected(&mut self) -> u64 {
        let held: BTreeSet<&str> = self
            .notes
            .iter()
            .map(|note| note.commitment.as_str())
            .collect();
        let before = self.rejected.len();
        // Collected first: `retain` cannot borrow `self.notes` while it holds
        // `self.rejected` mutably.
        let drop: BTreeSet<String> = self
            .rejected
            .iter()
            .filter(|entry| held.contains(entry.commitment.as_str()))
            .map(|entry| entry.commitment.clone())
            .collect();
        self.rejected
            .retain(|entry| !drop.contains(&entry.commitment));
        (before - self.rejected.len()) as u64
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
            nullifier: Digest::hash_bytes(&[b"nf", tag.as_bytes()]).to_hex().into(),
            rho: rho.to_hex().into(),
            r: r.to_hex().into(),
            memo: "a memo".into(),
            origin: NoteOrigin::Shield,
            spent: false,
            spent_seen_at_block: None,
            on_chain: true,
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
            nullifier: "cc".repeat(32).into(),
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
        assert!(loaded.notes[0].on_chain);

        // `used_nullifiers` is an in-memory working set. Every reader runs
        // inside the sync that just repaged it from the chain, so persisting
        // it never produced a cache hit; what it did produce was a file that
        // grew with the whole chain's settled spends, at about sixty-eight
        // bytes an entry in pretty-printed JSON, rewritten three times by a
        // single `send`.
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("used_nullifiers"),
            "the settled set is on disk again: {text}"
        );
        assert!(!text.contains(&"dd".repeat(32)), "{text}");
        assert!(loaded.used_nullifiers.is_empty());
        assert!(!loaded.nullifier_settled(&"dd".repeat(32)));
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
            !printed.contains(note.nullifier.as_str()),
            "the nullifier leaked: {printed}"
        );
        assert!(printed.contains(&note.commitment));
        assert!(printed.contains(REDACTED));

        let rejected = RejectedNote {
            leaf_index: 4,
            commitment: "bb".repeat(32),
            nullifier: "cc".repeat(32).into(),
            value: 5,
            reason: "duplicate nullifier".into(),
        };
        let printed = format!("{rejected:?}");
        assert!(
            !printed.contains(rejected.nullifier.as_str()),
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
        let first = store.notes[0].nullifier.as_str().to_string();

        store.used_nullifiers.insert(first.clone());
        assert_eq!(
            store.reconcile_spent(42, SpentDirection::BothWays),
            SpentReconciliation {
                newly_spent: 1,
                ..Default::default()
            }
        );
        assert_eq!(store.unspent_total(), 400);
        assert_eq!(store.notes[0].spent_seen_at_block, Some(42));

        // Idempotent: the same set at a later head changes nothing.
        assert_eq!(
            store.reconcile_spent(43, SpentDirection::BothWays),
            SpentReconciliation::default()
        );
        assert_eq!(store.notes[0].spent_seen_at_block, Some(42));

        // The settlement is orphaned out and does not re-land.
        store.used_nullifiers.remove(&first);
        assert_eq!(
            store.reconcile_spent(44, SpentDirection::BothWays),
            SpentReconciliation {
                newly_unspent: 1,
                ..Default::default()
            }
        );
        assert_eq!(store.unspent_total(), 1_400);
        assert!(!store.notes[0].spent);
        assert_eq!(store.notes[0].spent_seen_at_block, None);

        store.mark_unspent(&first);
        assert_eq!(store.unspent_total(), 1_400);
    }

    /// The regression the rule above opened, and the constraint that closes
    /// it: a nullifier absent from a node's map has two causes and the map
    /// alone cannot tell them apart.
    ///
    /// Either the settlement was orphaned, which is what the both-directions
    /// rule exists for, or the node has not reached the block that settled it.
    /// `submit_spend` latches a spend at its inclusion block, which is above
    /// the wallet's own watermark until the next sync, so this is every spend
    /// made since the last one: a sync against a node one block behind that
    /// inclusion put the input note back in the balance, and the next `send`
    /// selected an input the chain had already consumed and paid a full proof
    /// to have the settlement refused.
    ///
    /// Clearing the flag is the direction that can lose money, so it is the
    /// direction that carries the condition. Setting it stays as it was.
    #[test]
    fn a_spend_is_only_unspent_once_the_node_has_passed_the_block_it_settled_at() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        let nullifier = store.notes[0].nullifier.as_str().to_string();

        // The spend settles at block 30 and `submit_spend` latches it there.
        store.mark_spent(&nullifier, 30);
        assert_eq!(store.unspent_total(), 0);

        // A sync against a node whose head is block 29. Its map does not carry
        // the nullifier, because it has not executed the block that settled
        // it.
        assert_eq!(
            store.reconcile_spent(29, SpentDirection::BothWays),
            SpentReconciliation {
                held_spent: 1,
                ..Default::default()
            }
        );
        assert!(
            store.notes[0].spent,
            "a lagging node cannot un-spend a note"
        );
        assert_eq!(store.notes[0].spent_seen_at_block, Some(30));
        assert_eq!(store.unspent_total(), 0);

        // The same node at the settling block itself, still without the
        // nullifier: now the absence is the chain's own answer at a height it
        // has reached, so the settlement was orphaned.
        assert_eq!(
            store.reconcile_spent(30, SpentDirection::BothWays),
            SpentReconciliation {
                newly_unspent: 1,
                ..Default::default()
            }
        );
        assert!(!store.notes[0].spent);
        assert_eq!(store.unspent_total(), 1_000);

        // A note marked spent by a store written before the height meant
        // anything is cleared: there is nothing to compare against.
        store.notes[0].spent = true;
        store.notes[0].spent_seen_at_block = None;
        assert_eq!(
            store.reconcile_spent(1, SpentDirection::BothWays),
            SpentReconciliation {
                newly_unspent: 1,
                ..Default::default()
            }
        );
        assert!(!store.notes[0].spent);
    }

    /// The regression: a note the fork rescan proved is no longer on the chain
    /// stayed in `unspent()`.
    ///
    /// `unspent_total` and the `balance` table then reported value the chain
    /// does not back, permanently and with no marker in the store, and
    /// `select_notes` picks largest first, so a phantom larger than every real
    /// note also made every subsequent `send` fail on the path rebuild with no
    /// remedy but editing the JSON by hand.
    #[test]
    fn a_note_the_chain_no_longer_carries_leaves_the_unspent_total() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "held"));
        store.notes.push(sample_note(692, "orphaned"));
        store.notes[0].leaf_index = 5;
        store.notes[1].leaf_index = 6;
        let orphaned = store.notes[1].commitment.clone();
        assert_eq!(store.unspent_total(), 1_692);

        // The rescan walked leaves 6 and up and found the first commitment
        // again and not the second.
        let seen: BTreeSet<String> = [store.notes[0].commitment.clone()].into_iter().collect();
        assert_eq!(store.mark_vanished(6, &seen), 1);
        assert!(!store.notes[1].on_chain);
        assert_eq!(
            store.unspent_total(),
            1_000,
            "the balance has to be what the chain backs"
        );
        assert_eq!(store.off_chain_total(), 692);
        assert_eq!(store.off_chain().count(), 1);
        // Still held, because its secrets are the only copy and the extrinsic
        // can still be re-included.
        assert_eq!(store.notes.len(), 2);
        // Idempotent: a second rescan that finds it no better marks nothing
        // new.
        assert_eq!(store.mark_vanished(6, &seen), 0);
        // And a note below the rescanned range is untouched, whatever the
        // rescan saw: the leaves below the rewind point were folded at or
        // before a block that is still canonical.
        assert_eq!(store.mark_vanished(9, &BTreeSet::new()), 0);
        assert!(store.notes[0].on_chain);

        // The settlement re-lands and the scan sees the commitment again.
        assert!(store.relocate_note(&orphaned, 8, Some(14)));
        assert!(store.notes[1].on_chain);
        assert_eq!(store.unspent_total(), 1_692);
        assert_eq!(store.off_chain_total(), 0);

        // Even at the leaf it already held: seeing the commitment at all is
        // the chain carrying it.
        assert_eq!(store.mark_vanished(6, &BTreeSet::new()), 1);
        assert!(!store.relocate_note(&orphaned, 8, Some(14)));
        assert!(store.notes[1].on_chain);
    }

    /// The regression: a fork rescan walked a refused leaf again and appended
    /// a second identical `RejectedNote`.
    ///
    /// A refused note is never added to `notes`, so `has_commitment` does not
    /// see it and the rescan decrypts it, refuses it and reaches the push
    /// again. Each fork touching that range added another copy, and `balance`
    /// prints one line per copy, so an operator reading that list to answer
    /// "why is the payment someone says they sent not in my balance?" saw N
    /// refusals where the chain carried one output.
    #[test]
    fn a_refusal_is_recorded_once_per_commitment() {
        let mut store = WalletStore::new("qn1example".into());
        let refusal = |leaf_index: u64| RejectedNote {
            leaf_index,
            commitment: "bb".repeat(32),
            nullifier: "cc".repeat(32).into(),
            value: 7,
            reason: "its nullifier duplicates a note this wallet already holds".into(),
        };

        assert!(store.record_rejected(refusal(6)));
        assert_eq!(store.rejected.len(), 1);
        // The same output, walked again by the rescan a fork triggered.
        assert!(!store.record_rejected(refusal(6)));
        assert!(!store.record_rejected(refusal(6)));
        assert_eq!(store.rejected.len(), 1);
        // The chain moved it, the way it moves a held note's leaf. The entry
        // follows rather than doubling.
        assert!(!store.record_rejected(refusal(4)));
        assert_eq!(store.rejected.len(), 1);
        assert_eq!(store.rejected[0].leaf_index, 4);

        // A different output is a different refusal.
        let mut other = refusal(9);
        other.commitment = "dd".repeat(32);
        assert!(store.record_rejected(other));
        assert_eq!(store.rejected.len(), 2);
    }

    /// The regression: `off_chain_total` summed every member of a conflict set
    /// while `off_chain_rows` collapsed them, so the `balance` heading and the
    /// table under it disagreed on a number they both compute from the same
    /// notes.
    ///
    /// At most one member of a set can ever settle, so the heading counted
    /// value the chain could never back even if every one of those settlements
    /// re-landed. `unspent_total` collapses for exactly this reason; the
    /// off-chain total is the same sum over the same grouping.
    #[test]
    fn the_off_chain_heading_is_the_sum_of_the_off_chain_table() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(40, "small"));
        store.notes.push(sample_note(1_000, "large"));
        store.notes.push(sample_note(250, "apart"));
        // The first two share a nullifier: one sender, one repeated (rho, r).
        let shared = store.notes[1].nullifier.clone();
        store.notes[0].nullifier = shared.as_str().into();
        store.notes[0].leaf_index = 4;
        store.notes[1].leaf_index = 5;
        store.notes[2].leaf_index = 6;

        // A reorg took the whole set's leaves and left the note that shares
        // nothing where it was.
        store.notes[0].on_chain = false;
        store.notes[1].on_chain = false;

        let rows = store.off_chain_rows();
        assert_eq!(rows.len(), 1, "a conflict set is one row");
        assert_eq!(rows[0].members, 2);
        assert_eq!(rows[0].note.value, 1_000);
        assert_eq!(
            store.off_chain_total(),
            rows.iter().map(|row| row.note.value).sum::<u64>(),
            "the heading has to be the sum of the table under it"
        );
        assert_eq!(store.off_chain_total(), 1_000, "and not 1,040");
        assert_eq!(store.unspent_total(), 250);
    }

    /// The regression: `off_chain` had no spent filter, so a settled member of
    /// a conflict set was counted under the `balance` heading that says the
    /// chain does not back these notes and a sync that finds the commitment
    /// again puts them back. Neither half was true of it.
    ///
    /// The two flags meet on a conflict set and only there. `mark_vanished`
    /// writes `on_chain` over an unspent note alone, and one member of a set
    /// settling marks every member spent, because they share the nullifier.
    /// The table above the heading prints such a note once, as `spent`, so the
    /// heading contradicted the table it sums.
    #[test]
    fn a_settled_note_is_not_an_orphan_whatever_became_of_its_leaf() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(400, "vanished twin"));
        store.notes.push(sample_note(400, "settled twin"));
        let shared = store.notes[1].nullifier.clone();
        store.notes[0].nullifier = shared.as_str().into();
        store.notes[0].leaf_index = 4;
        store.notes[1].leaf_index = 5;

        // The reorg took the first member's leaf. Both are unspent, so it is
        // an orphan and the heading is the sum of the table under it.
        let seen: BTreeSet<String> = [store.notes[1].commitment.clone()].into_iter().collect();
        assert_eq!(store.mark_vanished(4, &seen), 1);
        assert_eq!(store.off_chain().count(), 1);
        assert_eq!(store.off_chain_total(), 400);

        // Then the member that is still on the chain settles, which settles
        // the nullifier both of them carry.
        store.used_nullifiers.insert(shared.as_str().to_string());
        let counts = store.reconcile_spent(30, SpentDirection::BothWays);
        assert_eq!(counts.newly_spent, 2);
        assert_eq!(store.unspent_total(), 0);
        assert_eq!(
            store.off_chain().count(),
            0,
            "the chain refuses a nullifier it has settled, so nothing puts this note back"
        );
        assert_eq!(store.off_chain_total(), 0);
        assert_eq!(
            store.off_chain_rows().len(),
            0,
            "the heading and the table have to agree, and both are empty"
        );

        // And the marking itself never writes over a spent note, so the two
        // flags cannot be made to disagree from this side either.
        assert_eq!(store.mark_vanished(0, &BTreeSet::new()), 0);
        assert!(!store.mark_note_off_chain(&store.notes[1].commitment.clone()));
    }

    /// The regression: `--rescan` walked past the node gate and then ran a
    /// reconciliation that reads a missing nullifier as an orphaned
    /// settlement. Against the node an operator reaches for a rescan on, that
    /// un-spends every note the node has not executed the settlement for, and
    /// the next `send` pays a full proof to have its segment skipped.
    #[test]
    fn an_add_only_pass_sets_spent_flags_and_clears_none() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "already settled"));
        store.notes.push(sample_note(250, "settling now"));
        store.notes[0].spent = true;
        store.notes[0].spent_seen_at_block = Some(12);
        store.used_nullifiers = [store.notes[1].nullifier.as_str().to_string()]
            .into_iter()
            .collect();

        // A head far above the block the first spend was latched at, so the
        // height guard on the clearing direction has nothing to say: only the
        // direction itself holds the flag.
        let counts = store.reconcile_spent(99, SpentDirection::AddOnly);
        assert_eq!(
            counts.newly_spent, 1,
            "a nullifier the node carries still counts"
        );
        assert_eq!(counts.newly_unspent, 0);
        assert_eq!(counts.held_spent, 1);
        assert!(store.notes[0].spent);
        assert_eq!(store.notes[0].spent_seen_at_block, Some(12));
        assert!(store.notes[1].spent);
        assert_eq!(store.unspent_total(), 0);

        // The ordinary direction, on the same store and the same set, is what
        // clears it.
        let counts = store.reconcile_spent(99, SpentDirection::BothWays);
        assert_eq!(counts.newly_unspent, 1);
        assert!(!store.notes[0].spent);
        assert_eq!(store.unspent_total(), 1_000);
    }

    /// The regression: the scan refused whichever member of a conflict set it
    /// met second, permanently, so a sender who put the large note second had
    /// the wallet keep the small one with no way back.
    ///
    /// Both are held now and the choice is made here, on value, where it can
    /// be remade on every command. Ties break on the leaf index so a retry
    /// proves the same leaf.
    #[test]
    fn a_conflict_set_is_one_candidate_at_its_largest_member() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(40, "small"));
        store.notes.push(sample_note(1_000, "large"));
        store.notes.push(sample_note(250, "apart"));
        // The first two share a nullifier: one sender, one repeated (rho, r).
        let shared = store.notes[1].nullifier.clone();
        store.notes[0].nullifier = shared.as_str().into();
        store.notes[0].leaf_index = 4;
        store.notes[1].leaf_index = 5;
        store.notes[2].leaf_index = 6;

        let spendable = store.spendable();
        assert_eq!(spendable.len(), 2, "a conflict set is one candidate");
        assert!(spendable.iter().any(|note| note.value == 1_000));
        assert!(spendable.iter().any(|note| note.value == 250));
        assert_eq!(
            store.unspent_total(),
            1_250,
            "the set counts once, at the value a spend would use"
        );
        assert_eq!(store.conflicted().len(), 2);

        // One row per nullifier, in the order the notes were met, carrying the
        // member a spend would use.
        let rows = store.rows();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_conflict());
        assert_eq!(rows[0].members, 2);
        assert_eq!(rows[0].note.value, 1_000);
        assert!(!rows[1].is_conflict());
        assert_eq!(rows[1].note.value, 250);

        // Two members of equal value break the tie on the leaf index, so a
        // retry proves the same leaf.
        store.notes[0].value = 1_000;
        assert_eq!(
            store
                .spendable()
                .iter()
                .find(|note| note.value == 1_000)
                .expect("the set is still a candidate")
                .leaf_index,
            4
        );

        // One member settling takes the whole set out of the balance, because
        // the nullifier is one value.
        store.used_nullifiers.insert(shared.as_str().to_string());
        assert_eq!(
            store.reconcile_spent(30, SpentDirection::BothWays),
            SpentReconciliation {
                newly_spent: 2,
                ..Default::default()
            }
        );
        assert_eq!(store.unspent_total(), 250);
    }

    /// The regression: a refusal outlived the reason for it.
    ///
    /// The one refusal left is a nullifier the chain has already settled, and
    /// a reorg can undo that. The rescan then holds the note and `balance`
    /// printed "its nullifier is already settled on chain" beside a note it
    /// had just added to the balance.
    #[test]
    fn a_refusal_goes_when_the_same_output_is_held() {
        let mut store = WalletStore::new("qn1example".into());
        store.notes.push(sample_note(1_000, "one"));
        let held = store.notes[0].commitment.clone();
        store.rejected.push(RejectedNote {
            leaf_index: 3,
            commitment: held,
            nullifier: "cc".repeat(32).into(),
            value: 1_000,
            reason: "its nullifier is already settled on chain".into(),
        });
        store.rejected.push(RejectedNote {
            leaf_index: 4,
            commitment: "bb".repeat(32),
            nullifier: "dd".repeat(32).into(),
            value: 7,
            reason: "its nullifier is already settled on chain".into(),
        });

        assert_eq!(store.prune_rejected(), 1);
        assert_eq!(store.rejected.len(), 1);
        assert_eq!(store.rejected[0].leaf_index, 4);
        // Idempotent.
        assert_eq!(store.prune_rejected(), 0);
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

    /// An older store upgrades in place: it holds every note secret, and the
    /// two fields the newer versions add both have a defined reading for a
    /// file written before they existed.
    #[test]
    fn an_older_store_upgrades_rather_than_being_refused() {
        let dir = std::env::temp_dir().join(format!("qnero-store-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("old.store.json");
        let _ = fs::remove_file(&path);

        let write_as = |version: u32| {
            let mut store = WalletStore::new("qn1example".into());
            store.notes.push(sample_note(1_000, "one"));
            store.record_checkpoint(9, "ab".repeat(32), 4);
            store.genesis_hash = Some("cd".repeat(32));
            store.save(&path).unwrap();
            let text = fs::read_to_string(&path).unwrap();
            let mut text = text.replace(
                &format!("\"version\": {STORE_VERSION}"),
                &format!("\"version\": {version}"),
            );
            if version < 5 {
                // A file written by a version that had no such field.
                text = text.replace(
                    &format!("  \"genesis_hash\": \"{}\",\n", "cd".repeat(32)),
                    "",
                );
            }
            if version < 4 {
                text = text.replace("      \"on_chain\": true\n", "");
                text = text.replace(",\n      \"on_chain\": true", "");
            }
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        };

        // Version 4 to 5. `genesis_hash` is absent, so the store belongs to no
        // chain this wallet can name and the first sync against a node records
        // that node's. Nothing else can be recovered: the version that wrote
        // the file never asked which chain it was on.
        write_as(4);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("genesis_hash"), "{text}");
        let mut loaded = WalletStore::load_or_new(&path, "qn1example").expect("it upgrades");
        assert_eq!(loaded.version, STORE_VERSION);
        assert_eq!(loaded.genesis_hash, None);
        assert_eq!(loaded.unspent_total(), 1_000);
        assert!(
            loaded.bind_genesis(&"ef".repeat(32)).expect("it records"),
            "a store with no chain takes the first one it is synced against"
        );
        assert_eq!(
            loaded.genesis_hash.as_deref(),
            Some("ef".repeat(32).as_str())
        );
        // And from then on it is bound.
        assert!(!loaded
            .bind_genesis(&"ef".repeat(32))
            .expect("the same chain"));
        assert!(loaded.bind_genesis(&"ab".repeat(32)).is_err());

        // Version 3 to 5. `on_chain` is absent from the file, and every note
        // in a version-3 store is on the chain as far as that version could
        // tell: it had no way to mark one otherwise.
        write_as(3);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("on_chain"), "{text}");
        let loaded = WalletStore::load_or_new(&path, "qn1example").expect("it upgrades");
        assert_eq!(loaded.version, STORE_VERSION);
        assert_eq!(loaded.unspent_total(), 1_000);
        assert!(loaded.notes[0].on_chain);
        // The checkpoints a version-3 store carries are still good: its block
        // hashes came from the same chain.
        assert_eq!(loaded.checkpoints.len(), 1);

        // Version 2 to 5. `checkpoints` did not exist, so whatever is in the
        // file is dropped: the first sync after the upgrade records one and
        // has nothing older to compare against.
        write_as(2);
        let loaded = WalletStore::load_or_new(&path, "qn1example").expect("it upgrades");
        assert_eq!(loaded.version, STORE_VERSION);
        assert_eq!(loaded.unspent_total(), 1_000);
        assert!(loaded.notes[0].on_chain);
        assert!(loaded.checkpoints.is_empty());

        write_as(1);
        assert!(WalletStore::load_or_new(&path, "qn1example").is_err());
        fs::remove_file(&path).unwrap();
    }
}
