//! The wallet's operations: scan, shield, spend.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::merkle::{MerklePath, TreeFrontier};
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{
    decrypt_note, encrypt_note, entry_rho, try_receive_coinbase, Address, Digest, MinerKey, Note,
    NoteCiphertext, ReceivedNote,
};
use qnero_notes::{IncomingViewingKey, SpendingKey};
use qnero_prover::WalletProver;
use rand::{Rng, TryRngCore};

use crate::chain::{withheld_key, Chain, ChainHead};
use crate::extrinsic::{
    encode_shield_call, encode_signed, encode_submit_private_batch, ShieldedOutput, SigningContext,
};
use crate::fee::{
    ensure_ciphertext_fits, ensure_memo_pad_fits, slot_fee_floor, submission_fee_floor,
};
use crate::keys::store_path_for;
use crate::memo::{pad_memo, unpad_memo};
use crate::metadata::ChainMetadata;
use crate::rpc::hex_0x;
use crate::select::select_notes;
use crate::store::{
    self, NoteOrigin, PendingKind, PendingNote, RejectedNote, SecretHex, SpentDirection,
    StoredNote, WalletStore,
};
use crate::typing::{
    check_chunk_appended_nothing, seed_frontier, type_chunk, LeafKind, MinerView, TypedLeaf,
};
use crate::units::qnr;
use crate::POOL_STEP;

/// Leaf slots in a private batch. Not a metadata value and not discoverable
/// over RPC.
///
/// `chain/pallets/shielded/build.rs` resolves it as
/// `QNERO_NUM_LEAF_PROOFS`, falling back to
/// `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS`, so the wallet resolves it
/// the same way: one environment produces one `N` on both sides. Reading only
/// the default would leave a wallet at six against a runtime someone built at
/// eight, and the chain's embedded verifier would refuse the proof's
/// public-input length after the full proving cost had been paid, with no
/// local check to catch it first.
pub const NUM_LEAF_PROOFS: usize = match option_env!("QNERO_NUM_LEAF_PROOFS") {
    Some(text) => parse_leaf_proofs(text),
    None => qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS,
};

/// `str::parse` is not const, and this has to be one so the constant stays a
/// constant.
const fn parse_leaf_proofs(text: &str) -> usize {
    let bytes = text.as_bytes();
    assert!(
        !bytes.is_empty(),
        "QNERO_NUM_LEAF_PROOFS is set to an empty string"
    );
    let mut value = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit >= b'0' && digit <= b'9',
            "QNERO_NUM_LEAF_PROOFS must be a decimal number"
        );
        value = value * 10 + (digit - b'0') as usize;
        index += 1;
    }
    assert!(value > 0, "QNERO_NUM_LEAF_PROOFS must be at least one");
    value
}

/// How far above the floor a caller's own fee may go before it is refused.
///
/// The pool gives every settlement submission the same constant priority
/// (`pallet_shielded::UNSIGNED_SETTLEMENT_PRIORITY`), deliberately, so a fee
/// above the floor buys nothing at all: half of it burns and the block author
/// takes the rest. A fee an order of magnitude over is therefore a typing, and
/// the one that is easy to type is a count of pool steps where QNR is wanted,
/// which is a hundredfold overpay that `preflight` would otherwise wave
/// through with nothing on screen to compare it against.
const FEE_CEILING_MULTIPLE: u64 = 10;

/// Whether a caller's own fee is so far over the floor that it reads as a
/// typing rather than an intention.
///
/// The floor is clamped to one step before it is multiplied, so a runtime that
/// declared `MinLeafFee` as zero on a slot carrying no ciphertext still has a
/// ceiling rather than refusing every fee above nothing.
fn fee_runs_away(fee: u64, floor: u64) -> bool {
    fee > floor.max(1).saturating_mul(FEE_CEILING_MULTIPLE)
}

/// What [`Wallet::preflight`] settled before any circuit was built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preflight {
    /// The fee this spend will carry, in pool steps.
    pub fee: u64,
    /// The floor it had to clear. The same as `fee` unless a caller asked for
    /// more, so printing the two together is what makes an overpay visible.
    pub floor: u64,
}

/// Where an input note's Merkle path comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MerkleSource {
    /// Rebuild the tree locally from `ZkTree::Leaves` at the anchor block.
    ///
    /// The default, and the private one. `Chain::leaves` already reads the
    /// whole leaf range during a scan, and that read says nothing about which
    /// leaves matter to the reader.
    #[default]
    Local,
    /// Ask the node for `zkTree_getMerkleProof(leaf_index)`, one call per
    /// input.
    ///
    /// Cheaper, and it tells the node exactly which leaves this wallet is
    /// about to spend, seconds before the settlement that publishes their
    /// nullifiers arrives on the same connection.
    Rpc,
}

/// Block intervals a submission is waited on: the pool's five, plus the one it
/// was submitted inside.
///
/// An unsigned settlement has `longevity(5)`: it leaves the pool after five
/// blocks and a byte-identical rebroadcast will not displace it, so the answer
/// to a timeout is to prove again against a fresh anchor. Five blocks is the
/// window in which the submission is still live and will almost certainly
/// settle, so the wait is denominated in blocks and read from the chain. A flat
/// 120 s was one block interval at the public target: the residual wait to the
/// next block is exponential with a mean of one interval, so roughly a third of
/// correct payments would have been reported as failures.
const INCLUSION_TIMEOUT_BLOCKS: u64 = 6;

/// The shortest inclusion wait, whatever the chain's interval.
///
/// Six 12 s blocks is 72 seconds, which is shorter than a single proof on one
/// thread, so a fast dev chain keeps the old flat wait.
const INCLUSION_TIMEOUT_FLOOR: Duration = Duration::from_secs(120);

/// [`INCLUSION_TIMEOUT_BLOCKS`] of the chain's own interval, floored.
///
/// The interval is read here, because one node binary serves a 120 s public
/// chain and a 12 s dev chain and no constant covers both. A node that
/// cannot answer gets the floor: this is called after the bytes are already in
/// the pool, so refusing the whole send over a failed constant read would throw
/// away a payment that is on its way.
fn inclusion_timeout(chain: &Chain) -> Duration {
    match chain.target_block_time_ms() {
        Ok(ms) => Duration::from_millis(ms.saturating_mul(INCLUSION_TIMEOUT_BLOCKS))
            .max(INCLUSION_TIMEOUT_FLOOR),
        Err(_) => INCLUSION_TIMEOUT_FLOOR,
    }
}

/// How many shield entries the origin walk hashes before it gives up.
///
/// `Shielded::EntryCount` is a `u64` the node answers with, and
/// [`entry_rho_matches`] runs one Poseidon2 hash per unit of it for every
/// non-coinbase note a scan receives. Unbounded, a single storage answer
/// decides how long the sync runs. The bound is affordable because the answer
/// is a label: `origin` separates a shield from a spend's output in the
/// listing and no rule selects on it. `wallet-web` holds the same bound in
/// `src/worker/protocol.ts`.
pub const ENTRY_WALK_LIMIT: u64 = 100_000;

/// How many blocks one chunk of the header walk carries.
///
/// The head is a number the node answers with, and the walk fetches, rehashes
/// and holds one header per block between the trusted anchor and it. Unbounded,
/// a node claiming a head billions of blocks ahead decided both how much this
/// wallet allocates and how long it runs. So the range is climbed in chunks:
/// each is fetched by the hash its child names down to the block below it,
/// every header rehashed, the chunk's leaf runs folded and checked against the
/// roots its headers carry, and a checkpoint recorded at its top before the
/// next chunk is read. A chain far ahead of the checkpoint therefore syncs in
/// one command, with the headers resident bounded by this number rather than
/// by the distance.
///
/// 1024 blocks is about 140 KiB of `VerifiedBlock` and 1024 `chain_getHeader`
/// round trips, which is one page of work either way. `docs/BENCH.md` carries
/// the per-block cost and this size. `wallet-web` holds the same bound in
/// `src/wallet/sync.ts`.
///
/// A block count, deliberately: what it bounds is memory and round trips per
/// chunk, and neither is a duration. At the public chain's 120 s target the
/// chunk covers 34 hours of chain where at 12 s it covered 3.4, so a wallet
/// opened daily now catches up inside one chunk.
pub const HEADER_WALK_LIMIT: u32 = 1024;

/// Block headers a pipelined walk gets through in a second, measured.
///
/// It is here to answer one question out loud: how long a wallet with no
/// birthday is going to take to read a chain from block zero. A number nobody
/// quotes is a progress bar somebody watches for an hour, which is what this
/// round started from.
///
/// Measured against the live testnet through its CDN, which is the slow case
/// and the honest one: a dev node on loopback answers far faster and would
/// quote an estimate nobody on a real chain will see. `docs/BENCH.md` carries
/// the runs, and `wallet-web/src/wallet/sync.ts` carries the same number for
/// the browser.
pub const MEASURED_HEADERS_PER_SECOND: u32 = 400;

/// How long a full scan of `blocks` blocks takes at the measured rate, in
/// whole seconds, rounded up and never zero.
pub fn full_scan_seconds(blocks: u32) -> u32 {
    blocks.div_ceil(MEASURED_HEADERS_PER_SECOND.max(1)).max(1)
}

/// The sentence a wallet about to read a chain whole prints.
///
/// A constant rather than an inline format string, because the browser wallet
/// prints it too and `wallet-web/tests/leaf-typing.test.ts` reads this literal
/// out of this file to hold the two identical. Two wallets quoting two
/// different waits for one chain is two operators told different things about
/// the same thing.
pub const FULL_SCAN_ESTIMATE: &str =
    "this wallet records no birthday, so the first sync reads the chain from block zero: \
     {blocks} block headers, {spell} at the rate this build measured, and the leaves under them \
     on top of that";

/// That estimate as a sentence, for a wallet about to read a chain whole.
pub fn full_scan_estimate(blocks: u32) -> String {
    let seconds = full_scan_seconds(blocks);
    let spell = |count: u32, unit: &str| -> String {
        if count == 1 {
            format!("about one {unit}")
        } else {
            format!("about {count} {unit}s")
        }
    };
    let spell = if seconds < 90 {
        spell(seconds, "second")
    } else if seconds < 5400 {
        spell(seconds.div_ceil(60), "minute")
    } else {
        spell(seconds.div_ceil(3600), "hour")
    };
    FULL_SCAN_ESTIMATE
        .replace("{blocks}", &blocks.to_string())
        .replace("{spell}", &spell)
}

/// How many per-leaf detector warnings one pass writes out in full.
///
/// The detector in the scan writes one sentence per leaf whose ciphertext this
/// wallet's key opens beside a commitment that note does not open, and how
/// many of those a pass meets is a node's choice: it can answer a mismatching
/// commitment at every leaf it serves. Uncapped that is one sentence per leaf
/// held in memory and printed, out of an answer nobody has checked. Past the
/// cap the pass counts instead and says how many, so the two summaries below
/// bound the list at eighteen entries whatever a node answers.
///
/// Eight, because the list is read by a person: it is enough entries to see
/// the pattern, and the count after them is what says the size. `wallet-web`
/// holds the same bound in `src/wallet/sync.ts`.
pub const WARNED_LEAVES_PER_PASS: u64 = 8;

/// "leaf" or "leaves", for a count that is written into a sentence.
fn leaves_word(count: u64) -> &'static str {
    if count == 1 {
        "leaf"
    } else {
        "leaves"
    }
}

/// One leaf whose opened note the same block holds at another index.
///
/// The payment arrives, at the index inside the block that holds the
/// commitment the note opens, and the sentence carries both indices because
/// the one this node answered at is the thing a second node would disagree
/// about. `wallet-web/src/wallet/sync.ts` writes the same sentence.
fn moved_leaf_warning(leaf: u64, block_number: u32, index: u64) -> String {
    format!(
        "leaf {leaf} carries a ciphertext this wallet's own key opens, and the tree entry \
         answered beside it is one that payment does not open. Block {block_number} holds the \
         opened payment's entry at leaf {index}, inside the range this pass folded against \
         that block's own header, so the payment is recorded at leaf {index} and it arrives. A \
         ciphertext that opens under this wallet's key is this wallet's payment, so the pair \
         was moved. Which index inside a block holds which entry is bound by nothing on chain: \
         sync against a second node before spending it."
    )
}

/// One leaf whose opened note its own block holds nowhere.
///
/// Skipped and said out loud, because a sender who encrypts a payload opening
/// a commitment it never published produces the identical reading and nothing
/// local tells the two apart. `wallet-web/src/wallet/sync.ts` writes the same
/// sentence.
fn unplaceable_leaf_warning(leaf: u64, block_number: u32) -> String {
    format!(
        "leaf {leaf} carries a ciphertext this wallet's own key opens, and block {block_number} \
         holds the tree entry it opens at none of the leaves it appended. The leaf is skipped \
         and the pass continues, because a sender who encrypts a payload opening a tree entry it \
         never published produces the same reading and nothing here tells the two apart. If a \
         payment is missing, sync against a second node."
    )
}

/// What the cap held back for moved leaves, carried as a count.
///
/// The sentence per leaf stops at [`WARNED_LEAVES_PER_PASS`] and this says how
/// many more there were, so a node that mismatches at every leaf costs one
/// closing sentence for the whole pass. `wallet-web/src/wallet/sync.ts` writes
/// the same sentence.
fn moved_overflow_warning(more: u64) -> String {
    format!(
        "and {more} more {} in this pass carried a ciphertext this wallet's own key \
         opens beside a tree entry that payment does not open, each recorded at the \
         index inside its own block that holds the entry it opens. Sync against \
         a second node before spending them.",
        leaves_word(more)
    )
}

/// What the cap held back for unplaceable leaves, carried as a count.
///
/// `wallet-web/src/wallet/sync.ts` writes the same sentence.
fn unplaceable_overflow_warning(more: u64) -> String {
    format!(
        "and {more} more {} in this pass carried a ciphertext this wallet's own key \
         opens whose tree entry their own block holds nowhere, each skipped. If a \
         payment is missing, sync against a second node.",
        leaves_word(more)
    )
}

pub struct Wallet {
    pub seed_path: PathBuf,
    pub store_path: PathBuf,
    key: SpendingKey,
    pub store: WalletStore,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wallet")
            .field("seed_path", &self.seed_path)
            .field("address", &self.store.address)
            .finish()
    }
}

impl Wallet {
    pub fn open(seed_path: &Path) -> Result<Self> {
        let key = crate::keys::load_seed(seed_path)?;
        let address = key.address().encode();
        let store_path = store_path_for(seed_path);
        let store = WalletStore::load_or_new(&store_path, &address)?;
        Ok(Self {
            seed_path: seed_path.to_path_buf(),
            store_path,
            key,
            store,
        })
    }

    /// Open a wallet and check its store against the chain this node serves.
    ///
    /// A store is bound to a seed by its address and to a chain by its
    /// genesis, and it needs both. Leaf indices, block numbers, checkpoint
    /// hashes and spent flags are all statements about one chain; a
    /// `--dev --tmp` node that restarted answers a fresh genesis with an empty
    /// tree, and against one of those the watermark sits above the new leaf
    /// count, so the scan range is empty and the wallet keeps reporting a
    /// balance nothing backs while every checkpoint names a block that does
    /// not exist.
    ///
    /// Opening checks the binding and never writes it. The binding is recorded
    /// by the save that commits a successful sync, shield or send, and that
    /// ordering is the whole of it: a store with no genesis yet is bound by
    /// whichever node it is first pointed at, so recording it here bound a
    /// fresh store to a node whose very next gate refused it. A wallet opened
    /// against a node that turns out to be behind, or serving a chain whose
    /// storage layout has drifted, would have been left naming that chain
    /// permanently, and every later sync against the right node would then
    /// refuse with a mismatch the operator never chose.
    ///
    /// `new_chain_store` is the escape. It archives the store beside itself
    /// rather than deleting it, because the note secrets in it are the only
    /// copy this wallet has of the `rho` and `r` that open its notes, and a
    /// chain that looks gone can come back: the operator may simply have typed
    /// the wrong `--node`.
    pub fn open_on_chain(
        seed_path: &Path,
        chain: &Chain,
        new_chain_store: bool,
    ) -> Result<(Self, ChainBinding)> {
        let mut wallet = Self::open(seed_path)?;
        let genesis = hex::encode(chain.genesis_hash()?);
        if new_chain_store && wallet.store.is_other_chain(&genesis) {
            // The rename is the only thing this writes. The fresh store takes
            // its genesis from the first operation that commits, like any
            // other fresh store.
            let archived = archive_store(&wallet.store_path)?;
            wallet.store = WalletStore::new(wallet.key.address().encode());
            return Ok((wallet, ChainBinding::Archived(archived)));
        }
        wallet
            .store
            .ensure_genesis(&genesis)
            .with_context(|| format!("{}", wallet.store_path.display()))?;
        let binding = if wallet.store.genesis_hash.is_some() {
            ChainBinding::Bound
        } else {
            ChainBinding::Unrecorded
        };
        Ok((wallet, binding))
    }

    pub fn address(&self) -> Address {
        self.key.address()
    }

    pub fn ivk(&self) -> IncomingViewingKey {
        self.key.incoming_viewing_key()
    }

    /// What a block author's node is configured with: this wallet's `pk` and
    /// its coinbase viewing key, and nothing that can spend. See
    /// `qnero_note_core::miner` for what holding it lets someone do.
    pub fn miner_key(&self) -> MinerKey {
        self.key.miner_key()
    }

    pub fn save(&self) -> Result<()> {
        self.store.save(&self.store_path)
    }

    /// Record where this wallet starts, and bind the store to this chain.
    ///
    /// `height` is the operator's restore height, or `None` for a wallet being
    /// created now, which starts at the node's own head. Either way it is
    /// rounded **down** to a multiple of [`store::BIRTHDAY_EPOCH`] before it is
    /// recorded, so what the store holds and what every later node is told is a
    /// coarse public epoch rather than the moment this wallet was made.
    ///
    /// Three reads, all public: the head, the hash of the epoch block, and the
    /// leaf count that block's state carried. The leaf count is the watermark,
    /// and it is checked on the first sync: the fold of the leaves under it has
    /// to reach the `zkTreeRoot` the epoch block's own header published.
    ///
    /// The genesis binding is written here as well, because this is an
    /// operation that commits: a birthday is a statement about one chain, and a
    /// store carrying one that named no chain would take its binding from
    /// whichever node it was pointed at next.
    ///
    /// A height above the node's head is refused by name. Everything else is
    /// the operator's claim and is taken: `docs/WALLET.md` says what a wrong
    /// one costs.
    pub fn record_birthday(
        &mut self,
        chain: &Chain,
        height: Option<u32>,
    ) -> Result<store::SyncCheckpoint> {
        let genesis = hex::encode(chain.genesis_hash()?);
        self.store
            .ensure_genesis(&genesis)
            .with_context(|| format!("{}", self.store_path.display()))?;
        let head = chain.head()?;
        let wanted = height.unwrap_or(head.number);
        if wanted > head.number {
            bail!(
                "this node's head is block {} and the height given is {wanted}, which names a \
                 block nobody has yet. A birthday above the chain's own head would put this \
                 wallet's watermark past every leaf there is. Nothing has been changed.",
                head.number
            );
        }
        let block_number = store::birthday_epoch_of(wanted);
        let block_hash = chain.block_hash(block_number)?;
        let next_leaf = chain.leaf_count_at(&block_hash)?;
        let checkpoint = store::SyncCheckpoint {
            block_number,
            block_hash: hex::encode(block_hash),
            next_leaf,
        };
        self.store.record_birthday(checkpoint.clone())?;
        self.store.genesis_hash = Some(genesis);
        self.save()?;
        Ok(checkpoint)
    }

    /// Scan from the last synced leaf to the tree's current count.
    ///
    /// Every read is pinned to one block hash, so a leaf appended mid-scan
    /// cannot be counted and then read as absent.
    ///
    /// The metadata is taken because the storage layout every key here is
    /// built from is checked against the runtime's own declaration first. On
    /// the read path a drifted key is silent: it reads as an empty map, and an
    /// empty map is a zero balance or a settled note reported unspent.
    pub fn sync(&mut self, chain: &Chain, metadata: &ChainMetadata) -> Result<SyncReport> {
        self.sync_with(chain, metadata, SyncOptions::default())
    }

    /// The same scan, with the operator's overrides.
    ///
    /// The only override is [`SyncOptions::rescan`], which drops the watermark
    /// and walks the whole tree again while keeping every note, and which is
    /// also the way past a node gate that has nothing to compare against. It
    /// buys that with reduced guarantees, and the order of the rules is what
    /// bounds them:
    ///
    /// 1. The chain gate runs first and `--rescan` never bypasses it. Leaf
    ///    indices, checkpoint hashes and spent flags are statements about one
    ///    chain, and a walk from leaf zero over a different chain's tree is
    ///    not a recovery of anything.
    /// 2. The checkpoint walk runs next. Without `--rescan` its refusal is
    ///    final. With it, a refusal is reported and bypassed: the checkpoints
    ///    it could not stand on are dropped, and the watermark and
    ///    `last_synced_block` go back to zero, since a rescan that trusts the
    ///    node less than the store must not keep the store's claims either.
    /// 3. The scan then runs **add only**. Every rule that would take
    ///    something away rests on this node's answers being at least as new as
    ///    the wallet's own knowledge, which is exactly what rule 2 may have
    ///    stopped checking. So a nullifier the node carries still marks a note
    ///    spent, a nullifier it does not carry clears nothing,
    ///    `mark_vanished` does not run, and a commitment met again still moves
    ///    its note and puts it back on chain. The report says so, and so does
    ///    the CLI.
    /// 4. The leaf-count gate stays exactly as it is for an ordinary sync.
    ///    Under `--rescan` it cannot fire, because the watermark it compares
    ///    against is zero.
    pub fn sync_with(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        options: SyncOptions,
    ) -> Result<SyncReport> {
        metadata.ensure_known_storage()?;
        // The chain this store belongs to, before anything in it is read as a
        // statement about the chain this node serves. Checked here and
        // recorded at the end, in the save that commits this sync: see
        // `Wallet::open_on_chain`.
        let genesis_hash = chain.genesis_hash()?;
        let genesis = hex::encode(genesis_hash);
        self.store
            .ensure_genesis(&genesis)
            .with_context(|| format!("{}", self.store_path.display()))?;

        let head = chain.head()?;
        // The node gates, and they come before every other read and every
        // write.
        //
        // Everything this sync derives is derived from what one node answers
        // at one block: which leaves exist, which nullifiers are settled,
        // which checkpoint hashes still stand. A node behind this wallet
        // answers all three with less than the wallet already knows, and each
        // answer is then read as a change when it is only a gap. The settled
        // set is the expensive one: `reconcile_spent` derives spent in both
        // directions, so a lagging node un-spends every note whose settlement
        // it has not seen and the next `send` selects an input the chain has
        // already consumed.
        //
        // Nothing is mutated until both gates have passed, so a refusal leaves
        // the store exactly as it found it, in memory and on disk.
        //
        // `--rescan` is the operator's override on the second gate, and only
        // on the second. A node that is behind, or that cannot answer for a
        // height this wallet checkpointed, is refused because the store has
        // nothing left to compare it against, and that is exactly the state an
        // operator reaches for a rescan in: a wallet whose branch is gone, or
        // whose checkpoints name blocks no node still serves. The refusal is
        // reported, the checkpoints behind it are dropped with the watermark,
        // and everything the sync would derive from the node being current is
        // switched off below.
        let (stance, bypassed_refusal) = match self.read_node_stance(chain, &head) {
            Ok(stance) => (stance, None),
            Err(refusal) if options.rescan => {
                // Inert: the rescan branch of `apply_stance` ignores the
                // stance and rewinds to leaf zero whatever it says.
                (NodeStance::Current, Some(format!("{refusal:#}")))
            }
            Err(refusal) => return Err(refusal),
        };
        let leaf_count = chain.leaf_count_at(&head.hash)?;
        // The leaf watermark, which is the gate the block heights and the
        // checkpoint hashes between them cannot see.
        //
        // A node can be on this wallet's chain, at a head above every
        // checkpoint, and still carry fewer leaves than the wallet has already
        // scanned: `ZkTree::LeafCount` at its head is a statement about the
        // state it has executed, and a node that answers a head it has not
        // finished executing answers a short tree. The scan range
        // `start..leaf_count` is then empty, so the whole scan is skipped, and
        // `mark_vanished` with it, while `self.store.next_leaf = leaf_count`
        // at the end walks the watermark backwards and leaves the store
        // claiming to have scanned less than it has.
        //
        // A fork does not reach here. The rewind above takes the watermark
        // back to a checkpoint whose hash still stands on this node's own
        // branch, so that block is the same block on both branches and its
        // tree held at least that many leaves there too; a tree only grows
        // along one chain, so the node's head carries at least the watermark.
        // A count below it is lag, and lag is refused. The watermark never
        // regresses outside the fork path.
        //
        // The gate is the ordinary sync's, and `--rescan` skips it by
        // construction: a rescan starts at leaf zero, no count is below zero,
        // so the comparison below can never fire. There is no exemption in it
        // for the override to take, which is why a rescan against a short tree
        // contradicts nothing here. What the gate protects, the watermark and
        // the checks that read backwards from it, a rescan gives up
        // explicitly and says so.
        let watermark = if options.rescan {
            0
        } else {
            stance.watermark(self.store.next_leaf)
        };
        if let Some(refusal) =
            short_tree_refusal(leaf_count, watermark, head.number, SYNC_SHORT_TREE)
        {
            return Err(refusal);
        }

        // Both gates have passed. From here the store is written.
        let rewind = self.apply_stance(stance, options);
        // The settled nullifier set, read whole and pinned to the same block.
        //
        // Spent status used to be a question asked of the node about this
        // wallet's own nullifiers, one key at a time. `UsedNullifiers` is
        // `Blake2_128Concat`, so those keys carried the raw nullifiers in the
        // clear, and a node that logged them learned the set of values this
        // wallet would publish when it spent, before any of them existed on
        // chain. Reading the public map whole and deciding locally asks the
        // same question and names nothing.
        self.store.used_nullifiers = chain.used_nullifiers_at(&head.hash)?;
        let start = self.store.next_leaf;
        let mut report = SyncReport {
            head_block: head.number,
            scanned_from: start,
            scanned_to: leaf_count,
            rewound_from: rewind.as_ref().map(|rewind| rewind.from),
            rewound_to: rewind.as_ref().map(|rewind| rewind.to),
            forked_at_block: rewind.as_ref().and_then(|rewind| rewind.forked_at),
            add_only: options.rescan,
            bypassed_refusal,
            ..Default::default()
        };

        // Whether this pass is allowed to take anything away. A rescan is not:
        // see the rules on `sync_with`. The two things it switches off are the
        // orphan marking below and the clearing half of the spent
        // reconciliation, and both are switched off for one reason, that the
        // node gate which makes a missing leaf or a missing nullifier mean
        // something may have been bypassed above.
        let reconciles = !options.rescan;

        // Commitments this wallet already holds that the scan saw again. Only
        // collected when the orphan marking will read them, which is after a
        // fork rewind: that is the only time a held leaf is inside the range
        // at all, and it is what tells a note that moved apart from a note
        // whose block was orphaned and never re-included.
        let mut seen_again: BTreeSet<String> = BTreeSet::new();

        // The trusted bottom of the header walk, resolved on every pass and
        // not only on one with leaves to scan.
        //
        // The walk stands on a block hash this wallet already trusts: the
        // genesis it is bound to when the scan starts at leaf zero, and
        // otherwise the checkpoint an earlier pass recorded at the watermark,
        // whose hash `read_node_stance` has just confirmed still stands on
        // this node's own branch. From there every header up to the head is
        // fetched by the hash its child names and rehashed from its own
        // preimage, so the `zkTreeRoot` each block published and the author
        // label in its digest are authenticated by the same recomputation.
        // See `crate::typing`.
        let (anchor_block, anchor_hash) = if start == 0 {
            (0u32, genesis_hash)
        } else {
            let checkpoint = self
                .store
                .newest_checkpoint()
                .filter(|checkpoint| checkpoint.next_leaf == start)
                .cloned()
                .ok_or_else(|| {
                    anyhow!(
                        "this store has read {start} leaves and carries no checkpoint that ends \
                         on them, so there is no block hash this wallet already trusts for the \
                         header walk to stand on. A store written before checkpoints existed is \
                         the one shape that reaches this. Run `sync --rescan`, which starts the \
                         walk at the genesis this store is bound to and keeps every note. \
                         Nothing has been changed."
                    )
                })?;
            let bytes = hex::decode(&checkpoint.block_hash)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                .ok_or_else(|| {
                    anyhow!(
                        "the checkpoint at block {} carries a block hash that is not 32 bytes of \
                         hex",
                        checkpoint.block_number
                    )
                })?;
            (checkpoint.block_number, bytes)
        };

        let ivk = self.ivk();
        let nk = self.key.nk();
        let miner_key = self.key.miner_key();
        let miner = MinerView {
            key: &miner_key,
            genesis_hash: &genesis_hash,
        };
        // Read once, outside the loop. The entry counter is chain wide and the
        // whole scan is pinned to one block, so it is the same value for every
        // leaf; asking per received note was one round trip each for a field
        // that is only a label.
        let entry_count = chain.entry_count_at(&head.hash)?;
        // Said out loud when the walk cannot cover the counter. The bound is
        // what keeps one storage answer from deciding how long this scan runs;
        // what it costs is a label, and a label nobody is told about is a label
        // an operator reads as a fact.
        if entry_count > ENTRY_WALK_LIMIT {
            report.entry_walk_truncated = Some(entry_count);
        }

        // The walk, climbed in chunks of at most `HEADER_WALK_LIMIT` blocks.
        //
        // The head is a number this node answers with, so a single walk over
        // the whole distance let one answer decide how much this wallet
        // allocates. Each chunk is fetched downward by `parentHash` from its
        // own top to the block below its bottom, every header rehashed, the
        // leaves the node dates into it folded and checked against the roots
        // those headers carry, and its top then becomes the bottom the next
        // chunk is authenticated against. Only the top of the last chunk is
        // the head itself, so every chunk below it learns its top's hash from
        // `chain_getBlockHash` and then proves it by walking down to a hash
        // already trusted.
        //
        // Checkpoints are collected here and written with the watermark at the
        // end of the pass, so the store never carries a checkpoint for a range
        // whose scan was refused.
        let mut checkpoints: Vec<(u32, String, u64)> = Vec::new();
        let mut frontier: Option<TreeFrontier> = None;
        let mut cursor_leaf = start;
        let mut trusted_block = anchor_block;
        let mut trusted_hash = anchor_hash;
        // The two detector counts of this pass, which are what the per-leaf
        // warnings are capped against. See [`WARNED_LEAVES_PER_PASS`].
        let mut moved_leaves: u64 = 0;
        let mut unplaceable_leaves: u64 = 0;
        loop {
            let top = trusted_block
                .saturating_add(HEADER_WALK_LIMIT)
                .min(head.number);
            let top_hash = if top == head.number {
                head.hash
            } else {
                chain.block_hash(top)?
            };
            let blocks = chain.header_chain(
                &ChainHead {
                    number: top,
                    hash: top_hash,
                },
                trusted_block,
            )?;
            let anchor = blocks
                .first()
                .ok_or_else(|| anyhow!("the header walk returned no blocks"))?;
            if anchor.hash != trusted_hash {
                bail!(
                    "the header walk reached block {trusted_block} at {}, and this wallet trusts \
                     {} there. Every header above it is authenticated by chaining down to this \
                     one, so a walk that lands somewhere else authenticates nothing. Nothing has \
                     been changed.",
                    hex::encode(anchor.hash),
                    hex::encode(trusted_hash)
                );
            }

            if leaf_count > start {
                if frontier.is_none() {
                    // The leaves below the watermark, which the walk's bottom
                    // block is what checks. Read at one key per leaf, which is
                    // the same wide read a spend already makes to rebuild its
                    // paths, and read once for the whole pass: the fold climbs
                    // with the chunks.
                    let prefix = chain.leaf_hashes(0..start, leaf_count, &head.hash)?;
                    frontier = Some(seed_frontier(anchor, start, &prefix)?);
                }
                let fold = frontier
                    .as_mut()
                    .ok_or_else(|| anyhow!("the leaf fold was not seeded"))?;
                let records = chain.leaves_up_to_block(cursor_leaf, leaf_count, top, &head.hash)?;
                // A gap in what the node answered, which the chain never
                // leaves. Every leaf below the count this pass read at this
                // same block hash was appended by one of `pallet-shielded`'s
                // three writers, and each writes `ZkTree::Leaves` and
                // `Shielded::LeafBlocks` in the call that appends the leaf.
                // Nothing removes either, so an absent answer below the count
                // is one this node withheld, and stepping over it is silent
                // and permanent: the leaf would be counted as scanned,
                // `next_leaf` and a checkpoint would be written above it, and
                // every later sync starts above it. The pass is refused
                // instead, before anything is saved. `Chain::leaf_window`
                // refuses the same pair one layer down, and `wallet-web`
                // refuses it in `chain/reads.ts` and again in `runSync`.
                //
                // The third key, `Shielded::Ciphertexts`, is not a flat
                // requirement: whether a leaf owes one is decided by where the
                // headers put it, in `crate::typing`, which is also what
                // refuses an invented `Shielded::CoinbaseValues` and what
                // requires one at every coinbase position.
                for record in &records {
                    if record.commitment.is_none() {
                        return Err(withheld_key(
                            record.index,
                            leaf_count,
                            &head.hash,
                            "ZkTree::Leaves",
                        ));
                    }
                    if record.block_number.is_none() {
                        return Err(withheld_key(
                            record.index,
                            leaf_count,
                            &head.hash,
                            "Shielded::LeafBlocks",
                        ));
                    }
                }
                let typed = type_chunk(fold, &blocks, &records, &miner)?;
                cursor_leaf += typed.len() as u64;
                // Where this chunk holds which commitment, built by the first
                // mismatch in it and by nothing else. An honest chain produces
                // none, so the ordinary pass never builds it. See
                // [`index_chunk`].
                let mut by_commitment: Option<HashMap<(u32, Digest), u64>> = None;
                for (record, leaf) in records.iter().zip(typed.iter()) {
                    report.leaves_scanned += 1;
                    let commitment = leaf.commitment;
                    let block_number = leaf.block_number;

                    // Whether the note came out of the coinbase rule, which is
                    // what `NoteOrigin::Coinbase` records and what the report
                    // counts. A leaf at a coinbase position that no coinbase rule
                    // opens is still offered to the transfer rule when it carries
                    // a ciphertext: under v1 a coinbase carries none, so a
                    // ciphertext there is either an encrypted coinbase or a leaf
                    // that is not a coinbase at all, and skipping it would be the
                    // silent step-over this whole pass exists to close.
                    let mut from_coinbase = false;
                    let opened = match leaf.kind {
                        LeafKind::Coinbase {
                            ours,
                            value,
                            label_disagrees,
                        } => {
                            report.coinbase_leaves += 1;
                            if label_disagrees {
                                report.coinbase_label_disagreed += 1;
                            }
                            match receive_coinbase(
                                &miner_key,
                                &ivk,
                                &genesis_hash,
                                block_number,
                                value,
                                &commitment,
                                record.ciphertext.as_deref(),
                            ) {
                                Some(received) => {
                                    from_coinbase = true;
                                    OpenedLeaf::Here(received)
                                }
                                // `ours` is the typing pass's own rebuild of
                                // this wallet's coinbase note against the
                                // tree-authenticated commitment, so the opener
                                // above rebuilds the identical note and cannot
                                // miss. Saying so out loud rather than falling
                                // through to the transfer arm is what keeps a
                                // later change to either rule from turning a
                                // mined reward back into a silent skip.
                                None if ours => bail!(
                                    "leaf {} was typed as this wallet's own coinbase for block \
                                     {block_number} at {} QNR and the same rebuild does not open \
                                     it. The two rebuilds are one rule, so this is a build whose \
                                     halves disagree. Nothing has been changed.",
                                    record.index,
                                    qnr(value)
                                ),
                                None => record
                                    .ciphertext
                                    .as_deref()
                                    .map_or(OpenedLeaf::NotOurs, |bytes| {
                                        try_transfer(&ivk, bytes, &commitment)
                                    }),
                            }
                        }
                        LeafKind::Transfer => match record.ciphertext.as_deref() {
                            Some(ciphertext) => try_transfer(&ivk, ciphertext, &commitment),
                            // Unreachable: `type_chunk` refuses a transfer leaf
                            // with no ciphertext by name.
                            None => OpenedLeaf::NotOurs,
                        },
                    };

                    // Where this note is recorded, and which commitment it is
                    // recorded under. Both are the leaf the pass is standing on
                    // until the detector below moves them.
                    let mut leaf_index = record.index;
                    let (received, commitment) = match opened {
                        OpenedLeaf::NotOurs => continue,
                        OpenedLeaf::Here(received) => (received, commitment),
                        // The one local detector for a leaf this node moved.
                        //
                        // These bytes decapsulated under this wallet's ML-KEM
                        // key and opened under an AEAD whose associated data is
                        // this wallet's own `pk`, so the note inside them is
                        // this wallet's. A commitment beside them that the note
                        // does not open is therefore the node taking a pair
                        // apart, and this pass can say where the pair belongs:
                        // the block's leaf range is already folded and compared
                        // against the `zkTreeRoot` its header carries, so a
                        // commitment found inside it is one the block appended.
                        OpenedLeaf::Elsewhere(received) => {
                            let found = by_commitment
                                .get_or_insert_with(|| index_chunk(&typed))
                                .get(&(block_number, received.commitment))
                                .copied();
                            match found {
                                Some(index) => {
                                    moved_leaves += 1;
                                    if moved_leaves <= WARNED_LEAVES_PER_PASS {
                                        report.warnings.push(moved_leaf_warning(
                                            record.index,
                                            block_number,
                                            index,
                                        ));
                                    }
                                    leaf_index = index;
                                    let commitment = received.commitment;
                                    (received, commitment)
                                }
                                // Skipped and said out loud, and a warning
                                // deliberately. One other thing produces this
                                // reading and nothing local tells it apart: a
                                // sender who encrypted a payload opening a
                                // commitment the sender never published. The
                                // circuit leaves `ct_digest` unconstrained
                                // (`docs/CIRCUIT.md` section 1), so no rule on
                                // chain ties a ciphertext's plaintext to the
                                // commitment beside it, and anyone holding this
                                // wallet's address can write such a leaf for
                                // the price of one transaction. Refusing the
                                // pass here would hand that sender a permanent
                                // sync denial: the leaf is read again on every
                                // later pass and on a rescan as well.
                                None => {
                                    unplaceable_leaves += 1;
                                    if unplaceable_leaves <= WARNED_LEAVES_PER_PASS {
                                        report.warnings.push(unplaceable_leaf_warning(
                                            record.index,
                                            block_number,
                                        ));
                                    }
                                    continue;
                                }
                            }
                        }
                    };

                    let commitment_hex = commitment.to_hex();
                    if self.store.has_commitment(&commitment_hex) {
                        // Already held, and possibly not where it was. A rescan
                        // reaches this line when the fork check rewound the
                        // watermark and the leaf range was walked again, which is
                        // what an orphaned block and a re-included extrinsic look
                        // like from here. See `WalletStore::relocate_note`.
                        if rewind.is_some() && reconciles {
                            seen_again.insert(commitment_hex.clone());
                        }
                        // Unconditional, the rescan included: a commitment the
                        // chain carries at another index is a note whose stored
                        // index is stale, and leaving it stale is what makes a
                        // note unspendable. This only ever adds, since it moves a
                        // note to where the chain has it and marks it on chain.
                        if self
                            .store
                            .relocate_note(&commitment_hex, leaf_index, Some(block_number))
                        {
                            report.relocated += 1;
                        }
                        continue;
                    }
                    let nullifier = received.note.nullifier(&nk);
                    let nullifier_hex = nullifier.to_hex();

                    // A note whose nullifier duplicates one this wallet already
                    // holds is kept.
                    //
                    // `docs/CIRCUIT.md` section 9.8: a sender picks `rho` and `r`
                    // for a note it creates, so a sender that repeats a pair hands
                    // over two notes sharing one nullifier, of which at most one
                    // can ever settle. Which one is not the sender's choice and
                    // not the scan's: it is whichever one this wallet spends
                    // first. The scan used to refuse the second note it met, which
                    // decided that by arrival order and decided it permanently, so
                    // a sender who put the large note second had the wallet keep
                    // the small one with no way back. Both are held now and
                    // `WalletStore::spendable` picks the larger, on every command.
                    if self.store.nullifier_settled(&nullifier_hex) {
                        if self.store.record_rejected(RejectedNote {
                            leaf_index,
                            commitment: commitment_hex,
                            nullifier: nullifier_hex.into(),
                            value: received.note.value,
                            reason: "its nullifier is already settled on chain".into(),
                        }) {
                            report.rejected += 1;
                        }
                        continue;
                    }

                    let origin = if from_coinbase {
                        // The coinbase rule is its own, and it is checked above:
                        // this note's commitment is the one the miner key and the
                        // chain's value produce. `entry_rho_matches` would walk the
                        // shield counter for a `rho` that never came from it.
                        NoteOrigin::Coinbase
                    } else if entry_rho_matches(block_number, &received.note.rho, entry_count) {
                        NoteOrigin::Shield
                    } else {
                        NoteOrigin::Spend
                    };
                    report.received += 1;
                    if origin == NoteOrigin::Coinbase {
                        report.coinbase_received += 1;
                    }
                    report.received_value += received.note.value;
                    if rewind.is_some() && reconciles {
                        // A note first recorded by this very scan is on the chain
                        // by construction, and the vanished count below walks
                        // every note inside the rescanned range.
                        seen_again.insert(commitment_hex.clone());
                    }
                    self.store.notes.push(StoredNote {
                        leaf_index,
                        block_number: Some(block_number),
                        value: received.note.value,
                        commitment: commitment_hex.clone(),
                        nullifier: nullifier_hex.into(),
                        rho: received.note.rho.to_hex().into(),
                        r: received.note.r.to_hex().into(),
                        memo: String::from_utf8_lossy(unpad_memo(&received.memo)).into_owned(),
                        origin,
                        spent: false,
                        spent_seen_at_block: None,
                        // Recorded by this scan, from the chain the scan is
                        // pinned to.
                        on_chain: true,
                    });
                    self.store
                        .pending
                        .retain(|pending| pending.commitment != commitment_hex);
                }
            } else {
                // Nothing was appended between the bottom of this walk and its
                // top, so there is no fold to seed and no leaf to check
                // against the roots. The headers are still fetched and
                // rehashed, because the checkpoint this pass records has to
                // name a head it authenticated, and every block in the chunk
                // has to carry the bottom block's own root: a moved root over
                // an unchanged leaf count is a node answering a count its own
                // headers do not carry.
                check_chunk_appended_nothing(&blocks)?;
            }

            checkpoints.push((top, hex::encode(top_hash), cursor_leaf));
            trusted_block = top;
            trusted_hash = top_hash;
            if top == head.number {
                break;
            }
        }

        // What the cap held back, carried as a count, so the report a person
        // reads stays one list whatever a node answered. See
        // [`moved_overflow_warning`] and [`unplaceable_overflow_warning`].
        if let Some(more) = moved_leaves.checked_sub(WARNED_LEAVES_PER_PASS) {
            if more > 0 {
                report.warnings.push(moved_overflow_warning(more));
            }
        }
        if let Some(more) = unplaceable_leaves.checked_sub(WARNED_LEAVES_PER_PASS) {
            if more > 0 {
                report.warnings.push(unplaceable_overflow_warning(more));
            }
        }

        if cursor_leaf != leaf_count {
            bail!(
                "the blocks this pass walked account for {cursor_leaf} leaves where this node \
                 reports {leaf_count} at the same block. Nothing has been changed."
            );
        }

        if leaf_count > start {
            // A leaf this scan accepted cannot still be a refusal. The one
            // refusal left is a settled nullifier, and a reorg that orphans
            // the settlement makes the same leaf acceptable on the rescan,
            // which used to leave the note in the balance and the refusal in
            // the file, both printed by `balance`. Once per scan rather than
            // once per note: it is a walk over two small lists.
            // See `WalletStore::prune_rejected`.
            report.rejected_cleared = self.store.prune_rejected();
        }

        // Spent status, derived against the local copy of the settled set that
        // was just repaged. Only the nullifier key can compute these values at
        // all, and a note this wallet holds may have been spent by another
        // copy of the same seed, so every note is decided on every sync. It is
        // decided locally: see the note above the set's refresh.
        //
        // Both directions. The flag used to be a latch, and a settlement that
        // was orphaned out of the chain left the note it spent reported spent
        // forever, out of the balance and unselectable, with the value fully
        // spendable on chain. See `WalletStore::reconcile_spent`.
        //
        // Add only under `--rescan`, which is the second half of rule 3. The
        // clearing direction reads the absence of a nullifier as an orphaned
        // settlement, and that reading is worth exactly as much as the gate
        // that proved this node is not simply missing the block which settled
        // it. A rescan may have bypassed that gate, so under it a note the
        // chain has consumed stays consumed and the count is reported as held.
        let direction = if reconciles {
            SpentDirection::BothWays
        } else {
            SpentDirection::AddOnly
        };
        let reconciled = self.store.reconcile_spent(head.number, direction);
        report.newly_spent = reconciled.newly_spent;
        report.newly_unspent = reconciled.newly_unspent;
        report.held_spent = reconciled.held_spent;

        // A rescanned range that did not carry a note back is a note the
        // current chain does not have: its settlement was orphaned and never
        // re-included. The note stays in the store, because its secrets are
        // the only copy this wallet has and a later block can still re-include
        // the extrinsic, and it is marked off chain, so `unspent_total`,
        // `select_notes` and the `balance` table agree with the chain instead
        // of reporting value nothing backs. `relocate_note` puts it back the
        // moment a scan sees the commitment again.
        //
        // Counted after the reconciliation above, and that ordering is the
        // whole of it. The flags this reads have to be the ones derived from
        // the set that was just repaged: a note that was spent and whose own
        // creating leaf was orphaned in the same reorg still carried
        // `spent: true` a few lines earlier, so a filter on `!note.spent`
        // skipped it, and the reconciliation then flipped it to unspent and
        // let it back into the balance as a phantom nobody had been told
        // about.
        //
        // A rescan does not run it at all. The marking says "the chain does
        // not carry this note", and the evidence for that is a range the scan
        // walked on a node proved to be at or ahead of everything this wallet
        // has read. A rescan may have bypassed that proof, and against a node
        // that is behind, or that is serving a head it has not executed, every
        // leaf it has not reached yet looks exactly like a leaf that is gone:
        // the whole store would be written off in one pass. The notes stay in
        // the balance, the report says they were not reconciled, and an
        // ordinary sync against a current node is what settles them.
        if rewind.is_some() && reconciles {
            report.vanished = self.store.mark_vanished(start, &seen_again);
        }

        // Said out loud rather than left to the operator to notice. See
        // `SyncReport::scanned_and_received_nothing`.
        report.scanned_and_received_nothing = report.leaves_scanned > 0 && report.received == 0;

        self.store.next_leaf = leaf_count;
        self.store.last_synced_block = head.number;
        // One per chunk of the walk, in ascending order, and every one of them
        // names a block whose header this pass fetched and rehashed down to a
        // hash it already trusted. A pass that scanned no leaf walked the
        // headers anyway, which is what keeps an idle pass from planting a
        // checkpoint on a hash nothing was fetched for: the next pass's walk
        // stands on that hash.
        for (block_number, block_hash, next_leaf) in checkpoints {
            self.store
                .record_checkpoint(block_number, block_hash, next_leaf);
        }
        // The binding, written by the save that commits this sync and by no
        // earlier one. A store with no genesis yet takes the chain of the
        // first node whose answers it actually kept, so a refusal above never
        // leaves a fresh store naming a chain it never read a leaf from.
        report.recorded_genesis = self.store.bind_genesis(&genesis)?;
        self.save()?;
        Ok(report)
    }

    /// Where this node stands against the store, decided before anything is
    /// written.
    ///
    /// One walk, one rule, and it answers both questions the sync has to ask
    /// of a node: is this node on the wallet's chain, and has it reached
    /// everything the wallet has already read. Both are questions about
    /// checkpoint hashes, and asking them separately is what made them
    /// contradict each other. The height comparison that used to stand in for
    /// the second one could not see a reorg onto a heavier shorter branch, and
    /// the fork walk read every checkpoint above a lagging node's head as a
    /// branch that was gone.
    ///
    /// The walk goes newest first:
    ///
    /// - A checkpoint above the node's head is skipped. On its own it says
    ///   nothing: the node may be behind, or that checkpoint may belong to a
    ///   branch this node replaced with a heavier shorter one. Which of those
    ///   it is, is decided by the first checkpoint the node can actually
    ///   answer for.
    /// - The first checkpoint at or below the head whose hash still stands
    ///   means the node is on this wallet's chain up to that height. If
    ///   anything was skipped above it, the node is behind the wallet on the
    ///   wallet's own chain, which is refused: its `UsedNullifiers` is missing
    ///   every settlement it has not executed, and `reconcile_spent` would
    ///   read that as those notes coming back into the balance.
    /// - A checkpoint at or below the head whose hash differs is a fork. The
    ///   walk continues down to the newest checkpoint that still stands, and
    ///   that survivor is where the watermark rewinds to. The checkpoints
    ///   above it, the ones above the head included, belong to the branch that
    ///   is gone. `last_synced_block` follows the survivor and is allowed to
    ///   go down, which is what a reorg onto a heavier shorter branch is.
    /// - No block at all at a height at or below the head is neither. A fork
    ///   is a *different* block at that height; no block there is a node that
    ///   is pruned or is serving a head it has not filled in behind, and
    ///   rewinding on it rescans leaves against a tree smaller than the one
    ///   already recorded. It is refused by name.
    ///
    /// The rewind exists because a rescan repairs a note's leaf index only
    /// when the scan walks that leaf again, and the scan starts at the
    /// watermark. A reorg happens because the replacement branch is heavier,
    /// so it normally carries at least as many leaves as the branch it
    /// replaced and a re-included commitment lands at or below where it was,
    /// which is below the watermark and is never re-read. The store then kept
    /// a leaf index that holds somebody else's commitment: `balance` went on
    /// reporting the note spendable and every spend that selected it failed on
    /// the path rebuild until the JSON was edited by hand.
    ///
    /// What this deliberately does not do is re-read `ZkTree::Leaves` at each
    /// held note's recorded index. That would name this wallet's own leaves to
    /// the node, which is the property `Chain::rebuild_tree` and
    /// `Chain::used_nullifiers_at` both pay for. `chain_getBlockHash` at a
    /// height names nothing, and the walk stops at the first checkpoint that
    /// stands, so the usual cost is one call.
    ///
    /// This reads and decides. It writes nothing, so the leaf gate in `sync`
    /// can still refuse afterwards with the store untouched.
    fn read_node_stance(&self, chain: &Chain, head: &ChainHead) -> Result<NodeStance> {
        let mut above_head = 0usize;
        let mut forked = false;
        for checkpoint in self.store.checkpoints.iter().rev() {
            if checkpoint.block_number > head.number {
                above_head += 1;
                continue;
            }
            let Some(hash) = chain.block_hash_at_height(checkpoint.block_number)? else {
                bail!(
                    "this node has no block at height {}, which this wallet checkpointed while \
                     syncing, and its head is block {}. A missing block at a height below a \
                     node's own head is a node that is pruned or has not filled in behind its \
                     head, and it is not a fork: a fork is a different block at that height. \
                     Rewinding on it would rescan leaves against a tree smaller than the one \
                     already recorded. Nothing has been changed.",
                    checkpoint.block_number,
                    head.number
                );
            };
            if hex::encode(hash) != checkpoint.block_hash {
                // A different block at a height this wallet checkpointed. That
                // checkpoint belongs to a branch that is gone, and the walk
                // carries on for the newest one that is not.
                forked = true;
                continue;
            }
            if forked {
                return Ok(NodeStance::Forked {
                    at_block: checkpoint.block_number,
                    next_leaf: checkpoint.next_leaf,
                });
            }
            if above_head > 0 {
                return Err(self.behind_this_wallet(head));
            }
            return Ok(NodeStance::Current);
        }
        if forked {
            // Every checkpoint this node can answer for is on a branch that is
            // gone. Rescanning the whole tree is correct and slow, and it is
            // what a reorg deeper than the checkpoints the store keeps costs.
            return Ok(NodeStance::Forked {
                at_block: 0,
                next_leaf: 0,
            });
        }
        if above_head > 0 {
            // Every checkpoint sits above this node's head and not one of them
            // could be probed, so there is no evidence of a fork and the node
            // is behind by every measure the wallet has.
            return Err(self.behind_this_wallet(head));
        }
        // No checkpoints at or below the head and none above it either: a
        // fresh store, or one whose checkpoints were dropped.
        Ok(NodeStance::Current)
    }

    /// The refusal a lagging node gets, by name.
    ///
    /// A node behind the wallet is an ordinary operational state: a second
    /// `--node`, a node resyncing, a load balancer answering from a lagging
    /// replica. It is not new information, and every answer it gives is read
    /// as a change when it is only a gap, so it is refused by name and
    /// nothing is written.
    ///
    /// A node on a branch that diverged above its own head is indistinguishable
    /// from this, because the checkpoints that would show the divergence are
    /// heights it cannot answer for. That case lands here too, and `--rescan`
    /// is the way through it.
    fn behind_this_wallet(&self, head: &ChainHead) -> anyhow::Error {
        anyhow!(
            "this node's head is block {} and this wallet has synced through block {} on the \
             chain this node is serving. This node is behind this wallet: it answers every \
             question with less than the wallet already knows, so notes it has not seen settled \
             would come back into the balance and the next send would select an input the chain \
             has already consumed. Nothing has been changed. Point --node at a node that has \
             caught up, wait for this one to, or pass --rescan to drop this wallet's watermark \
             and walk this node's tree from leaf zero.",
            head.number,
            self.store.last_synced_block
        )
    }

    /// Commit what the walk decided, and the operator's rescan on top of it.
    ///
    /// The first write of the sync. Both gates have already passed, or the
    /// checkpoint walk's refusal was bypassed by `--rescan` and the leaf gate
    /// cannot fire.
    fn apply_stance(&mut self, stance: NodeStance, options: SyncOptions) -> Option<ScanRewind> {
        let from = self.store.next_leaf;
        if options.rescan {
            // Asked for, so it is not a fork and does not report as one. Every
            // note stays: the tree is walked again from zero and whatever the
            // chain still carries is relocated back on chain.
            //
            // `rewind_to(0, 0)` is also what the bypass owes the store. It
            // drops every checkpoint and takes `last_synced_block` to zero, so
            // a rescan that walked past a node gate leaves behind no claim
            // that gate was measured against: the checkpoints this node could
            // not answer for are gone, and the store's next sync compares
            // against the one this rescan writes at the end.
            self.store.rewind_to(0, 0);
            return Some(ScanRewind {
                from,
                to: 0,
                forked_at: None,
            });
        }
        match stance {
            NodeStance::Current => None,
            NodeStance::Forked {
                at_block,
                next_leaf,
            } => {
                self.store.rewind_to(at_block, next_leaf);
                Some(ScanRewind {
                    from,
                    to: next_leaf,
                    forked_at: Some(at_block),
                })
            }
        }
    }

    /// Move transparent value into the pool as one note owned by this wallet.
    pub fn shield(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        from: &crate::dev_account::TransparentKey,
        steps: u64,
        memo: &str,
    ) -> Result<ShieldReport> {
        // The same guard `sync` and `prepare_spend` run, and for the same
        // reason: every key below is built from a compiled-in name and a
        // compiled-in hasher, and the node validates none of them. `shield`
        // reads `Shielded::EntryCount` and then `ZkTree::LeafCount` and
        // `ZkTree::Leaves` to confirm its own leaf. Under a drifted layout
        // every one of those keys reads as absent, so the count is zero, the
        // window the confirmation walks is empty, and it finds no leaf
        // carrying the commitment: a shield that actually settled is reported
        // as a dispatch that failed, dropping the pending entry that holds the
        // note's `r` on the way out. The note stays recoverable, since its plaintext is in
        // the ciphertext the chain stored, but the operator is told the value
        // was burned for nothing and sent to look at the dev account instead
        // of at the runtime.
        metadata.ensure_known_storage()?;
        ensure_memo_pad_fits(metadata)?;
        // The chain this store belongs to. A shield against another one burns
        // transparent value into a tree the store's own leaf indices do not
        // describe.
        let genesis = chain.genesis_hash()?;
        self.store.ensure_genesis(&hex::encode(genesis))?;
        if steps == 0 {
            bail!("a shield of zero moves nothing and the chain refuses it");
        }
        let head = chain.head()?;
        let entry_index = chain.entry_count_at(&head.hash)?;
        // The entry `rho` rule hashes the block the shield lands in and the
        // chain-wide entry counter at that moment
        // (`qnero_note_core::entry_rho`). Neither is knowable before
        // submission, so both are predicted and checked afterwards. The chain
        // does not evaluate the rule, and a prediction that misses strands
        // nothing: the note is this wallet's own and its commitment opens
        // whatever `rho` went into it.
        let predicted_block = head.number + 1;
        let rho = entry_rho(predicted_block, entry_index);
        let r = random_digest(b"qnero-wallet/shield-r")?;
        let note = Note::new(self.key.pk(), steps, rho, r)?;
        let inner = note.inner();
        let ciphertext = encrypt_note(
            &self.ivk().encapsulation_key(),
            &note,
            // Padded, like every other memo this wallet writes: a note
            // ciphertext is a fixed size plus its memo and the chain publishes
            // the bytes in full, so an unpadded memo publishes its own length.
            // See `crate::memo`.
            &pad_memo(memo)?,
            &random_bytes()?,
        )?
        .to_bytes();
        ensure_ciphertext_fits(metadata, ciphertext.len(), "shield")?;

        let planck = u128::from(steps)
            .checked_mul(POOL_STEP)
            .ok_or_else(|| anyhow!("{} QNR overflows the chain's balance type", qnr(steps)))?;
        let call = encode_shield_call(metadata, planck, &inner.to_bytes(), &ciphertext);
        let (spec_version, transaction_version) = chain.runtime_version()?;
        let context = SigningContext {
            spec_version,
            transaction_version,
            genesis_hash: genesis,
            nonce: chain.account_nonce(&from.account_id())?,
            tip: 0,
        };
        let encoded = encode_signed(metadata, from, &call, &context)?;

        // Written before the submission: the store is the only copy of this
        // note's `r`, and a crash between `author_submitExtrinsic` and the
        // confirmation would otherwise burn the value into a commitment
        // nothing can open.
        // The binding, recorded by the first save that keeps anything. A
        // shield is an explicit act against this node's chain, and the pending
        // entry below is already a statement about it.
        self.store.bind_genesis(&hex::encode(genesis))?;
        self.store.pending.push(PendingNote {
            kind: PendingKind::Shield,
            commitment: note.commitment().to_hex(),
            value: steps,
            rho: rho.to_hex().into(),
            r: r.to_hex().into(),
            memo: memo.to_string(),
            submitted_at_block: head.number,
            extrinsic: hex_0x(&encoded),
        });
        self.save()?;

        let started = Instant::now();
        chain.submit_extrinsic(&encoded)?;
        let included_at = wait_for_inclusion(chain, &hex_0x(&encoded), head.number)?;
        let inclusion = started.elapsed();

        // An extrinsic in a block is not a dispatch that succeeded. A shield
        // whose signer cannot pay, or whose value is not a whole multiple of
        // `POOL_STEP`, is included and then fails, appends no leaf and
        // creates no note. Reporting that as a success leaves a pending entry
        // in the store forever and an exit code of zero, and it is also what
        // would swallow a `POOL_STEP` drift, which `crate::POOL_STEP`
        // argues is loud precisely because `ValueNotQuantized` would surface.
        let included_hash = chain.block_hash(included_at)?;
        let parent_hash = chain.block_hash(included_at.saturating_sub(1))?;
        let commitment = note.commitment();
        let leaves_before = chain.leaf_count_at(&parent_hash)?;
        let leaves_after = chain.leaf_count_at(&included_hash)?;
        let appended =
            chain.leaf_hashes(leaves_before..leaves_after, leaves_after, &included_hash)?;
        let Some(offset) = appended.iter().position(|leaf| *leaf == commitment) else {
            self.store
                .pending
                .retain(|pending| pending.commitment != commitment.to_hex());
            self.save()?;
            bail!(
                "the shield was included in block {included_at} and its dispatch failed: no leaf \
                 in that block carries the commitment {}, so no note was created. The usual \
                 causes are a dev account that cannot pay {} planck and a value that is not a \
                 whole multiple of POOL_STEP. The pending entry has been dropped.",
                commitment.to_hex(),
                planck
            );
        };
        let leaf_index = leaves_before + offset as u64;

        // Both halves of the entry rule, against what the chain actually
        // assigned. Comparing `entry_rho(included_at, entry_index)` with the
        // `rho` built from that same `entry_index` only ever tested the block
        // half; the counter could have moved between the read and inclusion
        // and the check would still have said it matched.
        let entry_before = chain.entry_count_at(&parent_hash)?;
        let entry_after = chain.entry_count_at(&included_hash)?;
        let entry_check = classify_entry_rho(
            predicted_block,
            entry_index,
            included_at,
            entry_before,
            entry_after,
        );

        Ok(ShieldReport {
            steps,
            commitment: commitment.to_hex(),
            leaf_index,
            included_at,
            inclusion,
            predicted_block,
            predicted_entry_index: entry_index,
            entry_count_after: entry_after,
            entry_check,
        })
    }

    /// Resolve the fee and check the spend is fundable, before any circuit is
    /// built.
    ///
    /// Building the prover is seconds and proving is tens of seconds, and both
    /// are wasted on a spend that a fee floor or a two-input selection was
    /// always going to refuse. Everything here is a few ML-KEM encapsulations
    /// and a sort.
    pub fn preflight(
        &self,
        metadata: &ChainMetadata,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
    ) -> Result<Preflight> {
        ensure_memo_pad_fits(metadata)?;
        let plan = self.resolve_fee(metadata, to, memo, requested_fee)?;
        let target = amount
            .checked_add(plan.fee)
            .ok_or_else(|| anyhow!("{amount} plus {} overflows", plan.fee))?;
        select_notes(self.store.spendable(), target)?;
        Ok(plan)
    }

    /// The fee this submission owes, or the caller's if it clears the floor
    /// without running away from it.
    ///
    /// The ciphertext sizes decide the floor and the fee is a public input
    /// fixed at proving time, so both are settled before a witness exists. A
    /// `NoteCiphertext` is a fixed size plus its padded memo and the note's
    /// value does not move it, so measuring a probe pair is exact.
    fn resolve_fee(
        &self,
        metadata: &ChainMetadata,
        to: &Address,
        memo: &str,
        requested_fee: Option<u64>,
    ) -> Result<Preflight> {
        let (probe_payment, probe_change) = self.probe_lengths(to, memo)?;
        ensure_ciphertext_fits(metadata, probe_payment, "payment")?;
        ensure_ciphertext_fits(metadata, probe_change, "change")?;
        let floor = slot_fee_floor(metadata, probe_payment, probe_change);
        debug_assert_eq!(
            floor,
            submission_fee_floor(metadata, 1, (probe_payment + probe_change) as u64)
        );
        match requested_fee {
            None => Ok(Preflight { fee: floor, floor }),
            Some(fee) if fee < floor => bail!(
                "a fee of {} QNR is below this submission's floor of {}. The pallet asks \
                 MinLeafFee ({} QNR) plus 0.01 QNR per started {} bytes of ciphertext, and the \
                 two outputs here are {} bytes. The fee is a public input of the proof, so it \
                 cannot be raised afterwards: the settlement would be refused with \
                 PayloadUnderpaid.",
                qnr(fee),
                qnr(floor),
                qnr(metadata.min_leaf_fee),
                metadata.ciphertext_bytes_per_fee_quantum,
                probe_payment + probe_change
            ),
            Some(fee) if fee_runs_away(fee, floor) => bail!(
                "a fee of {} QNR is {} times this submission's floor of {}, so it is refused as a \
                 typing rather than an intention. The pool gives every settlement the same \
                 constant priority, so a fee above the floor buys nothing: half of it burns and \
                 the block author takes the rest. `--fee` is in QNR, so the floor here is `--fee \
                 {}`.",
                qnr(fee),
                fee / floor.max(1),
                qnr(floor),
                qnr(floor)
            ),
            Some(fee) => Ok(Preflight { fee, floor }),
        }
    }

    /// The exact byte length of each output ciphertext this spend will carry.
    ///
    /// One number twice. Both memos are padded to `memo::MEMO_BYTES` and an
    /// ML-KEM ciphertext is fixed size, so the payment and the change come out
    /// identical whatever the memo says and whoever the recipient is. That
    /// equality is the property, and it is asserted here: two different
    /// lengths published side by side name which of the pair is the sender's
    /// change and how long the payment's memo was.
    fn probe_lengths(&self, to: &Address, memo: &str) -> Result<(usize, usize)> {
        let payment = probe_ciphertext_len(&to.ek, &pad_memo(memo)?)?;
        let change = probe_ciphertext_len(&self.ivk().encapsulation_key(), &pad_memo("")?)?;
        if payment != change {
            bail!(
                "the payment ciphertext measures {payment} bytes and the change {change}. Every \
                 memo is padded to the same size precisely so these two agree, and a pair of \
                 different lengths publishes which output is the change and how long the \
                 payment's memo was."
            );
        }
        Ok((payment, change))
    }

    /// Spend up to two notes into a payment and a change note.
    ///
    /// [`Wallet::prepare_spend`] then [`Wallet::submit_spend`]: the two halves
    /// are apart so an aggregator can take the proof between them and wrap it
    /// in a public batch. A wallet calls this.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prover: &WalletProver,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
        merkle: MerkleSource,
    ) -> Result<SendReport> {
        let prepared = match self.prepare_spend(
            chain,
            metadata,
            prover,
            to,
            amount,
            requested_fee,
            memo,
            merkle,
        ) {
            Ok(prepared) => prepared,
            // One error carries a fact about the chain worth writing down:
            // an input this wallet selected is not in the tree the anchor
            // header roots. See `Wallet::write_off_missing_note`.
            Err(error) => return Err(self.write_off_missing_note(error)),
        };
        self.submit_spend(chain, metadata, prepared)
    }

    /// Everything up to and including the proof, with nothing submitted and
    /// nothing written to the store.
    ///
    /// What comes back is exactly what `submit_private_batch` takes, and it is
    /// also exactly what an aggregator wraps: a public batch's inner is a
    /// private batch that would have been accepted on its own.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_spend(
        &self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prover: &WalletProver,
        to: &Address,
        amount: u64,
        requested_fee: Option<u64>,
        memo: &str,
        merkle: MerkleSource,
    ) -> Result<PreparedSpend> {
        metadata.ensure_known_storage()?;
        ensure_memo_pad_fits(metadata)?;
        // The chain this store belongs to. Every leaf index a selection hands
        // the path rebuild is an index into one chain's tree.
        self.store
            .ensure_genesis(&hex::encode(chain.genesis_hash()?))?;
        let fee = self.resolve_fee(metadata, to, memo, requested_fee)?.fee;
        let (probe_payment, probe_change) = self.probe_lengths(to, memo)?;

        let target = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("{amount} plus {fee} overflows"))?;
        let selected: Vec<StoredNote> = select_notes(self.store.spendable(), target)?
            .into_iter()
            .cloned()
            .collect();
        let input_total: u64 = selected.iter().map(|note| note.value).sum();
        let change = input_total - target;

        // The anchor. Every read of it is pinned to one hash, because the tree
        // root moves every block and the header a proof binds to must be the
        // one whose root the input paths reach.
        //
        // The anchor is always the current head, and that is a privacy policy
        // as much as a correctness one. The anchor block is a public input of
        // the settlement, so every chain reader sees the gap between anchor
        // and inclusion. An anchor at head minus k, or one cached and reused
        // across two spends to save a `chain_getHeader`, is a distinguisher
        // inside the 256-block window and marks both spends as one wallet's.
        // So the anchor is always the head, and it is taken fresh for every
        // submission. It is taken here, with the circuits already built, so
        // that circuit build time stays out of the gap.
        //
        // What that does not buy is a uniform gap. Everything after this line
        // is inside it: the tree rebuild, which is O(leaf_count) reads and a
        // Poseidon2 fold, two ML-KEM encapsulations, and the proof. A
        // `--merkle-rpc` spend skips the rebuild and lands measurably sooner
        // than a default one; a slow machine or a long chain lands later. So
        // the gap is a per-wallet class marker, published to every chain
        // reader. Making it a constant means holding the submission until the
        // anchor plus a fixed number of blocks, which is latency M5 does not
        // spend. `docs/WALLET.md` records it as an open issue.
        let head = chain.head()?;
        let (header, anchor_hash) = chain.anchor_header(head.number)?;

        let pk = self.key.pk();
        let derived = self.key.derived();
        let mut paths = match merkle {
            MerkleSource::Local => {
                self.local_paths(chain, &selected, &header, &anchor_hash, head.number)?
            }
            MerkleSource::Rpc => {
                self.rpc_paths(chain, &selected, &header, &anchor_hash, head.number)?
            }
        };

        let depth = paths[0].1.depth();
        let mut rng = rand::rng();
        let inputs: [InputNote; 2] = match paths.len() {
            1 => {
                let (note, path) = paths.remove(0);
                [
                    InputNote::real(&derived, &note, path)?,
                    // `dummy_random` draws its `(rho, r)` from a CSPRNG. A
                    // repeated pair publishes a nullifier the chain has
                    // already settled and the whole submission is refused,
                    // naming a value the wallet cannot map to any note it
                    // holds.
                    InputNote::dummy_random(&mut rng, &derived, depth),
                ]
            }
            2 => {
                let (second_note, second_path) = paths.remove(1);
                let (first_note, first_path) = paths.remove(0);
                [
                    InputNote::real(&derived, &first_note, first_path)?,
                    InputNote::real(&derived, &second_note, second_path)?,
                ]
            }
            other => bail!("selected {other} notes for a circuit with two input slots"),
        };

        // Which slot carries the payment is drawn per spend. With the payment
        // fixed at slot 0 the chain publishes, for every settlement, which of
        // the two new leaves is the sender's change: `ct_1` belongs to
        // `cm_out_1` and `SlotSettled` names both leaf indices, so the pool's
        // outputs split publicly into "went to a counterparty" and "came back
        // to the sender" with no key material at all. The circuit derives each
        // output's `rho` from its own slot index (`SpendWitness::output_rho`),
        // so either assignment proves and settles unchanged.
        let payment_slot = choose_payment_slot(&mut rng);
        let change_slot = 1 - payment_slot;
        let payment_out =
            OutputNote::new(to.pk, amount, random_digest(b"qnero-wallet/out-payment")?);
        let change_out = OutputNote::new(pk, change, random_digest(b"qnero-wallet/out-change")?);
        let outputs = if payment_slot == 0 {
            [payment_out, change_out]
        } else {
            [change_out, payment_out]
        };
        // `ct_digest` binds ciphertexts that carry a `rho` the witness derives
        // from its own nullifiers, so the witness is built first with a
        // placeholder and the digest written once the outputs exist. Nothing
        // is proved in between.
        let mut witness = SpendWitness {
            header,
            depth,
            inputs,
            outputs,
            fee,
            ct_digest: Digest::from_bytes(&[0u8; 32]).expect("zero is canonical"),
        };
        witness.validate()?;

        let payment_note = witness.output_note(payment_slot)?;
        let change_note = witness.output_note(change_slot)?;
        let payment_ct =
            encrypt_note(&to.ek, &payment_note, &pad_memo(memo)?, &random_bytes()?)?.to_bytes();
        let change_ct = encrypt_note(
            &self.ivk().encapsulation_key(),
            &change_note,
            &pad_memo("")?,
            // Fresh per output, and nothing enforces it inside `encrypt_note`:
            // two outputs sharing `kem_randomness` are encrypted under one
            // ChaCha20-Poly1305 key and nonce, which leaks the XOR of the two
            // plaintexts and the authentication key.
            &random_bytes()?,
        )?
        .to_bytes();
        // `ct_1` belongs to `cm_out_1`, so the ciphertexts go out in slot
        // order and the payment's position rides with its note.
        let (ct_1, ct_2) = if payment_slot == 0 {
            (payment_ct, change_ct)
        } else {
            (change_ct, payment_ct)
        };
        if ct_1.len() != probe_payment || ct_2.len() != probe_change {
            bail!(
                "the ciphertexts came out at {} and {} bytes where the fee was computed for {} \
                 and {}",
                ct_1.len(),
                ct_2.len(),
                probe_payment,
                probe_change
            );
        }
        let outputs = vec![ShieldedOutput {
            ct_1: ct_1.clone(),
            ct_2: ct_2.clone(),
        }];
        witness.ct_digest = output_ct_digest(&outputs[0])?;
        witness.validate()?;

        let nullifiers = [
            witness.inputs[0].nullifier().to_bytes(),
            witness.inputs[1].nullifier().to_bytes(),
        ];

        let proving_started = Instant::now();
        let proof = prover
            .prove_submission(vec![witness])
            .context("failed to prove the private batch")?;
        let proving = proving_started.elapsed();
        // Verifying before sending costs milliseconds and turns a wallet-side
        // mistake into a local error. The pool refuses a bad settlement
        // without saying which public input was wrong.
        prover
            .batch_verifier_data()
            .verify(proof.clone())
            .map_err(|_| anyhow!("this wallet's own private-batch proof does not verify"))?;
        let proof_bytes = proof.to_bytes();

        Ok(PreparedSpend {
            proof: proof_bytes,
            outputs,
            nullifiers,
            change_note: PendingNote {
                kind: PendingKind::Change,
                commitment: change_note.commitment().to_hex(),
                value: change,
                rho: change_note.rho.to_hex().into(),
                r: change_note.r.to_hex().into(),
                memo: String::new(),
                submitted_at_block: head.number,
                extrinsic: String::new(),
            },
            spent_nullifiers: selected
                .iter()
                .map(|note| SecretHex::from(note.nullifier.as_str()))
                .collect(),
            input_leaves: selected.iter().map(|note| note.leaf_index).collect(),
            amount,
            fee,
            change,
            anchor_block: head.number,
            proving,
        })
    }

    /// Input paths, rebuilt locally from the whole leaf range at the anchor.
    ///
    /// The private route, and the default. `zkTree_getMerkleProof` is asked
    /// only about leaves a wallet is about to spend, so every such call names
    /// one of this wallet's own leaves to the node, and the settlement that
    /// publishes the matching nullifier arrives on the same connection seconds
    /// later. That join is the sender side of the pool deanonymized against
    /// whoever runs the RPC. Reading the whole leaf range says nothing about
    /// which leaf matters, and it is the read a scan already performs.
    ///
    /// `CommitmentTree` mirrors `pallet-zk-tree` exactly: the same 4-ary node
    /// rule, the same sorted children, the same all-zero padding for an absent
    /// child. The root it reaches is compared against the header's before any
    /// proving, which is the same check the RPC route makes and it covers the
    /// rebuild as well.
    fn local_paths(
        &self,
        chain: &Chain,
        selected: &[StoredNote],
        header: &qnero_circuit::header::HeaderInputs,
        anchor_hash: &[u8; 32],
        anchor_block: u32,
    ) -> Result<Vec<(Note, MerklePath)>> {
        let tree = chain.rebuild_tree(anchor_hash)?;
        // The root comparison comes first, and that ordering is what lets the
        // range check below say anything at all. A rebuilt tree whose root is
        // the one the anchor header carries **is** the chain's tree at that
        // block, so a leaf index past its end is a statement about the chain.
        // Checked after the range, the same out-of-range index could as easily
        // be a node serving a short leaf map.
        if tree.root() != header.zk_tree_root {
            bail!(
                "the tree this wallet rebuilt from {} leaves at depth {} roots at {} where \
                 header {anchor_block} carries {}. Proving against it would be refused. \
                 `--merkle-rpc` asks the node for the paths, at the cost of telling it which \
                 leaves are yours.",
                tree.leaf_count(),
                tree.depth(),
                tree.root().to_hex(),
                header.zk_tree_root.to_hex()
            );
        }
        // The watermark gate, which is the one `sync_with` refuses a node
        // behind this wallet with, repeated here because the write-off below
        // rests on it. Every other check in this function is against this
        // node's own answers: the rebuild roots to this node's own header, so
        // a node whose tree is shorter than what this wallet has already read
        // passes them all and still reaches `out_of_range`, which hands
        // `send` the typed error it writes a real, spendable note off on. A
        // losing fork, a rolled-back snapshot and a head the node has not
        // finished executing all have that shape, and none of them says the
        // chain dropped a leaf.
        if let Some(refusal) = short_tree_refusal(
            tree.leaf_count(),
            self.store.next_leaf,
            anchor_block,
            SPEND_SHORT_TREE,
        ) {
            return Err(refusal);
        }
        for note in selected {
            if note.leaf_index >= tree.leaf_count() {
                return Err(out_of_range(note, tree.leaf_count(), anchor_block));
            }
        }
        let pk = self.key.pk();
        let mut paths = Vec::with_capacity(selected.len());
        for note in selected {
            let stored = note.note(pk)?;
            let on_chain = tree
                .leaf(note.leaf_index)
                .ok_or_else(|| anyhow!("leaf {} is out of range", note.leaf_index))?;
            if on_chain != stored.commitment() {
                // The note is at an index this chain holds something else at,
                // and the tree it was read from roots at the value the anchor
                // header carries, so the chain is not the thing that is wrong.
                // A plain `sync` cannot repair it: the leaf is below the
                // watermark and an ordinary pass starts above it. `--rescan`
                // reads the range again from leaf zero and moves the note to
                // the index the chain holds it at, which is also the recovery
                // for a leaf a node moved inside its own group of four.
                bail!(
                    "leaf {} holds {} on chain and this wallet holds a note committing to {}. \
                     Run `sync --rescan`, against a second node where there is one: this leaf is \
                     below the watermark, so an ordinary sync starts above it and never reads it \
                     again.",
                    note.leaf_index,
                    on_chain.to_hex(),
                    stored.commitment().to_hex()
                );
            }
            let path = tree.path(note.leaf_index)?;
            let reached = path.root(stored.commitment())?;
            if reached != header.zk_tree_root {
                bail!(
                    "the path rebuilt for leaf {} reaches {} where header {anchor_block} carries \
                     {}",
                    note.leaf_index,
                    reached.to_hex(),
                    header.zk_tree_root.to_hex()
                );
            }
            paths.push((stored, path));
        }
        Ok(paths)
    }

    /// Input paths from `zkTree_getMerkleProof`, one call per input.
    ///
    /// Behind `--merkle-rpc`, and it tells the node which leaves this wallet
    /// is spending. See [`Wallet::local_paths`].
    fn rpc_paths(
        &self,
        chain: &Chain,
        selected: &[StoredNote],
        header: &qnero_circuit::header::HeaderInputs,
        anchor_hash: &[u8; 32],
        anchor_block: u32,
    ) -> Result<Vec<(Note, MerklePath)>> {
        let pk = self.key.pk();
        let mut paths = Vec::with_capacity(selected.len());
        for note in selected {
            let stored = note.note(pk)?;
            let path = chain
                .merkle_path(note.leaf_index, stored.commitment(), anchor_hash)?
                .ok_or_else(|| {
                    anyhow!(
                        "leaf {} is not folded into the tree at block {anchor_block} yet. A note \
                         cannot be minted and spent in the same block; wait one block and retry.",
                        note.leaf_index
                    )
                })?;
            if path.root != header.zk_tree_root {
                bail!(
                    "the Merkle proof for leaf {} reaches root {} where header {anchor_block} \
                     carries {}",
                    note.leaf_index,
                    path.root.to_hex(),
                    header.zk_tree_root.to_hex()
                );
            }
            paths.push((stored, path.path));
        }
        Ok(paths)
    }

    /// Write off a note the path rebuild proved the chain does not carry.
    ///
    /// [`Wallet::prepare_spend`] writes nothing, which is what makes it the
    /// seam an aggregator can take a proof from, so the one write this
    /// discovery needs is made here, by the command that owns the store for
    /// the whole spend. Every other error passes through untouched.
    ///
    /// The marking is the difference between an operator who retries and an
    /// operator who is told to retry forever. `select_notes` picks largest
    /// first, so a phantom larger than every real note is selected by every
    /// later `send` and fails on the same rebuild; out of
    /// [`WalletStore::unspent`] it is skipped, and the next attempt spends
    /// what the chain actually carries.
    fn write_off_missing_note(&mut self, error: anyhow::Error) -> anyhow::Error {
        let Some(missing) = error.downcast_ref::<NoteNotOnChain>() else {
            return error;
        };
        let commitment = missing.commitment.clone();
        if self.store.mark_note_off_chain(&commitment) {
            if let Err(failed) = self.save() {
                return error.context(format!(
                    "the note was also written off in memory and the store could not be saved: \
                     {failed:#}"
                ));
            }
        }
        error
    }

    /// Submit a prepared spend and wait for it to settle.
    pub fn submit_spend(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        prepared: PreparedSpend,
    ) -> Result<SendReport> {
        let encoded = encode_submit_private_batch(metadata, &prepared.proof, &prepared.outputs)?;
        let encoded_hex = hex_0x(&encoded);

        // Written before the submission: the store is the only copy of the
        // change note's `r`, and a crash between here and the confirmation
        // would leave a commitment in the tree that nothing can open.
        // The binding, recorded by the first save that keeps anything.
        // `prepare_spend` already refused a store belonging to another chain.
        self.store
            .bind_genesis(&hex::encode(chain.genesis_hash()?))?;
        let mut change_note = prepared.change_note.clone();
        change_note.extrinsic = encoded_hex.clone();
        self.store.pending.push(change_note);
        self.save()?;

        let submit_started = Instant::now();
        chain.submit_extrinsic(&encoded)?;
        let included_at = wait_for_inclusion(chain, &encoded_hex, prepared.anchor_block)?;
        let inclusion = submit_started.elapsed();

        // The settlement is what marks the inputs spent, so it is confirmed
        // against the chain: an extrinsic in a block is not yet a settled one.
        // A segment whose anchor went stale or whose nullifier was claimed
        // elsewhere is skipped, and the block carries it either way.
        let included_hash = chain.block_hash(included_at)?;
        let settled = chain.nullifiers_used(&prepared.nullifiers, &included_hash)?;
        if !settled[0] || !settled[1] {
            bail!(
                "the submission was included in block {included_at} and its nullifiers are not \
                 settled. The segment was skipped; re-sync and try again against a fresh anchor."
            );
        }
        for nullifier in &prepared.spent_nullifiers {
            self.store.mark_spent(nullifier.as_str(), included_at);
        }
        self.save()?;

        Ok(SendReport {
            amount: prepared.amount,
            fee: prepared.fee,
            change: prepared.change,
            inputs: prepared.input_leaves,
            anchor_block: prepared.anchor_block,
            included_at,
            proof_bytes: prepared.proof.len(),
            proving: prepared.proving,
            inclusion,
        })
    }
}

/// A proved spend, before anything is submitted or recorded.
#[derive(Clone)]
pub struct PreparedSpend {
    /// The private-batch proof, in plonky2's canonical encoding.
    pub proof: Vec<u8>,
    /// One entry per real leaf slot, in settlement order.
    pub outputs: Vec<ShieldedOutput>,
    /// Both nullifiers the leaf publishes, the dummy's included.
    pub nullifiers: [[u8; 32]; 2],
    change_note: PendingNote,
    /// The nullifiers of the notes this spend consumes, zeroized on drop.
    ///
    /// In `SecretHex` for the reason `StoredNote::nullifier` is: until the
    /// settlement lands these values have appeared nowhere, and a
    /// `PreparedSpend` exists exactly during that window. A plain `String`
    /// dropped without wiping sits in the memory a core dump or a swap page
    /// reaches, and beside the chain it names which settlement was this
    /// wallet's.
    spent_nullifiers: Vec<SecretHex>,
    pub input_leaves: Vec<u64>,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub anchor_block: u32,
    pub proving: Duration,
}

/// Redacted by hand, like every other type here that touches note material.
///
/// A derive prints `nullifiers`, `spent_nullifiers` and `input_leaves` in
/// full, and a `PreparedSpend` exists exactly during the window when none of
/// those is published yet. The first `dbg!` or `anyhow` context anyone wraps
/// around `submit_spend` while chasing an inclusion timeout would put the set
/// of nullifiers this wallet is about to publish, beside the leaf indices it
/// owns, into a log file created at the shell's umask. Those are the two
/// values the rest of this wallet takes care never to hand its own node.
impl core::fmt::Debug for PreparedSpend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedSpend")
            .field("proof", &self.proof.len())
            .field("outputs", &self.outputs.len())
            .field("nullifiers", &crate::store::REDACTED)
            .field("change_note", &self.change_note)
            .field("spent_nullifiers", &crate::store::REDACTED)
            .field("input_leaves", &crate::store::REDACTED)
            .field("amount", &self.amount)
            .field("fee", &self.fee)
            .field("change", &self.change)
            .field("anchor_block", &self.anchor_block)
            .field("proving", &self.proving)
            .finish()
    }
}

/// Which of the leaf's two output slots carries the payment.
///
/// Drawn per spend, so the chain does not publish which of a settlement's two
/// new leaves is the sender's change. See the call site.
fn choose_payment_slot<R: Rng + ?Sized>(rng: &mut R) -> usize {
    usize::from(rng.random_bool(0.5))
}

/// The `ct_digest` of one settlement slot, over the bytes the extrinsic
/// carries.
///
/// One rule, one implementation: `qnero_circuit::chain::ct_digest` is what
/// `pallet-shielded` recomputes over the `ShieldedOutput` it decoded, and it
/// is what the leaf's public input commits to. What a wallet owes is the
/// order, `ct_1` beside `cm_out_1`, and the exact bytes it is about to send.
pub fn output_ct_digest(output: &ShieldedOutput) -> Result<Digest> {
    Digest::from_bytes(&ct_digest(&[&output.ct_1, &output.ct_2]))
        .map_err(|_| anyhow!("ct_digest is not a canonical digest"))
}

/// One coinbase leaf, decided against this wallet.
///
/// Two ways in, and the order matters. The derived path is what a Qnero node
/// publishes: a block author's node cannot encrypt to an ML-KEM key, so it
/// derives the note from the miner key the operator configured it with and
/// publishes only `inner`. `qnero_note_core::coinbase_r` carries why. The
/// encrypted path is for a coinbase paid to an address whose coinbase viewing
/// key the author does not hold, which nothing in this wallet produces today
/// and the pallet still accepts.
///
/// Both end at the same check: rebuild the note against the value the chain
/// published and compare the commitment to the leaf. Nothing a block author
/// writes is trusted, the amount inside an encrypted payload included, which
/// is the one field of a coinbase note the chain has already decided.
///
/// The derived path takes the genesis because the derivation is deterministic
/// and is bound to one chain; the store is bound to the same genesis, and the
/// sync checked that before it read a leaf.
fn receive_coinbase(
    miner_key: &MinerKey,
    ivk: &IncomingViewingKey,
    genesis_hash: &[u8],
    block: u32,
    value: u64,
    commitment: &Digest,
    ciphertext: Option<&[u8]>,
) -> Option<ReceivedNote> {
    if let Ok(note) = miner_key.coinbase_note(genesis_hash, block, value) {
        let derived = note.commitment();
        if &derived == commitment {
            return Some(ReceivedNote {
                note,
                memo: Vec::new(),
                commitment: derived,
            });
        }
    }
    let parsed = NoteCiphertext::from_bytes(ciphertext?).ok()?;
    try_receive_coinbase(ivk, &parsed, value, commitment).ok()
}

/// What the ciphertext beside a leaf opened.
///
/// Three answers where there used to be two. The third is the whole of the one
/// local detector this wallet has for a moved leaf, and collapsing it into
/// "somebody else's" threw that detector away.
enum OpenedLeaf {
    /// Not this wallet's, or not a ciphertext at all. The ordinary answer for
    /// almost every leaf on the chain.
    NotOurs,
    /// This wallet's, and the commitment beside it is the one it opens.
    Here(ReceivedNote),
    /// This wallet's, and the commitment beside it is a different one.
    ///
    /// The payload is authenticated: it decapsulated under this wallet's
    /// ML-KEM decapsulation key and the AEAD opened with this wallet's own
    /// `pk` as associated data, so the note inside it is this wallet's note
    /// and the bytes were written by somebody who holds this wallet's address.
    /// What the commitment beside it says is that the pair was taken apart.
    Elsewhere(ReceivedNote),
}

/// One leaf opened by the ordinary transfer rule: a shield or a settled
/// output, whose value comes out of the payload and off the chain nowhere.
///
/// A payload that opens beside a commitment it does not open is carried out
/// of here as [`OpenedLeaf::Elsewhere`] and the caller acts on it. It used to
/// be folded into "somebody else's", which is the same reading as a
/// stranger's ciphertext and reaches the same silent skip, and it is the one
/// reading a wallet can tell apart on its own: a stranger's bytes do not open
/// at all, while these did.
fn try_transfer(ivk: &IncomingViewingKey, ciphertext: &[u8], commitment: &Digest) -> OpenedLeaf {
    let Ok(parsed) = NoteCiphertext::from_bytes(ciphertext) else {
        return OpenedLeaf::NotOurs;
    };
    // One decapsulation per leaf, and the comparison after it.
    //
    // `try_receive` is `decrypt_note` plus this comparison, so calling it and
    // then decrypting again on a mismatch ran the ML-KEM decapsulation and the
    // AEAD open twice for the same bytes. How many mismatches a pass meets is
    // a node's choice: it can answer a commitment the payload does not open at
    // every leaf it serves, and each one used to cost a second decapsulation.
    // The note the first open produced is the note either arm needs, so it is
    // kept and the commitment decides which arm it goes down.
    match decrypt_note(ivk, &parsed) {
        Ok(received) if received.commitment == *commitment => OpenedLeaf::Here(received),
        Ok(received) => OpenedLeaf::Elsewhere(received),
        Err(_) => OpenedLeaf::NotOurs,
    }
}

/// Where each block of this chunk holds each commitment, keyed by both.
///
/// The map is over the leaves this chunk already folded into the tree and
/// compared against each block's own `zkTreeRoot`, so a hit is a commitment
/// the block demonstrably appended. The block number is half the key because
/// a block's root pins that block's leaf set and nothing else: a commitment
/// elsewhere in the chain is a claim this pass has not checked against the
/// header that would settle it.
///
/// Built once per chunk and only when a leaf in it mismatches, because the
/// lookup used to be a walk of the whole chunk per moved leaf and how many
/// moved leaves a pass meets is a node's choice. One walk answers every
/// mismatch in the chunk instead. The first leaf wins a repeated commitment,
/// which is the leaf the walk used to return.
fn index_chunk(typed: &[TypedLeaf]) -> HashMap<(u32, Digest), u64> {
    let mut by_commitment = HashMap::with_capacity(typed.len());
    for leaf in typed {
        by_commitment
            .entry((leaf.block_number, leaf.commitment))
            .or_insert(leaf.index);
    }
    by_commitment
}

/// Whether a note's `rho` is the one the entry rule produces for the block its
/// leaf landed in.
///
/// The rule hashes `(block_number, entry_index)` and only the `Shielded` event
/// publishes `entry_index`, which needs the runtime's full type registry to
/// decode. So this walks the entry counter instead: the counter is chain wide
/// and monotone, a dev chain's is small, and a miss is not an error. A `false`
/// means the note came from a spend, whose `rho` the circuit derived from two
/// nullifiers, or from a shielder that ignored the rule.
///
/// The count is a parameter, because it is the same for every leaf of one
/// scan: the scan is pinned to a single block hash, so a per-note read was a
/// round trip whose answer could never move.
///
/// The walk stops at [`ENTRY_WALK_LIMIT`]. The count is a number the node
/// hands over and this is one Poseidon2 hash per unit of it, per received
/// note, so an unbounded walk lets one storage answer hold the sync for as
/// long as it likes. Past the bound a note is labelled `Transfer`, which is
/// what the answer is used for and nothing else.
fn entry_rho_matches(block: u32, rho: &Digest, entries: u64) -> bool {
    (0..entries.min(ENTRY_WALK_LIMIT)).any(|index| entry_rho(block, index) == *rho)
}

/// Poll blocks for the exact extrinsic that was submitted.
///
/// Matching the bytes keeps this honest about what it saw.
/// An unsigned settlement's `provides` tag is a function of the bundle, so a
/// rebroadcast of the same proof never displaces the copy already in the pool;
/// there is nothing useful to do but wait and then prove again.
fn wait_for_inclusion(chain: &Chain, extrinsic_hex: &str, from_block: u32) -> Result<u32> {
    let timeout = inclusion_timeout(chain);
    let deadline = Instant::now() + timeout;
    let mut next = from_block + 1;
    loop {
        let head = chain.head()?;
        while next <= head.number {
            let hash = chain.block_hash(next)?;
            if chain
                .block_extrinsics(&hash)?
                .iter()
                .any(|encoded| encoded == extrinsic_hex)
            {
                return Ok(next);
            }
            next += 1;
        }
        if Instant::now() >= deadline {
            bail!(
                "the submission was not included within {} seconds (watched blocks {}..={}). An \
                 unsigned settlement leaves the pool after five blocks and a rebroadcast of the \
                 same bytes will not displace it: prove again against a fresh anchor.",
                timeout.as_secs(),
                from_block + 1,
                head.number
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn probe_ciphertext_len(ek: &qnero_pqcrypto::ml_kem::MlKemPublicKey, memo: &[u8]) -> Result<usize> {
    let note = Note::new(
        Digest::hash_bytes(&[b"qnero-wallet/probe-pk"]),
        0,
        Digest::hash_bytes(&[b"qnero-wallet/probe-rho"]),
        Digest::hash_bytes(&[b"qnero-wallet/probe-r"]),
    )?;
    Ok(encrypt_note(ek, &note, memo, &random_bytes()?)?
        .to_bytes()
        .len())
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("the operating system's RNG refused")?;
    Ok(bytes)
}

fn random_digest(domain: &[u8]) -> Result<Digest> {
    Ok(Digest::hash_bytes(&[domain, &random_bytes()?]))
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub head_block: u32,
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub leaves_scanned: u64,
    /// Coinbase leaves seen, whoever they belong to. Every block mints one, so
    /// this counts the blocks the scanned range covers, and what it counts
    /// beyond `coinbase_received` is how many of them were somebody else's.
    pub coinbase_leaves: u64,
    /// Coinbase notes this wallet found: the blocks its own miner key authored.
    pub coinbase_received: u64,
    pub received: u64,
    pub received_value: u64,
    pub rejected: u64,
    /// Refusals dropped because this wallet now holds the same output.
    pub rejected_cleared: u64,
    /// Whether this sync was the one that wrote the chain's genesis into the
    /// store.
    pub recorded_genesis: bool,
    pub newly_spent: u64,
    /// Notes whose nullifier left the settled set: the block that settled
    /// them was orphaned and the settlement did not re-land.
    pub newly_unspent: u64,
    /// Notes whose nullifier this node does not carry, at a head that has not
    /// reached the block the spend was seen at. Left spent.
    pub held_spent: u64,
    /// Notes already held that the chain now carries at a different leaf.
    pub relocated: u64,
    /// The watermark this sync rewound from, when it found a fork.
    pub rewound_from: Option<u64>,
    /// The watermark it rewound to.
    pub rewound_to: Option<u64>,
    /// The newest block this wallet had synced that is still canonical.
    pub forked_at_block: Option<u32>,
    /// Held notes inside a rescanned range that the chain no longer carries.
    pub vanished: u64,
    /// Whether this sync ran add only, which is what `--rescan` runs.
    ///
    /// Nothing was taken away: no spent flag was cleared and no note was
    /// marked off chain, whatever this node's answers implied. See
    /// [`RESCAN_ADD_ONLY`] for the sentence a caller prints.
    pub add_only: bool,
    /// `Shielded::EntryCount` at this pass's block, when it is past
    /// [`ENTRY_WALK_LIMIT`] and the origin walk therefore stopped short.
    ///
    /// Set rather than silent, because `origin` is written once at receipt and
    /// no later pass revisits it: a shield received in a truncated pass keeps
    /// the `spend` label until a rescan. `wallet-web` reports the same bound
    /// as a warning on its own pass, and `docs/WALLET.md` open issue 3 is the
    /// rule.
    pub entry_walk_truncated: Option<u64>,
    /// Coinbase notes this pass rebuilt as its own at a coinbase position
    /// whose header carries another author's label.
    ///
    /// The rebuild decides ownership and the label decides nothing, so the
    /// reward is taken. It cannot happen on a block a Qnero node built: the
    /// label and the note's `r` come out of the same coinbase viewing key. So
    /// a non-zero count here is a header this wallet is being handed for a
    /// block it did not come from, and the checkpoint fork walk is what finds
    /// out on the next pass against another node. `docs/WALLET.md`, under
    /// "What a lying node can and cannot do", is the bound.
    pub coinbase_label_disagreed: u64,
    /// Whether this pass read leaves and took nothing out of them.
    ///
    /// Ordinary on most passes: almost every leaf on the chain is somebody
    /// else's. It is also exactly what the two per-leaf values nothing on
    /// chain binds look like, and that is why the pass says it out loud.
    ///
    /// The first is `Shielded::Ciphertexts(i)`: the commitment carries no
    /// ciphertext, and `ct_digest` binds the bytes only inside the settlement
    /// extrinsic at inclusion, which a storage-only reader never fetches. So a
    /// node with honest headers can answer a stranger's bytes at this wallet's
    /// incoming payment and the AEAD does not open.
    ///
    /// The second is where a commitment sits inside its block's own leaf
    /// range. `hash_node` sorts a node's children at every level and tags no
    /// level, so a block's `zkTreeRoot` pins that block's leaf multiset and
    /// each internal node's child multiset and nothing further: sibling swaps
    /// composed at any level move a payment to any position the range's
    /// aligned subtrees allow, the coinbase position included, and a shorter
    /// tree of internal node values served as leaves folds to the same root,
    /// so the root pins neither the leaf count nor the height inside a block.
    /// At the coinbase position a ciphertext is not owed and the coinbase
    /// rebuild opens nobody else's note, so the payment is skipped.
    ///
    /// One of those the scan does catch on its own, and the catch is the
    /// [`OpenedLeaf::Elsewhere`] detector: a move that leaves this wallet's
    /// ciphertext where the chain published it is a ciphertext that opens
    /// beside a commitment it does not open, and the note is recorded at the
    /// index inside the same block that holds the commitment it does open,
    /// with a warning. What stays hidden is a move that takes this wallet's
    /// ciphertext away with the commitment, or leaves none at all.
    ///
    /// Either way the leaf reads as somebody else's and the watermark is
    /// written above it. The checkpoint fork walk does not recover either,
    /// because the headers agree; a rescan against a second node recovers
    /// both. `docs/WALLET.md`, under "What a lying node can and cannot do",
    /// carries the bound and the closure that would end it.
    pub scanned_and_received_nothing: bool,
    /// What this pass gave up, could not verify, or recovered from a node
    /// answer the chain does not back, in sentences the caller prints.
    ///
    /// Rare by construction, which is what keeps the list worth reading. The
    /// two entries today both come out of the detector in the scan: a
    /// ciphertext this wallet's own key opened beside a commitment it does not
    /// open, either relocated to the index inside the same block that holds
    /// the opened note's commitment, or skipped because that block holds it
    /// nowhere. `wallet-web` carries the same list as `report.warnings`.
    ///
    /// Both of those are per leaf and a node decides how many leaves produce
    /// one, so both are capped at [`WARNED_LEAVES_PER_PASS`] sentences and the
    /// rest of each is one closing sentence carrying the count.
    pub warnings: Vec<String>,
    /// The node gate this sync bypassed, as the refusal it would have been.
    ///
    /// Only `--rescan` produces one, and only for the checkpoint walk: a node
    /// behind this wallet, or one with no block at a height the store
    /// checkpointed. It is carried so a caller can print it, because a
    /// bypassed gate that says nothing is a gate an operator stops knowing
    /// about.
    pub bypassed_refusal: Option<String>,
}

/// What a pass that read leaves and received nothing may also be, in one line.
///
/// See [`SyncReport::scanned_and_received_nothing`] for the bound. The
/// sentence is here so the command-line wallet and `wallet-web` print one
/// text, the way [`RESCAN_ADD_ONLY`] is shared, and the two copies are held
/// byte for byte identical by a test: `wallet-web/tests/leaf-typing.test.ts`
/// reads this literal out of this file and compares it against the browser's.
///
/// It names both values the chain leaves unbound and states the second one
/// whole, because one rescan is the recovery for either: a substituted
/// ciphertext and a leaf moved anywhere inside its block's range produce the
/// same reading, a leaf that opens for nobody.
pub const CIPHERTEXT_SUBSTITUTION_HINT: &str =
    "a pass that reads leaves and receives nothing is the ordinary case, and it is also what a \
     substituted or moved leaf looks like. Two per-leaf values are bound to a leaf by nothing on \
     chain: the bytes at Shielded::Ciphertexts, and where a leaf sits inside its block's own \
     range. The tree sorts a node's children at every level and tags no level, so a \
     block's root pins that block's leaf multiset and each internal node's child multiset and \
     nothing further: sibling swaps composed at any level reach any position the range's aligned \
     subtrees allow, the coinbase position included, and a shorter tree of internal node values \
     served as leaves folds to the same root, so the root pins neither the leaf count nor the \
     height inside a block. So a node with honest headers can answer a stranger's bytes at an \
     incoming payment, or move that payment onto its block's coinbase position where no \
     ciphertext is owed, and either way the leaf reads as somebody else's. If a payment was \
     expected and is not here, rescan against a second node, which is the recovery for both.";

/// What a rescan does not do, in one line, for the report and the CLI.
///
/// The guarantees an ordinary sync gives and this one does not: a spent flag
/// that follows the settled set in both directions, and a note the chain no
/// longer carries taken out of the balance. Both need a node proved to be at
/// or ahead of everything the wallet has read, which is the gate `--rescan`
/// exists to get past.
pub const RESCAN_ADD_ONLY: &str = "rescan: add-only, spent flags and orphans are not reconciled; \
     run a normal sync against a current node afterwards";

impl SyncReport {
    /// The add-only notice, when this sync was one.
    pub fn rescan_notice(&self) -> Option<&'static str> {
        self.add_only.then_some(RESCAN_ADD_ONLY)
    }

    /// The substituted-ciphertext hint, when this pass read leaves and took
    /// nothing out of them.
    pub fn ciphertext_hint(&self) -> Option<&'static str> {
        self.scanned_and_received_nothing
            .then_some(CIPHERTEXT_SUBSTITUTION_HINT)
    }
}

/// What checking a store against a node's chain found.
///
/// None of these writes anything. The genesis is recorded by the save that
/// commits a sync, a shield or a send, so a store that names no chain yet is
/// still naming none when a gate refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBinding {
    /// The store already named this chain.
    Bound,
    /// The store names no chain yet, and the first operation that commits will
    /// record this one. Every store written before version 5 starts here, and
    /// so does every fresh one.
    Unrecorded,
    /// The store named another chain and was archived at this path. The wallet
    /// carries a fresh store, which records this node's chain the first time it
    /// commits anything.
    Archived(PathBuf),
}

/// Move a store out of the way, keeping it.
///
/// Never a delete. The file holds every note's `rho` and `r`, which are the
/// only copy this wallet has of what opens its notes, and the reason it is
/// being moved may be an operator who typed the wrong `--node`.
///
/// The name is the store's own path with `.archived` appended, and a counter
/// after that for the second and every later archive at the same path. It
/// carries no genesis: which chain an archive belonged to is inside the file,
/// as its `genesis_hash`, and putting a hash in the filename would only say
/// again what one `grep` of the archive answers exactly.
fn archive_store(path: &Path) -> Result<PathBuf> {
    let mut base = path.as_os_str().to_os_string();
    base.push(".archived");
    for attempt in 0..1_000 {
        let mut candidate = base.clone();
        if attempt > 0 {
            candidate.push(format!(".{attempt}"));
        }
        let candidate = PathBuf::from(candidate);
        if !candidate.exists() {
            std::fs::rename(path, &candidate).with_context(|| {
                format!(
                    "failed to archive {} as {}",
                    path.display(),
                    candidate.display()
                )
            })?;
            return Ok(candidate);
        }
    }
    bail!(
        "{} has a thousand archived copies beside it already; move them somewhere else first",
        path.display()
    )
}

/// A note this wallet holds that the chain does not carry at the anchor.
///
/// A typed error because one caller acts on it. The path rebuild finds it and
/// `Wallet::send` writes the note off, through the same field
/// `WalletStore::mark_vanished` writes, so a note taken out of the balance by
/// either route comes back by the one route that puts it back, a scan meeting
/// the commitment again.
///
/// What makes it a fact and not a guess is the pair of conditions behind it.
/// The rebuilt tree roots at the value the anchor header carries, so it is the
/// chain's tree at that block and its leaf count is the chain's. And the store
/// recorded this leaf at a block strictly below the anchor, so the anchor's
/// state has executed the block that appended it. A leaf that is still missing
/// from that tree is a leaf this chain does not have.
///
/// The other side of that line is a same-block race, and it stays a retry: a
/// leaf appended in the anchor block itself, or one whose block the store
/// never recorded, is out of range on a tree that is perfectly current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteNotOnChain {
    /// The note's commitment, which is what `mark_note_off_chain` keys on.
    pub commitment: String,
    /// Where the store says the leaf is.
    pub leaf_index: u64,
    /// The block the store recorded that leaf at.
    pub recorded_at_block: u32,
    /// The anchor this spend was building against.
    pub anchor_block: u32,
    /// How many leaves the chain's tree holds at that anchor.
    pub leaf_count: u64,
}

impl core::fmt::Display for NoteNotOnChain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "this wallet holds a note at leaf {}, recorded at block {}, and the chain's tree at \
             block {} ends at leaf {}. Block {} has executed block {}, and the rebuilt tree roots \
             at the value that block's header carries, so this chain does not carry that leaf: the \
             block the note settled in was orphaned and the settlement has not been re-included. \
             `send` marks such a note off chain, so it keeps its secrets, leaves the unspent total \
             and is passed over by the next attempt, which spends what the chain does carry. Run \
             `sync` against a node at the current head: a sync that meets the commitment {} again \
             moves the note to the leaf the chain now holds it at and puts it back. If it does \
             not, run `sync --rescan` against a second node: an ordinary sync starts at the \
             watermark, so a leaf below it is never read again.",
            self.leaf_index,
            self.recorded_at_block,
            self.anchor_block,
            self.leaf_count,
            self.anchor_block,
            self.recorded_at_block,
            self.commitment,
        )
    }
}

impl std::error::Error for NoteNotOnChain {}

/// Classify a selected note whose leaf index is past the end of the chain's
/// tree at the anchor.
///
/// Two different conditions used to share one message, and the message was the
/// wrong one for the second. A leaf the anchor block has not folded yet is a
/// race against the block boundary and the answer is to wait; a leaf the chain
/// no longer carries never becomes foldable, and an operator following that
/// advice retries forever while `select_notes` keeps picking the same note.
/// The refusal a node whose tree is shorter than this wallet's own watermark
/// owes a spend, or `None` when it is at or ahead of every leaf read.
///
/// The honest case can never reach it. A stored `leaf_index` was read below
/// the watermark that recorded it, and a tree only grows along one chain, so
/// any head at or above that point carries at least that many leaves. What
/// trips it is a node that is behind, and the answer to that is a sync.
fn short_tree_refusal(
    leaf_count: u64,
    watermark: u64,
    block: u32,
    context: ShortTree,
) -> Option<anyhow::Error> {
    if leaf_count >= watermark {
        return None;
    }
    let ShortTree {
        read_at,
        consequence,
    } = context;
    Some(anyhow!(
        "this node's tree holds {leaf_count} leaves at {read_at}, block {block}, and this wallet \
         has already read {watermark}. A tree only grows along one chain, so a node whose tree is \
         shorter than that watermark is behind this wallet and the leaves it is missing are ones \
         it has not executed yet. {consequence} Point --node at a node that has caught up, or \
         wait for this one to."
    ))
}

/// What a caller of [`short_tree_refusal`] contributes to the sentence.
///
/// The rule is one rule and the two callers differ in two clauses: where the
/// count was read, and what that pass would have gone on to do with it. Two
/// copies of the comparison is how a sync and a spend end up disagreeing about
/// which node is short, each with a test of its own and neither crossing over.
#[derive(Debug, Clone, Copy)]
struct ShortTree {
    /// Where the count was read: the node's head for a sync, the anchor for a
    /// spend.
    read_at: &'static str,
    /// What this pass would have done against a short tree.
    consequence: &'static str,
}

/// What a sync contributes. The scan range would go empty, so the pass would
/// skip the vanished check and then write the watermark down to this node's
/// own count.
const SYNC_SHORT_TREE: ShortTree = ShortTree {
    read_at: "its head",
    consequence: "Scanning against it would walk the watermark backwards and skip the check \
                  that marks the notes the chain no longer carries. Nothing has been changed.",
};

/// What a spend contributes. Every other check it makes is against this node's
/// own answers, the rebuilt root included, so a short tree reaches the
/// write-off and marks a real, spendable note off chain.
const SPEND_SHORT_TREE: ShortTree = ShortTree {
    read_at: "the anchor",
    consequence: "The leaf indices this wallet holds cannot be checked against it. Nothing has \
                  been written off and nothing has been submitted.",
};

fn out_of_range(note: &StoredNote, leaf_count: u64, anchor_block: u32) -> anyhow::Error {
    match note.block_number {
        Some(block) if block < anchor_block => anyhow::Error::new(NoteNotOnChain {
            commitment: note.commitment.clone(),
            leaf_index: note.leaf_index,
            recorded_at_block: block,
            anchor_block,
            leaf_count,
        }),
        // The anchor has not executed the block this leaf was appended in, or
        // the store never recorded one. Both are a tree that is about to carry
        // the leaf.
        _ => anyhow!(
            "leaf {} is not folded into the tree at block {anchor_block} yet, which holds {} \
             leaves. A note cannot be minted and spent in the same block; wait one block and \
             retry.",
            note.leaf_index,
            leaf_count
        ),
    }
}

/// Where this node stands against the store, as the checkpoint walk found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeStance {
    /// On this wallet's chain and at or above every block the wallet has read.
    /// The scan runs from the watermark the store already holds.
    Current,
    /// On another branch. The newest checkpoint whose hash still stands is
    /// where the watermark and the block height both rewind to.
    Forked { at_block: u32, next_leaf: u64 },
}

impl NodeStance {
    /// The watermark the scan will start from, which is what the leaf gate has
    /// to compare the node's tree against. A fork has already taken it down to
    /// a checkpoint this node's own branch carries.
    fn watermark(self, held: u64) -> u64 {
        match self {
            Self::Current => held,
            Self::Forked { next_leaf, .. } => next_leaf,
        }
    }
}

/// What the operator asked this sync to do differently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncOptions {
    /// Drop the scan watermark to zero and walk the whole tree again, keeping
    /// every note.
    ///
    /// The recovery for a store an older build wrote. Before conflict sets,
    /// the scan refused the second note it met that shared a nullifier with
    /// one it already held, wrote that refusal into the file and never
    /// revisited it: the leaf was below the watermark from then on, so no
    /// later sync ever decrypted it again. Nothing in the store upgrade can
    /// recover the note, because the store never held its `rho` and `r`. A
    /// fresh walk of the tree does, since every note's plaintext is on chain
    /// inside its ciphertext.
    ///
    /// Keeping the notes is the difference from deleting the store: a note
    /// whose leaf the current chain no longer carries would otherwise lose its
    /// secrets, and those secrets are the only handle on a settlement that can
    /// still be re-included.
    ///
    /// It is also the operator's override on the checkpoint walk, which is
    /// what `docs/WALLET.md` has always said it was and what the code did not
    /// do: a node that diverged above its own head reads as a node that is
    /// behind, both are refused, and the rescan is the way through. The
    /// override costs the guarantees in [`RESCAN_ADD_ONLY`], and
    /// [`Wallet::sync_with`] carries the rules that bound them.
    pub rescan: bool,
}

/// What moved the scan watermark backwards: where it was, where it went, and,
/// when a fork is what moved it, the newest still-canonical block it anchored
/// that on.
#[derive(Debug, Clone, Copy)]
struct ScanRewind {
    from: u64,
    to: u64,
    /// `None` when the operator asked for the rescan, so nothing reports a
    /// fork that was not found.
    forked_at: Option<u32>,
}

#[derive(Debug)]
pub struct ShieldReport {
    /// What the note is worth, as a count of pool steps.
    pub steps: u64,
    pub commitment: String,
    /// The leaf the note actually landed at. Its existence is the proof the
    /// dispatch succeeded.
    pub leaf_index: u64,
    pub included_at: u32,
    pub inclusion: Duration,
    pub predicted_block: u32,
    pub predicted_entry_index: u64,
    pub entry_count_after: u64,
    pub entry_check: EntryRhoCheck,
}

/// What became of the entry-`rho` prediction a shield made.
///
/// The rule is `rho = H(RHO_ENTRY, block_number, entry_index)`
/// (`docs/CIRCUIT.md` section 9.8) and neither half is knowable before
/// submission: the block is the producer's choice and `EntryCount` moves with
/// every other shield. Both halves are checked afterwards against what the
/// chain assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryRhoCheck {
    /// Both halves confirmed. The block is the predicted one, the counter had
    /// not moved, and exactly one entry settled in that block, so the index
    /// the chain assigned is the predicted one.
    Confirmed,
    /// The prediction missed, and the note's `rho` does not follow the rule
    /// for the identifier the chain assigned it.
    Missed { reason: String },
    /// More than one shield settled in the inclusion block, so which index
    /// went to this note is not decidable from storage alone: only the
    /// `Shielded` event carries it, and decoding that needs the runtime's full
    /// type registry.
    Unproven { entries_in_block: u64 },
}

/// Classify a shield's entry-`rho` prediction against the chain.
///
/// Apart from the RPC so the rule can be exercised, which is what the
/// half-checked version could not be.
pub fn classify_entry_rho(
    predicted_block: u32,
    predicted_entry_index: u64,
    included_at: u32,
    entry_count_before: u64,
    entry_count_after: u64,
) -> EntryRhoCheck {
    if included_at != predicted_block {
        return EntryRhoCheck::Missed {
            reason: format!(
                "the shield was predicted to land in block {predicted_block} and landed in \
                 block {included_at}"
            ),
        };
    }
    if entry_count_before != predicted_entry_index {
        return EntryRhoCheck::Missed {
            reason: format!(
                "the entry counter stood at {predicted_entry_index} when the note was built and \
                 at {entry_count_before} when the block opened, so the chain assigned this note \
                 a different entry index"
            ),
        };
    }
    let entries_in_block = entry_count_after.saturating_sub(entry_count_before);
    match entries_in_block {
        0 => EntryRhoCheck::Missed {
            reason: "the inclusion block settled no shield entry at all".into(),
        },
        1 => EntryRhoCheck::Confirmed,
        entries => EntryRhoCheck::Unproven {
            entries_in_block: entries,
        },
    }
}

#[derive(Debug)]
pub struct SendReport {
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub inputs: Vec<u64>,
    pub anchor_block: u32,
    pub included_at: u32,
    pub proof_bytes: usize,
    pub proving: Duration,
    pub inclusion: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression: `--fee` took a count of pool steps and now takes QNR,
    /// so every `--fee 8` in a runbook, a shell history or a script resolves
    /// to a hundred times what it used to mean. An inflated fee cleared the
    /// floor, so nothing refused it: the spend proved and settled, half the
    /// fee burned and the block author took the rest.
    ///
    /// A ceiling is sound here because the pool gives every settlement the
    /// same constant priority, so a fee above the floor buys nothing at all
    /// and there is no bidding to leave room for.
    #[test]
    fn a_fee_that_runs_away_from_the_floor_is_refused() {
        // The floor for two real ciphertexts at this runtime, in pool steps.
        let floor = 8;
        assert!(!fee_runs_away(floor, floor), "the default is the floor");
        assert!(!fee_runs_away(floor * FEE_CEILING_MULTIPLE, floor));
        assert!(fee_runs_away(floor * FEE_CEILING_MULTIPLE + 1, floor));
        // `--fee 8` meant eight steps and now means eight QNR, which is the
        // hundredfold this exists to catch.
        assert!(fee_runs_away(800, floor));
        // And a floor of nothing still has a ceiling rather than refusing
        // every fee over zero.
        assert!(!fee_runs_away(FEE_CEILING_MULTIPLE, 0));
        assert!(fee_runs_away(FEE_CEILING_MULTIPLE + 1, 0));
    }

    /// The check this replaces compared `entry_rho(included_at, entry_index)`
    /// against a `rho` built from that same `entry_index`, which reduces to
    /// comparing the two block numbers. The counter half was fetched and
    /// thrown away, so a counter that moved between the read and inclusion was
    /// reported as a match, and two wallets shielding into one block both
    /// recorded the same `rho` for notes the chain gave different entry
    /// indices.
    #[test]
    fn the_entry_rule_is_checked_on_both_halves() {
        // The block matched, the counter had not moved, one entry settled.
        assert_eq!(
            classify_entry_rho(11, 7, 11, 7, 8),
            EntryRhoCheck::Confirmed
        );

        // The block missed. The counter agreeing does not save it.
        let missed = classify_entry_rho(11, 7, 12, 7, 8);
        assert!(matches!(missed, EntryRhoCheck::Missed { .. }));

        // The block matched and the counter moved under it. This is the case
        // the old check reported as a match.
        let missed = classify_entry_rho(11, 7, 11, 9, 10);
        match missed {
            EntryRhoCheck::Missed { reason } => {
                assert!(reason.contains("entry counter"), "{reason}");
            }
            other => panic!("a moved counter must be a miss, got {other:?}"),
        }

        // Two shields in one block: the counter started where the prediction
        // said, so one of the two notes holds the predicted index and storage
        // alone cannot say which.
        assert_eq!(
            classify_entry_rho(11, 7, 11, 7, 9),
            EntryRhoCheck::Unproven {
                entries_in_block: 2
            }
        );

        // A block that settled no entry at all cannot have settled this one.
        assert!(matches!(
            classify_entry_rho(11, 7, 11, 7, 7),
            EntryRhoCheck::Missed { .. }
        ));
    }

    /// The regression: every input whose leaf index sat past the end of the
    /// tree at the anchor was reported as a same-block race, with "wait one
    /// block and retry" for advice. A leaf the chain no longer carries never
    /// becomes foldable, and `select_notes` picks largest first, so an
    /// operator who took that advice retried forever against the same note.
    ///
    /// The rebuilt tree roots at the value the anchor header carries before
    /// this runs, so the tree is the chain's and its leaf count is the
    /// chain's. What is left to decide is whether the anchor has executed the
    /// block that appended the leaf.
    #[test]
    fn an_input_past_the_end_of_the_tree_is_a_race_or_a_missing_leaf() {
        let note = |block: Option<u32>| StoredNote {
            leaf_index: 9,
            block_number: block,
            value: 100,
            commitment: "ab".repeat(32),
            nullifier: "cd".repeat(32).into(),
            rho: "ef".repeat(32).into(),
            r: "01".repeat(32).into(),
            memo: String::new(),
            origin: NoteOrigin::Spend,
            spent: false,
            spent_seen_at_block: None,
            on_chain: true,
        };

        // Recorded at a block this anchor has executed: the chain does not
        // carry the leaf, and the caller is handed the fact to write down.
        let missing = out_of_range(&note(Some(11)), 8, 14);
        let missing = missing
            .downcast_ref::<NoteNotOnChain>()
            .expect("a leaf the chain does not carry is the typed error");
        assert_eq!(missing.commitment, "ab".repeat(32));
        assert_eq!(missing.leaf_index, 9);
        assert_eq!(missing.recorded_at_block, 11);
        assert_eq!(missing.anchor_block, 14);
        assert_eq!(missing.leaf_count, 8);

        // Appended in the anchor block itself: a note cannot be minted and
        // spent in the same block, so this is the race and the answer is to
        // wait.
        let racing = out_of_range(&note(Some(14)), 8, 14);
        assert!(racing.downcast_ref::<NoteNotOnChain>().is_none());
        assert!(format!("{racing:#}").contains("wait one block"));

        // Ahead of the anchor, which is a spend prepared against a node
        // behind the one the note was scanned from. Nothing is written off on
        // that.
        let ahead = out_of_range(&note(Some(20)), 8, 14);
        assert!(ahead.downcast_ref::<NoteNotOnChain>().is_none());

        // And a note whose block the store never recorded says nothing either
        // way, so it stays a race.
        let unknown = out_of_range(&note(None), 8, 14);
        assert!(unknown.downcast_ref::<NoteNotOnChain>().is_none());
        assert!(format!("{unknown:#}").contains("wait one block"));
    }

    /// The origin walk stops where the wallet says it does.
    ///
    /// Its length is `Shielded::EntryCount`, a number the node answers with,
    /// and every step is a Poseidon2 hash on the thread running the sync.
    /// Unbounded, one storage answer decides how long a scan runs. What is
    /// given up past the bound is a label: `origin` separates a shield from a
    /// spend's output in a listing and no rule selects on it.
    #[test]
    fn the_entry_walk_stops_at_the_bound() {
        // Found, so the bound is not smaller than it says.
        let last = entry_rho(7, ENTRY_WALK_LIMIT - 1);
        assert!(entry_rho_matches(7, &last, u64::MAX));

        // The first entry past the bound, offered with the largest count a
        // `u64` can carry. Without the bound this is a match.
        let past = entry_rho(7, ENTRY_WALK_LIMIT);
        assert!(!entry_rho_matches(7, &past, u64::MAX));
    }

    /// The gate that stands in front of the write-off above.
    ///
    /// Every check a spend makes about a leaf index is against the node's own
    /// answers, the rebuilt root included, so a node holding fewer leaves than
    /// this wallet has already read passes all of them and reaches the typed
    /// error `send` writes a note off on. The store's watermark is the one
    /// input that does not come from the node, and it is what separates "the
    /// chain does not carry this leaf" from "this node has not executed it
    /// yet".
    #[test]
    fn a_tree_shorter_than_the_watermark_refuses_the_spend_before_any_note_is_examined() {
        let note = StoredNote {
            leaf_index: 37,
            block_number: Some(1),
            value: 100,
            commitment: "ab".repeat(32),
            nullifier: "cd".repeat(32).into(),
            rho: "ef".repeat(32).into(),
            r: "01".repeat(32).into(),
            memo: String::new(),
            origin: NoteOrigin::Spend,
            spent: false,
            spent_seen_at_block: None,
            on_chain: true,
        };

        // A store that has read 40 leaves, against a node whose head holds 4.
        let refusal =
            short_tree_refusal(4, 40, 12, SPEND_SHORT_TREE).expect("a short tree is refused");
        let text = format!("{refusal:#}");
        assert!(text.contains("4 leaves"), "{text}");
        assert!(text.contains("already read 40"), "{text}");
        assert!(
            refusal.downcast_ref::<NoteNotOnChain>().is_none(),
            "a node that is behind is never evidence that the chain dropped a leaf"
        );

        // What it stands in front of: on the same numbers the per-note branch
        // hands `send` the error it writes the note off on.
        assert!(
            out_of_range(&note, 4, 12)
                .downcast_ref::<NoteNotOnChain>()
                .is_some(),
            "without the gate this node's answer writes off a real note"
        );

        // At the watermark and above it the gate is silent, which is every
        // honest node: leaf 37 was read below the watermark that recorded it.
        assert!(short_tree_refusal(40, 40, 12, SPEND_SHORT_TREE).is_none());
        assert!(short_tree_refusal(41, 40, 12, SPEND_SHORT_TREE).is_none());

        // One implementation, two callers. The sync's version of the same
        // refusal differs in the two clauses it passes and in nothing else,
        // and that is what keeps a sync and a spend from disagreeing about
        // which node is short.
        let sync_side = short_tree_refusal(
            4,
            40,
            12,
            ShortTree {
                read_at: "its head",
                consequence: "Nothing has been changed.",
            },
        )
        .expect("a short tree is refused on the sync path too");
        let sync_text = format!("{sync_side:#}");
        assert!(sync_text.contains("4 leaves at its head"), "{sync_text}");
        assert!(text.contains("4 leaves at the anchor"), "{text}");
    }

    /// `N` is resolved from the environment the way the pallet's build script
    /// resolves it. A wallet at a different `N` from its runtime pays the full
    /// proving cost and has its public-input length refused.
    #[test]
    fn the_leaf_slot_count_parses_the_way_the_build_script_reads_it() {
        assert_eq!(parse_leaf_proofs("6"), 6);
        assert_eq!(parse_leaf_proofs("53"), 53);
        assert_eq!(parse_leaf_proofs("1"), 1);
        if option_env!("QNERO_NUM_LEAF_PROOFS").is_none() {
            assert_eq!(
                NUM_LEAF_PROOFS,
                qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS
            );
        }
    }

    /// The private route is the default one. A default that asked the node for
    /// proofs would name every leaf this wallet spends.
    #[test]
    fn paths_are_rebuilt_locally_unless_asked_otherwise() {
        assert_eq!(MerkleSource::default(), MerkleSource::Local);
    }

    /// The regression: the payment was always output slot 0 and the change
    /// always slot 1. `ct_1` belongs to `cm_out_1` and `SlotSettled` publishes
    /// both leaf indices, so a fixed assignment tells every chain reader which
    /// of a settlement's two new leaves came back to the sender, with no key
    /// material at all.
    #[test]
    fn the_payment_takes_either_output_slot() {
        let mut rng = rand::rng();
        let mut seen = [0usize; 2];
        for _ in 0..256 {
            let slot = choose_payment_slot(&mut rng);
            assert!(slot < 2, "a leaf has two output slots, got {slot}");
            seen[slot] += 1;
        }
        assert!(
            seen[0] > 0 && seen[1] > 0,
            "the payment never moved off one slot: {seen:?}"
        );
    }

    /// The regression: `PreparedSpend` derived `Debug`, while
    /// `docs/WALLET.md` said it hand-wrote a redacting one. A
    /// `PreparedSpend` exists exactly while its nullifiers are still
    /// unpublished, so the first `dbg!` or `anyhow` context anyone added while
    /// chasing an inclusion timeout would write them, and the leaf indices
    /// this wallet owns, into a log file at the shell's umask.
    #[test]
    fn a_prepared_spend_prints_no_nullifier_and_no_leaf_index() {
        let first = Digest::hash_bytes(&[b"nullifier one"]).to_bytes();
        let second = Digest::hash_bytes(&[b"nullifier two"]).to_bytes();
        let spent = Digest::hash_bytes(&[b"a note this wallet spent"]).to_hex();
        let prepared = PreparedSpend {
            proof: vec![0u8; 150_908],
            outputs: vec![ShieldedOutput {
                ct_1: vec![1u8; 8],
                ct_2: vec![2u8; 8],
            }],
            nullifiers: [first, second],
            change_note: PendingNote {
                kind: PendingKind::Change,
                commitment: "aa".repeat(32),
                value: 699,
                rho: Digest::hash_bytes(&[b"change rho"]).to_hex().into(),
                r: Digest::hash_bytes(&[b"change r"]).to_hex().into(),
                memo: String::new(),
                submitted_at_block: 11,
                extrinsic: String::new(),
            },
            spent_nullifiers: vec![spent.as_str().into()],
            input_leaves: vec![1_068, 1_069],
            amount: 300,
            fee: 9,
            change: 699,
            anchor_block: 11,
            proving: Duration::from_secs(4),
        };

        let printed = format!("{prepared:?}");
        assert!(!printed.contains(&hex::encode(first)), "{printed}");
        assert!(!printed.contains(&hex::encode(second)), "{printed}");
        assert!(!printed.contains(&spent), "{printed}");
        assert!(!printed.contains("1068"), "a leaf index leaked: {printed}");
        assert!(
            !printed.contains(prepared.change_note.r.as_str()),
            "{printed}"
        );
        assert!(printed.contains(crate::store::REDACTED), "{printed}");
        // The lengths stay, because they are what a log line is for.
        assert!(printed.contains("150908"), "{printed}");
    }
}
