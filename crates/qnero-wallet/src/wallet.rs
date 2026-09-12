//! The wallet's operations: scan, shield, spend.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use qnero_circuit::chain::ct_digest;
use qnero_circuit::merkle::MerklePath;
use qnero_circuit::witness::{InputNote, OutputNote, SpendWitness};
use qnero_notes::{encrypt_note, entry_rho, try_receive, Address, Digest, Note, NoteCiphertext};
use qnero_notes::{IncomingViewingKey, SpendingKey};
use qnero_prover::WalletProver;
use rand::{Rng, TryRngCore};

use crate::chain::{Chain, ChainHead};
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
    NoteOrigin, PendingKind, PendingNote, RejectedNote, SecretHex, StoredNote, WalletStore,
};
use crate::POOL_QUANTUM;

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

/// How long a submission is waited on before the wallet gives up.
///
/// An unsigned settlement has `longevity(5)`: it leaves the pool after five
/// blocks and a byte-identical rebroadcast will not displace it, so the answer
/// to a timeout is to prove again against a fresh anchor.
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(120);

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

    /// Open a wallet and bind its store to the chain this node serves.
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
            let archived = archive_store(&wallet.store_path)?;
            wallet.store = WalletStore::new(wallet.key.address().encode());
            wallet.store.bind_genesis(&genesis)?;
            wallet.save()?;
            return Ok((wallet, ChainBinding::Archived(archived)));
        }
        let binding = if wallet
            .store
            .bind_genesis(&genesis)
            .with_context(|| format!("{}", wallet.store_path.display()))?
        {
            wallet.save()?;
            ChainBinding::Recorded
        } else {
            ChainBinding::Bound
        };
        Ok((wallet, binding))
    }

    pub fn address(&self) -> Address {
        self.key.address()
    }

    pub fn ivk(&self) -> IncomingViewingKey {
        self.key.incoming_viewing_key()
    }

    pub fn save(&self) -> Result<()> {
        self.store.save(&self.store_path)
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
        metadata.ensure_known_storage()?;
        // The chain this store belongs to, before anything in it is read as a
        // statement about the chain this node serves. See
        // `WalletStore::bind_genesis` and `Wallet::open_on_chain`.
        let recorded_genesis = self
            .store
            .bind_genesis(&hex::encode(chain.genesis_hash()?))
            .with_context(|| format!("{}", self.store_path.display()))?;

        let head = chain.head()?;
        // The freshness gate, and it comes before every read and every write.
        //
        // Everything this sync derives is derived from what one node answers
        // at one block: which leaves exist, which nullifiers are settled,
        // which checkpoint hashes still stand. A node behind this wallet's own
        // watermark answers all three with less than the wallet already knows,
        // and each answer is then read as a change rather than as a gap. The
        // settled set is the expensive one: `reconcile_spent` derives spent in
        // both directions, so a lagging node un-spends every note whose
        // settlement it has not seen and the next `send` selects an input the
        // chain has already consumed. The checkpoint walk is the other: every
        // checkpoint above the node's head answers with no block at all, which
        // reads as a fork and rewinds the watermark.
        //
        // A node behind the wallet is an ordinary operational state: a second
        // node, a node resyncing, a load balancer answering from a lagging
        // replica. So it is refused by name and nothing is written.
        if head.number < self.store.last_synced_block {
            bail!(
                "this node's head is block {} and this wallet has synced through block {}. A \
                 node behind the wallet answers every question with less than the wallet \
                 already knows: notes it has not seen settled would come back into the balance, \
                 and every checkpoint above its head would read as a fork. Nothing has been \
                 changed. Point --node at a node that has caught up, or wait for this one to.",
                head.number,
                self.store.last_synced_block
            );
        }
        let leaf_count = chain.leaf_count_at(&head.hash)?;
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
        // Before the watermark is read: a fork moves leaves, and the ones it
        // moves are normally below the watermark.
        let rewind = self.rewind_past_fork(chain, &head)?;
        let start = self.store.next_leaf;
        let mut report = SyncReport {
            head_block: head.number,
            scanned_from: start,
            scanned_to: leaf_count,
            rewound_from: rewind.as_ref().map(|rewind| rewind.from),
            rewound_to: rewind.as_ref().map(|rewind| rewind.to),
            forked_at_block: rewind.as_ref().map(|rewind| rewind.at_block),
            recorded_genesis,
            ..Default::default()
        };

        // Commitments this wallet already holds that the scan saw again. Only
        // collected after a rewind, which is the only time a held leaf is
        // inside the range at all, and it is what tells a note that moved
        // apart from a note whose block was orphaned and never re-included.
        let mut seen_again: BTreeSet<String> = BTreeSet::new();

        if leaf_count > start {
            let ivk = self.ivk();
            let nk = self.key.nk();
            // Read once, outside the loop. The entry counter is chain wide and
            // the whole scan is pinned to one block, so it is the same value
            // for every leaf; asking per received note was one round trip each
            // for a field that is only a label.
            let entry_count = chain.entry_count_at(&head.hash)?;
            for record in chain.leaves(start..leaf_count, &head.hash)? {
                report.leaves_scanned += 1;
                let (Some(commitment), Some(ciphertext)) = (record.commitment, record.ciphertext)
                else {
                    // A wormhole transfer leaf or a mining-reward leaf. The
                    // shielded pool shares one tree with both, so most leaf
                    // indices carry no ciphertext at all.
                    continue;
                };
                let Ok(commitment) = Digest::from_bytes(&commitment) else {
                    continue;
                };
                let Ok(parsed) = NoteCiphertext::from_bytes(&ciphertext) else {
                    continue;
                };
                let Ok(received) = try_receive(&ivk, &parsed, &commitment) else {
                    continue;
                };

                let commitment_hex = commitment.to_hex();
                if self.store.has_commitment(&commitment_hex) {
                    // Already held, and possibly not where it was. A rescan
                    // reaches this line when the fork check rewound the
                    // watermark and the leaf range was walked again, which is
                    // what an orphaned block and a re-included extrinsic look
                    // like from here. See `WalletStore::relocate_note`.
                    if rewind.is_some() {
                        seen_again.insert(commitment_hex.clone());
                    }
                    if self
                        .store
                        .relocate_note(&commitment_hex, record.index, record.block_number)
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
                        leaf_index: record.index,
                        commitment: commitment_hex,
                        nullifier: nullifier_hex.into(),
                        value: received.note.value,
                        reason: "its nullifier is already settled on chain".into(),
                    }) {
                        report.rejected += 1;
                    }
                    continue;
                }

                let origin = match record.block_number {
                    Some(block) if entry_rho_matches(block, &received.note.rho, entry_count) => {
                        NoteOrigin::Shield
                    }
                    _ => NoteOrigin::Spend,
                };
                report.received += 1;
                report.received_value += received.note.value;
                if rewind.is_some() {
                    // A note first recorded by this very scan is on the chain
                    // by construction, and the vanished count below walks
                    // every note inside the rescanned range.
                    seen_again.insert(commitment_hex.clone());
                }
                self.store.notes.push(StoredNote {
                    leaf_index: record.index,
                    block_number: record.block_number,
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
        let reconciled = self.store.reconcile_spent(head.number);
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
        if rewind.is_some() {
            report.vanished = self.store.mark_vanished(start, &seen_again);
        }

        self.store.next_leaf = leaf_count;
        self.store.last_synced_block = head.number;
        self.store
            .record_checkpoint(head.number, hex::encode(head.hash), leaf_count);
        self.save()?;
        Ok(report)
    }

    /// Rewind the scan watermark past a fork, before the range is computed.
    ///
    /// The regression this closes: a rescan repaired a note's leaf index only
    /// when the scan happened to walk that leaf again, and the scan starts at
    /// the watermark. A reorg happens because the replacement branch is
    /// heavier, so it normally carries at least as many leaves as the branch
    /// it replaced and a re-included commitment lands at or below where it
    /// was, which is below the watermark and is never re-read. The store kept
    /// a leaf index that now holds somebody else's commitment: `balance` went
    /// on reporting the note spendable, and every spend that selected it
    /// failed on the path rebuild until the JSON was edited by hand.
    ///
    /// So the fork is detected directly, through the block hashes. Each
    /// checkpoint is a block a sync finished at and the watermark it left;
    /// `chain_getBlockHash` at that height either still answers with the same
    /// hash, in which case every leaf below that watermark was folded at or
    /// before a block that is still canonical and cannot have moved, or it
    /// does not, in which case that checkpoint belongs to a branch that is
    /// gone. The walk stops at the first surviving checkpoint, so the usual
    /// cost is one call.
    ///
    /// What this deliberately does not do is re-read `ZkTree::Leaves` at each
    /// held note's recorded index. That would name this wallet's own leaves to
    /// the node, which is the property `Chain::rebuild_tree` and
    /// `Chain::used_nullifiers_at` both pay for. `chain_getBlockHash` at a
    /// height names nothing.
    ///
    /// A fork is one thing only: the node has a block at a checkpoint's height
    /// and it is a different block. No block at that height is not a fork, it
    /// is a node that does not reach that height, and this refuses rather than
    /// rewinding on it. The two used to be the same branch, which made a node
    /// lagging behind the wallet pop every checkpoint above its head and
    /// rewind the watermark to a height that node could still answer: the
    /// scan then walked leaves it had already scanned, against a leaf count
    /// smaller than the one already recorded. The freshness gate at the top of
    /// `sync` catches the case where the head itself is behind, and this
    /// catches what that cannot see, a node that answers a head it has no
    /// block history for.
    ///
    /// Nothing is written until every checkpoint has been probed, so a refusal
    /// leaves the checkpoint list exactly as it found it.
    fn rewind_past_fork(&mut self, chain: &Chain, head: &ChainHead) -> Result<Option<ForkRewind>> {
        let from = self.store.next_leaf;
        let mut dropped = 0usize;
        for checkpoint in self.store.checkpoints.iter().rev() {
            let Some(hash) = chain.block_hash_at_height(checkpoint.block_number)? else {
                bail!(
                    "this node has no block at height {}, which this wallet checkpointed while \
                     syncing, and its head is block {}. A missing block at a height a node \
                     claims to have reached is a node that is behind or pruned, and it is not a \
                     fork: a fork is a different block at that height. Rewinding on it would \
                     rescan leaves against a tree smaller than the one already recorded. \
                     Nothing has been changed.",
                    checkpoint.block_number,
                    head.number
                );
            };
            if hex::encode(hash) == checkpoint.block_hash {
                break;
            }
            // The node has a block at that height and it is a different one.
            // That checkpoint belongs to a branch that is gone.
            dropped += 1;
        }
        if dropped == 0 {
            return Ok(None);
        }
        self.store
            .checkpoints
            .truncate(self.store.checkpoints.len() - dropped);
        let (at_block, to) = match self.store.checkpoints.last() {
            Some(checkpoint) => (checkpoint.block_number, checkpoint.next_leaf),
            // Every checkpoint the wallet kept is on a branch that is gone.
            // Rescanning the whole tree is correct and slow, and it is what a
            // reorg deeper than `MAX_CHECKPOINTS` syncs costs.
            None => (0, 0),
        };
        self.store.rewind_to(at_block, to);
        Ok(Some(ForkRewind { from, to, at_block }))
    }

    /// Move transparent value into the pool as one note owned by this wallet.
    pub fn shield(
        &mut self,
        chain: &Chain,
        metadata: &ChainMetadata,
        from: &crate::dev_account::TransparentKey,
        quanta: u64,
        memo: &str,
    ) -> Result<ShieldReport> {
        // The same guard `sync` and `prepare_spend` run, and for the same
        // reason: every key below is built from a compiled-in name and a
        // compiled-in hasher, and the node validates none of them. `shield`
        // reads `Shielded::EntryCount` and then `ZkTree::LeafCount` and
        // `ZkTree::Leaves` to confirm its own leaf, and `Chain::leaf_hashes`
        // reads an absent key as an empty leaf by design. Under a drifted
        // layout the confirmation therefore finds no leaf carrying the
        // commitment and reports a shield that actually settled as a dispatch
        // that failed, dropping the pending entry that holds the note's `r` on
        // the way out. The note stays recoverable, since its plaintext is in
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
        if quanta == 0 {
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
        let note = Note::new(self.key.pk(), quanta, rho, r)?;
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

        let planck = u128::from(quanta)
            .checked_mul(POOL_QUANTUM)
            .ok_or_else(|| anyhow!("{quanta} quanta overflows the chain's balance type"))?;
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
        self.store.pending.push(PendingNote {
            kind: PendingKind::Shield,
            commitment: note.commitment().to_hex(),
            value: quanta,
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
        // `POOL_QUANTUM`, is included and then fails, appends no leaf and
        // creates no note. Reporting that as a success leaves a pending entry
        // in the store forever and an exit code of zero, and it is also what
        // would swallow a `POOL_QUANTUM` drift, which `crate::POOL_QUANTUM`
        // argues is loud precisely because `ValueNotQuantized` would surface.
        let included_hash = chain.block_hash(included_at)?;
        let parent_hash = chain.block_hash(included_at.saturating_sub(1))?;
        let commitment = note.commitment();
        let leaves_before = chain.leaf_count_at(&parent_hash)?;
        let leaves_after = chain.leaf_count_at(&included_hash)?;
        let appended = chain.leaf_hashes(leaves_before..leaves_after, &included_hash)?;
        let Some(offset) = appended.iter().position(|leaf| *leaf == commitment) else {
            self.store
                .pending
                .retain(|pending| pending.commitment != commitment.to_hex());
            self.save()?;
            bail!(
                "the shield was included in block {included_at} and its dispatch failed: no leaf \
                 in that block carries the commitment {}, so no note was created. The usual \
                 causes are a dev account that cannot pay {} planck and a value that is not a \
                 whole multiple of POOL_QUANTUM. The pending entry has been dropped.",
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
            quanta,
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
    ) -> Result<u64> {
        ensure_memo_pad_fits(metadata)?;
        let fee = self.resolve_fee(metadata, to, memo, requested_fee)?;
        let target = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow!("{amount} plus {fee} overflows"))?;
        select_notes(self.store.spendable(), target)?;
        Ok(fee)
    }

    /// The fee this submission owes, or the caller's if it clears the floor.
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
    ) -> Result<u64> {
        let (probe_payment, probe_change) = self.probe_lengths(to, memo)?;
        ensure_ciphertext_fits(metadata, probe_payment, "payment")?;
        ensure_ciphertext_fits(metadata, probe_change, "change")?;
        let floor = slot_fee_floor(metadata, probe_payment, probe_change);
        debug_assert_eq!(
            floor,
            submission_fee_floor(metadata, 1, (probe_payment + probe_change) as u64)
        );
        match requested_fee {
            None => Ok(floor),
            Some(fee) if fee < floor => bail!(
                "a fee of {fee} quanta is below this submission's floor of {floor}. The pallet \
                 asks MinLeafFee ({}) plus one quantum per started {} bytes of ciphertext, and \
                 the two outputs here are {} bytes. The fee is a public input of the proof, so \
                 it cannot be raised afterwards: the settlement would be refused with \
                 PayloadUnderpaid.",
                metadata.min_leaf_fee,
                metadata.ciphertext_bytes_per_fee_quantum,
                probe_payment + probe_change
            ),
            Some(fee) => Ok(fee),
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
        let prepared = self.prepare_spend(
            chain,
            metadata,
            prover,
            to,
            amount,
            requested_fee,
            memo,
            merkle,
        )?;
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
        let fee = self.resolve_fee(metadata, to, memo, requested_fee)?;
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
        for note in selected {
            if note.leaf_index >= tree.leaf_count() {
                bail!(
                    "leaf {} is not folded into the tree at block {anchor_block} yet. A note \
                     cannot be minted and spent in the same block; wait one block and retry.",
                    note.leaf_index
                );
            }
        }
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
        let pk = self.key.pk();
        let mut paths = Vec::with_capacity(selected.len());
        for note in selected {
            let stored = note.note(pk)?;
            let on_chain = tree
                .leaf(note.leaf_index)
                .ok_or_else(|| anyhow!("leaf {} is out of range", note.leaf_index))?;
            if on_chain != stored.commitment() {
                bail!(
                    "leaf {} holds {} on chain and this wallet holds a note committing to {}",
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
fn entry_rho_matches(block: u32, rho: &Digest, entries: u64) -> bool {
    (0..entries).any(|index| entry_rho(block, index) == *rho)
}

/// Poll blocks for the exact extrinsic that was submitted.
///
/// Matching the bytes keeps this honest about what it saw.
/// An unsigned settlement's `provides` tag is a function of the bundle, so a
/// rebroadcast of the same proof never displaces the copy already in the pool;
/// there is nothing useful to do but wait and then prove again.
fn wait_for_inclusion(chain: &Chain, extrinsic_hex: &str, from_block: u32) -> Result<u32> {
    let deadline = Instant::now() + INCLUSION_TIMEOUT;
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
                INCLUSION_TIMEOUT.as_secs(),
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
}

/// What binding a store to a node's chain did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBinding {
    /// The store already named this chain.
    Bound,
    /// The store named no chain, and now names this one. Every store written
    /// before version 5 starts here, and so does every fresh one.
    Recorded,
    /// The store named another chain and was archived at this path. The wallet
    /// carries a fresh store bound to the node's chain.
    Archived(PathBuf),
}

/// Move a store out of the way, keeping it.
///
/// Never a delete. The file holds every note's `rho` and `r`, which are the
/// only copy this wallet has of what opens its notes, and the reason it is
/// being moved may be an operator who typed the wrong `--node`.
///
/// The name carries the genesis the store was bound to, so two archives from
/// two different chains do not collide, and a counter covers the case of two
/// archives from the same one.
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

/// What a fork check found: the watermark it rewound from, the one it rewound
/// to, and the newest still-canonical block it could anchor that on.
#[derive(Debug, Clone, Copy)]
struct ForkRewind {
    from: u64,
    to: u64,
    at_block: u32,
}

#[derive(Debug)]
pub struct ShieldReport {
    pub quanta: u64,
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
