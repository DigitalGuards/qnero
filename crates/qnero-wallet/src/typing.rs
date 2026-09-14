//! What kind of note a leaf holds, decided from data the header authenticates.
//!
//! A leaf is a coinbase or it is a transfer, and the two are opened by
//! different rules: a coinbase is rebuilt from the miner key and the public
//! value the chain hashed into its commitment, a transfer is trial-decrypted
//! from the ciphertext beside it. Getting the kind wrong is silent. The wrong
//! rule simply does not open the leaf, the scan reads it as somebody else's,
//! and the pass then commits a watermark above it, so nothing looks at that
//! leaf again without a rescan.
//!
//! **The kind is never decided by which storage keys a node chose to answer.**
//! Presence of `Shielded::CoinbaseValues` used to be the whole test, and
//! presence is the node's to write: eight invented bytes at an incoming
//! transfer leaf sent it down the coinbase rebuild and hid the payment, and an
//! invented `Shielded::Ciphertexts` beside a withheld coinbase value hid a
//! mined reward the other way round.
//!
//! What decides instead is position, and position is what the block headers
//! commit to:
//!
//! 1. The header chain. Every header in the range is fetched by the hash its
//!    child names and rehashed from its own preimage, down to a hash the
//!    wallet already trusts ([`crate::chain::Chain::header_chain`]).
//! 2. The leaf range of each block. Leaves are folded into the tree once per
//!    block, in `pallet-zk-tree`'s `on_finalize`, and the root of that fold is
//!    the header's `zkTreeRoot`. So appending the leaves a node attributes to
//!    block `N` and comparing the root against that block's header is what
//!    makes the block's leaf range a fact rather than a claim.
//!    `Shielded::LeafBlocks` is the claim, and it is checked against this.
//!
//!    **The fold pins a block's leaf set, and it pins the count only together
//!    with the pad rule below it.** `TreeFrontier` fills the slots above the
//!    last leaf with `empty_digest()`, so pushing explicit all-zero leaves
//!    reaches the root a fold that stopped short reaches, inside one depth. A
//!    node could therefore answer a `ZkTree::LeafCount` above the one its own
//!    headers folded, hand over pads to make up the difference, and pass every
//!    root comparison. What closes it is that the pad is not a leaf any chain
//!    can hold: `pallet-zk-tree::insert_commitment` refuses an append of the
//!    all-zero digest by name and reads it as an unfilled slot everywhere
//!    else, so a leaf equal to it below the reported count is refused here and
//!    in `crate::chain::Chain::leaf_window`, and the count is a fact again.
//! 3. The coinbase position. `pallet-mining-rewards`' `on_finalize` mints the
//!    coinbase through `CoinbaseSink`, at pallet index 6, where every shield
//!    and every settled output was appended during extrinsic execution and
//!    `ZkTree` folds at index 21. So a block's coinbase, when it mints one, is
//!    the **last** leaf that block appended, and the only leaf index a
//!    coinbase can occupy is `leaf_count_at(N) - 1`.
//!
//! # No rule rests on the author label
//!
//! `qnero_note_core::MinerKey::author_label` is
//! `H("qnero/author-label", cvk, parent_hash)`, the node publishes it in the
//! block's pre-runtime digest item, and the header hash commits to it. That
//! makes it unforgeable **relative to a header this wallet already trusts**,
//! and nothing more. These wallets verify no proof of work and will not in v1,
//! so above the newest checkpoint every header field is the node's to invent,
//! the label included. A rule that asked for a key only on blocks whose label
//! says "this wallet's" was a rule the node switched off by publishing any
//! other label.
//!
//! So the rules below are label free, and they are per position:
//!
//! - At **every** coinbase position `Shielded::CoinbaseValues` is required,
//!   exactly eight bytes, whatever the label says. `pallet-shielded` writes it
//!   in the same call that appends the leaf, so an absent one is an answer
//!   withheld.
//! - At **every** coinbase position this wallet rebuilds its own coinbase note
//!   from `cvk`, the block number and that value, and compares it against the
//!   tree-authenticated leaf. A match makes the reward this wallet's, even
//!   when a node omits or forges the label of the block that minted it.
//! - The label is then a **cross-check** and decides nothing on its own. A
//!   label that says this wallet's over a rebuild that does not match refuses
//!   the pass by name: only the holder of `cvk` can produce that label for
//!   that parent, so on a block carrying it the value is the chain's and a
//!   wrong one is a node answering something the chain never wrote. The other
//!   direction is counted rather than refused: a rebuild that matches under a
//!   label that says another author's is still this wallet's note, because
//!   only `cvk` derives the `r` inside that commitment, and refusing there
//!   would hide the very reward the rule exists to find and hand a node a
//!   whole-sync refusal for the price of one forged header field. The pass
//!   takes the reward and reports the disagreement, which
//!   `SyncReport::coinbase_label_disagreed` counts and the CLI prints.
//! - A ciphertext at a coinbase position is still trial-decrypted. Under v1 a
//!   coinbase carries none, so one there is either an encrypted coinbase or a
//!   leaf that is not a coinbase at all.
//! - At **every** other position `Shielded::Ciphertexts` is required and
//!   trial-decrypted, and a `Shielded::CoinbaseValues` there refuses by name.
//!
//! `docs/WALLET.md`, under "What a lying node can and cannot do", carries the
//! bound these rules actually hold to and the fork walk that is the defence
//! above the newest checkpoint.
//!
//! The one thing a block can do that this does not pin is mint no coinbase at
//! all. `pallet-shielded::mint_coinbase` refuses a credit below one pool
//! quantum, so a block whose emission plus fees round to nothing appends no
//! coinbase leaf, and its last leaf would then be an ordinary shield or
//! settled output with no value beside it. That is unreachable until the
//! emission itself has rounded away at the supply cap, and until then the
//! required value above is what says a withheld one out loud.

use anyhow::{bail, Result};
use qnero_circuit::merkle::{empty_digest, TreeFrontier};
use qnero_notes::{Digest, MinerKey};

use crate::chain::{LeafRecord, VerifiedBlock};

/// Which rule opens a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// Below its block's last leaf, so it cannot be a coinbase: a shield or a
    /// settled output, opened by trial decryption.
    Transfer,
    /// The coinbase position of its block, with the value the chain published.
    ///
    /// `ours` is set by the **rebuild**: this wallet's own coinbase note for
    /// that block at that value is the commitment the tree holds. The author
    /// label is a cross-check and never a selector, and
    /// `label_disagrees` is set when the rebuild claimed the reward over a
    /// header whose label says another author's.
    Coinbase {
        ours: bool,
        value: u64,
        label_disagrees: bool,
    },
}

/// One leaf, typed, with the commitment the tree authenticates.
#[derive(Debug, Clone)]
pub struct TypedLeaf {
    pub index: u64,
    pub commitment: Digest,
    pub block_number: u32,
    pub kind: LeafKind,
}

/// What the walk needs of the wallet: its own author label and its own
/// coinbase commitments.
pub struct MinerView<'a> {
    pub key: &'a MinerKey,
    pub genesis_hash: &'a [u8; 32],
}

impl MinerView<'_> {
    fn label(&self, parent_hash: &[u8; 32]) -> [u8; 32] {
        self.key.author_label(parent_hash).to_bytes()
    }

    fn coinbase_commitment(&self, block_number: u32, value: u64) -> Option<Digest> {
        self.key
            .coinbase_note(self.genesis_hash, block_number, value)
            .ok()
            .map(|note| note.commitment())
    }
}

/// The fold the chunked walk climbs with, seeded from the leaves below the
/// watermark.
///
/// `anchor` is the block the walk stands on: one whose hash the caller has
/// already compared against something it trusts. `prefix` is every leaf hash
/// below `anchor_count`, in index order, and the anchor's own `zkTreeRoot` is
/// what makes those a fact rather than a list of answers.
pub fn seed_frontier(
    anchor: &VerifiedBlock,
    anchor_count: u64,
    prefix: &[Digest],
) -> Result<TreeFrontier> {
    if prefix.len() as u64 != anchor_count {
        bail!(
            "the leaf prefix carries {} hashes where the anchor block {} ended on {anchor_count} \
             leaves",
            prefix.len(),
            anchor.number
        );
    }
    let mut frontier = TreeFrontier::new();
    for leaf in prefix {
        frontier.push(*leaf);
    }
    if frontier.root()? != anchor.zk_tree_root {
        bail!(
            "the {anchor_count} leaves this node answered below the watermark do not hash to the \
             zkTreeRoot in the header of block {}, which is {}. The tree is folded once per block \
             and the header carries that fold, so a leaf range that roots elsewhere is a node \
             answering with leaves this chain does not hold. Nothing has been changed.",
            anchor.number,
            anchor.zk_tree_root.to_hex()
        );
    }
    Ok(frontier)
}

/// Type one chunk of the walk: the blocks above `blocks[0]`, and the leaves a
/// node dates to them.
///
/// `blocks` is one chunk of the header walk in ascending order, `blocks[0]`
/// being the chunk's anchor: a block already authenticated, either by the
/// caller's trusted hash or by being the previous chunk's top. `scanned` is
/// every leaf this chunk claims, in index order, starting where the previous
/// chunk stopped.
///
/// Every refusal names the rule it broke and leaves the caller's store
/// untouched, because nothing here writes anything.
pub fn type_chunk(
    frontier: &mut TreeFrontier,
    blocks: &[VerifiedBlock],
    scanned: &[LeafRecord],
    miner: &MinerView<'_>,
) -> Result<Vec<TypedLeaf>> {
    let Some(anchor) = blocks.first() else {
        bail!("a leaf typing pass was handed no blocks at all");
    };
    // The chunk starts where the last one stopped, so the fold that reaches
    // this chunk's anchor is the one the anchor's own header published. For
    // the first chunk this is the watermark check itself; for every chunk
    // after it, it is the check that the walk climbed in one piece.
    if frontier.root()? != anchor.zk_tree_root {
        bail!(
            "the {} leaves this walk has folded do not hash to the zkTreeRoot in the header of \
             block {}, which is {}. The tree is folded once per block and the header carries that \
             fold, so a leaf range that roots elsewhere is a node answering with leaves this \
             chain does not hold. Nothing has been changed.",
            frontier.count(),
            anchor.number,
            anchor.zk_tree_root.to_hex()
        );
    }

    let mut typed = Vec::with_capacity(scanned.len());
    // Parsed once, in the fold, and indexed afterwards. The per-position pass
    // below used to reparse each commitment and fall back to a placeholder
    // digest on a failure, which only ever stayed dead because the fold
    // refuses first: a reorder of the two loops made the placeholder live, and
    // a leaf typed against a digest nothing published is a leaf nobody can
    // open.
    let mut folded: Vec<Digest> = Vec::with_capacity(scanned.len());
    let mut cursor = 0usize;
    for (offset, block) in blocks.iter().enumerate().skip(1) {
        let parent = &blocks[offset - 1];
        if block.parent_hash != parent.hash {
            bail!(
                "block {}'s header names a parent this walk did not reach",
                block.number
            );
        }
        let run_start = cursor;
        while cursor < scanned.len() && scanned[cursor].block_number == Some(block.number) {
            cursor += 1;
        }
        for record in &scanned[run_start..cursor] {
            let Some(bytes) = record.commitment else {
                bail!(
                    "leaf {} carries no commitment at a point the caller has already refused an \
                     absent one",
                    record.index
                );
            };
            let commitment = Digest::from_bytes(&bytes).map_err(|_| {
                anyhow::anyhow!(
                    "ZkTree::Leaves({}) is not a canonical digest, so this wallet cannot fold it \
                     into the tree the chain published",
                    record.index
                )
            })?;
            // The tree's own pad, at an index the node's own count says the
            // chain appended. `pallet-zk-tree::insert_commitment` refuses an
            // append of the all-zero digest by name (`ZeroCommitment`) and
            // reads it as an unfilled slot everywhere else, so below the count
            // it is a leaf this chain never wrote. It is refused here and not
            // only in the read layer because folding it is what makes it
            // invisible: a pad pushed into the frontier reaches the same root
            // as a fold that stopped short, so a run of pads at the top of the
            // tree matches every root the headers carry while the count is
            // higher than the chain's, and the pass would write a watermark
            // above indices no block has filled. The real leaves that land
            // there afterwards are below the watermark and never read.
            if commitment == empty_digest() {
                bail!(
                    "this node answered ZkTree::Leaves({}) with the all-zero digest and dates it \
                     to block {}, whose header is {}. That digest is the tree's own pad for an \
                     unfilled slot and `pallet-zk-tree` refuses an append of it, so a leaf the \
                     count claims and the pad fills is a leaf this chain never appended. Folding \
                     it moves no root, which is what makes it a way to inflate the leaf count \
                     under honest headers, and the watermark would go above indices the chain \
                     has not filled. Nothing has been changed.",
                    record.index,
                    block.number,
                    hex::encode(block.hash)
                );
            }
            folded.push(commitment);
            frontier.push(commitment);
        }
        if frontier.root()? != block.zk_tree_root {
            bail!(
                "this node dates {} leaves to block {}, and folding exactly those into the tree \
                 does not reach the zkTreeRoot its header carries ({}). Shielded::LeafBlocks is \
                 what proposes a block's leaf range and the header is what settles it, so a \
                 disagreement is a node moving leaves between blocks, which is what decides where \
                 a coinbase sits. Nothing has been changed.",
                cursor - run_start,
                block.number,
                block.zk_tree_root.to_hex()
            );
        }

        let label_says_ours = block.author_label == Some(miner.label(&parent.hash));
        for (position, record) in scanned[run_start..cursor].iter().enumerate() {
            let is_last = run_start + position + 1 == cursor;
            let commitment = *folded.get(run_start + position).ok_or_else(|| {
                anyhow::anyhow!(
                    "the fold and the typing pass disagree about how many leaves block {} \
                     appended, at leaf {}",
                    block.number,
                    record.index
                )
            })?;
            let kind = if is_last {
                coinbase_position_kind(record, block.number, label_says_ours, &commitment, miner)?
            } else {
                below_the_coinbase_kind(record, block.number)?
            };
            typed.push(TypedLeaf {
                index: record.index,
                commitment,
                block_number: block.number,
                kind,
            });
        }
    }

    if cursor != scanned.len() {
        let stray = &scanned[cursor];
        bail!(
            "Shielded::LeafBlocks dates leaf {} to block {:?}, which is not where the header walk \
             puts it. Leaves are appended in block order and this chunk walked blocks {} to {}, \
             so a leaf that no block's range claims is a node disagreeing with the headers about \
             which block appended it. Nothing has been changed.",
            stray.index,
            stray.block_number,
            anchor.number,
            blocks[blocks.len() - 1].number
        );
    }
    Ok(typed)
}

/// A chunk over a range that appended nothing.
///
/// The walk still has to happen: the checkpoint this pass records has to be a
/// head it authenticated, and a pass that fetched no header authenticated
/// nothing. What it cannot do is fold, because seeding the frontier means
/// reading every leaf below the watermark and there is no new leaf to check
/// against it. The fold is not needed either: with no leaf appended between
/// the anchor and the top, every header in the chunk must carry the anchor's
/// own `zkTreeRoot`, and a node claiming an unchanged leaf count over a range
/// whose roots moved is refused right here.
pub fn check_chunk_appended_nothing(blocks: &[VerifiedBlock]) -> Result<()> {
    let Some(anchor) = blocks.first() else {
        bail!("a leaf typing pass was handed no blocks at all");
    };
    for (offset, block) in blocks.iter().enumerate().skip(1) {
        let parent = &blocks[offset - 1];
        if block.parent_hash != parent.hash {
            bail!(
                "block {}'s header names a parent this walk did not reach",
                block.number
            );
        }
        if block.zk_tree_root != anchor.zk_tree_root {
            bail!(
                "this node reports the same leaf count at block {} as at block {}, and their \
                 headers carry different commitment-tree roots ({} against {}). The tree is \
                 folded once per block and only ever grows, so a moved root over an unchanged \
                 count is a node answering a leaf count its own headers do not carry. Nothing \
                 has been changed.",
                block.number,
                anchor.number,
                block.zk_tree_root.to_hex(),
                anchor.zk_tree_root.to_hex()
            );
        }
    }
    Ok(())
}

/// A leaf below its block's last: a coinbase cannot sit here.
fn below_the_coinbase_kind(record: &LeafRecord, block_number: u32) -> Result<LeafKind> {
    if record.coinbase_value.is_some() {
        bail!(
            "this node answered a Shielded::CoinbaseValues for leaf {}, which is not the last \
             leaf block {block_number} appended. A block's coinbase is minted in on_finalize, \
             after every shield and every settled output, so it is always that block's last leaf. \
             A coinbase value anywhere else is an answer the chain never wrote, and taking it \
             would send a payment down the coinbase rebuild, which cannot open it. Nothing has \
             been changed.",
            record.index
        );
    }
    if record.ciphertext.is_none() {
        bail!(
            "this node answered with no Shielded::Ciphertexts for leaf {}, which the headers put \
             below the last leaf of block {block_number} and so cannot be a coinbase. Every \
             shield and every settled output stores its ciphertext in the call that appends the \
             leaf and nothing removes it, so an absent one there is an answer withheld. Reading \
             it as a leaf nobody can open would skip a payment and write a watermark above it. \
             Nothing has been changed.",
            record.index
        );
    }
    Ok(LeafKind::Transfer)
}

/// The one leaf index of a block a coinbase can occupy.
///
/// Label free in both directions. The value is required here whatever the
/// header's author label says, this wallet's own coinbase note is rebuilt here
/// whatever it says, and the label is compared against the rebuild afterwards
/// so that a disagreement is said out loud rather than deciding anything.
fn coinbase_position_kind(
    record: &LeafRecord,
    block_number: u32,
    label_says_ours: bool,
    commitment: &Digest,
    miner: &MinerView<'_>,
) -> Result<LeafKind> {
    let Some(value) = record.coinbase_value else {
        bail!(
            "this node answered with no Shielded::CoinbaseValues for leaf {}, the last leaf of \
             block {block_number} and the one leaf index that block's coinbase can occupy. The \
             value is public and `pallet-shielded` writes it in the same call that appends the \
             leaf, so an absent one is an answer withheld, and a scan that stepped over it would \
             drop whatever sat on that leaf behind a watermark. The value is required at every \
             coinbase position whatever the author label says: this wallet verifies no proof of \
             work, so above its newest checkpoint a node chooses every header field, the label \
             included, and a rule that asked for the value only under this wallet's own label \
             was one the node switched off by publishing another. Nothing has been changed.",
            record.index
        );
    };
    let rebuilt = miner.coinbase_commitment(block_number, value);
    let ours = rebuilt.as_ref() == Some(commitment);
    if label_says_ours && !ours {
        let rebuilt = rebuilt
            .map(|digest| digest.to_hex())
            .unwrap_or_else(|| "no coinbase note at all".to_string());
        bail!(
            "block {block_number} carries this wallet's own author label and this node answered \
             {value} quanta for its coinbase at leaf {}, which rebuilds to {rebuilt} where the \
             tree holds {}. The value is the one field of a coinbase note the chain decides, and \
             a wrong one reads the wallet's own reward as nobody's. Nothing has been changed.",
            record.index,
            commitment.to_hex()
        );
    }
    // The other direction is counted. The commitment the tree
    // holds is `H(CM, H(NOTE, pk, rho, r), value)` over an `r` derived from
    // this wallet's own `cvk`, so a leaf the rebuild opens is this wallet's
    // note whatever the header beside it says, and it is spendable with the
    // `ask` this wallet holds. Refusing here would leave the reward behind and
    // stop every later pass as well, which is a whole-sync denial for the
    // price of one forged header field. So the reward is taken and the
    // disagreement is reported: see `SyncReport::coinbase_label_disagreed`.
    Ok(LeafKind::Coinbase {
        ours,
        value,
        label_disagrees: ours && !label_says_ours,
    })
}
