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
//! What decides instead is what the block headers commit to:
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
//! 3. The coinbase position. `pallet-mining-rewards`' `on_finalize` mints the
//!    coinbase through `CoinbaseSink`, at pallet index 6, where every shield
//!    and every settled output was appended during extrinsic execution and
//!    `ZkTree` folds at index 21. So a block's coinbase, when it mints one, is
//!    the **last** leaf that block appended, and the only leaf index a
//!    coinbase can occupy is `leaf_count_at(N) - 1`.
//! 4. Whose block it is. `qnero_note_core::MinerKey::author_label` is
//!    `H("qnero/author-label", cvk, parent_hash)` and the node publishes it in
//!    the block's pre-runtime digest item, which the header hash commits to.
//!    `cvk` is the miner's secret, so no node can present this wallet's block
//!    as somebody else's or the other way round.
//!
//! The one thing a block can do that this does not pin is mint no coinbase at
//! all. `pallet-shielded::mint_coinbase` refuses a credit below one pool
//! quantum, so a block whose emission plus fees round to nothing appends no
//! coinbase leaf, and its last leaf is an ordinary shield or settled output.
//! That is unreachable until the emission itself has rounded away at the
//! supply cap. Until then the rule below asks for a coinbase value at the
//! coinbase position of a block **this wallet mined**, and says so by name
//! when a node does not answer one.

use anyhow::{bail, Result};
use qnero_circuit::merkle::TreeFrontier;
use qnero_notes::{Digest, MinerKey};

use crate::chain::{LeafRecord, VerifiedBlock};

/// Which rule opens a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// Below its block's last leaf, so it cannot be a coinbase: a shield or a
    /// settled output, opened by trial decryption.
    Transfer,
    /// The coinbase position of its block, with the value the chain published.
    /// `ours` is set when the block's author label is this wallet's, and then
    /// the value has already been checked against the authenticated
    /// commitment.
    Coinbase { ours: bool, value: u64 },
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

/// Type every scanned leaf against the authenticated block ranges.
///
/// `blocks` is the header walk in ascending order, `blocks[0]` being the
/// anchor: a block whose hash the caller has already compared against
/// something it trusts, and whose `zkTreeRoot` is what `prefix` is checked
/// against. `prefix` is every leaf hash below `anchor_count`, in index order,
/// and `scanned` is every leaf from `anchor_count` up to the count the pass
/// read, in index order.
///
/// Every refusal names the rule it broke and leaves the caller's store
/// untouched, because nothing here writes anything.
pub fn type_leaves(
    blocks: &[VerifiedBlock],
    anchor_count: u64,
    prefix: &[Digest],
    scanned: &[LeafRecord],
    leaf_count: u64,
    miner: &MinerView<'_>,
) -> Result<Vec<TypedLeaf>> {
    let Some(anchor) = blocks.first() else {
        bail!("a leaf typing pass was handed no blocks at all");
    };
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

    let mut typed = Vec::with_capacity(scanned.len());
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

        let ours = block.author_label == Some(miner.label(&parent.hash));
        for (position, record) in scanned[run_start..cursor].iter().enumerate() {
            let is_last = run_start + position + 1 == cursor;
            let commitment = Digest::from_bytes(&record.commitment.unwrap_or_default())
                .unwrap_or_else(|_| Digest::hash_bytes(&[b"unreachable"]));
            let kind = if is_last {
                coinbase_position_kind(record, block.number, ours, &commitment, miner)?
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
             puts it. Leaves are appended in block order and this pass walked blocks {} to {}, so \
             a leaf that no block's range claims is a node disagreeing with the headers about \
             which block appended it. Nothing has been changed.",
            stray.index,
            stray.block_number,
            anchor.number,
            blocks[blocks.len() - 1].number
        );
    }
    if frontier.count() != leaf_count {
        bail!(
            "the blocks this pass walked account for {} leaves where this node reports \
             {leaf_count} at the same block. Nothing has been changed.",
            frontier.count()
        );
    }
    Ok(typed)
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
fn coinbase_position_kind(
    record: &LeafRecord,
    block_number: u32,
    ours: bool,
    commitment: &Digest,
    miner: &MinerView<'_>,
) -> Result<LeafKind> {
    match record.coinbase_value {
        Some(value) if ours => {
            let rebuilt = miner
                .coinbase_commitment(block_number, value)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                    "this wallet's miner key derives no coinbase note for block {block_number} at \
                     {value} quanta, so leaf {} cannot be checked. Nothing has been changed.",
                    record.index
                )
                })?;
            if rebuilt != *commitment {
                bail!(
                    "block {block_number} carries this wallet's own author label and this node \
                     answered {value} quanta for its coinbase at leaf {}, which rebuilds to {} \
                     where the tree holds {}. The value is the one field of a coinbase note the \
                     chain decides, and a wrong one reads the wallet's own reward as nobody's. \
                     Nothing has been changed.",
                    record.index,
                    rebuilt.to_hex(),
                    commitment.to_hex()
                );
            }
            Ok(LeafKind::Coinbase { ours: true, value })
        }
        Some(value) => Ok(LeafKind::Coinbase { ours: false, value }),
        None if ours => bail!(
            "block {block_number} carries this wallet's own author label and this node answered \
             with no Shielded::CoinbaseValues for leaf {}, the one leaf index that block's \
             coinbase can occupy. The value is public and `pallet-shielded` writes it in the same \
             call that appends the leaf, so an absent one is an answer withheld, and a scan that \
             stepped over it would drop a mined reward behind a watermark. A block mints no \
             coinbase only once its emission and fees together fall below one pool quantum, which \
             is the supply cap. Nothing has been changed.",
            record.index
        ),
        None if record.ciphertext.is_some() => Ok(LeafKind::Transfer),
        None => bail!(
            "this node answered leaf {} with neither a Shielded::Ciphertexts nor a \
             Shielded::CoinbaseValues, at the last leaf of block {block_number}. One of the two \
             is there on every leaf the chain appends, so answering neither hides whichever it \
             was. Nothing has been changed.",
            record.index
        ),
    }
}
