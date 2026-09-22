//! Reads of chain state: headers, the commitment tree, nullifiers, and the
//! block bodies that carry the note ciphertexts.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use codec::Decode;
use qnero_circuit::chain::MAX_TREE_DEPTH;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::{empty_digest, CommitmentTree, MerklePath, SIBLINGS_PER_LEVEL};
use qnero_notes::Digest;
use qnero_state_proof::{MAX_BODY_BYTES, MAX_BODY_EXTRINSICS};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::metadata::{SHIELDED_PALLET, ZK_TREE_PALLET};
use crate::rpc::{decode_hash, decode_hex, decode_u32_hex, hex_0x, RpcClient, RpcError};
use crate::scale::{blake2_128_concat_map_key, identity_map_key, storage_prefix};

/// The chain head, and the hash every read of one sync pass is pinned to.
#[derive(Debug, Clone)]
pub struct ChainHead {
    pub number: u32,
    pub hash: [u8; 32],
}

/// A header exactly as `chain_getHeader` returns it.
///
/// Parsed by hand. `qp_header::Header` carries `zkTreeRoot` between
/// `extrinsicsRoot` and `digest`, which no generic Substrate header type has,
/// and that field is the anchor of every spend proof.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawHeader {
    pub parent_hash: String,
    pub number: String,
    pub state_root: String,
    pub extrinsics_root: String,
    pub zk_tree_root: String,
    pub digest: RawDigest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RawDigest {
    pub logs: Vec<String>,
}

impl RawHeader {
    pub fn block_number(&self) -> Result<u32> {
        decode_u32_hex(&self.number)
    }

    /// The 110 bytes of digest logs the header hash commits to.
    ///
    /// `chain_getHeader` hands over one hex string per `DigestItem`, each the
    /// SCALE encoding of that item. The chain hashes the `Digest` struct's own
    /// encoding, `compact(len) ++ concat(items)`, zero padded or truncated to
    /// `DIGEST_LOGS_SIZE` (`chain/primitives/header/src/lib.rs`). A sealed
    /// header encodes to exactly 110 with no slack; the padding is here so
    /// that a header which does not is still hashed the way the chain hashes
    /// it. A length check here would refuse what the chain accepts.
    pub fn digest_bytes(&self) -> Result<[u8; DIGEST_LOGS_SIZE]> {
        let mut encoded = crate::scale::compact_len(self.digest.logs.len());
        for log in &self.digest.logs {
            encoded.extend_from_slice(&decode_hex(log)?);
        }
        let mut padded = [0u8; DIGEST_LOGS_SIZE];
        let taken = encoded.len().min(DIGEST_LOGS_SIZE);
        padded[..taken].copy_from_slice(&encoded[..taken]);
        Ok(padded)
    }

    /// The 32 bytes of the block author's label, out of the pre-runtime
    /// digest item consensus puts there.
    ///
    /// The item is `DigestItem::PreRuntime(POW_ENGINE_ID, label)` and the
    /// label is `qnero_note_core::MinerKey::author_label(parent_hash)`, which
    /// is `H("qnero/author-label", cvk, parent_hash)`. `cvk` is the miner's
    /// secret, so nobody can compute another wallet's label and no wallet's
    /// blocks can be grouped by a reader; the wallet that holds the key
    /// recomputes its own and compares.
    ///
    /// The header's hash commits to the digest, so this is authenticated by
    /// the same recomputation that authenticates the rest of the header, and
    /// that is all it is: unforgeable **relative to a header this wallet
    /// already trusts**. This wallet verifies no proof of work, so above its
    /// newest checkpoint a node picks every header field including this one,
    /// and no rule rests on the label alone. `crate::typing` uses it as a
    /// cross-check against the coinbase note it rebuilds itself, and
    /// `docs/WALLET.md` carries the bound under "What a lying node can and
    /// cannot do".
    ///
    /// `None` when there is no such item, which is a block no Qnero node
    /// built.
    pub fn author_label(&self) -> Result<Option<[u8; 32]>> {
        for log in &self.digest.logs {
            let bytes = decode_hex(log)?;
            // `PreRuntime` is variant 6, then four bytes of engine id, then a
            // `Vec<u8>` with its compact length prefix.
            let Some(rest) = bytes.strip_prefix(&[PRE_RUNTIME_VARIANT]) else {
                continue;
            };
            let Some(rest) = rest.strip_prefix(&POW_ENGINE_ID) else {
                continue;
            };
            let mut cursor = rest;
            let Ok(payload) = Vec::<u8>::decode(&mut cursor) else {
                continue;
            };
            if !cursor.is_empty() {
                continue;
            }
            // A pre-runtime item of the right shape whose payload is not 32
            // bytes is not this consensus engine's label, so the scan carries
            // on rather than answering `None` for the whole header. Returning
            // there made the first shape-matching item the only one that could
            // ever answer, where `wallet-web`'s `authorLabelFromHeader` keeps
            // scanning, and the two wallets then read one header two ways.
            // `tests/leaf_typing.rs` holds them to the same fixture.
            let Ok(label) = <[u8; 32]>::try_from(payload.as_slice()) else {
                continue;
            };
            return Ok(Some(label));
        }
        Ok(None)
    }

    /// The circuit's view of this header.
    ///
    /// `parent_hash` and `zk_tree_root` are Poseidon2 outputs and take the
    /// strict decode; `state_root` and `extrinsics_root` are Blake2-256 and go
    /// in as raw bytes, because the chain reduces them mod p and validates
    /// neither.
    pub fn to_header_inputs(&self) -> Result<HeaderInputs> {
        let parent_hash = Digest::from_bytes(&decode_hash(&self.parent_hash)?)
            .map_err(|_| anyhow!("the header's parentHash is not a canonical digest"))?;
        let zk_tree_root = Digest::from_bytes(&decode_hash(&self.zk_tree_root)?)
            .map_err(|_| anyhow!("the header's zkTreeRoot is not a canonical digest"))?;
        HeaderInputs::new(
            parent_hash,
            self.block_number()?,
            decode_hash(&self.state_root)?,
            decode_hash(&self.extrinsics_root)?,
            zk_tree_root,
            &self.digest_bytes()?,
        )
    }
}

/// A Merkle proof exactly as `zkTree_getMerkleProof` returns it: byte arrays
/// as JSON arrays of numbers, siblings in child-index order with no position.
#[derive(Debug, Clone, Deserialize)]
pub struct RawMerkleProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    pub siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
    pub root: [u8; 32],
    pub depth: u8,
}

/// One input note's path, converted into the shape the circuit consumes.
#[derive(Debug)]
pub struct ChainMerklePath {
    pub path: MerklePath,
    pub root: Digest,
}

/// Whether this node answers `chain_getBlockHash` over a list of numbers, as
/// far as this command knows.
///
/// The same three states and the same reason as
/// [`BatchSupport`](crate::rpc::BatchSupport): asked once by asking, and then
/// remembered. A walk pages the heights, so a node that will not answer a list
/// would otherwise be probed once per page of every chunk of every sync, each
/// probe a wasted round trip.
///
/// `Refused` is only ever what a node **answered**: a hash where a list was
/// asked for, a list of the wrong length, or a JSON-RPC error. A request that
/// did not complete leaves this `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListSupport {
    Unknown,
    Taken,
    Refused,
}

pub struct Chain<'a> {
    pub rpc: &'a RpcClient,
    hash_lists: std::cell::Cell<ListSupport>,
}

impl<'a> Chain<'a> {
    pub fn new(rpc: &'a RpcClient) -> Self {
        Self {
            rpc,
            hash_lists: std::cell::Cell::new(ListSupport::Unknown),
        }
    }

    /// What this command has learned about `chain_getBlockHash` over a list.
    pub fn list_support(&self) -> ListSupport {
        self.hash_lists.get()
    }

    pub fn head(&self) -> Result<ChainHead> {
        let header: RawHeader = self.rpc.call_as("chain_getHeader", json!([]))?;
        let number = header.block_number()?;
        Ok(ChainHead {
            number,
            hash: self.block_hash(number)?,
        })
    }

    /// The canonical hash at a height, or `None` when this node has no block
    /// there.
    ///
    /// Apart from [`Chain::block_hash`] because `None` is an ordinary answer
    /// for the checkpoint walk and not an error. What it is not is a fork. A
    /// fork is a *different* hash at a height this wallet checkpointed; no
    /// hash at all is a node that has not reached that height, or that is
    /// pruned or has not filled in behind its own head. `Wallet::sync` reads
    /// the two apart: a height above the node's head is skipped and decided by
    /// the first checkpoint the node can answer for, and a missing block below
    /// its own head is refused by name.
    pub fn block_hash_at_height(&self, number: u32) -> Result<Option<[u8; 32]>> {
        let hash: Option<String> = self
            .rpc
            .call_as("chain_getBlockHash", json!([number]))
            .with_context(|| format!("no block hash at height {number}"))?;
        hash.as_deref().map(decode_hash).transpose()
    }

    /// The canonical hashes at a list of heights, in the order asked for.
    ///
    /// `chain_getBlockHash` takes a list of numbers and answers a list of
    /// hashes, which is what turns the hash half of a header walk from one
    /// round trip per block into one per page of [`HASH_PAGE`]. A node that
    /// answers a list with anything else gets one request per height instead:
    /// that is an older or a different implementation and not a lie, because
    /// nothing is decided from these hashes on their own. They are addresses.
    /// What makes the range a chain is the parent links checked over the
    /// headers they fetch, in [`Chain::header_chain`].
    ///
    /// A node that does not answer a list is asked once per command rather
    /// than once per page of heights: see [`ListSupport`].
    ///
    /// `None` is an ordinary answer for a height this node has no block at.
    pub fn block_hashes_at(&self, numbers: &[u32]) -> Result<Vec<Option<[u8; 32]>>> {
        if numbers.is_empty() {
            return Ok(Vec::new());
        }
        if self.hash_lists.get() != ListSupport::Refused {
            match self.try_hash_list(numbers)? {
                Some(hashes) => {
                    self.hash_lists.set(ListSupport::Taken);
                    return Ok(hashes);
                }
                None => self.hash_lists.set(ListSupport::Refused),
            }
        }
        numbers
            .iter()
            .map(|number| self.block_hash_at_height(*number))
            .collect()
    }

    /// One attempt at the list form. `Ok(None)` is a node that does not take
    /// it.
    ///
    /// Two shapes of "does not take it", because two kinds of node answer
    /// differently. One reads the parameter as a single number, ignores the
    /// rest and answers one hash, which is a list this wallet cannot read as
    /// one. Another deserializes the parameter as `Option<NumberOrHex>`, fails
    /// on an array and answers `-32602 Invalid params`, which arrives as a
    /// [`RpcError`]: the node answered, and what it said is that it does not
    /// implement this. Both are older implementations rather than lies, and
    /// both are answered around.
    ///
    /// A request that did not complete is neither, and it is returned: the
    /// caller is not made to re-ask 256 heights one at a time through an
    /// endpoint that is refusing or unreachable.
    fn try_hash_list(&self, numbers: &[u32]) -> Result<Option<Vec<Option<[u8; 32]>>>> {
        let listed: Value = match self.rpc.call("chain_getBlockHash", json!([numbers])) {
            Ok(listed) => listed,
            Err(error) if error.downcast_ref::<RpcError>().is_some() => return Ok(None),
            Err(error) => {
                return Err(error.context(format!(
                    "no block hashes for the {} heights from {}",
                    numbers.len(),
                    numbers.first().copied().unwrap_or_default()
                )))
            }
        };
        let Some(answers) = listed.as_array() else {
            return Ok(None);
        };
        if answers.len() != numbers.len() {
            return Ok(None);
        }
        answers
            .iter()
            .map(|answer| match answer {
                Value::Null => Ok(None),
                Value::String(hash) => decode_hash(hash).map(Some),
                other => bail!("chain_getBlockHash answered {other} inside a list"),
            })
            .collect::<Result<Vec<Option<[u8; 32]>>>>()
            .map(Some)
    }

    pub fn block_hash(&self, number: u32) -> Result<[u8; 32]> {
        let hash: Option<String> = self
            .rpc
            .call_as("chain_getBlockHash", json!([number]))
            .with_context(|| format!("no block hash at height {number}"))?;
        let hash = hash.ok_or_else(|| anyhow!("the chain has no block at height {number}"))?;
        decode_hash(&hash)
    }

    pub fn header_at(&self, hash: &[u8; 32]) -> Result<RawHeader> {
        self.rpc.call_as("chain_getHeader", json!([hex_0x(hash)]))
    }

    /// The header of `number`, checked against the hash the chain stores for
    /// it.
    ///
    /// A wallet that anchors on a header it recomputed wrongly pays for a
    /// proof and gets `BlockHashMismatch` back. The digest re-encoding is the
    /// part that goes wrong, so the check happens here, before any proving.
    pub fn anchor_header(&self, number: u32) -> Result<(HeaderInputs, [u8; 32])> {
        let hash = self.block_hash(number)?;
        let raw = self.header_at(&hash)?;
        let header = raw.to_header_inputs()?;
        let recomputed = header.block_hash().to_bytes();
        if recomputed != hash {
            bail!(
                "the header this wallet rebuilt for block {number} hashes to {} where the chain \
                 says {}. The digest re-encoding or a root decode is wrong; proving against it \
                 would be refused with BlockHashMismatch.",
                hex::encode(recomputed),
                hex::encode(hash)
            );
        }
        Ok((header, hash))
    }

    /// The headers of `anchor..=head`, each authenticated by its own hash.
    ///
    /// The walk used to descend by `parentHash`, one `chain_getHeader` at a
    /// time, each header fetched by the hash its child named. That is one
    /// round trip per block with nothing else in flight, and against a node
    /// behind a CDN the round trip is the whole cost: at the public chain's
    /// 120 s target a year of history is 262 000 of them in series.
    ///
    /// So the two halves are separated and both are pipelined. The heights are
    /// turned into hashes with `chain_getBlockHash` over a list of numbers,
    /// paged at [`HASH_PAGE`], and the headers are then fetched by hash in
    /// JSON-RPC batch arrays of [`HEADER_BATCH`]. A node that takes neither
    /// gets one request per call and the walk is what it always was; see
    /// [`Chain::block_hashes_at`] and [`RpcClient::call_many`]. One answer per
    /// call is `call_many`'s contract, and it is what makes the headers line
    /// up with the heights they were asked for; the count is checked where
    /// they are collected, before any of them is indexed against a hash.
    ///
    /// **Exactly what the descending walk verified is verified here, locally,
    /// and nothing about which values are trusted changes.** The hashes are
    /// the node's claim and decide nothing on their own:
    ///
    /// - every header's own number is the height it was asked for, or the walk
    ///   is refused;
    /// - every header is rehashed from its own preimage and the result has to
    ///   be the hash it was fetched by, or the walk is refused;
    /// - and every header names as its `parentHash` the hash this node
    ///   answered for the height below it, or the walk is refused. That is the
    ///   parent link the descending walk followed, checked rather than
    ///   followed, so a hash answered for a number the header chain does not
    ///   carry is a lie and is refused.
    ///
    /// Composed, those are the same equalities the descending walk produced:
    /// the recomputed hash of each header is the hash the header above it names
    /// as its parent, down to the bottom. So from a single trusted hash at the
    /// bottom, every field of every header above it is authenticated: the
    /// `zkTreeRoot` a leaf range is checked against, and the pre-runtime author
    /// label that says whose block it is.
    ///
    /// It names nothing about this wallet: every wallet on the chain reads the
    /// same headers, and a list of heights is the same list for all of them.
    ///
    /// The caller supplies the bottom of the chain and must compare
    /// `blocks[0].hash` against a hash it already trusts, which is the store's
    /// genesis or a checkpoint an earlier pass recorded. Without that
    /// comparison this returns a self-consistent chain and nothing more, and a
    /// node can build one of those out of nothing.
    ///
    /// What the walk does **not** do is verify proof of work, and it never
    /// will in v1: a RandomX verification needs a 256 MiB cache and has no
    /// browser build. So every field of every header above the trusted bottom
    /// is the node's to choose, and what this returns is one self-consistent
    /// chain descending from a hash the caller already had. `docs/WALLET.md`,
    /// under "What a lying node can and cannot do", carries that bound and the
    /// checkpoint fork walk that is the defence.
    ///
    /// **One chunk per call.** The span is bounded by
    /// [`crate::wallet::HEADER_WALK_LIMIT`], because `head.number` is a
    /// number the node answers with and this walks and holds one header per
    /// unit of it. `Wallet::sync_with` climbs a longer range in chunks of that
    /// size, authenticating and checkpointing each before it reads the next,
    /// so a chain far ahead of the checkpoint still syncs in one command.
    pub fn header_chain(&self, head: &ChainHead, anchor: u32) -> Result<Vec<VerifiedBlock>> {
        ensure_le(anchor, head.number)?;
        let span = head.number - anchor;
        if span > crate::wallet::HEADER_WALK_LIMIT {
            bail!(
                "a header walk was asked for blocks {anchor} to {}, which is {span} blocks where \
                 one walk carries at most {}. The head is a number this node answers with and this \
                 walk holds one header per unit of it, so the range is climbed in chunks rather \
                 than in one allocation. Nothing has been changed.",
                head.number,
                crate::wallet::HEADER_WALK_LIMIT
            );
        }
        let span = span as usize;

        // The hashes the headers are fetched by. The top's is the caller's,
        // which is the head itself or a hash the caller is about to prove by
        // walking down to one it already trusts, so it is never asked for
        // again.
        let mut hashes = vec![[0u8; 32]; span + 1];
        hashes[span] = head.hash;
        let mut height = anchor;
        while height < head.number {
            let end = (height as u64 + HASH_PAGE as u64).min(head.number as u64) as u32;
            let numbers: Vec<u32> = (height..end).collect();
            for (offset, answer) in self.block_hashes_at(&numbers)?.into_iter().enumerate() {
                let number = height + offset as u32;
                let hash = answer.ok_or_else(|| {
                    anyhow!(
                        "the chain has no block at height {number}, which is inside the range \
                         {anchor} to {} this node reports a head above. A header walk cannot skip \
                         a height: the chain it authenticates is the one with no gaps in it. \
                         Nothing has been changed.",
                        head.number
                    )
                })?;
                hashes[(number - anchor) as usize] = hash;
            }
            height = end;
        }

        // The headers, fetched by hash, many calls to a request.
        let mut raws: Vec<RawHeader> = Vec::with_capacity(span + 1);
        for page in hashes.chunks(HEADER_BATCH) {
            let calls: Vec<(&str, Value)> = page
                .iter()
                .map(|hash| ("chain_getHeader", json!([hex_0x(hash)])))
                .collect();
            for answer in self.rpc.call_many(&calls)? {
                raws.push(
                    serde_json::from_value(answer)
                        .context("chain_getHeader returned a header this wallet cannot read")?,
                );
            }
        }
        // Here rather than after the loop below, which is the only place it
        // can be violated: what guarantees one header per height is
        // `RpcClient::call_many`'s contract of one answer per call, and a page
        // that came back short would be indexed against `hashes` before any
        // count taken afterwards could say so.
        if raws.len() != span + 1 {
            bail!(
                "this node answered {} headers for blocks {anchor} to {}. Nothing has been \
                 changed.",
                raws.len(),
                head.number
            );
        }

        let mut blocks = Vec::with_capacity(span + 1);
        for (offset, raw) in raws.iter().enumerate() {
            let number = anchor + offset as u32;
            let hash = hashes[offset];
            let claimed = raw.block_number()?;
            if claimed != number {
                bail!(
                    "this node answered a header numbered {claimed} for the hash it gave as \
                     block {number}. A header read at the hash its child names is the only thing \
                     tying a block to a height, so the walk is refused rather than dating leaves \
                     by it. Nothing has been changed."
                );
            }
            let header = raw.to_header_inputs()?;
            let recomputed = header.block_hash().to_bytes();
            if recomputed != hash {
                bail!(
                    "the header this node served for block {number} hashes to {} where the hash \
                     asked for is {}. The header preimage is what authenticates a block's \
                     zkTreeRoot and its author label, so a header that does not hash to its own \
                     name authenticates nothing. Nothing has been changed.",
                    hex::encode(recomputed),
                    hex::encode(hash)
                );
            }
            let parent_hash = decode_hash(&raw.parent_hash)?;
            if offset > 0 && parent_hash != hashes[offset - 1] {
                bail!(
                    "this node gave {} as the hash of block {} and the header it served for \
                     block {number} names {} as its parent. The hashes are only addresses and \
                     the parent links are what make the range a chain, so a hash answered for a \
                     number the header chain does not carry is refused. Nothing has been changed.",
                    hex::encode(hashes[offset - 1]),
                    number - 1,
                    hex::encode(parent_hash)
                );
            }
            blocks.push(VerifiedBlock {
                number,
                hash,
                parent_hash,
                extrinsics_root: decode_hash(&raw.extrinsics_root)?,
                zk_tree_root: Digest::from_bytes(&decode_hash(&raw.zk_tree_root)?).map_err(
                    |_| anyhow!("block {number}'s zkTreeRoot is not a canonical digest"),
                )?,
                author_label: raw.author_label()?,
            });
        }
        Ok(blocks)
    }

    /// `Shielded::LeafBlocks` over a range, at one block.
    ///
    /// The block each leaf is dated at, as the node reports it. Advisory: the
    /// authenticated block ranges are what decide, and this is compared
    /// against them. See `crate::typing`.
    pub fn leaf_blocks(
        &self,
        range: std::ops::Range<u64>,
        at: &[u8; 32],
    ) -> Result<Vec<Option<u32>>> {
        let at = hex_0x(at);
        let mut out = Vec::with_capacity((range.end.saturating_sub(range.start)) as usize);
        for chunk_start in range.clone().step_by(LEAF_HASH_BATCH) {
            let chunk_end = (chunk_start + LEAF_HASH_BATCH as u64).min(range.end);
            let keys: Vec<Vec<u8>> = (chunk_start..chunk_end)
                .map(|index| identity_map_key(SHIELDED_PALLET, "LeafBlocks", index))
                .collect();
            for (offset, value) in self.rpc.storage_batch(&keys, &at)?.into_iter().enumerate() {
                let index = chunk_start + offset as u64;
                out.push(
                    value
                        .map(|bytes| {
                            decode_u32_exact(&bytes, &format!("Shielded::LeafBlocks({index})"))
                        })
                        .transpose()?,
                );
            }
        }
        Ok(out)
    }

    /// `zkTree_getState`, the tree's own view at the best block.
    pub fn tree_state(&self) -> Result<TreeState> {
        self.rpc.call_as("zkTree_getState", json!([]))
    }

    /// Leaf count as of one block, so a scan's reads are all pinned to the
    /// same state, at its declared width and bounded by what the circuit can
    /// prove over.
    ///
    /// `u64::decode` reads the first eight bytes of whatever it is handed and
    /// ignores the rest, so a node answering thirty-two bytes of `0xff` was
    /// read as `u64::MAX` and nothing bounded it: this count is what the scan
    /// turns into work, one window of reads per 64 of it, so that one answer
    /// was an unbounded scan. A 4-ary tree of depth `d` holds `4 ** d` leaves
    /// and `d` is capped by [`MAX_TREE_DEPTH`], which `pallet-zk-tree`'s
    /// `CIRCUIT_MAX_TREE_DEPTH` equals, so a count above that capacity is not
    /// a tree this chain carries. `wallet-web/src/chain/reads.ts` reads it the
    /// same way, in `readTreeShape`.
    pub fn leaf_count_at(&self, at: &[u8; 32]) -> Result<u64> {
        let key = storage_prefix(ZK_TREE_PALLET, "LeafCount");
        match self.rpc.storage(&key, Some(&hex_0x(at)))? {
            Some(bytes) => {
                let count = decode_u64_exact(&bytes, "ZkTree::LeafCount")?;
                let capacity = tree_capacity();
                if count > capacity {
                    bail!(
                        "ZkTree::LeafCount is {count} at block {} and a tree this wallet can \
                         prove over holds at most {capacity} leaves, which is 4 ** \
                         {MAX_TREE_DEPTH}. A count above that is not a tree this chain carries, \
                         and it is the number that decides how many leaves a scan reads.",
                        hex::encode(at)
                    );
                }
                Ok(count)
            }
            None => Ok(0),
        }
    }

    pub fn entry_count_at(&self, at: &[u8; 32]) -> Result<u64> {
        let key = storage_prefix(SHIELDED_PALLET, "EntryCount");
        match self.rpc.storage(&key, Some(&hex_0x(at)))? {
            Some(bytes) => decode_u64_exact(&bytes, "Shielded::EntryCount"),
            None => Ok(0),
        }
    }

    /// The tree depth as of one block.
    ///
    /// The pallet folds a block's leaves in `on_finalize` and grows the tree
    /// there, so the depth read at a block hash is the depth its root was
    /// computed at. A local rebuild at any other depth reaches a different
    /// root.
    pub fn tree_depth_at(&self, at: &[u8; 32]) -> Result<u8> {
        let key = storage_prefix(ZK_TREE_PALLET, "Depth");
        match self.rpc.storage(&key, Some(&hex_0x(at)))? {
            Some(bytes) => {
                let depth: [u8; 1] = bytes.as_slice().try_into().map_err(|_| {
                    anyhow!(
                        "ZkTree::Depth is {} bytes and this build decodes it as 1. This runtime \
                         declares a different type for it.",
                        bytes.len()
                    )
                })?;
                Ok(depth[0])
            }
            None => Ok(0),
        }
    }

    /// Every leaf hash in `range`, at one block, in index order.
    ///
    /// `leaf_count` is `ZkTree::LeafCount` read at this same block hash, and
    /// it is what an answer is measured against. Below it every index was
    /// appended by one of `pallet-shielded`'s three writers and carries a
    /// commitment, so an absent answer there is one the node withheld, and the
    /// all-zero digest there is the tree's own pad standing in for a leaf the
    /// chain never wrote: `insert_commitment` refuses an append of it by name.
    /// Both are refused here, by `withheld_key` and `padding_sentinel`.
    ///
    /// This is the read the spend path rebuilds its paths from, and it used to
    /// substitute `empty_digest()` for an absent answer at any index at all.
    /// A node could therefore pad below the count on the spend path and the
    /// wallet would build a path over a pad, which is the answer `fetchLeaves`
    /// and `fetchLeafHashes` in `wallet-web/src/chain/reads.ts` already
    /// refused: the two wallets disagreed about the same lie.
    ///
    /// At or above the count the padding is the pallet's own rule, which is
    /// what `tree::get_leaf_hash` substitutes, so a local rebuild pads the way
    /// the chain does.
    pub fn leaf_hashes(
        &self,
        range: std::ops::Range<u64>,
        leaf_count: u64,
        at: &[u8; 32],
    ) -> Result<Vec<Digest>> {
        let at_bytes = *at;
        let at = hex_0x(at);
        let mut out = Vec::with_capacity((range.end.saturating_sub(range.start)) as usize);
        for chunk_start in range.clone().step_by(LEAF_HASH_BATCH) {
            let chunk_end = (chunk_start + LEAF_HASH_BATCH as u64).min(range.end);
            let keys: Vec<Vec<u8>> = (chunk_start..chunk_end)
                .map(|index| identity_map_key(ZK_TREE_PALLET, "Leaves", index))
                .collect();
            for (offset, value) in self.rpc.storage_batch(&keys, &at)?.into_iter().enumerate() {
                let index = chunk_start + offset as u64;
                let digest = match value {
                    Some(bytes) => {
                        let bytes: [u8; 32] = bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("ZkTree::Leaves({index}) is not 32 bytes"))?;
                        let digest = Digest::from_bytes(&bytes).map_err(|_| {
                            anyhow!(
                                "ZkTree::Leaves({index}) is {} and is not a canonical digest, so \
                                 this wallet cannot rebuild the tree over it. Pass \
                                 `--merkle-rpc` to ask the node for the path.",
                                hex::encode(bytes)
                            )
                        })?;
                        if index < leaf_count && digest == qnero_circuit::merkle::empty_digest() {
                            return Err(padding_sentinel(index, leaf_count, &at_bytes));
                        }
                        digest
                    }
                    None => {
                        if index < leaf_count {
                            return Err(withheld_key(
                                index,
                                leaf_count,
                                &at_bytes,
                                "ZkTree::Leaves",
                            ));
                        }
                        qnero_circuit::merkle::empty_digest()
                    }
                };
                out.push(digest);
            }
        }
        Ok(out)
    }

    /// Rebuild the chain's commitment tree at one block, from its leaves.
    ///
    /// `pallet-zk-tree` folds a block's leaves in `on_finalize`, so at a block
    /// hash every leaf `< LeafCount` is in the root and `Depth` is the depth
    /// that root was computed at. `CommitmentTree` mirrors the pallet's node
    /// rule exactly, so the root this reaches equals the header's
    /// `zkTreeRoot`, and the caller checks that before it proves anything.
    ///
    /// This is the route a wallet takes for its own input paths. The proof
    /// RPC is asked only about leaves a wallet is spending, so every call
    /// names one of the caller's own leaves to the node moments before the
    /// settlement publishes the matching nullifier. Reading the whole leaf
    /// range is the read a scan already makes and it distinguishes nothing.
    pub fn rebuild_tree(&self, at: &[u8; 32]) -> Result<LocalTree> {
        let leaf_count = self.leaf_count_at(at)?;
        let depth = usize::from(self.tree_depth_at(at)?);
        let leaves = self.leaf_hashes(0..leaf_count, leaf_count, at)?;
        let tree = CommitmentTree::new(&leaves, depth).with_context(|| {
            format!(
                "failed to rebuild the commitment tree over {leaf_count} leaves at depth {depth}"
            )
        })?;
        Ok(LocalTree { leaves, tree })
    }

    /// The whole settled nullifier set at one block, in hex.
    ///
    /// Paged over the map's keys. `UsedNullifiers` is `Blake2_128Concat`, so
    /// the raw 32-byte nullifier is the tail of every key the node returns and
    /// no value fetch is needed.
    ///
    /// This replaces asking the node about one specific nullifier. That
    /// question hands the raw value over in the clear, and a node that logs it
    /// learns, per client, the set of nullifiers a wallet will publish when it
    /// spends: weeks later a settlement publishes one of them and the spend is
    /// attributed with certainty. Reading the public map whole says nothing
    /// about which entries matter.
    pub fn used_nullifiers_at(&self, at: &[u8; 32]) -> Result<BTreeSet<String>> {
        let prefix = storage_prefix(SHIELDED_PALLET, "UsedNullifiers");
        let entries = self.rpc.storage_prefix(&prefix, &hex_0x(at), KEY_PAGE)?;
        let mut out = BTreeSet::new();
        for (key, value) in entries {
            let Some(raw) = key.get(prefix.len() + 16..) else {
                bail!("a UsedNullifiers key is too short");
            };
            if raw.len() != 32 || !value.is_empty() {
                bail!("a UsedNullifiers entry has an unexpected encoding");
            }
            if blake2_128_concat_map_key(SHIELDED_PALLET, "UsedNullifiers", raw) != key {
                bail!("a UsedNullifiers key has an invalid Blake2_128Concat prefix");
            }
            out.insert(hex::encode(raw));
        }
        Ok(out)
    }

    /// The commitment, block and coinbase value of every leaf in `range`, at
    /// one block.
    ///
    /// Every map is `Identity`-hashed on the leaf index, so paging is by index
    /// alone and `state_getKeysPaged` is unnecessary.
    ///
    /// Three keys per leaf. `CoinbaseValues` is the third and it is what makes
    /// a coinbase note readable: its value is public, because the chain hashes
    /// it into the commitment over an `inner` it cannot open. The note
    /// ciphertexts are not among these keys at all: the chain keeps them in
    /// block bodies and this wallet reads them there, authenticated against
    /// the header's `extrinsicsRoot` rather than its `stateRoot`. See
    /// [`Chain::authenticated_body`].
    ///
    /// **A key the node withholds below `leaf_count` refuses the read.**
    /// `leaf_count` is `ZkTree::LeafCount` read at this same block hash, and
    /// every leaf under it was appended by one of the three writers in
    /// `pallet-shielded`, each of which writes its keys in the same call:
    ///
    /// - `shield` writes `Leaves` and `LeafBlocks`;
    /// - a settled slot writes `Leaves` and `LeafBlocks` for each of its two
    ///   outputs;
    /// - the coinbase writes `Leaves`, `LeafBlocks` and `CoinbaseValues`.
    ///
    /// Nothing removes any of them. So below the count there is a commitment
    /// and a block at every index, and an absent answer for either is a node
    /// withholding it. Each hides a leaf in its own way and both are
    /// permanent: without the commitment the leaf is skipped, without the
    /// block a coinbase leaf is stepped over, and either way the pass commits
    /// a watermark above it and nothing reads it again without a rescan. The
    /// read is refused instead, naming the key, the index, the count and the
    /// block. `fetchLeaves` in `wallet-web/src/chain/reads.ts` refuses the
    /// identical set.
    ///
    /// `CoinbaseValues` is the one key a leaf is allowed not to have, and its
    /// presence does **not** decide that a leaf is a coinbase: presence is the
    /// node's to write, and eight invented bytes beside an incoming transfer
    /// used to route it onto the coinbase rebuild and hide the payment. What
    /// decides is where the block headers put the leaf, in `crate::typing`,
    /// which refuses an invented coinbase value below a block's last leaf and
    /// a withheld one at every coinbase position.
    pub fn leaves(
        &self,
        range: std::ops::Range<u64>,
        at: &[u8; 32],
        leaf_count: u64,
    ) -> Result<Vec<LeafRecord>> {
        let mut out = Vec::new();
        for chunk_start in range.clone().step_by(LEAF_BATCH) {
            let chunk_end = (chunk_start + LEAF_BATCH as u64).min(range.end);
            out.extend(self.leaf_window(chunk_start..chunk_end, at, leaf_count)?);
        }
        Ok(out)
    }

    /// The leaves one chunk of the header walk claims, pinned to the pass's
    /// own block hash.
    ///
    /// Leaves are appended in block order, so the leaves of blocks at or below
    /// `top_block` are a prefix of what is left to read: this walks windows up
    /// from `from` and stops at the first leaf `Shielded::LeafBlocks` dates
    /// above `top_block`.
    ///
    /// The stop condition uses `Shielded::LeafBlocks` authenticated against
    /// the selected header's state root. The configured provider/checkpoint
    /// policy still determines which header chain is selected. A chunk holds
    /// the leaves dated within its own blocks; its memory use depends on that
    /// chain's actual leaf density. `crate::typing` also folds those leaves and
    /// checks each block's `zkTreeRoot` before scan progress is committed.
    pub fn leaves_up_to_block(
        &self,
        from: u64,
        leaf_count: u64,
        top_block: u32,
        at: &[u8; 32],
    ) -> Result<Vec<LeafRecord>> {
        let mut out = Vec::new();
        let mut cursor = from;
        while cursor < leaf_count {
            let window_end = (cursor + LEAF_BATCH as u64).min(leaf_count);
            let window = self.leaf_window(cursor..window_end, at, leaf_count)?;
            let mut stopped = false;
            for record in window {
                if record.block_number.is_some_and(|block| block > top_block) {
                    stopped = true;
                    break;
                }
                out.push(record);
            }
            if stopped {
                break;
            }
            cursor = window_end;
        }
        Ok(out)
    }

    /// One block's body, authenticated against the `extrinsicsRoot` in its own
    /// header.
    ///
    /// Note ciphertexts are in block bodies and in no state map, so this is
    /// the read that makes an incoming payment readable at all. Two steps
    /// here, and one the caller has already taken:
    ///
    /// 0. `block.extrinsics_root` came off a header the header walk fetched
    ///    and rehashed from its own preimage, and whose hash is
    ///    `block.hash`. That is the step this function no longer takes for
    ///    itself: a header that does not hash to the name it was asked for
    ///    carries nothing, so its `extrinsicsRoot` is a number a node chose,
    ///    and [`Chain::header_chain`] refuses such a header before any body
    ///    is asked for.
    /// 1. The body at `block.hash` is fetched.
    /// 2. The body is rooted with
    ///    [`qnero_state_proof::extrinsics_root`], the construction
    ///    `frame_system` makes while `system_version` is 1, and compared
    ///    against that field.
    ///
    /// **Why the root arrives with the block.** The walk already fetches and
    /// rehashes every header in the range, and it kept the hash while
    /// dropping the `extrinsicsRoot` beside it. Refetching the header here
    /// was a second `chain_getHeader` per block on top of the body, and
    /// `pallet-shielded` mints a coinbase leaf every block, so nearly every
    /// block of a scanned range paid for the same header twice. The node's
    /// front end answers `429 Too Many Requests` after about eighty requests
    /// in a window, which is what makes the count per block decide whether a
    /// scan finishes at all. What is trusted is unchanged: the root is the
    /// number the old refetch was checking against.
    ///
    /// What the root check buys is completeness as well as integrity. A state
    /// read authenticates one key at a time and an absent answer has to be
    /// caught by a rule about which keys a leaf owes; a body roots as a whole,
    /// so a node that drops one extrinsic, reorders two, or appends one
    /// reaches a root no header carries. There is no per-payload absence left
    /// to detect.
    ///
    /// `block` must be a block of the header walk, which is a hash this caller
    /// already trusts and the root of the header that hashes to it. This
    /// selects no chain and verifies no proof of work.
    pub fn authenticated_body(&self, block: &VerifiedBlock) -> Result<Vec<Vec<u8>>> {
        let at = &block.hash;
        let number = block.number;
        let expected = block.extrinsics_root;

        let answer: Value = self.rpc.call("chain_getBlock", json!([hex_0x(at)]))?;
        let extrinsics = answer
            .get("block")
            .and_then(|block| block.get("extrinsics"))
            .and_then(Value::as_array)
            .ok_or_else(|| withheld_body(at, number))?;
        // The two budgets, applied to what the node handed over before any of
        // it is decoded, which is the discipline the browser holds this read
        // to: a body inside these and outside the runtime's own limit simply
        // roots to a header no chain published.
        if extrinsics.len() > MAX_BODY_EXTRINSICS {
            bail!(
                "this node served a body for block {number} carrying {} extrinsics, above the \
                 {MAX_BODY_EXTRINSICS} this wallet will hash. Nothing has been read from it.",
                extrinsics.len()
            );
        }
        let mut bytes = 0usize;
        for extrinsic in extrinsics {
            let hex = extrinsic
                .as_str()
                .ok_or_else(|| anyhow!("chain_getBlock returned an extrinsic that is not hex"))?;
            bytes = bytes.saturating_add(hex.len() / 2);
            if bytes > MAX_BODY_BYTES {
                bail!(
                    "this node served a body for block {number} above {MAX_BODY_BYTES} bytes, \
                     which is more than `RuntimeBlockLength` lets a block carry. Nothing has \
                     been read from it."
                );
            }
        }
        let body = extrinsics
            .iter()
            .map(|extrinsic| {
                extrinsic
                    .as_str()
                    .ok_or_else(|| anyhow!("chain_getBlock returned an extrinsic that is not hex"))
                    .and_then(decode_hex)
            })
            .collect::<Result<Vec<_>>>()?;

        let recomputed = qnero_state_proof::extrinsics_root(&body)
            .map_err(|error| anyhow!("block {number}'s body cannot be rooted: {error}"))?;
        if recomputed != expected {
            bail!(
                "the body this node served for block {number} roots to {} where the \
                 extrinsicsRoot in the header it hashes to is {}. The body is what carries every \
                 note ciphertext, so a body the header does not carry is a node answering with \
                 extrinsics this chain did not include. Nothing has been changed.",
                hex::encode(recomputed),
                hex::encode(expected)
            );
        }
        Ok(body)
    }

    /// Every note ciphertext one block's body carries, in body order.
    ///
    /// The body has already been rooted to its header by
    /// [`Chain::authenticated_body`], so these bytes are the chain's. Which
    /// leaf each one belongs to is decided nowhere here: the scan trial
    /// decrypts every one of them and the note that comes out has to match a
    /// commitment the block demonstrably appended. See `crate::typing`.
    ///
    /// A payload this walk cannot reach refuses rather than being skipped. The
    /// body is the only copy, so an extrinsic this wallet cannot walk is one
    /// it cannot say carried no payment of this wallet's.
    pub fn block_payloads(
        &self,
        metadata: &crate::metadata::ChainMetadata,
        body: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for (position, extrinsic) in body.iter().enumerate() {
            out.extend(
                crate::extrinsic::extrinsic_payloads(metadata, extrinsic).with_context(|| {
                    format!(
                        "extrinsic {position} of this block cannot be walked; scan progress is \
                         unchanged"
                    )
                })?,
            );
        }
        Ok(out)
    }

    /// One read window of the three per-leaf maps.
    fn leaf_window(
        &self,
        range: std::ops::Range<u64>,
        at: &[u8; 32],
        leaf_count: u64,
    ) -> Result<Vec<LeafRecord>> {
        let at_hash = hex_0x(at);
        let mut keys = Vec::with_capacity(((range.end - range.start) * 3) as usize);
        for index in range.clone() {
            keys.push(identity_map_key(ZK_TREE_PALLET, "Leaves", index));
            keys.push(identity_map_key(SHIELDED_PALLET, "LeafBlocks", index));
            keys.push(identity_map_key(SHIELDED_PALLET, "CoinbaseValues", index));
        }
        let values = self.rpc.storage_batch(&keys, &at_hash)?;
        let mut out = Vec::with_capacity((range.end - range.start) as usize);
        for (offset, index) in range.enumerate() {
            let commitment = values[offset * 3].clone();
            let block = values[offset * 3 + 1].clone();
            let coinbase_value = values[offset * 3 + 2].clone();
            let below_count = index < leaf_count;
            if below_count && commitment.is_none() {
                return Err(withheld_key(index, leaf_count, at, "ZkTree::Leaves"));
            }
            if below_count && block.is_none() {
                return Err(withheld_key(index, leaf_count, at, "Shielded::LeafBlocks"));
            }
            let commitment = commitment
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| anyhow!("ZkTree::Leaves({index}) is not 32 bytes"))
                })
                .transpose()?;
            // The tree's own pad, answered below the count that says the chain
            // appended this leaf. See `padding_sentinel`.
            if below_count && commitment == Some(empty_digest().to_bytes()) {
                return Err(padding_sentinel(index, leaf_count, at));
            }
            out.push(LeafRecord {
                index,
                commitment,
                block_number: block
                    .map(|bytes| {
                        decode_u32_exact(&bytes, &format!("Shielded::LeafBlocks({index})"))
                    })
                    .transpose()?,
                coinbase_value: coinbase_value
                    .map(|bytes| {
                        decode_u64_exact(&bytes, &format!("Shielded::CoinbaseValues({index})"))
                    })
                    .transpose()?,
            });
        }
        Ok(out)
    }

    /// Whether each nullifier has been settled, at one block, by asking the
    /// node about those exact nullifiers.
    ///
    /// This names the values it asks about to whoever runs the node, so it is
    /// for nullifiers that are already public: the post-inclusion confirmation
    /// of a settlement this wallet has just broadcast. Everything else reads
    /// the set through [`Chain::used_nullifiers_at`] and decides locally.
    pub fn nullifiers_used(&self, nullifiers: &[[u8; 32]], at: &[u8; 32]) -> Result<Vec<bool>> {
        let at = hex_0x(at);
        let mut used = Vec::with_capacity(nullifiers.len());
        for chunk in nullifiers.chunks(LEAF_BATCH) {
            let keys: Vec<Vec<u8>> = chunk
                .iter()
                .map(|nullifier| {
                    blake2_128_concat_map_key(SHIELDED_PALLET, "UsedNullifiers", nullifier)
                })
                .collect();
            let values = self.rpc.storage_batch(&keys, &at)?;
            used.extend(values.into_iter().map(|value| value.is_some()));
        }
        Ok(used)
    }

    /// A Merkle proof at one block, converted into the circuit's shape.
    ///
    /// `Ok(None)` means the leaf is not folded into the tree yet, which is the
    /// ordinary case for a leaf appended in the current block: a note cannot
    /// be minted and spent in the same block. That has to stay apart from a
    /// node that is unwell, so this is where the two split: a leaf too new to
    /// prove is a `None`, and an unwell node is an error.
    pub fn merkle_path(
        &self,
        leaf_index: u64,
        leaf: Digest,
        at: &[u8; 32],
    ) -> Result<Option<ChainMerklePath>> {
        let raw: Option<RawMerkleProof> = self
            .rpc
            .call_as("zkTree_getMerkleProof", json!([leaf_index, hex_0x(at)]))?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        if raw.leaf_index != leaf_index {
            bail!(
                "asked for a proof of leaf {leaf_index} and got one for {}",
                raw.leaf_index
            );
        }
        if raw.leaf_hash != leaf.to_bytes() {
            bail!(
                "leaf {leaf_index} hashes to {} on chain, this wallet holds a note committing to \
                 {}. Run `sync --rescan`, against a second node where there is one: this leaf is \
                 below the watermark, so an ordinary sync starts above it and never reads it \
                 again.",
                hex::encode(raw.leaf_hash),
                leaf.to_hex()
            );
        }
        if raw.siblings.len() != raw.depth as usize {
            bail!(
                "the proof for leaf {leaf_index} declares depth {} and carries {} levels",
                raw.depth,
                raw.siblings.len()
            );
        }
        let siblings = raw
            .siblings
            .iter()
            .map(|level| {
                let mut converted = [Digest::from_bytes(&[0u8; 32]).expect("zero is canonical"); 3];
                for (slot, bytes) in level.iter().enumerate() {
                    converted[slot] = Digest::from_bytes(bytes)
                        .map_err(|_| anyhow!("a sibling is not a canonical digest"))?;
                }
                Ok(converted)
            })
            .collect::<Result<Vec<_>>>()?;
        let path = MerklePath::from_unsorted(&siblings, leaf)?;
        let root = Digest::from_bytes(&raw.root)
            .map_err(|_| anyhow!("the proof's root is not a canonical digest"))?;
        let recomputed = path.root(leaf)?;
        if recomputed != root {
            bail!(
                "the converted path for leaf {leaf_index} reaches {} where the chain's proof says \
                 {}",
                recomputed.to_hex(),
                root.to_hex()
            );
        }
        Ok(Some(ChainMerklePath { path, root }))
    }

    /// The next nonce of an account, read from `System::Account` at the best
    /// block.
    ///
    /// `AccountInfo`'s first field is the nonce, so the decode stops after
    /// four bytes and the wallet needs nothing from the rest of the type.
    pub fn account_nonce(&self, account: &[u8; 32]) -> Result<u32> {
        let key = blake2_128_concat_map_key("System", "Account", account);
        match self.rpc.storage(&key, None)? {
            Some(bytes) => u32::decode(&mut &bytes[..])
                .context("System::Account does not start with a u32 nonce"),
            None => Ok(0),
        }
    }

    pub fn genesis_hash(&self) -> Result<[u8; 32]> {
        self.block_hash(0)
    }

    pub fn runtime_version(&self) -> Result<(u32, u32)> {
        let value: Value = self.rpc.call("state_getRuntimeVersion", json!([]))?;
        let spec = value
            .get("specVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("the runtime version carries no specVersion"))?;
        let tx = value
            .get("transactionVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("the runtime version carries no transactionVersion"))?;
        Ok((spec as u32, tx as u32))
    }

    /// The chain's target block time, in milliseconds.
    ///
    /// Chain state since spec 104, so one node binary serves a 120 s public
    /// chain and a 12 s dev chain and no wallet may carry the interval as a
    /// constant. `QPoWApi_get_target_block_time` answers with a SCALE `u64`.
    pub fn target_block_time_ms(&self) -> Result<u64> {
        let hex: String = self
            .rpc
            .call_as("state_call", json!(["QPoWApi_get_target_block_time", "0x"]))?;
        let bytes = decode_hex(&hex).context("the target block time is not hex")?;
        let ms = u64::decode(&mut &bytes[..])
            .context("QPoWApi_get_target_block_time did not answer with a u64")?;
        if ms == 0 {
            bail!("the node reports a target block time of zero");
        }
        Ok(ms)
    }

    pub fn submit_extrinsic(&self, encoded: &[u8]) -> Result<String> {
        self.rpc
            .call_as("author_submitExtrinsic", json!([hex_0x(encoded)]))
    }

    /// The hex of every extrinsic in one block, for matching a submission
    /// against its inclusion.
    pub fn block_extrinsics(&self, hash: &[u8; 32]) -> Result<Vec<String>> {
        let block: Value = self.rpc.call("chain_getBlock", json!([hex_0x(hash)]))?;
        let extrinsics = block
            .get("block")
            .and_then(|b| b.get("extrinsics"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("chain_getBlock returned no extrinsics"))?;
        Ok(extrinsics
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect())
    }
}

/// The chain's commitment tree, rebuilt in memory at one block.
#[derive(Debug)]
pub struct LocalTree {
    leaves: Vec<Digest>,
    tree: CommitmentTree,
}

impl LocalTree {
    /// The root this rebuild reaches. Compare it against the anchor header's
    /// `zkTreeRoot` before proving.
    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn depth(&self) -> usize {
        self.tree.depth()
    }

    /// The leaf hash at an index, as the chain holds it.
    pub fn leaf(&self, index: u64) -> Option<Digest> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.leaves.get(index))
            .copied()
    }

    /// The circuit-shaped path to one leaf.
    pub fn path(&self, index: u64) -> Result<MerklePath> {
        let index = usize::try_from(index)
            .map_err(|_| anyhow!("leaf index {index} does not fit in memory"))?;
        self.tree.path(index)
    }
}

/// How many leaves a 4-ary tree at the depth the circuit can prove holds.
///
/// `pallet-zk-tree::capacity_at_depth(CIRCUIT_MAX_TREE_DEPTH)` is the same
/// arithmetic on the chain's side, and `pallet-shielded` asserts the two
/// depths are one number.
fn tree_capacity() -> u64 {
    4u64.saturating_pow(MAX_TREE_DEPTH as u32)
}

/// A key the node answered nothing for below the count it reports at the same
/// block.
///
/// One sentence per key for what stepping over it costs, because the three
/// hide a leaf in three different ways and an operator reading the refusal is
/// reading about the one that happened. The rule behind all three, and the set
/// of keys it covers, is on [`Chain::leaves`].
pub(crate) fn withheld_key(index: u64, leaf_count: u64, at: &[u8; 32], key: &str) -> anyhow::Error {
    let cost = match key {
        "ZkTree::Leaves" => {
            "Scanning past it would step over whatever was on that leaf and then write a \
             watermark above it"
        }
        _ => {
            "A leaf with no block is stepped over where it is a coinbase, and dated by nothing \
             where it is not, and the pass would write a watermark above it"
        }
    };
    anyhow!(
        "this node answered with no {key}({index}) at block {}, where it reports {leaf_count} \
         leaves. `pallet-shielded` writes that key in the same call that appends the leaf and \
         nothing removes it, so below the count it is an answer withheld rather than an absent \
         one. {cost}, and nothing would read it again. Nothing has been changed.",
        hex::encode(at)
    )
}

/// A block whose body this node will not serve.
///
/// The one failure the body path has that the state path did not: a node that
/// answers the header and refuses, or empties, the block beside it. There is
/// no per-payload absence to detect any more, because a body roots as a whole,
/// so this is the whole of it.
///
/// It is refused rather than read as a block that carried nothing. A block
/// that appended leaves carried the extrinsics that appended them, so an
/// answer with no body in it is an answer withheld, and scanning past it would
/// step over every payment in that block and write a watermark above it. The
/// discipline is the one `withheld_key` already applies: name the block, name
/// the height, change nothing.
pub(crate) fn withheld_body(at: &[u8; 32], number: u32) -> anyhow::Error {
    anyhow!(
        "this node served a header for block {number} at {} and no body beside it. The block \
         body is where every note ciphertext this chain publishes lives, so a block with no body \
         is a payment nobody can find, and a pass that stepped over it would write a watermark \
         above the whole block. Nothing has been changed: scan progress and notes are unchanged, \
         and another node, or this one once it has the block, answers the same pass.",
        hex::encode(at)
    )
}

/// A leaf answered as the tree's own pad, below the count that says the chain
/// appended it.
///
/// The all-zero digest is `tree::empty_hash()`, what `pallet-zk-tree` reads an
/// unfilled slot as at every level, and `insert_commitment` refuses an append
/// of it by name (`ZeroCommitment`), so below its own count the chain never
/// wrote one. Every real leaf is a note commitment, a Poseidon2 output over
/// four canonical limbs.
///
/// What it buys a node is a leaf count the headers appear to carry. A fold
/// that pushes the pad reaches the root a fold that stopped short reaches,
/// because padding is what the fold already does above the count, so a run of
/// pads at the top of the tree matches every root the headers published while
/// the count is higher than the chain's. The pass would commit a watermark and
/// a checkpoint above indices this chain has not filled, and the real leaves
/// that later land there are below the watermark and never read.
/// `refuse_padding_leaves` in `crates/qnero-prover-wasm/src/wallet.rs`, behind
/// the fold `block_roots` is, and `fetchLeaves` and `fetchLeafHashes` in
/// `wallet-web/src/chain/reads.ts` refuse the identical answer.
pub(crate) fn padding_sentinel(index: u64, leaf_count: u64, at: &[u8; 32]) -> anyhow::Error {
    anyhow!(
        "this node answered ZkTree::Leaves({index}) with the all-zero digest at block {}, where \
         it reports {leaf_count} leaves. That digest is the tree's own pad for an unfilled slot \
         and `pallet-zk-tree` refuses an append of it, so below the count it is a leaf this \
         chain never appended. Folding it moves no root, which is exactly what makes it a way to \
         inflate the leaf count under honest headers, and the pass would then write a watermark \
         above indices the chain has not filled. Nothing has been changed.",
        hex::encode(at)
    )
}

/// A `u64` storage value, refused by name at any other width.
///
/// `u64::decode` takes the first eight bytes of whatever it is handed and
/// leaves the rest, so a value of another width decodes to a plausible number
/// rather than to an error: a leaf count read out of thirty-two bytes of
/// `0xff`, or an entry counter the origin walk then hashes once per unit of.
/// Every integer this wallet reads out of storage is a number it turns into
/// work or into a label, and a runtime that changed the type is a runtime this
/// build cannot read. `decodeInteger` in `wallet-web/src/chain/reads.ts` is
/// the same rule on the browser's side.
fn decode_u64_exact(bytes: &[u8], what: &str) -> Result<u64> {
    let value: [u8; 8] = bytes.try_into().map_err(|_| {
        anyhow!(
            "{what} is {} bytes and this build decodes it as 8. This runtime declares a \
             different type for it.",
            bytes.len()
        )
    })?;
    Ok(u64::from_le_bytes(value))
}

/// The same rule for a `u32`, which is what `Shielded::LeafBlocks` holds.
fn decode_u32_exact(bytes: &[u8], what: &str) -> Result<u32> {
    let value: [u8; 4] = bytes.try_into().map_err(|_| {
        anyhow!(
            "{what} is {} bytes and this build decodes it as 4. This runtime declares a \
             different type for it.",
            bytes.len()
        )
    })?;
    Ok(u32::from_le_bytes(value))
}

/// `DigestItem::PreRuntime`'s SCALE variant index.
const PRE_RUNTIME_VARIANT: u8 = 6;

/// `sp_consensus_qpow::POW_ENGINE_ID`, the four bytes consensus tags its
/// pre-runtime item with.
const POW_ENGINE_ID: [u8; 4] = *b"pow_";

/// Leaves read per `state_queryStorageAt` call.
const LEAF_BATCH: usize = 64;

/// Leaf hashes read per `state_queryStorageAt` call. One key per leaf, where a
/// scan reads three, so the page is wider.
const LEAF_HASH_BATCH: usize = 256;

/// Keys read per `state_getKeysPaged` call.
const KEY_PAGE: usize = 1000;

/// Block numbers per `chain_getBlockHash` call.
///
/// The same width as the wide leaf page, and for the same reason: the answer
/// is 32 bytes a number, so a page is about 16 KiB of hex either way. The
/// browser wallet's `HASH_PAGE` is this number.
pub const HASH_PAGE: usize = 256;

/// `chain_getHeader` calls per JSON-RPC batch array.
///
/// A header walk is latency bound and not bandwidth bound: the work per block
/// is one hash and one comparison, and the wait is the round trip. Sixty-four
/// headers is about 40 KiB of answer, which is one comfortable response, and
/// it is the same number the leaf scan already reads per storage query.
///
/// The browser wallet pipelines the same walk differently, with 32 JSON-RPC
/// ids outstanding on its one socket, because a `WsProvider` multiplexes and
/// has no batch array. Both come to a handful of round trips per chunk.
pub const HEADER_BATCH: usize = 64;

#[derive(Debug, Clone, Deserialize)]
pub struct TreeState {
    pub root: [u8; 32],
    pub leaf_count: u64,
    pub depth: u8,
}

/// One block of a header walk, authenticated by its own preimage hash.
#[derive(Debug, Clone)]
pub struct VerifiedBlock {
    pub number: u32,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    /// The root of this block's body, off the same rehashed header.
    ///
    /// Carrying it is what lets [`Chain::authenticated_body`] root a block
    /// body without asking for that header a second time: a body costs one
    /// `chain_getBlock` and no `chain_getHeader`, which against a
    /// rate-limited front end is what decides whether a scan finishes.
    pub extrinsics_root: [u8; 32],
    /// The commitment-tree root this block published, which is what a leaf
    /// range is checked against.
    pub zk_tree_root: Digest,
    /// The pre-runtime author label, absent on a block no Qnero node built.
    pub author_label: Option<[u8; 32]>,
}

fn ensure_le(anchor: u32, head: u32) -> Result<()> {
    if anchor > head {
        bail!("a header walk was asked for block {anchor} down from block {head}");
    }
    Ok(())
}

/// One leaf as the chain holds it.
#[derive(Debug, Clone)]
pub struct LeafRecord {
    pub index: u64,
    pub commitment: Option<[u8; 32]>,
    pub block_number: Option<u32>,
    /// The public value of a coinbase note, as a count of pool steps. `Some` for exactly
    /// the leaves a block's coinbase minted.
    pub coinbase_value: Option<u64>,
}
