//! Reads of chain state: headers, the commitment tree, ciphertexts,
//! nullifiers.

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};
use codec::Decode;
use qnero_circuit::chain::MAX_TREE_DEPTH;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::{CommitmentTree, MerklePath, SIBLINGS_PER_LEVEL};
use qnero_notes::Digest;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::metadata::{SHIELDED_PALLET, ZK_TREE_PALLET};
use crate::rpc::{decode_hash, decode_hex, decode_u32_hex, hex_0x, RpcClient};
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
    /// the same recomputation that authenticates the rest of the header. That
    /// is what makes it usable for deciding which blocks this wallet mined:
    /// a node cannot present a block of this wallet's as somebody else's
    /// without changing the hash.
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
            return Ok(<[u8; 32]>::try_from(payload.as_slice()).ok());
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

pub struct Chain<'a> {
    pub rpc: &'a RpcClient,
}

impl<'a> Chain<'a> {
    pub fn new(rpc: &'a RpcClient) -> Self {
        Self { rpc }
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
    /// Walked **downward**, by `parentHash`, which is what makes the chain a
    /// chain rather than a list of answers. Every header is fetched by the
    /// hash its child named, its preimage is rehashed here, and the result has
    /// to be that hash; so from a single trusted hash at the bottom, every
    /// field of every header above it is authenticated: the `zkTreeRoot` a
    /// leaf range is checked against, and the pre-runtime author label that
    /// says whose block it is.
    ///
    /// The walk costs one `chain_getHeader` per block, and no
    /// `chain_getBlockHash` at all, because each header names its parent. It
    /// names nothing about this wallet: every wallet on the chain reads the
    /// same headers.
    ///
    /// The caller supplies the bottom of the chain and must compare
    /// `blocks[0].hash` against a hash it already trusts, which is the store's
    /// genesis or a checkpoint an earlier pass recorded. Without that
    /// comparison this returns a self-consistent chain and nothing more, and a
    /// node can build one of those out of nothing.
    pub fn header_chain(&self, head: &ChainHead, anchor: u32) -> Result<Vec<VerifiedBlock>> {
        ensure_le(anchor, head.number)?;
        let span = usize::try_from(head.number - anchor).unwrap_or(usize::MAX);
        let mut blocks = Vec::with_capacity(span.saturating_add(1));
        let mut hash = head.hash;
        let mut number = head.number;
        loop {
            let raw = self.header_at(&hash)?;
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
            blocks.push(VerifiedBlock {
                number,
                hash,
                parent_hash: decode_hash(&raw.parent_hash)?,
                zk_tree_root: Digest::from_bytes(&decode_hash(&raw.zk_tree_root)?).map_err(
                    |_| anyhow!("block {number}'s zkTreeRoot is not a canonical digest"),
                )?,
                author_label: raw.author_label()?,
            });
            if number == anchor {
                break;
            }
            hash = decode_hash(&raw.parent_hash)?;
            number -= 1;
        }
        blocks.reverse();
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
    /// A missing entry is the pallet's `empty_hash()`, which is what
    /// `tree::get_leaf_hash` substitutes, so a local rebuild pads the same way
    /// the chain does.
    pub fn leaf_hashes(&self, range: std::ops::Range<u64>, at: &[u8; 32]) -> Result<Vec<Digest>> {
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
                        Digest::from_bytes(&bytes).map_err(|_| {
                            anyhow!(
                                "ZkTree::Leaves({index}) is {} and is not a canonical digest, so \
                                 this wallet cannot rebuild the tree over it. Pass \
                                 `--merkle-rpc` to ask the node for the path.",
                                hex::encode(bytes)
                            )
                        })?
                    }
                    None => qnero_circuit::merkle::empty_digest(),
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
        let leaves = self.leaf_hashes(0..leaf_count, at)?;
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
        let at = hex_0x(at);
        let prefix_hex = hex_0x(&prefix);
        let mut out = BTreeSet::new();
        let mut start: Option<String> = None;
        loop {
            let params = match &start {
                Some(cursor) => json!([prefix_hex, KEY_PAGE, cursor, at]),
                None => json!([prefix_hex, KEY_PAGE, Value::Null, at]),
            };
            let keys: Vec<String> = self.rpc.call_as("state_getKeysPaged", params)?;
            if keys.is_empty() {
                break;
            }
            let last = keys[keys.len() - 1].clone();
            for key in &keys {
                let bytes = decode_hex(key)?;
                // `twox_128(pallet) ++ twox_128(item) ++ blake2_128(k) ++ k`.
                let Some(raw) = bytes.get(prefix.len() + 16..) else {
                    bail!("a UsedNullifiers key is {} bytes, too short", bytes.len());
                };
                if raw.len() != 32 {
                    bail!(
                        "a UsedNullifiers key carries a {}-byte nullifier, expected 32",
                        raw.len()
                    );
                }
                out.insert(hex::encode(raw));
            }
            if keys.len() < KEY_PAGE {
                break;
            }
            // The guard against a node that answers the same page forever.
            if start.as_deref() == Some(last.as_str()) {
                bail!("state_getKeysPaged stopped advancing at {last}");
            }
            start = Some(last);
        }
        Ok(out)
    }

    /// The commitment and ciphertext of every leaf in `range`, at one block.
    ///
    /// Every map is `Identity`-hashed on the leaf index, so paging is by index
    /// alone and `state_getKeysPaged` is unnecessary.
    ///
    /// Four keys per leaf. `CoinbaseValues` is the fourth and it is what makes
    /// a coinbase note readable: its value is public, because the chain hashes
    /// it into the commitment over an `inner` it cannot open, and the
    /// ciphertext beside it carries `(rho, r)` and a value of zero. Presence in
    /// that map is also what tells a coinbase leaf from a settled output.
    ///
    /// **A key the node withholds below `leaf_count` refuses the read.**
    /// `leaf_count` is `ZkTree::LeafCount` read at this same block hash, and
    /// every leaf under it was appended by one of the three writers in
    /// `pallet-shielded`, each of which writes its keys in the same call:
    ///
    /// - `shield` writes `Leaves`, `Ciphertexts` and `LeafBlocks`;
    /// - a settled slot writes `Leaves`, `Ciphertexts` and `LeafBlocks` for
    ///   each of its two outputs;
    /// - the coinbase writes `Leaves`, `LeafBlocks` and `CoinbaseValues`, and
    ///   `Ciphertexts` only when the author encrypted a payload, which under
    ///   v1 never happens.
    ///
    /// Nothing removes any of them. So below the count there is a commitment
    /// and a block at every index, and a ciphertext at every index that is not
    /// a coinbase, and an absent answer for one of those is a node withholding
    /// it. Each of the three hides a leaf in its own way and every one of them
    /// is permanent: without the commitment the leaf is skipped, without the
    /// ciphertext it reads as a leaf nobody can open, and without the block a
    /// coinbase leaf is stepped over, and in all three cases the pass commits
    /// a watermark above it and nothing reads it again without a rescan. The
    /// read is refused instead, naming the key, the index, the count and the
    /// block. `fetchLeaves` in `wallet-web/src/chain/reads.ts` refuses the
    /// identical set.
    ///
    /// The ciphertext rule here is the coarse half of a rule that is finished
    /// one layer up. Presence of `CoinbaseValues` does **not** decide that a
    /// leaf is a coinbase: presence is the node's to write, and eight invented
    /// bytes beside an incoming transfer used to route it onto the coinbase
    /// rebuild and hide the payment. What decides is where the block headers
    /// put the leaf, in `crate::typing`, which refuses an invented coinbase
    /// value below a block's last leaf and a withheld one at the coinbase
    /// position of a block this wallet mined. So this function refuses only
    /// the shape that is wrong whatever kind the leaf turns out to be, a leaf
    /// carrying neither key, and the typed rules refuse the rest by name.
    pub fn leaves(
        &self,
        range: std::ops::Range<u64>,
        at: &[u8; 32],
        leaf_count: u64,
    ) -> Result<Vec<LeafRecord>> {
        let at_hash = hex_0x(at);
        let mut out = Vec::new();
        for chunk_start in range.clone().step_by(LEAF_BATCH) {
            let chunk_end = (chunk_start + LEAF_BATCH as u64).min(range.end);
            let mut keys = Vec::with_capacity(((chunk_end - chunk_start) * 4) as usize);
            for index in chunk_start..chunk_end {
                keys.push(identity_map_key(ZK_TREE_PALLET, "Leaves", index));
                keys.push(identity_map_key(SHIELDED_PALLET, "Ciphertexts", index));
                keys.push(identity_map_key(SHIELDED_PALLET, "LeafBlocks", index));
                keys.push(identity_map_key(SHIELDED_PALLET, "CoinbaseValues", index));
            }
            let values = self.rpc.storage_batch(&keys, &at_hash)?;
            for (offset, index) in (chunk_start..chunk_end).enumerate() {
                let commitment = values[offset * 4].clone();
                let ciphertext = values[offset * 4 + 1].clone();
                let block = values[offset * 4 + 2].clone();
                let coinbase_value = values[offset * 4 + 3].clone();
                let below_count = index < leaf_count;
                if below_count && commitment.is_none() {
                    return Err(withheld_key(index, leaf_count, at, "ZkTree::Leaves"));
                }
                if below_count && block.is_none() {
                    return Err(withheld_key(index, leaf_count, at, "Shielded::LeafBlocks"));
                }
                if below_count && ciphertext.is_none() && coinbase_value.is_none() {
                    return Err(withheld_key(index, leaf_count, at, "Shielded::Ciphertexts"));
                }
                out.push(LeafRecord {
                    index,
                    commitment: commitment
                        .map(|bytes| {
                            <[u8; 32]>::try_from(bytes.as_slice())
                                .map_err(|_| anyhow!("ZkTree::Leaves({index}) is not 32 bytes"))
                        })
                        .transpose()?,
                    // `BoundedVec<u8, _>` encodes as a `Vec<u8>`.
                    ciphertext: ciphertext
                        .map(|bytes| decode_stored_bytes(&bytes, "Shielded::Ciphertexts", index))
                        .transpose()?,
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
                 {}",
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
        "Shielded::LeafBlocks" => {
            "A leaf with no block is stepped over where it is a coinbase, and dated by nothing \
             where it is not, and the pass would write a watermark above it"
        }
        _ => {
            "A leaf with no ciphertext and no coinbase value reads as a leaf nobody can open, so \
             a payment on it would be skipped and the pass would write a watermark above it"
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

/// A stored `Vec<u8>`: a compact length prefix, then exactly that many bytes.
///
/// The length is checked against what follows it rather than left to
/// `Vec::<u8>::decode`, which stops at the declared length and ignores
/// whatever trails it. `decodeBytes` in `wallet-web/src/chain/reads.ts`
/// refuses the same disagreement, and a wallet that took the prefix's word for
/// it would hand the ciphertext to `try_receive` at a length the chain did not
/// store: the decryption fails, the leaf counts as somebody else's, and the
/// pass reports a zero balance over a completed scan.
fn decode_stored_bytes(bytes: &[u8], what: &str, index: u64) -> Result<Vec<u8>> {
    let mut cursor = bytes;
    let value = Vec::<u8>::decode(&mut cursor)
        .with_context(|| format!("{what}({index}) is not a byte vector"))?;
    if !cursor.is_empty() {
        bail!(
            "{what}({index}) declares {} bytes and carries {} more after them. This runtime \
             stores it differently from what this build decodes.",
            value.len(),
            cursor.len()
        );
    }
    Ok(value)
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
    pub ciphertext: Option<Vec<u8>>,
    pub block_number: Option<u32>,
    /// The public value of a coinbase note, in pool quanta. `Some` for exactly
    /// the leaves a block's coinbase minted.
    pub coinbase_value: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored `Vec<u8>` whose length prefix and body disagree is refused.
    ///
    /// `Vec::<u8>::decode` stops at the declared length and ignores whatever
    /// trails it, so without this check a wallet hands `try_receive` a
    /// ciphertext at a length the chain did not store: the decryption fails,
    /// the leaf counts as somebody else's, and the pass reports a zero balance
    /// over a completed scan. `decodeBytes` in
    /// `wallet-web/src/chain/reads.ts` refuses the same disagreement.
    #[test]
    fn a_stored_byte_vector_whose_prefix_and_body_disagree_is_refused() {
        // Compact 3, then three bytes: the honest shape.
        let honest = [0x0cu8, 1, 2, 3];
        assert_eq!(
            decode_stored_bytes(&honest, "Shielded::Ciphertexts", 7).expect("decodes"),
            vec![1, 2, 3]
        );

        // The same prefix with a fourth byte trailing it.
        let trailing = [0x0cu8, 1, 2, 3, 4];
        let error = decode_stored_bytes(&trailing, "Shielded::Ciphertexts", 7)
            .expect_err("a body longer than its prefix is refused");
        let message = format!("{error:#}");
        assert!(message.contains("Shielded::Ciphertexts(7)"), "{message}");
        assert!(message.contains("declares 3 bytes"), "{message}");
        assert!(message.contains("carries 1 more"), "{message}");

        // And a prefix that promises more than the value carries, which
        // `Vec::<u8>::decode` refuses on its own.
        let short = [0x0cu8, 1, 2];
        assert!(decode_stored_bytes(&short, "Shielded::Ciphertexts", 7).is_err());
    }
}
