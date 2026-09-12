//! Reads of chain state: headers, the commitment tree, ciphertexts,
//! nullifiers.

use anyhow::{anyhow, bail, Context, Result};
use codec::Decode;
use qnero_circuit::header::{HeaderInputs, DIGEST_LOGS_SIZE};
use qnero_circuit::merkle::{MerklePath, SIBLINGS_PER_LEVEL};
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

    /// `zkTree_getState`, the tree's own view at the best block.
    pub fn tree_state(&self) -> Result<TreeState> {
        self.rpc.call_as("zkTree_getState", json!([]))
    }

    /// Leaf count as of one block, so a scan's reads are all pinned to the
    /// same state.
    pub fn leaf_count_at(&self, at: &[u8; 32]) -> Result<u64> {
        let key = storage_prefix(ZK_TREE_PALLET, "LeafCount");
        match self.rpc.storage(&key, Some(&hex_0x(at)))? {
            Some(bytes) => {
                Ok(u64::decode(&mut &bytes[..]).context("ZkTree::LeafCount is not a u64")?)
            }
            None => Ok(0),
        }
    }

    pub fn entry_count_at(&self, at: &[u8; 32]) -> Result<u64> {
        let key = storage_prefix(SHIELDED_PALLET, "EntryCount");
        match self.rpc.storage(&key, Some(&hex_0x(at)))? {
            Some(bytes) => {
                Ok(u64::decode(&mut &bytes[..]).context("Shielded::EntryCount is not a u64")?)
            }
            None => Ok(0),
        }
    }

    /// The commitment and ciphertext of every leaf in `range`, at one block.
    ///
    /// Both maps are `Identity`-hashed on the leaf index, so paging is by
    /// index alone and `state_getKeysPaged` is unnecessary. An absent
    /// ciphertext is
    /// normal: the shielded pool shares one tree with wormhole transfers and
    /// with the mining-reward leaf every block appends, and none of those
    /// carry one.
    pub fn leaves(&self, range: std::ops::Range<u64>, at: &[u8; 32]) -> Result<Vec<LeafRecord>> {
        let at = hex_0x(at);
        let mut out = Vec::new();
        for chunk_start in range.clone().step_by(LEAF_BATCH) {
            let chunk_end = (chunk_start + LEAF_BATCH as u64).min(range.end);
            let mut keys = Vec::with_capacity(((chunk_end - chunk_start) * 3) as usize);
            for index in chunk_start..chunk_end {
                keys.push(identity_map_key(ZK_TREE_PALLET, "Leaves", index));
                keys.push(identity_map_key(SHIELDED_PALLET, "Ciphertexts", index));
                keys.push(identity_map_key(SHIELDED_PALLET, "LeafBlocks", index));
            }
            let values = self.rpc.storage_batch(&keys, &at)?;
            for (offset, index) in (chunk_start..chunk_end).enumerate() {
                let commitment = values[offset * 3].clone();
                let ciphertext = values[offset * 3 + 1].clone();
                let block = values[offset * 3 + 2].clone();
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
                        .map(|bytes| {
                            Vec::<u8>::decode(&mut &bytes[..]).with_context(|| {
                                format!("Shielded::Ciphertexts({index}) is not a byte vector")
                            })
                        })
                        .transpose()?,
                    block_number: block
                        .map(|bytes| {
                            u32::decode(&mut &bytes[..]).with_context(|| {
                                format!("Shielded::LeafBlocks({index}) is not a u32")
                            })
                        })
                        .transpose()?,
                });
            }
        }
        Ok(out)
    }

    /// Whether each nullifier has been settled, at one block.
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

/// Leaves read per `state_queryStorageAt` call.
const LEAF_BATCH: usize = 64;

#[derive(Debug, Clone, Deserialize)]
pub struct TreeState {
    pub root: [u8; 32],
    pub leaf_count: u64,
    pub depth: u8,
}

/// One leaf as the chain holds it.
#[derive(Debug, Clone)]
pub struct LeafRecord {
    pub index: u64,
    pub commitment: Option<[u8; 32]>,
    pub ciphertext: Option<Vec<u8>>,
    pub block_number: Option<u32>,
}
