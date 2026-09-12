//! SCALE encoding and storage-key helpers.
//!
//! The wallet hand-encodes what it sends. `subxt` is the usual answer and it
//! cannot read this chain: `qp_header::Header` carries a sixth field,
//! `zk_tree_root`, between `extrinsics_root` and `digest`, and it hashes with
//! Poseidon2 where `subxt`'s `SubstrateHeader` hashes with Blake2. A decoder
//! that silently disagrees about the header is the one component a shielded
//! wallet cannot tolerate, because the header is the anchor every spend proof
//! commits to. See `docs/WALLET.md`.

use blake2::digest::{Update, VariableOutput};
use codec::{Compact, Encode};
use std::hash::Hasher;

/// `twox_128`, the hasher every pallet storage prefix uses.
pub fn twox_128(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, chunk) in out.chunks_mut(8).enumerate() {
        let mut hasher = twox_hash::XxHash64::with_seed(index as u64);
        hasher.write(data);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes());
    }
    out
}

/// Blake2b with a 16-byte output, the first half of a `Blake2_128Concat` key.
pub fn blake2_128(data: &[u8]) -> [u8; 16] {
    let mut hasher = blake2::Blake2bVar::new(16).expect("16 is a valid blake2b output length");
    hasher.update(data);
    let mut out = [0u8; 16];
    hasher
        .finalize_variable(&mut out)
        .expect("the output buffer is the requested length");
    out
}

/// Blake2b with a 32-byte output: the extrinsic hash and the hashed signing
/// payload both use it.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake2::Blake2bVar::new(32).expect("32 is a valid blake2b output length");
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("the output buffer is the requested length");
    out
}

/// The 32-byte prefix of one storage map or value: `twox_128(pallet) ++
/// twox_128(item)`.
pub fn storage_prefix(pallet: &str, item: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&twox_128(pallet.as_bytes()));
    key.extend_from_slice(&twox_128(item.as_bytes()));
    key
}

/// A map key under the `Identity` hasher: the SCALE encoding of the key, with
/// nothing hashed. Every leaf-indexed map in `pallet-shielded` and
/// `pallet-zk-tree` uses it, which is what lets a wallet page by leaf index
/// alone.
pub fn identity_map_key(pallet: &str, item: &str, index: u64) -> Vec<u8> {
    let mut key = storage_prefix(pallet, item);
    key.extend_from_slice(&index.to_le_bytes());
    key
}

/// A map key under `Blake2_128Concat`: `blake2_128(k) ++ k`.
pub fn blake2_128_concat_map_key(pallet: &str, item: &str, raw_key: &[u8]) -> Vec<u8> {
    let mut key = storage_prefix(pallet, item);
    key.extend_from_slice(&blake2_128(raw_key));
    key.extend_from_slice(raw_key);
    key
}

/// SCALE `Vec<u8>`: a compact length then the bytes.
pub fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut out = Compact(bytes.len() as u64).encode();
    out.extend_from_slice(bytes);
    out
}

/// A compact length prefix on its own.
pub fn compact_len(len: usize) -> Vec<u8> {
    Compact(len as u64).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned against `sp_core::hashing`, which is what the node computes its
    /// storage keys with. A drifted prefix reads an absent key and a wallet
    /// reports an empty pool where it should report an error.
    #[test]
    fn twox_128_matches_the_substrate_vectors() {
        assert_eq!(
            hex::encode(twox_128(b"System")),
            "26aa394eea5630e07c48ae0c9558cef7"
        );
        assert_eq!(
            hex::encode(twox_128(b"Account")),
            "b99d880ec681799c0cf30e8886371da9"
        );
    }

    #[test]
    fn blake2_vectors_match_substrate() {
        // `sp_core::hashing::blake2_256(b"")`.
        assert_eq!(
            hex::encode(blake2_256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex::encode(blake2_128(b"")),
            "cae66941d9efbd404e4d88758ea67670"
        );
    }

    #[test]
    fn a_vec_u8_encodes_as_a_compact_length_then_bytes() {
        assert_eq!(encode_bytes(&[1, 2, 3]), vec![0x0c, 1, 2, 3]);
        assert_eq!(encode_bytes(&[]), vec![0x00]);
    }
}
