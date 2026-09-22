//! Read values and absence from the raw nodes returned by state_getReadProof,
//! and recompute the `extrinsicsRoot` a block header carries over its body.
//!
//! The caller supplies the state root, or the extrinsics root, from a header
//! it has independently selected and rehashed. This verifies integrity
//! relative to that header. It does not establish proof of work or choose the
//! canonical chain.
#![no_std]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use sp_core::{Blake2Hasher, H256};
use sp_trie::{
    LayoutV0, LayoutV1, StorageProof, Trie, TrieConfiguration, TrieDBBuilder, TrieDBIterator,
};

type Layout = LayoutV1<Blake2Hasher>;

/// The layout `extrinsicsRoot` is built with.
///
/// `frame_system::extrinsics_data_root` hashes the body with the header's own
/// hasher at the state version the runtime's `system_version` selects
/// (`chain/pallets/frame-system/src/lib.rs`, `finalize`). The header hasher is
/// `BlakeTwo256`, and `system_version: 1` selects `StateVersion::V0`, which
/// `sp_io::trie::blake2_256_ordered_root` answers with exactly this layout.
///
/// `system_version` is therefore a consensus constant every wallet depends on:
/// sp-version switches the construction to V1 at 2, silently, and every
/// recomputation below would then disagree with every header. The runtime pins
/// it at 1 with a test that names this function.
type BodyLayout = LayoutV0<Blake2Hasher>;

/// Resource limits apply before constructing the proof database.
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROOF_NODES: usize = 1_000_000;
pub const MAX_PREFIX_ENTRIES: usize = 1_000_000;

/// The largest body this will hash, in bytes.
///
/// `RuntimeBlockLength` is `BlockLength::max_with_normal_ratio(5 * 1024 * 1024,
/// ..)` (`chain/runtime/src/configs/mod.rs`), so no block the chain accepts
/// carries more than 5 MiB of extrinsic data. The margin above it covers the
/// compact length prefixes `chain_getBlock` hands each extrinsic over with and
/// leaves the bound a resource guard rather than a second consensus rule: a
/// body inside this and outside the runtime's own limit simply roots to a
/// header no chain published.
pub const MAX_BODY_BYTES: usize = 6 * 1024 * 1024;

/// The largest number of extrinsics this will hash.
///
/// The trie is keyed by `Compact<u32>` of the index, so the construction has
/// no count limit of its own. This one is a memory guard on what a node can
/// hand over before anything is allocated per item.
pub const MAX_BODY_EXTRINSICS: usize = 65_536;

/// Recompute a block's `extrinsicsRoot` from the body a node served.
///
/// Each extrinsic is the SCALE-encoded `Vec<u8>` `chain_getBlock` returns,
/// compact length prefix included: that is what the runtime enumerated into
/// the trie and what the header commits to. The caller compares the answer
/// against the `extrinsicsRoot` of a header it has already rehashed to the
/// hash it asked for, and only then are the bodies authenticated.
///
/// The budgets are checked before anything is built, because the body is a
/// node's answer and its size is a node's choice.
pub fn extrinsics_root(extrinsics: &[Vec<u8>]) -> Result<[u8; 32], String> {
    if extrinsics.len() > MAX_BODY_EXTRINSICS {
        return Err(format!(
            "this block body carries {} extrinsics, above the {MAX_BODY_EXTRINSICS} this wallet \
             will hash. Nothing has been read from it.",
            extrinsics.len()
        ));
    }
    let bytes = extrinsics
        .iter()
        .try_fold(0usize, |sum, extrinsic| sum.checked_add(extrinsic.len()))
        .ok_or("block body size overflow")?;
    if bytes > MAX_BODY_BYTES {
        return Err(format!(
            "this block body measures {bytes} bytes, above the {MAX_BODY_BYTES} this wallet will \
             hash and above what `RuntimeBlockLength` lets a block carry. Nothing has been read \
             from it."
        ));
    }
    Ok(BodyLayout::ordered_trie_root(extrinsics).into())
}

fn database(nodes: Vec<Vec<u8>>) -> Result<sp_trie::MemoryDB<Blake2Hasher>, String> {
    if nodes.len() > MAX_PROOF_NODES {
        return Err("state proof has too many nodes".into());
    }
    let bytes = nodes
        .iter()
        .try_fold(0usize, |sum, node| sum.checked_add(node.len()))
        .ok_or("state proof size overflow")?;
    if bytes > MAX_PROOF_BYTES {
        return Err("state proof exceeds the verification memory budget".into());
    }
    Ok(StorageProof::new(nodes).into_memory_db::<Blake2Hasher>())
}

/// Reconstruct each requested value, including authenticated absence.
/// Missing proof nodes always produce an error, never an absent value.
/// Raw RPC proofs are storage proofs, not the compact proof format consumed
/// by sp_trie's verify_trie_proof helper.
pub fn read_values(
    root: [u8; 32],
    nodes: Vec<Vec<u8>>,
    keys: &[Vec<u8>],
) -> Result<Vec<Option<Vec<u8>>>, String> {
    let db = database(nodes)?;
    let root = H256::from(root);
    let trie = TrieDBBuilder::<Layout>::new(&db, &root).build();
    keys.iter()
        .map(|key| {
            trie.get(key)
                .map_err(|error| format!("state proof is invalid or incomplete: {error:?}"))
        })
        .collect()
}

/// One storage entry recovered from a proof: its full key and its value.
pub type StorageEntry = (Vec<u8>, Vec<u8>);

/// Reconstruct the entire prefix. Traversal proves completeness: an omitted
/// hashed branch fails, and an inline entry is recovered even if an RPC key
/// listing omitted it. No values outside the prefix need to be downloaded.
pub fn read_prefix(
    root: [u8; 32],
    nodes: Vec<Vec<u8>>,
    prefix: &[u8],
) -> Result<Vec<StorageEntry>, String> {
    let db = database(nodes)?;
    let root = H256::from(root);
    let trie = TrieDBBuilder::<Layout>::new(&db, &root).build();
    let iter = TrieDBIterator::<Layout>::new_prefixed(&trie, prefix)
        .map_err(|error| format!("state prefix proof is incomplete: {error:?}"))?;
    let mut out = Vec::new();
    for entry in iter {
        if out.len() == MAX_PREFIX_ENTRIES {
            return Err("state prefix exceeds the supported scan size".into());
        }
        out.push(entry.map_err(|error| format!("state prefix proof is incomplete: {error:?}"))?);
    }
    Ok(out)
}

#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures {
    use super::*;
    use sp_trie::{Recorder, TrieDBMutBuilder, TrieMut};

    /// Match the raw recorder format returned by a Substrate read-proof RPC.
    pub fn proof(entries: &[(Vec<u8>, Vec<u8>)], keys: &[Vec<u8>]) -> ([u8; 32], Vec<Vec<u8>>) {
        let mut db = sp_trie::MemoryDB::<Blake2Hasher>::new(&[0]);
        let mut root = H256::default();
        {
            let mut trie = TrieDBMutBuilder::<Layout>::new(&mut db, &mut root).build();
            for (key, value) in entries {
                trie.insert(key, value).unwrap();
            }
        }
        let mut recorder = Recorder::<Layout>::new();
        {
            let trie = TrieDBBuilder::<Layout>::new(&db, &root)
                .with_recorder(&mut recorder)
                .build();
            for key in keys {
                trie.get(key).unwrap();
            }
        }
        (
            root.into(),
            recorder
                .drain()
                .into_iter()
                .map(|record| record.data)
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn entries() -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (b"map/a".to_vec(), vec![7; 80]),
            (b"map/z".to_vec(), vec![9; 80]),
            (b"other".to_vec(), vec![4; 80]),
        ]
    }

    #[test]
    fn reads_values_external_value_nodes_and_absence() {
        let keys = vec![b"map/a".to_vec(), b"map/missing".to_vec()];
        let (root, proof) = fixtures::proof(&entries(), &keys);
        assert_eq!(
            read_values(root, proof, &keys).unwrap(),
            vec![Some(vec![7; 80]), None]
        );
    }

    #[test]
    fn refuses_missing_nodes_and_wrong_roots() {
        let keys = vec![b"map/a".to_vec()];
        let (root, proof) = fixtures::proof(&entries(), &keys);
        assert!(read_values([5; 32], proof.clone(), &keys).is_err());
        assert!(read_values(root, Vec::new(), &keys).is_err());
        let mut truncated = proof;
        truncated.pop();
        assert!(read_values(root, truncated, &keys).is_err());
    }

    /// The empty trie root, which is the one value in this construction that
    /// is published rather than computed here.
    ///
    /// `LayoutV0`'s hash of the empty node, `blake2_256(&[0x00])`, is the same
    /// constant every Substrate chain carries in the header of a block that
    /// included nothing. A body with no extrinsic in it must not panic and
    /// must reach it.
    const EMPTY_TRIE_ROOT: [u8; 32] =
        hex_literal_root("03170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c111314");

    /// A 64-character hex string as 32 bytes, at compile time, so the constant
    /// above reads as the value it is quoted from.
    const fn hex_literal_root(text: &str) -> [u8; 32] {
        let bytes = text.as_bytes();
        assert!(bytes.len() == 64);
        let mut out = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            out[index] = nibble(bytes[index * 2]) * 16 + nibble(bytes[index * 2 + 1]);
            index += 1;
        }
        out
    }

    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("the root literal is lowercase hex"),
        }
    }

    /// An idle block carries two inherents and nothing else, so that is the
    /// common case, and the empty body is the one that must not panic.
    #[test]
    fn an_inherents_only_body_roots_correctly() {
        assert_eq!(extrinsics_root(&[]).unwrap(), EMPTY_TRIE_ROOT);

        let timestamp = vec![
            0x28u8, 0x04, 0x00, 0x00, 0x0b, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00,
        ];
        let coinbase = vec![0x10u8, 0x04, 24, 3];
        let two = extrinsics_root(&[timestamp.clone(), coinbase.clone()]).unwrap();
        assert_ne!(two, EMPTY_TRIE_ROOT);
        // The trie is keyed by the extrinsic's index, so the body is ordered
        // and swapping two extrinsics is a different block.
        assert_ne!(two, extrinsics_root(&[coinbase, timestamp]).unwrap());
    }

    #[test]
    fn a_body_over_the_byte_or_count_budget_is_refused() {
        let one_too_many = vec![Vec::new(); MAX_BODY_EXTRINSICS + 1];
        let refused = extrinsics_root(&one_too_many).expect_err("the count is bounded");
        assert!(refused.contains("extrinsics"), "{refused}");

        // Two extrinsics whose lengths sum past the byte budget, so the
        // refusal is the total and not any one of them.
        let half = MAX_BODY_BYTES / 2 + 1;
        let over = vec![vec![0u8; half], vec![0u8; half]];
        let refused = extrinsics_root(&over).expect_err("the total is bounded");
        assert!(refused.contains("bytes"), "{refused}");

        // And the budget itself is reachable: a body exactly at it roots.
        let at = vec![vec![0u8; MAX_BODY_BYTES]];
        assert!(extrinsics_root(&at).is_ok());
    }

    #[test]
    fn prefix_requires_all_entries_and_proves_empty_prefix() {
        let keys = vec![
            b"map/".to_vec(),
            b"map/a".to_vec(),
            b"map/z".to_vec(),
            b"empty/".to_vec(),
        ];
        let (root, proof) = fixtures::proof(&entries(), &keys);
        assert_eq!(
            read_prefix(root, proof.clone(), b"map/").unwrap(),
            entries()[..2]
        );
        assert!(read_prefix(root, proof, b"empty/").unwrap().is_empty());
        let (root, partial) = fixtures::proof(&entries(), &keys[..2]);
        assert!(read_prefix(root, partial, b"map/").is_err());
    }
}
