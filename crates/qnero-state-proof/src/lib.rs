//! Read values and absence from the raw nodes returned by state_getReadProof.
//!
//! The caller supplies the state root from a header it has independently
//! selected and rehashed. This verifies state integrity relative to that
//! header. It does not establish proof of work or choose the canonical chain.
#![no_std]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use sp_core::{Blake2Hasher, H256};
use sp_trie::{LayoutV1, StorageProof, Trie, TrieDBBuilder, TrieDBIterator};

type Layout = LayoutV1<Blake2Hasher>;

/// Resource limits apply before constructing the proof database.
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROOF_NODES: usize = 1_000_000;
pub const MAX_PREFIX_ENTRIES: usize = 1_000_000;

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

/// Reconstruct the entire prefix. Traversal proves completeness: an omitted
/// hashed branch fails, and an inline entry is recovered even if an RPC key
/// listing omitted it. No values outside the prefix need to be downloaded.
pub fn read_prefix(
    root: [u8; 32],
    nodes: Vec<Vec<u8>>,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
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
