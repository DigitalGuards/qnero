mod support;

use qnero_wallet::{
    chain::Chain,
    rpc::{hex_0x, RpcClient},
    scale::{blake2_128_concat_map_key, storage_prefix},
};
use support::{FakeNode, NodeState};

#[test]
fn authenticated_values_and_absence_use_one_selected_header() {
    let mut state = NodeState::default();
    state.head_number = 2;
    let key = storage_prefix("Shielded", "EntryCount");
    state.put_storage(&key, &7u64.to_le_bytes());
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let at = Chain::new(&rpc).head().unwrap().hash;
    assert_eq!(
        rpc.storage(&key, Some(&hex_0x(&at))).unwrap(),
        Some(7u64.to_le_bytes().to_vec())
    );
    assert_eq!(rpc.storage(b"absent", Some(&hex_0x(&at))).unwrap(), None);
    let state = node.state();
    assert_eq!(state.calls("state_getStorage"), 0);
    assert_eq!(state.calls("state_queryStorageAt"), 0);
    assert_eq!(state.calls("state_getReadProof"), 2);
}

#[test]
fn missing_proof_nodes_refuse_without_unproven_fallback() {
    let mut state = NodeState::default();
    state.head_number = 1;
    state.missing_proof_nodes = true;
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let at = Chain::new(&rpc).head().unwrap().hash;
    assert!(rpc.storage(b"absent", Some(&hex_0x(&at))).is_err());
    assert_eq!(node.state().calls("state_getStorage"), 0);
}

#[test]
fn public_nullifier_enumeration_cannot_silently_omit_an_entry() {
    let mut state = NodeState::default();
    state.head_number = 1;
    let mut expected = std::collections::BTreeSet::new();
    for value in 0u8..32 {
        let nullifier = [value; 32];
        let key = blake2_128_concat_map_key("Shielded", "UsedNullifiers", &nullifier);
        state.put_storage(&key, &[]);
        expected.insert(hex::encode(nullifier));
        if value == 12 {
            state.hidden_listing_keys.insert(hex_0x(&key));
        }
    }
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let at = chain.head().unwrap().hash;
    // Inline nodes may recover an omitted entry; a missing hashed branch must
    // refuse. Neither outcome admits an incomplete spent set.
    if let Ok(actual) = chain.used_nullifiers_at(&at) {
        assert_eq!(actual, expected);
    }
    node.state().hidden_listing_keys.clear();
    assert_eq!(chain.used_nullifiers_at(&at).unwrap(), expected);
}

#[test]
fn pruned_ciphertext_is_recovered_from_its_authenticated_creation_state() {
    let mut state = NodeState::default();
    state.head_number = 1;
    state.put_storage(&storage_prefix("ZkTree", "LeafCount"), &2u64.to_le_bytes());
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let first = chain.head().unwrap();
    let before = chain.leaves(0..2, &first.hash, 2).unwrap();
    assert!(before[0].ciphertext.is_some());
    {
        let mut state = node.state();
        state.head_number = 100;
        state.withheld_ciphertexts.insert(0);
    }
    let later = chain.head().unwrap();
    let after = chain.leaves(0..2, &later.hash, 2).unwrap();
    assert_eq!(after[0].ciphertext, before[0].ciphertext);
    assert_eq!(
        chain.authenticated_ancestor(&later.hash, 1).unwrap(),
        first.hash
    );
}
