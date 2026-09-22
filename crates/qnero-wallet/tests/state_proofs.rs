mod support;

use qnero_wallet::{
    chain::Chain,
    rpc::{hex_0x, RpcClient},
    scale::{blake2_128_concat_map_key, storage_prefix},
};
use support::{FakeNode, NodeState};

#[test]
fn authenticated_values_and_absence_use_one_selected_header() {
    let mut state = NodeState {
        head_number: 2,
        ..Default::default()
    };
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
    let state = NodeState {
        head_number: 1,
        missing_proof_nodes: true,
        ..Default::default()
    };
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let at = Chain::new(&rpc).head().unwrap().hash;
    assert!(rpc.storage(b"absent", Some(&hex_0x(&at))).is_err());
    assert_eq!(node.state().calls("state_getStorage"), 0);
}

#[test]
fn public_nullifier_enumeration_cannot_silently_omit_an_entry() {
    let mut state = NodeState {
        head_number: 1,
        ..Default::default()
    };
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

/// A body is authenticated against the `extrinsicsRoot` of the header it is
/// asked for, and nothing else.
///
/// The state path proves one key at a time and an absent answer needs a rule
/// about which keys a leaf owes. A body roots as a whole: drop an extrinsic,
/// reorder two, change a byte, and the root moves. So there is no per-payload
/// absence left to detect, and the one thing a node can still do is refuse to
/// serve the block.
#[test]
fn a_body_is_authenticated_against_its_own_headers_extrinsics_root() {
    let mut state = NodeState {
        head_number: 3,
        ..Default::default()
    };
    support::put_payload(&mut state, 2, &[0x11u8; 96]);
    support::put_payload(&mut state, 2, &[0x22u8; 96]);
    let node = FakeNode::start(state);
    let rpc = RpcClient::new(&node.url);
    let chain = Chain::new(&rpc);
    let at = node.state().hash_at(2);

    let body = chain.authenticated_body(&at).expect("the body roots");
    assert_eq!(body.len(), 2);
    let payloads = chain
        .block_payloads(&support::test_metadata(), &body)
        .expect("the envelopes walk");
    assert_eq!(payloads, vec![vec![0x11u8; 96], vec![0x22u8; 96]]);

    // One byte, changed on the way out, so the header still carries the root
    // of the body this node holds.
    node.state().tampered_bodies.insert(2);
    let refused = chain
        .authenticated_body(&at)
        .expect_err("a body the header does not carry is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("roots to"), "{message}");
    assert!(message.contains("Nothing has been changed"), "{message}");

    // And a node that will not serve the block at all.
    node.state().tampered_bodies.clear();
    node.state().withheld_bodies.insert(2);
    let refused = chain
        .authenticated_body(&at)
        .expect_err("a withheld body is refused");
    let message = format!("{refused:#}");
    assert!(message.contains("no body beside it"), "{message}");
}
