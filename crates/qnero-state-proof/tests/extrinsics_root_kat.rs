//! The known answer for `extrinsicsRoot`, held in a file both wallets read.
//!
//! The construction is `LayoutV0<Blake2Hasher>::ordered_trie_root`, which is
//! what `frame_system::extrinsics_data_root` reaches while the runtime's
//! `system_version` is 1. sp-version switches that to V1 at 2 without
//! changing a type or a signature, so nothing but a pinned answer catches the
//! day the two constructions part: a wallet whose recomputation has moved
//! refuses every block of the chain it is pointed at, with no way to say why.
//!
//! The runtime writes its own vector at
//! `chain/runtime/tests/fixtures/extrinsics_root_kat.json`, out of a block it
//! actually executed, and that file is the authority. This one carries the
//! same two fields so the coordinator can run this function over the
//! runtime's list and compare, and so `wallet-web`'s `extrinsics-root.test.ts`
//! has a body to assert the same answer over without a node.

use std::path::PathBuf;

fn fixture(name: &str) -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&text).expect("the fixture is JSON")
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    let text = value.as_str().expect("a hex string");
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("hex")
}

/// The body in the fixture roots to the root in the fixture.
///
/// Byte fixed on both sides: change the construction and this fails, change
/// the body and this fails.
#[test]
fn an_ordered_trie_root_matches_the_runtimes_own() {
    let kat = fixture("extrinsics_root_kat.json");
    let body: Vec<Vec<u8>> = kat["extrinsics"]
        .as_array()
        .expect("a list of extrinsics")
        .iter()
        .map(bytes)
        .collect();
    let expected = bytes(&kat["root"]);
    assert_eq!(
        qnero_state_proof::extrinsics_root(&body).expect("the body is inside the budgets"),
        expected.as_slice(),
        "the extrinsics root of the known-answer body moved"
    );
}

/// Every extrinsic is committed to, at the index it sits at.
///
/// The trie is keyed by the extrinsic's index, so a node that reorders a body,
/// drops one or appends one reaches a different root and the header it was
/// asked for no longer carries it. Without this the budgets above would be the
/// only thing the recomputation proved.
#[test]
fn a_body_the_header_does_not_carry_roots_elsewhere() {
    let kat = fixture("extrinsics_root_kat.json");
    let body: Vec<Vec<u8>> = kat["extrinsics"]
        .as_array()
        .expect("a list of extrinsics")
        .iter()
        .map(bytes)
        .collect();
    let root = qnero_state_proof::extrinsics_root(&body).expect("it roots");

    let mut flipped = body.clone();
    flipped[1][8] ^= 0x01;
    assert_ne!(
        qnero_state_proof::extrinsics_root(&flipped).expect("it roots"),
        root
    );

    let mut reordered = body.clone();
    reordered.swap(0, 2);
    assert_ne!(
        qnero_state_proof::extrinsics_root(&reordered).expect("it roots"),
        root
    );

    let mut dropped = body.clone();
    dropped.pop();
    assert_ne!(
        qnero_state_proof::extrinsics_root(&dropped).expect("it roots"),
        root
    );

    let mut appended = body;
    appended.push(vec![0x04, 0x00, 0x00]);
    assert_ne!(
        qnero_state_proof::extrinsics_root(&appended).expect("it roots"),
        root
    );
}
