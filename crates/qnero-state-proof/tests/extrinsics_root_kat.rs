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
//!
//! Two vectors, both asserted here and both asserted in
//! `wallet-web/tests/extrinsics-root.test.ts`:
//!
//! | Fixture | Body | Root |
//! |---|---|---|
//! | `tests/fixtures/extrinsics_root_kat.json`, this crate's | 3 extrinsics of 12, 19 and 5 bytes | `0x7f1f55587ecb666b2ed2706a153d5b470352e0c3fc6117534817b78dcb0d9112` |
//! | `chain/runtime/tests/fixtures/extrinsics_root_kat.json`, the runtime's | 3 extrinsics of 11, 37 and 4108 bytes | `0xf96118c62fc4f880fe70d20216dec4fc50c6d2e595620c12675e95c8554c1af2` |

use std::path::PathBuf;

fn read(path: PathBuf) -> serde_json::Value {
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&text).expect("the fixture is JSON")
}

fn fixture(name: &str) -> serde_json::Value {
    read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
}

/// The runtime's own fixture, by a path relative to this crate.
///
/// Read rather than copied: a copy is a second answer that can be edited to
/// agree with a construction that moved, which is the one failure this file
/// exists to catch.
fn runtime_fixture() -> serde_json::Value {
    read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../chain/runtime/tests/fixtures/extrinsics_root_kat.json"),
    )
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

/// The runtime's own answer, reproduced by the wallets' recomputation.
///
/// `an_ordered_trie_root_matches_the_runtimes_own` above holds the shape; this
/// holds the cross-check the coordinator would otherwise run by hand. The body
/// is one the runtime executed, so its three extrinsics are the real thing: a
/// node-built inherent at preamble `0x05`, a second one, and a 4108-byte
/// settlement. The construction is `LayoutV0<Blake2Hasher>` on both sides, and
/// the runtime states the two fields that decide it, `system_version` 1 and
/// `state_version` V0, in the file.
#[test]
fn the_runtimes_own_fixture_roots_to_the_root_it_recorded() {
    let kat = runtime_fixture();
    assert_eq!(
        kat["system_version"].as_u64(),
        Some(1),
        "the runtime's fixture was written under a system_version this construction is not \
         LayoutV0 at"
    );
    assert_eq!(kat["state_version"].as_str(), Some("V0"));

    let body: Vec<Vec<u8>> = kat["extrinsics"]
        .as_array()
        .expect("a list of extrinsics")
        .iter()
        .map(bytes)
        .collect();
    assert_eq!(
        body.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![11, 37, 4108],
        "the runtime's fixture body moved"
    );
    let expected = bytes(&kat["extrinsics_root"]);
    assert_eq!(
        qnero_state_proof::extrinsics_root(&body).expect("the body is inside the budgets"),
        expected.as_slice(),
        "this crate's extrinsics root disagrees with the one the runtime computed over the same \
         body, so a wallet would refuse every block of the chain it is pointed at"
    );
}

/// The two fixtures carry two different bodies.
///
/// A cross-check is only a cross-check while the answers are independent: if
/// this crate's fixture were ever regenerated from the runtime's, both tests
/// above would pass on one construction.
#[test]
fn the_two_fixtures_carry_different_bodies() {
    let ours = fixture("extrinsics_root_kat.json");
    let theirs = runtime_fixture();
    assert_ne!(ours["extrinsics"], theirs["extrinsics"]);
    assert_ne!(bytes(&ours["root"]), bytes(&theirs["extrinsics_root"]));
}
