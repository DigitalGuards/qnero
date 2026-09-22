//! Known-answer vectors. Regenerate with `QNERO_WRITE_VECTORS=1 cargo test -p
//! qnero-notes --test kat` and review the diff; any change here is a
//! consensus-breaking change to key or note derivation.

use qnero_notes::{
    dummy_nullifier, encrypt_note, output_rho, pad_memo, Digest, Note, SpendingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Vector {
    seed_byte: u8,
    ask: String,
    nk: String,
    ak: String,
    pk: String,
    address_prefix: String,
    address_len: usize,
    note_value: u64,
    inner: String,
    cm: String,
    nf: String,
    /// What a padding input slot carrying the same `(nk, rho, r)` would
    /// publish. Consensus-critical: it must never equal `nf`, or a slot that
    /// proves no membership could settle a real note's nullifier.
    nf_dummy: String,
    /// `rho` the spend circuit derives for output 0 of a leaf that published
    /// `nf` and `nf_dummy`. Consensus-critical: the circuit computes it from
    /// the same rule and a note whose `rho` does not match is not the note the
    /// leaf committed to.
    output_rho_0: String,
    /// Serialized length of this note's ciphertext with an empty padded memo.
    /// Consensus-critical: settlement requires exactly this many bytes for a
    /// ciphertext declaring suite 1, so a change here is a change to what the
    /// chain accepts and every wallet that did not move with it is refused.
    ciphertext_len: usize,
    /// SHA-256 of those same bytes. The length alone would not notice a
    /// framing change that moved a field without moving the total, and this
    /// pins the whole wire object at once: framing, KEM ciphertext, both AEAD
    /// payloads and the pad.
    ciphertext_sha256: String,
}

fn make(seed_byte: u8) -> Vector {
    let sk = SpendingKey::from_bytes([seed_byte; 32]);
    let rho = Digest::hash_bytes(&[b"kat/rho", &[seed_byte]]);
    let r = Digest::hash_bytes(&[b"kat/r", &[seed_byte]]);
    let value = 1_000_000_000u64 + u64::from(seed_byte);
    let note = Note::new(sk.pk(), value, rho, r).unwrap();
    let address = sk.address();
    let addr = address.encode();
    // Deterministic: `encrypt_note` takes its KEM randomness as an argument.
    let ciphertext = encrypt_note(
        &address.ek,
        &note,
        &pad_memo("").expect("an empty memo fits the pad"),
        &[seed_byte; 32],
    )
    .expect("the note encrypts")
    .to_bytes();
    Vector {
        seed_byte,
        ask: sk.ask().to_hex(),
        nk: sk.nk().to_hex(),
        ak: sk.ak().to_hex(),
        pk: sk.pk().to_hex(),
        address_prefix: addr[..24].to_string(),
        address_len: addr.len(),
        note_value: value,
        inner: note.inner().to_hex(),
        cm: note.commitment().to_hex(),
        nf: note.nullifier(&sk.nk()).to_hex(),
        nf_dummy: dummy_nullifier(&sk.nk(), &rho, &r).to_hex(),
        output_rho_0: output_rho(
            &note.nullifier(&sk.nk()),
            &dummy_nullifier(&sk.nk(), &rho, &r),
            0,
        )
        .to_hex(),
        ciphertext_len: ciphertext.len(),
        ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
    }
}

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");

#[test]
fn known_answer_vectors() {
    let got: Vec<Vector> = [1u8, 2, 255].iter().map(|s| make(*s)).collect();
    if std::env::var("QNERO_WRITE_VECTORS").is_ok() {
        std::fs::write(PATH, serde_json::to_string_pretty(&got).unwrap()).unwrap();
        return;
    }
    let want: Vec<Vector> =
        serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors.json")).unwrap();
    assert_eq!(got, want);
}
