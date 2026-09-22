//! The ciphertext digest, from real note ciphertexts through the encoded
//! extrinsic and back.
//!
//! `ct_digest` is the whole binding between a spend proof and the ciphertexts
//! submitted beside it: the circuit treats it as a free public input, so the
//! chain recomputing it over the bytes it decoded is the only thing that stops
//! a relayer swapping the ciphertexts attached to a settled leaf. There is one
//! implementation, `qnero_circuit::chain::ct_digest`, which is what
//! `pallet-shielded` calls. What a wallet owes is the order and the exact
//! bytes, and this test walks them through the encoder the pallet decodes.

use codec::{Compact, Decode};
use qnero_circuit::chain::ct_digest;
use qnero_notes::{encrypt_note, Digest, Note, SpendingKey};
use qnero_wallet::extrinsic::{encode_submit_private_batch, ShieldedOutput};
use qnero_wallet::memo::{pad_memo, CIPHERTEXT_FIXED_BYTES, MEMO_BYTES};
use qnero_wallet::metadata::{ChainMetadata, KNOWN_SIGNED_EXTENSIONS};
use qnero_wallet::wallet::output_ct_digest;

fn runtime() -> ChainMetadata {
    ChainMetadata {
        protocol_profile: qnero_circuit::profile::SUPPORTED_PROFILE,
        shielded_pallet_index: 24,
        submit_private_batch: 0,
        submit_public_batch: 1,
        shield: 2,
        block_hash_window: 256,
        min_leaf_fee: 1,
        ciphertext_bytes_per_fee_quantum: 512,
        max_ciphertext_bytes: 2048,
        signed_extensions: KNOWN_SIGNED_EXTENSIONS
            .iter()
            .map(|name| name.to_string())
            .collect(),
        extrinsic_version: 4,
        storage: Vec::new(),
    }
}

fn ciphertext(seed: u8, value: u64, memo: &[u8]) -> Vec<u8> {
    let key = SpendingKey::from_bytes([seed; 32]);
    let note = Note::new(
        key.pk(),
        value,
        Digest::hash_bytes(&[b"ct-digest-test/rho", &[seed]]),
        Digest::hash_bytes(&[b"ct-digest-test/r", &[seed]]),
    )
    .expect("the value is in range");
    encrypt_note(
        &key.incoming_viewing_key().encapsulation_key(),
        &note,
        memo,
        &[seed; 32],
    )
    .expect("encryption succeeds")
    .to_bytes()
}

/// The pallet reads `ct_1` and `ct_2` out of the SCALE-encoded extrinsic and
/// hashes those bytes. So does this: decode what the wallet encoded and check
/// the digest the witness carried is the digest the chain will recompute.
#[test]
fn the_digest_a_witness_carries_is_the_one_the_pallet_recomputes() {
    // Through `pad_memo`, which is what a real spend does and what the exact
    // length settlement requires: an unpadded pair is a pair the chain refuses
    // before it ever recomputes a digest.
    let ct_1 = ciphertext(1, 600, &pad_memo("a memo").expect("it fits"));
    let ct_2 = ciphertext(2, 392, &pad_memo("").expect("it fits"));
    let output = ShieldedOutput {
        ct_1: ct_1.clone(),
        ct_2: ct_2.clone(),
    };
    let carried = output_ct_digest(&output).expect("a canonical digest");

    let encoded = encode_submit_private_batch(&runtime(), b"proof bytes", &[output])
        .expect("the runtime's extrinsic format version takes a bare preamble");
    let decoded = decode_outputs(&encoded);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].0, ct_1);
    assert_eq!(decoded[0].1, ct_2);

    let recomputed = ct_digest(&[&decoded[0].0, &decoded[0].1]);
    assert_eq!(carried.to_bytes(), recomputed);

    // The length the chain settles on, asserted on the bytes that came back
    // out of the encoder rather than on the bytes that went in.
    assert_eq!(
        decoded[0].0.len(),
        qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES
    );
    assert_eq!(
        decoded[0].1.len(),
        qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES
    );
}

/// `ct_1` belongs to `cm_out_1`. A wallet that submits the pair the other way
/// round publishes a digest that does not match, and the chain refuses the
/// slot: the ordering is part of the rule.
#[test]
fn the_digest_binds_the_output_order() {
    let ct_1 = ciphertext(3, 10, b"payment");
    let ct_2 = ciphertext(4, 20, b"");
    let forward = output_ct_digest(&ShieldedOutput {
        ct_1: ct_1.clone(),
        ct_2: ct_2.clone(),
    })
    .unwrap();
    let reversed = output_ct_digest(&ShieldedOutput {
        ct_1: ct_2,
        ct_2: ct_1,
    })
    .unwrap();
    assert_ne!(forward, reversed);
}

/// Three sizes, and only the third is one consensus accepts.
///
/// The fixed part of a `NoteCiphertext` is 1731 bytes: that is the constant
/// `memo::CIPHERTEXT_FIXED_BYTES` pins, and both the memo pad and the fee are
/// derived from it. 1731 and 1738 stay here as serializer facts, because they
/// are what `CIPHERTEXT_FIXED_BYTES` means and what a drift in the framing or
/// the AEAD would move. What this wallet actually sends is
/// `CIPHERTEXT_FIXED_BYTES + memo::MEMO_BYTES` for every output, because every
/// memo is padded, so the pair it publishes is twice that and its slot floor
/// is `MinLeafFee + ceil(2 * 1792 / 512)`, eight steps. The wallet sizes its
/// fee from the bytes it is about to send, so a drift in either number is a
/// fee that no longer clears the floor, and now also a length settlement
/// refuses outright.
#[test]
fn an_empty_memo_ciphertext_is_the_documented_size() {
    assert_eq!(ciphertext(5, 1, b"").len(), CIPHERTEXT_FIXED_BYTES);
    assert_eq!(
        ciphertext(5, 1, b"seven!!").len(),
        CIPHERTEXT_FIXED_BYTES + 7
    );
    // The size that reaches the chain, the one the fee is computed over, and
    // the only one a settlement may publish.
    assert_eq!(
        ciphertext(5, 1, &pad_memo("a memo").expect("it fits")).len(),
        CIPHERTEXT_FIXED_BYTES + MEMO_BYTES
    );
    assert_eq!(
        CIPHERTEXT_FIXED_BYTES + MEMO_BYTES,
        qnero_circuit::chain::SUITE_1_CIPHERTEXT_BYTES
    );
}

/// Pull the `Vec<ShieldedOutput>` back out of an encoded extrinsic, the way
/// the node's decoder does.
fn decode_outputs(encoded: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut cursor = encoded;
    // The extrinsic's own length prefix, then the bare preamble, the pallet
    // index and the call index.
    let _len = Compact::<u64>::decode(&mut cursor).expect("a length prefix");
    let mut cursor = &cursor[3..];
    let _proof = Vec::<u8>::decode(&mut cursor).expect("the proof");
    let count = Compact::<u64>::decode(&mut cursor)
        .expect("an output count")
        .0;
    (0..count)
        .map(|_| {
            let ct_1 = Vec::<u8>::decode(&mut cursor).expect("ct_1");
            let ct_2 = Vec::<u8>::decode(&mut cursor).expect("ct_2");
            (ct_1, ct_2)
        })
        .collect()
}
