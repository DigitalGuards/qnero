//! Extrinsic encoding.
//!
//! Two shapes. A settlement is bare: no signature, no nonce, no tip, admitted
//! by `ValidateUnsigned` and free. A `shield` is signed with ML-DSA-87 under
//! the FIPS 204 context `QUANTUS_EXTRINSIC`, with the runtime's twelve
//! transaction extensions laid out by hand.
//!
//! The layout is checked against the runtime's own metadata before anything is
//! signed ([`crate::metadata::ChainMetadata::ensure_known_signed_extensions`]):
//! every extension contributes explicit bytes to the extrinsic and implicit
//! bytes to the payload the signature covers, so an unknown one shifts both
//! and the node reports only `Transaction has a bad signature`.

use anyhow::Result;
use codec::{Compact, Encode};

use crate::dev_account::TransparentKey;
use crate::metadata::ChainMetadata;
use crate::scale::{compact_len, encode_bytes};

/// `sp_runtime`'s bare preamble. Versions 4 and 5 both decode; 4 is the one
/// every runtime in this lineage accepts.
const BARE_PREAMBLE: u8 = 0x04;
/// A signed preamble is legacy-only: version 4 with the signed type bits.
const SIGNED_PREAMBLE: u8 = 0x84;
/// `MultiAddress::Id`, the variant carrying a raw `AccountId32`.
const MULTI_ADDRESS_ID: u8 = 0x00;
/// `DilithiumSignatureScheme::Dilithium87`.
const SIGNATURE_SCHEME_ML_DSA_87: u8 = 0x00;
/// `Era::Immortal`.
const ERA_IMMORTAL: u8 = 0x00;
/// `CheckMetadataHash`'s `Mode::Disabled`.
const METADATA_HASH_DISABLED: u8 = 0x00;

/// The two ciphertexts of one real leaf slot, in output order: `ct_1` belongs
/// to `cm_out_1`.
#[derive(Debug, Clone)]
pub struct ShieldedOutput {
    pub ct_1: Vec<u8>,
    pub ct_2: Vec<u8>,
}

/// `submit_private_batch(proof, outputs)`, the whole extrinsic including its
/// length prefix.
pub fn encode_submit_private_batch(
    metadata: &ChainMetadata,
    proof: &[u8],
    outputs: &[ShieldedOutput],
) -> Vec<u8> {
    let mut call = vec![
        metadata.shielded_pallet_index,
        metadata.submit_private_batch,
    ];
    encode_batch_args(&mut call, proof, outputs);
    wrap_bare(&call)
}

/// `submit_public_batch(proof, outputs)`. A wallet never sends one; an
/// aggregator does, and the measurement in `docs/BENCH.md` needs it.
pub fn encode_submit_public_batch(
    metadata: &ChainMetadata,
    proof: &[u8],
    outputs: &[ShieldedOutput],
) -> Vec<u8> {
    let mut call = vec![metadata.shielded_pallet_index, metadata.submit_public_batch];
    encode_batch_args(&mut call, proof, outputs);
    wrap_bare(&call)
}

fn encode_batch_args(call: &mut Vec<u8>, proof: &[u8], outputs: &[ShieldedOutput]) {
    call.extend_from_slice(&encode_bytes(proof));
    call.extend_from_slice(&compact_len(outputs.len()));
    for output in outputs {
        // `BoundedVec<u8, MaxCiphertextBytes>` encodes exactly as a `Vec<u8>`.
        // Overrunning the bound fails the node's decode, which is why the size
        // check happens before proving.
        call.extend_from_slice(&encode_bytes(&output.ct_1));
        call.extend_from_slice(&encode_bytes(&output.ct_2));
    }
}

fn wrap_bare(call: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(call.len() + 1);
    body.push(BARE_PREAMBLE);
    body.extend_from_slice(call);
    let mut out = compact_len(body.len());
    out.extend_from_slice(&body);
    out
}

/// The `shield(value, inner, ciphertext)` call body, without a preamble.
pub fn encode_shield_call(
    metadata: &ChainMetadata,
    value_planck: u128,
    inner: &[u8; 32],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut call = vec![metadata.shielded_pallet_index, metadata.shield];
    call.extend_from_slice(&value_planck.encode());
    call.extend_from_slice(inner);
    call.extend_from_slice(&encode_bytes(ciphertext));
    call
}

/// What a signature has to commit to besides the call.
#[derive(Debug, Clone)]
pub struct SigningContext {
    pub spec_version: u32,
    pub transaction_version: u32,
    pub genesis_hash: [u8; 32],
    pub nonce: u32,
    pub tip: u128,
}

/// The explicit half of the transaction extensions: what rides in the
/// extrinsic.
///
/// Only four of the twelve encode anything. `CheckMortality` is immortal here,
/// so the era is one zero byte and its implicit hash is the genesis hash: a
/// mortal era would need the block hash its period starts at, and a wallet
/// that has to resubmit a `shield` gains nothing from the shorter window.
fn encode_extensions(context: &SigningContext) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ERA_IMMORTAL);
    out.extend_from_slice(&Compact(context.nonce).encode());
    out.extend_from_slice(&Compact(context.tip).encode());
    out.push(METADATA_HASH_DISABLED);
    out
}

/// The implicit half: what the signature covers and the extrinsic does not
/// carry.
fn encode_implicit(context: &SigningContext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&context.spec_version.encode());
    out.extend_from_slice(&context.transaction_version.encode());
    out.extend_from_slice(&context.genesis_hash);
    // `CheckMortality`'s implicit is the hash the era is anchored at, which
    // for an immortal era is the genesis hash.
    out.extend_from_slice(&context.genesis_hash);
    // `CheckMetadataHash`'s implicit is `Option<[u8; 32]>`, `None` while the
    // mode is disabled.
    out.push(0x00);
    out
}

/// Sign a call and wrap it into a signed extrinsic.
pub fn encode_signed(
    metadata: &ChainMetadata,
    key: &TransparentKey,
    call: &[u8],
    context: &SigningContext,
) -> Result<Vec<u8>> {
    metadata.ensure_known_signed_extensions()?;

    let extensions = encode_extensions(context);
    let mut payload = Vec::with_capacity(call.len() + extensions.len() + 72);
    payload.extend_from_slice(call);
    payload.extend_from_slice(&extensions);
    payload.extend_from_slice(&encode_implicit(context));
    // Substrate's rule: a payload over 256 bytes is signed as its blake2-256
    // hash. A `shield` carrying a note ciphertext is always over it.
    let signature = if payload.len() > 256 {
        key.sign(&crate::scale::blake2_256(&payload))?
    } else {
        key.sign(&payload)?
    };

    let mut body = Vec::with_capacity(call.len() + signature.len() + 2700);
    body.push(SIGNED_PREAMBLE);
    body.push(MULTI_ADDRESS_ID);
    body.extend_from_slice(&key.account_id());
    // `Dilithium87SignatureWithPublic` is a fixed-size array behind a one-byte
    // enum index: signature then public key, with no length prefix.
    body.push(SIGNATURE_SCHEME_ML_DSA_87);
    body.extend_from_slice(&signature);
    body.extend_from_slice(key.public_bytes());
    body.extend_from_slice(&extensions);
    body.extend_from_slice(call);

    let mut out = compact_len(body.len());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> ChainMetadata {
        ChainMetadata {
            shielded_pallet_index: 24,
            submit_private_batch: 0,
            submit_public_batch: 1,
            shield: 2,
            block_hash_window: 256,
            min_leaf_fee: 1,
            ciphertext_bytes_per_fee_quantum: 512,
            max_ciphertext_bytes: 2048,
            signed_extensions: crate::metadata::KNOWN_SIGNED_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// The bare settlement, byte for byte: length prefix, bare preamble,
    /// pallet, call, then the two arguments.
    #[test]
    fn a_private_batch_encodes_as_a_bare_extrinsic() {
        let outputs = vec![ShieldedOutput {
            ct_1: vec![0xaa, 0xbb],
            ct_2: vec![0xcc],
        }];
        let encoded = encode_submit_private_batch(&runtime(), &[0x01, 0x02], &outputs);
        // compact(12) = 0x30, then the body.
        assert_eq!(
            encoded,
            vec![0x30, 0x04, 24, 0, 0x08, 0x01, 0x02, 0x04, 0x08, 0xaa, 0xbb, 0x04, 0xcc]
        );
    }

    #[test]
    fn a_shield_call_carries_a_u128_value_then_a_raw_inner() {
        let call = encode_shield_call(&runtime(), 10_000_000_000, &[0x07; 32], b"ct");
        assert_eq!(&call[..2], &[24, 2]);
        assert_eq!(&call[2..18], &10_000_000_000u128.to_le_bytes());
        assert_eq!(&call[18..50], &[0x07; 32]);
        assert_eq!(&call[50..], &[0x08, b'c', b't']);
    }

    /// The signed extrinsic's shape, at the sizes ML-DSA-87 fixes. A signature
    /// carried with a length prefix, or an account derived with blake2, both
    /// decode into something the node rejects with one opaque message, so the
    /// offsets are pinned here.
    #[test]
    fn a_signed_extrinsic_lays_the_signature_out_without_a_length_prefix() {
        let key = TransparentKey::dev("alice").unwrap();
        let call = encode_shield_call(&runtime(), 10_000_000_000, &[0x07; 32], b"ct");
        let context = SigningContext {
            spec_version: 152,
            transaction_version: 6,
            genesis_hash: [0x11; 32],
            nonce: 3,
            tip: 0,
        };
        let encoded = encode_signed(&runtime(), &key, &call, &context).unwrap();
        let body_offset = crate::scale::compact_len(encoded.len()).len();
        let body = &encoded[body_offset..];
        assert_eq!(body[0], SIGNED_PREAMBLE);
        assert_eq!(body[1], MULTI_ADDRESS_ID);
        assert_eq!(&body[2..34], &key.account_id());
        assert_eq!(body[34], SIGNATURE_SCHEME_ML_DSA_87);
        let extensions_at =
            35 + crate::dev_account::SIGNATURE_LEN + crate::dev_account::PUBLIC_KEY_LEN;
        assert_eq!(
            &body[extensions_at - crate::dev_account::PUBLIC_KEY_LEN..extensions_at],
            key.public_bytes()
        );
        // era, compact nonce, compact tip, metadata-hash mode.
        assert_eq!(
            &body[extensions_at..extensions_at + 4],
            &[0x00, 0x0c, 0x00, 0x00]
        );
        assert_eq!(&body[extensions_at + 4..], &call[..]);
    }

    /// A runtime whose extension list this wallet does not know must refuse to
    /// sign. The payload it would produce reads at the node as a bad
    /// signature, with nothing to say why.
    #[test]
    fn signing_is_refused_when_the_runtime_declares_an_unknown_extension() {
        let mut metadata = runtime();
        metadata.signed_extensions.push("SomethingNew".into());
        let key = TransparentKey::dev("alice").unwrap();
        let call = encode_shield_call(&metadata, 10_000_000_000, &[0u8; 32], b"ct");
        let context = SigningContext {
            spec_version: 152,
            transaction_version: 6,
            genesis_hash: [0x11; 32],
            nonce: 0,
            tip: 0,
        };
        assert!(encode_signed(&metadata, &key, &call, &context).is_err());
    }
}
