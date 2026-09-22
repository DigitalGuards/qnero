//! Extrinsic encoding, and the walk back out of one.
//!
//! Two shapes. A settlement is bare: no signature, no nonce, no tip, admitted
//! by `ValidateUnsigned` and free. A `shield` is signed with ML-DSA-87 under
//! the FIPS 204 context `QUANTUS_EXTRINSIC`, with the runtime's eleven
//! transaction extensions laid out by hand.
//!
//! The layout is checked against the runtime's own metadata before anything is
//! signed ([`crate::metadata::ChainMetadata::ensure_known_signed_extensions`]):
//! every extension contributes explicit bytes to the extrinsic and implicit
//! bytes to the payload the signature covers, so an unknown one shifts both
//! and the node reports only `Transaction has a bad signature`.
//!
//! # The read direction
//!
//! Note ciphertexts live in block bodies and nowhere else, so a scan walks
//! each extrinsic of a block back to its call and takes the payloads out of
//! the arguments ([`extrinsic_payloads`]). It is the same layout read the
//! other way, and the same extension check guards it: an extension this wallet
//! does not know shifts the call index as surely as it shifts a signature, and
//! a call index read off by one is a payload silently not found.
//!
//! A generic Substrate client cannot do this walk. The ML-DSA-87 signature is
//! a fixed 7219-byte array and polkadot-js refuses a fixed array above 2048,
//! so `chain_getBlock` through a typed API throws on every block carrying a
//! signed extrinsic. `explorer/src/lib/extrinsics.ts` walks the same envelope
//! by hand and is the reference this follows.

use anyhow::{bail, Context, Result};
use codec::{Compact, Encode};

use crate::dev_account::{TransparentKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::metadata::ChainMetadata;
use crate::scale::{compact_len, encode_bytes, read_compact};

/// `sp_runtime`'s bare preamble. Versions 4 and 5 both decode; 4 is the one
/// every runtime in this lineage accepts.
///
/// Checked against the runtime's own declared format version before anything
/// goes out: see [`ChainMetadata::ensure_bare_preamble_decodes`].
pub(crate) const BARE_PREAMBLE: u8 = 0x04;
/// A signed preamble is legacy-only: version 4 with the signed type bits.
///
/// See [`ChainMetadata::ensure_signed_preamble_decodes`].
pub(crate) const SIGNED_PREAMBLE: u8 = 0x84;
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
) -> Result<Vec<u8>> {
    let mut call = vec![
        metadata.shielded_pallet_index,
        metadata.submit_private_batch,
    ];
    encode_batch_args(&mut call, proof, outputs);
    wrap_bare(metadata, &call)
}

/// `submit_public_batch(proof, outputs)`. A wallet never sends one; an
/// aggregator does, and the measurement in `docs/BENCH.md` needs it.
pub fn encode_submit_public_batch(
    metadata: &ChainMetadata,
    proof: &[u8],
    outputs: &[ShieldedOutput],
) -> Result<Vec<u8>> {
    let mut call = vec![metadata.shielded_pallet_index, metadata.submit_public_batch];
    encode_batch_args(&mut call, proof, outputs);
    wrap_bare(metadata, &call)
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

fn wrap_bare(metadata: &ChainMetadata, call: &[u8]) -> Result<Vec<u8>> {
    metadata.ensure_bare_preamble_decodes()?;
    let mut body = Vec::with_capacity(call.len() + 1);
    body.push(BARE_PREAMBLE);
    body.extend_from_slice(call);
    let mut out = compact_len(body.len());
    out.extend_from_slice(&body);
    Ok(out)
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
/// Only four of the eleven encode anything. `CheckMortality` is immortal here,
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
    metadata.ensure_signed_preamble_decodes()?;

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

/// Every note ciphertext one extrinsic carries, in the order it carries them.
///
/// The walk goes as far as the call index and no further for a call that
/// carries no payload, which is every call but the three below. A transparent
/// transfer's sender, recipient and amount are in the body forever and this
/// reads none of them.
///
/// Refuses rather than skipping. A body this wallet cannot walk is a body it
/// cannot say carried no payment, and a scan that stepped over one would write
/// a watermark above the block it was in. The three ways out are an envelope
/// shape this wallet does not know, an argument list that does not decode, and
/// an extension set the runtime declares and this wallet cannot lay out.
pub fn extrinsic_payloads(metadata: &ChainMetadata, extrinsic: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (declared, body_at) =
        read_compact(extrinsic, 0).context("an extrinsic with no length prefix at all")?;
    let body = extrinsic
        .get(body_at..)
        .filter(|body| body.len() as u64 == declared)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "an extrinsic declares {declared} bytes and carries {}. `chain_getBlock` returns \
                 each extrinsic as its own SCALE `Vec<u8>`, so the two are the same number on \
                 every block a node built.",
                extrinsic.len().saturating_sub(body_at)
            )
        })?;

    let preamble = *body
        .first()
        .context("an extrinsic with no preamble at all")?;
    // `sp_runtime`'s preamble: the top two bits are the transaction type and
    // the low six are the format version.
    let cursor = match preamble >> 6 {
        0b00 => 1,
        0b10 => {
            // The explicit half of a signed extrinsic, in the order
            // `encode_signed` writes it.
            metadata.ensure_known_signed_extensions()?;
            let address = *body.get(1).context("a signed extrinsic with no address")?;
            if address != MULTI_ADDRESS_ID {
                bail!(
                    "a signed extrinsic carries `MultiAddress` variant {address}, where this \
                     wallet walks `Id` ({MULTI_ADDRESS_ID}) alone. Every signer this runtime \
                     admits is an `AccountId32`."
                );
            }
            let scheme = *body
                .get(34)
                .context("a signed extrinsic with no signature scheme")?;
            if scheme != SIGNATURE_SCHEME_ML_DSA_87 {
                bail!(
                    "a signed extrinsic carries signature scheme {scheme}, where this wallet \
                     walks ML-DSA-87 ({SIGNATURE_SCHEME_ML_DSA_87}) alone. A scheme of another \
                     width moves the call index and every argument after it."
                );
            }
            // 1 preamble, 1 address variant, 32 account, 1 scheme variant,
            // then the signature and the public key, neither length prefixed.
            skip_extensions(body, 35 + SIGNATURE_LEN + PUBLIC_KEY_LEN)?
        }
        0b01 => {
            // A general transaction: an extension version byte, then the
            // extensions of that version, then the call. This runtime builds
            // none, and walking it is what keeps one appearing beside a
            // settlement from refusing the whole pass.
            metadata.ensure_known_signed_extensions()?;
            skip_extensions(body, 2)?
        }
        bits => bail!(
            "an extrinsic carries transaction type {bits:#04b}, which this wallet cannot walk. \
             Its call and every argument after it are at offsets this wallet would be guessing."
        ),
    };

    let pallet = *body
        .get(cursor)
        .context("an extrinsic with no call in it")?;
    let call = *body
        .get(cursor + 1)
        .context("an extrinsic with no call index")?;
    let args = &body[cursor + 2..];
    if pallet != metadata.shielded_pallet_index {
        return Ok(Vec::new());
    }
    if call == metadata.submit_private_batch || call == metadata.submit_public_batch {
        read_batch_payloads(args)
    } else if call == metadata.shield {
        read_shield_payload(args)
    } else {
        Ok(Vec::new())
    }
}

/// `submit_private_batch(proof, outputs)` and its public twin, read back.
fn read_batch_payloads(args: &[u8]) -> Result<Vec<Vec<u8>>> {
    let (proof_len, proof_at) =
        read_compact(args, 0).context("a settlement whose proof has no length prefix")?;
    let mut cursor = usize::try_from(proof_len)
        .ok()
        .and_then(|len| proof_at.checked_add(len))
        .filter(|end| *end <= args.len())
        .context("a settlement whose proof runs past the end of its call")?;
    let (slots, next) =
        read_compact(args, cursor).context("a settlement whose output list has no length")?;
    cursor = next;
    // Two ciphertexts per settled slot, and the bound is the bytes that are
    // actually there: `MaxOutputsPerBlock` is the chain's rule and this is a
    // node's answer, so the count is only believed as far as the body goes.
    let mut out = Vec::with_capacity((slots as usize).min(args.len() / 2).saturating_mul(2));
    for slot in 0..slots {
        for which in 1..=2 {
            let (payload, next) = read_bytes(args, cursor)
                .with_context(|| format!("a settlement whose slot {slot} carries no ct_{which}"))?;
            cursor = next;
            if !payload.is_empty() {
                out.push(payload.to_vec());
            }
        }
    }
    ensure_consumed(args, cursor, "a settlement")?;
    Ok(out)
}

/// `shield(value, inner, ciphertext)`, read back.
fn read_shield_payload(args: &[u8]) -> Result<Vec<Vec<u8>>> {
    // A `u128` balance and a raw 32-byte `inner`, neither length prefixed.
    const CIPHERTEXT_AT: usize = 16 + 32;
    if args.len() < CIPHERTEXT_AT {
        bail!("a shield whose value and inner do not fit in its call");
    }
    let (payload, cursor) =
        read_bytes(args, CIPHERTEXT_AT).context("a shield that carries no ciphertext")?;
    let payload = payload.to_vec();
    ensure_consumed(args, cursor, "a shield")?;
    Ok(if payload.is_empty() {
        Vec::new()
    } else {
        vec![payload]
    })
}

/// A `Vec<u8>` argument: a compact length and exactly that many bytes.
fn read_bytes(args: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let (len, at) = read_compact(args, offset)?;
    let end = usize::try_from(len)
        .ok()
        .and_then(|len| at.checked_add(len))?;
    Some((args.get(at..end)?, end))
}

/// Every argument accounted for, with nothing left over.
///
/// A call this wallet decodes short is a call whose shape has moved, and
/// reading a payload out of the wrong offsets is how a payment goes missing
/// without anything saying so.
fn ensure_consumed(args: &[u8], cursor: usize, what: &str) -> Result<()> {
    if cursor != args.len() {
        bail!(
            "{what} whose arguments this wallet decoded to {cursor} bytes of {}. The call's \
             shape has moved and this wallet would be reading payloads at offsets the chain did \
             not write them at.",
            args.len()
        );
    }
    Ok(())
}

/// The explicit bytes the eleven transaction extensions contribute, in order.
///
/// Only four of the eleven encode anything, and they are the same four
/// [`encode_extensions`] writes: `CheckMortality`'s era, `CheckNonce`'s
/// compact nonce, `ChargeTransactionPayment`'s compact tip and
/// `CheckMetadataHash`'s mode byte. The caller has already run
/// [`ChainMetadata::ensure_known_signed_extensions`], which is what makes that
/// list the runtime's own and not this wallet's guess.
fn skip_extensions(body: &[u8], offset: usize) -> Result<usize> {
    // `Era::Immortal` is one zero byte; a mortal era is two.
    let era = *body
        .get(offset)
        .context("a signed extrinsic that ends before its era")?;
    let mut cursor = offset + if era == ERA_IMMORTAL { 1 } else { 2 };
    for what in ["nonce", "tip"] {
        cursor = read_compact(body, cursor)
            .map(|(_, next)| next)
            .with_context(|| format!("a signed extrinsic that ends before its {what}"))?;
    }
    // `CheckMetadataHash`'s `Mode`, one byte whichever variant it is.
    Ok(cursor + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            signed_extensions: crate::metadata::KNOWN_SIGNED_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            extrinsic_version: crate::metadata::LEGACY_EXTRINSIC_FORMAT_VERSION,
            storage: Vec::new(),
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
        let encoded =
            encode_submit_private_batch(&runtime(), &[0x01, 0x02], &outputs).expect("it encodes");
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

    /// The two preamble bytes are compiled in and the runtime publishes the
    /// format version they have to match. A runtime that drops the legacy
    /// signed variant declares version 5 with the eleven extension identifiers
    /// unchanged, so the extension check passes and the signature dies inside
    /// the node's `Preamble::decode` with `Invalid transaction version`.
    #[test]
    fn a_format_version_the_preambles_do_not_decode_at_is_refused() {
        let key = TransparentKey::dev("alice").unwrap();
        let context = SigningContext {
            spec_version: 152,
            transaction_version: 6,
            genesis_hash: [0x11; 32],
            nonce: 0,
            tip: 0,
        };
        let outputs = vec![ShieldedOutput {
            ct_1: vec![0xaa],
            ct_2: vec![0xbb],
        }];

        // Version 5: a bare settlement still decodes, a signed `shield` does
        // not.
        let mut five = runtime();
        five.extrinsic_version = 5;
        let call = encode_shield_call(&five, 10_000_000_000, &[0u8; 32], b"ct");
        assert!(encode_submit_private_batch(&five, b"proof", &outputs).is_ok());
        let refused = encode_signed(&five, &key, &call, &context)
            .expect_err("a signed preamble decodes at version 4 alone");
        let message = refused.to_string();
        assert!(message.contains("format version 5"), "{message}");
        assert!(message.contains("0x84"), "{message}");

        // Version 6: neither preamble decodes.
        let mut six = runtime();
        six.extrinsic_version = 6;
        let refused = encode_submit_private_batch(&six, b"proof", &outputs)
            .expect_err("a bare preamble decodes for versions 4 to 5");
        let message = refused.to_string();
        assert!(message.contains("format version 6"), "{message}");
        assert!(message.contains("0x04"), "{message}");
        assert!(encode_signed(&six, &key, &call, &context).is_err());

        // Version 4 is what this lineage declares, and both go out.
        assert!(encode_submit_private_batch(&runtime(), b"proof", &outputs).is_ok());
        assert!(encode_signed(&runtime(), &key, &call, &context).is_ok());
    }

    /// One extrinsic, length prefix and all, out of a preamble and a call.
    fn bare_extrinsic(preamble: u8, call: &[u8]) -> Vec<u8> {
        let mut body = vec![preamble];
        body.extend_from_slice(call);
        let mut out = crate::scale::compact_len(body.len());
        out.extend_from_slice(&body);
        out
    }

    /// A real block body is a mixture of preamble bytes, and the walk reads
    /// no version out of either.
    ///
    /// The runtime builds its inherents at `EXTRINSIC_FORMAT_VERSION` 5, so a
    /// node-built inherent carries preamble `0x05`, while this wallet signs
    /// and settles at version 4 and its own extrinsics carry `0x04`.
    /// `Preamble::decode` admits both, so both are in every block. The walk
    /// keys off the top two bits alone: a wallet that pinned the low six
    /// would refuse half of every body, and a scan that refuses a body cannot
    /// say the block carried no payment of its owner's.
    #[test]
    fn a_body_mixing_version_5_and_version_4_preambles_walks() {
        let metadata = runtime();
        let outputs = vec![ShieldedOutput {
            ct_1: vec![0xaa, 0xbb],
            ct_2: vec![0xcc],
        }];
        let payloads = vec![vec![0xaa, 0xbb], vec![0xcc]];

        // A node-built inherent at version 5: `Timestamp::set(now)`, a call on
        // a pallet that is not `Shielded`, so the walk stops at the index.
        let inherent = bare_extrinsic(0x05, &[1, 0, 0x0b, 0x00, 0x8a, 0x35, 0xd7, 0x9a, 0x01]);
        assert!(extrinsic_payloads(&metadata, &inherent)
            .expect("a version 5 inherent walks")
            .is_empty());

        // And this wallet's settlement at version 4, beside it.
        let mut settlement =
            encode_submit_private_batch(&metadata, &[0x01, 0x02], &outputs).expect("it encodes");
        let (_, preamble_at) = read_compact(&settlement, 0).expect("it has a length prefix");
        assert_eq!(settlement[preamble_at], BARE_PREAMBLE);
        assert_eq!(
            extrinsic_payloads(&metadata, &settlement).expect("a version 4 settlement walks"),
            payloads
        );

        // The same settlement with the version the runtime's own builder
        // would stamp on it: the same two ciphertexts come back, which is
        // what says the version byte is not read.
        settlement[preamble_at] = 0x05;
        assert_eq!(
            extrinsic_payloads(&metadata, &settlement).expect("a version 5 settlement walks"),
            payloads
        );

        // A transaction type this wallet cannot walk still refuses, so the
        // tolerance is in the version bits and nowhere else.
        settlement[preamble_at] = 0b1100_0000 | 0x04;
        let refused = extrinsic_payloads(&metadata, &settlement)
            .expect_err("an unknown transaction type is refused");
        assert!(
            refused.to_string().contains("transaction type"),
            "{refused}"
        );
    }
}
