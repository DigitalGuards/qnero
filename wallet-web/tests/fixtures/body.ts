/**
 * Block bodies, built the way a Qnero node serves them.
 *
 * The payloads are in the bodies now, so a fixture that wants to hand a sync a
 * payment has to build an extrinsic around it. These writers are the inverse
 * of the walk in `src/chain/body.ts`, and keeping them here rather than
 * reusing that file is the point: a fixture built by the reader it is testing
 * proves nothing about the reader.
 *
 * The layout numbers are the runtime's own, taken from the block bodies
 * `explorer/tests/fixtures/extrinsics.json` was captured from: the `Shielded`
 * pallet at index 24, `submit_private_batch`, `submit_public_batch` and
 * `shield` at call indices 0, 1 and 2, eleven transaction extensions, and a
 * 7,219-byte ML-DSA-87 signature payload, which is the 4,627-byte signature
 * and the 2,592-byte public key the runtime declares as one fixed array.
 */

import type { BodyLayout } from '../../src/chain/body';
import { bytesToHex } from '../../src/lib/hex';
import { concatBytes, encodeCompact } from '../../src/lib/scale';

export const SIGNATURE_PAYLOAD_BYTES = 7219;

export const TEST_BODY_LAYOUT: BodyLayout = {
  signatureLengths: new Map([
    [0, SIGNATURE_PAYLOAD_BYTES],
    [1, 5261],
  ]),
  extensions: [
    'CheckNonZeroSender',
    'CheckSpecVersion',
    'CheckTxVersion',
    'CheckGenesis',
    'CheckMortality',
    'CheckNonce',
    'CheckWeight',
    'ReversibleTransactionExtension',
    'ChargeTransactionPayment',
    'CheckMetadataHash',
    'WeightReclaim',
  ],
  multiAddress: true,
  shieldedPallet: 24,
  submitPrivateBatch: 0,
  submitPublicBatch: 1,
  shield: 2,
};

/** A SCALE `Vec<u8>`: a compact length, then the bytes. */
function bytes(value: Uint8Array): Uint8Array {
  return concatBytes([encodeCompact(value.length), value]);
}

/** One extrinsic as `chain_getBlock` hands it over, length prefix included. */
function extrinsic(body: Uint8Array): string {
  return bytesToHex(concatBytes([encodeCompact(body.length), body]));
}

/**
 * The two preamble bytes a real body is a mixture of.
 *
 * The runtime builds its inherents with `EXTRINSIC_FORMAT_VERSION` 5, so
 * everything a node put in a block itself carries `0x05`, while a wallet signs
 * and settles at version 4 and its own extrinsics carry `0x04`.
 * `Preamble::decode` admits both, so both are in every block:
 * `chain/runtime/tests/fixtures/extrinsics_root_kat.json` is one such body,
 * captured out of a block the runtime executed. The walk keys off the top two
 * bits and reads no version out of the low six.
 */
export const BARE_PREAMBLE_V5 = 0x05;
export const BARE_PREAMBLE_V4 = 0x04;

/** The timestamp inherent: bare, and carrying nothing this wallet reads. */
export function timestampExtrinsic(millis = 0, preamble = BARE_PREAMBLE_V5): string {
  return extrinsic(concatBytes([new Uint8Array([preamble, 1, 0]), encodeCompact(millis)]));
}

/** The coinbase inherent: bare, and under v1 it carries no payload at all. */
export function coinbaseExtrinsic(preamble = BARE_PREAMBLE_V5): string {
  return extrinsic(new Uint8Array([preamble, TEST_BODY_LAYOUT.shieldedPallet, 3]));
}

/**
 * `submit_private_batch(proof, outputs)`, bare, carrying one pair per slot.
 *
 * The proof is a short stand-in: what the walk reads is its length prefix, so
 * the bytes inside it only have to be skipped correctly.
 */
export function settlementExtrinsic(
  slots: readonly (readonly [Uint8Array, Uint8Array])[],
  proof = new Uint8Array([9, 9, 9]),
  preamble = BARE_PREAMBLE_V4,
): string {
  return extrinsic(
    concatBytes([
      new Uint8Array([preamble, TEST_BODY_LAYOUT.shieldedPallet, TEST_BODY_LAYOUT.submitPrivateBatch]),
      bytes(proof),
      encodeCompact(slots.length),
      ...slots.flatMap(([first, second]) => [bytes(first), bytes(second)]),
    ]),
  );
}

/**
 * `shield(value, inner, ciphertext)`, signed, with the whole ML-DSA-87
 * envelope in front of it.
 *
 * The signature bytes are zeros. Nothing in the read direction verifies a
 * signature: the node did that before the block was built, and what this walk
 * has to get right is how far past it the call sits.
 */
export function shieldExtrinsic(payload: Uint8Array, value = 0n): string {
  const balance = new Uint8Array(16);
  for (let index = 0; index < 16; index += 1) {
    balance[index] = Number((value >> BigInt(8 * index)) & 0xffn);
  }
  return extrinsic(
    concatBytes([
      // A signed preamble at format version 4, `MultiAddress::Id`, the signer,
      // signature scheme 0, and the 7,219-byte signature payload.
      new Uint8Array([0x84, 0]),
      new Uint8Array(32).fill(0xaa),
      new Uint8Array([0]),
      new Uint8Array(SIGNATURE_PAYLOAD_BYTES),
      // The four extensions that encode anything: an immortal era, a compact
      // nonce, a compact tip and a `CheckMetadataHash` mode byte.
      new Uint8Array([0]),
      encodeCompact(3),
      encodeCompact(0),
      new Uint8Array([0]),
      new Uint8Array([TEST_BODY_LAYOUT.shieldedPallet, TEST_BODY_LAYOUT.shield]),
      balance,
      new Uint8Array(32).fill(0xbb),
      bytes(payload),
    ]),
  );
}

/** A transparent transfer, which carries no payload and is walked no further than its call. */
export function transferExtrinsic(): string {
  return extrinsic(
    concatBytes([
      new Uint8Array([0x84, 0]),
      new Uint8Array(32).fill(0xcc),
      new Uint8Array([0]),
      new Uint8Array(SIGNATURE_PAYLOAD_BYTES),
      new Uint8Array([0]),
      encodeCompact(0),
      encodeCompact(0),
      new Uint8Array([0]),
      // `Balances::transfer_keep_alive`, whose sender, recipient and amount
      // are in the body forever and which this walk reads none of.
      new Uint8Array([10, 3]),
      new Uint8Array(32).fill(0xdd),
      encodeCompact(1000),
    ]),
  );
}
