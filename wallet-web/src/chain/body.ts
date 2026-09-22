/**
 * The walk back out of an extrinsic, down to the note ciphertexts it carries.
 *
 * Note ciphertexts live in block bodies and nowhere else, so a scan walks each
 * extrinsic of a block back to its call and takes the payloads out of the
 * arguments. The body has already been rooted to its header by
 * `authenticatedBody` in `chain/authenticated.ts`, so these bytes are the
 * chain's: what is left here is reading them at the right offsets.
 *
 * A generic Substrate client cannot do this walk. The ML-DSA-87 signature is a
 * fixed 7219-byte array and polkadot-js refuses a fixed array above 2048, so
 * `chain_getBlock` through a typed API throws on every block carrying a signed
 * extrinsic. `explorer/src/lib/extrinsics.ts` walks the same envelope by hand
 * and is the ancestor of this file; `crates/qnero-wallet/src/extrinsic.rs`
 * reads the same three calls the same way.
 *
 * **Every offset comes from the runtime's own metadata**, through
 * [`BodyLayout`]: the signature widths, the address type, the transaction
 * extensions and the three call indices. An extension this wallet cannot lay
 * out shifts the call index as surely as it shifts a signature, and a call
 * index read off by one is a payload silently not found, so an unknown one
 * refuses rather than being guessed at.
 *
 * **It refuses rather than skipping.** A body this wallet cannot walk is a
 * body it cannot say carried no payment of this wallet's, and a scan that
 * stepped over one would write a watermark above the block it was in.
 */

import { hexToBytes, readCompact } from '../lib/hex';

/**
 * How many explicit bytes each transaction extension contributes.
 *
 * Only four of this runtime's eleven encode anything: `CheckMortality`'s era,
 * `CheckNonce`'s compact nonce, `ChargeTransactionPayment`'s compact tip and
 * `CheckMetadataHash`'s mode byte. An identifier that is not on this list
 * refuses the walk rather than guessing a width. The same table is in
 * `explorer/src/lib/extrinsics.ts`.
 */
const EXTENSION_WIDTH: Record<string, 'empty' | 'era' | 'compact' | 'byte'> = {
  CheckNonZeroSender: 'empty',
  CheckSpecVersion: 'empty',
  CheckTxVersion: 'empty',
  CheckGenesis: 'empty',
  CheckMortality: 'era',
  CheckNonce: 'compact',
  CheckWeight: 'empty',
  ReversibleTransactionExtension: 'empty',
  ChargeTransactionPayment: 'compact',
  CheckMetadataHash: 'byte',
  WeightReclaim: 'empty',
};

/** Everything about an envelope this wallet reads off the runtime's metadata. */
export interface BodyLayout {
  /** Signature-scheme variant index to payload length in bytes. */
  signatureLengths: ReadonlyMap<number, number>;
  /** Transaction extension identifiers, in the order the runtime declares them. */
  extensions: readonly string[];
  /** True when the runtime's address type is a `MultiAddress`, false for a bare `AccountId32`. */
  multiAddress: boolean;
  /** The `Shielded` pallet's index, and the three calls that carry a payload. */
  shieldedPallet: number;
  submitPrivateBatch: number;
  submitPublicBatch: number;
  shield: number;
}

/**
 * Every note ciphertext one block's body carries, in body order.
 *
 * Which leaf each one belongs to is decided nowhere here: the scan trial
 * decrypts every one of them and the note that comes out has to match a
 * commitment the block demonstrably appended. See `wallet/sync.ts`.
 */
export function blockPayloads(layout: BodyLayout, body: readonly string[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  body.forEach((extrinsic, position) => {
    try {
      for (const payload of extrinsicPayloads(layout, hexToBytes(extrinsic))) {
        out.push(payload);
      }
    } catch (error) {
      throw new Error(
        `extrinsic ${position} of this block cannot be walked, so this wallet cannot say it ` +
          `carried no payment: ${(error as Error).message}. Scan progress is unchanged.`,
      );
    }
  });
  return out;
}

/**
 * Every note ciphertext one extrinsic carries, in the order it carries them.
 *
 * The walk goes as far as the call index and no further for a call that
 * carries no payload, which is every call but the three below. A transparent
 * transfer's sender, recipient and amount are in the body forever and this
 * reads none of them.
 *
 * `extrinsic` is one entry of `chain_getBlock`'s list: the SCALE-encoded
 * `Vec<u8>`, so its own compact length prefix is part of these bytes.
 */
export function extrinsicPayloads(layout: BodyLayout, extrinsic: Uint8Array): Uint8Array[] {
  const { value: declared, next: bodyAt } = readCompact(extrinsic, 0);
  if (extrinsic.length - bodyAt !== declared) {
    throw new Error(
      `it declares ${declared} bytes and carries ${extrinsic.length - bodyAt}. ` +
        '`chain_getBlock` returns each extrinsic as its own SCALE `Vec<u8>`, so the two are the ' +
        'same number on every block a node built',
    );
  }
  const body = extrinsic.subarray(bodyAt);

  const preamble = body[0];
  if (preamble === undefined) {
    throw new Error('it carries no preamble at all');
  }
  // `sp_runtime`'s preamble: the top two bits are the transaction type and the
  // low six are the format version.
  let cursor: number;
  switch (preamble >> 6) {
    case 0b00:
      cursor = 1;
      break;
    case 0b10:
      cursor = skipExtensions(layout, body, skipSignature(layout, body, skipAddress(layout, body, 1)));
      break;
    case 0b01:
      // A general transaction: an extension version byte, then the extensions
      // of that version, then the call. This runtime builds none, and walking
      // it is what keeps one appearing beside a settlement from refusing the
      // whole pass.
      cursor = skipExtensions(layout, body, 2);
      break;
    default:
      throw new Error(
        `it carries transaction type ${(preamble >> 6).toString(2)}, which this wallet cannot ` +
          'walk, so its call and every argument after it are at offsets this wallet would be ' +
          'guessing',
      );
  }

  const pallet = body[cursor];
  const call = body[cursor + 1];
  if (pallet === undefined || call === undefined) {
    throw new Error('it ends before its call index');
  }
  if (pallet !== layout.shieldedPallet) {
    return [];
  }
  const args = body.subarray(cursor + 2);
  if (call === layout.submitPrivateBatch || call === layout.submitPublicBatch) {
    return readBatchPayloads(args);
  }
  if (call === layout.shield) {
    return readShieldPayload(args);
  }
  return [];
}

/** `submit_private_batch(proof, outputs)` and its public twin, read back. */
function readBatchPayloads(args: Uint8Array): Uint8Array[] {
  const proof = readCompact(args, 0);
  let cursor = proof.next + proof.value;
  if (cursor > args.length) {
    throw new Error('it is a settlement whose proof runs past the end of its call');
  }
  const slots = readCompact(args, cursor);
  cursor = slots.next;
  const out: Uint8Array[] = [];
  // Two ciphertexts per settled slot, and the bound is the bytes that are
  // actually there: `MaxOutputsPerBlock` is the chain's rule and this is a
  // node's answer, so the count is only believed as far as the body goes.
  for (let slot = 0; slot < slots.value; slot += 1) {
    for (const which of [1, 2]) {
      let payload: Uint8Array;
      try {
        const read = readBytes(args, cursor);
        payload = read.bytes;
        cursor = read.next;
      } catch (error) {
        throw new Error(
          `it is a settlement whose slot ${slot} carries no ct_${which}: ${(error as Error).message}`,
        );
      }
      if (payload.length > 0) {
        out.push(payload);
      }
    }
  }
  ensureConsumed(args, cursor, 'a settlement');
  return out;
}

/** `shield(value, inner, ciphertext)`, read back. */
function readShieldPayload(args: Uint8Array): Uint8Array[] {
  // A `u128` balance and a raw 32-byte `inner`, neither length prefixed.
  const CIPHERTEXT_AT = 16 + 32;
  if (args.length < CIPHERTEXT_AT) {
    throw new Error('it is a shield whose value and inner do not fit in its call');
  }
  const { bytes, next } = readBytes(args, CIPHERTEXT_AT);
  ensureConsumed(args, next, 'a shield');
  return bytes.length > 0 ? [bytes] : [];
}

/** A `Vec<u8>` argument: a compact length and exactly that many bytes. */
function readBytes(args: Uint8Array, offset: number): { bytes: Uint8Array; next: number } {
  const { value, next } = readCompact(args, offset);
  const end = next + value;
  if (end > args.length) {
    throw new Error(`a byte vector of ${value} bytes runs past the end of the call`);
  }
  return { bytes: args.subarray(next, end), next: end };
}

/**
 * Every argument accounted for, with nothing left over.
 *
 * A call this wallet decodes short is a call whose shape has moved, and
 * reading a payload out of the wrong offsets is how a payment goes missing
 * without anything saying so.
 */
function ensureConsumed(args: Uint8Array, cursor: number, what: string): void {
  if (cursor !== args.length) {
    throw new Error(
      `it is ${what} whose arguments this wallet decoded to ${cursor} bytes of ${args.length}. ` +
        "The call's shape has moved and this wallet would be reading payloads at offsets the " +
        'chain did not write them at',
    );
  }
}

function skipAddress(layout: BodyLayout, body: Uint8Array, offset: number): number {
  if (!layout.multiAddress) {
    return offset + 32;
  }
  const variant = body[offset];
  switch (variant) {
    case 0: // Id(AccountId32)
      return offset + 33;
    case 1: // Index(Compact<AccountIndex>)
      return readCompact(body, offset + 1).next;
    case 2: {
      // Raw(Vec<u8>)
      const { value, next } = readCompact(body, offset + 1);
      return next + value;
    }
    case 3: // Address32
      return offset + 33;
    case 4: // Address20
      return offset + 21;
    default:
      throw new Error(
        `it carries a MultiAddress variant this wallet does not know: ${String(variant)}`,
      );
  }
}

function skipSignature(layout: BodyLayout, body: Uint8Array, offset: number): number {
  const variant = body[offset];
  if (variant === undefined) {
    throw new Error('its signature runs past the end of the extrinsic');
  }
  const length = layout.signatureLengths.get(variant);
  if (length === undefined) {
    throw new Error(
      `it carries signature scheme ${variant}, which this runtime's metadata does not declare. ` +
        'A scheme of another width moves the call index and every argument after it',
    );
  }
  return offset + 1 + length;
}

function skipExtensions(layout: BodyLayout, body: Uint8Array, offset: number): number {
  let cursor = offset;
  for (const identifier of layout.extensions) {
    const width = EXTENSION_WIDTH[identifier];
    if (width === undefined) {
      throw new Error(
        `it carries a transaction extension this wallet cannot lay out: ${identifier}`,
      );
    }
    if (width === 'byte') {
      if (cursor >= body.length) {
        throw new Error(`it ends before its ${identifier} extension`);
      }
      cursor += 1;
    } else if (width === 'era') {
      // `Era::Immortal` is one zero byte; a mortal era is two. Reading the era
      // byte past the end used to take the mortal branch and walk on two bytes
      // further, which puts the call index at an offset this wallet is
      // guessing at. `skip_extensions` in
      // `crates/qnero-wallet/src/extrinsic.rs` checks the byte the same way.
      const era = body[cursor];
      if (era === undefined) {
        throw new Error('it ends before its era');
      }
      cursor += era === 0 ? 1 : 2;
      if (cursor > body.length) {
        throw new Error('it ends inside its era');
      }
    } else if (width === 'compact') {
      cursor = readCompact(body, cursor).next;
    }
  }
  if (cursor > body.length) {
    throw new Error('its transaction extensions run past the end of the extrinsic');
  }
  return cursor;
}
