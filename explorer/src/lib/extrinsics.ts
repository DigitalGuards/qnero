/**
 * Extrinsic envelopes, parsed by hand.
 *
 * A generic Substrate client cannot decode these: the ML-DSA-87 signature is a
 * fixed 7219-byte array and polkadot-js refuses any fixed array above 2048, so
 * `chain_getBlock` through the typed API throws on every block that carries a
 * signed extrinsic. The explorer therefore reads the raw hex and walks the
 * envelope itself.
 *
 * It walks far enough to name the call and no further. Any call a block
 * carries carries its own arguments with it, forever, and rendering those as an
 * ordinary row would publish them a second time in a form built for reading.
 * The page says the arguments are there and leaves them where the chain put
 * them. A call the runtime refuses never reaches a block at all, so it is not
 * what this rule is about.
 */

import { readCompact } from './hex';

export interface ExtrinsicLayout {
  /** Signature-scheme variant index to payload length in bytes, from the runtime's own metadata. */
  signatureLengths: ReadonlyMap<number, number>;
  /** Transaction extension identifiers, in the order the runtime declares them. */
  extensions: readonly string[];
  /** True when the runtime's address type is a `MultiAddress`, false for a bare `AccountId32`. */
  multiAddress: boolean;
}

export type ExtrinsicKind = 'bare' | 'signed' | 'general' | 'unknown';

export interface CallRef {
  palletIndex: number;
  callIndex: number;
}

export interface ExtrinsicEnvelope {
  index: number;
  /** Whole encoding including the compact length prefix, which is what the extrinsic hash covers. */
  byteLength: number;
  version: number;
  kind: ExtrinsicKind;
  call: CallRef | null;
  /** Why the call could not be located, when it could not. */
  unresolved: string | null;
}

/**
 * How many explicit bytes each transaction extension contributes.
 *
 * Only four of this runtime's eleven encode anything. An identifier that is
 * not on this list leaves the call unresolved rather than guessing a width.
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

class Unresolved extends Error {}

function skipAddress(bytes: Uint8Array, offset: number, layout: ExtrinsicLayout): number {
  if (!layout.multiAddress) {
    return offset + 32;
  }
  const variant = bytes[offset];
  switch (variant) {
    case 0: // Id(AccountId32)
      return offset + 33;
    case 1: {
      // Index(Compact<AccountIndex>)
      const { next } = readCompact(bytes, offset + 1);
      return next;
    }
    case 2: {
      // Raw(Vec<u8>)
      const { value, next } = readCompact(bytes, offset + 1);
      return next + value;
    }
    case 3: // Address32
      return offset + 33;
    case 4: // Address20
      return offset + 21;
    default:
      throw new Unresolved(`a MultiAddress variant this parser does not know: ${String(variant)}`);
  }
}

function skipSignature(bytes: Uint8Array, offset: number, layout: ExtrinsicLayout): number {
  const variant = bytes[offset];
  if (variant === undefined) {
    throw new Unresolved('the signature runs past the end of the extrinsic');
  }
  const length = layout.signatureLengths.get(variant);
  if (length === undefined) {
    throw new Unresolved(`a signature scheme this runtime's metadata does not declare: ${variant}`);
  }
  return offset + 1 + length;
}

function skipExtensions(bytes: Uint8Array, offset: number, layout: ExtrinsicLayout): number {
  let cursor = offset;
  for (const identifier of layout.extensions) {
    const width = EXTENSION_WIDTH[identifier];
    if (width === undefined) {
      throw new Unresolved(`a transaction extension this parser does not know: ${identifier}`);
    }
    if (width === 'empty') {
      continue;
    }
    if (width === 'byte') {
      cursor += 1;
    } else if (width === 'era') {
      cursor += bytes[cursor] === 0 ? 1 : 2;
    } else {
      cursor = readCompact(bytes, cursor).next;
    }
  }
  return cursor;
}

function readCall(bytes: Uint8Array, offset: number): CallRef {
  const palletIndex = bytes[offset];
  const callIndex = bytes[offset + 1];
  if (palletIndex === undefined || callIndex === undefined) {
    throw new Unresolved('the call runs past the end of the extrinsic');
  }
  return { palletIndex, callIndex };
}

/**
 * One extrinsic as `chain_getBlock` hands it over: the SCALE-encoded
 * `Vec<u8>`, so the compact length prefix is part of `bytes`.
 */
export function decodeExtrinsic(
  bytes: Uint8Array,
  index: number,
  layout: ExtrinsicLayout,
): ExtrinsicEnvelope {
  const envelope: ExtrinsicEnvelope = {
    index,
    byteLength: bytes.length,
    version: 0,
    kind: 'unknown',
    call: null,
    unresolved: null,
  };
  try {
    const { next: bodyStart } = readCompact(bytes, 0);
    const preamble = bytes[bodyStart];
    if (preamble === undefined) {
      throw new Unresolved('the extrinsic carries no preamble');
    }
    envelope.version = preamble & 0b0011_1111;
    const typeBits = preamble >> 6;
    if (typeBits === 0b00) {
      envelope.kind = 'bare';
      envelope.call = readCall(bytes, bodyStart + 1);
      return envelope;
    }
    if (typeBits === 0b10) {
      envelope.kind = 'signed';
      let cursor = skipAddress(bytes, bodyStart + 1, layout);
      cursor = skipSignature(bytes, cursor, layout);
      cursor = skipExtensions(bytes, cursor, layout);
      envelope.call = readCall(bytes, cursor);
      return envelope;
    }
    if (typeBits === 0b01) {
      envelope.kind = 'general';
      // A general transaction carries an extension version byte, then the
      // extensions of that version, then the call.
      const cursor = skipExtensions(bytes, bodyStart + 2, layout);
      envelope.call = readCall(bytes, cursor);
      return envelope;
    }
    throw new Unresolved(`an extrinsic type this parser does not know: ${typeBits}`);
  } catch (error) {
    envelope.unresolved = error instanceof Error ? error.message : String(error);
    return envelope;
  }
}
