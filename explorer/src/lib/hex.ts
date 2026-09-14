/** Hex and SCALE primitives, written here so the decoders stay dependency free. */

export function stripPrefix(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const body = stripPrefix(hex);
  if (body.length % 2 !== 0) {
    throw new Error(`hex string of odd length: ${body.length} characters`);
  }
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(body.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error('hex string carries a character that is not hex');
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '0x';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

/** Byte length of a hex-encoded blob, which is what the explorer shows for a ciphertext. */
export function hexByteLength(hex: string): number {
  const body = stripPrefix(hex);
  if (body.length % 2 !== 0) {
    throw new Error(`hex string of odd length: ${body.length} characters`);
  }
  return body.length / 2;
}

/** A little-endian byte string as an integer. `U512` and every fixed-width chain integer is one. */
export function leBytesToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    out = (out << 8n) | BigInt(bytes[i] ?? 0);
  }
  return out;
}

export interface CompactRead {
  value: number;
  next: number;
}

/**
 * SCALE compact integer at `offset`.
 *
 * The big-integer mode (the top two bits set) is refused: nothing this
 * explorer parses by hand carries one, and accepting it silently would mean
 * guessing at a length.
 */
export function readCompact(bytes: Uint8Array, offset: number): CompactRead {
  const first = bytes[offset];
  if (first === undefined) {
    throw new Error(`compact integer runs past the end of ${bytes.length} bytes`);
  }
  const mode = first & 0b11;
  if (mode === 0) {
    return { value: first >>> 2, next: offset + 1 };
  }
  if (mode === 1) {
    const second = bytes[offset + 1];
    if (second === undefined) {
      throw new Error('two-byte compact integer runs past the end');
    }
    return { value: ((first | (second << 8)) >>> 2) >>> 0, next: offset + 2 };
  }
  if (mode === 2) {
    const b1 = bytes[offset + 1];
    const b2 = bytes[offset + 2];
    const b3 = bytes[offset + 3];
    if (b1 === undefined || b2 === undefined || b3 === undefined) {
      throw new Error('four-byte compact integer runs past the end');
    }
    const raw = (first >>> 0) + b1 * 0x100 + b2 * 0x10000 + b3 * 0x1000000;
    return { value: Math.floor(raw / 4), next: offset + 4 };
  }
  const length = (first >>> 2) + 4;
  const slice = bytes.slice(offset + 1, offset + 1 + length);
  if (slice.length !== length) {
    throw new Error('big-mode compact integer runs past the end');
  }
  const value = leBytesToBigInt(slice);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('compact integer is larger than this parser handles');
  }
  return { value: Number(value), next: offset + 1 + length };
}

/** A hash shortened for a dense table. The full value stays in the title attribute. */
export function shortHash(hex: string, head = 8, tail = 6): string {
  const body = stripPrefix(hex);
  if (body.length <= head + tail + 2) {
    return `0x${body}`;
  }
  return `0x${body.slice(0, head)}…${body.slice(-tail)}`;
}
