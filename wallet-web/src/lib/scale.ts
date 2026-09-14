/**
 * The one piece of SCALE this wallet writes rather than reads.
 *
 * Everything else about an extrinsic comes out of metadata through
 * `@polkadot/api`, which resolves the pallet index, the call index and the
 * bounded-vec widths from the runtime rather than from a compiled-in copy.
 * What metadata cannot supply is the digest-log blob the header hash commits
 * to: `chain_getHeader` returns one hex string per `DigestItem`, and the chain
 * hashes the `Digest` struct's own encoding, which is
 * `compact(logs.length) ++ concat(items)`.
 */

/** A SCALE compact integer. Four modes; this writes the first three. */
export function encodeCompact(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error('a compact integer is a non-negative whole number');
  }
  if (value < 1 << 6) {
    return new Uint8Array([value << 2]);
  }
  if (value < 1 << 14) {
    const encoded = (value << 2) | 0b01;
    return new Uint8Array([encoded & 0xff, (encoded >>> 8) & 0xff]);
  }
  if (value < 2 ** 30) {
    const encoded = value * 4 + 0b10;
    return new Uint8Array([
      encoded & 0xff,
      (encoded >>> 8) & 0xff,
      (encoded >>> 16) & 0xff,
      Math.floor(encoded / 2 ** 24) & 0xff,
    ]);
  }
  // Nothing this wallet encodes reaches the big-integer mode: it is a count of
  // digest items, which a header carries two or three of.
  throw new Error('this compact encoder stops below the big-integer mode');
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
