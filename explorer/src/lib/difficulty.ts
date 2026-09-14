/**
 * Difficulty and the hash rate estimated from it.
 *
 * `QPoW::CurrentDifficulty` is a `U512`: 64 raw little-endian bytes, fixed
 * width, no compact prefix. Read big-endian or as a `u128` it still looks like
 * a number, so the byte order is the whole decoder.
 *
 * The comparison the node makes is Monero's, `hash * difficulty <= 2^256 - 1`
 * with the hash read little-endian, so the expected number of hashes per block
 * is the difficulty itself and the rate follows from the observed block time.
 */

import { hexToBytes, leBytesToBigInt } from './hex';

export const U512_BYTES = 64;

/** A `U512` as the chain encodes it. Accepts a short trailing-zero-trimmed blob too. */
export function decodeU512(hex: string): bigint {
  const bytes = hexToBytes(hex);
  if (bytes.length > U512_BYTES) {
    throw new Error(`a U512 is at most ${U512_BYTES} bytes, got ${bytes.length}`);
  }
  return leBytesToBigInt(bytes);
}

/**
 * Hashes per second, estimated.
 *
 * Expected hashes per block equals the difficulty, so the rate is the
 * difficulty over the observed inter-block time. It is an estimate over a
 * short window and it says so wherever it is displayed.
 */
export function estimateHashrate(difficulty: bigint, blockTimeMs: number): number | null {
  if (!Number.isFinite(blockTimeMs) || blockTimeMs <= 0) {
    return null;
  }
  return Number(difficulty) / (blockTimeMs / 1000);
}

const RATE_UNITS = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s'] as const;

export function formatHashrate(hashesPerSecond: number | null): string {
  if (hashesPerSecond === null || !Number.isFinite(hashesPerSecond)) {
    return 'unknown';
  }
  let value = hashesPerSecond;
  let unit = 0;
  while (value >= 1000 && unit < RATE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${RATE_UNITS[unit]}`;
}

/** A big integer with thousands separators, which is how a difficulty reads best. */
export function formatDifficulty(difficulty: bigint): string {
  return difficulty.toLocaleString('en-US');
}
