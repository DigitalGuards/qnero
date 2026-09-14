/**
 * Formatting that is the wallet's rather than the chain's.
 *
 * Amounts live in `units.ts`, which the explorer and this wallet share. What
 * is here is the wallet's own vocabulary: pool quanta are what a note is
 * denominated in and what a fee is quoted in, and they are what a person types
 * into the amount field, so they get their own formatters rather than being
 * converted to QNR at every seam and back at the next one.
 */

import { formatCount, formatQuantaAsQnr } from './units';

/** A note or a fee, in the unit the circuit counts in, with its QNR beside it. */
export function formatQuanta(quanta: bigint): string {
  return `${formatCount(quanta)} quanta`;
}

/** The pair every amount in this wallet is shown as: quanta, then QNR under it. */
export function formatQuantaWithQnr(quanta: bigint): { primary: string; secondary: string } {
  return { primary: formatCount(quanta), secondary: formatQuantaAsQnr(quanta) };
}

/**
 * A whole number of pool quanta out of what somebody typed.
 *
 * Refuses anything else. A fractional quantum has no representation in a note:
 * `value` is a `u64` of quanta and the circuit range-checks it, so rounding
 * here would build a proof for an amount nobody asked for.
 */
export function parseQuanta(input: string): bigint {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error('enter an amount in quanta');
  }
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new Error('an amount is a whole number of quanta, with no decimal point');
  }
  const value = BigInt(trimmed);
  if (value === 0n) {
    throw new Error('an amount has to be more than zero');
  }
  return value;
}

/** Milliseconds as a reading a person can compare against the expectation. */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) {
    return 'unknown';
  }
  if (ms < 1000) {
    return `${Math.round(ms)} ms`;
  }
  return `${(ms / 1000).toFixed(1)} s`;
}

/** A byte count, thousands separated. */
export function formatBytes(bytes: number): string {
  return `${formatCount(bytes)} bytes`;
}

/** A hash shortened for a dense row, with the whole value one hover away. */
export function shorten(hex: string, head = 10, tail = 8): string {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (body.length <= head + tail + 1) {
    return body;
  }
  return `${body.slice(0, head)}…${body.slice(-tail)}`;
}
