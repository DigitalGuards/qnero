/**
 * Formatting that is the wallet's rather than the chain's.
 *
 * Amounts live in `units.ts`, which the explorer and this wallet share: every
 * figure a person reads is QNR, and it is written there once. What is here is
 * the wallet's own vocabulary, plus the one parse that goes the other way.
 * Value in the pool moves in steps of 0.01 QNR, so what somebody types has to
 * land on a step before a proof is built for it, and that is a refusal the
 * form can make before the click rather than a rounding nobody asked for.
 */

import { PLANCK_PER_QNR, POOL_STEP_PLANCK, formatCount } from './units';

/** Pool steps in one QNR. A hundred, and derived rather than written twice. */
const STEPS_PER_QNR = PLANCK_PER_QNR / POOL_STEP_PLANCK;

/**
 * A count of pool steps out of the QNR amount somebody typed.
 *
 * Amounts move in steps of 0.01 QNR, so two decimal places is the whole
 * precision the pool has: a note's `value` is a count of steps and the circuit
 * range-checks it, so accepting a third decimal here would build a proof for
 * an amount nobody asked for.
 */
export function parseQnrToSteps(input: string): bigint {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new Error('enter an amount in QNR');
  }
  const parts = /^([0-9]+)(?:\.([0-9]*))?$/.exec(trimmed);
  if (parts === null) {
    throw new Error('an amount is a number of QNR, such as 12.34');
  }
  const fraction = parts[2] ?? '';
  if (fraction.length > 2) {
    throw new Error('amounts move in steps of 0.01 QNR, so an amount has at most two decimals');
  }
  const value = BigInt(parts[1] as string) * STEPS_PER_QNR + BigInt(fraction.padEnd(2, '0'));
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
