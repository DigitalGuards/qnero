/**
 * Units.
 *
 * The token has 12 decimals and the symbol `QNR`, both readable from
 * `system_properties`. The pool step has no metadata surface at all and has to
 * be compiled in: get it wrong by a factor of ten and every coinbase value on
 * the site is wrong by a factor of ten with nothing on chain to catch it.
 *
 * Two units are in play and they are easy to confuse. `CoinbaseValues` is a
 * count of pool steps (`u64`). `PoolValue`, `BatchSettled.fee`,
 * `AuthorFeeAccrued` and `Shielded.value` are in planck (`u128`).
 */

/** Planck in one QNR. The token's 12 decimals. */
export const PLANCK_PER_QNR = 10n ** 12n;

/** Planck in one pool step: amounts move in steps of 0.01 QNR. Compiled in, because metadata has no such constant. */
export const POOL_STEP_PLANCK = 10n ** 10n;

export const TOKEN_SYMBOL = 'QNR';

/** The size the reference wallet pads every note ciphertext to. Anything else was written by something else. */
export const REFERENCE_CIPHERTEXT_BYTES = 1792;

export function stepsToPlanck(steps: bigint): bigint {
  return steps * POOL_STEP_PLANCK;
}

/**
 * A planck amount as a decimal QNR string.
 *
 * Always at least two decimals, so a column of amounts lines its decimal
 * points up: these are rendered in a tabular-figures column and a variable
 * number of decimals defeats the point of one. Below a hundredth the trim
 * keeps going, because the pool step is 0.01 QNR and anything finer is a fee
 * remainder worth seeing in full.
 */
export function formatPlanck(planck: bigint): string {
  const negative = planck < 0n;
  const magnitude = negative ? -planck : planck;
  const whole = magnitude / PLANCK_PER_QNR;
  const fraction = magnitude % PLANCK_PER_QNR;
  const sign = negative ? '-' : '';
  const trimmed = fraction.toString().padStart(12, '0').replace(/0+$/, '');
  const digits = trimmed.length >= 2 ? trimmed : trimmed.padEnd(2, '0');
  return `${sign}${whole.toString()}.${digits}`;
}

/** A planck amount with its symbol, the form every amount on the site takes. */
export function formatQnr(planck: bigint): string {
  return `${formatPlanck(planck)} ${TOKEN_SYMBOL}`;
}

/** A count of pool steps with its symbol, converted through the compiled-in step. */
export function formatStepsAsQnr(steps: bigint): string {
  return formatQnr(stepsToPlanck(steps));
}

/** Thousands-separated integer, for leaf counts and heights. */
export function formatCount(value: bigint | number): string {
  return value.toLocaleString('en-US');
}

export function formatBytes(count: number): string {
  return `${formatCount(count)} bytes`;
}

/** Milliseconds as seconds with one decimal, the block-time form. */
export function formatSeconds(ms: number): string {
  if (!Number.isFinite(ms)) {
    return 'unknown';
  }
  return `${(ms / 1000).toFixed(1)} s`;
}

const MONTHS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
] as const;

/**
 * A block's time, written the way a reader reads a clock.
 *
 * It was an ISO timestamp with milliseconds in it, which is a machine's form
 * and the first thing on a block page. UTC because a chain has no local time
 * and a block explorer that prints the reader's zone invites two readers of
 * the same block to disagree about when it was.
 */
export function formatUtc(ms: number): string {
  const at = new Date(ms);
  const pad = (value: number): string => String(value).padStart(2, '0');
  const month = MONTHS[at.getUTCMonth()] ?? '???';
  return `${at.getUTCDate()} ${month} ${at.getUTCFullYear()} ${pad(at.getUTCHours())}:${pad(
    at.getUTCMinutes(),
  )}:${pad(at.getUTCSeconds())} UTC`;
}

/** How long ago, in the largest unit that leaves a number a reader can hold. */
export function formatAgo(ms: number, now: number = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - ms) / 1000));
  if (seconds < 60) {
    return `${seconds} s ago`;
  }
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const hours = Math.round(minutes / 60);
  if (hours < 48) {
    return `${hours} h ago`;
  }
  return `${Math.round(hours / 24)} days ago`;
}

/**
 * A span of milliseconds as the largest unit that leaves a number a reader can
 * hold: seconds under two minutes, then minutes, hours and days.
 *
 * Block counts on this page are turned into durations with the chain's own
 * target block time, and those spans range from a minute to several days, so
 * one fixed unit would print either "0.0 d" or "245760.0 s".
 */
export function formatSpan(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) {
    return 'unknown';
  }
  const seconds = ms / 1000;
  if (seconds < 120) {
    return `${seconds.toFixed(0)} s`;
  }
  const minutes = seconds / 60;
  if (minutes < 120) {
    return `${minutes.toFixed(0)} min`;
  }
  const hours = minutes / 60;
  if (hours < 48) {
    return `${hours.toFixed(1)} h`;
  }
  return `${(hours / 24).toFixed(2)} days`;
}
