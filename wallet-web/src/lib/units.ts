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

/** The exact size a settlement ciphertext must be: the chain requires it of every suite-1
 * ciphertext a settlement carries, and both wallets pad to it. On a settlement leaf anything
 * else is unreachable. It stays a reference size for a shield entry note. */
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

/**
 * An amount split into the digits that carry value and the zeros that pad.
 *
 * MyMonero renders a twelve-decimal balance as a bright "10.37" and a dim
 * "00000000000", which is what keeps a long number readable without rounding
 * away what is held. The rule is significance rather than the decimal point,
 * and the difference matters here: the pool step is 0.01 QNR, so
 * [`formatPlanck`] emits exactly two decimals for every shielded balance and
 * both of them carry value. Splitting on the point dimmed all of it.
 *
 * `6.92` splits into `6.92` and nothing; `6.00` into `6` and `.00`.
 */
export function splitAmountForDisplay(text: string): { significant: string; pad: string } {
  const point = text.indexOf('.');
  if (point < 0) {
    return { significant: text, pad: '' };
  }
  const whole = text.slice(0, point);
  const fraction = text.slice(point + 1);
  const carried = fraction.replace(/0+$/, '');
  if (carried.length === 0) {
    return { significant: whole, pad: `.${fraction}` };
  }
  return { significant: `${whole}.${carried}`, pad: fraction.slice(carried.length) };
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
