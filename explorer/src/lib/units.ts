/**
 * Units.
 *
 * The token has 12 decimals and the symbol `QNR`, both readable from
 * `system_properties`. `POOL_QUANTUM` has no metadata surface at all and has
 * to be compiled in: get it wrong by a factor of ten and every coinbase value
 * on the site is wrong by a factor of ten with nothing on chain to catch it.
 *
 * Two units are in play and they are easy to confuse. `CoinbaseValues` is in
 * pool quanta (`u64`). `PoolValue`, `BatchSettled.fee`, `AuthorFeeAccrued` and
 * `Shielded.value` are in planck (`u128`).
 */

/** Planck in one QNR. The token's 12 decimals. */
export const PLANCK_PER_QNR = 10n ** 12n;

/** Planck in one pool quantum: 0.01 QNR. Compiled in, because metadata has no such constant. */
export const POOL_QUANTUM_PLANCK = 10n ** 10n;

export const TOKEN_SYMBOL = 'QNR';

/** The size the reference wallet pads every note ciphertext to. Anything else was written by something else. */
export const REFERENCE_CIPHERTEXT_BYTES = 1792;

export function quantaToPlanck(quanta: bigint): bigint {
  return quanta * POOL_QUANTUM_PLANCK;
}

/** A planck amount as a decimal QNR string, trailing zeros trimmed. */
export function formatPlanck(planck: bigint): string {
  const negative = planck < 0n;
  const magnitude = negative ? -planck : planck;
  const whole = magnitude / PLANCK_PER_QNR;
  const fraction = magnitude % PLANCK_PER_QNR;
  const sign = negative ? '-' : '';
  if (fraction === 0n) {
    return `${sign}${whole.toString()}`;
  }
  const digits = fraction.toString().padStart(12, '0').replace(/0+$/, '');
  return `${sign}${whole.toString()}.${digits}`;
}

/** A planck amount with its symbol, the form every amount on the site takes. */
export function formatQnr(planck: bigint): string {
  return `${formatPlanck(planck)} ${TOKEN_SYMBOL}`;
}

/** A pool-quanta amount with its symbol, converted through the compiled-in quantum. */
export function formatQuantaAsQnr(quanta: bigint): string {
  return formatQnr(quantaToPlanck(quanta));
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
