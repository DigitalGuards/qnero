import { describe, expect, it } from 'vitest';

import {
  formatBytes,
  formatCount,
  formatPlanck,
  formatQnr,
  formatSeconds,
  formatSpan,
  formatStepsAsQnr,
  PLANCK_PER_QNR,
  POOL_STEP_PLANCK,
  stepsToPlanck,
} from '../src/lib/units';

describe('units', () => {
  it('pins the pool step at 0.01 QNR', () => {
    expect(PLANCK_PER_QNR).toBe(1_000_000_000_000n);
    expect(POOL_STEP_PLANCK).toBe(10_000_000_000n);
    expect(PLANCK_PER_QNR / POOL_STEP_PLANCK).toBe(100n);
  });

  it('formats planck as QNR with at least the two decimals a step needs', () => {
    expect(formatPlanck(0n)).toBe('0.00');
    expect(formatPlanck(PLANCK_PER_QNR)).toBe('1.00');
    expect(formatPlanck(450_000_000_000n)).toBe('0.45');
    expect(formatPlanck(1n)).toBe('0.000000000001');
    expect(formatPlanck(1_234_567_890_123_456n)).toBe('1234.567890123456');
  });

  it('keeps a column of amounts aligned on its decimal point', () => {
    const column = [10n * PLANCK_PER_QNR, PLANCK_PER_QNR / 2n, 0n].map(formatPlanck);
    expect(column).toEqual(['10.00', '0.50', '0.00']);
    for (const value of column) {
      expect(value.split('.')[1]).toHaveLength(2);
    }
  });

  it('keeps steps and planck apart, which is the easy way to publish a wrong number', () => {
    expect(stepsToPlanck(45n)).toBe(450_000_000_000n);
    expect(formatStepsAsQnr(45n)).toBe('0.45 QNR');
    expect(formatQnr(450_000_000_000n)).toBe('0.45 QNR');
    expect(formatStepsAsQnr(1000n)).toBe('10.00 QNR');
  });

  it('formats counts, sizes and times the way a table reads them', () => {
    expect(formatCount(1234567)).toBe('1,234,567');
    expect(formatCount(1234567n)).toBe('1,234,567');
    expect(formatBytes(1792)).toBe('1,792 bytes');
    expect(formatSeconds(12000)).toBe('12.0 s');
    expect(formatSeconds(120000)).toBe('120.0 s');
    expect(formatSeconds(Number.NaN)).toBe('unknown');
  });

  /**
   * Block counts become durations with the chain's own target, so one span
   * reaches from a dev chain's minutes to a seed epoch's days. The unit moves
   * with the number: a fixed one would print "0.0 d" or "245760.0 s".
   */
  it('names a span in the unit that leaves a readable number', () => {
    expect(formatSpan(90_000)).toBe('90 s');
    expect(formatSpan(30 * 120_000)).toBe('60 min');
    // 128 blocks of seed lag on the public chain: 15 360 000 ms is 4.267 h,
    // and a span below 48 h prints one decimal.
    expect(formatSpan(128 * 120_000)).toBe('4.3 h');
    // 256 blocks of shielded anchor validity, the same chain.
    expect(formatSpan(256 * 120_000)).toBe('8.5 h');
    // 2048 blocks of seed epoch: Monero's rotation, to the hour.
    expect(formatSpan(2048 * 120_000)).toBe('2.84 days');
    // The same epoch on a 12 s dev chain.
    expect(formatSpan(2048 * 12_000)).toBe('6.8 h');
    expect(formatSpan(Number.NaN)).toBe('unknown');
  });
});
