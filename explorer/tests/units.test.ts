import { describe, expect, it } from 'vitest';

import {
  formatBytes,
  formatCount,
  formatPlanck,
  formatQnr,
  formatQuantaAsQnr,
  formatSeconds,
  PLANCK_PER_QNR,
  POOL_QUANTUM_PLANCK,
  quantaToPlanck,
} from '../src/lib/units';

describe('units', () => {
  it('pins the quantum at a hundredth of a QNR', () => {
    expect(PLANCK_PER_QNR).toBe(1_000_000_000_000n);
    expect(POOL_QUANTUM_PLANCK).toBe(10_000_000_000n);
    expect(PLANCK_PER_QNR / POOL_QUANTUM_PLANCK).toBe(100n);
  });

  it('formats planck as QNR with the trailing zeros trimmed', () => {
    expect(formatPlanck(0n)).toBe('0');
    expect(formatPlanck(PLANCK_PER_QNR)).toBe('1');
    expect(formatPlanck(450_000_000_000n)).toBe('0.45');
    expect(formatPlanck(1n)).toBe('0.000000000001');
    expect(formatPlanck(1_234_567_890_123_456n)).toBe('1234.567890123456');
  });

  it('keeps quanta and planck apart, which is the easy way to publish a wrong number', () => {
    expect(quantaToPlanck(45n)).toBe(450_000_000_000n);
    expect(formatQuantaAsQnr(45n)).toBe('0.45 QNR');
    expect(formatQnr(450_000_000_000n)).toBe('0.45 QNR');
    expect(formatQuantaAsQnr(1000n)).toBe('10 QNR');
  });

  it('formats counts, sizes and times the way a table reads them', () => {
    expect(formatCount(1234567)).toBe('1,234,567');
    expect(formatCount(1234567n)).toBe('1,234,567');
    expect(formatBytes(1792)).toBe('1,792 bytes');
    expect(formatSeconds(12000)).toBe('12.0 s');
    expect(formatSeconds(Number.NaN)).toBe('unknown');
  });
});
