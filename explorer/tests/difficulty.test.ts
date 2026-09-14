import { describe, expect, it } from 'vitest';

import { decodeU512, estimateHashrate, formatDifficulty, formatHashrate } from '../src/lib/difficulty';

/** The same bytes read the wrong way round, which still looks like a number. */
function decodeBigEndian(hex: string): bigint {
  return BigInt(hex);
}

describe('difficulty', () => {
  it('reads a U512 as 64 little-endian bytes', () => {
    const hex = `0xc8${'00'.repeat(63)}`;
    expect(decodeU512(hex)).toBe(200n);
    expect(decodeBigEndian(hex)).not.toBe(200n);
  });

  it('reads a value wider than a u64', () => {
    const hex = `0x${'ff'.repeat(9)}${'00'.repeat(55)}`;
    expect(decodeU512(hex)).toBe(2n ** 72n - 1n);
  });

  it('refuses a blob wider than a U512', () => {
    expect(() => decodeU512(`0x${'00'.repeat(65)}`)).toThrow(/at most 64 bytes/);
  });

  it('estimates a hash rate as difficulty over the observed block time', () => {
    expect(estimateHashrate(120_000n, 12_000)).toBe(10_000);
    expect(estimateHashrate(120_000n, 0)).toBeNull();
    expect(estimateHashrate(120_000n, Number.NaN)).toBeNull();
  });

  it('scales a rate to the unit a reader can hold', () => {
    expect(formatHashrate(999)).toBe('999 H/s');
    expect(formatHashrate(1500)).toBe('1.50 kH/s');
    expect(formatHashrate(2_500_000)).toBe('2.50 MH/s');
    expect(formatHashrate(null)).toBe('unknown');
  });

  it('groups a difficulty so a reader can see its size', () => {
    expect(formatDifficulty(1234567n)).toBe('1,234,567');
  });
});
