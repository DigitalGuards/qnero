import { describe, expect, it } from 'vitest';

import {
  blocksToNextSeed,
  DEFAULT_SEED_EPOCH_BLOCKS,
  DEFAULT_SEED_EPOCH_LAG,
  nextSeedHeight,
  seedHeight,
} from '../src/lib/seed';

const EPOCH = DEFAULT_SEED_EPOCH_BLOCKS;
const LAG = DEFAULT_SEED_EPOCH_LAG;

/** The formula that circulates and is wrong, kept here only to be disagreed with. */
function folkFormula(height: number, epoch: number, lag: number): number {
  return height - (height % epoch) - lag;
}

describe('seed height', () => {
  it('is zero until one block past epoch plus lag', () => {
    expect(seedHeight(0, EPOCH, LAG)).toBe(0);
    expect(seedHeight(1, EPOCH, LAG)).toBe(0);
    expect(seedHeight(EPOCH + LAG, EPOCH, LAG)).toBe(0);
    expect(seedHeight(EPOCH + LAG + 1, EPOCH, LAG)).toBe(EPOCH);
  });

  it('disagrees with the folk formula at 2113, which is a chain split', () => {
    expect(seedHeight(2113, EPOCH, LAG)).toBe(2048);
    expect(folkFormula(2113, EPOCH, LAG)).toBe(1984);
  });

  it('steps on the anchor crossing an epoch boundary', () => {
    expect(seedHeight(4160, EPOCH, LAG)).toBe(2048);
    expect(seedHeight(4161, EPOCH, LAG)).toBe(4096);
  });

  it('holds across a whole epoch', () => {
    const start = EPOCH + LAG + 1;
    for (let height = start; height < start + EPOCH; height += 1) {
      expect(seedHeight(height, EPOCH, LAG)).toBe(EPOCH);
    }
    expect(seedHeight(start + EPOCH, EPOCH, LAG)).toBe(2 * EPOCH);
  });

  it('announces the next rotation a lag ahead', () => {
    expect(nextSeedHeight(4096, EPOCH, LAG)).toBe(seedHeight(4096 + LAG, EPOCH, LAG));
    expect(nextSeedHeight(4160, EPOCH, LAG)).toBe(4096);
    // At 4097 the seed in use is still 2048 and the next one is already named.
    expect(seedHeight(4097, EPOCH, LAG)).toBe(2048);
    expect(nextSeedHeight(4097, EPOCH, LAG)).toBe(4096);
  });

  it('counts the blocks left before the seed changes', () => {
    for (const height of [0, 1, 2112, 2113, 4160, 4161, 9999]) {
      const left = blocksToNextSeed(height, EPOCH, LAG);
      expect(left).toBeGreaterThan(0);
      expect(seedHeight(height + left, EPOCH, LAG)).not.toBe(seedHeight(height, EPOCH, LAG));
      expect(seedHeight(height + left - 1, EPOCH, LAG)).toBe(seedHeight(height, EPOCH, LAG));
    }
  });

  it('never divides by zero on a degenerate epoch', () => {
    expect(seedHeight(100, 0, LAG)).toBe(35);
  });
});
