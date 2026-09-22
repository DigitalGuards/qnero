import { describe, expect, it } from 'vitest';

import {
  announcedSeedHeight,
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

  it('disagrees with the folk formula at 2177, which is a chain split', () => {
    // 2177 - (2177 % 2048) - 128 = 2177 - 129 - 128.
    expect(seedHeight(2177, EPOCH, LAG)).toBe(2048);
    expect(folkFormula(2177, EPOCH, LAG)).toBe(1920);
  });

  it('steps on the anchor crossing an epoch boundary', () => {
    // The anchor is h - lag - 1, so the step is at 2 * 2048 + 128 + 1 = 4225.
    expect(seedHeight(4224, EPOCH, LAG)).toBe(2048);
    expect(seedHeight(4225, EPOCH, LAG)).toBe(4096);
  });

  it('holds across a whole epoch', () => {
    const start = EPOCH + LAG + 1;
    for (let height = start; height < start + EPOCH; height += 1) {
      expect(seedHeight(height, EPOCH, LAG)).toBe(EPOCH);
    }
    expect(seedHeight(start + EPOCH, EPOCH, LAG)).toBe(2 * EPOCH);
  });

  it('names the seed the next rotation installs, one epoch above the one in use', () => {
    // Mid-epoch is where the node-parity announcement and the rotation part
    // company, and mid-epoch is almost the whole chain.
    expect(seedHeight(5000, EPOCH, LAG)).toBe(4096);
    expect(nextSeedHeight(5000, EPOCH, LAG)).toBe(6144);
    expect(nextSeedHeight(5000, EPOCH, LAG)).not.toBe(seedHeight(5000, EPOCH, LAG));

    // On a chain below one epoch the seed in use is genesis and the first
    // rotation installs the epoch boundary.
    expect(seedHeight(44, EPOCH, LAG)).toBe(0);
    expect(nextSeedHeight(44, EPOCH, LAG)).toBe(EPOCH);

    // The rotation always lands exactly where the countdown says it will.
    for (const height of [0, 1, 2112, 2113, 4097, 4160, 5000, 9999]) {
      const left = blocksToNextSeed(height, EPOCH, LAG);
      expect(nextSeedHeight(height, EPOCH, LAG)).toBe(seedHeight(height + left, EPOCH, LAG));
      expect(nextSeedHeight(height, EPOCH, LAG)).toBe(seedHeight(height, EPOCH, LAG) + EPOCH);
    }
  });

  it('keeps the node-parity announcement as its own function', () => {
    // `next_seed_height` names the seed a rig should already be building for,
    // so it holds at the current seed until the lag window opens.
    expect(announcedSeedHeight(5000, EPOCH, LAG)).toBe(seedHeight(5000, EPOCH, LAG));
    expect(announcedSeedHeight(4097, EPOCH, LAG)).toBe(4096);
    expect(announcedSeedHeight(4160, EPOCH, LAG)).toBe(4096);
  });

  it('opens the announcement window exactly one lag before the rotation', () => {
    // The whole point of the lag: the window is `LAG` blocks wide and opens on
    // the block `LAG` below the rotation, so it is the lag alone that decides
    // how much notice a rig gets before the turn.
    const rotateAt = 2 * EPOCH + LAG + 1;
    expect(seedHeight(rotateAt - 1, EPOCH, LAG)).toBe(EPOCH);
    expect(seedHeight(rotateAt, EPOCH, LAG)).toBe(2 * EPOCH);
    expect(announcedSeedHeight(rotateAt - LAG - 1, EPOCH, LAG)).toBe(EPOCH);
    expect(announcedSeedHeight(rotateAt - LAG, EPOCH, LAG)).toBe(2 * EPOCH);
    for (let ahead = 0; ahead < LAG; ahead += 1) {
      expect(announcedSeedHeight(rotateAt - LAG + ahead, EPOCH, LAG)).toBe(2 * EPOCH);
    }
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
    // The epoch clamps to 1, so the height has to sit above `1 + LAG` for the
    // anchor branch to be the one under test: 200 - 128 - 1 = 71.
    expect(seedHeight(200, 0, LAG)).toBe(71);
  });
});
