/**
 * RandomX seed rotation.
 *
 * Nothing on chain stores the seed. It is derived from the height and two
 * runtime constants, and the rule is Monero's, copied from
 * `chain/client/consensus/randomx/src/seed.rs`:
 *
 * ```text
 * seed_height(h) = 0                            if h <= epoch + lag
 *                  (h - lag - 1) & ~(epoch - 1) otherwise
 * ```
 *
 * The masked form only holds for a power-of-two epoch, so this is the
 * truncating-division form the node uses, which agrees with the mask at every
 * power of two. The folk version `h - (h % epoch) - lag` is a different
 * function: at h = 2177 with the default constants it gives
 * 2177 - 129 - 128 = 1920 where the real rule gives 2048, and a one-block
 * disagreement about the seed is a chain split.
 */

export const DEFAULT_SEED_EPOCH_BLOCKS = 2048;
export const DEFAULT_SEED_EPOCH_LAG = 128;

export function seedHeight(height: number, epochBlocks: number, lag: number): number {
  const epoch = Math.max(epochBlocks, 1);
  if (height <= epoch + lag) {
    return 0;
  }
  const anchor = height - lag - 1;
  return anchor - (anchor % epoch);
}

/**
 * The seed the node announces ahead of a rotation, which is node parity with
 * `next_seed_height`: it names the seed a rig should already be building for,
 * so it equals `seedHeight` everywhere except the last `lag` blocks of an
 * epoch. It is the stratum announcement, and it is the wrong number to print
 * beside a countdown.
 */
export function announcedSeedHeight(height: number, epochBlocks: number, lag: number): number {
  return seedHeight(height + lag, epochBlocks, lag);
}

/**
 * The seed the next rotation installs, which is what a countdown is counting
 * down to. Always one epoch above the seed in use, so it never reads back the
 * height the chain is already mining against.
 */
export function nextSeedHeight(height: number, epochBlocks: number, lag: number): number {
  return seedHeight(height + blocksToNextSeed(height, epochBlocks, lag), epochBlocks, lag);
}

/**
 * Blocks until the seed changes.
 *
 * `seedHeight` steps exactly when the anchor crosses an epoch boundary, so the
 * next step is one block past `seedHeight(h) + epoch + lag`.
 */
export function blocksToNextSeed(height: number, epochBlocks: number, lag: number): number {
  const epoch = Math.max(epochBlocks, 1);
  const nextChange = seedHeight(height, epochBlocks, lag) + epoch + lag + 1;
  return nextChange - height;
}
