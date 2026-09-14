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
 * function: at h = 2113 with the default constants it gives 1984 where the
 * real rule gives 2048, and a one-block disagreement about the seed is a chain
 * split.
 */

export const DEFAULT_SEED_EPOCH_BLOCKS = 2048;
export const DEFAULT_SEED_EPOCH_LAG = 64;

export function seedHeight(height: number, epochBlocks: number, lag: number): number {
  const epoch = Math.max(epochBlocks, 1);
  if (height <= epoch + lag) {
    return 0;
  }
  const anchor = height - lag - 1;
  return anchor - (anchor % epoch);
}

/**
 * The seed the next epoch will use, which is what tells a viewer when the next
 * dataset rotation lands. Equal to `seedHeight` while the epoch is not about
 * to turn.
 */
export function nextSeedHeight(height: number, epochBlocks: number, lag: number): number {
  return seedHeight(height + lag, epochBlocks, lag);
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
