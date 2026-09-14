/**
 * The commitment tree, leaf by leaf.
 *
 * Every one of these maps is `Identity`-hashed on a `u64` leaf index, so a key
 * is computable with no enumeration and a range of leaves batches into one
 * `state_queryStorageAt`. Rebuilding the whole tree is `O(leaf_count)` reads
 * and never belongs in a page load.
 *
 * `zkTree_getMerkleProof` is never called. Every such call names one leaf to
 * whoever runs the node, which is the correlation the wallet's local rebuild
 * exists to avoid, and an explorer making it on a viewer's behalf would hand
 * the node a per-viewer leaf-interest log.
 */

import { hexToBytes, leBytesToBigInt, readCompact } from '../lib/hex';
import { storage, type ChainContext } from './api';

/** Leaves per `state_queryStorageAt` when four items are read per leaf. */
export const LEAF_BATCH = 64;

/** Leaves per call when one item is read per leaf, so the page is wider. */
export const LEAF_HASH_BATCH = 256;

export interface LeafRecord {
  index: number;
  commitment: string | null;
  ciphertextBytes: number | null;
  blockNumber: number | null;
  /** Set for exactly the leaves a block's coinbase minted, in pool quanta. */
  coinbaseQuanta: bigint | null;
}

interface StorageChangeSet {
  block: string;
  changes: [string, string | null][];
}

async function queryAt(
  context: ChainContext,
  keys: string[],
  at: string,
): Promise<Map<string, string>> {
  if (keys.length === 0) {
    return new Map();
  }
  const sets = await context.provider.send<StorageChangeSet[]>('state_queryStorageAt', [keys, at]);
  const out = new Map<string, string>();
  for (const set of sets) {
    for (const [key, value] of set.changes) {
      if (value !== null) {
        out.set(key, value);
      }
    }
  }
  return out;
}

/** A stored `Vec<u8>` declares its own length in a compact prefix, which is the size to show. */
function ciphertextBytes(value: string | undefined): number | null {
  if (value === undefined) {
    return null;
  }
  return readCompact(hexToBytes(value), 0).value;
}

/** A fixed-width little-endian integer in a storage value. */
function leInt(value: string | undefined): bigint | null {
  return value === undefined ? null : leBytesToBigInt(hexToBytes(value));
}

function leNumber(value: string | undefined): number | null {
  const parsed = leInt(value);
  return parsed === null ? null : Number(parsed);
}

/** Four items for each leaf in `[from, to)`, at one block. */
export async function fetchLeaves(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
): Promise<LeafRecord[]> {
  const leaves = storage(context, 'zkTree', 'leaves');
  const ciphertexts = storage(context, 'shielded', 'ciphertexts');
  const leafBlocks = storage(context, 'shielded', 'leafBlocks');
  const coinbaseValues = storage(context, 'shielded', 'coinbaseValues');
  const out: LeafRecord[] = [];
  for (let start = from; start < to; start += LEAF_BATCH) {
    const end = Math.min(start + LEAF_BATCH, to);
    const rows: { index: number; keys: [string, string, string, string] }[] = [];
    for (let index = start; index < end; index += 1) {
      rows.push({
        index,
        keys: [
          leaves.key(index),
          ciphertexts.key(index),
          leafBlocks.key(index),
          coinbaseValues.key(index),
        ],
      });
    }
    const values = await queryAt(
      context,
      rows.flatMap((row) => row.keys),
      at,
    );
    for (const row of rows) {
      out.push({
        index: row.index,
        commitment: values.get(row.keys[0]) ?? null,
        ciphertextBytes: ciphertextBytes(values.get(row.keys[1])),
        blockNumber: leNumber(values.get(row.keys[2])),
        coinbaseQuanta: leInt(values.get(row.keys[3])),
      });
    }
  }
  return out;
}

/** One leaf, read on its own. */
export async function fetchLeaf(
  context: ChainContext,
  index: number,
  at: string,
): Promise<LeafRecord | null> {
  const [leaf] = await fetchLeaves(context, index, index + 1, at);
  return leaf ?? null;
}

/**
 * The leaf index a commitment sits at, searched newest first.
 *
 * `ZkTree::Leaves` is index to commitment, so the reverse direction is a scan.
 * It is bounded by `limit` leaves and reports how far it looked.
 */
export async function findCommitment(
  context: ChainContext,
  commitment: string,
  leafCount: number,
  at: string,
  limit: number,
  onProgress?: (scanned: number) => void,
): Promise<{ index: number | null; scanned: number; exhausted: boolean }> {
  const leaves = storage(context, 'zkTree', 'leaves');
  const target = commitment.toLowerCase();
  let scanned = 0;
  let end = leafCount;
  while (end > 0 && scanned < limit) {
    const start = Math.max(0, end - LEAF_HASH_BATCH);
    const keys = new Map<number, string>();
    for (let index = start; index < end; index += 1) {
      keys.set(index, leaves.key(index));
    }
    const values = await queryAt(context, [...keys.values()], at);
    for (let index = end - 1; index >= start; index -= 1) {
      if ((values.get(keys.get(index) ?? '') ?? '').toLowerCase() === target) {
        return { index, scanned: scanned + (end - index), exhausted: start === 0 };
      }
    }
    scanned += end - start;
    end = start;
    onProgress?.(scanned);
  }
  return { index: null, scanned, exhausted: end === 0 };
}
