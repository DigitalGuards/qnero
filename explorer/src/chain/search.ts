/**
 * Locating things without an indexer.
 *
 * There is no server-side index behind this site, so anything the chain does
 * not key directly is a bounded walk backwards from the tip. Every walk here
 * takes a block budget, reports how far it looked, and says so in the answer
 * rather than pretending a miss is an absence.
 */

import { blockHashAt, fetchDetail, fetchEvents, type BlockDetail } from './blocks';
import type { ChainContext } from './api';
import { decodeSettlements } from '../lib/events';

export type QueryKind = 'height' | 'hash' | 'unknown';

export function classifyQuery(text: string): QueryKind {
  const trimmed = text.trim();
  if (/^[0-9]+$/.test(trimmed)) {
    return 'height';
  }
  if (/^0x[0-9a-fA-F]{64}$/.test(trimmed)) {
    return 'hash';
  }
  return 'unknown';
}

export interface ScanResult<T> {
  found: T | null;
  /** Blocks actually read. */
  scanned: number;
  /** True when the walk reached the genesis end of its window rather than the budget. */
  exhausted: boolean;
}

export interface ExtrinsicLocation {
  blockHash: string;
  height: number;
  index: number;
  detail: BlockDetail;
}

/**
 * The block holding an extrinsic with this hash.
 *
 * The hash is blake2-256 over the whole encoding, which is what the node's own
 * transaction pool uses, so it matches what a submitting client saw.
 */
export async function findExtrinsic(
  context: ChainContext,
  txHash: string,
  fromHeight: number,
  budget: number,
  onProgress?: (scanned: number) => void,
): Promise<ScanResult<ExtrinsicLocation>> {
  const target = txHash.toLowerCase();
  let scanned = 0;
  for (let height = fromHeight; height >= 0 && scanned < budget; height -= 1) {
    const hash = await blockHashAt(context, height);
    scanned += 1;
    onProgress?.(scanned);
    if (hash === null) {
      continue;
    }
    const detail = await fetchDetail(context, hash);
    const match = detail.extrinsics.find((extrinsic) => extrinsic.hash.toLowerCase() === target);
    if (match !== undefined) {
      return {
        found: { blockHash: hash, height, index: match.index, detail },
        scanned,
        exhausted: false,
      };
    }
    if (height === 0) {
      return { found: null, scanned, exhausted: true };
    }
  }
  return { found: null, scanned, exhausted: false };
}

export interface NullifierLocation {
  blockHash: string;
  height: number;
  extrinsicIndex: number | null;
}

/**
 * The block whose settlement published a nullifier.
 *
 * `UsedNullifiers` holds presence only, keyed by the nullifier, with no block
 * beside it, so the block is found by reading the `SlotSettled` events of a
 * bounded window. Events are far smaller than bodies, so this walk is cheaper
 * than the extrinsic one.
 */
export async function findNullifierBlock(
  context: ChainContext,
  nullifier: string,
  fromHeight: number,
  budget: number,
  onProgress?: (scanned: number) => void,
): Promise<ScanResult<NullifierLocation>> {
  const target = nullifier.toLowerCase();
  let scanned = 0;
  for (let height = fromHeight; height >= 0 && scanned < budget; height -= 1) {
    const hash = await blockHashAt(context, height);
    scanned += 1;
    onProgress?.(scanned);
    if (hash === null) {
      continue;
    }
    const settlements = decodeSettlements(await fetchEvents(context, hash));
    for (const settlement of settlements) {
      for (const slot of settlement.slots) {
        if (slot.nullifiers.some((value) => value.toLowerCase() === target)) {
          return {
            found: { blockHash: hash, height, extrinsicIndex: settlement.extrinsicIndex },
            scanned,
            exhausted: false,
          };
        }
      }
    }
    if (height === 0) {
      return { found: null, scanned, exhausted: true };
    }
  }
  return { found: null, scanned, exhausted: false };
}

/** Whether a 32-byte value is a block hash on this chain. */
export async function blockForHash(context: ChainContext, hash: string): Promise<number | null> {
  try {
    const header = await context.provider.send<{ number: string } | null>('chain_getHeader', [hash]);
    if (header === null) {
      return null;
    }
    return Number(BigInt(header.number));
  } catch {
    return null;
  }
}
