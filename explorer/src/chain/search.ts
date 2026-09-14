/**
 * Locating things without an indexer.
 *
 * There is no server-side index behind this site, so anything the chain does
 * not key directly is a bounded walk backwards from the tip. Every walk here
 * takes a block budget, reports how far it looked, and says so in the answer
 * rather than pretending a miss is an absence.
 *
 * A walk also ends where the node stops answering. A node keeps state for a
 * bounded number of finalized blocks and this chain finalizes its reorg depth
 * behind the tip, so a default-pruned node holds only a few hundred blocks of
 * state. Reaching the bottom of that is a boundary the answer names, not an
 * error that takes the page down.
 */

import { blockHashAt, fetchBlockState, fetchDetail, type BlockDetail } from './blocks';
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
  /** Why the walk stopped early, when the node stopped answering rather than the budget running out. */
  stopped: string | null;
}

const PRUNED =
  'the node answered nothing below this block, which is what a pruned state window looks like';

/**
 * What a node says when it no longer keeps the state at a block.
 *
 * Substrate answers a state read below its pruning window with an unknown-block
 * error naming the discarded state, and answers a hash it has never seen with
 * the header-and-parent message. Both are boundaries a walk can report.
 */
const STATE_BOUNDARY = [
  /state already discarded/i,
  /unknown ?block/i,
  /unable to retrieve header and parent/i,
];

/**
 * Whether a failed read is the bottom of the node's state window.
 *
 * Only this is reported as a boundary. A dropped socket or a timed-out request
 * establishes nothing about the blocks below it, and calling one a pruning
 * boundary would turn hundreds of unread blocks into "not published", which is
 * a negative inferred from a failure. Anything else is raised, and the page
 * shows the error it already has a branch for.
 */
function isStateBoundary(context: ChainContext, message: string): boolean {
  return context.api.isConnected && STATE_BOUNDARY.some((pattern) => pattern.test(message));
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
    let detail: BlockDetail;
    try {
      detail = await fetchDetail(context, hash);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (!isStateBoundary(context, message)) {
        throw error;
      }
      return { found: null, scanned, exhausted: true, stopped: PRUNED };
    }
    const match = detail.extrinsics.find((extrinsic) => extrinsic.hash.toLowerCase() === target);
    if (match !== undefined) {
      return {
        found: { blockHash: hash, height, index: match.index, detail },
        scanned,
        exhausted: false,
        stopped: null,
      };
    }
    if (height === 0) {
      return { found: null, scanned, exhausted: true, stopped: null };
    }
  }
  return { found: null, scanned, exhausted: false, stopped: null };
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
    const state = await fetchBlockState(context, hash);
    if (state.error !== null) {
      if (!isStateBoundary(context, state.error)) {
        throw new Error(state.error);
      }
      return { found: null, scanned, exhausted: true, stopped: PRUNED };
    }
    const settlements = decodeSettlements(state.events);
    for (const settlement of settlements) {
      for (const slot of settlement.slots) {
        if (slot.nullifiers.some((value) => value.toLowerCase() === target)) {
          return {
            found: { blockHash: hash, height, extrinsicIndex: settlement.extrinsicIndex },
            scanned,
            exhausted: false,
            stopped: null,
          };
        }
      }
    }
    if (height === 0) {
      return { found: null, scanned, exhausted: true, stopped: null };
    }
  }
  return { found: null, scanned, exhausted: false, stopped: null };
}

/**
 * Whether a 32-byte value is a block hash on this chain.
 *
 * The node answers a hash it does not know with null, so null is the whole
 * negative and nothing here catches. A dropped socket or a refused read has to
 * reach the caller: rendering it as "not seen" would tell a reader that a value
 * which is a block on this chain was never on it.
 */
export async function blockForHash(context: ChainContext, hash: string): Promise<number | null> {
  const header = await context.provider.send<{ number: string } | null>('chain_getHeader', [hash]);
  if (header === null) {
    return null;
  }
  return Number(BigInt(header.number));
}
