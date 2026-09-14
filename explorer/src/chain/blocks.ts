/**
 * Reading blocks.
 *
 * Headers and bodies come over the raw provider and are parsed here; events
 * come through the typed API, because metadata alone decodes them and the
 * decoders want the field names metadata carries. The body has to be raw: the
 * ML-DSA-87 signature is a 7219-byte fixed array and polkadot-js refuses any
 * fixed array above 2048, so the typed `chain_getBlock` throws on every block
 * holding a signed extrinsic.
 */

import { blake2AsHex } from '@polkadot/util-crypto';

import {
  decodeCoinbase,
  decodeDifficultyAdjustment,
  decodeFailures,
  decodeLeafInsertions,
  decodeSettlements,
  decodeShieldEntries,
  successfulExtrinsics,
  type CoinbaseNote,
  type DifficultyAdjustment,
  type DispatchFailure,
  type EventRecord,
  type Settlement,
  type ShieldEntry,
} from '../lib/events';
import { decodeExtrinsic, type ExtrinsicEnvelope } from '../lib/extrinsics';
import { hexToBytes } from '../lib/hex';
import { parseHeader, type BlockHeader } from '../lib/header';
import { callName, normaliseEvents, storageAt, type ChainContext } from './api';

export interface BlockSummary {
  hash: string;
  header: BlockHeader;
  timestampMs: number;
  leavesAdded: number[];
  settlements: Settlement[];
  entries: ShieldEntry[];
  coinbase: CoinbaseNote | null;
  failures: DispatchFailure[];
  difficulty: DifficultyAdjustment | null;
  events: EventRecord[];
}

export interface ExtrinsicRow extends ExtrinsicEnvelope {
  hash: string;
  name: string;
  succeeded: boolean;
}

export interface BlockDetail extends BlockSummary {
  extrinsics: ExtrinsicRow[];
}

export async function blockHashAt(context: ChainContext, height: number): Promise<string | null> {
  const hash = await context.provider.send<string | null>('chain_getBlockHash', [height]);
  if (hash === null || /^0x0+$/.test(hash)) {
    return null;
  }
  return hash;
}

export async function fetchHeader(context: ChainContext, hash: string): Promise<BlockHeader> {
  return parseHeader(await context.provider.send('chain_getHeader', [hash]));
}

export async function fetchEvents(context: ChainContext, hash: string): Promise<EventRecord[]> {
  const query = await storageAt(context, hash, 'system', 'events');
  const records = await query();
  return normaliseEvents(records as unknown as Parameters<typeof normaliseEvents>[0]);
}

export async function fetchTimestamp(context: ChainContext, hash: string): Promise<number> {
  const query = await storageAt(context, hash, 'timestamp', 'now');
  return Number((await query()).toString());
}

export function summarise(
  hash: string,
  header: BlockHeader,
  timestampMs: number,
  events: EventRecord[],
): BlockSummary {
  return {
    hash,
    header,
    timestampMs,
    leavesAdded: decodeLeafInsertions(events),
    settlements: decodeSettlements(events),
    entries: decodeShieldEntries(events),
    coinbase: decodeCoinbase(events),
    failures: decodeFailures(events),
    difficulty: decodeDifficultyAdjustment(events),
    events,
  };
}

export async function fetchSummary(context: ChainContext, hash: string): Promise<BlockSummary> {
  const [header, events, timestampMs] = await Promise.all([
    fetchHeader(context, hash),
    fetchEvents(context, hash),
    fetchTimestamp(context, hash),
  ]);
  return summarise(hash, header, timestampMs, events);
}

interface RawBlock {
  block: { header: unknown; extrinsics: string[] };
}

export async function fetchDetail(context: ChainContext, hash: string): Promise<BlockDetail> {
  const [raw, events, timestampMs] = await Promise.all([
    context.provider.send<RawBlock>('chain_getBlock', [hash]),
    fetchEvents(context, hash),
    fetchTimestamp(context, hash),
  ]);
  const header = parseHeader(raw.block.header);
  const succeeded = successfulExtrinsics(events);
  const extrinsics = raw.block.extrinsics.map((hex, index) => {
    const bytes = hexToBytes(hex);
    const envelope = decodeExtrinsic(bytes, index, context.layout);
    return {
      ...envelope,
      // The tx-pool hash the node itself uses: blake2-256 over the whole
      // encoding, length prefix included.
      hash: blake2AsHex(bytes, 256),
      name:
        envelope.call === null
          ? 'unresolved'
          : callName(context.pallets, envelope.call.palletIndex, envelope.call.callIndex),
      succeeded: succeeded.has(index),
    };
  });
  return { ...summarise(hash, header, timestampMs, events), extrinsics };
}

/**
 * A cache of finished blocks, keyed by hash.
 *
 * Blocks are immutable and a hash names one of them exactly, which is also why
 * nothing here is keyed by height: this is proof of work with no finality
 * gadget, so a height names different blocks on different branches.
 */
export class BlockCache {
  private readonly summaries = new Map<string, BlockSummary>();

  private readonly order: string[] = [];

  constructor(private readonly limit = 256) {}

  async summary(context: ChainContext, hash: string): Promise<BlockSummary> {
    const cached = this.summaries.get(hash);
    if (cached !== undefined) {
      return cached;
    }
    const fresh = await fetchSummary(context, hash);
    this.summaries.set(hash, fresh);
    this.order.push(hash);
    while (this.order.length > this.limit) {
      const evicted = this.order.shift();
      if (evicted !== undefined) {
        this.summaries.delete(evicted);
      }
    }
    return fresh;
  }
}

/** Summaries for `count` blocks ending at `height`, newest first. */
export async function fetchRecent(
  context: ChainContext,
  cache: BlockCache,
  height: number,
  count: number,
): Promise<BlockSummary[]> {
  const heights: number[] = [];
  for (let n = height; n > height - count && n >= 0; n -= 1) {
    heights.push(n);
  }
  const summaries = await Promise.all(
    heights.map(async (n) => {
      const hash = await blockHashAt(context, n);
      return hash === null ? null : cache.summary(context, hash);
    }),
  );
  return summaries.filter((summary): summary is BlockSummary => summary !== null);
}

/**
 * Rolling mean of the gaps between consecutive block timestamps, in
 * milliseconds. Null when there are not two blocks to compare.
 */
export function rollingBlockTimeMs(summaries: readonly BlockSummary[]): number | null {
  const times = summaries
    .map((summary) => summary.timestampMs)
    .filter((value) => Number.isFinite(value) && value > 0)
    .sort((a, b) => a - b);
  const first = times.at(0);
  const last = times.at(-1);
  if (first === undefined || last === undefined || times.length < 2) {
    return null;
  }
  return (last - first) / (times.length - 1);
}
