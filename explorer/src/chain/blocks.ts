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
import { callName, normaliseEvents, type ChainContext } from './api';

export interface BlockSummary {
  hash: string;
  header: BlockHeader;
  /** Null when the node keeps no state at this block, which prunes the timestamp with it. */
  timestampMs: number | null;
  /** Why the state reads failed, when they did. The header and the body survive it. */
  stateError: string | null;
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
  /**
   * Null when the node kept no state at this block, so the outcome was never
   * read. An unread outcome is not a failed one: the events that carry it are
   * state, and below a pruned node's state window there are none to read.
   */
  succeeded: boolean | null;
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

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Everything one block's state holds, read behind a single decoration. */
export interface BlockState {
  events: EventRecord[];
  timestampMs: number | null;
  error: string | null;
}

/**
 * The events and the timestamp of one block, in one decoration and one round
 * trip each.
 *
 * `api.at()` costs a header read and a runtime-version read on a registry
 * miss, so taking it once and using it twice halves the cost of a block and
 * cuts a twenty-row list by a third.
 *
 * Both reads need state, and a node keeps state for a bounded number of
 * finalized blocks. Below that window they fail, and that is an ordinary
 * answer rather than an error: the header and the body are still there, so a
 * failure here empties the panels that read events and leaves the rest of the
 * page standing.
 */
export async function fetchBlockState(context: ChainContext, hash: string): Promise<BlockState> {
  try {
    const at = await context.api.at(hash);
    const events = at.query['system']?.['events'];
    const now = at.query['timestamp']?.['now'];
    if (events === undefined || now === undefined) {
      throw new Error(`the runtime at ${hash} declares no System::Events or Timestamp::Now`);
    }
    const [records, timestamp] = await Promise.all([events(), now()]);
    return {
      events: normaliseEvents(records as unknown as Parameters<typeof normaliseEvents>[0]),
      timestampMs: Number(timestamp.toString()),
      error: null,
    };
  } catch (error: unknown) {
    return { events: [], timestampMs: null, error: messageOf(error) };
  }
}

export function summarise(hash: string, header: BlockHeader, state: BlockState): BlockSummary {
  const events = state.events;
  return {
    hash,
    header,
    timestampMs: state.timestampMs,
    stateError: state.error,
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
  const [header, state] = await Promise.all([
    fetchHeader(context, hash),
    fetchBlockState(context, hash),
  ]);
  return summarise(hash, header, state);
}

interface RawBlock {
  block: { header: unknown; extrinsics: string[] };
}

export async function fetchDetail(context: ChainContext, hash: string): Promise<BlockDetail> {
  const [raw, state] = await Promise.all([
    // A hash the node does not know is answered with null rather than an
    // error, and a hash is the one thing a reader can paste or follow from a
    // genesis parent link, so the miss is a written sentence here.
    context.provider.send<RawBlock | null>('chain_getBlock', [hash]),
    fetchBlockState(context, hash),
  ]);
  if (raw === null) {
    throw new Error(`this chain has no block with hash ${hash}`);
  }
  const header = parseHeader(raw.block.header);
  const succeeded = successfulExtrinsics(state.events);
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
      succeeded: state.error === null ? succeeded.has(index) : null,
    };
  });
  return { ...summarise(hash, header, state), extrinsics };
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
    // A block whose state did not answer is not cached. A dropped socket
    // during one list load would otherwise pin those rows to "state not kept
    // at this block" for the life of the tab, on a node that had the state all
    // along, and take their timestamps out of the rolling block time with them.
    if (fresh.stateError === null) {
      this.summaries.set(hash, fresh);
      this.order.push(hash);
      while (this.order.length > this.limit) {
        const evicted = this.order.shift();
        if (evicted !== undefined) {
          this.summaries.delete(evicted);
        }
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
 * Mean time per block over the window, in milliseconds. Null when there are not
 * two heights to compare.
 *
 * The divisor is the heights the two end samples span. A block whose state did
 * not answer carries no timestamp, so dividing by the samples that survived
 * shortens the divisor while the span stays as long as it was: two gaps in a
 * twelve-block window reported a block time about a fifth high and, through
 * `estimateHashrate`, a network hash rate about a fifth low, under a note
 * saying the window was twelve blocks.
 *
 * Genesis carries a zero timestamp where every other block carries a time, so
 * it is filtered out with the unread ones and the window starts at block 1.
 */
export function rollingBlockTimeMs(summaries: readonly BlockSummary[]): number | null {
  const timed = summaries
    .map((summary) => ({ height: summary.header.number, timestampMs: summary.timestampMs }))
    .filter((sample): sample is { height: number; timestampMs: number } => {
      const value = sample.timestampMs;
      return value !== null && Number.isFinite(value) && value > 0;
    })
    .sort((a, b) => a.height - b.height);
  const first = timed.at(0);
  const last = timed.at(-1);
  if (first === undefined || last === undefined) {
    return null;
  }
  const blocks = last.height - first.height;
  if (blocks <= 0) {
    return null;
  }
  return (last.timestampMs - first.timestampMs) / blocks;
}

/**
 * What a block's state answered about one extrinsic, or that it did not answer.
 *
 * A settlement's slots are events, and events are state. A node that keeps the
 * body of a block below its state window still serves the extrinsic, so
 * `detail.settlements` comes back empty there for a spend that published two
 * nullifiers and two commitments. Reading that empty list as "settled nothing"
 * is a negative inferred from a failure, on the one page whose subject is what
 * a settlement publishes, so the unread case is its own answer here and the
 * caller has to spell it.
 */
export type SettlementRead =
  | { kind: 'read'; settlement: Settlement | null }
  | { kind: 'not-read'; error: string };

export function settlementOf(block: BlockSummary, extrinsicIndex: number): SettlementRead {
  if (block.stateError !== null) {
    return { kind: 'not-read', error: block.stateError };
  }
  return {
    kind: 'read',
    settlement:
      block.settlements.find((entry) => entry.extrinsicIndex === extrinsicIndex) ?? null,
  };
}

/**
 * What the newest block in a window says about its coinbase note.
 *
 * Emission is the one quantity this chain publishes in full, and the home page
 * invites a reader to total it block by block, so "the newest block minted no
 * note" is a checkable claim about the chain. It is true only when a state read
 * answered and held no `CoinbaseMinted`. While the window is still being read,
 * when the read failed, and when the newest block's own state was not kept,
 * nothing was established and the page says which of those it is.
 */
export type LatestCoinbase =
  | { kind: 'reading' }
  | { kind: 'unread'; why: 'recent-read-failed' | 'no-block' | 'state-not-kept' }
  | { kind: 'none' }
  | { kind: 'minted'; note: CoinbaseNote };

export function latestCoinbase(
  status: 'loading' | 'error' | 'ready',
  blocks: readonly BlockSummary[],
): LatestCoinbase {
  if (status === 'loading') {
    return { kind: 'reading' };
  }
  if (status === 'error') {
    return { kind: 'unread', why: 'recent-read-failed' };
  }
  const newest = blocks.at(0);
  if (newest === undefined) {
    return { kind: 'unread', why: 'no-block' };
  }
  if (newest.stateError !== null) {
    return { kind: 'unread', why: 'state-not-kept' };
  }
  return newest.coinbase === null ? { kind: 'none' } : { kind: 'minted', note: newest.coinbase };
}
