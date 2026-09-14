/**
 * Everything a wallet reads off the chain, and nothing it should not.
 *
 * Two rules shape every function here, and they are rules about the requests
 * rather than about the answers:
 *
 * 1. **A sync never names a nullifier.** `UsedNullifiers` is
 *    `Blake2_128Concat`, so a point lookup carries the raw 32 bytes in the
 *    clear. A node that logged those would hold, per client, the set of values
 *    that wallet will publish when it spends, before it has spent anything.
 *    So the set is paged whole and every decision is made locally.
 * 2. **A spend never names a leaf.** Merkle paths are rebuilt from
 *    `ZkTree::Leaves` read as a range. Asking a node for one leaf's proof
 *    names it seconds before the settlement publishes the matching nullifiers.
 *
 * Both replacements read public data whole and distinguish nothing. They cost
 * `O(leaf_count)` per pass, which is the price of the property.
 *
 * Every read of one pass is pinned to one block hash. A leaf appended in the
 * middle of a scan would otherwise be counted by one call and read as absent
 * by the next.
 */

import { hexToBytes, leBytesToBigInt } from '../lib/hex';
import { storage, type ChainContext } from './api';

/** Leaves per `state_queryStorageAt` when four items are read per leaf. */
export const LEAF_BATCH = 64;

/** Leaves per call when one item is read per leaf, so the page is wider. */
export const LEAF_HASH_BATCH = 256;

/** Keys per `state_getKeysPaged` call. */
export const KEY_PAGE = 1000;

export interface Head {
  number: number;
  hash: string;
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
  const sets = await context.send<StorageChangeSet[]>('state_queryStorageAt', [keys, at]);
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

/** The best block, and the hash every read of this pass is pinned to. */
export async function fetchHead(context: ChainContext): Promise<Head> {
  const hash = await context.send<string>('chain_getBlockHash', []);
  const header = await context.send<{ number: string }>('chain_getHeader', [hash]);
  return { number: Number(BigInt(header.number)), hash };
}

/**
 * Follow the chain's head for as long as the caller wants it.
 *
 * A subscription rather than a poll, and the reason is the request stream
 * rather than the traffic: a poll asks the node a question every few seconds
 * for as long as the tab is open, which is a clock on how long this wallet
 * watched. One subscribe and then pushes says the same thing once.
 *
 * It names nothing: every wallet on the chain gets the same headers.
 */
export async function watchHead(
  context: ChainContext,
  onHead: (height: number) => void,
): Promise<() => void> {
  const unsubscribe = await context.api.rpc.chain.subscribeNewHeads((header) => {
    onHead(header.number.toNumber());
  });
  return () => {
    unsubscribe();
  };
}

/**
 * The canonical hash at a height, or `null` when this node has no block there.
 *
 * `null` is an ordinary answer for the checkpoint walk and not an error. It is
 * also not a fork: a fork is a *different* hash at a height this wallet
 * checkpointed, and no hash at all is a node that has not reached that height
 * or has not filled in behind its own head. The walk reads the two apart.
 */
export async function blockHashAt(context: ChainContext, number: number): Promise<string | null> {
  return context.send<string | null>('chain_getBlockHash', [number]);
}

/** A raw header, as `chain_getHeader` returns it. */
export async function headerAt(context: ChainContext, hash: string): Promise<unknown> {
  return context.send<unknown>('chain_getHeader', [hash]);
}

function leNumber(value: string | undefined): number {
  return value === undefined ? 0 : Number(leBytesToBigInt(hexToBytes(value)));
}

/** `ZkTree::LeafCount` and `ZkTree::Depth` at one block, in one call. */
export async function fetchTreeShape(
  context: ChainContext,
  at: string,
): Promise<{ leafCount: number; depth: number }> {
  const leafCount = storage(context, 'zkTree', 'leafCount').key();
  const depth = storage(context, 'zkTree', 'depth').key();
  const values = await queryAt(context, [leafCount, depth], at);
  return { leafCount: leNumber(values.get(leafCount)), depth: leNumber(values.get(depth)) };
}

/**
 * The tree's shape and the shield counter, at one block, in one call.
 *
 * `Shielded::EntryCount` rides along because a scan reads it once per pass:
 * it is chain wide and the whole scan is pinned to one block, so asking per
 * received note was a round trip each for a field that is only a label.
 */
export async function fetchTreeTotals(
  context: ChainContext,
  at: string,
): Promise<{ leafCount: number; depth: number; entryCount: bigint }> {
  const leafCount = storage(context, 'zkTree', 'leafCount').key();
  const depth = storage(context, 'zkTree', 'depth').key();
  const entryCount = storage(context, 'shielded', 'entryCount').key();
  const values = await queryAt(context, [leafCount, depth, entryCount], at);
  const entry = values.get(entryCount);
  return {
    leafCount: leNumber(values.get(leafCount)),
    depth: leNumber(values.get(depth)),
    entryCount: entry === undefined ? 0n : leBytesToBigInt(hexToBytes(entry)),
  };
}

/**
 * Every leaf hash in `[from, to)` at one block, as `32 * n` raw bytes.
 *
 * One buffer rather than an array of strings: this is the input to the wasm
 * tree rebuild, which takes bytes, and a 4000-leaf tree is 128 KB either way
 * but 4000 allocations in the string form.
 *
 * A missing entry is the pallet's `empty_hash()`, which is what
 * `tree::get_leaf_hash` substitutes, so a local rebuild pads the way the chain
 * does.
 */
export async function fetchLeafHashes(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
  onProgress?: (done: number) => void,
): Promise<Uint8Array> {
  const leaves = storage(context, 'zkTree', 'leaves');
  const out = new Uint8Array(Math.max(0, to - from) * 32);
  for (let start = from; start < to; start += LEAF_HASH_BATCH) {
    const end = Math.min(start + LEAF_HASH_BATCH, to);
    const keys = new Map<number, string>();
    for (let index = start; index < end; index += 1) {
      keys.set(index, leaves.key(index));
    }
    const values = await queryAt(context, [...keys.values()], at);
    for (let index = start; index < end; index += 1) {
      const value = values.get(keys.get(index) ?? '');
      if (value !== undefined) {
        out.set(hexToBytes(value), (index - from) * 32);
      }
    }
    onProgress?.(end - from);
  }
  return out;
}

/** One leaf, as the chain holds it. */
export interface LeafRecord {
  index: number;
  commitment: string | null;
  /** The ciphertext itself, decoded out of its `Vec<u8>` length prefix. */
  ciphertext: Uint8Array | null;
  blockNumber: number | null;
  /** Set for exactly the leaves a block's coinbase minted, in pool quanta. */
  coinbaseQuanta: bigint | null;
}

/** A stored `Vec<u8>`: a compact length prefix, then the bytes. */
function decodeBytes(value: string | undefined): Uint8Array | null {
  if (value === undefined) {
    return null;
  }
  const bytes = hexToBytes(value);
  const first = bytes[0] ?? 0;
  const mode = first & 0b11;
  const offset = mode === 0 ? 1 : mode === 1 ? 2 : mode === 2 ? 4 : (first >>> 2) + 5;
  return bytes.slice(offset);
}

/**
 * Four items for each leaf in `[from, to)`, at one block.
 *
 * `CoinbaseValues` is the fourth and it is what makes a coinbase note
 * readable: presence marks a coinbase leaf, and the value is public because
 * the chain hashes it into a commitment over an `inner` it cannot open.
 */
export async function fetchLeaves(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
  onProgress?: (done: number) => void,
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
      const block = values.get(row.keys[2]);
      const coinbase = values.get(row.keys[3]);
      out.push({
        index: row.index,
        commitment: values.get(row.keys[0]) ?? null,
        ciphertext: decodeBytes(values.get(row.keys[1])),
        blockNumber: block === undefined ? null : Number(leBytesToBigInt(hexToBytes(block))),
        coinbaseQuanta: coinbase === undefined ? null : leBytesToBigInt(hexToBytes(coinbase)),
      });
    }
    onProgress?.(end - from);
  }
  return out;
}

/**
 * The whole settled nullifier set at one block.
 *
 * Paged over the map's keys. `UsedNullifiers` is `Blake2_128Concat`, so the
 * raw 32-byte nullifier is the tail of every key the node returns and no value
 * fetch is needed.
 *
 * **Not capped.** The explorer caps its own walk and reports a floor, because
 * a floor on a count is honest. A wallet cannot: a short set is a settled note
 * reported unspent, which puts a consumed note back into selection and pays
 * for a proof the chain skips. So this pages to the end, and the only thing
 * that stops it early is `stillWanted`, which is the caller abandoning the
 * whole pass.
 */
export async function fetchUsedNullifiers(
  context: ChainContext,
  at: string,
  stillWanted?: () => boolean,
  onProgress?: (seen: number) => void,
): Promise<Set<string>> {
  const entry = storage(context, 'shielded', 'usedNullifiers');
  const prefix = entry.keyPrefix();
  // `twox_128(pallet) ++ twox_128(item) ++ blake2_128(k) ++ k`, in hex
  // characters: the prefix, then 16 bytes of hash, then the raw key.
  const rawOffset = prefix.length + 32;
  const out = new Set<string>();
  let cursor: string | null = null;
  for (;;) {
    if (stillWanted?.() === false) {
      throw new Error('the sync was abandoned while paging the settled nullifier set');
    }
    const keys: string[] = await context.send<string[]>('state_getKeysPaged', [
      prefix,
      KEY_PAGE,
      cursor,
      at,
    ]);
    if (keys.length === 0) {
      return out;
    }
    for (const key of keys) {
      const raw = key.slice(rawOffset);
      if (raw.length !== 64) {
        throw new Error(`a UsedNullifiers key carries a ${raw.length / 2}-byte nullifier`);
      }
      out.add(raw.toLowerCase());
    }
    onProgress?.(out.size);
    if (keys.length < KEY_PAGE) {
      return out;
    }
    const last = keys.at(-1);
    if (last === undefined || cursor === last) {
      // The guard against a node whose cursor stops advancing. A capped answer
      // is exactly the failure this whole function exists to avoid, so it is
      // an error rather than a short set.
      throw new Error('state_getKeysPaged stopped advancing, so the settled set is incomplete');
    }
    cursor = last;
  }
}

/**
 * Whether each of these nullifiers is settled, asked about by name.
 *
 * This names the values it asks about to whoever runs the node, so it is only
 * ever for nullifiers that are already public: the confirmation of a
 * settlement this wallet has just broadcast, whose proof published both of
 * them a moment ago. Everything else goes through
 * [`fetchUsedNullifiers`] and decides locally.
 */
export async function confirmNullifiersSettled(
  context: ChainContext,
  nullifiers: readonly string[],
  at: string,
): Promise<boolean[]> {
  const entry = storage(context, 'shielded', 'usedNullifiers');
  const keys = nullifiers.map((nullifier) => entry.key(`0x${nullifier.replace(/^0x/, '')}`));
  const values = await queryAt(context, keys, at);
  return keys.map((key) => values.has(key));
}

/** The extrinsics of one block, as hex, for matching a submission to its inclusion. */
export async function blockExtrinsics(context: ChainContext, hash: string): Promise<string[]> {
  const block = await context.send<{ block?: { extrinsics?: string[] } }>('chain_getBlock', [hash]);
  return block.block?.extrinsics ?? [];
}
