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

import { hexByteLength, hexToBytes, leBytesToBigInt, readCompact } from '../lib/hex';
import { parseRawHeader, type RawChainHeader } from './anchor';
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
 * It names nothing: every wallet on the chain gets the same headers, and the
 * parameter list is empty.
 *
 * Through `ChainContext.subscribe` rather than `api.rpc.chain.subscribeNewHeads`
 * for the reason the seam exists: a subscription is a request, and one written
 * against the typed API would be invisible to `tests/privacy.test.ts`, which
 * records the seam. The raw header is read for its number alone, so the custom
 * `Header` codec is not needed here either.
 */
export async function watchHead(
  context: ChainContext,
  onHead: (height: number) => void,
): Promise<() => void> {
  return context.subscribe('chain_newHead', 'chain_subscribeNewHead', [], (header) => {
    // The node's own JSON, read for one field. A header that does not carry a
    // number is not a header this wallet can do anything with, and a status
    // strip is not the place to throw over one.
    const number = (header as { number?: unknown }).number;
    if (typeof number === 'string' || typeof number === 'number') {
      onHead(Number(BigInt(number)));
    }
  });
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

/**
 * Every header from `anchor` up to `top`, walked **downward** by `parentHash`,
 * handed to a callback one at a time.
 *
 * Downward, and by the parent link, is what makes the range a chain rather
 * than a list of answers: each header is fetched by the hash its child names,
 * so one trusted hash at the bottom authenticates every field of every header
 * above it once the caller rehashes them. That is where a block's
 * `zkTreeRoot` and its pre-runtime author label come from, and those are what
 * decide a leaf's kind.
 *
 * One `chain_getHeader` per block and no `chain_getBlockHash` at all, because
 * each header names its parent. It asks nothing about this wallet: every
 * wallet on the chain reads the same headers.
 *
 * A callback rather than an array, and nothing accumulates here: `top.number`
 * is a height the caller learned from the node, and building an array of the
 * range let one answer decide how much this page allocates. `wallet/sync.ts`
 * climbs a longer range in chunks of `HEADER_WALK_LIMIT` blocks and holds one
 * chunk at a time.
 *
 * The headers arrive **descending**, `top` first, which is the order the
 * parent links can be followed in. The caller must rehash every one and
 * compare `anchor`'s against a hash it already trusts; `wallet/sync.ts` does
 * both.
 */
export async function fetchHeaderRange(
  context: ChainContext,
  anchor: number,
  top: Head,
  onHeader: (header: RawChainHeader) => void,
  onProgress?: (done: number) => void,
): Promise<void> {
  if (anchor > top.number) {
    throw new Error(`a header walk was asked for block ${anchor} down from block ${top.number}`);
  }
  let hash = top.hash;
  let seen = 0;
  for (let number = top.number; ; number -= 1) {
    const header = parseRawHeader(await context.send<unknown>('chain_getHeader', [hash]));
    const claimed = Number(BigInt(header.number));
    if (claimed !== number) {
      throw new Error(
        `this node answered a header numbered ${claimed} for the hash it gave as block ` +
          `${number}. A header read at the hash its child names is the only thing tying a block ` +
          'to a height, so the walk is refused rather than dating leaves by it. Nothing has been ' +
          'changed.',
      );
    }
    onHeader(header);
    seen += 1;
    onProgress?.(seen);
    if (number === anchor) {
      break;
    }
    hash = header.parentHash;
  }
}

/**
 * `Shielded::LeafBlocks` over a range, at one block.
 *
 * The block each leaf is dated at, as the node reports it. Advisory: the
 * authenticated block ranges are what decide, and this is what they are
 * checked against. Read on its own, one key per leaf, because the typing pass
 * needs every leaf's block before the windowed scan can say which leaf is a
 * block's last one, and a window carries kilobytes of ciphertext per leaf.
 */
export async function fetchLeafBlocks(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
): Promise<(number | null)[]> {
  const leafBlocks = storage(context, 'shielded', 'leafBlocks');
  const out: (number | null)[] = [];
  for (let start = from; start < to; start += LEAF_HASH_BATCH) {
    const end = Math.min(start + LEAF_HASH_BATCH, to);
    const keys = new Map<number, string>();
    for (let index = start; index < end; index += 1) {
      keys.set(index, leafBlocks.key(index));
    }
    const values = await queryAt(context, [...keys.values()], at);
    for (let index = start; index < end; index += 1) {
      const raw = values.get(keys.get(index) ?? '');
      const height = decodeInteger(raw, `Shielded::LeafBlocks(${index})`, 4);
      out.push(height === null ? null : Number(height));
    }
  }
  return out;
}

/**
 * `ZkTree::LeafCount` and `ZkTree::Depth`, each at its declared width and
 * bounded by what the circuit can prove over.
 *
 * `LeafCount` is a `u64` and `Depth` is a `u8`, which is what `Chain::
 * leaf_count_at` and `Chain::tree_depth_at` decode them as, naming the item at
 * any other width. Read at whatever width the bytes happened to carry, thirty
 * two bytes of `0xff` is a scan window of 2^256 - 1 leaves and a two-byte
 * `0x0004` is a depth of 1024 where the chain says 4.
 *
 * The count is bounded as well as sized. A 4-ary tree of depth `d` holds
 * `4 ** d` leaves and `d` is capped by the circuit at `limits.max_tree_depth`,
 * so a count above that is a number no tree on this chain can reach, and it is
 * the number the scan turns into work: one window of reads per 64 of it.
 */
function readTreeShape(
  values: Map<string, string>,
  keys: { leafCount: string; depth: string },
  maxTreeDepth: number,
): { leafCount: number; depth: number } {
  const leafCount = decodeInteger(values.get(keys.leafCount), 'ZkTree::LeafCount', 8) ?? 0n;
  const depth = decodeInteger(values.get(keys.depth), 'ZkTree::Depth', 1) ?? 0n;
  const capacity = 4n ** BigInt(maxTreeDepth);
  if (leafCount > capacity) {
    throw new Error(
      `ZkTree::LeafCount is ${leafCount} at this block and a tree this wallet can prove over ` +
        `holds at most ${capacity} leaves, which is 4 ** ${maxTreeDepth}. A count above that is ` +
        'not a tree this chain carries, and it is what decides how many leaves the scan reads.',
    );
  }
  return { leafCount: Number(leafCount), depth: Number(depth) };
}

/** `ZkTree::LeafCount` and `ZkTree::Depth` at one block, in one call. */
export async function fetchTreeShape(
  context: ChainContext,
  at: string,
  maxTreeDepth: number,
): Promise<{ leafCount: number; depth: number }> {
  const leafCount = storage(context, 'zkTree', 'leafCount').key();
  const depth = storage(context, 'zkTree', 'depth').key();
  const values = await queryAt(context, [leafCount, depth], at);
  return readTreeShape(values, { leafCount, depth }, maxTreeDepth);
}

/**
 * The tree's shape and the shield counter, at one block, in one call.
 *
 * `Shielded::EntryCount` rides along because a scan reads it once per pass:
 * it is chain wide and the whole scan is pinned to one block, so asking per
 * received note was a round trip each for a field that is only a label.
 *
 * All three are decoded at their declared widths, and each of the three is a
 * number the wallet turns into work. The counter is a `u64` and the origin
 * walk hashes once per unit of it, inside the worker that holds the seed, so a
 * value read at whatever width the bytes happened to carry is a node answer
 * that spends the session: thirty-two bytes of 0xff read as 2^256 - 1 before
 * this, and `ENTRY_WALK_LIMIT` is the second half of it. `LeafCount` is a
 * `u64` and it decides how many leaves the scan window walks;
 * [`readTreeShape`] bounds it by what the circuit can prove over. `Depth` is a
 * `u8`, which the command-line wallet decodes it as.
 */
export async function fetchTreeTotals(
  context: ChainContext,
  at: string,
  maxTreeDepth: number,
): Promise<{ leafCount: number; depth: number; entryCount: bigint }> {
  const leafCount = storage(context, 'zkTree', 'leafCount').key();
  const depth = storage(context, 'zkTree', 'depth').key();
  const entryCount = storage(context, 'shielded', 'entryCount').key();
  const values = await queryAt(context, [leafCount, depth, entryCount], at);
  return {
    ...readTreeShape(values, { leafCount, depth }, maxTreeDepth),
    entryCount: decodeInteger(values.get(entryCount), 'Shielded::EntryCount', 8) ?? 0n,
  };
}

/** The pallet's `empty_hash()`: 32 zero bytes, in the hex a node answers. */
const PADDING_SENTINEL = `0x${'00'.repeat(32)}`;

/**
 * The tree's own pad, answered as a leaf below the count the node reports at
 * the same block.
 *
 * The all-zero digest is `tree::empty_hash()`, what `pallet-zk-tree` reads an
 * unfilled slot as at every level, and `insert_commitment` refuses an append
 * of it by name (`ZeroCommitment`), so below its own count the chain never
 * wrote one. Every real leaf is a note commitment, a Poseidon2 output.
 *
 * What it buys a node is a leaf count its own headers appear to carry. A fold
 * that pushes the pad reaches the root a fold that stopped short reaches,
 * because padding is what the fold already does above the count, so a run of
 * pads at the top of the tree matches every root the headers published while
 * the count is higher than the chain's. The pass would commit a watermark and
 * a checkpoint above indices this chain has not filled, and the real leaves
 * that later land there are below the watermark and never read.
 * `Chain::leaf_window` and `typing::type_chunk` in the command-line wallet and
 * `block_roots` in the prover module refuse the identical answer.
 */
function paddingSentinel(index: number, leafCount: number, at: string): Error {
  return new Error(
    `this node answered ZkTree::Leaves(${index}) with the all-zero digest at block ${at}, where ` +
      `it reports ${leafCount} leaves. That digest is the tree's own pad for an unfilled slot ` +
      'and `pallet-zk-tree` refuses an append of it, so below the count it is a leaf this chain ' +
      'never appended. Folding it moves no root, which is exactly what makes it a way to inflate ' +
      'the leaf count under honest headers, and the pass would then write a watermark above ' +
      'indices the chain has not filled. Nothing has been changed.',
  );
}

/**
 * Every leaf hash in `[from, to)` at one block, as `32 * n` raw bytes.
 *
 * One buffer rather than an array of strings: this is the input to the wasm
 * tree rebuild, which takes bytes, and a 4000-leaf tree is 128 KB either way
 * but 4000 allocations in the string form.
 *
 * `leafCount` is `ZkTree::LeafCount` read at this same block hash, and it is
 * what an answer is measured against. Below it every index was appended by one
 * of `pallet-shielded`'s three writers and carries a commitment, so an absent
 * answer there is one the node withheld and the all-zero digest there is the
 * tree's own pad standing in for a leaf the chain never wrote. Both are
 * refused by name. At or above the count the padding is the pallet's own rule,
 * which is what `tree::get_leaf_hash` substitutes, so a local rebuild pads the
 * way the chain does.
 */
export async function fetchLeafHashes(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
  leafCount: number,
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
      if (value === undefined) {
        if (index < leafCount) {
          throw withheld('ZkTree::Leaves', index, leafCount, at);
        }
      } else {
        if (index < leafCount && value.toLowerCase() === PADDING_SENTINEL) {
          throw paddingSentinel(index, leafCount, at);
        }
        // Checked before the write, not after. A longer value would overwrite
        // the head of the next leaf's slot and a shorter one would leave the
        // tail of this one as zeros, which is a valid canonical digest: either
        // way the rebuild roots to the wrong number and the spend is refused
        // with a message about syncing again, which fixes nothing.
        const bytes = hexToBytes(value);
        if (bytes.length !== 32) {
          throw new Error(
            `ZkTree::Leaves(${index}) is ${bytes.length} bytes, expected 32, so this wallet ` +
              'cannot rebuild the tree over it.',
          );
        }
        out.set(bytes, (index - from) * 32);
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

/**
 * A stored `Vec<u8>`: a compact length prefix, then exactly that many bytes.
 *
 * The length is checked against what follows it rather than skipped. The CLI
 * runs `Vec::<u8>::decode` here (`crates/qnero-wallet/src/chain.rs`), which
 * refuses a value whose prefix and body disagree. A reader that only skipped
 * the prefix would hand the worker a truncated ciphertext, that ciphertext
 * would fail to decrypt, and the leaf would be counted as somebody else's:
 * a zero balance over a completed sync, with nothing said anywhere.
 */
function decodeBytes(value: string | undefined, what: string): Uint8Array | null {
  if (value === undefined) {
    return null;
  }
  const bytes = hexToBytes(value);
  const { value: length, next } = readCompact(bytes, 0);
  const carried = bytes.length - next;
  if (carried !== length) {
    throw new Error(
      `${what} declares ${length} bytes and carries ${carried}. This runtime stores it ` +
        'differently from what this build decodes, so the sync is refused rather than reading ' +
        "every leaf as somebody else's.",
    );
  }
  return bytes.slice(next);
}

/**
 * A fixed-width little-endian integer, refused by name at any other width.
 *
 * `u32` for `LeafBlocks` and `u64` for `CoinbaseValues`, which is what
 * `Chain::leaf_block` and `Chain::coinbase_value` decode them as. A wider or
 * narrower value is a runtime that changed the type, and reading it anyway
 * produces a plausible number: a block height off by a factor of 2^32, or a
 * coinbase this wallet then rebuilds at the wrong value and reads as nobody's.
 */
function decodeInteger(value: string | undefined, what: string, width: number): bigint | null {
  if (value === undefined) {
    return null;
  }
  const bytes = hexToBytes(value);
  if (bytes.length !== width) {
    throw new Error(
      `${what} is ${bytes.length} bytes and this build decodes it as ${width}. This runtime ` +
        'declares a different type for it.',
    );
  }
  return leBytesToBigInt(bytes);
}

/**
 * One leaf hash, which is 32 bytes or it is not a leaf hash.
 *
 * `Chain::leaves` converts each value with `<[u8; 32]>::try_from` and errors
 * with the leaf's own index. `REQUIRED_STORAGE` compares hashers and cannot
 * see a changed value type, so this is the check that names the item.
 */
function decodeCommitment(value: string | undefined, index: number): string | null {
  if (value === undefined) {
    return null;
  }
  const length = hexByteLength(value);
  if (length !== 32) {
    throw new Error(
      `ZkTree::Leaves(${index}) is ${length} bytes, expected 32. This runtime stores a leaf ` +
        'differently from what this build reads, so nothing about this tree can be trusted.',
    );
  }
  return value;
}

/**
 * A key the node answered nothing for below the count it reports at the same
 * block.
 *
 * One sentence per key for what stepping over it costs, because the three hide
 * a leaf in three different ways and an operator reading the refusal is
 * reading about the one that happened. The rule behind all three, and the set
 * of keys it covers, is on [`fetchLeaves`].
 */
function withheld(key: string, index: number, leafCount: number, at: string): Error {
  const cost =
    key === 'ZkTree::Leaves'
      ? 'Scanning past it would step over whatever was on that leaf and then write a watermark ' +
        'above it'
      : key === 'Shielded::LeafBlocks'
        ? 'A leaf with no block is stepped over where it is a coinbase, and dated by nothing ' +
          'where it is not, and the pass would write a watermark above it'
        : 'A leaf with no ciphertext and no coinbase value reads as a leaf nobody can open, so a ' +
          'payment on it would be skipped and the pass would write a watermark above it';
  return new Error(
    `this node answered with no ${key}(${index}) at block ${at}, where it reports ${leafCount} ` +
      'leaves. `pallet-shielded` writes that key in the same call that appends the leaf and ' +
      'nothing removes it, so below the count it is an answer withheld rather than an absent ' +
      `one. ${cost}, and nothing would read it again. Nothing has been changed.`,
  );
}

/**
 * Four items for each leaf in `[from, to)`, at one block.
 *
 * `CoinbaseValues` is the fourth and it is what makes a coinbase note
 * readable: presence marks a coinbase leaf, and the value is public because
 * the chain hashes it into a commitment over an `inner` it cannot open.
 *
 * `leafCount` is `ZkTree::LeafCount` read at this same block hash, and it is
 * what makes an absent answer mean something. Every leaf below it was appended
 * by one of `pallet-shielded`'s three writers, each of which writes its keys
 * in the same call:
 *
 * - `shield` writes `Leaves`, `Ciphertexts` and `LeafBlocks`;
 * - a settled slot writes `Leaves`, `Ciphertexts` and `LeafBlocks` for each of
 *   its two outputs;
 * - the coinbase writes `Leaves`, `LeafBlocks` and `CoinbaseValues`, and
 *   `Ciphertexts` only where the author encrypted a payload, which under v1
 *   never happens.
 *
 * Nothing removes any of them, so below the count there is a commitment and a
 * block at every index and a ciphertext at every index that is not a coinbase.
 * An absent one there is a node withholding an answer at a block it has just
 * told this wallet the tree is that long. Read as "nothing here" it is silent
 * and permanent, because the scan steps over the leaf and the caller then
 * writes a watermark past it, so a payment on that leaf is never looked at
 * again without a rescan. Each is refused by name instead, and the pass with
 * it.
 *
 * The ciphertext rule here is the coarse half of a rule that is finished one
 * layer up. Presence of `CoinbaseValues` does **not** decide that a leaf is a
 * coinbase: presence is the node's to write, and eight invented bytes beside
 * an incoming transfer used to route it onto the coinbase rebuild and hide the
 * payment. What decides is where the block headers put the leaf, which
 * `wallet/sync.ts` works out from the header chain and the root each block
 * published. So this refuses only the shape that is wrong whatever kind the
 * leaf turns out to be, a leaf carrying neither key, and the typed rules
 * refuse the rest by name.
 *
 * `Chain::leaves` and `Wallet::sync_with` in the command-line wallet refuse
 * the identical set.
 */
export async function fetchLeaves(
  context: ChainContext,
  from: number,
  to: number,
  at: string,
  leafCount: number,
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
      const rawCommitment = values.get(row.keys[0]);
      const rawCiphertext = values.get(row.keys[1]);
      const block = values.get(row.keys[2]);
      const coinbase = values.get(row.keys[3]);
      const belowCount = row.index < leafCount;
      if (belowCount && rawCommitment === undefined) {
        throw withheld('ZkTree::Leaves', row.index, leafCount, at);
      }
      if (belowCount && block === undefined) {
        throw withheld('Shielded::LeafBlocks', row.index, leafCount, at);
      }
      if (belowCount && rawCiphertext === undefined && coinbase === undefined) {
        throw withheld('Shielded::Ciphertexts', row.index, leafCount, at);
      }
      if (belowCount && rawCommitment?.toLowerCase() === PADDING_SENTINEL) {
        throw paddingSentinel(row.index, leafCount, at);
      }
      const height = decodeInteger(block, `Shielded::LeafBlocks(${row.index})`, 4);
      out.push({
        index: row.index,
        commitment: decodeCommitment(rawCommitment, row.index),
        ciphertext: decodeBytes(rawCiphertext, `Shielded::Ciphertexts(${row.index})`),
        blockNumber: height === null ? null : Number(height),
        coinbaseQuanta: decodeInteger(coinbase, `Shielded::CoinbaseValues(${row.index})`, 8),
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
