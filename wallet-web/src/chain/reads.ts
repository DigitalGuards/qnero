/**
 * Everything a wallet reads off the chain, and nothing it should not.
 *
 * Two rules shape every function here, and they are rules about the requests
 * rather than about the answers:
 *
 * 1. **A sync never selects an unpublished nullifier from private notes for a request.** `UsedNullifiers` is
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

import { hexByteLength, hexToBytes, leBytesToBigInt, normaliseHash, readCompact } from '../lib/hex';
import { birthdayEpochOf } from '../wallet/model';
import { parseRawHeader, type RawChainHeader } from './anchor';
import { storage, type ChainContext } from './api';
import { authenticatedValues, authenticatedPrefix, authenticatedHeaderHash } from './authenticated';

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

async function queryAt(
  context: ChainContext,
  keys: string[],
  at: string,
): Promise<Map<string, string>> {
  const values = await authenticatedValues(context, keys, at);
  if (values.length !== keys.length) throw new Error('state verifier returned an unexpected value count');
  const out = new Map<string, string>();
  values.forEach((value, index) => {
    const key = keys[index];
    if (key === undefined) throw new Error('state verifier returned an unexpected value count');
    if (value !== null) out.set(key, value);
  });
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
 * How many block numbers one `chain_getBlockHash` carries.
 *
 * Substrate's `chain_getBlockHash` takes a list of numbers and answers a list
 * of hashes, which is what turns the hash half of a header walk from one round
 * trip per block into one per page. 256 is the width the wide leaf page
 * already uses (`LEAF_HASH_BATCH`): the answer is 32 bytes a number, so a page
 * is about 16 KiB of hex.
 */
export const HASH_PAGE = 256;

/**
 * How many `chain_getHeader` requests are outstanding at once.
 *
 * The provider multiplexes JSON-RPC ids over the one socket, so this is a
 * count of ids in flight rather than of connections: the wallet opens no
 * second socket and contacts nothing else. What it buys is the round trip.
 * A header walk is latency bound, not bandwidth bound, and against a node
 * behind a CDN one sequential walk pays the wide-area round trip once per
 * block: a year of 120 s blocks is 262 000 of them.
 *
 * 32 rather than the whole chunk. Every answer is resident until the walk
 * verifies the range, and a node answers a request it was sent whether or not
 * the wallet is ready for it.
 */
export const HEADERS_IN_FLIGHT = 32;

/**
 * The longest span one call walks, which is the caller's chunk.
 *
 * `wallet/sync.ts` climbs a longer range in chunks of `HEADER_WALK_LIMIT`,
 * the same number, and the two are held equal by a test. The bound is here as
 * well because this function now holds the chunk: `top.number` is a height the
 * node answers with, and a walk that allocated one hash and one header per
 * unit of it let one answer decide how much the page allocates before a leaf
 * was read.
 */
export const HEADER_SPAN_LIMIT = 1024;

/**
 * Whether a node answers `chain_getBlockHash` over a list of numbers, as far
 * as this page knows, keyed by the context the question was asked through.
 *
 * Asked once, by asking. A walk pages its heights, so a node that will not
 * answer a list would otherwise be probed once per page of every chunk of
 * every sync, each probe a wasted round trip; the command-line wallet keeps
 * the same memo for batch arrays and says so in `rpc.rs`.
 *
 * `refused` is only ever what a node **answered**: a hash where a list was
 * asked for, a list of the wrong length, or a JSON-RPC error. A request that
 * did not complete leaves the question open, because a dropped socket is not a
 * fact about this node's parameter shapes.
 */
const hashLists = new WeakMap<ChainContext, 'taken' | 'refused'>();

/** What one attempt at the list form came back as. */
type ListAnswer =
  | { kind: 'list'; hashes: (string | null)[] }
  | { kind: 'refused' }
  | { kind: 'failed' };

/**
 * Whether a rejection is the node answering rather than the request failing.
 *
 * A JSON-RPC error carries a numeric `code`, and polkadot-js spells it into
 * the message as well. An implementation whose `chain_getBlockHash` parameter
 * is one number rather than Substrate's list-or-value fails to deserialize an
 * array and answers `-32602 Invalid params`, which is this shape: the node
 * said no, and what it said no to is the parameter.
 */
function answeredNo(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }
  if (typeof (error as { code?: unknown }).code === 'number') {
    return true;
  }
  const message = (error as { message?: unknown }).message;
  return typeof message === 'string' && /^-?\d+:/.test(message.trim());
}

/** One attempt at the list form, with nothing recorded and nothing thrown. */
async function tryHashList(
  context: ChainContext,
  numbers: readonly number[],
): Promise<ListAnswer> {
  let listed: unknown;
  try {
    listed = await context.send<unknown>('chain_getBlockHash', [[...numbers]]);
  } catch (error) {
    return answeredNo(error) ? { kind: 'refused' } : { kind: 'failed' };
  }
  if (!Array.isArray(listed) || listed.length !== numbers.length) {
    return { kind: 'refused' };
  }
  return { kind: 'list', hashes: listed.map((hash) => (typeof hash === 'string' ? hash : null)) };
}

/**
 * The canonical hashes at a list of heights, in the order asked for.
 *
 * One request for the whole list where the node takes one, and one request per
 * height where it does not. A node that answers a list with anything but a
 * list of the right length is an older or a different implementation, not a
 * liar, and so is one that refuses the parameter outright with a JSON-RPC
 * error: nothing is decided from these hashes on their own. They are
 * addresses, and what makes the range a chain is the parent links checked over
 * the headers they fetch. Which of the two answers came back is remembered, so
 * the probe is paid once per command rather than once per page of heights;
 * see `hashLists`.
 *
 * A request that did not complete is neither answer. The per-height loop is
 * run anyway and its first call fails with its own message, which names the
 * endpoint rather than the parameter.
 *
 * `null` is an ordinary answer for a height this node has no block at.
 */
export async function blockHashesAt(
  context: ChainContext,
  numbers: readonly number[],
): Promise<(string | null)[]> {
  if (numbers.length === 0) {
    return [];
  }
  if (hashLists.get(context) !== 'refused') {
    const answer = await tryHashList(context, numbers);
    if (answer.kind === 'list') {
      hashLists.set(context, 'taken');
      return answer.hashes;
    }
    if (answer.kind === 'refused') {
      hashLists.set(context, 'refused');
    }
  }
  const out: (string | null)[] = [];
  for (const number of numbers) {
    out.push(await blockHashAt(context, number));
  }
  return out;
}

/**
 * Every header from `anchor` up to `top`, verified as one chain and handed to
 * a callback in ascending order.
 *
 * The walk used to descend by `parentHash`, one `chain_getHeader` at a time,
 * each fetched by the hash its child named. That is one round trip per block
 * with nothing else in flight, and against a node behind a CDN the round trip
 * is the whole cost: at the public chain's 120 s target a year of history is
 * 262 000 of them in series, which is the "39 of 250 block headers" a person
 * watches crawl.
 *
 * So the two halves are separated and both are pipelined. The heights are
 * turned into hashes with `chain_getBlockHash` over a list of numbers, paged
 * at [`HASH_PAGE`], and the headers are then fetched by hash with
 * [`HEADERS_IN_FLIGHT`] requests outstanding on the one socket.
 *
 * **Exactly what the sequential walk verified is verified here, locally, and
 * nothing about which values are trusted changes.** The hashes are the node's
 * claim and decide nothing on their own:
 *
 * - every header's own `number` is the height it was asked for, or the walk is
 *   refused;
 * - every header names as its `parentHash` the hash this node answered for the
 *   height below it, or the walk is refused. That is the parent link the
 *   descending walk followed, checked rather than followed, so a hash answered
 *   for a number the header chain does not carry is a lie and is refused;
 * - and the caller rehashes every header from its own preimage and compares
 *   against the hash its child names, `anchor`'s against a hash it already
 *   trusts. `wallet/sync.ts` does that, unchanged.
 *
 * Composed, those are the same equalities the descending walk produced: the
 * recomputed hash of each header is the hash the header above it names as its
 * parent, down to a hash the wallet already trusted. No proof of work is
 * verified here and none was before; `docs/WALLET.md` carries that bound.
 *
 * The headers arrive **ascending**, `anchor` first, which is the order they
 * are verified in and the order the caller folds leaves in. They are emitted
 * only after the whole range checks out, so a refusal hands the caller
 * nothing.
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
  const span = top.number - anchor;
  if (span > HEADER_SPAN_LIMIT) {
    throw new Error(
      `a header walk was asked for blocks ${anchor} to ${top.number}, which is ${span} blocks ` +
        `where one walk carries at most ${HEADER_SPAN_LIMIT}. The head is a number this node ` +
        'answers with and this walk holds one header per unit of it, so the range is climbed in ' +
        'chunks rather than in one allocation. Nothing has been changed.',
    );
  }

  // The hashes the headers are fetched by. The top's is the caller's, which is
  // the head itself or a hash the caller is about to prove by walking down to
  // one it already trusts, so it is never asked for again.
  const hashes: string[] = new Array<string>(span + 1);
  hashes[span] = top.hash;
  for (let start = anchor; start < top.number; start += HASH_PAGE) {
    const end = Math.min(start + HASH_PAGE, top.number);
    const numbers: number[] = [];
    for (let number = start; number < end; number += 1) {
      numbers.push(number);
    }
    const page = await blockHashesAt(context, numbers);
    for (let index = 0; index < numbers.length; index += 1) {
      const hash = page[index];
      const number = numbers[index] ?? 0;
      if (typeof hash !== 'string') {
        throw new Error(
          `this node has no block at height ${number}, which is inside the range ${anchor} to ` +
            `${top.number} it reports a head above. A header walk cannot skip a height: the ` +
            'chain it authenticates is the one with no gaps in it. Nothing has been changed.',
        );
      }
      hashes[number - anchor] = hash;
    }
  }

  // The headers, with many requests outstanding at once. Each worker takes the
  // next height nobody has claimed, so the answers land out of order and the
  // range is assembled by index rather than by arrival.
  const headers: (RawChainHeader | undefined)[] = new Array<RawChainHeader | undefined>(span + 1);
  let next = 0;
  let done = 0;
  // How many workers have refused. A count on a field rather than a boolean
  // in a `let`, because every worker writes this and reads it across an
  // `await`, and what the compiler tracks is what *this* worker last left it
  // as: a boolean read that way is narrowed to a constant and the check is
  // compiled out.
  const walk = { refusals: 0 };
  const worker = async (): Promise<void> => {
    for (;;) {
      if (walk.refusals > 0) {
        return;
      }
      const slot = next;
      next += 1;
      if (slot > span) {
        return;
      }
      try {
        headers[slot] = parseRawHeader(
          await context.send<unknown>('chain_getHeader', [hashes[slot]]),
        );
      } catch (error) {
        // One refusal ends the walk. The requests already in flight are
        // answered and dropped: a node answers what it was sent whatever this
        // page does with it.
        walk.refusals += 1;
        throw error;
      }
      if (walk.refusals > 0) {
        // Another worker refused while this one was awaiting its answer. The
        // walk is over and its caller has the error already, so this arrival
        // is not reported: `runSync` turns `onProgress` into a rendered line,
        // and without this the page painted up to 31 header-progress lines
        // over the banner saying the sync had been refused.
        return;
      }
      done += 1;
      onProgress?.(done);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(HEADERS_IN_FLIGHT, span + 1) }, () => worker()),
  );

  for (let offset = 0; offset <= span; offset += 1) {
    const header = headers[offset];
    const number = anchor + offset;
    if (header === undefined) {
      throw new Error(
        `this node answered no header for block ${number}. Nothing has been changed.`,
      );
    }
    const claimed = Number(BigInt(header.number));
    if (claimed !== number) {
      throw new Error(
        `this node answered a header numbered ${claimed} for the hash it gave as block ` +
          `${number}. A header read at the hash its child names is the only thing tying a block ` +
          'to a height, so the walk is refused rather than dating leaves by it. Nothing has been ' +
          'changed.',
      );
    }
  }
  for (let offset = 0; offset < span; offset += 1) {
    const child = headers[offset + 1];
    const wanted = normaliseHash(hashes[offset] ?? '');
    if (child === undefined || normaliseHash(child.parentHash) !== wanted) {
      throw new Error(
        `this node gave ${wanted} as the hash of block ${anchor + offset} and the header it ` +
          `served for block ${anchor + offset + 1} names ${normaliseHash(child?.parentHash ?? '')} as ` +
          'its parent. The hashes are only addresses and the parent links are what make the ' +
          'range a chain, so a hash answered for a number the header chain does not carry is ' +
          'refused. Nothing has been changed.',
      );
    }
  }
  for (let offset = 0; offset <= span; offset += 1) {
    onHeader(headers[offset] as RawChainHeader);
  }
}

/**
 * Where a wallet being created or restored starts reading, read from the node.
 *
 * `height` is the operator's restore height, or the node's own head for a
 * wallet being created now. It is rounded **down** to a multiple of
 * `BIRTHDAY_EPOCH` before anything is asked for, so what the store holds and
 * what every later node is told is a coarse public epoch rather than the
 * moment this wallet was made, and so that a height a little too high still
 * starts below the first note.
 *
 * Three public reads: the head, the hash of the epoch block, and the leaf
 * count that block's state carried. None of them names this wallet.
 *
 * The leaf count becomes the watermark, and nothing here checks it. The first
 * sync that has leaves to scan folds the leaves under it and compares against
 * the `zkTreeRoot` the epoch block's own header published, which refuses a
 * count recorded too **high** and does not pin one that is too low; a pass
 * with nothing above the watermark to scan is left with the roots the chunk's
 * own headers carry. `wallet/model.ts` and `docs/WALLET.md` carry what that
 * settles and what it does not, and both refusals a too-high count trips name
 * this birthday and the rescan that drops it.
 */
export async function fetchBirthday(
  context: ChainContext,
  height: number | null,
  maxTreeDepth: number,
): Promise<{ blockNumber: number; blockHash: string; nextLeaf: number }> {
  const head = await fetchHead(context);
  const wanted = height ?? head.number;
  if (wanted > head.number) {
    throw new Error(
      `this node's head is block ${head.number} and the height given is ${wanted}, which names ` +
        "a block nobody has yet. A birthday above the chain's own head would put this wallet's " +
        'watermark past every leaf there is.',
    );
  }
  const blockNumber = birthdayEpochOf(Math.max(wanted, 0));
  const blockHash = await blockHashAt(context, blockNumber);
  if (blockHash === null) {
    throw new Error(`this node has no block at height ${blockNumber}`);
  }
  const shape = await fetchTreeShape(context, blockHash, maxTreeDepth);
  // Normalised, because this becomes a checkpoint and every other checkpoint
  // is written that way: one spelling in the store is one spelling the fork
  // walk compares.
  return { blockNumber, blockHash: normaliseHash(blockHash), nextLeaf: shape.leafCount };
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

/**
 * The pallet's `empty_hash()`: 32 zero bytes, in the one spelling this
 * compares.
 *
 * No `0x`, lower case, because that is what [`normaliseHash`] produces and a
 * node answers this value in whichever spelling it likes. The comparison used
 * to be against the prefixed form, so a node that answered the pad as 64 zero
 * hex digits with no prefix walked past the refusal below: `hexToBytes` and
 * `hexByteLength` both strip the prefix, so the unprefixed pad decoded to the
 * same 32 zero bytes and was written into the rebuild as a leaf.
 */
const PADDING_SENTINEL = '00'.repeat(32);

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
        if (index < leafCount && normaliseHash(value) === PADDING_SENTINEL) {
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
  /** Set for exactly the leaves a block's coinbase minted, as a count of pool steps. */
  coinbaseSteps: bigint | null;
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
const archiveAncestors = new WeakMap<ChainContext, { tip: string; oldest: number; hashes: Map<number, string> }>();

/** Link a historical ciphertext proof to this selected scan head. */
export async function authenticatedAncestor(context: ChainContext, at: string, wanted: number): Promise<string> {
  let cache = archiveAncestors.get(context);
  if (cache === undefined || normaliseHash(cache.tip) !== normaliseHash(at)) {
    const head = parseRawHeader(await headerAt(context, at));
    if (normaliseHash(await authenticatedHeaderHash(context, head)) !== normaliseHash(at)) {
      throw new Error('archive header does not hash to the selected block');
    }
    cache = { tip: at, oldest: Number(BigInt(head.number)), hashes: new Map([[Number(BigInt(head.number)), at]]) };
    archiveAncestors.set(context, cache);
  }
  const known = cache.hashes.get(wanted);
  if (known !== undefined) return known;
  let number = cache.oldest;
  let hash = cache.hashes.get(number);
  if (hash === undefined) throw new Error('archive ancestry cache has no selected head');
  if (wanted > number) throw new Error('ciphertext creation height is outside the selected header chain');
  while (number > wanted) {
    const lower = Math.max(wanted, number - HEADER_SPAN_LIMIT);
    const headers: RawChainHeader[] = [];
    await fetchHeaderRange(context, lower, { number, hash }, (header) => headers.push(header));
    const hashes = await Promise.all(headers.map((header) => authenticatedHeaderHash(context, header)));
    const topHash = hashes.at(-1);
    if (topHash === undefined || normaliseHash(topHash) !== normaliseHash(hash)) {
      throw new Error('archive header range does not reach the selected chain');
    }
    for (let index = 1; index < headers.length; index += 1) {
      const header = headers[index];
      const parent = hashes[index - 1];
      if (header === undefined || parent === undefined || normaliseHash(header.parentHash) !== normaliseHash(parent)) {
        throw new Error('archive header range contains an unauthenticated ancestor');
      }
    }
    for (let index = 0; index < hashes.length; index += 1) {
      const value = hashes[index];
      if (value === undefined) throw new Error('archive header range is incomplete');
      cache.hashes.set(lower + index, value.startsWith('0x') ? value : `0x${value}`);
    }
    if (cache.hashes.size > 1_000_000) throw new Error('archive ancestry exceeds the supported scan size');
    number = lower;
    cache.oldest = lower;
    hash = cache.hashes.get(number);
    if (hash === undefined) throw new Error('archive header range has no ancestor');
  }
  return hash;
}

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
    const archived = new Map<number, typeof rows>();
    for (const row of rows) {
      if (row.index < leafCount && !values.has(row.keys[0])) throw withheld('ZkTree::Leaves', row.index, leafCount, at);
      if (row.index < leafCount && !values.has(row.keys[1]) && !values.has(row.keys[3])) {
        const block = decodeInteger(values.get(row.keys[2]), `Shielded::LeafBlocks(${row.index})`, 4);
        if (block === null) throw withheld('Shielded::LeafBlocks', row.index, leafCount, at);
        const group = archived.get(Number(block)) ?? [];
        group.push(row);
        archived.set(Number(block), group);
      }
    }
    for (const [block, group] of [...archived].sort(([a], [b]) => a - b)) {
      const createdAt = await authenticatedAncestor(context, at, block);
      const keys = group.map((row) => row.keys[1]);
      let historical: (string | null)[];
      try {
        historical = await authenticatedValues(context, keys, createdAt);
      } catch (error) {
        throw new Error(`ciphertext archive unavailable at creation block ${block}; scan progress is unchanged: ${(error as Error).message}`);
      }
      historical.forEach((value, index) => {
        if (value === null) throw new Error(`Shielded::Ciphertexts archive has no authenticated payload at creation block ${block}; scan progress is unchanged`);
        const key = keys[index];
        if (key === undefined) throw new Error('archive proof returned an unexpected value count');
        values.set(key, value);
      });
    }
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
      if (belowCount && rawCommitment !== undefined && normaliseHash(rawCommitment) === PADDING_SENTINEL) {
        throw paddingSentinel(row.index, leafCount, at);
      }
      const height = decodeInteger(block, `Shielded::LeafBlocks(${row.index})`, 4);
      out.push({
        index: row.index,
        commitment: decodeCommitment(rawCommitment, row.index),
        ciphertext: decodeBytes(rawCiphertext, `Shielded::Ciphertexts(${row.index})`),
        blockNumber: height === null ? null : Number(height),
        coinbaseSteps: decodeInteger(coinbase, `Shielded::CoinbaseValues(${row.index})`, 8),
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
 * raw 32-byte nullifier is the tail of every proven key. The local trie walk
 * also authenticates the unit value and proves the set is complete.
 *
 * A partial set would report settled notes as unspent. Reaching a proof or
 * entry limit, or cancellation through `stillWanted`, therefore refuses the
 * complete pass without returning a partial result.
 */
export async function fetchUsedNullifiers(
  context: ChainContext,
  at: string,
  stillWanted?: () => boolean,
  onProgress?: (seen: number) => void,
): Promise<Set<string>> {
  const entry = storage(context, 'shielded', 'usedNullifiers');
  const prefix = entry.keyPrefix();
  const entries = await authenticatedPrefix(context, prefix, at, KEY_PAGE, stillWanted, onProgress);
  const out = new Set<string>();
  for (const [key, value] of entries) {
    const raw = key.slice(prefix.length + 32);
    if (raw.length !== 64 || value !== '0x' || entry.key(`0x${raw}`) !== key) {
      throw new Error('a proven UsedNullifiers entry has an unexpected encoding');
    }
    out.add(raw.toLowerCase());
  }
  return out;
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
