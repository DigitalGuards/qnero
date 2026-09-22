/**
 * What a node answers with, and what this wallet does about an answer it
 * cannot read.
 *
 * Two failures in one file, and they share a shape: both used to end in a
 * wallet that carried on and said nothing.
 *
 * A storage value of the wrong width is what a runtime change looks like from
 * here. `REQUIRED_STORAGE` compares hashers and cannot see a changed value
 * type, so a `Leaves` that stopped being `[u8; 32]` passed every gate, every
 * ciphertext then failed to decrypt, and the pass completed: "synced through
 * block N" over a zero balance, with the watermark written up past every leaf
 * it had misread. The CLI decodes each field by type and refuses by name, and
 * so does this now.
 *
 * A height a node has no block for is the other. `waitForInclusion` skipped
 * it and moved its cursor past it, so a reorg in progress, or a replica that
 * had not filled in behind its head, meant the block carrying this wallet's
 * settlement was never looked at: a landed payment reported as a timeout, the
 * inputs left unlatched, and the next send selecting two notes whose
 * nullifiers the chain had already settled.
 */

import { describe, expect, it } from 'vitest';

import type { ChainContext } from '../src/chain/api';
import { storagePrefix, indexKey } from './fixtures/storage-key';
import { bindFixtureProofs, fixtureProof, fixtureHeader } from './fixtures/state-proof';
import {
  fetchHeaderRange,
  fetchLeafHashes,
  fetchLeaves,
  fetchTreeShape,
  fetchTreeTotals,
  HEADER_SPAN_LIMIT,
  HEADERS_IN_FLIGHT,
} from '../src/chain/reads';
import { HEADER_WALK_LIMIT } from '../src/wallet/sync';
import { waitForInclusion } from '../src/chain/submit';

const AT = `0x${'aa'.repeat(32)}`;

/** What the module reports, and what bounds a leaf count here. */
const MAX_TREE_DEPTH = 20;

/** A storage entry whose keys this test can read back. See `privacy.test.ts`. */
function entry(prefix: string): unknown {
  return {
    key: (arg?: number | string): string =>
      arg === undefined ? prefix : `${prefix}${String(arg).replace(/^0x/, '')}`,
    keyPrefix: (): string => prefix,
  };
}

const KEYS = {
  leaves: storagePrefix('ZkTree', 'Leaves'),
  leafBlocks: storagePrefix('Shielded', 'LeafBlocks'),
  coinbaseValues: storagePrefix('Shielded', 'CoinbaseValues'),
  leafCount: storagePrefix('ZkTree', 'LeafCount'),
  depth: storagePrefix('ZkTree', 'Depth'),
  entryCount: storagePrefix('Shielded', 'EntryCount'),
} as const;

/** A node that answers exactly the values this test hands it. */
function nodeWith(values: Map<string, string>): ChainContext {
  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'chain_getHeader') return Promise.resolve(fixtureHeader(9) as T);
    if (method !== 'state_getReadProof') {
      throw new Error(`this fixture answers no ${method}`);
    }
    const keys = params[0] as string[];
    return Promise.resolve(fixtureProof(String(params[1]),
      keys.map((key) => [key, values.get(key) ?? null])) as T);
  };
  return bindFixtureProofs({
    send,
    api: {
      query: {
        zkTree: {
          leaves: entry(KEYS.leaves),
          leafCount: entry(KEYS.leafCount),
          depth: entry(KEYS.depth),
        },
        shielded: {
          leafBlocks: entry(KEYS.leafBlocks),
          coinbaseValues: entry(KEYS.coinbaseValues),
          entryCount: entry(KEYS.entryCount),
        },
      },
    },
  } as unknown as ChainContext, () => AT);
}

/** The same node, with the key lists of every request it was handed. */
function recordingNode(values: Map<string, string>, asked: string[][]): ChainContext {
  const inner = nodeWith(values);
  return bindFixtureProofs({
    ...inner,
    send: <T,>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'state_getReadProof') {
        asked.push(params[0] as string[]);
      }
      return inner.send<T>(method, params);
    },
  }, () => AT);
}

/**
 * Every key of one leaf row, as a chain carries it.
 *
 * `pallet-shielded` writes a leaf's keys in the call that appends it: a shield
 * and a settled output write `Leaves` and `LeafBlocks`, a coinbase writes
 * those two and `CoinbaseValues`, and nothing removes any of them. So a
 * fixture that fills one key and leaves the rest is describing a chain no node
 * can serve, and a test written over one is asserting on a refusal that a real
 * answer would have reached first. Every row here is complete, and a test that
 * is about a withheld key takes exactly that key away.
 */
function leafRow(
  values: Map<string, string>,
  index: number,
  row: {
    commitment?: string | null;
    leafBlock?: string | null;
    coinbaseValue?: string | null;
  } = {},
): Map<string, string> {
  const set = (key: string, value: string | null | undefined, fallback: string | null): void => {
    const chosen = value === undefined ? fallback : value;
    if (chosen !== null) {
      values.set(key, chosen);
    }
  };
  set(`${KEYS.leaves}${indexKey(index)}`, row.commitment, `0x${'cd'.repeat(32)}`);
  set(`${KEYS.leafBlocks}${indexKey(index)}`, row.leafBlock, '0x09000000');
  set(`${KEYS.coinbaseValues}${indexKey(index)}`, row.coinbaseValue, null);
  return values;
}

describe('a leaf row', () => {
  it('reads back when every field is the width the runtime declares', async () => {
    const values = leafRow(new Map<string, string>(), 0, {
      coinbaseValue: '0x0a00000000000000',
    });
    const [row] = await fetchLeaves(nodeWith(values), 0, 1, AT, 1);
    expect(row?.commitment).toBe(`0x${'cd'.repeat(32)}`);
    expect(row?.blockNumber).toBe(9);
    expect(row?.coinbaseSteps).toBe(10n);
  });

  it('refuses a leaf that is not 32 bytes, and names it', async () => {
    const values = leafRow(new Map<string, string>(), 3, {
      commitment: `0x${'cd'.repeat(31)}`,
    });
    await expect(fetchLeaves(nodeWith(values), 3, 4, AT, 4)).rejects.toThrow(
      /ZkTree::Leaves\(3\) is 31 bytes, expected 32/,
    );
  });

  it('refuses a block height that is not a u32', async () => {
    const values = leafRow(new Map<string, string>(), 0, { leafBlock: '0x0900000000000000' });
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      /Shielded::LeafBlocks\(0\) is 8 bytes and this build decodes it as 4/,
    );
  });

  it('refuses a coinbase value that is not a u64', async () => {
    const values = leafRow(new Map<string, string>(), 0, { coinbaseValue: '0x0a000000' });
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      /Shielded::CoinbaseValues\(0\) is 4 bytes and this build decodes it as 8/,
    );
  });
});

/**
 * The keys a node can withhold below the count it reports, one test each.
 *
 * The chain has no gaps under its own count: `pallet-zk-tree` appends a leaf
 * and raises `LeafCount` in one call, `pallet-shielded` writes the leaf's
 * other keys in that same call, and nothing removes any of them. So an absent
 * answer below the count read at this same block hash is an answer withheld,
 * and reading it as "nothing here" is silent and permanent in every case: the
 * scan steps over the leaf, the pass writes a watermark above it, and a
 * payment on that leaf is never read again without a rescan. The refusal used
 * to cover the commitment alone, which left the key beside it as a second way
 * to hide the same payment.
 */
describe('a key the node withholds below its own leaf count', () => {
  it('refuses an absent commitment, and names the leaf, the count and the block', async () => {
    const values = leafRow(leafRow(new Map<string, string>(), 0), 2);
    leafRow(values, 1, { commitment: null });
    await expect(fetchLeaves(nodeWith(values), 0, 3, AT, 3)).rejects.toThrow(
      new RegExp(`no ZkTree::Leaves\\(1\\) at block ${AT}, where it reports 3 leaves`),
    );
  });

  it("refuses the tree's own pad answered as a leaf below the count", async () => {
    // Not a withheld answer: a present one the chain cannot have written.
    // `insert_commitment` refuses an append of the all-zero digest by name,
    // and the tree reads it as an unfilled slot at every level, so folding one
    // moves no root and a run of them inflates the leaf count under headers
    // that are honest. The scan would commit a watermark above indices no
    // block has filled.
    const values = leafRow(leafRow(new Map<string, string>(), 0), 2);
    leafRow(values, 1, { commitment: `0x${'00'.repeat(32)}` });
    await expect(fetchLeaves(nodeWith(values), 0, 3, AT, 3)).rejects.toThrow(
      new RegExp(`ZkTree::Leaves\\(1\\) with the all-zero digest at block ${AT}`),
    );
  });

  it("refuses the pad spelled without the 0x prefix", async () => {
    // The spelling is the node's to pick. `hexToBytes` and `hexByteLength`
    // both strip the prefix, so an unprefixed pad decoded to the same 32 zero
    // bytes and every check below this one passed it: the comparison was
    // against the prefixed form alone, and in the spend path nothing else
    // catches the pad.
    const values = leafRow(leafRow(new Map<string, string>(), 0), 2);
    leafRow(values, 1, { commitment: '00'.repeat(32) });
    await expect(fetchLeaves(nodeWith(values), 0, 3, AT, 3)).rejects.toThrow(
      new RegExp(`ZkTree::Leaves\\(1\\) with the all-zero digest at block ${AT}`),
    );
  });

  it('refuses an absent block height', async () => {
    // `LeafBlocks` is what a coinbase note's `rho` and `r` are derived from
    // and what the shield-origin rule is checked against, so a leaf without it
    // is a coinbase stepped over and a note dated by nothing.
    const values = leafRow(new Map<string, string>(), 0, { leafBlock: null });
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      new RegExp(`no Shielded::LeafBlocks\\(0\\) at block ${AT}`),
    );
  });

  it('reads a coinbase leaf, which owes no payload at all', async () => {
    // Nothing is owed per leaf beyond the commitment and the block. The note
    // ciphertexts are in the block bodies, the body roots as a whole, and a
    // coinbase carries none of its own: the inherent refuses a payload by
    // name.
    const values = leafRow(new Map<string, string>(), 0, {
      coinbaseValue: '0x0a00000000000000',
    });
    const [row] = await fetchLeaves(nodeWith(values), 0, 1, AT, 1);
    expect(row?.coinbaseSteps).toBe(10n);
  });

  it('reads a leaf above the count as absent, which is what the range past the end is', async () => {
    // The same answers above the count are ordinary: a window may run to the
    // end of a range the count does not reach, and nothing there is withheld.
    const values = leafRow(new Map<string, string>(), 0);
    const rows = await fetchLeaves(nodeWith(values), 0, 2, AT, 1);
    expect(rows[1]?.commitment).toBeNull();
    expect(rows[1]?.blockNumber).toBeNull();
  });
});

describe('the chain-wide totals a pass reads once', () => {
  it('reads the three of them in one request', async () => {
    const values = new Map<string, string>([
      [KEYS.leafCount, '0x0800000000000000'],
      [KEYS.depth, '0x03'],
      [KEYS.entryCount, '0x0200000000000000'],
    ]);
    const asked: string[][] = [];
    const totals = await fetchTreeTotals(recordingNode(values, asked), AT, MAX_TREE_DEPTH);
    expect(totals).toEqual({ leafCount: 8, depth: 3, entryCount: 2n });
    // One call carrying all three keys. The counter used to be fetched again
    // through an accessor of its own, so every pass that found a leaf asked
    // this node the identical question twice.
    expect(asked).toEqual([[KEYS.leafCount, KEYS.depth, KEYS.entryCount]]);
  });

  it('refuses a shield counter that is not a u64, which is the one number it turns into work', async () => {
    // `EntryCount` decides how many Poseidon2 hashes the origin walk runs, on
    // the thread that holds the seed. Read at whatever width the bytes carry,
    // 32 bytes of 0xff is 2^256 - 1 and the worker spins until the tab is
    // reloaded, with the control that would stop it disabled while the sync
    // it belongs to is running.
    const values = new Map<string, string>([
      [KEYS.leafCount, '0x0800000000000000'],
      [KEYS.depth, '0x03'],
      [KEYS.entryCount, `0x${'ff'.repeat(32)}`],
    ]);
    await expect(fetchTreeTotals(nodeWith(values), AT, MAX_TREE_DEPTH)).rejects.toThrow(
      /Shielded::EntryCount is 32 bytes and this build decodes it as 8/,
    );
  });
});

describe('the two numbers that decide how long a scan runs', () => {
  it('refuses a leaf count that is not a u64, which used to be read at any width', async () => {
    // `LeafCount` decides how many leaves the scan window walks. Read at
    // whatever width the bytes carried, 32 bytes of 0xff is a scan of
    // 2^256 - 1 leaves out of one storage answer.
    const values = new Map<string, string>([
      [KEYS.leafCount, `0x${'ff'.repeat(32)}`],
      [KEYS.depth, '0x03'],
      [KEYS.entryCount, '0x0200000000000000'],
    ]);
    await expect(fetchTreeTotals(nodeWith(values), AT, MAX_TREE_DEPTH)).rejects.toThrow(
      /ZkTree::LeafCount is 32 bytes and this build decodes it as 8/,
    );
  });

  it('refuses a depth that is not a u8, where the command-line wallet names the item', async () => {
    // `u8::decode` is what `Chain::tree_depth_at` runs. A two-byte 0x0004 read
    // as a little-endian number is 1024 where the chain says 4, and a rebuild
    // at the wrong depth reaches a root the anchor header does not carry.
    const values = new Map<string, string>([
      [KEYS.leafCount, '0x0800000000000000'],
      [KEYS.depth, '0x0400'],
      [KEYS.entryCount, '0x0200000000000000'],
    ]);
    await expect(fetchTreeTotals(nodeWith(values), AT, MAX_TREE_DEPTH)).rejects.toThrow(
      /ZkTree::Depth is 2 bytes and this build decodes it as 1/,
    );
  });

  it('refuses a leaf count above what a tree this wallet can prove over holds', async () => {
    // A 4-ary tree at the circuit's maximum depth holds 4 ** depth leaves.
    // Above that is not a tree this chain carries, and it is the number the
    // scan turns into windows of reads.
    const values = new Map<string, string>([
      [KEYS.leafCount, `0x${'ff'.repeat(8)}`],
      [KEYS.depth, '0x03'],
      [KEYS.entryCount, '0x0200000000000000'],
    ]);
    await expect(fetchTreeTotals(nodeWith(values), AT, MAX_TREE_DEPTH)).rejects.toThrow(
      /ZkTree::LeafCount is 18446744073709551615 at this block/,
    );
  });

  it('reads the shape alone at the same widths', async () => {
    const values = new Map<string, string>([
      [KEYS.leafCount, '0x0600000000000000'],
      [KEYS.depth, '0x03'],
    ]);
    expect(await fetchTreeShape(nodeWith(values), AT, MAX_TREE_DEPTH)).toEqual({
      leafCount: 6,
      depth: 3,
    });
  });
});

describe('the leaf range a tree is rebuilt from', () => {
  it('refuses a value that is not 32 bytes rather than writing over the next slot', async () => {
    // A longer value overwrote the head of the next leaf's slot and a shorter
    // one left the tail of this one as zeros, which is a valid canonical
    // digest. Either way the rebuilt root is wrong and the spend is refused
    // with "sync again: the node may have appended a leaf", which fixes
    // nothing and names nothing.
    const values = new Map<string, string>([
      [`${KEYS.leaves}${indexKey(0)}`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leaves}${indexKey(1)}`, `0x${'cd'.repeat(33)}`],
    ]);
    await expect(fetchLeafHashes(nodeWith(values), 0, 2, AT, 2)).rejects.toThrow(
      /ZkTree::Leaves\(1\) is 33 bytes, expected 32/,
    );
  });

  it('leaves a missing leaf above the count as the pallet\'s empty digest', async () => {
    // Above the count the padding is the pallet's own rule: `get_leaf_hash`
    // substitutes `empty_hash()` for an unset slot, so a local rebuild pads
    // the way the chain does. Below the count the same answer is refused, by
    // the two tests under this one.
    const values = new Map<string, string>([[`${KEYS.leaves}${indexKey(0)}`, `0x${'cd'.repeat(32)}`]]);
    const bytes = await fetchLeafHashes(nodeWith(values), 0, 2, AT, 1);
    expect(bytes).toHaveLength(64);
    expect([...bytes.slice(32)]).toEqual(Array.from({ length: 32 }, () => 0));
  });

  it('refuses the tree\'s own pad answered as a leaf below the count', async () => {
    // The all-zero digest is `tree::empty_hash()`, what the tree reads an
    // unfilled slot as, and `pallet-zk-tree::insert_commitment` refuses an
    // append of it by name, so below the count it is a leaf the chain never
    // wrote. Folding one moves no root, because padding is what a fold already
    // does above the count, so a node can report a leaf count above the one
    // its headers folded, pad the difference and match every root this wallet
    // compares. The pass would then write a watermark above indices the chain
    // has not filled and never read the leaves that land there.
    const values = new Map<string, string>([
      [`${KEYS.leaves}${indexKey(0)}`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leaves}${indexKey(1)}`, `0x${'00'.repeat(32)}`],
    ]);
    await expect(fetchLeafHashes(nodeWith(values), 0, 2, AT, 2)).rejects.toThrow(
      /ZkTree::Leaves\(1\) with the all-zero digest/,
    );
  });

  it('refuses the pad spelled without the 0x prefix', async () => {
    // The same evasion on the read the spend path makes. This is the buffer
    // the tree is rebuilt from, so a pad accepted here is a pad folded into a
    // path that then roots correctly against a count the chain never reached.
    const values = new Map<string, string>([
      [`${KEYS.leaves}${indexKey(0)}`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leaves}${indexKey(1)}`, '00'.repeat(32)],
    ]);
    await expect(fetchLeafHashes(nodeWith(values), 0, 2, AT, 2)).rejects.toThrow(
      /ZkTree::Leaves\(1\) with the all-zero digest/,
    );
  });

  it('refuses a leaf hash the node withholds below the count', async () => {
    const values = new Map<string, string>([[`${KEYS.leaves}${indexKey(0)}`, `0x${'cd'.repeat(32)}`]]);
    await expect(fetchLeafHashes(nodeWith(values), 0, 2, AT, 2)).rejects.toThrow(
      /no ZkTree::Leaves\(1\)/,
    );
  });
});

/**
 * A node that has no block at one height until it is asked a second time.
 *
 * A reorg in progress, or a load balancer answering from a replica that has
 * not filled in behind its own head. The settlement lands at that height.
 */
function reorgingNode(gapHeight: number, encoded: string): { context: ChainContext; asked: () => number } {
  let askedForGap = 0;
  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    if (method === 'chain_getBlockHash') {
      const height = params[0] as number | undefined;
      if (height === undefined) {
        return Promise.resolve(`0x${'ff'.repeat(32)}` as T);
      }
      if (height === gapHeight) {
        askedForGap += 1;
        return Promise.resolve((askedForGap === 1 ? null : `0x${'bb'.repeat(32)}`) as T);
      }
      return Promise.resolve(`0x${String(height).padStart(64, 'c')}` as T);
    }
    if (method === 'chain_getHeader') {
      return Promise.resolve(fixtureHeader(gapHeight + 1) as T);
    }
    if (method === 'chain_getBlock') {
      const at = String(params[0]);
      return Promise.resolve({
        block: { extrinsics: at === `0x${'bb'.repeat(32)}` ? [encoded] : [] },
      } as T);
    }
    if (method === 'state_getReadProof') {
      return Promise.resolve(fixtureProof(String(params[1]),
        (params[0] as string[]).map((key) => [key, '0x'])) as T);
    }
    throw new Error(`this fixture answers no ${method}`);
  };
  const context = {
    send,
    api: { query: { shielded: { usedNullifiers: entry('0xusednullifiers-') } } },
  } as unknown as ChainContext;
  bindFixtureProofs(context, () => `0x${'bb'.repeat(32)}`);
  return { context, asked: () => askedForGap };
}

describe('waiting for a settlement to land', () => {
  it('reads a height again rather than walking past the block it could not read', async () => {
    const encoded = '0xdeadbeef';
    const { context, asked } = reorgingNode(11, encoded);
    const inclusion = await waitForInclusion(context, encoded, ['ab'.repeat(32)], {
      timeoutMs: 5000,
      fromBlock: 10,
      pollMs: 5,
    });
    expect(inclusion?.blockNumber).toBe(11);
    expect(inclusion?.settled).toBe(true);
    // Asked twice: once for the null, once for the answer. A cursor that
    // advanced past the null would have asked once and waited out the timeout.
    expect(asked()).toBe(2);
  });
});

/**
 * A node that serves a header chain, with the two ways to cost a walk a round
 * trip built in.
 *
 * Every answer is deferred by a microtask hop before it resolves, and the
 * headers come back in the order the promises settle rather than the order
 * they were asked for, because that is what a pipelined walk gets: 32 requests
 * are outstanding on one socket and the node answers them as it pleases. A
 * walk that assembled the range by arrival would build a different chain every
 * run.
 */
function headerNode(options: {
  head: number;
  /** Answers a list of numbers with one hash, the way an older node does. */
  refuseHashLists?: boolean;
  /**
   * Answers a list of numbers with a JSON-RPC error, the way a node whose
   * parameter is one number rather than Substrate's list-or-value does: the
   * array fails to deserialize and the node says `-32602 Invalid params`.
   */
  errorHashLists?: boolean;
  /** A height whose header carries a number that is not the one asked for. */
  misnumbered?: number;
  /** A height whose header names a parent that is not the hash below it. */
  brokenParent?: number;
  /** A height this node refuses to answer a header for at all. */
  refuseHeaderAt?: number;
}): {
  context: ChainContext;
  calls: { method: string; params: unknown[] }[];
  /** The heights this node answered a header for, in the order it answered. */
  answered: number[];
  /** The most `chain_getHeader` requests this node ever had outstanding. */
  peakInFlight: () => number;
} {
  const calls: { method: string; params: unknown[] }[] = [];
  const hashAt = (height: number): string => `0x${String(height).padStart(64, '0')}`;
  const headerAt = (height: number): unknown => ({
    parentHash:
      options.brokenParent === height ? `0x${'ff'.repeat(32)}` : hashAt(Math.max(height - 1, 0)),
    number: `0x${(options.misnumbered === height ? height + 1 : height).toString(16)}`,
    stateRoot: `0x${'22'.repeat(32)}`,
    extrinsicsRoot: `0x${'33'.repeat(32)}`,
    zkTreeRoot: `0x${'44'.repeat(32)}`,
    digest: { logs: [] },
  });
  const answered: number[] = [];
  let inFlight = 0;
  let peak = 0;
  const send = async <T,>(method: string, params: unknown[]): Promise<T> => {
    calls.push({ method, params });
    // One hop, so a caller with many requests in flight has them all issued
    // before any of them resolves.
    await Promise.resolve();
    if (method === 'chain_getBlockHash') {
      const asked = params[0] as number | number[] | undefined;
      if (Array.isArray(asked)) {
        if (options.errorHashLists === true) {
          // What a node answers, rather than a socket that failed: a JSON-RPC
          // error object, with the code polkadot-js carries on the rejection.
          throw Object.assign(new Error('-32602: Invalid params: expected a block number'), {
            code: -32602,
          });
        }
        if (options.refuseHashLists === true) {
          return hashAt(asked[0] ?? options.head) as T;
        }
        return asked.map((height) => hashAt(height)) as T;
      }
      return hashAt(asked ?? options.head) as T;
    }
    if (method === 'chain_getHeader') {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      const height = Number(String(params[0]).replace(/^0x0*/, '') || '0');
      // Deliberately out of order. A node with 32 requests outstanding answers
      // them as it pleases, and a walk that assembled the range by arrival
      // would build a different chain on every run.
      for (let hop = 0; hop <= (height * 7) % 11; hop += 1) {
        await Promise.resolve();
      }
      answered.push(height);
      inFlight -= 1;
      if (options.refuseHeaderAt === height) {
        throw new Error(`this node will not answer for block ${height}`);
      }
      return headerAt(height) as T;
    }
    throw new Error(`this fixture answers no ${method}`);
  };
  return {
    context: { send } as unknown as ChainContext,
    calls,
    answered,
    peakInFlight: () => peak,
  };
}

describe('the header walk', () => {
  const hashAt = (height: number): string => `0x${String(height).padStart(64, '0')}`;

  it('is climbed in the same chunk both wallets use', () => {
    // The read layer bounds the span for itself, because it now holds the
    // chunk it is fetching, and `wallet/sync.ts` is what chunks a longer
    // range. Two numbers for one thing is a walk that allocates more than the
    // caller thinks it asked for.
    expect(HEADER_SPAN_LIMIT).toBe(HEADER_WALK_LIMIT);
  });

  it('reads the hashes as a list and the headers with many in flight', async () => {
    const { context, calls, answered } = headerNode({ head: 300 });
    const seen: number[] = [];
    await fetchHeaderRange(context, 0, { number: 300, hash: hashAt(300) }, (header) => {
      seen.push(Number(BigInt(header.number)));
    });
    // Ascending, whatever order the answers landed in, and this node answered
    // them in a different order from the one they were asked in.
    expect(answered).not.toEqual([...answered].sort((a, b) => a - b));
    expect(seen).toEqual(Array.from({ length: 301 }, (_value, index) => index));
    // 300 heights below the top, paged at 256: two calls, not three hundred.
    // The top's own hash is the caller's and is never asked for.
    const hashCalls = calls.filter((call) => call.method === 'chain_getBlockHash');
    expect(hashCalls.length).toBe(2);
    expect((hashCalls[0]?.params[0] as number[]).length).toBe(256);
    expect((hashCalls[1]?.params[0] as number[]).length).toBe(44);
    expect(calls.filter((call) => call.method === 'chain_getHeader').length).toBe(301);
  });

  it('keeps no more requests in flight than the pool it declares', async () => {
    // The bound this page states, asserted rather than described. A walk that
    // issued every height at once would keep all seven other cases green while
    // putting a thousand requests on one socket, and every answer resident
    // with them.
    const { context, peakInFlight } = headerNode({ head: 300 });
    let seen = 0;
    await fetchHeaderRange(context, 0, { number: 300, hash: hashAt(300) }, () => {
      seen += 1;
    });
    expect(seen).toBe(301);
    expect(peakInFlight()).toBe(HEADERS_IN_FLIGHT);
  });

  it('reports no more headers once a walk has been refused', async () => {
    // The requests that were in flight when one worker refused are answered
    // afterwards, and a walk that counted them called back after its caller
    // had the error. In `runSync` that callback is a rendered line, so the
    // page painted header progress over its own refusal banner.
    const { context } = headerNode({ head: 200, refuseHeaderAt: 3 });
    const reported: number[] = [];
    await expect(
      fetchHeaderRange(
        context,
        0,
        { number: 200, hash: hashAt(200) },
        () => undefined,
        (done) => {
          reported.push(done);
        },
      ),
    ).rejects.toThrow(/will not answer for block 3/);
    const afterRefusal = reported.length;
    // Every request that was outstanding at the refusal settles here.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(reported.length).toBe(afterRefusal);
  });

  it('asks one height at a time when the node answers a list with an error', async () => {
    // A node whose `chain_getBlockHash` parameter is one number rather than
    // Substrate's list-or-value fails to deserialize the array and answers
    // `-32602 Invalid params`. That is an older implementation and not a lie,
    // so it is answered around rather than refused.
    const { context, calls } = headerNode({ head: 4, errorHashLists: true });
    const seen: number[] = [];
    await fetchHeaderRange(context, 0, { number: 4, hash: hashAt(4) }, (header) => {
      seen.push(Number(BigInt(header.number)));
    });
    expect(seen).toEqual([0, 1, 2, 3, 4]);
    const hashCalls = calls.filter((call) => call.method === 'chain_getBlockHash');
    expect(hashCalls.length).toBe(5);
    expect(hashCalls.slice(1).map((call) => call.params[0])).toEqual([0, 1, 2, 3]);
  });

  it('probes a node that will not answer a list once, not once per page', async () => {
    // The answer is remembered against the context it was asked through. A
    // walk pages its heights, so probing per page would pay the refused round
    // trip on every page of every chunk of every sync.
    const { context, calls } = headerNode({ head: 600, refuseHashLists: true });
    let seen = 0;
    await fetchHeaderRange(context, 0, { number: 600, hash: hashAt(600) }, () => {
      seen += 1;
    });
    expect(seen).toBe(601);
    const lists = calls.filter(
      (call) => call.method === 'chain_getBlockHash' && Array.isArray(call.params[0]),
    );
    expect(lists.length).toBe(1);
  });

  it('asks one height at a time when the node will not answer a list', async () => {
    const { context, calls } = headerNode({ head: 4, refuseHashLists: true });
    const seen: number[] = [];
    await fetchHeaderRange(context, 0, { number: 4, hash: hashAt(4) }, (header) => {
      seen.push(Number(BigInt(header.number)));
    });
    expect(seen).toEqual([0, 1, 2, 3, 4]);
    // The list, then one call per height it could not read as a list. Nothing
    // about the answer is trusted differently: the hashes are addresses and
    // the parent links are what the walk checks.
    const hashCalls = calls.filter((call) => call.method === 'chain_getBlockHash');
    expect(hashCalls.length).toBe(5);
    expect(hashCalls.slice(1).map((call) => call.params[0])).toEqual([0, 1, 2, 3]);
  });

  it('refuses a header answered for a height that is not its own', async () => {
    const { context } = headerNode({ head: 6, misnumbered: 3 });
    await expect(
      fetchHeaderRange(context, 0, { number: 6, hash: hashAt(6) }, () => undefined),
    ).rejects.toThrow(/answered a header numbered 4 for the hash it gave as block 3/);
  });

  it('refuses a parent link the hashes it answered do not carry', async () => {
    const { context } = headerNode({ head: 6, brokenParent: 4 });
    await expect(
      fetchHeaderRange(context, 0, { number: 6, hash: hashAt(6) }, () => undefined),
    ).rejects.toThrow(/names ff+ as its parent/);
  });

  it('hands the caller nothing at all when it refuses', async () => {
    const { context } = headerNode({ head: 6, brokenParent: 4 });
    const seen: number[] = [];
    await expect(
      fetchHeaderRange(context, 0, { number: 6, hash: hashAt(6) }, (header) => {
        seen.push(Number(BigInt(header.number)));
      }),
    ).rejects.toThrow();
    expect(seen).toEqual([]);
  });

  it('refuses a span longer than one chunk', async () => {
    const { context } = headerNode({ head: HEADER_SPAN_LIMIT + 1 });
    await expect(
      fetchHeaderRange(
        context,
        0,
        { number: HEADER_SPAN_LIMIT + 1, hash: hashAt(HEADER_SPAN_LIMIT + 1) },
        () => undefined,
      ),
    ).rejects.toThrow(/one walk carries at most 1024/);
  });
});
