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
import { fetchLeafHashes, fetchLeaves, fetchTreeShape, fetchTreeTotals } from '../src/chain/reads';
import { waitForInclusion } from '../src/chain/submit';

const AT = `0x${'aa'.repeat(32)}`;

/** What the module reports, and what bounds a leaf count here. */
const MAX_TREE_DEPTH = 16;

/** A storage entry whose keys this test can read back. See `privacy.test.ts`. */
function entry(prefix: string): unknown {
  return {
    key: (arg?: number | string): string =>
      arg === undefined ? prefix : `${prefix}${String(arg).replace(/^0x/, '')}`,
    keyPrefix: (): string => prefix,
  };
}

const KEYS = {
  leaves: '0xleaves-',
  ciphertexts: '0xciphertexts-',
  leafBlocks: '0xleafblocks-',
  coinbaseValues: '0xcoinbase-',
  leafCount: '0xleafcount',
  depth: '0xdepth',
  entryCount: '0xentrycount',
} as const;

/** A node that answers exactly the values this test hands it. */
function nodeWith(values: Map<string, string>): ChainContext {
  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    if (method !== 'state_queryStorageAt') {
      throw new Error(`this fixture answers no ${method}`);
    }
    const keys = params[0] as string[];
    return Promise.resolve([
      {
        block: String(params[1]),
        changes: keys.map((key) => [key, values.get(key) ?? null] as [string, string | null]),
      },
    ] as T);
  };
  return {
    send,
    api: {
      query: {
        zkTree: {
          leaves: entry(KEYS.leaves),
          leafCount: entry(KEYS.leafCount),
          depth: entry(KEYS.depth),
        },
        shielded: {
          ciphertexts: entry(KEYS.ciphertexts),
          leafBlocks: entry(KEYS.leafBlocks),
          coinbaseValues: entry(KEYS.coinbaseValues),
          entryCount: entry(KEYS.entryCount),
        },
      },
    },
  } as unknown as ChainContext;
}

/** The same node, with the key lists of every request it was handed. */
function recordingNode(values: Map<string, string>, asked: string[][]): ChainContext {
  const inner = nodeWith(values);
  return {
    ...inner,
    send: <T,>(method: string, params: unknown[]): Promise<T> => {
      if (method === 'state_queryStorageAt') {
        asked.push(params[0] as string[]);
      }
      return inner.send<T>(method, params);
    },
  };
}

/** A `Vec<u8>` whose one-byte compact prefix is written by hand. */
function vec(lengthByte: number, body: string): string {
  return `0x${(lengthByte << 2).toString(16).padStart(2, '0')}${body}`;
}

describe('a leaf row', () => {
  it('reads back when every field is the width the runtime declares', async () => {
    const values = new Map<string, string>([
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.ciphertexts}0`, vec(4, '00112233')],
      [`${KEYS.leafBlocks}0`, '0x09000000'],
      [`${KEYS.coinbaseValues}0`, '0x0a00000000000000'],
    ]);
    const [row] = await fetchLeaves(nodeWith(values), 0, 1, AT, 1);
    expect(row?.commitment).toBe(`0x${'cd'.repeat(32)}`);
    expect(row?.ciphertext).toEqual(new Uint8Array([0x00, 0x11, 0x22, 0x33]));
    expect(row?.blockNumber).toBe(9);
    expect(row?.coinbaseQuanta).toBe(10n);
  });

  it('refuses a leaf that is not 32 bytes, and names it', async () => {
    const values = new Map<string, string>([[`${KEYS.leaves}3`, `0x${'cd'.repeat(31)}`]]);
    await expect(fetchLeaves(nodeWith(values), 3, 4, AT, 4)).rejects.toThrow(
      /ZkTree::Leaves\(3\) is 31 bytes, expected 32/,
    );
  });

  it('refuses a ciphertext whose length prefix and body disagree', async () => {
    // The failure this replaces is silent: a truncated ciphertext decrypts as
    // nobody's, so every leaf on the chain reads as somebody else's and the
    // sync reports zero notes received over a completed pass.
    const values = new Map<string, string>([
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.ciphertexts}0`, vec(4, '001122')],
    ]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      /Shielded::Ciphertexts\(0\) declares 4 bytes and carries 3/,
    );
  });

  it('refuses a block height that is not a u32', async () => {
    const values = new Map<string, string>([
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leafBlocks}0`, '0x0900000000000000'],
    ]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      /Shielded::LeafBlocks\(0\) is 8 bytes and this build decodes it as 4/,
    );
  });

  it('refuses a leaf the node withheld below its own leaf count, and names all three', async () => {
    // The tree has no gaps under its own count: `pallet-zk-tree` appends a
    // leaf and raises `LeafCount` in one call and nothing removes one. So an
    // absent commitment below the count read at this same block hash is an
    // answer withheld, and reading it as "no leaf here" is silent and
    // permanent: the scan steps over it, the pass writes a watermark above it,
    // and a payment on that leaf is never read again without a rescan.
    const values = new Map<string, string>([
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leaves}2`, `0x${'ce'.repeat(32)}`],
    ]);
    await expect(fetchLeaves(nodeWith(values), 0, 3, AT, 3)).rejects.toThrow(
      new RegExp(`no ZkTree::Leaves\\(1\\) at block ${AT}, where it reports 3 leaves`),
    );
  });

  it('reads a leaf above the count as absent, which is what the range past the end is', async () => {
    // The same answer above the count is ordinary: a window may run to the end
    // of a range the count does not reach, and nothing there is withheld.
    const values = new Map<string, string>([[`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`]]);
    const rows = await fetchLeaves(nodeWith(values), 0, 2, AT, 1);
    expect(rows[1]?.commitment).toBeNull();
  });

  it('refuses a coinbase value that is not a u64', async () => {
    const values = new Map<string, string>([
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.coinbaseValues}0`, '0x0a000000'],
    ]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT, 1)).rejects.toThrow(
      /Shielded::CoinbaseValues\(0\) is 4 bytes and this build decodes it as 8/,
    );
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
      [`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`],
      [`${KEYS.leaves}1`, `0x${'cd'.repeat(33)}`],
    ]);
    await expect(fetchLeafHashes(nodeWith(values), 0, 2, AT)).rejects.toThrow(
      /ZkTree::Leaves\(1\) is 33 bytes, expected 32/,
    );
  });

  it('leaves a missing leaf as the pallet\'s empty digest', async () => {
    const values = new Map<string, string>([[`${KEYS.leaves}0`, `0x${'cd'.repeat(32)}`]]);
    const bytes = await fetchLeafHashes(nodeWith(values), 0, 2, AT);
    expect(bytes).toHaveLength(64);
    expect([...bytes.slice(32)]).toEqual(Array.from({ length: 32 }, () => 0));
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
      return Promise.resolve({ number: `0x${(gapHeight + 1).toString(16)}` } as T);
    }
    if (method === 'chain_getBlock') {
      const at = String(params[0]);
      return Promise.resolve({
        block: { extrinsics: at === `0x${'bb'.repeat(32)}` ? [encoded] : [] },
      } as T);
    }
    if (method === 'state_queryStorageAt') {
      const keys = params[0] as string[];
      return Promise.resolve([
        { block: String(params[1]), changes: keys.map((key) => [key, '0x'] as [string, string]) },
      ] as T);
    }
    throw new Error(`this fixture answers no ${method}`);
  };
  const context = {
    send,
    api: { query: { shielded: { usedNullifiers: entry('0xusednullifiers-') } } },
  } as unknown as ChainContext;
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
