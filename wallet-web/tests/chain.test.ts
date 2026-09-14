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
import { fetchLeafHashes, fetchLeaves } from '../src/chain/reads';
import { waitForInclusion } from '../src/chain/submit';

const AT = `0x${'aa'.repeat(32)}`;

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
        zkTree: { leaves: entry(KEYS.leaves) },
        shielded: {
          ciphertexts: entry(KEYS.ciphertexts),
          leafBlocks: entry(KEYS.leafBlocks),
          coinbaseValues: entry(KEYS.coinbaseValues),
        },
      },
    },
  } as unknown as ChainContext;
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
    const [row] = await fetchLeaves(nodeWith(values), 0, 1, AT);
    expect(row?.commitment).toBe(`0x${'cd'.repeat(32)}`);
    expect(row?.ciphertext).toEqual(new Uint8Array([0x00, 0x11, 0x22, 0x33]));
    expect(row?.blockNumber).toBe(9);
    expect(row?.coinbaseQuanta).toBe(10n);
  });

  it('refuses a leaf that is not 32 bytes, and names it', async () => {
    const values = new Map<string, string>([[`${KEYS.leaves}3`, `0x${'cd'.repeat(31)}`]]);
    await expect(fetchLeaves(nodeWith(values), 3, 4, AT)).rejects.toThrow(
      /ZkTree::Leaves\(3\) is 31 bytes, expected 32/,
    );
  });

  it('refuses a ciphertext whose length prefix and body disagree', async () => {
    // The failure this replaces is silent: a truncated ciphertext decrypts as
    // nobody's, so every leaf on the chain reads as somebody else's and the
    // sync reports zero notes received over a completed pass.
    const values = new Map<string, string>([[`${KEYS.ciphertexts}0`, vec(4, '001122')]]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT)).rejects.toThrow(
      /Shielded::Ciphertexts\(0\) declares 4 bytes and carries 3/,
    );
  });

  it('refuses a block height that is not a u32', async () => {
    const values = new Map<string, string>([
      [`${KEYS.leafBlocks}0`, '0x0900000000000000'],
    ]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT)).rejects.toThrow(
      /Shielded::LeafBlocks\(0\) is 8 bytes and this build decodes it as 4/,
    );
  });

  it('refuses a coinbase value that is not a u64', async () => {
    const values = new Map<string, string>([[`${KEYS.coinbaseValues}0`, '0x0a000000']]);
    await expect(fetchLeaves(nodeWith(values), 0, 1, AT)).rejects.toThrow(
      /Shielded::CoinbaseValues\(0\) is 4 bytes and this build decodes it as 8/,
    );
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
