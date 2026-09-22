/**
 * Where a payment comes from now, through the real read layer.
 *
 * `privacy.test.ts` asserts what the node is asked; this asserts what it is
 * never asked, and the two are different properties. `Shielded::Ciphertexts`
 * is gone from the chain, so a wallet that still built a key for it would
 * either read an absent value at every leaf, which is every payment silently
 * skipped behind a committed watermark, or refuse the sync at startup on a
 * storage drift the runtime is right about.
 *
 * Nothing in the wallet can build that key any more: it is off
 * `REQUIRED_STORAGE`, and `canonicalStorage` refuses the name
 * (`storage-keys.test.ts`). This drives a whole pass through the real read
 * layer and the real adapter anyway, over a recording transport, because a
 * key is only truly gone when no request carries it.
 */

import { describe, expect, it } from 'vitest';

import { chainAdapter } from '../src/app/adapters';
import type { ChainContext } from '../src/chain/api';
import { runSync, type ScannedNote, type SyncCrypto } from '../src/wallet/sync';
import { STORE_VERSION, type StoreMeta } from '../src/wallet/model';
import { TEST_PROTOCOL_PROFILE } from './fixtures/protocol-profile';
import { coinbaseExtrinsic, settlementExtrinsic, TEST_BODY_LAYOUT, timestampExtrinsic } from './fixtures/body';
import { bindFixtureProofs, fixtureProof } from './fixtures/state-proof';
import { indexKey, storagePrefix } from './fixtures/storage-key';

const HEAD = 4;
/** Two leaves a block: whatever the block appended, then its own coinbase. */
const LEAF_COUNT = 8;
/** This wallet's payment. Below its block's last leaf, so it cannot be a coinbase. */
const OUR_LEAF = 4;
const OUR_COMMITMENT = 'ab'.repeat(32);

const KEYS = {
  leaves: storagePrefix('ZkTree', 'Leaves'),
  leafCount: storagePrefix('ZkTree', 'LeafCount'),
  depth: storagePrefix('ZkTree', 'Depth'),
  ciphertexts: storagePrefix('Shielded', 'Ciphertexts'),
  leafBlocks: storagePrefix('Shielded', 'LeafBlocks'),
  coinbaseValues: storagePrefix('Shielded', 'CoinbaseValues'),
  entryCount: storagePrefix('Shielded', 'EntryCount'),
  usedNullifiers: storagePrefix('Shielded', 'UsedNullifiers'),
} as const;

function hashAt(height: number): string {
  return `0x${String(height).padStart(64, '0')}`;
}

function rootFor(count: number): string {
  return `0x${String(count).padStart(64, '7')}`;
}

function countAt(block: number): number {
  return Math.max(0, Math.min(block * 2, LEAF_COUNT));
}

function blockOfLeaf(index: number): number {
  return Math.floor(index / 2) + 1;
}

function isCoinbaseLeaf(index: number): boolean {
  return index % 2 === 1;
}

/** A little-endian integer of `bytes` bytes, hex, the way SCALE stores one. */
function le(value: bigint, bytes: number): string {
  let out = '0x';
  for (let index = 0; index < bytes; index += 1) {
    out += Number((value >> BigInt(8 * index)) & 0xffn)
      .toString(16)
      .padStart(2, '0');
  }
  return out;
}

function entry(prefix: string): unknown {
  return {
    key: (arg?: number | string): string =>
      arg === undefined ? prefix : `${prefix}${String(arg).replace(/^0x/, '')}`,
    keyPrefix: (): string => prefix,
  };
}

function recordingContext(): { context: ChainContext; calls: { method: string; params: unknown[] }[] } {
  const calls: { method: string; params: unknown[] }[] = [];
  const values = new Map<string, string>();
  values.set(KEYS.leafCount, le(BigInt(LEAF_COUNT), 8));
  values.set(KEYS.depth, le(3n, 1));
  values.set(KEYS.entryCount, le(0n, 8));
  for (let index = 0; index < LEAF_COUNT; index += 1) {
    values.set(
      `${KEYS.leaves}${indexKey(index)}`,
      `0x${index === OUR_LEAF ? OUR_COMMITMENT : 'cd'.repeat(32)}`,
    );
    values.set(`${KEYS.leafBlocks}${indexKey(index)}`, le(BigInt(blockOfLeaf(index)), 4));
    if (isCoinbaseLeaf(index)) {
      values.set(`${KEYS.coinbaseValues}${indexKey(index)}`, le(BigInt(index + 1), 8));
    }
    // And nothing else. There is no per-leaf payload on this chain at all:
    // every note ciphertext is in the body of the block that appended the
    // leaf, which is what `chain_getBlock` below serves.
  }

  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    calls.push({ method, params });
    if (method === 'chain_getBlockHash') {
      const height = params[0] as number | number[] | undefined;
      if (height === undefined) {
        return Promise.resolve(hashAt(HEAD) as T);
      }
      return Promise.resolve(
        (Array.isArray(height) ? height.map(hashAt) : hashAt(height)) as T,
      );
    }
    if (method === 'chain_getHeader') {
      const asked = params[0] as string | undefined;
      const number = asked === undefined ? HEAD : Number(asked.replace(/^0x0*/, '') || '0');
      return Promise.resolve({
        parentHash: hashAt(number - 1),
        number: `0x${number.toString(16)}`,
        stateRoot: `0x${'22'.repeat(32)}`,
        // The value the fixture verifier answers for any body, so the root
        // comparison passes and what this test records is the request.
        extrinsicsRoot: `0x${'22'.repeat(32)}`,
        zkTreeRoot: rootFor(countAt(number)),
        digest: { logs: [`0x06706f775f80${'9a'.repeat(32)}`] },
      } as T);
    }
    if (method === 'chain_getBlock') {
      const number = Number(String(params[0]).replace(/^0x0*/, '') || '0');
      const first = (number - 1) * 2;
      return Promise.resolve({
        block: {
          extrinsics: [
            timestampExtrinsic(number * 1000),
            settlementExtrinsic([[new Uint8Array([first, 1, 2]), new Uint8Array([first, 3, 4])]]),
            coinbaseExtrinsic(),
          ],
        },
      } as T);
    }
    if (method === 'state_getReadProof') {
      return Promise.resolve(fixtureProof(String(params[1]), [...values]) as T);
    }
    if (method === 'state_getKeysPaged') {
      return Promise.resolve([] as T);
    }
    throw new Error(`this test's node was asked ${method}, which a sync must not call`);
  };

  const context = {
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
          usedNullifiers: entry(KEYS.usedNullifiers),
        },
      },
    },
    bodyLayout: TEST_BODY_LAYOUT,
    storageDrift: [],
    constants: { blockHashWindow: 256 },
    targetBlockTimeMs: 12_000,
  } as unknown as ChainContext;

  bindFixtureProofs(context, (anchor) => hashAt(anchor.block_number));
  return { context, calls };
}

const OURS: ScannedNote = {
  value: 1000n,
  rho: 'dd'.repeat(32),
  r: 'ee'.repeat(32),
  commitment: OUR_COMMITMENT,
  nullifier: 'c0ffee'.padEnd(64, '0'),
  memo: 'lunch',
};

function crypto(): SyncCrypto {
  return {
    // Only the payload the settlement of block 3 carries. The first byte is
    // the leaf this fixture means it for; the real module decides by
    // decapsulating and answers the note's own commitment either way, which is
    // what places it.
    decryptBatch: (items) =>
      Promise.resolve(items.map((item) => (item.ciphertext[0] === OUR_LEAF ? OURS : null))),
    coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
    entryRhoMatches: () => Promise.resolve(false),
    headerHashes: (headers) => Promise.resolve(headers.map((header) => hashAt(header.block_number))),
    authorLabels: (parentHashes) => Promise.resolve(parentHashes.map(() => 'ff'.repeat(32))),
    blockRoots: (_leafHashes, counts) => Promise.resolve(counts.map((count) => rootFor(count))),
  };
}

function freshMeta(): StoreMeta {
  return {
    id: 'store',
    schemaVersion: STORE_VERSION,
    address: 'qn1test',
    genesisHash: null,
    birthday: null,
    lastSyncedBlock: 0,
    nextLeaf: 0,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000, saltHex: '00'.repeat(16) },
    createdAt: 0,
    updatedAt: 0,
    upgrades: [],
  };
}

const LIMITS = {
  memo_bytes: 61,
  ciphertext_fixed_bytes: 1731,
  padded_ciphertext_bytes: 1792,
  digest_logs_size: 110,
  max_tree_depth: 32,
  tree_arity: 4,
  siblings_per_level: 3,
  chain_num_leaves: 6,
  protocol_profile: TEST_PROTOCOL_PROFILE,
};

async function syncOnce(): Promise<{
  calls: { method: string; params: unknown[] }[];
  received: number;
  leafIndex: number | undefined;
}> {
  const { context, calls } = recordingContext();
  const result = await runSync(
    { meta: freshMeta(), held: [], rejected: [], checkpoints: [], pending: [] },
    chainAdapter(context, LIMITS),
    crypto(),
  );
  return { calls, received: result.report.received, leafIndex: result.notes[0]?.note.leafIndex };
}

describe('a sync that takes its payments out of block bodies', () => {
  it('finds the payment, which is what makes the rest of these assertions mean something', async () => {
    const { received, leafIndex } = await syncOnce();
    expect(received).toBe(1);
    // At the leaf whose commitment the payload opens, found by searching the
    // block's own folded range and never by an index a node chose.
    expect(leafIndex).toBe(OUR_LEAF);
  });

  it('never asks for a Shielded::Ciphertexts key, anywhere in the pass', async () => {
    const { calls } = await syncOnce();
    const wire = JSON.stringify(calls).toLowerCase();
    expect(wire).not.toContain(KEYS.ciphertexts.toLowerCase());
    // The prefix is 32 bytes of xxhash and would appear inside every key of
    // that map, so its absence from the whole recorded stream is the
    // assertion. Named here so a reader can see what was looked for.
    expect(KEYS.ciphertexts).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('reads three keys a leaf and no fourth', async () => {
    const { calls } = await syncOnce();
    const perLeaf = new Set<string>();
    for (const call of calls) {
      if (call.method !== 'state_getReadProof') {
        continue;
      }
      for (const key of call.params[0] as string[]) {
        for (const [name, prefix] of Object.entries(KEYS)) {
          if (key.startsWith(prefix) && key !== prefix) {
            perLeaf.add(name);
          }
        }
      }
    }
    expect([...perLeaf].sort()).toEqual(['coinbaseValues', 'leafBlocks', 'leaves']);
  });

  it('asks for one body per block that appended a leaf, by hash', async () => {
    const { calls } = await syncOnce();
    const bodies = calls.filter((call) => call.method === 'chain_getBlock');
    // Blocks 1 to 4 each appended two leaves, and the walk stands on the
    // anchor without rereading it.
    expect(bodies.map((call) => call.params[0])).toEqual([1, 2, 3, 4].map(hashAt));
    // By a hash this pass rehashed out of its own header walk. A height would
    // let the node pick which chain it answered for.
    for (const call of bodies) {
      expect(String(call.params[0])).toMatch(/^0x[0-9a-f]{64}$/);
    }
  });
});
