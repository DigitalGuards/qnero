/**
 * Where a wallet starts reading the chain, and how it is read off a node.
 *
 * A wallet cannot have been paid into a leaf that existed before the wallet
 * did, so one that records the head it was created at never walks the headers
 * under that block and never trial-decrypts the ciphertexts under its leaf
 * count. `sync.test.ts` drives what that does to a pass; here is where the
 * number comes from, what it is rounded to, and what the store does with it.
 *
 * Rounded **down**, always. A birthday is public: it is the bottom of the
 * header walk, so every node this wallet ever syncs against is told it, and
 * recorded exactly it would be the wallet's creation time to the block. Down
 * also means a height a little too high still starts below the first note,
 * where a height above the block a note arrived in is a note the wallet never
 * reads.
 */

import { describe, expect, it } from 'vitest';

import type { ChainContext } from '../src/chain/api';
import { fetchBirthday } from '../src/chain/reads';
import { heightFromRestoreField } from '../src/screens/RestoreWallet';
import { deriveKey, newSalt, bytesToHex } from '../src/wallet/crypto';
import { BIRTHDAY_EPOCH, birthdayEpochOf, STORE_VERSION } from '../src/wallet/model';
import { createStore, openDatabase, DB_NAME } from '../src/wallet/store';

const MAX_TREE_DEPTH = 16;

/** A storage entry whose keys this test can read back. See `privacy.test.ts`. */
function entry(prefix: string): unknown {
  return {
    key: (arg?: number | string): string =>
      arg === undefined ? prefix : `${prefix}${String(arg).replace(/^0x/, '')}`,
    keyPrefix: (): string => prefix,
  };
}

const KEYS = { leafCount: '0xleafcount', depth: '0xdepth', entryCount: '0xentrycount' } as const;

/**
 * A node with a head and a leaf count per height.
 *
 * `countAt` is the point: `ZkTree::LeafCount` read at the birthday block is
 * the count that block's state carried, and a fixture answering the head's
 * count there would hand back a watermark above leaves that block never held.
 */
function nodeWith(head: number, countAt: (height: number) => number): {
  context: ChainContext;
  calls: { method: string; params: unknown[] }[];
} {
  const calls: { method: string; params: unknown[] }[] = [];
  const hashAt = (height: number): string => `0x${String(height).padStart(64, '0')}`;
  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    calls.push({ method, params });
    if (method === 'chain_getBlockHash') {
      const asked = params[0] as number | undefined;
      return Promise.resolve(hashAt(asked ?? head) as T);
    }
    if (method === 'chain_getHeader') {
      return Promise.resolve({ number: `0x${head.toString(16)}` } as T);
    }
    if (method === 'state_queryStorageAt') {
      const at = String(params[1]);
      const height = Number(at.replace(/^0x0*/, '') || '0');
      const keys = params[0] as string[];
      const values = new Map<string, string>([
        [KEYS.leafCount, `0x${Buffer.from(
          new BigUint64Array([BigInt(countAt(height))]).buffer,
        ).toString('hex')}`],
        [KEYS.depth, '0x03'],
        [KEYS.entryCount, `0x${'00'.repeat(8)}`],
      ]);
      return Promise.resolve([
        {
          block: at,
          changes: keys.map((key) => [key, values.get(key) ?? null] as [string, string | null]),
        },
      ] as T);
    }
    throw new Error(`this fixture answers no ${method}`);
  };
  return {
    context: {
      send,
      api: {
        query: {
          zkTree: { leafCount: entry(KEYS.leafCount), depth: entry(KEYS.depth) },
          shielded: { entryCount: entry(KEYS.entryCount) },
        },
      },
    } as unknown as ChainContext,
    calls,
  };
}

describe('the epoch a birthday is recorded at', () => {
  it('is the height rounded down', () => {
    expect(birthdayEpochOf(0)).toBe(0);
    expect(birthdayEpochOf(BIRTHDAY_EPOCH - 1)).toBe(0);
    expect(birthdayEpochOf(BIRTHDAY_EPOCH)).toBe(BIRTHDAY_EPOCH);
    expect(birthdayEpochOf(BIRTHDAY_EPOCH + 1)).toBe(BIRTHDAY_EPOCH);
    expect(birthdayEpochOf(3 * BIRTHDAY_EPOCH - 1)).toBe(2 * BIRTHDAY_EPOCH);
  });
});

describe('reading a birthday off a node', () => {
  it('takes the head for a wallet being created now, at the epoch below it', async () => {
    const head = 2 * BIRTHDAY_EPOCH + 300;
    const { context } = nodeWith(head, (height) => Math.floor(height / 2));
    const birthday = await fetchBirthday(context, null, MAX_TREE_DEPTH);
    expect(birthday.blockNumber).toBe(2 * BIRTHDAY_EPOCH);
    // The count at the epoch block, not the count at the head.
    expect(birthday.nextLeaf).toBe(BIRTHDAY_EPOCH);
  });

  it('takes a restore height at the epoch below it', async () => {
    const head = 3 * BIRTHDAY_EPOCH;
    const { context } = nodeWith(head, (height) => height);
    const birthday = await fetchBirthday(context, BIRTHDAY_EPOCH + 700, MAX_TREE_DEPTH);
    expect(birthday.blockNumber).toBe(BIRTHDAY_EPOCH);
    expect(birthday.nextLeaf).toBe(BIRTHDAY_EPOCH);
  });

  it('refuses a height above the head rather than starting past every leaf', async () => {
    const { context } = nodeWith(100, () => 10);
    await expect(fetchBirthday(context, 500, MAX_TREE_DEPTH)).rejects.toThrow(
      /names a block nobody has yet/,
    );
  });
});

describe('the restore field', () => {
  it('reads a bare number as a height', () => {
    expect(heightFromRestoreField('197000', 200_000, 120_000)).toBe(197_000);
    expect(heightFromRestoreField('  4200 ', 200_000, 120_000)).toBe(4200);
  });

  it('reads nothing at all as a full scan', () => {
    expect(heightFromRestoreField('', 200_000, 120_000)).toBeNull();
    expect(heightFromRestoreField('   ', 200_000, 120_000)).toBeNull();
  });

  it('counts a date back from the head and then gives away an epoch', () => {
    const head = 200_000;
    const blockMs = 120_000;
    const days = 30;
    const when = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const height = heightFromRestoreField(when, head, blockMs);
    const blocksInThirtyDays = (days * 24 * 60 * 60 * 1000) / blockMs;
    expect(height).not.toBeNull();
    // Below the arithmetic answer by a whole epoch, because the conversion is
    // over a block time that holds on average and not block by block, and a
    // birthday that is too high is a note nobody reads.
    expect(height as number).toBeLessThanOrEqual(head - blocksInThirtyDays - BIRTHDAY_EPOCH + 1);
    expect(height as number).toBeGreaterThan(0);
  });

  it('reads neither a number nor a date as nothing, which is a full scan', () => {
    expect(heightFromRestoreField('soon after I made it', 200_000, 120_000)).toBeNull();
  });
});

describe('a store created with a birthday', () => {
  it('starts at it, keeps it, and carries it as its one checkpoint', async () => {
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = (): void => {
        resolve();
      };
      request.onerror = (): void => {
        reject(request.error ?? new Error('the test database could not be deleted'));
      };
      request.onblocked = (): void => {
        reject(new Error('a connection to the test database is still open'));
      };
    });
    const db = await openDatabase();
    const saltHex = bytesToHex(newSalt());
    const key = await deriveKey('correct horse battery staple', saltHex);
    const checkpoint = { blockNumber: BIRTHDAY_EPOCH, blockHash: 'ab'.repeat(32), nextLeaf: 42 };
    const store = await createStore(db, {
      address: 'qn1birthday',
      seedHex: '7f'.repeat(32),
      key,
      saltHex,
      iterations: 1000,
      birthday: { checkpoint, genesisHash: 'cd'.repeat(32) },
    });

    const meta = await store.meta();
    expect(meta.schemaVersion).toBe(STORE_VERSION);
    expect(meta.birthday).toEqual(checkpoint);
    expect(meta.nextLeaf).toBe(42);
    expect(meta.lastSyncedBlock).toBe(BIRTHDAY_EPOCH);
    // The genesis goes with it: a birthday is a statement about one chain, and
    // a store carrying one that named no chain would take its binding from
    // whichever node it was pointed at next.
    expect(meta.genesisHash).toBe('cd'.repeat(32));
    // And it is the store's one checkpoint, which is what the header walk
    // stands on.
    expect(await store.checkpoints()).toEqual([checkpoint]);
    db.close();
  });
});
