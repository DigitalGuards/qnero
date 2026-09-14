/**
 * The store: what it seals, what it does not, and what it refuses.
 *
 * The encryption primitives are covered in `crypto.test.ts`. What is here is
 * the store's own contract: a note's four secret fields go in sealed and come
 * back only under the passphrase, a locked store still answers a balance, one
 * wallet's envelope does not open in another's slot, and a schema from the
 * future is a named refusal rather than a deserialization that happens to
 * match on the fields it knows.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  deriveKey,
  newSalt,
  bytesToHex,
  UnreadableStoreError,
  WrongPassphraseError,
} from '../src/wallet/crypto';
import {
  checkVersion,
  createStore,
  openDatabase,
  WalletStore,
  DB_NAME,
} from '../src/wallet/store';
import { STORE_VERSION, type StoredNote } from '../src/wallet/model';

const ADDRESS = 'qn1testwallet';
const SEED_HEX = '7f'.repeat(32);
const PASSPHRASE = 'correct horse battery staple';

/**
 * A fresh database per test.
 *
 * `fake-indexeddb` keeps one database per process, so the delete has to happen
 * with no connection open to it: an open handle blocks the delete rather than
 * failing it, and a blocked delete is a hook that hangs until its timeout.
 */
async function freshDatabase(): Promise<IDBDatabase> {
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
  return openDatabase();
}

async function makeStore(db: IDBDatabase, passphrase = PASSPHRASE): Promise<WalletStore> {
  const saltHex = bytesToHex(newSalt());
  const key = await deriveKey(passphrase, saltHex);
  return createStore(db, {
    address: ADDRESS,
    seedHex: SEED_HEX,
    key,
    saltHex,
    // The real iteration count is 600,000 and it is a second of work per
    // unlock. These tests derive a key several times, so they state a lower
    // one rather than testing the constant, which `crypto.test.ts` does.
    iterations: 1000,
  });
}

const NOTE: StoredNote = {
  commitment: 'ab'.repeat(32),
  leafIndex: 4,
  blockNumber: 9,
  value: '1000',
  origin: 'transfer',
  spent: false,
  spentSeenAtBlock: null,
  onChain: true,
  secret: { v: 1, iv: '', ct: '' },
};

const SECRET = {
  rho: '11'.repeat(32),
  r: '22'.repeat(32),
  nullifier: '33'.repeat(32),
  memo: 'lunch',
};

let db: IDBDatabase;

beforeEach(async () => {
  db = await freshDatabase();
});

afterEach(() => {
  db.close();
});

describe('a new store', () => {
  it('holds the seed sealed and gives it back under the passphrase', async () => {
    const store = await makeStore(db);
    expect(bytesToHex(await store.seed())).toBe(SEED_HEX);
  });

  it('records no genesis until something commits', async () => {
    const store = await makeStore(db);
    // Binding at open pins a fresh wallet to whichever node it was first
    // pointed at, including one the very next gate refuses.
    expect((await store.meta()).genesisHash).toBeNull();
  });

  it('writes the schema version the command-line wallet is at', async () => {
    const store = await makeStore(db);
    expect((await store.meta()).schemaVersion).toBe(STORE_VERSION);
  });
});

describe("a note's secrets", () => {
  it('round-trip through the seal', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    expect(await store.openNoteSecret({ ...NOTE, secret: sealed })).toEqual(SECRET);
  });

  it('carry none of the four fields in the clear', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    const wire = JSON.stringify(sealed);
    expect(wire).not.toContain(SECRET.rho);
    expect(wire).not.toContain(SECRET.r);
    expect(wire).not.toContain(SECRET.nullifier);
    expect(wire).not.toContain(SECRET.memo);
  });

  it('do not open in another note\'s slot', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    await expect(
      store.openNoteSecret({ ...NOTE, commitment: 'cd'.repeat(32), secret: sealed }),
    ).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('do not open under another passphrase', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    const other = WalletStore.unlocked(
      db,
      ADDRESS,
      await deriveKey('a different passphrase', bytesToHex(newSalt())),
    );
    await expect(other.openNoteSecret({ ...NOTE, secret: sealed })).rejects.toBeInstanceOf(
      WrongPassphraseError,
    );
  });
});

describe('a locked store', () => {
  it('still answers the balance fields, and refuses the sealed ones', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    await store.commitSync({
      meta: { ...(await store.meta()), lastSyncedBlock: 9, nextLeaf: 5 },
      notes: [{ ...NOTE, secret: sealed }],
      removedNotes: [],
      rejected: [],
      removedRejected: [],
      checkpoints: [{ blockNumber: 9, blockHash: 'ff'.repeat(32), nextLeaf: 5 }],
      clearedPending: [],
    });
    store.lock();

    const notes = await store.notes();
    expect(notes).toHaveLength(1);
    // Value, leaf index and state are deliberately in the clear: that is what
    // lets a locked wallet show a balance and still sync.
    expect(notes[0]?.value).toBe('1000');
    expect(notes[0]?.leafIndex).toBe(4);
    expect(await store.checkpoints()).toHaveLength(1);
    await expect(store.seed()).rejects.toThrow(/locked/);
  });
});

describe('one sync commits as one transaction', () => {
  it('writes the meta, the notes and the checkpoints together', async () => {
    const store = await makeStore(db);
    const sealed = await store.sealNoteSecret(NOTE.commitment, SECRET);
    const meta = await store.meta();
    await store.commitSync({
      meta: { ...meta, genesisHash: '0x' + '11'.repeat(32), lastSyncedBlock: 12, nextLeaf: 8 },
      notes: [{ ...NOTE, secret: sealed }],
      removedNotes: [],
      rejected: [{ commitment: 'ee'.repeat(32), leafIndex: 6, value: '5', reason: 'settled' }],
      removedRejected: [],
      checkpoints: [{ blockNumber: 12, blockHash: 'aa'.repeat(32), nextLeaf: 8 }],
      clearedPending: [],
    });

    expect((await store.meta()).nextLeaf).toBe(8);
    expect(await store.notes()).toHaveLength(1);
    expect(await store.rejected()).toHaveLength(1);
    expect((await store.checkpoints())[0]?.blockNumber).toBe(12);
  });

  it('keeps at most sixteen checkpoints, newest last', async () => {
    const store = await makeStore(db);
    const meta = await store.meta();
    const checkpoints = Array.from({ length: 20 }, (_value, index) => ({
      blockNumber: index,
      blockHash: `${index}`.padStart(64, '0'),
      nextLeaf: index,
    }));
    await store.commitSync({
      meta,
      notes: [],
      removedNotes: [],
      rejected: [],
      removedRejected: [],
      checkpoints,
      clearedPending: [],
    });
    const kept = await store.checkpoints();
    expect(kept).toHaveLength(16);
    expect(kept[0]?.blockNumber).toBe(4);
    expect(kept.at(-1)?.blockNumber).toBe(19);
  });
});

describe('the version gate', () => {
  it('refuses a store written by a newer build, by name', () => {
    expect(() => {
      checkVersion(STORE_VERSION + 1);
    }).toThrow(UnreadableStoreError);
  });

  it('refuses a store older than the oldest upgrade this build carries', () => {
    expect(() => {
      checkVersion(1);
    }).toThrow(UnreadableStoreError);
  });

  it('accepts the version it writes', () => {
    expect(() => {
      checkVersion(STORE_VERSION);
    }).not.toThrow();
  });
});

describe('erasing the wallet', () => {
  it('leaves nothing behind, seed included', async () => {
    const store = await makeStore(db);
    await store.destroy();
    expect(await store.notes()).toHaveLength(0);
    expect(await WalletStore.open(db)).toBeNull();
  });
});
