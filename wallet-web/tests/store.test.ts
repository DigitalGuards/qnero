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
  MIN_PASSPHRASE,
  UnreadableStoreError,
  WeakPassphraseError,
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

describe('the passphrase floor', () => {
  // The floor used to live only in the create and restore screens, as a
  // `minLength` rule. react-hook-form skips `minLength` on an empty field, so
  // both wizards accepted the empty string and sealed the spend key under a
  // key derived from it while the screen said otherwise. A screen is not a
  // boundary; this is.
  it('refuses to derive a key from a passphrase below the floor', async () => {
    const saltHex = bytesToHex(newSalt());
    await expect(deriveKey('', saltHex)).rejects.toBeInstanceOf(WeakPassphraseError);
    await expect(deriveKey('x'.repeat(MIN_PASSPHRASE - 1), saltHex)).rejects.toBeInstanceOf(
      WeakPassphraseError,
    );
  });

  it('derives from the shortest passphrase it allows', async () => {
    const saltHex = bytesToHex(newSalt());
    await expect(deriveKey('x'.repeat(MIN_PASSPHRASE), saltHex)).resolves.toBeDefined();
  });

  it('leaves no way to create a store under an empty passphrase', async () => {
    // `createStore` takes a key rather than a passphrase, and the only way to
    // a key is `deriveKey`, so the refusal above is the whole surface.
    await expect(makeStore(db, '')).rejects.toBeInstanceOf(WeakPassphraseError);
    const meta = await WalletStore.open(db);
    expect(meta).toBeNull();
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

describe('the pending row a spend writes', () => {
  it('carries no settlement bytes, because the nullifiers are readable out of them', async () => {
    // The pallet reads a settlement's nullifiers out of the proof before it
    // verifies anything, so the extrinsic in the clear published exactly what
    // `nullifier` is sealed to hold back, for every spend that did not land.
    // Nothing read the field: `waitForInclusion` takes the bytes from the
    // spend that built them.
    const store = await makeStore(db);
    await store.commitPending({
      commitment: 'cc'.repeat(32),
      kind: 'change',
      value: '700',
      submittedAtBlock: 12,
      secret: await store.sealPendingSecret('cc'.repeat(32), {
        rho: '',
        r: '',
        nullifier: '',
        memo: '',
      }),
    });
    const rows = await store.pending();
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0] ?? {}).sort()).toEqual([
      'commitment',
      'kind',
      'secret',
      'submittedAtBlock',
      'value',
    ]);
  });

  it('can be taken back, for the settlement that never lands', async () => {
    // Three ways a spend fails after the row is written: a pool that refuses
    // the envelope, a segment skipped for a stale anchor or a claimed
    // nullifier, and a settlement nothing carries inside the anchor window. In
    // all three the change commitment is never appended, so no scan can meet
    // it and clear the row, and the balance carries a pending figure that only
    // erasing the wallet removes.
    const store = await makeStore(db);
    const commitment = 'dd'.repeat(32);
    await store.commitPending({
      commitment,
      kind: 'change',
      value: '700',
      submittedAtBlock: 12,
      secret: await store.sealPendingSecret(commitment, {
        rho: '',
        r: '',
        nullifier: '',
        memo: '',
      }),
    });
    expect(await store.pending()).toHaveLength(1);
    await store.dropPending(commitment);
    expect(await store.pending()).toEqual([]);
    // And dropping one that is already gone is not an error: a sync and a
    // spend can both decide the same row is finished.
    await store.dropPending(commitment);
  });
});

describe('latching a spend', () => {
  it('marks every member of a conflict set, because they share one nullifier', async () => {
    const store = await makeStore(db);
    // A sender who repeats a `(rho, r)` pair leaves this wallet two notes with
    // one nullifier between them. At most one can settle; spending the larger
    // one and latching only that commitment leaves the smaller the sole holder
    // of a nullifier the chain has settled, and the next selection offers it.
    const larger: StoredNote = {
      ...NOTE,
      commitment: 'aa'.repeat(32),
      leafIndex: 4,
      value: '1000',
      secret: await store.sealNoteSecret('aa'.repeat(32), SECRET),
    };
    const smaller: StoredNote = {
      ...NOTE,
      commitment: 'bb'.repeat(32),
      leafIndex: 7,
      value: '400',
      secret: await store.sealNoteSecret('bb'.repeat(32), SECRET),
    };
    const other: StoredNote = {
      ...NOTE,
      commitment: 'cc'.repeat(32),
      leafIndex: 9,
      value: '250',
      secret: await store.sealNoteSecret('cc'.repeat(32), { ...SECRET, nullifier: '44'.repeat(32) }),
    };
    await store.commitSync({
      meta: await store.meta(),
      notes: [larger, smaller, other],
      removedNotes: [],
      rejected: [],
      removedRejected: [],
      checkpoints: [],
      clearedPending: [],
    });

    await store.markSpentByNullifier([SECRET.nullifier], 31);

    const after = new Map((await store.notes()).map((note) => [note.commitment, note]));
    expect(after.get(larger.commitment)?.spent).toBe(true);
    expect(after.get(smaller.commitment)?.spent).toBe(true);
    expect(after.get(larger.commitment)?.spentSeenAtBlock).toBe(31);
    // A nullifier this settlement did not publish is untouched.
    expect(after.get(other.commitment)?.spent).toBe(false);
  });

  it('takes a nullifier however it was written', async () => {
    const store = await makeStore(db);
    const only: StoredNote = {
      ...NOTE,
      secret: await store.sealNoteSecret(NOTE.commitment, SECRET),
    };
    await store.commitSync({
      meta: await store.meta(),
      notes: [only],
      removedNotes: [],
      rejected: [],
      removedRejected: [],
      checkpoints: [],
      clearedPending: [],
    });
    await store.markSpentByNullifier([`0x${SECRET.nullifier.toUpperCase()}`], 12);
    expect((await store.notes())[0]?.spent).toBe(true);
  });
});

describe('writing a note off', () => {
  async function withNote(overrides: Partial<StoredNote>): Promise<WalletStore> {
    const store = await makeStore(db);
    await store.commitSync({
      meta: await store.meta(),
      notes: [{ ...NOTE, ...overrides, secret: await store.sealNoteSecret(NOTE.commitment, SECRET) }],
      removedNotes: [],
      rejected: [],
      removedRejected: [],
      checkpoints: [],
      clearedPending: [],
    });
    return store;
  }

  it('marks a held note the chain does not carry', async () => {
    const store = await withNote({});
    expect(await store.markOffChain(NOTE.commitment)).toBe(true);
    expect((await store.notes())[0]?.onChain).toBe(false);
  });

  it('refuses a spent note, whose value is already gone', async () => {
    const store = await withNote({ spent: true, spentSeenAtBlock: 9 });
    expect(await store.markOffChain(NOTE.commitment)).toBe(false);
    expect((await store.notes())[0]?.onChain).toBe(true);
  });

  it('says nothing happened for a note it does not hold', async () => {
    const store = await withNote({});
    expect(await store.markOffChain('ff'.repeat(32))).toBe(false);
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
  it('clears every record, closes the handle and deletes the database', async () => {
    const store = await makeStore(db);
    await store.destroy();

    // The handle is closed with the database it pointed at, so a read through
    // it is an error rather than an empty answer. "Erase everything" promised
    // more than `clear()` keeps: an IndexedDB clear removes what the API can
    // see and leaves the freed records in the backing store, so the sealed
    // seed could still be in the profile directory after the dialog said
    // otherwise.
    await expect(store.notes()).rejects.toThrow();

    const fresh = await openDatabase();
    try {
      expect(await WalletStore.open(fresh)).toBeNull();
      expect(await WalletStore.locked(fresh, ADDRESS).notes()).toHaveLength(0);
    } finally {
      fresh.close();
    }
  });
});
