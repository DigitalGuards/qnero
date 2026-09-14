/**
 * The store, in IndexedDB.
 *
 * The CLI writes one JSON document at mode 0600 through a `create_new` temp
 * file, renames it and fsyncs the directory. IndexedDB replaces that dance
 * with a transaction: a write that spans two object stores either lands whole
 * or does not land, which is exactly what the rename was for.
 *
 * What it does not replace is durability against the browser. IndexedDB is
 * evictable, and while it stands it is the fastest copy of every note's `r`.
 * [`requestPersistence`] asks for the origin to be exempt and the settings
 * screen reports the answer, which may be no. The answer to an eviction is the
 * seed: every note's plaintext is on the chain inside its ciphertext, so a
 * fresh store re-derives every note from a rescan. What it loses is the spent
 * history, which comes back as the refusals that rescan records, and the time
 * a full rescan costs.
 *
 * # Ordering rules that are not about storage
 *
 * The pending change note of a spend is written **before**
 * `author_submitExtrinsic`, in one committed transaction. The row seals no
 * randomness (`wallet/send.ts` rule 8): it is a claim that the note exists, so
 * a tab reclaimed between the submit and the write shows a balance missing its
 * own change until the next sync reaches the leaf.
 */

import {
  openJson,
  recordAad,
  sealJson,
  type Envelope,
  UnreadableStoreError,
} from './crypto';
import {
  MAX_CHECKPOINTS,
  OLDEST_UPGRADABLE_VERSION,
  STORE_VERSION,
  type NoteSecret,
  type PendingNote,
  type RejectedNote,
  type StoreMeta,
  type StoredNote,
  type SyncCheckpoint,
} from './model';

export const DB_NAME = 'qnero-wallet';
export const DB_VERSION = 1;

export const STORE_META = 'meta';
export const STORE_NOTES = 'notes';
export const STORE_PENDING = 'pending';
export const STORE_REJECTED = 'rejected';
export const STORE_CHECKPOINTS = 'checkpoints';
export const STORE_VAULT = 'vault';

const ALL_STORES = [
  STORE_META,
  STORE_NOTES,
  STORE_PENDING,
  STORE_REJECTED,
  STORE_CHECKPOINTS,
  STORE_VAULT,
] as const;

/**
 * One IndexedDB request as a promise.
 *
 * `IDBObjectStore.get` is typed `IDBRequest<any>` by the DOM library, so the
 * narrowing happens here, once, rather than at every call site. The shape a
 * record comes back in is whatever was written to it: this store is the only
 * writer, and the version gate is what guards against another build's shape.
 */
function request<T>(source: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    source.onsuccess = (): void => {
      resolve(source.result as T);
    };
    source.onerror = (): void => {
      reject(source.error ?? new Error('the store refused a read'));
    };
  });
}

/** Hashes compare as lower-case hex without a prefix, wherever they came from. */
function normaliseHash(hash: string): string {
  return hash.toLowerCase().replace(/^0x/, '');
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = (): void => {
      resolve();
    };
    transaction.onabort = (): void => {
      reject(transaction.error ?? new Error('the store aborted a write'));
    };
    transaction.onerror = (): void => {
      reject(transaction.error ?? new Error('the store refused a write'));
    };
  });
}

export function openDatabase(factory: IDBFactory = indexedDB): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = factory.open(DB_NAME, DB_VERSION);
    open.onupgradeneeded = (): void => {
      const db = open.result;
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_NOTES)) {
        const notes = db.createObjectStore(STORE_NOTES, { keyPath: 'commitment' });
        notes.createIndex('byLeaf', 'leafIndex', { unique: false });
        notes.createIndex('bySpent', 'spent', { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_PENDING)) {
        db.createObjectStore(STORE_PENDING, { keyPath: 'commitment' });
      }
      if (!db.objectStoreNames.contains(STORE_REJECTED)) {
        db.createObjectStore(STORE_REJECTED, { keyPath: 'commitment' });
      }
      if (!db.objectStoreNames.contains(STORE_CHECKPOINTS)) {
        db.createObjectStore(STORE_CHECKPOINTS, { keyPath: 'blockNumber' });
      }
      if (!db.objectStoreNames.contains(STORE_VAULT)) {
        db.createObjectStore(STORE_VAULT, { keyPath: 'id' });
      }
    };
    open.onsuccess = (): void => {
      resolve(open.result);
    };
    open.onerror = (): void => {
      reject(open.error ?? new Error('IndexedDB refused to open'));
    };
  });
}

/**
 * Delete the database itself, after its stores have been cleared.
 *
 * `onblocked` fires when another tab still holds the database open. The delete
 * then completes whenever that tab closes and there is nothing useful to wait
 * for here, so this resolves and the caller carries on: the records this call
 * came to remove are already gone.
 */
function deleteDatabase(factory: IDBFactory = indexedDB): Promise<void> {
  return new Promise((resolve) => {
    const request_ = factory.deleteDatabase(DB_NAME);
    request_.onsuccess = (): void => {
      resolve();
    };
    request_.onblocked = (): void => {
      resolve();
    };
    request_.onerror = (): void => {
      resolve();
    };
  });
}

/**
 * Ask the browser not to evict this origin.
 *
 * Without it a browser under storage pressure can drop everything here: the
 * sealed seed, every note and the record of which ones are spent. What comes
 * back from a written-down seed is every note, by rescanning the chain; what
 * does not is the spent history, which returns as refusals. The answer may be
 * no, and the caller says so rather than assuming.
 */
export async function requestPersistence(): Promise<boolean> {
  if (typeof navigator === 'undefined') {
    return false;
  }
  try {
    return await navigator.storage.persist();
  } catch {
    return false;
  }
}

/** A handle to one open store, with the key that opens its records. */
export class WalletStore {
  private constructor(
    readonly db: IDBDatabase,
    readonly address: string,
    private key: CryptoKey | null,
  ) {}

  /** Open an existing store, or report that there is none. */
  static async open(db: IDBDatabase): Promise<{ meta: StoreMeta } | null> {
    const transaction = db.transaction(STORE_META, 'readonly');
    const meta = await request<StoreMeta | undefined>(
      transaction.objectStore(STORE_META).get('store'),
    );
    if (meta === undefined) {
      return null;
    }
    checkVersion(meta.schemaVersion);
    return { meta };
  }

  /** An open store, once a passphrase has produced a key. */
  static unlocked(db: IDBDatabase, address: string, key: CryptoKey): WalletStore {
    return new WalletStore(db, address, key);
  }

  /** A store that can be read but not opened: balances without a passphrase. */
  static locked(db: IDBDatabase, address: string): WalletStore {
    return new WalletStore(db, address, null);
  }

  get isUnlocked(): boolean {
    return this.key !== null;
  }

  /** Drop the key handle. Everything sealed becomes unreadable this session. */
  lock(): void {
    this.key = null;
  }

  private requireKey(): CryptoKey {
    if (this.key === null) {
      throw new Error('this wallet is locked');
    }
    return this.key;
  }

  async meta(): Promise<StoreMeta> {
    const transaction = this.db.transaction(STORE_META, 'readonly');
    const meta = await request<StoreMeta | undefined>(
      transaction.objectStore(STORE_META).get('store'),
    );
    if (meta === undefined) {
      throw new Error('this database holds no wallet');
    }
    return meta;
  }

  async putMeta(meta: StoreMeta): Promise<void> {
    const transaction = this.db.transaction(STORE_META, 'readwrite');
    transaction.objectStore(STORE_META).put({ ...meta, updatedAt: Date.now() });
    await transactionDone(transaction);
  }

  async notes(): Promise<StoredNote[]> {
    const transaction = this.db.transaction(STORE_NOTES, 'readonly');
    return request<StoredNote[]>(transaction.objectStore(STORE_NOTES).getAll());
  }

  async pending(): Promise<PendingNote[]> {
    const transaction = this.db.transaction(STORE_PENDING, 'readonly');
    return request<PendingNote[]>(transaction.objectStore(STORE_PENDING).getAll());
  }

  async rejected(): Promise<RejectedNote[]> {
    const transaction = this.db.transaction(STORE_REJECTED, 'readonly');
    return request<RejectedNote[]>(transaction.objectStore(STORE_REJECTED).getAll());
  }

  async checkpoints(): Promise<SyncCheckpoint[]> {
    const transaction = this.db.transaction(STORE_CHECKPOINTS, 'readonly');
    const all = await request<SyncCheckpoint[]>(
      transaction.objectStore(STORE_CHECKPOINTS).getAll(),
    );
    return all.sort((a, b) => a.blockNumber - b.blockNumber);
  }

  /** The sealed seed. Unsealing it needs the key this store was unlocked with. */
  async seed(): Promise<Uint8Array> {
    const transaction = this.db.transaction(STORE_VAULT, 'readonly');
    const record = await request<{ id: string; secret: Envelope } | undefined>(
      transaction.objectStore(STORE_VAULT).get('seed'),
    );
    if (record === undefined) {
      throw new UnreadableStoreError('this wallet holds no seed');
    }
    const hex = await openJson<string>(
      this.requireKey(),
      recordAad(this.address, STORE_VAULT, 'seed'),
      record.secret,
    );
    const bytes = new Uint8Array(32);
    for (let index = 0; index < 32; index += 1) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  async sealNoteSecret(commitment: string, secret: NoteSecret): Promise<Envelope> {
    return sealJson(this.requireKey(), recordAad(this.address, STORE_NOTES, commitment), secret);
  }

  async openNoteSecret(note: StoredNote): Promise<NoteSecret> {
    return openJson<NoteSecret>(
      this.requireKey(),
      recordAad(this.address, STORE_NOTES, note.commitment),
      note.secret,
    );
  }

  async sealPendingSecret(commitment: string, secret: NoteSecret): Promise<Envelope> {
    return sealJson(this.requireKey(), recordAad(this.address, STORE_PENDING, commitment), secret);
  }

  async openPendingSecret(pending: PendingNote): Promise<NoteSecret> {
    return openJson<NoteSecret>(
      this.requireKey(),
      recordAad(this.address, STORE_PENDING, pending.commitment),
      pending.secret,
    );
  }

  /**
   * One sync's whole result, written as one transaction.
   *
   * A sync that refuses leaves the store exactly as it found it, in memory and
   * on disk, checkpoints and genesis binding included. That is what "nothing
   * is written until all the gates pass" means, and a transaction is what
   * enforces it here.
   */
  async commitSync(update: {
    meta: StoreMeta;
    notes: StoredNote[];
    removedNotes: string[];
    rejected: RejectedNote[];
    removedRejected: string[];
    checkpoints: SyncCheckpoint[];
    clearedPending: string[];
  }): Promise<void> {
    const transaction = this.db.transaction(
      [STORE_META, STORE_NOTES, STORE_REJECTED, STORE_CHECKPOINTS, STORE_PENDING],
      'readwrite',
    );
    transaction.objectStore(STORE_META).put({ ...update.meta, updatedAt: Date.now() });
    const notes = transaction.objectStore(STORE_NOTES);
    for (const commitment of update.removedNotes) {
      notes.delete(commitment);
    }
    for (const note of update.notes) {
      notes.put(note);
    }
    const rejected = transaction.objectStore(STORE_REJECTED);
    for (const commitment of update.removedRejected) {
      rejected.delete(commitment);
    }
    for (const entry of update.rejected) {
      rejected.put(entry);
    }
    const checkpoints = transaction.objectStore(STORE_CHECKPOINTS);
    checkpoints.clear();
    for (const checkpoint of update.checkpoints.slice(-MAX_CHECKPOINTS)) {
      checkpoints.put(checkpoint);
    }
    const pending = transaction.objectStore(STORE_PENDING);
    for (const commitment of update.clearedPending) {
      pending.delete(commitment);
    }
    await transactionDone(transaction);
  }

  /**
   * The change note of a spend, written before the extrinsic goes out.
   *
   * One transaction over both stores. The note is pending until a sync meets
   * it in the tree, and its `r` exists nowhere else in the world.
   */
  async commitPending(pending: PendingNote): Promise<void> {
    const transaction = this.db.transaction([STORE_PENDING], 'readwrite');
    transaction.objectStore(STORE_PENDING).put(pending);
    await transactionDone(transaction);
  }

  /**
   * Drop a pending row.
   *
   * Written before the submission, and there are three ways the submission
   * then does not land: the pool refuses the envelope, the segment is skipped
   * for a stale anchor or a claimed nullifier, or nothing carries it inside
   * the anchor window. In all three the change commitment is never appended,
   * so no scan can ever meet it and clear the row, and the balance carries a
   * pending figure that never resolves on a screen whose whole job is one
   * number.
   *
   * Dropping is safe even when the bytes did reach the pool: the next scan
   * that meets the leaf adds the note as a real one, out of the ciphertext the
   * chain carries.
   */
  async dropPending(commitment: string): Promise<void> {
    const transaction = this.db.transaction([STORE_PENDING], 'readwrite');
    transaction.objectStore(STORE_PENDING).delete(commitment);
    await transactionDone(transaction);
  }

  /**
   * Latch a spent flag at submit time, keyed on the nullifier.
   *
   * Once both nullifiers are confirmed settled at the inclusion block, the
   * notes they came from are spent whatever the next sync reads, so a send
   * that happens before the next sync cannot select the same input twice.
   *
   * On the nullifier rather than on the commitment, because a nullifier can
   * belong to more than one held note. A sender who repeats a `(rho, r)` pair
   * gives this wallet two notes sharing one nullifier, of which at most one
   * can ever settle. Latching only the member that was spent leaves the other
   * unspent and on chain, so it is the sole holder of that nullifier and the
   * next selection offers it: a whole proof paid for a nullifier the chain has
   * already settled. `WalletStore::mark_spent` in the command-line wallet
   * walks every note whose nullifier matches for the same reason.
   *
   * The secrets are opened outside the write, because an IndexedDB transaction
   * closes when its microtask queue drains and WebCrypto is slower than that.
   */
  async markSpentByNullifier(nullifiers: readonly string[], atBlock: number): Promise<void> {
    const wanted = new Set(nullifiers.map(normaliseHash));
    const held = await this.notes();
    const hits: StoredNote[] = [];
    for (const note of held) {
      if (note.spent) {
        continue;
      }
      let secret: NoteSecret;
      try {
        secret = await this.openNoteSecret(note);
      } catch {
        // A record this key cannot open. It keeps its flags: a note whose
        // secrets are unreadable is one nothing can select anyway.
        continue;
      }
      if (wanted.has(normaliseHash(secret.nullifier))) {
        hits.push(note);
      }
    }
    if (hits.length === 0) {
      return;
    }
    const transaction = this.db.transaction(STORE_NOTES, 'readwrite');
    const notes = transaction.objectStore(STORE_NOTES);
    for (const note of hits) {
      notes.put({ ...note, spent: true, spentSeenAtBlock: atBlock });
    }
    await transactionDone(transaction);
  }

  /**
   * Write a note off as one the chain does not carry.
   *
   * The spend path's answer to a selected note sitting past the end of a tree
   * whose root the anchor confirms, recorded at a block strictly below that
   * anchor. Reporting that and writing nothing leaves selection picking the
   * same phantom on every retry, because selection is largest first and the
   * phantom does not move. `Wallet::send` wraps its own preparation in
   * `write_off_missing_note` for exactly this.
   *
   * The gate is `mark_off_chain`'s: a spent note is never marked off chain,
   * because its value is already gone and `off chain` is the heading for value
   * the chain may still honour.
   */
  async markOffChain(commitment: string): Promise<boolean> {
    const read = this.db.transaction(STORE_NOTES, 'readonly');
    const existing = await request<StoredNote | undefined>(
      read.objectStore(STORE_NOTES).get(commitment),
    );
    if (existing === undefined || existing.spent || !existing.onChain) {
      return false;
    }
    const transaction = this.db.transaction(STORE_NOTES, 'readwrite');
    transaction.objectStore(STORE_NOTES).put({ ...existing, onChain: false });
    await transactionDone(transaction);
    return true;
  }

  /**
   * Erase the whole wallet, seed included, and take the database with it.
   *
   * `clear()` alone removes what the API can see and leaves the freed records
   * in the backing store until the browser compacts, which is not what
   * "erases the encrypted seed and every note from this browser" promises to
   * somebody wiping a wallet before handing the machine on. So the stores are
   * cleared first, in one transaction, and then the database itself is
   * deleted: the clear is what makes the promise hold even if the delete is
   * blocked by another tab.
   *
   * The handle is closed on the way, so the caller reopens. A delete blocked
   * by a second tab is reported as done rather than waited on forever: the
   * records are already gone.
   */
  async destroy(): Promise<void> {
    const transaction = this.db.transaction([...ALL_STORES], 'readwrite');
    for (const store of ALL_STORES) {
      transaction.objectStore(store).clear();
    }
    await transactionDone(transaction);
    this.lock();
    this.db.close();
    await deleteDatabase();
  }
}

/**
 * Create a store for a seed, sealed under a passphrase.
 *
 * `genesisHash` is deliberately null: it is recorded by the first operation
 * that commits, never at open. See [`StoreMeta.genesisHash`].
 */
export async function createStore(
  db: IDBDatabase,
  options: {
    address: string;
    seedHex: string;
    key: CryptoKey;
    saltHex: string;
    iterations: number;
  },
): Promise<WalletStore> {
  const store = WalletStore.unlocked(db, options.address, options.key);
  const secret = await sealJson(
    options.key,
    recordAad(options.address, STORE_VAULT, 'seed'),
    options.seedHex,
  );
  const now = Date.now();
  const meta: StoreMeta = {
    id: 'store',
    schemaVersion: STORE_VERSION,
    address: options.address,
    genesisHash: null,
    lastSyncedBlock: 0,
    nextLeaf: 0,
    kdf: {
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations: options.iterations,
      saltHex: options.saltHex,
    },
    createdAt: now,
    updatedAt: now,
    upgrades: [],
  };
  const transaction = db.transaction([STORE_META, STORE_VAULT], 'readwrite');
  transaction.objectStore(STORE_META).put(meta);
  transaction.objectStore(STORE_VAULT).put({ id: 'seed', secret });
  await transactionDone(transaction);
  return store;
}

/**
 * The version gate, with the CLI's answers.
 *
 * A store written by a newer build is refused by name rather than
 * deserialized into whatever fields happen to match. A store at version 1 is
 * refused outright, because the upgrade from it was never written and guessing
 * at it would silently change what a note means.
 */
export function checkVersion(version: number): void {
  if (version > STORE_VERSION) {
    throw new UnreadableStoreError(
      `this wallet was written by a newer build (store version ${version}, this build reads ` +
        `${STORE_VERSION}). Update the app rather than letting it guess at the fields it does ` +
        'not know.',
    );
  }
  if (version < OLDEST_UPGRADABLE_VERSION) {
    throw new UnreadableStoreError(
      `this wallet is at store version ${version} and the oldest one this build upgrades is ` +
        `${OLDEST_UPGRADABLE_VERSION}. Restore from the seed instead.`,
    );
  }
}
