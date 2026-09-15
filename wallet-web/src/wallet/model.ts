/**
 * The store's shape, field for field the CLI's.
 *
 * `crates/qnero-wallet/src/store.rs` is the definition and `STORE_VERSION` is
 * 6 there, so it is 6 here. Two wallets that disagree about what a note is are
 * two wallets that disagree about a balance, and the version gate exists so
 * that disagreement is a named refusal rather than a deserialization failure
 * that mentions one field.
 *
 * # What is encrypted and what is not
 *
 * Encrypted, each in its own envelope: `rho`, `r`, `nullifier`, `memo`. Those
 * four are the CLI's redacted set, and a pending row's settlement bytes were a
 * fifth until they were dropped: see [`PendingNote`]. `rho` and `r` beside a published nullifier
 * link a settled spend to its note, its value and its recipient; an unspent
 * note's nullifier has appeared nowhere at all, which is exactly why it is
 * held back.
 *
 * Plaintext, deliberately: `commitment` (the chain published it beside the
 * leaf), `leafIndex` (it names a leaf this wallet owns, which carries weight,
 * and it predicts nothing the wallet has yet to publish), `blockNumber`,
 * `value`, `origin`, `spent`, `spentSeenAtBlock`, `onChain`, the genesis
 * binding and every checkpoint. Keeping those in the clear is what lets a
 * locked wallet still show a balance and still sync: only spending needs the
 * vault open.
 *
 * That is a choice and it is stated rather than assumed. A threat model that
 * wants the value graph hidden too would encrypt `value` and `leafIndex` as
 * well, and would then need the passphrase to sync or to show a balance.
 */

import type { Envelope } from './crypto';

/** `crates/qnero-wallet/src/store.rs`'s `STORE_VERSION`. */
export const STORE_VERSION = 7;

/** The oldest schema this build upgrades rather than refuses. */
export const OLDEST_UPGRADABLE_VERSION = 2;

export type NoteOrigin = 'shield' | 'transfer' | 'coinbase' | 'change';

/** One note, as the store holds it. */
export interface StoredNote {
  /** The key. The chain published this beside the leaf. */
  commitment: string;
  leafIndex: number;
  blockNumber: number | null;
  value: string;
  origin: NoteOrigin;
  spent: boolean;
  /**
   * The head the sync that set `spent` was pinned to. `UsedNullifiers` carries
   * no height, so the block that settled it is unknown to the wallet. It is what makes clearing
   * the flag safe, because an absent nullifier below this height is an
   * orphaned settlement and above it is a node that has not got there yet.
   */
  spentSeenAtBlock: number | null;
  /**
   * False for a note whose leaf a reorg took away. Kept with its secrets and
   * its index, because a later block can re-include the identical commitment,
   * and out of every balance and every selection until it does.
   */
  onChain: boolean;
  /** `{rho, r, nullifier, memo}`, sealed. */
  secret: Envelope;
}

/** The four fields a note keeps behind the passphrase. */
export interface NoteSecret {
  rho: string;
  r: string;
  nullifier: string;
  memo: string;
}

/**
 * A note this wallet has written but the chain has not confirmed.
 *
 * The settlement's own bytes are deliberately **not** here. They used to be,
 * in the clear, and the pallet reads a settlement's nullifiers straight out of
 * the proof before it verifies anything, so a plaintext copy of them published
 * exactly what `nullifier` is sealed to hold back: on every path where the
 * settlement does not land, the input notes stay unspent and selectable while
 * their nullifiers sit in a plaintext field forever. Nothing read the field.
 * `waitForInclusion` takes the bytes as an argument, from the spend that built
 * them.
 *
 * `submittedAtBlock` is the anchor. A settlement anchored more than
 * `BlockHashWindow` blocks below the head can never be admitted, which is how
 * a sync knows a pending row is never going to clear.
 */
export interface PendingNote {
  commitment: string;
  kind: 'change' | 'payment' | 'shield';
  value: string;
  submittedAtBlock: number;
  secret: Envelope;
}

/**
 * A note whose nullifier the chain had already settled when it arrived.
 *
 * Provisional, and it says so: a later scan that ends up holding the note
 * drops the entry. The reason is kept because it is the one refusal a scan
 * makes about a note somebody sent this wallet.
 */
export interface RejectedNote {
  commitment: string;
  leafIndex: number;
  value: string;
  reason: string;
}

/** One sync's evidence that the node was on this chain at that height. */
export interface SyncCheckpoint {
  blockNumber: number;
  blockHash: string;
  nextLeaf: number;
}

/** At most this many checkpoints are kept, newest last. */
export const MAX_CHECKPOINTS = 16;

/**
 * How coarse a recorded birthday is, in blocks.
 *
 * A birthday is a public number: it is the bottom of the header walk, so every
 * node this wallet ever syncs against is told it. Recorded exactly, it is the
 * wallet's creation time to the block, which is a fingerprint that follows the
 * wallet across nodes and across syncs. Rounded down to a multiple of this, it
 * is a coarse epoch that a great many wallets share, and at the public chain's
 * 120 s target one epoch is a day and a half.
 *
 * Rounded **down**, always, on both paths: a birthday above the block a note
 * arrived in is a note the wallet never reads. `crates/qnero-wallet/src/
 * store.rs` carries the same number, which is `HEADER_WALK_LIMIT`, so one
 * epoch is one chunk of the walk.
 */
export const BIRTHDAY_EPOCH = 1024;

/** The epoch a height sits in: the height itself, rounded down. */
export function birthdayEpochOf(height: number): number {
  return height - (height % BIRTHDAY_EPOCH);
}

/** The plaintext head of the store. */
export interface StoreMeta {
  id: 'store';
  schemaVersion: number;
  address: string;
  /**
   * `chain_getBlockHash(0)`, recorded by the first operation that commits
   * rather than at open.
   *
   * Binding at open pinned a fresh store to whichever node it was first
   * pointed at, including one the very next check refused. It does not catch a
   * restarted `--dev --tmp` node, which has the same fixed spec and therefore
   * the same genesis; the checkpoint walk and the leaf gate catch that.
   */
  genesisHash: string | null;
  /**
   * The block this wallet was created or restored at, and the leaf count the
   * chain held there.
   *
   * A wallet cannot have received a note into a leaf that existed before it
   * did, so a wallet that records where it started never walks or scans the
   * history below it. What that saves is the header walk under the birthday
   * and every ciphertext under its leaf count; what it does not save is the
   * leaf hashes under the watermark, which the first sync still reads to seed
   * the fold, and that read is what checks this recorded leaf count against
   * the birthday block's own `zkTreeRoot`.
   *
   * **It is the node's claim, like every checkpoint.** Nothing verified this
   * hash when it was written, so a wallet created against a node serving a
   * branch of its own records that branch's block; the first honest node
   * disagrees at that height, the fork walk rewinds and the scan starts lower.
   * A restore height somebody types is a second claim on top, and a wrong one
   * costs notes rather than time: `docs/WALLET.md` says what.
   *
   * `null` in a store written before schema 7, and in one restored with no
   * height, and either way that is a full scan from leaf zero. It is written
   * into `checkpoints` as well, which is what the header walk stands on.
   */
  birthday: SyncCheckpoint | null;
  lastSyncedBlock: number;
  /** The leaf watermark: the first index the next scan reads. */
  nextLeaf: number;
  kdf: { name: 'PBKDF2'; hash: 'SHA-256'; iterations: number; saltHex: string };
  createdAt: number;
  updatedAt: number;
  /** Which upgrades have run, so a store says what happened to it. */
  upgrades: string[];
}

export interface Balances {
  /** Unspent, on chain, one member per nullifier conflict set. */
  unspent: bigint;
  /** Written by this wallet and not yet confirmed. */
  pending: bigint;
  /** Held, with secrets, but whose leaf a reorg took away. */
  offChain: bigint;
  /** What one spend can actually reach: the two largest spendable notes. */
  reachable: bigint;
  noteCount: number;
}

/** A note with the fields a screen needs, secrets opened. */
export interface NoteRow {
  note: StoredNote;
  secret: NoteSecret | null;
  /** How many notes share this nullifier. One unless the sender repeated a pair. */
  conflictMembers: number;
}
