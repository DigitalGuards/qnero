/**
 * One sync pass, rule for rule from `crates/qnero-wallet/src/wallet.rs`.
 *
 * The order is the whole of it. Nothing is written until every gate has
 * passed, and a refusal leaves the store exactly as it was found, genesis
 * binding and checkpoints included:
 *
 * 1. Genesis binding: the store records `chain_getBlockHash(0)` and every
 *    later pass refuses a node answering a different one.
 * 2. The checkpoint-hash fork walk, which answers both questions a node has to
 *    be asked: is it on this wallet's chain, and has it reached everything
 *    this wallet has already read.
 * 3. The leaf-count gate: a node can be on this chain, above every checkpoint,
 *    and still answer short because it has not finished *executing* its head.
 * 4. The scan, pinned to one block hash.
 * 5. Spent reconciliation, derived afresh from the whole paged set, in both
 *    directions.
 * 6. The vanished-note marking, which runs **after** the flags are derived.
 *
 * This module reads and decides; it writes nothing. The caller commits what it
 * returns in one transaction, which is what makes rule 7 hold.
 *
 * # Why the node learns nothing
 *
 * Two properties, and both are about the requests rather than the answers, so
 * no assertion over an answer can see them. `tests/privacy.test.ts` drives
 * this module with a recording transport and asserts them at the seam.
 *
 * - No request names a nullifier. The settled set is paged whole and every
 *   spent decision is local. `UsedNullifiers` is `Blake2_128Concat`, so a
 *   point lookup carries the raw value, and a node that logged those would
 *   hold the set of values this wallet will publish when it spends.
 * - No request names one of this wallet's leaves. Held notes are never
 *   re-read at their recorded index to check they are still there, which is
 *   the obvious optimisation and the one that names them. `chain_getBlockHash`
 *   at a height names nothing, which is why the orphan check goes through
 *   checkpoints.
 */

import { anchorFromHeader, authorLabelFromHeader, type Anchor, type RawChainHeader } from '../chain/anchor';
import { bytesToHex, normaliseHash } from '../lib/hex';
import { ENTRY_WALK_LIMIT } from '../worker/protocol';
import { MAX_CHECKPOINTS, type NoteOrigin, type NoteSecret, type RejectedNote, type StoreMeta, type StoredNote, type SyncCheckpoint } from './model';

/** What a scan needs out of the chain, so a test can supply it. */
export interface SyncChain {
  /**
   * How the runtime's storage differs from what this build assumes, empty when
   * it does not.
   *
   * Checked here rather than only on the screen that starts a sync, because
   * the rule belongs to the sync: a renamed item or a changed hasher builds a
   * key that is simply absent, and an absent key is indistinguishable from an
   * empty map, so `LeafCount` reads zero, a fresh store scans nothing and the
   * wallet reports a zero balance with no error. The command-line wallet opens
   * `sync_with`, `shield` and `prepare_spend` with the same check.
   */
  storageDrift: readonly string[];
  /**
   * `BlockHashWindow`: how far below the head an anchor may be and still be
   * admitted. A pending settlement anchored further back can never land.
   */
  anchorWindow: number;
  head(): Promise<{ number: number; hash: string }>;
  genesisHash(): Promise<string>;
  blockHashAt(height: number): Promise<string | null>;
  /**
   * `ZkTree::LeafCount`, `ZkTree::Depth` and `Shielded::EntryCount` at one
   * block.
   *
   * The counter rides along with them. All three are chain wide, the whole
   * pass is pinned to one block hash, and the read layer already bundles them
   * into a single `state_queryStorageAt` (`chain/reads.ts`), so a second
   * accessor made the node answer two byte-identical requests per pass.
   */
  treeShape(at: string): Promise<{ leafCount: number; depth: number; entryCount: bigint }>;
  /**
   * Four items for each leaf in `[from, to)`, at one block.
   *
   * `leafCount` is the count read at that same block hash, and the read layer
   * refuses an absent commitment below it: the leaf map has no gaps under its
   * own count, so a missing answer there is a node withholding one. See
   * `chain/reads.ts`.
   */
  leaves(
    from: number,
    to: number,
    at: string,
    leafCount: number,
    onProgress?: (done: number) => void,
  ): Promise<
    {
      index: number;
      commitment: string | null;
      ciphertext: Uint8Array | null;
      blockNumber: number | null;
      coinbaseQuanta: bigint | null;
    }[]
  >;
  usedNullifiers(at: string, onProgress?: (seen: number) => void): Promise<Set<string>>;
  /**
   * Every header from `anchor` up to `top`, walked downward by `parentHash`
   * so the range is a chain rather than a list of answers, handed over one at
   * a time as it is fetched.
   *
   * A callback rather than an array: the caller climbs the whole range in
   * chunks of `HEADER_WALK_LIMIT` and holds one chunk at a time, where an
   * array of the range let a node's claimed head decide how much this page
   * allocates before a single leaf was read.
   *
   * The headers arrive **descending**, `top` first, because that is the order
   * the parent links can be followed in. See `chain/reads.ts`. The caller
   * rehashes every one of them and compares the bottom against a hash it
   * already trusts.
   */
  headers(
    anchor: number,
    top: { number: number; hash: string },
    onHeader: (header: RawChainHeader) => void,
    onProgress?: (done: number) => void,
  ): Promise<void>;
  /**
   * `Shielded::LeafBlocks` over a range, at one block.
   *
   * Advisory: it proposes which block appended which leaves and the root in
   * that block's header settles it. Read apart from the windowed leaf scan,
   * because the typing needs every leaf's block before a window can say which
   * leaf is a block's last one.
   */
  leafBlocks(from: number, to: number, at: string): Promise<(number | null)[]>;
  /**
   * `ZkTree::Leaves` over `[0, to)` at one block, as `32 * n` raw bytes.
   *
   * These are the commitments the tree authenticates: folding them reaches the
   * `zkTreeRoot` each block published, and every leaf the scan opens is
   * checked against the bytes at its own index.
   */
  leafHashes(to: number, at: string, onProgress?: (done: number) => void): Promise<Uint8Array>;
}

/** One decrypted output, with the two digests only the seed can produce. */
export interface ScannedNote {
  value: bigint;
  rho: string;
  r: string;
  commitment: string;
  nullifier: string;
  memo: string;
  /**
   * Set when this wallet's own coinbase rebuild produced the note, as against
   * a payload beside it that happened to open.
   *
   * It is what makes a coinbase position's ownership a property of `cvk`
   * rather than of the author label a node published: the commitment the tree
   * holds is over an `r` only that key derives, so a rebuild that matches is
   * this wallet's note whatever header sits beside it. `coinbaseBatch` sets
   * it; `decryptBatch` never does.
   */
  mined?: boolean;
}

/** What a scan needs out of the prover module. */
export interface SyncCrypto {
  /**
   * One batch of leaves, decrypted.
   *
   * A batch rather than one leaf at a time: every call crosses the worker
   * boundary, and a scan of four thousand leaves is four thousand round trips
   * otherwise. `null` is a ciphertext that is not this wallet's, which is the
   * ordinary answer for almost every leaf on the chain.
   */
  decryptBatch(
    items: readonly { index: number; ciphertext: Uint8Array; commitment: string }[],
  ): Promise<(ScannedNote | null)[]>;
  /**
   * One batch of coinbase leaves, rebuilt.
   *
   * Batched for the same reason the decryption is: the chain mints one
   * coinbase per block, so a scan covering N blocks meets N of these whoever
   * they belong to, and one crossing per leaf is a cost that grows with the
   * chain rather than with this wallet.
   *
   * `value` is the chain's, out of `Shielded::CoinbaseValues`, and it is the
   * one the rebuild uses. A coinbase's amount is the chain's own arithmetic,
   * hashed into a commitment over an `inner` the chain cannot open, and a
   * payload beside it carries a value of zero.
   */
  coinbaseBatch(
    items: readonly {
      index: number;
      blockNumber: number;
      value: bigint;
      genesisHash: string;
      commitment: string;
      ciphertext: Uint8Array | null;
    }[],
  ): Promise<(ScannedNote | null)[]>;
  /**
   * Whether `rho` is one the shield rule produces for this block, over every
   * entry index up to `entryCount`.
   *
   * The whole walk in one crossing, rather than one crossing per candidate
   * index. `rho = H(RHO_ENTRY, block, index)` is the module's arithmetic and
   * the comparison is the module's too, which is where the command-line wallet
   * does it as well. A first sync receiving N notes on a chain with a large
   * counter was otherwise N walks of round trips through a message port.
   */
  entryRhoMatches(blockNumber: number, rho: string, entryCount: bigint): Promise<boolean>;
  /**
   * Every header of a scanned range, rehashed from its own preimage.
   *
   * The chain's block hash is Poseidon2 over a felt encoding of the header, so
   * this is the module's and cannot be a second implementation in TypeScript.
   * It is what authenticates a block's `zkTreeRoot` and its author label.
   */
  headerHashes(headers: Anchor[]): Promise<string[]>;
  /**
   * This wallet's own author label for each parent hash:
   * `H("qnero/author-label", cvk, parent_hash)`.
   *
   * Derived from the coinbase viewing key, so it happens behind the worker
   * boundary. A block whose label matches is one this wallet mined, and no
   * node can produce or withhold that fact.
   */
  authorLabels(parentHashes: string[]): Promise<string[]>;
  /**
   * The commitment-tree root after each of a list of leaf counts, ascending.
   *
   * Folded incrementally, so a per-block check costs one Poseidon path update
   * per leaf and one fold per block.
   */
  blockRoots(leafHashes: Uint8Array, counts: number[]): Promise<string[]>;
}

export interface HeldNote {
  note: StoredNote;
  secret: NoteSecret;
}

export interface SyncInput {
  meta: StoreMeta;
  held: readonly HeldNote[];
  rejected: readonly RejectedNote[];
  checkpoints: readonly SyncCheckpoint[];
  /**
   * The rows a spend wrote before submitting, with the block each was anchored
   * to. The anchor is what says a row can never clear: a settlement more than
   * `anchorWindow` blocks below the head is one the chain will not admit, so
   * its change commitment is never appended and no scan can meet it.
   */
  pending: readonly { commitment: string; submittedAtBlock: number }[];
}

export interface SyncOptions {
  /**
   * The operator override on the node gates.
   *
   * Four rules, in order: the chain check is never bypassed; a checkpoint-walk
   * refusal becomes a warning and the checkpoints it could not stand on are
   * dropped; the scan runs **add only**; the leaf gate is unchanged and cannot
   * trip, because the watermark is zero.
   */
  rescan?: boolean;
  onProgress?: (stage: string, detail?: string) => void;
}

export interface SyncReport {
  head: number;
  leavesScanned: number;
  received: number;
  receivedValue: bigint;
  coinbaseLeaves: number;
  coinbaseReceived: number;
  /**
   * Coinbase notes this pass rebuilt as its own at a coinbase position whose
   * header carries another author's label.
   *
   * The rebuild decides ownership and the label decides nothing, so the reward
   * is taken. It cannot happen on a block a Qnero node built: the label and the
   * note's own randomness come out of one coinbase viewing key. A non-zero
   * count is a header this wallet is being handed for a block it did not come
   * from, and the checkpoint fork walk is what finds out on the next pass
   * against another node.
   *
   * A non-zero count also puts a warning on `warnings`, which the balance
   * screen renders. The count on its own was read by nothing, so the one
   * operator-visible signal for that attack lived only in the command-line
   * wallet.
   */
  coinbaseLabelDisagreed: number;
  relocated: number;
  rejected: number;
  rejectedCleared: number;
  newlySpent: number;
  newlyUnspent: number;
  heldSpent: number;
  vanished: number;
  nullifierSetSize: number;
  /** Pending rows dropped because their anchor fell out of the window. */
  pendingAbandoned: number;
  recordedGenesis: boolean;
  forkedAt: number | null;
  /**
   * What the pass gave up or could not decide, in sentences the balance screen
   * renders.
   *
   * A bypassed node gate, the add-only notice a rescan owes, a truncated
   * origin walk, abandoned pending rows, a coinbase rebuilt under a foreign
   * label, and the one bound the per-leaf rules do not close: a pass that read
   * leaves and received nothing is also what a substituted ciphertext looks
   * like, so the sentence naming the rescan that recovers such a payment goes
   * here. `docs/WALLET.md`, under "What a lying node can and cannot do",
   * carries that bound.
   */
  warnings: string[];
  addOnly: boolean;
}

export interface SyncResult {
  meta: StoreMeta;
  notes: { note: StoredNote; secret: NoteSecret }[];
  removedNotes: string[];
  rejected: RejectedNote[];
  removedRejected: string[];
  checkpoints: SyncCheckpoint[];
  clearedPending: string[];
  report: SyncReport;
}

export type NodeStance =
  | { kind: 'current' }
  | { kind: 'forked'; atBlock: number; nextLeaf: number };

/** Refused because the node cannot answer for what this wallet has read. */
export class NodeRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NodeRefusedError';
  }
}

/**
 * A per-leaf key the node answered nothing for below the count it reports at
 * the same block.
 *
 * One sentence per key for what stepping over it costs, because the three hide
 * a leaf in three different ways and an operator reading the refusal is
 * reading about the one that happened. The set of keys and why each is
 * required is on `fetchLeaves` in `chain/reads.ts`, which refuses the same
 * answers one layer down; the wording is kept the same on both sides so a bug
 * report carries one sentence whichever layer caught it.
 */
function withheldLeafKey(
  key: string,
  index: number,
  leafCount: number,
  at: string,
): NodeRefusedError {
  const cost =
    key === 'ZkTree::Leaves'
      ? 'Scanning past it would step over whatever was on that leaf and then write a watermark ' +
        'above it'
      : key === 'Shielded::LeafBlocks'
        ? 'A leaf with no block is stepped over where it is a coinbase, and dated by nothing ' +
          'where it is not, and the pass would write a watermark above it'
        : 'A leaf with no ciphertext and no coinbase value reads as a leaf nobody can open, so a ' +
          'payment on it would be skipped and the pass would write a watermark above it';
  return new NodeRefusedError(
    `this node answered with no ${key}(${index}) at block ${at}, where it reports ${leafCount} ` +
      'leaves. `pallet-shielded` writes that key in the same call that appends the leaf and ' +
      'nothing removes it, so below the count it is an answer withheld rather than an absent ' +
      `one. ${cost}, and nothing would read it again. Nothing has been changed.`,
  );
}

/**
 * What kind of note each leaf of a scanned range holds, decided from data the
 * headers authenticate.
 *
 * A leaf is a coinbase or it is a transfer, and the two are opened by
 * different rules. Getting the kind wrong is silent: the wrong rule does not
 * open the leaf, the scan reads it as somebody else's, and the pass commits a
 * watermark above it, so nothing reads that leaf again without a rescan.
 *
 * The kind used to be decided by which per-leaf keys a node chose to answer,
 * and both directions of that were exploitable. Eight invented bytes at
 * `Shielded::CoinbaseValues` sent an incoming payment down the coinbase
 * rebuild, which cannot open it. An invented `Shielded::Ciphertexts` beside a
 * withheld coinbase value silenced the rule that was meant to catch the
 * withholding and hid a mined reward. Neither is a key the chain wrote.
 *
 * What decides is position, and position is what the headers commit to.
 * `crates/qnero-wallet/src/typing.rs` carries the identical rules:
 *
 * 1. The header chain, walked down from the head by `parentHash` to a hash
 *    this wallet already trusts, with every header rehashed from its own
 *    preimage, in chunks of `HEADER_WALK_LIMIT` blocks.
 * 2. Each block's leaf range, because the tree is folded once per block in
 *    `pallet-zk-tree`'s `on_finalize` and the header carries that fold.
 *    `Shielded::LeafBlocks` proposes the range and the root settles it.
 * 3. The coinbase position. `pallet-mining-rewards` mints the coinbase in its
 *    own `on_finalize`, after every shield and settled output, so a block's
 *    coinbase is the last leaf that block appended and no other index can hold
 *    one.
 *
 * **No rule rests on the author label.** This wallet verifies no proof of work
 * and will not in v1, so above the newest checkpoint a node picks every header
 * field, the label included, and a rule gated on the label is one the node
 * switches off by publishing another. So a coinbase value is required at every
 * coinbase position, this wallet's own coinbase note is rebuilt at every
 * coinbase position, and the label is a cross-check afterwards. `wallet-web/
 * README.md` and `docs/WALLET.md` carry the bound that does hold, under "What
 * a lying node can and cannot do".
 */
export interface LeafTyping {
  /** Block of each leaf from the watermark up, authenticated by the roots. */
  blockOf: Map<number, number>;
  /** Leaf indices that are their block's last, the only place a coinbase sits. */
  coinbasePositions: Set<number>;
  /**
   * Of those, the ones whose block carries this wallet's own author label.
   *
   * A cross-check and never a selector: what decides ownership is the rebuild
   * against the tree-authenticated commitment. See `LeafTyping` above.
   */
  labelSaysOurs: Set<number>;
  /** `ZkTree::Leaves` over the whole tree, `32 * n` bytes, index aligned. */
  commitments: Uint8Array;
  /**
   * One per chunk of the walk, ascending, each naming a block whose header
   * this pass fetched and rehashed down to a hash it already trusted.
   *
   * The caller commits them with the watermark at the end of the pass, so the
   * store never carries a checkpoint for a range whose scan was refused, and
   * never one for a head no header was fetched for.
   */
  checkpoints: SyncCheckpoint[];
}

function strip0x(hex: string): string {
  return hex.startsWith('0x') ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

/**
 * How many blocks one chunk of the header walk carries.
 *
 * The head is a number the node answers with, and the walk fetches, rehashes
 * and holds one header per block between the trusted anchor and it. Unbounded,
 * a node claiming a head far ahead decided how much this page allocates before
 * a single leaf was read: `RawChainHeader` is five hex strings, so a range of
 * a million blocks is hundreds of megabytes on the page. So the range is
 * climbed in chunks, each authenticated against the hash below it and
 * checkpointed before the next is read, and only one chunk is ever resident.
 *
 * The same number as the command-line wallet's `HEADER_WALK_LIMIT`, and
 * `docs/BENCH.md` carries the per-block cost beside it.
 */
export const HEADER_WALK_LIMIT = 1024;

/**
 * Walk the headers, check every block's leaf range against the root it
 * published, and say which leaf of each block is its coinbase position.
 *
 * Climbed in chunks of `HEADER_WALK_LIMIT`: each chunk learns its top's hash
 * from `chain_getBlockHash` and then proves it by walking down to a hash
 * already trusted, so the bound costs one request per chunk and no guarantee.
 * Only the last chunk's top is the head itself.
 *
 * The roots are folded once for the whole walk rather than once per chunk. The
 * fold is a single crossing into the module that owns Poseidon2
 * (`crypto.blockRoots`), which takes the leaf range in one call and starts
 * from an empty tree, so a per-chunk call would re-push every leaf below the
 * chunk and turn a linear check into a quadratic one. It runs before any leaf
 * is scanned and before the caller commits any checkpoint, so nothing stands
 * on an unchecked root either way.
 *
 * Refuses by name and writes nothing: this module writes nothing at all, and
 * its caller commits only what it returns.
 */
export async function authenticateLeaves(
  chain: SyncChain,
  crypto: SyncCrypto,
  head: { number: number; hash: string },
  trusted: { number: number; hash: string },
  watermark: number,
  leafCount: number,
  progress: (stage: string, detail?: string) => void,
): Promise<LeafTyping> {
  const scans = leafCount > watermark;
  const commitments = scans
    ? await chain.leafHashes(leafCount, head.hash, (done) => {
        progress('headers', `${done} of ${leafCount} leaf hashes`);
      })
    : new Uint8Array(0);
  if (scans && commitments.length !== leafCount * 32) {
    throw new NodeRefusedError(
      `this node answered ${commitments.length / 32} leaf hashes where it reports ${leafCount} ` +
        'leaves. Nothing has been changed.',
    );
  }
  const dates = scans ? await chain.leafBlocks(watermark, leafCount, head.hash) : [];
  for (let index = watermark; index < leafCount; index += 1) {
    if (dates[index - watermark] === null || dates[index - watermark] === undefined) {
      throw withheldLeafKey('Shielded::LeafBlocks', index, leafCount, head.hash);
    }
  }

  const blockOf = new Map<number, number>();
  const coinbasePositions = new Set<number>();
  const labelSaysOurs = new Set<number>();
  const checkpoints: SyncCheckpoint[] = [];
  const counts: number[] = [watermark];
  const roots: string[] = [];
  const runs: { block: number; from: number; to: number; ours: boolean }[] = [];
  let cursor = watermark;
  let bottomNumber = trusted.number;
  let bottomHash = strip0x(trusted.hash);
  let anchorRoot: string | null = null;

  for (;;) {
    const top = Math.min(bottomNumber + HEADER_WALK_LIMIT, head.number);
    const topHash =
      top === head.number ? strip0x(head.hash) : strip0x(await hashAtHeightOrRefuse(chain, top));

    // The chunk, streamed in descending order and reversed once. Only this
    // many headers are ever resident.
    const raw: RawChainHeader[] = [];
    await chain.headers(
      bottomNumber,
      { number: top, hash: topHash },
      (header) => {
        raw.push(header);
      },
      (done) => {
        // Counted from where the walk stands rather than from a running sum
        // of the chunks. Each chunk re-fetches the block it stands on, so
        // adding chunk lengths counted every boundary twice and a multi-chunk
        // sync reported more headers than the range holds.
        progress(
          'headers',
          `${bottomNumber - trusted.number + done} of ${head.number - trusted.number + 1} block headers`,
        );
      },
    );
    raw.reverse();
    if (raw.length !== top - bottomNumber + 1) {
      throw new NodeRefusedError(
        `this node answered ${raw.length} headers for blocks ${bottomNumber} to ${top}. ` +
          'Nothing has been changed.',
      );
    }

    const hashes = (await crypto.headerHashes(raw.map((header) => anchorFromHeader(header)))).map(
      strip0x,
    );
    // Every header is fetched by the hash its child names, so comparing each
    // recomputed hash against that name is what makes the range a chain. The
    // bottom is compared against a hash this wallet already trusts, and without
    // that comparison a node can build a self-consistent chain out of nothing.
    for (let index = 0; index < raw.length; index += 1) {
      const child = raw[index + 1];
      const wanted = child === undefined ? topHash : strip0x(child.parentHash);
      if (hashes[index] !== wanted) {
        throw new NodeRefusedError(
          `the header this node served for block ${bottomNumber + index} hashes to ` +
            `${hashes[index] ?? ''} where the hash asked for is ${wanted}. The header preimage is ` +
            "what authenticates a block's zkTreeRoot and its author label, so a header that does " +
            'not hash to its own name authenticates nothing. Nothing has been changed.',
        );
      }
    }
    if (hashes[0] !== bottomHash) {
      throw new NodeRefusedError(
        `the header walk reached block ${bottomNumber} at ${hashes[0] ?? ''}, and this wallet ` +
          `trusts ${bottomHash} there. Every header above it is authenticated by ` +
          'chaining down to this one, so a walk that lands somewhere else authenticates nothing. ' +
          'Nothing has been changed.',
      );
    }

    // Which of these blocks this wallet mined. The label is a function of the
    // parent hash and the coinbase viewing key, so the answers come from the
    // worker and the comparison is against what the header carries. It decides
    // nothing: it is compared against the rebuild in `runSync`.
    const ownLabels = (await crypto.authorLabels(hashes.slice(0, -1))).map(strip0x);

    const bottom = raw[0];
    if (bottom === undefined) {
      throw new NodeRefusedError('a header walk returned no blocks at all');
    }
    if (anchorRoot === null) {
      anchorRoot = strip0x(bottom.zkTreeRoot);
      roots.push(anchorRoot);
    }
    for (let index = 1; index < raw.length; index += 1) {
      const header = raw[index];
      if (header === undefined) {
        break;
      }
      const block = bottomNumber + index;
      if (!scans) {
        // Nothing was appended between the bottom of this walk and its top, so
        // there is no fold to seed and no leaf to check against the roots. The
        // headers are still fetched and rehashed, because the checkpoint this
        // pass records has to name a head it authenticated, and every block in
        // the range has to carry the bottom block's own root: a moved root
        // over an unchanged leaf count is a node answering a count its own
        // headers do not carry.
        if (strip0x(header.zkTreeRoot) !== anchorRoot) {
          throw new NodeRefusedError(
            `this node reports the same leaf count at block ${block} as at block ` +
              `${trusted.number}, and their headers carry different commitment-tree roots ` +
              `(${strip0x(header.zkTreeRoot)} against ${anchorRoot}). The tree is folded once ` +
              'per block and only ever grows, so a moved root over an unchanged count is a node ' +
              'answering a leaf count its own headers do not carry. Nothing has been changed.',
          );
        }
        continue;
      }
      const from = cursor;
      while (cursor < leafCount && dates[cursor - watermark] === block) {
        blockOf.set(cursor, block);
        cursor += 1;
      }
      const label = authorLabelFromHeader(header);
      const ours = label !== null && label.toLowerCase() === ownLabels[index - 1];
      runs.push({ block, from, to: cursor, ours });
      counts.push(cursor);
      roots.push(strip0x(header.zkTreeRoot));
    }

    checkpoints.push({ blockNumber: top, blockHash: topHash, nextLeaf: cursor });
    if (top === head.number) {
      break;
    }
    bottomNumber = top;
    bottomHash = topHash;
  }

  if (cursor !== leafCount) {
    throw new NodeRefusedError(
      `Shielded::LeafBlocks dates leaf ${cursor} to block ${String(dates[cursor - watermark])}, ` +
        'which is not where the header walk puts it. Leaves are appended in block order and ' +
        `this pass walked blocks ${trusted.number} to ${head.number}, so a leaf that no ` +
        "block's range claims is a node disagreeing with the headers about which block " +
        'appended it. Nothing has been changed.',
    );
  }

  if (scans) {
    progress('headers', 'checking each block against the tree it published');
    const computed = (await crypto.blockRoots(commitments, counts)).map(strip0x);
    for (let index = 0; index < counts.length; index += 1) {
      if (computed[index] === roots[index]) {
        continue;
      }
      if (index === 0) {
        throw new NodeRefusedError(
          `the ${watermark} leaves this node answered below the watermark do not hash to the ` +
            `zkTreeRoot in the header of block ${trusted.number}, which is ${roots[0] ?? ''}. The ` +
            'tree is folded once per block and the header carries that fold, so a leaf range that ' +
            'roots elsewhere is a node answering with leaves this chain does not hold. Nothing ' +
            'has been changed.',
        );
      }
      const run = runs[index - 1] ?? { block: trusted.number + index, from: 0, to: 0, ours: false };
      throw new NodeRefusedError(
        `this node dates ${run.to - run.from} leaves to block ${run.block}, and folding exactly ` +
          'those into the tree does not reach the zkTreeRoot its header carries ' +
          `(${roots[index] ?? ''}). Shielded::LeafBlocks is what proposes a block's leaf range ` +
          'and the header is what settles it, so a disagreement is a node moving leaves between ' +
          'blocks, which is what decides where a coinbase sits. Nothing has been changed.',
      );
    }
  }

  for (const run of runs) {
    if (run.to === run.from) {
      continue;
    }
    coinbasePositions.add(run.to - 1);
    if (run.ours) {
      labelSaysOurs.add(run.to - 1);
    }
  }
  return { blockOf, coinbasePositions, labelSaysOurs, commitments, checkpoints };
}

/** The hash at a chunk's top, refused by name when this node has no block there. */
async function hashAtHeightOrRefuse(chain: SyncChain, height: number): Promise<string> {
  const hash = await chain.blockHashAt(height);
  if (hash === null) {
    throw new NodeRefusedError(
      `this node answered its head above block ${height} and has no block at that height, which ` +
        'is where the header walk was going to stand for the next chunk of the range. Nothing ' +
        'has been changed.',
    );
  }
  return hash;
}

/**
 * Where this node stands against the store, decided before anything is
 * written.
 *
 * One walk, newest first, and it answers both questions:
 *
 * - A checkpoint above the node's head is **skipped**. On its own it says
 *   nothing: the node may be behind, or that checkpoint may belong to a branch
 *   this node replaced with a heavier shorter one.
 * - The first checkpoint at or below the head whose hash still stands means
 *   the node is on this chain up to there. If anything was skipped above it,
 *   the node is behind this wallet and the sync **refuses by name**: its
 *   `UsedNullifiers` is missing every settlement it has not executed, and the
 *   reconciliation would read that as those notes coming back into the
 *   balance.
 * - A checkpoint at or below the head whose hash **differs** is a fork. The
 *   walk continues down to the newest survivor, and the watermark and
 *   `lastSyncedBlock` both rewind to it. `lastSyncedBlock` is allowed to go
 *   down, which is what a reorg onto a heavier shorter branch is.
 * - **No block at all** at a height at or below the head is neither. A fork is
 *   a *different* block there; no block is a node that is pruned or is serving
 *   a head it has not filled in behind. Refused by name.
 *
 * Keying on heights instead of hashes was the bug this replaced: heaviest
 * chain does not order branches by length, so a shorter winning branch left
 * the wallet refusing every sync while a moved note stayed at its old index,
 * unspendable and reported spendable.
 */
export async function readNodeStance(
  checkpoints: readonly SyncCheckpoint[],
  head: { number: number },
  hashAt: (height: number) => Promise<string | null>,
  lastSyncedBlock: number,
): Promise<NodeStance> {
  let aboveHead = 0;
  let forked = false;
  const behind = (): NodeRefusedError =>
    new NodeRefusedError(
      `this node's head is block ${head.number} and this wallet has synced through block ` +
        `${lastSyncedBlock} on the chain this node is serving. This node is behind this wallet: ` +
        'it answers every question with less than the wallet already knows, so notes it has not ' +
        'seen settled would come back into the balance and the next send would select an input ' +
        'the chain has already consumed. Nothing has been changed. Point the wallet at a node ' +
        'that has caught up, wait for this one to, or rescan to drop this watermark and walk ' +
        "this node's tree from leaf zero.",
    );

  for (let index = checkpoints.length - 1; index >= 0; index -= 1) {
    const checkpoint = checkpoints[index];
    if (checkpoint === undefined) {
      continue;
    }
    if (checkpoint.blockNumber > head.number) {
      aboveHead += 1;
      continue;
    }
    const hash = await hashAt(checkpoint.blockNumber);
    if (hash === null) {
      throw new NodeRefusedError(
        `this node has no block at height ${checkpoint.blockNumber}, which this wallet ` +
          `checkpointed while syncing, and its head is block ${head.number}. A missing block at ` +
          'a height below a node\'s own head is a node that is pruned or has not filled in ' +
          'behind its head, and it is not a fork: a fork is a different block at that height. ' +
          'Rewinding on it would rescan leaves against a tree smaller than the one already ' +
          'recorded. Nothing has been changed.',
      );
    }
    if (normaliseHash(hash) !== normaliseHash(checkpoint.blockHash)) {
      forked = true;
      continue;
    }
    if (forked) {
      return { kind: 'forked', atBlock: checkpoint.blockNumber, nextLeaf: checkpoint.nextLeaf };
    }
    if (aboveHead > 0) {
      throw behind();
    }
    return { kind: 'current' };
  }

  if (forked) {
    // Every checkpoint this node can answer for is on a branch that is gone.
    // Walking the whole tree again is correct and slow, and it is what a reorg
    // deeper than the checkpoints the store keeps costs.
    return { kind: 'forked', atBlock: 0, nextLeaf: 0 };
  }
  if (aboveHead > 0) {
    throw behind();
  }
  // No checkpoints at or below the head and none above it: a fresh store, or
  // one whose checkpoints were dropped.
  return { kind: 'current' };
}

/**
 * A `rho` that came from the shield counter, which is what tells a shield
 * apart from a spend's output.
 *
 * The counter is chain wide and read once per pass, and the whole of it is
 * walked: a shield predicts `(head + 1, EntryCount)`, so the entry index of
 * one that settled is somewhere below the counter read at the head. It used to
 * walk the newest 64 entries only, which meant a wallet restored from its seed
 * on a chain with more shields than that labelled every one of its own older
 * shields `transfer`, permanently, because origin is written once at receipt
 * and no later pass revisits it. `crates/qnero-wallet/src/wallet.rs` walks the
 * whole counter and this now matches it.
 *
 * Only ever a label: getting it wrong misfiles a note's origin and moves no
 * value, and nothing selects on it. The store's field should still say what
 * the command-line wallet's says, because a later rule could key on it.
 */
async function originOf(
  crypto: SyncCrypto,
  blockNumber: number | null,
  rho: string,
  entryCount: bigint,
): Promise<NoteOrigin> {
  if (blockNumber === null) {
    return 'transfer';
  }
  return (await crypto.entryRhoMatches(blockNumber, rho, entryCount)) ? 'shield' : 'transfer';
}

export async function runSync(
  input: SyncInput,
  chain: SyncChain,
  crypto: SyncCrypto,
  options: SyncOptions = {},
): Promise<SyncResult> {
  const rescan = options.rescan === true;
  const reconciles = !rescan;
  const progress = options.onProgress ?? ((): void => undefined);
  const warnings: string[] = [];

  if (chain.storageDrift.length > 0) {
    // Before the first read. An absent key and an empty map are the same
    // answer, and an empty map here is a zero balance or a settled note
    // reported unspent, so this refuses rather than scanning.
    throw new NodeRefusedError(
      'this runtime declares storage differently from what this build assumes, so syncing ' +
        `against it is refused: ${chain.storageDrift.join('; ')}. Nothing has been changed.`,
    );
  }

  progress('chain', 'checking the chain this node serves');
  const genesis = normaliseHash(await chain.genesisHash());
  if (input.meta.genesisHash !== null && normaliseHash(input.meta.genesisHash) !== genesis) {
    // Never bypassed, rescan included. A store bound to one chain reading
    // another is not a sync, it is two wallets sharing a file.
    throw new NodeRefusedError(
      `this wallet is bound to the chain whose genesis is ${input.meta.genesisHash} and this ` +
        `node serves ${genesis}. Nothing has been changed. Point the wallet at a node on its ` +
        'own chain, or start a new wallet for this one.',
    );
  }

  const head = await chain.head();
  progress('gates', `head is block ${head.number}`);

  let checkpoints = [...input.checkpoints];
  let watermark = input.meta.nextLeaf;
  let lastSyncedBlock = input.meta.lastSyncedBlock;
  let forkedAt: number | null = null;
  let rewound = false;

  if (rescan) {
    // The bypass owes the store this: every checkpoint it could not stand on
    // is dropped and both counters go to zero with them, so a rescan that
    // walked past a node gate leaves behind no claim that gate was measured
    // against.
    try {
      await readNodeStance(checkpoints, head, (height) => chain.blockHashAt(height), lastSyncedBlock);
    } catch (error) {
      warnings.push(
        `the node gate was bypassed by the rescan: ${(error as Error).message.split('.')[0] ?? ''}.`,
      );
    }
    checkpoints = [];
    watermark = 0;
    lastSyncedBlock = 0;
    rewound = true;
  } else {
    const stance = await readNodeStance(
      checkpoints,
      head,
      (height) => chain.blockHashAt(height),
      lastSyncedBlock,
    );
    if (stance.kind === 'forked') {
      forkedAt = stance.atBlock;
      watermark = stance.nextLeaf;
      lastSyncedBlock = stance.atBlock;
      checkpoints = checkpoints.filter((checkpoint) => checkpoint.blockNumber <= stance.atBlock);
      rewound = true;
    }
  }

  const shape = await chain.treeShape(head.hash);
  // The leaf gate. A node can be on this chain, above every checkpoint, and
  // still answer short because it has not finished executing its head. The
  // scan range would then go empty, the vanished check would be skipped and
  // the watermark would be written back down. A rescan cannot trip it by
  // construction, with no exemption written into the gate.
  if (shape.leafCount < watermark) {
    throw new NodeRefusedError(
      `this node reports ${shape.leafCount} leaves at its head and this wallet has already read ` +
        `${watermark}. A node on this chain whose leaf count is short has a head it has not ` +
        'finished executing. Nothing has been changed.',
    );
  }

  progress('nullifiers', 'paging the settled set');
  const settled = await chain.usedNullifiers(head.hash, (seen) => {
    progress('nullifiers', `${seen} settled nullifiers`);
  });

  // The working set, keyed by commitment. Every held note starts here and the
  // scan adds to it; nothing is dropped, because the secrets in a held note
  // are the only copy this wallet has.
  const notes = new Map<string, { note: StoredNote; secret: NoteSecret }>();
  for (const held of input.held) {
    notes.set(held.note.commitment, { note: { ...held.note }, secret: held.secret });
  }
  const rejected = new Map<string, RejectedNote>();
  for (const entry of input.rejected) {
    rejected.set(entry.commitment, entry);
  }

  const report: SyncReport = {
    head: head.number,
    leavesScanned: 0,
    received: 0,
    receivedValue: 0n,
    coinbaseLeaves: 0,
    coinbaseReceived: 0,
    coinbaseLabelDisagreed: 0,
    relocated: 0,
    rejected: 0,
    rejectedCleared: 0,
    newlySpent: 0,
    newlyUnspent: 0,
    heldSpent: 0,
    vanished: 0,
    nullifierSetSize: settled.size,
    pendingAbandoned: 0,
    recordedGenesis: false,
    forkedAt,
    warnings,
    addOnly: rescan,
  };

  /**
   * Commitments this scan met again inside a re-walked range.
   *
   * Only populated when a range was actually re-walked and the pass
   * reconciles: it is what tells a note that moved apart from a note whose
   * block was orphaned and never re-included.
   */
  const seenAgain = new Set<string>();
  const clearedPending: string[] = [];

  // The trusted bottom of the header walk, resolved on every pass and not only
  // on one with leaves to scan: the checkpoint this pass records has to name a
  // head it authenticated, and a pass that fetched no header authenticated
  // nothing. It stands on a block hash this wallet already trusts, the genesis
  // it is bound to when the scan starts at leaf zero, and otherwise the
  // checkpoint an earlier pass recorded at the watermark, whose hash the stance
  // walk has just confirmed still stands on this node's own branch.
  const anchorCheckpoint = checkpoints.at(-1);
  let trusted: { number: number; hash: string };
  if (watermark === 0) {
    trusted = { number: 0, hash: genesis };
  } else if (anchorCheckpoint !== undefined && anchorCheckpoint.nextLeaf === watermark) {
    trusted = { number: anchorCheckpoint.blockNumber, hash: anchorCheckpoint.blockHash };
  } else {
    throw new NodeRefusedError(
      `this wallet has read ${watermark} leaves and carries no checkpoint that ends on them, ` +
        'so there is no block hash it already trusts for the header walk to stand on. Run a ' +
        'rescan, which starts the walk at the genesis this store is bound to and keeps every ' +
        'note. Nothing has been changed.',
    );
  }
  // What kind of note each leaf holds, decided from the headers rather than
  // from which keys this node chose to answer. See `authenticateLeaves`.
  const typing = await authenticateLeaves(
    chain,
    crypto,
    head,
    trusted,
    watermark,
    shape.leafCount,
    progress,
  );

  if (shape.leafCount > watermark) {
    // Read with the tree's shape, in the same call the read layer already
    // made. The walk it feeds is bounded in the worker, and a chain past that
    // bound is said out loud: `origin` is written once at receipt and no later
    // pass revisits it, so a note labelled `transfer` because the walk stopped
    // short keeps that label until a rescan.
    const entryCount = shape.entryCount;
    if (entryCount > ENTRY_WALK_LIMIT) {
      warnings.push(
        `this chain has settled ${entryCount} shield entries and the origin walk stops at ` +
          `${ENTRY_WALK_LIMIT}, so a shield received in this pass may be listed as a transfer. ` +
          'Origin is a label and no rule selects on it.',
      );
    }

    // Decryption goes over the boundary in batches, so a scan is one round
    // trip per batch rather than one per leaf.
    const BATCH = 64;
    /**
     * The scan reads one window of leaves, folds it in and drops it.
     *
     * The whole range used to be materialised first, and a `LeafRecord`
     * carries the leaf's ciphertext: 1,792 bytes each, one per leaf on the
     * chain, in the page, beside the worker's 918 MiB. The pallet mints a
     * coinbase leaf per block at a twelve-second target, so a chain that has
     * been running a year is gigabytes of ciphertext held at once for a first
     * sync, and a tab reclaimed under that pressure dies with no catchable
     * error and makes no progress, because nothing is committed until the pass
     * ends. Reading in windows bounds what is resident to one window plus the
     * notes this wallet actually holds.
     *
     * The window is the read batch, so the request stream is unchanged: the
     * same contiguous range, the same four keys per leaf, 64 leaves a query.
     * What the node is asked is what `tests/privacy.test.ts` asserts on.
     */
    const WINDOW = BATCH;
    const total = shape.leafCount - watermark;
    let ciphertextsTried = 0;
    for (let windowFrom = watermark; windowFrom < shape.leafCount; windowFrom += WINDOW) {
      const windowTo = Math.min(windowFrom + WINDOW, shape.leafCount);
      const records = await chain.leaves(windowFrom, windowTo, head.hash, shape.leafCount);
      progress('scan', `${windowTo - watermark} of ${total} leaves`);

      // Which rule opens each leaf, and both batches built from it. A leaf
      // below its block's last cannot be a coinbase whatever a node answers
      // for it; a leaf at a coinbase position is offered to the coinbase rule,
      // and to the transfer rule as well when it carries a ciphertext, because
      // under v1 a coinbase carries none and a ciphertext there is either an
      // encrypted coinbase or a leaf that is not a coinbase at all.
      for (const record of records) {
        if (record.index >= shape.leafCount) {
          continue;
        }
        const authenticated = bytesToHex(
          typing.commitments.subarray(record.index * 32, record.index * 32 + 32),
        ).slice(2);
        if (record.commitment !== null && normaliseHash(record.commitment) !== authenticated) {
          throw new NodeRefusedError(
            `this node answered ZkTree::Leaves(${record.index}) with two different commitments ` +
              'in one pass, at one block hash. The tree the headers authenticate carries ' +
              `${authenticated}. Nothing has been changed.`,
          );
        }
        const dated = typing.blockOf.get(record.index);
        if (record.blockNumber !== null && dated !== undefined && record.blockNumber !== dated) {
          throw new NodeRefusedError(
            `this node dated leaf ${record.index} to block ${record.blockNumber} here and to ` +
              `block ${dated} when the block ranges were checked. Nothing has been changed.`,
          );
        }
        const isCoinbasePosition = typing.coinbasePositions.has(record.index);
        if (!isCoinbasePosition && record.coinbaseQuanta !== null) {
          throw new NodeRefusedError(
            `this node answered a Shielded::CoinbaseValues for leaf ${record.index}, which is ` +
              `not the last leaf block ${String(dated)} appended. A block's coinbase is minted ` +
              'in on_finalize, after every shield and every settled output, so it is always ' +
              "that block's last leaf. A coinbase value anywhere else is an answer the chain " +
              'never wrote, and taking it would send a payment down the coinbase rebuild, which ' +
              'cannot open it. Nothing has been changed.',
          );
        }
        if (isCoinbasePosition && record.coinbaseQuanta === null) {
          throw new NodeRefusedError(
            `this node answered with no Shielded::CoinbaseValues for leaf ${record.index}, the ` +
              `last leaf of block ${String(dated)} and the one leaf index that block's coinbase ` +
              'can occupy. The value is public and `pallet-shielded` writes it in the same call ' +
              'that appends the leaf, so an absent one is an answer withheld, and a scan that ' +
              'stepped over it would drop whatever sat on that leaf behind a watermark. The ' +
              'value is required at every coinbase position whatever the author label says: ' +
              'this wallet verifies no proof of work, so above its newest checkpoint a node ' +
              'chooses every header field, the label included, and a rule that asked for the ' +
              "value only under this wallet's own label was one the node switched off by " +
              'publishing another. Nothing has been changed.',
          );
        }
        if (!isCoinbasePosition && record.ciphertext === null) {
          throw new NodeRefusedError(
            `this node answered with no Shielded::Ciphertexts(${record.index}), which the ` +
              `headers put below the last leaf of block ${String(dated)} and so cannot be a ` +
              'coinbase. Every shield and every settled output stores its ciphertext in the ' +
              'call that appends the leaf and nothing removes it, so an absent one there is an ' +
              'answer withheld. Reading it as a leaf nobody can open would skip a payment and ' +
              'write a watermark above it. Nothing has been changed.',
          );
        }
      }

      const candidates = records.filter(
        (record) =>
          record.index < shape.leafCount &&
          record.commitment !== null &&
          record.ciphertext !== null,
      );
      const decrypted = new Map<number, ScannedNote | null>();
      for (let start = 0; start < candidates.length; start += BATCH) {
        const slice = candidates.slice(start, start + BATCH);
        const answers = await crypto.decryptBatch(
          slice.map((record) => ({
            index: record.index,
            ciphertext: record.ciphertext as Uint8Array,
            // Normalised, because the module parses this as hex and `0x` is not
            // hex. A prefixed commitment makes `try_receive` refuse every
            // ciphertext on the chain, and the refusal is indistinguishable
            // from "none of these are yours": a wallet that reads its own
            // payments as nobody's, with no error anywhere.
            commitment: normaliseHash(record.commitment as string),
          })),
        );
        slice.forEach((record, offset) => {
          decrypted.set(record.index, answers[offset] ?? null);
        });
        ciphertextsTried += slice.length;
        progress('scan', `${ciphertextsTried} ciphertexts tried`);
      }

      // The coinbase leaves, in the same shape and for the same reason.
      const coinbases = records.filter(
        (record) =>
          record.index < shape.leafCount &&
          record.commitment !== null &&
          record.coinbaseQuanta !== null &&
          typing.coinbasePositions.has(record.index),
      );
      const minted = new Map<number, ScannedNote | null>();
      for (let start = 0; start < coinbases.length; start += BATCH) {
        const slice = coinbases.slice(start, start + BATCH);
        const answers = await crypto.coinbaseBatch(
          slice.map((record) => ({
            index: record.index,
            blockNumber: typing.blockOf.get(record.index) as number,
            value: record.coinbaseQuanta as bigint,
            genesisHash: genesis,
            // Normalised: the module parses this as hex and `0x` is not hex.
            commitment: normaliseHash(record.commitment as string),
            ciphertext: record.ciphertext,
          })),
        );
        slice.forEach((record, offset) => {
          minted.set(record.index, answers[offset] ?? null);
        });
        progress('scan', `${Math.min(start + BATCH, coinbases.length)} of ${coinbases.length} coinbase leaves in this window`);
      }

      for (const record of records) {
        report.leavesScanned += 1;
        // A gap in what the node answered, which the chain never leaves.
        // Every leaf below the count this pass read at this same block hash
        // was appended by one of `pallet-shielded`'s three writers, and each
        // writes `ZkTree::Leaves` and `Shielded::LeafBlocks` in the call that
        // appends the leaf. Nothing removes either, so an absent answer below
        // the count is one this node withheld.
        //
        // Stepping over one is silent and permanent. The leaf would be counted
        // as scanned, the pass would commit a watermark and a checkpoint above
        // it, and every later pass starts above it, so a payment on that leaf
        // is out of the balance with no error, no warning and no field in the
        // report until somebody rescans. The pass is refused instead, and
        // nothing is written: this function writes nothing at all and its
        // caller commits only what it returns. `chain/reads.ts` refuses the
        // same pair one layer down, and `Chain::leaves` and `Wallet::sync_with`
        // refuse them in the command-line wallet. Whether a leaf owes a
        // ciphertext or a coinbase value is decided above, by the headers.
        if (record.index < shape.leafCount) {
          if (record.commitment === null) {
            throw withheldLeafKey('ZkTree::Leaves', record.index, shape.leafCount, head.hash);
          }
          if (record.blockNumber === null) {
            throw withheldLeafKey(
              'Shielded::LeafBlocks',
              record.index,
              shape.leafCount,
              head.hash,
            );
          }
        }
        if (record.commitment === null) {
          // Above the count, where a window may run past the end of the tree
          // and nothing is being withheld.
          continue;
        }
        const commitment = normaliseHash(record.commitment);
        const blockNumber = typing.blockOf.get(record.index) ?? record.blockNumber;

        let received: ScannedNote | null = null;
        let isCoinbase = false;
        if (typing.coinbasePositions.has(record.index) && record.coinbaseQuanta !== null) {
          // The one leaf index of its block a coinbase can occupy, with the
          // value the chain published. Its value is public, because the chain
          // hashed it into a commitment over an `inner` it cannot open, and the
          // rest is rebuilt from this wallet's own miner key, or from a payload
          // under the chain's published value when somebody else minted it. The
          // commitment check decides in both cases, and in both cases the value
          // inside any payload is ignored: a coinbase's amount is the chain's
          // own arithmetic. The rule is the module's; see `worker/core.ts`.
          report.coinbaseLeaves += 1;
          received = minted.get(record.index) ?? null;
          isCoinbase = received !== null;
          // The rebuild runs at every coinbase position and it is what decides
          // ownership: the commitment the tree holds is over an `r` only this
          // wallet's coinbase viewing key derives, so a leaf it opens is this
          // wallet's note whatever header sits beside it. The author label is
          // read afterwards and never gates the rebuild.
          const mined = received?.mined === true;
          const labelSaysOurs = typing.labelSaysOurs.has(record.index);
          if (labelSaysOurs && !mined) {
            throw new NodeRefusedError(
              `block ${String(blockNumber)} carries this wallet's own author label and this ` +
                `node answered ${String(record.coinbaseQuanta)} quanta for its coinbase at leaf ` +
                `${record.index}, which does not rebuild to the commitment the tree holds. The ` +
                'value is the one field of a coinbase note the chain decides, and a wrong one ' +
                "reads the wallet's own reward as nobody's. Nothing has been changed.",
            );
          }
          if (mined && !labelSaysOurs) {
            // Counted rather than refused. The note is this wallet's, because
            // only its coinbase viewing key derives that commitment, and it is
            // spendable with the key this wallet holds. Refusing here would
            // leave the reward behind and stop every later pass with it, which
            // is a whole-sync denial for the price of one forged header field.
            // On a block a Qnero node built the label and the note come out of
            // one key, so a non-zero count is a header this wallet is being
            // handed for a block it did not come from, and the checkpoint fork
            // walk is what finds out against another node.
            report.coinbaseLabelDisagreed += 1;
          }
          if (received === null) {
            // Somebody else's coinbase, or a value that opens nothing. A
            // ciphertext at this position is still tried: under v1 a coinbase
            // carries none, so one here is a leaf that may not be a coinbase
            // at all, and skipping it is the silent step-over this pass exists
            // to close.
            received = decrypted.get(record.index) ?? null;
          }
        } else {
          // Not this wallet's, or a ciphertext nothing in this wallet can
          // open. A leaf with no ciphertext does not reach here: the rules
          // above refuse it below the count, and above the count the loop has
          // already moved on.
          received = decrypted.get(record.index) ?? null;
        }
        if (received === null) {
          continue;
        }

        const existing = notes.get(commitment);
        if (existing !== undefined) {
          if (rewound && reconciles) {
            seenAgain.add(commitment);
          }
          // Unconditional, the rescan included: a commitment the chain carries
          // at another index is a note whose stored index is stale, and leaving
          // it stale is what makes a note unspendable. This only ever adds,
          // because it moves a note to where the chain has it.
          // Back on chain unconditionally: this leaf is in the tree at this
          // block hash, whatever a previous pass wrote. A move is what is
          // counted, and only a move: a commitment met again at the same leaf
          // and the same block is a note quietly put back, which is what the
          // command-line wallet's `relocate_note` reports too.
          existing.note.onChain = true;
          if (
            existing.note.leafIndex !== record.index ||
            existing.note.blockNumber !== record.blockNumber
          ) {
            existing.note.leafIndex = record.index;
            existing.note.blockNumber = record.blockNumber;
            report.relocated += 1;
          }
          continue;
        }

        const nullifier = normaliseHash(received.nullifier);
        if (settled.has(nullifier)) {
          // The one refusal left, and it is provisional: a reorg that orphans
          // the settlement makes the same leaf acceptable on the next pass.
          //
          // A note this wallet already holds never reaches here: the branch
          // above returns first, so a wallet's own spent notes are relocated
          // rather than refused.
          if (!rejected.has(commitment)) {
            report.rejected += 1;
          }
          rejected.set(commitment, {
            commitment,
            leafIndex: record.index,
            value: received.value.toString(),
            reason: 'its nullifier is already settled on chain',
          });
          continue;
        }

        const origin: NoteOrigin = isCoinbase
          ? 'coinbase'
          : await originOf(crypto, record.blockNumber, received.rho, entryCount);

        report.received += 1;
        report.receivedValue += received.value;
        if (isCoinbase) {
          report.coinbaseReceived += 1;
        }
        if (rewound && reconciles) {
          // A note first recorded by this scan is on chain by construction.
          seenAgain.add(commitment);
        }
        notes.set(commitment, {
          note: {
            commitment,
            leafIndex: record.index,
            blockNumber: record.blockNumber,
            value: received.value.toString(),
            origin,
            spent: false,
            spentSeenAtBlock: null,
            onChain: true,
            // Sealed by the caller, which holds the key.
            secret: { v: 1, iv: '', ct: '' },
          },
          secret: {
            rho: received.rho,
            r: received.r,
            nullifier,
            memo: received.memo,
          },
        });
        if (input.pending.some((entry) => entry.commitment === commitment)) {
          clearedPending.push(commitment);
        }
      }
    }

    // A leaf this scan accepted cannot still be a refusal. Once per pass
    // rather than once per note: it is a walk over two small lists.
    for (const commitment of [...rejected.keys()]) {
      if (notes.has(commitment)) {
        rejected.delete(commitment);
        report.rejectedCleared += 1;
      }
    }
  }

  // Spent status, derived afresh from the whole paged set, in both directions.
  //
  // The flag is not a latch. A settlement whose block is orphaned and which
  // never re-lands leaves its nullifier permanently absent, and a latched note
  // would be out of the balance forever while fully spendable on chain.
  //
  // The two directions are asymmetric. Set on presence. Clear only when the
  // head this pass was pinned to is at or above the height the flag was set
  // at: an absent nullifier is either an orphaned settlement or a node that
  // has not reached the block that settled it, and clearing wrongly puts a
  // consumed note back into selection and pays for a proof the chain skips.
  for (const entry of notes.values()) {
    const isSettled = settled.has(normaliseHash(entry.secret.nullifier));
    if (isSettled && !entry.note.spent) {
      entry.note.spent = true;
      // The head this pass was pinned to. `UsedNullifiers` carries no height,
      // so the block that settled it is unknown here.
      entry.note.spentSeenAtBlock = head.number;
      report.newlySpent += 1;
      continue;
    }
    if (!isSettled && entry.note.spent) {
      const seen = entry.note.spentSeenAtBlock;
      const aboveThisHead = seen !== null && head.number < seen;
      if (!reconciles || aboveThisHead) {
        report.heldSpent += 1;
      } else {
        entry.note.spent = false;
        entry.note.spentSeenAtBlock = null;
        report.newlyUnspent += 1;
      }
    }
  }

  // A re-walked range that did not carry a note back is a note this chain does
  // not have. It stays in the store, because its secrets are the only copy
  // this wallet holds and a later block can still re-include the extrinsic,
  // and it is marked off chain so the balance agrees with the chain.
  //
  // After the reconciliation above, and that ordering is the whole of it: a
  // note that was spent and whose own creating leaf was orphaned in the same
  // reorg still carried `spent: true` a moment ago, so a filter on unspent
  // skipped it, and the reconciliation then flipped it and let it back in as a
  // phantom.
  //
  // Never under a rescan. The marking says "the chain does not carry this
  // note", and the evidence is a range walked on a node proved to be at or
  // ahead of everything this wallet has read. A rescan may have bypassed that
  // proof, and against a node that is behind every leaf it has not reached
  // looks exactly like a leaf that is gone.
  // Never over a spent note either, which is `mark_off_chain`'s own gate. A
  // reorg that orphans both a note's settlement and its creating leaf leaves
  // it spent and not met again, and writing `onChain: false` on it would
  // render it under the `off chain` heading, which is where value the chain
  // may still honour goes, and count it in `vanished`, which would tell the
  // operator it lost a note whose value was already gone.
  if (rewound && reconciles) {
    for (const entry of notes.values()) {
      if (entry.note.leafIndex >= watermark && !seenAgain.has(entry.note.commitment)) {
        if (entry.note.onChain && !entry.note.spent) {
          entry.note.onChain = false;
          report.vanished += 1;
        }
      }
    }
  }
  if (rescan) {
    warnings.push(
      'rescan: add-only, spent flags and orphans are not reconciled; run a normal sync against ' +
        'a current node afterwards.',
    );
  }
  if (report.coinbaseLabelDisagreed > 0) {
    // The one operator-visible signal for a node that rebuilt the headers, and
    // it existed only in the command-line wallet: the field was counted here
    // and read by nothing. Never on a block a Qnero node built, because the
    // author label and the note's own randomness come out of one coinbase
    // viewing key, so a non-zero count is a header this wallet is being handed
    // for a block it did not come from. The wording is the command-line
    // wallet's.
    const notes = report.coinbaseLabelDisagreed === 1 ? 'note' : 'notes';
    warnings.push(
      `${report.coinbaseLabelDisagreed} coinbase ${notes} this wallet rebuilt as its own sit in ` +
        "blocks whose author label is not this wallet's. The reward is taken, because only this " +
        "wallet's coinbase viewing key derives that commitment. Sync against a second node: a " +
        'branch built for this wallet alone is what the checkpoint walk finds there.',
    );
  }
  if (report.leavesScanned > 0 && report.received === 0) {
    // The ordinary case on most passes, because almost every leaf on the chain
    // is somebody else's, and also exactly what one substituted ciphertext
    // looks like. `Shielded::Ciphertexts(i)` is the one per-leaf value nothing
    // on chain binds to leaf `i`: the commitment the tree authenticates
    // carries no ciphertext, and `ct_digest` binds the bytes only inside the
    // settlement extrinsic at inclusion, which a storage-only reader never
    // fetches. So a node with honest headers can answer a stranger's bytes at
    // an incoming payment, the leaf reads as somebody else's and the watermark
    // is written above it. The checkpoint fork walk does not recover it,
    // because the headers agree. The sentence is the command-line wallet's
    // `CIPHERTEXT_SUBSTITUTION_HINT`, and `docs/WALLET.md` carries the bound.
    warnings.push(
      'a pass that reads leaves and receives nothing is the ordinary case, and it is also what ' +
        'one substituted ciphertext looks like: Shielded::Ciphertexts is the only per-leaf value ' +
        'nothing on chain binds to its leaf, so a node with honest headers can answer a ' +
        "stranger's bytes at an incoming payment and the leaf reads as somebody else's. If a " +
        'payment was expected and is not here, rescan against a second node, which is the ' +
        'recovery.',
    );
  }

  // One checkpoint per chunk of the header walk, ascending, and every one of
  // them names a block whose header this pass fetched and rehashed down to a
  // hash it already trusted. A pass that scanned no leaf walked the headers
  // anyway, which is what keeps an idle pass from planting a checkpoint on a
  // hash nothing was fetched for: the next pass's walk stands on that hash.
  //
  // Every existing checkpoint at or above the lowest new one goes first.
  // Syncing twice inside one block interval otherwise appends a second entry
  // at the same height, the trim drops the oldest real checkpoint to make
  // room, and the store collapses the pair afterwards because it is keyed on
  // the height: sixteen slots become fifteen, permanently, and the fork walk
  // can rewind less far.
  const lowestNew = typing.checkpoints[0]?.blockNumber ?? head.number;
  const nextCheckpoints = [
    ...checkpoints.filter((checkpoint) => checkpoint.blockNumber < lowestNew),
    ...typing.checkpoints.map((checkpoint) => ({
      blockNumber: checkpoint.blockNumber,
      blockHash: normaliseHash(checkpoint.blockHash),
      nextLeaf: checkpoint.nextLeaf,
    })),
  ].slice(-MAX_CHECKPOINTS);

  // Pending rows whose settlement can no longer be admitted.
  //
  // A spend writes its change note before it submits, and the row clears when
  // a scan meets that commitment in the tree. Three failures leave a
  // commitment that is never appended: a pool that refuses the envelope, a
  // segment skipped for a stale anchor or a claimed nullifier, and a
  // settlement nothing carries inside the window. The spend drops the row on
  // the first two, because it is there to see them. This is the third, and the
  // one nothing else can see: once the anchor is more than `anchorWindow`
  // blocks below the head, the chain will not admit that settlement at all.
  //
  // Dropping is safe when the bytes did land after all: the scan that meets
  // the leaf adds the note as a real one.
  for (const entry of input.pending) {
    if (clearedPending.includes(entry.commitment)) {
      continue;
    }
    if (head.number > entry.submittedAtBlock + chain.anchorWindow) {
      clearedPending.push(entry.commitment);
      report.pendingAbandoned += 1;
    }
  }
  if (report.pendingAbandoned > 0) {
    warnings.push(
      `${report.pendingAbandoned} submitted ${report.pendingAbandoned === 1 ? 'payment' : 'payments'} ` +
        `never settled inside the ${chain.anchorWindow}-block anchor window and ` +
        `${report.pendingAbandoned === 1 ? 'its change note is' : 'their change notes are'} no ` +
        'longer counted as pending. The notes they would have spent are unspent.',
    );
  }

  report.recordedGenesis = input.meta.genesisHash === null;

  return {
    meta: {
      ...input.meta,
      genesisHash: input.meta.genesisHash ?? genesis,
      lastSyncedBlock: head.number,
      nextLeaf: shape.leafCount,
    },
    notes: [...notes.values()],
    removedNotes: [],
    rejected: [...rejected.values()],
    removedRejected: input.rejected
      .map((entry) => entry.commitment)
      .filter((commitment) => !rejected.has(commitment)),
    checkpoints: nextCheckpoints,
    clearedPending,
    report,
  };
}
