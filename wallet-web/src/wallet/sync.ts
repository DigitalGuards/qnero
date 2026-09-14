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

import { MAX_CHECKPOINTS, type NoteOrigin, type NoteSecret, type RejectedNote, type StoreMeta, type StoredNote, type SyncCheckpoint } from './model';

/** What a scan needs out of the chain, so a test can supply it. */
export interface SyncChain {
  head(): Promise<{ number: number; hash: string }>;
  genesisHash(): Promise<string>;
  blockHashAt(height: number): Promise<string | null>;
  treeShape(at: string): Promise<{ leafCount: number; depth: number }>;
  leaves(
    from: number,
    to: number,
    at: string,
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
  entryCount(at: string): Promise<bigint>;
}

/** One decrypted output, with the two digests only the seed can produce. */
export interface ScannedNote {
  value: bigint;
  rho: string;
  r: string;
  commitment: string;
  nullifier: string;
  memo: string;
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
   * The coinbase note this wallet's miner key mints at a height, rebuilt from
   * the key rather than read out of a ciphertext.
   */
  coinbaseNote(blockNumber: number, value: bigint, genesisHash: string): Promise<ScannedNote>;
  /** `rho = H(RHO_ENTRY, block, index)`, for telling a shield from a spend output. */
  entryRho(blockNumber: number, entryIndex: bigint): Promise<string>;
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
  pending: readonly string[];
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
  relocated: number;
  rejected: number;
  rejectedCleared: number;
  newlySpent: number;
  newlyUnspent: number;
  heldSpent: number;
  vanished: number;
  nullifierSetSize: number;
  recordedGenesis: boolean;
  forkedAt: number | null;
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

function normaliseHash(hash: string): string {
  return hash.toLowerCase().replace(/^0x/, '');
}

/**
 * A `rho` that came from the shield counter, which is what tells a shield
 * apart from a spend's output.
 *
 * The counter is chain wide and read once per pass, so this walks candidate
 * entry indices rather than asking per note. Only ever a label: getting it
 * wrong misfiles a note's origin and moves no value.
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
  // A shield predicts `(head + 1, EntryCount)`, so the entry index of one that
  // settled is below the counter read at the head. The walk is bounded: a
  // handful of entries per block at most, and the counter only grows.
  const window = 64n;
  const from = entryCount > window ? entryCount - window : 0n;
  for (let index = from; index < entryCount; index += 1n) {
    if ((await crypto.entryRho(blockNumber, index)) === rho) {
      return 'shield';
    }
  }
  return 'transfer';
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
    relocated: 0,
    rejected: 0,
    rejectedCleared: 0,
    newlySpent: 0,
    newlyUnspent: 0,
    heldSpent: 0,
    vanished: 0,
    nullifierSetSize: settled.size,
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

  if (shape.leafCount > watermark) {
    const entryCount = await chain.entryCount(head.hash);
    const records = await chain.leaves(watermark, shape.leafCount, head.hash, (done) => {
      progress('scan', `${done} of ${shape.leafCount - watermark} leaves`);
    });

    // Decryption goes over the boundary in batches, so a scan is one round
    // trip per batch rather than one per leaf.
    const BATCH = 64;
    const candidates = records.filter(
      (record) => record.commitment !== null && record.ciphertext !== null,
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
      progress('scan', `${Math.min(start + BATCH, candidates.length)} of ${candidates.length} ciphertexts`);
    }

    for (const record of records) {
      report.leavesScanned += 1;
      if (record.commitment === null) {
        // A gap in the leaf map, which the tree never leaves: a node
        // answering about a block it does not have.
        continue;
      }
      const commitment = normaliseHash(record.commitment);

      let received: ScannedNote | null = null;
      let isCoinbase = false;
      if (record.coinbaseQuanta !== null) {
        // A block's coinbase note. Its value is public, because the chain
        // hashed it into a commitment over an `inner` it cannot open, and the
        // rest is rebuilt from this wallet's own miner key. The commitment
        // check decides, and the value inside any payload is ignored: a
        // coinbase's amount is the chain's own arithmetic.
        isCoinbase = true;
        report.coinbaseLeaves += 1;
        if (record.blockNumber === null) {
          continue;
        }
        const rebuilt = await crypto.coinbaseNote(
          record.blockNumber,
          record.coinbaseQuanta,
          genesis,
        );
        if (normaliseHash(rebuilt.commitment) === commitment) {
          received = rebuilt;
        } else {
          // Not this wallet's coinbase, or a corrupt miner key. The gap
          // between `coinbaseLeaves` and `coinbaseReceived` is the only signal
          // of the second one.
          const fallback = decrypted.get(record.index) ?? null;
          received = fallback !== null && normaliseHash(fallback.commitment) === commitment
            ? fallback
            : null;
        }
      } else {
        // A leaf with neither ciphertext nor coinbase value is skipped: a
        // pre-v1 wormhole transfer or a transparent reward leaf, and nothing
        // appends either any more.
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
        if (
          existing.note.leafIndex !== record.index ||
          existing.note.blockNumber !== record.blockNumber ||
          !existing.note.onChain
        ) {
          existing.note.leafIndex = record.index;
          existing.note.blockNumber = record.blockNumber;
          existing.note.onChain = true;
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
      if (input.pending.includes(commitment)) {
        clearedPending.push(commitment);
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
  if (rewound && reconciles) {
    for (const entry of notes.values()) {
      if (entry.note.leafIndex >= watermark && !seenAgain.has(entry.note.commitment)) {
        if (entry.note.onChain) {
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

  const nextCheckpoints = [...checkpoints, {
    blockNumber: head.number,
    blockHash: normaliseHash(head.hash),
    nextLeaf: shape.leafCount,
  }].slice(-MAX_CHECKPOINTS);

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
