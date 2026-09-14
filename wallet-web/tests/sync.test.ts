/**
 * The node gates and the reconciliation, rule for rule.
 *
 * These are the rules that decide whether a balance is right, and every one of
 * them has a failure behind it that looks like nothing at all: a node that is
 * behind reports settled notes as unspent, a node at a fork reports a note at
 * an index the chain does not have, a latched spent flag hides value forever,
 * and a cleared one pays for a proof the chain skips.
 *
 * The chain and the prover are both interfaces here, which is what lets the
 * rules be driven directly. `privacy.test.ts` drives the same rules through
 * the real read layer, because what the node is asked is a separate property
 * from what is done with the answers.
 */

import { describe, expect, it } from 'vitest';

import {
  NodeRefusedError,
  readNodeStance,
  runSync,
  type ScannedNote,
  type SyncChain,
  type SyncCrypto,
} from '../src/wallet/sync';
import { STORE_VERSION, type NoteSecret, type StoreMeta, type StoredNote } from '../src/wallet/model';

const GENESIS = '11'.repeat(32);

function hashAtHeight(height: number): string {
  return `${height}`.padStart(64, '0');
}

function meta(overrides: Partial<StoreMeta> = {}): StoreMeta {
  return {
    id: 'store',
    schemaVersion: STORE_VERSION,
    address: 'qn1test',
    genesisHash: GENESIS,
    lastSyncedBlock: 0,
    nextLeaf: 0,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000, saltHex: '00'.repeat(16) },
    createdAt: 0,
    updatedAt: 0,
    upgrades: [],
    ...overrides,
  };
}

interface FakeLeaf {
  index: number;
  commitment: string;
  blockNumber: number;
  note: ScannedNote | null;
  coinbaseQuanta?: bigint;
}

function fakeChain(options: {
  head: number;
  leaves: FakeLeaf[];
  settled?: Set<string>;
  genesis?: string;
  leafCount?: number;
  hashAt?: (height: number) => string | null;
}): SyncChain {
  const leafCount = options.leafCount ?? options.leaves.length;
  return {
    head: () => Promise.resolve({ number: options.head, hash: hashAtHeight(options.head) }),
    genesisHash: () => Promise.resolve(options.genesis ?? GENESIS),
    blockHashAt: (height) =>
      Promise.resolve(options.hashAt === undefined ? hashAtHeight(height) : options.hashAt(height)),
    treeShape: () => Promise.resolve({ leafCount, depth: 3 }),
    leaves: (from, to) =>
      Promise.resolve(
        options.leaves
          .filter((leaf) => leaf.index >= from && leaf.index < to)
          .map((leaf) => ({
            index: leaf.index,
            commitment: leaf.commitment,
            ciphertext: leaf.coinbaseQuanta === undefined ? new Uint8Array([1, 2, 3]) : null,
            blockNumber: leaf.blockNumber,
            coinbaseQuanta: leaf.coinbaseQuanta ?? null,
          })),
      ),
    usedNullifiers: () => Promise.resolve(options.settled ?? new Set<string>()),
    entryCount: () => Promise.resolve(0n),
  };
}

function fakeCrypto(leaves: readonly FakeLeaf[]): SyncCrypto {
  const byIndex = new Map(leaves.map((leaf) => [leaf.index, leaf.note]));
  return {
    decryptBatch: (items) => Promise.resolve(items.map((item) => byIndex.get(item.index) ?? null)),
    coinbaseBatch: (items) =>
      Promise.resolve(
        items.map((item) => {
          const leaf = leaves.find((entry) => entry.blockNumber === item.blockNumber);
          return leaf?.note ?? null;
        }),
      ),
    entryRho: () => Promise.resolve('00'.repeat(32)),
  };
}

function note(value: bigint, suffix: string): ScannedNote {
  return {
    value,
    rho: suffix.repeat(32),
    r: suffix.repeat(32),
    commitment: suffix.repeat(32),
    nullifier: `n${suffix}`.repeat(16),
    memo: '',
  };
}

function held(scanned: ScannedNote, overrides: Partial<StoredNote> = {}): {
  note: StoredNote;
  secret: NoteSecret;
} {
  return {
    note: {
      commitment: scanned.commitment,
      leafIndex: 0,
      blockNumber: 1,
      value: scanned.value.toString(),
      origin: 'transfer',
      spent: false,
      spentSeenAtBlock: null,
      onChain: true,
      secret: { v: 1, iv: '', ct: '' },
      ...overrides,
    },
    secret: {
      rho: scanned.rho,
      r: scanned.r,
      nullifier: scanned.nullifier,
      memo: scanned.memo,
    },
  };
}

describe('the checkpoint-hash fork walk', () => {
  const checkpoints = [
    { blockNumber: 10, blockHash: hashAtHeight(10), nextLeaf: 4 },
    { blockNumber: 20, blockHash: hashAtHeight(20), nextLeaf: 8 },
  ];

  it('says current when every checkpoint still stands', async () => {
    const stance = await readNodeStance(
      checkpoints,
      { number: 25 },
      (height) => Promise.resolve(hashAtHeight(height)),
      20,
    );
    expect(stance).toEqual({ kind: 'current' });
  });

  it('refuses a node behind this wallet rather than reading its short set', async () => {
    // Head 15: the checkpoint at 20 is above it, and the one at 10 still
    // stands. A node that has not executed the blocks this wallet has read is
    // missing every settlement in them, and the reconciliation would read that
    // as those notes coming back into the balance.
    await expect(
      readNodeStance(checkpoints, { number: 15 }, (height) => Promise.resolve(hashAtHeight(height)), 20),
    ).rejects.toBeInstanceOf(NodeRefusedError);
  });

  it('rewinds to the newest checkpoint that survives a fork', async () => {
    const stance = await readNodeStance(
      checkpoints,
      { number: 25 },
      (height) => Promise.resolve(height === 20 ? 'ff'.repeat(32) : hashAtHeight(height)),
      20,
    );
    expect(stance).toEqual({ kind: 'forked', atBlock: 10, nextLeaf: 4 });
  });

  it('walks the whole tree again when no checkpoint survives', async () => {
    const stance = await readNodeStance(
      checkpoints,
      { number: 25 },
      () => Promise.resolve('ff'.repeat(32)),
      20,
    );
    expect(stance).toEqual({ kind: 'forked', atBlock: 0, nextLeaf: 0 });
  });

  it('refuses a node with no block at a height below its own head', async () => {
    // Not a fork: a fork is a different block there. No block at all is a node
    // that is pruned or has not filled in behind its head, and rewinding on it
    // would rescan against a tree smaller than the one already recorded.
    await expect(
      readNodeStance(checkpoints, { number: 25 }, () => Promise.resolve(null), 20),
    ).rejects.toBeInstanceOf(NodeRefusedError);
  });
});

describe('the gates a sync passes before it writes', () => {
  it('refuses a node serving another chain, and changes nothing', async () => {
    const leaves: FakeLeaf[] = [];
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, genesis: '99'.repeat(32) }),
        fakeCrypto(leaves),
      ),
    ).rejects.toBeInstanceOf(NodeRefusedError);
  });

  it('records the genesis on the first pass that commits', async () => {
    const leaves: FakeLeaf[] = [];
    const result = await runSync(
      { meta: meta({ genesisHash: null }), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.meta.genesisHash).toBe(GENESIS);
    expect(result.report.recordedGenesis).toBe(true);
  });

  it('refuses a node whose leaf count is below the watermark', async () => {
    // On this chain, above every checkpoint, and still short: a head it has
    // not finished executing. The scan range would be empty, the vanished
    // check skipped, and the watermark written back down.
    const leaves: FakeLeaf[] = [];
    await expect(
      runSync(
        { meta: meta({ nextLeaf: 9 }), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, leafCount: 4 }),
        fakeCrypto(leaves),
      ),
    ).rejects.toBeInstanceOf(NodeRefusedError);
  });
});

describe('the hex a scan hands the prover', () => {
  it('carries no 0x prefix, which the module would refuse as not-hex', async () => {
    // The chain answers with `0x`-prefixed hex and the module parses hex. A
    // prefix makes every ciphertext refuse, and a refusal is the ordinary
    // answer for a ciphertext that is not this wallet's, so the wallet reads
    // its own payments as nobody's with no error anywhere. This was a real
    // bug, found against a live node and not by any assertion over a balance.
    const mine = note(1000n, 'a0');
    const leaves: FakeLeaf[] = [
      { index: 0, commitment: `0x${mine.commitment}`, blockNumber: 1, note: mine },
    ];
    const seen: string[] = [];
    const crypto = fakeCrypto(leaves);
    const recording: SyncCrypto = {
      ...crypto,
      decryptBatch: (items) => {
        seen.push(...items.map((item) => item.commitment));
        return crypto.decryptBatch(items);
      },
    };
    await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves }),
      recording,
    );
    expect(seen).toEqual([mine.commitment]);
  });
});

describe('what a scan does with what it finds', () => {
  it('keeps a note whose ciphertext opens against the published commitment', async () => {
    const mine = note(1000n, 'a1');
    const leaves: FakeLeaf[] = [
      { index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null },
      { index: 1, commitment: mine.commitment, blockNumber: 2, note: mine },
    ];
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.report.received).toBe(1);
    expect(result.report.receivedValue).toBe(1000n);
    expect(result.notes[0]?.note.leafIndex).toBe(1);
  });

  it('refuses an output whose nullifier the chain has already settled', async () => {
    const mine = note(1000n, 'a2');
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves, settled: new Set([mine.nullifier]) }),
      fakeCrypto(leaves),
    );
    expect(result.notes).toHaveLength(0);
    expect(result.rejected[0]?.reason).toMatch(/already settled/);
  });

  it('drops the refusal when a later pass ends up holding the note', async () => {
    const mine = note(1000n, 'a3');
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      {
        meta: meta(),
        held: [],
        rejected: [{ commitment: mine.commitment, leafIndex: 0, value: '1000', reason: 'settled' }],
        checkpoints: [],
        pending: [],
      },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.rejected).toHaveLength(0);
    expect(result.removedRejected).toEqual([mine.commitment]);
    expect(result.report.rejectedCleared).toBe(1);
  });

  it('relocates a held note the chain carries at another index', async () => {
    const mine = note(1000n, 'a4');
    const leaves: FakeLeaf[] = [
      { index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null },
      { index: 1, commitment: mine.commitment, blockNumber: 2, note: mine },
    ];
    const result = await runSync(
      {
        meta: meta(),
        held: [held(mine, { leafIndex: 7, blockNumber: 99 })],
        rejected: [],
        checkpoints: [],
        pending: [],
      },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.report.relocated).toBe(1);
    expect(result.notes[0]?.note.leafIndex).toBe(1);
  });
});

describe('spent status, derived afresh in both directions', () => {
  const mine = note(1000n, 'b1');

  it('marks spent on presence, and records the head it was seen at', async () => {
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      { meta: meta(), held: [held(mine)], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves, settled: new Set([mine.nullifier]) }),
      fakeCrypto(leaves),
    );
    expect(result.notes[0]?.note.spent).toBe(true);
    // The head this pass was pinned to. The map carries no height, so the
    // block that settled it is unknown to the wallet.
    expect(result.notes[0]?.note.spentSeenAtBlock).toBe(5);
    expect(result.report.newlySpent).toBe(1);
  });

  it('clears the flag when the settlement is gone and this node is at or past the height', async () => {
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      {
        meta: meta(),
        held: [held(mine, { spent: true, spentSeenAtBlock: 4 })],
        rejected: [],
        checkpoints: [],
        pending: [],
      },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.notes[0]?.note.spent).toBe(false);
    expect(result.report.newlyUnspent).toBe(1);
  });

  it('holds the flag when this node has not reached the height it was set at', async () => {
    // Clearing is the direction that can lose money: an absent nullifier below
    // that height is an orphaned settlement, and above it is a node that has
    // not got there yet.
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      {
        meta: meta(),
        held: [held(mine, { spent: true, spentSeenAtBlock: 9 })],
        rejected: [],
        checkpoints: [],
        pending: [],
      },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.notes[0]?.note.spent).toBe(true);
    expect(result.report.heldSpent).toBe(1);
  });
});

describe('a rescan', () => {
  const mine = note(1000n, 'c1');

  it('runs add only, and says so', async () => {
    const leaves: FakeLeaf[] = [{ index: 0, commitment: mine.commitment, blockNumber: 1, note: mine }];
    const result = await runSync(
      {
        meta: meta({ nextLeaf: 1 }),
        held: [held(mine, { spent: true, spentSeenAtBlock: 1 })],
        rejected: [],
        checkpoints: [],
        pending: [],
      },
      fakeChain({ head: 5, leaves }),
      fakeCrypto(leaves),
      { rescan: true },
    );
    // The nullifier is absent from this node's set and the flag stays, because
    // the evidence for clearing it is the node gate the rescan bypassed.
    expect(result.notes[0]?.note.spent).toBe(true);
    expect(result.report.addOnly).toBe(true);
    expect(result.report.vanished).toBe(0);
    expect(result.report.warnings.join(' ')).toMatch(/add-only/);
  });

  it('is never a bypass of the chain check', async () => {
    const leaves: FakeLeaf[] = [];
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, genesis: '99'.repeat(32) }),
        fakeCrypto(leaves),
        { rescan: true },
      ),
    ).rejects.toBeInstanceOf(NodeRefusedError);
  });
});

describe('a reorg that takes a leaf away', () => {
  const mine = note(1000n, 'd1');

  it('marks the note off chain, keeps its secrets, and keeps its index', async () => {
    // The node forked below the checkpoint, so the range is walked again and
    // this note is not met in it.
    const leaves: FakeLeaf[] = [{ index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null }];
    const result = await runSync(
      {
        meta: meta({ nextLeaf: 2, lastSyncedBlock: 20 }),
        held: [held(mine, { leafIndex: 1, blockNumber: 18 })],
        rejected: [],
        checkpoints: [{ blockNumber: 20, blockHash: 'ff'.repeat(32), nextLeaf: 2 }],
        pending: [],
      },
      fakeChain({ head: 25, leaves, leafCount: 1 }),
      fakeCrypto(leaves),
    );
    expect(result.report.forkedAt).toBe(0);
    expect(result.notes[0]?.note.onChain).toBe(false);
    expect(result.notes[0]?.secret.r).toBe(mine.r);
    expect(result.notes[0]?.note.leafIndex).toBe(1);
    expect(result.report.vanished).toBe(1);
  });

  it('leaves a spent note spent rather than marking it off chain', async () => {
    // Both the settlement and the creating leaf were orphaned. The note is
    // still spent (its nullifier is still in the settled set) and the re-walked
    // range does not carry it back. `off chain` is the heading for value the
    // chain may still honour, and this note's value is already gone, so the
    // command-line wallet's `mark_off_chain` refuses a spent note outright.
    const leaves: FakeLeaf[] = [{ index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null }];
    const result = await runSync(
      {
        meta: meta({ nextLeaf: 2, lastSyncedBlock: 20 }),
        held: [
          held(mine, { leafIndex: 1, blockNumber: 18, spent: true, spentSeenAtBlock: 19 }),
        ],
        rejected: [],
        checkpoints: [{ blockNumber: 20, blockHash: 'ff'.repeat(32), nextLeaf: 2 }],
        pending: [],
      },
      fakeChain({ head: 25, leaves, leafCount: 1, settled: new Set([mine.nullifier]) }),
      fakeCrypto(leaves),
    );
    expect(result.notes[0]?.note.spent).toBe(true);
    expect(result.notes[0]?.note.onChain).toBe(true);
    expect(result.report.vanished).toBe(0);
  });
});

describe('the checkpoints a pass writes', () => {
  it('replaces the one at this head rather than spending a slot on it', async () => {
    // Two syncs inside one block interval. Appending a second entry at the
    // same height costs a slot: the trim drops the oldest real checkpoint to
    // make room, and the store collapses the pair afterwards because it is
    // keyed on the height. Sixteen slots would become fifteen for good, and
    // the fork walk could rewind that much less far.
    const leaves: FakeLeaf[] = [{ index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null }];
    const existing = [
      { blockNumber: 4, blockHash: hashAtHeight(4), nextLeaf: 1 },
      { blockNumber: 9, blockHash: hashAtHeight(9), nextLeaf: 1 },
    ];
    const result = await runSync(
      {
        meta: meta({ nextLeaf: 1, lastSyncedBlock: 9 }),
        held: [],
        rejected: [],
        checkpoints: existing,
        pending: [],
      },
      fakeChain({ head: 9, leaves, leafCount: 1 }),
      fakeCrypto(leaves),
    );
    expect(result.checkpoints.map((entry) => entry.blockNumber)).toEqual([4, 9]);
  });
});
