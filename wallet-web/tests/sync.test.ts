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
import { ENTRY_WALK_LIMIT } from '../src/worker/protocol';

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

/** The runtime's `BlockHashWindow`, which is 256 on this chain. */
const ANCHOR_WINDOW = 256;

/** The four per-leaf keys a node can answer with nothing. */
type LeafKey = 'commitment' | 'ciphertext' | 'blockNumber' | 'coinbaseQuanta';

/**
 * Every leaf below the count, with all four of its keys.
 *
 * `pallet-zk-tree` appends a leaf and raises `LeafCount` in one call and
 * `pallet-shielded` writes the leaf's other keys in that same call, so a chain
 * has no gaps under its own count: a fixture that names three leaves and a
 * count of 130 is describing something no node can serve, and a scan driven by
 * one is never asked the question the refusals exist for. The leaves a test
 * names are the ones with notes on them; the rest are filled in here and
 * belong to nobody.
 *
 * `withheld` is the hook a test takes one key away with, per key and per
 * index, because each of the four hides a leaf in its own way.
 */
function fakeChain(options: {
  head: number;
  leaves: FakeLeaf[];
  settled?: Set<string>;
  genesis?: string;
  leafCount?: number;
  hashAt?: (height: number) => string | null;
  drift?: string[];
  anchorWindow?: number;
  entryCount?: bigint;
  withheld?: Partial<Record<LeafKey, number[]>>;
}): SyncChain {
  const leafCount = options.leafCount ?? options.leaves.length;
  const declared = new Map(options.leaves.map((leaf) => [leaf.index, leaf]));
  const withheld = (key: LeafKey, index: number): boolean =>
    options.withheld?.[key]?.includes(index) ?? false;
  return {
    storageDrift: options.drift ?? [],
    anchorWindow: options.anchorWindow ?? ANCHOR_WINDOW,
    head: () => Promise.resolve({ number: options.head, hash: hashAtHeight(options.head) }),
    genesisHash: () => Promise.resolve(options.genesis ?? GENESIS),
    blockHashAt: (height) =>
      Promise.resolve(options.hashAt === undefined ? hashAtHeight(height) : options.hashAt(height)),
    treeShape: () =>
      Promise.resolve({ leafCount, depth: 3, entryCount: options.entryCount ?? 0n }),
    leaves: (from, to) => {
      const rows = [];
      for (let index = from; index < Math.min(to, leafCount); index += 1) {
        const leaf = declared.get(index);
        const isCoinbase = leaf?.coinbaseQuanta !== undefined;
        rows.push({
          index,
          commitment: withheld('commitment', index)
            ? null
            : (leaf?.commitment ?? `f${index.toString(16)}`.padStart(64, '0')),
          // A coinbase leaf carries no ciphertext under v1, and every other
          // leaf carries one: an unnamed leaf gets bytes nothing can open.
          ciphertext:
            isCoinbase || withheld('ciphertext', index) ? null : new Uint8Array([1, 2, 3]),
          blockNumber: withheld('blockNumber', index) ? null : (leaf?.blockNumber ?? 1),
          coinbaseQuanta:
            withheld('coinbaseQuanta', index) ? null : (leaf?.coinbaseQuanta ?? null),
        });
      }
      return Promise.resolve(rows);
    },
    usedNullifiers: () => Promise.resolve(options.settled ?? new Set<string>()),
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
    entryRhoMatches: () => Promise.resolve(false),
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

  it('refuses a runtime whose storage it cannot read, before it reads anything', async () => {
    // The refusal the command-line wallet opens `sync_with` with. A renamed
    // item or a changed hasher builds a key that is simply absent, and an
    // absent key is indistinguishable from an empty map: `LeafCount` reads
    // zero, the scan finds nothing, and the wallet reports a zero balance with
    // no error at all. The screen checked this and the module did not, so any
    // caller that was not the screen skipped it.
    const leaves: FakeLeaf[] = [];
    let asked = 0;
    const chain = fakeChain({ head: 5, leaves, drift: ['ZkTree::Leaves is gone'] });
    const watched: SyncChain = {
      ...chain,
      genesisHash: () => {
        asked += 1;
        return chain.genesisHash();
      },
    };
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        watched,
        fakeCrypto(leaves),
      ),
    ).rejects.toBeInstanceOf(NodeRefusedError);
    expect(asked).toBe(0);
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

describe('a key the node withholds inside the scanned range', () => {
  /**
   * The pass is refused, nothing is written, and the watermark does not move.
   *
   * The chain has no gaps below `LeafCount`: `pallet-zk-tree` appends a leaf
   * and raises the count in one call, and `pallet-shielded` writes that leaf's
   * `Ciphertexts`, `LeafBlocks` and, for a coinbase, `CoinbaseValues` in the
   * same call. Nothing removes any of them. So an absent answer at an index
   * below the count read at this same block hash is a node withholding one,
   * and every one of them used to be stepped over in silence: the pass
   * reported the leaf as scanned, committed `nextLeaf` and a checkpoint above
   * it, and every later pass started above it, so a payment on that leaf was
   * out of the balance permanently with no error, no warning and no field in
   * the report.
   *
   * The refusal covered the commitment alone, which left the keys beside it as
   * three more ways to hide the same payment. One test each.
   */
  const mine = note(1000n, 'a1');
  const leaves: FakeLeaf[] = [
    { index: 0, commitment: 'cd'.repeat(32), blockNumber: 1, note: null },
    { index: 1, commitment: mine.commitment, blockNumber: 1, note: mine },
    { index: 2, commitment: 'ce'.repeat(32), blockNumber: 2, note: null },
  ];

  it('finds the payment when the node answers for every key, which is what the refusals guard', async () => {
    const found = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves, leafCount: 3 }),
      fakeCrypto(leaves),
    );
    expect(found.report.received).toBe(1);
    expect(found.meta.nextLeaf).toBe(3);
  });

  it('refuses an absent commitment rather than scanning past it', async () => {
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, leafCount: 3, withheld: { commitment: [1] } }),
        fakeCrypto(leaves),
      ),
    ).rejects.toThrow(/no ZkTree::Leaves\(1\)/);
  });

  it('refuses an absent ciphertext on a leaf that is not a coinbase', async () => {
    // The leaf is answered for and its ciphertext is not, so the scan reads it
    // as a leaf nobody can open: the same payment hidden through the key
    // beside the commitment.
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, leafCount: 3, withheld: { ciphertext: [1] } }),
        fakeCrypto(leaves),
      ),
    ).rejects.toThrow(/no Shielded::Ciphertexts\(1\)/);
  });

  it('refuses an absent block height', async () => {
    // `LeafBlocks` is what a coinbase note is rebuilt from and what the
    // shield-origin rule reads, so a leaf without it is a coinbase stepped
    // over and a note dated by nothing.
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves, leafCount: 3, withheld: { blockNumber: [1] } }),
        fakeCrypto(leaves),
      ),
    ).rejects.toThrow(/no Shielded::LeafBlocks\(1\)/);
  });

  it('refuses a coinbase leaf whose value is withheld, through the ciphertext rule', async () => {
    // `CoinbaseValues` is the one key of the four a leaf is allowed not to
    // have, since presence is what marks a coinbase. A withheld one leaves a
    // leaf below the count with neither a value nor a ciphertext, which is
    // what the rule beside it refuses: without that, a miner's own block
    // reward is read as somebody else's and stepped over.
    const mined = note(25n, 'c0');
    const coinbase: FakeLeaf[] = [
      { index: 0, commitment: mined.commitment, blockNumber: 3, note: mined, coinbaseQuanta: 25n },
    ];
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
        fakeChain({ head: 5, leaves: coinbase, leafCount: 1, withheld: { coinbaseQuanta: [0] } }),
        fakeCrypto(coinbase),
      ),
    ).rejects.toThrow(/no Shielded::Ciphertexts\(0\)/);

    // The same fixture answered for pays the miner.
    const paid = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves: coinbase, leafCount: 1 }),
      fakeCrypto(coinbase),
    );
    expect(paid.report.coinbaseReceived).toBe(1);
  });

  it('is a node refusal, so the caller leaves the store alone', async () => {
    for (const key of ['commitment', 'ciphertext', 'blockNumber'] as const) {
      await expect(
        runSync(
          { meta: meta({ nextLeaf: 0 }), held: [], rejected: [], checkpoints: [], pending: [] },
          fakeChain({ head: 5, leaves, leafCount: 3, withheld: { [key]: [0] } }),
          fakeCrypto(leaves),
        ),
      ).rejects.toBeInstanceOf(NodeRefusedError);
    }
  });
});

describe('a scan over more leaves than one window', () => {
  it('reads the range in contiguous windows and misses nothing between them', async () => {
    // The range used to be materialised whole before anything was decrypted,
    // and a `LeafRecord` carries the leaf's ciphertext: 1,792 bytes per leaf
    // on the chain, in the page, beside the worker's 918 MiB. It is read in
    // windows now, which is a change to what is resident and has to be no
    // change at all to what is found or to what the node is asked.
    const first = note(100n, 'a1');
    const middle = note(200n, 'b2');
    const last = note(300n, 'c3');
    const leaves: FakeLeaf[] = [
      { index: 0, commitment: first.commitment, blockNumber: 1, note: first },
      { index: 70, commitment: middle.commitment, blockNumber: 2, note: middle },
      { index: 129, commitment: last.commitment, blockNumber: 3, note: last },
    ];
    const chain = fakeChain({ head: 5, leaves, leafCount: 130 });
    const windows: [number, number][] = [];
    const watched: SyncChain = {
      ...chain,
      leaves: (from, to, at, leafCount, onProgress) => {
        windows.push([from, to]);
        return chain.leaves(from, to, at, leafCount, onProgress);
      },
    };

    const result = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      watched,
      fakeCrypto(leaves),
    );

    expect(result.report.received).toBe(3);
    // Every leaf below the count, which is what the chain carries and what the
    // three windows below walk. Three of them are this wallet's.
    expect(result.report.leavesScanned).toBe(130);
    expect(result.notes.map((entry) => entry.note.leafIndex).sort((a, b) => a - b)).toEqual([
      0, 70, 129,
    ]);
    // Contiguous, ascending, and covering the whole range: the same question
    // the whole-range read asked, in the same order.
    expect(windows).toEqual([
      [0, 64],
      [64, 128],
      [128, 130],
    ]);
    expect(result.meta.nextLeaf).toBe(130);
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

/**
 * The rows a spend writes before it submits.
 *
 * A change note is committed before `author_submitExtrinsic` so a tab
 * reclaimed in the gap still shows the change, and it clears when a scan meets
 * that commitment in the tree. A settlement that never lands leaves a
 * commitment that is never appended, so no scan can ever clear the row: the
 * balance then carries a pending figure forever, on the screen whose whole job
 * is one number, and the only control that removes it erases the wallet.
 *
 * The anchor is what makes this decidable rather than a guess. A settlement
 * more than `BlockHashWindow` blocks below the head cannot be admitted at all.
 */
describe('a pending row', () => {
  it('clears when the scan meets its commitment, which is the ordinary path', async () => {
    const change = note(700n, 'c1');
    const leaves: FakeLeaf[] = [
      { index: 0, commitment: change.commitment, blockNumber: 30, note: change },
    ];
    const result = await runSync(
      {
        meta: meta(),
        held: [],
        rejected: [],
        checkpoints: [],
        pending: [{ commitment: change.commitment, submittedAtBlock: 29 }],
      },
      fakeChain({ head: 31, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.clearedPending).toEqual([change.commitment]);
    expect(result.report.pendingAbandoned).toBe(0);
  });

  it('is held while its anchor is still inside the window', async () => {
    const leaves: FakeLeaf[] = [];
    const result = await runSync(
      {
        meta: meta(),
        held: [],
        rejected: [],
        checkpoints: [],
        pending: [{ commitment: 'ab'.repeat(32), submittedAtBlock: 100 }],
      },
      fakeChain({ head: 100 + ANCHOR_WINDOW, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.clearedPending).toEqual([]);
    expect(result.report.pendingAbandoned).toBe(0);
  });

  it('is dropped once its anchor falls out of the window, because it can never land', async () => {
    const leaves: FakeLeaf[] = [];
    const result = await runSync(
      {
        meta: meta(),
        held: [],
        rejected: [],
        checkpoints: [],
        pending: [{ commitment: 'ab'.repeat(32), submittedAtBlock: 100 }],
      },
      fakeChain({ head: 100 + ANCHOR_WINDOW + 1, leaves }),
      fakeCrypto(leaves),
    );
    expect(result.clearedPending).toEqual(['ab'.repeat(32)]);
    expect(result.report.pendingAbandoned).toBe(1);
    expect(result.report.warnings.join(' ')).toMatch(/never settled inside/);
  });
});

describe('the shield counter a pass reads', () => {
  const mine = note(500n, 'aa');
  const leaves: FakeLeaf[] = [
    { index: 0, commitment: mine.commitment, blockNumber: 1, note: mine },
  ];

  it('says out loud that the origin walk will stop short of it', async () => {
    // The walk is bounded in the worker because it is one hash per unit of a
    // number the node chose (`ENTRY_WALK_LIMIT`). Past the bound a shield is
    // labelled `transfer`, and origin is written once at receipt, so a pass
    // that quietly gave up would leave a wrong label behind with nothing said
    // anywhere.
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves, entryCount: ENTRY_WALK_LIMIT + 1n }),
      fakeCrypto(leaves),
    );
    expect(result.report.warnings.join(' ')).toMatch(/origin walk stops at/);
  });

  it('says nothing at the bound, which is every chain that exists', async () => {
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], checkpoints: [], pending: [] },
      fakeChain({ head: 5, leaves, entryCount: ENTRY_WALK_LIMIT }),
      fakeCrypto(leaves),
    );
    expect(result.report.warnings.join(' ')).not.toMatch(/origin walk/);
  });
});
