/**
 * What decides which rule opens a leaf, and what a node cannot do about it.
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
 * `crates/qnero-wallet/tests/leaf_typing.rs` is the same set against the
 * command-line wallet, and `crates/qnero-wallet/src/typing.rs` carries the
 * rules both wallets implement.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { authorLabelFromHeader, type RawChainHeader } from '../src/chain/anchor';

import {
  CIPHERTEXT_SUBSTITUTION_HINT,
  HEADER_WALK_LIMIT,
  runSync,
  WARNED_LEAVES_PER_PASS,
  type ScannedNote,
  type SyncChain,
  type SyncCrypto,
} from '../src/wallet/sync';
import { STORE_VERSION, type StoreMeta } from '../src/wallet/model';
import {
  chainParts,
  cryptoParts,
  depthFor,
  frontierRootOver,
  GENESIS,
  hashOf,
  leafBytes,
  sortedRootOver,
  type ChainShape,
} from './fixtures/chain';

const MINE: ScannedNote = {
  value: 1_000n,
  rho: 'aa'.repeat(32),
  r: 'bb'.repeat(32),
  commitment: 'cc'.repeat(32),
  nullifier: 'dd'.repeat(32),
  memo: '',
};

const MINED: ScannedNote = {
  value: 42n,
  rho: '01'.repeat(32),
  r: '02'.repeat(32),
  commitment: '03'.repeat(32),
  nullifier: '04'.repeat(32),
  memo: '',
};

function meta(): StoreMeta {
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
  };
}

interface Leaf {
  commitment: string;
  block: number;
  ciphertext: Uint8Array | null;
  coinbaseQuanta: bigint | null;
}

function shapeOf(head: number, leaves: readonly Leaf[], ours?: ReadonlySet<number>): ChainShape {
  return {
    head,
    leafCount: leaves.length,
    blockOf: (index) => leaves[index]?.block ?? 1,
    commitmentAt: (index) => leaves[index]?.commitment ?? 'ff'.repeat(32),
    ours,
  };
}

/** A store as one pass left it, so the next pass can be driven from it. */
function metaAfter(result: { meta: StoreMeta }): StoreMeta {
  return { ...result.meta };
}

function chainOf(shape: ChainShape, leaves: readonly Leaf[]): SyncChain {
  return {
    ...chainParts(shape),
    storageDrift: [],
    anchorWindow: 256,
    head: () => Promise.resolve({ number: shape.head, hash: hashOf(shape, shape.head) }),
    genesisHash: () => Promise.resolve(GENESIS),
    blockHashAt: (height) => Promise.resolve(hashOf(shape, height)),
    treeShape: () =>
      Promise.resolve({ leafCount: shape.leafCount, depth: 3, entryCount: 0n }),
    leaves: (from, to) =>
      Promise.resolve(
        leaves.slice(from, Math.min(to, leaves.length)).map((leaf, offset) => ({
          index: from + offset,
          commitment: leaf.commitment,
          ciphertext: leaf.ciphertext,
          blockNumber: leaf.block,
          coinbaseQuanta: leaf.coinbaseQuanta,
        })),
      ),
    usedNullifiers: () => Promise.resolve(new Set<string>()),
  };
}

/**
 * What the worker answers for a ciphertext that opened.
 *
 * The AEAD decides whether the bytes open at all, and the commitment beside
 * them decides nothing about that: `decryptBatch` opens without one and
 * compares afterwards, so a note that opens to a different commitment comes
 * back with `moved` set. See `src/worker/core.ts` and `OpenedLeaf` in
 * `crates/qnero-wallet/src/wallet.rs`.
 */
function openedAs(note: ScannedNote, commitment: string): ScannedNote {
  const beside = commitment.replace(/^0x/i, '').toLowerCase();
  return beside === note.commitment ? note : { ...note, moved: true };
}

/** A prover that opens exactly the leaves a test names. */
function cryptoOf(
  shape: ChainShape,
  options: { transfersAt?: ReadonlySet<number>; coinbaseAt?: ReadonlySet<number> } = {},
): SyncCrypto {
  return {
    ...cryptoParts(shape),
    decryptBatch: (items) =>
      Promise.resolve(
        items.map((item) =>
          options.transfersAt?.has(item.index) === true
            ? openedAs(MINE, item.commitment)
            : null,
        ),
      ),
    // `mined` is what says this wallet's own coinbase rebuild opened the leaf.
    // Ownership at a coinbase position is the rebuild's to decide and the
    // author label's to be compared against, never the other way round.
    coinbaseBatch: (items) =>
      Promise.resolve(
        items.map((item) =>
          options.coinbaseAt?.has(item.index) === true ? { ...MINED, mined: true } : null,
        ),
      ),
    entryRhoMatches: () => Promise.resolve(false),
  };
}

const CT = new Uint8Array([1, 2, 3]);
/** Well-formed bytes for somebody else, which open for nobody in these tests. */
const STRANGER_CT = new Uint8Array([4, 5, 6]);

/**
 * A prover that opens `CT` and nothing else, which is what an AEAD does.
 *
 * The bytes decide whether the payload opens at all, and the commitment beside
 * them decides only `moved`. Keeping those two apart is the whole point of the
 * detector: a stranger's bytes do not open, and this wallet's bytes do open,
 * whatever commitment a node put next to them.
 */
function opener(shape: ChainShape): SyncCrypto {
  return {
    ...cryptoParts(shape),
    decryptBatch: (items) =>
      Promise.resolve(
        items.map((item) =>
          item.ciphertext[0] === CT[0] ? openedAs(MINE, item.commitment) : null,
        ),
      ),
    // Nothing this wallet mined.
    coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
    entryRhoMatches: () => Promise.resolve(false),
  };
}

describe('a leaf whose kind the headers decide', () => {
  /** The control: a payment on one leaf, this wallet's mined coinbase on another. */
  it('pays a transfer and a mined coinbase from an honest node', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINED.commitment, block: 8, ciphertext: null, coinbaseQuanta: 42n },
    ];
    const shape = shapeOf(9, leaves, new Set([8]));
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, leaves),
      cryptoOf(shape, { transfersAt: new Set([1]), coinbaseAt: new Set([2]) }),
    );
    expect(result.report.received).toBe(2);
    expect(result.report.coinbaseLeaves).toBe(1);
    expect(result.report.coinbaseReceived).toBe(1);
    expect(result.report.warnings).toEqual([]);
    expect(result.meta.nextLeaf).toBe(3);
  });

  /**
   * An invented coinbase value on an incoming payment, below its block's last
   * leaf. The leaf cannot be a coinbase whatever a node answers for it.
   */
  it('refuses a coinbase value below a block’s last leaf', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: 1n },
      // Block 8's own coinbase, at the one index of the block that can hold
      // one, so the leaves below it are positions that cannot.
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const shape = shapeOf(9, leaves);
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        cryptoOf(shape, { transfersAt: new Set([1]) }),
      ),
    ).rejects.toThrow(/Shielded::CoinbaseValues for leaf 1/);

    // Without the invented key the payment arrives, which is what the refusal
    // is protecting.
    const honest = leaves.map((leaf, index) =>
      index === 1 ? { ...leaf, coinbaseQuanta: null } : leaf,
    );
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, honest),
      cryptoOf(shape, { transfersAt: new Set([1]) }),
    );
    expect(result.report.received).toBe(1);
  });

  /**
   * At the one position a coinbase can occupy, in somebody else's block,
   * nothing authenticates the value. The rule refuses to let it decide: the
   * ciphertext beside it is tried anyway, so the payment arrives.
   */
  it('still pays a leaf an invented coinbase value sits on at a foreign coinbase position', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: 1n },
    ];
    const shape = shapeOf(9, leaves);
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, leaves),
      cryptoOf(shape, { transfersAt: new Set([1]) }),
    );
    expect(result.report.received).toBe(1);
    expect(result.report.receivedValue).toBe(1_000n);
  });

  /**
   * The other direction: an invented ciphertext beside a withheld coinbase
   * value, at a coinbase position. The value is required at every one of them,
   * whatever the author label says, so the same fixture is driven under this
   * wallet's own label, under somebody else's and under no label at all.
   *
   * The requirement used to be gated on the label matching, and above the
   * trusted anchor no proof of work pins any header field, so a node that
   * rebuilt the block under a label of its own reached the transfer arm, found
   * a ciphertext nothing could open, and the mined coinbase was skipped behind
   * a committed watermark.
   */
  for (const [what, ours, unlabelled] of [
    ['this wallet’s own label', new Set([7]), undefined],
    ['a label that says another author’s', new Set<number>(), undefined],
    ['no label at all', new Set([7]), new Set([7])],
  ] as const) {
    it(`refuses a withheld coinbase value under ${what}`, async () => {
      const leaves: Leaf[] = [
        {
          commitment: MINED.commitment,
          block: 7,
          ciphertext: new Uint8Array([9, 9, 9]),
          coinbaseQuanta: null,
        },
      ];
      const shape: ChainShape = { ...shapeOf(9, leaves, ours), unlabelled };
      await expect(
        runSync(
          { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
          chainOf(shape, leaves),
          cryptoOf(shape, { coinbaseAt: new Set([0]) }),
        ),
      ).rejects.toThrow(/no Shielded::CoinbaseValues for leaf 0/);

      const first = leaves[0];
      if (first === undefined) {
        throw new Error('the fixture has a leaf');
      }
      const honest = [{ ...first, ciphertext: null, coinbaseQuanta: 42n }];
      const result = await runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, honest),
        cryptoOf(shape, { coinbaseAt: new Set([0]) }),
      );
      expect(result.report.coinbaseReceived).toBe(1);
      expect(result.report.receivedValue).toBe(42n);
    });
  }

  /**
   * This wallet's own reward, found under a label that says another author's.
   *
   * The rebuild runs at every coinbase position and it is what decides: only
   * the holder of the coinbase viewing key derives the `r` inside that
   * commitment, so a leaf the rebuild opens is this wallet's note whatever
   * header sits beside it. Gate the rebuild on the label the way the old rule
   * did and the reward is skipped with the watermark written above it. The
   * disagreement is reported rather than swallowed, because on a block a Qnero
   * node built the label and the note come out of one key.
   */
  it('finds this wallet’s own reward under a forged foreign label', async () => {
    const leaves: Leaf[] = [
      { commitment: MINED.commitment, block: 7, ciphertext: null, coinbaseQuanta: 42n },
    ];
    const shape = shapeOf(9, leaves, new Set<number>());
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, leaves),
      cryptoOf(shape, { coinbaseAt: new Set([0]) }),
    );
    expect(result.report.coinbaseReceived).toBe(1);
    expect(result.report.receivedValue).toBe(42n);
    expect(result.report.coinbaseLabelDisagreed).toBe(1);
    // Counted and also said out loud. The count used to be written into the
    // report and read by nothing, so the one operator-visible signal for a
    // node that rebuilt the headers existed only in the command-line wallet.
    // The balance screen renders every warning the pass returns.
    expect(
      result.report.warnings.some(
        (warning) =>
          warning.includes("author label is not this wallet's") &&
          warning.includes('second node'),
      ),
    ).toBe(true);
  });

  /**
   * The bound the per-leaf rules do not close, and the recovery that does.
   *
   * `Shielded::Ciphertexts(i)` is the one per-leaf value nothing on chain
   * binds to leaf `i`. The commitment the tree authenticates carries no
   * ciphertext, and `ct_digest` binds the bytes only inside the settlement
   * extrinsic at inclusion, which a storage-only reader never fetches. So a
   * node with honest headers answers a stranger's bytes at an incoming
   * payment, the AEAD does not open, the leaf reads as somebody else's, and
   * the watermark goes above it. Every root, every position and every header
   * still checks out, and the checkpoint fork walk finds nothing because the
   * headers agree.
   *
   * What the pass owes the operator is the sentence, and what recovers the
   * payment is a rescan against a second node. `docs/WALLET.md` states the
   * bound under "What a lying node can and cannot do" and `docs/DESIGN.md`
   * records the closure as the next wallet milestone.
   */
  it('hides a payment behind a substituted ciphertext until a rescan reads the leaf again', async () => {
    const SUBSTITUTED = new Uint8Array([9, 9, 9]);
    const rowsWith = (ciphertext: Uint8Array): Leaf[] => [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: STRANGER_CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext, coinbaseQuanta: null },
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];

    const lying = rowsWith(SUBSTITUTED);
    const lyingShape = shapeOf(9, lying);
    const hidden = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lying),
      opener(lyingShape),
    );
    expect(hidden.report.received).toBe(0);
    expect(hidden.meta.nextLeaf).toBe(3);
    expect(hidden.notes).toHaveLength(0);
    // On `hints` rather than on `warnings`: it fires on nearly every pass, so
    // beside the rare coinbase-label warning it was the constant entry that
    // made the list stop being read. The balance screen renders it under the
    // warnings and at less weight.
    expect(hidden.report.warnings).toEqual([]);
    expect(hidden.report.hints.some((hint) => hint.includes('Shielded::Ciphertexts'))).toBe(true);

    // An honest node serving the same headers recovers nothing on an ordinary
    // pass: no checkpoint moves, so the scan starts above the leaf.
    const honest = rowsWith(CT);
    const honestShape = shapeOf(9, honest);
    const ordinary = await runSync(
      {
        meta: metaAfter(hidden),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: hidden.checkpoints,
      },
      chainOf(honestShape, honest),
      opener(honestShape),
    );
    expect(ordinary.report.received).toBe(0);

    // The recovery, end to end.
    const rescanned = await runSync(
      {
        meta: metaAfter(ordinary),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: ordinary.checkpoints,
      },
      chainOf(honestShape, honest),
      opener(honestShape),
      { rescan: true },
    );
    expect(rescanned.report.received).toBe(1);
    expect(rescanned.notes).toHaveLength(1);
  });

  /**
   * The bound stated whole, and the one part of it a wallet catches on its own.
   *
   * `hash_node` sorts a node's four children before hashing them, in the
   * circuit and in `pallet-zk-tree` alike, which is what lets a Merkle path
   * carry siblings with no position. It sorts at **every** level and mixes in
   * no level tag, so a block's root pins that block's leaf multiset and each
   * internal node's child multiset and nothing further: sibling swaps composed
   * at any level reach any position the block's range allows, the coinbase
   * position included, and a shorter tree of internal node values served as
   * leaves folds to the same root.
   *
   * This is the case the pass does catch. The node exchanges this wallet's
   * payment with its block's coinbase and leaves every ciphertext where the
   * chain published it, so at the payment's old leaf a ciphertext this
   * wallet's own key opens sits beside a commitment that note does not open.
   * Opening is authenticated, by ML-KEM decapsulation and an AEAD over this
   * wallet's own `pk`, so the note is this wallet's and the pair was taken
   * apart. The block's leaf range is already folded against the `zkTreeRoot`
   * its header carries, so the pass searches that range, finds the opened
   * note's commitment, records the note there and warns.
   *
   * Drop the `received.moved` branch in `src/wallet/sync.ts` and this fails at
   * the first expectation: the payment is skipped and the watermark commits
   * above it. `crates/qnero-wallet/tests/leaf_typing.rs` drives the same
   * attack against the command-line wallet.
   */
  it('records a moved leaf where the block holds it when the ciphertext stayed', async () => {
    const STRANGER = 'a0'.repeat(32);
    const COINBASE = 'c0'.repeat(32);

    // The chain: leaf 1 is the payment, leaf 2 is block 8's coinbase.
    const honestRows: Leaf[] = [
      { commitment: STRANGER, block: 8, ciphertext: STRANGER_CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    // The liar: the payment's commitment and the coinbase's exchanged, every
    // ciphertext untouched, so `Shielded::Ciphertexts(1)` is still exactly the
    // bytes the chain published.
    const lyingRows: Leaf[] = [
      { commitment: STRANGER, block: 8, ciphertext: STRANGER_CT, coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const shapeFor = (rows: readonly Leaf[]): ChainShape => ({
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
    });
    const honestShape = shapeFor(honestRows);
    const lyingShape = shapeFor(lyingRows);
    expect(sortedRootOver(leafBytes(lyingShape), 3)).toBe(
      sortedRootOver(leafBytes(honestShape), 3),
    );

    const hit = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lyingRows),
      opener(lyingShape),
    );
    expect(hit.report.received).toBe(1);
    expect(hit.notes).toHaveLength(1);
    expect(hit.notes[0]?.note.leafIndex).toBe(2);
    const warning =
      hit.report.warnings.find((entry) => entry.includes("this wallet's own key")) ?? '';
    expect(warning).toContain('leaf 1');
    expect(warning).toContain('leaf 2');
    expect(warning).toContain('second node');
    // A pass that received a note raises no hint at all.
    expect(hit.report.hints).toEqual([]);

    // What the warning names is what stays open: leaf 2 is where this node
    // puts the commitment, and the chain holds it at leaf 1. A rescan against
    // a second node moves it.
    const moved = await runSync(
      {
        meta: metaAfter(hit),
        held: hit.notes.map((entry) => ({ note: entry.note, secret: entry.secret })),
        rejected: [],
        pending: [],
        checkpoints: hit.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
      { rescan: true },
    );
    expect(moved.report.relocated).toBe(1);
    expect(moved.notes[0]?.note.leafIndex).toBe(1);
  });

  /**
   * The same swap with this wallet's ciphertext gone: nothing opens, and the
   * bound stands.
   *
   * The detector above needs one thing the node controls: a ciphertext of this
   * wallet's answered somewhere. A node that moves the commitment onto the
   * coinbase position, where no ciphertext is owed, and answers a stranger's
   * bytes at the leaf the payment came from, hands this wallet nothing that
   * opens. Every root, every position rule and every header still check out.
   * The checkpoint fork walk finds nothing, because the headers agree, and a
   * rescan against a second node is the recovery, which this drives end to end.
   */
  it('hides a payment moved onto the coinbase position until a rescan reads the leaf again', async () => {
    const STRANGER = 'a0'.repeat(32);
    const COINBASE = 'c0'.repeat(32);
    // Well-formed bytes for somebody else, which is what the node answers
    // where the payment's ciphertext used to sit.
    const DECOY_CT = new Uint8Array([7, 7, 7]);

    const honestRows: Leaf[] = [
      { commitment: STRANGER, block: 8, ciphertext: STRANGER_CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const lyingRows: Leaf[] = [
      { commitment: STRANGER, block: 8, ciphertext: STRANGER_CT, coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: DECOY_CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const shapeFor = (rows: readonly Leaf[]): ChainShape => ({
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
    });
    const honestShape = shapeFor(honestRows);
    const lyingShape = shapeFor(lyingRows);

    // The premise, at the layer it comes from: one group, two orderings, one
    // root. Both nodes therefore serve one set of headers, which is what makes
    // this bound A rather than a fork.
    expect(sortedRootOver(leafBytes(lyingShape), 3)).toBe(
      sortedRootOver(leafBytes(honestShape), 3),
    );

    const hidden = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lyingRows),
      opener(lyingShape),
    );
    expect(hidden.report.received).toBe(0);
    expect(hidden.notes).toHaveLength(0);
    expect(hidden.report.warnings).toEqual([]);
    expect(hidden.meta.nextLeaf).toBe(3);
    // What the operator is given instead: the hint, which states the whole
    // bound because one rescan is the recovery for every part of it.
    expect(hidden.report.hints.some((hint) => hint.includes('at every level'))).toBe(true);

    // An honest node serving the same headers recovers nothing on an ordinary
    // pass: no checkpoint moves, so the scan starts above the leaf.
    const ordinary = await runSync(
      {
        meta: metaAfter(hidden),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: hidden.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
    );
    expect(ordinary.report.received).toBe(0);

    // The recovery, end to end.
    const rescanned = await runSync(
      {
        meta: metaAfter(ordinary),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: ordinary.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
      { rescan: true },
    );
    expect(rescanned.report.received).toBe(1);
    expect(rescanned.notes).toHaveLength(1);
    expect(rescanned.notes[0]?.note.leafIndex).toBe(1);
  });

  /**
   * A swap across two aligned groups of four, onto the coinbase position.
   *
   * The bound is the index inside the block's whole leaf range and never
   * inside one group of four: the sort applies at every level, so exchanging
   * the two groups and ordering the second one lands a payment six positions
   * away, on the coinbase position, with every root and every header
   * unchanged. The payment's own ciphertext is nowhere, because the position
   * it landed on owes none, so the detector has nothing to open and the bound
   * stands. `crates/qnero-wallet/tests/leaf_typing.rs` drives the same attack
   * against the command-line wallet.
   */
  it('hides a payment swapped across two groups of four until a rescan', async () => {
    const stranger = (n: number): string => `b${n}`.repeat(32).slice(0, 64);
    const strangerCt = (n: number): Uint8Array => new Uint8Array([100 + n, 0, 0]);
    const COINBASE = 'c0'.repeat(32);

    // The chain. Leaf 1 is the payment, leaf 7 is the coinbase: six leaves and
    // a group boundary apart.
    const honestRows: Leaf[] = [
      { commitment: stranger(0), block: 8, ciphertext: strangerCt(0), coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: stranger(2), block: 8, ciphertext: strangerCt(2), coinbaseQuanta: null },
      { commitment: stranger(3), block: 8, ciphertext: strangerCt(3), coinbaseQuanta: null },
      { commitment: stranger(4), block: 8, ciphertext: strangerCt(4), coinbaseQuanta: null },
      { commitment: stranger(5), block: 8, ciphertext: strangerCt(5), coinbaseQuanta: null },
      { commitment: stranger(6), block: 8, ciphertext: strangerCt(6), coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    // The two aligned groups exchanged, and inside the group that lands second
    // the payment is put last. The coinbase commitment lands at leaf 3, where
    // a ciphertext is owed, so the node invents one; it opens for nobody,
    // which is the ordinary reading of almost every leaf.
    const lyingRows: Leaf[] = [
      { commitment: stranger(4), block: 8, ciphertext: strangerCt(4), coinbaseQuanta: null },
      { commitment: stranger(5), block: 8, ciphertext: strangerCt(5), coinbaseQuanta: null },
      { commitment: stranger(6), block: 8, ciphertext: strangerCt(6), coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: new Uint8Array([9, 9, 9]), coinbaseQuanta: null },
      { commitment: stranger(0), block: 8, ciphertext: strangerCt(0), coinbaseQuanta: null },
      { commitment: stranger(2), block: 8, ciphertext: strangerCt(2), coinbaseQuanta: null },
      { commitment: stranger(3), block: 8, ciphertext: strangerCt(3), coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const shapeFor = (rows: readonly Leaf[]): ChainShape => ({
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
    });
    const honestShape = shapeFor(honestRows);
    const lyingShape = shapeFor(lyingRows);

    // The premise, one level up: whole sibling subtrees can be exchanged too,
    // so the payment moved six positions and no root moved at all.
    expect(sortedRootOver(leafBytes(lyingShape), 8)).toBe(
      sortedRootOver(leafBytes(honestShape), 8),
    );

    const hidden = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lyingRows),
      opener(lyingShape),
    );
    expect(hidden.report.received).toBe(0);
    expect(hidden.report.warnings).toEqual([]);
    expect(hidden.meta.nextLeaf).toBe(8);
    expect(
      hidden.report.hints.some((hint) => hint.includes("inside its block's own leaf range")),
    ).toBe(true);

    const ordinary = await runSync(
      {
        meta: metaAfter(hidden),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: hidden.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
    );
    expect(ordinary.report.received).toBe(0);

    const rescanned = await runSync(
      {
        meta: metaAfter(ordinary),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: ordinary.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
      { rescan: true },
    );
    expect(rescanned.report.received).toBe(1);
    expect(rescanned.notes[0]?.note.leafIndex).toBe(1);
  });

  /**
   * A shorter tree served as the whole of a block: eight leaves answered as
   * the two level-1 node values above them.
   *
   * The fold carries no level tag, so the node hands over a leaf count of 2
   * and the two node hashes, and the per-block root comparison passes against
   * the header the honest chain published. The watermark then commits at 2
   * with the payment at real leaf 1 behind it, and the checkpoint the pass
   * records names a leaf count this chain never had. An honest node afterwards
   * cannot even scan: the two leaves below that watermark fold to something
   * else, so the pass refuses by name and a rescan is the way back.
   */
  it('hides a payment behind a shorter tree of node values until a rescan', async () => {
    const stranger = (n: number): string => `b${n}`.repeat(32).slice(0, 64);
    const strangerCt = (n: number): Uint8Array => new Uint8Array([100 + n, 0, 0]);
    const COINBASE = 'c0'.repeat(32);

    const honestRows: Leaf[] = [
      { commitment: stranger(0), block: 8, ciphertext: strangerCt(0), coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: stranger(2), block: 8, ciphertext: strangerCt(2), coinbaseQuanta: null },
      { commitment: stranger(3), block: 8, ciphertext: strangerCt(3), coinbaseQuanta: null },
      { commitment: stranger(4), block: 8, ciphertext: strangerCt(4), coinbaseQuanta: null },
      { commitment: stranger(5), block: 8, ciphertext: strangerCt(5), coinbaseQuanta: null },
      { commitment: stranger(6), block: 8, ciphertext: strangerCt(6), coinbaseQuanta: null },
      { commitment: COINBASE, block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const honestShape: ChainShape = { ...shapeOf(9, honestRows), rootRule: sortedRootOver };
    const honestBytes = leafBytes(honestShape);

    // The two level-1 node values, which is what folding four leaves at a time
    // produces at the first level. `sortedRootOver` over exactly four leaves
    // is that one node.
    const nodeOver = (from: number): string =>
      sortedRootOver(honestBytes.subarray(from * 32, from * 32 + 128), 4);
    const lyingRows: Leaf[] = [
      { commitment: nodeOver(0), block: 8, ciphertext: new Uint8Array([9, 9, 9]), coinbaseQuanta: null },
      { commitment: nodeOver(4), block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const lyingShape: ChainShape = { ...shapeOf(9, lyingRows), rootRule: sortedRootOver };

    // The premise: with no level tag, two node values presented as two leaves
    // fold to the root of the eight leaves under them, so both nodes serve one
    // set of headers.
    expect(sortedRootOver(leafBytes(lyingShape), 2)).toBe(sortedRootOver(honestBytes, 8));

    const hidden = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lyingRows),
      opener(lyingShape),
    );
    expect(hidden.report.received).toBe(0);
    expect(hidden.report.leavesScanned).toBe(2);
    expect(hidden.meta.nextLeaf).toBe(2);
    expect(
      hidden.report.hints.some((hint) =>
        hint.includes('neither the leaf count nor the height'),
      ),
    ).toBe(true);

    // An ordinary pass against the honest node recovers nothing, and says so
    // loudly. The watermark this pass wrote sits above leaves block 8 really
    // appended, so the honest node dates leaves 2 to 7 to a block the header
    // walk has already checkpointed past, and no block in the range claims
    // them. The command-line wallet refuses the same lie one rule earlier, on
    // the fold it seeds below the watermark, because it folds before it walks.
    // Either way nothing is written and the way back is a rescan.
    await expect(
      runSync(
        {
          meta: metaAfter(hidden),
          held: [],
          rejected: [],
          pending: [],
          checkpoints: hidden.checkpoints,
        },
        chainOf(honestShape, honestRows),
        opener(honestShape),
      ),
    ).rejects.toThrow(/not where the header walk puts it/);

    // The recovery, end to end: a rescan starts at leaf zero, reads the eight
    // leaves this chain really has and finds the payment.
    const rescanned = await runSync(
      {
        meta: metaAfter(hidden),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: hidden.checkpoints,
      },
      chainOf(honestShape, honestRows),
      opener(honestShape),
      { rescan: true },
    );
    expect(rescanned.report.received).toBe(1);
    expect(rescanned.notes[0]?.note.leafIndex).toBe(1);
    expect(rescanned.meta.nextLeaf).toBe(8);
  });

  /**
   * A ciphertext of this wallet's beside a commitment the block holds nowhere:
   * warned, skipped, and the pass finishes.
   *
   * The detector's other arm, and it is a warning deliberately. Two things
   * produce this reading and nothing local tells them apart: a node that moved
   * a ciphertext across blocks, and a sender who encrypted a payload opening a
   * commitment the sender never published. The circuit leaves `ct_digest`
   * unconstrained (`docs/CIRCUIT.md` section 1), so no rule on chain ties a
   * ciphertext's plaintext to the commitment beside it, and anyone holding
   * this wallet's address can write such a leaf for the price of one
   * transaction. Refusing the pass would hand that sender a permanent sync
   * denial, because the leaf is read again on every later pass and on a rescan
   * as well.
   */
  it('warns and keeps scanning when the block holds the opened commitment nowhere', async () => {
    const rows: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: 'a1'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    const shape: ChainShape = { ...shapeOf(9, rows), rootRule: sortedRootOver };
    // The bytes at leaf 0 open under this wallet's key, and the note they open
    // is at no leaf of this block at all.
    const crypto: SyncCrypto = {
      ...cryptoParts(shape),
      decryptBatch: (items) =>
        Promise.resolve(items.map((item) => (item.index === 0 ? openedAs(MINE, item.commitment) : null))),
      coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
      entryRhoMatches: () => Promise.resolve(false),
    };

    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, rows),
      crypto,
    );
    expect(result.report.leavesScanned).toBe(3);
    expect(result.report.received).toBe(0);
    expect(result.notes).toHaveLength(0);
    const warning =
      result.report.warnings.find((entry) =>
        entry.includes('at none of the leaves it appended'),
      ) ?? '';
    expect(warning).toContain('leaf 0');
    expect(warning).toContain('second node');
    // And it is the same answer on every later pass, which is the point of
    // keeping it a warning: a sender cannot brick this wallet's sync.
    const again = await runSync(
      {
        meta: metaAfter(result),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: result.checkpoints,
      },
      chainOf(shape, rows),
      crypto,
      { rescan: true },
    );
    expect(again.report.received).toBe(0);
    expect(
      again.report.warnings.some((entry) => entry.includes('at none of the leaves it appended')),
    ).toBe(true);
  });

  /**
   * How many leaves a pass writes one sentence about is a node's choice, so
   * the sentences are capped and the rest are counted.
   *
   * Both detector warnings are per leaf, and a node answers the leaves: it can
   * put a commitment this wallet's payload does not open beside every
   * ciphertext it serves. Uncapped that is one string per leaf on
   * `report.warnings` and one `Notice` per leaf on the balance screen, out of
   * an answer nothing has checked. Past `WARNED_LEAVES_PER_PASS` the pass
   * counts instead and closes each kind with one sentence carrying the count,
   * so the list is bounded at eighteen entries whatever a node answers.
   *
   * `crates/qnero-wallet/tests/leaf_typing.rs` drives the same two overflows
   * against the command-line wallet.
   */
  it('caps the per-leaf detector warnings and counts the rest', async () => {
    const OVERFLOW = 2;
    const EACH = WARNED_LEAVES_PER_PASS + OVERFLOW;
    /** A second note of this wallet's, whose commitment the block never holds. */
    const ELSEWHERE: ScannedNote = {
      value: 5n,
      rho: '11'.repeat(32),
      r: '12'.repeat(32),
      commitment: '13'.repeat(32),
      nullifier: '14'.repeat(32),
      memo: '',
    };
    const OTHER_CT = new Uint8Array([7, 7, 7]);

    // Leaves 0..EACH-1 carry this wallet's payment ciphertext beside a
    // stranger's commitment, and the block holds the payment's own commitment
    // at its coinbase position, so each of them is a move the pass recovers.
    // The next EACH carry a ciphertext of this wallet's whose commitment the
    // block holds nowhere, so each of those is skipped.
    const rows: Leaf[] = [];
    for (let leaf = 0; leaf < EACH; leaf += 1) {
      rows.push({
        commitment: `${leaf.toString(16).padStart(2, '0')}a0`.repeat(16),
        block: 8,
        ciphertext: CT,
        coinbaseQuanta: null,
      });
    }
    for (let leaf = 0; leaf < EACH; leaf += 1) {
      rows.push({
        commitment: `${leaf.toString(16).padStart(2, '0')}b0`.repeat(16),
        block: 8,
        ciphertext: OTHER_CT,
        coinbaseQuanta: null,
      });
    }
    rows.push({ commitment: MINE.commitment, block: 8, ciphertext: null, coinbaseQuanta: 7n });
    const shape = shapeOf(9, rows);
    const crypto: SyncCrypto = {
      ...cryptoParts(shape),
      decryptBatch: (items) =>
        Promise.resolve(
          items.map((item) => {
            if (item.ciphertext[0] === CT[0]) {
              return openedAs(MINE, item.commitment);
            }
            return item.ciphertext[0] === OTHER_CT[0] ? openedAs(ELSEWHERE, item.commitment) : null;
          }),
        ),
      coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
      entryRhoMatches: () => Promise.resolve(false),
    };

    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, rows),
      crypto,
    );

    // The payment still arrives, at the index inside the block that holds the
    // commitment it opens. A cap on the sentences changes no decision.
    expect(result.report.received).toBe(1);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]?.note.leafIndex).toBe(EACH * 2);

    const moved = result.report.warnings.filter((entry) =>
      entry.includes('commitment answered beside it'),
    );
    const skipped = result.report.warnings.filter((entry) =>
      entry.includes('at none of the leaves it appended'),
    );
    expect(moved).toHaveLength(WARNED_LEAVES_PER_PASS);
    expect(skipped).toHaveLength(WARNED_LEAVES_PER_PASS);
    // The ones written out are the first of each kind, named by their leaf.
    expect(moved[0]).toContain('leaf 0');
    expect(skipped[0]).toContain(`leaf ${EACH}`);

    // And each kind closes with one sentence carrying what the cap held back.
    const movedMore = result.report.warnings.filter(
      (entry) => entry.startsWith(`and ${OVERFLOW} more leaves`) && entry.includes('each recorded'),
    );
    const skippedMore = result.report.warnings.filter(
      (entry) => entry.startsWith(`and ${OVERFLOW} more leaves`) && entry.includes('each skipped'),
    );
    expect(movedMore).toHaveLength(1);
    expect(skippedMore).toHaveLength(1);
    expect(movedMore[0]).toContain('second node');
    expect(skippedMore[0]).toContain('second node');

    // Eighteen, whatever a node answers: two kinds of eight plus one closing
    // sentence each, and nothing else fired on this pass.
    expect(result.report.warnings).toHaveLength(WARNED_LEAVES_PER_PASS * 2 + 2);
  });

  /** At the cap exactly, there is nothing left over to count. */
  it('writes no overflow sentence when the cap is not passed', async () => {
    const rows: Leaf[] = [];
    for (let leaf = 0; leaf < WARNED_LEAVES_PER_PASS; leaf += 1) {
      rows.push({
        commitment: `${leaf.toString(16).padStart(2, '0')}a0`.repeat(16),
        block: 8,
        ciphertext: CT,
        coinbaseQuanta: null,
      });
    }
    rows.push({ commitment: MINE.commitment, block: 8, ciphertext: null, coinbaseQuanta: 7n });
    const shape = shapeOf(9, rows);

    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, rows),
      opener(shape),
    );
    expect(result.report.warnings).toHaveLength(WARNED_LEAVES_PER_PASS);
    expect(result.report.warnings.some((entry) => entry.startsWith('and '))).toBe(false);
  });

  /** A value that does not rebuild this wallet's own coinbase commitment. */
  it('refuses a wrong coinbase value on this wallet’s own block', async () => {
    const leaves: Leaf[] = [
      { commitment: MINED.commitment, block: 7, ciphertext: null, coinbaseQuanta: 1_000n },
    ];
    const shape = shapeOf(9, leaves, new Set([7]));
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        // The rebuild does not open it, which is what a wrong value looks like.
        cryptoOf(shape, {}),
      ),
    ).rejects.toThrow(/does not rebuild to the commitment the tree holds/);
  });

  /** A node that moves a leaf from one block to another. */
  it('refuses a leaf dated to a block the headers do not put it in', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 7, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
    ];
    const shape: ChainShape = { ...shapeOf(9, leaves), misdated: new Map([[1, 7]]) };
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        cryptoOf(shape, { transfersAt: new Set([1]) }),
      ),
    ).rejects.toThrow(/zkTreeRoot/);
  });

  /** A header that does not hash to the name it was asked for. */
  it('refuses a header that does not hash to its own name', async () => {
    const leaves: Leaf[] = [
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
    ];
    const shape: ChainShape = { ...shapeOf(9, leaves), lyingHeaders: new Set([5]) };
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        cryptoOf(shape, { transfersAt: new Set([0]) }),
      ),
    ).rejects.toThrow(/hashes to/);
  });

  /** A node that answers a leaf count its own headers do not carry. */
  it('refuses a leaf count the headers do not carry', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
    ];
    const shape = shapeOf(9, leaves);
    const chain: SyncChain = {
      ...chainOf(shape, leaves),
      // Two leaves, says the node, on a chain whose headers carry three.
      treeShape: () => Promise.resolve({ leafCount: 2, depth: 3, entryCount: 0n }),
    };
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chain,
        cryptoOf(shape, { transfersAt: new Set([1]) }),
      ),
    ).rejects.toThrow(/zkTreeRoot/);
  });
});

describe('one header, read by both wallets', () => {
  /**
   * `authorLabelFromHeader` here and `RawHeader::author_label` in
   * `crates/qnero-wallet/src/chain.rs` are two implementations of one rule, and
   * a wallet that reads a header differently from the other types a leaf
   * differently from it. The Rust side used to answer nothing for the whole
   * header at the first pre-runtime item of the right shape whose payload was
   * not 32 bytes, where this one skipped it and carried on.
   *
   * One fixture file, read from both suites, so neither can drift on its own.
   */
  it('reads every shape of digest log the same way the command-line wallet does', () => {
    const raw = readFileSync(
      new URL('../../crates/qnero-wallet/tests/fixtures/author_label_headers.json', import.meta.url),
      'utf8',
    );
    const fixture = JSON.parse(raw) as {
      cases: { name: string; logs: string[]; label: string | null }[];
    };
    expect(fixture.cases.length).toBeGreaterThanOrEqual(6);
    for (const item of fixture.cases) {
      const header: RawChainHeader = {
        parentHash: `0x${'00'.repeat(32)}`,
        number: '0x1',
        stateRoot: `0x${'11'.repeat(32)}`,
        extrinsicsRoot: `0x${'22'.repeat(32)}`,
        zkTreeRoot: `0x${'33'.repeat(32)}`,
        digest: { logs: item.logs },
      };
      expect(authorLabelFromHeader(header), item.name).toBe(item.label);
    }
  });
});

describe('the checkpoint a pass records', () => {
  /**
   * A pass that scans no leaf still walks the headers, so the checkpoint it
   * records names a head it authenticated.
   *
   * The checkpoint is what the next pass's header walk stands on. A pass that
   * fetched no header authenticated nothing, and recording the node's claimed
   * head anyway planted a hash the next walk then chained down to and trusted.
   */
  it('is authenticated even when the pass scans no leaf', async () => {
    const shape: ChainShape = { ...shapeOf(9, []), lyingHeaders: new Set([5]) };
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, []),
        cryptoOf(shape),
      ),
    ).rejects.toThrow(/hashes to/);

    const honest = shapeOf(9, []);
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(honest, []),
      cryptoOf(honest),
    );
    expect(result.report.leavesScanned).toBe(0);
    expect(result.checkpoints).toEqual([
      { blockNumber: 9, blockHash: hashOf(honest, 9), nextLeaf: 0 },
    ]);
  });

  /**
   * A chain three chunks ahead of the checkpoint syncs in one pass, and records
   * a checkpoint per chunk.
   *
   * The head is a number the node answers with and the walk holds one header
   * per block between the trusted anchor and it, so the range is climbed in
   * chunks of `HEADER_WALK_LIMIT`. Each chunk learns its top's hash from
   * `chain_getBlockHash` and then proves it by walking down to a hash already
   * trusted, so the bound costs a request per chunk and no guarantee.
   */
  it('is recorded per chunk when the chain is three chunks ahead', async () => {
    const head = HEADER_WALK_LIMIT * 3;
    const leaves: Leaf[] = [
      { commitment: MINE.commitment, block: head - 1, ciphertext: CT, coinbaseQuanta: null },
      { commitment: 'b2'.repeat(32), block: head - 1, ciphertext: null, coinbaseQuanta: 9n },
    ];
    const shape = shapeOf(head, leaves);
    // The progress the walk reports, so a multi-chunk sync can be held to a
    // count the range holds. Each chunk re-fetches the block it stands on, and
    // a running sum of the chunk lengths therefore counted every boundary
    // twice: the strip read "3075 of 3073 block headers" at the end.
    let walked = 0;
    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, leaves),
      cryptoOf(shape, { transfersAt: new Set([0]) }),
      {
        onProgress: (stage, detail) => {
          const match = stage === 'headers' ? /^(\d+) of (\d+) block headers$/.exec(detail ?? '') : null;
          if (match !== null) {
            walked = Math.max(walked, Number(match[1]));
            expect(Number(match[1])).toBeLessThanOrEqual(Number(match[2]));
          }
        },
      },
    );
    expect(walked).toBe(head + 1);
    expect(result.report.received).toBe(1);
    expect(result.checkpoints.map((checkpoint) => checkpoint.blockNumber)).toEqual([
      HEADER_WALK_LIMIT,
      HEADER_WALK_LIMIT * 2,
      head,
    ]);
    expect(result.checkpoints.at(-1)?.blockHash).toBe(hashOf(shape, head));
  });
});

describe('a node that rebuilt the headers', () => {
  /**
   * It hides a payment and a mined reward, and the first honest node undoes it.
   *
   * This is the bound, and it is the one `docs/WALLET.md` states under "What a
   * lying node can and cannot do". No per-leaf rule reaches it: the wallet
   * verifies no proof of work, so above the newest checkpoint the node chooses
   * every header field, which means it chooses where each block's leaf range
   * ends, which leaf is a coinbase position and what label sits on each block.
   * Here it puts an incoming payment at a coinbase position and withholds the
   * ciphertext, and it publishes a wrong value under a foreign label over this
   * wallet's own coinbase. Both leaves are stepped over and the watermark goes
   * above them.
   *
   * What it cannot do is make that branch survive contact with anyone else. The
   * forged head is recorded only as a checkpoint, and the next pass against an
   * honest node finds the hash at that height disagreeing, rewinds to the
   * newest checkpoint both nodes stand on and rescans from its watermark.
   */
  it('hides two notes until an honest node answers', async () => {
    // The prefix both branches agree on.
    const agreed = shapeOf(5, []);
    const first = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(agreed, []),
      cryptoOf(agreed),
    );
    expect(first.checkpoints).toEqual([
      { blockNumber: 5, blockHash: hashOf(agreed, 5), nextLeaf: 0 },
    ]);

    // The rebuilt branch. The payment is the last leaf of block 6, so nothing
    // asks for a ciphertext there, and the node answers none. This wallet's own
    // coinbase for block 7 carries a value that rebuilds to nothing, under a
    // label that says another author's.
    const hiddenLeaves: Leaf[] = [
      { commitment: MINE.commitment, block: 6, ciphertext: null, coinbaseQuanta: 1n },
      { commitment: MINED.commitment, block: 7, ciphertext: null, coinbaseQuanta: 999n },
    ];
    const rebuilt = shapeOf(9, hiddenLeaves, new Set<number>());
    const hidden = await runSync(
      {
        meta: metaAfter(first),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: first.checkpoints,
      },
      chainOf(rebuilt, hiddenLeaves),
      cryptoOf(rebuilt),
    );
    expect(hidden.report.received).toBe(0);
    expect(hidden.meta.nextLeaf).toBe(2);
    expect(hidden.checkpoints.at(-1)?.blockNumber).toBe(9);

    // An honest node, on a branch that agrees below block 6 and disagrees above
    // it. The payment carries its ciphertext, block 7 carries this wallet's own
    // label, and the coinbase value is the one the chain wrote.
    const honestLeaves: Leaf[] = [
      { commitment: MINE.commitment, block: 6, ciphertext: CT, coinbaseQuanta: 1n },
      { commitment: MINED.commitment, block: 7, ciphertext: null, coinbaseQuanta: 42n },
    ];
    const honest: ChainShape = {
      ...shapeOf(9, honestLeaves, new Set([7])),
      forkTag: 'b',
      forkFrom: 6,
    };
    expect(hashOf(honest, 9)).not.toBe(hidden.checkpoints.at(-1)?.blockHash);

    const recovered = await runSync(
      {
        meta: metaAfter(hidden),
        held: [],
        rejected: [],
        pending: [],
        checkpoints: hidden.checkpoints,
      },
      chainOf(honest, honestLeaves),
      cryptoOf(honest, { transfersAt: new Set([0]), coinbaseAt: new Set([1]) }),
    );
    expect(recovered.report.forkedAt).toBe(5);
    expect(recovered.report.received).toBe(2);
    expect(recovered.report.coinbaseReceived).toBe(1);
    expect(recovered.report.receivedValue).toBe(1_042n);
  });
});

describe('the fold these bound tests are modelled on', () => {
  /**
   * The fixture's fold and `TreeFrontier`'s, over every count where a fold can
   * disagree with itself.
   *
   * `sortedRootOver` folds level by level over the whole range, which reads
   * easily in a test. `frontierRootOver` pushes one leaf at a time and carries
   * completed nodes upward, which is what `qnero_circuit::merkle::TreeFrontier`
   * does and what the chain and the prover module actually run. The level
   * count is where the two used to part: a loop that stops as soon as one node
   * is left roots a single leaf at the leaf itself, where `TreeFrontier` roots
   * it at `hash_node([leaf, pad, pad, pad])`, because it folds to
   * `depth_for(count)`. A bound test modelling a fold the production wasm does
   * not compute proves nothing, so the two are held together here.
   */
  it('folds to depthFor(count) the way TreeFrontier does', () => {
    const bytes = new Uint8Array(20 * 32);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = (index * 7 + 1) & 0xff;
    }
    for (let count = 0; count <= 20; count += 1) {
      expect(sortedRootOver(bytes, count)).toBe(frontierRootOver(bytes, count));
    }
    // The count that used to diverge, named: one leaf is a fold of one level,
    // so the root is a parent over the leaf and three pads.
    expect(depthFor(1)).toBe(1);
    expect(sortedRootOver(bytes, 1)).not.toBe(
      Array.from(bytes.subarray(0, 32))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join(''),
    );
    // And the depths the pallet's growth loop lands on.
    expect([depthFor(4), depthFor(5), depthFor(16), depthFor(17)]).toEqual([1, 2, 2, 3]);
  });
});

describe('the sentence both wallets print', () => {
  /**
   * One text, byte for byte, read out of the command-line wallet's own source.
   *
   * `docs/WALLET.md` says the two wallets print the identical sentence, and
   * nothing held them to it: they had drifted apart in their closing clause,
   * so two operators looking at one bound were told two different things. The
   * Rust literal is a `&str` with backslash line continuations, which strip
   * the newline and the indentation of the line below them.
   */
  it('is identical in the command-line wallet and the browser', () => {
    const source = readFileSync(
      new URL('../../crates/qnero-wallet/src/wallet.rs', import.meta.url),
      'utf8',
    );
    const marker = 'pub const CIPHERTEXT_SUBSTITUTION_HINT: &str =';
    const from = source.indexOf(marker);
    expect(from).toBeGreaterThan(0);
    let cursor = source.indexOf('"', from) + 1;
    let raw = '';
    for (;;) {
      const char = source[cursor] as string;
      if (char === '\\') {
        raw += source.slice(cursor, cursor + 2);
        cursor += 2;
        continue;
      }
      if (char === '"') {
        break;
      }
      raw += char;
      cursor += 1;
    }
    const rust = raw.replace(/\\\n\s*/g, '').replace(/\\"/g, '"');
    expect(rust).toBe(CIPHERTEXT_SUBSTITUTION_HINT);
  });
});
