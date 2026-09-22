// These tests exercise the consistency layer through an injected SyncChain.
// Production storage is authenticated before reaching this layer; state-proofs.test.ts
// and the real WASM worker smoke cover that boundary.
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
  fullScanEstimate,
  HEADER_WALK_LIMIT,
  MEASURED_HEADERS_PER_SECOND,
  runSync,
  type ScannedNote,
  type SyncChain,
  type SyncCrypto,
} from '../src/wallet/sync';
import { BIRTHDAY_EPOCH, STORE_VERSION, type StoreMeta } from '../src/wallet/model';
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
    birthday: null,
    lastSyncedBlock: 0,
    nextLeaf: 0,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000, saltHex: '00'.repeat(16) },
    createdAt: 0,
    updatedAt: 0,
    upgrades: [],
  };
}

/**
 * One leaf of a fixture's chain, and the payload its block's body carries for
 * it.
 *
 * `payload` is in the body rather than beside the leaf, which is what the
 * fixture models: the body is one list per block and nothing in it says which
 * leaf a payload belongs to. A leaf whose payload is `null` puts nothing in
 * the body, which is what every coinbase does.
 */
interface Leaf {
  commitment: string;
  block: number;
  payload: Uint8Array | null;
  coinbaseSteps: bigint | null;
}

function shapeOf(head: number, leaves: readonly Leaf[], ours?: ReadonlySet<number>): ChainShape {
  return {
    head,
    leafCount: leaves.length,
    blockOf: (index) => leaves[index]?.block ?? 1,
    commitmentAt: (index) => leaves[index]?.commitment ?? 'ff'.repeat(32),
    payloadAt: (index) => leaves[index]?.payload ?? null,
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
          blockNumber: leaf.block,
          coinbaseSteps: leaf.coinbaseSteps,
        })),
      ),
    usedNullifiers: () => Promise.resolve(new Set<string>()),
  };
}

/** Whether two payloads are the same bytes. */
function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/**
 * A prover that opens the payloads the leaves a test names carry.
 *
 * It is handed bytes and nothing else, because that is all a body payload
 * comes with. What it answers is a note carrying its own commitment, and where
 * that note lands is decided by the commitment search in `runSync` against the
 * leaves the block's own root folded.
 */
function cryptoOf(
  shape: ChainShape,
  options: { transfersAt?: ReadonlySet<number>; coinbaseAt?: ReadonlySet<number> } = {},
): SyncCrypto {
  const opens = [...(options.transfersAt ?? [])]
    .map((index) => shape.payloadAt?.(index) ?? null)
    .filter((payload): payload is Uint8Array => payload !== null);
  return {
    ...cryptoParts(shape),
    decryptBatch: (items) =>
      Promise.resolve(
        items.map((item) =>
          opens.some((payload) => sameBytes(payload, item.ciphertext)) ? MINE : null,
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
 * The bytes decide, and nothing else is offered: a payload out of a block body
 * arrives with no leaf and no commitment beside it, so a stranger's bytes do
 * not open and this wallet's do, wherever in the block the node put the leaf
 * they belong to.
 */
function opener(shape: ChainShape): SyncCrypto {
  return {
    ...cryptoParts(shape),
    decryptBatch: (items) =>
      Promise.resolve(items.map((item) => (item.ciphertext[0] === CT[0] ? MINE : null))),
    // Nothing this wallet mined.
    coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
    entryRhoMatches: () => Promise.resolve(false),
  };
}

describe('a leaf whose kind the headers decide', () => {
  /** The control: a payment on one leaf, this wallet's mined coinbase on another. */
  it('pays a transfer and a mined coinbase from an honest node', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINED.commitment, block: 8, payload: null, coinbaseSteps: 42n },
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
      { commitment: 'a0'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: 1n },
      // Block 8's own coinbase, at the one index of the block that can hold
      // one, so the leaves below it are positions that cannot.
      { commitment: 'a2'.repeat(32), block: 8, payload: null, coinbaseSteps: 7n },
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
      index === 1 ? { ...leaf, coinbaseSteps: null } : leaf,
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
      { commitment: 'a0'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: 1n },
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
          payload: new Uint8Array([9, 9, 9]),
          coinbaseSteps: null,
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
      const honest = [{ ...first, payload: null, coinbaseSteps: 42n }];
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
      { commitment: MINED.commitment, block: 7, payload: null, coinbaseSteps: 42n },
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
   * A payment the node moved to another position inside its own block.
   *
   * This is the move that used to hide a payment and no longer can, and the
   * body is the whole of why. `hash_node` sorts a node's four children at
   * every level and mixes in no level tag, so a block's root pins that block's
   * leaf multiset and each internal node's child multiset and nothing further:
   * sibling swaps composed at any level put a commitment at any position the
   * block's range allows. Under the old rule the payment's ciphertext sat
   * beside a leaf, so the node moved the pair apart and the payment was read
   * as somebody else's.
   *
   * The payload is in the block body now, which is rooted to the header's
   * `extrinsicsRoot` as a whole, and the note that opens is placed at the leaf
   * whose commitment it opens. Where inside the block the node put that leaf
   * decides nothing. `a_ciphertext_moved_between_two_positions_in_one_body_
   * still_finds_its_note` drives the same move against the command-line
   * wallet.
   */
  it('finds a payment the node moved to another position in its block', async () => {
    const STRANGER = 'a0'.repeat(32);
    const COINBASE = 'c0'.repeat(32);

    // The chain: leaf 1 is the payment, leaf 2 is block 8's coinbase. The
    // body of block 8 carries a stranger's payload and this wallet's, in that
    // order, and the same two whichever node serves it.
    const honestRows: Leaf[] = [
      { commitment: STRANGER, block: 8, payload: STRANGER_CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: COINBASE, block: 8, payload: null, coinbaseSteps: 7n },
    ];
    // The liar: the payment's commitment and the coinbase's exchanged.
    const lyingRows: Leaf[] = [
      { commitment: STRANGER, block: 8, payload: STRANGER_CT, coinbaseSteps: null },
      { commitment: COINBASE, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: null, coinbaseSteps: 7n },
    ];
    const shapeFor = (rows: readonly Leaf[]): ChainShape => ({
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
      // The body is one list per block whichever order the leaves are in, so
      // both nodes serve the identical two payloads.
      payloadAt: (index) => (index === 1 ? CT : index === 0 ? STRANGER_CT : null),
    });
    const honestShape = shapeFor(honestRows);
    const lyingShape = shapeFor(lyingRows);
    // The premise, at the layer it comes from: one group, two orderings, one
    // root. Both nodes therefore serve one set of headers.
    expect(sortedRootOver(leafBytes(lyingShape), 3)).toBe(
      sortedRootOver(leafBytes(honestShape), 3),
    );

    const moved = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(lyingShape, lyingRows),
      opener(lyingShape),
    );
    expect(moved.report.received).toBe(1);
    expect(moved.notes).toHaveLength(1);
    // Where the node put the commitment, which is where the chain holds it as
    // far as anything authenticated says.
    expect(moved.notes[0]?.note.leafIndex).toBe(2);
    // No warning at all. There is nothing left to disagree with: a payload has
    // no leaf beside it, so the pass has nothing to report and nothing to
    // relocate.
    expect(moved.report.warnings).toEqual([]);

    const honest = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(honestShape, honestRows),
      opener(honestShape),
    );
    expect(honest.report.received).toBe(1);
    expect(honest.notes[0]?.note.leafIndex).toBe(1);
  });

  /**
   * A payment at the coinbase position, which is where it used to disappear.
   *
   * The coinbase position owed no ciphertext, so a node that moved a payment
   * onto it handed this wallet nothing to open: the coinbase rebuild does not
   * open somebody else's note, the leaf read as nobody's and the watermark
   * committed above it. Every position rule, every root and every header still
   * checked out.
   *
   * The body's payloads are tried against every position now, the coinbase one
   * included, so a payload that opens a commitment there is taken.
   * `a_payment_at_the_coinbase_position_is_found` is the same test against the
   * command-line wallet.
   */
  it('finds a payment at the coinbase position', async () => {
    const STRANGER = 'a0'.repeat(32);
    const rows: Leaf[] = [
      { commitment: STRANGER, block: 8, payload: STRANGER_CT, coinbaseSteps: null },
      // The block's last leaf, so it is the one index a coinbase can occupy
      // and the value is required there. It is this wallet's payment.
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: 7n },
    ];
    const shape: ChainShape = { ...shapeOf(9, rows), rootRule: sortedRootOver };

    const result = await runSync(
      { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
      chainOf(shape, rows),
      // Nothing this wallet mined: the rebuild opens no commitment here.
      opener(shape),
    );
    expect(result.report.received).toBe(1);
    expect(result.report.coinbaseReceived).toBe(0);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]?.note.leafIndex).toBe(1);
    expect(result.notes[0]?.note.origin).not.toBe('coinbase');
  });

  /**
   * A payload of this wallet's whose commitment its own block holds nowhere:
   * discarded, and in silence.
   *
   * This is the ordinary case rather than a fault. A settlement publishes the
   * payload of every slot it carries, the segments the chain skipped included,
   * so a block full of other people's settlements produces these by the
   * hundred. The old per-leaf reading warned about it, because a payload sat
   * beside a leaf and a mismatch there was a pair taken apart; a payload in a
   * body sits beside nothing.
   *
   * The two readings nothing local tells apart are both in the bound: a sender
   * who encrypted a payload opening a commitment the sender never published,
   * and a node that reported the block's fold at the wrong height. The second
   * is the bound the test below drives end to end.
   * `a_skipped_segments_ciphertext_matches_no_commitment_and_is_discarded` is
   * the same test against the command-line wallet.
   */
  it('discards a payload whose commitment its block holds nowhere, in silence', async () => {
    const SKIPPED = new Uint8Array([8, 8, 8]);
    /** A note of this wallet's that this block appended no commitment for. */
    const ELSEWHERE: ScannedNote = {
      value: 5n,
      rho: '11'.repeat(32),
      r: '12'.repeat(32),
      commitment: '13'.repeat(32),
      nullifier: '14'.repeat(32),
      memo: '',
    };
    const rows: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 8, payload: STRANGER_CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: 'a2'.repeat(32), block: 8, payload: null, coinbaseSteps: 7n },
    ];
    const shape: ChainShape = {
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
      // The skipped segment's payload, riding in the same settlement.
      strayPayloads: new Map([[8, [SKIPPED]]]),
    };
    const crypto: SyncCrypto = {
      ...cryptoParts(shape),
      decryptBatch: (items) =>
        Promise.resolve(
          items.map((item) => {
            if (item.ciphertext[0] === CT[0]) {
              return MINE;
            }
            return item.ciphertext[0] === SKIPPED[0] ? ELSEWHERE : null;
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
    // The payment arrives and the skipped segment's note does not, with
    // nothing said about it: a sentence here would fire on nearly every block
    // of a busy chain.
    expect(result.report.received).toBe(1);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]?.note.commitment).toBe(MINE.commitment);
    expect(result.report.warnings).toEqual([]);
    expect(result.report.hints).toEqual([]);
  });

  /**
   * The premise the bound below rests on, at the layer it comes from.
   *
   * `hash_node` sorts a node's four children before hashing them, in the
   * circuit and in `pallet-zk-tree` alike, which is what lets a Merkle path
   * carry siblings with no position beside them. It sorts at every level, so
   * whole sibling subtrees can be exchanged too: two aligned groups of four
   * swapped move a commitment six positions and no root at all.
   *
   * It costs a node nothing now, because a payment is found by the commitment
   * its body payload opens wherever the leaf sits. What the sort still leaves
   * open is the height the fold is reported at, which the test after this one
   * drives.
   */
  it('moves no root when two aligned groups of four are exchanged', () => {
    const stranger = (n: number): string => `b${n}`.repeat(32).slice(0, 64);
    const COINBASE = 'c0'.repeat(32);
    const rowsOf = (commitments: readonly string[]): Leaf[] =>
      commitments.map((commitment, index) => ({
        commitment,
        block: 8,
        payload: index === commitments.length - 1 ? null : CT,
        coinbaseSteps: index === commitments.length - 1 ? 7n : null,
      }));
    const honest = rowsOf([
      stranger(0),
      MINE.commitment,
      stranger(2),
      stranger(3),
      stranger(4),
      stranger(5),
      stranger(6),
      COINBASE,
    ]);
    const swapped = rowsOf([
      stranger(4),
      stranger(5),
      stranger(6),
      COINBASE,
      stranger(0),
      MINE.commitment,
      stranger(2),
      stranger(3),
    ]);
    const shapeFor = (rows: readonly Leaf[]): ChainShape => ({
      ...shapeOf(9, rows),
      rootRule: sortedRootOver,
    });
    expect(sortedRootOver(leafBytes(shapeFor(swapped)), 8)).toBe(
      sortedRootOver(leafBytes(shapeFor(honest)), 8),
    );
  });


  /**
   * A shorter tree served as the whole of a block: eight leaves answered as
   * the two level-1 node values above them.
   *
   * **This is the bound that is left**, and it is the only one. The fold
   * carries no level tag, so the node hands over a leaf count of 2 and the two
   * node hashes, and the per-block root comparison passes against the header
   * the honest chain published. The body is the chain's own and the node
   * serves it unchanged, because it is rooted to the header's
   * `extrinsicsRoot`: the payment's payload is in there and it opens. What it
   * opens to is a commitment none of the two node values is, so the note is
   * discarded the way a skipped segment's is, in silence, and the watermark
   * commits at 2 with the payment at real leaf 1 behind it.
   *
   * It presents identically to the ordinary case above, which is why neither
   * warns. An honest node afterwards cannot even scan: the two leaves below
   * that watermark fold to something else, so the pass refuses by name and a
   * rescan is the way back. `crates/qnero-wallet/src/typing.rs` carries the
   * same bound in prose.
   */
  it('hides a payment behind a shorter tree of node values until a rescan', async () => {
    const stranger = (n: number): string => `b${n}`.repeat(32).slice(0, 64);
    const strangerCt = (n: number): Uint8Array => new Uint8Array([100 + n, 0, 0]);
    const COINBASE = 'c0'.repeat(32);

    const honestRows: Leaf[] = [
      { commitment: stranger(0), block: 8, payload: strangerCt(0), coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: stranger(2), block: 8, payload: strangerCt(2), coinbaseSteps: null },
      { commitment: stranger(3), block: 8, payload: strangerCt(3), coinbaseSteps: null },
      { commitment: stranger(4), block: 8, payload: strangerCt(4), coinbaseSteps: null },
      { commitment: stranger(5), block: 8, payload: strangerCt(5), coinbaseSteps: null },
      { commitment: stranger(6), block: 8, payload: strangerCt(6), coinbaseSteps: null },
      { commitment: COINBASE, block: 8, payload: null, coinbaseSteps: 7n },
    ];
    const honestShape: ChainShape = { ...shapeOf(9, honestRows), rootRule: sortedRootOver };
    const honestBytes = leafBytes(honestShape);

    // The two level-1 node values, which is what folding four leaves at a time
    // produces at the first level. `sortedRootOver` over exactly four leaves
    // is that one node.
    const nodeOver = (from: number): string =>
      sortedRootOver(honestBytes.subarray(from * 32, from * 32 + 128), 4);
    const lyingRows: Leaf[] = [
      { commitment: nodeOver(0), block: 8, payload: null, coinbaseSteps: null },
      { commitment: nodeOver(4), block: 8, payload: null, coinbaseSteps: 7n },
    ];
    const lyingShape: ChainShape = {
      ...shapeOf(9, lyingRows),
      rootRule: sortedRootOver,
      // The body is the chain's own and this node serves it unchanged: it is
      // rooted to the header's `extrinsicsRoot`, so there is nothing in it for
      // a node to change. The payment's payload is in there and it opens.
      strayPayloads: new Map([
        [
          8,
          honestRows
            .map((leaf) => leaf.payload)
            .filter((payload): payload is Uint8Array => payload !== null),
        ],
      ]),
    };

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
    expect(hidden.report.hints).toContain(CIPHERTEXT_SUBSTITUTION_HINT);

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

  /** A value that does not rebuild this wallet's own coinbase commitment. */
  it('refuses a wrong coinbase value on this wallet’s own block', async () => {
    const leaves: Leaf[] = [
      { commitment: MINED.commitment, block: 7, payload: null, coinbaseSteps: 1_000n },
    ];
    const shape = shapeOf(9, leaves, new Set([7]));
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        // The rebuild does not open it, which is what a wrong value looks like.
        cryptoOf(shape, {}),
      ),
    ).rejects.toThrow(/does not rebuild to the entry the tree holds/);
  });

  /** A node that moves a leaf from one block to another. */
  it('refuses a leaf dated to a block the headers do not put it in', async () => {
    const leaves: Leaf[] = [
      { commitment: 'a0'.repeat(32), block: 7, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: 'a2'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
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
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
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
      { commitment: 'a0'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
      { commitment: MINE.commitment, block: 8, payload: CT, coinbaseSteps: null },
      { commitment: 'a2'.repeat(32), block: 8, payload: CT, coinbaseSteps: null },
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
      { commitment: MINE.commitment, block: head - 1, payload: CT, coinbaseSteps: null },
      { commitment: 'b2'.repeat(32), block: head - 1, payload: null, coinbaseSteps: 9n },
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
      { commitment: MINE.commitment, block: 6, payload: null, coinbaseSteps: 1n },
      { commitment: MINED.commitment, block: 7, payload: null, coinbaseSteps: 999n },
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
      { commitment: MINE.commitment, block: 6, payload: CT, coinbaseSteps: 1n },
      { commitment: MINED.commitment, block: 7, payload: null, coinbaseSteps: 42n },
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

describe('the sentences both wallets print', () => {
  /** Shared warning literals stay identical across wallets. The routine hint
   * uses short browser copy and a detailed native explanation; a separate
   * assertion below holds both to the current trust boundary. */
  const RUST = readFileSync(
    new URL('../../crates/qnero-wallet/src/wallet.rs', import.meta.url),
    'utf8',
  );

  function rustLiteral(marker: string): string {
    const from = RUST.indexOf(marker);
    if (from < 0) {
      throw new Error(`the command-line wallet carries no ${marker}`);
    }
    let cursor = RUST.indexOf('"', from) + 1;
    let raw = '';
    for (;;) {
      const char = RUST[cursor] as string;
      if (char === '\\') {
        raw += RUST.slice(cursor, cursor + 2);
        cursor += 2;
        continue;
      }
      if (char === '"') {
        break;
      }
      raw += char;
      cursor += 1;
    }
    return raw.replace(/\\\n\s*/g, '').replace(/\\"/g, '"');
  }

  /** That literal with each placeholder filled the way the call fills it. */
  function rustSentence(marker: string, values: Record<string, string>): string {
    return rustLiteral(marker).replace(/\{(\w*)\}/g, (whole: string, name: string) => {
      const value = values[name];
      if (value === undefined) {
        throw new Error(`${marker} carries ${whole}, which this test has no value for`);
      }
      return value;
    });
  }

  const CASES: { name: string; marker: string; values: Record<string, string>; browser: string }[] =
    [
      {
        name: 'the wait a wallet with no birthday is quoted',
        marker: 'pub const FULL_SCAN_ESTIMATE: &str =',
        values: { blocks: '262980', spell: 'about 11 minutes' },
        browser: fullScanEstimate(262_980),
      },
    ];

  it.each(CASES)('$name is identical in both wallets', ({ marker, values, browser }) => {
    expect(rustSentence(marker, values)).toBe(browser);
  });

  it('keeps the current trust boundary in the copy and documentation', () => {
    const rust = rustLiteral('pub const CIPHERTEXT_SUBSTITUTION_HINT: &str =');
    const doc = readFileSync(new URL('../../docs/WALLET.md', import.meta.url), 'utf8');
    expect(rust).toContain('Payments and storage values are authenticated to the selected headers');
    expect(rust).toContain('trusts the configured node for chain selection');
    expect(rust).toContain('does not verify proof of work');
    expect(doc).toMatch(/state-trie proof/);
    expect(doc).toMatch(/do not verify\s+RandomX proof of work/);
    expect(CIPHERTEXT_SUBSTITUTION_HINT).toContain('trusts your node to follow the right chain');
    expect(CIPHERTEXT_SUBSTITUTION_HINT).toContain('rescan with another trusted node');
    expect(CIPHERTEXT_SUBSTITUTION_HINT.length).toBeLessThan(200);
    expect(CIPHERTEXT_SUBSTITUTION_HINT).not.toMatch(
      /\b(leaf|leaves|nullifier|commitment|note)s?\b/i,
    );
  });

  it('quotes the same measured rate in both wallets', () => {
    // The sentence above says "at the rate this build measured", so a rate
    // that moved on one side alone would leave both wallets printing a true
    // sentence about two different waits.
    const declared = /pub const MEASURED_HEADERS_PER_SECOND: u32 = (\d+);/.exec(RUST);
    expect(declared).not.toBeNull();
    expect(Number(declared?.[1])).toBe(MEASURED_HEADERS_PER_SECOND);
  });

  it('rounds a birthday to the same epoch in both wallets', () => {
    // A birthday is public and it is coarse on purpose. Two wallets rounding
    // to two different epochs would put one of them on a finer grid than the
    // other, which is a fingerprint the coarse one does not carry.
    const store = readFileSync(
      new URL('../../crates/qnero-wallet/src/store.rs', import.meta.url),
      'utf8',
    );
    const declared = /pub const BIRTHDAY_EPOCH: u32 = (\d+);/.exec(store);
    expect(declared).not.toBeNull();
    expect(Number(declared?.[1])).toBe(BIRTHDAY_EPOCH);
  });

  it('carries no per-leaf detector sentence on either side', () => {
    // The detector went with the per-leaf ciphertext. A payload out of a block
    // body has no leaf beside it to disagree with, so there is nothing to
    // relocate and nothing to warn about, and a wallet that still wrote one of
    // these sentences would be describing a reading it can no longer reach.
    for (const gone of [
      'moved_leaf_warning',
      'unplaceable_leaf_warning',
      'moved_overflow_warning',
      'unplaceable_overflow_warning',
      'WARNED_LEAVES_PER_PASS',
    ]) {
      expect(RUST, gone).not.toContain(gone);
    }
    const browser = readFileSync(
      new URL('../src/wallet/sync.ts', import.meta.url),
      'utf8',
    );
    for (const gone of [
      'movedLeafWarning',
      'unplaceableLeafWarning',
      'movedOverflowWarning',
      'unplaceableOverflowWarning',
      'WARNED_LEAVES_PER_PASS',
    ]) {
      expect(browser, gone).not.toContain(gone);
    }
  });
});
