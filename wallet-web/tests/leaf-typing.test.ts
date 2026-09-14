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
  HEADER_WALK_LIMIT,
  runSync,
  type ScannedNote,
  type SyncChain,
  type SyncCrypto,
} from '../src/wallet/sync';
import { STORE_VERSION, type StoreMeta } from '../src/wallet/model';
import {
  chainParts,
  cryptoParts,
  GENESIS,
  hashOf,
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

/** A prover that opens exactly the leaves a test names. */
function cryptoOf(
  shape: ChainShape,
  options: { transfersAt?: ReadonlySet<number>; coinbaseAt?: ReadonlySet<number> } = {},
): SyncCrypto {
  return {
    ...cryptoParts(shape),
    decryptBatch: (items) =>
      Promise.resolve(
        items.map((item) => (options.transfersAt?.has(item.index) === true ? MINE : null)),
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
      { commitment: 'a0'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
      { commitment: MINE.commitment, block: 8, ciphertext, coinbaseQuanta: null },
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: null, coinbaseQuanta: 7n },
    ];
    // A prover that opens the payment only when the bytes beside the leaf are
    // the ones its sender encrypted, which is what an AEAD does.
    const opener = (shape: ChainShape): SyncCrypto => ({
      ...cryptoParts(shape),
      decryptBatch: (items) =>
        Promise.resolve(
          items.map((item) => (item.index === 1 && item.ciphertext[0] === CT[0] ? MINE : null)),
        ),
      coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
      entryRhoMatches: () => Promise.resolve(false),
    });

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
    expect(
      hidden.report.warnings.some((warning) => warning.includes('Shielded::Ciphertexts')),
    ).toBe(true);

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
