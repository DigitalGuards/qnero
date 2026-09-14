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

import { describe, expect, it } from 'vitest';

import { runSync, type ScannedNote, type SyncChain, type SyncCrypto } from '../src/wallet/sync';
import { STORE_VERSION, type StoreMeta } from '../src/wallet/model';
import {
  chainParts,
  cryptoParts,
  GENESIS,
  hashAtHeight,
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

function chainOf(shape: ChainShape, leaves: readonly Leaf[]): SyncChain {
  return {
    ...chainParts(shape),
    storageDrift: [],
    anchorWindow: 256,
    head: () => Promise.resolve({ number: shape.head, hash: hashAtHeight(shape.head) }),
    genesisHash: () => Promise.resolve(GENESIS),
    blockHashAt: (height) => Promise.resolve(hashAtHeight(height)),
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
    coinbaseBatch: (items) =>
      Promise.resolve(
        items.map((item) => (options.coinbaseAt?.has(item.index) === true ? MINED : null)),
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
      { commitment: 'a2'.repeat(32), block: 8, ciphertext: CT, coinbaseQuanta: null },
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
   * value, at the coinbase position of a block this wallet mined. The author
   * label is what closes it.
   */
  it('refuses a withheld coinbase value on this wallet’s own block', async () => {
    const leaves: Leaf[] = [
      { commitment: MINED.commitment, block: 7, ciphertext: new Uint8Array([9, 9, 9]), coinbaseQuanta: null },
    ];
    const shape = shapeOf(9, leaves, new Set([7]));
    await expect(
      runSync(
        { meta: meta(), held: [], rejected: [], pending: [], checkpoints: [] },
        chainOf(shape, leaves),
        cryptoOf(shape, { coinbaseAt: new Set([0]) }),
      ),
    ).rejects.toThrow(/own author label/);

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
