/**
 * What the node is asked, which is the property no answer can show.
 *
 * "The node learns nothing" is a statement about the request stream. An
 * assertion over what a sync returns cannot see it: a wallet that asked the
 * node one point question per held nullifier would return exactly the same
 * balance as one that paged the whole set. So this drives the real read layer
 * through a recording transport and asserts on the calls themselves.
 *
 * Every read goes through `ChainContext.send`, which is one function for this
 * reason (`chain/api.ts`). A read that bypassed that seam would bypass this
 * test, which is why there is no second way to reach the node.
 *
 * The four properties, from `docs/WALLET.md` and the CLI's own rules:
 *
 * 1. No request names a nullifier this wallet holds. `UsedNullifiers` is
 *    `Blake2_128Concat`, so a point lookup carries the raw 32 bytes, and an
 *    unspent note's nullifier has appeared nowhere else in the world.
 * 2. No request names one of this wallet's leaves. Leaves are read as a
 *    contiguous range from the watermark to the leaf count, so every wallet
 *    syncing the same chain asks the identical question.
 * 3. `zkTree_getMerkleProof` is never called. It is the one RPC that is only
 *    ever asked about a leaf the caller is spending.
 * 4. Nothing but the methods a public read needs is called at all.
 *
 * Both paths that talk to a node are driven here, because the property is
 * about requests and the two paths make different ones. A spend rebuilds the
 * tree, and the whole leak it exists to avoid is one range read narrowed to
 * the leaves a path actually needs: the Merkle-proof lint fence keys on a
 * name, so an optimisation spelled `fetchLeafHashes(context, mine, mine + 1)`
 * passes it, passes every unit test, and names the spending wallet's own leaf
 * to the node seconds before the settlement publishes the matching nullifiers.
 */

import { describe, expect, it } from 'vitest';

import { chainAdapter } from '../src/app/adapters';
import type { ChainContext } from '../src/chain/api';
import { watchHead } from '../src/chain/reads';
import { runSync, type ScannedNote, type SyncCrypto } from '../src/wallet/sync';
import { spend } from '../src/wallet/send';
import type { WalletStore } from '../src/wallet/store';
import type { ProverClient } from '../src/worker/client';
import { STORE_VERSION, type StoreMeta } from '../src/wallet/model';

/** A recorded call, exactly as it went to the transport. */
interface Call {
  method: string;
  params: unknown[];
}

const HEAD_NUMBER = 12;

/**
 * The hash this fixture's node serves at a height, and the one a wallet
 * recomputes from that block's header.
 *
 * A sync walks the headers down from the head to a hash it already trusts and
 * rehashes every one, so a fixture whose hashes were not its headers' hashes
 * is a node that cannot serve a header at all.
 */
function hashAt(height: number): string {
  return `0x${String(height).padStart(64, '0')}`;
}

/** The root this fixture's tree reaches after `count` leaves. */
function rootFor(count: number): string {
  return `0x${String(count).padStart(64, '7')}`;
}

/**
 * Leaves folded in by the end of a block.
 *
 * Two per block, which is the shape a v1 chain has: a block appends whatever
 * its extrinsics created and then mints its own coinbase as the last leaf, and
 * a wallet requires a `CoinbaseValues` at every one of those last positions.
 * So leaf `2b - 2` and leaf `2b - 1` belong to block `b`, and the odd one is
 * that block's coinbase.
 */
function countAt(block: number): number {
  return Math.max(0, Math.min(block * 2, LEAF_COUNT));
}

/** The block a leaf was appended in, the inverse of `countAt`. */
function blockOfLeaf(index: number): number {
  return Math.floor(index / 2) + 1;
}

/** Whether a leaf is the last one its block appended, so a coinbase sits there. */
function isCoinbaseLeaf(index: number): boolean {
  return index % 2 === 1;
}

const HEAD_HASH = hashAt(HEAD_NUMBER);
const GENESIS = hashAt(0);
const LEAF_COUNT = 8;
/** The leaf this wallet owns. The point of the test is that it is not named. */
const OUR_LEAF = 4;
const OUR_NULLIFIER = 'c0ffee'.padEnd(64, '0');
const OUR_RHO = 'dd'.repeat(32);
const OUR_R = 'ee'.repeat(32);
const OUR_COMMITMENT = 'ab'.repeat(32);

/** A little-endian integer of `bytes` bytes, hex, the way SCALE stores one. */
function le(value: bigint, bytes: number): string {
  let out = '0x';
  for (let index = 0; index < bytes; index += 1) {
    out += Number((value >> BigInt(8 * index)) & 0xffn)
      .toString(16)
      .padStart(2, '0');
  }
  return out;
}

/** A `Vec<u8>` of fewer than 64 bytes: a one-byte compact prefix, then bytes. */
function vecU8(body: string): string {
  const length = body.length / 2;
  return `0x${(length << 2).toString(16).padStart(2, '0')}${body}`;
}

/**
 * A storage entry whose keys this test can read back.
 *
 * `key(i)` is the prefix and the argument, which is what an identity-hashed
 * `u64` map key looks like in shape if not in byte order, and it is enough to
 * assert which leaves were asked for.
 */
function entry(prefix: string): unknown {
  return {
    key: (arg?: number | string): string =>
      arg === undefined ? prefix : `${prefix}${String(arg).replace(/^0x/, '')}`,
    keyPrefix: (): string => prefix,
  };
}

const KEYS = {
  leaves: '0xleaves-',
  leafCount: '0xleafcount',
  depth: '0xdepth',
  ciphertexts: '0xciphertexts-',
  leafBlocks: '0xleafblocks-',
  coinbaseValues: '0xcoinbase-',
  entryCount: '0xentrycount',
  usedNullifiers: '0xusednullifiers-',
} as const;

function recordingContext(): { context: ChainContext; calls: Call[] } {
  const calls: Call[] = [];
  const values = new Map<string, string>();
  values.set(KEYS.leafCount, le(BigInt(LEAF_COUNT), 8));
  values.set(KEYS.depth, le(3n, 1));
  values.set(KEYS.entryCount, le(2n, 8));
  for (let index = 0; index < LEAF_COUNT; index += 1) {
    values.set(`${KEYS.leaves}${index}`, `0x${(index === OUR_LEAF ? OUR_COMMITMENT : 'cd'.repeat(32))}`);
    values.set(`${KEYS.leafBlocks}${index}`, le(BigInt(blockOfLeaf(index)), 4));
    if (isCoinbaseLeaf(index)) {
      // Its block's last leaf: a value and no payload, which is what the
      // inherent writes under v1.
      values.set(`${KEYS.coinbaseValues}${index}`, le(BigInt(index + 1), 8));
    } else {
      values.set(`${KEYS.ciphertexts}${index}`, vecU8('00112233'));
    }
  }

  // The seam's shape is a promise and this fixture answers out of a map, so
  // the body has nothing to await and says so by resolving explicitly.
  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    calls.push({ method, params });
    if (method === 'chain_getBlockHash') {
      const height = params[0] as number | undefined;
      if (height === undefined) {
        return Promise.resolve(HEAD_HASH as T);
      }
      return Promise.resolve(hashAt(height) as T);
    }
    if (method === 'chain_getHeader') {
      const asked = params[0] as string | undefined;
      const number =
        asked === undefined ? HEAD_NUMBER : Number(asked.replace(/^0x0*/, '') || '0');
      return Promise.resolve({
        parentHash: hashAt(number - 1),
        number: `0x${number.toString(16)}`,
        stateRoot: `0x${'22'.repeat(32)}`,
        extrinsicsRoot: `0x${'33'.repeat(32)}`,
        zkTreeRoot: rootFor(countAt(number)),
        // One pre-runtime item, the author label of somebody else.
        digest: { logs: [`0x06706f775f80${'9a'.repeat(32)}`] },
      } as T);
    }
    if (method === 'state_queryStorageAt') {
      const keys = params[0] as string[];
      return Promise.resolve([
        {
          block: String(params[1]),
          changes: keys.map((key) => [key, values.get(key) ?? null] as [string, string | null]),
        },
      ] as T);
    }
    if (method === 'state_getKeysPaged') {
      // Two settled nullifiers, neither of them this wallet's, returned as one
      // short page so the walk ends.
      const prefix = String(params[0]);
      const cursor = params[2];
      if (cursor !== null) {
        return Promise.resolve([] as T);
      }
      return Promise.resolve([
        `${prefix}${'00'.repeat(16)}${'12'.repeat(32)}`,
        `${prefix}${'00'.repeat(16)}${'34'.repeat(32)}`,
      ] as T);
    }
    throw new Error(`this test's node was asked ${method}, which a sync must not call`);
  };

  const context = {
    send,
    api: {
      query: {
        zkTree: {
          leaves: entry(KEYS.leaves),
          leafCount: entry(KEYS.leafCount),
          depth: entry(KEYS.depth),
        },
        shielded: {
          ciphertexts: entry(KEYS.ciphertexts),
          leafBlocks: entry(KEYS.leafBlocks),
          coinbaseValues: entry(KEYS.coinbaseValues),
          entryCount: entry(KEYS.entryCount),
          usedNullifiers: entry(KEYS.usedNullifiers),
        },
      },
    },
    storageDrift: [],
    // The two facts the sync rules now read off the chain rather than off the
    // screen: the drift list above, and the anchor window a pending row is
    // measured against.
    constants: { blockHashWindow: 256 },
    // The `dev` preset's cadence, because that is what these fixtures were
    // captured against. A payment's inclusion wait is six of these, so a
    // context without it gives `NaN` and the walk never runs.
    targetBlockTimeMs: 12_000,
  } as unknown as ChainContext;

  return { context, calls };
}

/** A prover that finds exactly one note, and never touches the transport. */
function crypto(): SyncCrypto {
  const ours: ScannedNote = {
    value: 1000n,
    rho: OUR_RHO,
    r: OUR_R,
    commitment: OUR_COMMITMENT,
    nullifier: OUR_NULLIFIER,
    memo: 'lunch',
  };
  return {
    decryptBatch: (items) =>
      Promise.resolve(items.map((item) => (item.index === OUR_LEAF ? ours : null))),
    // Somebody else's coinbases: the label in this fixture's headers is not
    // this wallet's and no value rebuilds its own note over those commitments.
    coinbaseBatch: (items) => Promise.resolve(items.map(() => null)),
    entryRhoMatches: () => Promise.resolve(false),
    // The module's own hash rules, stood in for: what this test covers is the
    // request stream, and the recomputations are covered against the pallet in
    // Rust.
    headerHashes: (headers) =>
      Promise.resolve(headers.map((header) => hashAt(header.block_number))),
    authorLabels: (parentHashes) => Promise.resolve(parentHashes.map(() => 'ff'.repeat(32))),
    blockRoots: (_leafHashes, counts) => Promise.resolve(counts.map((count) => rootFor(count))),
  };
}

function freshMeta(): StoreMeta {
  return {
    id: 'store',
    schemaVersion: STORE_VERSION,
    address: 'qn1test',
    genesisHash: null,
    lastSyncedBlock: 0,
    nextLeaf: 0,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000, saltHex: '00'.repeat(16) },
    createdAt: 0,
    updatedAt: 0,
    upgrades: [],
  };
}

async function syncOnce(): Promise<{ calls: Call[]; received: number }> {
  const { context, calls } = recordingContext();
  const result = await runSync(
    { meta: freshMeta(), held: [], rejected: [], checkpoints: [], pending: [] },
    chainAdapter(context, LIMITS),
    crypto(),
  );
  return { calls, received: result.report.received };
}

describe('the request stream a sync makes', () => {
  it('finds the note, which is what makes the rest of these assertions mean something', async () => {
    const { received } = await syncOnce();
    expect(received).toBe(1);
  });

  it('never names a nullifier this wallet holds', async () => {
    const { calls } = await syncOnce();
    const wire = JSON.stringify(calls).toLowerCase();
    expect(wire).not.toContain(OUR_NULLIFIER);
    // The other two secrets of a held note, for the same reason.
    expect(wire).not.toContain(OUR_RHO);
    expect(wire).not.toContain(OUR_R);
  });

  it('pages the settled set by prefix rather than asking about one key', async () => {
    const { calls } = await syncOnce();
    const paged = calls.filter((call) => call.method === 'state_getKeysPaged');
    expect(paged.length).toBeGreaterThan(0);
    for (const call of paged) {
      expect(call.params[0]).toBe(KEYS.usedNullifiers);
      expect(call.params[1]).toBe(1000);
    }
    // No point lookup at a `UsedNullifiers` key, which is the request that
    // would carry a raw nullifier.
    for (const call of calls.filter((entryCall) => entryCall.method === 'state_queryStorageAt')) {
      for (const key of call.params[0] as string[]) {
        expect(key.startsWith(KEYS.usedNullifiers)).toBe(false);
      }
    }
  });

  it('reads leaves as one contiguous range, so it names none of them', async () => {
    const { calls } = await syncOnce();
    const asked = new Set<number>();
    for (const call of calls.filter((entryCall) => entryCall.method === 'state_queryStorageAt')) {
      for (const key of call.params[0] as string[]) {
        if (key.startsWith(KEYS.leaves)) {
          asked.add(Number(key.slice(KEYS.leaves.length)));
        }
      }
    }
    expect([...asked].sort((a, b) => a - b)).toEqual(
      Array.from({ length: LEAF_COUNT }, (_value, index) => index),
    );
  });

  it('asks for no leaf proof, ever', async () => {
    const { calls } = await syncOnce();
    // The fence in `eslint.config.js` refuses this name where it would be a
    // call. Here it is the assertion that the call never happened, which is
    // the one place the name belongs.
    // eslint-disable-next-line no-restricted-syntax -- see above
    expect(calls.map((call) => call.method)).not.toContain('zkTree_getMerkleProof');
  });

  it('calls nothing but the four methods a public read needs', async () => {
    const { calls } = await syncOnce();
    const allowed = new Set([
      'chain_getBlockHash',
      'chain_getHeader',
      'state_queryStorageAt',
      'state_getKeysPaged',
    ]);
    for (const call of calls) {
      expect(allowed.has(call.method), `${call.method} is not a method a sync may call`).toBe(true);
    }
  });

  it('asks for the three chain-wide totals once, in one request', async () => {
    // They are read together because they are one answer: all three are chain
    // wide and the pass is pinned to one block. The counter used to have an
    // accessor of its own that called the same bundle again, so every pass
    // that found a leaf asked this node two byte-identical questions.
    const { calls } = await syncOnce();
    const totals = calls.filter(
      (call) =>
        call.method === 'state_queryStorageAt' &&
        (call.params[0] as string[]).includes(KEYS.entryCount),
    );
    expect(totals).toHaveLength(1);
    expect(totals[0]?.params[0]).toEqual([KEYS.leafCount, KEYS.depth, KEYS.entryCount]);
  });

  it('pins every read of the pass to one block hash', async () => {
    const { calls } = await syncOnce();
    const pinned = calls
      .filter((call) => call.method === 'state_queryStorageAt' || call.method === 'state_getKeysPaged')
      .map((call) => (call.method === 'state_queryStorageAt' ? call.params[1] : call.params[3]));
    expect(new Set(pinned)).toEqual(new Set([HEAD_HASH]));
  });
});

describe('the head this wallet follows', () => {
  it('subscribes through the seam, naming nothing and asking for nothing', async () => {
    // The third call path, and the one that was not going through the seam at
    // all: `api.rpc.chain.subscribeNewHeads` is invisible to this test, which
    // is what made the invariant in `chain/api.ts` false in tree. A
    // subscription is a request like any other, and the next one written that
    // way could be `api.rpc.state.subscribeStorage([myKey])`.
    const subscriptions: { type: string; method: string; params: unknown[] }[] = [];
    let deliver: (value: unknown) => void = () => undefined;
    const context = {
      send: () => {
        throw new Error('following the head asks the node nothing');
      },
      subscribe: (type: string, method: string, params: unknown[], onValue: (value: unknown) => void) => {
        subscriptions.push({ type, method, params });
        deliver = onValue;
        return Promise.resolve(() => undefined);
      },
    } as unknown as ChainContext;

    const heads: number[] = [];
    await watchHead(context, (height) => heads.push(height));
    expect(subscriptions).toEqual([
      { type: 'chain_newHead', method: 'chain_subscribeNewHead', params: [] },
    ]);
    deliver({ number: '0x2a' });
    expect(heads).toEqual([42]);
  });
});

// ---------------------------------------------------------------------------
// The spend path.
// ---------------------------------------------------------------------------

const ANCHOR_ROOT = '77'.repeat(32);
const SPEND_LEAF = 3;
const SPEND_COMMITMENT = '99'.repeat(32);
const SPEND_NULLIFIERS: [string, string] = ['ab'.repeat(32), 'cd'.repeat(32)];
const SUBMITTED_IN_BLOCK = HEAD_NUMBER + 1;

/** The header a spend anchors to, in the shape `chain_getHeader` answers with. */
function rawHeader(number: number): Record<string, unknown> {
  return {
    parentHash: `0x${'01'.repeat(32)}`,
    number: `0x${number.toString(16)}`,
    stateRoot: `0x${'02'.repeat(32)}`,
    extrinsicsRoot: `0x${'03'.repeat(32)}`,
    zkTreeRoot: `0x${ANCHOR_ROOT}`,
    digest: { logs: [`0x${'04'.repeat(20)}`] },
  };
}

/** The hash this fixture's node gives a height. */
function hashOf(height: number): string {
  return `0x${String(height).padStart(64, 'b')}`;
}

/**
 * A node a spend can talk to.
 *
 * It answers a tree, a header, a block carrying whatever was submitted to it,
 * and a settled set holding the two nullifiers the proof published. What the
 * test reads is the list of questions, in order.
 */
function spendContext(options: { refuseSubmission?: boolean; leafCount?: number } = {}): {
  context: ChainContext;
  calls: Call[];
} {
  const calls: Call[] = [];
  const leafCount = options.leafCount ?? LEAF_COUNT;
  const values = new Map<string, string>();
  values.set(KEYS.leafCount, le(BigInt(leafCount), 8));
  values.set(KEYS.depth, le(3n, 1));
  for (let index = 0; index < leafCount; index += 1) {
    values.set(
      `${KEYS.leaves}${index}`,
      `0x${index === SPEND_LEAF ? SPEND_COMMITMENT : 'cd'.repeat(32)}`,
    );
  }
  let submitted: string | null = null;

  const send = <T,>(method: string, params: unknown[]): Promise<T> => {
    calls.push({ method, params });
    if (method === 'chain_getBlockHash') {
      const height = params[0] as number | undefined;
      if (height === undefined) {
        // The chain moves on once the settlement is in the pool, which is what
        // the inclusion walk is walking.
        return Promise.resolve((submitted === null ? HEAD_HASH : hashOf(SUBMITTED_IN_BLOCK)) as T);
      }
      if (height === 0) {
        // Which chain this node serves, read live at the top of every spend
        // rather than taken off the connection.
        return Promise.resolve(GENESIS as T);
      }
      return Promise.resolve(hashOf(height) as T);
    }
    if (method === 'chain_getHeader') {
      const at = String(params[0]);
      return Promise.resolve(
        rawHeader(at === HEAD_HASH ? HEAD_NUMBER : SUBMITTED_IN_BLOCK) as T,
      );
    }
    if (method === 'state_queryStorageAt') {
      const keys = params[0] as string[];
      return Promise.resolve([
        {
          block: String(params[1]),
          changes: keys.map((key) => {
            if (key.startsWith(KEYS.usedNullifiers)) {
              // Settled, but only once the bytes are in a block: this is the
              // confirmation of a settlement, and there is nothing to confirm
              // before one exists.
              return [key, submitted === null ? null : '0x'] as [string, string | null];
            }
            return [key, values.get(key) ?? null] as [string, string | null];
          }),
        },
      ] as T);
    }
    if (method === 'author_submitExtrinsic') {
      if (options.refuseSubmission === true) {
        // What a pool that will not take the envelope looks like from here.
        throw new Error('1010: Invalid Transaction: Transaction is outdated');
      }
      submitted = String(params[0]);
      return Promise.resolve(`0x${'ee'.repeat(32)}` as T);
    }
    if (method === 'chain_getBlock') {
      return Promise.resolve({
        block: { extrinsics: submitted === null ? [] : [submitted] },
      } as T);
    }
    throw new Error(`this test's node was asked ${method}, which a spend must not call`);
  };

  const context = {
    send,
    extrinsicVersion: 4,
    genesisHash: GENESIS,
    constants: {
      blockHashWindow: 256,
      minLeafFee: 4n,
      ciphertextBytesPerFeeQuantum: 512,
      maxCiphertextBytes: 2048,
    },
    api: {
      tx: {
        shielded: { submitPrivateBatch: { callIndex: new Uint8Array([9, 0]) } },
      },
      query: {
        zkTree: {
          leaves: entry(KEYS.leaves),
          leafCount: entry(KEYS.leafCount),
          depth: entry(KEYS.depth),
        },
        shielded: {
          ciphertexts: entry(KEYS.ciphertexts),
          leafBlocks: entry(KEYS.leafBlocks),
          coinbaseValues: entry(KEYS.coinbaseValues),
          entryCount: entry(KEYS.entryCount),
          usedNullifiers: entry(KEYS.usedNullifiers),
        },
      },
    },
    storageDrift: [],
    // The `dev` preset's cadence. `send` sizes its inclusion wait at six block
    // intervals read from here, so a context without it waits `NaN` ms and
    // looks in no block at all.
    targetBlockTimeMs: 12_000,
  } as unknown as ChainContext;

  return { context, calls };
}

/** A prover that answers plausibly and opens no socket, because it cannot. */
function spendProver(overrides: Partial<ProverClient> = {}): ProverClient {
  return {
    addressIsValid: () => Promise.resolve(true),
    buildProver: () =>
      Promise.resolve({
        threads: 1,
        millis: 1,
        cached: false,
        peakLinearMemoryBytes: 0,
        degreeBits: { leaf: 9, privateBatch: 15 },
      }),
    // The circuit's own hash of the preimage the wallet rebuilt, which has to
    // agree with `chain_getBlockHash` before anything is proved.
    headerBlockHash: () => Promise.resolve(HEAD_HASH.replace(/^0x/, '')),
    treeRoot: () => Promise.resolve(ANCHOR_ROOT),
    treePath: () =>
      Promise.resolve({
        siblings: [['00'.repeat(32)]],
        positions: [0],
        root: ANCHOR_ROOT,
        leaf: SPEND_COMMITMENT,
        depth: 3,
      }),
    proveTransfer: () =>
      Promise.resolve({
        proof: new Uint8Array(16),
        ct1: new Uint8Array(1792),
        ct2: new Uint8Array(1792),
        report: {
          num_leaves: 6,
          proof_bytes: 16,
          ciphertext_bytes: [1792, 1792] as [number, number],
          public_inputs: {
            block_hash: HEAD_HASH,
            block_number: HEAD_NUMBER,
            nullifiers: SPEND_NULLIFIERS,
            commitments: ['11'.repeat(32), '22'.repeat(32)] as [string, string],
            fee: 8,
            ct_digest: '00'.repeat(32),
          },
          phases: [],
          peak_linear_memory_bytes_since_init: 0,
          linear_memory_growth_bytes: 0,
        },
      }),
    ...overrides,
  } as unknown as ProverClient;
}

/** What the module reports, which a spend measures its fee and its pad against. */
const LIMITS = {
  memo_bytes: 61,
  ciphertext_fixed_bytes: 1731,
  padded_ciphertext_bytes: 1792,
  digest_logs_size: 110,
  max_tree_depth: 32,
  tree_arity: 4,
  siblings_per_level: 3,
  chain_num_leaves: 6,
};

/** A store that records what it was told and holds nothing. */
function spendStore(
  genesisHash: string | null = GENESIS,
  meta: Partial<StoreMeta> = {},
): WalletStore {
  const written: string[] = [];
  return {
    meta: () => Promise.resolve({ ...freshMeta(), genesisHash, ...meta }),
    sealPendingSecret: () => Promise.resolve({ v: 1, iv: '', ct: '' }),
    commitPending: () => {
      written.push('pending');
      return Promise.resolve();
    },
    markSpentByNullifier: () => {
      written.push('spent');
      return Promise.resolve();
    },
    markOffChain: (commitment: string) => {
      // The commitment as well as the call: which note was written off is the
      // whole content of the assertion below.
      written.push(`offChain:${commitment}`);
      return Promise.resolve(false);
    },
    dropPending: () => {
      written.push('dropPending');
      return Promise.resolve();
    },
    written: () => written,
  } as unknown as WalletStore & { written: () => string[] };
}

async function spendOnce(options: {
  prover?: ProverClient;
  store?: WalletStore;
  to?: string;
} = {}): Promise<{ calls: Call[] }> {
  const { context, calls } = spendContext();
  await spend(
    context,
    options.prover ?? spendProver(),
    options.store ?? spendStore(),
    {
      to: options.to ?? 'qn1recipient',
      amount: 300n,
      memo: 'lunch',
      changeAddress: 'qn1mine',
      candidates: [
        {
          note: {
            commitment: SPEND_COMMITMENT,
            leafIndex: SPEND_LEAF,
            blockNumber: 4,
            value: '1000',
            origin: 'transfer',
            spent: false,
            spentSeenAtBlock: null,
            onChain: true,
            secret: { v: 1, iv: '', ct: '' },
          },
          secret: { rho: OUR_RHO, r: OUR_R, nullifier: OUR_NULLIFIER, memo: '' },
        },
      ],
    },
    LIMITS,
    () => undefined,
  );
  return { calls };
}

describe('the request stream a payment makes', () => {
  it('reads the whole leaf range, so it names none of its own leaves', async () => {
    // The property that a narrowing optimisation would destroy silently. A
    // spend needs one path out of the tree; asking for the leaves that path
    // touches is asking the node which leaf is being spent.
    const { calls } = await spendOnce();
    const asked = new Set<number>();
    for (const call of calls.filter((entryCall) => entryCall.method === 'state_queryStorageAt')) {
      for (const key of call.params[0] as string[]) {
        if (key.startsWith(KEYS.leaves)) {
          asked.add(Number(key.slice(KEYS.leaves.length)));
        }
      }
    }
    expect([...asked].sort((a, b) => a - b)).toEqual(
      Array.from({ length: LEAF_COUNT }, (_value, index) => index),
    );
  });

  it('never names the secrets of the note it is spending', async () => {
    const { calls } = await spendOnce();
    const wire = JSON.stringify(calls).toLowerCase();
    expect(wire).not.toContain(OUR_RHO);
    expect(wire).not.toContain(OUR_R);
    // The stored nullifier is the one the chain has not seen. The two the
    // proof publishes are a separate pair and are public the moment they are
    // in a block.
    expect(wire).not.toContain(OUR_NULLIFIER);
  });

  it('asks about a nullifier by name only after the bytes are in a block', async () => {
    const { calls } = await spendOnce();
    const namesNullifier = calls.findIndex(
      (call) =>
        call.method === 'state_queryStorageAt' &&
        (call.params[0] as string[]).some((key) => key.startsWith(KEYS.usedNullifiers)),
    );
    const inBlock = calls.findIndex((call) => call.method === 'chain_getBlock');
    const submitted = calls.findIndex((call) => call.method === 'author_submitExtrinsic');
    expect(namesNullifier).toBeGreaterThan(-1);
    expect(submitted).toBeGreaterThan(-1);
    expect(namesNullifier).toBeGreaterThan(inBlock);
    expect(inBlock).toBeGreaterThan(submitted);
  });

  it('asks for no leaf proof, ever', async () => {
    const { calls } = await spendOnce();
    // eslint-disable-next-line no-restricted-syntax -- the assertion, not the call
    expect(calls.map((call) => call.method)).not.toContain('zkTree_getMerkleProof');
  });

  it('calls nothing but the methods a settlement needs', async () => {
    const { calls } = await spendOnce();
    const allowed = new Set([
      'chain_getBlockHash',
      'chain_getHeader',
      'state_queryStorageAt',
      'author_submitExtrinsic',
      'chain_getBlock',
    ]);
    for (const call of calls) {
      expect(allowed.has(call.method), `${call.method} is not a method a spend may call`).toBe(true);
    }
  });

  it('refuses a node on another chain having asked it one question', async () => {
    // The gate the command-line wallet opens `prepare_spend` with. Without it
    // a spend anchors on the other chain's head, rebuilds the other chain's
    // tree, passes the root gate over it (a rebuild over that node's own
    // leaves roots to that node's own header) and then writes a real,
    // spendable note off as one this chain does not carry, which no ordinary
    // later sync undoes.
    //
    // The one question is `chain_getBlockHash(0)`, which names nothing and is
    // the same question every client of this chain asks. It is asked live
    // rather than taken off the connection, because a `WsProvider` reconnects
    // on its own and a tab left open across a chain relaunch at the same URL
    // holds a genesis hash naming a chain that is no longer there.
    const { context, calls } = spendContext();
    const store = spendStore(`0x${'99'.repeat(32)}`) as WalletStore & { written: () => string[] };
    await expect(
      spend(
        context,
        spendProver(),
        store,
        {
          to: 'qn1recipient',
          amount: 300n,
          memo: '',
          changeAddress: 'qn1mine',
          candidates: [],
        },
        LIMITS,
        () => undefined,
      ),
    ).rejects.toThrow(/bound to the chain whose genesis/);
    expect(calls).toEqual([{ method: 'chain_getBlockHash', params: [0] }]);
    expect(store.written()).toEqual([]);
  });

  it('refuses a node holding fewer leaves than this wallet has read, writing nothing off', async () => {
    // The gate `runSync` refuses the identical node with, hoisted into the
    // spend. Remove it and this test fails with the store carrying
    // `offChain:<the note>`: every other check in `spend` is against this
    // node's own answers, so they all pass over a short tree. The rebuild
    // roots to this node's own header, leaf 37 is then past the end of a
    // 4-leaf tree, the note's recorded block 1 is below the anchor at 12, and
    // a real, canonical, spendable note is marked off chain on that evidence.
    // The refusal even tells the reader to send again, so the next-largest
    // note goes the same way on the next attempt.
    //
    // A losing fork, a rolled-back snapshot and a head this node has not
    // finished executing all produce this shape with no lie told anywhere.
    const { context } = spendContext({ leafCount: 4 });
    const store = spendStore(GENESIS, { nextLeaf: 40, lastSyncedBlock: 5000 }) as WalletStore & {
      written: () => string[];
    };
    await expect(
      spend(
        context,
        spendProver(),
        store,
        {
          to: 'qn1recipient',
          amount: 300n,
          memo: '',
          changeAddress: 'qn1mine',
          candidates: [
            {
              note: {
                commitment: SPEND_COMMITMENT,
                // Read at a block this node's head has not reached, which is
                // what makes the index look phantom against its short tree.
                leafIndex: 37,
                blockNumber: 1,
                value: '1000',
                origin: 'transfer',
                spent: false,
                spentSeenAtBlock: null,
                onChain: true,
                secret: { v: 1, iv: '', ct: '' },
              },
              secret: { rho: OUR_RHO, r: OUR_R, nullifier: OUR_NULLIFIER, memo: '' },
            },
          ],
        },
        LIMITS,
        () => undefined,
      ),
    ).rejects.toThrow(/reports 4 leaves at its head and this wallet has already read 40/);
    expect(store.written()).toEqual([]);
  });

  it('refuses an address whose checksum does not hold, before it builds anything', async () => {
    // ~2,600 bech32m characters, so a truncated paste is the ordinary
    // mistake. Refused inside the module it costs the circuit build, the
    // anchor read and a rebuild of every leaf on the chain first.
    const { context, calls } = spendContext();
    let built = 0;
    const prover = spendProver({
      addressIsValid: () => Promise.resolve(false),
      buildProver: () => {
        built += 1;
        throw new Error('a spend refused on its address must not build the circuits');
      },
    });
    await expect(
      spend(
        context,
        prover,
        spendStore(),
        {
          to: 'qn1truncated',
          amount: 300n,
          memo: '',
          changeAddress: 'qn1mine',
          candidates: [],
        },
        LIMITS,
        () => undefined,
      ),
    ).rejects.toThrow(/checksum/);
    expect(built).toBe(0);
    // The chain check is the one question that comes first, and it names
    // nothing: see the refusal above.
    expect(calls).toEqual([{ method: 'chain_getBlockHash', params: [0] }]);
  });

  it('takes the pending change note back when the pool refuses the settlement', async () => {
    // The row is written before the submission so a tab reclaimed in the gap
    // still shows the change. Once the pool has refused there is no gap left
    // to cover, and the commitment it names is never appended, so no scan can
    // ever meet it: leaving the row puts a figure in the balance that no sync
    // can clear and only erasing the wallet removes.
    const { context } = spendContext({ refuseSubmission: true });
    const store = spendStore() as WalletStore & { written: () => string[] };
    await expect(
      spend(
        context,
        spendProver(),
        store,
        {
          to: 'qn1recipient',
          amount: 300n,
          memo: 'lunch',
          changeAddress: 'qn1mine',
          candidates: [
            {
              note: {
                commitment: SPEND_COMMITMENT,
                leafIndex: SPEND_LEAF,
                blockNumber: 4,
                value: '1000',
                origin: 'transfer',
                spent: false,
                spentSeenAtBlock: null,
                onChain: true,
                secret: { v: 1, iv: '', ct: '' },
              },
              secret: { rho: '11'.repeat(32), r: '22'.repeat(32), nullifier: SPEND_NULLIFIERS[0], memo: '' },
            },
          ],
        },
        LIMITS,
        () => undefined,
      ),
    ).rejects.toThrow(/outdated/);
    expect(store.written()).toEqual(['pending', 'dropPending']);
  });

  it('starts looking for its own bytes at the block after the anchor', async () => {
    // Not at the head observed after submission. A node can author the block
    // carrying the settlement and another one before that read returns, and a
    // settlement below the first observed head would never be looked at: a
    // landed payment reported as a timeout, with the inputs unlatched.
    const { calls } = await spendOnce();
    const searched = calls
      .filter((call) => call.method === 'chain_getBlockHash' && call.params.length > 0)
      .map((call) => call.params[0] as number)
      // Block zero is the chain check at the top of the spend rather than a
      // block the inclusion walk looked in.
      .filter((height) => height > 0);
    expect(searched).toContain(SUBMITTED_IN_BLOCK);
    expect(Math.min(...searched)).toBe(SUBMITTED_IN_BLOCK);
  });
});
