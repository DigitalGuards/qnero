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

const HEAD_HASH = '0x' + 'aa'.repeat(32);
const GENESIS = '0x' + '11'.repeat(32);
const HEAD_NUMBER = 12;
const LEAF_COUNT = 8;
/** The leaf this wallet owns. The point of the test is that it is not named. */
const OUR_LEAF = 5;
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
  values.set(KEYS.depth, le(3n, 4));
  values.set(KEYS.entryCount, le(2n, 8));
  for (let index = 0; index < LEAF_COUNT; index += 1) {
    values.set(`${KEYS.leaves}${index}`, `0x${(index === OUR_LEAF ? OUR_COMMITMENT : 'cd'.repeat(32))}`);
    values.set(`${KEYS.ciphertexts}${index}`, vecU8('00112233'));
    values.set(`${KEYS.leafBlocks}${index}`, le(BigInt(index + 1), 4));
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
      return Promise.resolve((height === 0 ? GENESIS : `0x${String(height).padStart(64, 'b')}`) as T);
    }
    if (method === 'chain_getHeader') {
      return Promise.resolve({ number: `0x${HEAD_NUMBER.toString(16)}` } as T);
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
    coinbaseBatch: () =>
      Promise.reject(new Error('this chain has no coinbase leaves in the fixture')),
    entryRho: () => Promise.resolve('00'.repeat(32)),
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
    chainAdapter(context),
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

  it('pins every read of the pass to one block hash', async () => {
    const { calls } = await syncOnce();
    const pinned = calls
      .filter((call) => call.method === 'state_queryStorageAt' || call.method === 'state_getKeysPaged')
      .map((call) => (call.method === 'state_queryStorageAt' ? call.params[1] : call.params[3]));
    expect(new Set(pinned)).toEqual(new Set([HEAD_HASH]));
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
function spendContext(): { context: ChainContext; calls: Call[] } {
  const calls: Call[] = [];
  const values = new Map<string, string>();
  values.set(KEYS.leafCount, le(BigInt(LEAF_COUNT), 8));
  values.set(KEYS.depth, le(3n, 4));
  for (let index = 0; index < LEAF_COUNT; index += 1) {
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
  } as unknown as ChainContext;

  return { context, calls };
}

/** A prover that answers plausibly and opens no socket, because it cannot. */
function spendProver(): ProverClient {
  return {
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
  } as unknown as ProverClient;
}

/** A store that records what it was told and holds nothing. */
function spendStore(): WalletStore {
  return {
    sealPendingSecret: () => Promise.resolve({ v: 1, iv: '', ct: '' }),
    commitPending: () => Promise.resolve(),
    markSpentByNullifier: () => Promise.resolve(),
    markOffChain: () => Promise.resolve(false),
  } as unknown as WalletStore;
}

async function spendOnce(): Promise<{ calls: Call[] }> {
  const { context, calls } = spendContext();
  await spend(
    context,
    spendProver(),
    spendStore(),
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
          secret: { rho: OUR_RHO, r: OUR_R, nullifier: OUR_NULLIFIER, memo: '' },
        },
      ],
    },
    {
      memo_bytes: 61,
      ciphertext_fixed_bytes: 1731,
      padded_ciphertext_bytes: 1792,
      digest_logs_size: 110,
      max_tree_depth: 32,
      tree_arity: 4,
      siblings_per_level: 3,
      chain_num_leaves: 6,
    },
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

  it('starts looking for its own bytes at the block after the anchor', async () => {
    // Not at the head observed after submission. A node can author the block
    // carrying the settlement and another one before that read returns, and a
    // settlement below the first observed head would never be looked at: a
    // landed payment reported as a timeout, with the inputs unlatched.
    const { calls } = await spendOnce();
    const searched = calls
      .filter((call) => call.method === 'chain_getBlockHash' && call.params.length > 0)
      .map((call) => call.params[0] as number);
    expect(searched).toContain(SUBMITTED_IN_BLOCK);
    expect(Math.min(...searched)).toBe(SUBMITTED_IN_BLOCK);
  });
});
