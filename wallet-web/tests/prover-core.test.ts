import { TEST_PROTOCOL_PROFILE } from './fixtures/protocol-profile';
/**
 * The two rules the worker enforces that nothing outside it can see.
 *
 * A page cannot tell a cached circuit build from a fresh one: both answer with
 * a build report and the wallet works either way. What differs is a quarter
 * gigabyte of linear memory per payment that never comes back, which is why
 * the rule is tested against a module that counts its own calls rather than
 * inferred from a measurement.
 *
 * The second is the coinbase rule. A coinbase's value is the chain's own
 * arithmetic and a payload beside it carries zero, so opening one under the
 * ordinary transfer rule rebuilds at the wrong value, fails the commitment
 * check and reads this wallet's own coinbase as nobody's, silently.
 *
 * The third is the seed's lifecycle, which is the one with a plaintext spend
 * key on the wrong side of it. An unlock used to install the seed and then
 * ask for the module, so an unlock against a worker that had never been
 * initialised (stop the prover on the settings screen, lock, unlock) left the
 * seed resident while the page read "locked" on every screen, with both
 * controls that could clear it behind an open wallet. The module comes first
 * now and the seed is installed only once a derivation has answered.
 */

import { describe, expect, it } from 'vitest';

import { ProverClient } from '../src/worker/client';
import { ENTRY_WALK_LIMIT } from '../src/worker/protocol';
import { ProverCore, type ModuleLoader, type WasmModule, type WasmProver } from '../src/worker/core';

const LIMITS = {
  memo_bytes: 61,
  ciphertext_fixed_bytes: 1731,
  padded_ciphertext_bytes: 1792,
  digest_logs_size: 110,
  max_tree_depth: 32,
  tree_arity: 4,
  siblings_per_level: 3,
  chain_num_leaves: 6,
  protocol_profile: TEST_PROTOCOL_PROFILE,
};

const ADDRESS = 'qn1stub';
/** What the chain published for the coinbase leaf under test. */
const CHAIN_VALUE = 5000n;
/** What the payload beside it carries, which is what the chain writes. */
const PAYLOAD_VALUE = 0n;

interface Counts {
  builds: number;
  /** Every `(value, rho)` pair the digests were asked for, in order. */
  digests: { value: bigint; rho: string }[];
  /** How many entry hashes the origin walk asked for. */
  entryRho: number;
}

/**
 * A module that answers plausibly and counts what it was asked.
 *
 * The commitment is `H(value, rho)` spelled as a string, which is enough for
 * the one property under test: which value the rebuild used.
 */
function stubModule(counts: Counts): WasmModule {
  const prover: WasmProver = {
    numLeaves: 6,
    buildReportJson: JSON.stringify({ leaf_degree_bits: 9, private_batch_degree_bits: 15 }),
    proveTransfer: () => {
      throw new Error('this stub does not prove');
    },
    verifyProof: () => 0,
  };
  return {
    default: () => Promise.resolve({ memory: { buffer: new ArrayBuffer(8) } as WebAssembly.Memory }),
    entropySelfCheck: () => undefined,
    walletLimits: () => JSON.stringify(LIMITS),
    readStateProof: () => '[]',
    deriveAccount: () =>
      JSON.stringify({ address: ADDRESS, pk: 'PK', ak: 'AK', cvk: 'CVK-SECRET' }),
    minerKey: () => 'qnm1stub',
    decryptNote: (_seed, ciphertext, expected) => {
      if (expected !== '') {
        // Nothing in the worker takes the module's checked path any more. Both
        // batches open the payload on its own and compare afterwards, which is
        // what keeps "this wallet's note, moved" apart from "somebody else's":
        // the module's refusal on a mismatch reads the same as a stranger's
        // ciphertext and threw the one local detector away.
        throw new Error('this stub refuses the checked path');
      }
      return JSON.stringify({
        value: Number(PAYLOAD_VALUE),
        rho: 'aa'.repeat(32),
        r: 'bb'.repeat(32),
        commitment: '',
        memo: `payload of ${ciphertext.length} bytes`,
      });
    },
    noteDigests: (_seed, value, rho) => {
      counts.digests.push({ value, rho });
      return JSON.stringify({
        inner: 'ff'.repeat(32),
        commitment: `commit-${value}-${rho.slice(0, 4)}`,
        nullifier: `null-${value}`,
      });
    },
    coinbaseNote: () =>
      JSON.stringify({
        rho: 'cc'.repeat(32),
        r: 'dd'.repeat(32),
        commitment: 'not-this-wallets-coinbase',
        nullifier: 'nn'.repeat(32),
      }),
    // `H(RHO_ENTRY, block, index)`, stubbed as something a test can predict.
    entryRho: (block: number, index: bigint) => {
      counts.entryRho += 1;
      return `entry-${block}-${index.toString()}`;
    },
    headerBlockHash: () => '00'.repeat(32),
    headerBlockHashes: (headersJson: string) =>
      JSON.stringify((JSON.parse(headersJson) as { block_number: number }[]).map(() => '00'.repeat(32))),
    authorLabel: () => 'aa'.repeat(32),
    blockRoots: (_leafHashes: Uint8Array, countsJson: string) =>
      JSON.stringify((JSON.parse(countsJson) as number[]).map(() => '00'.repeat(32))),
    treePath: () => '{}',
    treeRoot: () => '00'.repeat(32),
    depthFor: () => 3,
    addressIsValid: () => true,
    memoFits: (memo) => memo.length,
    ctDigest: () => '00'.repeat(32),
    chainNumLeaves: () => 6,
    peakLinearMemoryBytes: () => 910 * 1024 * 1024,
    WasmWalletProver: {
      fromSource: () => {
        counts.builds += 1;
        return prover;
      },
    },
  };
}

async function started(): Promise<{ core: ProverCore; counts: Counts }> {
  const counts: Counts = { builds: 0, digests: [], entryRho: 0 };
  const load: ModuleLoader = () => Promise.resolve({ module: stubModule(counts), threads: 1 });
  const core = new ProverCore(load);
  await core.handle({ kind: 'init', wasmBase: 'wasm/', numLeaves: 6, maxThreads: 1 }, () => undefined);
  return { core, counts };
}

describe('the circuits', () => {
  it('are built once however often a payment asks for them', async () => {
    const { core, counts } = await started();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await core.handle({ kind: 'buildProver' }, () => undefined);
    }
    expect(counts.builds).toBe(1);
  });

  it('say which answer was the build and which was the cache', async () => {
    const { core } = await started();
    const first = (await core.handle({ kind: 'buildProver' }, () => undefined)).value as {
      cached: boolean;
      millis: number;
    };
    const second = (await core.handle({ kind: 'buildProver' }, () => undefined)).value as {
      cached: boolean;
      millis: number;
    };
    expect(first.cached).toBe(false);
    expect(second.cached).toBe(true);
    // The cached answer carries the first build's cost, not this call's.
    expect(second.millis).toBe(first.millis);
  });
});

describe('an account derivation', () => {
  it('hands the page the address and nothing else', async () => {
    const { core } = await started();
    // Through the unlock, which is the only request that carries a seed and
    // the only one that answers with an account. The create path used to send
    // a second request carrying the seed as a plain string, for this address.
    const answer = (
      await core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined)
    ).value;
    expect(answer).toEqual({ address: ADDRESS });
    // The module answers with the coinbase viewing key beside the address.
    // Whatever a page later serialises, it cannot serialise that.
    expect(JSON.stringify(answer)).not.toContain('CVK-SECRET');
  });
});

describe('the shield walk', () => {
  it('walks the whole counter, so a restored wallet labels its older shields', async () => {
    // It used to walk the newest 64 entries and ask the page once per index.
    // A wallet restored from its seed on a chain with more shields than that
    // labelled every one of its own older shields `transfer`, for good, since
    // origin is written once at receipt. The command-line wallet walks the
    // whole counter, and the label should say what that one says.
    const { core } = await started();
    const answer = await core.handle(
      { kind: 'entryRhoMatches', blockNumber: 7, rho: 'entry-7-3', entryCount: '500' },
      () => undefined,
    );
    expect(answer.value).toBe(true);
  });

  it('stops at the bound rather than hashing once per unit of a number the node chose', async () => {
    // `EntryCount` is the node's answer and this loop is synchronous, on the
    // thread holding the seed. Unbounded, one small reply buys the worker
    // forever: the scan stops reporting, the sync never commits, and the
    // settings control that terminates the worker is disabled while a sync
    // runs, so a reload is the only way out and the same node does it again.
    // Remove the bound and this test runs until vitest kills it.
    //
    // The label is what is given up past the bound, and the sync says so:
    // `origin` separates a shield from a spend's output in a listing and no
    // rule selects on it.
    const { core, counts } = await started();
    const answer = await core.handle(
      {
        kind: 'entryRhoMatches',
        blockNumber: 7,
        rho: 'aa'.repeat(32),
        entryCount: (2n ** 256n - 1n).toString(),
      },
      () => undefined,
    );
    expect(answer.value).toBe(false);
    expect(counts.entryRho).toBe(Number(ENTRY_WALK_LIMIT));
  });

  it('says no when no entry produces that rho, which is every ordinary payment', async () => {
    const { core } = await started();
    const answer = await core.handle(
      { kind: 'entryRhoMatches', blockNumber: 7, rho: 'aa'.repeat(32), entryCount: '64' },
      () => undefined,
    );
    expect(answer.value).toBe(false);
  });

  it('crosses the boundary once for a note rather than once for an entry', async () => {
    // The walk is the module's, on the side that holds the secret it is
    // comparing. One request answers it.
    const { core } = await started();
    const answer = await core.handle(
      { kind: 'entryRhoMatches', blockNumber: 2, rho: '0xENTRY-2-9', entryCount: '10' },
      () => undefined,
    );
    // And the comparison is on one spelling of a digest, whatever spelling
    // each side wrote it in.
    expect(answer.value).toBe(true);
  });
});

describe('a transfer leaf', () => {
  /**
   * The transfer rule, and the answer the scan acts on.
   *
   * The payload opens on its own and the commitment beside it is compared
   * here. A note that opens to a different commitment comes back with `moved`
   * set, which is what `runSync` searches the block's authenticated leaf range
   * on. Handing the module the leaf's commitment instead would make it refuse,
   * and a refusal reads exactly like a stranger's ciphertext.
   */
  it('marks a note whose leaf carries a commitment it does not open', async () => {
    const { core } = await started();
    await core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined);
    const answer = (
      await core.handle(
        {
          kind: 'decryptBatch',
          items: [
            {
              index: 1,
              ciphertext: new Uint8Array([1, 2, 3]),
              commitment: `commit-${PAYLOAD_VALUE}-aaaa`,
            },
            { index: 2, ciphertext: new Uint8Array([1, 2, 3]), commitment: 'a-different-leaf' },
          ],
        },
        () => undefined,
      )
    ).value as ({ commitment: string; moved?: boolean } | null)[];

    expect(answer[0]?.commitment).toBe(`commit-${PAYLOAD_VALUE}-aaaa`);
    expect(answer[0]?.moved).toBeUndefined();
    expect(answer[1]?.commitment).toBe(`commit-${PAYLOAD_VALUE}-aaaa`);
    expect(answer[1]?.moved).toBe(true);
  });
});

describe('a coinbase leaf', () => {
  it('is rebuilt at the value the chain published, not the payload\'s', async () => {
    const { core, counts } = await started();
    const unlocked = new Uint8Array(32);
    await core.handle({ kind: 'unlock', seed: unlocked }, () => undefined);
    const answer = (
      await core.handle(
        {
          kind: 'coinbaseBatch',
          items: [
            {
              index: 4,
              blockNumber: 9,
              value: CHAIN_VALUE.toString(),
              genesisHash: '11'.repeat(32),
              commitment: `commit-${CHAIN_VALUE}-aaaa`,
              ciphertext: new Uint8Array([1, 2, 3]),
            },
          ],
        },
        () => undefined,
      )
    ).value as ({ value: string; memo: string } | null)[];

    expect(counts.digests).toEqual([{ value: CHAIN_VALUE, rho: 'aa'.repeat(32) }]);
    expect(answer[0]?.value).toBe(CHAIN_VALUE.toString());
    expect(answer[0]?.memo).toBe('payload of 3 bytes');
  });

  it('is nobody\'s when the commitment does not open at the chain\'s value', async () => {
    const { core } = await started();
    await core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined);
    const answer = (
      await core.handle(
        {
          kind: 'coinbaseBatch',
          items: [
            {
              index: 4,
              blockNumber: 9,
              value: CHAIN_VALUE.toString(),
              genesisHash: '11'.repeat(32),
              commitment: 'somebody-elses-coinbase',
              ciphertext: new Uint8Array([1, 2, 3]),
            },
          ],
        },
        () => undefined,
      )
    ).value as (object | null)[];
    expect(answer[0]).toBeNull();
  });
});

describe("the seed the worker holds", () => {
  it('installs nothing when there is no module to derive with', async () => {
    const counts: Counts = { builds: 0, digests: [], entryRho: 0 };
    const load: ModuleLoader = () => Promise.resolve({ module: stubModule(counts), threads: 1 });
    const core = new ProverCore(load);

    // The unlock a page makes against a worker it never initialised.
    await expect(
      core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined),
    ).rejects.toThrow(/the prover module has not been loaded/);

    // The module arrives, and the worker is still locked: nothing was kept
    // from the refused unlock.
    await core.handle({ kind: 'init', wasmBase: 'wasm/', numLeaves: 6, maxThreads: 1 }, () => undefined);
    await expect(core.handle({ kind: 'decryptBatch', items: [] }, () => undefined)).rejects.toThrow(
      /this wallet is locked, so the worker holds no seed/,
    );
  });

  it('installs nothing when the derivation refuses', async () => {
    const counts: Counts = { builds: 0, digests: [], entryRho: 0 };
    const load: ModuleLoader = () =>
      Promise.resolve({
        module: {
          ...stubModule(counts),
          deriveAccount: (): string => {
            throw new Error('this seed does not derive');
          },
        },
        threads: 1,
      });
    const core = new ProverCore(load);
    await core.handle({ kind: 'init', wasmBase: 'wasm/', numLeaves: 6, maxThreads: 1 }, () => undefined);
    await expect(
      core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined),
    ).rejects.toThrow(/does not derive/);
    await expect(core.handle({ kind: 'decryptBatch', items: [] }, () => undefined)).rejects.toThrow(
      /this wallet is locked, so the worker holds no seed/,
    );
  });

  it('answers the miner key from what it holds, so no request carries a seed', async () => {
    const { core } = await started();
    // Before the unlock there is nothing to derive from, and the refusal says
    // so rather than taking a seed off the caller.
    await expect(core.handle({ kind: 'minerKey' }, () => undefined)).rejects.toThrow(
      /this wallet is locked, so the worker holds no seed/,
    );
    await core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined);
    expect((await core.handle({ kind: 'minerKey' }, () => undefined)).value).toBe('qnm1stub');
  });

  it('drops it on lock', async () => {
    const { core } = await started();
    await core.handle({ kind: 'unlock', seed: new Uint8Array(32) }, () => undefined);
    await core.handle({ kind: 'lock' }, () => undefined);
    await expect(core.handle({ kind: 'minerKey' }, () => undefined)).rejects.toThrow(
      /this wallet is locked, so the worker holds no seed/,
    );
  });
});

describe('the prover the settings screen stopped', () => {
  it('does not start a worker to be told to forget a seed it never had', async () => {
    // `Worker` does not exist in this environment, so a `lock()` that reached
    // `ensureWorker()` would throw here and did: locking after the prover was
    // stopped spawned a fresh worker, and the settings switch went on reading
    // off while one ran.
    const client = new ProverClient();
    await expect(client.lock()).resolves.toBeNull();
    expect(client.isRunning).toBe(false);
  });

  it('stays stopped, and says which switch turns it back on', async () => {
    const client = new ProverClient();
    client.terminate();
    await expect(client.minerKey()).rejects.toThrow(/the prover is stopped/);
    expect(client.isRunning).toBe(false);
  });
});
