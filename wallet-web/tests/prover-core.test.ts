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
 */

import { describe, expect, it } from 'vitest';

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
};

const SEED = '7f'.repeat(32);
const ADDRESS = 'qn1stub';
/** What the chain published for the coinbase leaf under test. */
const CHAIN_VALUE = 5000n;
/** What the payload beside it carries, which is what the chain writes. */
const PAYLOAD_VALUE = 0n;

interface Counts {
  builds: number;
  /** Every `(value, rho)` pair the digests were asked for, in order. */
  digests: { value: bigint; rho: string }[];
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
    deriveAccount: () =>
      JSON.stringify({ address: ADDRESS, pk: 'PK', ak: 'AK', cvk: 'CVK-SECRET' }),
    minerKey: () => 'qnm1stub',
    decryptNote: (_seed, ciphertext, expected) => {
      if (expected !== '') {
        // The transfer rule: rebuild at the payload's value and check.
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
    entryRho: () => '00'.repeat(32),
    headerBlockHash: () => '00'.repeat(32),
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
  const counts: Counts = { builds: 0, digests: [] };
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
    const answer = (await core.handle({ kind: 'deriveAccount', seedHex: SEED }, () => undefined))
      .value;
    expect(answer).toEqual({ address: ADDRESS });
    // The module answers with the coinbase viewing key beside the address.
    // Whatever a page later serialises, it cannot serialise that.
    expect(JSON.stringify(answer)).not.toContain('CVK-SECRET');
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
