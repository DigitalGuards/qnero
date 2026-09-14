import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ESLint } from 'eslint';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * The Merkle-proof lint fence, run against every spelling of the call.
 *
 * The fence is the only thing standing between this codebase and a read that
 * names one leaf to whoever runs the node, and it is a set of syntax selectors,
 * which fail open: a selector that matches nothing lints clean and reads exactly
 * like a selector that is doing its job. Two of them matched nothing. The first
 * keyed on the method name in `provider.send`, so `api.call.zkTreeApi
 * .getMerkleProof` passed; the second read the runtime-call name out of
 * `arguments.1.elements.0`, which is where `state_call` puts it and where
 * `archive_v1_call`, whose parameters are `[hash, function, callParameters]`,
 * does not.
 *
 * So the selectors are exercised here rather than trusted. The options come out
 * of the shipped `eslint.config.js` through ESLint's own config resolution, so
 * a selector that is deleted or narrowed fails this test.
 *
 * The probe lints text with no type information, because the repository config
 * is type aware and a probe is not a file in the TypeScript project. Only
 * `no-restricted-syntax` is under test and it needs no types.
 */
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

interface Restriction {
  selector: string;
  message: string;
}

function restrictionsOf(value: unknown): Restriction[] {
  if (!Array.isArray(value)) {
    throw new Error('no-restricted-syntax is not configured with options');
  }
  const found: Restriction[] = [];
  for (const entry of value as readonly unknown[]) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    if (!('selector' in entry) || !('message' in entry)) {
      continue;
    }
    const selector: unknown = entry.selector;
    const message: unknown = entry.message;
    if (typeof selector === 'string' && typeof message === 'string') {
      found.push({ selector, message });
    }
  }
  if (found.length === 0) {
    throw new Error('no-restricted-syntax carries no selectors');
  }
  return found;
}

/** The rule options the repository's own config resolves to, for a file it lints. */
async function shippedFence(): Promise<Restriction[]> {
  const resolver = new ESLint({ cwd: ROOT });
  const config: unknown = await resolver.calculateConfigForFile(
    path.join(ROOT, 'src/chain/blocks.ts'),
  );
  if (typeof config !== 'object' || config === null || !('rules' in config)) {
    throw new Error('the explorer config resolved with no rules');
  }
  const rules: unknown = config.rules;
  if (typeof rules !== 'object' || rules === null || !('no-restricted-syntax' in rules)) {
    throw new Error('the explorer config declares no no-restricted-syntax');
  }
  return restrictionsOf(rules['no-restricted-syntax']);
}

let probe: ESLint;

beforeAll(async () => {
  const fence = await shippedFence();
  probe = new ESLint({
    cwd: ROOT,
    overrideConfigFile: true,
    overrideConfig: {
      rules: { 'no-restricted-syntax': ['error', ...fence] },
    },
  });
});

async function refusals(source: string): Promise<string[]> {
  const results = await probe.lintText(source, {
    filePath: path.join(ROOT, 'merkle-proof-probe.js'),
  });
  return (results[0]?.messages ?? []).map((message) => message.message);
}

/** Every spelling of the call the node serves, and the one it is written as here. */
const SPELLINGS: Record<string, string> = {
  'the RPC method by name': "provider.send('zkTree_getMerkleProof', [leafIndex]);",
  'the runtime call behind state_call': "provider.send('state_call', ['ZkTreeApi_get_merkle_proof', payload]);",
  'the runtime call behind state_callAt': "provider.send('state_callAt', ['ZkTreeApi_get_merkle_proof', payload, at]);",
  // [hash, function, callParameters]: the name is the second parameter here,
  // and a selector keyed on the first one never matched this line.
  'the runtime call behind archive_v1_call': "provider.send('archive_v1_call', [at, 'ZkTreeApi_get_merkle_proof', payload]);",
  'the runtime-call name held in a constant': "const METHOD = 'ZkTreeApi_get_merkle_proof';",
  'polkadot-js runtime-call sugar': 'api.call.zkTreeApi.getMerkleProof(leafIndex);',
  'polkadot-js runtime-call sugar, snake case': 'api.call.zkTreeApi.get_merkle_proof(leafIndex);',
  'polkadot-js runtime-call sugar under a computed key': "api.call.zkTreeApi['getMerkleProof'](leafIndex);",
  'the rpc namespace polkadot-js builds from metadata': 'api.rpc.zkTree.getMerkleProof(leafIndex);',
};

/** Reads the site does make, which have to keep linting clean. */
const ALLOWED: Record<string, string> = {
  'a consensus constant through state_call': "provider.send('state_call', ['QPoWApi_get_difficulty', '0x']);",
  'the paged key walk over the nullifier set': "provider.send('state_getKeysPaged', [prefix, 1000, cursor, at]);",
  'a block body': "provider.send('chain_getBlock', [hash]);",
  'the leaves read as a public range': 'api.query.zkTree.leaves.entriesPaged(options);',
};

describe('the Merkle-proof lint fence', () => {
  it('carries more than the two selectors that matched one argument position', async () => {
    expect((await shippedFence()).length).toBeGreaterThanOrEqual(4);
  });

  for (const [name, source] of Object.entries(SPELLINGS)) {
    it(`refuses ${name}`, async () => {
      const messages = await refusals(source);
      expect(messages.length).toBeGreaterThan(0);
      expect(messages[0]).toContain('names one leaf to whoever runs the node');
    });
  }

  for (const [name, source] of Object.entries(ALLOWED)) {
    it(`leaves ${name} alone`, async () => {
      expect(await refusals(source)).toStrictEqual([]);
    });
  }
});
