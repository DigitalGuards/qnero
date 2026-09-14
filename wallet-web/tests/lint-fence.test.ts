/**
 * The Merkle-proof fence, run against every spelling it has to catch.
 *
 * The fence is the one rule in this repository that is a privacy control
 * rather than a style: `zkTree_getMerkleProof` is only ever asked about a leaf
 * the caller is spending, seconds before the settlement publishes the matching
 * nullifiers. A lint rule that catches one spelling and misses four is worse
 * than none, because it reads as protection.
 *
 * The node answers to two names and a client can reach either through several
 * layers, so the selectors key on the name wherever it is written rather than
 * on where it sits in a parameter list. This test is what keeps that claim
 * true: every spelling below was reachable at some point, and two of them
 * passed an earlier version of the rule that keyed on the first argument.
 */

import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';

import { merkleProofFence } from '../eslint.config.js';

const linter = new Linter();

function lint(code: string): number {
  const messages = linter.verify(code, {
    rules: { 'no-restricted-syntax': ['error', ...merkleProofFence] },
  });
  return messages.length;
}

const CAUGHT: Record<string, string> = {
  'the RPC name, first argument':
    "await provider.send('zkTree_getMerkleProof', [leafIndex]);",
  'the runtime-call name through state_call':
    "await provider.send('state_call', ['ZkTreeApi_get_merkle_proof', args]);",
  'the runtime-call name second, through archive_v1_call':
    "await provider.send('archive_v1_call', [hash, 'ZkTreeApi_get_merkle_proof', args]);",
  'the polkadot-js runtime-call sugar':
    'await api.call.zkTreeApi.getMerkleProof(leafIndex);',
  'the polkadot-js RPC sugar':
    'await api.rpc.zkTree.getMerkleProof(leafIndex);',
  'the snake-case sugar':
    'await api.call.zkTreeApi.get_merkle_proof(leafIndex);',
  'a computed key':
    "await api.call.zkTreeApi['getMerkleProof'](leafIndex);",
  'a raw send with some other merkle-proof spelling':
    "await provider.send('qnero_merkleProof', [leafIndex]);",
};

const ALLOWED: Record<string, string> = {
  'reading the leaf range, which is the replacement':
    "await provider.send('state_queryStorageAt', [keys, at]);",
  'paging the settled set':
    "await provider.send('state_getKeysPaged', [prefix, 1000, cursor, at]);",
  'a local rebuild that mentions a tree but asks nobody':
    'const path = wasm.treePath(leafHashes, depth, leafIndex);',
};

describe('the Merkle-proof fence', () => {
  for (const [what, code] of Object.entries(CAUGHT)) {
    it(`catches ${what}`, () => {
      expect(lint(code)).toBeGreaterThan(0);
    });
  }

  for (const [what, code] of Object.entries(ALLOWED)) {
    it(`leaves ${what} alone`, () => {
      expect(lint(code)).toBe(0);
    });
  }
});
