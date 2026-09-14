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

import { merkleProofFence, nodeSeamFence } from '../eslint.config.js';

const linter = new Linter();

function lint(code: string): number {
  const messages = linter.verify(code, {
    rules: { 'no-restricted-syntax': ['error', ...merkleProofFence] },
  });
  return messages.length;
}

function lintSeam(code: string): number {
  const messages = linter.verify(code, {
    rules: { 'no-restricted-syntax': ['error', ...nodeSeamFence] },
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

/**
 * The transport fence.
 *
 * `chain/api.ts` said every read goes through one seam and that the privacy
 * test records the property there. The claim was already false: the head
 * subscription went out over `api.rpc.chain.subscribeNewHeads`, which that
 * test cannot see, and the next read written the same way could have been
 * `api.query.shielded.usedNullifiers(mine)`, which puts a raw 32-byte
 * nullifier on the wire and would pass every unit test in this suite.
 */
const SEAM_CAUGHT: Record<string, string> = {
  'a storage read through the typed API':
    'await context.api.query.shielded.usedNullifiers(mine);',
  'a subscription through the typed API':
    'await api.rpc.chain.subscribeNewHeads(onHead);',
  'a runtime call through the typed API':
    'await context.api.call.zkTreeApi.something(leaf);',
  'a derive helper':
    'await api.derive.chain.bestNumber();',
};

const SEAM_ALLOWED: Record<string, string> = {
  'the seam itself': "await context.send('state_queryStorageAt', [keys, at]);",
  'the subscription seam': "await context.subscribe('chain_newHead', 'chain_subscribeNewHead', [], onHead);",
  'reading a call index off a submittable, which opens no socket':
    "const index = context.api.tx['shielded']['submitPrivateBatch'].callIndex;",
  'a local query of something that is not an api':
    'const rows = store.query(everything);',
};

describe('the transport fence', () => {
  for (const [what, code] of Object.entries(SEAM_CAUGHT)) {
    it(`catches ${what}`, () => {
      expect(lintSeam(code)).toBeGreaterThan(0);
    });
  }

  for (const [what, code] of Object.entries(SEAM_ALLOWED)) {
    it(`leaves ${what} alone`, () => {
      expect(lintSeam(code)).toBe(0);
    });
  }
});
