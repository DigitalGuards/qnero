/**
 * What crosses the worker boundary.
 *
 * The split is the point of this file, so it is stated here rather than left
 * to be inferred from the message names:
 *
 * **The worker holds the seed, the wasm module and every rule that touches a
 * secret.** It derives the account, decrypts ciphertexts, derives nullifiers,
 * rebuilds the tree, hashes the anchor and proves. It never opens a socket.
 *
 * **The page holds the connection and the store.** It issues every chain
 * request and hands the worker public bytes.
 *
 * That is not only a convenience about which thread blocks. It is what makes
 * "the node learns nothing" checkable: the side that could leak a secret into
 * a request has no way to make a request, and the side that makes requests
 * holds no secret to leak. `tests/privacy.test.ts` records the page's requests
 * at one seam and asserts the property there.
 *
 * The other reason is the M8 measurement. A private batch is 33.6 s of
 * synchronous wasm and the circuit build is 12.1 s more. On the main thread
 * that is a frozen tab, and a frozen tab on iOS is a tab the operating system
 * may reclaim.
 *
 * # What never crosses
 *
 * The leaf proof, which is not returned by the module at all. The seed, once
 * it is in: it goes in as a transferred `Uint8Array` and the page's copy is
 * zeroed. And 910 MiB of linear memory, which cannot be copied and does not
 * need to be: a result is one proof of 150,908 bytes and two ciphertexts of
 * 1792 bytes each.
 */

import type { Anchor } from '../chain/anchor';

export interface ProverLimits {
  memo_bytes: number;
  ciphertext_fixed_bytes: number;
  padded_ciphertext_bytes: number;
  digest_logs_size: number;
  max_tree_depth: number;
  tree_arity: number;
  siblings_per_level: number;
  chain_num_leaves: number;
}

export interface ProverAccount {
  address: string;
  pk: string;
  ak: string;
  /** Secret bearing: it picks this wallet's coinbase notes out of the tree. */
  cvk: string;
}

export interface DecryptItem {
  index: number;
  ciphertext: Uint8Array;
  commitment: string;
}

export interface DecryptedNote {
  value: string;
  rho: string;
  r: string;
  commitment: string;
  nullifier: string;
  memo: string;
}

export interface PathAnswer {
  siblings: string[][];
  positions: number[];
  root: string;
  leaf: string;
  depth: number;
}

/** One output of a spend, as the page describes it. */
export interface OutputRequest {
  address: string;
  value: string;
  memo?: string;
}

export interface InputRequest {
  value: string;
  rho: string;
  r: string;
  path: { siblings: string[][]; positions: number[] };
}

export interface TransferRequest {
  anchor: Anchor;
  tree_depth: number;
  fee: string;
  inputs: InputRequest[];
  outputs: OutputRequest[];
}

export interface SubmissionAnswer {
  proof: Uint8Array;
  ct1: Uint8Array;
  ct2: Uint8Array;
  report: {
    num_leaves: number;
    proof_bytes: number;
    ciphertext_bytes: [number, number];
    public_inputs: {
      block_hash: string;
      block_number: number;
      nullifiers: [string, string];
      commitments: [string, string];
      fee: number;
      ct_digest: string;
    };
    phases: { phase: string; millis: number }[];
    peak_linear_memory_bytes_since_init: number;
    linear_memory_growth_bytes: number;
  };
}

export interface BuildAnswer {
  /** Whether the threaded module was used, and with how many threads. */
  threads: number;
  millis: number;
  peakLinearMemoryBytes: number;
  degreeBits: { leaf: number; privateBatch: number };
}

export interface InitAnswer {
  limits: ProverLimits;
  threads: number;
  moduleBytes: number;
  initMillis: number;
  entropyMillis: number;
}

/** Every request the page may send. */
export type WorkerRequest =
  | { kind: 'init'; wasmBase: string; numLeaves: number; maxThreads: number }
  | { kind: 'limits' }
  | { kind: 'deriveAccount'; seedHex: string }
  | { kind: 'minerKey'; seedHex: string }
  | { kind: 'unlock'; seed: Uint8Array }
  | { kind: 'lock' }
  | { kind: 'addressIsValid'; address: string }
  | { kind: 'memoFits'; memo: string }
  | { kind: 'decryptBatch'; items: DecryptItem[] }
  | { kind: 'coinbaseNote'; blockNumber: number; value: string; genesisHash: string }
  | { kind: 'entryRho'; blockNumber: number; entryIndex: string }
  | { kind: 'noteDigests'; value: string; rho: string; r: string }
  | { kind: 'headerBlockHash'; anchor: Anchor }
  | { kind: 'treePath'; leafHashes: Uint8Array; depth: number; leafIndex: number }
  | { kind: 'treeRoot'; leafHashes: Uint8Array; depth: number }
  | { kind: 'depthFor'; leafCount: number }
  | { kind: 'buildProver' }
  | { kind: 'proveTransfer'; request: TransferRequest };

export type WorkerResponse =
  | { id: number; ok: true; value: unknown; transfer?: Transferable[] }
  | { id: number; ok: false; error: string }
  | { id: -1; progress: { stage: string; detail?: string } };
