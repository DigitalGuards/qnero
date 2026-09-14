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
 * Both halves of that are now checked rather than stated. The page's half is
 * that seam and the transport fence in `eslint.config.js`; the worker's half
 * is the worker fence beside it, which refuses `WebSocket`, `fetch`,
 * `XMLHttpRequest`, `EventSource` and `sendBeacon` anywhere under
 * `src/worker/`, with every spelling run through `tests/lint-fence.test.ts`.
 * Nothing else could see a request made from here: the end-to-end recorder
 * patches `WebSocket.prototype.send` in the page's frames, and a worker has
 * its own realm.
 *
 * The other reason is the M8 measurement. A private batch is 33.6 s of
 * synchronous wasm and the circuit build is 12.1 s more. On the main thread
 * that is a frozen tab, and a frozen tab on iOS is a tab the operating system
 * may reclaim.
 *
 * # What never crosses
 *
 * The leaf proof, which is not returned by the module at all. And 910 MiB of
 * linear memory, which cannot be copied and does not need to be: a result is
 * one proof of 150,908 bytes and two ciphertexts of 1792 bytes each.
 *
 * The seed crosses exactly once, in `unlock`, as a transferred `Uint8Array`
 * whose page-side copy is detached by the transfer. Every other request that
 * needs it is answered from what the worker holds, and `unlock` answers with
 * the account, so the create path learns its address from the same crossing.
 *
 * Two requests used to carry one and no longer do. `minerKey` made the page
 * read the vault back out to ask a routine question, which left an uncleanable
 * copy of the spend key in the page for the life of the tab. `deriveAccount`
 * carried the seed as a plain string on the create path, and structured clone
 * leaves a string copy in the worker's heap that neither side can erase, for
 * an address `unlock` already returns.
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

/**
 * What an account derivation hands back.
 *
 * The address and nothing else. The module derives `pk`, `ak` and `cvk` too,
 * and `cvk` is viewing-tier secret: its holder picks this wallet's coinbase
 * notes out of the tree. The page uses none of the three, so none of them
 * crosses, and the one place a wallet means to show the miner key has its own
 * request behind a dialog that says what it is.
 */
export interface ProverAccount {
  address: string;
}

export interface DecryptItem {
  index: number;
  ciphertext: Uint8Array;
  commitment: string;
}

/**
 * One coinbase leaf to rebuild.
 *
 * `value` is the chain's, out of `Shielded::CoinbaseValues`, and it is the one
 * that decides: a coinbase payload carries a value of zero, because the chain
 * hashed its own arithmetic into the commitment. The ciphertext is the second
 * way in, for a coinbase this wallet's miner key did not mint.
 */
export interface CoinbaseItem {
  index: number;
  blockNumber: number;
  value: string;
  genesisHash: string;
  commitment: string;
  ciphertext: Uint8Array | null;
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
  /**
   * Whether the circuits were already resident, so `millis` is the first
   * build's rather than this call's. A rebuild costs a quarter gigabyte of
   * linear memory that never comes back: see `core.ts`.
   */
  cached: boolean;
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
  | { kind: 'minerKey' }
  | { kind: 'unlock'; seed: Uint8Array }
  | { kind: 'lock' }
  | { kind: 'addressIsValid'; address: string }
  | { kind: 'memoFits'; memo: string }
  | { kind: 'decryptBatch'; items: DecryptItem[] }
  | { kind: 'coinbaseBatch'; items: CoinbaseItem[] }
  | { kind: 'entryRhoMatches'; blockNumber: number; rho: string; entryCount: string }
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
