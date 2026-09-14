/// <reference lib="webworker" />
/**
 * The worker: the wasm module, the seed, and every rule that touches either.
 *
 * The module is fetched at runtime from `wasmBase` rather than bundled. Three
 * reasons, and the third is the one that decides it:
 *
 * - It is three megabytes, and Vite has no business parsing it.
 * - The same build then serves either module, and which one is a runtime
 *   decision the page cannot make at build time.
 * - `wasm-bindgen --target web` emits an ES module with a default `init()`.
 *   Fetching it inside the worker is what lets the browser's own code cache do
 *   the compile once.
 *
 * # Threads
 *
 * If `wasmBase + 'threaded/'` carries a module and this context is
 * cross-origin isolated, that one is loaded and its rayon pool is started with
 * `min(hardwareConcurrency, maxThreads)` workers. Otherwise the
 * single-threaded module is loaded. The fallback is silent by design: a static
 * host that does not send COOP and COEP is the common deployment, and a wallet
 * that refused to work there would be a wallet nobody could host. The page
 * reports which module it got, because the difference is the whole of the M8
 * finding.
 *
 * # The seed
 *
 * It arrives as a transferred `Uint8Array`, is turned into hex once, and the
 * transferred buffer is zeroed. The hex string is what the module's exports
 * take and it is a JavaScript `String`, so it cannot be wiped: see the crate
 * docs on `qnero-prover-wasm` and `README.md`. It is dropped on `lock`.
 */

import type {
  BuildAnswer,
  DecryptedNote,
  InitAnswer,
  PathAnswer,
  ProverAccount,
  ProverLimits,
  SubmissionAnswer,
  WorkerRequest,
} from './protocol';

interface WasmSubmission {
  readonly proof: Uint8Array;
  readonly ct1: Uint8Array;
  readonly ct2: Uint8Array;
  readonly reportJson: string;
}

interface WasmProver {
  readonly numLeaves: number;
  readonly buildReportJson: string;
  proveTransfer(requestJson: string): WasmSubmission;
  verifyProof(proof: Uint8Array): number;
}

interface WasmModule {
  default: (input?: unknown) => Promise<{ memory: WebAssembly.Memory }>;
  initThreadPool?: (threads: number) => Promise<void>;
  entropySelfCheck: () => void;
  walletLimits: () => string;
  deriveAccount: (seedHex: string) => string;
  minerKey: (seedHex: string) => string;
  decryptNote: (seedHex: string, ciphertext: Uint8Array, expected: string) => string;
  noteDigests: (seedHex: string, value: bigint, rho: string, r: string) => string;
  coinbaseNote: (seedHex: string, genesis: string, block: number, value: bigint) => string;
  entryRho: (block: number, entryIndex: bigint) => string;
  headerBlockHash: (anchorJson: string) => string;
  treePath: (leafHashes: Uint8Array, depth: number, leafIndex: number) => string;
  treeRoot: (leafHashes: Uint8Array, depth: number) => string;
  depthFor: (leafCount: number) => number;
  addressIsValid: (address: string) => boolean;
  memoFits: (memo: string) => number;
  ctDigest: (ct1: Uint8Array, ct2: Uint8Array) => string;
  chainNumLeaves: () => number;
  peakLinearMemoryBytes: () => number;
  WasmWalletProver: { fromSource: (numLeaves: number) => WasmProver };
}

let wasm: WasmModule | null = null;
let limits: ProverLimits | null = null;
let threadCount = 1;
let seedHex: string | null = null;
let prover: WasmProver | null = null;

function progress(stage: string, detail?: string): void {
  postMessage({ id: -1, progress: { stage, detail } });
}

function requireWasm(): WasmModule {
  if (wasm === null) {
    throw new Error('the prover module has not been loaded');
  }
  return wasm;
}

function requireSeed(): string {
  if (seedHex === null) {
    throw new Error('this wallet is locked, so the worker holds no seed');
  }
  return seedHex;
}

/** Try the threaded module, then the single-threaded one. */
async function loadModule(
  base: string,
  maxThreads: number,
): Promise<{ module: WasmModule; threads: number }> {
  // A cap of one means the single-threaded module rather than a rayon pool of
  // one, which is the serial module with a worker's worth of overhead.
  const threadsPossible =
    maxThreads > 1 &&
    typeof SharedArrayBuffer !== 'undefined' &&
    (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated === true;
  if (threadsPossible) {
    try {
      const url = new URL(`${base}threaded/qnero_prover_wasm.js`, self.location.href).href;
      const module = (await import(/* @vite-ignore */ url)) as unknown as WasmModule;
      await module.default();
      if (typeof module.initThreadPool === 'function') {
        const threads = Math.max(
          1,
          Math.min(maxThreads, navigator.hardwareConcurrency || 1),
        );
        await module.initThreadPool(threads);
        return { module, threads };
      }
      // A module with no pool starter is the single-threaded one served under
      // the threaded path. Fall through rather than claiming threads.
    } catch {
      // No threaded module published, or it refused to start its pool. The
      // single-threaded one is the answer, and it is not an error.
    }
  }
  const url = new URL(`${base}qnero_prover_wasm.js`, self.location.href).href;
  const module = (await import(/* @vite-ignore */ url)) as unknown as WasmModule;
  await module.default();
  return { module, threads: 1 };
}

/** What the module cost to ship, from this worker's own resource timing. */
function moduleBytes(): number {
  const entry = performance
    .getEntriesByType('resource')
    .find((resource) => resource.name.endsWith('.wasm'));
  if (entry === undefined) {
    return 0;
  }
  const timing = entry as PerformanceResourceTiming;
  return timing.encodedBodySize || timing.transferSize || 0;
}

async function handle(request: WorkerRequest): Promise<{ value: unknown; transfer?: Transferable[] }> {
  switch (request.kind) {
    case 'init': {
      const started = performance.now();
      progress('module', 'fetching and instantiating the prover');
      const loaded = await loadModule(request.wasmBase, request.maxThreads);
      wasm = loaded.module;
      threadCount = loaded.threads;
      const initMillis = performance.now() - started;

      // Both entropy paths, once, before anything is offered. Without it a
      // page served from a non-secure context fails tens of seconds into the
      // first private batch, inside plonky2, with an error nobody can
      // attribute.
      const entropyStarted = performance.now();
      progress('entropy', 'drawing from both entropy paths');
      loaded.module.entropySelfCheck();
      const entropyMillis = performance.now() - entropyStarted;

      limits = JSON.parse(loaded.module.walletLimits()) as ProverLimits;
      // A wrong leaf count is only detected after the whole proving cost has
      // been paid, and its only failure message is "the proof did not verify",
      // which reads identically to a feature-graph divergence. So it is
      // checked here and refused.
      if (limits.chain_num_leaves !== request.numLeaves) {
        throw new Error(
          `this prover builds ${limits.chain_num_leaves} leaf slots per batch and this app is ` +
            `configured for ${request.numLeaves}. A proof at the wrong count is refused by the ` +
            'runtime only after the full proving cost, and the message it comes back with says ' +
            'nothing about the count.',
        );
      }
      const answer: InitAnswer = {
        limits,
        threads: threadCount,
        moduleBytes: moduleBytes(),
        initMillis,
        entropyMillis,
      };
      return { value: answer };
    }

    case 'limits': {
      if (limits === null) {
        throw new Error('the prover module has not been loaded');
      }
      return { value: limits };
    }

    case 'deriveAccount': {
      return { value: JSON.parse(requireWasm().deriveAccount(request.seedHex)) as ProverAccount };
    }

    case 'minerKey': {
      return { value: requireWasm().minerKey(request.seedHex) };
    }

    case 'unlock': {
      const bytes = request.seed;
      let hex = '';
      for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
      }
      // The transferred buffer is this worker's now, and it is erased. What
      // cannot be erased is `hex`: a JavaScript string is immutable and
      // garbage collected, which is the boundary the crate docs name.
      bytes.fill(0);
      seedHex = hex;
      return { value: JSON.parse(requireWasm().deriveAccount(hex)) as ProverAccount };
    }

    case 'lock': {
      seedHex = null;
      return { value: null };
    }

    case 'addressIsValid': {
      return { value: requireWasm().addressIsValid(request.address) };
    }

    case 'memoFits': {
      try {
        return { value: { fits: true, bytes: requireWasm().memoFits(request.memo) } };
      } catch (error) {
        return { value: { fits: false, reason: (error as Error).message } };
      }
    }

    case 'decryptBatch': {
      const module = requireWasm();
      const seed = requireSeed();
      const out: (DecryptedNote | null)[] = [];
      for (const item of request.items) {
        try {
          const decrypted = JSON.parse(
            module.decryptNote(seed, item.ciphertext, item.commitment),
          ) as { value: number; rho: string; r: string; commitment: string; memo: string };
          const digests = JSON.parse(
            module.noteDigests(seed, BigInt(decrypted.value), decrypted.rho, decrypted.r),
          ) as { commitment: string; nullifier: string };
          out.push({
            value: String(decrypted.value),
            rho: decrypted.rho,
            r: decrypted.r,
            commitment: digests.commitment,
            nullifier: digests.nullifier,
            memo: decrypted.memo,
          });
        } catch {
          // Not this wallet's ciphertext, which is the ordinary answer for
          // almost every leaf on the chain. The refusal says nothing about
          // what was inside it and neither does this.
          out.push(null);
        }
      }
      return { value: out };
    }

    case 'coinbaseNote': {
      const module = requireWasm();
      const seed = requireSeed();
      const note = JSON.parse(
        module.coinbaseNote(seed, request.genesisHash, request.blockNumber, BigInt(request.value)),
      ) as { rho: string; r: string; commitment: string; nullifier: string };
      return {
        value: {
          value: request.value,
          rho: note.rho,
          r: note.r,
          commitment: note.commitment,
          nullifier: note.nullifier,
          memo: '',
        } satisfies DecryptedNote,
      };
    }

    case 'entryRho': {
      return { value: requireWasm().entryRho(request.blockNumber, BigInt(request.entryIndex)) };
    }

    case 'noteDigests': {
      return {
        value: JSON.parse(
          requireWasm().noteDigests(requireSeed(), BigInt(request.value), request.rho, request.r),
        ) as { inner: string; commitment: string; nullifier: string },
      };
    }

    case 'headerBlockHash': {
      return { value: requireWasm().headerBlockHash(JSON.stringify(request.anchor)) };
    }

    case 'treePath': {
      return {
        value: JSON.parse(
          requireWasm().treePath(request.leafHashes, request.depth, request.leafIndex),
        ) as PathAnswer,
      };
    }

    case 'treeRoot': {
      return { value: requireWasm().treeRoot(request.leafHashes, request.depth) };
    }

    case 'depthFor': {
      return { value: requireWasm().depthFor(request.leafCount) };
    }

    case 'buildProver': {
      const module = requireWasm();
      progress('build', 'building the leaf and private-batch circuits');
      const started = performance.now();
      // From the compiled code, reading nothing. That removes the fetch, the
      // cache invalidation and the pinning surface entirely, and it costs one
      // padding-leaf prove more than the artifact route, which is noise
      // against the build.
      prover = module.WasmWalletProver.fromSource(module.chainNumLeaves());
      const millis = performance.now() - started;
      const report = JSON.parse(prover.buildReportJson) as {
        leaf_degree_bits: number;
        private_batch_degree_bits: number;
      };
      const answer: BuildAnswer = {
        threads: threadCount,
        millis,
        peakLinearMemoryBytes: module.peakLinearMemoryBytes(),
        degreeBits: {
          leaf: report.leaf_degree_bits,
          privateBatch: report.private_batch_degree_bits,
        },
      };
      return { value: answer };
    }

    case 'proveTransfer': {
      if (prover === null) {
        throw new Error('the circuits have not been built');
      }
      const seed = requireSeed();
      progress('prove', 'proving the leaf and the private batch');
      const payload = {
        seed,
        anchor: request.request.anchor,
        tree_depth: request.request.tree_depth,
        fee: Number(request.request.fee),
        inputs: request.request.inputs.map((input) => ({
          value: Number(input.value),
          rho: input.rho,
          r: input.r,
          path: input.path,
        })),
        outputs: request.request.outputs.map((output) => ({
          address: output.address,
          value: Number(output.value),
          memo: output.memo ?? '',
        })),
      };
      const submission = prover.proveTransfer(JSON.stringify(payload));
      const proof = submission.proof;
      const ct1 = submission.ct1;
      const ct2 = submission.ct2;

      // Verify locally before the page is told the proof exists. Fourteen
      // milliseconds turns a wallet-side mistake into a local error; the pool
      // refuses a bad settlement without saying which public input was wrong.
      progress('verify', 'verifying the proof against this build');
      const verifyMillis = prover.verifyProof(proof);
      const report = JSON.parse(submission.reportJson) as SubmissionAnswer['report'];
      report.phases.push({ phase: 'local_verify', millis: verifyMillis });
      const answer: SubmissionAnswer = { proof, ct1, ct2, report };
      return {
        value: answer,
        transfer: [proof.buffer, ct1.buffer, ct2.buffer],
      };
    }
  }
}

self.onmessage = (event: MessageEvent<{ id: number; request: WorkerRequest }>): void => {
  const { id, request } = event.data;
  handle(request).then(
    (answer) => {
      if (answer.transfer !== undefined) {
        postMessage({ id, ok: true, value: answer.value }, answer.transfer);
      } else {
        postMessage({ id, ok: true, value: answer.value });
      }
    },
    (error: unknown) => {
      // Nothing from the module's own error funnel is reconstructed here: a
      // plonky2 witness error names a note's amount or its position in the
      // tree, and a console line outlives the call.
      postMessage({ id, ok: false, error: (error as Error).message });
    },
  );
};

export type { WasmModule };
