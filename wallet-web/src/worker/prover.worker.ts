/// <reference lib="webworker" />
/**
 * The worker: a shell around [`ProverCore`], and the module loader.
 *
 * Everything the worker decides lives in `core.ts`, which has no reference to
 * `self` and can be run against a stub module. What is here is the part that
 * is only true inside a worker: where the module comes from, and the message
 * plumbing.
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
 */

import { ProverCore, type WasmModule } from './core';
import type { WorkerRequest } from './protocol';

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
        const threads = Math.max(1, Math.min(maxThreads, navigator.hardwareConcurrency || 1));
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

const core = new ProverCore(loadModule);

function progress(stage: string, detail?: string): void {
  postMessage({ id: -1, progress: { stage, detail } });
}

self.onmessage = (event: MessageEvent<{ id: number; request: WorkerRequest }>): void => {
  const { id, request } = event.data;
  core.handle(request, progress).then(
    (answer) => {
      if (answer.transfer !== undefined) {
        postMessage({ id, ok: true, value: answer.value }, answer.transfer);
      } else {
        postMessage({ id, ok: true, value: answer.value });
      }
    },
    (error: unknown) => {
      // The module's own error text is forwarded as it is, and the page renders
      // it: a plonky2 witness failure can name a note's amount or its position
      // in the tree, so what the send and sync notices carry is shown to the
      // wallet's owner and belongs in neither a screenshot nor a pasted bug
      // report. `App.tsx` marks both notices for that reason.
      postMessage({ id, ok: false, error: (error as Error).message });
    },
  );
};

export type { WasmModule };
