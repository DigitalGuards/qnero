/**
 * The page's handle on the worker.
 *
 * One worker, one prover, for the life of the session. Both circuits are
 * resident in its linear memory, which is 910 MiB at the M8 measurement and
 * never shrinks: wasm linear memory grows and stays grown, so a second prover
 * in the same worker adds its own gigabyte on top and the only way back to
 * eight megabytes is to terminate the worker, which also discards the 12-second
 * circuit build.
 *
 * [`ProverClient.terminate`] exists for exactly that trade and the settings
 * screen offers it by name. It is not automatic: a wallet that dropped its
 * circuits after every payment would charge twelve seconds for the next one.
 */

import type {
  BuildAnswer,
  DecryptItem,
  DecryptedNote,
  InitAnswer,
  PathAnswer,
  ProverAccount,
  ProverLimits,
  SubmissionAnswer,
  TransferRequest,
  WorkerRequest,
} from './protocol';
import type { Anchor } from '../chain/anchor';

type Progress = (stage: string, detail?: string) => void;

interface Waiting {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

export class ProverClient {
  private worker: Worker | null = null;
  private nextId = 1;
  private waiting = new Map<number, Waiting>();
  private listeners = new Set<Progress>();

  /** Whether a worker is running and therefore whether memory is held. */
  get isRunning(): boolean {
    return this.worker !== null;
  }

  onProgress(listener: Progress): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private ensureWorker(): Worker {
    if (this.worker !== null) {
      return this.worker;
    }
    const worker = new Worker(new URL('./prover.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<Record<string, unknown>>): void => {
      const data = event.data;
      if (data['id'] === -1) {
        const progress = data['progress'] as { stage: string; detail?: string };
        for (const listener of this.listeners) {
          listener(progress.stage, progress.detail);
        }
        return;
      }
      const id = data['id'] as number;
      const pending = this.waiting.get(id);
      if (pending === undefined) {
        return;
      }
      this.waiting.delete(id);
      if (data['ok'] === true) {
        pending.resolve(data['value']);
      } else {
        pending.reject(new Error(String(data['error'])));
      }
    };
    worker.onerror = (event: ErrorEvent): void => {
      const error = new Error(event.message || 'the prover worker failed');
      for (const pending of this.waiting.values()) {
        pending.reject(error);
      }
      this.waiting.clear();
    };
    this.worker = worker;
    return worker;
  }

  private call<T>(request: WorkerRequest, transfer?: Transferable[]): Promise<T> {
    const worker = this.ensureWorker();
    const id = this.nextId;
    this.nextId += 1;
    return new Promise<T>((resolve, reject) => {
      this.waiting.set(id, { resolve: resolve as (value: unknown) => void, reject });
      if (transfer !== undefined) {
        worker.postMessage({ id, request }, transfer);
      } else {
        worker.postMessage({ id, request });
      }
    });
  }

  init(wasmBase: string, numLeaves: number, maxThreads: number): Promise<InitAnswer> {
    return this.call<InitAnswer>({ kind: 'init', wasmBase, numLeaves, maxThreads });
  }

  limits(): Promise<ProverLimits> {
    return this.call<ProverLimits>({ kind: 'limits' });
  }

  deriveAccount(seedHex: string): Promise<ProverAccount> {
    return this.call<ProverAccount>({ kind: 'deriveAccount', seedHex });
  }

  minerKey(seedHex: string): Promise<string> {
    return this.call<string>({ kind: 'minerKey', seedHex });
  }

  /**
   * Hand the seed over and keep nothing.
   *
   * The buffer is transferred, so the page's `Uint8Array` is detached the
   * moment this returns and there is no copy left on this side to erase. The
   * caller still zeroes whatever it decoded the seed out of.
   */
  unlock(seed: Uint8Array<ArrayBuffer>): Promise<ProverAccount> {
    return this.call<ProverAccount>({ kind: 'unlock', seed }, [seed.buffer]);
  }

  lock(): Promise<null> {
    return this.call<null>({ kind: 'lock' });
  }

  addressIsValid(address: string): Promise<boolean> {
    return this.call<boolean>({ kind: 'addressIsValid', address });
  }

  memoFits(memo: string): Promise<{ fits: boolean; bytes?: number; reason?: string }> {
    return this.call({ kind: 'memoFits', memo });
  }

  decryptBatch(items: DecryptItem[]): Promise<(DecryptedNote | null)[]> {
    return this.call({ kind: 'decryptBatch', items });
  }

  coinbaseNote(blockNumber: number, value: bigint, genesisHash: string): Promise<DecryptedNote> {
    return this.call({
      kind: 'coinbaseNote',
      blockNumber,
      value: value.toString(),
      genesisHash,
    });
  }

  entryRho(blockNumber: number, entryIndex: bigint): Promise<string> {
    return this.call({ kind: 'entryRho', blockNumber, entryIndex: entryIndex.toString() });
  }

  noteDigests(
    value: bigint,
    rho: string,
    r: string,
  ): Promise<{ inner: string; commitment: string; nullifier: string }> {
    return this.call({ kind: 'noteDigests', value: value.toString(), rho, r });
  }

  headerBlockHash(anchor: Anchor): Promise<string> {
    return this.call({ kind: 'headerBlockHash', anchor });
  }

  /** The leaf range is transferred: it is 32 bytes a leaf and copying is waste. */
  treePath(leafHashes: Uint8Array<ArrayBuffer>, depth: number, leafIndex: number): Promise<PathAnswer> {
    return this.call({ kind: 'treePath', leafHashes, depth, leafIndex }, [leafHashes.buffer]);
  }

  treeRoot(leafHashes: Uint8Array<ArrayBuffer>, depth: number): Promise<string> {
    return this.call({ kind: 'treeRoot', leafHashes, depth }, [leafHashes.buffer]);
  }

  depthFor(leafCount: number): Promise<number> {
    return this.call({ kind: 'depthFor', leafCount });
  }

  buildProver(): Promise<BuildAnswer> {
    return this.call<BuildAnswer>({ kind: 'buildProver' });
  }

  proveTransfer(request: TransferRequest): Promise<SubmissionAnswer> {
    return this.call<SubmissionAnswer>({ kind: 'proveTransfer', request });
  }

  /**
   * Stop the worker and give the memory back.
   *
   * The only way linear memory shrinks. Everything goes with it: the circuits,
   * the seed, and any call in flight, which is why the callers in flight are
   * rejected by name rather than left hanging.
   */
  terminate(): void {
    if (this.worker === null) {
      return;
    }
    this.worker.terminate();
    this.worker = null;
    for (const pending of this.waiting.values()) {
      pending.reject(new Error('the prover was stopped'));
    }
    this.waiting.clear();
  }
}
