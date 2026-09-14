/**
 * The page's handle on the worker, driven against a stub worker.
 *
 * Three failures, all of them on paths a wallet reaches with one click.
 *
 * Stopping the prover in settings and then locking made the wallet impossible
 * to unlock: the locked phase has exactly one screen, and the unlock refused
 * with advice naming a screen it forbids, beside a button that erases the
 * wallet. The client's part of the fix is that a stop is lifted by starting
 * the prover again, which is what `App.unlock` now does before handing over a
 * seed.
 *
 * `unlock` documents the seed buffer as transferred and therefore uncopyable,
 * and on that basis no caller erases it. On the two paths that reject before
 * anything is posted, the transfer never happens, so the caller was left
 * holding a live spend key it believed was detached.
 *
 * And a worker that fails to load used to stay installed: the first failure
 * was reported and every later call posted into a dead worker and hung, with
 * no rejection, no timeout and nothing on screen.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ProverClient } from '../src/worker/client';

interface Posted {
  id: number;
  request: { kind: string };
}

class StubWorker {
  static instances: StubWorker[] = [];
  static answer: ((request: { kind: string }) => unknown) | null = null;

  onmessage: ((event: { data: Record<string, unknown> }) => void) | null = null;
  onerror: ((event: { message: string }) => void) | null = null;
  readonly posted: Posted[] = [];
  terminated = false;

  constructor() {
    StubWorker.instances.push(this);
  }

  postMessage(message: Posted): void {
    this.posted.push(message);
    queueMicrotask(() => {
      this.onmessage?.({
        data: { id: message.id, ok: true, value: StubWorker.answer?.(message.request) ?? null },
      });
    });
  }

  terminate(): void {
    this.terminated = true;
  }
}

const ACCOUNT = { address: 'qn1test' };

beforeEach(() => {
  StubWorker.instances.length = 0;
  StubWorker.answer = (request) => (request.kind === 'unlock' ? ACCOUNT : null);
  (globalThis as unknown as { Worker: unknown }).Worker = StubWorker;
});

afterEach(() => {
  delete (globalThis as unknown as { Worker?: unknown }).Worker;
});

function seedBytes(): Uint8Array<ArrayBuffer> {
  return new Uint8Array(32).fill(0xab);
}

describe('a prover that was stopped', () => {
  it('refuses every request until it is started again', async () => {
    const client = new ProverClient();
    await client.init('wasm/', 6, 4);
    client.terminate();
    expect(client.isRunning).toBe(false);
    await expect(client.unlock(seedBytes())).rejects.toThrow(/stopped/);
    await expect(client.minerKey()).rejects.toThrow(/stopped/);
  });

  it('takes a seed again once it is started, which is how a locked wallet reopens', async () => {
    const client = new ProverClient();
    await client.init('wasm/', 6, 4);
    client.terminate();
    // What `App.unlock` does when it finds the prover stopped: start it, then
    // hand over the seed. Without this the only route back was a page reload,
    // which nothing on the unlock screen suggests.
    await client.init('wasm/', 6, 4);
    expect(client.isRunning).toBe(true);
    await expect(client.unlock(seedBytes())).resolves.toEqual(ACCOUNT);
  });

  it('erases the seed it refused rather than leaving it in the page', async () => {
    const client = new ProverClient();
    await client.init('wasm/', 6, 4);
    client.terminate();
    const seed = seedBytes();
    await expect(client.unlock(seed)).rejects.toThrow(/stopped/);
    // Nothing was posted, so nothing was transferred, so this side still owns
    // the buffer. It is 32 zero bytes rather than a spend key.
    expect(seed.byteLength).toBe(32);
    expect([...seed]).toEqual(new Array<number>(32).fill(0));
  });
});

describe('a worker that fails', () => {
  it('is dropped, so the next call gets an answer rather than silence', async () => {
    const client = new ProverClient();
    await client.init('wasm/', 6, 4);
    const first = StubWorker.instances[0];
    expect(first).toBeDefined();

    const inFlight = client.minerKey();
    // A module script that 404s, or one that throws at the top level.
    first?.onerror?.({ message: 'failed to load the prover module' });
    await expect(inFlight).rejects.toThrow(/failed to load/);
    expect(first?.terminated).toBe(true);

    // The next call spawns a fresh worker and settles.
    await expect(client.limits()).resolves.toBeNull();
    expect(StubWorker.instances).toHaveLength(2);
  });
});
