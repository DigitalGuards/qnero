/**
 * The browser wallet's header walk, before and after, over one socket.
 *
 * A measurement rather than an assertion, so it skips itself, loudly, unless
 * `QNERO_BENCH_WS` names an endpoint:
 *
 * ```text
 * QNERO_BENCH_WS=wss://rpc.qnero.io nice -n 19 npx vitest run tests/header-walk-bench.test.ts
 * ```
 *
 * It runs the walk this wallet had, one `chain_getHeader` at a time descending
 * by `parentHash`, and the walk it has, which pages the hashes and keeps 32
 * requests outstanding on the one socket. Both go through the real
 * `ChainContext.send`, the seam every read in this wallet goes through and the
 * one `privacy.test.ts` records, so what is measured is the wallet's own path
 * and not a model of it. `WsProvider` multiplexes JSON-RPC ids the same way in
 * Node as in a page, which is what makes this measurable here at all.
 *
 * `docs/BENCH.md` carries the runs.
 */

import { describe, expect, it } from 'vitest';

import { parseRawHeader } from '../src/chain/anchor';
import type { ChainContext } from '../src/chain/api';
import { fetchHeaderRange, HEADER_SPAN_LIMIT } from '../src/chain/reads';

const ENDPOINT = process.env['QNERO_BENCH_WS'];

/** The walk as it was: one header at a time, downward by `parentHash`. */
async function sequentialWalk(
  context: ChainContext,
  anchor: number,
  top: { number: number; hash: string },
): Promise<number> {
  let hash = top.hash;
  let walked = 0;
  for (let number = top.number; ; number -= 1) {
    const header = parseRawHeader(await context.send<unknown>('chain_getHeader', [hash]));
    if (Number(BigInt(header.number)) !== number) {
      throw new Error(`a header numbered ${header.number} came back for block ${number}`);
    }
    walked += 1;
    if (number === anchor) {
      return walked;
    }
    hash = header.parentHash;
  }
}

describe.skipIf(ENDPOINT === undefined)('the header walk over a live socket', () => {
  it(
    'walks the same range both ways and says what each cost',
    async () => {
      const { WsProvider } = await import('@polkadot/api');
      const provider = new WsProvider(ENDPOINT, 2500);
      await provider.isReady;
      let calls = 0;
      const context = {
        send: async <T,>(method: string, params: unknown[]): Promise<T> => {
          calls += 1;
          return provider.send<T>(method, params);
        },
      } as unknown as ChainContext;

      try {
        const hash = await context.send<string>('chain_getBlockHash', []);
        const raw = await context.send<{ number: string }>('chain_getHeader', [hash]);
        const head = { number: Number(BigInt(raw.number)), hash };
        const anchor = Math.max(head.number - HEADER_SPAN_LIMIT, 0);
        const blocks = head.number - anchor + 1;
        console.log(`node ${ENDPOINT ?? ''} at block ${head.number}, walking ${blocks} headers`);

        calls = 0;
        let started = Date.now();
        let seen = 0;
        await fetchHeaderRange(context, anchor, head, () => {
          seen += 1;
        });
        const after = (Date.now() - started) / 1000;
        console.log(
          `pipelined  ${seen} headers in ${after.toFixed(2)} s, ` +
            `${Math.round(seen / Math.max(after, 1e-9))} headers/s, ${calls} requests`,
        );
        expect(seen).toBe(blocks);

        calls = 0;
        started = Date.now();
        const walked = await sequentialWalk(context, anchor, head);
        const before = (Date.now() - started) / 1000;
        console.log(
          `sequential ${walked} headers in ${before.toFixed(2)} s, ` +
            `${Math.round(walked / Math.max(before, 1e-9))} headers/s, ${calls} requests, ` +
            `${(before / Math.max(after, 1e-9)).toFixed(1)}x the pipelined walk`,
        );
        expect(walked).toBe(blocks);
      } finally {
        await provider.disconnect();
      }
    },
    900_000,
  );
});
