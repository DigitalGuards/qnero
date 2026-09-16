/**
 * The runtime configuration, which is the only thing about a chain that is not
 * compiled in.
 *
 * The expectation printed beside the sending clock used to be one number for
 * both modules. The threaded module proves in about a third of the
 * single-threaded one's time, so a page on four threads told a reader to
 * expect three times the wait they were about to have, while its own clock
 * underneath said otherwise.
 *
 * It was then a proving-only figure printed beside a clock that starts at the
 * send button, so it was exceeded about halfway through every correct payment.
 * The two have to measure the same interval, and the interval is the one the
 * reader is in: the button to a settled block.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { parseConfig } from '../src/chain/config';

const MINIMAL = { rpcEndpoint: 'ws://127.0.0.1:9944', chainName: 'Qnero devnet' };

describe('the proving expectation', () => {
  it('takes one figure per module', () => {
    const config = parseConfig({
      ...MINIMAL,
      expectedProvingSeconds: { threaded: 11, single: 38 },
    });
    expect(config.expectedProvingSeconds).toEqual({ threaded: 11, single: 38 });
  });

  it('reads one number as both, so an older config still loads', () => {
    const config = parseConfig({ ...MINIMAL, expectedProvingSeconds: 34 });
    expect(config.expectedProvingSeconds).toEqual({ threaded: 34, single: 34 });
  });

  it('has a measured default when the file says nothing', () => {
    const config = parseConfig(MINIMAL);
    expect(config.expectedProvingSeconds.threaded).toBeGreaterThan(0);
    expect(config.expectedProvingSeconds.single).toBeGreaterThan(
      config.expectedProvingSeconds.threaded,
    );
  });

  it('ships the proof alone, because the block half comes from the chain', () => {
    // `docs/BENCH.md`: `proveTransfer` is 11.6 to 13.3 s threaded and 36.0 s
    // single. "Send to settled" for the same runs is 21.6 to 25.6 s and 55.4 s
    // and this key is deliberately not that figure: the gap between them is
    // one block interval, which is chain state and differs by a factor of ten
    // between the public chain and a dev chain. The sending screen composes
    // the two.
    const config = parseConfig(MINIMAL);
    expect(config.expectedProvingSeconds.threaded).toBeGreaterThanOrEqual(11);
    expect(config.expectedProvingSeconds.threaded).toBeLessThanOrEqual(14);
    expect(config.expectedProvingSeconds.single).toBeGreaterThanOrEqual(30);
    expect(config.expectedProvingSeconds.single).toBeLessThanOrEqual(40);
  });

  it('is the same figure the shipped config.json carries', () => {
    const shipped = JSON.parse(
      readFileSync(join(import.meta.dirname, '..', 'public', 'config.json'), 'utf8'),
    ) as Record<string, unknown>;
    expect(parseConfig(shipped).expectedProvingSeconds).toEqual(
      parseConfig(MINIMAL).expectedProvingSeconds,
    );
  });

  it('refuses a figure that is not a positive number, by name', () => {
    expect(() => parseConfig({ ...MINIMAL, expectedProvingSeconds: 0 })).toThrow(
      /expectedProvingSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedProvingSeconds: 'soon' })).toThrow(
      /expectedProvingSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedProvingSeconds: { threaded: -1 } })).toThrow(
      /threaded/,
    );
  });
});

describe('the chain the shipped file names', () => {
  const shipped = parseConfig(
    JSON.parse(
      readFileSync(join(import.meta.dirname, '..', 'public', 'config.json'), 'utf8'),
    ) as Record<string, unknown>,
  );

  it('is the public testnet, because the header prints it to whoever opens the page', () => {
    // The testnet has been live since 2026-09-15 and this file is what a built
    // directory carries: a build shipped naming a devnet on 127.0.0.1 is a
    // header that is false for every reader and a wallet that connects to
    // nothing. A node of your own is the settings field, which is what
    // persists.
    expect(shipped.rpcEndpoint).toBe('wss://rpc.qnero.io');
    expect(shipped.chainName).toBe('Qnero testnet');
  });
});

describe('the endpoint', () => {
  it('has to be a WebSocket URL, because a head needs a subscription', () => {
    expect(() => parseConfig({ ...MINIMAL, rpcEndpoint: 'http://127.0.0.1:9944' })).toThrow(
      /ws:\/\//,
    );
  });
});
