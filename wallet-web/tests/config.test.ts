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

describe('the send expectation', () => {
  it('takes one figure per module', () => {
    const config = parseConfig({
      ...MINIMAL,
      expectedSendSeconds: { threaded: 11, single: 38 },
    });
    expect(config.expectedSendSeconds).toEqual({ threaded: 11, single: 38 });
  });

  it('reads one number as both, so an older config still loads', () => {
    const config = parseConfig({ ...MINIMAL, expectedSendSeconds: 34 });
    expect(config.expectedSendSeconds).toEqual({ threaded: 34, single: 34 });
  });

  it('has a measured default when the file says nothing', () => {
    const config = parseConfig(MINIMAL);
    expect(config.expectedSendSeconds.threaded).toBeGreaterThan(0);
    expect(config.expectedSendSeconds.single).toBeGreaterThan(
      config.expectedSendSeconds.threaded,
    );
  });

  it('ships a default that is the whole send rather than the proof alone', () => {
    // `docs/BENCH.md`: `proveTransfer` is 11.6 to 13.3 s threaded and 36.0 s
    // single, and "Send to settled" for the same runs is 21.6 to 25.6 s and
    // 55.4 s. A default inside the first band would be the figure that made
    // every payment overdue.
    const config = parseConfig(MINIMAL);
    expect(config.expectedSendSeconds.threaded).toBeGreaterThan(15);
    expect(config.expectedSendSeconds.single).toBeGreaterThan(45);
  });

  it('is the same figure the shipped config.json carries', () => {
    const shipped = JSON.parse(
      readFileSync(join(import.meta.dirname, '..', 'public', 'config.json'), 'utf8'),
    ) as Record<string, unknown>;
    expect(parseConfig(shipped).expectedSendSeconds).toEqual(
      parseConfig(MINIMAL).expectedSendSeconds,
    );
  });

  it('refuses a figure that is not a positive number, by name', () => {
    expect(() => parseConfig({ ...MINIMAL, expectedSendSeconds: 0 })).toThrow(
      /expectedSendSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedSendSeconds: 'soon' })).toThrow(
      /expectedSendSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedSendSeconds: { threaded: -1 } })).toThrow(
      /threaded/,
    );
  });
});

describe('the endpoint', () => {
  it('has to be a WebSocket URL, because a head needs a subscription', () => {
    expect(() => parseConfig({ ...MINIMAL, rpcEndpoint: 'http://127.0.0.1:9944' })).toThrow(
      /ws:\/\//,
    );
  });
});
