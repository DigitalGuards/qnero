/**
 * The runtime configuration, which is the only thing about a chain that is not
 * compiled in.
 *
 * The expectation printed beside the sending clock used to be one number for
 * both modules. The threaded module proves in about a third of the
 * single-threaded one's time, so a page on four threads told a reader to
 * expect three times the wait they were about to have, while its own clock
 * underneath said otherwise.
 */

import { describe, expect, it } from 'vitest';

import { parseConfig } from '../src/chain/config';

const MINIMAL = { rpcEndpoint: 'ws://127.0.0.1:9944', chainName: 'Qnero devnet' };

describe('the proving expectation', () => {
  it('takes one figure per module', () => {
    const config = parseConfig({
      ...MINIMAL,
      expectedProveSeconds: { threaded: 11, single: 38 },
    });
    expect(config.expectedProveSeconds).toEqual({ threaded: 11, single: 38 });
  });

  it('reads one number as both, so an older config still loads', () => {
    const config = parseConfig({ ...MINIMAL, expectedProveSeconds: 34 });
    expect(config.expectedProveSeconds).toEqual({ threaded: 34, single: 34 });
  });

  it('has a measured default when the file says nothing', () => {
    const config = parseConfig(MINIMAL);
    expect(config.expectedProveSeconds.threaded).toBeGreaterThan(0);
    expect(config.expectedProveSeconds.single).toBeGreaterThan(
      config.expectedProveSeconds.threaded,
    );
  });

  it('refuses a figure that is not a positive number, by name', () => {
    expect(() => parseConfig({ ...MINIMAL, expectedProveSeconds: 0 })).toThrow(
      /expectedProveSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedProveSeconds: 'soon' })).toThrow(
      /expectedProveSeconds/,
    );
    expect(() => parseConfig({ ...MINIMAL, expectedProveSeconds: { threaded: -1 } })).toThrow(
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
