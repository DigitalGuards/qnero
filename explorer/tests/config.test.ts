import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { parseConfig } from '../src/chain/config';

const minimal = { rpcEndpoint: 'ws://127.0.0.1:9944', chainName: 'Qnero devnet' };

describe('runtime config', () => {
  it('takes an endpoint and a chain name and fills the rest in', () => {
    const config = parseConfig(minimal);
    expect(config.rpcEndpoint).toBe('ws://127.0.0.1:9944');
    expect(config.chainName).toBe('Qnero devnet');
    expect(config.recentBlocks).toBe(12);
    expect(config.searchWindowBlocks).toBe(512);
    expect(config.nullifierPageLimit).toBe(25);
  });

  it('insists on a WebSocket endpoint, because subscriptions are WS only', () => {
    expect(() => parseConfig({ ...minimal, rpcEndpoint: 'http://127.0.0.1:9944' })).toThrow(/ws:/);
    expect(() => parseConfig({ ...minimal, rpcEndpoint: '' })).toThrow(/rpcEndpoint/);
    expect(parseConfig({ ...minimal, rpcEndpoint: 'wss://example.invalid' }).rpcEndpoint).toBe(
      'wss://example.invalid',
    );
  });

  it('refuses a file that is not an object, or a name that is empty', () => {
    expect(() => parseConfig([])).toThrow(/JSON object/);
    expect(() => parseConfig(null)).toThrow(/JSON object/);
    expect(() => parseConfig({ ...minimal, chainName: '' })).toThrow(/chainName/);
  });

  it('refuses a budget that is not a positive number', () => {
    expect(() => parseConfig({ ...minimal, recentBlocks: 0 })).toThrow(/recentBlocks/);
    expect(() => parseConfig({ ...minimal, searchWindowBlocks: -1 })).toThrow(/searchWindowBlocks/);
    expect(parseConfig({ ...minimal, nullifierPageLimit: 4 }).nullifierPageLimit).toBe(4);
  });
});

describe('the chain the shipped file names', () => {
  const shipped = parseConfig(
    JSON.parse(
      readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'),
    ) as Record<string, unknown>,
  );

  // The public testnet has been live since 2026-09-15 and public/config.json
  // is what a built directory carries. A build shipped naming a devnet on
  // loopback puts "Qnero devnet" in the header of every page and connects to
  // nothing. The Playwright suite rewrites the copy in dist/ after the build.
  it('is the public testnet, because the header prints it to whoever opens the page', () => {
    expect(shipped.rpcEndpoint).toBe('wss://rpc.qnero.io');
    expect(shipped.chainName).toBe('Qnero testnet');
  });

  it('is a wss endpoint, because a page served over https cannot open a ws socket', () => {
    expect(shipped.rpcEndpoint.startsWith('wss://')).toBe(true);
  });
});
