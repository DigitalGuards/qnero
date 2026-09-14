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
