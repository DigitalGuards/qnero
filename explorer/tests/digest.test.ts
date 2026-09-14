import { describe, expect, it } from 'vitest';

import { authorLabel, decodeDigestItem, decodeDigestLogs, POW_ENGINE_ID, sealPayload } from '../src/lib/digest';
import header from './fixtures/header-settlement.json' with { type: 'json' };

const logs = header.header.digest.logs;

describe('header digest', () => {
  it('takes a pre-runtime item apart', () => {
    const item = decodeDigestItem(logs[0] as string);
    expect(item.kind).toBe('preRuntime');
    expect(item.engine).toBe(POW_ENGINE_ID);
    expect(item.payload).toBe(
      '0xbdbfb351e4eef53d892633dec8f77996ce1856eea1077ede2ed3950b55c0be48',
    );
  });

  it('takes a seal apart, 64 bytes with the nonce at the front', () => {
    const item = decodeDigestItem(logs[1] as string);
    expect(item.kind).toBe('seal');
    expect(item.engine).toBe(POW_ENGINE_ID);
    expect(item.payload).toHaveLength(2 + 64 * 2);
    expect(item.payload?.slice(0, 18)).toBe('0xcc1674f4865d46a6');
  });

  it('reads the author label out of the pow_ pre-runtime item', () => {
    const items = decodeDigestLogs(logs);
    expect(authorLabel(items)).toBe(
      '0xbdbfb351e4eef53d892633dec8f77996ce1856eea1077ede2ed3950b55c0be48',
    );
    expect(sealPayload(items)).not.toBeNull();
  });

  it('refuses a pre-runtime item under another engine', () => {
    const items = decodeDigestLogs([
      `0x06616c6961${(logs[0] as string).slice(12)}`,
    ]);
    expect(items[0]?.engine).not.toBe(POW_ENGINE_ID);
    expect(authorLabel(items)).toBeNull();
  });

  it('reads a runtime-environment-updated item, which carries nothing', () => {
    expect(decodeDigestItem('0x08')).toEqual({
      kind: 'runtimeEnvironmentUpdated',
      engine: null,
      payload: null,
    });
  });

  it('refuses a truncated item rather than inventing a payload', () => {
    expect(() => decodeDigestItem('0x06706f775f80bdbf')).toThrow(/claims 32 bytes/);
  });
});
