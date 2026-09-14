import { describe, expect, it } from 'vitest';

import { parseHeader } from '../src/lib/header';
import fixture from './fixtures/header-settlement.json' with { type: 'json' };

describe('header', () => {
  it('reads zkTreeRoot from between extrinsicsRoot and digest', () => {
    const header = parseHeader(fixture.header);
    expect(header.number).toBe(10);
    expect(header.parentHash).toBe(fixture.header.parentHash);
    expect(header.stateRoot).toBe(fixture.header.stateRoot);
    expect(header.extrinsicsRoot).toBe(fixture.header.extrinsicsRoot);
    expect(header.zkTreeRoot).toBe(
      '0xb8117c3dee8aec584e51fd2ed07c36672819c0e688968e427ca82fafa0b93982',
    );
    expect(header.digestItems).toHaveLength(2);
    expect(header.authorLabel).toBe(
      '0xbdbfb351e4eef53d892633dec8f77996ce1856eea1077ede2ed3950b55c0be48',
    );
  });

  it('reads the number as the hex string the RPC sends', () => {
    expect(parseHeader({ ...fixture.header, number: '0x0' }).number).toBe(0);
    expect(parseHeader({ ...fixture.header, number: '0x1e8480' }).number).toBe(2000000);
  });

  it('refuses a header with no zkTreeRoot instead of decoding around it', () => {
    const rest: Record<string, unknown> = { ...fixture.header };
    delete rest['zkTreeRoot'];
    expect(() => parseHeader(rest)).toThrow(/zkTreeRoot/);
  });
});
