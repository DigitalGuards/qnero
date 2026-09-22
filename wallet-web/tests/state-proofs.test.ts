import { describe, expect, it } from 'vitest';
import { canonicalStorage, type ChainContext } from '../src/chain/api';
import { authenticatedPrefix, authenticatedValues, bindStateProofVerifier } from '../src/chain/authenticated';
import { fetchUsedNullifiers } from '../src/chain/reads';
import { fixtureHeader } from './fixtures/state-proof';

const AT = `0x${'aa'.repeat(32)}`;
const PREFIX = `0x${'bc'.repeat(32)}`;

function node(options: { wrongBlock?: boolean; incompletePrefix?: boolean; wrongHeader?: boolean } = {}) {
  const calls: string[] = [];
  const context = {
    send: <T,>(method: string): Promise<T> => {
      calls.push(method);
      if (method === 'chain_getHeader') return Promise.resolve(fixtureHeader() as T);
      if (method === 'state_getReadProof') return Promise.resolve({
        at: options.wrongBlock ? `0x${'bb'.repeat(32)}` : AT, proof: [],
      } as T);
      if (method === 'state_getKeysPaged') return Promise.resolve([] as T);
      throw new Error(`unexpected unproven RPC ${method}`);
    },
  } as unknown as ChainContext;
  bindStateProofVerifier(context, {
    headerBlockHash: () => Promise.resolve(options.wrongHeader ? 'bb'.repeat(32) : AT),
    extrinsicsRoot: () => Promise.resolve(`0x${'22'.repeat(32)}`),
    readStateProof: () => Promise.resolve([null]),
    readStatePrefix: () => options.incompletePrefix ? Promise.reject(new Error('incomplete prefix proof')) : Promise.resolve([]),
  });
  return { context, calls };
}

describe('authenticated read plumbing', () => {
  it('requires the verification worker before any storage read', async () => {
    await expect(authenticatedValues({} as ChainContext, ['0x12'], AT)).rejects.toThrow('verification worker');
  });

  it('accepts proven absence without an unproven storage RPC', async () => {
    const { context, calls } = node();
    expect(await authenticatedValues(context, ['0x12'], AT)).toEqual([null]);
    expect(calls).toEqual(['chain_getHeader', 'state_getReadProof']);
  });

  it('refuses proof and header block mismatches', async () => {
    await expect(authenticatedValues(node({ wrongBlock: true }).context, ['0x12'], AT)).rejects.toThrow('different block');
    await expect(authenticatedValues(node({ wrongHeader: true }).context, ['0x12'], AT)).rejects.toThrow('requested block');
  });

  it('does not accept an empty key listing without a complete prefix proof', async () => {
    await expect(authenticatedPrefix(node({ incompletePrefix: true }).context, PREFIX, AT, 1000)).rejects.toThrow('incomplete prefix');
  });

  it('checks the runtime encoding of proven nullifier entries', async () => {
    const { context } = node();
    const entry = canonicalStorage('shielded', 'usedNullifiers');
    const nullifier = '12'.repeat(32);
    const key = entry.key(`0x${nullifier}`);
    let entries: [string, string][] = [[key, '0x']];
    bindStateProofVerifier(context, {
      headerBlockHash: () => Promise.resolve(AT),
      extrinsicsRoot: () => Promise.resolve(`0x${'22'.repeat(32)}`),
      readStateProof: () => Promise.resolve([]),
      readStatePrefix: () => Promise.resolve(entries),
    });
    expect(await fetchUsedNullifiers(context, AT)).toEqual(new Set([nullifier]));
    entries = [[key, '0x00']];
    await expect(fetchUsedNullifiers(context, AT)).rejects.toThrow('unexpected encoding');
    entries = [[`${entry.keyPrefix()}${'00'.repeat(16)}${nullifier}`, '0x']];
    await expect(fetchUsedNullifiers(context, AT)).rejects.toThrow('unexpected encoding');
  });
});
