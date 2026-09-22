import { describe, expect, it } from 'vitest';
import { canonicalStorage, storage } from '../src/chain/api';
import type { ChainContext } from '../src/chain/api';

const LEAF_BLOCKS = '0xcad93014ca4e3d270e8f2677345d6f090b916412057c54bdc7c1ca6d4e71baf3';
const NULLIFIERS = '0xcad93014ca4e3d270e8f2677345d6f0901239bbc95787a4c6519eafa1fe501c9';
const LEAF_COUNT = '0xa40fcc202f608fe42e097dbf79522f643bddea35263a128d602ae2b1451398a9';

describe('canonical Qnero storage keys', () => {
  it('encodes fixed namespaces, Identity u64 indexes, and Blake2_128Concat nullifiers', () => {
    const leafBlocks = canonicalStorage('shielded', 'leafBlocks');
    expect(leafBlocks.keyPrefix()).toBe(LEAF_BLOCKS);
    expect(leafBlocks.key(257)).toBe(`${LEAF_BLOCKS}0101000000000000`);
    expect(leafBlocks.key(0xffffffffffffffffn)).toBe(`${LEAF_BLOCKS}ffffffffffffffff`);
    expect(canonicalStorage('zkTree', 'leafCount').key()).toBe(LEAF_COUNT);
    const nullifiers = canonicalStorage('shielded', 'usedNullifiers');
    expect(nullifiers.keyPrefix()).toBe(NULLIFIERS);
    expect(nullifiers.key(`0x${'00'.repeat(32)}`)).toBe(
      `${NULLIFIERS}ff0f22492f44bac4c4b30ae58d0e8daa${'00'.repeat(32)}`,
    );
  });

  it('preserves the authenticated namespace after ApiPromise metadata refresh', () => {
    const api = {
      query: {
        shielded: {
          leafBlocks: { key: () => '0xobsolete', keyPrefix: () => '0xobsolete' },
          usedNullifiers: { key: () => '0xobsolete', keyPrefix: () => '0xobsolete' },
        },
      },
    };
    const context = { api } as unknown as ChainContext;
    const original = storage(context, 'shielded', 'leafBlocks');
    api.query.shielded = {
      leafBlocks: { key: () => '0xother', keyPrefix: () => '0xother' },
      usedNullifiers: { key: () => '0xother', keyPrefix: () => '0xother' },
    };
    expect(original.key(1)).toBe(`${LEAF_BLOCKS}0100000000000000`);
    expect(storage(context, 'shielded', 'leafBlocks').key(1)).toBe(original.key(1));
    expect(storage(context, 'shielded', 'usedNullifiers').keyPrefix()).toBe(NULLIFIERS);
  });

  it('builds no key for the ciphertext map, because the chain has none', () => {
    // The payloads are in block bodies and in no state map, so a wallet that
    // could still hash a key for them is a wallet that could still ask a node
    // for one. The list this is derived from is `REQUIRED_STORAGE`, which is
    // also what refuses the sync at startup against a runtime that declares
    // the map. See `chain/api.ts` and `crates/qnero-wallet/src/metadata.rs`.
    expect(() => canonicalStorage('shielded', 'ciphertexts')).toThrow(
      'unsupported Qnero storage',
    );
  });

  it('refuses unknown namespaces and malformed key arguments', () => {
    expect(() => canonicalStorage('other', 'leafCount')).toThrow('unsupported Qnero storage');
    expect(() => canonicalStorage('zkTree', 'leafCount').key(1)).toThrow('takes no storage key');
    const leafBlocks = canonicalStorage('shielded', 'leafBlocks');
    for (const index of [undefined, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '-1', '0x1', 1n << 64n]) {
      expect(() => leafBlocks.key(index)).toThrow('requires a u64 leaf index');
    }
    const nullifiers = canonicalStorage('shielded', 'usedNullifiers');
    for (const invalid of [undefined, 1, '00', 'gg'.repeat(32), '00'.repeat(33)]) {
      expect(() => nullifiers.key(invalid)).toThrow('requires a 32-byte nullifier');
    }
  });
});
