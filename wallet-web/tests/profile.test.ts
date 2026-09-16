import { describe, expect, it } from 'vitest';
import { ensureCompatibleProfile } from '../src/chain/profile';
import type { ProverLimits } from '../src/worker/protocol';
import { TEST_PROTOCOL_PROFILE } from './fixtures/protocol-profile';

const limits: ProverLimits = {
  memo_bytes: 61,
  ciphertext_fixed_bytes: 1731,
  padded_ciphertext_bytes: 1792,
  digest_logs_size: 110,
  max_tree_depth: 16,
  tree_arity: 4,
  siblings_per_level: 3,
  chain_num_leaves: 6,
  protocol_profile: TEST_PROTOCOL_PROFILE,
};

describe('protocol profile preflight', () => {
  it('accepts the profile compiled into the proving module', () => {
    expect(() => { ensureCompatibleProfile(`0x${TEST_PROTOCOL_PROFILE}`, limits); }).not.toThrow();
  });

  it('rejects changes to every protocol or verifier byte before building', () => {
    for (let index = 0; index < 192; index += 1) {
      const offset = index * 2;
      const byte = Number.parseInt(TEST_PROTOCOL_PROFILE.slice(offset, offset + 2), 16) ^ 1;
      const changed = TEST_PROTOCOL_PROFILE.slice(0, offset) + byte.toString(16).padStart(2, '0') +
        TEST_PROTOCOL_PROFILE.slice(offset + 2);
      expect(() => { ensureCompatibleProfile(changed, limits); }).toThrow('incompatible Qnero protocol profile');
    }
  });

  it('rejects truncation, trailing bytes, absent profiles and configured dimension drift', () => {
    expect(() => { ensureCompatibleProfile(TEST_PROTOCOL_PROFILE.slice(2), limits); }).toThrow();
    expect(() => { ensureCompatibleProfile(`${TEST_PROTOCOL_PROFILE}00`, limits); }).toThrow();
    expect(() => { ensureCompatibleProfile('', limits); }).toThrow();
    expect(() => { ensureCompatibleProfile(TEST_PROTOCOL_PROFILE, { ...limits, chain_num_leaves: 8 }); }).toThrow();
  });
});
