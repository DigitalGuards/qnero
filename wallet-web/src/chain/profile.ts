/** Release compatibility before constructing or using the wallet circuits. */
import type { ChainContext } from './api';
import { authenticatedValues } from './authenticated';
import type { ProverLimits } from '../worker/protocol';

// twox128("Shielded") ++ twox128("ActiveProtocolProfile"). The value's
// SCALE encoding is the 192-byte profile, without a vector length prefix.
export const ACTIVE_PROFILE_KEY =
  '0xcad93014ca4e3d270e8f2677345d6f09f3593aefbef3dca83dba417658faf114';

export function ensureCompatibleProfile(declared: string, limits: ProverLimits): void {
  if (typeof declared !== 'string') {
    throw new Error('this runtime declares no Qnero protocol profile; update before sending');
  }
  const profile = declared.replace(/^0x/, '').toLowerCase();
  const embedded = (limits as Partial<ProverLimits>).protocol_profile;
  if (typeof embedded !== 'string') {
    throw new Error('this wallet module has no Qnero protocol profile; update before sending');
  }
  const supported = embedded.replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{384}$/.test(profile) ||
      !/^[0-9a-f]{384}$/.test(supported) || !supported.startsWith('514e5250524630310100')) {
    throw new Error('this runtime or wallet has no supported Qnero protocol profile; update before sending');
  }
  const count = Number.parseInt(supported.slice(120, 122), 16) +
    256 * Number.parseInt(supported.slice(122, 124), 16);
  if (profile !== supported || count !== limits.chain_num_leaves) {
    throw new Error('incompatible Qnero protocol profile; update the wallet or select a compatible chain before building circuits');
  }
}

export async function ensureActiveProfile(
  context: ChainContext, limits: ProverLimits, at: string,
): Promise<void> {
  ensureCompatibleProfile(context.protocolProfile, limits);
  const [active] = await authenticatedValues(context, [ACTIVE_PROFILE_KEY], at);
  if (active === null || active === undefined) {
    throw new Error('this chain has no authenticated active protocol profile; a compatible runtime upgrade is required');
  }
  ensureCompatibleProfile(active, limits);
}
