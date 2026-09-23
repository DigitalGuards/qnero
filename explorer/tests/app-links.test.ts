import { describe, expect, it } from 'vitest';

import { apexOf, appUrl } from '../src/lib/appLinks';

describe('app links', () => {
  it('follows the apex of the deployment serving the explorer', () => {
    expect(apexOf('explorer.qnero.io')).toBe('qnero.io');
    expect(appUrl('wallet', 'explorer.example.org')).toBe('https://wallet.example.org/');
    expect(appUrl('', 'explorer.example.org')).toBe('https://example.org/');
    expect(appUrl('faucet', 'explorer.qnero.io')).toBe('https://faucet.qnero.io/');
  });

  it('falls back to the public apps on a host with no app shape', () => {
    for (const host of ['localhost', '127.0.0.1', '', 'explorer.localhost', 'qnero.io']) {
      expect(apexOf(host)).toBe('qnero.io');
    }
    expect(appUrl('wallet', 'localhost')).toBe('https://wallet.qnero.io/');
  });
});
