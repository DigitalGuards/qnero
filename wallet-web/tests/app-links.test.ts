import { describe, expect, it } from 'vitest';

import { apexOf, appUrl } from '../src/lib/appLinks';

describe('app links', () => {
  it('follows the apex of the deployment serving the wallet', () => {
    expect(apexOf('wallet.qnero.io')).toBe('qnero.io');
    expect(appUrl('explorer', 'wallet.example.org')).toBe('https://explorer.example.org/');
    expect(appUrl('', 'wallet.example.org')).toBe('https://example.org/');
    expect(appUrl('faucet', 'wallet.qnero.io')).toBe('https://faucet.qnero.io/');
  });

  it('falls back to the public apps on a host with no app shape', () => {
    for (const host of ['localhost', '127.0.0.1', '', 'wallet.localhost', 'qnero.io']) {
      expect(apexOf(host)).toBe('qnero.io');
    }
    expect(appUrl('wallet', 'localhost')).toBe('https://wallet.qnero.io/');
  });
});
