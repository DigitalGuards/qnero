/**
 * The other Qnero apps, addressed from the host serving this one.
 *
 * `wallet.<apex>` links to `explorer.<apex>`, `faucet.<apex>` and `<apex>`, so
 * a second deployment links to its own apps. A host with no such shape (a
 * development server, an IP address) links to the project's public apps.
 */
export type AppHost = '' | 'wallet' | 'explorer' | 'faucet';

export const PUBLIC_APEX = 'qnero.io';

const SURFACE = /^(wallet|explorer|faucet)\.(.+\..+)$/;

export function apexOf(hostname: string): string {
  const match = SURFACE.exec(hostname);
  return match?.[2] ?? PUBLIC_APEX;
}

export function appUrl(host: AppHost, hostname: string): string {
  const apex = apexOf(hostname);
  return `https://${host === '' ? '' : `${host}.`}${apex}/`;
}

export const APPS: readonly { host: AppHost; label: string }[] = [
  { host: '', label: 'Qnero' },
  { host: 'wallet', label: 'Qloak wallet' },
  { host: 'explorer', label: 'silQ Road explorer' },
  { host: 'faucet', label: 'Testnet faucet' },
];
