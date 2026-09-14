/**
 * The endpoint actually in use, remembered.
 *
 * `config.json` is the default a fresh install gets. What persists is the
 * choice made on the settings screen, because a wallet that showed one
 * endpoint and read from another is a wallet whose "what this reveals to the
 * node" panel is about the wrong node.
 */

const KEY = 'qnero-wallet-endpoint';

export function readEndpoint(fallback: string): string {
  try {
    const stored = localStorage.getItem(KEY);
    return stored !== null && stored.length > 0 ? stored : fallback;
  } catch {
    return fallback;
  }
}

export function writeEndpoint(endpoint: string): void {
  try {
    localStorage.setItem(KEY, endpoint);
  } catch {
    // A private window, or site data blocked. The endpoint then lasts the
    // session, which is worse and is not a failure.
  }
}
