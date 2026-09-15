import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

/**
 * The one directive this page cannot be served without.
 *
 * `@polkadot/api` awaits `cryptoWaitReady()` when the provider connects, and
 * `@polkadot/wasm-crypto-init` resolves to the wasm-only builder in a browser.
 * A policy that refuses WebAssembly compilation makes that call return `false`
 * rather than throw, so `ApiPromise` never emits `ready`, `connect()` never
 * settles, and the page reports the endpoint as unreachable while the node is
 * answering normally.
 *
 * Nothing else catches it: `nginx -t` checks syntax, the built `index.html`
 * carries no `<meta>` policy, and a root-URL probe returns 200 either way. So
 * every copy of the policy this repository ships is asserted here, and
 * `vite.config.ts` serves the preview under it so the Playwright suite runs
 * against the real thing.
 */
const WASM = "'wasm-unsafe-eval'";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXPLORER = path.join(HERE, '..');
const REPO = path.join(EXPLORER, '..');

/** Every `Content-Security-Policy` value in a file, header or config form. */
function policiesIn(text: string): string[] {
  const found: string[] = [];
  const pattern = /Content-Security-Policy\s*\n?\s*"([^"]+)"/g;
  for (const match of text.matchAll(pattern)) {
    const policy = match[1];
    if (policy !== undefined) {
      found.push(policy);
    }
  }
  return found;
}

function expectWasm(policy: string): void {
  const directive = policy
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('script-src'));
  expect(directive, `no script-src in ${policy}`).toBeDefined();
  expect(directive).toContain(WASM);
}

describe('the shipped content-security-policy', () => {
  it('lets the preview server compile WebAssembly', () => {
    const config = readFileSync(path.join(EXPLORER, 'vite.config.ts'), 'utf8');
    expect(config).toContain("preview: { headers: { 'Content-Security-Policy'");
    expect(config).toContain(WASM);
  });

  it('is documented with the directive in it', () => {
    const readme = readFileSync(path.join(EXPLORER, 'README.md'), 'utf8');
    const policies = policiesIn(readme);
    expect(policies.length).toBeGreaterThan(0);
    for (const policy of policies) {
      expectWasm(policy);
    }
  });

  it('carries it in every copy in the packaged vhost', () => {
    const vhost = path.join(REPO, 'packaging', 'nginx', '40-explorer.conf');
    // The explorer is also usable outside this repository, where the packaging
    // set is not present. Nothing to assert then; inside the repository there
    // are two copies, because a location with its own add_header inherits
    // none and the set is repeated rather than lost.
    if (!existsSync(vhost)) {
      return;
    }
    const policies = policiesIn(readFileSync(vhost, 'utf8'));
    expect(policies.length).toBe(2);
    for (const policy of policies) {
      expectWasm(policy);
    }
  });
});
