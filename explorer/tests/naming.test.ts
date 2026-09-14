/**
 * The name, which is fixed by decision and spelled one way.
 *
 * "silQ Road": a lower-case s, a capital Q, one space, a capital R. The
 * spelling is fixed by decision, and until this test nothing in the one-second
 * gate read it: the rail, the tab title and the description passed lint,
 * types, every unit case and the production build with "SilQ Road" or "Silq
 * road" written into them, and the one assertion on the name in the whole
 * repository sat in a Playwright suite that needs a `--dev --tmp` node. So the
 * two files a reader meets the name in are read here, and every spelling of it
 * in them is compared against the one.
 *
 * `wallet-web/tests/policy.test.ts` holds the same case over "Qloak".
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

describe('the wordmark', () => {
  it('spells the name one way in the rail and the tab title', () => {
    const layout = readFileSync(new URL('../src/components/Layout.tsx', import.meta.url), 'utf8');
    const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
    expect(layout).toContain('silQ Road');
    expect(html).toContain('<title>silQ Road, the Qnero explorer</title>');
    for (const [file, source] of [
      ['src/components/Layout.tsx', layout],
      ['index.html', html],
    ] as const) {
      for (const found of source.matchAll(/silq[\s_-]?road/gi)) {
        expect(`${file}: ${found[0]}`).toBe(`${file}: silQ Road`);
      }
    }
  });
});
