// Uses staged single/threaded WASM through the production worker client.
// Start the Vite dev server, then run:
// node scripts/smoke-state-proof.js <fixture.json> [http://127.0.0.1:5173]
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { log } from 'node:console';
import { setTimeout } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const fixturePath = process.argv[2];
assert(fixturePath, 'the deterministic Rust fixture path is required');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const base = process.argv[3] ?? 'http://127.0.0.1:5173';
const browser = await chromium.launch({ headless: true });
try {
  for (const maxThreads of [1, 2]) {
    const page = await browser.newPage();
    const smokePage = `${base}/__state-proof-smoke__`;
    await page.route(smokePage, (route) => route.fulfill({
      contentType: 'text/html',
      headers: {
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
      },
      body: '<!doctype html><title>Local state proof worker check</title>',
    }));
    await page.goto(smokePage);
    const result = await Promise.race([
      page.evaluate(async ({ fixture, maxThreads }) => {
        const { ProverClient } = await import('/src/worker/client.ts');
        const client = new ProverClient();
        try {
          const init = await client.init(`${globalThis.location.origin}/wasm/`, 6, maxThreads);
          const values = await client.readStateProof(fixture.root, fixture.nodes, fixture.keys);
          const entries = await client.readStatePrefix(fixture.root, fixture.nodes, fixture.prefix);
          const empty = await client.readStatePrefix(fixture.root, fixture.nodes, fixture.emptyPrefix);
          let missingRejected = false;
          let rootRejected = false;
          try {
            await client.readStateProof(fixture.root, [], fixture.keys);
          } catch {
            missingRejected = true;
          }
          try {
            await client.readStateProof(`0x${'05'.repeat(32)}`, fixture.nodes, fixture.keys);
          } catch {
            rootRejected = true;
          }
          return { init, values, entries, empty, missingRejected, rootRejected };
        } finally {
          client.terminate();
        }
      }, { fixture, maxThreads }),
      setTimeout(60_000, undefined, { ref: false }).then(() => {
        throw new Error(`state proof worker smoke timed out with ${maxThreads} threads`);
      }),
    ]);
    assert.equal(result.init.threads, maxThreads, 'the requested module must load without fallback');
    assert.deepEqual(result.values, fixture.values);
    assert.deepEqual(result.entries, fixture.entries);
    assert.deepEqual(result.empty, []);
    assert.equal(result.missingRejected, true);
    assert.equal(result.rootRejected, true);
    log(JSON.stringify({ threads: result.init.threads, checks: 6, passed: true }));
    await page.close();
  }
} finally {
  await browser.close();
}
