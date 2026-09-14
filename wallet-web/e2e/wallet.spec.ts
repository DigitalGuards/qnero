/**
 * One payment, end to end, through the browser.
 *
 * The chain is real, the node is real, the proof is real and it is built in
 * this page's worker. What the suite asserts is the thing no unit test can:
 * that a wallet created in a browser receives value from an implementation
 * that shares no code with it, spends it, and that the second implementation
 * reads the payment back.
 *
 * The order matters. A shielded pool has one way in, and it is a signed
 * extrinsic the browser cannot build: the wasm module exports no ML-DSA-87
 * signing. So the command-line wallet shields into itself in global setup, and
 * this spec has it send to the browser's address once the browser has one.
 * That is also the honest test of the receive path, because the sender is not
 * this code.
 *
 * The measurement it writes out is the M8 follow-up: the same payment on the
 * threaded module and on the single-threaded one, on this machine, in this
 * browser.
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { expect, test, type Page } from '@playwright/test';

import { APP_DIR, headHeight, readFacts, wallet, walletProving } from './devnet';

const PASSPHRASE = 'a passphrase for the test wallet';
/** What the command-line wallet sends the browser wallet, in pool quanta. */
const FUNDING = 1000n;
/** What the browser then pays back out. */
const PAYMENT = 300n;
const MEMO = 'e2e';

interface Measurement {
  mode: 'threaded' | 'single';
  proveMillis: number;
  wholeSendMillis: number;
  peakMiB: number;
  proofBytes: number;
  settledBlock: number;
}

/**
 * Which module this run exercises.
 *
 * The preview origin is cross-origin isolated, so the default is the threaded
 * module. `QNERO_PROVER=single` asks the page for the single-threaded one
 * through `?prover=single`, which is how both rows in `docs/BENCH.md` come out
 * of one suite on one machine.
 */
const MODE: 'threaded' | 'single' = process.env['QNERO_PROVER'] === 'single' ? 'single' : 'threaded';

const measurements: Measurement[] = [];

/**
 * Every JSON-RPC method this page sends, recorded off the wire.
 *
 * `tests/privacy.test.ts` records the sync and the spend at the transport
 * seam, which is where the rules live. This records the socket itself, so it
 * also covers the part no unit test reaches: what `@polkadot/api` asks on its
 * own during a connection, and what a head subscription costs. The property is
 * the same one and it is the whole of "the node learns nothing": a name it is
 * never given.
 */
const RECORD_RPC = `
  (() => {
    const sent = [];
    globalThis.__qneroRpc = sent;
    const send = WebSocket.prototype.send;
    WebSocket.prototype.send = function (data) {
      try {
        const frame = JSON.parse(String(data));
        for (const call of Array.isArray(frame) ? frame : [frame]) {
          if (typeof call.method === 'string') {
            sent.push({ method: call.method, params: JSON.stringify(call.params ?? []) });
          }
        }
      } catch {
        // Not a JSON-RPC frame. Nothing this wallet sends looks like that, and
        // a recorder that threw here would break the page it is watching.
      }
      return send.call(this, data);
    };
  })();
`;

/**
 * What a wallet may ask a node.
 *
 * The first group is polkadot-js describing the chain it has just connected
 * to, which every client of this runtime sends and none of which names
 * anything. The second is this wallet's own reads, batched and pinned.
 * `state_getStorage` is deliberately absent: every storage read here is a
 * range or a batch at one block hash, and a point lookup is the shape that
 * carries a name.
 */
const ALLOWED_RPC = new Set([
  'rpc_methods',
  'system_chain',
  'system_chainType',
  'system_name',
  'system_properties',
  'system_version',
  'system_health',
  'state_call',
  'state_getMetadata',
  'state_getRuntimeVersion',
  'state_subscribeRuntimeVersion',
  'state_unsubscribeRuntimeVersion',
  'chain_getFinalizedHead',
  'chain_subscribeNewHead',
  'chain_subscribeNewHeads',
  'chain_unsubscribeNewHead',
  'chain_unsubscribeNewHeads',
  'chain_getBlockHash',
  'chain_getHeader',
  'chain_getBlock',
  'state_queryStorageAt',
  'state_getKeysPaged',
  'author_submitExtrinsic',
]);

/**
 * The runtime APIs `state_call` may name.
 *
 * `state_call` is on the list because polkadot-js reads this runtime's
 * metadata through it, and it is also the shape the Merkle-proof fence exists
 * for: `state_call` with `ZkTreeApi_get_merkle_proof` is one leaf named to the
 * node. So the method is allowed and the function it carries is not.
 */
const ALLOWED_RUNTIME_CALLS = /^(Metadata_|Core_)/;

/** `formatDuration`'s two forms: "980 ms" and "11.3 s". */
function millisFrom(reading: string): number {
  const value = Number(reading.replace(/[^0-9.]/g, ''));
  return reading.includes('ms') ? value : value * 1000;
}

test.afterAll(() => {
  if (measurements.length > 0) {
    writeFileSync(
      join(APP_DIR, '.devnet', `browser-measurement-${MODE}.json`),
      `${JSON.stringify(measurements, null, 2)}\n`,
    );
    // The measurement is the point of running this suite twice, and a file
    // nobody reads is not a report.
    console.log(`measurement (${MODE}):`, JSON.stringify(measurements));
  }
});

/** Create a wallet through the wizard, including the written confirmation. */
async function createWallet(page: Page): Promise<string> {
  await page.getByTestId('create-wallet').click();
  // Group by group, by the number each is shown under. The confirmation asks
  // for them by ordinal, so the numbering is part of what the screen owes a
  // reader and part of what this suite reads.
  const shown = page.locator('[data-testid^="seed-group-"]');
  await expect(shown.first()).toBeVisible();
  const groups = await shown.allInnerTexts();
  expect(groups).toHaveLength(8);
  for (const group of groups) {
    expect(group.trim()).toMatch(/^[0-9a-f]{8}$/);
  }

  await page.getByTestId('seed-written-down').click();

  // The confirmation asks for three groups drawn after the seed was hidden.
  // Which three is not knowable in advance, and the index is in the test id.
  const inputs = page.locator('[data-testid^="confirm-group-"]');
  await expect(inputs.first()).toBeVisible();
  const count = await inputs.count();
  expect(count).toBe(3);
  for (let index = 0; index < count; index += 1) {
    const input = inputs.nth(index);
    const id = await input.getAttribute('data-testid');
    const group = Number((id ?? '').replace('confirm-group-', ''));
    await input.fill((groups[group] ?? '').trim());
  }
  await page.getByTestId('confirm-seed').click();

  await page.getByTestId('passphrase').fill(PASSPHRASE);
  await page.getByTestId('passphrase-repeat').fill(PASSPHRASE);
  await page.getByTestId('finish-create').click();

  // Creating lands on the receive screen, which is where the address is.
  const address = await page.getByTestId('receive-address').innerText();
  expect(address.startsWith('qn1')).toBe(true);
  return address.trim();
}

async function syncUntil(page: Page, want: (unspent: bigint) => boolean): Promise<bigint> {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    await page.getByTestId('tab-balance').click();
    await page.getByTestId('do-sync').click();
    await expect(page.getByTestId('do-sync')).toBeEnabled({ timeout: 120_000 });
    const shown = (await page.getByTestId('balance-unspent').innerText()).replace(/,/g, '');
    const unspent = BigInt(shown);
    if (want(unspent)) {
      return unspent;
    }
    // The funding settlement may not be in a block yet.
    await page.waitForTimeout(3000);
  }
  throw new Error('the browser wallet never reached the balance this test waited for');
}

test.describe('the browser wallet against a dev chain', () => {
  test('receives from the command-line wallet, spends, and the payment is read back', async ({
    page,
  }) => {
    const facts = readFacts();
    const problems: string[] = [];
    page.on('pageerror', (error) => problems.push(`page error: ${error.message}`));
    await page.addInitScript(RECORD_RPC);
    // The endpoint this suite's node is actually on, seeded the way the
    // settings screen would write it. `public/config.json` carries the
    // default, and the default port is the one every Substrate node wants, so
    // the suite states its own rather than assuming nothing else on this
    // machine wanted 9944.
    await page.addInitScript((endpoint: string) => {
      try {
        localStorage.setItem('qnero-wallet-endpoint', endpoint);
      } catch {
        // Site data blocked. The page then falls back to `config.json`, which
        // is right whenever the node is on the default port.
      }
    }, facts.rpc);

    await page.goto(MODE === 'single' ? '/?prover=single' : '/');
    await expect(page.getByTestId('create-wallet')).toBeVisible({ timeout: 60_000 });

    // The policy travels with the files. `tests/policy.test.ts` asserts what
    // the directives say; this asserts that the page a host serves carries
    // them at all, which is the half a unit test cannot see. A build that
    // dropped the injection would serve a wallet that works perfectly and
    // refuses nothing.
    const policy = await page
      .locator('meta[http-equiv="Content-Security-Policy"]')
      .getAttribute('content');
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("connect-src 'self' ws: wss:");

    const address = await createWallet(page);

    // The node the page is talking to is the one this suite started.
    await expect(page.getByTestId('chain-status')).toContainText('block', { timeout: 60_000 });

    // And the module under test is the one this run asked for. A page that
    // silently fell back to the single-threaded module would still pass every
    // other assertion here, three times slower, and the measurement would be
    // labelled wrong.
    await page.getByTestId('tab-settings').click();
    await expect(page.getByText('Proving runs in a background worker.')).toBeVisible();
    const proverMode = await page.getByText('Proving runs in a background worker.').innerText();
    expect(proverMode).toContain(
      MODE === 'threaded' ? 'threaded module is in use' : 'single-threaded module',
    );

    // The command-line wallet funds it. This is the first time the browser's
    // address has existed, which is why it could not happen in setup.
    wallet(['--file', facts.senderSeed, 'sync']);
    walletProving([
      '--file',
      facts.senderSeed,
      'send',
      '--to',
      address,
      '--amount',
      String(FUNDING),
      '--memo',
      'funding the browser wallet',
    ]);

    const funded = await syncUntil(page, (unspent) => unspent >= FUNDING);
    expect(funded).toBe(FUNDING);
    await expect(page.getByTestId('notes-table')).toContainText('1,000');

    // The fee floor is read off the screen rather than computed here: it comes
    // from this runtime's own constants and a second copy of the arithmetic in
    // the test would agree with the wallet and disagree with the chain.
    await page.getByTestId('tab-send').click();
    const feeShown = (await page.getByTestId('send-fee').innerText()).replace(/[^0-9]/g, '');
    const fee = BigInt(feeShown);
    expect(fee).toBeGreaterThan(0n);

    await page.getByTestId('send-to').fill(facts.recipientAddress);
    await page.getByTestId('send-amount').fill(String(PAYMENT));
    await page.getByTestId('send-memo').fill(MEMO);

    const startedAt = Date.now();
    await page.getByTestId('do-send').click();
    await expect(page.getByTestId('send-phases')).toBeVisible();
    // The proof is the long pole: a circuit build and two proofs in wasm.
    await expect(page.getByTestId('send-result')).toBeVisible({ timeout: 600_000 });
    const wholeSendMillis = Date.now() - startedAt;

    const settledBlock = (await page.getByTestId('send-block').innerText()).trim();
    expect(settledBlock).not.toBe('-');

    // The result leads with what the payment was. The prover's own figures are
    // behind a disclosure, which this opens to read them.
    await expect(page.getByTestId('send-amount-paid')).toContainText(String(PAYMENT));
    await expect(page.getByTestId('send-recipient')).toContainText(facts.recipientAddress);
    await page.getByText('What the proof cost').click();
    const proverText = await page.getByTestId('send-prover').innerText();
    measurements.push({
      mode: MODE,
      proveMillis: millisFrom(await page.getByTestId('prove-millis').innerText()),
      wholeSendMillis,
      peakMiB: Number(/([0-9.]+) MiB/.exec(proverText)?.[1] ?? '0'),
      proofBytes: Number((/([0-9,]+) bytes/.exec(proverText)?.[1] ?? '0').replace(/,/g, '')),
      settledBlock: Number(settledBlock.replace(/,/g, '')),
    });

    await page.getByTestId('send-done').click();

    // The second implementation reads the payment back. It shares no code with
    // the browser: a different language, a different prover, a different store.
    wallet(['--file', facts.recipientSeed, 'sync']);
    const balance = wallet(['--file', facts.recipientSeed, 'balance']);
    expect(balance).toContain(String(PAYMENT));
    expect(balance).toContain(MEMO);

    // And the browser sees its own change, with the input it spent gone.
    const change = FUNDING - PAYMENT - fee;
    const after = await syncUntil(page, (unspent) => unspent === change);
    expect(after).toBe(change);
    await expect(page.getByTestId('notes-table')).toContainText('spent');

    expect(await headHeight()).toBeGreaterThan(0);

    // The prover switch, which is the only control that gives back the 918 MiB
    // this page holds and the one control with no test on it. Its test id was
    // passed as `data-testid` to a component that destructured a fixed prop
    // list and spread nothing, so the hook the settings screen advertised did
    // not reach the DOM at all and JSX could not catch it: a hyphenated
    // attribute name is not type checked.
    await page.getByTestId('tab-settings').click();
    const proverSwitch = page.getByTestId('prover-resident');
    await expect(proverSwitch).toHaveAttribute('data-state', 'checked');
    await proverSwitch.click();
    await expect(proverSwitch).toHaveAttribute('data-state', 'unchecked');
    // Nothing syncs while it is stopped, which is what the panel beside it
    // says. The button used to stay live and pay for every node gate and the
    // whole settled nullifier set before dying at the first worker call.
    await page.getByTestId('tab-balance').click();
    await expect(page.getByTestId('do-sync')).toBeDisabled();
    await page.getByTestId('tab-settings').click();
    await proverSwitch.click();
    await expect(proverSwitch).toHaveAttribute('data-state', 'checked', { timeout: 180_000 });
    await page.getByTestId('tab-balance').click();
    await expect(page.getByTestId('do-sync')).toBeEnabled({ timeout: 60_000 });

    // What the node was asked, over a whole session: a connection, two syncs,
    // a payment and a confirmation.
    const rpc = await page.evaluate(
      () => (globalThis as unknown as { __qneroRpc: { method: string; params: string }[] }).__qneroRpc,
    );
    expect(rpc.length).toBeGreaterThan(10);
    const methods = [...new Set(rpc.map((call) => call.method))].sort();
    console.log(`rpc methods (${MODE}):`, methods.join(', '));
    for (const method of methods) {
      expect(ALLOWED_RPC.has(method), `${method} is not a method this wallet may call`).toBe(true);
    }
    for (const call of rpc.filter((entry) => entry.method === 'state_call')) {
      const named = (JSON.parse(call.params) as unknown[])[0];
      expect(
        typeof named === 'string' && ALLOWED_RUNTIME_CALLS.test(named),
        `state_call named ${String(named)}, which is not a runtime API this wallet reads`,
      ).toBe(true);
    }
    // The one call that is only ever asked about a leaf the caller is
    // spending, under any of its spellings.
    expect(JSON.stringify(rpc)).not.toMatch(/merkle/i);

    expect(problems).toEqual([]);
  });
});
