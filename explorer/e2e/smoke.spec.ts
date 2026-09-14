import { expect, test, type Page } from '@playwright/test';

import { readFacts, type DevnetFacts } from './devnet';

// Read lazily: the spec files are loaded before global setup has written them.
let cached: DevnetFacts | null = null;
function facts(): DevnetFacts {
  cached ??= readFacts();
  return cached;
}

/** The value under a field label, which is the stable hook every page shares. */
function field(page: Page, label: string) {
  return page.locator(`[data-field="${label}"] .field__value`).first();
}

function panel(page: Page, title: string) {
  return page.locator(`[data-panel="${title}"]`).first();
}

async function open(page: Page, route: string): Promise<void> {
  await page.goto(`/${route}`);
  await expect(page.getByRole('status').first()).toContainText('connected');
}

/** The head height the status strip is showing, which is how a new block is noticed. */
async function stripHeight(page: Page): Promise<number> {
  const text = await page.getByRole('status').first().innerText();
  return Number((/block ([\d,]+)/.exec(text)?.[1] ?? '0').replace(/,/g, ''));
}

test('the home page reads the head, the work and the pool off the node', async ({ page }) => {
  await open(page, '#/');
  await expect(page.getByRole('heading', { name: 'Qnero devnet' })).toBeVisible();

  await expect(field(page, 'Best block')).toHaveText(/\d/);
  const best = Number((await field(page, 'Best block').innerText()).replace(/,/g, ''));
  expect(best).toBeGreaterThanOrEqual(facts().settlementHeight);

  await expect(field(page, 'Finalized')).toHaveText(/\d/);
  await expect(field(page, 'Block time')).toHaveText(/ s$/);
  await expect(field(page, 'Difficulty')).toHaveText(/\d/);
  await expect(field(page, 'Network hash rate')).toHaveText(/H\/s$/);

  // The devnet is far below one epoch, so the seed in use is the genesis block
  // and the next rotation installs the first epoch boundary. The two are never
  // the same number: a next-seed field that reads back the seed already in use
  // would be telling the reader the dataset rotates to itself.
  await expect(field(page, 'RandomX seed height')).toHaveText('0');
  await expect(field(page, 'Next seed height')).toHaveText('2,048');
  await expect(page.locator('[data-field="Next seed height"] .field__note')).toContainText(
    'epoch 2,048 lag 64',
  );

  await expect(field(page, 'Commitment tree leaves')).toHaveText(/\d/);
  await expect(page.locator('[data-field="Commitment tree leaves"] .field__note')).toContainText(
    'depth',
  );
  // One send settled one slot, and a slot spends two notes.
  await expect(field(page, 'Nullifiers settled')).toHaveText('2');
  await expect(field(page, 'Pool value')).toContainText('QNR');
  await expect(page.locator('[data-field="Pool value"] .field__note')).toContainText(
    '1 entry has been shielded',
  );
  await expect(field(page, 'Latest coinbase')).toContainText('QNR');

  const rows = panel(page, 'Recent blocks').locator('tbody tr');
  await expect(rows.first()).toBeVisible();
  expect(await rows.count()).toBeGreaterThan(1);
});

test('the shield block names the payer, the amount and the leaf together', async ({ page }) => {
  await open(page, `#/block/${facts().shieldHeight}`);
  await expect(page.getByRole('heading', { name: `Block ${facts().shieldHeight}` })).toBeVisible();

  await expect(field(page, 'Author label')).toHaveText(/^0x[0-9a-f]{64}$/);
  await expect(field(page, 'zk tree root')).toHaveText(/^0x[0-9a-f]{64}$/);
  await expect(field(page, 'Hash')).toHaveText(/^0x[0-9a-f]{64}$/);
  await expect(field(page, 'RandomX seed height')).toHaveText('0');

  const coinbase = panel(page, 'Coinbase note');
  await expect(coinbase.locator('[data-field="Value"] .field__value')).toContainText('QNR');
  await expect(coinbase.locator('[data-field="Leaf index"] .field__value')).toHaveText(/\d/);

  const entries = page.locator('[data-panel="Shield entries (1)"]');
  await expect(entries).toBeVisible();
  await expect(entries).toContainText('the one linkable event in the system');
  const row = entries.locator('tbody tr').first();
  await expect(row).toContainText(facts().shieldQnr);
  await expect(row).toContainText(String(facts().shieldLeaf));
  await expect(row).toContainText('1,792 bytes');
});

test('the settlement block shows slots, both nullifiers and both commitments', async ({ page }) => {
  await open(page, `#/block/${facts().settlementHeight}`);

  const settlements = page.locator('[data-panel="Settlements (1)"]');
  await expect(settlements).toBeVisible();
  await expect(settlements.locator('[data-field="Slots settled"] .field__value')).toHaveText('1');
  await expect(settlements.locator('[data-field="Circuit segments"] .field__value')).toHaveText('1');
  await expect(settlements.locator('[data-field="Fee"] .field__value')).toContainText('QNR');

  const slot = settlements.locator('.slot').first();
  await expect(slot.locator('.slot__title')).toHaveText('Slot 1');
  await expect(slot).toContainText('Nullifiers spent');
  await expect(slot).toContainText('Commitments appended, unordered');
  expect(await slot.locator('.field__value').allInnerTexts()).toHaveLength(4);
  await expect(slot).toContainText('1,792 bytes of ciphertext');

  // The tree grew by the settlement's two leaves plus the block's coinbase.
  const extrinsics = page.locator('[data-panel="Extrinsics (3)"]');
  await expect(extrinsics).toContainText('Shielded.submit_private_batch');
  await expect(extrinsics).toContainText('Timestamp.set');
  await expect(extrinsics).toContainText('Shielded.coinbase');

  // Only the settlement links to the settlement page. A timestamp inherent
  // opened there would be titled as a settlement and would carry a statement
  // about spent notes over an extrinsic that spent nothing.
  const rows = extrinsics.locator('tbody tr');
  for (const row of await rows.all()) {
    const call = await row.locator('td').nth(1).innerText();
    const links = await row.locator('td a').count();
    expect(links).toBe(call === 'Shielded.submit_private_batch' ? 1 : 0);
  }
});

test('a settlement page states what it publishes and what it does not', async ({ page }) => {
  await open(page, `#/block/${facts().settlementHeight}`);
  await page.getByRole('link', { name: /submit_private_batch/ }).first().click();

  await expect(page.getByRole('heading', { name: 'Settlement' })).toBeVisible();
  await expect(field(page, 'Call')).toHaveText('Shielded.submit_private_batch');
  await expect(field(page, 'Included in')).toContainText(`block ${facts().settlementHeight}`);
  await expect(field(page, 'Anchor block')).toContainText('a canonical block in');
  await expect(page.locator('[data-field="Anchor block"] .field__note')).toContainText(
    'public input inside the proof',
  );

  await expect(panel(page, 'Slots').locator('.slot')).toHaveCount(1);
  await expect(page.locator('.notice')).toContainText('What this publishes');
  await expect(page.locator('.notice')).toContainText('the pair is rendered here with no order');
  // The join a slot does publish is stated beside the join it does not.
  await expect(page.locator('.notice')).toContainText(
    'Nothing on chain joins a nullifier to the leaf it spent',
  );
  await expect(panel(page, 'Slots')).toContainText('The two leaves beside it are the outputs');
});

test('search answers a height, a block hash and a settled nullifier', async ({ page }) => {
  // Every frame this page sends, so the point lookup can be counted. It is the
  // one read on this site that names its argument to whoever runs the node.
  const sent: string[] = [];
  page.on('websocket', (socket) => {
    socket.on('framesent', (frame) => {
      sent.push(String(frame.payload));
    });
  });
  const lookups = (): number =>
    sent.filter((frame) => frame.includes('"state_getStorage"')).length;

  await open(page, `#/search?q=${facts().settlementHeight}`);
  await expect(panel(page, 'Height')).toContainText(`Block ${facts().settlementHeight}`);

  // A block hash, taken from the block page itself.
  await open(page, `#/block/${facts().settlementHeight}`);
  const blockHash = await field(page, 'Hash').innerText();
  const nullifier = await page
    .locator('[data-panel="Settlements (1)"] .slot .field__value')
    .first()
    .innerText();

  await open(page, `#/search?q=${blockHash}`);
  await expect(field(page, 'A block on this chain')).toContainText(
    `block ${facts().settlementHeight}`,
  );

  // The nullifier lookup names its argument to the node, so it never runs on
  // its own: the warning is on the page and the answer is not, until asked.
  const lookup = panel(page, 'The settled nullifier set');
  await expect(page.locator('.notice')).toContainText('learns that someone asked about that value');
  await expect(page.locator('[data-field="In the settled nullifier set"]')).toHaveCount(0);
  await lookup.getByRole('button', { name: 'Check the settled nullifier set' }).click();
  await expect(field(page, 'In the settled nullifier set')).toHaveText('not seen');

  // A second 32-byte query starts from the warning again: one click is not
  // permission for every value typed after it.
  await open(page, `#/search?q=${nullifier}`);
  // The value being asked about is on screen inside the same keyed subtree as
  // the consent notice, so the copy's "those 32 bytes" cannot name one value
  // while the lookup sends another.
  await expect(page.locator('.notice').first()).toContainText(nullifier);
  await expect(field(page, 'A block on this chain')).toHaveText('not seen');
  await expect(page.locator('[data-field="In the settled nullifier set"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Check the settled nullifier set' }).click();
  await expect(field(page, 'In the settled nullifier set')).toHaveText('seen');
  // The answer names the block it is as of, because it was asked once.
  await expect(page.locator('[data-field="In the settled nullifier set"] .field__note')).toContainText(
    'as of block',
  );

  // The scans are explicit too, and the nullifier one finds the settling block.
  await page.getByRole('button', { name: /Read the last/ }).click();
  await expect(panel(page, 'Which settlement published it')).toContainText(
    `block ${facts().settlementHeight}`,
  );

  // One consent is one read. Keyed on the live head, this lookup re-sent the
  // nullifier to the node on every imported block and dropped the answer back
  // to loading each time, which unmounted the walk above mid-flight.
  const asked = lookups();
  const before = await stripHeight(page);
  await expect
    .poll(async () => stripHeight(page), { timeout: 60_000, intervals: [1000] })
    .toBeGreaterThan(before);
  expect(lookups()).toBe(asked);
  await expect(field(page, 'In the settled nullifier set')).toHaveText('seen');
  await expect(panel(page, 'Which settlement published it')).toContainText(
    `block ${facts().settlementHeight}`,
  );
});

test('genesis and an unknown hash are pages, not stack traces', async ({ page }) => {
  await open(page, '#/block/0');
  await expect(page.getByRole('heading', { name: 'Block 0' })).toBeVisible();
  // Genesis names an all-zero parent that is no block on this chain, so the
  // page does not offer it as a link to one.
  await expect(page.locator('[data-field="Parent"] a')).toHaveCount(0);
  await expect(page.locator('[data-field="Parent"] .field__note')).toContainText(
    'genesis has no parent',
  );
  await expect(panel(page, 'Extrinsics (0)')).toContainText('This block carries no extrinsics');

  const unknown = `0x${'00'.repeat(31)}01`;
  await open(page, `#/block/${unknown}`);
  await expect(page.getByRole('heading', { name: 'Block' })).toBeVisible();
  await expect(page.locator('.error')).toContainText('no block with hash');
  await expect(page.getByRole('link', { name: 'Back to the chain' })).toBeVisible();
});

test('the reveals page states both halves in plain words', async ({ page }) => {
  await open(page, '#/reveals');
  await expect(page.getByRole('heading', { name: 'What this chain reveals' })).toBeVisible();
  await expect(panel(page, 'What an observer learns from one block')).toContainText(
    'Total emission is therefore auditable block by block',
  );
  await expect(panel(page, 'What an observer learns from one block')).toContainText(
    /payment and its change are publicly a pair/,
  );
  await expect(panel(page, 'What stays hidden')).toContainText('no note names a recipient');
  await expect(panel(page, 'What stays hidden')).toContainText(
    'Membership proves some note was spent',
  );
  await expect(panel(page, 'What this site does not ask the node')).toContainText(
    'never calls the Merkle-proof endpoint',
  );
  await expect(page.locator('.notice')).toContainText('1,792');
});

test('every page is reachable from the keyboard and readable at 400 px', async ({ page }) => {
  await page.setViewportSize({ width: 400, height: 900 });
  await open(page, '#/');
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBe(0);

  // The first tab stop is the skip link, then the status strip's one control,
  // then the rail in the order it is read.
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toHaveText('Skip to content');
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toContainText('theme:');
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toContainText('Qnero');
  for (const name of ['Chain', 'Blocks', 'Search', 'Reveals']) {
    await page.keyboard.press('Tab');
    await expect(page.locator(':focus')).toHaveText(name);
  }
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'What this chain reveals' })).toBeVisible();

  // The skip link moves focus into the page and leaves the route alone. Its
  // href is the fragment the router owns, so following it as a link would
  // navigate to "main" and render the not-a-page view over every page. The
  // reload puts the focus starting point back at the top of the document: a
  // hash navigation keeps the document, and with it whatever holds focus.
  await open(page, '#/');
  await page.reload();
  await expect(page.getByRole('status').first()).toContainText('connected');
  await page.keyboard.press('Tab');
  await expect(page.locator(':focus')).toHaveText('Skip to content');
  await page.keyboard.press('Enter');
  await expect(page.locator(':focus')).toHaveAttribute('id', 'main');
  expect(await page.evaluate(() => window.location.hash)).toBe('#/');
  await expect(page.getByRole('heading', { name: 'Qnero devnet' })).toBeVisible();

  // A wide table scrolls inside its wrapper instead of collapsing its cells:
  // a hash is one line and an amount is never clipped into a smaller amount.
  await open(page, `#/block/${facts().settlementHeight}`);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    ),
  ).toBe(0);
  const extrinsics = page.locator('[data-panel^="Extrinsics"] .table-wrap');
  const box = await extrinsics.evaluate((element) => ({
    scroll: element.scrollWidth,
    client: element.clientWidth,
  }));
  expect(box.scroll).toBeGreaterThan(box.client);
  const cell = await page
    .locator('[data-panel^="Extrinsics"] td.mono')
    .first()
    .evaluate((element) => element.getBoundingClientRect().height);
  expect(cell).toBeLessThan(40);

  // The block list drops the author label at phone width and keeps the amount.
  await open(page, '#/');
  await expect(page.locator('thead th', { hasText: 'Author label' })).toBeHidden();
  await expect(page.locator('thead th', { hasText: 'Coinbase' })).toBeVisible();
});
