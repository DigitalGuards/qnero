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

  // The devnet is far below one epoch, so the seed is still the genesis block
  // and the rotation is announced ahead of it.
  await expect(field(page, 'RandomX seed height')).toHaveText('0');
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
  await expect(page.locator('.notice')).toContainText('a pair with no order');
});

test('search answers a height, a block hash and a settled nullifier', async ({ page }) => {
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
  await expect(field(page, 'In the settled nullifier set')).toHaveText('not seen');

  await open(page, `#/search?q=${nullifier}`);
  await expect(field(page, 'In the settled nullifier set')).toHaveText('seen');
  await expect(field(page, 'A block on this chain')).toHaveText('not seen');
  await expect(page.locator('.notice')).toContainText('names that value to whoever runs it');

  // The scans are explicit, and the nullifier one finds the settling block.
  await page.getByRole('button', { name: /Read the last/ }).click();
  await expect(panel(page, 'Which settlement published it')).toContainText(
    `block ${facts().settlementHeight}`,
  );
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
});
