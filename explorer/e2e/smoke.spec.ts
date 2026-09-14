import { expect, test, type Page } from '@playwright/test';

import { readFacts, RPC_PORT, type DevnetFacts } from './devnet';

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
  // One send settled one slot, and a slot settles two nullifiers, one per
  // input position. Every block in the window answered, so the figure carries
  // no "at least" marker.
  await expect(field(page, 'Nullifiers settled')).toHaveText('2');
  await expect(page.locator('[data-field="Nullifiers settled"] .field__note')).toContainText(
    'two per settled slot, and a slot spends one note or two, so this is an upper bound on the notes spent',
  );
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
  await expect(slot).toContainText('Nullifiers settled');
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
  await expect(panel(page, 'Slots')).toContainText('The two leaves beside them are the outputs');

  // What a settled nullifier stands for. A slot has two input positions and its
  // two nullifiers mark both consumed; a position holding a dummy input
  // publishes a nullifier over no note (docs/CIRCUIT.md section 5, the NF_DUMMY
  // tag, and section 9.5 on settling both nullifiers of every real slot). So
  // the page bounds what the slot spent and counts positions.
  await expect(page.locator('.notice')).toContainText(
    'A slot has two input positions and its two nullifiers mark both consumed',
  );
  await expect(page.locator('.notice')).toContainText(
    'a position holding a dummy input publishes a nullifier over no note',
  );
  await expect(page.locator('.notice')).toContainText('a slot spends one note or two');
  await expect(page.locator('.notice')).toContainText(
    'the nullifiers below count positions',
  );
  await expect(panel(page, 'Slots')).toContainText(
    'Each of these marks one of the slot’s two input positions consumed',
  );
  await expect(panel(page, 'Slots')).toContainText(
    'A real input spends one note and a dummy input publishes a nullifier over no note',
  );

  // And the claim it replaced is gone from the page, label included: a settled
  // nullifier is not evidence that the note behind it was spent.
  const settlementText = await page.locator('#main').innerText();
  expect(settlementText).not.toContain('proves some note was spent');
  expect(settlementText).not.toContain('Nullifiers spent');
  expect(settlementText).not.toContain('that some notes were spent');
});

test('a settlement that cannot be answered is a page with a way out', async ({ page }) => {
  // The same shape the block page fails in: the heading, the value the page was
  // opened by, the node's own message, and a link back. The error branch here
  // was a bare error box with no heading and nothing to click.
  const unknown = `0x${'00'.repeat(31)}02`;
  await open(page, `#/settlement/${unknown}?at=${unknown}`);
  await expect(page.getByRole('heading', { name: 'Extrinsic' })).toBeVisible();
  await expect(page.locator('.page__lede')).toContainText(unknown);
  await expect(page.locator('.error')).toContainText('no block with hash');
  await expect(page.getByRole('link', { name: 'Back to the chain' })).toBeVisible();
});

test('search answers a height, a block hash and a settled nullifier', async ({ page }) => {
  // Every frame this page sends, so the reads that carry the query's own 32
  // bytes can be counted. The match is on the bare hex, because a value reaches
  // the node in two shapes: as the whole parameter of a header read, and inside
  // a Blake2_128Concat key, which is the hash followed by the raw key. Counting
  // only frames naming `state_getStorage` counted the second and missed the
  // first, which is how an automatic header read survived three rounds here.
  const sent: string[] = [];
  page.on('websocket', (socket) => {
    socket.on('framesent', (frame) => {
      sent.push(String(frame.payload));
    });
  });
  const naming = (value: string): number => {
    const bytes = value.replace(/^0x/, '').toLowerCase();
    return sent.filter((frame) => frame.toLowerCase().includes(bytes)).length;
  };

  await open(page, `#/search?q=${facts().settlementHeight}`);
  await expect(panel(page, 'Height')).toContainText(`Block ${facts().settlementHeight}`);

  // A block hash, taken from the block page itself.
  await open(page, `#/block/${facts().settlementHeight}`);
  const blockHash = await field(page, 'Hash').innerText();
  const nullifier = await page
    .locator('[data-panel="Settlements (1)"] .slot .field__value')
    .first()
    .innerText();

  // The block check is a request carrying the query's 32 bytes, so it waits for
  // a click like the rest. The count is taken first because the block page
  // above already asked the node for this hash, which it is entitled to: a
  // block page opened by hash has to send the hash it was asked for.
  const askedHash = naming(blockHash);
  await open(page, `#/search?q=${blockHash}`);
  await expect(page.locator('.notice').first()).toContainText('Opening it sends the node nothing');
  // The count first: it is the claim. The missing field below it is only how
  // the page shows that the read has not run.
  expect(naming(blockHash)).toBe(askedHash);
  await expect(page.locator('[data-field="A block on this chain"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Ask the node for the header' }).click();
  await expect(field(page, 'A block on this chain')).toContainText(
    `block ${facts().settlementHeight}`,
  );
  expect(naming(blockHash)).toBeGreaterThan(askedHash);

  // A second 32-byte query starts from the warning again: one click is not
  // permission for every value typed after it. This one is a settled nullifier
  // read off the chain moments ago, and nothing this browser sent has ever
  // named it, because it arrived in a frame the node sent.
  await open(page, `#/search?q=${nullifier}`);
  // The value being asked about is on screen inside the same keyed subtree as
  // the consent notice, so the copy's "those 32 bytes" cannot name one value
  // while the lookup sends another.
  await expect(page.locator('.notice').first()).toContainText(nullifier);
  await expect(page.locator('.notice')).toContainText(
    'tells whoever runs the node that someone asked about this value',
  );
  expect(naming(nullifier)).toBe(0);
  await expect(page.locator('[data-field="A block on this chain"]')).toHaveCount(0);
  await expect(page.locator('[data-field="In the settled nullifier set"]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Ask the node for the header' }).click();
  await expect(field(page, 'A block on this chain')).toHaveText('not seen');
  expect(naming(nullifier)).toBe(1);

  await panel(page, 'The settled nullifier set')
    .getByRole('button', { name: 'Check the settled nullifier set' })
    .click();
  await expect(field(page, 'In the settled nullifier set')).toHaveText('seen');
  expect(naming(nullifier)).toBe(2);
  // The answer names the block it is as of, because it was asked once.
  await expect(
    page.locator('[data-field="In the settled nullifier set"] .field__note'),
  ).toContainText('as of block');

  // The scans are explicit too, and the nullifier one finds the settling block
  // by reading events in bulk, so it names the value to nobody.
  await page.getByRole('button', { name: /Read the last/ }).click();
  await expect(panel(page, 'Which settlement published it')).toContainText(
    `block ${facts().settlementHeight}`,
  );
  expect(naming(nullifier)).toBe(2);

  // One consent is one read. Keyed on the live head, this lookup re-sent the
  // nullifier to the node on every imported block and dropped the answer back
  // to loading each time, which unmounted the walk above mid-flight.
  const asked = naming(nullifier);
  const before = await stripHeight(page);
  await expect
    .poll(async () => stripHeight(page), { timeout: 60_000, intervals: [1000] })
    .toBeGreaterThan(before);
  expect(naming(nullifier)).toBe(asked);
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
    'Membership marks one input position of one settlement consumed',
  );
  await expect(panel(page, 'What stays hidden')).toContainText(
    'a dummy input publishes a nullifier over no note',
  );
  await expect(panel(page, 'What an observer learns from one block')).toContainText(
    'a position holding a dummy input publishes a nullifier over no note',
  );
  await expect(panel(page, 'What an observer learns from one block')).toContainText(
    'which bounds the notes this chain has spent from above',
  );
  expect(await page.locator('#main').innerText()).not.toContain('proves some note was spent');
  await expect(panel(page, 'What this site does not ask the node')).toContainText(
    'never calls the Merkle-proof endpoint',
  );
  // A page does send what it was asked to open, and the difference between a
  // route carrying a block hash and a reader pasting 32 bytes of unknown kind
  // is stated here rather than left to the search page's own copy.
  await expect(panel(page, 'What this site does not ask the node')).toContainText(
    'nothing there is sent until a button is pressed',
  );
  await expect(page.locator('.notice')).toContainText('1,792');
});

/**
 * The node's answer at a block it no longer keeps state for, without pruning a
 * dev chain to get there.
 *
 * Substrate refuses a state read below its pruning window and serves the header
 * and the body out of the archive regardless, so a settlement older than the
 * window comes back as an extrinsic with no events beside it. That shape is
 * what turned an unread event log into the sentence "this extrinsic settled no
 * slot", on a spend that published two nullifiers and two commitments.
 *
 * The socket is relayed rather than mocked: every frame goes to the real node
 * and back, except a `state_` request naming this one block hash, which is
 * answered with the node's own wording and never forwarded.
 */
const DISCARDED = 'Client error: UnknownBlock: State already discarded for';

interface RpcRequest {
  id: unknown;
  method: string;
  params?: unknown;
}

function isRequest(value: unknown): value is RpcRequest {
  return (
    typeof value === 'object' &&
    value !== null &&
    'method' in value &&
    typeof value.method === 'string'
  );
}

/** The frames to refuse and the frames to forward, out of one client frame. */
function split(text: string, target: string): { refused: unknown[]; kept: unknown[]; batch: boolean } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { refused: [], kept: [text], batch: false };
  }
  const batch = Array.isArray(parsed);
  const list: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  const refused: unknown[] = [];
  const kept: unknown[] = [];
  for (const entry of list) {
    const names =
      isRequest(entry) &&
      entry.method.startsWith('state_') &&
      JSON.stringify(entry.params ?? []).toLowerCase().includes(target);
    if (names && isRequest(entry)) {
      refused.push({
        jsonrpc: '2.0',
        id: entry.id,
        error: { code: -32000, message: `${DISCARDED} ${target}` },
      });
    } else {
      kept.push(entry);
    }
  }
  return { refused, kept, batch };
}

/**
 * Relay the page's socket to the node, refusing state reads at whichever block
 * the caller names.
 *
 * The relay is installed before the first navigation, because a route reaches
 * only sockets opened after it was set, and the block to refuse is not known
 * until a page has been read. It refuses nothing until `refuse` is called.
 */
async function relayWithStateBoundary(page: Page): Promise<(blockHash: string) => void> {
  let target: string | null = null;
  await page.routeWebSocket(
    (url) => url.href.includes(`:${String(RPC_PORT)}`),
    (client) => {
      const node = client.connectToServer();
      client.onMessage((message) => {
        const text = typeof message === 'string' ? message : message.toString('utf8');
        if (target === null) {
          node.send(text);
          return;
        }
        const { refused, kept, batch } = split(text, target);
        if (refused.length > 0) {
          client.send(JSON.stringify(batch ? refused : refused[0]));
        }
        if (kept.length > 0) {
          node.send(JSON.stringify(batch ? kept : kept[0]));
        }
      });
      node.onMessage((message) => {
        client.send(message);
      });
    },
  );
  return (blockHash: string) => {
    target = blockHash.toLowerCase();
  };
}

test('a settlement whose block state is gone is never written up as one that settled nothing', async ({
  page,
}) => {
  const refuse = await relayWithStateBoundary(page);
  await open(page, `#/block/${facts().settlementHeight}`);
  const blockHash = await field(page, 'Hash').innerText();
  const link = await page
    .getByRole('link', { name: /submit_private_batch/ })
    .first()
    .getAttribute('href');
  expect(link).not.toBeNull();

  refuse(blockHash);

  // The settlement, opened the way a block page's link opens it: the block it
  // came from is in the query, so this is one body read and one state read.
  // The reload is what makes it a read: a hash change keeps the document, and
  // polkadot-js memoises a storage query at a fixed block, so the events the
  // block page just read would be answered out of memory and this page would
  // never touch the socket.
  await page.goto(`/${String(link)}`);
  await page.reload();
  await expect(page.getByRole('status').first()).toContainText('connected');
  // The body is archived, so the submission is all still here.
  await expect(field(page, 'Call')).toHaveText('Shielded.submit_private_batch');
  await expect(field(page, 'Included in')).toContainText(`block ${facts().settlementHeight}`);

  // What is not here is a claim about what it settled. The page said
  // "Extrinsic", dropped the anchor window and the publishes/does-not notice,
  // and printed "This extrinsic settled no slot" with no error anywhere.
  await expect(page.locator('.notice')).toContainText('State already discarded');
  await expect(panel(page, 'Slots')).toContainText('This is not an absence');
  await expect(panel(page, 'Slots')).not.toContainText('settled no slot');

  // The block page under the identical failure has always said this, which is
  // the wording the settlement page now shares.
  await open(page, `#/block/${blockHash}`);
  await expect(page.locator('.notice').first()).toContainText(
    'The node answered no state at this block',
  );
  // And the panel titles carry no count over it. "Settlements (0)" over a body
  // that says the read failed is the same absence the body refuses, printed in
  // the heading a reader believes first.
  await expect(panel(page, 'Settlements (not counted)')).toContainText('This is not an absence');
  await expect(panel(page, 'Settlements (not counted)')).not.toContainText('No settlement landed');
  await expect(page.locator('[data-panel="Settlements (0)"]')).toHaveCount(0);
  await expect(panel(page, 'Shield entries (not counted)')).toContainText('This is not an absence');
  await expect(page.locator('[data-panel="Shield entries (0)"]')).toHaveCount(0);
  // The refused-calls panel is a panel now. It used to disappear over an unread
  // event log, which reports "nothing was refused here" by absence.
  await expect(panel(page, 'Refused and failed calls (not counted)')).toContainText(
    'This is not an absence',
  );
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
