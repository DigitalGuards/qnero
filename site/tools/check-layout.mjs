/*
 * Measures the site in a headless browser at the widths a phone actually
 * reports, and fails on the two things a stylesheet comment cannot enforce:
 *
 *   1. A page that scrolls sideways. The body never does; a table, a diagram
 *      or a code block scrolls inside its own container instead.
 *   2. An inline `code` chip wider than the box holding it. Chips do not wrap,
 *      which is what keeps `--stratum-port` from reading as two flags, so a
 *      chip long enough to push the page sideways has to take `.code--wrap`
 *      or be shortened. 320 px is an iPhone SE and a Galaxy Fold cover screen,
 *      and it is the width the invariant was asserted at and never measured.
 *
 *   node site/tools/check-layout.mjs        # needs the site served on :8931
 *
 * Playwright resolves from explorer/ the way tools/make-images.mjs does, so the
 * site keeps no package.json of its own. The deploy is static files and runs
 * none of this.
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const from = process.env.PLAYWRIGHT_FROM || resolve(here, '../../explorer/package.json');
const { chromium } = createRequire(from)('playwright');

const BASE = process.env.SITE_BASE || 'http://127.0.0.1:8931';
const WIDTHS = [320, 400, 1280];
const PAGES = [
  'index.html', 'how-it-works.html', 'wallet.html', 'mine.html',
  'explorer.html', 'docs.html', 'about.html', '404.html',
];

const problems = [];
const browser = await chromium.launch();
const page = await browser.newPage();

for (const width of WIDTHS) {
  await page.setViewportSize({ width, height: 900 });
  for (const name of PAGES) {
    await page.goto(`${BASE}/${name}`, { waitUntil: 'load' });
    const found = await page.evaluate(() => {
      const doc = document.documentElement;
      const out = { scroll: doc.scrollWidth - doc.clientWidth, chips: [] };
      for (const el of document.querySelectorAll('code')) {
        if (el.closest('pre')) continue;
        const parent = el.parentElement.getBoundingClientRect();
        const own = el.getBoundingClientRect();
        if (own.width > parent.width + 0.5) {
          out.chips.push({ text: el.textContent.trim().slice(0, 48), own: Math.round(own.width), parent: Math.round(parent.width) });
        }
      }
      return out;
    });
    if (found.scroll > 0) {
      problems.push(`${name} at ${width}px: the page scrolls ${found.scroll}px sideways`);
    }
    for (const c of found.chips) {
      problems.push(`${name} at ${width}px: chip "${c.text}" is ${c.own}px inside a ${c.parent}px box; give it .code--wrap or shorten it`);
    }
  }
}

await browser.close();

console.log(`${PAGES.length} pages measured at ${WIDTHS.join(', ')} px`);
if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('no sideways page scroll, no chip wider than its box');
