/*
 * Renders site/img/og.png (1200x630) from tools/og-template.html and
 * site/img/favicon-32.png from site/img/favicon.svg, with one headless
 * Chromium. Run from anywhere:
 *
 *   node site/tools/make-images.mjs
 *
 * Playwright is already a development dependency of explorer/, so this
 * resolves it from there and the site keeps no package.json of its own. The
 * deploy is static files and runs none of this.
 */
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const site = resolve(here, '..');
const from = process.env.PLAYWRIGHT_FROM || resolve(site, '../explorer/package.json');
const { chromium } = createRequire(from)('playwright');

/*
 * Where the browser binary is.
 *
 * Playwright normally finds its own download. On a machine where Chromium is
 * provisioned outside that cache -- a CI image, a container that ships one --
 * `PLAYWRIGHT_CHROMIUM` names the executable and nothing has to be downloaded.
 * Unset, this is exactly the default.
 */
function launchOptions() {
  const executablePath = process.env.PLAYWRIGHT_CHROMIUM;
  return executablePath ? { executablePath } : {};
}

const browser = await chromium.launch(launchOptions());
try {
  const og = await browser.newPage({ viewport: { width: 1200, height: 630 } });
  await og.goto('file://' + resolve(here, 'og-template.html'));
  await og.screenshot({ path: resolve(site, 'img/og.png') });
  console.log('wrote site/img/og.png');

  const icon = await browser.newPage({
    viewport: { width: 32, height: 32 },
    deviceScaleFactor: 1,
  });
  await icon.goto('file://' + resolve(site, 'img/favicon.svg'));
  await icon.screenshot({ path: resolve(site, 'img/favicon-32.png'), omitBackground: true });
  console.log('wrote site/img/favicon-32.png');
} finally {
  await browser.close();
}
