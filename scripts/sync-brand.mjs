/*
 * Copies brand/ into the four apps, and fails when a copy has drifted.
 *
 *   node scripts/sync-brand.mjs            # write the copies
 *   node scripts/sync-brand.mjs --check    # fail if any copy is stale
 *
 * Why copies rather than one shared import. The four apps deploy
 * independently and by different means: the site is static files with no
 * build step, silQ Road and Qloak are Vite builds, and the faucet compiles its
 * assets into a Rust binary with `include_str!` and `include_bytes!`. Nothing
 * spans all four but the filesystem. So the palette lives once in brand/, this
 * script fans it out, and `--check` is what keeps the fan-out honest: before
 * this existed the same tokens were maintained by hand in four places and had
 * already drifted.
 *
 * The fonts are duplicated per app for the same reason, and each copy carries
 * the OFL licence text beside it, which is what OFL 1.1 requires of anyone
 * redistributing the font files.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, relative } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const brand = resolve(root, 'brand');

/* Where each app keeps the stylesheet that `./fonts/` is relative to. */
const STYLE_DIRS = [
  'site/css',
  'explorer/src/styles',
  'wallet-web/src/styles',
  'faucet/src/assets',
];

/* The mark, as a file. Qloak and silQ Road inline theirs as a `data:` URI
   instead, so that they cost no request and need no `img-src` beyond what
   their content policies already admit; `--check` verifies those separately
   in each app's own tests. */
const FAVICON_TARGETS = ['site/img/favicon.svg', 'faucet/src/assets/favicon.svg'];

const FONT_FILES = readdirSync(resolve(brand, 'fonts')).sort();

/** [source, destination] pairs, all relative to the repo root. */
function plan() {
  const pairs = [];
  for (const dir of STYLE_DIRS) {
    pairs.push(['brand/tokens.css', `${dir}/brand-tokens.css`]);
    pairs.push(['brand/fonts.css', `${dir}/brand-fonts.css`]);
    for (const font of FONT_FILES) {
      pairs.push([`brand/fonts/${font}`, `${dir}/fonts/${font}`]);
    }
  }
  for (const target of FAVICON_TARGETS) {
    pairs.push(['brand/favicon.svg', target]);
  }
  return pairs;
}

const check = process.argv.includes('--check');
const pairs = plan();
const stale = [];
let written = 0;

for (const [from, to] of pairs) {
  const source = readFileSync(resolve(root, from));
  const target = resolve(root, to);

  if (check) {
    if (!existsSync(target) || !readFileSync(target).equals(source)) {
      stale.push(to);
    }
    continue;
  }

  mkdirSync(dirname(target), { recursive: true });
  if (existsSync(target) && readFileSync(target).equals(source)) continue;
  writeFileSync(target, source);
  written += 1;
  console.log(`  ${relative(root, target)}`);
}

if (check) {
  if (stale.length > 0) {
    console.error('These copies do not match brand/:\n');
    for (const path of stale) console.error(`  ${path}`);
    console.error('\nRun: node scripts/sync-brand.mjs');
    process.exit(1);
  }
  console.log(`brand/ is in sync across ${pairs.length} files.`);
} else {
  console.log(
    written === 0
      ? `brand/ was already in sync across ${pairs.length} files.`
      : `\nSynced ${written} of ${pairs.length} files from brand/.`,
  );
}
