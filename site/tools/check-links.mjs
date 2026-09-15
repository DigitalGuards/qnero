/*
 * Walks every HTML file in site/ and checks that each internal link and each
 * referenced asset exists on disk, that every fragment target exists in the
 * page it points at, and that no page links a host that does not answer yet.
 *
 *   node site/tools/check-links.mjs
 *
 * External links are listed and left alone: this checker makes no network
 * request, because the site makes none either.
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const site = resolve(here, '..');

const pages = readdirSync(site).filter((f) => f.endsWith('.html'));
const external = new Map();
const problems = [];

/* id="..." per page, so a fragment can be checked against its target. */
const idsOf = new Map();
for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  const ids = new Set();
  for (const m of html.matchAll(/\sid="([^"]+)"/g)) ids.add(m[1]);
  idsOf.set(page, ids);
}

for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  const refs = [];
  for (const m of html.matchAll(/(?:href|src)="([^"]+)"/g)) refs.push(m[1]);

  for (const ref of refs) {
    if (ref.startsWith('http://') || ref.startsWith('https://')) {
      external.set(ref, (external.get(ref) || 0) + 1);
      continue;
    }
    if (ref.startsWith('mailto:') || ref.startsWith('data:')) continue;

    if (ref.startsWith('#')) {
      if (!idsOf.get(page).has(ref.slice(1))) {
        problems.push(`${page}: fragment ${ref} has no target in this page`);
      }
      continue;
    }
    if (!ref.startsWith('/')) {
      problems.push(`${page}: ${ref} is a relative reference; use a root-relative one`);
      continue;
    }

    const [path, fragment] = ref.split('#');
    const target = path === '/' ? 'index.html' : path.replace(/^\//, '');
    if (!existsSync(join(site, target))) {
      problems.push(`${page}: ${ref} points at ${target}, which does not exist`);
      continue;
    }
    if (fragment && target.endsWith('.html')) {
      const ids = idsOf.get(target);
      if (ids && !ids.has(fragment)) {
        problems.push(`${page}: ${ref} has no target #${fragment} in ${target}`);
      }
    }
  }
}

/* The testnet subdomains answer nothing yet, so a link to one would be a dead
   link shipped on purpose. They are named as plain text on the pages. The
   apex is fine: it is this site, and it is what canonical and og:url carry. */
for (const url of external.keys()) {
  const host = new URL(url).hostname;
  if (host.endsWith('.qnero.io') && host !== 'www.qnero.io') {
    problems.push(`a page links ${url}, which is a testnet host that does not answer yet`);
  }
}

console.log(`${pages.length} pages, ${external.size} distinct external links`);
for (const [url, n] of [...external].sort()) console.log(`  ${n}x ${url}`);

if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('\nno broken internal links, assets or fragments');
