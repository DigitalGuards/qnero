/*
 * Walks every HTML file in site/ and checks that each internal link and each
 * referenced asset exists on disk, that every fragment target exists in the
 * page it points at, that sitemap.xml lists exactly the pages that exist, that
 * every absolute qnero.io meta URL resolves to a file, and that every link to
 * an M11 subdomain carries the marker that labels it.
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

/* The M11 subdomains are linked and labelled "testnet, coming online", which is
   what the brief asks for and what site/README.md records. They answer nothing
   until M11 deploys, so each one carries `data-m11-host` on its anchor: that
   marker is the single grep that finds every one of them on the day they go
   live, and this check fails an unmarked one so a new subdomain link cannot
   arrive without the label beside it. The apex is not one of them: it is this
   site, and it is what canonical and og:url carry. */
const m11 = [];
for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  for (const m of html.matchAll(/<a\b([^>]*)>/g)) {
    const attrs = m[1];
    const href = /href="([^"]+)"/.exec(attrs);
    if (!href || !/^https?:\/\//.test(href[1])) continue;
    const host = new URL(href[1]).hostname;
    if (!host.endsWith('.qnero.io') || host === 'www.qnero.io') continue;
    if (attrs.includes('data-m11-host')) m11.push(`${page}: ${href[1]}`);
    else problems.push(`${page}: ${href[1]} is an M11 host and its anchor has no data-m11-host`);
  }
}

/* sitemap.xml is hand-written beside eight hand-written pages, so it drifts the
   moment one is added or renamed and nothing else would notice. */
const sitemap = readFileSync(join(site, 'sitemap.xml'), 'utf8');
const listed = new Set();
for (const m of sitemap.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)) {
  const path = new URL(m[1]).pathname;
  listed.add(path === '/' ? 'index.html' : path.replace(/^\//, ''));
}
const expected = new Set(pages.filter((p) => p !== '404.html'));
for (const page of expected) {
  if (!listed.has(page)) problems.push(`sitemap.xml does not list ${page}`);
}
for (const page of listed) {
  if (!expected.has(page)) problems.push(`sitemap.xml lists ${page}, which is not a page of this site`);
}

/* An absolute qnero.io URL in a meta tag points at a file on this disk, and
   og:image is the one a renamed asset breaks with nothing on the page to show
   for it. */
for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  for (const m of html.matchAll(/content="(https:\/\/qnero\.io[^"]*)"/g)) {
    const path = new URL(m[1]).pathname;
    const target = path === '/' ? 'index.html' : path.replace(/^\//, '');
    if (!existsSync(join(site, target))) {
      problems.push(`${page}: meta URL ${m[1]} points at ${target}, which does not exist`);
    }
  }
}

console.log(`${pages.length} pages, ${external.size} distinct external links`);
for (const [url, n] of [...external].sort()) console.log(`  ${n}x ${url}`);
console.log(`\n${m11.length} M11 host link(s), each labelled "testnet, coming online":`);
for (const entry of m11) console.log(`  ${entry}`);
console.log('  These answer nothing until M11 deploys. Grep data-m11-host to find them all.');

if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('\nno broken internal links, assets or fragments');
