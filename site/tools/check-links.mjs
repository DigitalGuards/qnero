/*
 * Walks every HTML file in site/ and checks that each internal link and each
 * referenced asset exists on disk, that every fragment target exists in the
 * page it points at, that sitemap.xml lists exactly the pages that exist, that
 * every absolute qnero.io meta URL resolves to a file, and that the two light
 * palette blocks in css/site.css still declare the same values.
 *
 * The rule that every `*.qnero.io` reference had to sit inside a
 * `data-m11-host` element beside the words "testnet, coming online" is gone,
 * and the hosts it protected are the reason. It existed so that a link which
 * 404s could not be shipped before the testnet was deployed, and so that
 * `grep -rn data-m11-host site/` was the complete list of what to unwrap on
 * launch day. The testnet is deployed, the four names answer, and the same
 * rule now forbids the links the site is supposed to carry. What replaces it
 * is the external watchdog: the hosts are checked by request rather than by
 * regular expression.
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

/* The light palette is declared twice, once for a system preference and once
   for the toggle, and nothing else notices when an edit lands in one copy only.
   The failure is invisible to anyone whose OS theme already matches their
   toggle, so it is asserted here. */
{
  const css = readFileSync(join(site, 'css/site.css'), 'utf8');
  const block = (start) => {
    const at = css.indexOf(start);
    if (at < 0) return null;
    const open = css.indexOf('{', at + start.length - 1);
    let depth = 0;
    let i = open;
    for (; i < css.length; i += 1) {
      if (css[i] === '{') depth += 1;
      else if (css[i] === '}') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    const body = css.slice(open + 1, i);
    const decls = new Map();
    for (const m of body.matchAll(/(--[\w-]+|color-scheme)\s*:\s*([^;]+);/g)) {
      decls.set(m[1], m[2].trim());
    }
    return decls;
  };
  const media = block(":root:not([data-theme='dark'])");
  const toggle = block(":root[data-theme='light']");
  if (!media || !toggle) {
    problems.push('css/site.css: one of the two light palette blocks is missing');
  } else {
    for (const [name, value] of media) {
      if (!toggle.has(name)) problems.push(`css/site.css: ${name} is in the system light palette and not in the toggled one`);
      else if (toggle.get(name) !== value) {
        problems.push(`css/site.css: ${name} is ${value} in the system light palette and ${toggle.get(name)} in the toggled one`);
      }
    }
    for (const name of toggle.keys()) {
      if (!media.has(name)) problems.push(`css/site.css: ${name} is in the toggled light palette and not in the system one`);
    }
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
if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('\nno broken internal links, assets or fragments');
