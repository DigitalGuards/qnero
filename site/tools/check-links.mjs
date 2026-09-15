/*
 * Walks every HTML file in site/ and checks that each internal link and each
 * referenced asset exists on disk, that every fragment target exists in the
 * page it points at, that sitemap.xml lists exactly the pages that exist, that
 * every absolute qnero.io meta URL resolves to a file, and that every M11
 * subdomain reference, in an anchor or in prose, carries its marker and its
 * "testnet, coming online" label, and that the two light palette blocks in
 * css/site.css still declare the same values.
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

/* The M11 subdomains answer nothing until M11 deploys, so every one of them
   carries `data-m11-host` and the words "testnet, coming online" beside it.
   Checking only the marker would be checking the half a reader never sees, so
   this walks the tags with a stack, takes the marked element's parent, and
   requires the label inside it. A link to one of those hosts that arrives
   without the marker fails too, so a new subdomain cannot be added unlabelled.
   The marker sits on an `<a>` for the three hosts a browser renders and on a
   `<code>` for the RPC endpoint, which is a WebSocket and is not a control.
   The apex is not one of them: it is this site, and it is what canonical and
   og:url carry. */
const LABEL = 'testnet, coming online';
const VOID = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
  'link', 'meta', 'param', 'source', 'track', 'wbr',
]);
const m11 = [];
for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  const stack = [];
  const pending = [];

  for (const m of html.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*)>/g)) {
    const [tag, closing, name, attrs] = [m[0], m[1] === '/', m[2].toLowerCase(), m[3]];

    if (closing) {
      for (let i = stack.length - 1; i >= 0; i -= 1) {
        if (stack[i].name !== name) continue;
        const frame = stack[i];
        const inner = html.slice(frame.contentStart, m.index);
        for (const mark of pending) {
          if (mark.frame === frame) mark.scope = inner;
        }
        stack.length = i;
        break;
      }
      continue;
    }

    const marked = /\sdata-m11-host(?=[\s=]|$)/.test(attrs);
    if (marked) {
      const href = /href="([^"]+)"/.exec(attrs);
      const text = href ? href[1] : null;
      pending.push({ name, href: text, frame: stack[stack.length - 1], scope: null });
    }

    /* An anchor at one of those hosts must be marked, whatever else it is. */
    if (name === 'a') {
      const href = /href="([^"]+)"/.exec(attrs);
      if (href && /^https?:\/\//.test(href[1])) {
        const host = new URL(href[1]).hostname;
        if (host.endsWith('.qnero.io') && host !== 'www.qnero.io' && !marked) {
          problems.push(`${page}: ${href[1]} is an M11 host and its anchor has no data-m11-host`);
        }
      }
    }

    if (!VOID.has(name) && !attrs.trimEnd().endsWith('/')) {
      stack.push({ name, contentStart: m.index + tag.length });
    }
  }

  for (const mark of pending) {
    const inner = mark.scope;
    const what = mark.href || `<${mark.name}> at ${page}`;
    if (inner === null) {
      problems.push(`${page}: ${what} carries data-m11-host but its parent element never closes`);
    } else if (!inner.includes(LABEL)) {
      problems.push(`${page}: ${what} carries data-m11-host but "${LABEL}" is not beside it`);
    } else {
      m11.push(`${page}: ${mark.href || `${mark.name} element`}`);
    }
  }
}

/* An anchor is not the only way to name a subdomain. A hostname in prose or in a
   bare <code> would pass the tag walk above untouched, so every occurrence of
   one in the source is required to sit inside an element that carries the
   marker. That is what makes `grep -rn data-m11-host site/` a complete list on
   the day the hosts go live. */
const HOST = /[a-z0-9-]+\.qnero\.io/g;
const MARKED = /<([a-z]+)([^>]*\sdata-m11-host(?=[\s=>])[^>]*)>([\s\S]*?)<\/\1>/g;
for (const page of pages) {
  const html = readFileSync(join(site, page), 'utf8');
  const covered = [];
  for (const m of html.matchAll(MARKED)) covered.push([m.index, m.index + m[0].length]);
  for (const m of html.matchAll(HOST)) {
    const inside = covered.some(([a, b]) => m.index >= a && m.index < b);
    if (!inside) {
      problems.push(
        `${page}: ${m[0]} is named outside any data-m11-host element, so the M11 grep would miss it`,
      );
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
console.log(`\n${m11.length} M11 host reference(s), each with "${LABEL}" beside it:`);
for (const entry of m11) console.log(`  ${entry}`);
console.log('  These answer nothing until M11 deploys. Grep data-m11-host to find them all.');

if (problems.length) {
  console.error(`\n${problems.length} problem(s):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('\nno broken internal links, assets or fragments');
