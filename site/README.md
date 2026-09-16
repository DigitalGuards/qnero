# qnero.io

The project site. Eight pages of hand-written HTML, one stylesheet, two small
scripts, three images. There is no build step, no framework, no package.json, no
font download, no analytics and no third-party request of any kind, which is
the rule the explorer states for itself and the rule this site lives by.

```
site/
  index.html          how-it-works.html   wallet.html     mine.html
  explorer.html       docs.html           about.html      404.html
  css/site.css        one stylesheet, tokens first
  js/theme.js         the stored theme, applied before the first paint
  js/site.js          the theme toggle, and nothing else
  img/favicon.svg     img/favicon-32.png  img/og.png
  robots.txt          sitemap.xml         NOTICE
  tools/              the open-graph template and its renderer, kept out of the deploy
```

## Deploy

Copy the eight pages, `css/`, `js/`, `img/`, `robots.txt` and `sitemap.xml`.
`tools/`, `README.md` and `NOTICE` are repository files and are not served: the
nginx block below returns 404 for `/tools/`, and a host with no rewrite layer
needs the payload named instead.

```
rsync -a --delete \
  --exclude tools/ --exclude README.md --exclude NOTICE \
  site/ user@host:/path/to/webroot/
```

```nginx
server {
    listen 443 ssl;
    server_name qnero.io;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    root /path/to/webroot;
    index index.html;

    # Optional: serve /wallet as well as /wallet.html. Every internal link
    # carries the extension, so the site works with this block absent.
    location / {
        try_files $uri $uri.html $uri/ =404;
    }

    error_page 404 /404.html;

    location = /404.html {
        internal;
    }

    # `svg` and `png` only. `css/site.css` and the two scripts carry no
    # fingerprint and no version query, and there is no build step to give them
    # one, so a long max-age serves a returning reader new HTML against a
    # stylesheet their browser will not re-fetch for a week. They fall through
    # to nginx's ETag and Last-Modified, which revalidate on every load and cost
    # one 304.
    location ~* \.(svg|png)$ {
        add_header Cache-Control "public, max-age=604800";
    }

    location /tools/ {
        return 404;
    }
}
```

Every host, path and certificate above is a placeholder. The site makes no
outbound request, so no content policy of its own is required; a host that
sends one can send `default-src 'none'; style-src 'self'; script-src 'self';
img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
and the pages still render, with the stored theme intact. That policy is the
reason there is no inline script and no inline style anywhere in the eight
files: `script-src 'self'` would block an inline theme bootstrap and discard a
reader's choice on every load, silently and with no visible failure.

Redirect `www` to the apex, and serve `404.html` for anything missing.

`site/` reaches `origin/main` before the site is served anywhere. `about.html`
links `site/NOTICE` on GitHub, and that is the one link whose job is to back the
BSD-3-Clause attribution, so a deploy from an unpushed tree answers 404 on it.
No gate catches this: the link checker makes no network request, by design.
Check it by hand with `git cat-file -e origin/main:site/NOTICE` before serving.

## Editing

Each page carries its own copy of the shell: the status strip, the header and
nav, and the footer. A change to any of the three is a change to all eight
files. That is the price of having no build step, and it is deliberate: what is
in the repository is exactly what is served.

The shell has a fixed shape below 641 px: a 24 px status strip, a 44 px row
holding the wordmark and a 32 px theme control, and a 44 px row holding six
links. The nav carries roles, `Wallet` and `Explorer`, because the reader meets
the names Qloak and silQ Road on those pages; `GitHub` is hidden at that width
and reached through the footer. The six labels measure 312 px in the 335 px
column at 375 px and 277 px in the 280 px column at 320 px, where the gap
tightens to 8 px, so a seventh link or a longer label wraps the row and has to
be paid for somewhere else.

The wordmark renders once per page. No h1 repeats it: the index h1 is the
proposition, and every other h1 names its page.

`css/site.css` starts with the token block. The values match
`explorer/src/styles/tokens.css` and `wallet-web/src/styles/tokens.css`, so the
site, silQ Road and Qloak read as one project. Dark is the default. The light
palette is redefined under `prefers-color-scheme: light` and again under
`[data-theme='light']`, so the toggle wins in both directions.

Every page carries `<link rel="stylesheet">` and two `<script src>` tags and
no inline block of either, which is what keeps the content policy above true.

Every claim and every number on these pages comes from `README.md`,
`docs/DESIGN.md`, `docs/BENCH.md`, `docs/CIRCUIT.md` or `chain/MINING.md`. A
figure with no source in those files does not belong on the site. The status
strip is the first line on every page, one line at 375 px and at most 60
characters, and says the same three things: pre-alpha, a public testnet that
may be reset, and no part of Qnero's own code audited. It reads
"Pre-alpha. Public testnet, may be reset. Unaudited." Change the sentence and
the strip has to stay one line; `.status-strip p` holds it to one with
`white-space: nowrap`.

## Images

`img/og.png` is rendered from `tools/og-template.html`, and `img/favicon-32.png`
from `img/favicon.svg`, by one headless Chromium:

```
node site/tools/make-images.mjs
```

Playwright is resolved from `explorer/node_modules`, so the site keeps no
dependencies of its own. Set `PLAYWRIGHT_FROM` to another `package.json` to
resolve it elsewhere. Edit the template and re-run to change the card.

## Checks

```
npx html-validate site/*.html
node site/tools/check-links.mjs
python3 -m http.server 8931 -d site &   # check-layout.mjs needs the site served
node site/tools/check-layout.mjs
grep -rnP '\x{2014}' site/ && echo 'em dash found'
```

The link checker walks every internal link and asset reference and reports
anything missing, asserts that `sitemap.xml` lists exactly the pages that
exist, and resolves every absolute `qnero.io` URL in a meta tag against disk.

`check-layout.mjs` measures the rendered pages in a headless browser at 320,
400 and 1280 px and fails on two things a stylesheet comment cannot enforce: a
page that scrolls sideways, and an inline `code` chip wider than the box holding
it. What it does not measure, and what a change to the shell has to be checked
against by hand, is the phone header: one wordmark, one nav row, 116 px of
chrome above the first content edge, and the page's primary button inside the
first screen. It needs the site served on port 8931, which is what the line above it does,
and it resolves Playwright from `explorer/node_modules` the way
`tools/make-images.mjs` does.

**The testnet hosts are linked.** `wallet.qnero.io`, `explorer.qnero.io` and
`faucet.qnero.io` are anchors, and `wss://rpc.qnero.io` and
`node.qnero.io:3333` are `code` chips, because an endpoint a rig or a wallet is
configured with is an address a reader copies rather than a control a browser
can follow. Each carries its state beside it in a `.tag`.

Every page that has a live thing to open leads with one amber primary that
opens it, and one ghost `Source` after it: index "Open the wallet", wallet
"Open wallet.qnero.io", explorer "Open explorer.qnero.io", mine "Get testnet
QNR". `.hostline` is the mono caption under that button and is reserved for
hosts; nothing else takes it.

They were plain unlinked hostnames until the testnet was deployed, marked with
`data-m11-host` so that the checker could fail any `*.qnero.io` occurrence
outside such an element and `grep -rn data-m11-host site/` was the complete
list to unwrap on launch day. That rule is gone with the launch it was written
for: the same check now forbids the links the site is supposed to carry.
Whether these hosts actually answer is the external watchdog's job, and it
asks them rather than reading the HTML.

`sitemap.xml` carries a hand-written `lastmod` on each page. Bump it when the
content changes; nothing derives it, because nothing builds.

## Licence

Qnero is MIT licensed. The site's design provenance is in `NOTICE`, and the
about page carries the same notice where a reader of the published site
reaches it.
