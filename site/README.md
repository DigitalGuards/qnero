# qnero.io

The project site. Eight pages of hand-written HTML, one stylesheet, one small
script, two images. There is no build step, no framework, no package.json, no
font download, no analytics and no third-party request of any kind, which is
the rule the explorer states for itself and the rule this site lives by.

```
site/
  index.html          how-it-works.html   wallet.html     mine.html
  explorer.html       docs.html           about.html      404.html
  css/site.css        one stylesheet, tokens first
  js/site.js          the theme toggle, and nothing else
  img/favicon.svg     img/favicon-32.png  img/og.png
  robots.txt          sitemap.xml         NOTICE
  tools/              the open-graph template and its renderer, kept out of the deploy
```

## Deploy

Copy the files. Any static host serves them.

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

    location ~* \.(css|js|svg|png)$ {
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
and the pages still render.

Redirect `www` to the apex, and serve `404.html` for anything missing.

## Editing

Each page carries its own copy of the shell: the status strip, the header and
nav, and the footer. A change to any of the three is a change to all eight
files. That is the price of having no build step, and it is deliberate: what is
in the repository is exactly what is served.

`css/site.css` starts with the token block. The values match
`explorer/src/styles/tokens.css` and `wallet-web/src/styles/tokens.css`, so the
site, silQ Road and Qloak read as one project. Dark is the default. The light
palette is redefined under `prefers-color-scheme: light` and again under
`[data-theme='light']`, so the toggle wins in both directions.

Every claim and every number on these pages comes from `README.md`,
`docs/DESIGN.md`, `docs/BENCH.md`, `docs/CIRCUIT.md` or `chain/MINING.md`. A
figure with no source in those files does not belong on the site. The status
disclosure sits above the fold on every page and says the same three things:
pre-alpha, devnet only, and no part of Qnero's own code has been audited.

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
grep -rnP '\x{2014}' site/ && echo 'em dash found'
```

The link checker walks every internal link and asset reference and reports
anything missing. The `qnero.io` subdomains are labelled "testnet, coming
online" on the pages and answer nothing yet, which is why they are written as
plain text on the page and carry no link.

## Licence

Qnero is MIT licensed. The site's design provenance is in `NOTICE`, and the
about page carries the same notice where a reader of the published site
reaches it.
