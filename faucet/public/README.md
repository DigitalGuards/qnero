# Public discovery files

Serve `robots.txt` as `text/plain` and `sitemap.xml` as `application/xml` at the
faucet origin through the reverse proxy. Copy these two files only; this README
is deployment guidance. The faucet binary does not mount this directory.

The sitemap lists the public landing page. Robots rules exclude operational
and claim endpoints while leaving the page's scripts, stylesheet and icon
available to crawlers. These rules govern cooperative crawling; access controls
remain the responsibility of the application.

On the landing page response, configure this HTTP header:

```http
Link: <https://faucet.qnero.io/>; rel="canonical"
```

Preserve the existing security headers on the proxied page and the discovery
responses. In nginx, adding an `add_header` inside a location can replace
inherited header directives, so include the complete existing header set there.
Keep API responses outside the sitemap and mark them `X-Robots-Tag: noindex`.

Serving these files and the canonical header requires no faucet rebuild or
process restart. Search engine ownership verification is configured separately.
