import tailwindcss from '@tailwindcss/postcss';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

/**
 * Cross-origin isolation, set now rather than later.
 *
 * COOP `same-origin` plus COEP `require-corp` is what a page needs before
 * `SharedArrayBuffer` exists, and `SharedArrayBuffer` is what a threaded wasm
 * prover needs. The headers also break every cross-origin subresource that
 * does not send CORP, which is why they go in while this app has no third
 * party embeds at all: retrofitting them onto a deployed origin is a change
 * that silently breaks images, fonts and analytics.
 *
 * They are a development and preview convenience here. A real deployment sends
 * them from its own server, and `README.md` says so, because a static host
 * that does not send them falls back to the single-threaded module with no
 * error anywhere.
 */
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

/**
 * The content policy, which is what makes "nothing but the node you configure"
 * a rule rather than a description.
 *
 * This page ships a few hundred npm packages. One compromised release among
 * them reaches the seed at three points: the unlock message into the worker,
 * the create path's seed hex, and the create wizard's own React state. Without
 * a policy, one `fetch` or one `new Image().src=` carries it off the machine
 * and nothing refuses. With this one, every host but the configured node is
 * refused by the browser, whatever the code wanted.
 *
 * Each directive, and why it is what it is:
 *
 * - `default-src 'none'` so anything not listed below is refused rather than
 *   inherited from a permissive default.
 * - `script-src 'self' 'wasm-unsafe-eval'`: the prover is WebAssembly, which
 *   needs the second keyword to compile. No CDN, no inline script.
 * - `style-src 'self' 'unsafe-inline'`: React writes `style` attributes (the
 *   send screen's progress bar) and Radix injects one for its scroll lock.
 *   Inline style attributes have no nonce, so this is the only spelling that
 *   admits them.
 * - `img-src 'self' data:` for the QR codes, which are drawn in the page.
 * - `connect-src 'self' ws: wss:`: the endpoint is chosen at runtime from the
 *   settings screen, so the scheme is the only part that can be pinned here.
 *   The settings screen refuses anything but `ws`/`wss`, and this still
 *   refuses every `http(s)` destination, which is every exfiltration path a
 *   compromised dependency would reach for.
 * - `worker-src 'self' blob:`: the prover worker and, in the threaded module,
 *   rayon's pool workers.
 * - `base-uri 'none'` and `form-action 'none'`: this app has neither.
 *
 * `frame-ancestors` is ignored in a `<meta>` element, so it is sent as a
 * header and left out of the tag rather than logged as a warning on every
 * load.
 */
const CSP_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' ws: wss:",
  "worker-src 'self' blob:",
  "base-uri 'none'",
  "form-action 'none'",
];

/** What the built `index.html` carries, so a static host needs no config. */
export const CONTENT_SECURITY_POLICY = CSP_DIRECTIVES.join('; ');

/** What a server sends. A header can say what a meta tag cannot. */
const CSP_HEADER = `${CONTENT_SECURITY_POLICY}; frame-ancestors 'none'`;

/**
 * The dev server's policy.
 *
 * `@vitejs/plugin-react` injects the refresh preamble as an inline module
 * script, so a dev server sending the built policy serves a page that cannot
 * start. The relaxation is exactly that one keyword, and it is named here so
 * nobody copies this variant onto a host.
 */
const CSP_HEADER_DEV = CSP_HEADER.replace(
  "script-src 'self'",
  "script-src 'self' 'unsafe-inline'",
);

/** Put the policy in the built HTML, where it travels with the files. */
function contentSecurityPolicy(): Plugin {
  return {
    name: 'qnero-content-security-policy',
    apply: 'build',
    transformIndexHtml(html) {
      return {
        html,
        tags: [
          {
            tag: 'meta',
            attrs: { 'http-equiv': 'Content-Security-Policy', content: CONTENT_SECURITY_POLICY },
            injectTo: 'head-prepend',
          },
        ],
      };
    },
  };
}

export default defineConfig({
  // Relative asset URLs, so the built directory works at a domain root and in
  // a subdirectory with no rebuild.
  base: './',
  plugins: [react(), contentSecurityPolicy()],
  // Tailwind v4 through PostCSS, configured in CSS rather than in a config
  // file, which is how the sibling web wallet builds it.
  css: { postcss: { plugins: [tailwindcss()] } },
  server: { headers: { ...isolation, 'Content-Security-Policy': CSP_HEADER_DEV } },
  preview: { headers: { ...isolation, 'Content-Security-Policy': CSP_HEADER } },
  worker: { format: 'es' },
  build: { target: 'es2022', sourcemap: false },
  // The wasm module and its generated glue are staged into `public/wasm/` by
  // `scripts/stage-wasm.sh` and loaded at runtime, so Vite never parses three
  // megabytes of wasm and the same build serves either module.
  optimizeDeps: { exclude: ['@qnero/prover'] },
});
