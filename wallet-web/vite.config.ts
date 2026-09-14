import tailwindcss from '@tailwindcss/postcss';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

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

export default defineConfig({
  // Relative asset URLs, so the built directory works at a domain root and in
  // a subdirectory with no rebuild.
  base: './',
  plugins: [react()],
  // Tailwind v4 through PostCSS, configured in CSS rather than in a config
  // file, which is how the sibling web wallet builds it.
  css: { postcss: { plugins: [tailwindcss()] } },
  server: { headers: isolation },
  preview: { headers: isolation },
  worker: { format: 'es' },
  build: { target: 'es2022', sourcemap: false },
  // The wasm module and its generated glue are staged into `public/wasm/` by
  // `scripts/stage-wasm.sh` and loaded at runtime, so Vite never parses three
  // megabytes of wasm and the same build serves either module.
  optimizeDeps: { exclude: ['@qnero/prover'] },
});
