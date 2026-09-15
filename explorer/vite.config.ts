import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

/**
 * The policy a host serves this build under, minus the one directive that
 * cannot be the same locally: `connect-src` names the deployed node, and the
 * Playwright suite talks to a dev node on loopback.
 *
 * It lives here so that `vite preview`, which is what the Playwright suite
 * serves the built site with, enforces the real policy. Without it the suite
 * runs under no policy at all and cannot see the failure that matters:
 * `@polkadot/api` calls `cryptoWaitReady()` on connect, `wasm-crypto-init`
 * ships the wasm-only builder, and a policy without `'wasm-unsafe-eval'` makes
 * that call resolve FALSE rather than throw. `ApiPromise` then never emits
 * `ready`, and the page blames the endpoint for a refusal the browser made.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self' ws://127.0.0.1:* ws://localhost:*",
  "img-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join('; ');

// Relative asset URLs, so the built directory works at a domain root and in a
// subdirectory without a rebuild.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: { target: 'es2022', sourcemap: false },
  preview: { headers: { 'Content-Security-Policy': CONTENT_SECURITY_POLICY } },
});
