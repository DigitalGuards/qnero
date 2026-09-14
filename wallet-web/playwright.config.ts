import { defineConfig, devices } from '@playwright/test';

/**
 * One browser, one worker, one dev chain.
 *
 * `fullyParallel` is off and `workers` is one because the suite proves in the
 * browser: a wasm prover holds most of a gigabyte of linear memory and a
 * second one beside it on this workstation is the machine. The timeout is
 * generous for the same reason. A payment is a circuit build and two proofs,
 * and the whole point of the M8 measurement is that this is tens of seconds
 * rather than milliseconds.
 *
 * The preview server sends COOP `same-origin` and COEP `require-corp`
 * (`vite.config.ts`), so the page is cross-origin isolated and the threaded
 * module is the one under test. `QNERO_PROVER=single` makes the page
 * take the single-threaded path instead, which is how both rows in
 * `docs/BENCH.md` are measured with one suite.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 900_000,
  expect: { timeout: 60_000 },
  reporter: [['list']],
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'off',
    video: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'nice -n 19 npm run build && nice -n 19 npx vite preview --port 4173 --strictPort',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 300_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
