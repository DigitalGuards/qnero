// The M16 scan runner: serve the harness, drive one headless Chromium, and
// print what one ciphertext costs a browser wallet as JSON.
//
//   node run-scan.mjs                       500 ciphertexts per shape
//   node run-scan.mjs --n 2000 --derive 500
//
// It reads the two fixture ciphertexts the native bench writes, so run that
// first:
//
//   RAYON_NUM_THREADS=1 cargo test --release -p qnero-prover-wasm \
//     --test m16_scan_bench -- --ignored --nocapture --test-threads 1
//
// One browser, one worker, one thread. `run.mjs` is the prover's runner and
// this is deliberately a second file: it shares the server and the browser
// discovery and nothing else, and a flag that changed the prover's invocation
// shape would change which file M8's rows came from.

import { mkdir, writeFile } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { serve } from "./server.mjs";

const here = dirname(fileURLToPath(import.meta.url));

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const options = {
  iterations: Number(arg("n", 500)),
  deriveIterations: Number(arg("derive", 200)),
  // Which wasm-bindgen out-dir to measure, relative to this directory.
  pkg: arg("pkg", "./pkg/qnero_prover_wasm.js"),
  maxWasmPages: Number(arg("max-wasm-pages", 32768)),
  timeoutMs: Number(arg("timeout", 600000)),
};

/** The Chromium in Playwright's cache, without downloading one. */
async function findChromium() {
  if (process.env.QNERO_CHROMIUM) {
    return process.env.QNERO_CHROMIUM;
  }
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH ?? join(homedir(), ".cache", "ms-playwright");
  const entries = await readdir(root).catch(() => []);
  const candidates = entries
    .filter((entry) => /^chromium-\d+$/.test(entry))
    .sort((a, b) => Number(a.slice("chromium-".length)) - Number(b.slice("chromium-".length)))
    .reverse()
    .map((entry) => join(root, entry, "chrome-linux64", "chrome"));
  if (candidates.length === 0) {
    throw new Error(
      `no chromium in ${root}. Set QNERO_CHROMIUM to a Chromium binary, or install one.`,
    );
  }
  return candidates[0];
}

const executablePath = await findChromium();
const { server, port } = await serve(here, 0);
let report = null;
let browserVersion = null;

try {
  const browser = await chromium.launch({
    executablePath,
    args: [
      "--no-sandbox",
      "--disable-gpu",
      `--js-flags=--wasm-max-mem-pages=${options.maxWasmPages}`,
    ],
  });
  try {
    browserVersion = browser.version();
    const page = await browser.newPage();
    page.on("console", (message) => {
      const text = message.text();
      if (text.startsWith("QNERO_ERROR") || text.startsWith("QNERO_SCAN_PROGRESS")) {
        process.stderr.write(text + "\n");
      }
    });
    const query = new URLSearchParams({
      n: String(options.iterations),
      derive: String(options.deriveIterations),
      pkg: options.pkg,
    });
    await page.goto(`http://localhost:${port}/scan.html?${query}`, { waitUntil: "load" });
    process.stderr.write(`scanning ${options.iterations} ciphertexts per shape\n`);
    await page.waitForFunction(
      () => globalThis.__qneroScanResult !== undefined || globalThis.__qneroScanError !== undefined,
      undefined,
      { timeout: options.timeoutMs, polling: 500 },
    );
    const failure = await page.evaluate(() => globalThis.__qneroScanError);
    if (failure) {
      throw new Error(failure);
    }
    report = await page.evaluate(() => globalThis.__qneroScanResult);
  } finally {
    await browser.close();
  }
} finally {
  server.close();
}

const summary = {
  measured_at: new Date().toISOString(),
  invocation: ["node", "run-scan.mjs", ...process.argv.slice(2)].join(" "),
  chromium: executablePath.split("/").slice(-3, -2)[0],
  chromium_version: browserVersion,
  wasm_max_mem_pages: options.maxWasmPages,
  ...report,
};

const outDir = join(here, "results");
await mkdir(outDir, { recursive: true });
const path = join(outDir, `m16-scan-n${options.iterations}.json`);
await writeFile(path, JSON.stringify(summary, null, 2));
process.stderr.write(`wrote ${path}\n`);

console.log(JSON.stringify(summary, null, 2));
