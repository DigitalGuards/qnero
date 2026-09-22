// The browser acceptance for `extrinsicsRoot`: load a built module in headless
// Chromium, initialise it, and assert both known-answer roots.
//
//   node run-extrinsics-root.mjs                      the single-threaded module
//   node run-extrinsics-root.mjs --pkg ./pkg-threaded/qnero_prover_wasm.js
//
// Why a browser and not a Rust test. The Rust tests assert the construction
// and both vectors already. What they cannot say is that the module as built,
// wasm-bindgen'd and optimised still initialises where it runs: binaryen 108,
// which is what some distributions package, emits a module current Chromium
// refuses at `init` with `WebAssembly.Table.grow(): failed to grow table`, and
// nothing before the browser says so. Build with binaryen 116 or newer
// (`cargo install wasm-opt --locked`).
//
// Exit status is the result: 0 when the module initialises and both roots
// match, 1 otherwise.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { serve } from "./server.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const options = {
  pkg: arg("pkg", "./pkg/qnero_prover_wasm.js"),
  timeoutMs: Number(arg("timeout", 120000)),
};

function fixture(path) {
  return JSON.parse(readFileSync(join(repo, path), "utf8"));
}

/** Both known answers, read from the files the Rust tests read. */
const ours = fixture("crates/qnero-state-proof/tests/fixtures/extrinsics_root_kat.json");
const runtime = fixture("chain/runtime/tests/fixtures/extrinsics_root_kat.json");
const vectors = [
  {
    name: "crates/qnero-state-proof/tests/fixtures/extrinsics_root_kat.json",
    extrinsics: ours.extrinsics,
    root: ours.root,
  },
  {
    name: "chain/runtime/tests/fixtures/extrinsics_root_kat.json",
    extrinsics: runtime.extrinsics,
    // The runtime writes its root bare; `extrinsicsRoot` answers with `0x`.
    root: `0x${runtime.extrinsics_root}`,
  },
];

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
  const browser = await chromium.launch({ executablePath, args: ["--no-sandbox", "--disable-gpu"] });
  try {
    browserVersion = browser.version();
    const page = await browser.newPage();
    page.on("console", (message) => {
      if (message.type() === "error") {
        process.stderr.write(`page error: ${message.text()}\n`);
      }
    });
    page.on("pageerror", (error) => process.stderr.write(`page threw: ${error.message}\n`));
    await page.goto(`http://localhost:${port}/extrinsics-root.html`, { waitUntil: "load" });
    await page.waitForFunction(() => globalThis.__qneroExtrinsicsRoot !== undefined, undefined, {
      timeout: options.timeoutMs,
    });
    report = await page.evaluate(
      (request) => globalThis.__qneroExtrinsicsRoot(request),
      { pkgUrl: options.pkg, vectors },
    );
  } finally {
    await browser.close();
  }
} finally {
  server.close();
}

const summary = {
  measured_at: new Date().toISOString(),
  chromium: executablePath.split("/").slice(-3, -2)[0],
  chromium_version: browserVersion,
  ...report,
};
console.log(JSON.stringify(summary, null, 2));

const passed = summary.init === "ok" && summary.vectors.every((row) => row.matches);
if (!passed) {
  process.stderr.write("the module did not answer both known roots\n");
  process.exit(1);
}
