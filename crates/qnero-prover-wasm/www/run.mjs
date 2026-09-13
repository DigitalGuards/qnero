// The Node runner: serve the harness, drive one headless Chromium at a time,
// and print the measurement as JSON.
//
//   node run.mjs                       three runs, artifact mode, ZK leaf on
//   node run.mjs --runs 1 --mode source
//   node run.mjs --no-zk --max-wasm-pages 32768
//
// One browser at a time, closed before the next starts. The measurement is
// single threaded by construction and a second Chromium would be measuring
// contention.

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
  runs: Number(arg("runs", 3)),
  mode: arg("mode", "artifacts"),
  zkLeaf: !process.argv.includes("--no-zk"),
  numLeaves: Number(arg("n", 6)),
  // A V8 flag Chrome for Testing 149 honours, so the wasm memory ceiling this
  // measurement ran under is a stated number rather than "whatever the browser
  // allows". 32768 pages is 2 GiB.
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
    .filter((entry) => entry.startsWith("chromium-"))
    .sort()
    .reverse()
    .map((entry) => join(root, entry, "chrome-linux64", "chrome"));
  if (candidates.length === 0) {
    throw new Error(
      `no chromium in ${root}. Set QNERO_CHROMIUM to a Chromium binary, or install one.`,
    );
  }
  return candidates[0];
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function summarize(values) {
  return {
    median: Number(median(values).toFixed(1)),
    min: Number(Math.min(...values).toFixed(1)),
    max: Number(Math.max(...values).toFixed(1)),
    runs: values.map((value) => Number(value.toFixed(1))),
  };
}

async function runOnce(port, executablePath, index) {
  const browser = await chromium.launch({
    executablePath,
    args: [
      "--no-sandbox",
      "--disable-gpu",
      `--js-flags=--wasm-max-mem-pages=${options.maxWasmPages}`,
    ],
  });
  try {
    const page = await browser.newPage();
    page.on("console", (message) => {
      const text = message.text();
      if (text.startsWith("QNERO_ERROR")) {
        process.stderr.write(text + "\n");
      }
    });
    const query = new URLSearchParams({
      mode: options.mode,
      n: String(options.numLeaves),
      zk: options.zkLeaf ? "1" : "0",
    });
    await page.goto(`http://localhost:${port}/?${query}`, { waitUntil: "load" });
    process.stderr.write(`run ${index + 1}/${options.runs}: proving\n`);
    await page.waitForFunction(
      () => globalThis.__qneroResult !== undefined || globalThis.__qneroError !== undefined,
      undefined,
      { timeout: options.timeoutMs, polling: 1000 },
    );
    const failure = await page.evaluate(() => globalThis.__qneroError);
    if (failure) {
      throw new Error(failure);
    }
    const report = await page.evaluate(() => globalThis.__qneroResult);
    const proofBase64 = await page.evaluate(() => globalThis.__qneroProofBase64);
    return { report, proofBase64 };
  } finally {
    await browser.close();
  }
}

const executablePath = await findChromium();
const { server, port } = await serve(here, 0);
const results = [];
let lastProof = null;

try {
  for (let index = 0; index < options.runs; index += 1) {
    const { report, proofBase64 } = await runOnce(port, executablePath, index);
    results.push(report);
    lastProof = proofBase64;
  }
} finally {
  server.close();
}

// Every stage name any run reported, in the order the first run saw them.
const stageNames = [];
for (const stage of results[0].stages) {
  stageNames.push(stage.stage);
}

const stages = {};
for (const name of stageNames) {
  const values = results.map(
    (report) => report.stages.find((stage) => stage.stage === name)?.millis ?? NaN,
  );
  if (values.some(Number.isNaN)) {
    continue;
  }
  stages[name] = summarize(values);
}

const summary = {
  measured_at: new Date().toISOString(),
  target: "wasm32-unknown-unknown",
  threads: 1,
  // A desktop core under headless Chromium, which is the phone proxy: this box
  // has no aarch64 cross toolchain and no qemu, so a phone CPU is out of
  // reach. docs/BENCH.md states the factor to read these through.
  phone_proxy: true,
  user_agent: results[0].user_agent,
  chromium: executablePath.split("/").slice(-3, -2)[0],
  wasm_max_mem_pages: options.maxWasmPages,
  wasm_memory_ceiling_bytes: options.maxWasmPages * 65536,
  mode: options.mode,
  num_leaves: results[0].num_leaves,
  runs: options.runs,
  proof_bytes: results[0].proof_bytes,
  ciphertext_bytes: results[0].ciphertext_bytes,
  artifact_bytes: results[0].artifact_bytes,
  stages_millis: stages,
  rust_phases_millis: Object.fromEntries(
    results[0].rust_report.phases.map((phase) => [
      phase.phase,
      summarize(
        results.map(
          (report) =>
            report.rust_report.phases.find((other) => other.phase === phase.phase).millis,
        ),
      ),
    ]),
  ),
  zk_leaf_millis: results[0].zk_leaf
    ? {
        build: summarize(results.map((report) => report.zk_leaf.build_millis)),
        prove: summarize(results.map((report) => report.zk_leaf.prove_millis)),
        proof_bytes: results[0].zk_leaf.proof_bytes,
      }
    : null,
  linear_memory_bytes: {
    after_init: summarize(results.map((report) => report.memory.after_init_bytes)),
    peak: summarize(results.map((report) => report.memory.peak_bytes)),
    final: summarize(results.map((report) => report.memory.final_bytes)),
  },
};

const outDir = join(here, "results");
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, "wasm-measurement.json"), JSON.stringify(summary, null, 2));
await writeFile(join(outDir, "runs.json"), JSON.stringify(results, null, 2));
if (lastProof) {
  // The acceptance gate: this is verified natively, against the same artifact
  // set, by `cargo test -p qnero-prover-wasm --test wasm_proof -- --ignored`.
  await writeFile(join(outDir, "private_batch.proof"), Buffer.from(lastProof, "base64"));
}

console.log(JSON.stringify(summary, null, 2));
