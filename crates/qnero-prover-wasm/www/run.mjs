// The Node runner: serve the harness, drive one headless Chromium at a time,
// and print the measurement as JSON.
//
//   node run.mjs                       three runs, artifact mode, ZK leaf on
//   node run.mjs --runs 1 --mode source
//   node run.mjs --no-zk --max-wasm-pages 32768
//   node run.mjs --runs 9 --mode source --no-zk      the per-payment figures
//   node run.mjs --runs 3 --zk-only                  a leaf-only prover's own peak
//   node run.mjs --runs 1 --mode source --no-zk --n 7
//
// Every row in docs/BENCH.md's M8 tables names the invocation it came from.
// Stage timings from two different invocations are two different measurements.
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
  // The ZK leaf on its own, in a worker that builds nothing else. That is the
  // only run whose memory figure sizes a delegated leaf-only prover: in a
  // normal run the private-batch circuit is already resident and linear memory
  // never shrinks, so the module's high-water mark is the batch's.
  zkOnly: process.argv.includes("--zk-only"),
  numLeaves: Number(arg("n", 6)),

  // A V8 flag Chrome for Testing 149 honours, so the wasm memory ceiling this
  // measurement ran under is a stated number rather than "whatever the browser
  // allows". 32768 pages is 2 GiB.
  maxWasmPages: Number(arg("max-wasm-pages", 32768)),
  timeoutMs: Number(arg("timeout", 600000)),
};

// A leaf-only run fetches nothing, so it is a source-mode run whatever the
// default says. Naming it otherwise would label its results file with an
// artifact set it never read.
if (options.zkOnly) {
  options.mode = "source";
}

/** The Chromium in Playwright's cache, without downloading one. */
async function findChromium() {
  if (process.env.QNERO_CHROMIUM) {
    return process.env.QNERO_CHROMIUM;
  }
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH ?? join(homedir(), ".cache", "ms-playwright");
  const entries = await readdir(root).catch(() => []);
  // Numeric, and numeric revisions only. A string sort puts "chromium-999"
  // after "chromium-1228", and Playwright's `chromium-tip-of-tree-<rev>` passes
  // a `chromium-` prefix test and sorts after every digit, so either one would
  // quietly move the measurement to a different browser.
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

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  // Average the two middle samples on an even count. Taking the upper one
  // biases every figure upward, and the tables call this column a median.
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function mean(values) {
  return values.reduce((total, value) => total + value, 0) / values.length;
}

/** The standard error of the mean: how well this sample pins its own mean. */
function stderr(values) {
  if (values.length < 2) {
    return 0;
  }
  const average = mean(values);
  const variance =
    values.reduce((total, value) => total + (value - average) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance / values.length);
}

function summarize(values) {
  return {
    // The mean is here for the leaf. Its FRI challenge carries 16 grinding
    // bits and the search for them is a geometric random variable, and every
    // `prepare` randomizes the dummy input, so each leaf grinds a different
    // transcript and a median over a few samples hides that. docs/BENCH.md
    // compares means for that stage, and reads them against `stderr`: nine
    // samples of the leaf still leave several percent on the mean, which is
    // why its wasm/native ratio is published as a range.
    mean: Number(mean(values).toFixed(1)),
    stderr: Number(stderr(values).toFixed(1)),
    median: Number(median(values).toFixed(1)),
    min: Number(Math.min(...values).toFixed(1)),
    max: Number(Math.max(...values).toFixed(1)),
    runs: values.map((value) => Number(value.toFixed(1))),
  };
}

let browserVersion = null;

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
    // The full browser version, so a rerun on a different Chromium is visible
    // in the results rather than only in a cache directory name.
    browserVersion = browser.version();
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
      zk: options.zkLeaf || options.zkOnly ? "1" : "0",
      zkonly: options.zkOnly ? "1" : "0",
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
  chromium_version: browserVersion,
  // The exact invocation, so a row in a table can be tied back to the run that
  // produced it.
  invocation: ["node", "run.mjs", ...process.argv.slice(2)].join(" "),
  wasm_max_mem_pages: options.maxWasmPages,
  wasm_memory_ceiling_bytes: options.maxWasmPages * 65536,
  mode: options.mode,
  num_leaves: results[0].num_leaves,
  runs: options.runs,
  proof_bytes: results[0].proof_bytes,
  ciphertext_bytes: results[0].ciphertext_bytes,
  // The Rust-side verify, timed inside the module with deserialization
  // outside the clock, and the second verify the module executes. The
  // `private_batch_verify` phase in `rust_phases_millis` is the first one,
  // which is what a cold V8 charges for the same call. Both are published.
  standalone_verify_millis: results[0].standalone_verify_millis
    ? summarize(results.map((report) => report.standalone_verify_millis))
    : null,
  artifact_bytes: results[0].artifact_bytes,
  stages_millis: stages,
  module_bytes: results[0].module_bytes,
  zk_only: Boolean(results[0].zk_only),
  rust_phases_millis: results[0].rust_report
    ? Object.fromEntries(
        results[0].rust_report.phases.map((phase) => [
          phase.phase,
          summarize(
            results.map(
              (report) =>
                report.rust_report.phases.find((other) => other.phase === phase.phase).millis,
            ),
          ),
        ]),
      )
    : null,
  zk_leaf_millis: results[0].zk_leaf
    ? {
        build: summarize(results.map((report) => report.zk_leaf.build_millis)),
        prove: summarize(results.map((report) => report.zk_leaf.prove_millis)),
        proof_bytes: results[0].zk_leaf.proof_bytes,
        degree_bits: results[0].zk_leaf.degree_bits,
        // In a normal run this counts the private-batch circuit that is
        // already resident. `--zk-only` is the run where it does not.
        peak_bytes_since_init: summarize(
          results.map((report) => report.zk_leaf.peak_linear_memory_bytes_since_init),
        ),
        growth_bytes: summarize(
          results.map((report) => report.zk_leaf.linear_memory_growth_bytes),
        ),
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
// One name per invocation shape, and no fixed name at all. A fixed name is how
// a run at another `N` hands the acceptance gate a proof the gate's own
// verifier cannot read, and the gate's failure carries no hint of which run
// wrote the file: it reads as a feature-graph divergence.
const tag = [
  options.mode,
  `n${options.numLeaves}`,
  options.zkOnly ? "zkonly" : options.zkLeaf ? "zk" : "nozk",
  `x${options.runs}`,
].join("-");
const measurementPath = join(outDir, `wasm-measurement-${tag}.json`);
await writeFile(measurementPath, JSON.stringify(summary, null, 2));
await writeFile(join(outDir, `runs-${tag}.json`), JSON.stringify(results, null, 2));
let proofPath = null;
if (lastProof) {
  // The acceptance gate reads this exact path, which names the `N` it was
  // proved at:
  //   QNERO_WASM_PROOF=www/results/private_batch-<tag>.proof \
  //   QNERO_ARTIFACT_DIR=www/artifacts \
  //     cargo test -p qnero-prover-wasm --release --test wasm_proof \
  //       -- --ignored --nocapture
  proofPath = join(outDir, `private_batch-${tag}.proof`);
  await writeFile(proofPath, Buffer.from(lastProof, "base64"));
}
process.stderr.write(`wrote ${measurementPath}\n`);
if (proofPath) {
  process.stderr.write(`wrote ${proofPath}\n`);
}

console.log(JSON.stringify(summary, null, 2));
