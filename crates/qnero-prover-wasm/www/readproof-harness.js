// The M16 read-proof harness: call `readStateProof` over and over on one
// thread and report what one page of authenticated reads costs a browser
// wallet.
//
// Main thread rather than a worker, because one call here is milliseconds
// where one prove is tens of seconds, and the wallet's own verification worker
// runs the identical module. The module is imported dynamically so the build
// under test is a parameter, the way `scan-worker.js` takes one.

const status = document.getElementById("status");
const result = document.getElementById("result");

const params = new URLSearchParams(location.search);
const config = {
  iterations: Number(params.get("n") ?? 50),
  dir: params.get("dir") ?? "./results/m16-readproof",
  pkgUrl: params.get("pkg") ?? "./pkg/qnero_prover_wasm.js",
};

// Three windows per map: `head` is the first indices in the tree, which on
// this dev chain are coinbase leaves with no ciphertext; `tail` is the last
// indices in the tree; `settled` ends on the newest leaf whose ciphertext is
// still inside the runtime's retention window, which is the shape a wallet
// scanning a settlement reads.
const CASES = [
  "zktree_leaves_head_64",
  "zktree_leaves_head_16",
  "zktree_leaves_tail_64",
  "zktree_leaves_tail_16",
  "zktree_leaves_settled_64",
  "zktree_leaves_settled_16",
  "shielded_ciphertexts_head_64",
  "shielded_ciphertexts_head_16",
  "shielded_ciphertexts_tail_64",
  "shielded_ciphertexts_tail_16",
  "shielded_ciphertexts_settled_64",
  "shielded_ciphertexts_settled_16",
];

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

try {
  status.textContent = "loading the module";
  const module = await import(config.pkgUrl);
  const initStarted = performance.now();
  const wasm = await module.default();
  const initMillis = performance.now() - initStarted;
  const readStateProof = module.readStateProof;

  const rows = [];
  for (const name of CASES) {
    status.textContent = `verifying ${name}`;
    const request = await (await fetch(`${config.dir}/${name}.json`)).json();
    const json = JSON.stringify(request);
    // One call outside the clock, so the reported median is not the first
    // call's code-generation and page-fault cost.
    const values = JSON.parse(readStateProof(json));
    const samples = [];
    for (let index = 0; index < config.iterations; index += 1) {
      const started = performance.now();
      const read = readStateProof(json);
      if (read.length === 0) {
        throw new Error("empty answer");
      }
      samples.push(performance.now() - started);
    }
    rows.push({
      case: name,
      keys: request.keys.length,
      proof_nodes: request.nodes.length,
      proof_bytes: request.nodes.reduce(
        (sum, node) => sum + (node.length - (node.startsWith("0x") ? 2 : 0)) / 2,
        0,
      ),
      values_present: values.filter((value) => value !== null).length,
      samples: samples.length,
      median_millis: Number(median(samples).toFixed(4)),
      min_millis: Number(Math.min(...samples).toFixed(4)),
      max_millis: Number(Math.max(...samples).toFixed(4)),
    });
  }

  const report = {
    target: "wasm32-unknown-unknown",
    threads: 1,
    pkg: config.pkgUrl,
    user_agent: navigator.userAgent,
    wasm_init_millis: Number(initMillis.toFixed(1)),
    linear_memory_bytes: wasm.memory.buffer.byteLength,
    rows,
  };
  status.textContent = "done";
  result.textContent = JSON.stringify(report, null, 2);
  console.log("QNERO_READPROOF_JSON " + JSON.stringify(report));
  globalThis.__qneroReadProofResult = report;
} catch (error) {
  status.textContent = "failed";
  result.textContent = String(error && error.stack ? error.stack : error);
  console.log("QNERO_ERROR " + String(error));
  globalThis.__qneroReadProofError = String(error);
}
