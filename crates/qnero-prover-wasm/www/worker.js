// The worker: build the circuits once, prove one transfer, report what each
// stage cost in wall time and in linear memory.
//
// Memory is read the boring way, from `WebAssembly.Memory.prototype.buffer
// .byteLength`, before and after every stage.
// `performance.measureUserAgentSpecificMemory()` needs cross-origin isolation,
// which this measurement deliberately does not take, and the byteLength is the
// number that matters anyway: wasm linear memory grows and never shrinks, so
// the value after a stage is the high-water mark of everything up to it and it
// stays that way for the life of the worker.

import init, {
  WasmWalletProver,
  chainNumLeaves,
  entropySelfCheck,
  peakLinearMemoryBytes,
  proveZkLeaf,
  syntheticTransferRequest,
} from "./pkg/qnero_prover_wasm.js";

// Fixed seeds, so a rerun measures the same witness. They are fixtures: no
// chain has ever seen the notes they own.
const SENDER_SEED = "31".repeat(32);
const RECIPIENT_SEED = "32".repeat(32);

let wasm = null;

function memoryBytes() {
  return wasm ? wasm.memory.buffer.byteLength : 0;
}

function progress(stage, detail) {
  postMessage({ type: "progress", stage, detail });
}

/** Run one stage, and record what it cost. */
function stage(stages, name, run) {
  progress(name);
  const before = memoryBytes();
  const started = performance.now();
  const value = run();
  const millis = performance.now() - started;
  const after = memoryBytes();
  stages.push({
    stage: name,
    millis,
    memory_before_bytes: before,
    memory_after_bytes: after,
  });
  progress(name, `${millis.toFixed(1)} ms, linear memory ${(after / 1048576).toFixed(1)} MiB`);
  return value;
}

async function fetchBytes(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} came back ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

function base64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

async function run(config) {
  const stages = [];

  progress("wasm_init");
  wasm = await init();
  progress("wasm_init", `module instantiated, linear memory ${(memoryBytes() / 1048576).toFixed(1)} MiB`);
  const memoryAfterInit = memoryBytes();

  // Both entropy paths, before anything offers to prove. A page served from a
  // non-secure context has no crypto.getRandomValues, and without this the
  // failure lands inside plonky2 tens of seconds into the private batch.
  stage(stages, "entropy_self_check", () => entropySelfCheck());

  const numLeaves = config.numLeaves || chainNumLeaves();
  let artifactBytes = { leaf_verifier: 0, padding_leaf_proof: 0 };
  let prover;

  if (config.mode === "artifacts") {
    progress("fetch_artifacts");
    const started = performance.now();
    const [leafVerifier, paddingLeafProof, configJson] = await Promise.all([
      fetchBytes(config.artifactBase + "leaf_verifier.bin"),
      fetchBytes(config.artifactBase + "padding_leaf_proof.bin"),
      fetch(config.artifactBase + "config.json").then((response) => response.json()),
    ]);
    const millis = performance.now() - started;
    artifactBytes = {
      leaf_verifier: leafVerifier.length,
      padding_leaf_proof: paddingLeafProof.length,
    };
    stages.push({
      stage: "fetch_artifacts",
      millis,
      memory_before_bytes: memoryAfterInit,
      memory_after_bytes: memoryBytes(),
    });
    progress("fetch_artifacts", `${leafVerifier.length + paddingLeafProof.length} bytes in ${millis.toFixed(1)} ms`);

    if (configJson.num_leaf_proofs !== numLeaves) {
      // A set built at another N produces proofs whose public-input length the
      // runtime's embedded verifier cannot read, and the rejection arrives
      // only after the whole proving cost has been paid.
      throw new Error(
        `the artifact set is for N = ${configJson.num_leaf_proofs} and this run asked for ${numLeaves}`,
      );
    }

    prover = stage(stages, "circuit_build_from_artifacts", () =>
      WasmWalletProver.fromArtifacts(leafVerifier, paddingLeafProof, numLeaves),
    );
  } else {
    prover = stage(stages, "circuit_build_from_source", () =>
      WasmWalletProver.fromSource(numLeaves),
    );
  }

  const request = stage(stages, "build_request", () =>
    syntheticTransferRequest(SENDER_SEED, RECIPIENT_SEED, config.decoys ?? 2),
  );

  let zkLeaf = null;
  if (config.zkLeaf) {
    // A second leaf circuit, blinded. This is the shape a phone would hand to
    // a batcher it does not run, and it is measured because that path's cost
    // is the only reason to consider its privacy price.
    zkLeaf = JSON.parse(stage(stages, "zk_leaf", () => proveZkLeaf(request)));
  }

  const submission = stage(stages, "prove_transfer", () => prover.proveTransfer(request));
  const report = JSON.parse(submission.reportJson);
  const proof = submission.proof;

  const verifyMillis = stage(stages, "verify_proof", () => prover.verifyProof(proof));

  return {
    target: "wasm32-unknown-unknown",
    threads: 1,
    user_agent: navigator.userAgent,
    mode: config.mode,
    num_leaves: numLeaves,
    artifact_bytes: artifactBytes,
    stages,
    // What the Rust side timed, phase by phase, from inside the module.
    rust_report: report,
    zk_leaf: zkLeaf,
    build_report: JSON.parse(prover.buildReportJson),
    standalone_verify_millis: verifyMillis,
    proof_bytes: proof.length,
    ciphertext_bytes: [submission.ct1.length, submission.ct2.length],
    memory: {
      after_init_bytes: memoryAfterInit,
      final_bytes: memoryBytes(),
      peak_bytes: Math.max(memoryBytes(), peakLinearMemoryBytes()),
    },
    proofBase64: base64(proof),
  };
}

self.addEventListener("message", (event) => {
  if (event.data?.type !== "run") {
    return;
  }
  run(event.data.config)
    .then((report) => {
      const { proofBase64, ...rest } = report;
      postMessage({ type: "result", report: rest, proofBase64 });
    })
    .catch((error) => {
      postMessage({
        type: "error",
        message: String(error?.message ?? error),
        stack: String(error?.stack ?? ""),
      });
    });
});
