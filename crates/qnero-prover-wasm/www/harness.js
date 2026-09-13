// The page side of the harness: start the worker, show what it reports, and
// leave the finished JSON somewhere a Playwright runner can read it.
//
// Every measurement runs in the worker. A private batch is tens of seconds of
// synchronous wasm, which on the main thread is a frozen tab, and a frozen tab
// on iOS is a tab the OS may reclaim.

const status = document.getElementById("status");
const stages = document.getElementById("stages");
const result = document.getElementById("result");

const params = new URLSearchParams(location.search);
const config = {
  // "artifacts" fetches leaf_verifier.bin and padding_leaf_proof.bin from a
  // set qnero-circuit-builder produced; "source" builds every circuit from the
  // compiled code and fetches nothing.
  mode: params.get("mode") === "source" ? "source" : "artifacts",
  numLeaves: Number(params.get("n") ?? 6),
  // The ZK leaf is the delegated-batcher shape. It builds a second leaf
  // circuit, so it is opt-out.
  zkLeaf: params.get("zk") !== "0",
  // The ZK leaf and nothing else, in a worker that never builds a private
  // batch. That is the run whose peak sizes a delegated leaf-only prover.
  zkOnly: params.get("zkonly") === "1",
  decoys: Number(params.get("decoys") ?? 2),
  artifactBase: "./artifacts/",
};

function line(text) {
  const item = document.createElement("li");
  item.textContent = text;
  stages.append(item);
}

const worker = new Worker("./worker.js", { type: "module" });

worker.addEventListener("message", (event) => {
  const message = event.data;
  if (message.type === "progress") {
    status.textContent = message.stage;
    line(message.detail ? `${message.stage}: ${message.detail}` : message.stage);
    return;
  }
  if (message.type === "result") {
    status.textContent = "done";
    result.textContent = JSON.stringify(message.report, null, 2);
    // Both of these are what the Node runner reads.
    console.log("QNERO_RESULT_JSON " + JSON.stringify(message.report));
    globalThis.__qneroResult = message.report;
    globalThis.__qneroProofBase64 = message.proofBase64;
    return;
  }
  if (message.type === "error") {
    status.textContent = "failed";
    result.textContent = message.message + "\n" + (message.stack ?? "");
    console.log("QNERO_ERROR " + message.message);
    globalThis.__qneroError = message.message;
  }
});

worker.addEventListener("error", (event) => {
  status.textContent = "failed";
  result.textContent = String(event.message ?? event);
  globalThis.__qneroError = String(event.message ?? event);
});

worker.postMessage({ type: "run", config });
