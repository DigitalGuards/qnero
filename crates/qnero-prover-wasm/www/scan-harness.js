// The page side of the M16 scan harness. Same shape as `harness.js`: start the
// worker, show what it reports, and leave the finished JSON where a Playwright
// runner can read it.
//
// The measurement runs in the worker for the same reason the prover's does: a
// long synchronous wasm loop on the main thread is a frozen tab.

const status = document.getElementById("status");
const stages = document.getElementById("stages");
const result = document.getElementById("result");

const params = new URLSearchParams(location.search);
const config = {
  // Ciphertexts per shape. The measurement asks for at least 500.
  iterations: Number(params.get("n") ?? 500),
  // How many key derivations to time beside them. It is the same ML-KEM key
  // generation `decryptNote` repeats per ciphertext, so a few hundred pins it.
  deriveIterations: Number(params.get("derive") ?? 200),
  fixtureUrl: params.get("fixture") ?? "./results/m16-scan-ciphertexts.json",
  // Which wasm-bindgen out-dir to measure. The default is the module the
  // wallet ships.
  pkgUrl: params.get("pkg") ?? "./pkg/qnero_prover_wasm.js",
};

function line(text) {
  const item = document.createElement("li");
  item.textContent = text;
  stages.append(item);
}

const worker = new Worker("./scan-worker.js", { type: "module" });

worker.addEventListener("message", (event) => {
  const message = event.data;
  if (message.type === "progress") {
    status.textContent = message.stage;
    line(message.detail ? `${message.stage}: ${message.detail}` : message.stage);
    // Also on the console, so the Node runner can print the stage a failure
    // landed in rather than only the message it failed with.
    console.log(
      "QNERO_SCAN_PROGRESS " + (message.detail ? `${message.stage}: ${message.detail}` : message.stage),
    );
    return;
  }
  if (message.type === "result") {
    status.textContent = "done";
    result.textContent = JSON.stringify(message.report, null, 2);
    console.log("QNERO_SCAN_JSON " + JSON.stringify(message.report));
    globalThis.__qneroScanResult = message.report;
    return;
  }
  if (message.type === "error") {
    status.textContent = "failed";
    result.textContent = message.message + "\n" + (message.stack ?? "");
    console.log("QNERO_ERROR " + message.message);
    globalThis.__qneroScanError = message.message;
  }
});

worker.addEventListener("error", (event) => {
  status.textContent = "failed";
  result.textContent = String(event.message ?? event);
  globalThis.__qneroScanError = String(event.message ?? event);
});

worker.postMessage({ type: "run", config });
