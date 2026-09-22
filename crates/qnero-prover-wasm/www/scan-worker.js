// The M16 scan worker: call `decryptNote` over and over on one thread and
// report what one ciphertext costs a browser wallet.
//
// Two shapes, because a scan meets both and they cost different things. A
// ciphertext addressed to this wallet decapsulates, opens two AEAD payloads,
// rebuilds the note and hashes its commitment. A ciphertext addressed to
// somebody else decapsulates all the same (ML-KEM answers every ciphertext
// with a shared secret, and a wrong key gives a wrong one), then fails the
// note AEAD's tag and never reaches the memo. The refusal crosses the
// wasm-bindgen boundary as a thrown JsError, and the catch below is inside the
// clock because a real scan loop pays for it too.
//
// A third row times `deriveAccount`, which does the same ML-KEM key
// generation `decryptNote` repeats on every call: this API takes a seed rather
// than a viewing key, so the key tree is rebuilt per ciphertext.

// The module is imported dynamically, because which build is under test is a
// parameter. `./pkg` is the single-threaded module `stage-wasm.sh` ships; a
// `pkg=` on the page's URL points this at another out-dir, which is what the
// M16 run did after the pre-built `pkg` on the bench VM turned out to have
// been through binaryen 108 and to fail at init with
// `WebAssembly.Table.grow(): failed to grow table by 4`.
const DEFAULT_PKG = "./pkg/qnero_prover_wasm.js";

let wasm = null;
let decryptNote = null;
let deriveAccount = null;
let peakLinearMemoryBytes = null;

function memoryBytes() {
  return wasm ? wasm.memory.buffer.byteLength : 0;
}

function progress(stage, detail) {
  postMessage({ type: "progress", stage, detail });
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.substr(index * 2, 2), 16);
  }
  return bytes;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function mean(values) {
  return values.reduce((total, value) => total + value, 0) / values.length;
}

function stderr(values) {
  if (values.length < 2) {
    return 0;
  }
  const average = mean(values);
  const variance =
    values.reduce((total, value) => total + (value - average) ** 2, 0) / (values.length - 1);
  return Math.sqrt(variance / values.length);
}

function percentile(values, fraction) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.round((sorted.length - 1) * fraction)];
}

/**
 * Run `count` timed calls of `body`.
 *
 * Two clocks, deliberately. The per-call samples carry the distribution, and
 * this page is cross-origin isolated so `performance.now` is not coarsened
 * past five microseconds; `total_millis` is the whole loop measured once,
 * which carries no per-sample clock cost at all, and it is the figure the
 * rates below are computed from.
 */
function bench(count, body) {
  for (let index = 0; index < 8; index += 1) {
    body(index);
  }
  const samples = new Array(count);
  const whole = performance.now();
  for (let index = 0; index < count; index += 1) {
    const started = performance.now();
    body(index);
    samples[index] = performance.now() - started;
  }
  const total = performance.now() - whole;
  return {
    count,
    total_millis: Number(total.toFixed(3)),
    per_call_millis: Number((total / count).toFixed(4)),
    per_second: Number((1000 / (total / count)).toFixed(1)),
    mean_millis: Number(mean(samples).toFixed(4)),
    stderr_millis: Number(stderr(samples).toFixed(4)),
    median_millis: Number(median(samples).toFixed(4)),
    p95_millis: Number(percentile(samples, 0.95).toFixed(4)),
    min_millis: Number(Math.min(...samples).toFixed(4)),
    max_millis: Number(Math.max(...samples).toFixed(4)),
  };
}

function report(stage, row) {
  progress(
    stage,
    `${row.count} calls, ${row.per_call_millis.toFixed(3)} ms each, ${row.per_second.toFixed(1)}/s`,
  );
}

async function run(config) {
  const pkgUrl = config.pkgUrl || DEFAULT_PKG;
  progress("wasm_init", pkgUrl);
  const module = await import(pkgUrl);
  decryptNote = module.decryptNote;
  deriveAccount = module.deriveAccount;
  peakLinearMemoryBytes = module.peakLinearMemoryBytes;
  const initStarted = performance.now();
  wasm = await module.default();
  const initMillis = performance.now() - initStarted;
  const memoryAfterInit = memoryBytes();

  progress("fetch_fixture", config.fixtureUrl);
  const response = await fetch(config.fixtureUrl);
  if (!response.ok) {
    throw new Error(
      `${config.fixtureUrl} came back ${response.status}. Run the native M16 scan bench first: ` +
        "it writes the ciphertexts this page loops over.",
    );
  }
  const fixture = await response.json();
  const mine = hexToBytes(fixture.mine_hex);
  const stranger = hexToBytes(fixture.stranger_hex);
  const seed = fixture.wallet_seed;

  // The labels have to be true before the timings mean anything.
  const opened = JSON.parse(decryptNote(seed, mine, ""));
  let strangerRefused = false;
  try {
    decryptNote(seed, stranger, "");
  } catch {
    strangerRefused = true;
  }
  if (!strangerRefused) {
    throw new Error("the stranger's ciphertext opened under this wallet's seed");
  }

  progress("scan_mine");
  const ours = bench(config.iterations, () => decryptNote(seed, mine, ""));
  report("scan_mine", ours);

  progress("scan_stranger");
  const theirs = bench(config.iterations, () => {
    try {
      decryptNote(seed, stranger, "");
      return true;
    } catch {
      return false;
    }
  });
  report("scan_stranger", theirs);

  progress("derive_account");
  const derive = bench(config.deriveIterations, () => deriveAccount(seed));
  report("derive_account", derive);

  return {
    target: "wasm32-unknown-unknown",
    threads: 1,
    pkg: pkgUrl,
    user_agent: navigator.userAgent,
    fixture: {
      url: config.fixtureUrl,
      mine_bytes: fixture.mine_bytes,
      stranger_bytes: fixture.stranger_bytes,
      note_value: opened.value,
    },
    wasm_init_millis: Number(initMillis.toFixed(1)),
    scan_mine: ours,
    scan_stranger: theirs,
    derive_account: derive,
    memory: {
      after_init_bytes: memoryAfterInit,
      final_bytes: memoryBytes(),
      peak_bytes: Math.max(memoryBytes(), peakLinearMemoryBytes()),
    },
  };
}

self.addEventListener("message", (event) => {
  if (event.data?.type !== "run") {
    return;
  }
  run(event.data.config)
    .then((report) => postMessage({ type: "result", report }))
    .catch((error) => {
      postMessage({
        type: "error",
        message: String(error?.message ?? error),
        stack: String(error?.stack ?? ""),
      });
    });
});
