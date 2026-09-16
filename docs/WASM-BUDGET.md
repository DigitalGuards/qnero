# Runtime WASM budget qualification

`chain/runtime/examples/shielded_budget.rs` runs bounded, valid-proof component
measurements through `sc_executor::WasmExecutor` using the node's Wasmtime
`PoolingCopyOnWrite` backend and `sp_io::SubstrateHostFunctions`. Native execution
is refused. This measures the runtime compilation of the verifier and pallet
components, including the embedded verifier artifacts.

The separate `shielded-budget-bench` runtime feature adds the measurement exports.
It registers no node RPC and is incompatible with `on-chain-release-build`.
Production runtimes omit these exports. Every report records the exact benchmark
WASM hash and protocol profile, so its identity is explicit.

## Run offline

Build and run from `chain/`, using a valid private-batch proof generated for the
supported six-leaf release profile. `--wasm` may select an independently built
benchmark-feature runtime; otherwise the example uses its freshly built runtime.

```sh
RAYON_NUM_THREADS=4 CARGO_BUILD_JOBS=2 taskset -c 0-7 nice -n 19 \
  cargo run --release -p qnero-runtime --example shielded-budget \
  --features shielded-budget-bench -- \
  --private-proof /path/to/private_batch.proof --runs 9 > wasm-budget.json
```

Add `--public-proof /path/to/public_batch.proof` to qualify the 53-inner public
verifier. A verifier artifact is insufficient: the file must contain a valid
public proof. Parsing and verification failures abort the run. The harness does
not submit transactions, start a node, mine, or contact a network.

## Measurements and gates

The first `Core_version` call reports cold module compilation separately. Each
component then reports its first call, repeated calls with the executor module
cache warm, median, p95 and maximum. The maximum includes the first call. Budgets
are returned by the measured runtime in reference-time picoseconds; a measured
component exceeding its declared budget makes the process exit unsuccessfully.
Artifact-only load rows are informational and carry no independent weight gate.

| Component | Covered work |
| --- | --- |
| Private/public artifact load | Embedded artifact deserialization and profile validation |
| Private/public parse | Canonical proof decode, round trip and public-input parsing |
| Private/public parse and verify | The pallet's exact verifier path, once or twice in one runtime call |
| Payload digest | Both inclusion checks, at one slot and the maximum public-batch slot count, with maximum ciphertext lengths |
| Retention hook | The full bounded cleanup pass over expired ciphertexts, using a fresh in-memory state per sample |

Wasmtime resets runtime-local memory between calls. A warm executor cache means
the module is compiled; it does not imply that a lazy verifier remains loaded.
The two-verification rows exercise reuse within one runtime invocation, matching
the repeated pre-dispatch and dispatch verification shape. Their measured total
has a direct budget gate. Subtracting single-call medians is only an estimate of
the additional warm verification cost.

Fixture setup, proof-file reading and JSON rendering are outside the timer. Every
measured call includes host/runtime argument handling. Payload contents vary
between iterations to prevent loop-invariant hash elimination. Retention fixtures
span multiple creation blocks and respect the per-block creation cap.

## Remaining qualification

These component measurements do not qualify successful full settlement, full
block import, disk database latency, public-node transaction admission capacity,
or the minimum supported hardware. The report lists those gaps explicitly.
Without `--public-proof`, it also marks public verification unmeasured.

Record the source revision, working-tree diff identity, compiler/toolchain,
hardware, CPU limits and report alongside release artifacts. Repeat on the
supported reference machine before changing release weights. A workstation pass
does not bound slower machines. Transaction admission also needs operational
concurrency and queue budgets, because an unsuccessful admission pays no fee.
