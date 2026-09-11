# Changes from upstream

Upstream shape is `qp-wormhole-verifier` (Quantus-Network/qp-zk-circuits, MIT).

- No artifact loading. Upstream reads `verifier.bin` and `common.bin` from
  disk behind a size cap and a keccak256 pin of the byte-exact canonical
  artifacts. Qnero has no released circuit yet, so every pin would be a
  placeholder that a circuit edit invalidates. The verifier is built from
  source here; artifact loading plus the pin lands with the first tagged
  circuit, together with the batch verifier that a runtime actually needs.
- The public-input parser returns field elements. The chain compares
  nullifiers and commitments as field elements, so a conversion to bytes and
  back would only add a lossy step.
- One shared layout module, `qnero_circuit::layout`. Upstream keeps a separate
  inputs crate and the aggregator restates the same indices under different
  names.
- `no_std` plus `alloc` with default features off, matching upstream. This is
  what lets the M4 `pallet-shielded` runtime link it into a wasm build, the way
  `pallet-wormhole` takes `qp-wormhole-verifier` today. Gated by
  `cargo check -p qnero-verifier --no-default-features`.
- `verify_and_parse` takes the proof by value and reads the public inputs
  before verifying, so the byte path does not clone about 100 kB of FRI
  openings per proof. `verify_ref` stays for callers that hold only a
  reference, and says in its doc what it costs.
