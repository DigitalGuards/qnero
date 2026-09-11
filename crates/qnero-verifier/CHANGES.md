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
