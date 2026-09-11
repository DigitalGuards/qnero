# Changes from upstream

Upstream shape is `qp-wormhole-verifier` (Quantus-Network/qp-zk-circuits, MIT).

- No keccak pin, and no disk path. Upstream reads `verifier.bin` and
  `common.bin` from disk behind a size cap and a keccak256 pin of the
  byte-exact canonical artifacts. Qnero has no released circuit yet, so every
  pin would be a placeholder that a circuit edit invalidates; artifacts are
  taken as bytes from a caller that owns their provenance, and the pin lands
  with the first tagged circuit, together with the batch verifier that a
  runtime actually needs.
- A parameter floor stands in for that pin in the meantime. Upstream has none,
  because the hash covers it. `QneroVerifier::new` holds the artifact to
  `qnero_circuit::params`: public-input count, `security_bits`,
  `num_challenges`, FRI query rounds, grinding bits, rate, cap height, and the
  leaf's degree. Without it, verifier data built over this same public-input
  layout with one query round and no grinding deserializes cleanly, since
  plonky2's own check rejects only a zero challenge count, a zero constant
  count and fewer than three routed wires, and it would then verify forged
  proofs with high probability.
- Proof bytes must be the canonical encoding. Plonky2's reader stops when it
  has read a whole proof without checking that the buffer is exhausted, and it
  decodes public inputs with an unreduced constructor whose range check is a
  debug assertion, so one proof has many valid encodings. Value soundness is
  unaffected, but proof bytes are the natural transaction identity at M4, so
  `verify_proof_bytes` re-serializes and compares. Upstream carries the same
  gap and does not close it.
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
