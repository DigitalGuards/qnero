# Changes from upstream

Upstream shape is `qp-wormhole-verifier` (Quantus-Network/qp-zk-circuits, MIT)
plus the batch-verifier loading in `quantus-chain/pallets/wormhole`.

- The batch verifiers are the runtime-facing API, and the leaf entry points sit
  behind the non-default `leaf` feature (M3). A leaf proof does not blind and
  is not a transaction; it is an input to the wallet's own aggregator. A
  runtime takes this crate with default features off and cannot name a leaf
  verifier at all.
- Batch artifacts cannot be hash-pinned, because their bytes are a function of
  the batch dimensions. In their place: the exact public-input count for those
  dimensions, the exact `CircuitConfig` (which catches a private-batch artifact
  whose `zero_knowledge` is false, an artifact that would verify every proof
  while quietly ending the privacy the layer exists for), the whole `FriParams`
  recomputed from that config at the degree the artifact claims, and a ceiling
  on that degree. Recomputing `FriParams` is what pins `reduction_arity_bits`
  and `leaf_hiding`, which live only in the second copy and which no config
  comparison reaches. `pallet-wormhole` compares the config and the
  public-input count and leaves the rest.
- The leaf floor also pins the two values that live only in the artifact's
  second FRI copy, the folding schedule and the blinding flag, which M2 left
  open. Both are recomputed from the canonical config at the canonical degree.
  Comparing the schedule exactly costs the floor nothing: it is a function of
  the rate, the cap height and the degree, all of which the floor already pins
  exactly, so an artifact that legitimately carried more query rounds still
  produces the same schedule.
- Both loaders refuse an artifact whose index structure does not describe its
  own gate list. A gate's filter is a product over its selector group, so a
  group of `0..2^40` is not a wrong answer but a verifier that never returns,
  and one flipped bit in a length byte produces exactly that. The other half of
  the same structure is the per-gate index that picks a group: plonky2 reads
  the two vectors independently and relates neither to the other, and
  constraint evaluation indexes `groups[selector_indices[gate]]` directly, so
  an index past the group count is an out-of-bounds panic at the first
  verification, which traps a wasm runtime. Both are bounded here. Nothing else
  catches either: the circuit digest does not cover the selector layout.
  Upstream relies on its keccak pin, which a batch artifact cannot have.
- The expected batch configs are restated here from `qnero_circuit::params`,
  because `qnero-circuit`'s own constructors live behind its circuit feature
  and pull in plonky2's prover, which cannot be compiled into a runtime.
  `qnero-aggregator`, which sees both sides, carries the test that they agree.
  `pallet-wormhole` has the same duplication for the same reason.

- No keccak pin at any layer, and no disk path. Upstream reads `verifier.bin` and
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
  proofs with high probability. The floor also requires the artifact's two
  copies of the FRI configuration, `common.config.fri_config` and
  `common.fri_params.config`, to be equal. They deserialize independently from
  the same bytes and plonky2 never compares them, while the FRI verifier reads
  the grinding bits, the query count and the rate from the `fri_params` copy,
  so a floor over one copy alone leaves an artifact whose
  `fri_params.config.proof_of_work_bits` is zero accepted and verified with no
  grinding.
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
  `cargo check -p qnero-verifier --no-default-features` on the host and by the
  same check `--target wasm32v1-none`. The host check proves only that this
  crate's own code compiles under `#![no_std]`; a dependency that reaches for
  std or an OS facility still links there and would surface at M4, after the
  circuit is tagged and the verifier artifact pinned. The toolchain file
  already installs the target for exactly this.
- `verify_and_parse` takes the proof by value and reads the public inputs
  before verifying, so the byte path does not clone about 100 kB of FRI
  openings per proof. `verify_ref` stays for callers that hold only a
  reference, and says in its doc what it costs.
- The public-batch artifact carries a sixteen-byte dimension header, checked
  before anything is deserialized. Upstream pins its leaf artifact by keccak
  and never faces the question at the batch layers. Here the batch profile's
  only dimension-dependent check is the public-input count, and
  `4 + n * (5 + 21 * N)` is not injective in `(n, N)`: `n = 34, N = 1` and
  `n = 13, N = 3` both give 888. Without the header an artifact built for one
  pair loads under the other and every proof it verifies is then split into
  segments at the wrong offsets.
- `PublicBatchPublicInputs::settleable_batches` filters out padding segments,
  so a consumer settles the right segments by default. A padding inner's slot
  region is zeroed, so its nullifiers are the all-zero digest and repeat across
  every batch; settling them would make a chain reject its own next batch.
