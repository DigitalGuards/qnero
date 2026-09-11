# Changes from upstream

Upstream is Quantus-Network/qp-zk-circuits 4.4.0 (MIT). Qnero forks the two
aggregation layers; the public-input layouts and the padding rule are Qnero's.

## Kept

- Recursive verification against a **constant** inner verifier key, never a
  witnessed one. A witnessed key lets a prover substitute a circuit with no
  constraints and have the wrapper accept its proof.
- No prover artifact is emitted or loaded, at any layer. Prover data decides
  which witness values become public inputs.
- Untrusted verifier artifacts are pinned by comparing raw bytes against a
  canonical rebuild, never by deserializing the untrusted side first, and the
  `load_canonical_*` functions return the rebuild.
- The full proof-shape preflight before `set_proof_with_pis_target`, which
  panics, silently half-assigns or silently leaves targets unset depending on
  which length disagrees.
- Padding templates are validated on every path that loads one, the build path
  included, and the sentinel is checked before the cryptographic verify.
- Admission checks run before the recursive proving run: every inner proof is
  verified against the pinned inner verifier, and a batch the circuit could
  never prove is refused in milliseconds rather than after minutes.
- The low-level witness fillers stay crate-private, guarded by a `compile_fail`
  doctest plus a passing companion that pins the same path prefix, so a crate
  or module rename cannot make the negative test pass vacuously.
- A uniform shuffle of the leaf-proof vector at the private batch, and no
  shuffle at the public batch, where forwarding must stay attributable.
- Zero knowledge at the private batch only, with `qp-plonky2/rand` compiled in
  unconditionally: plonky2 panics at build time on a `zero_knowledge` config
  without it, so making it optional would be a privacy failure that only
  surfaces when a wallet proves.

## Changed

- **Both nullifiers of every leaf are forwarded.** A Qnero leaf publishes two,
  one per input slot. Upstream's wrapper carries one per leaf, and a mechanical
  port of it, editing only the leaf-side offsets, would drop every leaf's
  `nf_2` at this boundary: a note spent from input slot 1 would never be marked
  used and could be spent again without limit. `docs/CIRCUIT.md` section 8
  names this as the one place a port goes wrong quietly.
- **Pairwise distinctness covers all `2N` nullifiers**, not `N`. At two per
  leaf, constraining one per leaf leaves the same leaf proof replayable across
  slots.
- **The padding sentinel is a fixed header preimage.** Upstream's sentinel is
  an all-zero `block_hash`, which no preimage produces, so it has to make the
  leaf's header binding conditional. Qnero's padding leaf hashes a real
  preimage, so the binding stays unconditional at every layer. See
  `qnero_circuit::padding`.
- **A padding slot's nullifiers are replaced, its other values zeroed.** The
  replacement is `H(NF_BATCH_PADDING, preimage)` over fresh randomness the
  prover draws per slot per run, so the chain settles every published nullifier
  by one rule; its commitments, fee and `ct_digest` become zero, which is how
  the chain knows to append nothing. Upstream masks exits and amounts for the
  same reason and calls it defense in depth; here it is the enforcement, since
  the leaf's own rule is not what keeps a padding slot from settling.
- **No fee arithmetic in circuit.** Upstream enforces a volume fee over 32-bit
  amounts, with a 52-bit range check that assumes 64 leaves of `u32`. A Qnero
  leaf's fee is a 62-bit field element, so `N` of them overflow Goldilocks for
  `N` above 3. Each leaf's fee is forwarded and the pallet sums them natively.
- **No exit-account grouping or deduplication.** Upstream sums amounts across
  matching exit accounts and zeroes duplicates. Qnero has no exit accounts: a
  leaf's outputs are note commitments, each of which the chain appends once.
- **No separate nullifier permutation network.** Upstream needs one because its
  exit-slot region is grouped and correlated with slot order. Qnero forwards
  each slot's six values as one unit, so the prover's uniform shuffle of the
  proof vector already randomizes every emitted position.
- **The public batch forwards each inner proof's public inputs verbatim** into
  one contiguous segment, header included, rather than hoisting a shared header
  and re-emitting grouped exit slots. A padding inner keeps its sentinel header
  and has its slot region zeroed.
- **One verifier file per layer**, holding common data and verifier-only data
  together. Upstream writes two files per layer, which a consumer has to pair
  up correctly.
- **The padding template is compared against the canonical padding leaf's whole
  public-input vector.** The padding witness is fully determined, so any
  deviation is a template that is not the padding leaf. Upstream can check only
  a handful of sentinel fields, because its dummy leaf carries prover-chosen
  values the sentinel does not cover, and that gap is what forces its wrapper
  to re-mask exit accounts.
- No `std` feature: this crate is prover-side and always has an allocator and a
  filesystem. The runtime-facing crate is `qnero-verifier`.
- No pool, no service layer, no `aggregator.rs`. Upstream carries a proof pool
  with eviction policies and a cloneable proving context for a running
  aggregator service. That is M4 work for Qnero, and shipping it now would be
  shipping an untested queue.

## Added

- An opt-in `parallel` feature. Plonky2's rayon support is off by default so a
  wallet cannot saturate a machine unasked; the proofs are identical either
  way. `docs/BENCH.md` reports both.
- `prove_padding_batch`, which is the one batch proved without the admission
  checks, and the only proof the artifact builder produces at this layer.
