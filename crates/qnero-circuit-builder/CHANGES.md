# Changes from upstream

Upstream shape is `qp-wormhole-circuit-builder` (Quantus-Network/qp-zk-circuits,
MIT).

## Kept

- Whole-directory staging. Every artifact is written into a hidden sibling
  directory and the set is swapped into place by rename once the last stage
  has succeeded, so a failed run never leaves a directory holding a mix of
  generations. `config.json` is written last: its presence marks the set
  complete.
- No prover artifact, at any layer. Every prover rebuilds its circuit from
  source; see `qnero-aggregator`'s `artifacts` module for why.
- The padding templates are validated before they are published, on the build
  path as well as on the loading paths, and both are read back out of the
  staging directory through the validator their consumer runs.

## Changed

- One verifier file per layer, holding common data and verifier-only data
  together, because that is the single deserialization boundary
  `qnero-verifier` exposes. Upstream writes two files per layer, which a
  consumer has to pair up correctly.
- The artifact names say what they are: `leaf_verifier.bin`,
  `private_batch_verifier.bin`, `public_batch_verifier.bin`,
  `padding_leaf_proof.bin`, `padding_private_batch_proof.bin`. Upstream's leaf
  files are `common.bin`, `verifier.bin` and `dummy_proof.bin`.
- The generated Rust snippet is written by this crate, next to the artifacts it
  describes. Upstream leaves it to the consuming pallet's build script, where a
  set's dimensions and its artifacts can disagree.
- No `clap`. The CLI parses its flags by hand, which keeps the dependency tree
  of a crate that runs on a build host to what the circuits already need.
- The dimensions can come from `QNERO_NUM_LEAF_PROOFS` and
  `QNERO_NUM_PRIVATE_BATCH_PROOFS`, which is how a build script with no command
  line sets them, the way `pallet-wormhole` reads `QP_NUM_LEAF_PROOFS`. A flag
  beats the environment. Such a build script must also emit
  `cargo:rerun-if-env-changed` for both, or Cargo reuses a previous `OUT_DIR`
  after a variable is unset and embeds a verifier built for other dimensions.

## Added

- Every published file is read back out of the staging directory before the set
  is committed: each verifier file through `qnero-verifier`'s own loader (the
  leaf profile, the private-batch profile at the set's `num_leaf_proofs`, and
  the public-batch profile at both dimensions) and each padding proof through
  the validator its consumer runs. Upstream publishes what it built and leaves
  every check to the pallet or aggregator that loads the set, which is another
  machine and, at the chain dimensions, tens of minutes later. The read-back
  costs milliseconds and makes the staging-then-rename guarantee cover "this
  set is loadable". The padding proofs are also the largest files in the set,
  105 KB and 157 KB against 1.7 KB for a verifier, so they are the ones a
  truncated write hits.
- `include_padding_batch`, which controls only the all-padding private-batch
  proof. A runtime build does not need it and would pay a full recursive
  proving run for it; an aggregator does. Upstream's `include_prover` flag
  means the same thing by now, under a name that no longer matches what it
  does.
