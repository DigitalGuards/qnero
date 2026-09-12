# Running the Qnero dev chain

The chain lives in `chain/`, a git subtree of Quantus-Network/chain at
`f1176ce` (v1.0.1). It is its own Cargo workspace with its own toolchain and
lock file; the Qnero root workspace excludes it, and the two meet only through
the path dependencies `chain/Cargo.toml` declares on `../crates/*`.

Every command below is prefixed with `nice -n 19`. The circuit generation and
the proving tests are CPU and memory heavy, and a chain build at `-j 4` will
occupy a machine for the better part of an hour.

## Building

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

The node binary lands at `chain/target/release/quantus-node`.

`LIBCLANG_PATH` is not optional on Linux. `librocksdb-sys` runs bindgen, whose
`clang-sys` build script panics with "couldn't find any valid shared libraries
matching: ['libclang.so', 'libclang-*.so']" when it cannot locate one.
`chain/.cargo/config.toml` sets the variable only on macOS, where Homebrew puts
it somewhere non-standard; on a Debian-family box point it at whichever
`/usr/lib/llvm-*/lib` holds `libclang.so`, and install `libclang-dev` if none
does.

`pallet-shielded`'s build script generates the circuit artifact set before the
pallet compiles, which is where the first minute goes and where most of the
memory goes. Two sizing knobs override the defaults, and both are declared
`cargo:rerun-if-env-changed` so a change to either rebuilds the pallet:

```
QNERO_NUM_LEAF_PROOFS=2 QNERO_NUM_PRIVATE_BATCH_PROOFS=2 cargo build ...
```

Small dimensions are for fixtures and local iteration. A node built with them
settles only proofs built with them.

### One lock pin the fork needs

`chain/Cargo.lock` pins `kem` at `0.3.0-pre.0`:

```
cargo update -p kem --precise 0.3.0-pre.0
```

That is the version `ml-kem 0.2.1` needs, which `clatter` needs, which the
post-quantum Noise transport needs. The requirement is written `^0.3.0-pre.0`,
which the released `0.3.0` also satisfies, so anything that pulls a second
`ml-kem` into the graph lets Cargo pick `0.3.0` and `ml-kem 0.2.1` then fails to
compile against an API it was never written for. Nothing in the Qnero crates
pulls one any more, so the pin is defensive; it is here because the symptom is
eighteen type errors in a crate nobody in this repository calls.

## Tests

```
cd chain
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded --release
nice -n 19 cargo clippy -j 4 -p pallet-shielded --all-targets
```

`--release` is not optional for this crate's tests: several build a real
private-batch proof, and proving in a debug build takes minutes per proof.
`SKIP_WASM_BUILD=1` skips the runtime wasm blob, which the pallet tests do not
need.

Rayon is deliberately off in this crate's dev-dependencies, so a test run proves
single threaded and cannot saturate the machine. The proofs are memoized across
tests and guarded by a mutex, so one proving runs at a time whatever the test
harness's thread count is.

The public-batch settlement path is covered by its algebra and by its verifier
loading, and not by a proof: proving a public batch at the chain default of 53
inner proofs needs 53 private-batch proofs first. To exercise it end to end,
rebuild small:

```
QNERO_NUM_LEAF_PROOFS=2 QNERO_NUM_PRIVATE_BATCH_PROOFS=2 \
  SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded --release
```

## Running a dev chain

```
cd chain
nice -n 19 ./target/release/quantus-node --dev --tmp
```

`--tmp` keeps the chain state in a temporary directory, so a rerun starts from
genesis. Without it, use `purge-chain --dev` between runs. The RPC endpoint is
the Substrate default, `http://127.0.0.1:9944`.

## Smoke checks

Blocks are produced:

```
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getHeader","params":[]}' \
  http://127.0.0.1:9944
```

The header carries `zkTreeRoot` beside `stateRoot` and `extrinsicsRoot`. That
field is the whole anchoring chain: a spend proof's public `block_hash` commits
to this header, the header carries the tree root, and each input note's Merkle
path reaches that root.

The commitment tree's own view, which should agree with the header:

```
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"zkTree_getState","params":[]}' \
  http://127.0.0.1:9944
```

A leaf appended in block N becomes provable only after that block's
`on_finalize`, so `zkTree_getMerkleProof` on a leaf from the current block
returns an error. That is a property a wallet has to
respect: a note cannot be minted and spent in the same block.

The shielded pallet is in the runtime:

```
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"state_getMetadata","params":[]}' \
  http://127.0.0.1:9944 > /tmp/metadata.json
```

Decoding that blob needs a SCALE decoder. The cheap check without one is that
the hex contains the pallet name and its call names, which the smoke run below
used.

## The M4 smoke run, 2026-09-12

Recorded so a rerun has something to compare against. Development workstation,
20 cores, WSL2.

Build:

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

14 minutes 11 seconds of wall clock with a warm dependency cache, of which 41
seconds was `pallet-shielded`'s build script generating the circuit artifact
set. A cold cache is longer: the earlier passes of this same build spent about
an hour reaching the runtime, and `librocksdb-sys` alone compiles hundreds of
C++ objects. The binary is 80 MB at
`chain/target/release/quantus-node`.

Run:

```
nice -n 19 ./target/release/quantus-node --dev --tmp
```

Blocks from the first second: `Imported #1` two seconds after genesis, height
50 shortly after. What the smoke run checked:

- `chain_getHeader` carries `zkTreeRoot` beside `stateRoot` and
  `extrinsicsRoot`, and it equals the root `zkTree_getState` reports
  (`0x6f1d7291c5bb3948d26006250226bc9f7a09f2ca66a4b11f1cf0fc4c8ebe0575` at
  height 50, tree depth 3, 55 leaves). Those leaves are the wormhole's: the
  genesis endowments it records at block 1 and a mining-reward leaf per block.
  The pool is empty until someone shields.
- `zkTree_getMerkleProof(0)` returns a proof whose `leaf_hash` and `leaf_data`
  are the same 32 bytes, which is the fork's leaf rule showing through the RPC.
- `state_getMetadata` carries the pallet: `Shielded`, its three calls
  (`submit_private_batch`, `submit_public_batch`, `shield`), its storage
  (`UsedNullifiers`, `Ciphertexts`, `LeafBlocks`, `EntryCount`, `PoolValue`),
  its constants (`BlockHashWindow`, `MinLeafFee`, `FeeBurnRate`,
  `MaxCiphertextBytes`), its events and the `ShieldedOutput` type.
- `state_getRuntimeVersion` reports `quantus-runtime` spec 152, transaction
  version 6. `transaction_version` is genuinely unchanged, because the signed
  extrinsic encoding did not move. `spec_version` is a different matter and the
  number was left alone for a different reason: upstream's release workflow owns
  that field (`runtime/src/lib.rs` says so), and a feature branch that bumps it
  fights the release tooling.

  **This is an open issue.** The runtime did change:
  it carries a new pallet and a `pallet-zk-tree` whose `Leaves` storage went
  from a typed `ZkLeaf` to a raw `Hash256`, with no migration (see
  `docs/CIRCUIT.md` section 4). Two runtimes with different metadata and an
  incompatible storage layout now answer the same `quantus-runtime` 152, which
  is the one thing the version triple exists to prevent: a node cannot tell them
  apart, and `set_code` refuses an upgrade whose `spec_version` did not
  increase. Before the fork runs anything but a throwaway `--dev` chain it needs
  its own identity, `spec_name = "qnero-runtime"` or a distinct `spec_version`.
  Nothing here is affected while every chain is genesis fresh.

## The review fix pass, 2026-09-12

Same workstation. The pallet and the runtime changed, so the node was rebuilt
and re-smoked.

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

3 minutes 17 seconds of wall clock against the warm tree from the first pass,
of which 54 seconds was the circuit artifact set regenerating. The reason is
that this pass edited `chain/pallets/shielded/build.rs` itself: the build
script binary was recompiled, so Cargo threw away its cached output and ran it
again. Editing the pallet's Rust sources does **not** do that, and the module
doc at the top of `build.rs` states the contract: the script emits only
`cargo:rerun-if-env-changed` for the two `QNERO_NUM_*` knobs, and a script that
emits any `rerun-if` directive at all opts out of Cargo's default "rerun when
any file in the package changed" scan. What triggers a regeneration is one of
those two vars changing, the build script or its build-dependency graph
changing, or a fresh `OUT_DIR`. The binary is 80 MB at
`chain/target/release/quantus-node`.

`--dev --tmp` again, stopped after about two minutes at height 17. Blocks from
the first second, `Imported #1` through `#17`. What this run checked:

- `chain_getHeader`'s `zkTreeRoot` equals the root `zkTree_getState` reports
  (`0x900fc49126275fe988cd7d95a29da563adb251b45ae6b3c2e39a7a933bfc4077` at
  height 8, tree depth 2, 13 leaves, all of them the wormhole's).
- `zkTree_getMerkleProof(0)` returns a proof whose `leaf_hash` and `leaf_data`
  are the same 32 bytes.
- `state_getMetadata` carries `Shielded` with its three calls, its five storage
  items, its errors including `FeeBelowMinimum` and `CiphertextDigestMismatch`,
  and its six constants: `MintingAccount`, `BlockHashWindow`, `MinLeafFee`,
  `CiphertextBytesPerFeeQuantum` (new in this pass, the per-byte half of the fee
  floor), `FeeBurnRate` and `MaxCiphertextBytes`.
- `state_getRuntimeVersion` still reports `quantus-runtime` spec 152,
  transaction version 6. The runtime identity issue above is unchanged and still
  open: this pass added a pallet constant, which is another metadata change
  behind the same version number.

## The second review fix pass, 2026-09-12

Same workstation. The pallet split its settlement check in two and the runtime
moved one constant, so the node was rebuilt and re-smoked.

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

1 minute 6 seconds of wall clock against the warm tree, three crates recompiled
(`pallet-shielded`, `quantus-runtime`, `quantus-node`). The circuit artifact set
did not regenerate this time: the build script's inputs did not change, only the
pallet's Rust sources. The binary is at `chain/target/release/quantus-node`.

`--dev --tmp`, stopped after about two minutes at height 73, 75 blocks imported
from the first second. What this run checked:

- `chain_getHeader`'s `zkTreeRoot` equals the root `zkTree_getState` reports
  (`0xf6ea283327bc24daff781f0b5cb380439f810ab3dd35cf680653e92cca751ac2` at
  height 73, tree depth 4, 78 leaves, all of them the wormhole's).
- `zkTree_getMerkleProof(0)` returns a proof whose `leaf_hash` and `leaf_data`
  are the same 32 bytes.
- `state_getMetadata` carries `Shielded` with its calls, its storage items
  (`UsedNullifiers`, `Ciphertexts`, `LeafBlocks`, `PoolValue`, `EntryCount`),
  its errors including `FeeBelowMinimum` and `CiphertextDigestMismatch`, and its
  six constants. `CiphertextBytesPerFeeQuantum` reads `512` in the metadata
  blob, which is the value this pass moved it to so that a slot padded to the
  ciphertext cap costs strictly more than one carrying real ciphertexts.
- `state_getRuntimeVersion` still reports `quantus-runtime` spec 152,
  transaction version 6. The runtime identity issue above is unchanged and still
  open: this pass changed a constant's value, which is another metadata change
  behind the same version number.

## The third review fix pass, 2026-09-12

Same workstation. The pallet changed the settlement plan and the runtime gained
one constant. **The node was deliberately not rebuilt in this pass**, so
`chain/target/release/quantus-node` and the metadata it serves are still the
second pass's: they carry neither the `MaxPayloadSlotRatio` constant nor the
`PayloadRatioExceeded` error. The next build of the node picks both up, and it
will not regenerate the circuit artifact set, because this pass touched neither
`QNERO_NUM_*` nor `build.rs` (see the correction in the first pass's entry
above).

Gates run for this pass, all green:

```
cd chain
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded -p pallet-zk-tree --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p pallet-shielded -p pallet-zk-tree --all-targets
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p quantus-runtime
```

56 tests in `pallet-shielded` and 35 in `pallet-zk-tree`, no clippy warnings in
either, and the runtime compiles against the new `Config` item. The root
workspace was unchanged and its four gates were re-run for the record.

What changed, and what a node operator sees once the node is rebuilt:

- One new pallet constant in the metadata, `MaxPayloadSlotRatio`, set to `4`.
  It bounds the real leaf slots a submission may carry against the real leaf
  slots it settles. A skipped segment pays no fee, so without it the fraction
  of a submission that settles is the fraction of its payload that is priced,
  and the submitter picks that fraction.
- One new error, `PayloadRatioExceeded`.
- A settlement whose block anchor does not resolve is now skipped like a
  nullifier conflict, where before it refused the whole submission. A submission
  with nothing left to settle still refuses, and it names the anchor error
  (`BlockOutsideWindow`, `BlockNotFound`, `BlockHashMismatch`) when an anchor
  was the reason, so a wallet's single-segment private batch reports what it
  reported before.
- `shield`'s declared weight takes the ciphertext length and adds it to
  `proof_size`, matching what a settlement already declares for the same map.
  Nothing is metered against it while `RuntimeBlockWeights` leaves `proof_size`
  at `u64::MAX`.

The runtime identity issue above is unchanged and still open: this pass adds a
constant and an error, which is another metadata change behind `quantus-runtime`
spec 152.

## The fourth review fix pass, 2026-09-12

Same workstation. The pallet replaced its payload bound and the runtime dropped
a constant, so the node was rebuilt and re-smoked. **This is the build the third
pass deferred**, so its entry above is now history on one point: the constant
and the error it said the next build would pick up
(`MaxPayloadSlotRatio`, `PayloadRatioExceeded`) were removed before that build
happened, and neither is in the metadata this binary serves.

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

Two builds, because a comment and a whitespace revert landed after the first
one: 1 minute 6 seconds for the build that was smoked first (three crates:
`pallet-shielded`, `quantus-runtime`, `quantus-node`), then 2 minutes 0 seconds
for the build of the tree as committed, which recompiled `quantus-node` alone.
The circuit artifact set did not regenerate in either: this pass touched neither
`QNERO_NUM_*` nor `build.rs`. The binary is 80,468,704 bytes at
`chain/target/release/quantus-node`, and the figures below are that binary's.

`nice -n 19 ./target/release/quantus-node --dev --tmp`, 49 seconds from the
first imported block to the stop, 48 blocks imported, height 48. Stopped by its
pidfile; `ss -ltn` then shows no listener on 9944, a `curl` to it is refused,
and `pgrep quantus-node` finds nothing, so the port is closed and no process is
left. What this run checked:

- `chain_getHeader`'s `zkTreeRoot` equals the root `zkTree_getState` reports
  (`0x241adc0c8c67b7b74067dcb4f443a59491de8a1a43b53a74d4131f1ac2aa6e8d` at
  height 42, tree depth 3, 47 leaves, all of them the wormhole's), on three
  consecutive probe pairs.
- `zkTree_getMerkleProof(0)` returns a proof whose `leaf_hash` and `leaf_data`
  are the same 32 bytes.
- `state_getMetadata` carries `Shielded` with its three calls, its five storage
  items (`UsedNullifiers`, `Ciphertexts`, `LeafBlocks`, `EntryCount`,
  `PoolValue`) and six constants: `MintingAccount`, `BlockHashWindow`,
  `MinLeafFee`, `CiphertextBytesPerFeeQuantum`, `MaxCiphertextBytes` and
  `FeeBurnRate`.
  `MaxPayloadSlotRatio` is gone from the blob, and so is the
  `PayloadRatioExceeded` error. Two errors are new, `PayloadUnderpaid` and
  `EmptyCiphertext`, and `FeeBelowMinimum` and `CiphertextDigestMismatch` are
  where they were.
- `state_getRuntimeVersion` still reports `quantus-runtime` spec 152,
  transaction version 6. The runtime identity issue above is unchanged and still
  open: this pass removed a constant and moved two errors, which changes the
  metadata and the error indices behind the same version number. Nothing is
  affected while every chain is genesis fresh.

Gates run for this pass, all green:

```
# in the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check

cd chain
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded -p pallet-zk-tree --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p pallet-shielded --all-targets
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p quantus-runtime
```

27 test binaries in the root workspace with no failure, 60 tests in
`pallet-shielded` and 35 in `pallet-zk-tree`, no clippy warnings anywhere, and
the root workspace is rustfmt clean. `cargo fmt --check` in the chain workspace
reports drift that predates this pass, in the vendored Substrate tree and in
files this pass did not touch: that workspace's `rustfmt.toml` asks for nightly
options (`wrap_comments`, `imports_granularity`) that the pinned stable
toolchain ignores. The files this pass edited add no new diff to that set,
which was checked by running the same command against a stash of the changes.

What changed, and what a node operator sees:

- `MaxPayloadSlotRatio` and `PayloadRatioExceeded` are gone. The bound they
  carried compared real leaf slot counts, and a submitter picks both the payload
  per slot and the slot count per segment, so it priced two numbers the
  submitter controls.
- The settling slots of a submission now owe
  `settling slots * MinLeafFee + ceil(carried bytes / CiphertextBytesPerFeeQuantum)`,
  where the carried bytes are every ciphertext in the extrinsic, the positions
  of skipped segments included. Refused with `PayloadUnderpaid`. No new
  parameter: it reads the two the per-slot floor already reads.
- A position belonging to a segment the submission skips may be a pair of
  zero-length ciphertexts. Such a position carries no bytes, so it is priced at
  nothing and no `ct_digest` is evaluated for it. An aggregator refused with
  `PayloadUnderpaid` after a race resubmits with the skipped segments' outputs
  emptied. A settling position may not be emptied: `EmptyCiphertext`.
- The stale-anchor skip is unchanged. What is documented now is its scope: the
  public-batch circuit constrains every non-padding inner to one block hash and
  one block number, so for a batch these circuits produce the anchor decides the
  whole submission, and a private batch has one segment anyway.

## Review verification of the fourth fix pass, 2026-09-12

Independent re-check of the rebuild and smoke recorded above, at
`dce3af9`, on the same workstation.

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

`Finished release profile in 0.50s`: nothing to recompile. The binary at
`chain/target/release/quantus-node` is the one the entry above describes,
80,468,704 bytes, so the tree as committed and the binary already agree and no
second build was produced.

`nice -n 19 ./target/release/quantus-node --dev --tmp`, 202 seconds, 214 blocks
imported, stopped by its pidfile. `ss -ltn` then shows no listener on 9944,
`curl` to it returns no response, and `pgrep quantus-node` finds nothing.

`state_getMetadata` (229,604 hex characters) was searched for each name the
pass claims to have moved:

- `MaxPayloadSlotRatio` and `PayloadRatioExceeded` are absent from the blob.
- `PayloadUnderpaid` and `EmptyCiphertext` are present.
- `MinLeafFee`, `CiphertextBytesPerFeeQuantum`, `MaxCiphertextBytes`,
  `FeeBurnRate`, `BlockHashWindow` and `MintingAccount` are the six `Shielded`
  constants, and `FeeBelowMinimum` and `CiphertextDigestMismatch` are still
  there.
- `state_getRuntimeVersion` reports `quantus-runtime` spec 152. The runtime
  identity issue recorded in the passes above is unchanged.

Gates re-run for the review, all green:

```
cd chain
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 2 -p pallet-shielded -p pallet-zk-tree --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 2 -p pallet-shielded --all-targets
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 2 -p quantus-runtime
# in the repository root
nice -n 19 cargo fmt --all -- --check
```

60 tests in `pallet-shielded` and 35 in `pallet-zk-tree`, no clippy warnings,
the runtime compiles, and the root workspace is rustfmt clean. The chain
workspace's rustfmt drift in `pallets/shielded/src/tests.rs` predates this pass
and comes from the nightly-only options in its `rustfmt.toml`.

## The fifth review fix pass, 2026-09-12

Same workstation. The pallet changed one consensus rule, the submission fee
floor, so the node was rebuilt and re-smoked.

What changed, and what a node operator sees:

- The submission floor now charges `MinLeafFee` for **every real leaf slot the
  submission carries**, settling and skipped alike, where it previously charged
  it for the settling slots only:

  ```
  sum(fee of settling slots)
      >= (settling slots + skipped slots) * MinLeafFee
         + ceil(carried bytes / CiphertextBytesPerFeeQuantum)
  ```

  The byte term is unchanged and the per-slot floor is unchanged. Refused with
  `PayloadUnderpaid`, which is the same error at a higher threshold.
- What it closes: a skipped position may be emptied to a zero-length ciphertext
  pair, which removes its bytes from the byte term, and the slot behind it still
  costs every node the admission walk, two `UsedNullifiers` probes, a position
  in `outputs` and the weight the extrinsic declares. Under the old floor one
  settling slot beside 317 emptied skipped ones commanded all of that for one
  quantum, on an unsigned and fee-free extrinsic.
- What it costs an aggregator: a submission that settles everything it carries
  is unaffected, because each slot already pays this minimum once through the
  per-slot floor, so every private batch and every ungriefed public batch prices
  exactly as before. A griefed public batch of six-slot inners that loses one
  inner owes six quanta more than its settling slots' own minimums. At the far
  end, a batch that settles one slot beside 317 skipped ones owes 318 minimums,
  3.18 QTC at the runtime's parameters, and the aggregator's alternative is to
  recompose a fresh public batch without the conflicted inners for the cost of
  one proof.
- **No structural metadata change.** No call, storage item, constant or error
  variant was added, removed or reordered, so the `Shielded` error indices are
  where the fourth pass left them and a wallet built against the previous
  metadata still decodes this runtime's refusals. What moved is the number a
  submission has to clear. The blob did grow, from 229,604 hex characters to
  230,554, because pallet doc strings are part of the metadata and this pass
  rewrote several of them, `PayloadUnderpaid`, `MinLeafFee` and
  `CiphertextBytesPerFeeQuantum` among them.

Gates run for this pass, all green:

```
# in the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check

cd chain
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded -p pallet-zk-tree --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p pallet-shielded --all-targets
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p quantus-runtime
```

27 test binaries in the root workspace with no failure, 61 tests in
`pallet-shielded` (one more than the fourth pass: the grief-shape test was
rewritten around the new floor and a single-segment floor-equality test was
added) and 35 in `pallet-zk-tree`, no clippy warnings anywhere, the runtime
compiles, and the root workspace is rustfmt clean. The chain workspace's
`cargo fmt --check` drift is the same six hunks it was before this pass, in
`pallets/shielded/src/tests.rs:484` and five places in
`pallets/shielded/src/weights.rs`, plus the runtime tree; it comes from the
nightly-only options in that workspace's `rustfmt.toml` and this pass adds
nothing to it, which was checked by running the same command against a stash of
the changes.

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

Two builds, because three doc comments were tightened after the first one:
1 minute 3 seconds, then 1 minute 5 seconds for the build of the tree as
committed, each recompiling the same three crates (`pallet-shielded`,
`quantus-runtime`, `quantus-node`). The circuit artifact set regenerated in 28.8
seconds on the first of them, which is the release profile's own `OUT_DIR`
regenerating: this pass touched neither `QNERO_NUM_*` nor `build.rs`, so the
dimensions are the ones every earlier build used. The binary of the committed
tree is 80,465,200 bytes at `chain/target/release/quantus-node`, and the
figures below are that binary's.
Both builds serve a byte-identical `state_getMetadata` blob, which is what a
comment-only difference should produce.

`nice -n 19 ./target/release/quantus-node --dev --tmp`, 77 seconds of uptime,
74 blocks imported, final height 74. Stopped by its pidfile; `ss -ltn` then
shows no listener on 9944, `curl` to it exits 7 (connection refused), and
`pgrep quantus-node` finds nothing, so the port is closed and no process is
left. What this run checked:

- `chain_getHeader`'s `zkTreeRoot`
  (`0x62a24fdbf914c81ebfe4749a951c50c7ff62e8fda8f9eb2d38259e533716fab9` at
  height 74) equals the root `zkTree_getState` reports, at 79 leaves and tree
  depth 4, all of them the wormhole's.
- `zkTree_getMerkleProof(0)` returns a proof whose `leaf_hash` and `leaf_data`
  are the same 32 bytes.
- `state_getMetadata` (230,554 hex characters) carries `PayloadUnderpaid`,
  `EmptyCiphertext`, `FeeBelowMinimum`, `CiphertextDigestMismatch` and the rest
  of the `Shielded` error list in the order the fourth pass recorded, and the
  six `Shielded` constants `MintingAccount`, `BlockHashWindow`, `MinLeafFee`,
  `CiphertextBytesPerFeeQuantum`, `MaxCiphertextBytes` and `FeeBurnRate`.
  `MaxPayloadSlotRatio` and `PayloadRatioExceeded` are still absent.
- `state_getRuntimeVersion` reports `quantus-runtime` spec 152, transaction
  version 6. The runtime identity issue recorded in the passes above is
  unchanged, and this pass is the first of the five to change a consensus rule
  behind that version number while leaving the metadata's structure alone, which
  is the worse half of that issue: a node on the previous runtime reads the same
  call and error indices and disagrees about which submissions are admissible.


## The M5 wallet run, 2026-09-12

The wallet CLI end to end against a fresh `--dev --tmp` node, on the same
development workstation. `docs/WALLET.md` is the reference for the commands and
the store format; this is the run that produced the M5 numbers.

Re-run after the M5 review pass, so the transcript below is the fixed wallet:
spent status decided against a locally paged copy of `UsedNullifiers`, Merkle
paths rebuilt locally from the whole leaf range, the shield's dispatch
confirmed by finding its leaf, both halves of the entry rule checked, the
storage layout validated against metadata on the read path, and a seed default
under the user's data directory. Store format is version 2.

Build:

```
nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel
export RAYON_NUM_THREADS=4
```

Gates, all green:

```
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   262 passed, 0 failed, 4 ignored
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
```

The chain half was built and tested with `-j 4` from `chain/`:

```
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo test -j 4 --release \
  -p pallet-shielded --lib -- --ignored a_real_public_batch --nocapture
   1 passed (validate_public_batch native 5.86ms over the 237544-byte proof)
```

That test now panics when the proof artifact is missing. It used to return
early and print `ok`, which is the state of every fresh clone and of anything
after a `cargo clean`, since the proof lives under `target/`. Verified both
ways: with the artifact it passes, and with
`QNERO_PUBLIC_BATCH_PROOF=/nonexistent/proof.bin` it fails and names the command
that regenerates one.

### The run

Addresses are truncated in the middle: a `qn1` address is 2572 characters,
almost all of it the ML-KEM-1024 encapsulation key. Everything ran from a
scratch directory with explicit `--file` paths.

```text
=== 1. start a fresh dev node ===

$ nice -n 19 ./chain/target/release/quantus-node --dev --tmp   (backgrounded, pidfile)

$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*          
LISTEN 0      1024            [::1]:9944          [::]:*          

=== 2. wallet A ===

$ qnero-wallet --file A.seed keygen
seed    A.seed
store   A.seed.store.json
address qn1qyg4qe7xr3dedw2jx7cx...ecj748rh

The seed is unencrypted hex at mode 0600. Anyone who can read it can spend every note this wallet holds.

$ qnero-wallet status
node              http://127.0.0.1:9944
runtime           spec 152, transaction 6
chain head        18 (d0bc5e1d256861187e92654624c6e07bb5bbc981e2938b614b0518ab156b4895)
tree leaves       23
tree depth        3
tree root         28c528dad7753a95b576c1cfc2feee5c0cdc2e8236904ac50b315d6c1e0ff2c5
last synced block (no wallet at /home/<user>/.local/share/qnero/qnero-wallet.seed)

The default seed path now resolves under the user's data directory. `keygen`
with no `--file` used to drop an unencrypted spending key into whatever
repository the caller was standing in.

=== 3. shield 1000 quanta from the dev account alice into A ===

$ qnero-wallet --file A.seed shield --from-dev-account alice --amount 1000 --memo 'first shield'
shielding 1000 quanta (10000000000000 planck) from alice
commitment  182dc28a74ad0316eb6eeae48d4f8faa8e1a87372ca02d418bcec6971ccedc55
leaf        30
included    block 26 after 1.51s
synced      1 new note(s), unspent total 1000 quanta

The `leaf` line is the dispatch confirmation: the wallet reads the leaves the
inclusion block appended and finds its own commitment among them. An included
extrinsic whose dispatch failed appends none, and used to be reported as a
success with a pending note nothing would ever clear. No entry-rho note printed,
so both halves of the rule held: the shield landed in the predicted block and
was the only entry in it.

$ qnero-wallet --file A.seed balance
address        qn1qyg4qe7xr3dedw2jx7cx...ecj748rh
unspent        1000 quanta
pending        0 quanta
synced through block 26

      leaf        quanta    block    state  memo
        30          1000       26  unspent  first shield

=== 4. wallet B ===

$ qnero-wallet --file B.seed keygen
seed    B.seed
store   B.seed.store.json
address qn1qy3vw5ygq6pxm3fl43fs...r5my8znt

=== 5. a fee below the floor is refused ===

$ qnero-wallet --file A.seed send --to <B> --amount 300 --fee 1 --memo 'payment to B'
Error: a fee of 1 quanta is below this submission's floor of 8. The pallet asks MinLeafFee (1) plus one quantum per started 512 bytes of ciphertext, and the two outputs here are 3474 bytes. The fee is a public input of the proof, so it cannot be raised afterwards: the settlement would be refused with PayloadUnderpaid.

=== 6. A sends 300 quanta to B at the floor ===

$ time qnero-wallet --file A.seed send --to <B> --amount 300 --memo 'payment to B'
fee         8 quanta
circuits    built in 2.37s (6 leaf slots per batch)
anchor      block 38
inputs      leaves [30] for 300 quanta plus 8 fee
change      692 quanta
proof       150908 bytes
proving     3.58s
inclusion   block 41 after 1.04s
synced      1 new note(s), unspent total 692 quanta
wall clock  7.22 s

=== 7. B sees the note; A sees the input spent and its change ===

$ qnero-wallet --file B.seed sync
scanned leaves 0..56 at block 47
received 1 note(s) worth 300 quanta
newly spent 0
unspent total 300 quanta

$ qnero-wallet --file B.seed balance
address        qn1qy3vw5ygq6pxm3fl43fs...r5my8znt
unspent        300 quanta
pending        0 quanta
synced through block 47

      leaf        quanta    block    state  memo
        46           300       41  unspent  payment to B

$ qnero-wallet --file A.seed balance
address        qn1qyg4qe7xr3dedw2jx7cx...ecj748rh
unspent        692 quanta
pending        0 quanta
synced through block 47

      leaf        quanta    block    state  memo
        30          1000       26    spent  first shield
        47           692       41  unspent  

=== 8. B spends the note it received, back to A ===

$ time qnero-wallet --file B.seed send --to <A> --amount 100 --memo 'back to A'
fee         8 quanta
circuits    built in 2.38s (6 leaf slots per batch)
anchor      block 52
inputs      leaves [46] for 100 quanta plus 8 fee
change      192 quanta
proof       150908 bytes
proving     3.44s
inclusion   block 59 after 1.04s
synced      1 new note(s), unspent total 192 quanta
wall clock  7.06 s

$ qnero-wallet --file A.seed sync
scanned leaves 56..77 at block 65
received 1 note(s) worth 100 quanta
newly spent 0
unspent total 792 quanta

$ qnero-wallet --file A.seed balance
address        qn1qyg4qe7xr3dedw2jx7cx...ecj748rh
unspent        792 quanta
pending        0 quanta
synced through block 65

      leaf        quanta    block    state  memo
        30          1000       26    spent  first shield
        47           692       41  unspent  
        67           100       59  unspent  back to A

$ qnero-wallet --file B.seed balance
address        qn1qy3vw5ygq6pxm3fl43fs...r5my8znt
unspent        192 quanta
pending        0 quanta
synced through block 59

      leaf        quanta    block    state  memo
        46           300       41    spent  payment to B
        68           192       59  unspent  

=== 9. the opt-in RPC path, and the store permission check ===

$ qnero-wallet --file A.seed send --to <B> --amount 50 --memo 'via merkle rpc' --merkle-rpc
merkle      zkTree_getMerkleProof (this names the leaves being spent to the node)
fee         8 quanta
circuits    built in 2.25s (6 leaf slots per batch)
anchor      block 107
inputs      leaves [47] for 50 quanta plus 8 fee
change      634 quanta
proof       150908 bytes
proving     3.56s
inclusion   block 110 after 1.54s
synced      1 new note(s), unspent total 734 quanta

$ chmod 644 A.seed.store.json && qnero-wallet --file A.seed balance
Error: A.seed.store.json is readable or writable beyond its owner (mode 644). Fix it with `chmod 600 A.seed.store.json`.

=== 10. the store on disk ===

$ ls -l A.seed A.seed.store.json
-rw------- 1 waterfall waterfall   65 Sep 12 09:19 A.seed
-rw------- 1 waterfall waterfall 4591 Sep 12 09:20 A.seed.store.json

$ jq '{version, next_leaf, last_synced_block, used_nullifiers: (.used_nullifiers|length), notes: [.notes[] | {leaf_index, value, spent, memo}]}' A.seed.store.json
{
  "version": 2,
  "next_leaf": 77,
  "last_synced_block": 65,
  "used_nullifiers": 4,
  "notes": [
    { "leaf_index": 30, "value": 1000, "spent": true,  "memo": "first shield" },
    { "leaf_index": 47, "value": 692,  "spent": false, "memo": "" },
    { "leaf_index": 67, "value": 100,  "spent": false, "memo": "back to A" }
  ]
}

=== 11. the same flow as an integration test, then stop the node ===

$ QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
    -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
shield of 1000 quanta included at block 79 (504.77ms), leaf 90
300 quanta to B: proved in 3.40s, 150908 proof bytes, included at block 91
100 quanta back to A: proved in 3.44s, included at block 96
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok
test result: ok. 1 passed; 0 failed

$ kill $(cat node.pid), then wait for 9944 to close
9944 has no listener
```

### What this run checked

- **The signed path.** `shield` builds a legacy signed extrinsic by hand, with
  `MultiAddress::Id`, a 7219-byte `Dilithium87SignatureWithPublic` behind a
  one-byte enum index and no length prefix, an immortal era, a nonce read from
  the best block, and the twelve transaction extensions the runtime declares.
  The signature is made under the FIPS 204 context `QUANTUS_EXTRINSIC` over the
  blake2-256 of the payload. The account is Poseidon2 of the public key.
- **The dispatch.** The shield's note was found at leaf 30 of block 26 before
  the command reported success. Inclusion alone no longer counts as one.
- **The unsigned path.** `send` submits a bare `submit_private_batch` with no
  signature, no nonce and no tip, and both of its nullifiers were in
  `UsedNullifiers` at the inclusion block.
- **The anchor.** Every spend rebuilt its anchoring header from
  `chain_getHeader`'s six fields plus the re-encoded digest logs, hashed it with
  Poseidon2 and compared the result against `chain_getBlockHash` before proving.
- **The local tree.** Every spend rebuilt the commitment tree from
  `ZkTree::Leaves` at the anchor block and checked its root against the header's
  `zkTreeRoot` before proving. Three settlements proved and settled against
  locally computed paths, so the rebuild agrees with `pallet-zk-tree` on real
  chain state, and one more settled through `--merkle-rpc` for the opt-in path.
- **The fee floor, read from metadata.** Two ciphertexts of 1731 and 1743 bytes
  are 3474, so the floor is `MinLeafFee(1) + ceil(3474 / 512) = 8` quanta. The
  wallet defaults to it, refuses `--fee 1` with the arithmetic spelled out, and
  every settlement carried exactly 8.
- **A received note is spendable.** B spent the note A sent it, whose `rho` the
  circuit derived from the two nullifiers A's leaf published and whose value and
  randomness reached B only inside A's ciphertext.
- **The books.** 1000 shielded, 300 paid, 692 change, 8 fee; then 100 paid back,
  192 change, 8 fee; then 50 more from A over the RPC path, 634 change, 8 fee.

### Timings, `RAYON_NUM_THREADS=4`

Two payments, so every range below is a two-sample range.

| | |
|---|---:|
| `send` wall clock, whole command | 7.06 s and 7.22 s |
| of which circuit build, once per process | 2.37 s and 2.38 s |
| of which private batch proving | 3.44 s and 3.58 s |
| of which submit to inclusion | 1.04 s and 1.04 s |
| `shield` wall clock, submit to inclusion | 1.51 s |
| private batch proof | 150908 bytes |

The circuit build is paid once per process and a longer-lived wallet would pay
it once per run. `docs/BENCH.md` carries these beside the public batch at
`n = 53`, which this milestone measured for the first time.
