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
