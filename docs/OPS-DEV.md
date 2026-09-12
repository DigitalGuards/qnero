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

**M6 hit it, and it decided a design.** The coinbase note was to be encrypted
to the miner's address with the wallet's own note encryption, which is
`qnero-notes`, which is `ml-kem` 0.3. Adding that edge to the node resolved
`kem` to `0.3.0` and broke `ml-kem 0.2.1` in exactly the eighteen ways above.
There is no resolution that satisfies both: `ml-kem 0.2.3` pins
`=0.3.0-pre.0`, `ml-kem 0.3.2` needs `^0.3`, and a pre-release does not satisfy
a stable requirement. `clatter 2.3.0`, the newest, is still on `ml-kem 0.2.1`.
So the block author's node does not encrypt: it is configured with a miner key
and derives the note (`docs/DESIGN.md` section 7.1, `docs/CIRCUIT.md` section
10.2). The node links `qnero-note-core`, which is the crate that exists so a
binary can have Poseidon note rules without a lattice dependency, and links no
`ml-kem` of its own at all. Check `cargo tree -i ml-kem` before adding a
dependency to `node`, `runtime` or any pallet.

## Tests

```
cd chain
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p pallet-shielded -p pallet-mining-rewards --release
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p quantus-runtime --release --test call_filter
nice -n 19 cargo clippy -j 4 -p pallet-shielded -p pallet-mining-rewards --all-targets
```

The runtime's call-filter test is named, and `cargo test -p quantus-runtime`
without `--test call_filter` is not the gate: the `tests/mod.rs` target has not
compiled since the M4 subtree fork, where `pallet-zk-tree` changed `Leaves` to a
raw `Hash256` and `runtime/tests/governance/vesting.rs:58` still reads `leaf.to`
off it. That target is a pre-existing failure, it is listed as an open issue in
`docs/WALLET.md`, and most of what it covers is transparent transfers, which v1
refuses.

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

### Mining under v1: the miner key

From M6 every block mints its reward as one shielded note, and that is the only
way value enters circulation after genesis. The genesis allocation is
transparent and is paid out by `Vesting::claim`; `docs/DESIGN.md` section 7.1
is the split. The node needs to know which note to mint, so an
authority is configured with a **miner key**: `pk` and a coinbase viewing key
`cvk`, in one bech32m string, printed by the wallet.

```
# once, on the machine that holds the wallet
qnero-wallet miner-address          # the key alone on stdout

# on the node
export QNERO_MINER_KEY=qnm1...
nice -n 19 ./target/release/quantus-node --dev --tmp
# or --rewards-miner-key qnm1...
```

`--dev` authors blocks, so it needs the key like any other authority. A node
without one builds blocks that carry no coinbase inherent, and every node
refuses those, its own import included, so the node refuses to start instead.

Two properties of that string:

- **It is secret-bearing, and the address is not.** `cvk` is what a coinbase note's `r` is derived
  from, so whoever holds the miner key can pick that miner's coinbase notes out of the tree. It
  cannot spend them and it says nothing about any other note the wallet holds. Prefer the
  environment variable to a command line, which every process listing on the machine can read.
- **It is not an address.** Its human-readable part is `qnm` rather than `qn`, so pasting one where
  the other belongs fails on the checksum rather than halfway through a decode.
- **One key is safe on more than one chain.** A coinbase note is derived rather than drawn at
  random, so the genesis hash is in the preimage of its `r`. The same `qnm1...` on a testnet and on
  mainnet mints unrelated notes at equal heights, and nobody carries an identification from one
  chain to the other by comparing note commitments. A chain relaunched from a fresh genesis counts
  as another chain here, which is what makes a repeated `--dev --tmp` run safe as well.

`--rewards-inner-hash` stays, and stays required of an authority, but it is no
longer a payout address: under v1 no account is paid. It is the fallback author
label for a node with no miner key, which cannot author a valid block anyway.
The two flags are independent and only one of them decides where value goes.

The startup log says which is which, and it is worth reading once:

```
⛏️ Consensus author fallback, paid nothing: qz...
⛏️ Coinbase notes are minted for miner key qnm1abcdefgh…wxyz0123
```

The second line is the one to check against what `qnero-wallet miner-address`
printed, both ends of the string. A stale or mistyped miner key mines correct
blocks into notes the operator's wallet cannot open, block after block, and the
only other symptom is a balance that never grows.

### The block-author seam

Everything in the runtime that needs to know who authored a block reads it
through one implementation, `quantus_runtime::configs::QpowAuthor`, which
implements `frame_support::traits::FindAuthor<AccountId>`. It takes the first
`PreRuntime` digest item under `POW_ENGINE_ID`, requires exactly 32 bytes, and
derives the wormhole address from it (`qp_wormhole::derive_wormhole_address`).

**What those 32 bytes are.** Not the operator's identity. An authoring node
publishes `H(cvk, parent_hash)` there, computed by
`qnero_note_core::MinerKey::author_label` and handed to the consensus client as
`sc_consensus_qpow::AuthorLabel`, so the item changes every block. A constant
item would label every block one operator won, and `Shielded::CoinbaseValues`
publishes each coinbase note's value while `Shielded::LeafBlocks` dates it, so
an observer could partition the tree by miner and read each miner's income
block by block. The label must be four canonical Goldilocks limbs, which a
Poseidon digest always is: the runtime treats an item it cannot derive an
account from as a block with no author, and that fails the coinbase inherent,
which fails the block. A new engine supplies its own label and owes the same two
properties, per block and always canonical.

Two pallets read it and nothing else in the runtime touches the proof of work:

- `pallet-mining-rewards` asks whether the block has an author at all. A block without one retains
  its credit for the next block rather than minting it.
- `pallet-shielded` asks the same question at the coinbase inherent. A block with no author has
  nobody the coinbase belongs to, and the inherent fails, which fails the block.

Neither asks who. No event carries the author either: the coinbase note's
recipient is the miner key the author's own node holds, which the chain never
sees, and an account published beside every block's credit would be a mining
identity attached to every coinbase note.

**This is the seam a later engine swap goes through.** `docs/DESIGN.md` section
10 keeps RandomX open so Monero rigs can mine Qnero, and the evaluation is
recorded for M7. Swapping the engine is this impl plus the consensus client:
whatever the new engine puts in the pre-runtime digest, and whatever account it
derives, the two pallets above are unchanged, no storage item moves, and the
shape of a block is unchanged. Do not reach for
`qp_wormhole::extract_author_from_digest` from a pallet again; it is called
from exactly one place on purpose.

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

## The M5 review fix pass, 2026-09-12

Thirteen review findings, two of them about what the chain publishes rather
than what the wallet asks its node. The fix pass re-ran the whole end-to-end
flow against a fresh `--dev --tmp` node, because two of the changes move
numbers that the M5 run above recorded: every memo is now padded to 256 bytes,
so each output ciphertext is a uniform 1987 bytes and the submission floor is
9 quanta where it was 8.

### What changed

- **Memo padding.** A `NoteCiphertext` is 1731 bytes plus its memo, and the
  chain publishes those bytes in full. An unpadded pair therefore published the
  payment memo's exact byte count as `len(ct_1) - len(ct_2)`, and made the
  change note, whose memo is empty, always the shorter of the two.
- **The payment's output slot is drawn per spend.** `ct_1` belongs to
  `cm_out_1` and `SlotSettled` names both leaf indices, so a payment fixed at
  slot 0 told every chain reader which of a settlement's two new leaves came
  back to the sender.
- **Memos are escaped before they reach a terminal.** A memo is remote input
  and `balance` printed it byte for byte.
- **`shield` runs `ensure_known_storage` first**, the check `sync` and
  `prepare_spend` already ran. Without it a drifted `ZkTree::Leaves` turned a
  shield that settled into a reported dispatch failure and dropped the pending
  record of the note's `r`.
- **A note that moved leaf is repaired**, so an orphaned block and a
  re-included extrinsic cannot leave a stale leaf index that makes a balance
  unspendable.
- **The runtime's extrinsic format version is read** and checked against the
  two compiled-in preamble bytes.
- Plus: `PreparedSpend` hand-writes a redacting `Debug`, the store's JSON text
  is read and written inside `Zeroizing`, the entry counter is read once per
  sync instead of once per received note, and two stale claims in the prose
  were corrected.

### The run

```text
=== 1. a fresh dev node ===

$ nice -n 19 ./chain/target/release/quantus-node --dev --tmp   (backgrounded, pidfile)
$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*
LISTEN 0      1024            [::1]:9944          [::]:*

=== 2. two wallets ===

$ qnero-wallet --file a.seed keygen
seed    a.seed
store   a.seed.store.json
address qn1qxjjyfnf59hfkc0nvk6wa...amq4hdr4l
$ qnero-wallet --file b.seed keygen
seed    b.seed
store   b.seed.store.json
address qn1q...

$ qnero-wallet status
node              http://127.0.0.1:9944
runtime           spec 152, transaction 6
chain head        21 (3fff5b5b63b08e44802c652e98cc06ec8a7e8f902b1bb12aa00ab8c5b83dd065)
tree leaves       26
tree depth        3
tree root         75990b78259a9838c626e449211220f35d1a73b541dc9ca002317f26b1460a0f
last synced block (no wallet at /home/<user>/.local/share/qnero/qnero-wallet.seed)

=== 3. shield 1000 quanta from the dev account alice into A ===

$ /usr/bin/time qnero-wallet --file a.seed shield --from-dev-account alice --amount 1000 --memo 'first shield'
shielding 1000 quanta (10000000000000 planck) from alice
commitment  934a9a35feec79df35b115a3d555304c7ac70c6d643199b3f2707f453a937350
leaf        34
included    block 30 after 2.51s
synced      1 new note(s), unspent total 1000 quanta
wall 2.54 s, peak RSS 5312 KB

$ qnero-wallet --file a.seed balance
unspent        1000 quanta
pending        0 quanta
synced through block 31

      leaf        quanta    block    state  memo
        34          1000       30  unspent  first shield

=== 4. a fee below the floor, and a memo over the pad ===

$ qnero-wallet --file a.seed send --to <B> --amount 300 --fee 1 --memo 'payment to B'
Error: a fee of 1 quanta is below this submission's floor of 9. The pallet asks MinLeafFee (1) plus one quantum per started 512 bytes of ciphertext, and the two outputs here are 3974 bytes. The fee is a public input of the proof, so it cannot be raised afterwards: the settlement would be refused with PayloadUnderpaid.

$ qnero-wallet --file a.seed send --to <B> --amount 10 --memo "$(python3 -c 'print("m"*257, end="")')"
Error: the memo is 257 bytes and every memo is padded to 256. A longer one would make this note's ciphertext a different length from every other note's, which is the leak the padding closes.

=== 5. A sends 300 quanta to B at the floor ===

$ /usr/bin/time qnero-wallet --file a.seed send --to <B> --amount 300 --memo 'payment to B'
fee         9 quanta
circuits    built in 2.45s (6 leaf slots per batch)
anchor      block 41
inputs      leaves [34] for 300 quanta plus 9 fee
change      691 quanta
proof       150908 bytes
proving     3.61s
inclusion   block 45 after 1.54s
synced      1 new note(s), unspent total 691 quanta
wall 7.81 s, peak RSS 1108432 KB

=== 6. B sees the note; A sees the input spent and its change ===

$ qnero-wallet --file b.seed sync
scanned leaves 0..59 at block 50
received 1 note(s) worth 300 quanta
newly spent 0
unspent total 300 quanta

$ qnero-wallet --file b.seed balance
unspent        300 quanta
pending        0 quanta
synced through block 50

      leaf        quanta    block    state  memo
        50           300       45  unspent  payment to B

$ qnero-wallet --file a.seed balance
unspent        691 quanta
pending        0 quanta
synced through block 50

      leaf        quanta    block    state  memo
        34          1000       30    spent  first shield
        51           691       45  unspent

=== 7. B spends the note it received, back to A ===

$ /usr/bin/time qnero-wallet --file b.seed send --to <A> --amount 100 --memo 'back to A'
fee         9 quanta
circuits    built in 2.42s (6 leaf slots per batch)
anchor      block 59
inputs      leaves [50] for 100 quanta plus 9 fee
change      191 quanta
proof       150908 bytes
proving     3.58s
inclusion   block 65 after 535.45ms
synced      1 new note(s), unspent total 191 quanta
wall 6.74 s, peak RSS 1108440 KB

$ qnero-wallet --file a.seed sync
scanned leaves 59..77 at block 65
received 1 note(s) worth 100 quanta
newly spent 0
unspent total 791 quanta

$ qnero-wallet --file a.seed balance
      leaf        quanta    block    state  memo
        34          1000       30    spent  first shield
        51           691       45  unspent
        74           100       65  unspent  back to A

$ qnero-wallet --file b.seed balance
      leaf        quanta    block    state  memo
        50           300       45    spent  payment to B
        73           191       65  unspent

=== 8. what the chain published ===

$ state_getStorage Shielded::Ciphertexts(i) for the four settled output leaves
leaf 50: ciphertext 1987 bytes
leaf 51: ciphertext 1987 bytes
leaf 73: ciphertext 1987 bytes
leaf 74: ciphertext 1987 bytes

The payment carried a 12-byte memo and the change carried none, and the two
are the same length on chain. The payment took leaf 50 in the first spend and
leaf 74 in the second, so the slot draw moved between them: in the first the
change is the higher leaf and in the second it is the lower one.

=== 9. a hostile memo cannot drive the terminal ===

$ qnero-wallet --file b.seed send --to <A> --amount 10 --memo $'\r\x1b[2K        99      999999       1  unspent  forged'
fee         9 quanta
proving     3.59s
inclusion   block 98 after 536.13ms

$ qnero-wallet --file a.seed sync && qnero-wallet --file a.seed balance | cat -v
      leaf        quanta    block    state  memo
        34          1000       30    spent  first shield
        51           691       45  unspent
        74           100       65  unspent  back to A
       109            10       98  unspent  \u{0d}\u{1b}[2K        99      999999       1  unspent  forged

Piped through `cat -v`, so a surviving ESC would read as `^[`. The escape
sequence the sender chose is inert text on one row.

=== 10. the same flow as an integration test, then stop the node ===

$ QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
    -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
shield of 1000 quanta included at block 106 (1.51s), leaf 120
300 quanta to B: proved in 3.57s, 150908 proof bytes, included at block 113
100 quanta back to A: proved in 3.40s, included at block 117
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok
test result: ok. 1 passed; 0 failed

$ kill $(cat node.pid), then wait for 9944 to close
9944 has no listener
```

### Gates

```
# in the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   all suites ok, 0 failed (the dev-node e2e skips itself without QNERO_DEV_NODE,
   the public-batch measurement stays ignored)
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
```

### What the fix pass cost

One quantum of fee per spend. The floor is
`MinLeafFee(1) + ceil(3974 / 512) = 9` where it was
`MinLeafFee(1) + ceil(3474 / 512) = 8`, because padding both memos to 256 bytes
takes the pair from 3474 bytes to 3974. Nothing else moved: the proof is the
same 150908 bytes, proving is the same 3.6 s, and the padded plaintext is
stripped back on receive.

## The second M5 review fix pass, 2026-09-12

Ten review findings, two of them high or medium on the sync path and two on
what the memo pad costs the chain. The fix pass re-ran the whole end-to-end
flow against a fresh `--dev --tmp` node, because one change moves numbers the
run above recorded: the memo pad is 61 bytes where it was 256, so each output
ciphertext is a uniform 1792 bytes and the submission floor is back to 8
quanta.

### What changed

- **A fork is detected through the block hashes a sync records.** The previous pass repaired a
  note's leaf index only when the scan happened to walk that leaf again, and
  the scan starts at the watermark, which only moves forward. A reorg happens
  because the replacement branch is heavier, so a re-included commitment
  normally lands at or below where it was: below the watermark, outside every
  later scan, and the store kept an index that now holds somebody else's
  commitment. The
  store now keeps a checkpoint per sync, the block it finished at and the
  watermark it left, and a sync asks `chain_getBlockHash` at the newest
  checkpoint's height before it computes the range. A mismatch pops the
  checkpoint and the watermark rewinds to the newest survivor, so every moved
  leaf is inside the next scan. It deliberately does not re-read
  `ZkTree::Leaves` at the wallet's own leaf indices, which would be cheaper and
  would name those leaves to the node.
- **Spent status is derived on every sync.** The settled set is repaged whole on
  every sync, and the flag was only ever set true. A settlement whose block was
  orphaned and which did not re-land left its note reported spent forever, out
  of the balance and unselectable, with the value fully spendable on chain.
  Every note's flag is now recomputed from the set each sync, in both
  directions. `submit_spend` still latches, which covers the window before the
  next sync repages.
- **The memo pad is chosen against the fee.**
  `ShieldedCiphertextBytesPerFeeQuantum` (512) is sized so a real ciphertext
  pair and a pair padded to `MaxCiphertextBytes` fall in different buckets,
  since the chain never parses those bytes and `Shielded::Ciphertexts` is never
  pruned. A 256-byte pad put a real pair at 3974 bytes, in the cap's own
  bucket, so a settler could pad both ciphertexts to the cap and write 512
  bytes of permanent state per slot for what an honest spend pays. The pad is
  61, the largest that keeps the pair a bucket below. The pallet's endpoint
  test now pins `1731 + pad` against the cap, where it pinned a bare 1731: a
  slot no wallet on this chain produces.
- **The memo budget counts terminal columns.** It counted characters, and the
  balance table spends 44 columns before the memo, so a memo of full-width
  characters drew a row past any ordinary terminal, wrapped, and let the sender
  shape the continuation line into a forged balance row without one control
  byte. Everything outside printable ASCII is escaped now, so a character is a
  column, and the budget is the terminal width less the prefix.
- **The compiled-in pad is checked against the runtime's own cap** once per
  command, because every other chain value this wallet uses is read from
  metadata and this one cannot be. The oversized-ciphertext message names the
  pad, where it used to send an operator after a memo length that no longer
  moves the ciphertext.
- Plus: `StoredNote` and `RejectedNote` redact the nullifier in `Debug`, which
  for an unspent note is a value nobody has published; `rho` and `r` are held
  in a `SecretHex` that zeroizes on drop, so the copies `serde_json` allocates
  are wiped and not merely freed; and a stale parity claim beside the
  ciphertext-size test was corrected.

### The run

```text
=== 1. a fresh dev node ===

$ nohup nice -n 19 ./chain/target/release/quantus-node --dev --tmp > node.log 2>&1 &
$ echo $! > node.pid
$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*
LISTEN 0      1024            [::1]:9944          [::]:*

=== 2. two wallets ===

$ qnero-wallet --file a.seed keygen
seed    a.seed
store   a.seed.store.json
address qn1qydhanly96tgp395mrlnly...pfjdsm4hu49zuvrhkkemggq57g4w94
$ qnero-wallet --file b.seed keygen
address qn1qxp99c33g3y5mgg7h4z9yc...25wplz5frmdf2gy8ukvhyrj

$ qnero-wallet status
node              http://127.0.0.1:9944
runtime           spec 152, transaction 6
chain head        10 (485d6683a42c27b40dc2b194f96c11f7d013322ecb9795fbcc2915c35a81f3b4)
tree leaves       15
tree depth        2
tree root         e292a9fb9cae69dfa565d86eb31f09303983d40638792090646a0c8403ecc12b

=== 3. shield 1000 quanta from the dev account alice into A ===

$ /usr/bin/time qnero-wallet --file a.seed shield --from-dev-account alice --amount 1000 --memo 'first shield'
shielding 1000 quanta (10000000000000 planck) from alice
commitment  d3ccd8713f39ca68f30523da18f43a7bf7cf8803570101e213d896610e6416cf
leaf        20
included    block 16 after 506.06ms
synced      1 new note(s), unspent total 1000 quanta
wall 0.55 s, peak RSS 5176 KB

$ qnero-wallet --file a.seed balance
unspent        1000 quanta
pending        0 quanta
synced through block 16

      leaf        quanta    block    state  memo
        20          1000       16  unspent  first shield

=== 4. a fee below the floor, and a memo over the pad ===

$ qnero-wallet --file a.seed send --to <B> --amount 300 --fee 1 --memo 'payment to B'
Error: a fee of 1 quanta is below this submission's floor of 8. The pallet asks MinLeafFee (1) plus one quantum per started 512 bytes of ciphertext, and the two outputs here are 3584 bytes. The fee is a public input of the proof, so it cannot be raised afterwards: the settlement would be refused with PayloadUnderpaid.

$ qnero-wallet --file a.seed send --to <B> --amount 10 --memo "$(python3 -c 'print("m"*62, end="")')"
Error: the memo is 62 bytes and every memo is padded to 61. A longer one would make this note's ciphertext a different length from every other note's, which is the leak the padding closes.

=== 5. A sends 300 quanta to B at the floor ===

$ /usr/bin/time qnero-wallet --file a.seed send --to <B> --amount 300 --memo 'payment to B'
fee         8 quanta
circuits    built in 2.38s (6 leaf slots per batch)
anchor      block 30
inputs      leaves [20] for 300 quanta plus 8 fee
change      692 quanta
proof       150908 bytes
proving     3.34s
inclusion   block 37 after 536.30ms
synced      1 new note(s), unspent total 692 quanta
wall 6.47 s, peak RSS 1108500 KB

=== 6. B sees the note; A sees the input spent and its change ===

$ qnero-wallet --file b.seed sync
scanned leaves 0..50 at block 41
received 1 note(s) worth 300 quanta
newly spent 0
unspent total 300 quanta

$ qnero-wallet --file b.seed balance
      leaf        quanta    block    state  memo
        42           300       37  unspent  payment to B

$ qnero-wallet --file a.seed balance
      leaf        quanta    block    state  memo
        20          1000       16    spent  first shield
        43           692       37  unspent

=== 7. B spends the note it received, back to A ===

$ /usr/bin/time qnero-wallet --file b.seed send --to <A> --amount 100 --memo 'back to A'
fee         8 quanta
circuits    built in 2.31s (6 leaf slots per batch)
anchor      block 49
inputs      leaves [42] for 100 quanta plus 8 fee
change      192 quanta
proof       150908 bytes
proving     3.51s
inclusion   block 50 after 533.33ms
synced      1 new note(s), unspent total 192 quanta
wall 6.56 s, peak RSS 1108188 KB

$ qnero-wallet --file a.seed sync
scanned leaves 47..63 at block 51
received 1 note(s) worth 100 quanta
newly spent 0
unspent total 792 quanta

$ qnero-wallet --file a.seed balance
      leaf        quanta    block    state  memo
        20          1000       16    spent  first shield
        43           692       37  unspent
        58           100       50  unspent  back to A

$ qnero-wallet --file b.seed balance
      leaf        quanta    block    state  memo
        42           300       37    spent  payment to B
        59           192       50  unspent

=== 8. what the chain published ===

$ state_getStorage Shielded::Ciphertexts(i), for the shield and the four spend outputs
leaf 20: ciphertext 1792 bytes
leaf 42: ciphertext 1792 bytes
leaf 43: ciphertext 1792 bytes
leaf 58: ciphertext 1792 bytes
leaf 59: ciphertext 1792 bytes

1792 is 1731 plus the 61-byte pad. The payment carried a 12-byte memo, the
change carried none and the shield carried another, and all five are one
length on chain. The pair per spend is 3584 bytes, which is `ceil(3584 / 512)
= 7` quanta of payload where a pair padded to the cap is 8: the separation the
divisor exists for is back.

=== 9. a hostile memo cannot drive the terminal, or widen the row ===

$ qnero-wallet --file b.seed send --to <A> --amount 10 \
    --memo $'\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\uff10\r\x1b[2K 99 999999 1 unspent'
fee         8 quanta
proving     3.51s
inclusion   block 97 after 533.74ms

$ qnero-wallet --file a.seed sync && qnero-wallet --file a.seed balance | cat -v
      leaf        quanta    block    state  memo
        20          1000       16    spent  first shield
        43           692       37  unspent
        58           100       50  unspent  back to A
       108            10       97  unspent  \u{ff10}\u{ff10}\u{ff10}\u{ff10}...

$ qnero-wallet --file a.seed balance | tail -5 | awk '{print length($0)}'
48
56
44
53
79

61 bytes of memo, thirteen full-width digits and then an escape sequence. Every
character outside printable ASCII is escaped, so the count and the column width
are the same number, and the row is 79 columns: one row on an 80-column
terminal. Piped through `cat -v`, so a surviving ESC would read as `^[`.

=== 10. the same flow as an integration test, then stop the node ===

$ QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
    -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
shield of 1000 quanta included at block 115 (1.01s), leaf 129
300 quanta to B: proved in 3.45s, 150908 proof bytes, included at block 122
100 quanta back to A: proved in 3.49s, included at block 130
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok
test result: ok. 1 passed; 0 failed

$ kill $(cat node.pid), then wait for 9944 to close
9944 has no listener
```

The store the run left behind is version 3 and carries six checkpoints, the
newest `{ block_number: 101, next_leaf: 116 }`. A dev chain does not reorg, so
the fork path is covered by `tests/sync_reorg.rs` against the scriptable node:
a commitment re-included below the watermark, one re-included at it, and a
settlement orphaned out of `UsedNullifiers`.

### Gates

```
# the chain workspace, for the endpoint test the memo pad is chosen against
cd chain && LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo test -j 4 -p pallet-shielded
   61 passed, 0 failed, 1 ignored

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   36 suites ok, 0 failed (the dev-node e2e skips itself without QNERO_DEV_NODE,
   the public-batch measurement stays ignored)
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
```

### What the fix pass cost

One quantum of fee back per spend, and 195 bytes of memo. The floor is
`MinLeafFee(1) + ceil(3584 / 512) = 8` where the 256-byte pad made it
`MinLeafFee(1) + ceil(3974 / 512) = 9`, and a memo is 61 bytes where it was
256. Nothing else moved: the proof is the same 150908 bytes, proving is the
same 3.4 s, and every ciphertext the chain carries is still one length.

## The third M5 review fix pass, 2026-09-12

Ten review findings against the fork-rewind commit: one high, four medium, five
low. The high one and two of the mediums are on the sync path, one medium is
the fee bound the memo pad is chosen against, one is the `balance` table's memo
column, and the lows are the store file, note-secret wiping and three stale
figures in the docs and the pallet.

The whole end-to-end flow was re-run against a fresh `--dev --tmp` node,
because the store format moved to version 4.

### What changed

- **A note the chain no longer carries leaves the balance.** The rescan already
  computed the fact and reported a count, and then wrote nothing down. The note
  kept `spent: false`, so `unspent_total` and the `balance` table reported value
  the chain does not back, permanently and with no marker in the file; `balance`
  does not sync, so the one-off line was never seen again. The selection picks
  largest first, so a phantom larger than every real note also failed every
  later `send` on the path rebuild. `StoredNote` carries `on_chain` now, the
  rescan sets it false for exactly the notes it walked past without finding,
  `relocate_note` sets it true the moment a scan sees the commitment again, and
  `unspent()` skips it so the total, the selection and the table agree with the
  chain. `balance` lists such notes under a heading of their own with the
  reason.
- **The vanished count is taken after the spent flags are derived.** It read
  `!note.spent` against the flags the reconciliation four lines later was about
  to flip, so a note that was spent and whose own creating leaf was orphaned in
  the same reorg was skipped, and then came back into the balance as a phantom
  nobody had been told about. The operator was told one note was missing while
  two were.
- **The memo pad is checked against the bound that chose it.** The guard added
  last pass compared `CIPHERTEXT_FIXED_BYTES + MEMO_BYTES` against
  `MaxCiphertextBytes`, which is the looser of the two bounds. The tighter one
  is the fee, and nothing compared the compiled-in pad against the runtime's own
  `CiphertextBytesPerFeeQuantum`, so a runtime that widened the divisor with the
  cap untouched re-opened the free-padding hole the previous pass closed and
  both existing gates stayed green, each pinning 61 against a fixture of its
  own. `ensure_memo_pad_fits` now evaluates both bounds against the metadata the
  wallet actually fetched, and names the largest pad that restores the
  separation, or says no pad does.
- **A fork rescan records one refusal per refused output.** A refused note is
  never added to the note list, so `has_commitment` does not see it and the
  rescan decrypts and refuses it again. Neither branch asked whether the
  `rejected` list already held that commitment, so every fork touching the range
  appended another identical entry and `balance` printed one line per copy. It
  is keyed on the commitment now and a later rescan moves the entry's leaf
  index.
- **The `balance` table asks the terminal for its width.** It read `COLUMNS`,
  which bash and zsh maintain without exporting, so no child process ever saw
  one and every row was drawn at 80 columns whatever terminal it was printed
  into. On a 64-column terminal the last sixteen of those columns opened a fresh
  line at column 1 made entirely of printable ASCII the sender chose, which is
  the forged row the escaping exists to close, reached without one control
  character. The width comes from `TIOCGWINSZ` on standard output now, with
  `COLUMNS` and then 80 as fallbacks; the table prefix is measured from the
  fields it is about to print rather than assumed at 44; and the sixteen-column
  floor is gone, since a floor is a budget that overrides the terminal in the
  other direction. A terminal too narrow for the prefix and a usable memo column
  puts the memo on a line of its own, indented and budgeted the same way.
- **The settled nullifier set is no longer written to disk.** Every reader runs
  inside the sync that just repaged it, so the persisted copy never produced a
  cache hit while it grew the file with the whole chain's activity instead of
  this wallet's. It is `#[serde(skip)]`.
- **A note's nullifier is wiped when it drops.** It sat in a plain `String`
  beside `rho` and `r` in `SecretHex`, on the weaker half of the argument: for a
  note that has not been spent the nullifier has never appeared anywhere, which
  is why the `Debug` impls already redact it. The duplicate check a scan runs is
  a scan over the notes now, where it used to clone every held nullifier into a
  fresh set once per received note and drop each copy unwiped.
- **Three stale figures.** `docs/BENCH.md`'s proof-size table labelled 157476
  bytes as the `N = 6` private batch, which is the M3 `N = 7` measurement; the
  chain default produces 150908. `MAX_PROOF_BYTES`' own documentation still said
  the public batch had never been produced at `n = 53` and that its size was a
  213 KB estimate M5 owed, which M5 measured at 237544. The same claim was
  repeated in the pallet's tests.

### The store format

Version 4. `on_chain` is new on every note, and `used_nullifiers` is gone from
the file. A version-3 store upgrades in place: its notes read as on chain, which
is what every note in one is, and its checkpoints are kept because their block
hashes came from the same chain. A version-2 store upgrades with an empty
checkpoint list. A version-1 store is still refused.

### The run

Fresh seed files, a fresh `--dev --tmp` node, addresses truncated in the middle.

```text
=== 1. start a fresh dev node ===

$ nice -n 19 ./chain/target/release/quantus-node --dev --tmp   (backgrounded, pidfile)

$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*
LISTEN 0      1024            [::1]:9944          [::]:*

=== 2. two wallets ===

$ qnero-wallet --file A.seed keygen
seed    A.seed
store   A.seed.store.json
address qn1q9r6ynpyvvjl0tym0c2u...gsm44a9v

$ qnero-wallet --file A.seed status
node              http://127.0.0.1:9944
runtime           spec 152, transaction 6
chain head        9 (41ce10945df88e4ff24f7daec47edb409db65014e1923f920b2b938a5345cfc0)
tree leaves       14
tree depth        2
tree root         ae442fdfc28b12f42070bed89ad069dbc198a545fe9a7b4b33db26146d4a9671
last synced block 0
next leaf to scan 0

$ qnero-wallet --file B.seed keygen
address qn1qx5cyal7ea3984tfsute...dsc9szhe

=== 3. shield 1000 quanta from the dev account alice into A ===

$ qnero-wallet --file A.seed shield --from-dev-account alice --amount 1000 --memo 'first shield'
shielding 1000 quanta (10000000000000 planck) from alice
commitment  07693db050f97ba4523eed7c17a427e085212ef7d5c15d3e70e1fbb64377e40f
leaf        24
included    block 20 after 1.01s
synced      1 new note(s), unspent total 1000 quanta

=== 4. a fee below the floor is refused ===

$ qnero-wallet --file A.seed send --to <B> --amount 300 --fee 1 --memo 'payment to B'
Error: a fee of 1 quanta is below this submission's floor of 8. The pallet asks MinLeafFee (1) plus one quantum per started 512 bytes of ciphertext, and the two outputs here are 3584 bytes. The fee is a public input of the proof, so it cannot be raised afterwards: the settlement would be refused with PayloadUnderpaid.

=== 5. A sends 300 quanta to B at the floor ===

$ time qnero-wallet --file A.seed send --to <B> --amount 300 --memo 'payment to B'
fee         8 quanta
circuits    built in 2.48s (6 leaf slots per batch)
anchor      block 31
inputs      leaves [24] for 300 quanta plus 8 fee
change      692 quanta
proof       150908 bytes
proving     3.40s
inclusion   block 34 after 535.02ms
synced      1 new note(s), unspent total 692 quanta
wall clock  6.61 s

=== 6. B sees the note; A sees the input spent and its change ===

$ qnero-wallet --file B.seed sync
scanned leaves 0..43 at block 34
received 1 note(s) worth 300 quanta
newly spent 0
unspent total 300 quanta

$ qnero-wallet --file B.seed balance
address        qn1qx5cyal7ea3984tfsute...dsc9szhe
unspent        300 quanta
pending        0 quanta
synced through block 34

      leaf        quanta    block    state  memo
        40           300       34  unspent  payment to B

$ qnero-wallet --file A.seed balance
address        qn1q9r6ynpyvvjl0tym0c2u...gsm44a9v
unspent        692 quanta
pending        0 quanta
synced through block 34

      leaf        quanta    block    state  memo
        24          1000       20    spent  first shield
        39           692       34  unspent

=== 7. B spends the note it received, back to A ===

$ time qnero-wallet --file B.seed send --to <A> --amount 100 --memo 'back to A'
fee         8 quanta
circuits    built in 2.41s (6 leaf slots per batch)
anchor      block 41
inputs      leaves [40] for 100 quanta plus 8 fee
change      192 quanta
proof       150908 bytes
proving     3.57s
inclusion   block 45 after 534.19ms
synced      1 new note(s), unspent total 192 quanta
wall clock  6.71 s

$ qnero-wallet --file A.seed sync
scanned leaves 43..63 at block 51
received 1 note(s) worth 100 quanta
newly spent 0
unspent total 792 quanta

=== 8. the opt-in RPC path, and the store permission check ===

$ qnero-wallet --file A.seed send --to <B> --amount 50 --memo 'via merkle rpc' --merkle-rpc
merkle      zkTree_getMerkleProof (this names the leaves being spent to the node)
fee         8 quanta
circuits    built in 2.38s (6 leaf slots per batch)
anchor      block 53
inputs      leaves [39] for 50 quanta plus 8 fee
change      634 quanta
proof       150908 bytes
proving     3.57s
inclusion   block 57 after 1.04s
synced      1 new note(s), unspent total 734 quanta

$ chmod 644 A.seed.store.json && qnero-wallet --file A.seed balance
Error: A.seed.store.json is readable or writable beyond its owner (mode 644). Fix it with `chmod 600 A.seed.store.json`.

=== 9. the store on disk, version 4 ===

$ ls -l A.seed A.seed.store.json
-rw------- 1 waterfall waterfall   65 Sep 12 12:11 A.seed
-rw------- 1 waterfall waterfall 5654 Sep 12 12:12 A.seed.store.json

$ jq '{version, next_leaf, last_synced_block, has_used_nullifiers: has("used_nullifiers"),
      checkpoints: (.checkpoints|length),
      notes: [.notes[] | {leaf_index, value, spent, on_chain, memo}]}' A.seed.store.json
{
  "version": 4,
  "next_leaf": 72,
  "last_synced_block": 57,
  "has_used_nullifiers": false,
  "checkpoints": 5,
  "notes": [
    { "leaf_index": 24, "value": 1000, "spent": true,  "on_chain": true, "memo": "first shield" },
    { "leaf_index": 39, "value": 692,  "spent": true,  "on_chain": true, "memo": "" },
    { "leaf_index": 54, "value": 100,  "spent": false, "on_chain": true, "memo": "back to A" },
    { "leaf_index": 68, "value": 634,  "spent": false, "on_chain": true, "memo": "" }
  ]
}

=== 10. the memo column, against a memo a sender chose ===

B paid A 20 quanta with the 36-byte printable-ASCII memo
`....................unspent 99999 qu`, which is the shape the review's probe
used: nothing in it is escaped, so every character costs a column, and its tail
reads as a balance row of its own. Row widths measured with `awk`, the table
header and earlier rows elided:

COLUMNS=80   80  |       115            20       93  unspent  ....................unspent 99999 qu
COLUMNS=64   64  |       115            20       93  unspent  ....................
COLUMNS=50   42  |       115            20       93  unspent
             40  |    ....................unspent 99999 qu

At 64 the memo is truncated to the 20 columns left over, ellipsis included, and
the row is exactly 64. At 50 there are six columns left over, which is under the
sixteen-column minimum, so the memo takes an indented line of its own at 40
columns. Before this pass every one of these three ran at 80 columns.

=== 11. the same flow as an integration test, then stop the node ===

$ QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
    -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
shield of 1000 quanta included at block 72 (1.01s), leaf 86
300 quanta to B: proved in 3.55s, 150908 proof bytes, included at block 76
100 quanta back to A: proved in 3.45s, included at block 79
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok
test result: ok. 1 passed; 0 failed

$ kill $(cat node.pid), then wait for 9944 to close
9944 has no listener
```

A dev chain does not reorg, so every fork path above is covered against the
scriptable node in `tests/sync_reorg.rs`: a commitment re-included below the
watermark, one re-included at it, a settlement orphaned out of
`UsedNullifiers`, an orphaned settlement whose note leaves the balance and
comes back when the extrinsic re-lands, a spend and its own creating leaf
orphaned together, and a refused output walked by three successive rescans.

### Gates

```
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   36 suites ok, 0 failed, 4 ignored
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
  -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
   1 passed, 0 failed
```

### Timings

Two payments plus one over the RPC path, on the same workstation with
`RAYON_NUM_THREADS=4` and the crate's `parallel` feature on. Nothing in the
proving path moved: the changes are the store, the scan's bookkeeping and one
comparison per command.

| | |
|---|---:|
| `send` wall clock, whole command | 6.61 s and 6.71 s |
| of which circuit build, once per process | 2.41 s and 2.48 s |
| of which private batch proving | 3.40 s and 3.57 s |
| private batch proof | 150908 bytes, unchanged |
| submit to inclusion | 0.53 s both times |

## The fourth M5 review fix pass, 2026-09-12

Eight review findings against the balance-backing commit: one high, three
medium, four low. The high one and two of the mediums are the same fault seen
from three sides, which is that a sync trusted whatever one node answered and
had no way to tell an answer that carries less information from an answer that
carries a correction. The third medium is the duplicate-nullifier refusal,
which was permanent and decided by arrival order. The lows are a stale refusal
entry, an unwiped nullifier vector, a chain-wide property refused as if it were
this spend's problem, and a dead public API.

Four rules came out of it, and all four are properties of the sync.

### What changed

- **A node behind this wallet is refused, and the sync that refuses writes
  nothing.** Nothing required a node's view to be at least as new as the
  wallet's own last sync, and everything a sync derives is derived from what
  one node answers at one block. `reconcile_spent` derives spent status in both
  directions from `UsedNullifiers`, so a node that has not executed the block a
  settlement landed in answers a map without that nullifier and the note it
  spent came straight back into the balance; the next `send` then selected an
  input the chain had already consumed and paid a full proof to have the
  settlement skipped. The same answer moved the watermark too, because every
  checkpoint above that node's head has no block at its height. The gate is
  `head.number < last_synced_block` and it runs before the first read.
- **No block at a checkpoint height is refused, and is not a fork.** The fork
  walk treated "no block at that height" and "a different block at that height"
  as one answer. Only the second is a fork. The first is a node that does not
  reach that height, and rewinding on it rescans leaves against a tree smaller
  than the one already recorded. The walk also probes every checkpoint before
  it writes anything, so a refusal leaves the checkpoint list untouched.
- **Spent is cleared only once the node has passed the block the spend was seen
  at.** A nullifier absent from a node's map has two causes and the map alone
  cannot tell them apart: the settlement was orphaned, or the node has not
  reached it. The height gate covers the first version of that; what it cannot
  see is a spend `submit_spend` latched at an inclusion block above the
  watermark, which is every spend made since the last sync. Clearing is the
  direction that can lose money, so it is the direction that carries the
  condition. Setting is unchanged.
- **The store names the chain it belongs to.** `genesis_hash` is new and
  `STORE_VERSION` is 5. The address bound the store to a seed and nothing bound
  it to a chain, while every leaf index, block number, checkpoint hash and
  spent flag in the file is a statement about one. `--new-chain-store` archives
  the old file as `<store>.archived` rather than deleting it, since it holds
  the only copy of every note's `rho` and `r`. A version-4 store records the
  genesis of the node it is first synced against, which is the most that can be
  recovered: the version that wrote it never asked.
- **A duplicated nullifier is a conflict set.** A sender picks `rho` and `r`,
  so a sender that repeats a pair hands over two notes sharing one nullifier,
  of which at most one can ever settle. Which one is decided by the recipient
  spending it. The scan refused the second note it met, permanently, so a
  sender who put the large note second had the wallet keep the small one with
  no way back and a rescan after a fork wrote the same note off again. Every
  output is held now; `WalletStore::spendable` yields one note per nullifier,
  the largest member with ties on the leaf index, and that is what the
  selection sees, what `unspent_total` sums and what `balance` prints, once,
  with a `conflict` marker. A private batch constrains its nullifiers pairwise
  distinct, so collapsing is also what keeps two members of one set out of one
  leaf.
- **A refusal goes when the same output becomes holdable.** The one refusal
  left is a nullifier the chain has settled, which a reorg can undo. The
  rescan then held the note and `balance` printed "its nullifier is already
  settled on chain" beside a note it had just added to the balance.
- **`PreparedSpend::spent_nullifiers` is zeroized.** It was a `Vec<String>`,
  and a `PreparedSpend` exists exactly during the window between proving a
  spend and its settlement landing, so those values have appeared nowhere at
  all while it is alive. It is `Vec<SecretHex>` now, the same type `rho`, `r`
  and a held note's nullifier already used.
- **A merged fee bucket is a warning, and the spend goes ahead.** The guard
  added last pass refused every send and every shield against a runtime whose
  `CiphertextBytesPerFeeQuantum` swallowed the gap between an honest pair and a
  pair padded to the cap. That is a property of the chain: a settler pads to
  the cap whatever this wallet does, the operator cannot change the divisor,
  and this wallet shrinking its own pad alone would publish its own ciphertext
  length. `fee::memo_pad_separation_warning` says what the runtime did, once
  per process, and names the pad that would restore the separation as a
  coordinated move. The `MaxCiphertextBytes` bound stays a refusal, because
  there the extrinsic would fail to decode.
- **`render_memo` and `MEMO_DISPLAY_COLUMNS` are gone.** Dead since the table
  started measuring its own prefix and asking the terminal for its width.

### What the genesis binding does not catch

`--dev` is a fixed chain spec, so a `--dev --tmp` node that restarts on an
empty database answers the same genesis hash as the one before it. Both nodes
in the run below answered
`0xf759610207b350d194f0829b5dc0e595658e960c983665236f7b7aa05d0a8645`. The
restarted dev node is caught by the height gate while its head is below the
wallet's watermark, and after it climbs past that by the fork walk, which finds
a different block at every checkpoint height and rewinds to zero. The genesis
binding catches a store pointed at a genuinely different chain, where the fork
walk would rewind to zero and rescan against a tree that belongs to someone
else. The run shows both halves.

### The store format

Version 5. `genesis_hash` is new on the store itself and nothing else moved. A
version-4 store upgrades in place with no chain recorded, and the first sync
records the node's. Versions 3 and 2 upgrade as before. A version-1 store is
still refused.

### The run

Two `--dev --tmp` nodes in sequence, fresh seeds, addresses truncated in the
middle.

```text
=== 1. a fresh dev node, and a wallet that has never seen a chain ===

$ nice -n 19 ./chain/target/release/quantus-node --dev --tmp   (backgrounded, pidfile)
$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*
LISTEN 0      1024            [::1]:9944          [::]:*

$ qnero-wallet --file A.seed status
node              http://127.0.0.1:9944
runtime           spec 152, transaction 6
chain head        35 (eeeb57d742f40986...)
tree leaves       47
store chain       not recorded yet; the next sync records it
last synced block 0
next leaf to scan 0

$ qnero-wallet --file A.seed sync
chain       recorded this node's genesis in the store
scanned leaves 0..47 at block 35
received 0 note(s) worth 0 quanta
newly spent 0
unspent total 0 quanta

$ qnero-wallet --file A.seed status
store chain       bound to this chain
last synced block 35
next leaf to scan 47

=== 2. a shield and a payment, unchanged by this pass ===

$ qnero-wallet --file A.seed shield --from-dev-account alice --amount 1000 --memo "first shield"
shielding 1000 quanta (10000000000000 planck) from alice
commitment  8258ba3f288fae15...
leaf        65
included    block 54 after 504.85ms
synced      1 new note(s), unspent total 1000 quanta

$ qnero-wallet --file A.seed send --to qn1... --amount 300 --memo "payment to B"
fee         8 quanta
circuits    built in 2.38s (6 leaf slots per batch)
anchor      block 54
inputs      leaves [65] for 300 quanta plus 8 fee
change      692 quanta
proof       150908 bytes
proving     3.49s
inclusion   block 57 after 1.04s
synced      1 new note(s), unspent total 692 quanta

$ qnero-wallet --file B.seed sync
chain       recorded this node's genesis in the store
scanned leaves 0..73 at block 57
received 1 note(s) worth 300 quanta
unspent total 300 quanta

$ qnero-wallet --file A.seed balance
unspent        692 quanta
      leaf        quanta    block    state  memo
        65          1000       54    spent  first shield
        70           692       57  unspent

=== 3. the node is replaced by a fresh --dev --tmp node ===

$ kill $(cat node.pid), wait for 9944 to close, start a new one
9944 has no listener
9944 up after 3s
chain_getBlockHash(0) -> 0xf759610207b350d1...   (the same genesis as before)

$ qnero-wallet --file A.seed status
chain head        11 (673a511c07046579...)
tree leaves       16
store chain       bound to this chain
last synced block 57
next leaf to scan 73

$ qnero-wallet --file A.seed sync
Error: this node's head is block 11 and this wallet has synced through block 57.
A node behind the wallet answers every question with less than the wallet
already knows: notes it has not seen settled would come back into the balance,
and every checkpoint above its head would read as a fork. Nothing has been
changed. Point --node at a node that has caught up, or wait for this one to.
exit 1

$ qnero-wallet --file A.seed balance
unspent        692 quanta
      leaf        quanta    block    state  memo
        65          1000       54    spent  first shield
        70           692       57  unspent

Before this pass that sync reported 1692 quanta: the spent note came back
because the new chain has never settled its nullifier, and the watermark
rewound because the new chain has no block at any checkpoint height.
`tests/sync_guards.rs` holds the same case against the scriptable node, and
with the gate removed it reports `newly_unspent: 1, vanished: 1`.

=== 4. the new chain climbs past the old watermark ===

$ qnero-wallet --file A.seed sync
scanned leaves 0..66 at block 61
received 0 note(s) worth 0 quanta
the chain forked below block 1: rescanned leaves from 0 where this wallet had reached 73
2 note(s) this wallet holds are not on the current chain: their settlement was
orphaned and has not been re-included. [...]
newly spent 0
back in the balance 1: their settlement is no longer on the chain
unspent total 0 quanta

$ qnero-wallet --file A.seed balance
unspent        0 quanta
not on chain   1692 quanta
      leaf        quanta    block    state  memo
        65          1000       54   orphan  first shield
        70           692       57   orphan

The fork walk reaches the right answer once the node can be asked: a chain that
does not carry these commitments backs none of their value, so the unspent
total is zero and both notes are listed as orphans, with their secrets kept.

=== 5. the store on disk, version 5 ===

{
  "version": 5,
  "genesis_hash": "f759610207b350d194f0829b5dc0e595658e960c983665236f7b7aa05d0a8645",
  "last_synced_block": 61,
  "next_leaf": 66,
  "has_used_nullifiers": false,
  "notes": [
    { "leaf_index": 65, "value": 1000, "spent": false, "on_chain": false,
      "spent_seen_at_block": null },
    { "leaf_index": 70, "value": 692, "spent": false, "on_chain": false,
      "spent_seen_at_block": null }
  ],
  "checkpoints": 1
}

=== 6. stop the node ===

$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed
node stopped
```

A dev chain does not reorg and does not lag behind itself, so the rest is
covered against the scriptable node in `tests/sync_guards.rs`: a node behind
the wallet refused with the store byte-identical afterwards on disk and in
memory, a node with no block at a checkpoint height refused with no checkpoint
popped and the same height answering the same hash treated as no fork at all, a
store refused against another chain by both `open_on_chain` and `sync` with
`--new-chain-store` archiving the old file, and a conflict set spending its
largest member and reporting every member spent once the shared nullifier
settles. Each of the four was re-run with its constraint removed and each
failed.

### Gates

```
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   37 suites ok, 0 failed, 4 ignored
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
  -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
   1 passed, 0 failed
```

### What the fix pass cost

One `chain_getBlockHash(0)` per command, which is the genesis check, and one
`chain_getHeader` comparison. Nothing in the proving path moved: the proof is
the same 150908 bytes and proving is the same 3.5 s. No consensus rule, hash
layout, nullifier rule or `rho` rule changed, so no KAT vector was regenerated.

## The fifth M5 review fix pass, 2026-09-12

Eight review findings against the node-gate commit: one high, two medium, five
low. The high one and the two mediums are one fault seen from three sides. The
sync asked the node three separate questions, a block-height comparison, a
checkpoint-hash walk and nothing at all about the leaf count, and the three
could contradict each other. The lows are an off-chain total that did not
collapse conflict sets, a section of `docs/CIRCUIT.md` still prescribing the
refusal conflict sets replaced, two doc comments that described behaviour the
code does not have, and a store upgrade with no recovery path.

### What changed

- **One walk, keyed on checkpoint hashes, answers both node questions.** Is
  this node on the wallet's chain, and has it reached everything the wallet has
  read. The walk goes newest first. A checkpoint above the node's head is
  skipped, because on its own it says nothing: the node may be behind, or that
  checkpoint may belong to a branch the node has replaced. The first checkpoint
  at or below the head decides it. Same hash and nothing skipped: the scan runs
  from the watermark the store holds. Same hash with something skipped: the
  node is behind the wallet on the wallet's own chain and the sync refuses.
  Different hash: a fork, and the walk continues down to the newest checkpoint
  that still stands, which is where the watermark and `last_synced_block` both
  rewind to. No block at all at a height at or below the head stays what it
  was, a refusal by name.
- **`last_synced_block` is allowed to go down.** Heaviest-chain rules do not
  order branches by length, so a reorg onto a heavier shorter branch leaves a
  head below a height the wallet recorded on a branch that no longer exists.
  The height comparison refused every sync until the chain climbed back, and
  the note that moved leaf in that reorg sat at its old index for the whole
  window, unspendable, with `balance` reporting it spendable. A height is a
  statement about one branch, and when the branch is gone the statement goes
  with it.
- **The leaf watermark is a gate.** `ZkTree::LeafCount` at the node's head is
  read before the scan and a count below the watermark the scan would start
  from is refused. A node can be on this wallet's chain, at a head above every
  checkpoint, and answer a shorter tree: the count is a statement about the
  state it has executed. The scan range was then empty, so the scan and the
  vanished-note check were both skipped while `next_leaf` was written back down
  to the node's count. A fork does not reach this gate, because the rewind
  takes the watermark to a checkpoint whose hash stands on the node's own
  branch and a tree only grows along one chain. So a short tree is lag, and the
  watermark never regresses outside the fork path.
- **The genesis binding is written by the operation that commits.** Opening a
  wallet on a chain recorded the genesis and saved it before any gate had run,
  so a store with no chain yet was bound by whichever node it was first pointed
  at, including one the very next check refused. A wallet opened once against a
  wrong `--node` then named that chain permanently and every later sync against
  the right node refused with a mismatch the operator never chose. Opening
  checks and writes nothing; the successful sync, shield or send records it.
- **`sync --rescan`.** Drops the watermark to zero and walks the whole tree
  again, keeping every note. It is the recovery for a store an older build
  wrote: that build refused the second note it met sharing a nullifier with one
  already held, kept no copy of that note's `rho` and `r`, and left the leaf
  below the watermark where no later sync reads it. The secrets are not in the
  file to restore; they are on chain inside the ciphertext. Keeping the notes
  is the difference from deleting the store, since a note the current chain no
  longer carries would otherwise lose the secrets that are the only handle on a
  settlement that can still be re-included.
- **`off_chain_total` collapses conflict sets, the way `off_chain_rows`
  already did.** The `balance` heading and the table under it disagreed on a
  number they both compute from the same notes, and the heading counted value
  the chain could never back even if every settlement re-landed.
- **`docs/CIRCUIT.md` section 9.8 describes conflict sets.** It still asked a
  wallet to refuse a received note whose nullifier duplicates one it holds,
  which is the rule the previous pass replaced. The recipient rule is about
  counting: hold every member, count the set once at the value a spend would
  use, and never put two members in one leaf.
- **Two doc comments now match the code.** `Chain::block_hash_at_height` said a
  missing block is the fork itself. `archive_store` said the filename carries
  the genesis the store was bound to; it carries `.archived` and a counter, and
  the genesis is inside the file.

### Tests

Four new cases in `tests/sync_guards.rs`, one per finding that needed one, and
each was re-run with its constraint removed:

- A lagging node on the same chain, with a checkpoint below its head whose hash
  still stands and a tree the same size, is refused and writes nothing. Drop
  the count of skipped checkpoints and the sync runs, reporting `held_spent: 1`
  against a node that has not executed the settlement.
- A reorg onto a heavier shorter branch, a different hash at a checkpoint below
  the head and a head below `last_synced_block`, is a fork and syncs: the
  survivor is the newest checkpoint that stands, the moved note is relocated,
  and `last_synced_block` follows the survivor downwards from 21 to 17. Put the
  height comparison back and it is refused.
- A leaf count below the watermark with every checkpoint hash standing is
  refused and the watermark is unchanged. Remove the gate and `next_leaf` goes
  from 6 to 4 with the scan and the vanished check both skipped.
- A refused sync leaves a fresh store bound to no chain, and the same wallet
  then binds to the node the operator meant. Bind at open and the store is
  already named after the wrong node, so the second sync refuses.

Plus `store.rs::the_off_chain_heading_is_the_sum_of_the_off_chain_table` for
the low, and a rescan case covering both halves of `--rescan`: a leaf below the
watermark recovered into a conflict set, and a note the chain no longer carries
marked off chain while its secrets stay.

### The run

```text
=== 1. a fresh dev node and a wallet that has never seen a chain ===

$ nice -n 19 ./chain/target/release/quantus-node --dev --tmp   (backgrounded, pidfile)
$ ss -ltn | grep 9944
LISTEN 0      1024        127.0.0.1:9944       0.0.0.0:*
LISTEN 0      1024            [::1]:9944          [::]:*
port 9944 open after 1s

$ qnero-wallet --file cli2.seed sync
chain       this store names no chain yet. The first sync, shield or send that commits records this node's genesis.
chain       recorded this node's genesis in the store
scanned leaves 0..84 at block 72
received 0 note(s) worth 0 quanta
newly spent 0
unspent total 0 quanta

$ qnero-wallet --file cli2.seed sync
scanned leaves 84..84 at block 72
received 0 note(s) worth 0 quanta
newly spent 0
unspent total 0 quanta

The binding line before the sync says what will happen and the line after says
that it did. A sync that refuses prints the first and not the second, and the
store on disk names no chain.

=== 2. --rescan against the same node ===

$ qnero-wallet --file cli.seed sync --rescan
scanned leaves 0..58 at block 46
received 0 note(s) worth 0 quanta
rescanned the whole tree from leaf 0, where this wallet had reached 58. Every note already held is kept.
newly spent 0
unspent total 0 quanta

A rescan reports itself as a rescan. It is not a fork and does not print the
fork line, which names the block the chain forked below.

=== 3. the end-to-end flow, unchanged by this pass ===

shield of 1000 quanta included at block 292 (2.01s), leaf 303
300 quanta to B: proved in 3.57s, 150908 proof bytes, included at block 297
100 quanta back to A: proved in 3.42s, included at block 301

=== 4. stop the node ===

$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed after 1s
node stopped
```

A dev chain does not reorg, does not lag behind itself and does not serve a
tree shorter than the state it has executed, so the four gate cases are covered
against the scriptable node in `tests/sync_guards.rs`, each with its constraint
removed once to show the test fails.

### Gates

```
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   37 suites ok, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean
QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 cargo test \
  -j 2 --release -p qnero-wallet --features parallel --test dev_node_e2e -- --nocapture
   1 passed, 0 failed
```

### What the fix pass cost

One `ZkTree::LeafCount` read that the sync already made, moved ahead of the
scan, and the checkpoint walk still stops at the first checkpoint that stands,
so the ordinary cost is the one `chain_getBlockHash` it always was. A lagging
node is now refused before `UsedNullifiers` is paged, which is one fewer whole
map read on the path that refuses. Nothing in the proving path moved: the proof
is the same 150908 bytes and proving is the same 3.5 s. No consensus rule, hash
layout, nullifier rule or `rho` rule changed, so no KAT vector was regenerated.

## The M6 run: v1 mandatory privacy, 2026-09-12

Every unit of value that enters circulation is a shielded note, and no call a
user can make moves transparent value between accounts. Development
workstation, 20 cores, WSL2.

### What changed

- **The block reward is a note.** `pallet-mining-rewards` computes the emission and collects fees as
  before and mints nothing to an account; `pallet-shielded` takes the credit through a
  `CoinbaseSink` and turns it into the block's coinbase note, with the author's share of every fee
  the block settled folded in. The payload comes from a required inherent the author's node
  supplies. `docs/DESIGN.md` section 7.1 and `docs/CIRCUIT.md` section 10.
- **The author's fee share stopped being a transparent credit**, which removed the last reason for
  the wormhole leaf that made a keyless account's balance spendable.
- **`BaseCallFilter` refuses every call that moves transparent value between accounts**, the
  wrappers included. `docs/DESIGN.md` section 7.2 is the allowlist.
- **`pallet-wormhole` left the runtime** with its transaction extension and its migration, taking
  the transparent exit with it. The crate stays in the tree and `qp-wormhole`, the primitives crate,
  stays in the runtime: the author derivation is there.
- **The runtime says what it is.** `spec_name` `qnero`, `impl_name` `qnero-node`, `spec_version`
  100, `transaction_version` 7. The node reports `Qnero Node` and the dev chain is `Qnero DevNet` at
  id `qnero-dev`.
- **One author seam.** `configs::QpowAuthor`, a `FindAuthor` implementation, is the only place the
  runtime reads consensus. See "The block-author seam" above.
- **The wallet finds the blocks it mined**, from a miner key the node is configured with, and
  `miner-address` prints that key.

### The run

The miner's wallet is made first, because the node is configured with a key it
prints.

```
$ qnero-wallet --file /tmp/qnero-m6/miner.seed keygen
seed    /tmp/qnero-m6/miner.seed
store   /tmp/qnero-m6/miner.seed.store.json
address qn1qywupkzeswff4n96l3ts7e9pxg5f… (2571 characters)

$ QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6/miner.seed miner-address)
   qnm1qywupkzeswff…gemxynpz (114 characters)

$ QNERO_MINER_KEY=$QNERO_MINER_KEY nice -n 19 ./target/release/quantus-node --dev --tmp
2026-09-12 17:24:32 Qnero Node
2026-09-12 17:24:32 📋 Chain specification: Qnero DevNet
2026-09-12 17:24:32 💾 Database: RocksDb at /tmp/substrate…/chains/qnero-dev/db/full
2026-09-12 17:24:32 ⛏️ Using treasury address for rewards: 6d6f646c70792f7472737279… (qzmviwoP…)
2026-09-12 17:24:32 ⛏️ Coinbase notes are minted for pk 1dc0d85983929acc…
```

The chain says what it is:

```
$ curl … state_getRuntimeVersion
{'specName': 'qnero', 'implName': 'qnero-node', 'specVersion': 100, 'transactionVersion': 7}
$ curl … system_chain
"Qnero DevNet"
```

**The miner is paid in notes.** Twenty-three blocks in, the wallet holds one
note per block and nothing else. The tree holds nothing else either: 23 blocks,
23 leaves.

```
$ qnero-wallet --file /tmp/qnero-m6/miner.seed sync
scanned leaves 0..23 at block 23
received 23 note(s) worth 945 quanta

$ qnero-wallet --file /tmp/qnero-m6/miner.seed balance
unspent        945 quanta
synced through block 23

      leaf        quanta    block    state  memo
         0            41        1  unspent
         1            41        2  unspent
         …
         8            42        9  unspent
         …
        22            41       23  unspent

$ qnero-wallet --file /tmp/qnero-m6/miner.seed status
runtime           spec 100, transaction 7
chain head        23
tree leaves       23
tree depth        3
```

41 quanta is the emission at genesis supply, `(21_000_000 - 0) / 50_000_000`
QTC quantized down to a whole pool quantum. The occasional 42 is the carry: a
block's credit is not a whole number of quanta, the remainder waits in
`PendingCoinbaseFee`, and every eighth block or so it completes one. Nothing is
lost between the two books and nothing is created.

**A mined note spends like any other, and the fee comes back in the next
coinbase.** The end-to-end test drives this, against the same node:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=/tmp/qnero-m6/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture \
    the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused

sync: 36 leaves, 36 coinbase leaves, 36 of them this wallet's, 4975 quanta
5 quanta to B at fee 8: included at block 124, change 29
coinbase of block 124: 45 quanta against 41 to 42 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
test the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused ... ok
```

Four things in four lines:

1. **Every block's coinbase is this wallet's**, and the scan says so in both counts.
2. **A coinbase note spends.** 42 in, 5 to B, 8 of fee, 29 of change, and B's own sync finds its
   note at 5 quanta with the memo the sender wrote. The fee is the submission's floor, which at two
   ciphertexts of 1731 bytes is 8 quanta; the milestone's "fee 1" is below it and the chain refuses
   a fee below the floor, which is the anti-spam rule M4 built.
3. **The author's share of that fee is in the coinbase of the block that settled it**: 45 against 41
   elsewhere, and the share of an 8-quantum fee is 8 - ceil(8/2) = 4. It is in that block's note and
   in no other.
4. **A transparent transfer is refused.** `0x0001030005000000` is
   `Ok(Err(DispatchError::Module { index: 0, error: [5, 0, 0, 0] }))`: `frame_system` is pallet 0
   and `CallFiltered` is its sixth error. The extrinsic is signed with a genuine ML-DSA key, passes
   every transaction extension, and is refused at dispatch.

The wallet's own view afterwards, with the settlement in it:

```
      leaf        quanta    block    state  memo
         8            42        9    spent          <- the note that paid B
       123            29      124  unspent          <- the change
       125            45      124  unspent          <- the coinbase of the settling block
       126            41      125  unspent
```

Leaf 124, between the change and the coinbase, is B's note. This wallet cannot
read it, which is the point.

### Gates

```
# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   38 suites ok, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean

# the chain workspace
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p pallet-zk-tree --release
   74 + 30 + 35 passed, 0 failed
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p quantus-runtime --release
   41 lib + 6 call_filter + 59 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p quantus-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p quantus-node --all-targets
   no warnings
```

`cargo test -p quantus-runtime` is a gate again. It had not compiled since the
M4 subtree fork; see "Tests" above for what it covers now.

### Timings

Development workstation, 20 cores, WSL2, `nice -n 19`, `-j 4`.

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build --release -p quantus-node`, cold for the runtime wasm | 10:35 | 5.4 GB |
| the same after a runtime source change, artifacts cached | 1:05 | |
| chain pallet tests (`pallet-shielded`, real proofs) | 25 s | |
| runtime tests, all three targets | under 1 s | |
| root workspace tests | 2:40 | |
| the end-to-end, including one private-batch proof at four threads | 8.3 s | |

The node was built three times over the milestone rather than once: the first
build predated the vesting proof-recorder fix, and the second found the
`pre_dispatch` bug through the end-to-end, which is what an end-to-end is for.
Only the first paid the full wasm cost.

The whole run above was repeated against the binary built from the committed
tree, on a fresh `--tmp` chain, and reproduced every number: fee 8, change 29,
the settling block's coinbase 45 against 41 to 42 elsewhere, an author share of
4, and `0x0001030005000000` from the dry run. Only the heights differ, because
the second chain was younger. The node was stopped by pidfile afterwards and
port 9944 confirmed closed.

## The M6 fix pass: what the review found, 2026-09-12

Six defects in the milestone above, three of them things a chain would have
lived with for a long time before anyone noticed. Same workstation, same rules.

### What changed

- **The header stopped naming the miner.** Every block carried `--rewards-inner-hash` verbatim in
  its `PreRuntime` item and `CoinbaseCredited` named the account derived from it, so beside
  `Shielded::CoinbaseValues` and `Shielded::LeafBlocks` an observer could partition the tree by
  miner and read each miner's income block by block. An authoring node now publishes
  `H(cvk, parent_hash)` and the events carry amounts and no accounts. See "The block-author seam"
  above.
- **`set_high_security` is refused.** It was a one-way door into a feature whose every call v1
  refuses: from the block it succeeded in, the account's whitelisted calls died at dispatch on the
  filter and everything else died at validation on the whitelist, `shield` included. Its whole
  balance was then unreachable, and the guardian could not sweep it either. `shield` and `burn`
  joined the whitelist so an account enrolled before v1 keeps a way out.
- **`Vesting::claim` is dispatchable again.** Every preset endows a keyless vesting pot against
  genesis schedules, so refusing the claim stranded the whole genesis allocation inside
  `total_issuance`, where the emission counts it as supply forever. The other half of that decision
  is that no preset may endow an account that cannot sign: the dev preset's keyless wormhole test
  address lost its endowment and its schedule with it.
- **The coinbase inherent refuses an encrypted payload.** Nothing builds one, an inherent pays no
  fee and a mandatory dispatch does not compete for block weight, so the field was the only place
  on the chain where an author could buy permanent state for nothing.
- **A block with no emission still mints.** The author's share of a settled fee only leaves
  `PendingCoinbaseFee` through a mint, so a zero credit now reaches the pool anyway. Without that,
  every settled fee's author share would strand from the moment emission rounds to zero.
- **The filter's regression guard covers what the filter covers**: every enumerated pallet's call
  list, both wrappers, and the runtime's own pallet list.

### The run

Fresh chain, fresh miner wallet, the binary built from the committed tree
(`1.0.1-338baebdcfb`).

```
$ QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6fix2/miner.seed miner-address) \
    nice -n 19 ./target/release/quantus-node --dev --tmp
2026-09-12 19:46:13 Qnero Node
2026-09-12 19:46:13 📋 Chain specification: Qnero DevNet
2026-09-12 19:46:13 ⛏️ Coinbase notes are minted for miner key qnm1q9y0s6gq…wcagpvwl
```

**Every block's author item is its own.** This is the finding, checked against
the chain the way the review checked it: before the fix, blocks 3, 7, 11 and 19
carried byte-identical payloads.

```
#   1  PreRuntime 0x06706f775f80af052f0951e9648908324e4cf00a162416ee75b7ba51c3231c3d3bd7cdeae15c
#   2  PreRuntime 0x06706f775f809dc216521bf58ef0125f5f3b12c0d611bd0a8d65dc523bb9959f66d711473724
#   3  PreRuntime 0x06706f775f8081a6b951c0874d4b1877bf4f9f9670db1c13c18d7c6672008898ac2f41ae568d
#   5  PreRuntime 0x06706f775f80ea7c1166a56a3a9693aa2203ebb82d27dfe0f2cdb81b38cef146a70641405379
#   8  PreRuntime 0x06706f775f80f636f15e6ed2e7855b93e4ba148de24333f5c3fe2afc6f180d6ca56c29a37482
#  26  PreRuntime 0x06706f775f80a34d6e5a164f226f6019fe34592def2ae542037359bc61e3b6f92e7e73a4d2ab
#  27  PreRuntime 0x06706f775f803c5a81f78cc9a89b6d843f670c9e885c8941b2bf23a4f91232a6c644623a707b
distinct author labels: 7 over 7 blocks
```

The miner is still paid, and the notes are still found:

```
$ qnero-wallet --file /tmp/qnero-m6fix2/miner.seed sync
scanned leaves 0..26 at block 26
received 26 note(s) worth 1074 quanta

$ qnero-wallet --file /tmp/qnero-m6fix2/miner.seed status
runtime           spec 100, transaction 7
chain head        26
tree leaves       26
tree depth        3
```

The end-to-end, with two dry runs added for the two calls this pass decided:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=/tmp/qnero-m6fix2/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 7 leaves, 7 coinbase leaves, 7 of them this wallet's, 1364 quanta
shield of 1000 quanta included at block 34 (505.13ms), leaf 33
5 quanta to B at fee 8: included at block 43, change 29
coinbase of block 43: 45 quanta against 41 to 42 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
system_dryRun of set_high_security: 0x0001030005000000
system_dryRun of a vesting claim: 0x0001031602000000
test the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused ... ok
300 quanta to B: proved in 3.91s, 150908 proof bytes, included at block 46
100 quanta back to A: proved in 2.99s, included at block 49
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok

test result: ok. 2 passed; 0 failed
```

The three dry runs are the whole decision, in encoded form:

- `0x0001030005000000` is `Ok(Err(Module { index: 0, error: [5, 0, 0, 0] }))`: `frame_system` is
  pallet 0 and `CallFiltered` is its sixth error. A transparent transfer gets it, and now so does
  `set_high_security`.
- `0x0001031602000000` is the same shape at index 22, `pallet-vesting`, error 2, `NothingToClaim`:
  the dev chain's genesis schedules are inside their 90-day cliff. The call reached the pallet,
  which is the point. A filtered claim would have been `0x0001030005000000` like the other two, and
  the genesis allocation would be unreachable forever.

Everything the milestone measured measured the same: fee 8, change 29, the
settling block's coinbase 45 against 41 to 42 elsewhere, an author share of 4,
and the proof still 150908 bytes.

```
$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed after 1s
node stopped
```

### Gates

```
# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   38 suites ok, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean

# the chain workspace
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p pallet-shielded -p pallet-mining-rewards --release
   74 + 31 passed, 0 failed
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p quantus-runtime --release
   42 lib + 8 call_filter + 60 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p quantus-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p quantus-node -p sc-consensus-qpow --all-targets
   no warnings
```

### Timings

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build -j 4 --release -p quantus-node`, the one rebuild this pass owes | 10:06 | 5.4 GB |
| chain pallet tests | 27 s | |
| runtime tests, all three targets | under 1 s | |
| root workspace tests | 2:20 | |
| the end-to-end, both tests, three proofs | 14.1 s | |

**One formatting trap, for the next pass.** The chain subtree's `.rustfmt.toml`
sets nightly-only options (`wrap_comments`, `comment_width`,
`imports_granularity`). Running stable `rustfmt` there silently drops them and
reformats whatever it touches under the defaults, which rewrote binary operators
in two files nobody had edited. Use `rustfmt +nightly` on the files you touched,
and check `git status` afterwards: rustfmt formats a module's children too, so
one file's format can move three.

## The second M6 review fix pass, 2026-09-12

Seventeen findings against the first fix pass: one high, six medium, ten low.
The high one reversed a decision the previous pass made, and most of the rest
are documents that promised more than the code does.

### What changed

- **`Shielded::shield` and `Balances::burn` came back off the high-security whitelist.** The
  previous pass put them there so an account enrolled before v1 could still move its own balance,
  and that trade was the wrong way round. Every other call on that list is delayed and reversible,
  which is the whole guarantee the feature sells: a stolen key can only schedule, and the owner's
  `cancel` or the guardian's `recover_funds` beats the delay. A `shield` is immediate, commits to a
  `pk` the thief chose, settles in the next block and leaves `recover_funds`, which walks
  `PendingTransfersBySender` and releases holds, with nothing to find. `burn` is the same shape with
  total loss. A measured shield is 9104 bytes at a 0.0118 UNIT inclusion fee, inside both blanket
  caps, so one of the sixteen daily extrinsics empties the account. The freeze that trade was paying
  for is unreachable on a v1-genesis chain: `QneroCallFilter` refuses `set_high_security` and no
  non-benchmark preset seeds `HighSecurityAccounts`. An account enrolled before v1 stays frozen and
  that is written down, in `chain/docs/RUNTIME_SURFACE.md` section 5 and in `docs/DESIGN.md` 7.2.
- **`spec_version` is 101.** The previous pass changed runtime metadata and left the version at 100:
  a new `pallet-shielded` error variant, `CoinbaseMinted`'s field layout, and two
  `pallet-mining-rewards` event layouts. Every client that caches metadata keys the cache on
  `spec_version`, so a stale decoder reads `has_ciphertext: false` as a compact-zero length and
  renders an empty ciphertext, and reads an event that lost its leading `AccountId` by over-running
  into the next one. Both succeed silently. `the_runtime_identity_is_pinned` fails whenever the pair
  moves, so the next metadata change has to decide the version rather than inherit it. The rule now
  sits above `VERSION`: `spec_version` moves for any metadata change, `transaction_version` only for
  the signed extrinsic encoding, which is unchanged at 7.
- **Every preset's endowed set is pinned, not just `dev`.** The guard checked `amount > 0` for
  `heisenberg`, `planck` and `mainnet`, which the bug it exists to catch would have passed: the
  keyless wormhole address was endowed with plenty. Each preset's endowed accounts are now compared
  against the tables that preset builds them from. What it still cannot check is whether a key
  exists behind an address a human typed into `mainnet`'s grant table, and the test says so.
- **The `--dev` startup log no longer calls the treasury a reward recipient.** The explicit-flag
  branch was relabelled last pass and this one was missed, so a `--dev` node printed "Using treasury
  address for rewards" two lines above the miner key that is actually paid.
- **The chain subtree is format-checked too.** Only the root workspace was, and the chain is where
  every runtime and node change in this milestone lives. `cargo +nightly-2026-08-30 fmt --all --
  --check` failed on one pre-existing doc paragraph in `pallets/shielded/src/lib.rs`, because the
  pinned nightly rewrapped a fee formula onto a line starting with `+`, which markdown reads as a
  list bullet and `clippy::doc_lazy_continuation` then flags five times. The paragraph says the same
  thing in words now, so the formatter and the lint agree, and the gate is in the standing list
  below.
- **Five documents stopped overclaiming.** DESIGN's opening, its section 3 table, its M6 row, its
  section 10 positioning bullet and pillar 1 all said no call moves transparent value between
  accounts, while its own section 7.2 lists `Vesting::claim` as allowed and load bearing. All five
  say what the code supports: no call moves value between accounts a user chooses, and the one
  transparent payout is a genesis-fixed amount to a genesis-fixed payee out of a pot that cannot
  sign. CIRCUIT 10.7, which DESIGN points at as the full list of what a block reveals, gained the
  vesting row, and its `SlotSettled` row now says what that event actually publishes: two
  nullifiers, two commitments, two leaf indices and two ciphertexts, so a payment and its change are
  publicly siblings at consecutive indices. That is the linkage the wallet's per-spend output-slot
  draw exists to blunt, which is also now cross-referenced.
- **Three smaller document corrections.** DESIGN 7.1 rule 5 said the inherent accepts a third-party
  encrypted payload; it refuses one, and a reader building that path would have had every block it
  authors refused on a Mandatory dispatch. DESIGN section 7 item 6 said both the entry and the
  absence of an exit go at v1; neither does, and `shield` is still the only entry. DESIGN section 4
  was missing `cvk` from the key hierarchy while claiming parity with Monero's view-key split, which
  is false for a mining wallet: a full viewing key is `(ivk, nk)` and neither half derives `cvk`, so
  an auditor handed one sees every shielded receipt and no coinbase note at all.
- **The wallet says that a coinbase note's value is public.** `docs/WALLET.md`'s "What every chain
  reader learns" and the binary's own `--help` preamble listed three leaks and not the one a miner
  cares about: `Shielded::CoinbaseValues` publishes each coinbase note's value and
  `Shielded::LeafBlocks` dates it, so a whole mining income stream is readable with no keys and only
  the per-block author label keeps the blocks one operator won from being grouped.
- **Two tests stopped lying about themselves.** The mining-rewards test named for crediting the
  author's derived address asserts that the address is paid nothing and that no event names it,
  which is the opposite of its name, so it is now
  `the_authors_derived_address_is_paid_nothing_and_named_nowhere`. The vesting dry run asserted only that the answer
  was not `CallFiltered`, which a decode failure also satisfies; it decodes the `DispatchError` and
  pins the module index against the constant the call was built with, so a drifted
  `VESTING_PALLET_INDEX` fails instead of passing.

### The run

Fresh chain, fresh miner wallet, the rebuilt binary.

```
$ QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6fix3/miner.seed miner-address) \
    nice -n 19 ./target/release/quantus-node --dev --tmp
2026-09-12 20:45:05 Qnero Node
2026-09-12 20:45:05 📋 Chain specification: Qnero DevNet
2026-09-12 20:45:05 ⛏️ Consensus author fallback, paid nothing: 6d6f646c70792f74727372790000… (qzmviwoP…)
2026-09-12 20:45:05 ⛏️ Coinbase notes are minted for miner key qnm1q9fgxslr…wzf88au6
```

The fallback line is the low finding: a `--dev` node with no `--rewards-inner-hash` used to call
that account the reward recipient, and v1 pays it nothing.

```
$ qnero-wallet --file /tmp/qnero-m6fix3/miner.seed sync
scanned leaves 0..38 at block 38
received 38 note(s) worth 1570 quanta

$ qnero-wallet --file /tmp/qnero-m6fix3/miner.seed status
runtime           spec 101, transaction 7
chain head        38
tree leaves       38
tree depth        3
```

`spec 101` is the metadata bump reaching the wire. The end-to-end is unchanged
in shape, and the vesting dry run is now decoded rather than compared against
one string:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=/tmp/qnero-m6fix3/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 8 leaves, 8 coinbase leaves, 8 of them this wallet's, 1901 quanta
shield of 1000 quanta included at block 47 (1.01s), leaf 46
5 quanta to B at fee 8: included at block 59, change 29
coinbase of block 59: 46 quanta against 41 to 43 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
system_dryRun of set_high_security: 0x0001030005000000
system_dryRun of a vesting claim: 0x0001031602000000
pallet-vesting answered with error 2
test the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused ... ok
300 quanta to B: proved in 5.94s, 150908 proof bytes, included at block 60
100 quanta back to A: proved in 3.18s, included at block 64
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok

test result: ok. 2 passed; 0 failed
```

The settling block's coinbase is 46 quanta against 41 to 43 elsewhere, so the
author's share of the fee 8 is 4 and the other 4 burned, which is what the
milestone measured every time.

```
$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed
```

### Gates

```
# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   38 suites ok, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean

# the chain workspace
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p pallet-shielded -p pallet-mining-rewards --release
   74 + 31 passed, 0 failed
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p quantus-runtime --release
   42 lib + 9 call_filter + 60 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p quantus-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p quantus-node -p sc-consensus-qpow --all-targets
   no warnings
cargo +nightly-2026-08-30 fmt --all -- --check
   clean
```

The last one is new and belongs in the standing list. The chain subtree pins its
own nightly in `chain/rustfmt-toolchain` and its `.rustfmt.toml` sets
nightly-only options, so stable `rustfmt` silently drops them and reformats
whatever it touches under the defaults. Checking only the root workspace left
the subtree carrying every runtime and node change in this milestone unchecked.

### Timings

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build -j 4 --release -p quantus-node`, the one rebuild this pass owes | 1:04 | 1.7 GB |
| chain pallet tests | 26 s | |
| runtime tests, all three targets | under 1 s | |
| root workspace tests | 2:12 | |
| the end-to-end, both tests, three proofs | 14.8 s | |

The rebuild is a minute rather than the ten the milestone's first one took,
because only the runtime and the node changed and every dependency below them
was already built.
