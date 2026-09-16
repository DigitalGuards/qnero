# Running the Qnero dev chain

**Runtime 105 policy:** confirmations remain reversible, genesis is the only
irreversible checkpoint, and nodes retain all branch states and block bodies.
Wallets authenticate storage and require the matching protocol profile. Read
[NATIVE-UPGRADE.md](NATIVE-UPGRADE.md) before changing an existing database or
network. Dated entries below describe the implementation at their recorded time.

The chain lives in `chain/`, a git subtree of Quantus-Network/chain at
`f1176ce` (v1.0.1). It is its own Cargo workspace with its own toolchain and
lock file; the Qnero root workspace excludes it, and the two meet only through
the path dependencies `chain/Cargo.toml` declares on `../crates/*`.

Every command below is prefixed with `nice -n 19`. The circuit generation and
the proving tests are CPU and memory heavy, and a chain build at `-j 4` will
occupy a machine for the better part of an hour.

## What is renamed and what stays upstream

`chain/` is a subtree of somebody else's repository, so the next merge from
Quantus-Network/chain arrives carrying upstream's names in every file it
touches. One rule decides each conflict: **what an operator types, reads or is
answered with is Qnero's, and what only the build system sees stays
upstream's.**

Renamed. A merge that brings the old name back is a regression:

| Upstream | Qnero | Where |
|---|---|---|
| package and binary `quantus-node` | `qnero-node` | `node/Cargo.toml` (`name`, `default-run`, `description`) and every `target/release/...` path in docs, scripts and tests |
| package `quantus-runtime` | `qnero-runtime` | `runtime/Cargo.toml`, the workspace dependency in `chain/Cargo.toml`, and `node/Cargo.toml`'s dependency plus its `std`, `runtime-benchmarks` and `try-runtime` feature lists |
| crate path `quantus_runtime::` | `qnero_runtime::` | every `use` in `node/src/` and `runtime/tests/` |
| wasm blob `wbuild/quantus-runtime/quantus_runtime.wasm` | `wbuild/qnero-runtime/qnero_runtime.wasm` | follows the package rename; `scripts/regenerate_weights.sh` reads that path |
| `key quantus` and its banners | `key qnero`, "Qnero Account Details", "Qnero Wormhole Details" | `node/src/cli.rs`, `node/src/command.rs` |
| the `--rewards-inner-hash` error hints | `qnero-node key qnero --scheme wormhole` | `node/src/command.rs` |
| two `--help` strings naming Quantus | ML-DSA-87, and "upstream" | `client/cli/src/params/transaction_pool_params.rs` |
| the startup banner's byline | `DigitalGuards <https://github.com/DigitalGuards/qnero>` | `SubstrateCli::author` in `node/src/command.rs` |
| the bug-report address, `support.anonymous.an` | `https://github.com/DigitalGuards/qnero/issues` | `SubstrateCli::support_url` in `node/src/command.rs`: the last line of `--help`, and the address `sp_panic_handler` prints on every panic |
| the `mainnet` preset's chain name `Quantus` and protocol id `quantus` | `Qnero` and `qnero` | `node/src/chain_spec.rs`. A spec file is the one artifact no runtime upgrade reaches |
| the metadata-hash token symbol `UNIT` | `QNR` | `runtime/build.rs`. This is what a hardware or offline signer displays under `on-chain-release-build`, and it has to equal `qnero_properties()`'s symbol |
| the upstream telemetry endpoint and bootnodes on `heisenberg`, `planck` and `mainnet` | removed | `node/src/chain_spec.rs`. All three build this tree's genesis, so upstream's peers refuse them and upstream's telemetry server was collecting a node that was never on that network. Both fields are outside genesis |
| default base path `~/.local/share/quantus-node` | `~/.local/share/qnero-node` | nothing declares it: `sc_cli` derives it from the executable's file name (`client/cli/src/lib.rs`'s `executable_name`, `config.rs`'s `base_path_or_default`), so the binary rename moved it. See below |

Three user-facing strings needed no edit of their own, and each is worth
knowing about, because each looks like an omission until you check it:

- **The version string and the `--help` about line.** `sc_cli` builds both from
  the package: the version line names the executable file, and the about line
  is `CARGO_PKG_DESCRIPTION`. Renaming the package and its description moved
  both. `SubstrateCli::impl_name` has said `Qnero Node` since M6. The rest of
  `--help` comes from the flags of every crate `RunCmd` flattens, which is why
  two strings in `client/cli` had to move as well and why the guard runs the
  binary: a grep of `node/src` finds neither of them.
- **The prometheus namespace.** The one metric this node registers is
  `qpow_metrics` (`node/src/prometheus.rs`), named after the consensus engine.
- **The miner-facing log lines.** Every one of them is `⛏️ ...`. M7 replaced
  upstream's QUIC miner server with a stratum endpoint
  (`node/src/stratum.rs`), so the ALPN that used to be pinned here,
  `quantus-miner/2`, is gone with it. The wire identifier that is pinned now is
  `rx/0`, and it is pinned for the same reason: it is what a stock xmrig
  negotiates, and changing it would refuse every miner that connects.

One thing moved that no file names, and it has state behind it: **the default
base path**. `sc_cli` derives it from the executable's file name, so a node
started with no `--base-path` reads and writes `~/.local/share/qnero-node`
where it used to read and write `~/.local/share/quantus-node`. Drop the new
binary over the old one on a machine with a persistent local chain and it finds
an empty database, resyncs from genesis, and generates a fresh
`network/secret_ed25519`, which is a fresh peer id. The old directory sits
untouched beside it. Either move it:

```
mv ~/.local/share/quantus-node ~/.local/share/qnero-node
```

or pass `--base-path` and name the directory yourself. `purge-chain` prints the
path it is about to delete, which is the cheapest way to see which one a binary
is using. Qnero has no live network and has published no binaries, so this is a
developer-machine migration and nothing more. A fork that had operators would
pin `SubstrateCli::executable_name()` and hold the directory still while the
file name moves.

Kept as upstream, deliberately:

- **The two-variant signature enum, with the runtime refusing one variant.**
  `qp-dilithium-crypto`'s `DilithiumSignatureScheme` carries `Dilithium87`
  (ML-DSA-87) and `Dilithium65` (ML-DSA-65). Qnero refuses the second one at
  the transparent entry and leaves every primitive under it exactly as upstream
  wrote it: the enum, its `Verify` and `IdentifyAccount` implementations, the
  `define_dilithium_scheme!` invocation, its unit tests, and the refused
  variant's own `ml-dsa-65` feature on `qp-rusty-crystals-dilithium` in
  `chain/Cargo.toml`, which the macro invocation will not compile without.
  Deleting the variant would conflict on every merge and would move the
  runtime's metadata, which is where a client reads the encoded length of a
  signature per variant index.

  The rule sits one layer up, in the runtime, where merges do not reach:
  `chain/runtime/src/extrinsic.rs` wraps the generic extrinsic, and its
  `Checkable` implementation admits a signed extrinsic only when its signature
  is the `Dilithium87` variant and refuses every other variant with
  `InvalidTransaction::BadSigner`, on the live path and on the `try-runtime`
  replay path alike. An allowlist, so a variant a later subtree merge adds is
  refused by the arm that is already there. That is a consensus rule, written
  up in `docs/DESIGN.md` section 7.3, guarded by
  `chain/runtime/tests/transactions/signature_scheme.rs` and by the
  repository-wide `crates/qnero-wallet/tests/one_signature_scheme.rs`.

  The vendored `sc-cli` fork still offers `--scheme dilithium65` on its key
  commands; the node's own dispatch refuses the flag before `sc-cli` sees it
  (`chain/node/src/command.rs`), so upstream's tree stays untouched and the CLI
  says what the entry says. Anything minted elsewhere is inert under the rule.
- **Every other crate under `chain/`**: `client/*`, `frame/*`, `pallets/*`,
  `primitives/*` and the `qp-*` dependencies. Renaming them buys nothing an
  operator sees and costs a conflict in every merge. Two went away at M7
  instead of being renamed: `miner-api`'s `quantus-miner-api` and
  `client/consensus/qpow`, both of which described a proof of work this chain
  no longer has.
- **Module paths and Rust identifiers** inside the node crate:
  `QuantusKeySubcommand`, `QuantusAddressType`, `generate_quantus_key`,
  `QuantusKeyDetails`. The clap attribute `#[command(name = "qnero")]` is what
  renames the typed subcommand, so the identifier and the word an operator
  types are decoupled on purpose.
- **`chain/LICENSE` and `chain/SECURITY.md`.** Upstream documents, and the
  attribution in them is the licence condition.

  The licence condition is the copyright and the notice text. It is not the
  build and run commands, and the first pass read it too widely: `chain/README.md`
  told a reader who had just run `cargo build --release` in this tree that the
  binary was at `./target/release/quantus-node` and to run `key quantus`, and
  both of those are now hard errors. So the commands in `chain/README.md` and
  `chain/docs/RELEASE_PREFLIGHT.md` name what this tree builds, the attribution
  and the network names in them are untouched, and each carries a banner saying
  which half is which. `chain/docs/RUNTIME_SURFACE.md`, `RUNTIME_UPDATE.md` and
  `CHAINSPEC_CREATION.md` are Qnero-maintained (M6 edited all three) and say
  `qnero-runtime` throughout. `chain/MINING.md` keeps upstream's names, under an M7 banner saying its external-miner half no longer describes this node: every
  binary in it is a release binary from `Quantus-Network/chain` or an image
  from `ghcr.io/quantus-network`, and every network in it is upstream's, so a
  rename would have produced a guide telling an operator to download one binary
  and run another. It has a banner too, and the two defaults that differ
  between the binaries (the base path, the log path) are called out where they
  appear.
- **The release pipeline: the four release workflows under
  `chain/.github/workflows/` and `chain/Dockerfile`.** These build tags,
  release assets and images for Quantus-Network/chain, they read the upstream
  repository's releases, and GitHub runs workflows only from the repository
  root, so nothing here executes for this fork. They still say `quantus-node`,
  and they are dead either way.

  `chain/.github/workflows/ci.yml` is the exception in that directory and is
  renamed. It is the only workflow there that is not release-specific, it
  builds and tests this workspace, and it would be the first one anybody lifts
  to the repository root to get CI on this fork. It passed
  `--features quantus-runtime/fast-governance` on two steps, which is a package
  that no longer exists, so an adopter would have met "package `quantus-runtime`
  does not exist" and read it as a broken workflow. There is no `.github/` at
  the repository root, so nothing under `chain/.github/` runs today.

  `Dockerfile.local`, which builds from this tree, is renamed, and so are the
  runtime user and the data directory it prepares: `qnero` and `/var/lib/qnero`.
  The image passes `--base-path /var/lib/qnero` explicitly, since the sc_cli
  default is derived from the executable name under a `$HOME` the image's
  system user does not have.
- **`scripts/install-quantus-node.sh` and `scripts/clean-quantus-node.sh`.**
  Both fetch upstream release binaries, install them under upstream's names and
  remove them again, and Qnero publishes no releases, so there is nothing here
  for them to name.

  The first pass put `genesis_generate_draft.sh` and `genesis_generate_spec.sh`
  in this bullet on the grounds that they fetch upstream release assets. That
  is half true and it left both scripts broken: each downloads an upstream
  `quantus-runtime-v*.wasm`, and each also runs
  `cargo build --release --package quantus-node` **in this tree** and then
  invokes the binary it just built. That build now exits with "package ID
  specification `quantus-node` did not match any packages", and
  `genesis_generate_spec.sh` reaches it only after `set -e` has already created
  and checked out a new branch at an upstream tag. Both are renamed on the
  build-and-invoke half; the downloaded asset name stays upstream's, with a
  comment at each site saying so.

  The local-development scripts are renamed: `kill_chains.sh`,
  `run_local_nodes.sh`, `start_testnet.sh`, `create_custom_chain_spec.sh`,
  `regenerate_weights.sh`. Three of them had a second defect the rename walked
  past. `start_testnet.sh` ran the renamed binary against `--chain planck`, so
  it started a working Qnero node wearing an upstream network identity, dialling
  `quantus.cat` bootnodes and reporting to `quantus.cat` telemetry; it runs
  `--chain dev` now. `create_custom_chain_spec.sh` passed `--chain local`, an id
  `load_spec` has never had, which fell through to the file-path arm and died on
  a missing file; it passes `--chain dev`. `kill_chains.sh` and
  `run_local_nodes.sh` matched only the new name, so a `quantus-node` left
  running from before the rename survived the kill and held 30333 and 9944
  against the new binary; both match `q(nero|uantus)-node` for one release
  cycle.
- **Generated weight headers** (`pallets/*/src/weights.rs`), which record the
  benchmark command that produced them. `regenerate_weights.sh` rewrites those
  headers the next time weights are measured.
- **The FIPS 204 signing context `QUANTUS_EXTRINSIC`.** It is consensus, and
  both ends of the wallet and the runtime hash it.

### Chain specs

`chain/node/src/chain-specs/` is gone. M6 deleted the three raw JSON specs that
lived there, because `sc_cli` resolved an empty `--chain` to the first of them
and that started an upstream network with none of v1's privacy rules. Every
`--chain` id now builds its genesis from a preset compiled into this binary.

Of the four presets the node builds, one is Qnero's and three are upstream
identities kept for reference:

- `dev` and `qnero-dev` are Qnero's: name `Qnero DevNet`, protocol id
  `qnero-devnet`, token `QNR`. This is what `--dev` resolves to and the only
  preset the project runs.
- `heisenberg`, `planck` and `mainnet` keep upstream's ids, because the id is
  what selects the runtime preset that builds their genesis, and deleting a
  preset is a change to genesis code with nothing to do with a rename. They are
  reference presets until Qnero has a live network of its own.

  Their node-side network identity is gone, and that half was a live defect
  until this pass. All three carried `/dns/shard-telemetry.quantus.cat/...`, and
  `heisenberg` and `planck` carried `quantus.cat` bootnodes, while building this
  tree's genesis: an operator who started one dialled peers that refuse it on
  genesis hash and published a node name, a client version and a block height to
  a telemetry server run by somebody else, for a network the node was never on.
  `start_testnet.sh` did exactly this. `mainnet` also answered with the chain
  name `Quantus` and the protocol id `quantus`, which is what a wallet, an
  explorer or an exchange reads out of a spec file, and no runtime upgrade
  reaches a file somebody already holds. Both fields sit outside genesis, so
  they were fixable without touching the preset list: the name and protocol id
  are `Qnero` and `qnero`, and the telemetry and bootnode entries are removed
  until Qnero runs peers and a telemetry server of its own.

The token symbol is `QNR` on all four, from the one `qnero_properties()` map
that `every_preset_names_the_token_qnr` pins. The symbol is written in a second
place, `runtime/build.rs`, which hands it to `enable_metadata_hash`: that is the
unit a hardware or offline signer displays when it decodes a call under the
`on-chain-release-build` feature. It said `UNIT`, the Substrate template's
placeholder, so a release build would have shown a signing device one unit while
every spec file said another. It says `QNR`, and each site's comment names the
other.

### The guard

`node/tests/naming_guard.rs` is what holds this. It runs the binary Cargo just
built and asserts that:

- `--version` names `qnero-node`;
- `--help` says `Qnero`;
- every subcommand's own help says nothing of Quantus: `key`, `key qnero`, `build-spec`,
  `check-block`, `export-blocks`, `export-state`, `import-blocks`, `purge-chain`, `revert`,
  `chain-info`. `RunCmd`'s flags are flattened into the root help and a subcommand's doc comments
  are not, which is where an upstream doc comment lands when a subtree merge restores one;
- `build-spec --chain dev` answers with name `Qnero DevNet`, id `qnero-dev`, protocol id
  `qnero-devnet` and token symbol `QNR`;
- `build-spec` over **every** id `load_spec` accepts, the `_live_spec` aliases included, names the
  token `QNR` and says nothing of Quantus outside the genesis blob.

The last one is what the first pass missed. A dev-only guard is green while
`--chain mainnet` hands out a spec named `Quantus`, and a preset the project
never runs is still a preset the binary produces on request.

`the_startup_banner_names_qnero_and_no_upstream_maintainer` in
`node/src/command.rs` covers the banner, which appears under neither flag, and
pins `support_url` as well: the placeholder `support.anonymous.an` names no
project at all, so a guard looking for the word `quantus` cannot see it.

The whole file runs under `cargo test -p qnero-node --release`, which is in the
gate list below. The chain-spec assertions skip themselves when
`SKIP_WASM_BUILD` is set, since without the wasm there is no spec to build, so
run that line with the wasm.

### What `quantus` still means when you grep for it

Two things, and they are worth telling apart:

- **`quantus-runtime` in the entries below dated before the M6 run** is the
  on-chain `spec_name` those chains answered with. M6 changed the chain's
  identity to `qnero` / `qnero-node` at `spec_version` 101; this pass changed
  the crate that builds it. Those lines record what a node reported at the
  time, so they are left alone.
- **The binary and package names in the transcripts below were updated in
  place.** Passes before this one ran the node as `quantus-node` and tested
  `-p quantus-runtime`. Every command in this file is runnable against the tree
  as it stands, and the timings and outputs beside them are the ones those
  older runs produced.

## Building

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

The node binary lands at `chain/target/release/qnero-node`.

`LIBCLANG_PATH` is not optional on Linux. `librocksdb-sys` runs bindgen, whose
`clang-sys` build script panics with "couldn't find any valid shared libraries
matching: ['libclang.so', 'libclang-*.so']" when it cannot locate one.
`chain/.cargo/config.toml` sets the variable only on macOS, where Homebrew puts
it somewhere non-standard; on a Debian-family box point it at whichever
`/usr/lib/llvm-*/lib` holds `libclang.so`, and install `libclang-dev` if none
does.

**cmake and a C++17 compiler are not optional either, since M7.** The proof of
work is RandomX, and the bindings (`randomx-rs`) vendor tevador's `librandomx`
and build it with cmake in their build script. On a Debian-family box:

```
sudo apt install cmake g++
```

Without cmake the build fails inside `randomx-rs`'s `build.rs` with `failed to
execute CMake`, which is a long way from the crate an operator was building.
The RandomX sources ship inside the published crate, so the build needs no git
submodule and no second fetch, and `configuration.h` in that tree is stock,
which is what makes these hashes `rx/0` rather than a private algorithm.
`chain/client/consensus/randomx` asserts the `librandomx` known-answer vectors
in its own tests, so a toolchain that miscompiled RandomX fails the test suite
rather than forking the chain.

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
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release --test call_filter
LIBCLANG_PATH=/usr/lib/llvm-18/lib RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 4 -p qnero-node --release
nice -n 19 cargo clippy -j 4 -p pallet-shielded -p pallet-mining-rewards --all-targets
```

The node line is the rename guard, and it is the one line here that must run
**without** `SKIP_WASM_BUILD`: the chain-spec assertions build a preset spec and
therefore need `WASM_BINARY`, and with the variable set they skip themselves and
say so on stderr, which is most of the guard silently not running. It is in this
list because the guard exists for the next subtree merge from
Quantus-Network/chain, and a merge is exactly the moment somebody runs the
documented gates and reads green. `chain/.github/workflows/ci.yml` does not run
this or anything else: GitHub reads workflows only from the repository root and
there is no `.github/` there.

The runtime's call-filter test is named, and `cargo test -p qnero-runtime`
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
nice -n 19 ./target/release/qnero-node --dev --tmp
```

`--dev` is what picks the chain here. Every `--chain` id the node accepts
(`dev`, `heisenberg`, `planck`, `mainnet`, and the `<profile>_live_spec`
aliases) builds its genesis from a preset compiled into the binary, so all of
them run this tree's runtime. A command line carrying neither `--chain` nor
`--dev` is refused with those ids named: the three raw specs the binary used to
embed were upstream Quantus networks whose genesis runtime had no shielded
pool, no coinbase inherent and no call filter, and the empty id resolved to one
of them.

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
nice -n 19 ./target/release/qnero-node --dev --tmp
# or --rewards-miner-key qnm1...
```

`--dev` authors blocks, so it needs the key like any other authority. A node
without one builds blocks that carry no coinbase inherent, and every node
refuses those, its own import included, so the node refuses to start instead.

Three properties of that string:

- **It is secret-bearing, and the address is not.** `cvk` is what a coinbase note's `r` is derived
  from, so whoever holds the miner key can pick that miner's coinbase notes out of the tree. It
  cannot spend them and it says nothing about any other note the wallet holds. Prefer the
  environment variable to a command line, which every process listing on the machine can read.
- **It is not an address.** Its human-readable part is `qnm` rather than `qn`, so pasting one where
  the other belongs fails on the checksum rather than halfway through a decode.
- **One key is safe on more than one chain.** A coinbase note is derived rather than drawn at
  random, so the genesis hash is in the preimage of its `r`. The same `qnm1...` on a testnet and on
  mainnet mints unrelated notes at equal heights, and nobody carries an identification from one
  chain to the other by comparing note commitments. What separates two chains is the genesis hash
  and nothing else: `--dev --tmp` builds the same genesis every run, so two dev chains from one
  miner key mint the identical note at every height. The third M6 fix pass measured that on two
  dev chains and it is harmless on a throwaway one; a network whose genesis a relaunch does not change is the same
  chain by this rule.

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

### The block interval: 120 s in public, 12 s in `dev`

The public chain targets 120 000 ms, Monero's interval. `docs/DESIGN.md` section
7.4 carries the decision and what moved with it.

One binary serves both cadences, because the target is chain state rather than a
compile-time constant. `pallet_qpow::TargetBlockTimeMs` is written once at
genesis from the chain spec and there is no setter and no extrinsic that can
move it afterwards; when it is unset the pallet falls back to
`TARGET_BLOCK_TIME_MS`, which is 120 000.

| preset | target | why |
|---|---|---|
| `dev` | 12 000 | every end-to-end suite is sized for this cadence, and ten times longer blocks would make each of them ten times slower |
| `heisenberg`, `planck`, `mainnet` | 120 000 | the public default |

`the_dev_preset_keeps_the_fast_block_time` in
`runtime/src/genesis_config_presets/mod.rs` asserts both halves, so neither can
drift silently.

**What the storage target reaches, and what it does not.** Three readers follow
it: the retarget, `TimestampBucketSize` in the scheduler and
`MinDelayPeriodMoment` in reversible transfers. Everything else denominated in
the interval reads the compile-time `TARGET_BLOCK_TIME_MS`, because it is
`#[pallet::constant]` metadata a client reads a governance period or a supply
schedule out of. So on the `dev` chain `MINUTES`, `HOURS` and `DAYS` keep the
public chain's block counts and mean a tenth of their names: `DAYS` is 720
blocks, which is 2.4 hours there, and the quota window, the default reversal
delay and the multisig expiry cap all shrink with it. `EmissionDivisor` is the
same kind of constant, so a `dev` chain emits at ten times the public per-second
rate. A spec that sets `qPoW.targetBlockTime` to anything but 120 000 for a
chain whose supply curve has to mean something needs a runtime carrying a
matching divisor. `runtime/tests/block_time.rs` pins both halves.

**Reading it.** Everything that quotes a wait, estimates a hash rate or turns a
block count into a duration reads the chain rather than a constant. Over JSON-RPC
that is one `state_call`:

```
curl -s -H 'Content-Type: application/json'   -d '{"jsonrpc":"2.0","id":1,"method":"state_call","params":["QPoWApi_get_target_block_time","0x"]}'   http://127.0.0.1:9944
# {"jsonrpc":"2.0","id":1,"result":"0xe02e000000000000"}   0x2ee0 = 12000
```

The answer is a SCALE `u64`, eight little-endian bytes.

**Running a dev node at the public target.** Useful for a stratum or miner smoke
test that has to see the cadence a rig will actually meet. Build the `dev` spec,
edit the one field and start from the file:

```
./target/release/qnero-node build-spec --chain dev --disable-default-bootnode > /tmp/dev.json
# set .genesis.runtimeGenesis.patch.qPoW.targetBlockTime to 120000
./target/release/qnero-node --chain /tmp/dev.json --tmp --validator --mining-threads 1
```

The difficulty stays the `dev` preset's floor of 128, which is what keeps a
single machine finding blocks; only the cadence the retarget aims at changes.
The emission divisor does not follow that edit, so such a chain pays a 120 s
block the reward a 12 s block earns. It is a cadence smoke test and nothing
should read a supply figure off it.

### The proof of work: RandomX, and what to point at it

Since M7 the engine is RandomX, algorithm `rx/0`, stock constants. That is the
same hash Monero uses, computed by the same C library every Monero miner
links, so a rig that mines Monero mines Qnero with a config change and no
patched miner.

Two things mine a Qnero node, and both run at once by default:

```
# in process, light mode, one thread. This is what makes --dev produce blocks.
nice -n 19 ./target/release/qnero-node --dev --tmp --mining-threads 1

# and/or a stratum endpoint for real rigs
nice -n 19 ./target/release/qnero-node --dev --tmp \
  --stratum-port 3333 --mining-threads 0
```

| Flag | Default | What it does |
|---|---|---|
| `--mining-threads N` | 1 | In-process RandomX threads, light mode. 0 turns it off. |
| `--stratum-port PORT` | off | Opens the endpoint xmrig connects to. Requires `--validator` (`--dev` is one). |
| `--stratum-host ADDR` | `127.0.0.1` | Bind address. A rig on another machine needs `0.0.0.0`. Requires `--stratum-port`. |
| `--stratum-share-difficulty D` | 5000 | Per-connection share difficulty, clamped per job to the block difficulty. Requires `--stratum-port`. |
| `--stratum-max-connections-per-ip N` | 16 | Connections one address may hold. A farm behind one NAT gateway and several xmrig instances on the node's own box all arrive from a single address. Requires `--stratum-port`. |
| `--stratum-share-timeout S` | 600, rising with the share difficulty | How long a logged-in session has to produce an accepted share. The endpoint's whole liveness rule. Independent of the block interval: 600 s is five block intervals at the public 120 s target. Requires `--stratum-port`. |

An authority with `--mining-threads 0` and no `--stratum-port` has nothing
mining, so the node refuses to start and says so. `--mining-threads` above the
machine's own parallelism is refused too: every thread is a `spawn_blocking` on
the pool rocksdb and block import share, so oversubscribing queues the node's
hashing in front of its own import. Every stratum flag that needs a port says
so at startup for the same reason: an address or a share difficulty with no
listener behind it is a flag that silently did nothing, and the operator finds
out from the rig that cannot connect.

**What the endpoint bounds.** The port is off by default and binds loopback by
default, and opening it to a network is a decision, so it is bounded like
anything an unauthenticated peer can reach:

- a line is bounded at 8 KiB as it accumulates, so a peer that never sends a
  newline cannot make the node buffer for it. The read is cancel safe, because
  the deadline below re-enters it: a line split across two TCP segments is
  resumed whole, and the share in a submit split that way is not lost to a
  parse error;
- 64 connections at once, and `--stratum-max-connections-per-ip` (16) from any
  one address, so one peer cannot multiply a per-connection allowance across
  sockets and one host cannot take the endpoint away from the operator's rigs.
  A refused peer is told `Too many connections` before the socket closes, and
  the refusal is logged at `warn`, rate limited to one a minute with the count
  of what it suppressed. A cap that refuses in silence is a rig retrying every
  five seconds forever with neither end saying why;
- 30 seconds to log in, counted from the moment the connection opened. The
  share deadline below is a rig's allowance and a peer earns it by
  logging in. Nothing a peer sends before it logs in extends the 30 seconds: a
  blank line and a `keepalived` are both answered before any login, so a
  deadline measured from the last line would have been one newline a window
  away from no deadline at all;
- one accepted share every `--stratum-share-timeout` once logged in, which is
  the endpoint's whole liveness rule and is the next paragraph;
- 10 seconds for one write to land, and a 32-line outgoing queue. A peer that
  stops reading its socket is disconnected, so it cannot park a connection task
  on a stalled `write_all` and keep the slot that task holds;
- four share hashes at once, each on the blocking pool and none on the async
  runtime, so a flood of submits cannot take the runtime away from block import
  and networking;
- 64 submits of burst per connection, refilling at 32 a second: far above any
  real rig's submit rate and far below what it would take to keep all four hash
  slots saturated. The refill rises to 256 a second for a job whose share
  target is the block target, which is every job on a chain sitting at the
  difficulty floor, because there a share refused for budget is a block thrown
  away before it was hashed;
- 100 000 entries in the duplicate-share set, cleared at the ceiling. Eviction
  is otherwise driven by the template rolling, and a stalled chain rolls none;
- miner-supplied strings truncated to 64 characters and logged with `{:?}`, so
  a login cannot forge a log line or rewrite a terminal.

**The liveness rule is an accepted share.** A logged-in session has
`--stratum-share-timeout` to produce its first share at or above the job's share
target, and the same window between accepted shares after that. Nothing else
refreshes that clock: a blank line does not, a `keepalived` does not, a
malformed line does not, a rejected share does not, and neither does a job the
node pushes. This is the rule a pool uses, and it is the only one the endpoint
has, so there is one thing to explain and one thing to tune. A connection slot
is there to be mined with.

`keepalived` is still answered, because xmrig arms a keepalive timer inside a
successful login and expects a reply. It is inert otherwise.

The default is 600 seconds and it rises with `--stratum-share-difficulty`:
twelve expected share intervals for a rig of 100 H/s, capped at 7200. Neither
number is denominated in block intervals and neither moved when the target went
to 120 s: 600 seconds is five block intervals there, where it was fifty at 12 s,
and 7200 is sixty where it was six hundred. What the rule counts is accepted
shares, and a share is found against the share difficulty. A deadline
fixed in seconds is a bet on the rig's hash rate. It is computed from the
*configured* share difficulty, and a job's share difficulty is that value
clamped down to the block difficulty, so the estimate is never shorter than the
time a share actually takes to find: a chain sitting at the difficulty floor
hands out shares far easier than the configuration asks for, and the deadline
stays sized for the harder one. At the default share difficulty of 5000 a
900 H/s box finds a share every six seconds, so the window is a hundred expected
shares wide, and it also covers the minute a full-mode rig spends building its
dataset after login, before it hashes anything at all.

A session that runs out is told `No accepted shares` and then closed.
Deliberately not one of the four strings xmrig treats as critical: the endpoint
wants the rig back, the usual causes are a rig pointed at the wrong algorithm
and a rig that stopped hashing, and both are fixed on the rig while xmrig keeps
retrying on its own timer.

**What the endpoint does not bound, and why it is open.** Every deadline above
is a property of one TCP connection, and a connection costs a peer nothing to
replace. A peer that logs in, mines nothing, is closed at the share deadline
and reconnects at once holds a slot continuously, and the only handle the
endpoint has on it is its address, which `--stratum-max-connections-per-ip`
already bounds at 16 of the 64 slots. Closing this fully means keying on the
peer rather than the socket: a per-address strike for every session closed
with `No accepted shares`, and a cooldown during which that address is refused
at accept, which a peer with many addresses still walks around, at which point
the answer is a firewall in front of a port that is loopback by default. It is
recorded here as the known limit of an unauthenticated endpoint and left
open; an operator who exposes the port to a network should put it behind an
address allowlist or a pool.

**When authoring pauses**, on a stale tip, on no peers, or for the length of an
initial sync, the endpoint stops handing the template out and closes the
connections holding it: `Node is not authoring`, then an EOF. That is the same
answer a rig gets when it connects during a pause, and it is what makes xmrig
count a failure and retry on its own timer. A connection left open through a
pause is answered `OK` for every share it finds against a template with no
build behind it, which is a 100% accept rate on work that cannot become a
block. The one-generation grace slot stays for what it is for: a genuine
template roll, where a rig is always mid-nonce when the push goes out.

**The xmrig command line**, against a node with `--stratum-port 3333`:

```
nice -n 19 xmrig --threads=2 --algo rx/0 -o 127.0.0.1:3333 -u qnero-rig -p x --no-color
```

`-u` is a worker label and nothing is paid to it. Qnero's block reward is a
shielded note minted for the key in `--rewards-miner-key`, and that key is
secret-bearing, so it is exactly the thing not to put on a stratum login line.
This is a solo-mining endpoint: whoever runs the node owns the coinbase. A pool
paying many miners would need a payout ledger and share accounting, which is a
different product.

**Light mode versus full mode.** The node always runs RandomX in light mode: a
256 MiB Argon2d cache per seed and no 2 GiB dataset. It hashes once per block
it verifies and once per share it is offered, so a dataset would cost more
memory than the rest of the node for no gain. A rig does the opposite, and
that is why it is roughly an order of magnitude faster per thread. On this
workstation light mode is about 33 H/s per thread (`docs/BENCH.md`). Neither
mode changes the hash; a light-mode verifier and a full-mode miner agree on
every bit.

**The seed rule.** RandomX is keyed by a 32-byte seed that moves on a slow
schedule, because every move costs a full-mode rig a dataset rebuild. The rule
is Monero's, and the two constants are runtime constants
(`pallet_qpow::Config::SeedEpochBlocks` and `SeedEpochLag`, 2048 and 64), so a
chain can pick its own without a client release:

```
seed_height(h) = 0                             if h <= epoch + lag
                 (h - lag - 1) rounded down to a multiple of epoch   otherwise
```

The seed is the hash of the block at that height, resolved along the
candidate's **own ancestry** rather than by canonical height, so a block on a
fork hashes under its own branch's seed. Every job a rig is handed carries
`next_seed_hash` as well, so xmrig builds the next dataset in the background
instead of stalling at the boundary.

Two things about 2048 and 64 are worth knowing before a launch, and both are a
one-line change in `runtime/src/configs/mod.rs`:

- 2048 blocks at Monero's 120 s target is 2.84 days, and this chain's target is
  the same 120 s, so the block count and the wall clock both match Monero. A rig
  rebuilds its dataset here as often as it does there and no more. Under the old
  12 s target the same 2048 blocks was 6.8 hours and the epoch was the constant
  that would have had to move; it does not.
- The lag is 64 and `MaxReorgDepth` is 100, so the seed block is still inside
  the window a legal reorg can move. That cannot split the chain, because the
  seed follows each candidate's ancestry, but a deep reorg across an epoch
  boundary does change the seed under work already started. A lag of 128
  removes even that. In wall clock the lag is 2.1 hours and the reorg window
  3.3 hours at a 120 s target.

**The difficulty floor moved with the engine.** `get_min_difficulty()` was
Ethereum's 2^17 and is now 128. At the 33 H/s one light-mode thread manages,
the old floor was 66 core-minutes per block, which no single-machine devnet
would ever produce against any target this chain has had. The `dev` preset starts at the
floor, and the Homestead retarget's increment is `max(difficulty / 2048, 1)`.
Integer division rounds `difficulty / 2048` to zero anywhere below 2048, which
left a chain at the floor unable to leave it, so M7 floored the increment at
one: a dev chain now climbs one step per block for as long as blocks come in
under the target. `docs/BENCH.md` measures it, 128 at block 1 and 189 at block
66. Live presets take `QPoWInitialDifficulty`, now 1 000 000, unless their own
preset overrides it: `qnero-testnet` sets 5 000, sized for the single light-mode
thread its node mines with rather than for a network (`docs/TESTNET.md`).

**What did not move.** The header shape (one 32-byte `PreRuntime` item plus a
64-byte `Seal`, filling the 110-byte digest window exactly), the author label
`H(cvk, parent_hash)`, the `FindAuthor` seam below, the coinbase inherent, the
fork-choice rule and the aux-store work entries. The engine swap went through
the seam and touched nothing the runtime reads.

**Where the seal's 64 bytes went.** A RandomX proof is a 4-byte nonce, and the
digest window needs 64. The seal is `nonce_le(4) || extra_nonce_le(4) || 56
zero bytes`, both miner-chosen fields are inside the hashed 76-byte blob, and
the 56 remaining bytes are pinned: a seal whose padding is not exactly zero is
refused before the header is hashed. Without that pin one won nonce would be
2^448 distinct valid block hashes, and a block hash is what every child commits
to.

### The block-author seam

Everything in the runtime that needs to know who authored a block reads it
through one implementation, `qnero_runtime::configs::QpowAuthor`, which
implements `frame_support::traits::FindAuthor<AccountId>`. It takes the first
`PreRuntime` digest item under `POW_ENGINE_ID`, requires exactly 32 bytes, and
derives the wormhole address from it (`qp_wormhole::derive_wormhole_address`).

**What those 32 bytes are.** Not the operator's identity. An authoring node
publishes `H(cvk, parent_hash)` there, computed by
`qnero_note_core::MinerKey::author_label` and handed to the consensus client as
`sc_consensus_randomx::AuthorLabel`, so the item changes every block. A constant
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

## Reading the runs below

The fenced blocks from here down are transcripts: what a command printed on
the day it ran, pasted unedited so a later reader can compare a fresh run
against it. The prose around them was written after the fact and reads like the
rest of `docs/`, in QNR.

The transcripts dated before 2026-09-15 quote amounts as a count of pool steps,
under the name those steps used to carry. `qnero-wallet` prints QNR now and
takes QNR on the command line, so "1000 quanta" in a fenced block below is what
today reads as `10.00 QNR`, "8 quanta" of fee is `0.08 QNR`, and
`--amount 1000` is `--amount 10`. The amounts themselves have not moved: the chain settles the
same steps of 0.01 QNR it always did. The transcripts are left as they were
printed, because a record that is edited to match today is no longer a record.

## The M4 smoke run, 2026-09-12

Recorded so a rerun has something to compare against. Development workstation,
20 cores, WSL2.

Build:

```
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

14 minutes 11 seconds of wall clock with a warm dependency cache, of which 41
seconds was `pallet-shielded`'s build script generating the circuit artifact
set. A cold cache is longer: the earlier passes of this same build spent about
an hour reaching the runtime, and `librocksdb-sys` alone compiles hundreds of
C++ objects. The binary is 80 MB at
`chain/target/release/qnero-node`.

Run:

```
nice -n 19 ./target/release/qnero-node --dev --tmp
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
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
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
`chain/target/release/qnero-node`.

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
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

1 minute 6 seconds of wall clock against the warm tree, three crates recompiled
(`pallet-shielded`, `qnero-runtime`, `qnero-node`). The circuit artifact set
did not regenerate this time: the build script's inputs did not change, only the
pallet's Rust sources. The binary is at `chain/target/release/qnero-node`.

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
`chain/target/release/qnero-node` and the metadata it serves are still the
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
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p qnero-runtime
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
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

Two builds, because a comment and a whitespace revert landed after the first
one: 1 minute 6 seconds for the build that was smoked first (three crates:
`pallet-shielded`, `qnero-runtime`, `qnero-node`), then 2 minutes 0 seconds
for the build of the tree as committed, which recompiled `qnero-node` alone.
The circuit artifact set did not regenerate in either: this pass touched neither
`QNERO_NUM_*` nor `build.rs`. The binary is 80,468,704 bytes at
`chain/target/release/qnero-node`, and the figures below are that binary's.

`nice -n 19 ./target/release/qnero-node --dev --tmp`, 49 seconds from the
first imported block to the stop, 48 blocks imported, height 48. Stopped by its
pidfile; `ss -ltn` then shows no listener on 9944, a `curl` to it is refused,
and `pgrep qnero-node` finds nothing, so the port is closed and no process is
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
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p qnero-runtime
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
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

`Finished release profile in 0.50s`: nothing to recompile. The binary at
`chain/target/release/qnero-node` is the one the entry above describes,
80,468,704 bytes, so the tree as committed and the binary already agree and no
second build was produced.

`nice -n 19 ./target/release/qnero-node --dev --tmp`, 202 seconds, 214 blocks
imported, stopped by its pidfile. `ss -ltn` then shows no listener on 9944,
`curl` to it returns no response, and `pgrep qnero-node` finds nothing.

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
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 2 -p qnero-runtime
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
  pool step, 0.01 QNR, on an unsigned and fee-free extrinsic.
- What it costs an aggregator: a submission that settles everything it carries
  is unaffected, because each slot already pays this minimum once through the
  per-slot floor, so every private batch and every ungriefed public batch prices
  exactly as before. A griefed public batch of six-slot inners that loses one
  inner owes 0.06 QNR more than its settling slots' own minimums. At the far
  end, a batch that settles one slot beside 317 skipped ones owes 318 minimums,
  3.18 QNR at the runtime's parameters, and the aggregator's alternative is to
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
SKIP_WASM_BUILD=1 nice -n 19 cargo check -j 4 -p qnero-runtime
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
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

Two builds, because three doc comments were tightened after the first one:
1 minute 3 seconds, then 1 minute 5 seconds for the build of the tree as
committed, each recompiling the same three crates (`pallet-shielded`,
`qnero-runtime`, `qnero-node`). The circuit artifact set regenerated in 28.8
seconds on the first of them, which is the release profile's own `OUT_DIR`
regenerating: this pass touched neither `QNERO_NUM_*` nor `build.rs`, so the
dimensions are the ones every earlier build used. The binary of the committed
tree is 80,465,200 bytes at `chain/target/release/qnero-node`, and the
figures below are that binary's.
Both builds serve a byte-identical `state_getMetadata` blob, which is what a
comment-only difference should produce.

`nice -n 19 ./target/release/qnero-node --dev --tmp`, 77 seconds of uptime,
74 blocks imported, final height 74. Stopped by its pidfile; `ss -ltn` then
shows no listener on 9944, `curl` to it exits 7 (connection refused), and
`pgrep qnero-node` finds nothing, so the port is closed and no process is
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

$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)

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
-rw------- 1 user user   65 Sep 12 09:19 A.seed
-rw------- 1 user user 4591 Sep 12 09:20 A.seed.store.json

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
  are 3474, so the floor is `MinLeafFee(1) + ceil(3474 / 512) = 8` steps,
  0.08 QNR. The wallet defaults to it, refuses a fee below it with the
  arithmetic spelled out, and every settlement carried exactly that.
- **A received note is spendable.** B spent the note A sent it, whose `rho` the
  circuit derived from the two nullifiers A's leaf published and whose value and
  randomness reached B only inside A's ciphertext.
- **The books.** 10.00 QNR shielded, 3.00 paid, 6.92 change, 0.08 fee; then
  1.00 paid back, 1.92 change, 0.08 fee; then 0.50 more from A over the RPC
  path, 6.34 change, 0.08 fee.

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
0.09 QNR where it was 0.08.

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

$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)
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

One pool step of fee per spend, 0.01 QNR. The floor is
`MinLeafFee(1) + ceil(3974 / 512) = 9` steps, 0.09 QNR, where it was
`MinLeafFee(1) + ceil(3474 / 512) = 8`, because padding both memos to 256 bytes
takes the pair from 3474 bytes to 3974. Nothing else moved: the proof is the
same 150908 bytes, proving is the same 3.6 s, and the padded plaintext is
stripped back on receive.

## The second M5 review fix pass, 2026-09-12

Ten review findings, two of them high or medium on the sync path and two on
what the memo pad costs the chain. The fix pass re-ran the whole end-to-end
flow against a fresh `--dev --tmp` node, because one change moves numbers the
run above recorded: the memo pad is 61 bytes where it was 256, so each output
ciphertext is a uniform 1792 bytes and the submission floor is back to
0.08 QNR.

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

$ nohup nice -n 19 ./chain/target/release/qnero-node --dev --tmp > node.log 2>&1 &
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

One pool step of fee back per spend, 0.01 QNR, and 195 bytes of memo. The
floor is `MinLeafFee(1) + ceil(3584 / 512) = 8` steps, 0.08 QNR, where the
256-byte pad made it `MinLeafFee(1) + ceil(3974 / 512) = 9`, and a memo is 61
bytes where it was
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

$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)

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
-rw------- 1 user user   65 Sep 12 12:11 A.seed
-rw------- 1 user user 5654 Sep 12 12:12 A.seed.store.json

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
  the old file as `<store>.archived` rather than deleting it, since it is the
  fastest copy of every note's `rho` and `r`: the seed recovers them, because
  every note's plaintext is on the chain inside its ciphertext, and what a lost
  store costs is the spent record and the time of a full rescan. A version-4 store records the
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

$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)
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

$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)
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

$ QNERO_MINER_KEY=$QNERO_MINER_KEY nice -n 19 ./target/release/qnero-node --dev --tmp
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

0.41 QNR was the emission at genesis supply under the 12 s target,
`(21_000_000 - 0) / 50_000_000` QNR rounded down to a whole pool step. At the
120 s target the divisor is 5 000 000 and the figure is 4.11 QNR, which is the
same supply against the same wall clock. The transcript below is from the 12 s
run and its numbers are read with that divisor. The occasional carry: a block's
credit is not a whole number of steps, the remainder waits in
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
2. **A coinbase note spends.** 0.42 QNR in, 0.05 to B, 0.08 of fee, 0.29 of change, and B's own
   sync finds its note at 0.05 QNR with the memo the sender wrote. The fee is the submission's
   floor, which at two ciphertexts of 1731 bytes is 0.08 QNR; the milestone's "fee 1" is one pool
   step, below the floor, and the chain refuses a fee below it, which is the anti-spam rule M4
   built.
3. **The author's share of that fee is in the coinbase of the block that settled it**: 0.45 QNR
   against 0.41 elsewhere, and the author's share of a 0.08 QNR fee is 0.04, the chain burning
   `ceil(8/2)` of its eight steps. It is in that block's note and in no other.
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
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release
   41 lib + 6 call_filter + 59 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p qnero-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node --all-targets
   no warnings
```

`cargo test -p qnero-runtime` is a gate again. It had not compiled since the
M4 subtree fork; see "Tests" above for what it covers now.

### Timings

Development workstation, 20 cores, WSL2, `nice -n 19`, `-j 4`.

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build --release -p qnero-node`, cold for the runtime wasm | 10:35 | 5.4 GB |
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
    nice -n 19 ./target/release/qnero-node --dev --tmp
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
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release
   42 lib + 8 call_filter + 60 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p qnero-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p sc-consensus-qpow --all-targets
   no warnings
```

### Timings

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build -j 4 --release -p qnero-node`, the one rebuild this pass owes | 10:06 | 5.4 GB |
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
    nice -n 19 ./target/release/qnero-node --dev --tmp
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

The settling block's coinbase is 0.46 QNR against 0.41 to 0.43 elsewhere, so
the author's share of the 0.08 QNR fee is 0.04 and the other 0.04 burned, which
is what the milestone measured every time.

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
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release
   42 lib + 9 call_filter + 60 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p qnero-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p sc-consensus-qpow --all-targets
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
| `cargo build -j 4 --release -p qnero-node`, the one rebuild this pass owes | 1:04 | 1.7 GB |
| chain pallet tests | 26 s | |
| runtime tests, all three targets | under 1 s | |
| root workspace tests | 2:12 | |
| the end-to-end, both tests, three proofs | 14.8 s | |

The rebuild is a minute rather than the ten the milestone's first one took,
because only the runtime and the node changed and every dependency below them
was already built.

## The third M6 review fix pass, 2026-09-12

Eight findings against the second pass: four medium, four low. One is a real
privacy leak in the coinbase derivation, one is a test that never tested half of
what it is named for, and the rest are documents claiming more than the runtime
does.

### What changed

- **A coinbase note is bound to the chain that minted it.** `coinbase_rho`'s rustdoc claimed `r` is
  drawn fresh per block from the operating system. There is no randomness in the derivation at all,
  and the node's own test asserts the opposite. The half that mattered was the chain boundary: one
  miner key on a testnet and on mainnet published byte-identical `inner` values at equal heights on
  both, so anyone who could name that operator's coinbase notes on the chain that matters less named
  them on the other by comparing 32 bytes, with no keys involved. `r` now hashes the genesis:
  `r = H(R_COINBASE, cvk, H_bytes("qnero/coinbase-chain", genesis_hash), block_number)`. The node
  reads the genesis from its own
  client and the wallet from the store it is already bound to, so a scan pays nothing.
- **What the binding does not cover, measured rather than assumed.** Two candidates at one height on
  one chain still carry one note; the header's author label `H(cvk, parent_hash)` is already
  identical for two candidates on one parent, so the note adds no linkage the block did not already
  carry, and only the canonical block is ever in a tree. And the boundary is the genesis hash and
  nothing else: `--dev --tmp` rebuilds the same genesis every run, which the run below shows by
  syncing a second dev chain and getting the same four commitments at the same four heights. That is
  harmless on a throwaway chain and it is worth knowing before someone reads "two chains" as "two
  runs". `docs/CIRCUIT.md` 10.2 carries both.
- **A genesis vesting row now has to name an account with a key.**
  `every_genesis_planck_is_reachable_under_the_call_filter` states its property as "a preset that
  endows a keyless account, or vests to one" and only checked the endowment half. Re-adding the
  schedule the dev preset used to carry, paying the keyless wormhole test address, left the suite
  green, because the pot's endowment is computed from the schedule totals and so covers a payee
  nobody can sign for. Every beneficiary is checked against a per-preset table now.
- **The genesis allocation is not a note, and five sentences said it was.** `mainnet_vesting`
  minted 5,670,000 QNR at genesis as transparent balances at the time of this review, and every
  planck of it reaches its holder through `Vesting::claim`. The allocation is 420,000 QNR now, of
  which 419,940 is the one placeholder vesting row and 60 is the seed endowments; DESIGN 7.1 and
  7.3 carry it. "Value enters circulation in exactly one place" is true of value created
  after genesis, which is what DESIGN 7.1, the pillar list, the M6 row, CIRCUIT section 10, the
  runtime's `NoTransferProofNeeded` comment, `qp-coinbase` and the `--rewards-miner-key` help now
  say.
- **CIRCUIT 10.7 gained the two rows it was missing.** A refused call is a valid extrinsic: it
  enters a block, pays its fee and fails with `CallFiltered`, leaving the sender, the recipient and
  the amount in the block body and the event log forever. One mistaken transfer therefore publishes
  exactly the triple the policy exists to deny. `Balances::burn` is the other: it is on the allowed
  list and it names the burner and the amount. DESIGN 7.2 now says the filter is a dispatch-time
  check and names moving it into a transaction extension as the open option.
- **`chain/docs/RUNTIME_SURFACE.md` is the v1 runtime again.** DESIGN 7.2 points at it as "the
  surface" and it documented the wormhole exit as live, `pallet-shielded` not at all, and the spec
  identity as `quantus-runtime` 147/6. An auditor asking what can move value out of the pool read
  that an exit exists and that vesting payouts write ZK-spendable leaves.
- **Two stale `spec_version` 100s** in DESIGN's M6 row and CIRCUIT section 4, both in the present
  tense, both against a runtime that answers 101.

### The run

Fresh chain, fresh miner wallet, the binary built from the committed tree
(`1.0.1-ce8ac24812a`).

```
$ QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6fix4/miner.seed miner-address | tail -1) \
    nice -n 19 ./target/release/qnero-node --dev --tmp
2026-09-12 22:19:28 Qnero Node
2026-09-12 22:19:28 📋 Chain specification: Qnero DevNet
2026-09-12 22:19:28 ⛏️ Coinbase notes are minted for miner key qnm1q998shke…636vsxqe
```

The derivation changed, so the first thing to check is that the node and the
wallet still agree on every note:

```
$ qnero-wallet --file /tmp/qnero-m6fix4/miner.seed sync
chain       recorded this node's genesis in the store
scanned leaves 0..30 at block 30
received 30 note(s) worth 1240 quanta

$ qnero-wallet --file /tmp/qnero-m6fix4/miner.seed status
runtime           spec 101, transaction 7
chain head        30
tree leaves       30
tree depth        3
```

Thirty blocks, thirty coinbase notes, all thirty this wallet's, at the public
values the chain published (41, 41, 42, repeating).

The end to end, unchanged in every number the milestone measured:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=/tmp/qnero-m6fix4/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 46 leaves, 46 coinbase leaves, 46 of them this wallet's, 3141 quanta
shield of 1000 quanta included at block 77 (2.01s), leaf 76
5 quanta to B at fee 8: included at block 81, change 29
coinbase of block 81: 45 quanta against 41 to 43 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
system_dryRun of set_high_security: 0x0001030005000000
system_dryRun of a vesting claim: 0x0001031602000000
test the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused ... ok
300 quanta to B: proved in 3.75s, 150908 proof bytes, included at block 85
100 quanta back to A: proved in 3.08s, included at block 91
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok

test result: ok. 2 passed; 0 failed
```

Then the measurement that corrected a sentence in this pass's own
documentation. The node was stopped, a second `--dev --tmp` chain started with
the same miner key, and a copy of the store synced against it:

```
chain 1  genesis 035c0a98a01c566a
  leaf 0  block 1  41 quanta  cm ff59e44df24240895eda85ee0bfe1fa7…
  leaf 1  block 2  41 quanta  cm b227e6eebfeaeddaac21f827f4efb496…
  leaf 2  block 3  42 quanta  cm f1036d0dc50e6dd1072ea5628ba765b4…
  leaf 3  block 4  41 quanta  cm 81adab02422e79ce9ded52487467f2b1…

chain 2  genesis 035c0a98a01c566a
  leaf 0  block 1  41 quanta  cm ff59e44df24240895eda85ee0bfe1fa7…
  leaf 1  block 2  41 quanta  cm b227e6eebfeaeddaac21f827f4efb496…
  leaf 2  block 3  42 quanta  cm f1036d0dc50e6dd1072ea5628ba765b4…
  leaf 3  block 4  41 quanta  cm 81adab02422e79ce9ded52487467f2b1…
```

Identical, because the dev chain spec is deterministic and both runs have the
same genesis hash. The draft of this entry had claimed a `--dev --tmp` relaunch
counts as another chain; it does not, and the docs say so now. Two chains are
two genesis blocks, which is what a testnet and a mainnet are.

```
$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed
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
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release
   42 lib + 9 call_filter + 60 integration passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards -p qp-coinbase -p qnero-runtime --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p sc-consensus-qpow --all-targets
   no warnings
cargo +nightly-2026-08-30 fmt --all -- --check
   clean
```

### Timings

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build -j 4 --release -p qnero-node`, the one rebuild this pass owes | 9:40 | 5.4 GB |
| chain pallet tests | 25 s | |
| runtime tests, all three targets | under 1 s | |
| root workspace tests | 2:10 | |
| the end-to-end, both tests, three proofs | 16.4 s | |

The rebuild is the milestone's first one again rather than the previous pass's
minute, because `qnero-note-core` changed: it sits under `pallet-shielded`, so
the runtime, its WASM and the node all rebuilt below it.

### Verifying the two new guards against the defects they name

Both were run against a deliberately broken tree and both failed, which is the
only evidence that a green test means anything:

- Genesis dropped from the coinbase `r` preimage:
  `a_coinbase_from_another_chain_is_not_this_wallets_note` fails, receiving 2 coinbase notes where
  it expects 1.
- A fourth dev vesting schedule paying a keyless address:
  `every_genesis_planck_is_reachable_under_the_call_filter` fails, naming the address and the
  missing list.

## The fourth M6 review fix pass, 2026-09-12

Eight findings against the third pass: one medium, seven low. The medium is the
only one that changes what a binary does, and it changes it completely: the
chain the shipped node started by default was not a Qnero chain. The token
symbol was in scope for this pass whatever the review found.

### What changed

- **The default chain was somebody else's network.** Three raw specs were embedded in the node
  (`heisenberg.json`, `planck.json`, `mainnet.json`), and `sc_cli` maps both a missing `--chain` and
  a missing `--dev` to the empty id, which resolved to the first of them. Their genesis `:code` is a
  775,278-byte compressed `quantus-runtime`: decompressed it holds zero occurrences of `qnero`,
  `Shielded`, `CoinbaseValues`, `coinbase` and `QneroCallFilter`, and fifteen of `Wormhole`. So
  `qnero-node --validator --rewards-inner-hash 0x… --rewards-miner-key qnm1…`, the invocation this
  runbook demands of an authority, started a node on the upstream Quantus network: transparent
  transfers succeeded there, no coinbase inherent existed so nothing read the miner key, and the
  wormhole exit was live, while the author-label seam still derived a fresh reward account every
  block from `H(cvk, parent_hash)` whose preimage nobody holds. All three files are deleted, every
  `--chain` id now builds its genesis from a preset compiled into the binary, and the empty id is a
  refusal that names the ids. A raw spec comes back when one is generated from a Qnero preset
  against a live Qnero network; `chain/docs/CHAINSPEC_CREATION.md` says so and keeps the procedure.
- **One token symbol, `QNR`.** The symbol had split four ways (`QNR` on dev, `HEI` on Heisenberg,
  `PLK` on Planck, `QTC` on mainnet) with the docs saying `QTC`. Every preset reads one
  `qnero_properties()` map now, and the docs say `QNR`. The symbol is the one chain-spec field a
  runtime upgrade cannot correct, because wallets, explorers and exchanges read it out of a spec
  file an operator already holds.
- **The surface named a hook that does not exist.** `RUNTIME_SURFACE.md` attributed the mint to
  `pallet-shielded::on_finalize`. The pallet declares only `on_initialize`; the mint runs in
  `pallet-mining-rewards`' `on_finalize` through `CoinbaseSink`, and that indirection is load
  bearing: hooks run in pallet-index order, `MiningRewards` is 6 and `ZkTree` is 21, so a mint from
  a hook of `Shielded` at index 24 would append every coinbase leaf after `ZkTree` folded the block,
  one block late against the root its own header carries. No test in the tree would have caught it.
- **`PendingCoinbaseFee` does carry, on most blocks.** CIRCUIT 10.1 said it survives its block only
  when a block mints no note at all. A successful mint writes `total % POOL_STEP` straight back
  into it, which on the dev chain completes one extra 0.01 QNR step roughly every eighth block. Read as
  written, any supply audit or try-runtime invariant built on that sentence would flag healthy
  state as a missing coinbase on most blocks.
- **The high-security whitelist doc claimed two calls it does not admit.** `HighSecurityConfig`'s
  type doc still offered "the two calls that move the signer's own balance out of the transparent
  layer". The second review pass took `Shielded::shield` and `Balances::burn` off, and the code, the
  function comment below it, `RUNTIME_SURFACE.md` section 5 and
  `the_high_security_whitelist_admits_only_reversible_calls` all say so. An account enrolled before
  v1 has no exit at all, which is the documented cost.
- **One coinbase `r` rule, written the same way everywhere.** DESIGN 7.1 gave it without the inner
  hash and `digest.rs` gave it without the genesis at all, so the tag's own definition still carried
  the pre-fix formula. All seven statements now read
  `r = H(R_COINBASE, cvk, H_bytes("qnero/coinbase-chain", genesis_hash), block_number)`, the
  two column diagrams naming that inner hash `chain` on its own line.
  `qnero_note_core::coinbase_r` stays the authority.
- **The node crate's tests are a gate now.** Every earlier gate ran `cargo test` for the pallets and
  the runtime and only `clippy --all-targets` for `qnero-node`, and clippy compiles a test without
  running it. The four tests pinning the node's inherent payload against `MinerKey::coinbase_note`
  had therefore never executed, including across the pass that edited both sides of that agreement.
  They pass. The gate list below runs them, and node tests stay wasm-independent so
  `SKIP_WASM_BUILD=1` keeps working.
- **"Two properties of that string" introduced three bullets.** The genesis-binding pass appended
  the third without updating the count.

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
  -p pallet-shielded -p pallet-mining-rewards -p qnero-runtime --release
   74 + 31 + (42 lib + 9 call_filter + 60 integration) passed, 0 failed
LIBCLANG_PATH=/usr/lib/llvm-18/lib RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 \
  cargo test -j 4 -p qnero-node --release
   68 passed, 0 failed
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p pallet-shielded -p pallet-mining-rewards --all-targets
   no warnings
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p qp-coinbase -p qnero-runtime --all-targets
   no warnings
cargo +nightly-2026-08-30 fmt --all -- --check
   clean
```

The node test line is new and stays in the list. It is the only automated
statement that the node's `build_payload` equals `MinerKey::coinbase_note`,
which is the agreement the wallet's whole coinbase scan rests on.

### The run

The chain id resolution first, against the rebuilt binary, because that is the
finding a green test suite would not have shown anybody:

```
$ ./target/release/qnero-node build-spec
Error: Input("no chain was named. Pass --dev for a throwaway development chain,
or --chain with one of dev, heisenberg, planck, mainnet, or the path to a chain
spec file")

$ ./target/release/qnero-node build-spec --chain heisenberg   # properties, genesis shape
{'ss58Format': 189, 'tokenDecimals': 12, 'tokenSymbol': 'QNR'}
genesis keys ['runtimeGenesis']
```

Before this pass the first command printed `"name": "Heisenberg"`, `"id":
"heisenberg"`, `"tokenSymbol": "HEI"` and a raw genesis carrying the upstream
runtime.

Fresh chain, fresh miner wallet, the binary built from this tree
(`1.0.1-3358f799ff8`):

```
$ QNERO_MINER_KEY=$(qnero-wallet --file /tmp/qnero-m6fix5/miner.seed miner-address | tail -1) \
    nice -n 19 ./target/release/qnero-node --dev --tmp
2026-09-12 23:42:58 📋 Chain specification: Qnero DevNet
2026-09-12 23:42:58 ⛏️ Coinbase notes are minted for miner key qnm1qyuytz60…rdjtv2fg

$ qnero-wallet --file /tmp/qnero-m6fix5/miner.seed sync
chain       recorded this node's genesis in the store
scanned leaves 0..44 at block 44
received 44 note(s) worth 1818 quanta

$ qnero-wallet --file /tmp/qnero-m6fix5/miner.seed status
runtime           spec 101, transaction 7
chain head        44
tree leaves       44
tree depth        3
```

Forty-four blocks, forty-four coinbase notes, all forty-four this wallet's.

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=/tmp/qnero-m6fix5/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 32 leaves, 32 coinbase leaves, 32 of them this wallet's, 3141 quanta
shield of 1000 quanta included at block 77 (505.37ms), leaf 76
5 quanta to B at fee 8: included at block 87, change 29
coinbase of block 87: 45 quanta against 41 to 43 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
system_dryRun of set_high_security: 0x0001030005000000
system_dryRun of a vesting claim: 0x0001031602000000
test the_miner_is_paid_in_notes_and_a_transparent_transfer_is_refused ... ok
300 quanta to B: proved in 6.29s, 150908 proof bytes, included at block 88
100 quanta back to A: proved in 2.99s, included at block 92
test a_shield_a_payment_and_a_payment_back_settle_end_to_end ... ok

test result: ok. 2 passed; 0 failed
```

```
$ kill $(cat node.pid), then wait for 9944 to close
port 9944 closed
node stopped
```

### Verifying the new guard against the defect it names

The two `load_spec` tests were written before the fix and run against the tree
as it stood, which is the only evidence that a green test means anything:

```
---- command::tests::every_chain_id_this_node_accepts_is_a_qnero_chain ----
assertion `left == right` failed: --chain heisenberg resolves to a spec this tree's runtime did not build
  left: {"ss58Format": 189, "tokenDecimals": 12, "tokenSymbol": "HEI"}
 right: {"ss58Format": 189, "tokenDecimals": 12, "tokenSymbol": "QNR"}

---- command::tests::an_empty_chain_id_names_the_chains_this_node_has ----
an empty chain id must not resolve to a chain: ChainSpec(name = "Heisenberg", id = "heisenberg")
```

Both hold under `SKIP_WASM_BUILD=1`, which is what makes them worth running in
a gate. A spec built from a preset needs `WASM_BINARY` and fails without it; a
raw spec carries its properties in its JSON and loads either way, so any id that
answers at all with properties this tree's runtime did not build fails the test.

### Timings

| Step | Wall | Peak RSS |
|---|---|---|
| `cargo build -j 4 --release -p qnero-node`, the one rebuild this pass owes | 9:23 | 5.4 GB |
| `pallet-shielded` suite | 25.3 s | |
| node crate suite | under 1 s | |
| the end-to-end, both tests, three proofs | 15.0 s | |

The rebuild is a full one because `qnero-note-core` changed: only doc comments
moved, and it sits under `pallet-shielded`, so the runtime, its WASM and the
node all rebuilt below it.

## The Qnero rename pass, 2026-09-13

The node binary and the runtime crate still carried upstream's names. Every
build line in this file said `-p quantus-node`, every run line pointed at
`chain/target/release/quantus-node`, `--help` opened with "Quantus Node - Echo
Chamber", and the startup banner credited "Quantus Network Developers
<hello@quantus.com>" at every start. The chain those commands start has
answered `qnero` / `qnero-node` over `state_getRuntimeVersion` since M6, so the
product and the binary an operator types had two different names, which is what
makes a bug report unanswerable.

"What is renamed and what stays upstream" above is the rule this pass applied
and the contract for the next subtree merge. This entry is the run.

### What changed

- **`quantus-node` is `qnero-node`.** The package name, `default-run`, and the
  package description, which `sc_cli` uses as the `--help` about line. There is
  no explicit `[[bin]]` in `node/Cargo.toml`: the binary target is named after
  the package, so the package rename is the binary rename, and the version line
  follows because `sc_cli` builds it from the executable's file name.
- **`quantus-runtime` is `qnero-runtime`.** The package, the workspace
  dependency, the node's dependency and its three feature lists, and every
  `quantus_runtime::` path in `node/src/` and `runtime/tests/`. The wasm builder
  names its output after the package, so the blob is
  `wbuild/qnero-runtime/qnero_runtime.wasm` and `scripts/regenerate_weights.sh`
  reads the new path.
- **Two `--help` strings under `client/cli`.** `--pool-limit` said "Default
  sized for Quantus PQ signatures" and `--pool-type` said "to preserve prior
  Quantus node behavior". The first is a property of ML-DSA-87 and now says so;
  the second says upstream. They are the only two `quantus` strings in the whole
  of `--help`, and running the built binary is what found them: a grep of the
  node crate reaches neither, which is why the guard runs the binary.
- **The startup banner's byline.** `SubstrateCli::author` answered
  `CARGO_PKG_AUTHORS`, which is the upstream workspace's attribution, so a Qnero
  node printed somebody else's maintainer and somebody else's contact address at
  every start. It answers `DigitalGuards <https://github.com/DigitalGuards/qnero>`
  now. `chain/Cargo.toml` keeps upstream's `authors` field, and the credit that
  the licence asks for is in `chain/LICENSE`, in each crate's `NOTICE` and in the
  repository README. `copyright_start_year` moved from the Substrate template's
  2017 to 2026, which is this repository's first commit.
- **`key quantus` is `key qnero`,** through `#[command(name = "qnero")]`, so the
  upstream Rust identifiers stay. Its two printed banners say Qnero, and the five
  error hints that told an operator to run `quantus-node key quantus --scheme
  wormhole` name the new command.
- **The local-development scripts and `Dockerfile.local`** point at
  `target/release/qnero-node`.
- **Two new tests.** `node/tests/naming_guard.rs` runs the binary Cargo built and
  checks `--version`, `--help` and `build-spec --chain dev`.
  `the_startup_banner_names_qnero_and_no_upstream_maintainer` in
  `node/src/command.rs` covers the banner, which appears under neither flag.

No consensus rule moved: no storage item, no hash layout, no public-input layout
and no derivation. The runtime's on-chain identity was already `qnero` /
`qnero-node` at `spec_version` 101 and is unchanged.

`impl_version` did move, in the fix pass below, and the reason belongs here:
renaming the crate changed the emitted wasm. The panic paths carry the crate
name, so the pre-rename blob and the post-rename blob differ byte for byte while
implementing the same specification, and at `impl_version` 1 both answered the
same version triple. A `set_code` preflight, an srtool reproducible-build
comparison and `try-runtime --disable-spec-version-check` all identify a runtime
by that triple, so all three would have accepted either blob. `impl_version` is
the field for a changed build of an unchanged specification, it sits outside the
metadata hash (RFC-0078 covers `spec_name`, `spec_version`, the extrinsic
version, the SS58 prefix, decimals and symbol), and it is 2.

### Verifying the guard against the defect it names

The binary from the previous commit was still on disk at the time, which made a
negative control free. Against it:

```
$ ./chain/target/release/quantus-node --version
quantus-node 1.0.1-3358f799ff8
$ ./chain/target/release/quantus-node --version | grep -ic quantus
1
$ ./chain/target/release/quantus-node --help | grep -ic quantus
5
Quantus Node - Echo Chamber
Usage: quantus-node [OPTIONS]
       quantus-node <COMMAND>
          Default sized for Quantus PQ signatures (~7300 bytes/tx) within ~256 MiB.
```

So `the_version_string_names_qnero_and_not_quantus` and
`the_help_text_names_qnero_and_not_quantus` both fail against the tree as it
stood. The third assertion is a tripwire, and it was green before this pass:
the same binary already answered `build-spec --chain dev` with name
`Qnero DevNet`, id `qnero-dev`, protocol id `qnero-devnet` and symbol `QNR`,
because M6 fixed the spec. It is in the guard so a merge cannot quietly undo
M6.

That binary and the stale `target/release/wbuild/quantus-runtime` tree beside it
are deleted now, and the fix pass below says why: a leftover `quantus-node` holds
30333 and 9944 against the new binary, and a stale wbuild directory is a path a
runbook resolves to a pre-rename wasm. The transcript above is what the negative
control leaves behind.

### The run

`$SCRATCH` below is a temporary directory outside the repository.

```
$ qnero-wallet --file $SCRATCH/miner.seed keygen
$ export QNERO_MINER_KEY=$(qnero-wallet --file $SCRATCH/miner.seed miner-address)
$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)

2026-09-13 09:32:39 Qnero Node
2026-09-13 09:32:39 ✌️  version 1.0.1-709c604561e
2026-09-13 09:32:39 ❤️  by DigitalGuards <https://github.com/DigitalGuards/qnero>, 2026-2026
2026-09-13 09:32:39 📋 Chain specification: Qnero DevNet
2026-09-13 09:32:39 👤 Role: AUTHORITY
2026-09-13 09:32:39 💾 Database: RocksDb at /tmp/substrateiPOi5Y/chains/qnero-dev/db/full
2026-09-13 09:32:39 ⛏️ Coinbase notes are minted for miner key qnm1qynvayhr…8ure20yn

RPC up 3 s after start, height 6 after 8 s.
```

`grep -ci quantus` over the whole node log is 0.

```
$ curl ... state_getRuntimeVersion
{"specName":"qnero","implName":"qnero-node","authoringVersion":1,
 "specVersion":101,"implVersion":1,"transactionVersion":7,
 "systemVersion":1,"stateVersion":1}

$ curl ... system_name         "Qnero Node"
$ curl ... system_version      "1.0.1-709c604561e"
$ curl ... system_chain        "Qnero DevNet"
$ curl ... system_chainType    "Development"
$ curl ... system_properties   {"ss58Format":189,"tokenDecimals":12,"tokenSymbol":"QNR"}
```

The wallet end-to-end against that node, both tests:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=$SCRATCH/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 49 leaves, 49 coinbase leaves, 49 of them this wallet's, 2025 quanta
shield of 1000 quanta included at block 50 (1.51s), leaf 49
5 quanta to B at fee 8: included at block 59, change 29
coinbase of block 59: 46 quanta against 41 to 43 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
300 quanta to B: proved in 3.20s, 150908 proof bytes, included at block 63
100 quanta back to A: proved in 3.07s, included at block 67
test result: ok. 2 passed; 0 failed; finished in 15.75s
```

Stopped by pidfile: the process exits 2 s after `kill`, `pgrep qnero-node` finds
nothing, `ss -ltn` does not list 9944, and `curl` to it returns nothing, so the
port is closed and no process is left behind.

### Gates

```
# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   38 suites, 327 passed, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean

# the chain workspace
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p qnero-runtime -p pallet-shielded --release
   74 + (42 lib + 9 call_filter + 60 integration) passed, 0 failed, 2 ignored
LIBCLANG_PATH=/usr/lib/llvm-18/lib RAYON_NUM_THREADS=4 nice -n 19 \
  cargo test -j 4 -p qnero-node --release
   69 unit + 3 naming_guard passed, 0 failed
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p qnero-runtime -p pallet-shielded -p sc-cli --all-targets
   no warnings
cargo +nightly-2026-08-30 fmt --all -- --check
   clean
```

The node test line runs without `SKIP_WASM_BUILD`, which is the change from the
previous pass's list. The chain-spec third of the guard builds a preset spec and
therefore needs `WASM_BINARY`; with the variable set it skips itself and says so,
which is a third of the guard silently not running. Run it with the wasm.

`sc-cli` joins the clippy line because this pass edited `client/cli`, which no
earlier pass had touched.

### What the rename cost

| Step | Wall |
|---|---|
| `cargo build -j 4 --release -p qnero-node`, the package rename, cold for the runtime wasm | 10:09 |
| the same after the two `client/cli` help strings, sc-cli and the node relinking | 0:43 |
| the same after the banner byline, the node crate alone | 0:43 |
| `cargo test -j 4 -p qnero-node --release` after the fmt pass, node relink only | 1:04 |
| the end-to-end, both tests, three proofs | 15.8 s |

Four node links, and the reason is worth writing down: the two `--help`
strings and the banner byline live outside the node crate's own text and outside
anything a grep of `chain/node` finds. Running the built binary is what found
them. A rename pass that greps the crate it is renaming and stops there ships a
binary that still says the old name in the first line it prints.

## The rename review fix pass, 2026-09-13

The rename pass moved the package names and the strings a grep of `node/src`
finds. The review found six more surfaces that answer an operator, and the
pattern in all six is the same: each is a place where the name is written
somewhere the rename never looked, so a grep of the crate being renamed reaches
none of them.

### What changed

- **`support_url` was `support.anonymous.an`,** the Substrate node template's
  default, which is the last line of `--help` and the address
  `sp_panic_handler` prints on every panic. A node that crashed told its
  operator to report it to a domain nobody owns. The byline two lines above it
  moved in the rename pass for this exact reason, and this line was left
  because it does not contain the word `quantus`. It is
  `https://github.com/DigitalGuards/qnero/issues`, and
  `the_startup_banner_names_qnero_and_no_upstream_maintainer` pins it, because
  a guard that looks for `quantus` cannot see a placeholder that names no
  project at all.
- **`--chain mainnet` answered with the chain name `Quantus` and the protocol
  id `quantus`,** on a preset that builds this tree's genesis. The guard built
  only `--chain dev`, and `every_chain_id_this_node_accepts_is_a_qnero_chain`
  asserts on the properties map that all four presets share, so neither saw it.
  A spec file is the artifact no runtime upgrade reaches. Both fields are
  outside genesis, so the runtime preset list the rename deliberately left
  alone stays untouched: the name is `Qnero`, the protocol id is `qnero`.
- **Three presets carried upstream's telemetry endpoint and bootnodes.**
  `heisenberg`, `planck` and `mainnet` all pointed at
  `shard-telemetry.quantus.cat`, and the first two dialled `quantus.cat`
  bootnodes, while building this tree's genesis. An operator who started one
  dialled peers that refuse it on genesis hash and published a node name, a
  client version and a block height to a third party for a network the node was
  never on. `scripts/start_testnet.sh` did exactly this: the rename gave it
  `qnero-node` and left `--chain planck`. Both fields are outside genesis and
  both are gone; the script runs `--chain dev`.
- **`runtime/build.rs` committed the token symbol `UNIT`** into the metadata
  hash, which is the unit a hardware or offline signer displays when it decodes
  a call. Every chain spec says `QNR`. `enable_metadata_hash` is on only under
  `on-chain-release-build`, so the drift was invisible in a development build
  and would have shipped in a release one. Both sites now carry a comment
  naming the other.
- **`impl_version` stayed at 1 across the crate rename,** and the rename
  changed the emitted wasm: the panic paths carry the crate name, so the
  pre-rename blob (684,724 bytes compressed) and the post-rename blob (684,659)
  implement the same specification and differed byte for byte while answering
  the same version triple. A `set_code` preflight, an srtool reproducible-build
  comparison and `try-runtime --disable-spec-version-check` all identify a
  runtime by that triple and would have accepted either. `impl_version` is the
  field for a changed build of an unchanged specification and sits outside the
  metadata hash, so it is 2. The rule above `VERSION` in `runtime/src/lib.rs`
  says when to move it.
- **Six scripts, a workflow and the local Dockerfile.** Both genesis scripts
  ran `cargo build --release --package quantus-node` in this tree and then
  invoked the binary, so both aborted, and `genesis_generate_spec.sh` reaches
  that line only after `set -e` has created and checked out a branch at an
  upstream tag. `create_custom_chain_spec.sh` passed `--chain local`, an id
  `load_spec` has never had, which falls through to the file-path arm and dies
  on a missing file. `kill_chains.sh` and `run_local_nodes.sh` matched only the
  new name, so a `quantus-node` left running from before the rename survived
  the kill and held 30333 and 9944 against the new binary. `ci.yml` passed
  `--features quantus-runtime/fast-governance` on two steps, and it is the one
  workflow under `chain/.github` that anybody would lift to the repository root.
  `Dockerfile.local` created a system user named `quantus` with its data under
  `/var/lib/quantus`, and created it with no home directory, so a run without
  `--base-path` fell back to a `$HOME` that does not exist.

Two things the rename table did not say, and both are now in it:

- **The default base path moved** from `~/.local/share/quantus-node` to
  `~/.local/share/qnero-node`, because `sc_cli` derives it from the
  executable's file name. Nothing declares it, so nothing in the diff showed
  it, and it is the one consequence of the binary rename with state behind it.
  The migration is one `mv`, and it is written out above.
- **The guard was absent from the standing gate list,** which is the list
  somebody runs after the subtree merge the guard exists to survive. It is in
  the chain gate block now, with the note that it must run without
  `SKIP_WASM_BUILD` or the chain-spec assertions skip themselves.

The docs the rename classified as upstream were reclassified where the
classification was wrong. The licence condition is the copyright and the notice
text, and `chain/README.md` had build-and-run commands for **this** tree that
were hard errors after the rename: `./target/release/quantus-node` after a
`cargo build --release` that produces `qnero-node`, and `key quantus`, which
`cli.rs` renamed to `key qnero` with no alias. Those and
`chain/docs/RELEASE_PREFLIGHT.md`'s are renamed, the attribution and network
names in both are untouched, and each file opens with a banner saying which
half is which. `chain/docs/RUNTIME_SURFACE.md`, `RUNTIME_UPDATE.md` and
`CHAINSPEC_CREATION.md` are Qnero-maintained and say `qnero-runtime`.
`chain/MINING.md` keeps upstream's names, because every binary in it is a
release binary from `Quantus-Network/chain` or an image from
`ghcr.io/quantus-network` and every network in it is upstream's; a rename there
would have produced a guide telling an operator to download one binary and run
another. It has a banner, and the two defaults that differ between the binaries
are called out where they appear.

`RUNTIME_UPDATE.md`'s local-build block was the sharpest of these. It read
`cargo build --release -p quantus-runtime` followed by an export of
`wbuild/quantus-runtime/quantus_runtime.compact.compressed.wasm`. The build
fails, the block has no `set -e`, and on any machine that built before the
rename the export resolves to a real pre-rename blob, so the operator authorizes
a governance `set_code` with a runtime nobody tagged. The stale
`chain/target/release/wbuild/quantus-runtime` tree and the stale
`chain/target/release/quantus-node` binary are deleted for the same reason, and
because the leftover binary is what the kill scripts were missing.

### Verifying the new guard against the defect it names

`no_chain_spec_this_node_builds_says_quantus` is the assertion that was missing.
With the mainnet builder's two fields put back to what they said before this
pass, and the binary rebuilt:

```
$ cargo test -j 4 -p qnero-node --release --test naming_guard

test no_chain_spec_this_node_builds_says_quantus ... FAILED

the --chain mainnet spec outside its genesis still says Quantus:
  "name": "Quantus",
  "protocolId": "quantus",

test result: FAILED. 4 passed; 1 failed
```

The other four passed throughout, which is the point: `--chain dev` was correct
before this pass and stayed correct, and a guard that reads only the preset the
project runs is green while the binary hands out a spec named Quantus on
request. The fields were restored and the node rebuilt; all five pass.

### The run

`$SCRATCH` below is a temporary directory outside the repository.

```
$ qnero-wallet --file $SCRATCH/miner.seed keygen
$ export QNERO_MINER_KEY=$(qnero-wallet --file $SCRATCH/miner.seed miner-address)
$ nice -n 19 ./chain/target/release/qnero-node --dev --tmp   (backgrounded, pidfile)

2026-09-13 10:20:43 Qnero Node
2026-09-13 10:20:43 ✌️  version 1.0.1-814f60693da
2026-09-13 10:20:43 ❤️  by DigitalGuards <https://github.com/DigitalGuards/qnero>, 2026-2026
2026-09-13 10:20:43 📋 Chain specification: Qnero DevNet
2026-09-13 10:20:43 👤 Role: AUTHORITY
2026-09-13 10:20:43 💾 Database: RocksDb at /tmp/substrateXGFJ87/chains/qnero-dev/db/full
2026-09-13 10:20:43 ⛏️ Coinbase notes are minted for miner key qnm1q9x8k3ne…520wr248

RPC up within 8 s of start, height 16 after 14 s.
```

`grep -ci quantus` over the whole node log is 0.

```
$ curl ... state_getRuntimeVersion
{"specName":"qnero","implName":"qnero-node","authoringVersion":1,
 "specVersion":101,"implVersion":2,"transactionVersion":7}

$ curl ... system_name         "Qnero Node"
$ curl ... system_chain        "Qnero DevNet"
$ curl ... system_chainType    "Development"
$ curl ... system_properties   {"ss58Format":189,"tokenDecimals":12,"tokenSymbol":"QNR"}

$ qnero-node --help | tail -1
Support: https://github.com/DigitalGuards/qnero/issues
```

`implVersion` is 2 here and 1 in the rename pass's transcript above, which is
the bump this pass made.

Every preset, read back out of the built binary with `build-spec
--disable-default-bootnode`:

```
chain        name          id           protocolId    symbol  bootNodes  telemetry  quantus hits
dev          Qnero DevNet  qnero-dev    qnero-devnet  QNR     0          none       0
heisenberg   Heisenberg    heisenberg   heisenberg    QNR     0          none       0
planck       Planck        planck       planck        QNR     0          none       0
mainnet      Qnero         mainnet      qnero         QNR     0          none       0
```

The wallet end-to-end against that node, both tests:

```
$ QNERO_DEV_NODE=http://127.0.0.1:9944 QNERO_MINER_SEED=$SCRATCH/miner.seed \
    RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release -p qnero-wallet \
    --features parallel --test dev_node_e2e -- --nocapture

sync: 20 leaves, 20 coinbase leaves, 20 of them this wallet's, 826 quanta
shield of 1000 quanta included at block 21 (2.01s), leaf 20
5 quanta to B at fee 8: included at block 24, change 29
coinbase of block 24: 46 quanta against 41 to 43 elsewhere, author share 4
system_dryRun of a transparent transfer: 0x0001030005000000
300 quanta to B: proved in 3.06s, 150908 proof bytes, included at block 27
100 quanta back to A: proved in 3.33s, included at block 34
test result: ok. 2 passed; 0 failed; finished in 16.53s
```

Stopped by pidfile: `ss -ltn` does not list 9944, `curl` to it returns nothing,
and the only `pgrep -f 'q(nero|uantus)-node'` match left is the shell running
the `pgrep`.

### Gates

```
# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
   38 suites, 327 passed, 0 failed
nice -n 19 cargo clippy -j 2 --workspace --all-targets
   no warnings
cargo fmt --all -- --check
   clean

# the chain workspace
RAYON_NUM_THREADS=4 SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p qnero-runtime -p pallet-shielded --release
   74 + 42 + 9 + 60 passed, 0 failed, 2 ignored
LIBCLANG_PATH=/usr/lib/llvm-18/lib RAYON_NUM_THREADS=4 nice -n 19 \
  cargo test -j 4 -p qnero-node --release
   69 unit + 5 naming_guard passed, 0 failed
LIBCLANG_PATH=/usr/lib/llvm-18/lib SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p qnero-node -p qnero-runtime -p pallet-shielded -p sc-cli --all-targets
   no warnings
cargo +nightly-2026-08-30 fmt --all -- --check
   clean
```

`sc-transaction-pool` took a one-line doc comment in this pass, so clippy was
run over it too: its lib is clean, and its lib-test target fails the vendored
`unwrap_used` and `expect_used` lints on 123 pre-existing sites that no pass
here has touched. That crate is outside the documented clippy set for this
reason.

### Timings

| Step | Wall |
|---|---|
| `cargo build -j 4 --release -p qnero-node` after the six code fixes, runtime wasm relinked | 1:05 |
| `cargo test -j 4 -p qnero-node --release`, the widened guard | 4.9 s of test time |
| the negative control: rebuild with the mainnet fields restored, guard, rebuild forward | 2 x 1:05 |
| the end-to-end, both tests, three proofs | 16.5 s |

## The M7 run: RandomX proof of work, 2026-09-13

### What changed

The engine. Qnero's proof of work is RandomX `rx/0`, stock upstream constants,
so the hash is the one Monero mines and a rig moves over by editing a pool
address. Six things moved and one thing deliberately did not.

- **`chain/client/consensus/randomx`** is the new engine crate and replaces
  `chain/client/consensus/qpow`, which is deleted. It carries the blob layout,
  the seed rule, Monero's target comparison, the RandomX cache and VM pool, the
  block import, the import-queue verifier and the mining worker. The bindings
  are `randomx-rs`, which vendors tevador's `librandomx` and builds it with
  cmake; the crate asserts `librandomx`'s own known-answer vectors in its
  tests, so a toolchain that miscompiled RandomX fails a test rather than
  forking a chain.
- **Verification left the runtime.** RandomX cannot run in wasm: the Argon2d
  cache alone is 256 MiB against a 128 MiB runtime heap, there is no JIT, and
  the VM sets a floating-point rounding mode wasm has no way to express. So
  `pallet_qpow::verify_nonce_on_import_block`, `verify_nonce_local_mining` and
  `verify_and_get_achieved_difficulty` are gone, with the three matching
  runtime-API methods and the `ProofSubmitted` event. `chain/qpow-math` is
  deleted with them.
- **`pallet-qpow` kept its difficulty half, and that was the point of looking.**
  The retarget is a pure function of the parent difficulty, the observed block
  time and the target block time. Nothing in it reads a nonce, a hash or an
  engine id, so there was no engine-specific part to fork out, and an LWMA
  would have been a different tuning of the same inputs rather than a different
  pallet. Storage, the genesis override and the `DifficultyAdjusted` event are
  untouched, so no storage item moved. Two constants joined the config,
  `SeedEpochBlocks` and `SeedEpochLag`, and two runtime-API methods read them.
- **The floor moved, and the increment grew a floor of its own.**
  `get_min_difficulty()` was Ethereum's 2^17 and is 128: at 33 H/s the old
  floor was 66 core-minutes per block, which no single-machine devnet could ever
  produce. `QPoWInitialDifficulty` went from about 10^11 to 100 000 for the same
  reason, and to 1 000 000 when the target block time moved to 120 s: difficulty
  is expected hashes per block, so the same network needs ten times as much at a
  ten times longer target. And because the Homestead
  increment is `parent / 2048`, which integer division rounds to zero below
  2048, a chain that reached the new floor could never leave it; the increment
  is now `max(parent / 2048, 1)`, which changes nothing above 2048.
- **The node grew a stratum endpoint** (`node/src/stratum.rs`, `--stratum-port`)
  and lost the QUIC miner server (`node/src/miner_server.rs`, the
  `quantus-miner-api` crate, `--miner-listen-port`, `--miner-auth-token-file`).
  Upstream's external miner computes Poseidon hashes; no transport would have
  let it mine this chain, so keeping its protocol would have meant shipping an
  interface nothing could speak.
- **In-process mining is RandomX light mode on `--mining-threads` threads**,
  one by default, which is what keeps `--dev` producing blocks with no rig
  attached.

What did not move is the seam M6 built. `configs::QpowAuthor` was not edited.
`POW_ENGINE_ID` is still `pow_`, the header still carries one 32-byte
`PreRuntime` item and one 64-byte `Seal` filling the 110-byte digest window
exactly, the author label is still `H(cvk, parent_hash)`, the coinbase inherent
still mints the block's note from the node's own miner key, and fork choice is
still `parent_work + difficulty` in the aux store. `spec_version` moved to 102
for the metadata the deleted API methods and event took with them;
`transaction_version` stayed at 7.

### Where the seal's 64 bytes went

A RandomX proof is four bytes and the digest window needs 64. The blob is a
fixed 76 bytes with the nonce at offset 39, because that is where xmrig writes
and it is not configurable on the miner side:

```
0..7    b"qnero/1"                      domain tag
7..39   pre-seal header hash
39..43  nonce, little-endian u32        <- the four bytes xmrig writes
43..51  block height, little-endian
51..55  extra nonce, little-endian u32  <- per stratum connection
55..76  zero padding
```

and the seal is `nonce_le(4) || extra_nonce_le(4) || 56 zero bytes`. Both
miner-chosen fields are inside the hashed blob and the remaining 56 bytes are
pinned: a seal whose padding is not exactly zero is refused before the header
is hashed. Without that pin one won nonce would be 2^448 distinct valid block
hashes, and a block hash is what every child commits to, including through the
parent hash the author label is derived from.

### The run

```
# in the chain workspace
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node

export QNERO_MINER_KEY=$(qnero-wallet miner-address)
RUST_LOG=info nice -n 19 ./target/release/qnero-node --dev --tmp \
  --stratum-port 3333 --mining-threads 1
```

```
⛏️ Coinbase notes are minted for miner key qnm1q8ams9rq…0dfx95rk
Genesis: Set initial difficulty to 80
⛏️ Stratum listening on 127.0.0.1:3333 (algo rx/0, share difficulty 5000)
⛏️ Point a rig at 127.0.0.1:3333: xmrig --algo rx/0 -o 127.0.0.1:3333 -u <label>
⛏️ RandomX: initialising the seed cache for c61648d3…e622b037 (light mode, 256 MiB)
⛏️ RandomX mining task spawned (rx/0, 1 in-process thread(s), flags FLAG_HARD_AES | FLAG_JIT | FLAG_ARGON2_SSSE3 | FLAG_ARGON2_AVX2)
⛏️ Mining #7 with rx/0: pre_hash=144b6dcb…f396229e, difficulty=132, seed #0 c61648d3…e622b037
🥇 Successfully mined and submitted a new block in process (mining time: 4s)
🏆 Imported #7 (0x199d…fd59 → 0x89cb…b080)
```

`seed #0` is the seed height, genesis for every block below `epoch + lag`,
which on a devnet is every block it will ever have. Blocks #1 to #14 took 56 s
on one light-mode thread, 4.3 s each, with the difficulty climbing one step per
block from the floor of 128.

Then a stock xmrig, downloaded as a release tarball outside the repository and
never into it:

```
nice -n 19 xmrig --threads=2 --algo rx/0 -o 127.0.0.1:3333 -u qnero-rig -p x --no-color
```

xmrig's own transcript, unedited except for trimming:

```
 * ABOUT        XMRig/6.21.3 gcc/13.2.1 (built for Linux x86-64, 64 bit)
 * POOL #1      127.0.0.1:3333 algo rx/0
[..] net      use pool 127.0.0.1:3333  127.0.0.1
[..] net      new job from 127.0.0.1:3333 diff 182 algo rx/0 height 56
[..] randomx  init dataset algo rx/0 (20 threads) seed c61648d3568edb0a...
[..] randomx  allocated 2336 MB (2080+256) huge pages 0% 0/1168 +JIT (0 ms)
[..] randomx  dataset ready (3809 ms)
[..] cpu      use profile  *  (2 threads) scratchpad 2048 KB
[..] cpu      accepted (1/0) diff 182 (23 ms)
[..] net      new job from 127.0.0.1:3333 diff 183 algo rx/0 height 57
[..] cpu      accepted (2/0) diff 182 (38 ms)
...
[..] miner    speed 10s/60s/15m 817.6 n/a n/a H/s max 851.0 H/s
[..] cpu      accepted (309/0) diff 205 (24 ms)
```

and the node's side of the same conversation:

```
⛏️ Miner 127.0.0.1:36264 logged in as "qnero-rig" ("XMRig/6.21.3 (Linux x86_64) …"), extra nonce 0xbc53418c
🥇 Share from "qnero-rig" meets the block difficulty 176 at height 50
🥇 Successfully mined and submitted a new block by stratum miner "qnero-rig" (mining time: 1s)
⛏️ Stratum so far: 912 shares accepted, 0 rejected, 911 of them blocks
```

The chain reached #84 in 4 m 02 s: **74 blocks mined in process and 10 mined by
xmrig**, every one of them verified by the node's own RandomX before import.
Every share the node accepted it re-hashed itself, over a blob it rebuilt from
the job it issued; the `result` field a miner sends is compared against that
and never used in its place. The in-process miner wins most of this devnet
because at a difficulty of 180 almost any nonce is a block and the node is
holding the build: on a real difficulty the rig's 817.6 H/s here, and ~900 H/s
in the later sessions below, against the node's 33 H/s decides it.

That run also measured what the loop did with the rig's winning shares. It
hashed a whole batch before polling the seal channel for a millisecond, so a
block-worthy share waited up to half a second and was then dropped if the
template had moved: `48 + 17 = 65`, the node sealing 48 of the rig's 65
block-worthy shares and logging `dropping a seal for the superseded job` for
the other 17, each of them acknowledged to the miner with `status: OK` and then
thrown away. The two producers are raced against each other now, so a seal is
taken the moment it lands.

The zero in that rejection count is the whole point of the run, and it was not
zero the first time. xmrig's `Client::isCriticalError` treats four pool error
strings as fatal and closes the socket on any of them: `Unauthenticated`,
`your IP is banned`, `IP Address currently banned`, and `Invalid job id`. An
earlier build answered a stale share with `Invalid job id`, which is the
ordinary outcome of a template roll, so every burst of stale shares cost a
disconnect and a retry pause:

```
[..] cpu      rejected (74/1) diff 184 "Invalid job id" (1653 ms)
[..] net      no active pools, stop mining
[..] net      use pool 127.0.0.1:3333  127.0.0.1
```

Six of those in 69 s of mining, about half the wall time at zero hash rate. Two
changes closed it. The endpoint keeps the immediately-previous template beside
the current one and credits shares against it, because a rig is always
mid-nonce when the template moves and that work was earned; and nothing below a
connection-level failure is ever answered with one of xmrig's four strings, so
a genuinely expired job is `Block expired` and the rig keeps mining. A test
enumerates the share-level rejections and fails if any of them is in that set.

The header of block #65, read back over RPC, is the whole seal design in one
line:

```
PreRuntime  0x06 706f775f 80 d232d9d0…cedf504e          (32-byte author label)
Seal        0x05 706f775f 0101 5f30fa7a 3c3881e7 00…00  (nonce, extra nonce, 56 zero bytes)
```

Shut down by pidfile, with `ss -ltn` confirming 9944 and 3333 closed and no
`qnero-node` or `xmrig` process left.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p sc-consensus-randomx -p pallet-qpow -p qnero-runtime -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 \
  -p sc-consensus-randomx -p pallet-qpow -p sp-consensus-qpow -p qnero-node --all-targets
cargo +nightly fmt -p sc-consensus-randomx -p pallet-qpow -p sp-consensus-qpow \
  -p qnero-node -p qnero-runtime -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

All green. 55 tests in `sc-consensus-randomx`, 21 in `pallet-qpow`, 75 in the
node crate (16 of them stratum protocol tests driven by a fake miner that
speaks xmrig's messages), 60 in the runtime's integration suite, and 38 test
binaries in the root workspace.

The chain workspace's formatting convention is **nightly** rustfmt: its
`rustfmt.toml` sets `binop_separator`, `match_arm_blocks` and six other
unstable options, and stable rustfmt silently ignores them and then disagrees
with the result. `cargo fmt` on stable reformats upstream crates that were
never stable-clean, so the chain-side format gate is `cargo +nightly fmt`. The
root workspace is stable-clean and its gate is the stable one.

## The M7 review fix pass, 2026-09-13

Thirteen findings against the M7 tip: three high, three medium, seven low. Two
of the highs and one medium were the same shape, a connection the endpoint
could not get rid of, and the third high was a rig that could not tell it had
been refused.

### What changed

**A peer that stops reading can no longer keep a connection slot.** The reply
path was `out_tx.send(...).await`, which waits for queue capacity, and the
writer task behind it awaited `write_all` with no deadline. A peer that opened a
socket, sent lines that each earn a reply, and then stopped reading filled its
own receive window, then the node's send buffer, then the 32-line queue, and
parked the connection task for good. With the 64-connection cap this pass added,
64 such sockets from one address took the endpoint permanently: the accept loop
refused every rig and the node fell back to its one light-mode thread, 33 H/s
against a rig's 800. Three changes: every reply goes out with `try_send` and a
full queue ends the connection, the same rule login and `broadcast_job` already
used; each `write_all` is deadlined at 10 seconds; and the join that waits for
the writer to drain is deadlined too, with an `abort()` behind it, so the slot
comes back even when the socket is wedged. A test floods one connection from a
client that never reads and asserts a fresh login is served afterwards. Against
the previous code it fails after 35 s.

**The pre-login window is 30 seconds, and the long one is earned.** The idle
deadline was computed once from the share difficulty and applied from the first
byte, so a peer that never authenticated held its slot for 300 s at the floor
and 7200 s at the ceiling. It is now split: `LOGIN_TIMEOUT` until a session
exists, the share-scaled deadline after. Alongside it, a per-address cap of 4
connections, because the global cap alone lets one host hold every slot.

**The deadline counts writes as well as reads.** xmrig re-arms its keepalive
timer on every line it *receives*, so a rig taking job pushes sends nothing at
all: over a 156 s session with pushes every 2 s it sent 66 submits and zero
keepalives. A deadline measured only on inbound lines was therefore a bet on
the rig's hash rate, and at 20 H/s against the default share difficulty it was
four expected share intervals, about a 1.8 percent chance of a spurious
disconnect per window. The connection now records the time of its last
successful write and takes whichever of read or write came last.

**A login the node cannot serve now closes the socket.** `No job available yet`
is the answer while authoring is paused or before the first template, and
measured against xmrig 6.21.3 the rig logged one line and then did nothing for
75 s: `Client::parse` clears the expiry timer on every line received, and the
keepalive timer is armed only inside a *successful* login, so both sat at zero.
Answering `status: OK` with no job fails too: `parseLogin` runs `parseJob` over
the result and fails the login when the job is missing. The refusal is queued and the connection then
closes, which is the EOF xmrig counts as a failure and retries after.

**A rig's seal is no longer gated behind a batch of local hashing.** The loop
hashed `LOCAL_MINING_BATCH` nonces, about half a second on one light-mode
thread, and only then polled the seal channel for a millisecond. A block-worthy
share waited out that batch and was dropped if the template moved first. The
two producers are raced against each other now, `tokio::select!` with the rig
first, both futures cancel safe. The measurement is in the run below.

**Authoring pausing keeps the template creditable.** `clear_current_job` reset
both job slots, so every rig already connected was answered `Block expired` for
the whole of a pause. The current template moves to the grace slot instead, so
shares in flight when the pause began are still hashed and credited. A fresh
login is still refused, which is the part of the behaviour that was wanted.

**Smaller ones.** xmrig compares its four critical error strings with
`strncasecmp`, so they are case-insensitive prefixes: the guard that stopped a
share-level rejection from being one of them tested whole-string equality and
would have passed `Invalid job id (expired)`. It matches on the prefix now,
ignoring case, and a test enumerates the cases. The duplicate-share set is
evicted when the template rolls and a stalled chain rolls none, so it has a
100 000-entry ceiling. `--mining-threads` is refused above the machine's
available parallelism, since every thread is a blocking task on the pool
rocksdb and block import share.

### The run

```
export QNERO_MINER_KEY=$(qnero-wallet miner-address)
RUST_LOG=info nice -n 19 ./target/release/qnero-node --dev --tmp \
  --stratum-port 3336 --mining-threads 1

nice -n 19 xmrig --threads=2 -o 127.0.0.1:3336 -u qnero-rig --algo rx/0
```

The node mined blocks #1 to #12 on its own thread in 36 s, the rig logged in at
13:37:41, and the chain reached #211 by 13:39:45. Of the 199 blocks in the
rig's two-minute window, **190 were mined by xmrig**:

```
⛏️ Miner 127.0.0.1:47612 logged in as "qnero-rig" ("XMRig/6.21.3 (Linux x86_64) …"), extra nonce 0x3fc0afe9
🥇 Share from "qnero-rig" meets the block difficulty 215 at height 89
🥇 Successfully mined and submitted a new block by stratum miner "qnero-rig" (mining time: 0s)
⛏️ Stratum so far: 478 shares accepted, 0 rejected, 469 of them blocks
```

One login, no reconnects, 0 rejected, and **zero `dropping a seal for the
superseded job`**. The previous pass's run on the same workstation logged 17 of
those against 65 block-worthy shares and sealed 10 blocks from the rig; this one
sealed 190. The remaining gap between 469 block-worthy shares and 190 blocks is
arithmetic: at a difficulty around 210 nearly every nonce clears it, so a rig
sends several block-worthy shares against one template, and one template is one
block by definition.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p sc-consensus-randomx -p pallet-qpow -p qnero-runtime -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p qnero-node --all-targets
cargo +nightly fmt -p qnero-node -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

All green. The node crate is at 84 tests, 22 of them stratum protocol tests
driven by a fake miner that speaks xmrig's messages, with the node built once
for the run above.

## The M7 second review fix pass, 2026-09-13

Nine findings against the first fix pass: four medium, five low. Three of the
four mediums were the stratum endpoint again, and each one was a way for a
connection to cost the node something it could not get back: a slot held
forever, a rig hashing a dead template, a farm refused in silence. The fourth
was the verifier.

### What changed

**A header at or below the finalized height is refused.** `verify_pow` bounded
a candidate's height against its parent and nothing else, so on an archive node
a peer chose which RandomX seed epoch the verifier resolved. A fork response
carries up to `MaxReorgDepth` headers of which only the last is pinned to the
hash that was asked for; the other 99 are free-form, and an archive node still
resolves every old parent they name. Headers whose heights fall in three
rotating epochs miss both seed caches the engine holds, and a miss is a 256 MiB
Argon2d fill before one byte of the hash meets the target: hundreds of
milliseconds of the import queue's single verification task per header carrying
no proof of work, and the eviction costs the live seed a re-fill for the honest
block that follows. The floor is the one `sc-client` applies a few stages later
as `NotInFinalizedChain`, so nothing importable is lost, and what it leaves is
the unfinalized window, `MaxReorgDepth` blocks wide and therefore at most the
two epochs the cache pool already holds. Two exemptions, both paid for only on
the path that is about to reject: the block that fills a warp or fast sync gap,
which is the exemption `sc-client` carries, and a block the node already has,
which is what `check-block` and `import-blocks` hand back to the import queue
by design.

**A pause now reaches the rigs that are already connected.** `pause_authoring`
fires once on the enabled-to-disabled edge and moves the template to the grace
slot, and while authoring is paused nothing rolls it out of there: the mining
loop never reaches `mine_one_template`, so `broadcast_job` is never called. A
connected rig therefore kept its job, kept its keepalives answered, and had
every share hashed, counted and answered `OK`, for the length of a stale tip or
an initial sync. Meanwhile a rig connecting during the same pause was told
`No job available yet` and closed. The endpoint now answers both the same way:
`Node is not authoring`, then the EOF that makes xmrig count a failure and
retry on its own timer. Dropping the server's copy of the outgoing sender does
not do it, because the connection holds its own, so a session carries a
`Notify` the read loop selects on.

**A logged-in connection can reach the idle deadline again.** The deadline
counts the node's own job pushes as proof of life, which is what keeps a rig at
a high share difficulty from being disconnected while it hashes. It also meant
a peer that sent one login line and then only drained was refreshed by the node
every block interval against a floor of 25 of them: 16 addresses at four
connections each took all 64 slots with one line apiece and held them until the
node restarted. There is now a ceiling on inbound silence that writes do not
refresh, and it is part of the wait itself: the share-scaled deadline is hours
away, so a check made only on re-entry would leave the loop inside one read for
all of it. Two hours leaves a real rig, which submits or keepalives far
inside that, untouched.

**And the read is cancel safe.** `read_line` is documented as not cancel safe:
the bytes it has taken off the socket live in the future and are dropped with
it. Harmless while a timeout ended the connection, and not harmless once the
timeout began re-entering the read, because the resumed call started mid-line.
A submit split across two TCP segments with the timer firing between them came
back as a parse error and the share in it was lost with nobody able to say
which. `fill_buf` consumes nothing when cancelled, and the line buffer now
outlives the iteration.

**The per-address cap is a flag, and a refusal says so.** It was a hard-coded
4: a normal number of rigs behind one NAT gateway, and a normal number of xmrig
instances pinned per CCX on the node's own box. Past it the socket was dropped
with nothing written and the only trace was a `debug` line, which is off at the
default `RUST_LOG=info`, so the rig logged "connection closed" and retried every
five seconds forever with neither end saying why.
`--stratum-max-connections-per-ip` defaults to 16, both refusal paths write
`Too many connections` before closing, and both log at `warn`, rate limited to
one a minute with the suppressed count carried to the next line.

**Smaller ones.** A dropped local mining round kept hashing: its workers are
`spawn_blocking` tasks, which cannot be aborted, so every time a rig won a
template the round's threads ran their whole batch on the pool that also
carries rocksdb and block import. The round now holds a stop flag its workers
poll, set by the flag's `Drop`. The operator's stratum line counted
block-worthy shares as blocks, which on an easy chain overstates a rig's output
by more than a factor of two; shares at the block difficulty, blocks sealed and
seals that arrived too late are now three numbers, and blocks are counted where
the seal is consumed. And the submit budget could refuse a block before it was
hashed: the share difficulty is clamped per job to the block difficulty, so on
a chain at the difficulty floor every share is a block, and a 10 kH/s rig there
submits about 78 a second into a bucket refilling at 32. The refill now follows
what a share is worth.

### The run

```
export QNERO_MINER_KEY=$(qnero-wallet miner-address)
RUST_LOG=info nice -n 19 ./target/release/qnero-node --dev --tmp \
  --stratum-port 3338 --mining-threads 1

nice -n 19 xmrig --threads=2 -o 127.0.0.1:3338 -u qnero-rig -p x --algo rx/0 \
  --no-color --log-file=rig.log --print-time=15
```

Node side, with the counters split:

```
⛏️ Stratum listening on 127.0.0.1:3338 (algo rx/0, share difficulty 5000, idle timeout 1000s)
⛏️ Mining #5 with rx/0: pre_hash=3cdcb854…, difficulty=131, seed #0 c61648d3…
⛏️ Miner 127.0.0.1:… logged in as "qnero-rig" ("XMRig/6.21.3 (Linux x86_64) …"), extra nonce 0xd78f8e2e
🥇 Share from "qnero-rig" meets the block difficulty 220 at height 94
🥇 Successfully mined and submitted a new block by stratum miner "qnero-rig" (mining time: 0s)
⛏️ Stratum so far: 334 shares accepted, 0 rejected, 334 at the block difficulty, 128 sealed, 205 too late
```

Rig side, from its own log:

```
[14:42:52.567]  net      use pool 127.0.0.1:3338  127.0.0.1
[14:43:10.785]  miner    speed 10s/60s/15m 924.4 n/a n/a H/s max 926.6 H/s
[14:44:11.644]  cpu      accepted (334/0) diff 270 (24 ms)
```

Both ends agree: 334 shares accepted, 0 rejected, one pool connection and no
reconnects over the 79-second window, about 900 H/s on two threads against the
node's own 33 H/s on one. The node's `128 sealed` is exactly the number of
`by stratum miner` lines in its log, which is the point of splitting the
counter: one template is one block by definition, and at a difficulty around
250 a 900 H/s rig finds several block-worthy nonces against each one. The
`205 too late` is that arithmetic, and it is now a number an operator can read
at the default log level. An earlier 103-second run on the same build reached
#181 with 167 of its blocks mined by the rig on the same terms.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 \
  -p sc-consensus-randomx -p pallet-qpow -p qnero-runtime -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p qnero-node -p sc-consensus-randomx --all-targets
cargo +nightly fmt --all -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

All green. The consensus crate is at 58 tests and the node crate at 92, 26 of
them stratum protocol tests driven by a fake miner that speaks xmrig's
messages, with the node built once for the run above.

## The M7 third review fix pass, 2026-09-13

Five findings against the second fix pass: two mediums, which are the same
defect reported twice, and three lows. The medium is the stratum endpoint for
the fourth time, and it is the bound the second pass thought it had already
set: a connection slot an unauthenticated peer keeps for the life of the
process.

### What changed

**The pre-login deadline is the connection's age.** `LOGIN_TIMEOUT` was
subtracted from the time since the last line in either direction, and every
completed inbound line stamps that clock at the top of the read loop. A blank
line is a completed line: `read_one_line` returns `Line::Complete`, the clock
is stamped, and only then is the line discarded as blank. So one `\n` bought a
peer a fresh 30 seconds, and it also refreshed the 7200-second silence ceiling
the second pass added, which left no bound that could fire. Nothing else ends
a connection before login, because `keepalived` is answered without a session
and a `submit` before login replies `Unauthenticated` and keeps serving. Four
source addresses, or one IPv6 /64, took all 64 slots for about two bytes per
30 seconds per socket, and every real rig was answered `Too many connections`
until the node restarted. On the documented rig-only deployment,
`--mining-threads 0` with a stratum port, that is a node that stops authoring.

The window now runs from `opened`, the instant the connection was accepted,
and it is folded into the read's own timeout the way the silence ceiling is,
so a read already in progress ends on it. The share-scaled deadline
a rig earns by logging in is unchanged and is still an activity deadline,
which is what a rig that is hashing and has found nothing needs. A peer that
does not log in inside 30 seconds is closed with `did not log in`.

`a_peer_that_talks_without_logging_in_gives_its_slot_back` is the regression
test, and it runs the case twice: once with a bare newline and once with a
`keepalived`, which is answered and therefore moves the write clock too. Both
are written every half window. Against the old rule both hold the slot for the
whole five seconds the test waits, and the rig behind them is refused; against
the new one both are closed and the rig logs in. The existing
`a_connection_that_never_logs_in_gives_its_slot_back` does not cover this,
because a peer that sends nothing at all refreshes nothing.

**Three low findings, all documentation of behaviour that had moved.**

- `docs/OPS-DEV.md` still said the retarget increment is `difficulty / 2048`
  and therefore zero below 2048, so a dev chain stays at 128. M7 floored the
  increment at one, `docs/BENCH.md` measures the consequence, 128 at block 1
  and 189 at block 66, and the two docs contradicted each other inside one
  milestone. The mining section now states `max(difficulty / 2048, 1)` and
  points at the measured row.
- The comment in the librandomx known-answer test said the seeds are the test
  keys zero-padded to 32 bytes, while the code passes the raw key, which is
  what the published vectors are defined over. A RandomX key is variable
  length, so a maintainer acting on the comment would pad the key, build a
  different cache and fail all four vectors. The comment now says what the
  code does and names `the_engine_passes_the_seed_to_randomx_unchanged` as the
  test that covers the 32-byte seed the node actually uses.
- `insert_seen` clears the whole duplicate set at its ceiling, and the comment
  claimed that costs at most one re-credited duplicate. It re-opens every
  entry, including shares already credited against a job that is still live,
  and every submitted nonce counts toward the ceiling whether or not it was
  valid, so a full endpoint spending its ordinary refill reaches 100 000 in
  under a minute. The comment now says that, and says what it costs: hashing
  the dedup exists to save, and `accepted` and `block_candidates` that can
  over-report by the duplicates it buys. No consensus impact:
  `MiningHandle::submit` verifies and consumes the build under one lock, so a
  duplicate seal cannot produce a second block. Keying the set per job was
  considered and left alone, because the case the ceiling exists for is a
  chain whose one live job never rolls, and a per-job map still needs a
  ceiling there.

### The run

The node was rebuilt once for the stratum change, then `--dev --tmp
--stratum-port 3348 --mining-threads 1` against xmrig 6.21.3 at
`nice -n 19 --threads=2` for a little over two minutes:

```
⛏️ Miner 127.0.0.1:47930 logged in as "qnero-rig" ("XMRig/6.21.3 (Linux x86_64) …"), extra nonce 0x342e7bac
⛏️ Stratum so far: 508 shares accepted, 0 rejected, 508 at the block difficulty, 215 sealed, 293 too late
```

One login, no reconnects, 0 rejected, 215 blocks sealed from the rig, and the
chain reached #235 at difficulty 361 from a genesis of 128, which is the
floored increment climbing. Both ends were stopped by pidfile and port 3348
was closed afterwards.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 \
  -p sc-consensus-randomx -p pallet-qpow -p qnero-runtime -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 2 -p qnero-node -p sc-consensus-randomx --all-targets
cargo +nightly fmt --all -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

All green. The consensus crate is at 58 tests and the node crate at 93, 27 of
them stratum protocol tests driven by a fake miner that speaks xmrig's
messages. `-j 2` throughout on this workstation, in place of the `-j 4` the
earlier passes used on the chain workspace.

A note on `cargo fmt` here: the chain workspace's `.rustfmt.toml` sets options
that only nightly rustfmt honours, so `cargo +nightly fmt` is the gate. Stable
`rustfmt` on a file in that workspace rewrites match arms and binary operators
that nightly leaves alone, and it follows `mod` declarations into files it was
not handed.

## The M7 fourth review fix pass, 2026-09-13

One finding against the third fix pass, a medium, and it is the stratum
endpoint for the fifth time: the same connection slot, held by the same kind of
peer, through the last bound that was still refreshed by a line the peer chose
to send.

### What changed

**The liveness rule is an accepted share, and it is the only rule.** The
post-login bound was a ceiling on inbound silence, and every completed line
refreshed it. A blank line is a completed line, `keepalived` is answered without
looking at the session, and a malformed line and a rejected share are both
answered too, so a peer that logged in once and then sent one byte every hour
held its connection slot for the life of the process. Beside that ceiling sat a
share-scaled deadline that counted the node's own job pushes as proof of life,
which meant the node itself kept such a session alive. The third pass closed the
pre-login half of this, and the post-login half is the same defect one line
later: 16 peers at the per-address cap, or 64 across four addresses, and the
operator's own rigs are answered `Too many connections` until the node restarts.
On the documented rig-only deployment, `--mining-threads 0` with a stratum
port, that is a node that stops authoring.

The new rule is the one a pool uses. A logged-in session has
`first_share_timeout` to produce a share that verifies at or above the job's
share target, and `share_timeout` between accepted shares after that. Nothing
else refreshes the clock. A blank line does not, a `keepalived` does not, a
malformed line does not, a rejected share does not, and neither does anything
the node writes to the connection. `keepalived` is still answered, because
xmrig arms a keepalive timer inside a successful login and expects a reply, and
it is inert otherwise. The silence ceiling is gone, so there is one bound after
login to explain and one flag to tune, and the pre-login window from the
connection's age is untouched. A session that runs out is told
`No accepted shares`, which is deliberately not one of the four strings xmrig
treats as critical, and then closed.

The deadline is carried out of the request handler, so nothing has to be
inferred from the answer's text: `Reply` gained an `accepted_share` flag that
only the final `OK` of a verified share sets, and every rejection path returns
`Reply::open`. A second login does not restart the clock either, because a
login line is as cheap to repeat as a newline and that is exactly the hole this
rule closes.

**The deadline is configuration, and its default is derived.**
`--stratum-share-timeout` sets both windows; left alone they are 600 seconds,
rising with `--stratum-share-difficulty` at twelve expected share intervals for
a rig of 100 H/s and capped at 7200. A deadline fixed in seconds is a bet on the
rig's hash rate. It is computed from the configured share difficulty, and a
job's share difficulty is that value clamped down to the block difficulty, so
the estimate is never shorter than the time a share actually takes to find: a
chain at the difficulty floor hands out shares far easier than the configuration
asks for and the deadline stays sized for the harder one. At the default share
difficulty of 5000 a 900 H/s box finds a share every six seconds, so the window
is a hundred expected shares wide, and it also covers the minute a full-mode rig
spends building its dataset after login.

### The tests

`a_logged_in_session_that_never_submits_a_share_is_closed` is the regression
test, and it runs the case three times: a peer that sends nothing, one that
sends a bare newline every half window, and one that sends a `keepalived` every
half window, with the node broadcasting a job every 100 ms underneath all three.
It replaces `a_session_that_goes_silent_is_dropped_even_while_jobs_are_pushed`,
which is its first shape. `a_session_whose_shares_are_all_rejected_is_closed`
covers the shape that reaches furthest into the endpoint: every submit carries a
fresh nonce, so every one of them is hashed on the blocking pool and refused as
low difficulty, and none of them counts.
`an_accepted_share_refreshes_the_deadline_and_a_stopped_rig_is_closed` is the
other direction, eight accepted shares a third of a window apart across three
deadlines with no disconnect, and then the same connection closed one window
after it stops producing.

All three were run against the rule they defend, removed. Putting the old
refresh back, so that any completed line stamps the clock, fails
`a_logged_in_session_that_never_submits_a_share_is_closed` on the newline shape
and fails `a_session_whose_shares_are_all_rejected_is_closed` outright:
`30 passed; 2 failed`. Dropping the accepted-share stamp instead fails
`an_accepted_share_refreshes_the_deadline_and_a_stopped_rig_is_closed` on its
third submit, with a broken pipe, the server having closed the connection at the
first deadline: `31 passed; 1 failed`. The silent shape passes under both
removals, which is why the newline and the `keepalived` are in the test beside
it.

### The run

The node was rebuilt once for this change, then `--dev --tmp --stratum-port
3350 --mining-threads 1` against xmrig 6.21.3 at `nice -n 19 --threads=2` for
two minutes. The deadline was set to `--stratum-share-timeout 20` on purpose:
at the 600-second default a two-minute session cannot tell a working rule from
a missing one, where at 20 seconds a rig whose accepted shares stopped
refreshing the clock would be disconnected six times over the run and every
reconnect writes its own login line.

```
⛏️ Stratum listening on 127.0.0.1:3350 (algo rx/0, share difficulty 5000, first share within 20s, a share every 20s after that)
⛏️ Miner 127.0.0.1:39048 logged in as "qnero-rig" ("XMRig/6.21.3 (Linux x86_64) libuv/1.48.0 gcc/13.2.1"), extra nonce 0x943bdbb6
🥇 Successfully mined and submitted a new block by stratum miner "qnero-rig" (mining time: 1s)
⛏️ Stratum so far: 455 shares accepted, 0 rejected, 455 at the block difficulty, 189 sealed, 266 too late
```

One login in the whole log and no second one, which is what says the session was
never closed and never retried. The first accepted share landed 3 seconds after
the login, xmrig's 2336 MB dataset build included, against a 20-second first
share window. 455 shares accepted, 0 rejected, 189 blocks sealed from the rig,
and the chain reached #197 at difficulty 325 from a genesis of 128. Both ends
were stopped by pidfile; port 3350 and the RPC port were closed afterwards and
no process survived.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p qnero-node --all-targets
cargo +nightly fmt --all -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

All green. The node crate is at 98 unit tests plus 5 integration tests, 32 of
the unit tests stratum protocol tests driven by a fake miner that speaks
xmrig's messages, and the root workspace is unchanged by this pass. The one
node rebuild took 10:01, cold for the runtime wasm and for rocksdb.

`cargo +nightly fmt` is the gate in the chain workspace, as before: its
`.rustfmt.toml` sets options only nightly honours, and stable `rustfmt` on a
file there rewrites match arms and binary operators that nightly leaves alone.

## The M11 preparation run: a two-node rehearsal of the public testnet, 2026-09-15

Everything the public testnet needs, built and exercised on this workstation
before a host exists: the `qnero-testnet` preset and the raw spec it exports,
a bootnode key and the multiaddr it produces, systemd units and an nginx set
for six hostnames, a deploy script, the faucet, a node probe, an on-box monitor
and the runbook at `docs/TESTNET.md`. The deploy itself is a separate phase.

### What the chain is

`--chain qnero-testnet`, or the committed raw spec at
`chain/node/chain-specs/qnero-testnet.json`. Name `Qnero Testnet`, id and
protocol id `qnero-testnet`, `ChainType::Live`, QNR at twelve decimals and
ss58 189.

Genesis is one endowed account and nothing else: the faucet, with 100 000 QNR
of transparent balance, which under v1 can go exactly one place, into the pool
through a `shield` it signs for itself. No vesting row, no mainnet placeholder,
no tech collective, no sudo, and no treasury. That last one widened
`TreasuryGenesis.account` to `Option<AccountId>`, which is a state the runtime
already supported: the pallet's genesis build returns early on `None`,
`TreasuryAccountOption` answers `None`, `EnsureTreasury` matches no origin, and
`pallet_vesting`'s admin calls refuse with `TreasuryNotConfigured`. Nothing in
the runtime calls the panicking `Pallet::account_id()`. What an empty collective
costs is named in the runbook: nobody can pass
`RootOrMemberForTechReferendaOrigin`, so there is no runtime upgrade by
referendum on this chain and the recovery for a runtime bug is a relaunch.

**The initial difficulty is 5 000, and it is the one number in the spec that
cannot be corrected afterwards.** Difficulty is expected hashes per block, and
the retarget's equilibrium is the divisor rather than the target:
`divisor = target * 10 / 12` is 100 000 ms at a 120 s target and the neutral
band is one to two divisors wide, so a chain settles between `100 * H` and
`200 * H`. The hash rate this chain is certain of is its own node's single
light-mode RandomX thread, 32.9 H/s from the M7 measurements, which puts that
band at 3 300 to 6 600 and its middle at one block every 152 seconds with no
retarget pressure at all.

Low on purpose, and the asymmetry is the argument. The Homestead retarget moves
by one 2048th of the difficulty per step, which works out as linear growth at
`H / 2048` per second upward and exponential decay with a time constant of
`100 * 2048` seconds downward: 57 hours per e-fold whatever the numbers are. A
difficulty above the available hash rate is days of a chain that looks dead; one
below it is hours of fast blocks that fix themselves. Inheriting
`QPoWInitialDifficulty`, 1 000 000 and sized for about 8 300 H/s, would have
been 8.4 hours to the first block on the node alone and about a week to
converge. There is no floor field to set beside it: `get_min_difficulty()` is a
hard-coded 128 and genesis only validates against it.

The seed epoch stays at 2 048 blocks with a lag of 64, both runtime constants a
spec cannot move. The open question is restated in the runbook rather than
closed here: the lag sits inside the 100-block reorg window, so a deep reorg
across an epoch boundary changes the seed under work already started. That
cannot split the chain, because the seed follows each candidate's own ancestry
rather than canonical height, and a lag of 128 would remove even the
disturbance, at the cost of a runtime upgrade.

### The faucet account

ML-DSA-87, minted with `qnero-faucet keygen`, which is
`TransparentKey::from_seed` over 32 bytes from the operating system and
therefore the same derivation as `Dilithium87Pair::from_seed`. Both variants of
`DilithiumSignatureScheme` hash to the same 32-byte account, so an SS58 literal
carries no trace of its scheme and no test can assert one. Provenance is a
procedure, and the procedure is that the node derives the address independently
before genesis is cut:

```
printf '%s%064d' "$(cat <seed>)" 0 > /tmp/seed64
chain/target/release/qnero-node key qnero --scheme standard --no-derivation --seed < /tmp/seed64
```

`from_seed` reads the first 32 bytes of what it is handed, so padding to the 64
that command wants derives the same pair. Both sides printed the same address.
The spec carries the address; the seed is in the operator's own store and
nowhere else.

### The spec is generated, and a test says so

`scripts/build-testnet-spec.sh` exports it in one step, with
`--disable-default-bootnode`, which is not optional: without it a spec naming no
bootnode gets a throwaway `/ip4/127.0.0.1` one injected into the file every
operator is handed. Two consecutive runs gave the same sha256, so the export is
deterministic.

`chain/node/tests/testnet_spec.rs` regenerates it with the binary Cargo built
for the test and compares every one of its 1 365 586 bytes, the megabyte of
runtime wasm included. A preset edit nobody re-exported fails there rather than
shipping a genesis the tree can no longer rebuild. `bootNodes` is the one field
a deployment writes into the file afterwards, and it sits outside genesis, so
when it is non-empty the test compares everything else and validates each
multiaddr's shape instead. A second test reads the four identifying fields off
the file rather than off a builder, and asserts `telemetryEndpoints` is absent
and that `:code` is large enough to be a real runtime rather than a
`SKIP_WASM_BUILD` stub.

### Two flags a copied runbook gets wrong

**`key generate-node-key` resolves a chain before it does anything.** Even with
`--file` given, and even though the resolved id is then unused, `KeySubcommand`
calls `load_spec(cmd.chain.unwrap_or(""))` first, and this tree refuses an empty
id by naming its chains. So `--chain` has to be passed to generate a node key.
`scripts/generate-bootnode-key.sh` does, and also captures the peer id from
**stderr**, which a naive `> file` loses.

**`--force-authoring` is what lets a new chain start at all.** Two gates pause
authoring without it and a seed node on a fresh network trips both: a node with
no peers does not author, and a node whose tip is older than `--max-tip-age`
does not author, which a genesis block whose timestamp is zero always is. The
first rehearsal start without it produced no blocks. With it, block 1 arrived.
The flag costs the guard itself, so the unit carries it with a comment saying to
remove it once the network has other authoring peers.

### The rehearsal

Two nodes on this box, both from the committed raw spec, genesis
`0x439dee7cb5609728e54aa60ef8bed2924196c4a3d837f2c8a7e64685df69d900`.

Node A, the seed: `--node-key-file`, `--port 30333`, `--validator
--force-authoring --mining-threads 1`, `--stratum-port 3333`, `--rpc-port 9944
--rpc-methods safe`, `--no-mdns --no-telemetry`, the miner key from
`QNERO_MINER_KEY` in the environment rather than argv. Node B, a plain full
node on 30334 and 9945, joining through
`/dns/localhost/tcp/30333/p2p/QmSewr5LQZ4yTZKZ3CvvEk4rAP3vo12LnaZwfXmxihw4CQ`,
which is the multiaddr the key script printed.

B had A as a peer 5 seconds after start, and imported every block A produced
within a second of it:

```
# node A
2026-09-15 12:03:03 🥇 Successfully mined and submitted a new block in process (mining time: 199s)
2026-09-15 12:03:03 🏆 Imported #1 (0x439d…d900 → 0x2db2…c9a3)
2026-09-15 12:03:09 🥇 Successfully mined and submitted a new block in process (mining time: 5s)
2026-09-15 12:03:09 🏆 Imported #2 (0x2db2…c9a3 → 0xd5bb…bddb)

# node B, the same two blocks
2026-09-15 12:03:04 🏆 Imported #1 (0x439d…d900 → 0x2db2…c9a3)
2026-09-15 12:03:09 🏆 Imported #2 (0x2db2…c9a3 → 0xd5bb…bddb)
```

Block 1 took **199 seconds** on one in-process light-mode thread at difficulty
5 000. The expectation at 32.9 H/s is 152 seconds and block times are
exponentially distributed, so 199 is an ordinary draw; block 2 took 5 seconds,
which is the other tail of the same distribution. Both are inside the neutral
band the difficulty was chosen for, which is what the spec's 5 000 was meant to
produce and is the whole reason the number is not 1 000 000.

`scripts/probe-node.sh` against both nodes:

```
peers                  1
isSyncing              false
height                 55
genesis                0x439dee7cb5609728e54aa60ef8bed2924196c4a3d837f2c8a7e64685df69d900
target block time      120000 ms
stratum                127.0.0.1:3333 open

all checks passed
```

The target block time line is the probe decoding the little-endian SCALE `u64`
that `state_call` of `QPoWApi_get_target_block_time` returns, which is how a
client reads the interval a chain actually retargets against. Run against a
deliberately wrong genesis and a height floor of 999 999, it failed both checks
by name and exited 1, so the failure path is exercised rather than assumed.

**The stratum port.** xmrig 6.21.3 at `nice -n 19 --threads=2` against A:
**54 shares accepted, 0 rejected, 53 at the block difficulty, 52 sealed, 1 too
late.** Every share at the block difficulty is what a share difficulty of 5 000
clamped to a block difficulty of about 5 000 means. Over one measured window,
10 shares in 71 seconds at a block difficulty near 5 090, which is about
**717 H/s** for the rig while a node was mining beside it and the faucet was
proving. The difficulty climbed from 5 000 to 5 106 across 55 blocks, which is
+2.1% over 55 steps against the +1/2048 per block the retarget applies below
the target: the arithmetic in the preset's doc comment, observed.

**The faucet**, pointed at A:

```
faucet      transparent account qzjpnqS6zVnCLeXgqAPn85dquWQNbSVr3ba54YivjzdYLKieZ
faucet      circuits built in 4.74s (6 leaf slots per batch)
faucet      listening on 127.0.0.1:8080
faucet      shielding 50000 quanta from the genesis account (note 1 of 2)
faucet      funded: leaf 15 in block 16
faucet      ready, 50000 quanta spendable across 1 note(s)
```

The circuit build is 4.74 s, once, before the listener opens. Funding is a
`shield` of the genesis endowment into the faucet's own notes, which is the only
way to fund a faucet on this chain: there is no transparent transfer between
accounts, and `Wallet::shield` always builds the note for `self.key.pk()`.

A drip to a wallet created seconds earlier:

```
POST /drip  -> {"status":"queued","id":1,"amountQuanta":1000,"amountQnr":"10"}
faucet      drip 1000 quanta plus 8 fee, proved in 11.18s, block 21
faucet      claim 1 settled in block 21 after 15.81s
GET /drip/1 -> {"status":"sent","includedAt":21}
```

11.18 s of proving, and the whole claim settled 15.81 s after it left the queue.
That is the shape the endpoint is built around: `POST /drip` answers `queued`
and the page polls, because holding a request open across a proof and a block
would be a two-minute socket per claim in front of a server that proves one at a
time.

The recipient wallet, synced against **node B** rather than the miner:

```
scanned leaves 0..25 at block 22
received 1 note(s) worth 1000 quanta
unspent total 1000 quanta

      leaf        quanta    block    state  memo
        22          1000       21  unspent  qnero testnet faucet
```

A second claim for the same address from a different client was refused
`429 address-cooldown` with `retry-after: 86353` and the message "this address
has already been paid. It can claim again in 23 hours"; a malformed address was
refused `400` with nothing read and nothing written. The faucet's `/status`
afterwards read `balanceQuanta: 48992`, `paidQuanta: 1000`, one note, which is
the 500 QNR it shielded less the 10 QNR drip and its 0.08 QNR fee, held in the
change note.

**Stopping.** Everything was started with a pidfile and stopped by it, in
reverse order, with a 60-second wait before any SIGKILL because rocksdb has to
close cleanly. The faucet printed `stopping` and then `the worker's queue
closed, stopping`, which is the graceful path through the channel close and the
thread join. Afterwards no `qnero-node`, `qnero-faucet` or `xmrig` process
remained and all eight ports (9944, 9945, 30333, 30334, 3333, 8080, 9615, 9616)
were closed.

### What the rehearsal did not cover

It ran on one machine with `localhost` in the multiaddr, so it did not test DNS
resolution, the CDN, nginx, TLS, the cross-origin isolation headers Qloak needs,
or a rig on a second machine. Those are the verify section of
`docs/TESTNET.md`, and they belong to the deploy phase.

### Gates

```
# the chain workspace
SKIP_WASM_BUILD=1 nice -n 19 cargo test -j 4 -p qnero-runtime --release --lib genesis_config_presets
LIBCLANG_PATH=/usr/lib/llvm-18/lib RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 4 -p qnero-node --release
SKIP_WASM_BUILD=1 nice -n 19 cargo clippy -j 4 -p qnero-node -p qnero-runtime --all-targets
cargo +nightly fmt --all -- --check

# the repository root
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
nice -n 19 cargo clippy -j 2 --workspace --all-targets
cargo fmt --all -- --check
```

The node line runs **without** `SKIP_WASM_BUILD` on purpose: both the rename
guard and the new spec reproducibility test build a preset spec and therefore
need `WASM_BINARY`, and with the variable set they skip themselves and say so on
stderr, which is most of the guard silently not running.

## The M11 fix pass: a review, twelve fixes and a second rehearsal, 2026-09-15

A review of the preparation run above returned eighteen findings, several of
them the same defect seen twice. Twelve distinct ones were applied and one was
left open with a reason. What the fix pass is worth saying anything about is
this: three of the twelve are code that reads correctly, passed its tests, and
did not work. Two rehearsals are what separates that group from the rest.

### The on-box monitor was decorative in two places

**The operator's env file was sourced after every default had been resolved.**
`DOMAIN="${MONITOR_DOMAIN:-<domain>}"` and the five settings derived from it
were expanded above the `. "$ENV_FILE"` line, so setting `MONITOR_DOMAIN` did
nothing: the TLS check asked curl for the literal host `wallet.<domain>`, got
000 on the first tick and every tick after, and `MONITOR_SSL_DIR` pointed at a
directory with no certificate in it, so the expiry of a fifteen-year origin
certificate that nothing else watches was never checked at all. The source now
runs directly after `ENV_FILE` is computed and above the defaults, and a
placeholder is refused rather than probed:

```
$ monitor.sh                 # with an unedited ~/.monitor.env
MONITOR_DOMAIN is still the placeholder (<domain>). Set it in ~/.monitor.env
$ echo $?
2
```

**A resolve never cleared the last key.** `grep -vxF "$key" "$ALERT_STATE" >
new && mv new "$ALERT_STATE"` looks like a rewrite and is a conditional one:
grep exits 1 when it matches nothing, which is exactly the case where the key
being resolved was the only one in the file, so the `&&` never fired and the
key stayed. Since `alert()` begins with `is_alerting "$key" && return`, the
first check to ever recover became permanently silent. Driven through the
script's own functions, before and after:

```
tick 1  nginx down    (debounced, silent)
tick 2  nginx down    red   "nginx is not active"
tick 3  nginx up      green "nginx is running again"
tick 4  nginx up      (silent)
tick 5  nginx up      (silent)
        alert state:  empty
tick 6  nginx down    (debounced, silent)
tick 7  nginx down    red   "nginx is not active"
```

Before the fix, ticks 3, 4 and 5 each sent the green message and ticks 6 to 8
sent nothing at all, which is the nine-hour nginx outage this file exists to
catch, silently.

### The faucet had no heartbeat, and no way out of a failed top-up

`last_seen_node` was written only by `sync()`, and `sync()` ran at startup,
during funding and after a job. `/health` reports the node stale after six
minutes. So a faucet that served nobody overnight, which is the ordinary state
of a new testnet at four in the morning, answered 503 with `nodeFresh:false`
while the node was fine, and both monitoring layers paged for it. The same
absence wedged the faucet in a second way: a top-up was retried only after a
drip, and a balance under the floor refuses every claim before it enqueues
anything, so one failed shield meant no job, which meant no retry, which meant
a faucet that stayed dead until a human restarted the unit.

The worker now waits with a deadline instead of blocking on the channel, and
one tick a minute refreshes the balance and retries a top-up that is still
needed. Measured on the rehearsal chain, 430 seconds after the last claim and
so well past the 360-second window:

```
GET /health -> 200
{"balanceQuanta":47984,"chainHead":87,"funded":true,"nodeFresh":true,"ready":true,"status":"ok"}
```

The chain head was 35 when the last claim settled and 87 at that probe, with no
claim in between, which is the tick calling `sync` with nothing else to do.

### One lock hold, and one spelling of an address

Two defects in `POST /drip`, both about the ledger:

- **The two rate-limit reads and the row insert took the mutex separately, with a Turnstile
  await between them.** Every concurrent claim read a ledger none of them had written to yet.
  With Turnstile enabled, which is what a public faucet runs, that gap is a round trip to
  Cloudflare, and N tokens fired together are N drips for one address.
- **The cooldown was keyed on the requester's own string.** bech32m lowercases the
  human-readable part and maps `A-Z` onto the same values as `a-z`, so `QN1...` decodes to
  the same account as `qn1...`, while a `TEXT` column with binary collation sees two
  recipients. The first rehearsal paid that address twice.

The limits are now read and the row written under one lock hold, with the
cheap pre-check left in front of Turnstile so an already-refused claim still
costs no outbound request, and the ledger is keyed on `recipient.encode()`.
Live, against the rehearsal chain: the shouted spelling of an address that had
just been paid was refused `429 address-cooldown` with `retry-after: 86400`
from a different client, and eight simultaneous claims for one fresh address
from eight clients produced exactly one 202, seven 429s and two rows in the
whole ledger.

### The public RPC had no per-caller bound

The vhost's comment said the node's rate limit counted per caller because the
node was started with `--rpc-rate-limit-trust-proxy-headers`. Neither half was
true. `--rpc-rate-limit` is "calls/minute for each connection" in the node's
own help and the limiting middleware is built per accepted connection, and in
`sc-rpc-server` the proxy address decides one thing only, whether a caller
falls inside `--rpc-rate-limit-whitelisted-ips` and is therefore exempt. No
whitelist was set, so the flag was inert. One client with 200 sockets would
have taken every connection slot the node has and 200 times the call budget,
while both wallets were refused at connect.

The inert flag is gone from the unit, both comments now say what the limit
actually counts, and the bound is where it can exist: `limit_conn rpc_conn 8`
and a `limit_req` in the rpc vhost, with the zones beside the faucet's in
`00-qnero-common.conf`. The whole six-vhost set was then checked against a real
nginx 1.24, the host's version, with a self-signed certificate and the
placeholders filled: `syntax is ok`, `test is successful`.

### The scripts and the runbook

- **`generate-bootnode-key.sh` swallowed every failure.** `2>&1 >/dev/null | tr` folded the
  node's diagnostics into the substitution that captures the peer id, and `set -e` aborted
  before the assignment, so an unwritable `/etc/qnero` was exit 1 with zero bytes on both
  streams, on the first command of a deployment. Diagnostics now go to a temp file and are
  printed on failure. Three paths were exercised: an unwritable directory, an existing key
  that is not hex, and the ordinary generation, which also confirmed the peer id from
  `generate-node-key` on stderr and from `inspect-node-key` on stdout are the same string.
- **The rollback depended on a copy nothing took.** `docs/TESTNET.md` told the operator to
  keep `/usr/local/bin/qnero-node.previous` "before deploying", and the prescribed path is
  `deploy-testnet.sh`, which did not. The node stage now copies both binaries to `.previous`
  before installing and prints where they are, and the runbook's rollback uses them.
- **The static stages could not write.** The webroots are root-owned and the three `rsync`
  calls ran as the deploy account, so a first deploy would have installed the binaries and
  the spec and had every static asset refused. Each tree is now staged under the deploy
  account's own `/tmp` and moved in with one `sudo rsync`, excludes applied to both hops so
  `--delete` cannot remove the `config.json` the first hop was careful not to copy.
- **The nginx step would have failed on the distro default site.** Ubuntu 24.04 ships
  `sites-enabled/default` with `listen 80 default_server`, and so does `qnero-10-default`.
  Reproduced against real nginx: `[emerg] a duplicate default server for 0.0.0.0:80`, and
  because of the `&&` the reload never runs and the operator is left mid-step. The runbook
  removes it, with the reason.
- **The node key was left root-owned while the unit runs as `qnero`.** Section 5 now runs the
  generator under sudo, creates the service user if it is missing and chowns the key, and
  section 6 has a three-line ownership checklist for the files a reinstall can drop.
- **The pre-genesis seed confirmation wrote `/tmp/seed64` under the invoking umask.** It is
  `(umask 077; ...)` now, in the runbook and in `faucet/README.md`, because 0644 for the
  second between writing the key to the whole genesis endowment and shredding it is a leak
  with no recovery: the address is in genesis.

### What the second rehearsal found that the review did not

The worker's new wait panicked on its first idle minute:

```
thread 'qnero-faucet-wallet' panicked at faucet/src/worker.rs:369:41:
there is no reactor running, must be called from the context of a Tokio 1.x runtime
```

`tokio::time::timeout` builds its `Sleep` when the future is **constructed**
rather than at the first poll, so `block_on(timeout(TICK, jobs.recv()))` builds
the timer on a plain `std::thread` with no runtime entered. Wrapping it in an
`async` block, which is what puts the construction inside the runtime's
context, is the whole difference. Funding had already succeeded and the
listener was already up, so the faucet answered `/status` normally with a dead
worker behind it: the failure a test suite that never starts a worker cannot
see, and a rehearsal sees in under a minute. `worker.rs` carries the shape as a
test now.

### The second rehearsal

Same shape as the first: two nodes from the committed raw spec, genesis
`0x439dee7cb5609728e54aa60ef8bed2924196c4a3d837f2c8a7e64685df69d900`, node A
the seed with `--node-key-file`, `--mining-threads 1` and the stratum port,
node B a plain full node on 30334 dialing
`/dns/localhost/tcp/30333/p2p/QmTALAUeWs3iEzgK1yB6BUCCDtdUjnjBcdFG576ut7VhP8`.

Block 1 was mined 8 seconds after start this time, against 199 seconds in the
first rehearsal, which is the same exponential distribution at difficulty 5 000
seen from its other tail. B had A as a peer within 8 seconds of its own start
and imported block 1 one second after A produced it. xmrig 6.21.3 at
`nice -n 19 --threads=2` was attached to the stratum port and sealed blocks
from then on.

`scripts/probe-node.sh` against both nodes, with the genesis pinned and a height
floor of 5:

```
# node A                          # node B
peers                  1          peers                  1
isSyncing              false      isSyncing              false
height                 34         height                 34
advancing              yes, from 0 to 34
genesis                0x439d…d900
target block time      120000 ms  target block time      120000 ms
stratum                open       stratum                open

all checks passed                 all checks passed
```

The faucet, pointed at A: transparent account
`qzjpnqS6zVnCLeXgqAPn85dquWQNbSVr3ba54YivjzdYLKieZ`, circuits built in 6.06 s,
funded by shielding 500 QNR of the genesis endowment into leaf 12 in
block 13. A drip to a wallet created seconds earlier proved in 21.70 s and
settled in block 31, 31.94 s after it left the queue. The recipient wallet,
synced against **node B** rather than the miner, found exactly one note:

```
scanned leaves 0..35 at block 32
received 1 note(s) worth 1000 quanta
unspent total 1000 quanta

      leaf        quanta    block    state  memo
        32          1000       31  unspent  qnero testnet faucet
```

Exactly one, which is the point: in the first rehearsal the same address
claimed twice by shouting its own address back at the faucet.

Stopping, in reverse order, each by its pidfile with a 60-second wait before any
SIGKILL: xmrig, the faucet, node B, node A. All four stopped on SIGTERM within
two seconds. The faucet's last three lines are the graceful path and also the
new tick's error handling, since node A had gone first:

```
faucet      sync failed: ... Connection refused (os error 111)
faucet      stopping
faucet      the worker's queue closed, stopping
```

A tick that cannot reach the node logs and returns, which is what leaves
`/health` to report the staleness rather than the worker dying of it.
Afterwards no `qnero-node`, `qnero-faucet` or `xmrig` process remained and all
eight ports (9944, 9945, 30333, 30334, 3333, 8080, 9615, 9616) were closed.

### Gates

```
# the repository root
cargo fmt --all -- --check                                        0
nice -n 19 cargo clippy -j 2 --workspace --all-targets            0, no warnings
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
                                                                  30 binaries, 0 failed
nice -n 19 cargo test -j 2 --release -p qnero-faucet              28 + 12 passed

# the chain workspace, which this pass does not touch
cargo +nightly fmt --all -- --check                               0

# the web properties
explorer: lint, typecheck, test, build                            0
wallet-web: lint, typecheck, test                                 0
site: node site/tools/check-links.mjs                             no broken links

# the nginx set, against the host's own version
nginx -t (nginx/1.24.0, six vhosts, placeholders filled)          test is successful
```

One review finding was left open rather than fixed: two wall-clock stratum
tests (`chain/node/src/stratum/tests.rs:864` and `:897`) flake under a loaded
parallel `cargo test`, because they drive 250 ms intervals against 1 000 ms and
1 500 ms deadlines. It is real and it is pre-existing: M11 touches nothing in
`chain/node/src/stratum`, and the fix is to drive those two on paused tokio
time rather than on the wall clock, which is a change to a subsystem this
milestone has no other reason to rebuild.

## The M11 third pass: a page that could never connect, limits that counted the CDN, and a third rehearsal, 2026-09-15

A second review of the preparation returned eleven findings. Ten were applied
and one was folded into another. The shape of this pass is worth naming,
because it is the same shape as the last one: the three most expensive findings
are all configuration that parses, tests green and does nothing, and each of
them fails by blaming a component that is healthy.

### The explorer's policy refused the one thing the explorer needs

`packaging/nginx/40-explorer.conf` shipped `default-src 'self'` with no
`script-src` at all, so a browser refuses `WebAssembly.instantiate`. What
follows from that is the whole finding. `@polkadot/api` awaits
`cryptoWaitReady()` when its provider connects, `@polkadot/wasm-crypto-init`
resolves to the wasm-only builder in a browser with no asm.js fallback, and
`cryptoWaitReady()` resolves **false** rather than throwing. In
`ApiPromise`'s connect handler that false is `cryptoReady`, and `_isReady` is
set only when it is true, so `ready` is never emitted, the `ApiPromise.create`
in `explorer/src/chain/api.ts` never settles, and after fifteen seconds the page
says the node did not answer. silQ Road would have shipped as a page that can
never connect to any chain on any browser, and the message it prints sends
whoever reads it to debug a node that is fine.

Nothing caught it, and the reason each layer did not is the useful part.
`nginx -t` reads syntax. The built `index.html` carries no `<meta>` policy, so a
local `vite preview` has no policy at all. A root-URL probe answers 200 whether
the page works or not. So the fix is three things rather than one:

- The policy gains `script-src 'self' 'wasm-unsafe-eval'`, in both copies in the vhost, in
  `explorer/README.md`, and as the shape the external watchdog asserts.
- `vite.config.ts` now serves `vite preview` under that same policy, with only `connect-src`
  differing because the suite talks to a dev node on loopback. The Playwright suite runs
  against `vite preview`, so from here it runs under the real policy.
- `explorer/tests/csp.test.ts` asserts every copy of the policy the repository ships carries
  the directive, which is a check that runs inside the ordinary `npm test` gate.

Both directions were measured. Under the shipped policy the full Playwright
suite passes, ten of ten. With `'wasm-unsafe-eval'` removed from the preview
header and nothing else changed, the first test fails at the status strip:

```
- unexpected value "connectingws://127.0.0.1:9944theme: system"
- unexpected value "connection failedws://127.0.0.1:9944ws://127.0.0.1:9944 did not answer
  in 15 seconds. The node may be down, or this page may be configured with the wrong
  endpoint.theme: system"
```

The node was answering throughout. That sentence is what an operator would have
been given to work from.

### Three rate limits that counted the CDN instead of the caller

`00-qnero-common.conf` enabled `real_ip_header CF-Connecting-IP` with every
`set_real_ip_from` line commented out. The realip module is inert without a
trusted-proxy list, so `$remote_addr` stays the CDN's edge address on every
proxied name and all three limit zones key on a handful of addresses. The
faucet cost was written down in the runbook. The RPC cost was not, and it is
worse: `limit_conn rpc_conn` was a cap on the number of WebSockets the entire
internet could hold open at once, so past that number every wallet and explorer
tab in the world is answered 429 while the node sits idle. An operator testing
from one machine sees nothing wrong, which is the property that makes this kind
of finding expensive.

Measured here on nginx 1.24.0 with the shipped files, a slow upstream and
`limit_conn rpc_conn 2`:

```
four concurrent callers, four distinct /64s, with the trusted-proxy list:      200 200 200 200
the same four callers with the list removed:                                   429 429 200 200
```

Filling the list in was an instruction in the runbook, placed after the
`nginx -t && systemctl reload nginx` line that ends the section's command
block. An operator working top to bottom reloads first and reads second. So the
list is no longer an instruction:

```nginx
include /etc/nginx/qnero-real-ip.conf;
```

A missing file fails `nginx -t` with the path in the message, which is a far
better failure than a limit that silently became global.
`scripts/fetch-real-ip-ranges.sh` writes that file from the CDN's published
lists, refuses to write a suspiciously short one, and accepts `file://` URLs for
a host that fetches its copy from somewhere else.

### An IPv6 /64 is one client, in both places that count one

Both the nginx zones and the faucet's ledger keyed on the whole address, and an
ordinary residential or cloud client is handed a /64. That is 2^64 keys for one
requester, so the documented three-claims-per-client bound cost nothing to
defeat, and the recipient side is no help either, since `qn1` addresses are
minted locally for free. What was left bounding a drain was the prover at one
drip at a time, which empties the endowment in about three days.

nginx now derives a `$limit_key` that groups IPv6 to its /64, and
`store::client_key` does the same before the ledger hashes a client. The nginx
map is three expressions because nginx writes IPv6 compressed and the /64 can
only be read off the text when four groups are written out; the other two
expressions key on the text before the zero run, which is always a prefix of
the network part, so they group wider than a /64 and never narrower. Measured
against the running server:

```
203.0.113.7                 -> 203.0.113.7
2001:db8:1:2:3:4:5:6        -> 2001:db8:1:2
2001:db8:1:2::9             -> 2001:db8:1:2      the same key, which is the point
2a02:1234:5678:9abc::1      -> 2a02:1234:5678:9abc
2001:db8::1                 -> 2001:db8          wider, because the /64 is not in the text
::ffff:203.0.113.9          -> 203.0.113.9
::1                         -> (empty, and nginx does not count an empty key)
```

Grouping is not a defence on its own, and the faucet now says so by refusing to
start. `serve` stops with the reason when `QNERO_FAUCET_TURNSTILE_SECRET` is
empty unless `QNERO_FAUCET_ALLOW_NO_CAPTCHA=1` is set, so a first launch cannot
quietly be a public faucet with no challenge.

### The monitor's env file was not valid shell

`MONITOR_DOMAIN=<domain>` is an assignment followed by two redirection
operators. Bash reports a syntax error and stops reading the file at that line,
and `[ -f "$ENV_FILE" ] && . "$ENV_FILE"` never looked at the result. So an
operator who filled in the domain and the genesis hash and left one shipped line
alone lost every setting below it, including `MONITOR_EXPECT_GENESIS`, and the
genesis check is gated on that variable being non-empty. It was skipped with no
message at all: the one check that catches a node which lost its database and
resynced from the spec, silently absent, on the deployment whose empty-tree case
it exists to catch.

Both halves are fixed. The template quotes its placeholders and derives
`MONITOR_SSL_DIR` from `MONITOR_DOMAIN` so there is no second place to forget,
and the script exits 2 when the source fails. Against the rehearsal node:

```
correct genesis   no genesis alert
wrong genesis     red  "the node serves genesis 0x439dee7c...d900 and this deployment is 0xdeadbeef"
one unquoted placeholder left in the file:
                  broken.env: line 33: syntax error near unexpected token `newline'
                  broken.env could not be sourced. It is shell: a value
                  containing < or > has to be quoted, and everything after the failing
                  line never reached this script.
                  exit 2
```

### A drip that could be paid twice

The claim row is written before the proof and cleared by `mark_sent` after
`Wallet::send` returns. A process that dies in between leaves a row that still
says `queued` and a payment that may already be in a block, and
`recover_queued_claims` re-queued exactly that row at the next start. One crash,
two payments to one address, one claim in the ledger and a `paidQuanta` that is
wrong. `Restart=always` makes that crash five seconds old, and `TimeoutStopSec`
expiring into a SIGKILL, or `MemoryMax` landing on a proof that peaks near a
gigabyte, are ordinary ways to get there.

The worker now marks the row immediately before the send, and a row that carries
that mark is failed as `interrupted` rather than re-queued. `interrupted` is
also the one failure that holds the address cooldown and the client's window,
because the faucet cannot tell a payment that landed from one that did not, and
paying twice is the worse of the two mistakes. The requester is told the claim
failed and that the address can claim again after the cooldown. Driven live in
the rehearsal below.

### The deploy script sent the operator to mint a second identity

After every spec copy, `deploy-testnet.sh` printed
`./scripts/generate-bootnode-key.sh /etc/qnero/node-key <domain>`, and the
runbook sent the operator to that message. Three things go wrong from following
it. It runs on the workstation, where `/etc/qnero/node-key` does not exist, so
the script takes its generate branch and, under the sudo the runbook has already
trained the operator to use, mints a brand new Dilithium identity into the
workstation's `/etc/qnero` and prints a peer id no running node has. It writes
nothing into the spec, so `bootNodes` stays empty. And the hostname is the
proxied apex rather than `node.<domain>`, which blackholes p2p. Each of the
three ends the same way: a published testnet nobody can join, with the symptom
appearing only when a second operator tries.

The script now prints the jq edit the runbook documents, run on the host and
naming the p2p hostname, and `generate-bootnode-key.sh` refuses an apex
hostname outright with `QNERO_ALLOW_APEX=1` for a zone that really is not
proxied. `localhost` and address literals still pass, which is what a rehearsal
on one workstation dials.

### Three smaller ones

**`sudo rsync -a` was chowning the webroots to the deploy account.** `-a`
implies `-o -g`, and running as root they take effect, so every file staged
under the deploy account landed in `/var/www` owned by it, along with the
webroot itself. The runbook said the opposite in as many words. Reproduced with
rsync 3.2.7, a root-owned destination and a file staged as an ordinary user:

```
sudo rsync -a --delete stage/ web/                    web/ and web/app.js both owned by the staging account
sudo rsync -a --delete --chown=root:root stage/ web/  both root root
```

**The staging path was fixed and in `/tmp`.** `/tmp/qnero-deploy/var/www/...`
is predictable and world-writable ground, and the second hop reads it as root.
It is an `mktemp -d` on the host now.

**`/tmp/seed64` in two documents.** `umask 077` sets the mode of a file the
command creates and does nothing about a file or a symlink already sitting at a
fixed path, and what goes through that file is the key to the entire genesis
endowment. Both copies use `mktemp`.

### The third rehearsal

Same shape as the previous two, from the committed raw spec, genesis
`0x439dee7cb5609728e54aa60ef8bed2924196c4a3d837f2c8a7e64685df69d900`. Node A is
the seed with `--node-key-file`, `--mining-threads 1` and the stratum port on
30333/3333/9944; node B is a plain full node on 30334/9945 dialing
`/dns/localhost/tcp/30333/p2p/QmSvDLagG23qX2yALD9aWWhVxaz5oEE1r2PamWWGTCEpaK`,
which is the multiaddr `generate-bootnode-key.sh` printed, through its new
hostname guard's `localhost` exemption.

B had A as a peer 5 seconds after its own start, at the same genesis. Block 1
arrived 75 seconds after A started and B imported it 3 seconds later. xmrig
6.21.3 at `nice -n 19 --threads=2` sealed every one of the 45 blocks the run
produced, and the difficulty climbed from 5 000 to 5 086 while it ran.
`scripts/probe-node.sh` against both, genesis pinned and a height floor of 5:

```
# node A                             # node B
peers                  1             peers                  1
isSyncing              false         isSyncing              false
height                 36            height                 36
genesis                0x439d…d900   genesis                0x439d…d900
target block time      120000 ms     target block time      120000 ms
stratum                open          stratum                open

all checks passed                    all checks passed
```

**The faucet refused to start first**, which is the new precondition working:

```
Error: QNERO_FAUCET_TURNSTILE_SECRET is empty, so every claim would be answered with no
challenge at all. The address cooldown bounds nobody, since addresses are free to mint,
and the per-client limit counts an IPv6 /64, which a client with several prefixes simply
rotates. Set the Turnstile pair, or set QNERO_FAUCET_ALLOW_NO_CAPTCHA=1 to say
deliberately that this faucet does not need one
```

With the override set it started, built its circuits in 6.20 s before the
listener opened, and funded itself by shielding 500 QNR of the genesis
endowment into leaf 6 in block 7. A drip to a wallet created seconds earlier
proved in 14.86 s and settled in block 13, 19.01 s after it left the queue. The
recipient wallet, synced against **node B** rather than the miner:

```
scanned leaves 0..16 at block 13
received 1 note(s) worth 1000 quanta
unspent total 1000 quanta

      leaf        quanta    block    state  memo
        13          1000       13  unspent  qnero testnet faucet
```

**The per-client limit, live.** Five claims to five fresh addresses, four of
them from one /64:

```
2001:db8:aa:bb:1:2:3:4                 202 queued
2001:db8:aa:bb::99                     202 queued
2001:db8:aa:bb:ffff:ffff:ffff:ffff     202 queued
2001:db8:aa:bb:dead:beef:dead:beef     429 client-limit
2001:db8:aa:cc::1                      202 queued
```

Three addresses inside one /64 spend that /64's allowance and the fourth is
refused, while a different /64 is a different client. Before this pass all five
were different clients and the limit bounded nothing.

**The interrupted drip, live.** A claim was submitted and the faucet was killed
with SIGKILL five seconds later, mid-proof and past the submission mark, which
is the `MemoryMax` and `TimeoutStopSec` shape. On restart:

```
faucet      claim 6 was interrupted mid-drip and is NOT being paid again. Its payment may
            have settled; check qn1qxxfd7af... before refunding it by hand.

GET /drip/6 -> {"status":"failed","reason":"interrupted","includedAt":null,...}
POST /drip  -> 429 address-cooldown
               "this address has already been paid. It can claim again in 23 hours"

/status     -> paidQuanta 5000, balance 44960     unchanged by the interrupted claim
```

That address held 0 notes afterwards, so this particular drip really had not
settled, and the requester waits out the cooldown for a payment nobody made.
That is the cost of the decision and it is the right way round: the faucet
cannot tell the two cases apart, and the other way round pays twice.

Stopping, in reverse order, each by its pidfile: xmrig, the faucet, node B, node
A. All four stopped on SIGTERM, the faucet through its graceful path
(`stopping`, then `the worker's queue closed, stopping`). Afterwards no
`qnero-node`, `qnero-faucet` or `xmrig` process remained and all eight ports
(9944, 9945, 30333, 30334, 3333, 8080, 9615, 9616) were closed.

### Gates

```
# the repository root
cargo fmt --all -- --check                                        0
nice -n 19 cargo clippy -j 2 --workspace --all-targets            0, no warnings
RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --workspace --release
                                                                  40 binaries, 0 failed
nice -n 19 cargo test -j 2 --release -p qnero-faucet              30 + 14 passed

# the chain workspace, which this pass does not touch
cargo +nightly fmt --all -- --check                               0

# the web properties
explorer: lint, typecheck, test, build                            0, 104 unit tests
explorer: npm run e2e (Playwright, under the shipped policy)      10 passed
wallet-web: lint, typecheck, test                                 0
site: node site/tools/check-links.mjs                             no broken links

# the nginx set, against the host's own version
nginx -t (nginx/1.24.0, seven files, placeholders filled)         test is successful
nginx -t with the real-ip include missing                         fails, and names the file
```

The stratum test flake noted at the end of the previous pass is still open and
still pre-existing. This pass touches nothing in `chain/node/src/stratum`.
