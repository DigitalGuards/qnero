# Qnero chain

This directory is the Qnero node and runtime: a Substrate chain with RandomX
proof of work, ML-DSA-87 accounts, and the shielded pool in `pallets/shielded`
where every unit of value minted after genesis lives as a note. It is its own
Cargo workspace with its own lock file; the wallet and the proof crates live in
the repository root workspace.

ML-DSA-87 is the only signature scheme the transparent entry admits, and the
runtime enforces it as a consensus rule: `runtime/src/extrinsic.rs`
refuses a signed extrinsic carrying the level-3 variant of the upstream
`DilithiumSignatureScheme` enum with `InvalidTransaction::BadSigner`, before
its signature is verified and before its call is dispatched. The enum keeps
both variants so the next subtree merge stays clean. `docs/DESIGN.md` section
7.3 in the repository root is the write-up.

The project README at the repository root is the place to start. This file
covers what is specific to building and running the node.

## Build

```
cd chain
cargo update -p kem --precise 0.3.0-pre.0
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
```

Three prerequisites are not optional on Linux: `LIBCLANG_PATH` (rocksdb runs
bindgen), and `cmake` with a C++17 compiler (the RandomX library is built by
its Rust bindings). On a Debian-family box, `sudo apt install cmake g++
libclang-dev`.

The binary lands at `target/release/qnero-node` and the runtime at
`target/release/wbuild/qnero-runtime/qnero_runtime.wasm`.

## Run a devnet

```
./target/release/qnero-node --dev --tmp \
  --rewards-miner-key "$QNERO_MINER_KEY" --rewards-inner-hash <hash>
```

`QNERO_MINER_KEY` comes from `qnero-wallet miner-address`: it is the key the
block reward is minted to, as a shielded note. A node without one refuses to
start. JSON-RPC listens on 127.0.0.1:9944.

## Mine

`MINING.md` in this directory explains the proof of work, the node's own
miner, and how to point a Monero rig running xmrig at the stratum port.

## Layout

| Path | What |
|---|---|
| `node/` | the `qnero-node` binary: CLI, service wiring, stratum server, coinbase inherent |
| `runtime/` | the `qnero-runtime` crate: pallets, call filter, difficulty and seed schedule |
| `pallets/shielded/` | the shielded pool: batch settlement, nullifiers, commitment tree, coinbase notes |
| `pallets/zk-tree/` | the 4-ary Poseidon commitment tree |
| `client/consensus/randomx/` | the RandomX engine: sealing, verification, seed rotation |
| `docs/` | operator runbooks (chain specs, runtime upgrades, release preflight) |

The repository's `docs/OPS-DEV.md` records what was renamed from upstream and
what stays as upstream so that future subtree merges remain possible.

## Licence

MIT. This directory is a fork of an upstream Substrate chain; its copyright
notice is preserved in `LICENSE` as the licence requires.
