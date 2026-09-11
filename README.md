# Qnero

Post-quantum private coin with Monero's policy (everything shielded), built on
the Quantus Network stack: ML-DSA-87 accounts, Plonky2 hash-based proving,
Poseidon Merkle commitment tree, nullifier set.

See `docs/DESIGN.md` for the design and `docs/CIRCUIT.md` for the implemented
spend-circuit specification (public-input layout, tree leaf rule, constraints).

Reference checkouts (gitignored, clone locally):

```
git clone --depth 50 https://github.com/Quantus-Network/chain quantus-chain
git clone --depth 50 https://github.com/Quantus-Network/qp-zk-circuits qp-zk-circuits
git clone https://github.com/monero-project/monero monero
```

## Layout

| Crate | What | Origin |
|---|---|---|
| `crates/qnero-pqcrypto` | ML-KEM-1024, ML-DSA, SLH-DSA wrappers and ML-KEM + ChaCha20-Poly1305 note encryption | vendored from Hegemon `crypto/` (MIT), see its NOTICE |
| `crates/qnero-notes` | Spending key hierarchy, bech32m addresses, Poseidon2 note commitments and nullifiers, note scan | Qnero, hashes via `qp-poseidon-core` (Quantus) |
| `crates/qnero-circuit` | v0 spend leaf: 2 inputs, 2 outputs, 4-ary Merkle membership, balance; plus the off-circuit commitment tree | forked from `qp-zk-circuits` (MIT), see its NOTICE and CHANGES.md |
| `crates/qnero-prover` | Builds the leaf circuit from source and proves one spend; `WalletProver` is the wallet's path from notes to a submittable transaction | same fork |
| `crates/qnero-verifier` | Verifies the private and public batch proofs a runtime settles, and behind a non-default feature a leaf proof; depends on the plonky2 verifier only | same fork |
| `crates/qnero-aggregator` | The two recursive layers: the zero-knowledge private batch over N leaves, and the public batch over n private batches | forked from `qp-zk-circuits` (MIT), see its NOTICE and CHANGES.md |
| `crates/qnero-circuit-builder` | Writes the artifact set a pallet embeds and a wallet loads | same fork |

The `circuit_parity` test pins the off-circuit Poseidon2 to Plonky2's
`Poseidon2Hash::hash_no_pad`, so wallet-side commitments equal what the spend
circuit will compute. `tests/vectors.json` is the consensus known-answer set.

```
cargo test --workspace --release
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

Configurations the workspace gate does not reach, because `cargo test
--workspace` unifies features and always turns `qnero-circuit`'s defaults on:

```
cargo check -p qnero-circuit --no-default-features
cargo check -p qnero-verifier --no-default-features
cargo check -p qnero-verifier --no-default-features --target wasm32v1-none
cargo test -p qnero-prover --release --features zk
```

The first two are the layout-only and `no_std` builds the M4 runtime depends
on. The third is what actually proves the verifier's dependency graph links on
a bare-metal wasm target: the host `no_std` check covers only this workspace's
own code, so a dependency bump that pulls in std stays green on x86 and
surfaces when M4 builds the runtime. The fourth is the only run that exercises
plonky2 row blinding at the leaf, since the feature gate's own unit test passes
vacuously when the feature is off. The private batch blinds unconditionally, so
the workspace gate covers that half.

Plonky2's rayon support is off by default, so a prover stays single threaded
unless asked. Both configurations are measured in `docs/BENCH.md`:

```
RAYON_NUM_THREADS=4 cargo test -p qnero-aggregator --release --features parallel
```

Proving needs `--release`; a leaf takes minutes in a debug build and about
0.2 s in a release one, with a wide spread because the FRI grind dominates a
circuit this small (`docs/CIRCUIT.md` section 6). A 7-slot private batch takes
about 20 s single threaded and 6 s on four threads. Both sizes are reported by
ignored tests that prove several samples and report the mean:

```
cargo test -p qnero-prover --release -- --ignored --nocapture
RAYON_NUM_THREADS=4 cargo test -p qnero-aggregator --release --features parallel \
    --test bench -- --ignored --nocapture
```

The artifact set a pallet embeds is written by the builder:

```
cargo run -p qnero-circuit-builder --release -- --output generated-artifacts \
    --num-leaf-proofs 7 --num-private-batch-proofs 53
```

Both dimensions also read from `QNERO_NUM_LEAF_PROOFS` and
`QNERO_NUM_PRIVATE_BATCH_PROOFS`, which is how the M4 pallet's build script
will set them.
