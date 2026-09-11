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
| `crates/qnero-prover` | Builds the leaf circuit from source and proves one spend | same fork |
| `crates/qnero-verifier` | Verifies a leaf proof and reads its public inputs; depends on the plonky2 verifier only | same fork |

The `circuit_parity` test pins the off-circuit Poseidon2 to Plonky2's
`Poseidon2Hash::hash_no_pad`, so wallet-side commitments equal what the spend
circuit will compute. `tests/vectors.json` is the consensus known-answer set.

```
cargo test --workspace --release
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

Proving needs `--release`; a leaf takes minutes in a debug build and about a
third of a second in a release one. The leaf's size is reported by an ignored
test:

```
cargo test -p qnero-prover --release -- --ignored --nocapture
```
