# Qnero

Post-quantum private coin with Monero's policy (everything shielded), built on
the Quantus Network stack: ML-DSA-87 accounts, Plonky2 hash-based proving,
Poseidon Merkle commitment tree, nullifier set.

See `docs/DESIGN.md`.

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

The `circuit_parity` test pins the off-circuit Poseidon2 to Plonky2's
`Poseidon2Hash::hash_no_pad`, so wallet-side commitments equal what the spend
circuit will compute. `tests/vectors.json` is the consensus known-answer set.

```
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```
