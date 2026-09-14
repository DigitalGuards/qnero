# `crypto/`: Post-Quantum Primitive Crate

This crate (`qnero-pqcrypto`) hosts SLH-DSA signatures, ML-KEM encryption, and hash/commitment utilities described in `DESIGN.md §1` and the `docs/API_REFERENCE.md` entry. It is consumed by `consensus`, `wallet`, and the benchmarking binaries.

Transparent spend authorization lives in `chain/`. Qnero signs a transparent extrinsic with ML-DSA-87 through `qp-dilithium-crypto`, and `chain/runtime/src/extrinsic.rs` is the consensus rule that admits exactly that scheme. The level-3 ML-DSA module this crate carried was unused by anything in the workspace and was dropped with that rule; see `CHANGES.md`.

## Quickstart

```bash
cargo fmt -p synthetic-crypto
cargo clippy -p synthetic-crypto --all-targets --all-features
cargo test -p synthetic-crypto
```

Use the deterministic RNG helpers in `src/deterministic.rs` for reproducible tests and benches.

## Doc Sync

When adding or changing APIs here:

1. Update `docs/API_REFERENCE.md#crypto` with the new function signatures.
2. Update `DESIGN.md §1` if the change affects PQ assumptions or serialization.
3. Update `METHODS.md` with new operational/testing steps so CI coverage stays accurate.
