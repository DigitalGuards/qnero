# `qnero-pqcrypto`: Post-Quantum Primitive Crate

This crate hosts SLH-DSA signatures, ML-KEM encryption, note encryption, and hash/commitment
utilities. What they are and why they were chosen is `docs/DESIGN.md` section 1 and the primitive
mapping in section 2; the API itself is the crate's own rustdoc (`cargo doc -p qnero-pqcrypto
--open`). It is consumed by `qnero-notes` and `qnero-wallet`, and through `qnero-notes` by the
prover crates.

Transparent spend authorization lives in `chain/`. Qnero signs a transparent extrinsic with
ML-DSA-87 through `qp-dilithium-crypto`, and `chain/runtime/src/extrinsic.rs` is the consensus rule
that admits exactly that scheme. The level-3 ML-DSA module this crate carried was unused by anything
in the workspace and was dropped with that rule; see `CHANGES.md`.

## Quickstart

```bash
cargo fmt -p qnero-pqcrypto
cargo clippy -p qnero-pqcrypto --all-targets --all-features
cargo test -p qnero-pqcrypto
```

Use the deterministic RNG helpers in `src/deterministic.rs` for reproducible tests and benches.

## Doc Sync

When adding or changing APIs here:

1. Update the rustdoc on the item itself. That is the API reference; there is no second copy of it
   to drift.
2. Update `docs/DESIGN.md` section 1 if the change affects PQ assumptions or serialization, and the
   section 2 mapping table if a primitive moves.
3. Update `CHANGES.md` with what changed against the upstream crate this one was vendored from.
