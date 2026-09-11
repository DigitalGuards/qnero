# Changes from upstream

- Renamed package `synthetic-crypto` to `qnero-pqcrypto`.
- Dropped `examples/` and the workspace lints table.
- Tests import `qnero_pqcrypto` instead of `synthetic_crypto`.
- Lint fixes only, no behaviour change (2026-09-11): dropped three needless
  borrows in tests, and made the `ExpandedKeyEncoding` deprecation an explicit
  `#[allow(deprecated)]` with a note. Moving to `DecapsulationKey::from_seed`
  changes the stored secret-key encoding that the pinned vectors cover, so it
  needs its own change with regenerated vectors.
