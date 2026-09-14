# Changes from upstream

- Renamed package `synthetic-crypto` to `qnero-pqcrypto`.
- Dropped `examples/` and the workspace lints table.
- Tests import the renamed crate as `qnero_pqcrypto`.
- Lint fixes only, no behaviour change (2026-09-11): dropped three needless
  borrows in tests, and made the `ExpandedKeyEncoding` deprecation an explicit
  `#[allow(deprecated)]` with a note. Moving to `DecapsulationKey::from_seed`
  changes the stored secret-key encoding that the pinned vectors cover, so it
  needs its own change with regenerated vectors.
- Redacting `Debug` on `note_encryption::NotePlaintext` and its private
  `NotePayload` (2026-09-11): both hold the note value, `rho`, `r` and, for the
  plaintext, the memo. The shield publishes `nf = H(NF, nk, rho, r)` on chain,
  so a log line carrying those values beside a settled nullifier links the
  nullifier to an amount and a recipient. `qnero_notes::Note` and
  `ReceivedNote` already redact them, and `NotePlaintext` is the value
  `decrypt_note` binds on the way to building both. The `asset_id` stays in the
  clear because it names the pool. Covered by
  `qnero-notes/tests/roundtrip.rs::note_plaintext_debug_does_not_leak_the_note`.
- Dropped the `ml_dsa` module, ML-DSA-65 (FIPS 204 level 3), and the `ml-dsa`
  dependency and its `std` feature entry with it (2026-09-14). Nothing in the
  workspace imported the module except its own vectors test, and Qnero has one
  signature scheme at the transparent entry, ML-DSA-87, admitted through
  `qp-dilithium-crypto` in `chain/`. The consensus rule that refuses every
  other variant is `chain/runtime/src/extrinsic.rs`. The `ml_dsa_pk`,
  `ml_dsa_sk` and `ml_dsa_sig` keys left `tests/vectors.json` with the test
  that read them; the ML-KEM, SLH-DSA and hash vectors are untouched.
