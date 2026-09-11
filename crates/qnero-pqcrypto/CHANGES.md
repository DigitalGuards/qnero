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
