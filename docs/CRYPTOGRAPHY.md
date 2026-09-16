# Cryptographic profile and qualification

Status: experimental testnet protocol. Qnero's exact circuit composition and
protocol have not received an independent cryptographic assessment. The runtime
mainnet preset is disabled while `EXPERIMENTAL_PROOF_SYSTEM` is true, in addition
to the allocation gate. Changing that flag requires a reviewed profile and any
resulting circuit migration. Custom chain specifications can bypass a preset;
the preset gate is a release safeguard, not a consensus proof of audit status.

## Implemented primitives

The two Cargo lockfiles pin `qp-plonky2`, its core, field and verifier to 1.5.5.
The exact verifier bytes and protocol dimensions are recorded in
[PROTOCOL-PROFILE.md](PROTOCOL-PROFILE.md). This inventory describes those bytes
and the source configuration; it makes no uniform chain-wide security claim.

| Purpose | Implementation and assumptions |
| --- | --- |
| Shielded spending authority | Knowledge of Poseidon2-derived `ask` and `nk`, membership of the committed note, nullifier derivation, and balance/range constraints in `qnero-circuit`. A spending proof enforces these together. |
| Notes and key derivation | Poseidon2 over Goldilocks, domain-tagged field hashes and the byte sponge from `qp-poseidon-core`; `qnero-note-core` defines the layouts. |
| Commitment tree | Sorted quaternary Poseidon2 children, depth 16. Sorted hashing does not independently authenticate a leaf's storage index; wallet trie proofs bind indexes and values. |
| Proof transcript and commitments | Original `PoseidonGoldilocksConfig`, including the proof Merkle commitments and Fiat-Shamir challenger. Width 12, eight full rounds, 22 partial rounds, exponent seven. These are separate from the note/tree Poseidon2 hashes. |
| Proof soundness parameters | Goldilocks with extension degree two; configured target 100 bits, two challenges, 28 FRI queries, rate bits three, cap height four, and 16 grinding bits. Six leaves per private batch and 53 private batches per public batch. |
| Zero knowledge | Leaf proofs stay local and use the non-ZK configuration. The private batch uses row blinding and is the first proof allowed to cross a trust boundary. The public batch wraps already blinded private proofs. The composition and implementation need independent review. |
| Ordinary note delivery | ML-KEM-1024 followed by ChaCha20-Poly1305. The vendored `qnero-pqcrypto::note_encryption` KDF derives separate note/memo material from the shared secret, labels and suite; version, suite and diversifier are authenticated. Ciphertext version 1, suite 1. Wallets pad ordinary outputs to 1792 bytes; the runtime accepts payloads up to 2048 bytes. Fresh encapsulation randomness is required for every output. |
| Coinbase discovery | A miner viewing key derives the coinbase randomness bound to genesis and block height. Coinbase value and creation height are public; current coinbase outputs have no encrypted payload. |
| Transparent entry signatures | ML-DSA-87 through `qp-dilithium-crypto`. Shielded settlements use proof authorization and publish nullifiers. |
| Header and state authentication | Poseidon2 for the custom header hash; Blake2-256 for the runtime's Substrate state trie, LayoutV1. State proofs authenticate values relative to a selected header. Wallets retain provider/checkpoint trust for chain selection and freshness. |
| P2P transport | Vendored litep2p uses Clatter pqXX with ML-KEM-768, ChaChaPoly and SHA-256, plus signed identity binding. Wallet HTTP/WebSocket TLS is a separate deployment boundary and does not inherit the P2P suite. |
| Proof of work | Stock RandomX `rx/0` through the native engine. Honest-chain selection depends on cumulative work and availability; its security is separate from proof soundness and note confidentiality. |

ML-KEM and ML-DSA are standardized in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). Standardization of a
primitive does not assess Qnero's key derivation, protocol composition, source
implementation, or build artifacts.

## Security targets and review status

The configured 100-bit target describes the proof configuration. It is not a
certified classical or quantum security level for Qnero. The original Plonky2
documentation describes a conjectured FRI target and an approximately 95-bit
caveat for the original Poseidon parameters listed above. That caveat is relevant
to evaluating this configuration; it is not a demonstrated Qnero forgery.
[Plonky2 security documentation](https://github.com/0xPolygonZero/plonky2#security).

The project aims to preserve note confidentiality and spending authorization
against classical and quantum attackers. Numerical acceptance targets for each
property remain to be agreed with the independent reviewer. In particular,
NIST categories for the lattice primitives do not transfer to the proof system,
and a quantum estimate cannot be obtained by mechanically halving every
classical number. Zero knowledge, soundness, hash security and metadata privacy
must each be evaluated under their own model.

Existing upstream audits establish evidence only for their reviewed revisions
and scope. Qnero adds its own note relations, recursive wiring, settlement,
encryption integration and consensus. Those changes need their own assessment.
The original Polygon Plonky2 repository is deprecated; the locked implementation
here comes from the Quantus fork. Dependency updates must record the upstream
patch and audit provenance, regenerate the profile, and rerun compatibility and
performance gates. [Polygon maintenance notice](https://github.com/0xPolygonZero/plonky2#%EF%B8%8F-plonky2-deprecation-notice),
[Quantus fork](https://github.com/Quantus-Network/qp-plonky2).

## Qualification before mainnet

An independent assessment must cover the locked proof library and generated
leaf/private/public verifier artifacts, Fiat-Shamir assumptions, the sorted
tree, field encodings and range constraints, blinding and recursive privacy,
nullifier uniqueness, note encryption/KDF and key separation, and all public
inputs bound by settlement. Record explicit classical and quantum assumptions,
accepted targets and unresolved limitations in the resulting review.

If that assessment requires new hashes or parameters, update the circuits,
runtime, native wallet, browser prover and aggregator together. Regenerate the
verifier digests and protocol profile, measure the exact runtime WASM and wallet
proving cost, and use an explicit upgrade or fresh-genesis plan. The current
experimental flag remains set until that work is complete.
