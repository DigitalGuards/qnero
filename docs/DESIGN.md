# Qnero design (draft v0.1, 2026-09-11)

Qnero is a post-quantum private coin with Monero's policy: every transfer is
shielded, sender, recipient and amount are hidden, and there is no transparent
option for users. It is built on the Quantus Network stack (MIT) so the
post-quantum account layer, hash-based ZK proving and recursion, Merkle
commitment tree and nullifier set are reused as audited code.

## 1. Why not port Monero's cryptography

Monero's privacy is Ed25519 in four places: CLSAG ring signatures with key
images, RingCT Pedersen commitments with Bulletproofs+, ECDH stealth addresses,
and the in-progress FCMP++ curve trees. None of those has a production-grade
post-quantum replacement. Lattice RingCT designs (MatRiCT+, Raptor) exist as
papers with transactions in the tens of KB and no audited implementation.

Hash-based STARK/FRI proving does have production implementations, and it is
post-quantum by construction. A shielded pool in Zcash Orchard semantics (note
commitments, nullifiers, membership proofs, balance proved in zero knowledge)
needs only a hash function inside the circuit. Monero's user-facing property
survives: the pool is the only place value lives.

## 2. Primitive mapping

| Monero piece | Qnero replacement | Source |
|---|---|---|
| Ed25519 spend/view keys | Hash-derived spend key, ML-KEM decapsulation key as view key | new + `clatter`/rust-crypto ML-KEM already in Quantus deps |
| Stealth address (ECDH) | ML-KEM encapsulation per output, AEAD note ciphertext | new |
| Pedersen commitment | Poseidon note commitment `cm = H(H(pk, rho, r), v)` | new, `qp-poseidon` |
| Bulletproofs+ range proof | 64-bit range check inside the Plonky2 circuit | plonky2 gadget |
| CLSAG ring + key image | Merkle membership proof in the 4-ary Poseidon tree + nullifier `nf = H(nk, rho)` | `qp-zk-circuits` `zk_merkle`, `nullifier` fragments |
| Ring size / decoys | Anonymity set = the whole tree (all notes ever) | `pallet-zk-tree` |
| Transaction signature | Spend proof bound to the transaction digest as a public input | plonky2 public inputs |
| RandomX PoW | QPoW (kept for v0) | `pallets/qpow` |
| Node identity, p2p | ML-DSA-87 accounts, PQ Noise (ML-KEM) | Quantus |

Field: Goldilocks. Hash: Poseidon (Quantus parameters, Eiger reviewed). Proof
system: Plonky2 (FRI), conjectured 100-bit security at the Quantus config.
Every primitive is hash-based or lattice-based; there are no elliptic curves in
the transaction path.

## 3. What is reused from Quantus, verbatim or by fork

Verified on this machine 2026-09-11: `cargo test -p qp-wormhole-circuit
--release` passes (25 tests) on toolchain 1.93.0.

| Component | Reuse | Notes |
|---|---|---|
| Leaf circuit fragments: `zk_merkle_proof`, `nullifier`, `block_header`, `sensitive` (zeroize) | fork | The unspendable-account and dual-exit fragments are replaced by note fragments |
| `PrivateBatchAggregator` (7 leaves, ZK, client side) | fork | New public-input layout |
| `PublicBatchAggregator` (53 batches, delegatable) | fork | Forward-only, minimal change |
| `pallet-wormhole` verify flow: PI parse, block hash check, nullifier dedupe, plonky2 verify, tx-pool tags | fork as `pallet-shielded` | Exit-account minting becomes commitment append + ciphertext event |
| `pallet-zk-tree` 4-ary Poseidon tree | as is | Leaf becomes the note commitment |
| `UsedNullifiers` storage | as is | |
| ML-DSA-87 accounts, hdwallet | as is | Transparent layer, needed for miners and fees in v0 |
| Audits | as is | Eiger Wormhole audit 2026-03-20, Substrate audit 2026-05-13, PoW + Poseidon review |

## 4. Keys and addresses

```
sk        : 32 random bytes                     (seed, backed up by the user)
ask       = H("qnero/ask", sk)                  spend authorizing key, private
nk        = H("qnero/nk",  sk)                  nullifier key, private
ak        = H("qnero/ak",  ask)                 public spend commitment
pk        = H("qnero/pk",  ak, nk)              note-receiving key, 32 bytes
(ek, dk)  = ML-KEM.KeyGen(H("qnero/kem", sk))   view key pair
address   = bech32m("qn", pk || ek)
```

Address size is dominated by the ML-KEM encapsulation key: 1184 bytes at
ML-KEM-768, 1568 at ML-KEM-1024. Decision pending: ML-KEM-1024 for level-5
parity with ML-DSA-87, or ML-KEM-768 for shorter addresses. Either way
addresses are QR-code sized, the same trade-off the QRL Connect protocol
already made.

Viewing: `dk` alone lets a wallet detect and decrypt incoming notes and see
outgoing note contents it authored. `nk` alone reveals which notes were spent.
`ask` is needed to spend. This matches Monero's view-key / spend-key split.

## 5. Notes

```
note      = (pk, v: u64, rho: 32 bytes, r: 32 bytes)
inner     = H("qnero/note", pk, rho, r)
cm        = H("qnero/cm", inner, v)
nf        = H("qnero/nf", nk, rho)
```

The two-layer commitment lets a coinbase note carry a public `v` and a public
`inner` that the chain checks against `cm` while `pk` stays hidden. Regular
notes keep both layers private.

Output on chain: `cm` (32 bytes), ML-KEM ciphertext (1088 or 1568 bytes),
AEAD ciphertext of `(v, rho, r, memo)` keyed by `H(shared_secret, cm)`.
Recipients scan every output by decapsulating and attempting decryption,
the same linear scan Monero wallets do.

## 6. v0 spend circuit (leaf)

One leaf = one shielded transfer: up to 2 inputs, exactly 2 outputs.

Private inputs: for each input, the note `(pk, v, rho, r)`, `ask`, `nk`,
Merkle path to `zk_tree_root`, dummy flag; for each output, the note fields.

Public inputs (felts): `block_hash(4)`, `block_number(1)`, `nf_1(4)`,
`nf_2(4)`, `cm_out_1(4)`, `cm_out_2(4)`, `fee(1)`, `ct_digest(4)`.

Constraints:
1. Block hash equals `H(header preimage)`; the header carries `zk_tree_root`
   (existing fragment).
2. For each non-dummy input: `pk = H(ak, nk)` with `ak = H(ask)`; `cm`
   recomputed from the note; Merkle path from `cm` to `zk_tree_root`;
   `nf = H(nk, rho)`. Dummy inputs have `v = 0` and a random nullifier
   preimage (existing dummy pattern).
3. For each output: `cm_out` recomputed from the note; `v_out` range-checked
   to 62 bits.
4. Balance: `v_in_1 + v_in_2 = v_out_1 + v_out_2 + fee`, all values 62-bit so
   no field wrap.
5. `ct_digest` is a free public input. The chain recomputes
   `H(ciphertexts)` from the submitted outputs and compares, which binds the
   ciphertexts to the proof without hashing them in-circuit.

Private batch: 7 leaves as today, ZK enabled, produced by the wallet. The
batch is the on-chain transaction unit. Public batch: unchanged in shape.

## 7. Pallet changes (`pallet-shielded`, forked from `pallet-wormhole`)

1. Parse the new PI layout; keep the block-hash-at-height check and nullifier
   dedupe.
2. For each real leaf: mark both nullifiers used, append `cm_out_1`,
   `cm_out_2` to `pallet-zk-tree`, emit the ciphertexts in an event and store
   them by leaf index for wallet sync.
3. Fee: sum of leaf fees, split burn / block author as Wormhole does today.
4. Entry in v0: Wormhole-style deposit from a transparent account into a note
   (public `v`, coinbase-style commitment). Exit in v0: a leaf whose output
   is a transparent account with public `v`. Both removed in v1.

## 8. Milestones

| # | Deliverable | Estimate |
|---|---|---|
| M1 | `qnero-notes` crate: keys, addresses, note commitment, ML-KEM note encryption, scan; KATs pinned | DONE 2026-09-11 |
| M2 | Leaf circuit fork with note fragments, tests, gate profile, prove/verify bench | 2 to 3 weeks |
| M3 | Private and public batch aggregators on the new PI layout | 1 week |
| M4 | `pallet-shielded` + runtime wiring, local dev chain end to end | 2 weeks |
| M5 | Wallet CLI: keygen, sync/scan, build leaf + batch, submit | 2 weeks |
| M6 | v1 mandatory privacy: coinbase into notes, transparent transfers disabled | 2 weeks |

About 10 to 12 weeks to a private testnet. The measured risk to retire first
is wallet-side proving time and memory for a 2-in/2-out leaf plus a
7-slot private batch (see `docs/BENCH.md` once measured).

## 9. Open questions

1. ML-KEM-1024 chosen for addresses (level-5 parity with ML-DSA-87, same as Hegemon). Encoded address is 2571 characters.
2. Proof size and verify weight for the private batch under the new PI
   layout; Wormhole's numbers are the baseline.
3. Whether to keep QPoW or bring RandomX; unrelated to privacy, defer.
4. Fee visibility: fees are public, as in Monero. Fixed-fee tiers would reduce
   fingerprinting; decide at M4.
5. Memo field size and whether it is mandatory (Zcash pads to 512 bytes).

## 10. Positioning: Qnero vs Hegemon

Hegemon (Pauli-Group/Hegemon, MIT, alpha) is the closest existing project:
shielded-only pool, PoW, ML-DSA / SLH-DSA / ML-KEM-1024, hash commitments,
STARK proofs, MASP multi-asset notes, viewing keys, proofs of disclosure.
Surveyed 2026-09-11 at b819911.

| | Hegemon | Qnero |
|---|---|---|
| Started | Nov 2025, v0.10.0 Mar 2026, still alpha | Sep 2026 |
| Team | one main author (1936 of 1979 commits), 16 stars | DigitalGuards, QRL ecosystem |
| Proof system | in-house "SmallWood" STARK backend plus an in-house lattice folding layer, both `candidate_under_review`; Plonky3 dropped | Plonky2 (Polygon lineage, years in production), unchanged |
| External review | one review pass by an LLM (Codex), verdict "claim unsupported" for the 128-bit claim; no audit firm | Eiger audit of the Wormhole circuits and Poseidon, Substrate audit of the chain, both by a firm |
| Chain stack | everything custom: consensus, p2p, sled state, sync | Substrate plus Quantus PQ p2p, already running a public network |
| Tx proof size | about 105 KB per tx, 524 KB block artifact | to measure (private batch proof; 7 tx per proof amortizes it) |
| Tx shape | 2 in, 2 out fixed | 2 in, 2 out in v0 |
| Codebase | 271k lines of Rust, docs and Lean proofs generated at machine scale, hard to review | small delta on top of audited upstream |
| Narrative | "post-quantum shielded money", governance and versioning heavy | post-quantum Monero: private by default, proof of work, CPU mining |

Where Hegemon is ahead: it runs, it has a wallet, a desktop app, a testnet
with seed nodes, multi-asset notes, diversified addresses, disclosure proofs.
None of that is in Qnero yet, and 12 weeks will not close all of it.

Where Qnero beats it, if we execute:
1. Trust. Every cryptographic component in Qnero is either standardized
   (ML-DSA, ML-KEM, SHA3) or externally audited by a firm (Plonky2 circuits,
   Poseidon, Substrate runtime). Hegemon's soundness rests on a novel proof
   backend that its own review package calls unsupported. For private money
   this is the whole argument.
2. Narrative. Monero has the largest privacy community in crypto and no
   post-quantum path. Qnero speaks Monero: spend key and view key, private by
   default, no transparent pool, proof of work, the anonymity set is the
   whole chain. Hegemon speaks protocol governance.
3. Ecosystem. Explorer, web wallet, mobile wallet, desktop wallet, connect
   SDK and dApp tooling already exist in the QRL stack and can be pointed at
   Qnero. Hegemon has one Electron app.
4. Reviewability. A reviewer can read Qnero's delta over Quantus in a day.
5. Mining story. Consider RandomX in place of QPoW so Monero miners can move
   over with the software they already run. Decision deferred to M4.

Concrete "beat it" targets for the first testnet:
- proof per tx smaller than 105 KB, or clearly amortized below it per batch
- wallet proving under 5 s on a laptop, under 60 s on a phone
- audit-grade claim: no cryptographic component without a firm's review
- a running public testnet with the explorer and web wallet attached

## 11. Narrative

One line: Monero's principles, rebuilt without elliptic curves.

Pillars, in this order:
1. Private by default. There is no transparent pool. Every output is a
   sealed note, every spend is a proof.
2. Proof of work. No stake, no validators, no foundation keys in consensus.
3. Post-quantum from genesis. Hash-based proofs, lattice signatures and
   encapsulation, nothing for Shor to break.
4. Audited parts only. Standardized primitives and firm-audited circuits.
   No novel cryptography.
