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
| Pedersen commitment | Poseidon note commitment `cm = H(CM, H(NOTE, pk, rho, r), v)` | new, `qp-poseidon` |
| Bulletproofs+ range proof | 62-bit range check inside the Plonky2 circuit | plonky2 gadget |
| CLSAG ring + key image | Merkle membership proof in the 4-ary Poseidon tree + nullifier `nf = H(NF, nk, rho, r)`, or `nf = H(NF_DUMMY, nk, rho, r)` for a padding input slot | `qp-zk-circuits` `zk_merkle`, `nullifier` fragments |
| Ring size / decoys | Anonymity set = the whole tree (all notes ever) | `pallet-zk-tree` |
| Transaction signature | Spend proof bound to the transaction digest as a public input | plonky2 public inputs |
| RandomX PoW | QPoW (kept for v0) | `pallets/qpow` |
| Node identity, p2p | ML-DSA-87 accounts, PQ Noise (ML-KEM) | Quantus |

Field: Goldilocks. Hash: Poseidon (Quantus parameters, Eiger reviewed). Proof
system: Plonky2 (FRI), conjectured 100-bit security at the Quantus config.
Every primitive is hash-based or lattice-based; there are no elliptic curves in
the transaction path.

The two hash rules above are quoted for orientation. Section 5 and
`docs/CIRCUIT.md` section 3 are the authority on them, and both `r` in the
nullifier preimage and the separate padding tag are load bearing: they are what
keeps `nk` a viewing-tier secret and what stops a padding slot from settling a
real note's nullifier. Section 4 explains both.

## 3. What is reused from Quantus, verbatim or by fork

Verified on this machine 2026-09-11: `cargo test -p qp-wormhole-circuit
--release` passes (25 tests) on toolchain 1.93.0.

| Component | Reuse | Notes |
|---|---|---|
| Leaf circuit fragments: `zk_merkle_proof`, `nullifier`, `block_header`, `sensitive` (zeroize) | fork | The unspendable-account and dual-exit fragments are replaced by note fragments |
| `PrivateBatchAggregator` (7 leaves, ZK, client side) | fork | New public-input layout |
| `PublicBatchAggregator` (53 batches, delegatable) | fork | Forward-only, minimal change |
| `pallet-wormhole` verify flow: PI parse, block hash check, nullifier dedupe, plonky2 verify, tx-pool tags | fork as `pallet-shielded` | Exit-account minting becomes commitment append + ciphertext event |
| `pallet-zk-tree` 4-ary Poseidon tree | small fork | Node hashing unchanged; `Leaves` holds a raw `Hash256`, the note commitment, see `docs/CIRCUIT.md` section 4 |
| `UsedNullifiers` storage | as is | |
| ML-DSA-87 accounts, hdwallet | as is | Transparent layer, needed for miners and fees in v0 |
| Audits | as is | Eiger Wormhole audit 2026-03-20, Substrate audit 2026-05-13, PoW + Poseidon review |

## 4. Keys and addresses

```
sk        : 32 random bytes                     (seed, backed up by the user)
ask       = H("qnero/ask", sk)                  spend authorizing key, private
nk        = H("qnero/nk",  sk)                  nullifier key, private
ak        = H(AK, ask)                          public spend commitment
pk        = H(PK, ak, nk)                       note-receiving key, 32 bytes
(ek, dk)  = ML-KEM.KeyGen(H("qnero/kem", sk))   view key pair
address   = bech32m("qn", pk || ek)
```

Two hash forms appear here and they are not interchangeable. `H("qnero/...",
...)` is Poseidon2 over bytes with that ASCII string as a literal prefix, and
it is used exactly where written: `ask`, `nk`, and the ML-KEM seed. `H(TAG,
...)` is Poseidon2 over field elements with a one-felt domain tag as the first
sponge input: `AK = 0x716e_0001`, `PK = 0x716e_0002`, `NOTE = 0x716e_0003`,
`CM = 0x716e_0004`, `NF = 0x716e_0005`, `RHO = 0x716e_0006` (hashes the two
nullifiers a spend publishes and an output index, derived in circuit),
`NF_DUMMY = 0x716e_0007` (the nullifier a padding input slot publishes) and
`NF_BATCH_PADDING = 0x716e_0008` (the nullifier the private-batch wrapper
emits for a padding slot, over randomness it draws per slot per proving run,
`docs/CIRCUIT.md` section 8.4). Those are the values in
`qnero_notes::digest::domain`, and the spend circuit imports them from that
crate so the two copies cannot drift. A test in that module asserts the tags
are pairwise distinct, because two rules sharing a tag is the failure that has
no symptom until someone finds the collision. `docs/CIRCUIT.md` section 3 is
the authority.

`0x716e_0008` is taken. A note created outside a spend proof, a shield today
and a coinbase at M6, needs a tag of its own at `0x716e_0009` or above.

Address size is dominated by the ML-KEM encapsulation key: 1184 bytes at
ML-KEM-768, 1568 at ML-KEM-1024. Decision pending: ML-KEM-1024 for level-5
parity with ML-DSA-87, or ML-KEM-768 for shorter addresses. Either way
addresses are QR-code sized, the same trade-off the QRL Connect protocol
already made.

Viewing: `dk` alone lets a wallet detect and decrypt incoming notes and see
outgoing note contents it authored. `nk` tells the holder of a note whether it
has been spent. `ask` is needed to spend. This matches Monero's view-key /
spend-key split.

`nk` is a viewing-tier secret and confers nothing beyond detection. Two
properties of the spend circuit keep it that way, both in `docs/CIRCUIT.md`
section 3. The nullifier hashes `(nk, rho, r)`, and `r` reaches only the note's
sender and its holder, so `nk` plus the publicly derivable `rho` of every
output note is still not enough to compute anyone's nullifiers and link their
spends pool-wide. And a padding input slot's nullifier is domain separated, so
a holder of someone else's `nk` cannot publish that person's nullifier from a
slot that proves no membership and burn the note.

## 5. Notes

```
note      = (pk, v: u64 capped at 2^62 - 1, rho: 32 bytes, r: 32 bytes)
inner     = H(NOTE, pk, rho, r)
cm        = H(CM, inner, v)
nf        = H(NF, nk, rho, r)                 real input slot
nf_dummy  = H(NF_DUMMY, nk, rho, r)           padding input slot, tag selected in circuit
rho_out_j = H(RHO, nf_1, nf_2, j)             a spend output's rho is derived in circuit
```

The 62-bit cap on `v` is a consensus rule. The no-wrap argument behind the
circuit's balance equation (`docs/CIRCUIT.md` section 5, constraint 8) holds
only while every term is below `2^62`, so every path that creates a note,
coinbase and deposit included, has to enforce the cap.

The two-layer commitment lets a coinbase note carry a public `v` and a public
`inner` that the chain checks against `cm` while `pk` stays hidden. Regular
notes keep both layers private.

Output on chain: `cm` (32 bytes), ML-KEM ciphertext (1088 or 1568 bytes),
AEAD ciphertext of `(v, rho, r, memo)`. Recipients scan every output by
decapsulating and attempting decryption, the same linear scan Monero wallets
do. The leaf's `ct_digest` public input binds the ciphertexts to the proof;
`qnero_circuit::chain::ct_digest` is the rule and `docs/CIRCUIT.md` section 1
states it. It lives in the circuit crate's layout-only surface, which compiles
without the prover stack, which is what lets the chain and a wallet call one
function, where two copies of one rule could drift.

The AEAD key and nonce come from the KEM shared secret, a per-payload label and
the crypto suite (`qnero_pqcrypto::note_encryption`), with the version, suite
and diversifier index as associated data. The commitment is not an input to
that derivation, so key separation between two outputs rests entirely on the
KEM randomness being fresh per output. `encrypt_note` documents the
requirement and nothing enforces it, so reusing `kem_randomness` across two
outputs to one recipient encrypts both payloads under one ChaCha20-Poly1305 key
and nonce, which leaks the XOR of the two plaintexts and the Poly1305
authentication key. M5 owns two things here: make per-output freshness an
invariant a wallet cannot violate, and decide whether to feed `cm` into the
derivation so that a reuse bug is survivable.

## 6. v0 spend circuit (leaf)

Built at M2. `docs/CIRCUIT.md` is the implemented specification, including the
tree leaf rule M3 and M4 depend on; this section is the design intent it was
built from, and the two agree.

One leaf = one shielded transfer: up to 2 inputs, exactly 2 outputs.

Private inputs: for each input, `(v, rho, r)` plus `ask`, `nk`, a Merkle path
to `zk_tree_root` and a dummy flag; for each output, `pk`, `v` and `r`. An
input's `pk` is derived in circuit from `ask` and `nk`, so a wrong credential
yields a commitment that is not in the tree, and an
output's `rho` is derived from both nullifiers the leaf publishes, so a
sender cannot hand two notes the same nullifier seed.

Public inputs (felts): `block_hash(4)`, `block_number(1)`, `nf_1(4)`,
`nf_2(4)`, `cm_out_1(4)`, `cm_out_2(4)`, `fee(1)`, `ct_digest(4)`.

Constraints:
1. Block hash equals `H(header preimage)`; the header carries `zk_tree_root`
   (existing fragment).
2. For each non-dummy input: `pk = H(ak, nk)` with `ak = H(ask)`; `cm`
   recomputed from the note; Merkle path from `cm` to `zk_tree_root`;
   `nf = H(NF, nk, rho, r)`. Dummy inputs have `v = 0` and a random nullifier
   preimage under a separate domain tag (`NF_DUMMY`), and at least one input
   must be real unless the leaf is the batch padding leaf
   (`docs/CIRCUIT.md` constraint 9), so every leaf that binds a real block
   consumes a note. That does not bound how many leaves a prover can produce;
   see `docs/CIRCUIT.md` section 8.6 on the minimum per-leaf fee, which is the
   anti-spam mechanism.
3. For each output: `rho` derived as `H(RHO, nf_1, nf_2, j)`; `cm_out`
   recomputed from the note; `v_out` range-checked to 62 bits.
4. Balance: `v_in_1 + v_in_2 = v_out_1 + v_out_2 + fee`, all values 62-bit so
   no field wrap.
5. `ct_digest` is a free public input. The chain recomputes
   `H(ciphertexts)` from the submitted outputs and compares, which binds the
   ciphertexts to the proof without hashing them in-circuit.

Private batch: 7 leaves as today, ZK enabled, produced by the wallet. The
batch is the on-chain transaction unit. Public batch: unchanged in shape.

Built at M3, and two things about it are not "unchanged in shape". The private
batch forwards **both** nullifiers of every leaf, where the Wormhole wrapper
carries one per leaf, and it constrains all `2N` of them pairwise distinct: a
wrapper that kept upstream's shape would drop each leaf's second nullifier and
leave a note spent from input slot 1 spendable again. And it does not sum fees
in circuit, because seven 62-bit fees overflow Goldilocks; the pallet sums them
natively. `docs/CIRCUIT.md` section 8 is the specification, including the
padding rule: a padding leaf is one that binds a fixed, publicly known header
preimage, and the wrapper masks every value such a slot publishes.

## 7. Pallet changes (`pallet-shielded`, forked from `pallet-wormhole`)

`docs/CIRCUIT.md` section 8.6 is the full settlement contract; this is its
shape.

1. Parse the new PI layout; keep the block-hash-at-height check and nullifier
   dedupe.
2. Skip every batch segment carrying `PADDING_BLOCK_HASH`. Such a segment
   settles nothing at all: no nullifier entered, no commitment appended, no fee
   accounted. Its slot region is zeroed, so a chain that settled it would
   insert the all-zero nullifier and reject its own next padding segment as a
   double spend, which at 53 inner slots is close to every batch.
   `PublicBatchPublicInputs::settleable_batches` is that filter, and a zero
   nullifier must never enter the nullifier set.
3. Inside a segment that survives the filter, for every slot: mark both
   published nullifiers used, including a dummy input's, which the chain
   cannot tell from a real one; append `cm_out_1` and `cm_out_2` to
   `pallet-zk-tree`, skipping a zero commitment, which is how a padding slot
   says it created no note; recompute `ct_digest` over the submitted
   ciphertexts and compare; emit the ciphertexts in an event and store them by
   leaf index for wallet sync.
4. Fee: sum of the leaf fees of those same segments, split burn / block author
   as Wormhole does today.
5. A public batch is checked whole before any state changes. A segment holding a
   nullifier already settled, or one an earlier segment of the same submission
   claimed, is skipped and the rest settles; a repeat inside one segment refuses
   the submission, and a submission that settles nothing is refused.
   `docs/CIRCUIT.md` section 9.5 carries the reasoning.
6. Entry in v0: `shield(value, inner, ciphertext)`, a signed extrinsic that
   burns transparent value and appends `cm = H(CM, inner, value)`. There is no
   exit in v0: value that enters the pool moves only between notes. Both go at
   v1, when a coinbase mints straight into a note.

Built at M4, in `chain/pallets/shielded`. Two rules the pallet owns that this
section did not spell out: a minimum fee per real leaf slot, which is the only
thing bounding how many leaves a prover can produce, and a `rho` rule for a note
created outside a spend proof, `rho = H(RHO_ENTRY, block_number, entry_index)`
under a domain tag of its own. `docs/CIRCUIT.md` section 9 is the contract as
built, including the open decisions it closed.

## 8. Milestones

| # | Deliverable | Estimate |
|---|---|---|
| M1 | `qnero-notes` crate: keys, addresses, note commitment, ML-KEM note encryption, scan; KATs pinned | DONE 2026-09-11 |
| M2 | Leaf circuit fork with note fragments, tests, gate profile, prove/verify bench | DONE 2026-09-11 (319 gates at M2, 320 after the M3 padding sentinel; degree_bits 9, 26 public inputs; see `docs/CIRCUIT.md`) |
| M3 | Private and public batch aggregators on the new PI layout | DONE 2026-09-11 (private batch 5 + 21N public inputs, ZK, N = 7; public batch forwards each inner verbatim under an aggregator address and refuses a repeated inner in circuit; see `docs/CIRCUIT.md` section 8) |
| M4 | `pallet-shielded` + runtime wiring, local dev chain end to end | DONE 2026-09-12 (chain forked as a git subtree at `chain/`; `pallet-shielded` settles private and public batches, `shield` is the only v0 entry, `pallet-zk-tree` stores raw `Hash256` leaves; N = 6, n = 53; see `docs/CIRCUIT.md` section 9 and `docs/OPS-DEV.md`) |
| M5 | Wallet CLI: keygen, sync/scan, build leaf + batch, submit | 2 weeks |
| M6 | v1 mandatory privacy: coinbase into notes, transparent transfers disabled | 2 weeks |

About 10 to 12 weeks to a private testnet. The measured risk to retire first
is wallet-side proving time and memory for a 2-in/2-out leaf plus a
6-slot private batch (see `docs/BENCH.md`).

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
