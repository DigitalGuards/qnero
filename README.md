# Qnero

Qnero is a post-quantum private coin with Monero's policy: every transfer shielded, sender, recipient and amount hidden, no transparent option for users.

**Pre-alpha, devnet only, and no part of Qnero itself has been audited.** The repository is 48 commits from 2026-09-11 and 2026-09-12. What runs today is a local `--dev --tmp` chain and a CLI wallet, exercised end to end on one workstation: no public testnet, no seed node, no explorer, no GUI. The wallet docs say it plainly, use this on a dev chain and nowhere else. The design draft estimates 10 to 12 weeks to a private testnet.

## What Qnero is

Monero's privacy is Ed25519 in four places: CLSAG ring signatures with key images, RingCT Pedersen commitments with Bulletproofs+, ECDH stealth addresses, and the in-progress FCMP++ curve trees. None has a production-grade post-quantum replacement, and lattice RingCT designs (MatRiCT+, Raptor) remain unaudited papers with tens-of-KB transactions. Qnero keeps the policy and rebuilds the machinery from hashes and lattices.

That machinery is Zcash Orchard in shape: note commitments, nullifiers, membership proofs, balance proved in zero knowledge. Four pillars, in order: private by default, every spend a proof; proof of work, with no stake and no validators; post-quantum from genesis; audited parts only, standardized primitives and firm-audited circuits, those audited parts being upstream's.

The base is the Quantus Network stack (MIT): ML-DSA-87 accounts, post-quantum Noise (ML-KEM) p2p, a 4-ary Poseidon commitment tree, a nullifier set. No elliptic curve appears in the transaction path. Field Goldilocks, hash Poseidon2 at the Quantus parameters (Eiger reviewed), proofs Plonky2 (FRI) at a conjectured 100 bits.

`crates/` holds the Qnero workspace, from `qnero-pqcrypto` to `qnero-wallet`; `qnero-verifier` builds for `wasm32v1-none`, so the runtime links no prover stack. `chain/` is the forked Quantus chain, a git subtree at `f1176ce` (v1.0.1) with its own workspace and lock file, where `pallets/shielded` settles.

## The Monero mapping

| Monero | Qnero | State |
|---|---|---|
| Spend key | `ask = H("qnero/ask", sk)`; `pk = H(PK, ak, nk)` receives | Replaced, hash-based |
| View key, stealth address | An ML-KEM encapsulation and AEAD ciphertext per output; `dk` decrypts, `nk` shows spent status | Replaced, split kept |
| Ring, decoys, ring size 16 | Merkle membership proof; the set is every note appended | Replaced, larger |
| Key image | `nf = H(NF, nk, rho, r)` in `UsedNullifiers` | Replaced, same role |
| RingCT commitments | `cm = H(CM, H(NOTE, pk, rho, r), v)`, balance proved in circuit | Replaced, hash-based |
| Bulletproofs+ | A 62-bit range check per output inside the spend proof | Replaced, folded in |
| Wallet scanning | The same linear trial decryption of every output | Present |
| Coinbase | A shielded note per block from a required inherent; its value is public | Present |
| Unlock time | No unlock field; anchors expire after `BlockHashWindow`, 256 blocks | Absent |
| Fungibility | `shield` in, no exit at v0, `BaseCallFilter` blocks transparent transfers; Root and the scheduler bypass it | Present, two bypasses |
| RandomX | QPoW through v1, behind one `FindAuthor` seam | Planned for M7 |
| Tail emission | Undesigned; the Quantus schedule runs against `MAX_SUPPLY` | Absent |

## How a transfer works

One leaf proof is one shielded transfer: up to 2 input notes, exactly 2 outputs, a public fee, and `ct_digest` binding the output ciphertexts, as 26 public inputs fixed in `qnero_circuit::layout`. Per real input the circuit derives `pk` from `ask` and `nk`, recomputes `cm`, walks a 16-level Merkle path to the anchored header's `zk_tree_root`, and emits the nullifier. An input's `pk` is never witnessed, so a wrong credential yields a commitment absent from the tree, and outputs range-check to 62 bits so the balance equation cannot wrap the field.

Two recursive layers sit above in `qnero-aggregator`: N leaf proofs make a zero-knowledge private batch, the on-chain transaction unit, and n of those a public batch, an aggregator's non-ZK bundle. Both check inner proofs against a baked-in verifier key.

`pallet-shielded` settles each real slot: both nullifiers marked used, both commitments appended, `ct_digest` recomputed and compared. A segment carrying an already-claimed nullifier is skipped and the rest settles, since refusing it would let one participant destroy an aggregator's batch for free. Settlements are unsigned and fee free, so fee floors carry anti-spam alone. Value enters circulation only in the note a block mints to its author, and transparent value enters through `shield`, whose signer and value are public.

## Numbers

One workstation, 20 cores, WSL2.

- Leaf: 320 gates, proof 105500 bytes, verify 2.2 ms. Single threaded, prove mean 183 ms over 9 runs (138 to 381 ms, the spread being 16 grinding bits).
- Private batch at the chain default N = 6, four threads: proof 150908 bytes, 131 felts, prove 3.34 to 3.61 s. N = 7 is 24530 gates, 6.4 s and 2.06 GiB peak, about 2x the cost of six for one more slot.
- Public batch at n = 53: proof 237544 bytes, prove 29 s, a 2.2x margin under `MAX_PROOF_BYTES` of 524288, 318 real slots.
- Verify is flat in what a proof wraps: 2.2 ms for a leaf, 4.2 ms for a private batch, 6.04 ms for the public-batch check, all native. `WASM_VERIFY_FACTOR = 5` is unmeasured.
- An address `qn1...` is 2571 characters, mostly its 1568-byte ML-KEM-1024 key. Amounts are pool quanta of 10^10 planck, 0.01 QNR; a `send` defaults to a fee of 8 quanta and takes 6.47 to 7.81 s, and emission at genesis supply is 41 quanta a block.

## Run it

Each block starts at the repository root. Release builds are mandatory: a leaf takes about 0.2 s in release, minutes in debug.

```
cd chain
cargo update -p kem --precise 0.3.0-pre.0
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p quantus-node
```

`chain/` is a separate Cargo workspace, so build the wallet from the root one; Plonky2's rayon is off by default.

```
nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel
./target/release/qnero-wallet keygen
export QNERO_MINER_KEY=$(./target/release/qnero-wallet miner-address)
```

The miner key is secret-bearing and cannot spend: its holder picks that miner's coinbase notes out of the tree. A node without one refuses to start.

```
nice -n 19 ./chain/target/release/quantus-node --dev --tmp \
  --rewards-miner-key "$QNERO_MINER_KEY" --rewards-inner-hash <hash>
```

```
export RAYON_NUM_THREADS=4
./target/release/qnero-wallet shield --from-dev-account alice --amount 100
./target/release/qnero-wallet sync
./target/release/qnero-wallet send --to qn1... --amount 5
```

RPC is the Substrate default, port 9944. A `send` picks two notes largest-first, rebuilds Merkle paths locally and proves the batch itself.

## Status, audits and caveats

M1 through M6 are done, through the wallet CLI and v1 mandatory privacy. The audits are upstream's: Eiger on the Wormhole circuits (2026-03-20), a Substrate audit of the chain (2026-05-13), a proof-of-work and Poseidon review. **No external audit of the Qnero delta exists.** That delta is the leaf circuit's note fragments, the public-input layouts at all three layers, the aggregator rules, and `pallet-shielded`. The design claims a reviewer can read it in a day, and Plonky2's 100-bit security here is a conjecture.

- Key storage is dev grade: 32 bytes of hex in a `0600` file, no passphrase or encryption, beside a note store holding every `rho` and `r` in clear text.
- Weights are unbenchmarked, and admission work is unpaid per gossiped blob: a settlement walk and a verify each, with no rate limit.
- The real-transfer count is public: a padding slot publishes zero commitments, which the chain needs to append correctly.
- One transfer per submission today: six slots, one filled, so 150908 bytes carries one transfer, about 22 KB each when full.
- Two leaks are closed by construction, asserted in `tests/node_learns_nothing.rs`: a sync never names a nullifier, and a spend never names a leaf, though `--merkle-rpc` opts back into naming it. Traffic analysis stays open: a node sees an IP, a cadence, submission timing.
- `N` and `POOL_QUANTUM` are undiscoverable over RPC, so a runtime and a wallet built apart diverge silently, the chain refusing the proof after its cost is paid.

Next is M7, RandomX, so Monero rigs can mine Qnero with the software they already run; the evaluation is recorded and no engine work has started. M6 made that swap a one-file change, since everything needing the block author reads one `FindAuthor` implementation. Also queued: real key storage, a keccak pin on the first tagged circuit release, hiding the real-transfer count. Testnet targets: a proof per transaction under 105 KB or amortized below it, proving under 5 s on a laptop, no cryptographic component without a firm's review.

## Credits and licence

Qnero is MIT licensed (`LICENSE` at the repository root, DigitalGuards). `chain/LICENSE` is the MIT License, "Copyright 2025 Quantus Network", and `crates/qnero-pqcrypto/LICENSE.hegemon` carries the vendored text.

- **Quantus Network** (MIT), chain: a subtree of Quantus-Network/chain at `f1176ce` (v1.0.1). `pallet-zk-tree`'s Poseidon tree, `UsedNullifiers` and ML-DSA-87 accounts come as is; `pallet-wormhole`'s verify flow is forked as `pallet-shielded`.
- **Quantus Network** (MIT), circuits: parts of `qnero-circuit` and `qnero-aggregator` derive from qp-zk-circuits at 4.4.0, and three more crates follow its Wormhole equivalents in shape. All five carry a `NOTICE` and `CHANGES.md`; the layouts, padding rule and forwarding contract are Qnero's own.
- **Hegemon** (Pauli-Group/Hegemon, MIT): `qnero-pqcrypto` vendors its `crypto` crate at `b819911`, carrying its own `NOTICE` and `CHANGES.md`.
- **Plonky2** (Polygon lineage), through `qp-plonky2` and `qp-plonky2-verifier` at `=1.5.5`, with `qp-poseidon-core` 3.1.0 off circuit, tied to the in-circuit hash by `circuit_parity`. `quantus-cli` 2.2.2 was read while the wallet was written; no code was copied.

Maintained by DigitalGuards at https://github.com/DigitalGuards/qnero.
