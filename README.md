# Qnero

Monero's principles, rebuilt without elliptic curves: every transfer shielded, sender, recipient and amount hidden, no transparent option for users, and no elliptic curve anywhere in the transaction path. Emission is proof of work, with no stake, no validators, no foundation keys in consensus.

**Pre-alpha, devnet only, and no part of Qnero itself has been audited.** The repository is two days of commits, 2026-09-11 and 2026-09-12. What runs today is a local `--dev --tmp` chain and a CLI wallet, exercised end to end on one workstation. No public testnet, no seed node, no explorer, no GUI. Key storage is dev grade. The wallet docs say it plainly: use this on a dev chain and nowhere else. The design draft estimates 10 to 12 weeks to a private testnet.

## For Monero users

The mental model carries over almost intact.

**The spend key and the view key are still split.** Spending authority is `ask = H("qnero/ask", sk)` and the address half that receives is `pk = H(PK, ak, nk)`. The viewing side is an ML-KEM decapsulation key, `dk`, opening the AEAD ciphertext on each output the way a view key opens an ECDH stealth address, with a separate `nk` for spent status. Scanning is the same linear trial decryption of every output.

**The whole chain is your ring.** Ring size 16 with decoys is gone. A spend proves Merkle membership in a 4-ary Poseidon tree whose leaves are every note ever appended, so the set it hides in is the pool itself.

**Key images become nullifiers.** A spend publishes `nf = H(NF, nk, rho, r)` into `UsedNullifiers`, same role: the chain refuses one it has already seen, so a note spends once.

**RingCT and Bulletproofs+ fold into one proof.** A note commits as `cm = H(CM, H(NOTE, pk, rho, r), v)`, balance is proved in circuit, and each output range-checks to 62 bits inside the spend proof.

**A coinbase still pays the miner in a note.** One note per block, minted from a required inherent, its value and its block public, the recipient hidden. Every unit minted after genesis is a note, and the pool is where it lives, which is what fungibility rests on: `shield` is the only door in, v0 has no exit, and `BaseCallFilter` blocks transparent transfers. Two bypasses are open, for Root and the scheduler.

**Rigs mine it.** Qnero's proof of work is RandomX, stock `rx/0`, behind the same `FindAuthor` seam QPoW ran behind, so a Monero rig mines Qnero with a config change. The node serves the stratum dialect xmrig speaks to a Monero pool.

Two habits do not carry over. There is no unlock time field: an anchor expires after `BlockHashWindow`, 256 blocks, and that is the only waiting rule.

Tail emission is undesigned. The emission schedule inherited from the upstream chain runs against `MAX_SUPPLY`, so the question Monero answered with a tail is open here, listed in the mapping as absent.

## Why the cryptography was replaced

Monero's privacy is Ed25519 in four places: CLSAG ring signatures with key images, RingCT Pedersen commitments with Bulletproofs+, ECDH stealth addresses, and the in-progress FCMP++ curve trees. None of the four has a production-grade post-quantum replacement, and lattice RingCT designs (MatRiCT+, Raptor) remain unaudited papers with transactions in the tens of KB. Hash-based FRI proving is post-quantum by construction and has production implementations, and a shielded pool in Zcash Orchard semantics needs only a hash function inside the circuit. Qnero keeps the policy and rebuilds the machinery from hashes and lattices.

The design fixes four priorities in that order: private by default, every spend a proof; proof of work, with no stake and no validators; post-quantum from genesis; audited parts only, standardized primitives and firm-audited circuits, those audited parts being upstream's.

The base is an upstream post-quantum Substrate stack (MIT, credited below): ML-DSA-87 accounts, post-quantum Noise (ML-KEM) p2p, a 4-ary Poseidon commitment tree, a nullifier set. Field Goldilocks, hash Poseidon2 at parameters an audit firm has reviewed, proofs Plonky2 (FRI) at a conjectured 100 bits. `crates/` holds the Qnero workspace, from `qnero-pqcrypto` to `qnero-wallet`; `qnero-verifier` builds for `wasm32v1-none`, so the runtime links no prover stack. `chain/` is the forked upstream chain, a git subtree at `f1176ce` with its own workspace and lock file, where `pallets/shielded` settles.

## How a transfer works

One leaf proof is one shielded transfer: up to 2 input notes, exactly 2 outputs, a public fee, and `ct_digest` binding the output ciphertexts, as 26 public inputs fixed in `qnero_circuit::layout`. Per real input the circuit derives `pk` from `ask` and `nk`, recomputes `cm`, walks a 16-level Merkle path to the anchored header's `zk_tree_root`, and emits the nullifier. An input's `pk` is never witnessed, so a wrong credential yields a commitment absent from the tree, and outputs range-check to 62 bits so the balance equation cannot wrap the field.

Two recursive layers sit above in `qnero-aggregator`. N leaf proofs make a zero-knowledge private batch, the on-chain transaction unit, and n of those a public batch, an aggregator's non-ZK bundle. Both check inner proofs against a baked-in verifier key.

`pallet-shielded` settles each real slot: both nullifiers marked used, both commitments appended, `ct_digest` recomputed and compared. A segment carrying an already-claimed nullifier is skipped and the rest settles, since refusing it would let one participant destroy an aggregator's batch for free. Settlements are unsigned and fee free, so the fee floors carry anti-spam alone.

## What the node you ask learns

Run your own node. Short of that, two rules hold over what the wallet asks, both asserted in `tests/node_learns_nothing.rs`. A sync never names a nullifier: spent status is decided against a local copy of `UsedNullifiers`, paged whole through `state_getKeysPaged`, because probing that map with this wallet's own nullifiers hands a node, in the clear, the set of values this wallet will publish when it spends. A spend never names a leaf: Merkle paths are rebuilt locally from `ZkTree::Leaves` at the anchor block, and `--merkle-rpc` opts back into naming one. A node still sees an IP, a cadence and the submissions, so traffic analysis stays open.

## Numbers

One workstation, 20 cores, WSL2. `docs/BENCH.md` is the log.

- Leaf: 320 gates, proof 105500 bytes, verify 2.2 ms. Single threaded, prove mean 183 ms over 9 runs (138 to 381 ms, the spread being 16 grinding bits).
- Private batch at the chain default N = 6, four threads: proof 150908 bytes, 131 felts, prove 3.34 to 3.61 s. N = 7 is 24530 gates, 6.4 s and 2.06 GiB peak natively, and 65.8 s and 1.72 GiB in a browser, about 2x the cost of six for one more slot.
- Public batch at n = 53: proof 237544 bytes, prove 29 s, a 2.2x margin under `MAX_PROOF_BYTES` of 524288, 318 real slots.
- Verify is flat in what a proof wraps: 2.2 ms for a leaf, 4.2 ms for a private batch, 6.04 ms for the public-batch check, all native. A private batch verifies in 14.1 ms of browser wasm against 3.7 ms for the same call natively, 3.8x, and the module's very first verify costs 20.5 ms because V8 has yet to tier that code up. Neither is `WASM_VERIFY_FACTOR = 5`, which governs the runtime's own wasmtime executor and stays unmeasured.
- In a browser, single threaded: a payment is 33.6 s of wasm and 910.4 MiB of peak linear memory, on top of 12.1 s of circuit build once per worker. Natively on one thread the same batch is 9.82 s, so wasm costs about 3.3x. There is no phone in these figures: a desktop core under headless Chromium is the proxy, and the stated 2-to-4 factor is a floor, because its low end is a peak single-core score ratio that leaves out both throttling and mobile browser engines. A phone therefore lands at 67 to 134 s per payment or worse. The memory fits a 6 GB device and the single-threaded clock misses the 60 s target, so threads are the measured gap.
- An address `qn1...` is 2571 characters, mostly its 1568-byte ML-KEM-1024 key. Amounts are pool quanta of 10^10 planck, 0.01 QNR; a `send` defaults to a fee of 8 quanta and takes 6.47 to 7.81 s, and emission at genesis supply is 41 quanta a block.

## Running it

Each block starts at the repository root. Release builds are mandatory: a leaf takes about 0.2 s in release and minutes in debug. `chain/` is a separate Cargo workspace, so the node and the wallet build from different roots, and Plonky2's rayon is off by default.

```
cd chain
cargo update -p kem --precise 0.3.0-pre.0
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
cd ..
nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel
```

The miner key is secret-bearing and cannot spend: its holder picks that miner's coinbase notes out of the tree. A node without one refuses to start.

```
./target/release/qnero-wallet keygen
export QNERO_MINER_KEY=$(./target/release/qnero-wallet miner-address)
nice -n 19 ./chain/target/release/qnero-node --dev --tmp \
  --rewards-miner-key "$QNERO_MINER_KEY" --rewards-inner-hash <hash>
```

```
export RAYON_NUM_THREADS=4
./target/release/qnero-wallet shield --from-dev-account alice --amount 100
./target/release/qnero-wallet sync
./target/release/qnero-wallet send --to qn1... --amount 5
```

RPC is the Substrate default, port 9944. A `send` picks two notes largest-first, rebuilds Merkle paths locally and proves the batch itself. `docs/OPS-DEV.md` carries the build preconditions and the end-to-end transcripts; `docs/WALLET.md` is the wallet's reference.

`explorer/` is a static web explorer for the same chain: `cd explorer && nice -n 19 npm ci && nice -n 19 npm run dev` serves it at `http://127.0.0.1:5173` against the node above, and `explorer/README.md` covers the build, the one runtime JSON that points it at a chain, and what it deliberately declines to show.

### Point a rig at it

The proof of work is RandomX, stock `rx/0`, the same algorithm and the same
constants Monero uses. A rig that mines Monero mines Qnero with a config
change. Open the stratum port on the node:

```
nice -n 19 ./chain/target/release/qnero-node --dev --tmp \
  --rewards-miner-key "$QNERO_MINER_KEY" --rewards-inner-hash <hash> \
  --stratum-port 3333 --mining-threads 0
```

and point a stock xmrig at it:

```
nice -n 19 xmrig --threads=2 --algo rx/0 \
  -o 127.0.0.1:3333 -u qnero-rig -p x --no-color
```

`--mining-threads 0` turns off the node's own in-process miner, which is there
so a devnet produces blocks with no rig attached and is an order of magnitude
slower than a rig (light mode, no 2 GiB dataset). Leave it at 1 to run both.

Nothing is paid to the `-u` login. The block reward is a shielded note minted
for the key in `--rewards-miner-key`, so this is a solo-mining endpoint and the
login is a worker label. `--stratum-host` defaults to loopback; a rig on
another machine needs `0.0.0.0` and a firewall rule you chose.

## Status, audits and caveats

M1 through M9 are done, through the wallet CLI, v1 mandatory privacy, RandomX proof of work, a measured browser prover and a static explorer. The audits are upstream's: Eiger on the Wormhole circuits (2026-03-20), a Substrate audit of the chain (2026-05-13), a proof-of-work and Poseidon review. **No external audit of the Qnero delta exists.** That delta is the leaf circuit's note fragments, the public-input layouts at all three layers, the aggregator rules, and `pallet-shielded`. The design claims a reviewer can read it in a day, and Plonky2's 100-bit security here is a conjecture.

- Key storage is dev grade: 32 bytes of hex in a `0600` file, no passphrase or encryption, beside a note store holding every `rho` and `r` in clear text.
- Weights are unbenchmarked, and admission work is unpaid per gossiped blob: a settlement walk and a verify each, with no rate limit.
- `N` and `POOL_QUANTUM` are undiscoverable over RPC, so a runtime and a wallet built apart diverge silently, the chain refusing the proof after its cost is paid.
- The real-transfer count is public: a padding slot publishes zero commitments, which the chain needs to append correctly.
- One transfer per submission today: six slots, one filled, so 150908 bytes carries one transfer, about 22 KB each when full.

M7 is done: the proof of work is RandomX, so a Monero rig mines Qnero through the node's stratum port. M8 measured the browser prover and found the one number short: a phone has the memory and does not have the single-threaded clock. Queued next: wasm threads, which is the measured gap and needs a nightly toolchain and cross-origin isolation to try; then a device test to replace the 2 to 4 proxy factor; then real key storage, a keccak pin on the first tagged circuit release, and hiding the real-transfer count. Testnet targets: a proof per transaction under 105 KB or amortized below it, proving under 5 s on a laptop and under 60 s on a phone, no cryptographic component without a firm's review.

## Credits and licence

Qnero is MIT licensed (`LICENSE` at the repository root, DigitalGuards). The upstream copyright notices are kept where the licence requires them: `chain/LICENSE` for the chain fork and `crates/qnero-pqcrypto/LICENSE.hegemon` for the vendored crypto crate.

- **Upstream chain and circuits** (Quantus Network, MIT): `chain/` is a subtree of the upstream Substrate chain at `f1176ce`; its Poseidon tree, nullifier set and ML-DSA-87 accounts come as is, and its mixer pallet's verify flow is forked as `pallet-shielded`. Parts of `qnero-circuit` and `qnero-aggregator` derive from the upstream `qp-zk-circuits` at 4.4.0, and three more crates follow its equivalents in shape. All five carry a `NOTICE` and `CHANGES.md`; the layouts, padding rule and forwarding contract are Qnero's own.
- **Hegemon** (Pauli-Group/Hegemon, MIT): `qnero-pqcrypto` vendors its `crypto` crate at `b819911`, carrying its own `NOTICE` and `CHANGES.md`.
- **Plonky2** (Polygon lineage), through `qp-plonky2` and `qp-plonky2-verifier` at `=1.5.5`, with `qp-poseidon-core` 3.1.0 off circuit, tied to the in-circuit hash by `circuit_parity`. The upstream CLI was read while the wallet was written; no code was copied.

Design: `docs/DESIGN.md`. Circuit: `docs/CIRCUIT.md`.

Maintained by DigitalGuards at https://github.com/DigitalGuards/qnero.
