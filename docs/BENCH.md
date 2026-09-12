# Wormhole baseline benchmarks (2026-09-11)

Measured on the dev workstation (20 threads, WSL2) with the unmodified
`qp-zk-circuits` at 7387fd8, criterion, 10 samples. These are the baseline
Qnero's shielded circuits will be compared against; the Qnero leaf will be
heavier (two Merkle paths, two note openings, range checks).

Run was stopped early because it saturated the workstation; the public-batch
verify series beyond n=8 is missing. Rerun with `RAYON_NUM_THREADS=4 nice -n
19` next time.

## Private batch (client side, ZK): prove N leaf slots into one proof

| N leaf slots | prove (mean) | verify (mean) |
|---:|---:|---:|
| 2 | 1.0 s | 3.9 ms |
| 4 | 2.2 s | 5.3 ms |
| 8 | 4.5 s | 5.6 ms |
| 9 | 4.1 s | 6.3 ms |
| 16 | 8.8 s | 8.0 ms |
| 25 | 8.9 s | 4.7 ms |
| 32 | 9.7 s | 6.3 ms |
| 36 | 18.6 s | 7.3 ms |
| 49 | 18.7 s | 6.6 ms |

These are M3 measurements at N = 7, which is where the aggregator was built and
timed. **The chain default is N = 6** (M4, see the degree-boundary note below
and `docs/CIRCUIT.md` section 9.1), so one shielded transaction (the private
batch the wallet submits) costs less than the N = 7 row and about 5 ms to
verify on chain. Verify time is flat in N, which is what makes recursion worth
it, and the runtime meters it with a wasm slowdown factor on top: the figures
here are native.

## Public batch (delegatable aggregator): n private batches of 7 leaves

| n private batches | prove (mean) | verify (mean) |
|---:|---:|---:|
| 2 | 1.1 s | 7.4 ms |
| 4 | 2.6 s | 5.4 ms |
| 8 | 5.1 s | 11.2 ms |
| 16 | 8.5 s | not measured |
| 32 | 21.0 s | not measured |
| 53 (chain default) | 21.3 s | not measured |

## Not measured

- Leaf prove time in ZK mode: the `qp-wormhole-prover` bench panics with
  `Cannot use zero_knowledge without rand feature`; the prover crate exposes
  no feature that enables it. Leaf proofs are non-ZK by design (the wallet
  aggregates them itself), so the private-batch numbers above are the user
  facing cost.
- Peak memory. Needed before deciding whether phones can prove; measure with
  `wormhole/memprof`.

# Qnero (2026-09-11)

Measured on the dev workstation (20 cores, WSL2) at M3, with
`RAYON_NUM_THREADS=4 nice -n 19 cargo test -j 2 --release`. Every timing, size
and gate count below is from an ignored test that prints its own `parallel`
flag and `RAYON_NUM_THREADS`, so a rerun says which configuration it measured:

```
cargo test -p qnero-prover  --release -- --ignored --nocapture
cargo test -p qnero-aggregator --release [--features parallel] --test bench -- --ignored --nocapture
```

The two peak-RSS rows are the exception: no test measures them. They come from
wrapping the private-batch bench run in `/usr/bin/time -v` and reading
`Maximum resident set size`, which covers the whole test process, the circuit
build included.

## Leaf: one shielded transfer, 2 in / 2 out

Single threaded. Plonky2's `parallel` feature is off by default so a wallet
cannot saturate a machine unasked.

| | |
|---|---|
| gates before padding | 320 |
| degree_bits | 9 |
| public inputs | 26 |
| zero knowledge | no |
| build | 64 ms |
| prove, mean of 9 | 183 ms |
| prove, min / median / max | 138 / 169 / 381 ms |
| verify | 2.2 ms |
| proof bytes | 105500 |

The spread is the measurement itself. The FRI challenge carries 16 grinding
bits and the search for them is a geometric random variable seeded by the
transcript, which dominates a circuit this small. Compare means over the same
sample count.

## Private batch: N = 7 leaf slots, one real transfer and six padding

This is the transaction a wallet submits, and the shape it submits most often.
Zero knowledge, so these numbers include row blinding. Mean of 3 proofs.

| | single threaded | `--features parallel`, `RAYON_NUM_THREADS=4` |
|---|---:|---:|
| build | 8.6 s | 4.7 s |
| prove, mean of 3 | 20.0 s | 6.4 s |
| prove, min / max | 19.8 / 20.4 s | 6.3 / 6.5 s |
| verify | 4.2 ms | 4.1 ms |
| peak RSS of the run | 1.82 GiB | 2.06 GiB |

| | |
|---|---|
| gates before padding | 24530 |
| degree_bits | 16 |
| padded gates | 65536 |
| public inputs | 152 |
| proof bytes | 157476 |
| verifier artifact | 1749 bytes |

Reading these:

- **Verify is flat and cheap.** 4.2 ms for a batch that settles up to seven
  transfers, against 2.2 ms for one leaf. That is the whole point of recursion,
  and it is what the chain pays.
- **Proof size is a property of the FRI config.** `N` barely moves it: 157 KB
  carries up to seven transfers, where Hegemon reports about 105 KB per
  transaction. At seven real transfers that is 22 KB each; at one real
  transfer it is worse than theirs, which is the cost of a fixed-size
  anonymity shape.
- **The recursive verifiers are the circuit.** 24324 of the 24530 gates are the
  seven recursive verifications; the wrapper's own constraints are 206 gates,
  including the `2N` pairwise nullifier comparisons. Nothing in the wrapper is
  worth optimizing.
- **`N = 7` sits just past a degree boundary.** Blinding adds about 9000 rows
  at this size, so a batch fits in `degree_bits = 15` only below about 23700
  gates, and seven recursive verifiers are 24324. Six leaves fit; seven do not,
  and pay 2x in proving time and about 2x in memory for it. **M4 shipped
  `N = 6`**: the halved wallet proving time and memory is the difference
  between a phone that can prove and one that cannot, and the slot it costs is
  amortized across a batch where the memory is paid by every user.
- **Phone-class memory.** About 2 GiB peak. Upstream's own guidance is that
  `degree_bits = 16` limits proving to 6 GB+ devices, which matches.

Not measured at M3: the public batch at the chain default of 53 inner proofs.
The tests exercise it at 2 inner proofs over 2-leaf batches, which says nothing
useful about its cost at production size. Upstream's 53-batch number is about
21 s of proving on 20 threads, and the Qnero public batch is the same shape
with a wider forwarded region. M5 measured it: 29 s on four threads, and the
M5 section below carries the rest.

## M4: the artifact set a runtime embeds (2026-09-12)

`chain/pallets/shielded`'s build script generates the whole set on every clean
build of the pallet, so this is a build cost every contributor pays once and CI
pays per cache miss. Measured at the chain defaults with
`RAYON_NUM_THREADS=4 nice -n 19`, plonky2's `parallel` feature off, wrapping the
builder in `/usr/bin/time -v`:

| | `N = 6`, `n = 53` |
|---|---:|
| wall clock, generation only | 52.6 s |
| wall clock, including the builder's own compile | 71.7 s |
| peak RSS | 5.4 GiB |
| `leaf_verifier.bin` | 1609 bytes |
| `padding_leaf_proof.bin` | 105500 bytes |
| `private_batch_verifier.bin` | 1749 bytes |
| `public_batch_verifier.bin` | 1905 bytes |

`padding_private_batch_proof.bin` is not generated for a runtime: it is an input
a public-batch *prover* needs, and proving it costs a full recursive run.

This is the first time the public batch has been built at `n = 53`. It is still
not *timed* at that size: the builder writes a verifier, which needs the circuit
built but no proof produced. The pallet's weight for a public-batch verify is a
ceiling chosen to be wrong in the safe direction, and `chain/pallets/shielded/src/weights.rs`
says so at the constant.

### Proof size against the pallet's size gate

`pallet-shielded` refuses a settlement blob above `MAX_PROOF_BYTES`, 512 KiB,
before it is copied or parsed.

| proof | serialized bytes | source |
|---|---:|---|
| private batch, `N = 6` | 157476 | measured at M3, asserted against the cap by `a_real_private_batch_settles_end_to_end` |
| public batch, `n = 53`, `N = 6` | 237544 | measured at M5, see below |

The private batch is the half a test covers: the end-to-end test proves one at
the chain's `N` and asserts its length against the cap, so a circuit change that
pushed it past 512 KiB fails in the test suite first. The public batch figure
was an estimate at M4 and is a measurement at M5: 237544 bytes, against an
estimate of about 213000 built from a 157 KB recursive proof plus
`public_batch_pi_len(53, 6) = 6947` public-input felts at eight bytes. The
estimate was 10 percent low and the margin against the cap is 2.2x. Nothing
enforces it in a test that runs by default: producing the proof is a minute of
CPU and about ten gigabytes of peak memory, so the measurement is an ignored
test. A circuit change that grew a public batch past 512 KiB would refuse every
public-batch settlement with `ProofTooLarge` and no default test would say so
first. The M5 section below has the whole measurement.

## M5: the wallet, and the public batch at `n = 53` (2026-09-12)

Same development workstation (20 cores, WSL2). Everything below was measured
with `RAYON_NUM_THREADS=4 nice -n 19` and the crate's `parallel` feature on,
against a `--dev --tmp` node that was producing about one block a second.

### What a wallet pays per transaction

`qnero-wallet send`, at the chain's `N = 6`, one real transfer and five padding
slots. Every figure below is the range over the **two payments** of the
end-to-end run in `docs/OPS-DEV.md`, and a two-sample range is exactly what it
looks like: a wider sample would widen it, and the block time the node happens
to be running at moves the inclusion term on its own.

| | `--features parallel`, `RAYON_NUM_THREADS=4` (2 samples) |
|---|---:|
| leaf + private batch circuit build, once per process | 2.37 to 2.38 s |
| private batch prove | 3.44 to 3.58 s |
| private batch proof | 150908 bytes |
| submit to inclusion | 1.04 s |
| whole `send` command, wall clock | 7.06 to 7.22 s |

An earlier revision of this table published 6.4 s of wall clock, a 0.5 to 1.6 s
inclusion range and a 3.3 to 3.5 s proving range, none of which the transcript
it cited supported. The numbers above are the transcript's own, and the
inclusion term is the one to distrust: it is the wait for a block, so it is a
property of the chain.

The M5 review fix pass re-ran the same two payments on the same workstation,
after memo padding took each output ciphertext from 1731 and 1743 bytes to a
uniform 1987. Circuit build 2.42 and 2.45 s, proving 3.58 and 3.61 s, proof
150908 bytes unchanged, submit to inclusion 0.54 and 1.54 s, wall clock 6.74
and 7.81 s. The padding costs one quantum of fee per spend at the runtime's
`CiphertextBytesPerFeeQuantum` of 512: the floor moved from 8 quanta to 9. It
buys a chain that publishes no memo length and no marker for which output is
the sender's change; `docs/WALLET.md` has the argument.

The proof is 150908 bytes at `N = 6`, where M3 measured 157476 at `N = 7`: a
recursive proof's size moves a little with the number of inner verifications
and mostly with the FRI config.

Proving is about 3.5 s where M3 measured 6.4 s for `N = 7`. That is the halving
M4 bought when it chose six slots: seven recursive verifiers are 24324 gates
and do not fit `degree_bits = 15` once blinding adds its rows, six do.

The local Merkle rebuild a spend now does, in place of asking the node for a
proof of each input leaf, is invisible at this resolution: at the dev chain's
tree size it is one `state_queryStorageAt` of at most 256 keys plus a Poseidon2
fold of the whole tree. It is `O(leaf_count)` and it will show on a long chain;
`docs/WALLET.md` open issue 7 records that.

### The public batch at the chain default

**This is the M4 open item, and it is now measured, verified through the
pallet's embedded verifier, and settled on a dev chain.** The shape is the one
`docs/CIRCUIT.md` section 9.1 describes: `n = 53` inner private batches of
`N = 6` leaf slots, one real inner carrying one real transfer and 52 padding
inners. `crates/qnero-wallet/tests/public_batch_bench.rs` is the measurement
and `a_real_public_batch_verifies_through_the_embedded_verifier` in
`chain/pallets/shielded/src/tests.rs` is the verify.

| | `n = 53`, `N = 6` |
|---|---:|
| public batch circuit build | 28.4 to 28.9 s |
| public batch prove | 28.9 to 29.9 s |
| proof | **237544 bytes** |
| public inputs | 6947 felts |
| native verify, warm | 5.6 ms |
| native verify, first in the process | 156 ms |
| `validate_public_batch` in the pallet, native | **6.04 ms** (5.86 ms on a re-run) |
| `submit_public_batch` extrinsic | 241027 bytes |
| peak RSS of the whole measurement process | 9.50 GiB |

Three numbers are worth reading closely.

- **237544 bytes against a 512 KiB gate.** `docs/BENCH.md` estimated about
  213000 and `MAX_PROOF_BYTES` is 524288, so the estimate was 10 percent low
  and the margin is 2.2x. Nothing enforces it: the end-to-end test asserts the
  *private* batch against the cap, and the public batch is now measured once.
  A circuit change that grew a proof by 2.2x would refuse every public-batch
  settlement with `ProofTooLarge` and no test would say so first.
- **6.04 ms to verify on chain, against 4.2 ms for a private batch.** Verify is
  flat in what a proof wraps, which is the whole reason recursion is worth its
  proving cost: 53 inner batches of up to 6 transfers each settle for about the
  price of verifying one. The figure is native; a wasm runtime pays a multiple
  of it, and `chain/pallets/shielded/src/weights.rs` says why its declared
  weight is a ceiling.
- **The first verify in a process is 156 ms and every one after it is 5.6 ms.**
  Measured three times in a row in the proving process, which is holding about
  9.5 GiB of circuit data at that point. The pallet's own 6.04 ms agrees with
  the warm figure, so the cold number is first-touch cost in a large heap and
  says nothing about what a node pays.

Peak RSS is the whole measurement process: the wallet's leaf and private-batch
circuits, the public-batch circuit, and one proving run of each. An aggregator
that only ever proves public batches would peak lower; nothing here separates
the terms.

The anchor window is the operational constraint, and it is tighter than the
proving cost suggests. A segment must name a block inside `BlockHashWindow`,
256 blocks, and everything from taking the anchor to inclusion has to fit
inside it: at `n = 53` that is about 33 s of proving on top of the inner
batch's 3.4 s. The measurement builds every circuit before it takes an anchor,
which is what keeps the 28 s build out of the window. An aggregator collecting
inners from wallets has less room: its participants' anchors are already older
when they arrive.
