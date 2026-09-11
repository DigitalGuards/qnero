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

The chain default is N = 7, so one shielded transaction (the private batch the
wallet submits) costs about 4 s of proving on 20 threads and about 5 ms to
verify on chain. Verify time is flat in N, which is what makes recursion
worth it.

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

Not measured yet: the public batch at the chain default of 53 inner proofs.
The tests exercise it at 2 inner proofs over 2-leaf batches, which says nothing
useful about its cost at production size. Upstream's 53-batch number is about
21 s of proving on 20 threads, and the Qnero public batch is the same shape
with a wider forwarded region.

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
