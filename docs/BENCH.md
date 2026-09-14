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
| private batch, `N = 6` | 150908 | measured at M5, asserted against the cap by `a_real_private_batch_settles_end_to_end` |
| private batch, `N = 7` | 157476 | measured at M3, which is where the aggregator was timed |
| public batch, `n = 53`, `N = 6` | 237544 | measured at M5, see below |

The private batch is the half a test covers: the end-to-end test proves one at
the chain's `N` and asserts its length against the cap, so a circuit change that
pushed it past 512 KiB fails in the test suite first. The public batch figure
was an estimate at M4 and is a measurement at M5: 237544 bytes, against an
estimate of about 213000 built from the 157 KB `N = 7` recursive proof plus
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
and 7.81 s. The padding buys a chain that publishes no memo length and no
marker for which output is the sender's change; `docs/WALLET.md` has the
argument.

The second review fix pass re-ran them again, with the memo pad cut from 256
bytes to 61. The fee is what bounds the pad, ahead of
`MaxCiphertextBytes`: `CiphertextBytesPerFeeQuantum` (512) is sized so that a
real ciphertext pair and a pair padded to the cap fall in different buckets,
and a 256-byte pad put `2 * (1731 + 256) = 3974` in the cap's own bucket, which
let a settler pad to the cap and write 512 bytes of permanent state per slot
for the same fee an honest spend pays. At 61 each output is 1792 bytes, the
pair is 3584, and the floor is back to 8 quanta where the unpadded wallet paid
8 and the 256-padded one paid 9. Circuit build 2.31 and 2.38 s, proving 3.34
and 3.51 s, proof 150908 bytes unchanged, submit to inclusion 0.53 s both
times, wall clock 6.47 and 6.56 s. Nothing in the proving path moved: the
ciphertext rides in the extrinsic, and only its `ct_digest` reaches the
circuit.

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

# M7: RandomX proof of work (2026-09-13)

Measured on the dev workstation (AMD Ryzen AI 9 365, 10C/20T, 23.5 GB, WSL2)
against the M7 node at `--dev --tmp`. Everything the node does is RandomX
**light mode**; xmrig builds the full dataset, which is the gap in the first
table.

## Hash rate

| | mode | memory | threads | rate |
|---|---|---|---:|---:|
| node, in process | light (cache only) | 256 MiB + 2 MiB per VM | 1 | **32.9 H/s** |
| node, verification | light (cache only) | shared with the above | 1 | ~30 ms per block verified |
| xmrig 6.21.3 | full (dataset) | 2336 MiB (2080 + 256) | 2 | ~40 shares/s at difficulty 175, so roughly **3.5 kH/s** |

The node is about two orders of magnitude slower per thread than the rig, and
that is the intended shape: the node hashes once per block it verifies and once
per share it is offered, so a 2 GiB dataset would cost more memory than the
rest of the node for nothing. A rig pays the dataset once and gets it back
immediately.

Fixed costs measured alongside:

- **Argon2d cache fill: 372 ms**, once per seed epoch, 256 MiB. The node holds
  two caches so a block that straddles an epoch boundary, or a reorg across
  one, verifies without paying it again.
- **xmrig dataset build: 3809 ms** with 20 threads, 2080 MiB. This is what
  `next_seed_hash` in every job exists to hide: a rig that is told the next
  seed in advance builds the next dataset in the background instead of
  stalling for four seconds at the boundary.

## Dev-chain block time

`--dev --tmp --mining-threads 1`, genesis difficulty 128 (the pallet's floor):

| | value |
|---|---|
| blocks #1 to #14, in process only | 56 s, **4.3 s per block** |
| difficulty at #1 | 128 |
| difficulty at #66 | 189 |
| blocks in the run | 66 in 3 m 48 s, 50 mined in process and 14 by xmrig |

4.3 s against a 12 s target is the retarget climbing: at 32.9 H/s a difficulty
of 128 is about four seconds, so the chain runs fast and the difficulty rises
one step per block. The step is one because integer division rounds
`difficulty / 2048` to zero below 2048, and M7 floored the increment at one so
a chain that reaches the difficulty floor can leave it again.

With xmrig attached the same chain produced blocks as fast as the node could
build templates, which is what a 3.5 kH/s rig against a difficulty of 175
means: the proof of work stopped being the constraint and block building became
one.

# M8: the prover budget on a phone-class device (2026-09-14)

The milestone question is whether a wallet can prove its own transaction on a
phone. This section answers it with two columns out of one crate,
`crates/qnero-prover-wasm`, compiled once for this box and once for
`wasm32-unknown-unknown` and run in headless Chromium.

The two columns share the crate, the code path and the fixture seeds, and they
differ in three things worth naming before any row is read. The native column
builds the circuits once and proves nine times in one warm process. The browser
column launches a browser per run, instantiates a fresh module and proves once.
And on both sides every `prepare` draws a fresh randomized dummy input and
fresh KEM randomness, so no two proofs in either column are quite the same
work. The seeds are the ones `www/worker.js` holds fixed, and the native bench
pins `request(0x31)` to that same pair.

The request is one real input note and a randomized dummy in the second input
slot, two outputs, on a three-leaf tree, one level deep at arity 4. It costs
what a genuine two-note spend against a full tree costs: both input slots are
always present in the circuit, `merkle_root_from_path` evaluates all
`MAX_DEPTH = 16` levels for each of them whatever the witness holds
(`crates/qnero-circuit/src/merkle.rs`), and the witness fills every level for
the dummy too. A leaf that proved faster with one input would publish how many
notes it spent.

## Where each figure came from

Four invocations of the harness runner, one browser at a time, the browser
closed between runs. Every table below names the invocation it came from,
because stage timings from two invocations are two measurements. All four ran
against the harness exactly as committed here, and the runner writes one
results file per invocation shape and no fixed name, so every row traces to a
file under `www/results/` (gitignored, regenerated by rerunning the row's
invocation).

| run | invocation, from `crates/qnero-prover-wasm/www` | what it is for |
|---|---|---|
| **A** | `node run.mjs --runs 9 --mode source --no-zk` | the per-payment figures, the peak, the cold start |
| **B** | `node run.mjs --runs 3 --mode artifacts --no-zk` | the fetch, and the build with the padding leaf supplied |
| **C** | `node run.mjs --runs 3 --zk-only` | the ZK leaf in a worker that builds nothing else |
| **D** | `node run.mjs --runs 1 --mode source --no-zk --n 7` | seven leaf slots |

The file names follow the invocation,
`wasm-measurement-<mode>-n<N>-<zk|nozk|zkonly>-x<runs>.json`, so run A wrote
`wasm-measurement-source-n6-nozk-x9.json` and run D wrote
`wasm-measurement-source-n7-nozk-x1.json`, each beside a `runs-<tag>.json` with
every sample and a `private_batch-<tag>.proof` the acceptance gate reads.

The native column is one invocation:

```
RAYON_NUM_THREADS=1 nice -n 19 cargo test -j 2 --release \
  -p qnero-prover-wasm --test native_bench -- --ignored --nocapture --test-threads 1
```

Nine samples natively and nine in run A, because of the leaf. Its FRI challenge
carries 16 grinding bits, the search for them is a geometric random variable,
and the witness moves under it on every run, so a leaf prove is a draw. Nine
draws pin its mean to about 7 percent on each side (native mean 180.5 ms with a
standard error of 12.4 ms, run A 763.5 ms with a standard error of 57.9 ms),
which is why the leaf's wasm ratio below is published as a range while the two
heavy stages are point figures. Both harnesses print a standard error beside
every row for exactly this reason. An earlier revision of this section derived
a leaf ratio from three samples and published 2.06x, and three samples put this
stage anywhere in a 2x spread.

Both columns ran on the dev workstation (AMD Ryzen AI 9 365, 10C/20T, WSL2)
with `nice -n 19`, plonky2's `parallel` feature off everywhere below the crate.

## The phone proxy, stated

**There is no phone in these numbers.** This box has no aarch64 cross toolchain
and no qemu, so a phone CPU is out of reach and the single-threaded wasm run in
headless Chromium is the proxy. The wasm column is read by multiplying it by
**2 to 4**, and that range has a basis for its low end only:

- The low end is a published peak single-core score ratio. This box's CPU
  scores about 2,800 in Geekbench 6 single core; a mid-range phone SoC of the
  generation a wallet has to work on, the Snapdragon 7 Gen 3, scores about
  1,150. That is 2.4x.
- Two effects are absent from that ratio and both push the true factor up. A
  phone running 30 to 130 seconds of flat-out single-core wasm throttles, and a
  burst benchmark is measured before throttling starts, so a sustained workload
  costs more than the score ratio says. And a mobile browser's wasm tier-up and
  memory policy are not desktop V8's, with iOS on a different engine entirely.
- Geekbench is also not this workload. Proving here is Poseidon2 over
  Goldilocks and memory traffic through a 2^18-row low-degree extension, and
  nothing says a phone's ratio on that mix matches its ratio on a mixed suite.

So **2 to 4 is a floor**. The true factor can sit above it and nothing here
bounds it from above, which makes it the widest source of error in everything
below. A device test is what replaces it.

## Native, single threaded, `N = 6`

Nine samples per row, one warm process.

| | mean | stderr | median | min | max |
|---|---:|---:|---:|---:|---:|
| leaf + private batch circuit build, once per process | | | 4.26 s | one sample | |
| leaf prove, non-ZK | 180.5 ms | 12.4 ms | 173.6 ms | 136.7 ms | 265.7 ms |
| private batch prove | 9.83 s | 21.5 ms | 9.82 s | 9.74 s | 9.95 s |
| private batch verify | 3.7 ms | 0.0 ms | 3.7 ms | 3.7 ms | 3.8 ms |

Proof 150908 bytes, leaf `degree_bits` 9, private batch `degree_bits` 15, which
matches M5's figures at four threads scaled by the threading factor M3
measured. The leaf's 129 ms spread is the grind; the batch holds to 2 percent.

The verify row times `verify` and nothing else. `verify` consumes the proof and
the proof is needed afterwards for its bytes, so a copy has to be made, and
`batch_verifier_data()` clones the common circuit data on every call; both
copies are made before the clock starts. An earlier revision of this section
timed them inside it and published 4.1 ms here.

## wasm32, single threaded, headless Chromium 149

Chrome for Testing 149.0.7827.55 from the Playwright cache, launched with
`--js-flags=--wasm-max-mem-pages=32768`, so the run states the ceiling it
passed under: **2 GiB**. Served over `http://localhost` with COOP and COEP set,
so the page is cross-origin isolated and a later threads experiment needs no
different server. All proving happens in a dedicated Worker.

Run A, nine samples per row.

| | mean | stderr | median | min | max |
|---|---:|---:|---:|---:|---:|
| module fetch, compile and instantiate | 22.2 ms | 0.8 ms | 21.7 ms | 18.7 ms | 26.2 ms |
| entropy self check | | | 0.6 ms | | |
| circuit build from source | 12.16 s | 50 ms | 12.11 s | 11.97 s | 12.50 s |
| build the request | | | 3.1 ms | | |
| leaf prove, non-ZK | 763.5 ms | 57.9 ms | 738.6 ms | 539.9 ms | 1105.6 ms |
| private batch prove | 32.84 s | 59 ms | 32.83 s | 32.57 s | 33.10 s |
| private batch verify, first in a fresh module | 20.7 ms | 0.2 ms | 20.5 ms | 19.7 ms | 21.8 ms |
| private batch verify, warm | 14.1 ms | 0.1 ms | 14.1 ms | 14.0 ms | 14.5 ms |
| whole `proveTransfer` call | 33.63 s | 55 ms | 33.59 s | 33.44 s | 33.92 s |
| linear memory after module init | | | 8.2 MiB | | |
| **peak linear memory** | | | **910.4 MiB** | 910.4 MiB | 910.4 MiB |

Two verify rows, because a module's first verify and its second differ by 6 ms,
and what differs between them is V8's state. The first is the
`private_batch_verify` phase inside `proveTransfer`, which is the first time
that code runs in a freshly instantiated module. The second is the harness's
own `prover.verifyProof` call right afterwards, timed the same way with
deserialization outside the clock. Natively those two are both 3.7 ms and there
is no gap. **14.1 ms is the figure to size a wallet-side verify budget with**,
and 20.5 ms is what a cold module charges for the first one.

The peak was byte-identical across all nine runs (954597376 bytes), which is
what a deterministic circuit over a fixed witness shape should do. The module
is 3069517 bytes uncompressed, with no `wasm-opt` pass. The 22 ms init is a
loopback fetch plus compile and instantiate, so it prices the compile and says
nothing about three megabytes crossing a mobile network.

Run B, three samples, for the two rows that need an artifact set.

| | median | min | max |
|---|---:|---:|---:|
| fetch of the set, 107109 bytes | 8.2 ms | 7.9 ms | 9.8 ms |
| circuit build from that set | 11.70 s | 11.68 s | 12.01 s |
| peak linear memory | 909.9 MiB | | |

A browser wallet therefore pays **12.1 s once per worker and 33.6 s per
payment**, and 45.7 s for the first payment after a cold start, that last
figure being module init plus circuit build plus request plus proof over
loopback.

## The wasm penalty, by stage

Native against run A, medians, except the leaf, which is compared by mean over
nine samples on each side for the sampling reason above. The ZK leaf rows are
run C against the native ZK leaf test.

| stage | native | wasm | ratio |
|---|---:|---:|---:|
| circuit build from source | 4.26 s | 12.11 s | 2.84x |
| leaf prove, non-ZK (means) | 180.5 ms | 763.5 ms | about 4x, see below |
| private batch prove | 9.82 s | 32.83 s | 3.34x |
| private batch verify, warm | 3.7 ms | 14.1 ms | 3.81x |
| private batch verify, first in a fresh module | 3.7 ms | 20.5 ms | 5.54x |
| ZK leaf build | 2.27 s | 6.78 s | 3.00x |
| ZK leaf prove | 4.75 s | 16.64 s | 3.51x |

The leaf ratio is 4.23x as a point estimate and this sample pins it no better
than **3.8 to 4.7x** at one standard error on each mean. Independent 9-sample
native means of that same stage have landed at 177.2 ms, 180.5 ms, 183 ms (the
M5 section at the top of this file) and 211.4 ms, which widens the honest range
to about **3.4 to 4.7x**. Quote it as a range. The two heavy stages reproduce
to within 1 percent between invocations and keep their precision.

Everything else sits between 2.8x and 3.6x, which is where the two proving
stages and both circuit builds land. The verify rows are the outliers and the
least interesting ones: 14 ms is 14 ms, and the first-verify row is measuring
V8 tier-up on code that runs once. Neither is the measurement
`WASM_VERIFY_FACTOR = 5` wants (`chain/pallets/shielded/src/weights.rs`). That
constant multiplies a verify weight the runtime meters under its own wasmtime
executor, and these figures are V8 in a browser, a different engine over a
different workload. The constant stays unmeasured, and M5 still owes the
in-runtime measurement `docs/CIRCUIT.md` section 9.11 names.

## The zero-knowledge leaf

A ZK leaf is the artifact a phone could hand to somebody else's batcher, so
what it costs decides whether that path is worth designing. Run C measures it
in a worker that builds nothing else, which is the only run whose memory figure
means anything for a leaf-only prover: linear memory never shrinks, so in a
normal run the module's high-water mark is the private-batch circuit's and it
says nothing about the leaf.

| | native | wasm (run C) |
|---|---:|---:|
| build | 2.27 s (2.26 to 2.45) | 6.78 s (6.77 to 6.81) |
| prove | 4.75 s (4.67 to 4.85) | 16.64 s (16.45 to 16.69) |
| build plus prove, cold worker | 7.01 s | 23.4 s |
| proof bytes | 150932 | 150932 |
| `degree_bits` | 14 | 14 |
| peak linear memory | | 510.9 MiB |

Three numbers in that table decide the delegation question.

- **Blinding takes the leaf from `degree_bits` 9 to 14.** That is 32x the rows
  before anything is proved, and it is why a ZK leaf costs 16.6 s in wasm
  where the non-ZK leaf costs 0.76 s. The leaf is cheap because it does not
  blind; blinding is what the private batch already pays for, one layer up.
- **A ZK leaf is 150932 bytes and a whole private batch is 150908.** The leaf
  carrying one transfer is 24 bytes *larger* than the batch that settles up to
  six. Proof size here is a property of the FRI config, so delegating uploads
  the same bytes and buys the batcher's recursion with them.
- **A leaf-only prover still needs 511 MiB.** Delegation saves 44 percent of
  the peak, and a device that cannot hold 910 MiB is unlikely to be comfortable
  with 511 MiB plus a renderer either.

So the trade is 16.6 s of local work against 33.6 s, a 2.0x saving, for an
upload of the same size. A delegating wallet also builds its own ZK leaf
circuit per worker, so its first payment after a cold start is 23.4 s of wasm.
Section 8 of `docs/DESIGN.md` prices what that saving costs in privacy.

## Fetching the artifact set buys almost nothing

The artifact set removes exactly one padding-leaf prove from the build, and
these tables measure a wasm leaf prove at 0.54 to 1.18 s. Differencing the two
invocations' build medians gives 0.41 s (12.11 s in run A against 11.70 s in
run B), which sits inside the build stage's own spread on both sides. The
mechanism is the stable estimate and it agrees with the difference: **under a
second off a 12.1 s build**, 3 to 6 percent. Against that it adds a fetch, a
cache, a pinning step and a way for a wallet to be serving proofs against the
wrong `N`. `leaf_verifier.bin` saves nothing at all, because the loader pins it
to a canonical rebuild and then uses the rebuild.

The browser prover therefore defaults to building from source and fetching
nothing, and the harness keeps the artifact path only so this row exists.

## Seven slots, measured

M4 chose `N = 6`, and `docs/CIRCUIT.md` section 9.1 argued it against seven as
"the difference between a phone that can prove and one that cannot" on an
estimate. Run D measures seven on the same browser, at the same ceiling.

| | `N = 6` (run A) | `N = 7` (run D) |
|---|---:|---:|
| private batch `degree_bits` | 15 | 16 |
| circuit build from source | 12.11 s | 23.62 s |
| private batch prove | 32.83 s | 65.84 s |
| peak linear memory | 910.4 MiB | 1765.4 MiB |
| proof bytes | 150908 | 157476 |

Seven slots cost 2.01x the proving time and 1.94x the peak, for 4 percent more
proof carrying one more settlement.

Two things follow, and the second corrects what an earlier revision of this
section said. Seven slots do fit this browser: 1.72 GiB passed under the same
2 GiB ceiling the measurement pins, at 86 percent of it, so the claim that
`N = 7` would land over that ceiling was wrong. What seven slots do not fit is
a phone. 65.8 s of wasm is 132 to 263 s per payment at the stated factor, and
1.72 GiB of linear memory that never shrinks, inside a renderer with its own
footprint, is where a 4 GB Android device meets the OOM killer and where iOS
reclaims the tab. Section 9.1's sentence holds as a statement about phones, and
the margin `N = 6` buys is 1.9x of peak memory and half the clock.

## What this means against the design's targets

The target is proving under 60 s on a phone. Reading runs A and C through the
stated 2 to 4 factor, which is a floor:

| | wasm measured | phone at 2x | phone at 3x | phone at 4x |
|---|---:|---:|---:|---:|
| one payment (`proveTransfer`) | 33.6 s | 67 s | 101 s | 134 s |
| circuit build, once per worker | 12.1 s | 24 s | 36 s | 48 s |
| first payment after a cold start | 45.7 s | 91 s | 137 s | 183 s |
| ZK leaf alone, per payment | 16.6 s | 33 s | 50 s | 66 s |
| first ZK leaf after a cold start | 23.4 s | 47 s | 70 s | 94 s |

**A phone misses the 60 s target on a single thread, at every point of the
range.** The most optimistic reading puts one payment at 67 s, and that is
before the first-payment circuit build. The ZK leaf alone fits at 2x and 3x
once its worker is warm, and its own cold start fits at 2x only.

Memory is the part that came in comfortably. 910.4 MiB peak against the 2 GiB
ceiling this run pinned, and against the 4 GiB a 32-bit linear memory can
address at all: 44 percent of the ceiling and 22 percent of the address space.
It leaves room. A 6 GB or 8 GB Android device has it, a 3 GB or 4 GB device is
marginal once the renderer's own footprint is counted, and iOS Safari polices
per-tab memory hard enough that the failure there is a reloaded tab with no
catchable error. Note that linear memory never shrinks, so the 910 MiB is
sticky for the life of the worker and a second prover would add its own.

## The anchor window is not the constraint here

A segment must name a block inside `BlockHashWindow`, 256 blocks, which at the
12 s target is about 51 minutes. A browser payment is 45.7 s cold and 33.6 s
warm, so the window has room to spare even at 4x. The ordering still matters:
the harness builds every circuit before it takes an anchor, and a wallet that
anchored first would spend a third of a browser payment on work that has
nothing to do with the anchor.

## Acceptance: the browser's proof verifies natively

The proof the browser produced was written out and verified on this box
against `private_batch_verifier.bin`, the same artifact a runtime embeds. Both
the source-built proof (run A) and the artifact-built one (run B) pass:

```
QNERO_WASM_PROOF=<abs>/www/results/private_batch-source-n6-nozk-x9.proof \
QNERO_ARTIFACT_DIR=<abs>/www/artifacts \
  cargo test -p qnero-prover-wasm --release --test wasm_proof -- --ignored --nocapture
```

150908 bytes, 6 slots, 1 real, 131 public-input felts, under the 512 KiB
`MAX_PROOF_BYTES` gate. The circuits are deterministic and no floating point is
involved, so this is the check that the two builds did not diverge in their
feature graph, which is the failure a `zk` flag or a plonky2 version skew would
produce. The proof file name carries the mode, the `N` and the run count it was
proved at, because this gate's only failure message is that the proof did not
verify: run D's seven-slot proof handed to a six-slot verifier fails the same
way a feature-graph divergence would, so the test names the slot count in its
panic and the runner writes no fixed-name file for a stale run to occupy.

## What is still unmeasured

- **A phone.** The 2 to 4 factor is a floor with a peak-clock ratio under it. A
  device test on a mid-range Android and on an iPhone is what replaces it, and
  the iOS answer may be that the tab is reclaimed before it finishes.
- **Threads.** ~~The single-threaded wasm number is the one that misses the
  target, and M3 measured about 3.1x from four native threads. Whether
  wasm threads deliver that is unmeasured.~~ **Measured at M10: 3.36x from
  four threads, at the same peak memory.** See the M10 section.
- **The module over a real network.** The cold-start figure covers init,
  circuit build and one payment over loopback. Three megabytes uncompressed, no
  `wasm-opt` pass, and no measurement of what that costs on a mobile link or of
  what a service worker holding it would save.
- **`wasm-opt`.** ~~Neither the size nor the speed after a `wasm-opt -O` pass
  is known.~~ **Sized at M10:** 18% of the raw single-threaded module and 49%
  of the threaded one, 3% and 10% compressed. The speed effect is still
  unmeasured, and both shipped modules have been through the pass since, so
  every browser figure in the M10 section is an optimised one.
- **Scanning at chain scale.** `decryptNote` is measured only as part of the
  round-trip test. A wallet scanning thousands of ciphertexts per sync is a
  different budget and nothing here bounds it.

# M10: the browser wallet, threaded and single threaded (2026-09-14)

M8 measured one browser prover on one thread and left three things unmeasured
by name: threads, `wasm-opt`, and what a payment costs end to end rather than
in a harness. M10 is a wallet rather than a harness, so all three are measured
here the way a person would meet them: in `wallet-web`'s own Playwright suite,
against a `--dev --tmp` node mining on the same box, from pressing Send to a
settled block.

That last clause is why these numbers are not directly comparable with M8's.
The harness ran alone; this runs beside a RandomX miner at one thread, a
Substrate node, a preview server and the test runner, on the same workstation.
The single-threaded row is 37.6 s where M8's harness measured 32.8 s, and the
difference is the rest of the machine.

## One payment, in the wallet

Two invocations of one suite, each against its own fresh chain, one browser at
a time:

```
cd wallet-web
nice -n 19 npx playwright test                      # the threaded module
QNERO_PROVER=single nice -n 19 npx playwright test  # the single-threaded one
```

`?prover=single` is what the second one sets. The preview origin is
cross-origin isolated either way, so the difference is the module and the pool
rather than the headers.

| | threaded, 4 threads | single threaded | ratio |
|---|---|---|---|
| `proveTransfer` (leaf, private batch, verify) | **11.2 s** | **37.6 s** | 3.36x |
| Send pressed to settled block | 24.6 s | 53.4 s | 2.17x |
| Peak linear memory | 917.6 MiB | 910.2 MiB | 1.01x |
| Proof | 150,908 bytes | 150,908 bytes | 1.00x |

The pool is `min(navigator.hardwareConcurrency, 4)`, and this box reports 20,
so the threaded column is four threads.

**Threads deliver what M3 measured natively.** The open question M8 left was
whether wasm threads reach the 3.1x that four native threads bought. They
reach 3.36x, and the extra is the miner's contention falling on the serial run
harder than on the parallel one rather than a claim that wasm threads beat
native ones.

**The memory did not move.** 917.6 MiB against 910.2 MiB. Four threads share
one linear memory and each reserves an 8 MiB stack, which is what the 7 MiB is.
A threaded prover is not a memory tradeoff at this size, which is the answer
that matters for a phone: M8's peak stands.

**What the other 13 seconds are.** The whole-send figure carries the circuit
build (about 4.5 s threaded), the anchor read and its header check, a local
rebuild of the whole commitment tree, the submission, and the wait for a block.
A dev chain at a 12 s target block time contributes most of the remainder, and
it is the one part a faster prover cannot shorten. It is also the noisiest
figure here: repeat runs of the threaded row landed at 19.6 s and 24.6 s,
because where the settlement falls inside a block interval is luck. The
proving time moves too, by more than this paragraph first claimed. See the
re-measurement below.

## What a second payment costs, and why it used to cost a gigabyte

The table above is one payment in a fresh tab, which is what the suite
measures. A wallet is not used that way, and the second payment was where the
cost was.

The circuits were rebuilt from source on every send. The new set was built
while the old one was still referenced, wasm linear memory never shrinks, and
wasm-bindgen releases a replaced handle only at the next garbage collection,
so every payment added its own quarter gigabyte permanently. Measured in
headless Chromium against the committed threaded module, doing what the send
path does three times in one module:

| payment | linear memory after | growth |
|---|---|---|
| 1 | 918.1 MiB | |
| 2 | 1,175.5 MiB | +257.4 MiB |
| 3 | 1,432.8 MiB | +257.3 MiB |

Three payments in one tab sat at 1.4 GB and climbing, and each of them also
paid about 4.5 s of circuit build it did not need. A build-only loop gave the
same slope, 481.1 to 735.9 to 990.9 MiB, which is what identifies the build
rather than the proof as the term that grows.

The worker answers the build from cache after the first one, so the figure is
now flat: the M10 rows re-measured after the fix read 11.8 s and 918.4 MiB
threaded, 39.7 s and 910.2 MiB single threaded, which is the same peak within
this suite's noise. Terminating the worker is the only thing that gives the
memory back and the settings screen offers it by name.

## The same suite, re-run, and what the clock is worth

Three further runs of the same suite on the same workstation on 2026-09-14,
after the fixes above, with other sessions using the box:

| run | `proveTransfer` | Send to settled | peak |
|---|---|---|---|
| threaded | 27.2 s | 71.5 s | 917.8 MiB |
| threaded | 23.2 s | 37.5 s | 917.8 MiB |
| single threaded | 67.0 s | 104.0 s | 910.2 MiB |

Two things reproduce exactly and one does not, and the split is the useful
part of this table.

**The module facts reproduce.** Peak linear memory lands within a fifth of a
MiB of the M10 table (917.8 against 917.6 threaded, 910.2 against 910.2
single), and the proof is 150,908 bytes in every run ever measured. Those are
properties of the circuits and the module, so they travel.

**The ratio survives.** 67.0 s against a 25.2 s threaded mean is 2.66x, where
the table measured 3.36x. Four threads buy most of what they bought before,
and the gap between the two figures is contention falling on the two runs
differently.

**The seconds are the machine's, on the day.** Both rows came out about 1.8x
slower than the table, which measured the same modules through the same suite.
A laptop part under sustained load and a workstation with other work on it are
the whole difference. Read the absolute figures as a band of roughly 11 s to
27 s threaded and 38 s to 67 s single threaded on this class of machine, and
read the M8 phone floor of 2x to 4x on top of the band's upper half rather
than its lower one: a payment on a phone is minutes, which is what the M8
finding said and what the threaded module has not changed.

## After the review fixes (2026-09-14)

The same suite again on the same workstation, against the code the review
fixes landed, on a dev chain the suite now puts on a port of its own:

| run | `proveTransfer` | Send to settled | peak |
|---|---|---|---|
| threaded | 13.3 s | 21.6 s | 918.1 MiB |
| threaded | 11.9 s | 25.6 s | 917.7 MiB |
| threaded | 11.6 s | 23.6 s | 917.9 MiB |
| single threaded | 36.0 s | 55.4 s | 910.2 MiB |

**The module facts reproduce for a fourth sitting.** Peak lands inside half a
MiB of every figure above it and the proof is 150,908 bytes again.

**The clock came back to the fast end of the band.** These three threaded runs
sit at 11.6 to 13.3 s where the previous sitting read 23.2 and 27.2 s, with the
same modules and the same suite, and the single-threaded row is 36.0 s against
that sitting's 67.0 s. That is the point the previous section made: the seconds
are the machine's on the day, which is why the wallet now quotes the last
payment it actually measured on the machine it is running on.

**The ratio holds a third time.** 36.0 s against a 12.3 s threaded mean is
2.93x, between the 3.36x of the M10 table and the 2.66x of the sitting after
it. Four threads buy about three.

**The scan reads in windows now and none of these figures moved.** A chain
twenty blocks deep fits in one window either way. What changed is what is
resident during a sync of a chain that does not: a leaf record carries that
leaf's 1,792-byte ciphertext, and the range used to be materialised whole
before anything was decrypted.

## After the second review pass (2026-09-14)

The same suite once more, on the same workstation, against the code the second
round of review fixes landed:

| run | `proveTransfer` | Send to settled | peak |
|---|---|---|---|
| threaded | 12.4 s | 24.1 s | 918.4 MiB |
| threaded, re-run on the committed tree | 11.7 s | 19.6 s | 917.8 MiB |
| single threaded | 37.8 s | 56.0 s | 910.2 MiB |

**The module facts reproduce for a fifth sitting.** Peak is within 0.6 MiB of
every figure above it and the proof is 150,908 bytes in all three runs. The
ratio against the 12.1 s threaded mean is 3.14x, inside the 2.66x to 3.36x the
four sittings before it measured.

**These two rows are what the sending screen now quotes.** It used to print
`proveTransfer`'s milliseconds beside a clock that starts at the send button,
so the "longer than this browser expected" admission fired about halfway
through every correct payment and the figure it withdrew was out by roughly a
factor of two. The published defaults are the "Send to settled" column,
rounded: 23 s threaded and 55 s single, which these runs came in at 24.1 s,
19.6 s and 56.0 s. After the first payment the screen quotes what this machine actually
took over the same interval.

## `wasm-opt -O`, both modules

Measured by running `wasm-bindgen` into a scratch directory and optimising a
copy, so the before and after are the same build.

| module | raw | raw after `-O` | gzip | gzip after `-O` |
|---|---|---|---|---|
| single threaded | 3,117,321 | 2,551,705 (-18.1%) | 753,401 | 729,045 (-3.2%) |
| threaded | 5,632,049 | 2,854,132 (-49.3%) | 861,576 | 774,119 (-10.2%) |

The threaded module halves because `-Z build-std` compiles a `std` that has
never been through an optimiser, and the single-threaded one uses the shipped
`std`, which has. Over the wire the two end up 45 KB apart compressed, so
threading costs about six percent of transfer for 3.36x of clock.

The M8 section's module size of 3,069,517 bytes was this crate before the
wallet surface: `noteDigests`, `coinbaseNote`, `treePath`, `headerBlockHash`,
`walletLimits` and the rest add about 48 KB unoptimised, and `wasm-opt` takes
the shipped module below the old unoptimised one either way.

Both build scripts run the pass when binaryen is on `PATH` and say so when it
is not, because a size pass is not a correctness pass and a clone without
binaryen should still produce a working module.

## What per-block header verification costs a sync (2026-09-14)

A leaf's kind is derived from what the headers authenticate rather than from
which storage keys a node chose to answer, so a sync now walks the header of
every block its range covers: see `docs/WALLET.md` under "How a leaf's kind is
decided". The cost is one request per block and one Poseidon path update per
leaf, and this is what it measures out at.

Measured against a `--dev --tmp` node at one mining thread, through a counting
proxy on loopback, with the command-line wallet:

| Pass | blocks | leaves | `chain_getHeader` | `chain_getBlockHash` | `state_queryStorageAt` | wall clock |
|---|---|---|---|---|---|---|
| first sync, empty store | 0 to 103 | 110 | 105 | 3 | 2 | 0.05 to 0.08 s |
| the next sync, one block later | 103 to 104 | 1 | 3 | 4 | 2 | 0.02 s |

Three things set that shape.

- **One `chain_getHeader` per block, and no `chain_getBlockHash` at all.** The
  walk goes downward from the head by `parentHash`, so each header names the
  hash the next one is fetched by. Walking upward would cost a second call per
  block to learn each height's hash, and those answers would be the node's
  rather than the chain's.
- **The fold is incremental.** `qnero_circuit::merkle::TreeFrontier` keeps, per
  level, the completed children of the node being filled there, which is at
  most three digests a level over at most `MAX_TREE_DEPTH` levels. An append is
  one Poseidon permutation per level it carries into, and a root is one fold of
  the frontier. Rebuilding the whole tree once per block would be one tree per
  block of the range.
- **The leaves below the watermark are read once.** The anchor block's own
  `zkTreeRoot` is what checks them, at one key per leaf in pages of 256, which
  is the same wide read a spend already makes to rebuild its paths. A first
  sync pays nothing for it, because the watermark is zero.

### The chunked walk (2026-09-14)

The header walk is climbed in chunks of `HEADER_WALK_LIMIT = 1024` blocks, the
same number in both wallets (`crates/qnero-wallet/src/wallet.rs` and
`wallet-web/src/wallet/sync.ts`). The head is a number the node answers with
and an unchunked walk fetched, rehashed and held one header per block between
the trusted checkpoint and it, so one storage answer decided how much a wallet
allocated before a leaf was read.

The per-block cost is unchanged by the chunking, because the work per block is
the same work: one `chain_getHeader`, one Poseidon2 header rehash, one author
label, and one root comparison. What the chunk size sets is how much is
resident and what a chunk costs to enter:

| Term | Per chunk at 1024 | Why |
|---|---|---|
| headers resident, command line | ~140 KiB | a `VerifiedBlock` is four 32-byte fields and a number |
| headers resident, browser | ~700 KiB | a `RawChainHeader` is five `0x` hex strings the page holds as `String`s |
| extra requests | 1 | `chain_getBlockHash` at the chunk's top, for every chunk but the last |
| leaves read, command line | the chunk's own | `Chain::leaves_up_to_block` stops at the first leaf dated above the chunk's top, so a chunk never holds the whole range's ciphertexts |

The extra request buys the bound and no guarantee: the chunk's top hash comes
from the node, and the walk down from it to a hash already trusted is what
proves it, exactly as the single walk proved the head. Only the last chunk's
top is the head itself.

Two terms are still per block of the whole range rather than per chunk, in the
browser alone, and both are small beside a header: the leaf count each block
ended on, and the `zkTreeRoot` it published. They are accumulated across the
chunks and checked in one fold at the end of the walk, before any leaf is
scanned and before any checkpoint is committed. The fold is a single crossing
into the module that owns Poseidon2 and it starts from an empty tree, so
calling it once per chunk would re-push every leaf below that chunk and turn a
linear check into a quadratic one. The command-line wallet carries its
`TreeFrontier` across the chunks and checks each chunk's roots as it climbs.

What this does not measure is a chain deep enough for the per-block term to
matter. At a twelve-second target a year is about 2.6 million blocks, so a
first sync on such a chain is 2.6 million header requests, against the 2.6
million coinbase leaves it already reads. The two grow together, which is why
the header walk does not change the shape of a first sync, and it is also why
neither is affordable at that depth without the checkpointed frontier the
structure is already built for: `TreeFrontier` is a few dozen digests and
serializes, so an incremental sync can stand on a stored one rather than
reading the tree below the watermark again. That is the next step and it is not
taken here.

## What M10 leaves unmeasured

- **A phone.** Still the 2 to 4 factor with no device under it, and now over a
  band rather than a point: 11.2 s at 4x is 45 s and 27.2 s at 4x is close to
  two minutes, with four usable cores assumed inside both. Threads make the
  arithmetic comfortable at the fast end of the band and leave it open at the
  slow end.
- **What sets the clock on a given day.** The same suite, the same modules and
  the same box spread by about 1.8x between sittings. Nothing here separates
  sustained-load clock throttling from contention with other work. The send
  screen no longer quotes a figure from this file: after the first payment it
  quotes what the machine it is running on actually took, and the published
  figure is the first payment's estimate alone.
- **Scanning at chain scale.** The wallet's sync reads every leaf, tries every
  ciphertext and now walks every block's header, and this suite's chain is tens
  of blocks deep. Nothing here bounds the *time* of a sync against a chain with
  a million leaves, and the batching constants (64 leaves per query, 256 per
  wide page, 1000 keys per key page) are the CLI's rather than a measured
  optimum. What is bounded is the memory: the scan reads
  one 64-leaf window, folds it in and drops it, so a first sync holds one
  window plus the notes the wallet keeps rather than every ciphertext on the
  chain at once.
- **The module over a real network.** Everything above is loopback.
- **A long-lived tab.** The per-payment growth above is closed, and the figure
  after three payments in one worker is measured. What is not measured is a
  tab left open for hours over many syncs, where the terms that could grow are
  the store and the paged nullifier set rather than the circuits.

