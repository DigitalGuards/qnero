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
pair is 3584, and the floor is back to 0.08 QNR where the unpadded wallet paid
0.08 and the 256-padded one paid 0.09. Circuit build 2.31 and 2.38 s, proving
3.34 and 3.51 s, proof 150908 bytes unchanged, submit to inclusion 0.53 s both
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
| xmrig 6.21.3 | full (dataset) | 2336 MiB (2080 + 256) | 2 | **~900 H/s** |

The rig's rate is one session's, `docs/OPS-DEV.md` under the split counters:
334 shares accepted and 0 rejected over a 79-second window, every one of them
at the block difficulty, which ran from 131 to 270 across the window. That is
4.2 shares a second, and the product lands where xmrig's own speed line does,
924.4 H/s over ten seconds and 926.6 H/s at its peak. Both ends of one
conversation, and no figure here is assembled out of two runs.

The node is more than an order of magnitude slower per thread than the rig,
32.9 H/s against about 450, and that is the intended shape: the node hashes
once per block it verifies and once per share it is offered, so a 2 GiB
dataset would cost more memory than the rest of the node for nothing. A rig
pays the dataset once and gets it back immediately.

Fixed costs measured alongside:

- **Argon2d cache fill: 372 ms**, once per seed epoch, 256 MiB. The node holds
  two caches so a block that straddles an epoch boundary, or a reorg across
  one, verifies without paying it again.
- **xmrig dataset build: 3809 ms** with 20 threads, 2080 MiB. This is what
  `next_seed_hash` in every job exists to hide: a rig that is told the next
  seed in advance builds the next dataset in the background instead of
  stalling for four seconds at the boundary.

## Dev-chain block time

Measured on the `dev` preset, whose target is 12 s. The public chain targets
120 s (`docs/DESIGN.md` section 7.4), and the `dev` preset keeps 12 s precisely
so figures like these stay comparable and the suites keep their cadence. What a
120 s target changes here is the wall clock and not the block counts: the
retarget's step is a fixed fraction per block at any target, so a climb that
takes 66 blocks takes 66 blocks either way and ten times as long in seconds.

| | value |
|---|---|
| blocks #1 to #14, in process only | 56 s, **4.3 s per block** |
| difficulty at #1 | 128 |
| difficulty at #66 | 189 |
| blocks in the run | 84 in 4 m 02 s, 74 mined in process and 10 by xmrig |

4.3 s against this chain's 12 s dev target is the retarget climbing: at 32.9 H/s a difficulty
of 128 is about four seconds, so the chain runs fast and the difficulty rises
one step per block. The step is one because integer division rounds
`difficulty / 2048` to zero below 2048, and M7 floored the increment at one so
a chain that reaches the difficulty floor can leave it again.

With xmrig attached the same chain produced blocks as fast as the node could
build templates, which is what a 900 H/s rig against a difficulty of 175
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

A segment must name a block inside `BlockHashWindow`, 256 blocks. At the public
chain's 120 s target that is 8.5 hours; the measurements below were taken on a
12 s dev chain where the same 256 blocks was about 51 minutes. A browser payment
is 45.7 s cold and 33.6 s warm, so the window had room to spare even at 4x on
the tighter of the two. The ordering still matters:
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

# M10: Qloak, threaded and single threaded (2026-09-14)

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
it is the one part a faster prover cannot shorten. On the public chain's 120 s
target that term is ten times larger and it dominates: a payment there is the
proof plus up to two minutes, which is why both wallets now quote the wait as
those two parts and read the interval from the chain. It is also the noisiest
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
| leaves read, command line | the chunk's own, on an honest node | `Chain::leaves_up_to_block` stops at the first leaf `Shielded::LeafBlocks` dates above the chunk's top, so a chunk holds its own blocks' ciphertexts |

The extra request buys the bound and no guarantee: the chunk's top hash comes
from the node, and the walk down from it to a hash already trusted is what
proves it, exactly as the single walk proved the head. Only the last chunk's
top is the head itself.

The leaves row is a figure for an honest node, and it is written that way
deliberately. The stop condition is `Shielded::LeafBlocks`, which the node
answers, so a node that dates the whole range into the chunk's top block makes
one chunk read the whole range: the memory is spent before the check that
catches it. What that node does not get is a wrong answer. `typing::type_chunk`
folds exactly the leaves it was handed and compares against each block's own
`zkTreeRoot`, so an over-reported range reaches a long fold and the pass stops
with nothing written. Bounding the read itself would take a per-block ceiling
on appended leaves, which is a consensus number the wallet cannot read over
RPC.

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
matter. At the public chain's 120 s target a year is 262 980 blocks, so a first
sync on such a chain is 262 980 header requests, against the 262 980 coinbase
leaves it already reads. At the 12 s target these figures were measured against
it was ten times that. The two grow together, which is why
the header walk does not change the shape of a first sync, and it is also why
neither is affordable at that depth without the checkpointed frontier the
structure is already built for: `TreeFrontier` is a few dozen digests and
serializes, so an incremental sync can stand on a stored one rather than
reading the tree below the watermark again. That is the next step and it is not
taken here.

## The pipelined header walk (2026-09-15)

The walk above is one `chain_getHeader` per block, in series, each header
fetched by the hash its child names. That is one round trip per block with
nothing else in flight, and against a node behind a CDN the round trip is the
whole cost. Watching Qloak count "39 of 250 block headers" on the live testnet
is watching 250 of them one after another.

It is two pipelined halves now: `chain_getBlockHash` over a **list** of numbers
paged at 256, then headers by hash with many requests outstanding, 32 JSON-RPC
ids on the browser's one socket and JSON-RPC batch arrays of 64 from the
command-line wallet. `docs/WALLET.md` carries what is verified locally in place
of the parent-link walk, which is the same set of equalities.

Both harnesses run the old walk and the new one against **one node in one
process**, so the comparison is not across two builds, and both compare the two
walks' output rather than counting them: the Rust harness walks the parent
links of the pipelined chain and checks its top against the head, and the
browser harness compares the two walks header for header, number, parent hash
and tree root. A pipelined walk that assembled a different range of the same
length would otherwise report a clean twelvefold.

- `crates/qnero-wallet/tests/header_walk_bench.rs`, ignored by default:
  `cargo test -j 2 --release -p qnero-wallet --test header_walk_bench --
  --ignored --nocapture`, with `QNERO_BENCH_NODE` to aim it at an endpoint and
  `QNERO_BENCH_ONLY` to run one walk at a time.
- `wallet-web/tests/header-walk-bench.test.ts`, which skips itself unless
  `QNERO_BENCH_WS` names one: `QNERO_BENCH_WS=wss://rpc.qnero.io npx vitest run
  --disable-console-intercept tests/header-walk-bench.test.ts`.

### Against the live testnet

`rpc.qnero.io`, from the development workstation, with the chain at 324 to 326
blocks over the runs. This is the case the change is for: a real wide-area
round trip through a CDN.

The command-line wallet cannot speak HTTPS at all in this build, because `ureq`
is compiled with no TLS backend, so its rows go through a loopback
HTTP-to-HTTPS forwarder: a twenty-line Node script that reads each request
body, posts it to the endpoint over one keep-alive TLS connection and passes
the answer and its status back. That adds a process hop on loopback and leaves
the wide-area round trip, which is the term being measured, as it is. The
browser wallet's rows are its own read layer over `wss://rpc.qnero.io` with no
forwarder.

**Where each number comes from.** The `Headers`, `Wall` and `Headers/s` columns
are printed by the two harnesses named above. The `Requests` column is printed
by them too: `RpcClient::requests()` counts the HTTP requests the command-line
wallet sends, batch arrays counting once, and the browser harness counts the
calls through `ChainContext.send`. The forwarder logs one line per request with
the status it got back, which is the second count for the command-line rows and
where the 429s below are read off.

| Wallet | Walk | Headers | Wall | Headers/s | Requests |
|---|---|---|---|---|---|
| command line | sequential | 63 of 326, then refused | 1.39 s | 45 | 65, then HTTP 429 |
| command line | pipelined | 326 | 0.34 s | 948 | 9 |
| browser | sequential | 325 | 5.26 s | 62 | 325 |
| browser | pipelined | 325 | 0.45 s | 727 | 327 |

Three browser runs back to back at block 324: 0.45 s, 0.43 s and 0.46 s
pipelined, which is 727, 752 and 707 headers a second, against 5.26 s, 4.88 s
and 5.50 s sequential, which is 62, 67 and 59. The ratio is 11.3x to 12.0x
across the three.

**The two wallets win it in different ways, and the table says so.** The
browser makes the same 325 requests either way: what it buys is 32 of them in
flight on one socket instead of one. The command-line wallet makes 9 requests
instead of 326, because a batch array of 64 headers is one HTTP request.

**The command-line wallet's sequential walk cannot finish at all.** The node's
front end rate-limits HTTP requests, answering `429 Too Many Requests` after
about eighty in a window, so a sequential walk over any chain longer than that
is refused partway through whatever the wallet does. A full fresh sync of the
whole chain, `qnero-wallet --node <endpoint> --file <seed> sync` against a
store with nothing in it:

| Build | Fresh sync of the whole chain | Wall | Requests |
|---|---|---|---|
| `9b1b765`, before the walk | refused: `chain_getHeader failed against <endpoint>: status code 429` | 1.42 s | 67, the last one a 429 |
| after | 330 leaves through block 325 | 0.68 s | 23 |

The before row wants that commit built, which is what it was measured from: a
worktree at `9b1b765` and its own `qnero-wallet` binary, against the same
endpoint through the same forwarder, minutes apart from the row under it.

Rate limiting is also what the pipelined walk stops running into. Run
immediately after the sequential walk above had spent the window on 65
requests, the pipelined walk went through it in 9: 326 headers in 0.35 s. On
this endpoint the sequential walk is the request pattern the limiter refuses,
and the pipelined walk fits inside the window the limiter allows.

Two shapes of refusal reach an operator here, and the wallet quotes both. A
forwarder that passes the status through gives `status code 429`; something in
front that answers `200` with an HTML page gives a body that is not JSON, and
`RpcClient` quotes the head of it, so the message reads `<html>
<head><title>429 Too Many Requests</title></head> …` rather than saying only
that the body was unreadable, which sent an operator looking for a decoding bug
in the wallet.

The WebSocket endpoint does not rate-limit the same way, which is why the
browser's sequential row completes where the command-line wallet's does not.

### On loopback

The round trip is microseconds here, so this is the floor: what is left is
request handling rather than waiting.

| Chain | Walk | Headers | Wall | Headers/s | Requests |
|---|---|---|---|---|---|
| 3 x `HEADER_WALK_LIMIT` fixture | sequential | 3073 | 1.65 s | 1860 | 3078 |
| 3 x `HEADER_WALK_LIMIT` fixture | pipelined | 3073 | 0.65 s | 4752 | 66 |

Repeated once: 1.64 s and 0.64 s. Both rows count the blocks in the range
rather than the fetches each walk made, because both walks re-fetch the block
each chunk stands on; the harness prints one denominator for the two so the
rates are over the same thing.

The three-chunk fixture is the 3072-block chain the round asked for; a `--dev
--tmp` node at one mining thread was at 206 blocks after twenty minutes on this
workstation and 3072 would have been six hours of mining for a number the
fixture already serves.

A full fresh sync against that dev node, 206 blocks and 206 leaves, was 0.10 s
before and 0.05 s after. That pair is a hand-run one-off from the day of the
change: no harness produces it, and the dev chain it ran against is gone. The
live-testnet sync rows above are the reproducible before and after.

### What this projects to a year-old chain

At the public chain's 120 s target a year is 262 980 blocks. The header walk
alone, at the rates above:

| Where | At the measured rate | Header walk over a year of blocks |
|---|---|---|
| browser, live testnet, sequential | 59 to 67 headers/s | 65 to 74 minutes |
| browser, live testnet, pipelined | 707 to 752 headers/s | 6 minutes |
| command line, live testnet, pipelined | 948 headers/s | 5 minutes |
| command line, live testnet, sequential | 45 headers/s | it cannot finish: the node refuses it after about 80 requests |

Both wallets quote 400 headers/s when they estimate a full scan
(`MEASURED_HEADERS_PER_SECOND`, held equal by a test), which is under every
pipelined figure here on purpose: an estimate that overstates the wait is the
one to be wrong in.

**This is the header walk and not the whole sync.** A year of blocks is also a
year of coinbase leaves, one per block, and each of those is a commitment, a
block number, a value and a rebuild. The leaf reads are already batched at 64
and 256 per request and they are not what this round changed. What the walk
projection says is that the header term stopped being the one that decides
whether a first sync finishes, and the leaf term is now what a full scan costs.
The answer to that term is the **birthday**: a wallet that records where it
started reads neither the headers under it nor the ciphertexts under its leaf
count. `docs/WALLET.md`, "Where a wallet starts reading", has it.

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



## Runtime 105 executor component check (2026-09-16)

The `shielded-budget-bench` feature was compiled to runtime WASM and measured
through the node's Wasmtime executor. The measured runtime build source is in
`5888617`: the run started from `d0c8d12` plus its portable-path and nested-lock
build changes. Concurrent UI merges and the generated testnet candidate
specification were separate changes. This is a component qualification build
with benchmark-only exports. Its exact WASM hash, 192-byte protocol profile, valid
private/public proof hashes, raw samples and declared budgets are in the
[JSON record](bench/2026-09-16-runtime-components.json). The procedure and limits
are in [WASM-BUDGET.md](WASM-BUDGET.md).

Measured WASM Blake2-256:
`cfef3de17bdd22888b6705ba843a1878450bd41ccc2b546c15bf21e8ad6b8513`.
The runtime build supplies its workspace hint and remaps source locations to
`/qnero`, `/cargo` and `/target`. Both the decompressed compact WASM and the
uncompressed build artifact contain zero actual workstation-prefix matches.
Dependency resolution was offline. Every nested WASM dependency's name, version,
source and checksum matches `chain/Cargo.lock`; the generated
`qnero-runtime-blob` wrapper is its only additional package. Earlier attempts with an unpinned nested lock or local
compiler paths are preserved as diagnostics and excluded from this report.

Host: AMD Ryzen AI 9 365, x86_64, affinity CPUs 0-7, nice 19, four Rayon threads,
two Cargo jobs, Rust 1.93.0. Each row used one first call plus nine cached-executor
calls. The max includes the first call; module compilation is recorded separately.
Cold module compilation and the first `Core_version` call took 576.135 ms.
Storage setup used in-memory externalities. Fixtures were valid release-shape
proofs: six leaf slots and 53 private batches.

| Component | Median ms | Max ms | Declared budget ms |
| --- | ---: | ---: | ---: |
| Private proof parse | 1.292 | 1.446 | 5.066 |
| Private parse and verification, once | 23.225 | 23.320 | 30.066 |
| Private parse and verification, twice | 45.825 | 46.032 | 60.131 |
| Public proof parse | 1.779 | 1.858 | 8.474 |
| Public parse and verification, once | 33.466 | 33.518 | 158.474 |
| Public parse and verification, twice | 66.152 | 66.858 | 316.947 |
| Payload binding, two checks, one maximum-size slot | 1.098 | 1.163 | 2.600 |
| Payload binding, two checks, 318 maximum-size slots | 337.790 | 340.211 | 824.620 |
| Full bounded ciphertext-retention hook | 10.372 | 10.842 | 927.376 |

All measured component gates passed. This single-host sample does not justify
reducing weights. This closes the absence of runtime-executor component
measurements. Full successful settlement, block import,
disk costs, admission under legitimate congestion and minimum-hardware capacity
remain unqualified. Production runtimes omit the measurement exports; changes to
the execution logic or build configuration require fresh measurements.

# M16: measurements before the relaunch bundle (2026-09-21)

## ML-KEM-1024 decapsulation, and what one ciphertext costs a scan (2026-09-22)

`docs/BENCH.md` has named the decapsulation unmeasured twice, under M8 and
under M10, and every wallet-scan figure in `docs/DESIGN.md` 12.6 is parametric
on it. This section measures it on both sides of the wasm boundary, and
measures the scan step the wallet actually calls around it.

### The machine

A GCP `c3-highcpu-22` bench VM: Intel Xeon Platinum 8481C at 2.70 GHz, 22
vCPU, 43 GB, Ubuntu 24.04, Rust 1.93.0, nothing else running on the box. Every
section above this one was measured on the dev workstation (AMD Ryzen AI 9 365,
WSL2), so a row here and a row there are two machines and their ratio is not
like for like. Ratios *within* this section are like for like: both columns ran
on this VM, minutes apart.

Every row is one thread. The native invocations set `RAYON_NUM_THREADS=1` and
nothing in these paths uses rayon; `-j 20` is build parallelism. The browser
rows are the single-threaded module in one dedicated Worker.

### The invocations

Native, from the repository root:

```
RAYON_NUM_THREADS=1 cargo test --release -j 20 -p qnero-pqcrypto \
  --test m16_ml_kem_bench -- --ignored --nocapture --test-threads 1
RAYON_NUM_THREADS=1 cargo test --release -j 20 -p qnero-prover-wasm \
  --test m16_scan_bench -- --ignored --nocapture --test-threads 1
```

Both are `#[ignore]`d tests added for M16, in the house style of
`tests/native_bench.rs`. The second one also writes the two fixture
ciphertexts the browser harness loops over, into the gitignored
`www/results/`.

Browser, from `crates/qnero-prover-wasm/www`:

```
node run-scan.mjs --n 2000 --derive 500 --pkg ./results/pkg-m16/qnero_prover_wasm.js
```

`run-scan.mjs`, `scan.html`, `scan-harness.js` and `scan-worker.js` are the M16
browser harness, beside M8's `run.mjs` rather than inside it, so a flag here
cannot move which invocation an M8 row came from. They share `server.mjs`, the
Chromium discovery and nothing else. Chrome for Testing 143.0.7499.4 from the
Playwright cache, `--js-flags=--wasm-max-mem-pages=32768`, served over
`http://localhost` with COOP and COEP, so the page is cross-origin isolated and
`performance.now` is coarsened to five microseconds rather than a hundred.

Each row reports both clocks: per-call samples, and the whole loop timed once
and divided by the call count. The ratios below use the second, which carries
no per-sample clock cost. The two agree everywhere here to under one percent.

### The module the browser rows ran against

The `www/pkg` already built on the VM fails at module init in this Chromium
with `WebAssembly.Table.grow(): failed to grow table by 4`. It fails the same
way under the repository's own `run.mjs`, so it is the module rather than the
new harness: binaryen on that box is `wasm-opt version 108`, old enough to pin
a maximum on the externref table that wasm-bindgen 0.2.128 then cannot grow.

So the browser column ran against a module rebuilt on the VM from the same
commit, through `cargo build --target wasm32-unknown-unknown --lib` and
`wasm-bindgen --target web`, with no `wasm-opt` pass. That is the same shape of
module M8 measured, and it is not the optimised module the wallet ships, which
is a reason to treat the browser rows as a ceiling on module quality rather
than a statement about the shipped bundle.

### What each row is

The note channel is ML-KEM-1024 encapsulation to the recipient's `ek` plus
ChaCha20-Poly1305 over the payload and the memo. A wallet scanning the chain
decapsulates once per ciphertext, whoever it was addressed to: a ciphertext
addressed elsewhere still produces a shared secret, and what refuses it is the
note AEAD's tag. That path never reaches the memo, which is why the two browser
rows differ at all.

Two shapes of scan call are timed because the wallet and the browser take
different arguments. `qnero-wallet`'s per-leaf step (`wallet.rs::try_transfer`)
takes an incoming viewing key it derived once for the whole scan. The browser's
`decryptNote` takes a seed, so it rebuilds the key tree, and with it one
ML-KEM key generation, on every ciphertext. `deriveAccount` is timed beside
them because it is that same derivation plus the encapsulation key and the
address, so the two halves of `decryptNote` can be read apart.

### Native, one thread

Medians, and the loop average that the rates come from, in microseconds.

| | median | mean | p95 | loop total/n | per second |
|---|---:|---:|---:|---:|---:|
| **decapsulate, crate API** | **92.23** | 92.86 | 97.25 | **92.92** | **10762** |
| decapsulate, `ml-kem` 0.3.2 directly, key parsed once | 83.69 | 84.12 | 88.63 | 84.17 | 11881 |
| encapsulate, crate API | 78.14 | 78.77 | 83.12 | 78.84 | 12685 |
| key generation, crate API | 82.40 | 82.93 | 87.49 | 84.11 | 11889 |

Five thousand iterations per row, one thousand for key generation. A rerun
minutes later reproduced every row, and both logs are kept.

The second row is the same lattice work with the decapsulation key parsed once
outside the clock. `MlKemSecretKey::decapsulate` parses the expanded key on
every call, and the gap between those two rows is what that parse costs.

The scan rows, from the same VM, five thousand iterations each and two thousand
for the two derivation rows.

| | median | mean | p95 | loop total/n | per second |
|---|---:|---:|---:|---:|---:|
| wallet per-leaf step, ciphertext addressed to this wallet | 100.36 | 101.16 | 106.04 | 101.22 | 9879 |
| wallet per-leaf step, ciphertext addressed elsewhere | 95.69 | 96.27 | 101.05 | 96.33 | 10381 |
| `decrypt_note_json`, the `decryptNote` body, ours | 194.37 | 195.10 | 200.60 | 195.18 | 5124 |
| `decrypt_note_json`, the `decryptNote` body, elsewhere | 186.09 | 186.76 | 192.20 | 186.81 | 5353 |
| `derive_account_json`, the `deriveAccount` body | 135.93 | 137.11 | 142.20 | 137.19 | 7289 |
| incoming viewing key from a seed | 86.98 | 87.62 | 92.40 | 88.85 | 11255 |

Each ciphertext is one output of a synthetic 2-in / 2-out transfer, and its
bytes are mostly the KEM's.

| one output ciphertext | bytes |
|---|---:|
| ML-KEM-1024 ciphertext | 1568 |
| header, note payload, padded memo | 224 |
| total | 1792 |

### The browser, one thread

Two thousand ciphertexts per shape, five hundred derivations, in milliseconds.

| | median | mean | p95 | loop total/n | per second |
|---|---:|---:|---:|---:|---:|
| `decryptNote`, ciphertext addressed to this wallet | 0.470 | 0.4735 | 0.490 | 0.4740 | 2110 |
| `decryptNote`, ciphertext addressed elsewhere | 0.455 | 0.4536 | 0.460 | 0.4540 | 2203 |
| `deriveAccount` | 0.355 | 0.3591 | 0.385 | 0.3595 | 2782 |

A scan holds one ciphertext at a time, and the module's high-water mark says
so: after four and a half thousand of them, linear memory is the module at rest
plus one page.

| | |
|---|---:|
| module fetch, compile and instantiate, one sample | 18.3 ms |
| linear memory after init | 8.2 MiB |
| peak linear memory over the whole run | 8.3 MiB |

Three invocations were run, two against the rebuilt module in one out-dir and
one after it was moved. The published row is the third. The two `decryptNote`
rows agree across all three to three significant figures, 0.473 and 0.473 and
0.474 ms for ours and 0.455 and 0.455 and 0.454 ms for the stranger's.
`deriveAccount` does not: the first two invocations put it at 0.343 ms and the
published third at 0.3595 ms, a spread of about 5 percent, so its 2.62x ratio
below is the slowest of the three and reads as a ceiling.

### The wasm penalty, and the scan rate

Loop averages, browser against native, on the same box.

| call | native | browser | ratio |
|---|---:|---:|---:|
| `decryptNote`, ciphertext addressed to this wallet | 195.2 us | 474.0 us | 2.43x |
| `decryptNote`, ciphertext addressed elsewhere | 186.8 us | 454.0 us | 2.43x |
| `deriveAccount` | 137.2 us | 359.5 us | 2.62x |

That is a tighter penalty than M8's proving stages carried. Those ran on a
different machine and on a different workload, so read this as this workload's
ratio on this box rather than as a revision of M8's.

The rate `docs/DESIGN.md` 12.6 wants, per second per thread:

| path | native | browser |
|---|---:|---:|
| per ciphertext, key derived per call, which is the exported API today | 5353 | 2203 |
| per ciphertext, key derived once per scan | 10381 | about 4000, estimated |

The browser estimate is the native per-leaf step carried across at the measured
ratio. There is no export that takes a viewing key, so that figure is an
inference, and it is flagged again below.

### What these numbers decide

**A browser scan is a decapsulation loop.** Almost every microsecond of the
per-leaf step is the KEM, whichever wallet the ciphertext was addressed to.

| the per-leaf step, ciphertext addressed elsewhere | us |
|---|---:|
| ML-KEM-1024 decapsulation | 92.8 |
| parse, the failed note AEAD, everything else | 3.5 |
| total | 96.3 |

So any plan to make a scan faster is a plan about ML-KEM, or about running it
fewer times.

**What a first sync costs in a tab, at the rate as it stands:**

| ciphertexts on the chain | browser, exported API | browser, key derived once, estimated | native CLI wallet |
|---:|---:|---:|---:|
| 100000 | 45 s | 25 s | 10 s |
| 1000000 | 7.6 min | 4.2 min | 1.6 min |

A million ciphertexts is minutes of flat-out single-core wasm in a tab, before
any of the fetching, tree folding or header walking that M10 measured around
it. The phone factor M8 states, 2 to 4 and a floor, multiplies the browser
column directly.

**Two cheap wins are now priced.** The wallet's seed-taking `decryptNote` spends
more of its time deriving keys than opening ciphertexts, and an export that
took a viewing key once per scan would roughly halve the per-ciphertext cost.
Below that, the crate's decapsulation re-parses the expanded secret key on
every call, and the two decapsulation rows above price that parse. A scan holds
one key for its whole life.

**The threaded module is the other lever.** M10 measured 3.36x from four wasm
threads on the prover. A scan is embarrassingly parallel over ciphertexts, so
the same pool should apply, and that is unmeasured here.

### What this leaves unmeasured

- **The browser scan with a reused viewing key.** The 4000 per second is an
  inference from the native row at the measured ratio. Measuring it needs an
  export that holds a key across calls, which is a change to the crate's public
  surface rather than to a harness.
- **Threads.** Every row here is one thread. No scan was run on the threaded
  module.
- **The shipped module.** The browser rows ran against a module with no
  `wasm-opt` pass, because the optimised one on the bench VM cannot initialise
  under that box's binaryen. What the shipped module scans at is unmeasured.
- **A phone.** Still no device. The M8 factor is the only bridge.
- **A chain walk.** These rows price one ciphertext. A sync also fetches, folds
  64-leaf windows, pages the nullifier set and walks every header, which is
  M10's territory, and none of it is in these rows.
- **Wrong-length and malformed ciphertexts.** Every ciphertext here parses. A
  node serving garbage would be refused before the decapsulation, which is
  cheaper, and no row bounds that path.

## The leaf circuit at tree depth 20 (2026-09-22)

`docs/DESIGN.md` 12.5 decides to raise `MAX_TREE_DEPTH` from 16 to 20 before
genesis, gated on one build: keep 16 if depth 20 moves the leaf circuit off
`degree_bits = 9`. This section is that build, plus the two things that would
have to move with it, the private batch that recursively verifies the leaf and
the artifact set a runtime embeds.

### The machine

The same GCP `c3-highcpu-22` bench VM as the section above: Intel Xeon Platinum
8481C at 2.70 GHz, 22 vCPU, 43 GB, Ubuntu 24.04, cargo and rustc 1.93.0.
Nothing else ran on the box. Every section above M16 was measured on the dev
workstation, so a row here against a row there is two machines and the ratio is
not like for like. The depth-16 and depth-20 columns below are like for like:
the same box, the same toolchain, minutes apart, one constant different.

Every measured number is single threaded. plonky2's `parallel` feature is off
in all three invocations, which the logs print as `parallel : false`, and
`RAYON_NUM_THREADS=1` was exported anyway. The `-j 20` in each command line is
rustc build parallelism and touches no prover thread.

### The invocations

From the repository root, once with the tree as it stands and once with
`crates/qnero-circuit/src/chain.rs` `MAX_TREE_DEPTH` set to 20 and nothing else
changed:

```
RAYON_NUM_THREADS=1 cargo test --release -j 20 -p qnero-prover \
  --test spend -- --ignored --nocapture --test-threads 1
RAYON_NUM_THREADS=1 cargo test --release -j 20 -p qnero-aggregator \
  --test bench -- --ignored --nocapture --test-threads 1
cargo run --release -j 20 -p qnero-circuit-builder -- \
  --output /tmp/m16-artifacts-<depth> --skip-padding-batch
```

The first two are the existing `#[ignore]`d tests, `leaf_gate_count` and
`private_batch_cost_at_the_chain_default`. No harness was added for this
section. The third is the generator `chain/pallets/shielded/build.rs` calls,
driven through the builder's own CLI at the same dimensions the build script
passes, 6 leaf slots and 53 private batches per public batch, so the chain
workspace and `pallet-zk-tree`'s mirrored `CIRCUIT_MAX_TREE_DEPTH` stayed
untouched at 16 throughout.

One reading trap in the raw logs: the leaf test's banner line hardcodes the
string `MAX_DEPTH=16` and prints it at either depth. The constant actually
compiled in is the one each log's header greps out of `chain.rs`.

### The leaf circuit

| | depth 16 | depth 20 |
|---|---:|---:|
| gates before padding | 320 | 387 |
| `degree_bits` | 9 | 9 |
| padded rows | 512 | 512 |
| public inputs | 26 | 26 |
| proof bytes | 105500 | 105500 |
| build | 103 ms | 105 ms |
| prove, mean of 9 | 294 ms | 281 ms |
| prove, min / median / max | 226 / 306 / 380 ms | 229 / 254 / 436 ms |
| verify | 3.96 ms | 3.97 ms |

Four extra tree levels are 67 gates, and the circuit had 192 rows of headroom
before it would need a tenth degree bit. The 12.5 estimate was 344 to 416
gates, and the measurement lands inside it.

Proving time does not move, and the spread says why: at 512 rows the 16 FRI
grinding bits dominate a leaf proof, the grind is a geometric random variable
seeded by the transcript, and its spread here is wider than the difference
between the two columns. Both columns are a mean over nine proofs and the
depth-20 mean is the lower of the two, which is grinding luck.

### The private batch that verifies the leaf

Every figure is identical at both depths, to the gate and to the byte:

| | depth 16 | depth 20 |
|---|---:|---:|
| leaf `degree_bits` | 9 | 9 |
| gates before padding | 24530 | 24530 |
| `degree_bits` | 16 | 16 |
| padded gates | 65536 | 65536 |
| public inputs | 152 | 152 |
| proof bytes | 157476 | 157476 |
| build | 12.7 s | 12.5 s |
| prove, mean of 3 | 33.08 s | 32.91 s |
| verify | 7.23 ms | 7.20 ms |
| peak RSS of the run | 1.82 GiB | 1.82 GiB |

This is the `N = 7` shape the aggregator's bench test pins, the one M3 measured
at 24530 gates, so the depth-16 column also reproduces that M3 row on this box.
The shipped chain default is `N = 6`.

A recursive verifier's size is set by the inner circuit's `degree_bits`, its
FRI parameters and its public-input count. Depth 20 moves none of the three, so
the batch does not notice the deeper tree. `docs/CIRCUIT.md` section 9.1 puts
the ceiling for `degree_bits = 15` at about 23700 gates and seven recursive
verifiers at 24324: depth 20 adds nothing to that 24324, so the batch's
`degree_bits` stays where it was and the `N = 6` against `N = 7` argument is
unchanged by this decision.

### The artifact set a runtime embeds

Generated at the release dimensions, single threaded:

| | depth 16 | depth 20 |
|---|---:|---:|
| wall clock, generation only | 68.1 s | 75.2 s to the pin check |
| peak RSS | 5.15 GiB | 5.15 GiB |
| `leaf_verifier.bin` | 1609 B | 1609 B |
| `private_batch_verifier.bin` | 1749 B | 1749 B |
| `public_batch_verifier.bin` | 1905 B | not written |
| `padding_leaf_proof.bin` | 105500 B | 105500 B |

The depth-16 run reproduces the M4 sizes exactly. The depth-20 run builds the
whole set and then exits 1:

```
Error: regenerated release artifacts differ from the release pin: incompatible
Qnero protocol profile; update the wallet or select a compatible chain before
building circuits
```

That is `generate_all_artifacts` calling `profile::ensure_supported` at the
release dimensions, against the digests pinned in
`crates/qnero-circuit/src/profile.rs`. It is the expected failure and nothing
was regenerated for it. The profile encodes `MAX_TREE_DEPTH` in its own bytes
at offset 20 and pins a blake2b-256 digest of each verifier file, so both the
depth field and all three artifact digests change together.

Re-running the generator at non-release dimensions (`--no-public-batch`) skips
that check and writes the files, which is where the depth-20 sizes above come
from. Both verifier files keep their exact byte length at depth 20 and change
content: the leaf verifier's digest moves from `f55f252d...` to `8938aadf...`
and the private batch verifier's from `67826803...` to `adc53f02...`, blake2b
over the whole file. A deeper tree is a new circuit, so a regenerated set and a
refreshed pin travel with it, which is the cost 12.5 already lists.

`cargo test --release -j 20 -p qnero-circuit --lib` at depth 20 passes all 46
tests, the profile tests included: they check the encoding against the
compiled constant, so they follow the constant wherever it goes. The release pin in the
artifact generator is the only thing this change turns red.

### What these numbers decide

**The 12.5 rule points to 20.** Its condition was that the leaf stay at
`degree_bits = 9`, and it does: 387 gates in the same 512 padded rows, the same
26 public inputs, the same 105500-byte proof, proving time inside the grinding
noise. Depth 20 raises the 4-ary tree's capacity from 4.29e9 leaves to 1.10e12
and every prover pays 67 gates for it, none of which cross a degree boundary.

**Nothing downstream of the leaf moves.** The private batch is identical at
both depths, so the recursion budget the `N = 6` choice was made against is
untouched, and no proof anywhere in the stack changes size.

**The bundle carries a regenerated artifact set and a refreshed pin.** That was
already in 12.5's cost line. This section makes it concrete: three pinned
digests in `profile.rs`, the two verifier files whose content changed, and the
profile bytes themselves. Both verifier files keep their length, so no size
gate or storage width moves with them.

### What this leaves unmeasured

- **`pallet-zk-tree` at depth 20.** `CIRCUIT_MAX_TREE_DEPTH` was deliberately
  left at 16, so the chain workspace was never built at depth 20 and the
  const-assert that ties the two constants was never exercised against the new
  value. The pallet's own `MAX_TREE_DEPTH` is 32 already.
- **The frontier and finalize costs 12.5 forecasts.**
  `FINALIZE_BASE_POSEIDON_EVALS` 19 to 23 and 48 to 60 frontier digests are the
  pallet's side of the change, and this section touched no pallet.
- **The public batch verifier at depth 20.** The generator refused before
  writing it. Its size follows the private batch's shape, which did not move,
  so it is expected to hold at 1905 bytes, and expected is not measured.
- **A wallet proving at depth 20.** The leaf here proves a witness the test
  builds. No end-to-end wallet run, no wasm prover, and no browser proof was
  produced at depth 20.
- **Threads.** Every row is one thread. Nothing here says what four wasm
  threads or a saturated 22-vCPU pool would do to either column, and the
  earlier M8 and M10 sections are the only guide.

## Real state, RocksDB and `state_getReadProof` at a page (2026-09-22)

`docs/DESIGN.md` 12.3 quotes 4.1 to 4.3 KB of raw state per transfer with
ciphertexts in state, quotes 600 to 750 B for the layout that moves them into
block bodies, and says in the same paragraph that the disk multiplier is
unmeasured. 12.7 Step 0 item 3 asks for the real number. This section measures
both sides of that: what a settled 2-in/2-out transfer writes into state and
onto disk, and what the authenticated read a wallet scan makes around it costs
in bytes and in verify time.

### The machine

The same GCP `c3-highcpu-22` bench VM as the two sections above: Intel Xeon
Platinum 8481C at 2.70 GHz, 22 vCPU, 43 GB, Ubuntu 24.04, Rust 1.93.0, Node
22.23.2, Chrome for Testing 143.0.7499.4 from the Playwright cache. Nothing
else ran on the box. Every section above M16 was measured on the dev
workstation, so a row here against a row there is two machines and the ratio is
not like for like. Every row inside this section is like for like: one chain,
one box, one hour.

Thread counts. The node authored with `--mining-threads 1`. The CLI wallet
proves single threaded, because plonky2's `parallel` feature is off in the
shipped binary. The native verify rows ran with `RAYON_NUM_THREADS=1` and
`--test-threads 1`. The browser rows are the single-threaded wasm module on
one page's main thread, one Chromium at a time. The disk rows measure bytes,
so no thread count enters them.

### The chain

```
qnero-node --dev --tmp --database rocksdb --mining-threads 1 \
  --rpc-port 9944 --port 30333 --rewards-miner-key qnm1…
```

`--database rocksdb` is explicit because the shipped default is `auto`, which
creates ParityDb on a fresh path. The question asked about RocksDB. Dev genesis
sets a 12 s target block time and initial difficulty 80, and the node mined a
coinbase leaf into every block, so the tree grows by one leaf per block with no
traffic at all. The miner key came from `qnero-wallet keygen` plus
`qnero-wallet miner-address` against an unreachable node, and the seed and its
note store were shredded at the end. `--tmp` removed the base path on shutdown.

### The invocations

The driver script, which is the sequence the numbers below come from: eleven
`du -sb` snapshots one block apart with no traffic, then `shield` of 50 QNR
from the `alice` dev account, then ten `send` calls of 1 QNR to the wallet's
own address, each one a 2-in/2-out private batch proved locally and waited on
until its settlement block. One `du -sb` of the RocksDB directory and one
`qnero-wallet status` bracket every transfer.

The read-proof and body measurements are one `#[ignore]`d test added for M16,
in the house style of `docs/CIRCUIT.md` section 6:

```
QNERO_NODE=http://127.0.0.1:9944 \
QNERO_M16_OUT=…/www/results/m16-readproof RAYON_NUM_THREADS=1 \
  cargo test -p qnero-wallet --release --test m16_read_proof_bench -- \
  --ignored --nocapture --test-threads 1
```

`m16_read_proof_pages` asks the node for `state_getReadProof` over three
windows of leaf indices, times `qnero_state_proof::read_values` over each
answer fifty times, and writes each answer out as the JSON request
`readStateProof` takes. `m16_settlement_state_and_body` reads the stored value
length of every map at each of the last 24 leaves, reads the settled nullifier
map, and walks every block body from genesis to head.

The browser twin, from `crates/qnero-prover-wasm/www`:

```
node run-readproof.mjs --n 50 --pkg ./results/pkg-m16/qnero_prover_wasm.js
```

`run-readproof.mjs`, `readproof.html` and `readproof-harness.js` are the M16
read-proof harness, beside `run-scan.mjs` and M8's `run.mjs` rather than inside
either, so a flag here cannot move which invocation another row came from. The
`--pkg` is the module the scan section rebuilt on this VM, for the reason that
section gives.

### What a block costs when nothing happens

Eleven snapshots, one per block, on an idle chain. Every block still appends
one coinbase leaf, so this baseline already carries a leaf write.

| Quantity | Value |
|---|---|
| Blocks sampled | 10 |
| RocksDB directory at height 35 | 1 205 000 B |
| RocksDB directory at height 45 | 1 285 641 B |
| Growth per idle block | 8 064 B |
| Block body per idle block | 48 B |

### What one settled transfer costs

Each row brackets one `send`. `blocks` is how many blocks passed while the
wallet built circuits, proved and waited; `leaves` is blocks plus the two
settlement outputs. The baseline column is 8 064 B times `blocks`, and the
settlement column is what is left after subtracting it.

| # | blocks | leaves | RocksDB growth | idle-block share | settlement share | settlement minus body |
|---|---|---|---|---|---|---|
| 1 | 8 | 10 | 230 399 B | 64 513 B | 165 886 B | 11 378 B |
| 2 | 9 | 11 | 243 097 B | 72 577 B | 170 520 B | 16 012 B |
| 3 | 5 | 7 | 208 081 B | 40 320 B | 167 760 B | 13 252 B |
| 4 | 3 | 5 | 191 629 B | 24 192 B | 167 437 B | 12 929 B |
| 5 | 5 | 7 | 207 612 B | 40 320 B | 167 292 B | 12 784 B |
| 6 | 5 | 7 | 210 524 B | 40 320 B | 170 204 B | 15 696 B |
| 7 | 9 | 11 | 246 916 B | 72 577 B | 174 339 B | 19 831 B |
| 8 | 8 | 10 | 240 944 B | 64 513 B | 176 431 B | 21 923 B |
| 9 | 5 | 7 | 211 976 B | 40 320 B | 171 656 B | 17 148 B |
| 10 | 5 | 7 | 215 537 B | 40 320 B | 175 216 B | 20 708 B |
| all ten | 62 | 82 | 2 206 715 B | 499 974 B | 170 674 B each | 16 166 B each |

The last column trends upward across the run, from 11 378 B to 20 708 B, as the
trie deepens under a tree that grew from 47 to 129 leaves. Ten transfers is a
small sample of that curve.

### One settlement on the wire

Every block body from genesis to head, read with `chain_getBlock` and measured
as hex length over two.

| Block shape | Extrinsics | Body bytes | Largest extrinsic |
|---|---|---|---|
| Idle | 2 | 48 | 37 |
| The `shield` | 3 | 9 152 | 9 104 |
| A settlement | 3 | 154 556 | 154 508 |

The settlement extrinsic is the 150 908-byte private-batch proof the wallet
printed, plus two 1 794-byte ciphertexts, plus 12 bytes of envelope. It is
99.97 percent of the block it lands in.

### Raw state per transfer

Stored value lengths read one key at a time at the head block, with the key
lengths that `sp-trie` stores beside them. `Leaves`, `Ciphertexts` and
`LeafBlocks` are `Identity`-hashed maps, so their key is a 32-byte pallet and
item prefix plus the 8-byte little-endian index. `UsedNullifiers` is
`Blake2_128Concat`, so its key is that prefix plus 16 bytes of hash plus the
32-byte nullifier, and its value is the unit type.

| Item | Writes per transfer | Key bytes | Value bytes | Total |
|---|---|---|---|---|
| `ZkTree::Leaves` | 2 | 40 | 32 | 144 B |
| `Shielded::Ciphertexts` | 2 | 40 | 1 794 | 3 668 B |
| `Shielded::LeafBlocks` | 2 | 40 | 4 | 88 B |
| `Shielded::UsedNullifiers` | 2 | 80 | 0 | 160 B |
| **All four** | 8 | | | **4 060 B** |
| The same without ciphertexts | 6 | | | 392 B |

A coinbase leaf writes `Leaves`, `LeafBlocks` and an 8-byte `CoinbaseValues`
and leaves the ciphertext slot empty, which is 164 B with its keys. The
`shield` writes one leaf with a ciphertext.

### The disk multiplier

| Ratio | Value |
|---|---|
| RocksDB growth per transfer, state only, against 4 060 B of raw state | 3.98x |
| RocksDB growth per transfer, everything, against 4 060 B of raw state | 42.0x |
| RocksDB growth per transfer against raw state plus the on-wire body | 1.08x |
| DESIGN 12.3's raw-state band, against the 4 060 B measured | 4.1 to 4.3 KB quoted |
| DESIGN 12.3's bodies-layout band, against the 392 B measured | 600 to 750 B quoted |

### Where the bytes live

`du` during the run measures the write-ahead log, because RocksDB had flushed
nothing: at shutdown the directory held one 3 883 189-byte `000008.log` and
zero SST files. Reopening the database flushed it. The per-column figures below
are the `data_size` each SST reported in RocksDB's own `LOG`, at chain height
155 with 175 leaves and eleven settlements on the chain.

| Column | `sc-client-db` name | SST data bytes |
|---|---|---|
| col5 | `BODY` | 1 723 402 |
| col1 | `STATE` | 1 435 704 |
| col4 | `HEADER` | 31 076 |
| col3 | `KEY_LOOKUP` | 10 565 |
| col8 | `AUX` | 7 614 |
| col0 | `META` | 7 322 |
| col2 | `STATE_META` | 35 |
| | whole directory | 3 551 578 |

The column number alone leaves the mapping open, so arithmetic settles it: the
same chain's block bodies sum to 1 716 132 B on the wire, which is 0.4 percent
under what col5 holds. A block body therefore costs its wire size on disk and
nothing more, and the state trie is the other 1.4 MB.

`qnero-node chain-info` prints the head, genesis and finalized hashes and no
column sizes, so it answers none of this.

### `state_getReadProof` at a page of 64 and a page of 16

One block hash, state root `0xc5391fe1…`, leaf count 175. `head` is leaf 0
upward, which on this chain is coinbase leaves whose ciphertext slot was never
written. `settled` ends on leaf 172, the newest leaf whose ciphertext is still
inside the runtime's `CIPHERTEXT_RETENTION_BLOCKS` window of 64 blocks. `tail`
is the last indices in the tree. Proof bytes are the sum of the returned node
hex strings over two.

| Map | Window | Page | First leaf | Nodes | Proof bytes | Bytes per key | Values present |
|---|---|---|---|---|---|---|---|
| `ZkTree::Leaves` | head | 64 | 0 | 72 | 5 683 | 88.8 | 64 |
| `ZkTree::Leaves` | head | 16 | 0 | 21 | 2 122 | 132.6 | 16 |
| `ZkTree::Leaves` | settled | 64 | 109 | 73 | 6 181 | 96.6 | 64 |
| `ZkTree::Leaves` | settled | 16 | 157 | 22 | 2 620 | 163.8 | 16 |
| `ZkTree::Leaves` | tail | 64 | 111 | 73 | 6 181 | 96.6 | 64 |
| `ZkTree::Leaves` | tail | 16 | 159 | 22 | 2 620 | 163.8 | 16 |
| `Shielded::Ciphertexts` | head | 64 | 0 | 4 | 811 | 12.7 | 0 |
| `Shielded::Ciphertexts` | head | 16 | 0 | 4 | 811 | 50.7 | 0 |
| `Shielded::Ciphertexts` | settled | 64 | 109 | 23 | 15 822 | 247.2 | 8 |
| `Shielded::Ciphertexts` | settled | 16 | 157 | 9 | 4 548 | 284.2 | 2 |
| `Shielded::Ciphertexts` | tail | 64 | 111 | 23 | 15 822 | 247.2 | 8 |
| `Shielded::Ciphertexts` | tail | 16 | 159 | 9 | 4 548 | 284.2 | 2 |

A ciphertext page is dominated by the values it carries: the 64-key settled
page returns 14 352 B of ciphertext inside 15 822 B of proof, so 1 470 B is
trie structure for 64 keys. A page of 64 commitments costs 5 683 to 6 181 B for
2 048 B of value, which is where the per-key figure sits three to four times
higher. JSON transport doubles every figure above, because the node answers in
hex.

### Verify time

Fifty samples per row, medians. Native is `qnero_state_proof::read_values`
through `cargo test --release`, one thread. Browser is `readStateProof` in the
single-threaded wasm module in Chrome for Testing 143, same proofs, same keys.
`performance.now` in that page is not cross-origin isolated here, so the
browser column is quantized to five microseconds.

| Map | Window | Page | Native median | Browser median | Browser over native |
|---|---|---|---|---|---|
| `ZkTree::Leaves` | head | 64 | 0.091 ms | 0.347 ms | 3.8x |
| `ZkTree::Leaves` | head | 16 | 0.024 ms | 0.090 ms | 3.8x |
| `ZkTree::Leaves` | settled | 64 | 0.092 ms | 0.305 ms | 3.3x |
| `ZkTree::Leaves` | settled | 16 | 0.025 ms | 0.095 ms | 3.8x |
| `ZkTree::Leaves` | tail | 64 | 0.092 ms | 0.320 ms | 3.5x |
| `ZkTree::Leaves` | tail | 16 | 0.025 ms | 0.095 ms | 3.8x |
| `Shielded::Ciphertexts` | head | 64 | 0.042 ms | 0.110 ms | 2.6x |
| `Shielded::Ciphertexts` | head | 16 | 0.012 ms | 0.040 ms | 3.3x |
| `Shielded::Ciphertexts` | settled | 64 | 0.074 ms | 0.515 ms | 7.0x |
| `Shielded::Ciphertexts` | settled | 16 | 0.021 ms | 0.140 ms | 6.7x |
| `Shielded::Ciphertexts` | tail | 64 | 0.074 ms | 0.520 ms | 7.0x |
| `Shielded::Ciphertexts` | tail | 16 | 0.021 ms | 0.140 ms | 6.7x |

Module init in the browser was 26.4 ms and linear memory settled at 8 781 824 B
for the whole set.

### What these numbers decide

**12.3's raw-state figure holds, a little low.** The measured 4 060 B per
transfer sits just under the quoted 4.1 to 4.3 KB. The quote is safe to keep
and the measurement is now the number behind it.

**12.3's bodies-layout figure is conservative by 1.6x.** What state keeps once
ciphertexts leave it is 392 B per transfer against the quoted 600 to 750 B. The
8 to 9x ratio 12.3 argues from becomes 10.4x on measured values, so the case
for Q3 is stronger than the paragraph claims, with the same shape.

**The disk multiplier on state is about 4x.** The RocksDB write-ahead log grows
16 166 B per transfer for 4 060 B of raw state. That is the trie paying for
itself: eight changed keys, each rewriting its branch path, plus the two 1 794-
byte ciphertexts inlined into their leaf nodes.

**The multiplier on block bodies is 1.0x.** A body costs its wire size on disk,
confirmed by col5 landing 0.4 percent over the summed `chain_getBlock` hex. So
Q3 moves the ciphertexts out of the column that charges 4x and into the column
that charges 1x, and the block itself grows by nothing at all, because the
ciphertexts already ride in the settlement extrinsic.

| What Q3 moves, per transfer | Bytes |
|---|---|
| Ciphertext raw state today | 3 668 |
| Its disk cost at the measured state multiplier | about 14 600 |
| Its disk cost as body | 3 588 |
| Projected saving | about 11 000 |

That table is arithmetic over the two measured columns. No run here ships the
layout, so the saving is a projection.

**A page of 64 is the right width for the authenticated read.** The widest page
measured is 15 822 B of proof and 0.52 ms of browser verify, against the
`MAX_PROOF_BYTES` budget of 64 MiB. What bounds a scan at this width is the
1 794 B per ciphertext the node has to ship and the wallet has to decrypt,
which the M16 scan section above prices. Half a millisecond of trie work per
page sits well under that.

**Today's runtime already prunes ciphertexts.**
`CIPHERTEXT_RETENTION_BLOCKS` is 64, and the head page of 64 leaves returned
zero ciphertexts against a proof of four nodes, because they had expired out of
state. So 12.3's "about 1.7 TB, unprunable" describes a layout this build does
not ship, and Q3's real gain is against the live window plus whatever the
history an archive node keeps costs, which is the next thing to measure.

### What this leaves unmeasured

- **A chain long enough for the trie to settle.** 175 leaves is a shallow trie.
  The per-transfer state share climbed 82 percent across ten transfers and the
  curve had not flattened. Every state figure here is a floor.
- **ParityDb.** The shipped default is `auto`, which picks ParityDb on a fresh
  path. Every disk figure here is RocksDB with `--database rocksdb` passed
  explicitly, and nothing says the two agree.
- **Compaction over time.** The per-transfer rows are write-ahead log growth.
  One flush reduced a 4 180 506-byte directory to 3 551 578 B, which is 85
  percent, and that is one flush on one small chain rather than a steady state.
- **What the ciphertext prune actually reclaims.** The retention window
  expires an entry and leaves a tombstone until compaction, and the old trie
  nodes survive until state pruning removes them. Neither was measured.
- **Historical state proofs.** Every proof here was taken at the head. The
  archive path `docs/AUTHENTICATED_READS.md` describes, where a wallet reads a
  ciphertext at its creation block's state root, was never exercised.
- **The nullifier map at scale.** 20 entries, 80 bytes of key each, no value.
  The complete-prefix traversal the wallets do over it was not timed, and it is
  the read whose cost grows forever.
- **A wallet scanning through this.** No `readStateProof` row here is a whole
  page cycle: no JSON parse, no hex decode, no worker message, and no RPC
  round trip. The M16 scan section above measures the decryption side of the
  same loop, and nothing measures the two together.
