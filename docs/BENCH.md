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
