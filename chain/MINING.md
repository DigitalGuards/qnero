# Mining Qnero

Qnero's proof of work is RandomX, stock `rx/0`, with the same algorithm and the
same constants Monero uses. A rig that mines Monero mines Qnero with a config
change. The block reward is paid as a shielded note to the key the node was
started with; nothing is paid to a stratum login.

## What you need

- A built node (`chain/README.md`, "Build").
- A wallet and its miner key:

```
./target/release/qnero-wallet keygen
export QNERO_MINER_KEY=$(./target/release/qnero-wallet miner-address)
```

The miner key is secret-bearing and cannot spend. Its holder can pick that
miner's coinbase notes out of the tree, so keep it with the seed.

## The node's own miner

Every authoring node runs an in-process RandomX miner in light mode, one thread
by default, so a devnet produces blocks with no rig attached:

```
nice -n 19 ./chain/target/release/qnero-node --dev --tmp \
  --rewards-miner-key "$QNERO_MINER_KEY" --rewards-inner-hash <hash>
```

`--mining-threads N` sets the thread count; `0` turns the in-process miner off
so only external rigs mine. Values above the machine's own parallelism are
refused. Light mode is an order of magnitude slower than a rig with the full
2 GiB dataset, which is what a real rig brings.

## Point a rig at it

Open the stratum port on the node:

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

The `-u` login is a worker label. This is a solo-mining endpoint: every block
the rig finds pays the note for `--rewards-miner-key`, whatever the login says.

## Stratum flags

| Flag | Default | What it does |
|---|---|---|
| `--stratum-port PORT` | off | Opens the endpoint xmrig connects to. Requires an authoring node (`--dev` is one). |
| `--stratum-host ADDR` | `127.0.0.1` | Bind address. A rig on another machine needs `0.0.0.0` and a firewall rule you chose. |
| `--stratum-share-difficulty D` | 5000 | Per-connection share difficulty, clamped per job to the block difficulty. |
| `--stratum-max-connections-per-ip N` | 16 | Connections one address may hold. Several rigs behind one NAT gateway arrive from a single address. |
| `--stratum-share-timeout S` | 600, rising with the share difficulty | How long a logged-in session has to produce an accepted share before it is closed. |

The share deadline is sized in expected share intervals at the configured share
difficulty, so it does not depend on the block interval: 600 seconds is five
block intervals at this chain's 120 second target and was fifty at 12 seconds,
and the ceiling of 7200 seconds is sixty intervals where it was six hundred.
A rig that has stopped hashing is still cut loose inside ten minutes. Longer
blocks do make the endpoint quieter in one way: a job is rolled on each new
template, so a rig holds one for about 120 seconds and meets a tenth as many
stale shares across a roll.

The endpoint speaks the Monero stratum dialect xmrig uses: `login`, `job`
pushes with `blob`, `target`, `seed_hash` and `next_seed_hash`, `submit`,
`keepalived`. A stale share is answered with a retryable message so the rig
keeps its pool. An authoring pause (stale tip, no peers) closes sessions with a
retryable message too, and rigs reconnect on their own timer.

## What the endpoint bounds

The port is off by default and binds loopback by default. When it is open it
is bounded like anything an unauthenticated peer can reach: 8 KiB lines, 64
connections, a per-address cap, a 30 second login window from connection open,
one accepted share per `--stratum-share-timeout` after login, a write deadline,
a bounded number of share hashes in flight and a per-connection submit budget.
What it cannot bound is a peer that reconnects every window and mines nothing;
that is the known limit of an unauthenticated endpoint, recorded in
`docs/OPS-DEV.md`, and a port exposed to a network belongs behind an address
allowlist or a pool.

## Seed rotation

RandomX's key rotates the way Monero's does: every 2048 blocks, lagged 128
blocks, resolved along the block's own ancestry. Both constants are runtime
constants and are read by the node. At this chain's 120 second target 2048
blocks is 2.84 days, which is Monero's own rotation cadence to the hour: the
block count and the wall clock both match, so a rig pays the same dataset
rebuild here as it pays there and no more often. The lag is twice Monero's 64,
decided on 2026-09-22 and recorded in `docs/DESIGN.md`: 128 blocks is 4.3
hours, and that is how long before the turn every job already carries the
coming seed in `next_seed_hash`, so a full-mode rig has 4.3 hours to build its
next 2 GiB dataset in the background.

## Difficulty

Difficulty adjusts per block toward the target block time, floored so a chain
at the floor can climb. A devnet starts at the floor and retargets within the
first minute of a rig attaching. Measured figures are in `docs/BENCH.md`.

The adjustment is Homestead's and its buckets scale with the target, so at 120
seconds the neutral band is 100 to 200 seconds: an honest block leaves
difficulty flat, a faster one raises it by 1/2048 and a much slower one lowers
it by up to 99/2048.

A chain climbing from the floor of 128 to a live difficulty costs about 13 600
blocks and about 2.4 days for one 900 H/s rig, against about 8 900 blocks and
0.25 days at a 12 second target. Both numbers grow, and for different reasons.
The block count grows by half because the difficulty it has to reach is ten
times higher and every step is a fixed 1/2048 of where it already is. The days
grow by ten because of that same difficulty: the whole climb runs far below the
target, so multiplying the block count by 120 seconds would overstate the
bootstrap by a factor of eight. `pallets/qpow`'s own test pins both.

The band is dead in both directions, and a chain settles at whichever edge it
arrives from. Climbing, it stops at the bottom and sits at about 100 second
blocks. Falling, it stops at the top and sits at about 200: take nine tenths of
the hash rate off a settled chain and difficulty drops monotonically over about
1 550 blocks and then holds, with block times steady at 200 seconds and no
oscillation. So a network that has lost its miners runs at double the target
until hash rate comes back. That ratio is Homestead's and is unchanged from 12
seconds, where the band was 10 to 20; what is new is that the overshoot is 80
seconds of wall clock. The knob is the divisor, `target * 10 / 12` in
`calculate_difficulty`, for the day the average is meant to land on the target
itself.

## Numbers from one workstation

On two threads a stock xmrig 6.21.3 reported about 900 H/s against a devnet
whose in-process miner did about 33 H/s on one light-mode thread; 334 shares
were accepted and 0 rejected over a 79 second session, 128 of them sealed as
blocks. Every figure is in `docs/BENCH.md` and `docs/OPS-DEV.md`.
