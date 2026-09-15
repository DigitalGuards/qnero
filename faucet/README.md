# The Qnero testnet faucet

Pays a fixed amount to one `qn1` address as a shielded note, rate limited per
address and per client, with an optional Cloudflare Turnstile challenge. It is
what stands behind `faucet.<domain>`.

## The one fact the whole design comes from

Under v1's mandatory privacy there is no transparent transfer between accounts
a user chooses. `QneroCallFilter` refuses every one of them, and the only
transparent payout left is `Vesting::claim` from a genesis-fixed keyless pot.
So **a faucet cannot send transparent QNR.** The only payout it can make is a
shielded note, and a shielded note is a private-batch zero-knowledge proof:
about 9.8 seconds of proving and roughly a gigabyte of working memory, then up
to one 120 second block to settle (`docs/BENCH.md`).

A drip is therefore a job rather than a request. Everything else follows:

- One `WalletProver`, built once at startup, before the listener opens. Building it is 4.26 s
  and a few hundred megabytes held for the life of the process. Building it per request is
  the regression Qloak shipped, which added a permanent quarter gigabyte per payment.
- One worker thread that owns the wallet. `qnero_wallet` is synchronous (`ureq`), `sync` and
  `send` take `&mut self`, and the note store is one JSON file with no lock: two writers
  corrupt it and lose the `rho` and `r` that open the notes in it. Ownership is the lock, and
  the HTTP side reaches the wallet only through a bounded channel.
- `POST /drip` answers `queued` and the page polls `GET /drip/{id}`. Holding a request open
  for a proof plus a block would be a two-minute socket per claim in front of a server that
  can do one at a time.

## Funding

Genesis endows one account, the faucet's, with 100 000 QNR of transparent
balance. That balance can go exactly one place: into the pool, through a
`shield` the faucet signs for itself. `Wallet::shield` always builds the note
for `self.key.pk()`, so shielding cannot pay anybody else either; it moves the
faucet's own balance into the faucet's own notes, and `send` is what pays.

At first start, and whenever the spendable balance falls under
`QNERO_FAUCET_MIN_BALANCE_QUANTA`, the worker shields
`QNERO_FAUCET_FUND_CHUNK_QUANTA` up to `QNERO_FAUCET_FUND_NOTES` times. Several
notes rather than one, so a drip never waits on the change of the one before
it. A `send` spends up to two notes into a payment and a change note, and the
change is what keeps the note count roughly flat.

A faucet that cannot fund itself still serves `/status` and refuses claims with
`drained`, which is a more useful state than a process that exits at boot, and
it is not a state a human has to clear: the worker takes a tick every minute
with no traffic, which refreshes what `/health` reports and retries a top-up
that is still needed. Without that tick a single failed shield would wedge the
faucet, because a balance under the floor refuses every claim and a claim was
the only thing that reached the funding path.

## Two secrets, and neither derives from the other

- **The transparent seed** (`QNERO_FAUCET_TRANSPARENT_SEED`) is the ML-DSA-87 key behind the
  address the chain spec endows. 32 bytes as 64 hex characters, mode 0600. There is no
  recovery: the address is in a genesis and cannot be changed without a new chain.
- **The shielded spending key** (`QNERO_FAUCET_SEED`) is the wallet's own, created on first
  start if absent, with its note store beside it. Losing the store costs a full rescan and
  the record of which notes are spent; losing the seed costs the notes.

`QNERO_FAUCET_EXPECT_ADDRESS` is the address the transparent seed must derive,
copied from the preset. The faucet refuses to start if the two disagree.
Without that check a wrong seed file is a faucet that starts, serves, accepts
claims and fails every shield at the transparent entry with `BadSigner`, which
is also the code for "the signature did not verify" and sends an operator to
debug the payload instead of the file.

## Commands

```
qnero-faucet keygen --seed-file <path>   # mint the transparent seed, print the address
qnero-faucet address                     # print both addresses this faucet answers to
qnero-faucet serve                       # the server
```

`keygen` is run once, before genesis is cut. It prints the SS58 address that
goes into the `qnero-testnet` preset, and the address it prints is the node's
own answer for the same seed:

```
seed64=$(mktemp)
printf '%s%064d' "$(cat <seed-file>)" 0 > "$seed64"
chain/target/release/qnero-node key qnero --scheme standard --no-derivation --seed < "$seed64"
shred -u "$seed64"
```

`mktemp` rather than a fixed path, and it is the file that matters rather than
the mode: a name like `/tmp/seed64` is world-writable ground somebody else can
own first, and a `umask` does nothing about a symlink already sitting there
pointing somewhere readable. What would go through it is the key to the entire
genesis endowment, and there is no recovery from that leak: the address is
fixed in genesis and the chain has to be relaunched.

`Dilithium87Pair::from_seed` reads the first 32 bytes of what it is handed, so
padding a 32-byte seed to the 64 bytes that command wants derives the same
pair. Both sides agreeing is the confirmation `docs/TESTNET.md` asks for.

## Routes

| Route | What it is |
|---|---|
| `GET /` | the page, with `/app.css` and `/app.js` beside it |
| `GET /health` | 200 when the worker is up, the node answered inside six minutes and the balance is above the floor; 503 otherwise. The worker's minute tick is what keeps that freshness true with no traffic |
| `GET /status` | the deep check: `configured`, `captchaEnabled`, `dripQuanta`, `cooldownHours`, `balanceQuanta`, `notes`, `queued`, `chainHead`, `address`, `genesis` |
| `POST /drip` | `{"address": "qn1...", "turnstileToken": "..."}` → 202 `{"status":"queued","id":N}` |
| `GET /drip/{id}` | `queued`, `sent` with `includedAt`, or `failed` with a reason code |

`/status` is GET only so a probe can never submit a claim. `/health` is 503 when
the faucet is drained, on purpose: a faucet that is up and cannot pay is an
outage worth paging for even though the process is running.

## The order a claim is refused in

Cheapest first, because the last step holds a spend key and costs ten seconds
and a gigabyte:

1. the address decodes (nothing read, nothing written),
2. the per-address cooldown (one indexed read),
3. the per-client window (one indexed read),
4. the faucet has funds,
5. Turnstile (one outbound HTTPS request),
6. the queue has room,
7. the proof.

Turnstile is below the two rate limits deliberately: a client that has already
had its drips today is refused without Cloudflare being asked about it. A
network failure reaching Turnstile is a refusal and never a pass, because a
faucet that treats an unreachable Cloudflare as a success has no captcha for
the length of the outage, which is exactly when somebody is likely to be
draining it.

The client's address comes from `X-Real-IP` or `CF-Connecting-IP`, and **only
when the socket peer is loopback**, which is the one peer this server is meant
to have. Without that condition a faucet bound to a public interface would take
every client's word for its own address and the per-client limit would be no
limit at all. nginx has to set `real_ip_header` from the CDN's ranges, or every
claim reads as coming from the CDN and the per-client limit is one global
limit. The packaged `00-qnero-common.conf` includes that list from a file and
fails `nginx -t` while it is missing, for exactly this reason.

An IPv6 client is counted **by its /64**, which is the unit an ISP or a cloud
provider hands out. Counting whole addresses would give one requester 2^64 keys
and a limit that bounds nothing. `store::client_key` does the grouping and
nginx groups the same way, and the two have to agree.

### What the per-client limit is worth, and what it is not

It is worth the cost of a second prefix. It is not a bound on a determined
drain, and nothing in this list is:

- The address side bounds nobody. A `qn1` address is minted locally for free, so a
  requester who wants a second drip makes a second address.
- The client side costs an attacker one more /64. That is real friction and it is not
  much: a second VPS, or a prefix an ISP hands out on request.
- What is left is the prover. One drip at a time, roughly half a minute end to end, so
  about 2 880 drips a day, which is 2.88M quanta against a 10M-quanta endowment: three
  days to empty, and every claim after that answers `drained`.

**Turnstile is the only defence here that costs an attacker something per
claim**, so `serve` refuses to start with no `QNERO_FAUCET_TURNSTILE_SECRET`
unless `QNERO_FAUCET_ALLOW_NO_CAPTCHA=1` says deliberately that this faucet does
not need one. A devnet does not. A public faucet with an endowment does.

## The ledger

One SQLite file in WAL mode, one table, two indexed queries. A rate limit held
in memory resets on every deploy, and this process restarts on every deploy.

The client address is stored as a keyed hash, so the file records how much was
paid out rather than who asked. The key is generated once at mode 0600 beside
the database.

A claim's row is written **before** the proof. A claim that is accepted and
then lost to a crash has still spent its requester's cooldown, which is the
safe side of that trade for a faucet; the queued rows are re-queued at the next
start, so nothing is left pending for ever. A **failed** drip does not hold the
cooldown: nobody was paid.

One failure is different, and it is the one a restart cannot decide.
`submitted_at` is written just before the payment goes to the node and cleared
by nothing, so a row that is still `queued` at the next start and carries one
was interrupted between submission and settlement: the drip may be in a block
with nothing having recorded it. Re-queueing that row pays the same address
twice for one crash, and `Restart=always` makes the crash five seconds old, so
it is failed as `interrupted` instead. That reason code is the one failure that
**does** hold the cooldown and the client's window, because the alternative is
paying twice, and the operator's log line says which address to check.

## What it must not do, and does not

- No amount comes from the request. The drip is a config constant.
- No error body names the seed path, the node URL or an extrinsic. Failures are reason codes
  (`no-spendable-note`, `fee-floor`, `not-included`, `send-failed`, `queue-full`,
  `interrupted`); the
  operator gets the whole error on stderr, where a response body is not.
- Never two proofs at once. One worker, one queue, and a full queue is a 503 with a
  `Retry-After`.

## Tests

```
nice -n 19 cargo test -j 2 -p qnero-faucet
```

The unit tests cover the parts that are decidable without a chain: the SS58
encoder against the node's own answer for a known seed, the cooldown and window
arithmetic including a clock that went backwards, the ledger's behaviour across
a restart and for a failed claim, the proxy-header trust rule, and that no
refusal string names a path, a URL or a key. `tests/drip.rs` drives the whole
HTTP surface against a fake worker, so the route shapes and the refusal codes
are exercised without a ten-second proof.

What none of that covers is a real drip. That is the rehearsal in
`docs/OPS-DEV.md` and the verify step in `docs/TESTNET.md`: a faucet pointed at
a live node, a claim, and a fresh wallet syncing the note.
