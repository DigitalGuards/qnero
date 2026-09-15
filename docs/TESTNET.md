# Running the Qnero public testnet

The operator runbook for the chain at `<domain>`. Every host, address, key and
secret in it is a placeholder: `<domain>` for the apex, `<host>` for the
machine, `<user>` for the account with sudo on it. The real values live in the
operator's own notes and never in this repository, which is public.

The deploy itself is a separate phase. This file is what that phase follows,
and the M11 preparation is everything it describes being buildable, testable
and rehearsed before a machine is touched.

Contents:

1. [What this deployment is](#1-what-this-deployment-is)
2. [Prerequisites](#2-prerequisites)
3. [Build here, copy there](#3-build-here-copy-there)
4. [The chain spec](#4-the-chain-spec)
5. [The seed node's identity](#5-the-seed-nodes-identity)
6. [The systemd units](#6-the-systemd-units)
7. [nginx](#7-nginx)
8. [The stratum port](#8-the-stratum-port)
9. [The faucet](#9-the-faucet)
10. [Verify](#10-verify)
11. [Monitoring](#11-monitoring)
12. [Rollback](#12-rollback)
13. [The site edit](#13-the-site-edit)

---

## 1. What this deployment is

One machine, six names, five services.

| Name | What answers | Proxied |
|---|---|---|
| `<domain>` | the project site, static files | yes |
| `wallet.<domain>` | Qloak, the browser wallet, static files | yes |
| `explorer.<domain>` | silQ Road, the explorer, static files | yes |
| `faucet.<domain>` | `qnero-faucet` on `127.0.0.1:8080` | yes |
| `rpc.<domain>` | the node's JSON-RPC WebSocket on `127.0.0.1:9944` | a decision, see below |
| `node.<domain>` | p2p on 30333 and stratum on 3333, raw TCP | **no, DNS-only** |

`node.<domain>` must stay DNS-only. p2p is raw TCP under a post-quantum Noise
handshake and stratum is the Monero pool dialect; neither is HTTP, and a
proxied record blackholes both.

Whether `rpc.<domain>` is proxied is a real decision with a cost either way. A
proxied record adds the CDN's own read timeout, around 100 s on the entry plan,
on top of the 400 s nginx already allows, and at a 120 s block interval a head
subscription can idle past it. Both wallets reconnect and drive their status
strip off the socket rather than deciding once at connect, so a reconnect is
survivable. DNS-only removes the question and removes the CDN's protection from
an unauthenticated RPC endpoint. **Write down which was chosen**, because the
symptom of the proxied choice is a wallet that reconnects every hundred seconds
and nothing that says why.

The chain: 120 second blocks, RandomX proof of work, an initial difficulty of
5 000, one endowed account at genesis (the faucet's), no treasury, no vesting,
no tech collective and no sudo. `chain/runtime/src/genesis_config_presets/mod.rs`
carries the reasoning for each of those; the short version is in section 4.

## 2. Prerequisites

On the host:

- Ubuntu 24.04, glibc 2.39, 2 vCPU, 8 GB. The glibc version matters: the node binary is
  built on a workstation and copied, so the two must match.
- nginx 1.24. Write `listen 443 ssl http2`; the separate `http2 on;` directive is 1.25 and
  later and fails the config test here.
- A `<user>` account with sudo.
- An origin certificate covering the apex and `*.<domain>` already installed at
  `/home/<user>/ssl/<domain>/{cert.pub,key.priv}`, with the zone in Full (strict) mode.
  **There is no Let's Encrypt here and no certbot.** The certificate is a 15-year origin
  certificate with no renewal timer, which is why the monitor watches its expiry: nothing
  else will.
- `jq`, `curl` and `netcat` for the checks below.

On the workstation: the toolchain this repository pins, `cmake`, `clang`,
`libclang-dev`, and node/npm for the two web apps.

## 3. Build here, copy there

**Nothing is built on the host.** The node's build wants cmake and a C++17
compiler for `randomx-rs`, libclang for the rocksdb bindings, and a
`pallet-shielded` build script that generates the circuit artifact set before
the pallet compiles. On 2 vCPU and 8 GB that is hours or an out-of-memory kill.

```bash
cd chain
LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
cd ..
nice -n 19 cargo build -j 2 --release -p qnero-faucet
```

**Never with `SKIP_WASM_BUILD` set.** That produces a binary whose runtime wasm
is a stub, and every genesis it exports and every block it executes is that
stub's.

Then, once the host is prepared by the sections below:

```bash
QNERO_HOST=<user>@<host> QNERO_DOMAIN=<domain> ./scripts/deploy-testnet.sh
```

That script builds both binaries, copies them, restarts the two units, copies
the chain spec, builds Qloak against `wss://rpc.<domain>` and silQ Road, rsyncs
all three static payloads, and writes the two runtime `config.json` files. It
installs no units, writes no nginx configuration, opens no ports and generates
no keys: those are the one-time steps below, and they are steps a person reads
before running.

Run a single stage with an argument: `deploy-testnet.sh wallet`.

## 4. The chain spec

The committed raw spec is `chain/node/chain-specs/qnero-testnet.json`. It is
generated and never hand-edited:

```bash
./scripts/build-testnet-spec.sh          # regenerate
./scripts/build-testnet-spec.sh --check  # compare, change nothing
```

`chain/node/tests/testnet_spec.rs` regenerates it in CI and compares every
byte, so a preset edit nobody re-exported fails a test rather than shipping a
genesis the tree can no longer rebuild.

What is in it, and what is deliberately not:

- **One endowed account**, the faucet's, with 100 000 QNR of transparent balance. Under v1
  there is no transparent transfer between accounts a user chooses, so that balance can go
  exactly one place: into the pool, through a `shield` the faucet signs for itself.
- **No vesting table.** The dev and Heisenberg example table pays three public keys.
- **No mainnet placeholder.** That allocation is 2% of the supply to an address nobody holds
  a key for, and it reaches a chain only through the mainnet preset.
- **No treasury and no tech collective.** A collective is five real key holders or none;
  with none, nobody can pass the tech-referenda origin, so **there is no runtime upgrade by
  referendum on this chain** and the recovery for a runtime bug is a relaunch. On a testnet
  that is the cheaper side of the trade.
- **No sudo.** There is no sudo pallet in this runtime.
- **A 120 000 ms target block time**, written into `pallet_qpow::TargetBlockTimeMs` at
  genesis. There is no setter and no extrinsic that moves it afterwards; clients read it
  with `QPoWApi_get_target_block_time`.
- **An initial difficulty of 5 000**, set rather than inherited. Difficulty is expected
  hashes per block and the retarget's equilibrium is the divisor, so a chain settles between
  `100 * H` and `200 * H` for a hash rate of `H`. The rate this chain is certain of is its
  own node's single light-mode RandomX thread, about 33 H/s, which puts that band at 3 300
  to 6 600 and its middle at one block every 152 seconds with no retarget pressure at all.
  The inherited constant is 1 000 000, sized for 8 300 H/s, which would be 8.4 hours to the
  first block.
- **There is no difficulty floor field.** `get_min_difficulty()` is a hard-coded 128; genesis
  validates against it and cannot move it. Do not go looking for a knob.
- **Seed epoch constants stay at 2 048 blocks with a lag of 64.** They are runtime constants
  a chain spec cannot move. 2 048 blocks at 120 s is 2.84 days, which is Monero's own
  rotation interval, and matching it is why the target is 120 s. **The open question:** the
  lag of 64 sits inside the 100-block reorg window, so a deep reorg across an epoch boundary
  can change the seed under work already started. That cannot split the chain, because the
  seed follows each candidate's own ancestry rather than canonical height. A lag of 128 would
  remove even that, at the cost of a runtime upgrade, and nothing here has decided it.

Record the genesis hash at first start. Everything binds to it: the wallet
store refuses a store built against another chain, coinbase note derivation
mixes it into `r`, and the monitor compares against it.

```bash
qnero-node --chain /etc/qnero/qnero-testnet.json --tmp 2>&1 | grep 'Initialized genesis block'
```

### The faucet account

The address in the preset is ML-DSA-87, which is the one scheme the transparent
entry admits. Both variants of `DilithiumSignatureScheme` hash to the same 32
bytes, so an address carries no trace of its scheme and no test can assert one:
provenance is a procedure. It was minted with

```bash
qnero-faucet keygen --seed-file <seed-path>
```

and the seed goes straight into the operator's secret store, at mode 0600, with
no second copy. Confirm the seed and the address belong together before genesis
is cut, using the node's own derivation rather than the faucet's:

```bash
printf '%s%064d' "$(cat <seed-path>)" 0 > /tmp/seed64
chain/target/release/qnero-node key qnero --scheme standard --no-derivation --seed < /tmp/seed64
shred -u /tmp/seed64
```

`Dilithium87Pair::from_seed` reads the first 32 bytes of whatever it is handed,
so padding a 32-byte seed to the 64 that command wants derives the same pair.
Both sides printing the same address is the confirmation. If they disagree, the
genesis is wrong and there is no fix after launch: the endowment is stranded
and the chain has to be relaunched.

## 5. The seed node's identity

The node key is **Dilithium**. This tree's `sc-cli` generates a litep2p
dilithium keypair and the file the node writes for itself is
`network/secret_dilithium`. Any runbook that says ed25519 is describing
upstream.

```bash
sudo mkdir -p /etc/qnero
QNERO_NODE=/usr/local/bin/qnero-node \
  ./scripts/generate-bootnode-key.sh /etc/qnero/node-key node.<domain>
```

Three things that script handles and a hand-rolled command gets wrong:

- **The peer id prints on stderr**, so a naive `> file` loses it. Recover it later with
  `qnero-node key inspect-node-key --file /etc/qnero/node-key`.
- **`key generate-node-key` resolves a chain first**, even with `--file` given and even though
  the id is then unused, and this tree refuses an empty `--chain` by naming its chains. So
  `--chain` has to be passed.
- **A bootnode's identity must never rotate.** Its peer id is published in other people's
  spec files. Never `--unsafe-force-node-key-generation`, and never let the node generate one
  into its base path, where a base-path wipe would silently change the network's entry point.

Pass the key as `--node-key-file`. Never `--node-key <hex>`: argv is
world-readable in `ps`.

### Writing the bootnode into the spec

`bootNodes` sits **outside genesis**, so filling it in does not move the
genesis hash and nothing has to be regenerated. This is the exact edit, on the
host's copy:

```bash
PEER_ID=$(qnero-node key inspect-node-key --file /etc/qnero/node-key)
jq --arg addr "/dns/node.<domain>/tcp/30333/p2p/$PEER_ID" '.bootNodes = [$addr]' \
   /etc/qnero/qnero-testnet.json > /tmp/spec.json
sudo install -m 0644 -o root -g root /tmp/spec.json /etc/qnero/qnero-testnet.json
rm -f /tmp/spec.json
```

The committed copy in this repository keeps an empty `bootNodes`, because the
peer id of a node that does not exist yet is not a thing a repository can know.
`deploy-testnet.sh spec` copies the committed file over the host's, so **the
bootnode entry has to be put back after every spec copy**, and the script says
so when it runs. If the list is ever written back into the repository copy, the
reproducibility test compares everything except `bootNodes` and validates the
multiaddr shape, so it keeps working.

## 6. The systemd units

```bash
sudo useradd --system --home-dir /var/lib/qnero --create-home --shell /usr/sbin/nologin qnero
sudo useradd --system --home-dir /var/lib/qnero-faucet --create-home --shell /usr/sbin/nologin qnero-faucet
sudo chmod 0750 /var/lib/qnero
sudo chmod 0700 /var/lib/qnero-faucet

sudo mkdir -p /etc/qnero
sudo install -m 0644 packaging/systemd/qnero-node.service   /etc/systemd/system/
sudo install -m 0644 packaging/systemd/qnero-faucet.service /etc/systemd/system/
sudo mkdir -p /etc/systemd/system/nginx.service.d
sudo install -m 0644 packaging/systemd/nginx-restart.conf   /etc/systemd/system/nginx.service.d/restart.conf

sudo install -m 0600 packaging/systemd/node.env.example   /etc/qnero/node.env
sudo install -m 0600 packaging/systemd/faucet.env.example /etc/qnero/faucet.env
sudo chown root:qnero-faucet /etc/qnero/faucet.env && sudo chmod 0640 /etc/qnero/faucet.env
sudoedit /etc/qnero/node.env      # fill in QNERO_MINER_KEY and QNERO_REWARDS_INNER_HASH
sudoedit /etc/qnero/faucet.env    # fill in QNERO_FAUCET_EXPECT_ADDRESS and the Turnstile pair
```

Then replace `<node-name>` and the two `<domain>` occurrences in
`qnero-node.service`, and `sudo systemctl daemon-reload`.

Four things in those units that are load-bearing:

- **`--force-authoring` is what lets the chain start at all.** Two gates pause authoring
  without it, and a seed node on a fresh network trips both: a node with no peers does not
  author, and a node whose tip is older than `--max-tip-age` (24 hours) does not author,
  which a genesis block whose timestamp is zero always is. Without the flag the chain never
  produces block 1 and the log says "Mining paused" once and then nothing. What it costs is
  the guard: a node genuinely behind during an initial sync will author on a stale tip and
  fork rather than wait. Remove the flag once the network has other authoring peers.
- **The miner key is in the environment file and never in argv.** It carries the coinbase
  viewing key, so whoever reads `ps` can pick this miner's coinbase notes out of the tree. It
  cannot spend them. Check both ends of the string against `qnero-wallet miner-address`: a
  mistyped key mines correct blocks into notes the operator's wallet cannot open, block after
  block, and the only other symptom is a balance that never grows.
- **`--rpc-methods safe`, not `auto`.** Auto means safe when external and unsafe on loopback,
  and nginx proxies to loopback, so auto would publish the unsafe methods. There is no
  `--rpc-external`: the node binds `127.0.0.1:9944` and nginx is the only thing in front.
- **`--state-pruning archive` is a decision made before genesis.** The explorer's
  search-by-extrinsic-hash walk needs state at the block it lands on, and a pruned node keeps
  a few hundred blocks of it. Archive costs disk on a small box, and changing it later means
  a resync.

```bash
sudo systemctl enable --now qnero-node
sudo journalctl -u qnero-node -f
```

The faucet is started after the node is producing blocks, in section 9.

## 7. nginx

```bash
sudo install -m 0644 packaging/nginx/00-qnero-common.conf /etc/nginx/conf.d/
for site in 10-default 20-site 30-wallet 40-explorer 50-rpc 60-faucet; do
  sudo install -m 0644 "packaging/nginx/$site.conf" "/etc/nginx/sites-available/qnero-$site"
  sudo ln -sf "/etc/nginx/sites-available/qnero-$site" "/etc/nginx/sites-enabled/qnero-$site"
done
sudo sed -i -e 's/<domain>/<the real domain>/g' -e 's|<user>|<the real account>|g' \
  /etc/nginx/sites-available/qnero-* /etc/nginx/conf.d/00-qnero-common.conf
sudo mkdir -p /var/www/<domain> /var/www/wallet.<domain> /var/www/explorer.<domain>
sudo nginx -t && sudo systemctl reload nginx
```

Also fill in the CDN's published address ranges in the `set_real_ip_from` lines
of `00-qnero-common.conf`. Without them every faucet claim reads as coming from
the CDN and the per-client limit is one global limit.

Four rules those files encode, each of which cost an outage somewhere:

- **`listen 443 ssl http2`, never `http2 on;`.** The separate directive is nginx 1.25+.
- **Never pin `ssl_ciphers`.** OpenSSL 3.5 plus a CDN's TLS 1.2 origin pulls plus an ECC
  origin certificate gives 525 "bad cipher". Leave the distro default.
- **Any `proxy_pass` to an external hostname must resolve at request time.** A DNS blip during
  an unattended restart otherwise fails `nginx -t` and takes every vhost on the host offline.
  Every proxy in this set targets `127.0.0.1`, so none of them needs it; a future one might.
- **`add_header` does not accumulate.** A location block that declares one of its own drops
  every header from the enclosing server block. That is how COOP and COEP silently vanish
  from `wallet.<domain>/assets/` and Qloak falls back to the single-threaded prover: 37.6 s a
  payment instead of 11.2 s, with no error anywhere. Caching in those files is done with
  `expires`, which does not have this behaviour, and the two locations that do declare
  headers repeat the full set.

## 8. The stratum port

Opening it is the point of a testnet that invites miners, and it is a decision
rather than a default.

```bash
sudo ufw allow 30333/tcp comment 'qnero p2p'
sudo ufw allow 3333/tcp  comment 'qnero stratum'
```

What that port is: an unauthenticated endpoint speaking the Monero pool dialect
xmrig speaks. It has 64 connection slots in total and 16 per address, a
per-session deadline of one accepted share within `--stratum-share-timeout` and
one every window after that, and no other bound. A peer that reconnects after
every share-timeout closure is bounded only by those slots. If it is abused, the
answer is a firewall address allowlist or a pool in front of it, and the number
to remember is 64.

Port 9944 and port 9615 are never opened. nginx reaches both on loopback.

## 9. The faucet

Install the two seeds first:

```bash
sudo install -m 0600 -o qnero-faucet -g qnero-faucet <seed-path> \
  /var/lib/qnero-faucet/transparent.seed
```

The shielded spending key is created by the faucet itself on first start, at
mode 0600, with its note store beside it. Back up both: losing the store costs
a full rescan and the record of which notes are spent; losing the seed costs
the notes.

```bash
sudo systemctl enable --now qnero-faucet
sudo journalctl -u qnero-faucet -f
```

What the first start does, and what to look for in the log:

1. It derives the transparent address from the seed and refuses to start if it is not
   `QNERO_FAUCET_EXPECT_ADDRESS`. Without that check a wrong seed file is a faucet that
   starts, serves, accepts claims and fails every shield with `BadSigner`, which is also the
   code for "the signature did not verify" and sends an operator to debug the payload instead
   of the file.
2. It builds the proving circuits once, about five seconds, before the listener opens.
3. It shields `QNERO_FAUCET_FUND_CHUNK_QUANTA` from the genesis account, up to
   `QNERO_FAUCET_FUND_NOTES` times, until the spendable balance clears the floor. Each shield
   waits for a block, so at 120 s blocks funding takes a few minutes. This is the only way to
   fund a faucet on this chain: `Wallet::shield` always builds the note for the faucet
   itself, and there is no transparent transfer, so shielding moves the endowment into the
   faucet's own notes and `send` is what pays.
4. It logs `ready, N quanta spendable across M note(s)`.

A faucet that cannot fund itself still serves `/status` and refuses claims with
`drained`. That is deliberate: a process that exits at boot tells an operator
less.

## 10. Verify

Run these from a machine that is not the host, because a check that runs on the
box cannot tell you the box is unreachable.

**Height and peers.** The node has no health endpoint; these are the probes.

```bash
./scripts/probe-node.sh   # on the host, against 127.0.0.1:9944
QNERO_MIN_PEERS=1 QNERO_MIN_HEIGHT=1 \
QNERO_GENESIS=<the genesis hash> ./scripts/probe-node.sh
```

It checks `system_health` for peers and `isSyncing`, `chain_getHeader` for
height, `chain_getBlockHash(0)` against the expected genesis, a `state_call` of
`QPoWApi_get_target_block_time` whose little-endian SCALE u64 must read 120 000,
and a TCP connect to the stratum port.

Two failure shapes it exists for: **authoring paused**, which looks like a
height that is not moving with peers at zero rather than a dead process; and **a
node that resynced from the spec**, whose genesis hash matches and whose RPC
answers while both wallets are handed an empty tree, which only the height floor
catches.

**The public endpoints.**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://<domain>/
curl -sS https://wallet.<domain>/config.json     # .rpcEndpoint is wss://rpc.<domain>
curl -sS https://explorer.<domain>/config.json
curl -sSI https://wallet.<domain>/ | grep -i cross-origin
curl -sSI https://wallet.<domain>/assets/ | grep -i cross-origin   # must also carry both
curl -sS -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' https://rpc.<domain>
curl -sS https://faucet.<domain>/status
```

**The explorer.** Open `https://explorer.<domain>/`, confirm the head block
number matches the node's and that a block page renders.

**Qloak.** Open `https://wallet.<domain>/`, check the settings screen says the
**threaded** prover. If it says single-threaded, the isolation headers are not
reaching the page and every payment will take 37.6 s instead of 11.2 s. Create a
wallet and let it sync.

**A faucet drip.**

```bash
qnero-wallet keygen --file /tmp/probe.seed          # a throwaway wallet
ADDR=$(qnero-wallet address --file /tmp/probe.seed | awk '{print $2}')
curl -sS -X POST -H 'content-type: application/json' \
  -d "{\"address\":\"$ADDR\"}" https://faucet.<domain>/drip
# -> {"status":"queued","id":N,...}
curl -sS https://faucet.<domain>/drip/N              # poll until "sent"
qnero-wallet --node wss://rpc.<domain> --file /tmp/probe.seed sync
# -> received 1 note(s) worth 1000 quanta
```

A drip is about ten seconds of proving and then up to one block, so two minutes
end to end is the expected time.

**A rig from a second machine.**

```bash
xmrig --algo rx/0 -o node.<domain>:3333 -u <a label> --threads=2
```

Watch the node: it logs each accepted share and a running counter. What to
expect from one two-thread rig in full mode is a few hundred hashes a second
and a share every few seconds at this difficulty, every one of them at the
block difficulty, and the difficulty climbing by one 2048th per block while the
rig runs.

## 11. Monitoring

Two layers, deliberately independent. A monitor that lives on the box it
watches cannot report that box being down, and one that only probes loopback is
blind to the reverse proxy.

**On the box:**

```bash
# as <user>, whose $HOME is what every path in the script is relative to
install -m 0755 packaging/monitor/monitor.sh "$HOME/monitor.sh"
install -m 0600 packaging/monitor/monitor.env.example "$HOME/.monitor.env"
${EDITOR:-vi} "$HOME/.monitor.env"    # webhook, domain, genesis hash
mkdir -p "$HOME/monitor-state"
( crontab -l 2>/dev/null; echo '* * * * * $HOME/monitor.sh >> $HOME/monitor.log 2>&1' ) | crontab -
```

It checks the three units and their restart counters, the node's peers, height,
staleness and genesis, the stratum port, the faucet's `/health`, **nginx TLS on
loopback**, the origin certificate's expiry, and disk. Alerts are edge-triggered
and debounced at two ticks, and the state lives outside `/tmp`, because a reboot
wipes `/tmp` and every active alert then re-fires as new.

**Verify the webhook delivers before relying on it.** Discord answers HTTP 204
on success, and a revoked or mistyped webhook fails invisibly:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' \
  -d '{"content":"qnero monitor test"}' "$DISCORD_WEBHOOK_URL"
```

**Off the box:** `packaging/monitor/watchdog-entry.md` lists the deep checks to
add to the external watchdog, and says which of them catch what. Root-URL checks
are nearly worthless here on their own: all three web properties are static
files, so the node and the faucet can both be dead while every root returns 200.

## 12. Rollback

**A bad binary.** Keep the previous one. The deploy installs over
`/usr/local/bin/qnero-node`, so take a copy first and put it back:

```bash
sudo cp /usr/local/bin/qnero-node /usr/local/bin/qnero-node.previous   # before deploying
sudo install -m 0755 /usr/local/bin/qnero-node.previous /usr/local/bin/qnero-node
sudo systemctl restart qnero-node
```

A rollback across a runtime change is not a rollback: the chain's state was
produced by whichever runtime executed it. Under v1 there is no runtime upgrade
by referendum on this chain anyway, so the runtime in the genesis wasm is the
runtime for the chain's life.

**A bad static deploy.** `git checkout` the previous commit of `site/`,
`wallet-web/` or `explorer/` and run that stage again. `--delete` means the
webroot matches the source exactly, so re-running is the whole rollback. Then
rewrite `config.json`, which the sync excludes.

**A bad chain spec.** If the genesis changed, this is not a rollback and not a
deploy: it is a new chain. Every wallet store, every balance and every note on
the old one is gone with it. Say so before doing it.

**A stalled chain.** If height stops moving with peers at zero, the node has
stopped authoring. Check `journalctl -u qnero-node` for "Mining paused", and
check that `--force-authoring` is still on the command line if this node is the
only authority. If the difficulty has run far above the available hash rate, the
retarget will come back down at one 2048th per step, which is about 57 hours per
e-fold; pointing a rig at the stratum port is faster than waiting.

**Stopping everything:**

```bash
sudo systemctl stop qnero-faucet qnero-node
ss -ltn | grep -E ':(9944|30333|3333|8080|9615)'   # expect nothing
```

## 13. The site edit

`wallet.<domain>`, `explorer.<domain>`, `rpc.<domain>` and `faucet.<domain>` are
named on the project site as plain hostnames with "testnet, coming online"
beside each, because a link that 404s is worse than a name a reader cannot
click. Every one of them carries `data-m11-host`, and the site's link checker
fails any occurrence outside such an element, so the marker cannot be forgotten
when a new one is added.

At launch, `grep -rn data-m11-host site/` is the complete list. Unwrapping those
spans into anchors is the last edit of the deploy, after the hosts actually
answer, and nothing else on the site has to change.
