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
5 000, one endowed account at genesis (the faucet's), no treasury, no vesting
and no privileged origin of any kind. `chain/runtime/src/genesis_config_presets/mod.rs`
carries the reasoning for the genesis; `docs/DESIGN.md` section 7.6 carries the
reasoning for the last of those. The short version is in section 4.

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

**Deploying the faucet on its own.** `node` builds, copies and restarts both
binaries, so a change to the faucet page used to arrive by restarting the
chain. There is a stage for the faucet alone, and it is the one to use for
anything that is only the faucet:

```bash
QNERO_HOST=<user>@<host> QNERO_DOMAIN=<domain> ./scripts/deploy-testnet.sh faucet
```

It builds `qnero-faucet` here, keeps the binary it is about to replace as
`/usr/local/bin/qnero-faucet.previous`, installs the new one and restarts
`qnero-faucet`. Nothing else is touched: the chain does not miss a block and no
peer is dropped.

`faucet.<domain>` answers **502 for about 20 seconds** across that restart.
The worker opens the wallet, asks the node for runtime metadata and builds the
proving circuits before the listener binds, which is deliberate: a faucet that
cannot pay fails at startup instead of serving a page and refusing every claim.
Wait for `/health` rather than watching the page:

```bash
until curl -sf -m 4 https://faucet.<domain>/health > /dev/null; do sleep 2; done
curl -sS https://faucet.<domain>/status | jq '{chainHead, balanceQnr, queued}'
```

The stage is not in the default run, because `node` already installs the same
binary and running both would build and restart it twice.

## 4. The chain spec

The committed raw spec is `chain/node/chain-specs/qnero-testnet.json`. It is
generated and never hand-edited:

```bash
./scripts/build-testnet-spec.sh          # regenerate
./scripts/build-testnet-spec.sh --check  # compare, change nothing
```

`bootNodes` is the one field a deployment writes in after the file is
generated, and it is fed through the script rather than edited in afterwards:

```bash
QNERO_BOOTNODES=/dns/node.<domain>/tcp/30333/p2p/<peer id> \
  ./scripts/build-testnet-spec.sh
```

With the variable unset the list already in the committed file is preserved, so
an ordinary re-export after a preset edit keeps the launched network's entry
point instead of silently dropping it. `QNERO_BOOTNODES=`, empty, clears it.

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
- **No treasury**, because there is nothing for one to hold and nothing to spend from it.
- **No admin keys, as a property of the runtime rather than of this genesis.** The tech
  collective, its referenda instance and the fast-upgrade origin were removed from the
  binary, and with them every `frame-system` dispatchable that could write `:code`,
  `:heappages` or a raw storage key. No chain this binary launches has an origin that can
  change its own rules, so **there is no runtime upgrade on this chain** and the recovery
  for a runtime bug is a relaunch. `docs/DESIGN.md` section 7.6 carries the decision and
  its cost; on a testnet it is the cheaper side of the trade.
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
seed64=$(mktemp)
printf '%s%064d' "$(cat <seed-path>)" 0 > "$seed64"
chain/target/release/qnero-node key qnero --scheme standard --no-derivation --seed < "$seed64"
shred -u "$seed64"
```

`mktemp` rather than a fixed path, and the reason is the path rather than the
mode. `/tmp/seed64` is a predictable name in a world-writable directory: a file
already sitting there, or a symlink pointing at one somebody else can read, is
written through at whatever mode and ownership it already has, and `shred` then
destroys their copy rather than closing anything. A `umask` cannot help with
that. What goes through this file is the key to the entire genesis endowment,
and there is no recovery from the leak: the address is fixed in genesis and the
chain has to be relaunched.

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
# The key is given to the service user, so the service user has to exist. This
# is the same line section 6 runs, and running it twice is harmless.
id -u qnero >/dev/null 2>&1 || \
  sudo useradd --system --home-dir /var/lib/qnero --create-home --shell /usr/sbin/nologin qnero
sudo QNERO_NODE=/usr/local/bin/qnero-node \
  ./scripts/generate-bootnode-key.sh /etc/qnero/node-key node.<domain>
sudo chown qnero:qnero /etc/qnero/node-key
sudo chmod 0600 /etc/qnero/node-key
```

The `sudo` and the `chown` are both load-bearing:

- **`sudo` on the generator.** `/etc/qnero` is root-owned, so without it the script cannot
  write the key at all.
- **`chown qnero:qnero`.** The unit runs `User=qnero` and passes the file as
  `--node-key-file`. A root-owned 0600 key is unreadable to that user, so the node exits 1
  with `Service(Network(Permission denied (os error 13)))` on every start, and
  `Restart=always` turns that into a crash loop whose message names neither the file nor the
  permission. Section 6's checklist is where a reinstall that drops the ownership is caught.

Four things that script handles and a hand-rolled command gets wrong:

- **The peer id prints on stderr**, so a naive `> file` loses it. Recover it later with
  `qnero-node key inspect-node-key --file /etc/qnero/node-key`.
- **`key generate-node-key` resolves a chain first**, even with `--file` given and even though
  the id is then unused, and this tree refuses an empty `--chain` by naming its chains. So
  `--chain` has to be passed.
- **A bootnode's identity must never rotate.** Its peer id is published in other people's
  spec files. Never `--unsafe-force-node-key-generation`, and never let the node generate one
  into its base path, where a base-path wipe would silently change the network's entry point.
- **It refuses an apex hostname.** `<domain>` is proxied and p2p is raw TCP, so a multiaddr
  pointing at the apex blackholes every dial, and the symptom turns up days later on somebody
  else's machine. Pass `node.<domain>`. `QNERO_ALLOW_APEX=1` is there for a zone that really
  is not proxied.

Pass the key as `--node-key-file`. Never `--node-key <hex>`: argv is
world-readable in `ps`.

### Writing the bootnode into the spec

`bootNodes` sits **outside genesis**, so filling it in does not move the
genesis hash and nothing has to be regenerated. This is the exact edit, on the
host's copy:

```bash
PEER_ID=$(qnero-node key inspect-node-key --file /etc/qnero/node-key)
spec=$(mktemp)
jq --arg addr "/dns/node.<domain>/tcp/30333/p2p/$PEER_ID" '.bootNodes = [$addr]' \
   /etc/qnero/qnero-testnet.json > "$spec"
sudo install -m 0644 -o root -g root "$spec" /etc/qnero/qnero-testnet.json
rm -f "$spec"
```

Three things this is not. It is not `generate-bootnode-key.sh`, which would
mint a second identity if it were pointed at a path with no key on it; the peer
id is **read** out of the key that is already there. It is not run on the
workstation, where `/etc/qnero/node-key` does not exist. And the hostname is
`node.<domain>` rather than `<domain>`, because the apex is proxied and a
proxied record blackholes p2p. `deploy-testnet.sh spec` prints this exact
command after every spec copy.

That edit is what a first launch does, before the repository knows the peer id
of a node that does not exist yet. **Then put the same multiaddr into the
repository**, through `QNERO_BOOTNODES` in section 4, and commit it. Until that
is done, `deploy-testnet.sh spec` copies a file with an empty list over the
host's and the entry is lost on every deploy; once it is done, the two copies
are byte-identical and the stage is idempotent. The reproducibility test
compares everything except `bootNodes` and validates the multiaddr shape, so a
committed list keeps it green.

One caveat, found 2026-09-21: the committed spec's runtime wasm was exported by
a binary built in a checkout at another path (the worktree PR #5 came from),
and a build of the same sources with the same compiler and lock file in this
checkout produces a wasm that differs in symbol names and custom-section order.
The likely cause is cargo's crate metadata hash, which for path dependencies
includes the path. Until the spec is regenerated at the next relaunch the byte
comparison fails here, and it must not be regenerated before then: a different
wasm is a different genesis hash, which would cut new nodes off from the live
chain. Nothing about a node release depends on it; the node stage copies the
binary and the host keeps its spec.

A peer id is public and belongs in a public repository. The key that produces
it is not, and it never leaves `/etc/qnero/node-key`.

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

Before the first start, check that every file a service user has to read is
readable by that user. Each of these is root-owned by default and each is a
crash loop if it stays that way:

```bash
sudo ls -l /etc/qnero/node-key /etc/qnero/node.env /etc/qnero/faucet.env
# node-key    qnero:qnero          0600
# node.env    root:root            0600   (systemd reads it before dropping to the user)
# faucet.env  root:qnero-faucet    0640
```

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
ss -ltn | grep -E ':(9944|30333|3333)'    # all three, and 30333 is the one to look at
```

**Check 30333 in that list rather than trusting the unit.** The sandbox in
`qnero-node.service` names the address families the node may open, and litep2p
decides what to listen on by calling `getifaddrs(3)`, which glibc implements
over a netlink socket. A `RestrictAddressFamilies=` without `AF_NETLINK` makes
that call fail, and what follows is not a crash: the node logs
`failed to fetch network interfaces` and `litep2p started with no listen
addresses, cannot accept inbound connections` among a hundred startup lines,
binds 9944, 3333 and 9615 normally, authors blocks normally, and never opens
30333 at all. A seed node whose peer id is published in other people's spec
files, which nobody can ever dial. The shipped unit carries `AF_NETLINK` for
exactly this; the `ss` line is what catches a unit that lost it.

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

# The trusted-proxy list, WITHOUT which every limit below counts the CDN
# rather than callers. 00-qnero-common.conf includes this file, so nginx -t
# fails while it is missing rather than reloading a configuration whose limits
# have quietly become global.
sudo ./scripts/fetch-real-ip-ranges.sh /etc/nginx/qnero-real-ip.conf
grep -c '^set_real_ip_from' /etc/nginx/qnero-real-ip.conf    # a dozen or more
# Ubuntu ships /etc/nginx/sites-enabled/default, which also declares
# `listen 80 default_server`, and so does qnero-10-default. Two of them is
# `nginx -t` failing with "a duplicate default server for 0.0.0.0:80" and the
# reload never running. Leaving the distro one instead of ours is worse than
# the error: an unknown Host would be served /var/www/html under the wildcard
# certificate rather than refused.
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

The webroots stay root-owned. `deploy-testnet.sh` stages each tree into an
`mktemp -d` of the deploy account's own and finishes with one
`sudo rsync --chown=root:root`, so nothing under `/var/www` is writable by the
account that ships builds. That `--chown` is the whole of it: `rsync -a`
implies `-o -g`, so without it the replace would hand the deploy account
ownership of everything nginx serves, Qloak's bundle included.

**Why the `set_real_ip_from` list is a precondition rather than a nicety.**
Until nginx has it, the realip module never rewrites `$remote_addr`, every
request arrives from one of a handful of CDN edge addresses, and all three
limit zones count the whole internet as one caller:

- `limit_conn rpc_conn 16` on `rpc.<domain>` becomes sixteen concurrent WebSockets for
  everybody at once. The seventeenth wallet or explorer tab in the world gets 429 while
  the node sits idle, and an operator testing from one machine sees nothing wrong.
- `limit_req zone=rpc_calls` becomes 240 calls a minute shared by everybody.
- `limit_req zone=faucet_claim` becomes 6 claims a minute shared by everybody, so one
  abusive client locks every other claimant out.

Measured on nginx 1.24.0 with these files: twelve callers carrying twelve
distinct `CF-Connecting-IP` headers got eight 200s and four 429s with no list,
and twelve 200s with one. That is why the include is unconditional and why the
generator runs before `nginx -t` above rather than after it.

Six rules those files encode, each of which cost an outage somewhere:

- **`rpc.<domain>` proxies with `Host: 127.0.0.1:9944`, the upstream's own authority.** A
  `$host` there is the whole failure below. jsonrpsee's host
  filter is switched on by `--rpc-cors` being set to anything other than `all`, and the
  allowlist it builds is exactly `localhost:<port>` and `127.0.0.1:<port>`. Forwarding the
  public name gets every call answered `Provided Host header is not whitelisted.` as
  plain text, which is not JSON-RPC, so both wallets and the explorer report the endpoint
  as unreachable while the node is answering perfectly on loopback and its log says
  nothing. Browser origin checking is untouched: `Origin` is what `--rpc-cors` validates,
  and nginx passes it through unchanged.

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
- **The explorer's policy carries `script-src 'self' 'wasm-unsafe-eval'`, and it is not
  decoration.** `@polkadot/api` awaits `cryptoWaitReady()` when its socket connects and
  `@polkadot/wasm-crypto-init` ships the wasm-only builder, so a policy that refuses
  WebAssembly makes that call resolve **false** rather than throw: `ApiPromise` never emits
  `ready` and silQ Road reports the endpoint as unreachable while the node is answering
  normally. Nothing static catches it, since `nginx -t` reads syntax and the root URL
  returns 200 either way, which is why section 10 loads the page and looks for a block.

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

**The Turnstile pair is a precondition and the service enforces it.** `serve`
refuses to start with an empty `QNERO_FAUCET_TURNSTILE_SECRET` unless
`QNERO_FAUCET_ALLOW_NO_CAPTCHA=1` is set in the same environment file, so a
first launch cannot quietly be a faucet with no challenge. The rate limits are
not a substitute: a `qn1` address is minted locally for nothing, so the
per-address cooldown bounds nobody, and the per-client limit counts an IPv6
/64, which a requester with two prefixes rotates through. What is left is the
prover at one drip at a time, which takes a 100 000 QNR endowment down in about
three days of somebody's attention. Set the pair, or set the override and know
which decision was made.

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
4. It logs `ready, N QNR spendable across M note(s)`.

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

**The explorer, in a browser rather than with curl.** A root-URL 200 proves
only that files are being served, and the one failure mode that matters here
looks exactly like a healthy page until the socket should have connected: if
the policy is missing `'wasm-unsafe-eval'`, `cryptoWaitReady()` resolves false,
`ApiPromise` never emits `ready`, and after fifteen seconds the page says the
node did not answer. So load `https://explorer.<domain>/`, wait for the status
strip to read **connected**, confirm the head block number matches the node's,
and open a block page. Check the header is what shipped:

```bash
curl -sSI https://explorer.<domain>/ | grep -i content-security-policy
# ... script-src 'self' 'wasm-unsafe-eval' ...
```

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
qnero-wallet --node https://rpc.<domain> --file /tmp/probe.seed sync
# -> received 1 note(s) worth 10.00 QNR
```

**`https://` for the CLI wallet and `wss://` for the two browser apps**, at the
same hostname and the same nginx vhost. `qnero-wallet` speaks JSON-RPC over
HTTP and its client rejects a WebSocket URL outright with
`Unknown Scheme: unknown scheme 'wss'`, which reads like a broken endpoint and
is a scheme the binary never had.

A drip is about ten seconds of proving and then up to one block, so two minutes
end to end is the expected time.

**Each caller gets its own share of the limits.** This is the check that catches a
`set_real_ip_from` list that was never written, and it needs two source
addresses, because from one machine a global limit and a per-caller limit look
identical:

```bash
# on the host, before anything else: the list is there and it is not comments
grep -c '^set_real_ip_from' /etc/nginx/qnero-real-ip.conf

# from two different machines at once, each opening several sockets
for i in $(seq 1 6); do
  curl -sS -o /dev/null -w '%{http_code}\n' -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' \
    https://rpc.<domain> &
done; wait
```

Every one of those should be 200. A 429 from the second machine while the first
is idle means `$remote_addr` is still the CDN.

**The webroots are still root-owned**, which is what stops the deploy account
rewriting the page that handles seeds:

```bash
ls -ld /var/www/wallet.<domain> && ls -l /var/www/wallet.<domain>/assets | head -3
# every line root root
```

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

**The height it remembers.** A node that lost its database and resynced from
the spec answers every call happily and serves both wallets an empty tree, and
the height is the one reading that gives it away. The monitor keeps the best
height it has seen in `$MONITOR_STATE_DIR/height` and alerts when the head
falls more than `MONITOR_HEIGHT_DROP` (100 blocks) below it, so a floor no
longer has to be raised by hand as the chain grows. It alerts as well when the
head has not moved for `MONITOR_STALE_SECS` (1800 s, fifteen block intervals),
with the peer count and `isSyncing` in the message, because a stall with peers
is a different problem from a stall without them. `MONITOR_MIN_HEIGHT` is still
there as an optional absolute floor, 1 by default, and it covers the one case
the memory cannot: a monitor whose state directory is as new as the resynced
node it is watching. **After replacing the chain on purpose, delete that state
file and set the new `MONITOR_EXPECT_GENESIS`**, or the monitor alerts on the
new chain until it passes the old one's height.

Three things it does on purpose, all of which are the difference between a
monitor and the appearance of one:

- **It exits 2 while `MONITOR_DOMAIN` is still `<domain>`.** The env file is sourced before
  any default is resolved, so an unedited one stops the monitor in a way the cron log shows.
  The alternative is what a placeholder actually does: `curl` cannot resolve a host with
  angle brackets, so the nginx check fails on the first tick, alerts once, and never clears.
- **It exits 2 when the env file cannot be sourced at all**, and the template's placeholders
  are quoted so that it can be. The file is shell: `MONITOR_DOMAIN=<domain>` unquoted is an
  assignment followed by two redirection operators, bash stops reading the file at that line,
  and everything below it silently never arrives. An operator who filled in the domain and
  the genesis hash but left one shipped line alone would lose `MONITOR_EXPECT_GENESIS`, and
  the check that catches a node which resynced from the spec would be skipped with no message
  at all. Keep a value containing `<` or `>` in quotes, and let the script stop if you do
  not.
- **A recovery really clears the key.** An alert fires once when a check starts failing and
  once when it recovers, and the state file empties as checks recover, so the all-clear is an
  empty file and a check that has recovered can alert again.

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

**A bad binary.** The previous one is already kept. The `node` and `faucet`
stages copy whatever they are about to replace to `<name>.previous` before they
install, and print where they put it, so a rollback is one install and a restart
with nothing to have remembered beforehand:

```bash
sudo install -m 0755 /usr/local/bin/qnero-node.previous /usr/local/bin/qnero-node
sudo systemctl restart qnero-node

# The faucet keeps its own .previous, written by whichever stage installed it,
# the `node` stage or the `faucet` stage, and rolls back the same way.
sudo install -m 0755 /usr/local/bin/qnero-faucet.previous /usr/local/bin/qnero-faucet
sudo systemctl restart qnero-faucet
```

There is exactly one generation of this: a second deploy overwrites
`.previous` with the binary the first deploy installed. Roll back before
deploying again, or keep a dated copy of your own.

A rollback across a runtime change is not a rollback: the chain's state was
produced by whichever runtime executed it. No dispatchable on this chain can
replace `:code`, so the runtime in the genesis wasm is the runtime for the
chain's life, and a runtime change is a new chain.

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

**Refused blocks in the log.** Two warn lines are policy and self-healing:

```
randomx: budget refusal for block #N on parent 0x…: Side-branch block #N … the side-branch budget is spent; retry in S s
randomx: budget refusal for block #N on parent 0x…: Block #N … needs a RandomX cache fill … the seed-fill budget is spent; retry in S s
```

The first is a block on a side branch whose difficulty is below an eighth of
the tip's, offered faster than `--side-branch-budget` (default 900 an hour)
admits: a long-partitioned minority rejoining, or somebody spamming cheap
branches. The second is a block off the tip that would need a 256 MiB RandomX
cache fill, offered faster than `--seed-fill-budget` (default 24 an hour)
admits: junk seals naming old epochs, or a branch carrying its own seed block.
Each is printed at most once a minute per budget with the count it hid. The
`Verification failed … received from (peer)` line and the peer drop that follow
are expected: sync offers the branch again when the bucket has refilled, and a
heavier honest chain always gets in at that rate. A steady stream from many
peer identities is the attack the budgets exist for, and the four counters on
`:9615` (`qnero_pow_side_branch_charged_total`, `…_refused_total`,
`qnero_pow_seed_fill_charged_total`, `…_refused_total`, beside
`qnero_randomx_cache_fills_total`) say how much it is costing. `Invalid seal for
block` at error level is something else: a seal that does not meet the target,
which on a healthy network is a chain-split alarm.

To let a known-honest deep branch in faster than the default, restart with a
higher budget, or `--side-branch-budget 0` for unlimited; the node never needs
a database reset to adopt a heavier chain.

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
