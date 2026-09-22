# The external watchdog entries for the Qnero testnet

The other half of the monitoring, and the half that can say the box is down.
`packaging/monitor/monitor.sh` runs on the host and tells you *why* something
broke; this runs somewhere else entirely and tells you *that* it broke. Keep
both. A monitor that lives on the box it watches cannot report that box being
down, and one that only probes loopback is blind to the reverse proxy: a
sibling deployment served a CDN 521 for nine hours with nginx dead, every
application behind it healthy, and its on-box monitor green the whole time.

These are descriptions to add to whatever external checker is already running,
on a five-minute timer with a two-tick debounce, skipping the tick silently
when the checker's own uplink is down so a local outage cannot fire false
alarms.

## Why root-URL checks are nearly worthless here

All three web properties are static files. The node can be entirely dead, the
faucet can be out of funds, and `https://<domain>/`, `https://wallet.<domain>/`
and `https://explorer.<domain>/` all still answer 200. Adding this deployment
means adding **deep** checks, and the shallow ones are only there to separate
"the site is gone" from "the chain is gone".

## The entries

| Check | Request | Passes when |
|---|---|---|
| site | `GET https://<domain>/` | exactly 200 |
| wallet | `GET https://wallet.<domain>/` | exactly 200 |
| wallet config | `GET https://wallet.<domain>/config.json` | 200 and `.rpcEndpoint == "wss://rpc.<domain>"` |
| wallet isolation | `GET https://wallet.<domain>/` headers | `cross-origin-opener-policy: same-origin` and `cross-origin-embedder-policy: require-corp` are both present |
| explorer | `GET https://explorer.<domain>/` | exactly 200 |
| explorer config | `GET https://explorer.<domain>/config.json` | 200 and `.rpcEndpoint == "wss://rpc.<domain>"` |
| explorer wasm policy | `GET https://explorer.<domain>/` headers | `content-security-policy` contains `'wasm-unsafe-eval'` |
| rpc health | `POST https://rpc.<domain>` with `system_health` | 200 and `.result.peers` present and `.result.isSyncing == false` |
| rpc height | `POST https://rpc.<domain>` with `chain_getHeader` | 200, `.result.number` present, and advancing within 30 minutes; configure `QNERO_HEIGHT_STALL_SECS=1800` to match the on-box stall window |
| faucet status | `GET https://faucet.<domain>/status` | 200, `.configured == true`, `.captchaEnabled == true`, `.dripQuanta > 0`, `.cooldownHours` positive and finite |
| faucet genesis | `GET https://faucet.<domain>/status` | 200 and `.genesis` equals the deployment's genesis hash |
| faucet health | `GET https://faucet.<domain>/health` | exactly 200 (it is 503 when drained, when the wallet is not open, or when the node has not answered in six minutes) |
| p2p reachable | TCP connect `node.<domain>:30333` | connects |
| stratum reachable | TCP connect `node.<domain>:3333` | connects |
| edge certificates | TLS expiry of the four proxied names | more than 14 days left |

`node.<domain>` is DNS-only at the CDN, so those two TCP checks are a real
end-to-end test of the box's network path that none of the proxied names can
give.

Three notes on what these do and do not prove:

- **The wallet isolation check is the one that catches a silent 4x slowdown.** A location
  block in the wallet vhost that declares its own `add_header` drops every header from the
  server block, COOP and COEP vanish, and Qloak falls back to the single-threaded prover:
  37.6 s a payment instead of 11.2 s, with no error anywhere and only the settings screen
  saying which module it got.
- **The explorer policy check catches a page that can never connect.** `@polkadot/api`
  awaits `cryptoWaitReady()` on connect and `@polkadot/wasm-crypto-init` ships the wasm-only
  builder, so a policy without `'wasm-unsafe-eval'` makes that call resolve false rather than
  throw. `ApiPromise` never emits `ready`, and silQ Road reports the endpoint as unreachable
  while the node is fine, which sends whoever is on call to debug the node. The root-URL
  check answers 200 throughout.
- **The height check has to compare across ticks.** A JSON-RPC endpoint that answers is not a
  chain that is advancing, and a node stops authoring when its tip is stale, when it has no
  peers or during an initial sync, unless configured for solo authoring. The 120 s
  block target permits variable PoW arrival times. Use a 30-minute stall window,
  fifteen target intervals, on both monitors. Keep RPC and service failures on
  their existing short debounce.
- **The faucet's `.genesis` is the off-box second copy of the genesis check.** The on-box
  monitor holds the same hash in `MONITOR_EXPECT_GENESIS`, and a monitor on the box cannot
  report the box being down. The faucet reads the hash off the node it pays from, so a
  `.genesis` that has moved is a node serving a chain this deployment is not, which is what a
  lost database resynced from the spec looks like. Configure it with the hash from
  `Initialized genesis block` at first start.
- **The remembered height is reset at a chain replacement, and only then.** Both monitors
  compare each tick's height against the highest they have seen, so a fresh genesis reads as
  a node that fell days behind and alerts every tick until the new chain passes the old one's
  height. At a deliberate replacement, delete the on-box `$MONITOR_STATE_DIR/height` and
  reset the external checker's remembered height in the same pass as updating the expected
  genesis hash. An external checker that already treats a lower height as a new chain and
  re-baselines itself needs nothing here; confirm which it does against its own state
  directory rather than assuming.
- **`/status` does not prove a claim would settle.** A configured server is not the page
  carrying the matching Turnstile site key, nor Cloudflare accepting the domain, nor a
  funded faucet actually paying. The only thing that proves the last one is a synthetic
  claim to a throwaway address, once a day. It costs one drip and it is worth it; run it
  against an address whose wallet nobody syncs, and exclude the response body from the
  alert text.

`GET /status` and never `POST /drip` for the routine check. A probe must not be
able to submit a claim.
