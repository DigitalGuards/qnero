# Qloak, a Qnero wallet (M10)

Qloak is a wallet that runs in a page. It creates a spending key here,
encrypts it here, scans the chain here, proves a payment here in a background
worker, and contacts nothing but the node you configure. There is no server
component and there is no account: the only thing between this page and a
chain is one WebSocket to a node.

The directory is `wallet-web/`, the built page is `dist/`, and the name on the
page is Qloak. `qnero-wallet` is the command-line wallet in
`crates/qnero-wallet`, and the two are named apart on purpose: this readme
says "Qloak" for the page and "the command-line wallet" for the binary.

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
testnet and nothing about a chain is compiled in. What ships names the public
testnet, which has been live since 2026-09-15:

```json
{
  "rpcEndpoint": "wss://rpc.qnero.io",
  "chainName": "Qnero testnet",
  "wasmBase": "wasm/",
  "numLeaves": 6,
  "expectedProvingSeconds": { "threaded": 12, "single": 36 }
}
```

- `rpcEndpoint` is the default. The settings screen overrides it and that
  choice is what persists, so a chain of your own is a field rather than a
  rebuild: point it at `ws://127.0.0.1:9944` for a local `--dev` node. The
  header names the chain this file does, so a build served to readers has to
  carry the chain it is actually on.
- `wasmBase` is where the prover is served from, relative to the page. The
  threaded module, when there is one, lives at `wasmBase + "threaded/"`.
- `numLeaves` is the private batch's leaf-slot count and has to match the
  runtime's embedded verifier. A proof built at another N has a public-input
  length that verifier cannot read, and the refusal arrives after the whole
  proving cost.
- `expectedProvingSeconds` is the proof alone, per module, from the
  `proveTransfer` rows of the M10 table in `docs/BENCH.md`. The proof is the
  only half of the wait that belongs to this browser: the sending screen quotes
  a payment as that figure plus one block interval, and it reads the interval
  from the chain over `QPoWApi_get_target_block_time`, because one node binary
  serves a 120 s public chain and a 12 s dev chain and no file here can know
  which. It replaced `expectedSendSeconds`, a single send-to-settled number that
  was right only on the chain it was measured against; that key is no longer
  read. After the first payment the screen quotes what this machine actually
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

  A new wallet records its **birthday**: the head the node it is connected to
  is at, rounded down to a multiple of 1024 blocks, with the leaf count that
  block held as its first watermark. A wallet cannot have been paid into a leaf
  that existed before it did, so it never walks the headers under that block or
  trial-decrypts the ciphertexts under that count. It is recorded as the
  store's first checkpoint, so it is the node's claim like every checkpoint and
  the fork walk rewinds through it; the screen says what was recorded and whose
  claim it is.

  The leaf count beside it is the same kind of claim and nothing checks it when
  it is written. The first sync that has leaves to scan folds the leaves under
  it against that block's own `zkTreeRoot`, which refuses a count recorded too
  high; while the watermark is still that number, any refusal resting on it
  names the birthday and the rescan on the Settings screen, because a watermark
  that was wrong when it was written is not a node being behind and no other
  node can satisfy it.
- **Restore from a seed.** The 64 hex characters, and one optional field: "the
  chain height when this wallet was created, leave empty to scan everything".
  Empty reads the whole chain from leaf zero, which is always correct, and the
  screen quotes what that will take at the rate `docs/BENCH.md` measured before
  anybody chooses it.

  A height is taken as a block number or as a date, and it is recorded rounded
  **down** to the 1024-block epoch below it, so what every node this wallet
  syncs against is told is a coarse public epoch rather than the day the wallet
  was made. Down, so a height a little too high still starts below the first
  transfer. A height **above** the block a transfer arrived in is a transfer
  this wallet never reads and a balance quietly short, with no warning
  anywhere, and the only recovery is a rescan; the field says so and says to
  leave it empty if you are not sure. A date is converted by counting back from
  the node's head at the chain's own target block time and then dropped a whole
  epoch, because that conversion is arithmetic over a block time that holds on
  average, and it needs a node to count back from: with none connected the
  field says that rather than calling the date unreadable, and a block number
  works either way. Something that is neither a number nor a date is refused
  where it is typed rather than submitted as an empty field, because the
  difference between the two is reading the whole chain by accident.
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
  which nullifiers are this wallet's. A per-leaf key the node answers nothing
  for below the count it reports at that same block refuses the pass:
  `ZkTree::Leaves` and `Shielded::LeafBlocks` are required at every index,
  because `pallet-shielded` writes both in the call that appends the leaf and
  removes neither. The chain has no gaps under its own count, so such an answer
  is withheld rather than absent, and stepping over either would hide a payment
  on that leaf behind a watermark written above it. A commitment answered as
  the tree's own all-zero pad below that count is refused the same way:
  `pallet-zk-tree` refuses an append of that digest by name and reads it as an
  unfilled slot everywhere else, and folding one moves no root, so a run of
  them would inflate the leaf count under headers that are honest and put the
  watermark above indices no block has filled.
- **Which rule opens a leaf.** A coinbase is rebuilt from the miner key and the
  public value the chain hashed into its commitment; everything else is
  trial-decrypted. **The kind is derived only from position, and position is
  what the headers authenticate, never from which storage keys a node chose to
  answer.**
  Presence of `Shielded::CoinbaseValues` used to decide it and presence is the
  node's to write, so eight invented bytes on an incoming payment routed it
  onto the coinbase rebuild, which cannot open it, and an invented
  `Shielded::Ciphertexts` beside a withheld coinbase value hid a mined reward
  the other way round. What decides now is the header chain, walked between
  the head and a hash this wallet already trusts and rehashed from each
  header's own preimage, in chunks of `HEADER_WALK_LIMIT` blocks so a
  chain far ahead of the checkpoint syncs in one pass with one chunk resident;
  each block's leaf range, folded and compared against the `zkTreeRoot` its
  header carries, which makes `Shielded::LeafBlocks` advisory; and the coinbase
  position, which is a block's last leaf because the pallet mints it in
  `on_finalize`. So a coinbase value below a block's last leaf is refused, a
  withheld one at any coinbase position is refused, and a ciphertext is
  required at every other position.
- **No rule rests on the author label.** This wallet verifies no proof of work
  and will not in v1, so above its newest checkpoint a node picks every header
  field, the label included, and a rule gated on the label is one the node
  switches off by publishing another. The coinbase value is required at every
  coinbase position whatever the label says, this wallet's own coinbase note is
  rebuilt at every one of them whatever the label says, and the label is read
  afterwards as a cross-check: a label claiming this wallet's block over a
  rebuild that does not match refuses the pass, and a rebuild that matches
  under another author's label takes the reward and reports the disagreement.
  What no per-leaf rule reaches is a node that rebuilds the headers themselves,
  and the defence there is the checkpoint fork walk: the forged head is
  recorded only as a checkpoint, and the first honest node disagrees with it,
  rewinds to the newest checkpoint both stand on and rescans.
  `docs/WALLET.md` carries the per-position table and the section "What a lying
  node can and cannot do", and the same rules are in the command-line wallet's
  `crates/qnero-wallet/src/typing.rs`.
- **Two per-leaf values are bound to a leaf by nothing, and both are open.**
  The first is the ciphertext: `Shielded::Ciphertexts(i)` is tied to leaf `i`
  by nothing on chain, because the commitment the tree authenticates carries no
  ciphertext and `ct_digest` binds the bytes only inside the settlement
  extrinsic at inclusion, which a storage-only reader never fetches. The second
  is where a commitment sits inside its block's own leaf range: the tree sorts
  a node's four children before hashing them, which is what lets a path carry
  siblings with no position, and it mixes in neither the level nor the child
  slot. So a block's `zkTreeRoot` pins that block's leaf multiset and each
  internal node's child multiset and nothing else. Sibling swaps compose at
  every level, so a payment can be moved to any position the range's aligned
  subtrees allow, across group boundaries and onto the coinbase position where
  no ciphertext is owed; and a shorter tree of internal node values served as
  leaves folds to the same root, so the root pins neither the leaf count nor
  the height inside a block. Every root and every header still checks out in
  each case.
- **One part of that the scan catches on its own.** A move that leaves this
  wallet's ciphertext where the chain published it puts a payload that opens
  under this wallet's key beside a commitment that note does not open, and
  opening is authenticated: ML-KEM decapsulation plus an AEAD over this
  wallet's own `pk`. The pass searches that block's own folded leaf range for
  the commitment the note opens, records the note there and puts a warning on
  the balance screen naming both indices. A commitment the block holds nowhere
  is warned and skipped, because a sender who encrypts a payload opening a
  commitment it never published produces the same reading and a refusal would
  be a sync denial anyone could buy with one transaction. What
  stays hidden is a move that takes this wallet's ciphertext with it, and the
  checkpoint fork walk does not recover it, because the headers agree. **A
  rescan against a second node is the recovery**, and a pass that read leaves
  and received nothing says so on the balance screen, as a hint under the
  warnings and at less weight. That sentence is the ordinary case on most
  passes, so it reads as a prompt to check against a second node, and it is the
  command-line wallet's word for word. `docs/WALLET.md` states the whole bound
  and `docs/DESIGN.md` open question 6 records the closure, reading every
  per-leaf value with a `state_getReadProof` trie proof against the header's
  own `stateRoot`, as the next wallet milestone, beside the consensus-level
  alternative that would pin the position and the height in the tree hash.
- **One scan at a time with a payment**, in both directions: a scan reads every note before it starts and
  commits them at the end, and a payment writes `spent` on those same rows the
  moment it settles, so the Settings screen's rescan is disabled while a
  payment is being proved and says so.
- **Balance.** Unspent, pending, off chain, and what one payment can reach,
  with the note table under it.
- **Send.** The fee floor from the runtime's own constants, note selection
  largest first up to two notes, the Merkle paths rebuilt locally at the
  anchor, the header preimage checked against `chain_getBlockHash` before
  anything is proved, the proof built in the worker with its phases named, the
  settlement submitted as a bare unsigned extrinsic, and inclusion matched byte
  for byte. The node gates the sync applies apply here too, in the same order
  and with the same wording: the storage-drift refusal, the genesis binding
  read live off the node, and the leaf gate, which refuses a node whose tree at
  the anchor is shorter than what this wallet has already read. That last one
  is what stands in front of the write-off: a selected note past the end of a
  tree the anchor confirms is marked off chain, every other check the spend
  makes is against the same node's answers, and a losing fork or a head the
  node has not finished executing would otherwise be evidence enough to write
  off a real, spendable note.
- **Receive.** The address as text and as a code, and the miner key behind a
  labelled control, because the miner key is not the address and it carries the
  coinbase viewing key.
- **Settings.** The node, the lock, a rescan, and a plain statement of what
  this wallet reveals to the node. The rescan is disabled while a scan or a
  payment is running, with the reason under it: the one-job-at-a-time rule is
  the screen's as well as the handler's, and a control that presses and then
  refuses is the screen contradicting what it says.

### What it cannot do

**Shielding is a command-line step.** Entering the pool is a signed extrinsic,
and the signature is ML-DSA-87 under the FIPS 204 context. The wasm module
exports no signing at all, and `qnero-wallet`'s extrinsic, fee and selection
modules are not wasm-clean (they reach for `libc`, `ureq`, `clap` and
`twox-hash`). So a browser wallet can predict and recognise a shield, and it
cannot make one. Fund it from the faucet at https://faucet.qnero.io, from
`qnero-wallet shield` followed by a `send`, or from a node configured with its
miner key. Closing this properly means a
wasm-clean crate split and an ML-DSA-87 signer in the module, and that is not
M10.

## Threat model, in plain words

**This is pre-alpha and browser hosted. None of Qnero's own code has been
audited, the public testnet has been live since 2026-09-15 and the network may
be reset.**

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
note selection and the conflict-set rule, memo escaping, the node gates on both
the sync and the spend, the spent reconciliation in both directions, the widths
every storage value is decoded at and the tree capacity `ZkTree::LeafCount` is
bounded by, the refusal of each per-leaf key withheld below that count, one
test per key on both the read layer and the scan, the refusal of the tree's own
pad answered as a leaf below that count, the substituted ciphertext that
nothing refuses and the rescan that recovers the payment, the merge that
keeps a spend's own writes when a scan commits over them, the bound on the
shield-origin walk, the pipelined header walk against a node that answers
headers out of order or a hash for a number its own header chain does not
carry, where a wallet starts reading and what a restore height is rounded to,
and the lint fence that keeps `zkTree_getMerkleProof` out of every spelling it
has.

`tests/header-walk-bench.test.ts` is a measurement and skips itself unless
`QNERO_BENCH_WS` names an endpoint. It runs the walk this wallet had and the
walk it has against one socket and prints both rates; `docs/BENCH.md` carries
the runs.

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
