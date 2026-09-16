# silQ Road, the Qnero explorer

silQ Road is a block explorer for a Qnero chain. One static directory, one
WebSocket to a node, no server-side indexer and no third party: every number on
every page is read live from the node the page is configured with, and the only
other requests are to the host serving the page, for `config.json` at startup
and for the page's own assets.

The directory is `explorer/`, the built site is `dist/`, and the name on the
page is silQ Road, spelled that way everywhere: lowercase `s`, capital `Q`, a
space, capital `R`.

It is built for a chain where value is private by default, so it is as careful
about what it declines to show as about what it shows. The "What this chain
reveals" page states both halves in plain words, and the presentation rules
behind it are in [What it will not do](#what-it-will-not-do).

## Pages

| Route | What it holds |
|---|---|
| `#/` | Head and finalized height, rolling block time, difficulty and an estimated hash rate, the RandomX seed height and its next rotation, tree leaves and depth, the settled nullifier count, pool value, the newest block's coinbase, and a live list of recent blocks |
| `#/blocks` | A paged list, newest first |
| `#/block/<height or hash>` | Header fields, the coinbase note, every settlement in full, every shield entry, refused calls, and every extrinsic summarised |
| `#/settlement/<extrinsic hash>` | One settlement: its slots, the anchor window, and what it publishes and does not |
| `#/search?q=` | A height, a block hash, an extrinsic hash, a nullifier or a commitment |
| `#/reveals` | What an observer learns per block, and what stays hidden |

Routing is in the fragment, so any static host serves it with no rewrite rule
and a pasted link survives a refresh.

## Run it

silQ Road needs a node to read. For a local one, from the repository root:

```
./target/release/qnero-wallet keygen
export QNERO_MINER_KEY=$(./target/release/qnero-wallet miner-address | grep -o 'qnm1[a-z0-9]*')
nice -n 19 ./chain/target/release/qnero-node --dev --tmp --mining-threads 1
```

Then, in `explorer/`:

```
nice -n 19 npm ci
nice -n 19 npm run dev
```

`npm run dev` serves on `http://127.0.0.1:5173` and reads `public/config.json`,
which points at `ws://127.0.0.1:9944` out of the box.

## Build it

```
nice -n 19 npm run build
```

The result is `dist/`: an `index.html`, one JS bundle, one stylesheet and
`config.json`. Asset URLs are relative, so the directory works at a domain root
and in a subdirectory without a rebuild.

The bundle is about 1.2 MB, 440 kB compressed, and almost all of it is
`@polkadot/api`, which carries the SCALE codec and the type registry the event
decoding needs.

## Configure it

`config.json` sits beside the built assets and is read at startup, so one build
serves a devnet and a testnet. Edit the file in `dist/`, or replace it at
deploy time; nothing about a chain is compiled in. What ships names the public
testnet, which has been live since 2026-09-15, because the header prints this
chain name to whoever opens the page:

```json
{
  "rpcEndpoint": "wss://rpc.qnero.io",
  "chainName": "Qnero testnet",
  "recentBlocks": 12,
  "searchWindowBlocks": 512,
  "nullifierPageLimit": 25
}
```

For a local `--dev` node, point it at `ws://127.0.0.1:9944` and name the chain
`Qnero devnet`. `npm run dev` reads `public/config.json` as it is; the
Playwright suite rewrites the copy in `dist/` after the build, so the file the
repository ships stays the one a deployment wants.

| Key | Meaning |
|---|---|
| `rpcEndpoint` | Required. Must be `ws://` or `wss://`: the live head is a subscription and subscriptions are WebSocket only |
| `chainName` | Required. The chain page's heading, and the header's status slot on every other page |
| `recentBlocks` | Blocks in the home list and in the rolling block-time window. Default 12 |
| `searchWindowBlocks` | How far back a search by extrinsic hash or nullifier walks before giving up. Default 512. A walk that needs a block's events also needs the node's state at that block, and a node started without `--state-pruning archive` keeps only a few hundred blocks of it, so on a pruned node a walk ends at the bottom of that window and says so |
| `nullifierPageLimit` | Pages of 1000 keys the nullifier count reads before reporting a floor instead of a total. Default 25 |

A page served over `https` cannot open a `ws://` socket. Put the node behind
the same TLS the site uses and configure `wss://`.

### When the page says No connection

Every figure here is read live, so a node that does not answer inside fifteen
seconds leaves the site with nothing to show. The page says which endpoint did
not answer, offers one `Try again`, and retries on its own at 5, 15 and 60
seconds with the header counting it down. If it keeps failing, the endpoint in
`config.json` is the first thing to check: it is read at startup from beside
the built assets, and a `wss://` host that resolves but refuses the upgrade
fails exactly like a node that is down.

## Deploy it

Copy `dist/` to a webroot and serve it as files. The site needs no rewrite rule
of its own, because every route lives in the fragment.

```nginx
server {
    listen 443 ssl;
    server_name explorer.example.invalid;

    ssl_certificate     /etc/ssl/example/cert.pem;
    ssl_certificate_key /etc/ssl/example/key.pem;

    root /srv/qnero-explorer;
    index index.html;

    # The runtime config, never cached: it is how one build serves two chains.
    location = /config.json {
        add_header Cache-Control "no-store" always;
    }

    # Hashed assets, cached hard.
    location /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }

    # The page talks to the node and to nothing else.
    add_header Content-Security-Policy
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' wss://rpc.qnero.io; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
}

# The node's WebSocket under the same origin, if it is served here too.
# map $http_upgrade $connection_upgrade { default upgrade; '' close; }
#
# location /rpc {
#     proxy_pass http://127.0.0.1:9944;
#     proxy_http_version 1.1;
#     proxy_set_header Upgrade $http_upgrade;
#     proxy_set_header Connection $connection_upgrade;
#     proxy_read_timeout 600s;
# }
```

Every host, path and certificate above is a placeholder.

**`'wasm-unsafe-eval'` in `script-src` is not optional.** `@polkadot/api` calls
`cryptoWaitReady()` when the socket connects, and `@polkadot/wasm-crypto-init`
resolves to the wasm-only builder in a browser, with no asm.js fallback. Under a
policy that refuses WebAssembly compilation the call resolves **false** rather
than throwing: `ApiPromise` never emits `ready`, `connect()` never settles, and
the page reports the endpoint as unreachable against a node that is answering
normally. Nothing in a static check catches it, since `nginx -t` reads syntax
and a root-URL probe returns 200 either way, so `npm run e2e` serves the built
site under this exact policy.

The tighter alternative, for a host that will not permit wasm compilation at
all, is `initWasm: false` in the `ApiPromise.create` call in
`src/chain/api.ts`. The only crypto this page uses is `blake2AsHex`, and
`@polkadot/util-crypto` keeps a pure-JS branch for it, so the explorer works
either way; the header is what this repository ships.

## What it will not do

Each of these is a decision.

- **It never asks for a Merkle proof.** `zkTree_getMerkleProof` names one leaf
  to whoever runs the node, which is the correlation a wallet's local tree
  rebuild exists to avoid. An explorer making that call for a viewer would hand
  the node a per-viewer leaf-interest log. Leaves and the root are read as
  public ranges, and `npm run lint` fails on the spellings of the call it knows (the
  `zkTree_getMerkleProof` method, the `ZkTreeApi_get_merkle_proof` runtime call
  behind `state_call`, `state_callAt` and `archive_v1_call` at whichever
  parameter position that method's layout puts the name in, and the polkadot-js
  sugar `api.call.<api>.getMerkleProof` with its snake-case and computed-key
  spellings). A template literal or an aliased reference would pass the fence,
  which is a reviewer's aid for this codebase and never a security boundary; the
  privacy property rests on the reads the code makes. A syntax fence fails open,
  so `tests/lint-fence.test.ts` runs each spelling through the shipped selectors
  and fails if one of them lints clean.
- **It does not read a settled nullifier as a note that was spent.** A leaf
  slot has two input positions and its two nullifiers mark both of them
  consumed. A position holding a real input spends one note; a position holding
  a dummy input publishes a nullifier over no note, and the two are the same
  uniform hash in the public record (`docs/CIRCUIT.md` section 5, the
  `NF_DUMMY` tag, and section 9.5 on settling both nullifiers of every real
  slot). At least one position of a settled slot is real, so a slot spends one
  note or two. Every page that shows a nullifier says that, and the home page's
  figure is twice the slots that settled, which bounds the notes this chain has
  spent from above.
- **It renders a slot's two outputs unordered.** Which one is the sender's
  change is hidden only because the wallet draws the payment's output slot per
  spend. Ordering them, or labelling one "to" and one "change", would
  reintroduce by presentation what the protocol pays to hide.
- **It has no miner table.** The author label is `H(cvk, parent_hash)` and
  changes every block, so grouping by it groups nothing and any heuristic that
  looked like it worked would be a privacy regression shipped as a feature.
- **It does not reprint a refused call's arguments.** A transparent transfer
  the runtime's filter refuses still enters a block and its arguments stay in
  the body forever. The block page names the call, says why the arguments are
  public, and leaves them where the chain put them.
- **It does not sort by ciphertext size or by anchor gap.** Both are documented
  open leaks. The size is shown per leaf, and a size other than 1792 bytes is
  marked, because that is worth knowing; neither is a sortable column.
- **It does not decode a settlement's anchor height.** The anchor is a public
  input inside the proof. The settlement page states the window the chain
  enforced, which is what the site can establish from chain state alone.
- **No analytics, no fonts, no images, no CDN.** The only requests the page
  makes are to the configured node and to the host serving the page, which
  answers for `config.json` at startup and for the page's own assets.

## What it reads, and what that costs

There is no index behind the site, so anything the chain does not key directly
is a bounded walk that says how far it looked.

| Page | Reads |
|---|---|
| Home | One header, four storage values, and one state decoration per recent block carrying that block's events and timestamp. Blocks are cached by hash, so a poll fetches only what is new. The three consensus constants are three runtime calls, made after the connection is published |
| Block | One body and one state decoration |
| Settlement from a block link | One body. From a bare hash, one body per block walked backwards, capped at `searchWindowBlocks` |
| Search, a 32-byte value | Nothing, until a button says so. The same 32 bytes can be a block hash, a nullifier or a commitment, so the page cannot tell which without asking, and the request is what leaks |
| Search, block check | One `chain_getHeader` whose one parameter is the value itself. The answer names nothing the chain does not already publish; the question names the value, so it is behind the same click as the rest |
| Search, nullifier | One point lookup on a constructed key, which names that nullifier to the node: a `Blake2_128Concat` key is the hash followed by the raw key. The page prints that before it offers the button, and the lookup runs once per click, pinned to the block the chain was at when it was asked, so an imported block never re-sends it |
| Search, commitment | `ZkTree::Leaves` newest first, 256 keys per request, capped. A match is followed by a read of the window it came out of, so no request the scan makes names one leaf |
| Nullifier count | `state_getKeysPaged` at 1000 keys a page, capped by `nullifierPageLimit`, and reported as a floor when it hits the cap. It is pinned to a baseline block that moves once per recent-list window, and the blocks after the baseline are counted from the settlement events the recent list already holds, so an imported block costs no new walk. A block after the baseline whose state did not answer settled events nobody decoded, so the figure carries a `+` and its note names how many blocks went unread; a baseline walk that did not answer leaves no figure to mark and reads as "not a count" |

Every one of these degrades rather than failing a page. A refused unsafe method
or a missing runtime call empties the fields that needed it and leaves the rest
readable; a block whose state the node no longer keeps still renders its header
and its body, on the block page and on the settlement page alike, with the
panels that read events saying that the state was not kept; and a walk that
reaches the bottom of a pruned state window ends as a bounded miss that names
the boundary. A node that never answers at all is a
written failure after fifteen seconds naming the endpoint that did not answer
and the file it is set in, so the commonest deployment mistake does not read as
an indefinite "connecting".

A negative is never inferred from a failure, because the absence is the answer
someone acts on. "Not in the settled nullifier set" is rendered only when the
node answered, and a refused or drifted read reads as "not answered". A walk
reports a pruned state window only when the node named one, so a dropped socket
three blocks into a 512-block walk raises an error where it would otherwise have
concluded "not published" about 509 blocks nobody read. A block whose state did
not answer says so in every panel that needed it, down to the outcome column,
and it is not cached, so a blip does not pin those rows for the life of the
tab. A count follows the same rule, and a heading counts as a claim: a panel
over an unread event log is titled "(not counted)", the refused-calls panel is
rendered over one so a refusal is never reported by absence, and a total that
spans blocks which went unread is marked and says how many. The same rule reaches the sentences beside a figure: a settlement whose
block state was not kept is never written up as an extrinsic that settled no
slot, the newest block is called empty of a coinbase note only once a state
read has answered for it, and a nullifier count that did not answer says so
instead of printing a dash under a note about what the number would have meant.

## Two decoder seams worth knowing about

A generic Substrate client gets both of these wrong silently.

**The header.** `qp_header::Header` carries `zkTreeRoot` between
`extrinsicsRoot` and `digest`. Without the custom type this application
registers, polkadot-js decodes the digest out of the `zkTreeRoot` bytes and
every header comes back as plausible garbage and nothing throws. Block hashes
are Poseidon2 over a felt encoding, and Blake2 of the SCALE header is a
different number that looks exactly as plausible, so no hash here is ever
recomputed locally. They come from the node.

**The body.** The ML-DSA-87 signature is a fixed 7219-byte array and polkadot-js
refuses any fixed array above 2048, so the typed `chain_getBlock` throws on
every block carrying a signed extrinsic. `src/lib/extrinsics.ts` walks the
envelope itself, using the signature lengths and the extension list out of the
runtime's own metadata, and leaves a call unresolved rather than guessing a
width it does not know.

Nothing else is hand-decoded. Storage, events, constants and call names all come
from metadata, which is read on every start: this runtime has changed event
layouts inside one `spec_version`, so a compiled-in position is a decoder that
goes quietly wrong. The storage items the site builds keys for are checked
against metadata with the hashers they assume, because an absent key and an
empty map are indistinguishable and the difference is a site that reads "0
leaves, 0 nullifiers" with no error anywhere.

## Tests

```
nice -n 19 npm run lint
nice -n 19 npm run typecheck
nice -n 19 npm test
nice -n 19 npm run build
```

`npm test` is vitest over the decoders and the reads built on them: the
settlement, coinbase and shield event shapes, the header and its digest, the
extrinsic envelope, the `U512` difficulty, the units, the seed-height and
rotation rules, the route grammar, the three answers a page is allowed to give
about a block whose state the node did not keep, what a count may say over an
unread event log, and the Merkle-proof lint fence against every spelling of the
call. The fixtures in
`tests/fixtures/` were captured from a `--dev --tmp` node that had shielded once
and sent once, by:

```
nice -n 19 npx vite-node scripts/capture-fixtures.ts -- ws://127.0.0.1:9944
```

Nothing in them is hand-written and nothing in them names the machine they came
from.

### The end-to-end smoke

```
nice -n 19 npm run e2e
```

It starts its own dev node at one mining thread, shields once so an entry
exists, sends once so a settlement exists, builds the site, serves the build,
and drives a headless Chromium over the home, block, settlement, search and
reveals pages asserting the values the wallet reported, and the words those
pages use about what a settled nullifier stands for. It also counts the
frames the page sends that carry the query's own 32 bytes, so a read that runs
before its button, or twice after it, fails the run; it relays the page's own
socket and answers the state reads at one block the way a node below its
pruning window does, so the settlement page is driven through the failure that
used to render as an extrinsic which settled nothing; it opens genesis, an unknown block hash and a
settlement at a block this chain does not have, which are the pages a
dereference used to take down and the one that used to fail into a bare error
box with nothing to click;
and at 400 px it checks that a wide table scrolls inside its wrapper
and that the skip link lands in the page with the route intact. It stops the
node by its pidfile and does not finish until the RPC port is free again.

It needs release builds of both binaries and it needs port 9944 to itself:

```
cd chain && LIBCLANG_PATH=/usr/lib/llvm-18/lib nice -n 19 cargo build -j 4 --release -p qnero-node
nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel
```

Proving runs at `RAYON_NUM_THREADS=4`. The whole run is about a minute on top of
the builds.

## Layout

```
src/lib/        pure decoders, no network and no framework: hex and SCALE,
                units, seed height, difficulty, digest, header, events,
                extrinsic envelopes
src/chain/      the connection and the reads: metadata, blocks, state, leaves,
                bounded searches
src/app/        the hash router, the connection context, one async hook
src/pages/      one file per route
src/components/ the shared shell and the field, panel and notice primitives
src/styles/     tokens.css is the family resemblance, app.css is this app
tests/          vitest over src/lib and src/chain/config, with captured fixtures
e2e/            the dev-node lifecycle and the Playwright smoke
scripts/        the fixture capture
```

`src/styles/` follows MyMonero's stylesheet, rebranded. See `NOTICE`.

Known limit: the settled-nullifier baseline walk on the home page is keyed on
the baseline height, so a reorg that replaces the block at that height keeps
the walk from the abandoned branch until the page reloads or the baseline
moves.
