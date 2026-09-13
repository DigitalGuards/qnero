# Chain release preflight

> Upstream's release process, carried in with the subtree and kept because the
> gates in it are the right gates. Two things in it are not Qnero's: the
> networks (`heisenberg`, `planck`, every `quantus.cat` endpoint) belong to
> `Quantus-Network/chain`, and so does the `quantus-cli` / `quantus exercise`
> tool. Qnero publishes no releases yet. Every command that runs against this
> tree names `qnero-node` and `wbuild/qnero-runtime`, which is what this tree
> builds.

Run this **before** tagging or publishing a `qnero-node` / runtime release.
CI green is not enough. The last ship-blocker we missed was a binary that
could not sync a live chain — a fresh node would have caught it immediately.

Do not skip the sync gate for "small" client changes.

Related:

- Runtime upgrade after the release exists: [`RUNTIME_UPDATE.md`](./RUNTIME_UPDATE.md)
- Warp sync details: [`FAST_SYNC.md`](./FAST_SYNC.md)
- CLI exercise suite: `quantus-cli` README, `quantus exercise`

---

## Gates (in order)

| # | Gate | Required | Passes when |
|---|---|---|---|
| 1 | Build the binary you will ship | yes | `./target/release/qnero-node --version` is the candidate |
| 2 | Fresh node full-syncs a live chain | **yes** | Idle at tip, no import/panic errors |
| 3 | `quantus exercise` on a local `--dev` node | **yes** | All default phases pass |
| 4 | Warp sync (if this release touches sync / checkpoints) | if relevant | Reaches tip in minutes |
| 5 | `try-runtime` against live (if runtime changed) | if runtime changed | `on-runtime-upgrade` succeeds |

Ship only after 1–3 are green.

---

## 1. Build the candidate

From the commit you intend to tag:

```sh
cd /path/to/chain
cargo build --release -p qnero-node
./target/release/qnero-node --version
```

Use **this** binary for every step below. Do not test with an older
`QNERO_NODE_BIN` or a leftover `binary_node_version/` copy.

---

## 2. Fresh node sync (hard gate)

Start a **new** node with an **empty** `--base-path`. Reusing an existing
DB is not a sync test.

Full sync is the one that would have caught the last incident. Run it
against every network this binary is meant to join.

```sh
CANDIDATE=./target/release/qnero-node
STAMP=$(date +%Y%m%d_%H%M%S)

# Heisenberg
rm -rf /tmp/qnero-preflight-heisenberg
"$CANDIDATE" \
  --chain heisenberg \
  --sync full \
  --base-path /tmp/qnero-preflight-heisenberg \
  --name "preflight-heisenberg-$STAMP"

# Planck (second terminal / after Heisenberg is clearly progressing)
rm -rf /tmp/qnero-preflight-planck
"$CANDIDATE" \
  --chain planck \
  --sync full \
  --base-path /tmp/qnero-preflight-planck \
  --name "preflight-planck-$STAMP"
```

### Pass

- Peers connect and block import starts.
- Best / finalized keep moving.
- Node reaches **Idle** at the live tip (compare `system_syncState` or
  `chain_getHeader` against `wss://a1-heisenberg.quantus.cat` /
  `wss://a1-planck.quantus.cat`).
- No panic, repeated import failures, or disconnect loops.

A full Heisenberg sync can take well over an hour on a long-lived chain.
Let it finish. "It started downloading" is not a pass.

### Fail (do not ship)

- Never finds peers / never imports.
- Imports then stalls or crashes.
- Reaches a height and cannot continue.
- Finalized / best diverge from public RPC and do not recover.

Throw the `--base-path` away after the run (`rm -rf /tmp/qnero-preflight-*`).

Optional local helper (same idea, more logging): `../sync-heisenberg.sh`
from the workspace, pointed at this candidate via `QNERO_NODE_BIN`.

### Warp sync (extra, when sync/checkpoint code changed)

```sh
rm -rf /tmp/qnero-preflight-heisenberg-warp
"$CANDIDATE" \
  --chain heisenberg \
  --sync warp \
  --base-path /tmp/qnero-preflight-heisenberg-warp \
  --name "preflight-warp-$STAMP"
```

Must still end Idle at tip. Warp is not a substitute for gate 2.

---

## 3. Full CLI exercise on a local dev node (hard gate)

This is the transaction suite we already run: `quantus exercise` against
a `--dev` node. `crystal_alice` is genesis-funded there, so every default
phase can run (including governance).

**Terminal 1 — fresh dev node**

```sh
rm -rf /tmp/qnero-preflight-dev
./target/release/qnero-node --dev --base-path /tmp/qnero-preflight-dev
```

Wait until it is producing blocks (`ws://127.0.0.1:9944`).

**Terminal 2 — full suite**

```sh
# Build or use a CLI that matches this runtime
quantus exercise --fail-fast
```

Default phases (all required): `reads`, `balances`, `utility`, `reversible`,
`multisig`, `preimage`, `governance`, `vesting`, `negative`,
`fuzz`, `wormhole`.

Do **not** `--skip` phases for a release candidate. `wormhole` is slow; still
run it. Leave `upgrade` off unless this is a runtime-upgrade rehearsal on a
fast-governance node.

### Pass

- Command exits 0.
- Report shows every phase/step passed.
- Dev node did not panic while the suite ran.

### Fail

- Any phase fails.
- Timeouts / "node not ready" after the node is clearly up — usually a
  CLI/runtime mismatch; fix and rerun, do not ship.

Reproduce a fuzz failure with the printed `--seed`.

---

## 4. Runtime-changing releases only

If `spec_version` / storage / migrations changed:

```sh
cargo build --release --features try-runtime
try-runtime \
  --runtime target/release/wbuild/qnero-runtime/qnero_runtime.wasm \
  on-runtime-upgrade --disable-spec-version-check --blocktime 10000 \
  live --uri wss://a1-heisenberg.quantus.cat
```

Repeat against Planck if that network will get the same wasm.

After the GitHub release exists, the live upgrade itself is
[`RUNTIME_UPDATE.md`](./RUNTIME_UPDATE.md) — that is post-ship, not this
checklist.

---

## Do not ship if

- Gate 2 did not reach tip on every target live chain.
- Gate 3 did not finish green on `--dev`.
- You tested a different binary than the one in the release artifacts.
- You "synced" by restarting a node that already had a DB.
