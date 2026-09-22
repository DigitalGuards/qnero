# Native architecture changes: runtime 106

This change set requires coordinated node and wallet releases. Preparing a build
or a new chain specification does not activate a network upgrade. Preserve the
existing chain and database until an activation plan has been chosen and tested.

## Consensus and database policy

The native client selects the chain with the most accumulated work. Genesis is
the sole irreversible checkpoint. Confirmation counts describe reversible
history; `chain_getFinalizedHead` remains at genesis. Applications should follow
best-chain changes and handle reorganizations. The legacy `MaxReorgDepth` runtime
API returns `u32::MAX`, which prevents depth finalization by older consumers over
the entire u32 block-height range. It cannot reverse checkpoints already stored
by those clients.

The node and offline import/check commands retain all block bodies and all branch
states (`KeepAll`, `ArchiveAll`). They require full synchronization. State and
warp synchronization depend on finality assumptions this protocol does not make.
Fork requests use bounded reverse chunks and pinned hashes; the synchronizer
fetches a known ancestor before queuing the branch for execution. Accumulated
work is retained for every imported block.

A database carrying a non-genesis finalized checkpoint is rejected. Changing a
runtime constant or copying that database does not erase its finality boundary.
The database backend can also reject an incompatible stored pruning mode before
the explicit finality check is reached.

### Side-branch admission budgets (client policy, 2026-09-21)

Because every valid block on every branch is executed and archived, a peer can
make a node pay for a side branch whose difficulty has decayed far below the
tip's. The client bounds that with two token budgets, charged in the import
queue's verifier only and never by `import_block` or by the node's own blocks:

- **Side-branch blocks.** A block whose parent is the tip is free. A block on
  another parent is free while its difficulty is at least the tip's divided by
  8 (`SIDE_BRANCH_DIFFICULTY_FRACTION`). Anything cheaper draws one token from
  a bucket of 1024 that refills at `--side-branch-budget` blocks per hour
  (default 900, 0 = unlimited), once its seal has met the branch difficulty.
- **RandomX cache fills.** A block extending the tip fills its seed for free.
  Any other block whose seed is neither pinned nor resident draws one token
  from a bucket of 4 that refills at `--seed-fill-budget` fills per hour
  (default 24, 0 = unlimited). The seeds the node mines under now and next are
  pinned in their own slots and never evicted by a fill a peer forces.

A refusal is `randomx: budget refusal for block #N ...` at warn level, once a
minute per budget with the count of what the minute hid. It travels the
ordinary verification-failed path, so sync drops the sending peer and offers
the branch again later; the block is valid or invalid independently of it, and
an honest heavier chain is admitted at the budget's rate and can never be
refused for good. Four counters on the Prometheus endpoint say what the budgets
are doing: `qnero_pow_side_branch_charged_total`,
`qnero_pow_side_branch_refused_total`, `qnero_pow_seed_fill_charged_total`,
`qnero_pow_seed_fill_refused_total`, beside `qnero_randomx_cache_fills_total`.

Neither budget is a consensus rule and neither needs a runtime bump: every
block valid before is valid after, only admission timing and cache residency
change. A depth floor below the tip and a hard difficulty threshold were both
considered and rejected: with genesis as the only irreversible block, either
one turns a partition longer than the floor, or a chain whose hashrate migrated,
into a branch the node refuses for ever.

### Keeping an existing chain

1. Preserve a consistent backup of its database, original chain specification,
   binary, and runtime artifacts. Use the previous binary to export canonical
   blocks from the preserved database: the new client's startup policy rejects
   a legacy finalized database, including for export commands.
2. With the original genesis, replay complete block bodies into a separate new
   archive database using the new client. Replay executes the historical runtime
   stored in chain state. Check block hashes, state roots, accumulated work,
   balances and recoverable wallet history against the preserved chain.
3. Coordinate adoption of the native client. There is no second step here, and
   this is where the route ends: no Qnero chain has an authorized upgrade
   mechanism. The runtime deleted every dispatchable that could write `:code`,
   so the runtime in a chain's genesis wasm is the runtime for that chain's
   life. Keeping an existing chain therefore means keeping its existing
   runtime; a runtime change is the next section.
4. Publish the exact protocol manifest and matching wallets. New wallets require
   the authenticated profile, so a wallet release that moves the profile is a
   wallet release for the next chain rather than for this one.

### Starting a new testnet

Build the node with real runtime WASM, generate and review a new raw chain spec,
record its genesis hash and profile, and distribute matching wallets and nodes.
Use a separate database and explicit network identity. Existing balances and
wallet scan checkpoints belong to the previous genesis. Generating that candidate
specification in a development branch does not reset the active testnet.

The raw `chain/node/chain-specs/qnero-testnet.json` in this branch was
regenerated from runtime 106 at the close of the relaunch bundle, and it carries
the seed node's bootnode, `/dns/node.qnero.io/tcp/30333/p2p/QmfXuYvCz21mBHhPCuaQkchwN9tR5fS9VjKcLEeLiQpYzv`.
That list sits outside genesis, so it did not move the genesis hash. It is a
candidate for a new genesis. Keep the deployed network's original specification for an upgrade or
replay of its existing history; choose a separate network identity before
activating this candidate.

## Transaction and artifact compatibility

Runtime `spec_version` is 106; `transaction_version` remains 7. The signed SCALE
encoding and extension tuple are unchanged. Unsupported transparent calls become
invalid at extrinsic checking, before inclusion, fees, nonce updates or body
recording. That now covers a `Multisig::propose` payload: the check decodes the
opaque bytes and holds them to the same rule, so a proposal carrying a refused
call is invalid too. The dispatch filter remains in place for internal
dispatch. Historical blocks use their
historical runtime; importing them under a replacement genesis is a different
chain and is unsupported.

The runtime publishes a 192-byte profile both in metadata and authenticated
state. Native and browser wallets compare it with their supported profile before
building circuits or producing proofs, and pin generated verifier artifact
digests. See [PROTOCOL-PROFILE.md](PROTOCOL-PROFILE.md). Mainnet presets also require
independent cryptographic qualification, described in
[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md).

## Ciphertext delivery and wallet recovery

Note ciphertexts live in block bodies and are authenticated against the header's
extrinsics root. The runtime writes none of them to state:
`CiphertextRetentionBlocks` is 0, `integrity_test` asserts it, and storage
version 3 removes the live ciphertext map, its FIFO queue and its cleanup
cursor. There is no retention window, no per-block pruning budget and no
migration backlog to drain. Commitments, nullifiers, creation heights and
coinbase values keep their existing lifetime state behavior.

A block may create at most 2048 output notes. Settlement requires the exact
serialized length the declared crypto suite fixes, 1792 bytes for suite 1, so
the per-block payload is bounded by construction and the profile carries that
length in bytes 92..94. See [PROTOCOL-PROFILE.md](PROTOCOL-PROFILE.md).

A wallet scans by reading block bodies over headers it has authenticated. The
node must retain and serve the bodies for the range being scanned. Missing or
invalid body data aborts scanning before advancing the affected watermark.
Coinbase discovery uses its authenticated public value and the wallet's miner
viewing key. [AUTHENTICATED_READS.md](AUTHENTICATED_READS.md) defines the read bounds
and the separate provider/checkpoint trust assumption.

Every node built with this policy retains archive state and block bodies. Total
disk use still grows with history, including fork history. Scanning cost grows
with the range a wallet has to walk.

## Qualification and remaining limits

The regression suites cover call-policy admission, state-proof membership and
absence, prefix completeness, profile mismatch, legacy database refusal and fork
transport progress.
[WASM-BUDGET.md](WASM-BUDGET.md) provides an offline runtime-executor measurement
harness with valid private/public proof fixtures and explicit component gates.

A fresh RocksDB-backed dev rehearsal passed isolated mining, follower restart,
reconnect, actual PoW imports, work-based convergence, former-branch archive
reads and native wallet synchronization. Its shallow fork is detailed below.
Activation still needs long-partition and deep-reorganization qualification,
replay/recovery on the selected deployed database, deep-history wallet
recovery, and reference-hardware full-block and admission-capacity measurements.
The exact cryptographic composition remains subject to independent assessment.

The admission budgets bound the side-branch cost. What a
spammer with hashrate `A` against honest hashrate `H` can still make every node
execute is about `8 * (A/H) * 30` blocks an hour for free plus the budgeted
900 an hour, at roughly 22 KB of archive per block, and four cache fills in a
burst then one per 150 s. An honest chain that carries `N` cheap blocks (a
minority partition whose hashrate returned) imports `min(N, 1024)` at once and
the rest at the budgeted rate, each exhausted batch costing the serving peer one
drop and the node one sync restart; a partition holding under a ninth of the
hash settles below the free line within about two and a half days and is charged
from then on. Two follow-ups remain open: an ancestor search
that recognises a known side-branch block, so budgeted recovery re-downloads
nothing it already holds; and headers-first admission, which would verify
seals only and execute a branch's bodies once its header work is competitive.
Side-branch state below any horizon is never pruned.

### Local fork and wallet smoke

The [2026-09-16 result](bench/2026-09-16-native-upgrade-smoke.json) passed with A
at height 1 and B at height 2, carrying configured cumulative work 129 and 257.
Both followers selected B after reconnect and retained A's former block and
historical profile state. Finalization remained at genesis. Wallet B verified
the runtime profile and state proofs, reached height 2, and discovered both
positive coinbase notes. All owned processes stopped and their ports were
closed and bindable. The result pins both executable hashes and the dev genesis.

After building fresh release binaries with the actual runtime WASM, run from
the repository root:

```sh
python3 scripts/check-native-upgrade.py \
  --node-bin chain/target/release/qnero-node \
  --wallet-bin target/release/qnero-wallet
```

The script requires explicit executable paths and refuses binaries older than
their Rust/workspace source inputs. It does not build them. It uses fresh dev
databases under ignored `target/native-upgrade-smoke/`, dynamic loopback ports,
CPUs 0-7, nice 19, Rayon 4, and one mining thread at a time. A file lock prevents
two copies of this smoke from running together. Each phase has a 180-second
deadline and each owned child has a 30-second shutdown bound.

It mines distinct ordinary forks, restarts both nodes as followers, connects
their reserved peers, and requires convergence to B's strictly greater
configured chain work. It checks genesis-only finalization, retrieval of the
former A block body and historical profile proof on A after its reorganization,
runtime 106, the 192-byte profile, and native wallet discovery of B's positive
coinbase notes.
The result also records whether B learned the losing A branch during reconnect;
that depends on ordinary peer timing and is optional.
Native wallet synchronization performs the local profile and state-proof checks.

The printed `facts.json` path is the public result. Node logs omit miner-viewing
key lines. Wallet output is suppressed; a failed sync records only its bounded,
sanitized error chain in `facts.json`. Generated wallet seeds, stores, and
interrupted store-save temporary files are removed during cleanup. Scratch
databases can contain node identity keys, so
share `facts.json` rather than the whole scratch directory. All spawned children
are stopped in cleanup, and their ports must be closed and bindable.

This smoke covers a shallow fork, normal PoW imports, restart, archive reads,
and native wallet synchronization. Deep forks and shorter heavier candidates
have separate transport unit tests. It does not qualify long partitions,
deep-history wallet recovery, or reference-hardware capacity.
