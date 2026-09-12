# The Qnero wallet CLI (M5)

`crates/qnero-wallet` is the v0 wallet: it creates a spending key, moves
transparent value into the shielded pool, scans the chain for notes it can
decrypt, proves a spend and submits it.

It talks to a node over JSON-RPC and hand-encodes what it sends. There is no
`subxt` here, and that is deliberate: `qp_header::Header` carries a sixth
field, `zk_tree_root`, between `extrinsics_root` and `digest`, and it hashes
with Poseidon2 where a generic Substrate header hashes with Blake2. The header
is the anchor every spend proof commits to, so a decoder that silently
disagrees about it is the one component a shielded wallet cannot tolerate.

```
build:  nice -n 19 cargo build -j 2 --release -p qnero-wallet --features parallel
run:    RAYON_NUM_THREADS=4 ./target/release/qnero-wallet <command>
```

`--features parallel` lets plonky2 use rayon. It is off by default, the way
`qnero-prover` keeps it off: a wallet that saturates every core unasked is a
wallet that freezes the machine it runs on. With it on, bound the pool with
`RAYON_NUM_THREADS`. The proofs are identical either way; only the time
differs, about 3.4 s against about 13 s for one private batch on the
development workstation.

## Key handling, and why it is not good enough

**Dev grade, deliberately, and stated in `--help` as well as here.**

- The seed is 32 bytes of hex in a file at mode 0600. No passphrase, no key
  derivation, no encryption at rest.
- The note store beside it holds every note's `rho` and `r` in the clear. Those
  two values plus the nullifier the chain publishes are what link a spend to
  its note, so the store is as sensitive as the seed and is written 0600 too.
- Anyone who can read those two files can spend every note the wallet holds
  and can link every spend it has made.
- `load_seed` refuses a seed file that is group or world readable.

M6 owes real key storage. Until then, use this on a dev chain and nowhere else.

The transparent ML-DSA-87 key and the shielded spending key are separate
secrets and neither derives from the other. A transparent key that could derive
the spending key would make every shield linkable to its notes by anyone
holding it. v0 has no unshield, so the transparent key exists only to move
value in, and the CLI only offers the dev chain's well-known accounts for it.

## Amounts

Every amount on the command line is in **pool quanta**. One quantum is
`10^10` planck, 0.01 QTC. Note values and fees are counted in quanta and
range checked to 62 bits; the chain's transparent balance is `u128` planck.
`shield --amount 1000` burns `10^13` planck and creates a note of 1000 quanta.

## Commands

```
qnero-wallet [--node URL] [--file SEED] <command>
```

`--node` defaults to `http://127.0.0.1:9944`. `--file` defaults to
`qnero-wallet.seed` in the working directory.

### `keygen`

Creates the seed file and prints the address. Refuses to overwrite an existing
seed: the notes behind it would be unspendable.

### `address`

Prints the `qn1...` address for the seed. It is about 2600 characters, because
an ML-KEM-1024 encapsulation key is 1568 bytes of it. Wallets exchange it as a
QR code or a copy-paste string.

### `shield --from-dev-account <alice|bob|charlie> --amount N [--memo TEXT]`

Signs and submits `shield(value, inner, ciphertext)` from a dev account. The
wallet draws the note's randomness, derives `rho` by the entry rule, computes
`inner = H(NOTE, pk, rho, r)`, encrypts the note to its own encapsulation key
and submits. The note is written to the store as *pending* **before** the
extrinsic is sent, because the store is the only copy of its `r`.

One thing here is a prediction. The entry rule is
`rho = H(RHO_ENTRY, block_number, entry_index)` (`docs/CIRCUIT.md` section
9.8), and neither half is knowable before submission: the block a signed
extrinsic lands in is the block producer's choice and `EntryCount` moves with
every other shield. So the wallet predicts `(head + 1, EntryCount)`, submits,
and checks afterwards, printing a note when the prediction missed. A miss
strands nothing. The chain does not evaluate the rule, `inner` is opaque to it,
and the note is this wallet's own: its commitment opens whatever `rho` went
into it. What a miss costs is the rule's uniqueness argument for that one note,
and a recipient that checked the rule strictly would refuse it. This is an open
issue, listed below.

### `sync`

Scans from the last synced leaf to the tree's current leaf count, pinned to one
block hash so a leaf appended mid-scan cannot be counted and then read as
absent. For each leaf it reads `ZkTree::Leaves`, `Shielded::Ciphertexts` and
`Shielded::LeafBlocks` in batches of 64 through `state_queryStorageAt`. All
three maps are `Identity` hashed on the leaf index, so paging is by index and
never by `state_getKeysPaged`.

Most leaves carry no ciphertext at all and that is normal: the shielded pool
shares one commitment tree with wormhole transfers and with the mining-reward
leaf every block appends.

Every ciphertext that decrypts goes through `qnero_notes::try_receive`, which
also checks the plaintext opens the commitment the chain published beside it.
Then two refusals, both from `docs/CIRCUIT.md` section 9.8:

- a note whose nullifier duplicates one this wallet already holds, and
- a note whose nullifier is already settled on chain.

A sender picks `rho` and `r` for a note it creates, so a sender that repeats a
pair hands over two notes sharing one nullifier, of which exactly one can ever
be spent. The recipient is the last line. A refused note is recorded in the
store's `rejected` list with its reason, so a wallet can say why a payment
someone claims to have sent is missing from its balance.

Finally every unspent note's nullifier is probed against `UsedNullifiers` and
the matches are marked spent. Only the nullifier key can ask that question.

### `balance`

Unspent total, pending total, and the note list with leaf indices, block
numbers, spent state and memos. Pending and refused entries are listed under
it.

### `send --to <qn1...> --amount N [--fee F] [--memo TEXT] [--no-sync]`

Syncs, then spends up to two notes into a payment and a change note.

Order of operations, and every step before the proof exists is there so that a
refusal costs nothing:

1. **Fee floor.** Measured from the ciphertexts the submission will actually
   carry. A `NoteCiphertext` is 1731 bytes plus its memo and a note's value
   does not move that, so a probe encryption gives the exact size. The floor is
   `MinLeafFee + ceil(bytes / CiphertextBytesPerFeeQuantum)`, and for the
   single real slot a wallet submits it equals the whole-submission floor. At
   the current runtime that is 8 quanta for two ordinary outputs. `--fee`
   defaults to it and a lower one is refused with the arithmetic spelled out:
   the fee is a public input of the proof, fixed at proving time, so it cannot
   be raised afterwards and the chain would refuse the settlement with
   `PayloadUnderpaid`.
2. **Selection.** Largest first, at most two notes, covering amount plus fee.
   The leaf circuit has two input slots, so a balance spread over three notes
   is not reachable in one spend and the wallet says so, naming what is
   reachable. A witness built anyway carries a balance equation that cannot
   hold.
3. **Anchor.** The current head. `chain_getHeader` and `zkTree_getMerkleProof`
   are read at that one hash, because the tree root moves every block and the
   header a proof binds to must be the one whose root the path reaches. The
   wallet recomputes the header hash from the six fields plus the re-encoded
   digest logs and compares it against `chain_getBlockHash`. That check is the
   cheap way to catch a wrong digest re-encoding, which otherwise costs a proof
   and comes back as `BlockHashMismatch`.
4. **Paths.** `zkTree_getMerkleProof` returns siblings in child-index order
   with no position; `MerklePath::from_unsorted` converts them into the sorted
   form plus the 2-bit position hint the circuit consumes. The wallet then
   recomputes the root from the converted path and compares it against both the
   proof's root and the header's `zkTreeRoot`. A leaf appended in the current
   block is not folded into the tree yet and the RPC returns `null`; that is
   reported as "wait one block", separately from a node that is unwell.
5. **Witness.** One real input per selected note, and
   `InputNote::dummy_random` for the empty slot. Never `InputNote::dummy`: a
   repeated `(rho, r)` publishes a nullifier the chain has already settled and
   the whole submission is refused, naming a value the wallet cannot map to any
   note it holds.
6. **Outputs and `ct_digest`.** An output's `rho` is derived in circuit from
   both nullifiers the leaf publishes, so the witness is built first and the
   output plaintexts come out of it (`SpendWitness::output_note`). Each is
   encrypted with its own fresh KEM randomness. Reusing it across two outputs
   encrypts both under one ChaCha20-Poly1305 key and nonce, which leaks the XOR
   of the plaintexts and the authentication key, and nothing inside
   `encrypt_note` enforces freshness. `ct_digest` is then computed over the two
   ciphertext blobs in output order with `qnero_circuit::chain::ct_digest`, the
   same function `pallet-shielded` recomputes it with.
7. **Prove, self-verify, submit.** The private batch is proved, verified
   locally against the wallet's own batch verifier data, and submitted as a
   bare unsigned extrinsic. The change note is written to the store as pending
   before the submission.
8. **Confirm.** The wallet polls blocks for the exact bytes it submitted, then
   checks both nullifiers are in `UsedNullifiers` at the inclusion block. An
   extrinsic in a block is not yet a settled one: a segment whose anchor went
   stale or whose nullifier was claimed elsewhere is skipped and the block
   carries it anyway.

An unsigned settlement has `longevity(5)` and a constant priority, so a
byte-identical rebroadcast will not displace the copy already in the pool.
When the wait times out the answer is to prove again against a fresh anchor,
and the error says so.

### `status`

Node URL, runtime spec and transaction versions, chain head, tree leaf count,
depth and root, and the wallet's own last synced block.

## Store format

One JSON file beside the seed: `<seed path>.store.json`, mode 0600, written
through a temporary file and renamed, so an interrupted write cannot truncate
the only copy of a note's `r`.

```json
{
  "version": 1,
  "address": "qn1...",
  "last_synced_block": 1062,
  "next_leaf": 1069,
  "notes": [
    {
      "leaf_index": 1068,
      "block_number": 1062,
      "value": 692,
      "commitment": "<64 hex chars>",
      "nullifier": "<64 hex chars>",
      "rho": "<64 hex chars>",
      "r": "<64 hex chars>",
      "memo": "",
      "origin": "spend",
      "spent": false,
      "spent_seen_at_block": null
    }
  ],
  "pending": [
    {
      "kind": "change",
      "commitment": "<64 hex chars>",
      "value": 692,
      "rho": "<64 hex chars>",
      "r": "<64 hex chars>",
      "memo": "",
      "submitted_at_block": 1057,
      "extrinsic": "0x..."
    }
  ],
  "rejected": [
    {
      "leaf_index": 42,
      "commitment": "<64 hex chars>",
      "nullifier": "<64 hex chars>",
      "value": 5,
      "reason": "its nullifier duplicates a note this wallet already holds"
    }
  ]
}
```

Field notes:

- `version` is checked on load. A store written by another version is refused.
- `address` is checked against the seed on load, so a store opened with the
  wrong seed is refused and two wallets' notes never merge.
- `next_leaf` is one past the last leaf index scanned, and `last_synced_block`
  is the block every read of that pass was pinned to.
- `origin` is `shield` when the note's `rho` matches the entry rule for the
  block its leaf landed in, and `spend` otherwise. It is a label. Nothing in
  the spend path reads it.
- `spent_seen_at_block` is when this wallet first saw the nullifier settled,
  which is not the block that settled it: spent status is learned by probing
  `UsedNullifiers`, and that map carries no height.
- `pending` holds notes this wallet created and has not yet seen on chain. A
  pending entry is dropped when a sync records the note at its commitment. One
  left behind by a submission that never settled stays until it is deleted by
  hand; it carries the block it was submitted at and the extrinsic it was
  submitted as, which is enough to tell the two apart.
- `rejected` holds decryptable outputs that were refused, with the reason.

Deleting the store and re-syncing recovers every unspent note, because every
note's plaintext is on chain in its ciphertext. What it does not recover is
the spent history: a note that was received and later spent comes back as a
`rejected` entry reading "its nullifier is already settled on chain", which is
true and is why it is not in the balance.

## Tests

```
# unit tests, no chain, fast
nice -n 19 cargo test -j 2 --release -p qnero-wallet

# the whole flow against a running dev node
QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 \
  cargo test -j 2 --release -p qnero-wallet --features parallel \
  --test dev_node_e2e -- --nocapture

# the public batch measurement, ignored (see docs/BENCH.md)
QNERO_DEV_NODE=http://127.0.0.1:9944 RAYON_NUM_THREADS=4 nice -n 19 \
  cargo test -j 2 --release -p qnero-wallet --features parallel \
  --test public_batch_bench -- --ignored --nocapture
```

`dev_node_e2e` skips itself, loudly, when `QNERO_DEV_NODE` is unset, so the
workspace gate does not need a chain.

## Provenance

`quantus-cli` 2.2.2 was read while this was written and **no code was copied
from it**, so there is no `NOTICE` to carry. Two structural reasons:

- Its `ChainConfig` declares `Header = SubstrateHeader<u32, SubxtBlake2bHasher>`,
  which has no `zk_tree_root` field and hashes with Blake2. Its serde helpers
  for `zkTree_getMerkleProof` pin `leaf_data` at 60 bytes, where this fork's
  leaf data is the 32-byte commitment, so they reject every proof this chain
  produces.
- Depending on the crate pulls the whole `qp-wormhole-*` plonky2 stack and a
  build script that generates a second, incompatible circuit family.

What was taken from reading it is knowledge, and it is recorded where it is
used: the FIPS 204 signing context, the `MultiAddress` and
`DilithiumSignatureScheme` layout, that `AccountId32` is Poseidon2 of the
public key, and the habit of reading a nonce from the best block, which is
where a fresh one lives. The chain's own sources are the authority for all of it and
are cited at each site.

## Open issues

1. **Key storage is dev grade.** Above. M6.
2. **The entry `rho` for a shield is predicted.** A wallet cannot know the
   block its signed extrinsic lands in, and `EntryCount` moves with every
   other shield. The prediction is checked afterwards and a miss is printed.
   Closing it properly needs either a chain-side rule that does not depend on
   the inclusion block, or a shield that carries `inner` derived at settlement
   time, and both are M6 decisions.
3. **A received note's `rho` is not checked against the entry rule.** The rule
   hashes `(block_number, entry_index)` and only the `Shielded` event publishes
   `entry_index`, which needs the runtime's full type registry to decode. The
   wallet walks the entry counter instead, which is exact on a dev chain and
   O(entries) on a long-lived one. The refusal that actually protects the
   recipient, a duplicated nullifier, does not depend on it.
4. **`POOL_QUANTUM` is the one chain value with no metadata surface.** It is a
   constant of the pallet crate with no `#[pallet::constant]` declaration, so
   the wallet carries a copy. A mismatch is loud: `shield` refuses a value that
   is not a whole multiple with `ValueNotQuantized`.
5. **`N` is not discoverable over RPC either.** The wallet reads
   `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS`, which is the same constant
   `chain/pallets/shielded/build.rs` reads. A wallet built at a different `N`
   produces a proof whose public-input length the chain's embedded verifier
   refuses, after the full proving cost has been paid. The wallet does not
   compare its leaf verifier bytes against `pallet_shielded::LEAF_VERIFIER_ARTIFACT`,
   which exists for exactly that check and is not reachable over RPC.
6. **One transfer per submission.** A private batch has six slots and the
   wallet fills one. Filling more needs a queue and a policy for what to batch
   with what, and the anonymity argument for batching is the whole point of the
   shape, so it is a design decision, and the loop is the smallest part of it.
7. **No local tree rebuild.** The chain exposes `zkTree_getMerkleProof` and the
   wallet uses it, checking the converted path's root against the header before
   proving. `qnero_circuit::merkle::CommitmentTree` mirrors the pallet exactly
   and would rebuild the tree from `ZkTree::Leaves` if the RPC were ever
   disabled; nothing wires it up today.
