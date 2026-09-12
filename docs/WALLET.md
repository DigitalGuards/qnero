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

## What the node learns

A shielded wallet leaks through what it *asks* as much as through what it
publishes, and the node it asks is a third party for anyone who does not run
their own. Two rules hold here, and both are properties of the request stream
alone. No assertion over an answer can see either one:

- **A sync never names a nullifier.** Spent status is decided against a local
  copy of `UsedNullifiers`, paged whole through `state_getKeysPaged`. Probing
  the map with this wallet's own nullifiers would hand them over in the clear,
  because the hasher is `Blake2_128Concat` and the raw key travels in the
  request. A node that logged those would hold, per client, the set of values
  this wallet will publish when it spends, and could attribute any later
  settlement that published one of them with certainty, before the wallet had
  spent anything at all.
- **A spend never names a leaf.** Merkle paths are rebuilt locally from
  `ZkTree::Leaves` at the anchor block. `zkTree_getMerkleProof` is only ever
  asked about a leaf the caller is spending, so every such call identifies one
  of the caller's own leaves, and the settlement publishing the matching
  nullifiers arrives on the same connection seconds later. `--merkle-rpc` opts
  back into that, and its help text says what it gives up.

Both replacements read public data whole: the whole leaf range, the whole
settled set. That costs `O(leaf_count)` reads per spend where the proof RPC
costs one, and it distinguishes nothing.

What is still visible to the node: this wallet's IP, that it is a Qnero wallet,
when it syncs, and the extrinsics it submits. Traffic analysis over submission
timing is not addressed here and is not addressable inside the wallet.

## What every chain reader learns

A wider audience than the section above, and a different one. The rules above
are about the request stream, which only the node sees. What follows is
published on chain, where anyone with an RPC connection and no key material at
all reads it.

- **Every note ciphertext this wallet writes is one length.** A
  `NoteCiphertext` is a fixed 1731 bytes plus its memo, byte for byte, and the
  chain publishes those bytes in full: in `Shielded::Ciphertexts`, and in the
  `SlotSettled` event beside both leaf indices. So an unpadded memo publishes
  its own exact byte count, `len(ct_1) - len(ct_2)` correlates any two payments
  carrying the same memo string, and a spend's change note, whose memo is
  always empty, is always the shorter of the published pair. Every memo is
  therefore padded to `memo::MEMO_BYTES`, 61 bytes, so every ciphertext this
  wallet writes is exactly 1792 bytes. Zcash's 512-byte memo field is the
  precedent; the size differs because this ciphertext's fixed part is larger
  and because this chain prices payload bytes. A memo over the pad is refused,
  at the top of the command.

  The pad is bounded twice and the tighter bound picks it. `MaxCiphertextBytes`
  leaves 317 bytes over a memoless ciphertext, and a pad over that fails the
  extrinsic's SCALE decode after the proof exists. The fee is the tighter one:
  `ShieldedCiphertextBytesPerFeeQuantum` (512) is sized so a real pair and a
  pair padded to `MaxCiphertextBytes` fall in different buckets, since the
  chain never parses those bytes and `Shielded::Ciphertexts` is never pruned,
  and a pad of 61 is the largest that keeps `2 * (1731 + pad) = 3584` a bucket
  below `2 * 2048 = 4096`. A 256-byte pad put the two in the same bucket, which
  let a settler pad both ciphertexts to the cap, write 512 bytes of permanent
  state per slot and pay exactly what an honest spend pays.
  `fee::the_wallets_own_pair_stays_a_bucket_below_a_padded_one` is the gate on
  this side and `a_slot_pays_for_the_ciphertext_bytes_it_publishes` is the one
  on the chain's. `fee::ensure_memo_pad_fits` checks the compiled-in pad
  against both of the runtime's own values once per command, because every
  other chain value this wallet uses is read from metadata and this one cannot
  be.

  The two bounds get different answers. A pad the runtime's
  `MaxCiphertextBytes` cannot take is a refusal, because the extrinsic would
  fail to decode after the proof committing to those bytes exists. A runtime
  whose divisor merged the two fee buckets is a warning printed once per
  process, and the spend goes ahead. That second one is a property of the
  chain: a settler pads to the cap whatever this wallet does, so refusing fixed
  nothing and stopped every send and every shield this wallet makes. The
  operator cannot change `CiphertextBytesPerFeeQuantum`, and this wallet
  shrinking its own pad below what every other wallet on the chain uses would
  publish its own ciphertext length, which is the leak the pad exists to close.
  `fee::memo_pad_separation_warning` is the sentence and it names the pad that
  would restore the separation, as a coordinated move.
- **Which output is the change is drawn per spend.** `ct_1` belongs to
  `cm_out_1` and `SlotSettled` names both leaf indices, so a payment fixed at
  output slot 0 splits the pool's outputs publicly into "went to a
  counterparty" and "came back to the sender". The wallet draws the payment's
  slot per spend instead. The circuit derives each output's `rho` from its own
  slot index (`SpendWitness::output_rho`), so either assignment proves and
  settles unchanged.
- **The gap between a spend's anchor block and its inclusion block is not
  uniform, and that is open.** Both are public inputs of the settlement. The
  anchor is always the head, which keeps a wallet from marking two of its own
  spends with a shared offset, but everything after the anchor is taken sits
  inside the gap: the local tree rebuild, which is `O(leaf_count)` reads and a
  Poseidon2 fold, two ML-KEM encapsulations, and the proof. A `--merkle-rpc`
  spend skips the rebuild and lands measurably sooner than a default one on the
  same chain; a slow machine or a long chain lands later. So the gap is a
  per-wallet class marker on every settlement. Making it a constant means
  holding the submission until the anchor plus a fixed number of blocks, which
  is latency M5 does not spend. Listed under open issues.

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

`--new-chain-store` archives a store built against another chain and starts a
fresh one; the store format section below says what binds a store to a chain
and why. It archives rather than deletes, because the file is the only copy of
every note's `rho` and `r`.

`--node` defaults to `http://127.0.0.1:9944`. `--file` defaults to
`$XDG_DATA_HOME/qnero/qnero-wallet.seed`, or
`~/.local/share/qnero/qnero-wallet.seed` when `XDG_DATA_HOME` is unset. It is
never relative: the documented way to run this binary is from a checkout, and
a default that resolved in the working directory would drop an unencrypted
spending key and a store full of note secrets into whatever repository the
user happened to be standing in, one `git add -A` from a public history. The
repository also gitignores `*.seed` and `*.store.json` for the same reason.

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
with the memo padded to one size, and submits. The runtime's storage layout is
checked against what the wallet hashes before any of this, the same check
`sync` and `send` run: this command reads `Shielded::EntryCount` and then
`ZkTree::LeafCount` and `ZkTree::Leaves` to confirm its own leaf, and an absent
key reads as an empty map, which would turn a shield that settled into a
reported dispatch failure. The note is written to the store as *pending* **before** the
extrinsic is sent, because the store is the only copy of its `r`.

One thing here is a prediction. The entry rule is
`rho = H(RHO_ENTRY, block_number, entry_index)` (`docs/CIRCUIT.md` section
9.8), and neither half is knowable before submission: the block a signed
extrinsic lands in is the block producer's choice and `EntryCount` moves with
every other shield. So the wallet predicts `(head + 1, EntryCount)`, submits,
and checks **both halves** afterwards against what the chain assigned:

- the block half, `included_at == head + 1`;
- the index half, `EntryCount` at the parent of the inclusion block equals the
  value the note was built from;
- and how many entries settled in the inclusion block. Exactly one means the
  index the chain assigned is the predicted one. More than one means the
  prediction is not decidable from storage alone, because only the `Shielded`
  event carries an entry index and decoding it needs the runtime's full type
  registry; that case is reported as unproven.

A miss strands nothing. The chain does not evaluate the rule, `inner` is opaque
to it, and the note is this wallet's own: its commitment opens whatever `rho`
went into it. What a miss costs is the rule's uniqueness argument for that one
note, and a recipient that checked the rule strictly would refuse it. This is
an open issue, listed below.

The dispatch is then confirmed. An extrinsic in a block is not a dispatch that
succeeded: a shield the runtime refused, because the dev account cannot pay or
the value is not a whole multiple of `POOL_QUANTUM`, is included and appends no
leaf. So after inclusion the wallet reads the leaves the block appended and
looks for its own commitment among them, prints the leaf index it landed at,
and turns an absent one into an error that drops the pending entry.

### `sync [--rescan]`

Scans from the last synced leaf to the tree's current leaf count, pinned to one
block hash so a leaf appended mid-scan cannot be counted and then read as
absent. For each leaf it reads `ZkTree::Leaves`, `Shielded::Ciphertexts` and
`Shielded::LeafBlocks` in batches of 64 through `state_queryStorageAt`. All
three maps are `Identity` hashed on the leaf index, so paging is by index and
never by `state_getKeysPaged`.

Most leaves carry no ciphertext at all and that is normal: the shielded pool
shares one commitment tree with wormhole transfers and with the mining-reward
leaf every block appends.

Before anything else, the node itself is checked. Everything a sync derives is
derived from what one node answers at one block, and a node that answers with
less than the wallet already knows is not a correction.

**The chain.** The store records the genesis hash of the chain it was built
against and the sync refuses a node that answers a different one. See "Store
format" below, which also says what this does not catch: `--dev` is a fixed
chain spec, so a restarted `--dev --tmp` node answers the same genesis and is
caught by the checkpoint walk and the leaf gate instead.

A store that names no chain **yet** takes one from the first operation that
commits, a successful sync, shield or send, and never from opening the wallet.
The ordering is the whole of it. Recording it at open bound a fresh store to
whichever node it was first pointed at, including a node the very next check
refused, so a wallet opened once against a wrong `--node` named that chain
permanently and every later sync against the right node refused with a mismatch
the operator never chose.

**The checkpoint walk**, which answers two questions at once: is this node on
the wallet's chain, and has it reached everything the wallet has already read.
Both are questions about checkpoint hashes. Asking them separately, one as a
block-height comparison and one as a fork walk, is what made them contradict
each other.

The store keeps a `checkpoints` list, one entry per sync, each the block that
sync finished at, its hash, and the leaf watermark it left. The walk goes
newest first:

- A checkpoint **above the node's head** is skipped. On its own it says
  nothing: the node may be behind, or that checkpoint may belong to a branch
  this node has replaced with a heavier shorter one. Which it is, is decided by
  the first checkpoint the node can answer for.
- The first checkpoint **at or below the head whose hash still stands** means
  the node is on this wallet's chain up to that height, so every leaf below
  that watermark was folded at or before a block that is still canonical and
  cannot have moved. If anything was skipped above it, the node is behind the
  wallet on the wallet's own chain, and the sync refuses by name. Otherwise the
  scan runs from the watermark the store already holds.
- A checkpoint **at or below the head whose hash differs** is a fork. The walk
  continues down to the newest checkpoint that still stands, and that survivor
  is where the watermark rewinds to. The checkpoints above it, the ones above
  the head included, belong to the branch that is gone, and `last_synced_block`
  follows the survivor **downwards**. A fork deeper than the sixteen
  checkpoints the store keeps rewinds to zero and rescans the whole tree, which
  is correct and slow.
- **No block at all** at a height at or below the head is neither. A fork is a
  *different* block at that height; no block there is a node that is pruned or
  is serving a head it has not filled in behind, and rewinding on it rescans
  leaves against a tree smaller than the one already recorded. The sync refuses
  by name.

The walk stops at the first checkpoint that stands, so the ordinary cost is one
`chain_getBlockHash`.

`last_synced_block` going down on a fork is the point of keying this on hashes.
The gate used to compare heights, and heaviest-chain rules do not order
branches by length: a shorter branch can win. Against one of those the wallet
refused every sync until the chain climbed back past a height it had recorded
on a branch that no longer existed, and the note that moved leaf in the reorg
stayed at its old index for the whole of that window, unspendable, with
`balance` reporting it as spendable. A height is a statement about one branch,
and when the branch is gone the statement goes with it.

**The leaf watermark**, which is the one thing the heights and the hashes
between them cannot see. `ZkTree::LeafCount` at the node's head is read, and a
count below the watermark the scan is about to start from is refused. A node
can be on this wallet's chain, at a head above every checkpoint, and still
answer with a shorter tree: the count is a statement about the state that node
has **executed**, and a node serving a head it has not finished executing
answers short. The scan range `start..leaf_count` is then empty, so the whole
scan is skipped and the vanished-note check with it, while the watermark is
written back down to the node's count and the store is left claiming to have
scanned less than it has. A fork cannot reach this gate, because the rewind
above takes the watermark to a checkpoint the node's own branch carries and
that checkpoint was written at a block whose tree was at least that large. So a
short tree is lag, and the watermark never regresses outside the fork path.

The gate is the ordinary sync's and `--rescan` skips it by construction: a
rescan starts at leaf zero and no leaf count is below zero, so the comparison
cannot fire. There is no exemption in it for the override to take. What the
gate protects, the watermark and every check that reads backwards from it, a
rescan gives up openly and says so.

A lagging node is an ordinary operational state, so it is refused by name: a
second `--node`, a node resyncing, a load balancer answering from a lagging
replica. What it is not is new information. Its `UsedNullifiers` is
missing every settlement it has not executed, and the spent reconciliation
below derives spent status in both directions, so a lagging node un-spent every
note whose settlement it had not reached; the next `send` then selected an
input the chain had already consumed and paid a full proof to have the
settlement skipped. A node on a branch that diverged **above** its own head is
indistinguishable from a lagging one, because the checkpoints that would show
the divergence are heights it cannot answer for, so it lands in the same
refusal and `--rescan` is the way through. What that means exactly is under
`--rescan` below: the refusal is printed, the checkpoints behind it are
dropped, and the scan that follows is allowed to add and forbidden to take
away.

Nothing is written until both gates have passed. A refusal leaves the store
exactly as it found it, in memory and on disk, checkpoint list and genesis
binding included.

Then the scan, which is where a leaf index gets repaired. Every read is pinned
to `chain_getHeader`, which is the best block, and a best block can still be
orphaned, so a leaf index is provisional when a scan first records it. When the
block a note settled in is orphaned the extrinsic is still in the pool, is
re-included, and appends the identical commitment at whatever index the
replacement block has room for. A stale index makes the note unspendable: the
path rebuild refuses a leaf whose commitment is not the note's, and
`--merkle-rpc` refuses it the same way, while the balance goes on reporting it
as spendable. The watermark alone cannot see that, because it only moves
forward and a reorg happens because the replacement branch is heavier, so it
normally carries at least as many leaves as the branch it replaced and the
re-included commitment lands at or below where it was: below the watermark, and
never re-read. The rewind puts every moved leaf back inside the range, and a
commitment the scan meets again is relocated in place.

**`--rescan`** drops the watermark to zero and walks the whole tree again,
keeping every note. It is the recovery for a store an older build wrote: that
build refused the second note it met that shared a nullifier with one it
already held, wrote a `rejected` entry, kept no copy of the note's `rho` and
`r`, and left the leaf below the watermark where no later sync reads it again.
No store upgrade can bring those secrets back, because they were never in the
file. They are on chain, inside the ciphertext beside the commitment, so a walk
from leaf zero recovers them. Keeping the notes is the difference from deleting
the store: a note whose leaf the current chain no longer carries would
otherwise lose the secrets that are the only handle on a settlement that can
still be re-included.

It is also the operator's override on the checkpoint walk, which is the one
gate a store can be on the wrong side of through no fault of the node. A wallet
whose branch is gone, or whose checkpoints name blocks no node still serves,
is refused by every node it can reach, and the refusal names `--rescan` as the
way through. Four rules bound what the override buys, in this order.

1. **The chain check is never bypassed.** A genesis mismatch refuses a rescan
   exactly as it refuses a sync. Leaf indices, checkpoint hashes and spent
   flags are statements about one chain, and walking another chain's tree from
   leaf zero recovers nothing.
2. **A checkpoint-walk refusal is printed and bypassed.** The refusal text
   goes to the operator as a warning naming what was walked past, the
   checkpoints it could not stand on are dropped, and `last_synced_block` and
   the watermark go to zero with them. A rescan that trusts the node less than
   the store does not get to keep the store's claims either.
3. **The scan runs add only.** Every rule that takes something away rests on
   this node being at or ahead of everything the wallet has read, which is
   exactly what rule 2 may have stopped checking. So a nullifier the node
   carries still marks a note spent, a nullifier it does not carry clears
   nothing, no note is marked off chain, and a commitment met again still moves
   its note to the leaf the chain holds it at and puts it back on chain. Both
   the report and the CLI say `rescan: add-only, spent flags and orphans are
   not reconciled; run a normal sync against a current node afterwards`.
4. **The leaf-count gate is unchanged**, and a rescan cannot trip it, because
   its watermark is zero.

The add-only rule is what makes the override safe to hand an operator. Against
a node that is behind, or one serving a head it has not executed, every leaf it
has not reached looks exactly like a leaf that is gone and every settlement it
has not executed looks exactly like a settlement that was orphaned. A rescan
that reconciled would write the whole store off in one pass: notes marked off
chain, and settled notes back in the balance for the next `send` to select and
lose a full proof on. It adds what it finds, leaves everything else alone, and
hands the reconciliation to an ordinary sync against a node at the current
head.

What that later sync gives back is not symmetric, and the notice's wording is
the short version of it. Every spent flag is derived afresh on every pass, so
pointing `--node` at a node that has executed its head is all the first half
takes. The orphan check reads a range the scan re-walked, and a scan re-walks
leaves it has already read when the watermark rewinds, which is what the fork
behind an orphaned settlement produces. A held note whose leaf the chain
dropped without any visible fork therefore waits for the sync that does rewind,
and it is in the balance until then.

This deliberately does not re-read `ZkTree::Leaves` at each held note's
recorded index, which would be the cheaper check. That names this wallet's own
leaves to the node, which is the property the local tree rebuild pays for.
`chain_getBlockHash` at a height names nothing.

A held note inside a rescanned range that the scan did not meet again is a note
the current chain does not have: its settlement was orphaned and has not been
re-included. The note is marked `on_chain: false` and stays in the store, with
its secrets and its recorded leaf index, because a later block can still
re-include the extrinsic and that index is the only handle on where the note
was. What it does not stay in is the balance: `unspent_total`, the note
selection a spend runs and the `balance` table all skip it, and `balance` lists
it under a heading of its own with the reason.

Marking it is the point. The sync used to report a count and write nothing
down, so `unspent_total` went on reporting value the chain does not back,
permanently and with no marker in the file; `balance` does not sync, so the
one-off line was never seen again. The note selection picks largest first, so a
phantom larger than every real note also failed every later `send` on the path
rebuild, with no remedy but editing the JSON by hand.

The marking does not run under `--rescan`, for the reason rule 3 above gives,
and it does not run when the scan found nothing to re-walk: a held note is only
inside the scan range at all after a rewind.

The marking runs after the spent flags are derived, and that ordering carries
weight. A note that was spent and whose own creating leaf was orphaned in the
same reorg still reads as spent until the reconciliation below has run against
the repaged set; counted before it, such a note was skipped and then let back
into the balance a moment later as a phantom nobody had been told about.

A refusal is recorded once per output however many rescans walk past it, and
it goes away again when the same output becomes holdable. A refused note is never added to
the note list, so nothing stops the scan decrypting and refusing it again, and
before the rewind existed no leaf was ever scanned twice. The `rejected` list
is keyed on the commitment, a later rescan moves the entry's leaf index the way
a held note's is moved, and a scan that ends up holding an output drops the
entry: the one refusal left is a statement about chain state that a reorg can
undo, and `balance` used to print "its nullifier is already settled on chain"
beside a note it had just added to the balance.

Every ciphertext that decrypts goes through `qnero_notes::try_receive`, which
also checks the plaintext opens the commitment the chain published beside it.
The memo it returns has its padding stripped, trailing zeros only, so a memo
from a wallet that does not pad passes through unchanged.
One refusal is left, from `docs/CIRCUIT.md` section 9.8: a note whose nullifier
is already settled on chain. It is recorded in the store's `rejected` list with
its reason, so a wallet can say why a payment someone claims to have sent is
missing from its balance.

**A duplicated nullifier is a conflict set.** A sender picks
`rho` and `r` for a note it creates, so a sender that repeats a pair hands over
two notes sharing one nullifier, of which at most one can ever settle. Which
one is not the sender's choice and not the scan's: it is whichever one this
wallet spends first, because the chain refuses a nullifier it has already seen.
The scan used to refuse the second note it met, which decided that by arrival
order and decided it permanently, so a sender who put the large note second had
the wallet keep the small one with no way back and a rescan after a fork wrote
the same note off again.

Every decryptable output is held now. `WalletStore::spendable` yields one note
per nullifier, the largest member with ties broken on the leaf index, and that
is what the selection sees, what `unspent_total` sums and what the `balance`
table prints, once, with a `conflict` marker and the member count. The
collapsing is not only about the total: a private batch constrains all its
nullifiers pairwise distinct (`docs/CIRCUIT.md` section 8), so a selection that
put two members of one set into one leaf would fail in circuit. Once a member
settles, its nullifier enters `UsedNullifiers` and the reconciliation below
marks every member of the set spent, which needs no rule of its own.

Finally the settled nullifier set is read whole, pinned to the same block, and
every note's spent flag is derived from it, in both directions. Only the
nullifier key can compute those values at all, and the question is asked
locally: see "What the node learns" above.

Both directions, because the flag used to be a latch. The set is repaged whole
on every sync, so the store always holds the chain's current answer, and a
settlement whose block is orphaned and which does not re-land, because the
unsigned extrinsic leaves the pool after five blocks or its anchor falls
outside the 256-block window, leaves its nullifier permanently absent. The note
it spent then stayed `spent` forever: out of the balance, passed over by every
selection, and fully spendable on chain, recoverable only by deleting the
store. `submit_spend` still latches the flag the
moment it has confirmed both nullifiers are settled at the inclusion block,
which covers the window before the next sync repages the set, so
`send --no-sync` cannot select the same input twice.

The two directions are not symmetric, and clearing carries a condition setting
does not. A nullifier absent from a node's map has two possible causes and the
map alone cannot tell them apart: the settlement was orphaned, which is what
this exists for, or the node has not reached the block that settled it. The
node gates at the top of the sync cover the first version of that, a node
behind the wallet on its own chain. What it cannot see is a spend latched at an
inclusion block *above* that watermark, which is every spend made since the
last sync, so the flag is cleared only when `head >= spent_seen_at_block`.
Otherwise the note stays spent and the sync says how many it held back.
Clearing is the direction that can lose money: an un-spent note goes back into
the balance and the next `send` selects an input the chain has already
consumed, which is a full proof paid for a settlement that is skipped. A note
marked spent with no height recorded is cleared, since there is nothing to
compare against; only a store written before the field carried meaning holds
one.

`--rescan` clears nothing at all, whatever the heights say, and the count it
reports as held back says so. The clearing direction reads a missing nullifier
as an orphaned settlement, and that reading is worth what the gate behind it is
worth; a rescan may have walked past that gate.

Every storage key a sync builds is checked against the runtime's own metadata
first (`ensure_known_storage`). On the read path a drifted name or hasher is
silent, because a key that is not there reads as an empty map, and an empty map
is a zero balance or a settled note reported unspent.

### `balance`

Unspent total, pending total, and the note list with leaf indices, block
numbers, state and memos. A note's state is `unspent`, `spent`, or `orphan` for
one the current chain no longer carries. A settled note reads `spent` whatever
became of its leaf, and the orphan heading skips it for the same reason: the
chain refuses a nullifier it has settled, so no re-inclusion brings that value
back and counting it as value awaiting one contradicted the table above it. The
two flags meet on a conflict set, where the orphan marking writes one member
and one member settling marks them all spent.
Orphans are listed again under their
own heading with their total, since they are out of the unspent total and no
spend selects them; `sync` above says how a note gets there and what puts it
back. Pending and refused entries are listed under that.

The table is one row per nullifier. Two notes sharing a
nullifier are a conflict set and at most one of them can ever settle, so a row
per member would print a total the chain will never back. The row carries the
member a spend would use, at its value, and its state reads
`unspent conflict 2` with the number of notes it stands for. A summary line
above the table counts how many held notes are in conflict sets at all.
`sync` above has the rule.

A memo is remote input. Anyone holding this wallet's address can send it a note
and choose the memo's bytes, and printed byte for byte that is an escape
sequence injection into the operator's terminal: `\r\x1b[2K` erases the row
just written and lets the sender redraw the table with leaf indices, values and
spent flags of their choosing, and OSC 52 writes the sender's own address into
the clipboard the operator then pastes into `send --to`. So everything outside
printable ASCII is escaped as `\u{..}` on the way to the terminal, and the
rendering is truncated to the terminal's width less the table prefix, so one
note is always one row.

The escaping is wider than the set of characters that can drive a terminal, and
that is what makes the truncation hold. Counting characters is only counting
columns while every character is one column wide: an East Asian Wide glyph
costs two, a combining mark costs none, so a character budget let a sender of
full-width digits draw a row past any ordinary terminal width, wrap it, and
shape the continuation line into a forged balance row without using one control
byte. U+200B, U+200D, U+2028 and U+2029 are none of them control characters
either, and the first two make two different memos render identically. Escaping
everything outside printable ASCII makes character count and column count the
same number by construction.

The width comes from the terminal itself, through `TIOCGWINSZ` on standard
output, with `COLUMNS` as the fallback and 80 as the fallback after that. It
used to come from `COLUMNS` alone, which is a shell parameter bash and zsh
maintain without exporting, so no child process ever sees one and every row was
drawn at 80 columns whatever terminal it was printed into. On a 64-column
terminal the last sixteen of those columns opened a fresh line at column 1 made
entirely of printable ASCII the sender chose, which is the forged row the
escaping exists to close, reached with no control character at all.

The prefix is measured from the fields the table is about to print rather than
assumed: a leaf index past ten digits or a value past twelve widens its own
column. There is no floor under the memo column, because a floor is a budget
that overrides the terminal, which is the same failure in the other direction:
the old one held the column at sixteen, so a 40-column terminal was handed a
60-column row. A terminal that cannot hold the prefix and a memo column of at
least sixteen columns gets the memo on a line of its own, indented and budgeted
against the same width.

The store keeps the raw bytes: serde_json escapes control characters on the way
to the file, and a wallet that rewrote what it received could not show an
operator what was actually sent.

### `send --to <qn1...> --amount N [--fee F] [--memo TEXT] [--no-sync] [--merkle-rpc]`

Syncs, then spends up to two notes into a payment and a change note.

Order of operations, and every step before the proof exists is there so that a
refusal costs nothing:

1. **Fee floor.** Measured from the ciphertexts the submission will actually
   carry. A `NoteCiphertext` is 1731 bytes plus its padded memo and a note's
   value does not move that, so a probe encryption gives the exact size: 1792
   bytes for both outputs, and the two are asserted equal, since a difference
   is the leak the padding closes. The floor is
   `MinLeafFee + ceil(bytes / CiphertextBytesPerFeeQuantum)`, and for the
   single real slot a wallet submits it equals the whole-submission floor. At
   the current runtime that is 8 quanta for two outputs. `--fee`
   defaults to it and a lower one is refused with the arithmetic spelled out:
   the fee is a public input of the proof, fixed at proving time, so it cannot
   be raised afterwards and the chain would refuse the settlement with
   `PayloadUnderpaid`.
2. **Selection.** Largest first, at most two notes, covering amount plus fee.
   The leaf circuit has two input slots, so a balance spread over three notes
   is not reachable in one spend and the wallet says so, naming what is
   reachable. A witness built anyway carries a balance equation that cannot
   hold.
3. **Anchor.** Always the current head, and every read of the anchor is pinned
   to that one hash, because the tree root moves every block and the header a
   proof binds to must be the one whose root the input paths reach. The wallet
   recomputes the header hash from the six fields plus the re-encoded digest
   logs and compares it against `chain_getBlockHash`. That check is the cheap
   way to catch a wrong digest re-encoding, which otherwise costs a proof and
   comes back as `BlockHashMismatch`.

   Head-anchoring is also a privacy policy, and it is written down here because
   nothing else would stop a later change from breaking it. The anchor block is
   a public input of the settlement, so an observer reads the gap between
   anchor and inclusion. Everyone anchoring at the head makes that gap the same
   short interval for everyone. An anchor at head minus `k`, or one cached and
   reused across two spends to save a `chain_getHeader`, is a distinguisher
   inside the 256-block window and marks both spends as one wallet's. So the
   anchor is never behind the head and never reused. The head is taken after
   the circuits are built for the same reason: the anchor-to-inclusion gap
   otherwise publishes this machine's circuit build time.
4. **Paths.** Rebuilt locally. The wallet reads `ZkTree::Leaves`,
   `ZkTree::LeafCount` and `ZkTree::Depth` at the anchor block and rebuilds the
   tree with `qnero_circuit::merkle::CommitmentTree`, which mirrors
   `pallet-zk-tree` exactly: the same 4-ary node rule, the same sorted
   children, the same all-zero padding for an absent child. The rebuilt root is
   compared against the header's `zkTreeRoot`, each input's leaf against the
   note's commitment, and each path's recomputed root against the header again,
   all before any proving.

   The root comparison comes first, and that ordering is what lets an input's
   leaf index mean anything: a rebuilt tree that roots at the value the anchor
   header carries **is** the chain's tree at that block, so its leaf count is
   the chain's. An input past the end of it is then one of two different
   things. A leaf the anchor block has not folded yet, or one whose block the
   store never recorded, is a race against the block boundary and is reported
   as "wait one block": a note cannot be minted and spent in the same block. A
   leaf the store recorded at a block *strictly below* the anchor is a leaf
   this chain does not carry, because the anchor has executed the block that
   appended it. That one is not a race and never becomes one, so `send` marks
   the note off chain through the same field the sync's orphan check writes,
   and says what happened. Reported as a race it left an operator retrying
   forever, because selection picks largest first and picked the same phantom
   note every time. The note keeps its secrets and its leaf index, and a sync
   that meets the commitment again puts it back.

   `--merkle-rpc` asks the node. `zkTree_getMerkleProof` returns siblings in
   child-index order with no position and
   `MerklePath::from_unsorted` converts them into the sorted form plus the
   2-bit position hint the circuit consumes, with the same root checks. It is
   one call per input against `O(leaf_count)` reads, and it tells the node
   which leaves are yours.
5. **Witness.** One real input per selected note, and
   `InputNote::dummy_random` for the empty slot. Never `InputNote::dummy`: a
   repeated `(rho, r)` publishes a nullifier the chain has already settled and
   the whole submission is refused, naming a value the wallet cannot map to any
   note it holds.
6. **Outputs and `ct_digest`.** An output's `rho` is derived in circuit from
   both nullifiers the leaf publishes, so the witness is built first and the
   output plaintexts come out of it (`SpendWitness::output_note`). Which slot
   carries the payment is drawn per spend, and both memos are padded to one
   size; see "What every chain reader learns". Each is
   encrypted with its own fresh KEM randomness. Reusing it across two outputs
   encrypts both under one ChaCha20-Poly1305 key and nonce, which leaks the XOR
   of the plaintexts and the authentication key, and nothing inside
   `encrypt_note` enforces freshness. `ct_digest` is then computed over the two
   ciphertext blobs in output order with `qnero_circuit::chain::ct_digest`, the
   same function `pallet-shielded` recomputes it with.
7. **Prove, self-verify, submit.** The private batch is proved, verified
   locally against the wallet's own batch verifier data, and submitted as a
   bare unsigned extrinsic, whose preamble byte is checked against the
   extrinsic format version the runtime declares in its own metadata. The change note is written to the store as pending
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
depth and root, and the wallet's own last synced block. It also says whether
the store is bound to this node's chain, which is the one command that reports
a genesis mismatch without refusing: nothing it prints comes out of the store's
own leaf indices.

## Store format

One JSON file beside the seed: `<seed path>.store.json`, mode 0600, written
through a uniquely named temporary file opened with `create_new` and renamed,
with the containing directory synced afterwards. An interrupted write cannot
truncate the only copy of a note's `r`, a pre-existing temporary file cannot
receive the secrets at a looser mode, and a crash after the rename cannot lose
the directory entry.

It is refused on load if anyone but its owner can read or write it, by the same
check the seed beside it gets. `save` writes 0600, and nothing re-establishes
that for a file restored from a tarball without `--preserve-permissions` or
copied between machines under a permissive umask.

```json
{
  "version": 5,
  "address": "qn1...",
  "genesis_hash": "<64 hex chars>",
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
      "spent_seen_at_block": null,
      "on_chain": true
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
      "reason": "its nullifier is already settled on chain"
    }
  ],
  "checkpoints": [
    {
      "block_number": 1062,
      "block_hash": "<64 hex chars>",
      "next_leaf": 1069
    }
  ]
}
```

Field notes:

- `version` is checked on load. A store written by another version is refused.
- `address` is checked against the seed on load, so a store opened with the
  wrong seed is refused and two wallets' notes never merge.
- `genesis_hash` is `chain_getBlockHash(0)` of the chain the store was built
  against, and it is the other half of the same idea: the address binds the
  store to a seed and nothing bound it to a chain. Every leaf index, block
  number, checkpoint hash and spent flag in the file is a statement about one
  chain, and against another one they are all wrong at once: the watermark can
  sit above the other chain's leaf count, so the scan range is empty and the
  wallet goes on reporting a balance that chain has never carried, while the
  settled set the spent flags are derived from is somebody else's. The first
  operation that **commits** against a node records that node's genesis, a
  successful sync, shield or send, and every command after it refuses a node
  that answers a different one. Opening a wallet on a chain checks the binding
  and never writes it: a store's chain is the chain whose answers it actually
  kept, so a gate that refuses leaves a fresh store naming nothing and free to
  take the right node's chain when the operator corrects `--node`. The escape
  is `--new-chain-store`, which **archives** the store beside itself as
  `<store>.archived` and starts fresh: the file is the only copy of every
  note's `rho` and `r`, and the reason it looks wrong may be an operator who
  typed the wrong `--node`. `status` reports a mismatch without refusing,
  because nothing it prints comes out of the store's own leaf indices.

  What this does **not** catch is the case that prompted it, and the
  distinction is worth writing down. `--dev` is a fixed chain spec, so a
  `--dev --tmp` node that restarts on an empty database answers the *same*
  genesis hash as the one before it. Measured on this workstation: two
  successive `--dev --tmp` nodes both answer
  `0xf759610207b350d194f0829b5dc0e595658e960c983665236f7b7aa05d0a8645`. The
  restarted dev node is caught by the checkpoint walk, which finds a different
  block at every height the store checkpointed and rewinds to zero, and by the
  leaf gate, which refuses a tree shorter than the watermark the wallet had
  already reached. Both were run against a live node and the transcript is in
  `docs/OPS-DEV.md`. What the genesis binding catches is a store pointed at a
  genuinely different chain, a testnet against a local dev chain, where the
  checkpoint walk would rewind to zero and rescan happily against a tree that
  belongs to someone else.
- `next_leaf` is one past the last leaf index scanned, and `last_synced_block`
  is the block every read of that pass was pinned to.
- `origin` is `shield` when the note's `rho` matches the entry rule for the
  block its leaf landed in, and `spend` otherwise. It is a label. Nothing in
  the spend path reads it.
- `spent_seen_at_block` is when this wallet first saw the nullifier settled,
  which is not the block that settled it. Spent status is decided locally
  against the paged copy of `UsedNullifiers`, and that map carries no height at
  all, so the best a wallet can record is the head its sync was pinned to.
- `pending` holds notes this wallet created and has not yet seen on chain. A
  pending entry is dropped when a sync records the note at its commitment. One
  left behind by a submission that never settled stays until it is deleted by
  hand; it carries the block it was submitted at and the extrinsic it was
  submitted as, which is enough to tell the two apart.
- `rejected` holds decryptable outputs that were refused, with the reason.
- `on_chain` is false for a note a fork rescan walked past without finding, and
  for one a spend's path rebuild proved the chain's own tree does not carry: its
  settlement was orphaned and has not been re-included, so the chain does not
  back its value. Such a note keeps its secrets and its leaf index and stays out
  of the unspent total and out of every note selection until a scan sees the
  commitment again. `sync` above has the whole rule, and `send` step 4 has the
  second writer. It is only ever written over an unspent note: a settled
  nullifier ends a note whatever became of its leaf.
- The chain's settled nullifier set is **not** on disk. It is paged whole on
  every sync and held in memory for that sync alone, because both of its
  readers, the scan's duplicate check and the spent reconciliation, run inside
  the sync that just repaged it, and no other command reads it at all. A
  persisted copy therefore never produced a cache hit, while it grew the file
  with the whole chain's activity instead of this wallet's and a single `send`
  rewrote the file three times. Version 3 wrote it as `used_nullifiers`; a
  version-3 file still loads and that field is ignored.
- `checkpoints` is one entry per sync, oldest first, at most sixteen: the block
  that sync finished at, its hash, and the leaf watermark it left. It is the
  fork detector's memory, and `sync` above says what it is for. Deleting it
  costs nothing except the ability to notice a fork that happened before the
  next sync.
- `version` is 5. Every older shape from 2 up is upgraded in place on load. A
  version-4 store, written before `genesis_hash` existed, loads with no chain
  recorded, and the first sync that commits after the upgrade records the
  genesis of the node it runs against: which chain it actually came from is not
  a question that version ever asked, so that is the most this can recover.

  What no upgrade recovers is a note an older build refused as a duplicate
  nullifier. Builds before the conflict-set rule refused the second note they
  met that shared a nullifier with one already held: they wrote a `rejected`
  entry, kept no copy of that note's `rho` and `r`, and left the leaf below the
  watermark, where no later sync reads it again. The secrets are not in the
  file to restore. They are on chain, inside the ciphertext beside the
  commitment, so `sync --rescan` walks the tree from leaf zero and picks them
  up, keeping every note already held. A fresh store against the same chain
  recovers the same notes and loses the spent history; `--rescan` keeps it. A version-3
  store, written before `on_chain` existed, has every note read as on chain,
  which is what every note in one is, since that version had no way to mark a
  note otherwise; its checkpoints are kept, because their block hashes came
  from the same chain. A version-2 store, written before `checkpoints` existed,
  is upgraded with an empty checkpoint list. A version-1 store is refused.
  Deleting a store and re-syncing recovers every unspent note, which is the
  same recovery the paragraph below describes.

Note secrets never reach a `Debug` format. `StoredNote`, `PendingNote`,
`RejectedNote`, `WalletStore`, `SecretHex` and `PreparedSpend` all hand-write
`Debug` and print `[REDACTED]`, the way every other type in this workspace that
touches note material does. `genesis_hash` is not covered: it is the hash of
block zero, which every chain reader has. What is covered, field by field: `rho`, `r`, the
memo and the nullifier for the store types, and for `PreparedSpend` the
nullifiers it is about to publish, the nullifiers of the notes it spends and
the leaf indices it holds.

The nullifier is covered because for a note that has not been spent it has
never appeared anywhere: it is exactly the value `Chain::used_nullifiers_at`
pages a whole public map for, so a log line carrying it lets whoever reads that
file later watch the chain and attribute the settlement that publishes it to
this wallet with certainty. What is deliberately not
covered is `StoredNote::leaf_index`, and `SendReport` likewise prints the input
leaves of a settled spend. A leaf index names a leaf this wallet owns, which
carries its own weight, and what it stops short of is predicting a value the
wallet has yet to publish.
`commitment` stays in the clear as well, since the chain published it beside
the leaf. `store.rs::debug_output_carries_no_note_secrets` and
`wallet.rs::a_prepared_spend_prints_no_nullifier_and_no_leaf_index` are the
gates behind all of it.

Note secrets are wiped when they are dropped. `rho`, `r` and the nullifier are
held in `SecretHex`, a transparent newtype over `String` that zeroizes on drop,
so the copies the wallet keeps longest, the ones `serde_json` allocates while
parsing and the clones `prepare_spend` takes, are wiped on the way out. The
nullifier is in there on the argument the `Debug` redaction already made: for a
note that has not been spent it has never appeared anywhere, so it is the more
predictive of the three, and a plain `String` freed without wiping sits in
exactly the memory a core dump or a swap page reaches.
`PreparedSpend::spent_nullifiers` holds the same type for the same reason, and
on the sharpest version of the argument: a `PreparedSpend` exists exactly
during the window between proving a spend and its settlement landing, so those
values have appeared nowhere at all while it is alive. The conflict-set queries
a scan runs key on borrowed nullifiers for the same reason, since the
duplicate check they replaced built a fresh owned set per received note and
every one of those copies dropped unwiped. The
store's own JSON text is read and written inside `Zeroizing` as well, and the
seed one file over gets the same treatment. What is not covered: serde_json's
internal buffers, and any `String` that reallocated while growing, which leaves
the old allocation behind. These are built once from a fixed 64-character hex
and never grown.

Deleting the store and re-syncing recovers every unspent note, because every
note's plaintext is on chain in its ciphertext. What it does not recover is
the spent history: a note that was received and later spent comes back as a
`rejected` entry reading "its nullifier is already settled on chain", which is
true and is why it is not in the balance.

## Tests

```
# unit tests plus the fake-node tests, no chain, fast
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

Two of the default tests run the wallet against a scriptable JSON-RPC node in
`tests/support/mod.rs` that records every request body:

- `tests/node_learns_nothing.rs` asserts a sync never names one of this
  wallet's nullifiers and that a rebuilt tree asks nothing about a leaf. Those
  are properties of the request stream alone: the probing version and the
  paging version reach identical balances, so no assertion over a balance can
  see the difference.
- `tests/shield_dispatch.rs` asserts that a shield whose extrinsic was
  included and whose dispatch failed is an error, and leaves no pending note
  behind in memory or on disk, and that a runtime whose storage layout is not
  the one the wallet hashes stops a shield before it is signed.
- `tests/sync_reorg.rs` asserts that a note re-included at a different leaf
  after its block was orphaned is moved in the store to the leaf it now
  occupies. A skipped one keeps a stale leaf index, reads as spendable, and
  fails every spend on the path rebuild. It also asserts that one refused
  output is one entry in `rejected` however many forks walk past it, and that
  the entry goes when the settlement that claimed its nullifier leaves the
  chain and the output becomes holdable.
- `tests/sync_guards.rs` asserts what a sync refuses. A node behind the
  wallet's own watermark is refused and the store is byte-identical afterwards,
  on disk as well as in memory. A node with no block at a checkpoint's height
  is refused and no checkpoint is popped, while the same hash at that height is
  not a fork and the sync runs with nothing rewound. A store built against
  another chain is refused by `open_on_chain` and by `sync` on its own, and
  `--new-chain-store` archives the old file with its note secrets intact. And a
  conflict set is one candidate at its largest member's value, spends that
  member, and reports every member spent once the shared nullifier settles.

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
   other shield. Both halves are checked afterwards and a miss is printed, and
   a block that settled more than one entry is reported as unproven, because
   the index the chain assigned is only in the `Shielded` event. Closing it
   properly needs either a chain-side rule that does not depend on the
   inclusion block, or a shield that carries `inner` derived at settlement
   time, and both are M6 decisions.
3. **A received note's `rho` is not checked against the entry rule.** The rule
   hashes `(block_number, entry_index)` and only the `Shielded` event publishes
   `entry_index`, which needs the runtime's full type registry to decode. The
   wallet walks the entry counter instead, which is exact on a dev chain and
   O(entries) per received note on a long-lived one. The counter itself is read
   once per sync, since the whole scan is pinned to one block and the value
   cannot move under it. What the walk buys is the `origin` label, and nothing
   in the spend path reads it; the refusal that actually protects the
   recipient, a duplicated nullifier, does not depend on it either.
4. **`POOL_QUANTUM` is the one chain value with no metadata surface.** It is a
   constant of the pallet crate with no `#[pallet::constant]` declaration, so
   the wallet carries a copy. A mismatch surfaces as a `shield` whose dispatch
   failed, because the runtime refuses a value that is not a whole multiple
   with `ValueNotQuantized` and the wallet now confirms that a leaf was
   actually appended. It surfaces as "the dispatch failed and no note was
   created". Surfacing the error's own name would need the runtime's full type
   registry to decode a failed dispatch's `DispatchError`.
5. **`N` is not discoverable over RPC either.** The wallet resolves it as
   `QNERO_NUM_LEAF_PROOFS` falling back to
   `qnero_circuit_builder::DEFAULT_NUM_LEAF_PROOFS`, which is exactly how
   `chain/pallets/shielded/build.rs` resolves it, so one environment produces
   one `N` on both sides. Building the runtime and the wallet in *different*
   environments still diverges silently: the proof's public-input length is
   refused by the chain's embedded verifier after the full proving cost has
   been paid. The wallet does not compare its leaf verifier bytes against
   `pallet_shielded::LEAF_VERIFIER_ARTIFACT`, which exists for exactly that
   check and is not reachable over RPC.
6. **One transfer per submission.** A private batch has six slots and the
   wallet fills one. Filling more needs a queue and a policy for what to batch
   with what, and the anonymity argument for batching is the whole point of the
   shape, so it is a design decision, and the loop is the smallest part of it.
7. **A local rebuild costs `O(leaf_count)` reads per spend.** Merkle paths are
   rebuilt locally because asking the node for a proof names the leaf being
   spent, and that is the sender side of the pool deanonymized against whoever
   runs the RPC. The price is reading the whole leaf range at the anchor block
   on every spend where the proof RPC is one call. On a long-lived chain that
   wants an incremental local tree kept across syncs, which is bookkeeping this
   wallet does not have. `--merkle-rpc` trades the privacy back for the speed,
   and says so.
8. **Traffic analysis is not addressed.** No request names a note, but the node
   still sees an IP, a sync pattern and submission timing. Nothing inside a
   wallet fixes that.
9. **The anchor-to-inclusion gap is a per-wallet class marker.** Both blocks are
   public inputs of the settlement, so every chain reader sees the gap, and
   everything between the anchor and the submission is inside it: the local
   tree rebuild, the encryptions and the proof. A `--merkle-rpc` spend, a slow
   machine and a long chain each land at a measurably different gap. Making it
   uniform means holding the submission until the anchor plus a fixed number of
   blocks, which is latency M5 does not spend. See "What every chain reader
   learns".
10. **A memo is capped at 61 bytes.** Every memo is padded to one size so the
    published ciphertext lengths say nothing, and the fee bounds the pad ahead
    of the ciphertext cap: it has to leave `2 * (1731 + pad)` a
    `CiphertextBytesPerFeeQuantum` bucket below `2 * MaxCiphertextBytes`, or a
    settler pads to the cap and writes permanent state for free. A longer memo
    is refused, so nothing goes out at a length of its own. Raising the cap is
    a coordinated change: the pad and the runtime's divisor move together, and
    every wallet on the chain has to agree on the size or the padding buys
    nothing. A runtime that merged the two buckets is a warning and not a
    refusal, for the reason "What every chain reader learns" gives, so a wallet
    can go on sending against a chain whose fee schedule it cannot fix.
11. **A conflict set holds value the wallet can never reach.** Two notes
    sharing a nullifier are one spendable value, and the smaller members are
    dead weight that the store keeps and the balance does not count. Nothing in
    v0 can recover them, because the chain refuses a nullifier it has already
    settled, and nothing in a wallet can stop a sender creating them. What a
    wallet owes is to hold every one of them and to pick the best member, which
    is what it does; the recipient-side rule `docs/CIRCUIT.md` section 9.8 asks
    for is a refusal to *count* them, and that is where it lives now.
12. **The node gates are local, and a lying node is still a lying node.** The
    checkpoint walk compares against hashes this wallet recorded from a node,
    the leaf gate against a watermark it reached against a node, and the chain
    gate against a genesis it recorded from a node. A node that answers a
    plausible head it does not have, or that forks below every checkpoint the
    store kept, still drives a full rescan. None of the three is a consensus
    check and none is meant to be: they refuse the answers that a wallet can
    prove are not new information. Verifying the chain itself is running a
    node.
13. **A node that diverged above its own head reads as a lagging node.** The
    checkpoints that would show the divergence are heights it cannot answer
    for, so the walk has nothing to compare and the sync refuses as though the
    node were simply behind. The refusal is the safe answer, since the two are
    indistinguishable from the store alone, and `--rescan` is the way through
    it, at the price `sync` above states: that pass adds what the node carries
    and reconciles nothing, so an ordinary sync against a node at the current
    head still owes the wallet its spent flags and its orphans. Telling them apart needs the wallet to keep block hashes below every
    checkpoint, which is a header chain, which is a node.
