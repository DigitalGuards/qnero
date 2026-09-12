# Qnero design (draft v0.1, 2026-09-11)

Qnero is a post-quantum private coin with Monero's policy: every transfer is
shielded, sender, recipient and amount are hidden, and no call moves value
between accounts a user chooses. The single transparent payout is
`Vesting::claim`, whose payee and amount are both fixed at genesis and whose
pot cannot sign (section 7.2). Qnero is built on the Quantus Network stack
(MIT) so the post-quantum account layer, hash-based ZK proving and recursion,
Merkle commitment tree and nullifier set are reused as audited code.

Three things a v1 block publishes, stated here because the rest of this
document is about what it hides. `shield`, the one door into the pool, is a
signed extrinsic that names the payer, the amount and the leaf it created, so
the entry is public and only what happens after it is not. A coinbase publishes
its note's value and the block that minted it, with the recipient inside an
`inner` the chain cannot open. A vesting claim publishes a genesis-fixed
allocation, the account it went to and when. `docs/CIRCUIT.md` section 10.7 is
the full list of what one block reveals.

## 1. Why not port Monero's cryptography

Monero's privacy is Ed25519 in four places: CLSAG ring signatures with key
images, RingCT Pedersen commitments with Bulletproofs+, ECDH stealth addresses,
and the in-progress FCMP++ curve trees. None of those has a production-grade
post-quantum replacement. Lattice RingCT designs (MatRiCT+, Raptor) exist as
papers with transactions in the tens of KB and no audited implementation.

Hash-based STARK/FRI proving does have production implementations, and it is
post-quantum by construction. A shielded pool in Zcash Orchard semantics (note
commitments, nullifiers, membership proofs, balance proved in zero knowledge)
needs only a hash function inside the circuit. Monero's user-facing property
survives: every unit minted after genesis is a note, and the pool is where it
lives.

## 2. Primitive mapping

| Monero piece | Qnero replacement | Source |
|---|---|---|
| Ed25519 spend/view keys | Hash-derived spend key, ML-KEM decapsulation key as view key | new + `clatter`/rust-crypto ML-KEM already in Quantus deps |
| Stealth address (ECDH) | ML-KEM encapsulation per output, AEAD note ciphertext | new |
| Pedersen commitment | Poseidon note commitment `cm = H(CM, H(NOTE, pk, rho, r), v)` | new, `qp-poseidon` |
| Bulletproofs+ range proof | 62-bit range check inside the Plonky2 circuit | plonky2 gadget |
| CLSAG ring + key image | Merkle membership proof in the 4-ary Poseidon tree + nullifier `nf = H(NF, nk, rho, r)`, or `nf = H(NF_DUMMY, nk, rho, r)` for a padding input slot | `qp-zk-circuits` `zk_merkle`, `nullifier` fragments |
| Ring size / decoys | Anonymity set = the whole tree (all notes ever) | `pallet-zk-tree` |
| Transaction signature | Spend proof bound to the transaction digest as a public input | plonky2 public inputs |
| RandomX PoW | QPoW (kept through v1, behind one author seam; section 10) | `pallets/qpow` |
| Node identity, p2p | ML-DSA-87 accounts, PQ Noise (ML-KEM) | Quantus |

Field: Goldilocks. Hash: Poseidon (Quantus parameters, Eiger reviewed). Proof
system: Plonky2 (FRI), conjectured 100-bit security at the Quantus config.
Every primitive is hash-based or lattice-based; there are no elliptic curves in
the transaction path.

The two hash rules above are quoted for orientation. Section 5 and
`docs/CIRCUIT.md` section 3 are the authority on them, and both `r` in the
nullifier preimage and the separate padding tag are load bearing: they are what
keeps `nk` a viewing-tier secret and what stops a padding slot from settling a
real note's nullifier. Section 4 explains both.

## 3. What is reused from Quantus, verbatim or by fork

Verified on this machine 2026-09-11: `cargo test -p qp-wormhole-circuit
--release` passes (25 tests) on toolchain 1.93.0.

| Component | Reuse | Notes |
|---|---|---|
| Leaf circuit fragments: `zk_merkle_proof`, `nullifier`, `block_header`, `sensitive` (zeroize) | fork | The unspendable-account and dual-exit fragments are replaced by note fragments |
| `PrivateBatchAggregator` (7 leaves, ZK, client side) | fork | New public-input layout |
| `PublicBatchAggregator` (53 batches, delegatable) | fork | Forward-only, minimal change |
| `pallet-wormhole` verify flow: PI parse, block hash check, nullifier dedupe, plonky2 verify, tx-pool tags | fork as `pallet-shielded` | Exit-account minting becomes commitment append + ciphertext event |
| `pallet-zk-tree` 4-ary Poseidon tree | small fork | Node hashing unchanged; `Leaves` holds a raw `Hash256`, the note commitment, see `docs/CIRCUIT.md` section 4 |
| `UsedNullifiers` storage | as is | |
| ML-DSA-87 accounts, hdwallet | as is | Transparent layer. At v0 it carried miner rewards and fees; at v1 it carries fees, the shield entry and the genesis vesting payout, and no transfer between accounts a user chooses (section 7.2) |
| Audits | as is | Eiger Wormhole audit 2026-03-20, Substrate audit 2026-05-13, PoW + Poseidon review |

## 4. Keys and addresses

```
sk        : 32 random bytes                     (seed, backed up by the user)
ask       = H("qnero/ask", sk)                  spend authorizing key, private
nk        = H("qnero/nk",  sk)                  nullifier key, private
ak        = H(AK, ask)                          public spend commitment
pk        = H(PK, ak, nk)                       note-receiving key, 32 bytes
(ek, dk)  = ML-KEM.KeyGen(H("qnero/kem", sk))   view key pair
cvk       = H("qnero/cvk", sk)                  coinbase viewing key, private
address   = bech32m("qn", pk || ek)
```

`cvk` is the one key an operator copies out of a wallet and into a node.
`qnero-wallet miner-address` prints `pk || cvk` as a single bech32m string and
the node is configured with that, so every coinbase note the node mints is one
the wallet can find. Section 7.1 rule 5 is why a coinbase note is derived from
`cvk` rather than encrypted to `ek`.

Two hash forms appear here and they are not interchangeable. `H("qnero/...",
...)` is Poseidon2 over bytes with that ASCII string as a literal prefix, and
it is used exactly where written: `ask`, `nk`, and the ML-KEM seed. `H(TAG,
...)` is Poseidon2 over field elements with a one-felt domain tag as the first
sponge input: `AK = 0x716e_0001`, `PK = 0x716e_0002`, `NOTE = 0x716e_0003`,
`CM = 0x716e_0004`, `NF = 0x716e_0005`, `RHO = 0x716e_0006` (hashes the two
nullifiers a spend publishes and an output index, derived in circuit),
`NF_DUMMY = 0x716e_0007` (the nullifier a padding input slot publishes) and
`NF_BATCH_PADDING = 0x716e_0008` (the nullifier the private-batch wrapper
emits for a padding slot, over randomness it draws per slot per proving run,
`docs/CIRCUIT.md` section 8.4). Those are the values in
`qnero_notes::digest::domain`, and the spend circuit imports them from that
crate so the two copies cannot drift. A test in that module asserts the tags
are pairwise distinct, because two rules sharing a tag is the failure that has
no symptom until someone finds the collision. `docs/CIRCUIT.md` section 3 is
the authority.

`0x716e_0008` is taken. A note created outside a spend proof, a shield today
and a coinbase at M6, needs a tag of its own at `0x716e_0009` or above. M4 took
`RHO_ENTRY = 0x716e_0009` for the shield. M6 took two more, both for the
coinbase, because its `rho` and its `r` are derived from public data and a
configured key rather than drawn at random: `RHO_COINBASE = 0x716e_000a` over
the block number, and `R_COINBASE = 0x716e_000b` over the coinbase viewing key,
the chain's genesis and the block number. Section 7.1 is why they are derived, and
`qnero_note_core::coinbase_r` is the rule.

Address size is dominated by the ML-KEM encapsulation key: 1184 bytes at
ML-KEM-768, 1568 at ML-KEM-1024. Decision pending: ML-KEM-1024 for level-5
parity with ML-DSA-87, or ML-KEM-768 for shorter addresses. Either way
addresses are QR-code sized, the same trade-off the QRL Connect protocol
already made.

Viewing: `dk` alone lets a wallet detect and decrypt incoming notes and see
outgoing note contents it authored. `nk` tells the holder of a note whether it
has been spent. `ask` is needed to spend. This matches Monero's view-key /
spend-key split for notes that arrive as payments, and it stops one step short
of Monero for a mining wallet: a coinbase note is derived from `cvk`, which
neither `dk` nor `nk` produces, so a holder of the full viewing key sees every
shielded receipt and no coinbase note at all. A full disclosure of a mining
wallet is `(ivk, nk, cvk)`. Monero's view key does cover coinbase outputs,
which is what makes the gap worth stating. `docs/WALLET.md` carries the same
rule where the miner key is printed.

`nk` is a viewing-tier secret and confers nothing beyond detection. Two
properties of the spend circuit keep it that way, both in `docs/CIRCUIT.md`
section 3. The nullifier hashes `(nk, rho, r)`, and `r` reaches only the note's
sender and its holder, so `nk` plus the publicly derivable `rho` of every
output note is still not enough to compute anyone's nullifiers and link their
spends pool-wide. And a padding input slot's nullifier is domain separated, so
a holder of someone else's `nk` cannot publish that person's nullifier from a
slot that proves no membership and burn the note.

## 5. Notes

```
note      = (pk, v: u64 capped at 2^62 - 1, rho: 32 bytes, r: 32 bytes)
inner     = H(NOTE, pk, rho, r)
cm        = H(CM, inner, v)
nf        = H(NF, nk, rho, r)                 real input slot
nf_dummy  = H(NF_DUMMY, nk, rho, r)           padding input slot, tag selected in circuit
rho_out_j = H(RHO, nf_1, nf_2, j)             a spend output's rho is derived in circuit
```

The 62-bit cap on `v` is a consensus rule. The no-wrap argument behind the
circuit's balance equation (`docs/CIRCUIT.md` section 5, constraint 8) holds
only while every term is below `2^62`, so every path that creates a note,
coinbase and deposit included, has to enforce the cap.

The two-layer commitment lets a coinbase note carry a public `v` and a public
`inner` that the chain checks against `cm` while `pk` stays hidden. Regular
notes keep both layers private.

Output on chain: `cm` (32 bytes), ML-KEM ciphertext (1088 or 1568 bytes),
AEAD ciphertext of `(v, rho, r, memo)`. Recipients scan every output by
decapsulating and attempting decryption, the same linear scan Monero wallets
do. The leaf's `ct_digest` public input binds the ciphertexts to the proof;
`qnero_circuit::chain::ct_digest` is the rule and `docs/CIRCUIT.md` section 1
states it. It lives in the circuit crate's layout-only surface, which compiles
without the prover stack, which is what lets the chain and a wallet call one
function, where two copies of one rule could drift.

The AEAD key and nonce come from the KEM shared secret, a per-payload label and
the crypto suite (`qnero_pqcrypto::note_encryption`), with the version, suite
and diversifier index as associated data. The commitment is not an input to
that derivation, so key separation between two outputs rests entirely on the
KEM randomness being fresh per output. `encrypt_note` documents the
requirement and nothing enforces it, so reusing `kem_randomness` across two
outputs to one recipient encrypts both payloads under one ChaCha20-Poly1305 key
and nonce, which leaks the XOR of the two plaintexts and the Poly1305
authentication key. M5 drew every output's randomness from the operating
system's CSPRNG at the point of encryption, so the wallet has no variable to
reuse and no path that could: `crates/qnero-wallet/src/wallet.rs` calls
`random_bytes()` once per output. A `NoteCiphertext` is a fixed size plus its
memo and the chain publishes the bytes whole, so the wallet also pads every
memo to one size; that is a wallet-side rule with no chain enforcement behind
it, and every wallet on a chain has to agree on the size for it to buy
anything (`docs/WALLET.md`). That closes it for this wallet and leaves the
API able to be misused by the next one. The second half stays open: feeding
`cm` into the AEAD key derivation would make a reuse bug survivable, and it is
a wire-format change that belongs beside the M6 coinbase.

## 6. v0 spend circuit (leaf)

Built at M2. `docs/CIRCUIT.md` is the implemented specification, including the
tree leaf rule M3 and M4 depend on; this section is the design intent it was
built from, and the two agree.

One leaf = one shielded transfer: up to 2 inputs, exactly 2 outputs.

Private inputs: for each input, `(v, rho, r)` plus `ask`, `nk`, a Merkle path
to `zk_tree_root` and a dummy flag; for each output, `pk`, `v` and `r`. An
input's `pk` is derived in circuit from `ask` and `nk`, so a wrong credential
yields a commitment that is not in the tree, and an
output's `rho` is derived from both nullifiers the leaf publishes, so a
sender cannot hand two notes the same nullifier seed.

Public inputs (felts): `block_hash(4)`, `block_number(1)`, `nf_1(4)`,
`nf_2(4)`, `cm_out_1(4)`, `cm_out_2(4)`, `fee(1)`, `ct_digest(4)`.

Constraints:
1. Block hash equals `H(header preimage)`; the header carries `zk_tree_root`
   (existing fragment).
2. For each non-dummy input: `pk = H(ak, nk)` with `ak = H(ask)`; `cm`
   recomputed from the note; Merkle path from `cm` to `zk_tree_root`;
   `nf = H(NF, nk, rho, r)`. Dummy inputs have `v = 0` and a random nullifier
   preimage under a separate domain tag (`NF_DUMMY`), and at least one input
   must be real unless the leaf is the batch padding leaf
   (`docs/CIRCUIT.md` constraint 9), so every leaf that binds a real block
   consumes a note. That does not bound how many leaves a prover can produce;
   see `docs/CIRCUIT.md` section 8.6 on the minimum per-leaf fee, which is the
   anti-spam mechanism.
3. For each output: `rho` derived as `H(RHO, nf_1, nf_2, j)`; `cm_out`
   recomputed from the note; `v_out` range-checked to 62 bits.
4. Balance: `v_in_1 + v_in_2 = v_out_1 + v_out_2 + fee`, all values 62-bit so
   no field wrap.
5. `ct_digest` is a free public input. The chain recomputes
   `H(ciphertexts)` from the submitted outputs and compares, which binds the
   ciphertexts to the proof without hashing them in-circuit.

Private batch: 7 leaves as today, ZK enabled, produced by the wallet. The
batch is the on-chain transaction unit. Public batch: unchanged in shape.

Built at M3, and two things about it are not "unchanged in shape". The private
batch forwards **both** nullifiers of every leaf, where the Wormhole wrapper
carries one per leaf, and it constrains all `2N` of them pairwise distinct: a
wrapper that kept upstream's shape would drop each leaf's second nullifier and
leave a note spent from input slot 1 spendable again. And it does not sum fees
in circuit, because seven 62-bit fees overflow Goldilocks; the pallet sums them
natively. `docs/CIRCUIT.md` section 8 is the specification, including the
padding rule: a padding leaf is one that binds a fixed, publicly known header
preimage, and the wrapper masks every value such a slot publishes.

## 7. v1 mandatory privacy: the pool, the coinbase and the call filter

`docs/CIRCUIT.md` section 8.6 is the full settlement contract; this is its
shape.

1. Parse the new PI layout; keep the block-hash-at-height check and nullifier
   dedupe.
2. Skip every batch segment carrying `PADDING_BLOCK_HASH`. Such a segment
   settles nothing at all: no nullifier entered, no commitment appended, no fee
   accounted. Its slot region is zeroed, so a chain that settled it would
   insert the all-zero nullifier and reject its own next padding segment as a
   double spend, which at 53 inner slots is close to every batch.
   `PublicBatchPublicInputs::settleable_batches` is that filter, and a zero
   nullifier must never enter the nullifier set.
3. Inside a segment that survives the filter, for every slot: mark both
   published nullifiers used, including a dummy input's, which the chain
   cannot tell from a real one; append `cm_out_1` and `cm_out_2` to
   `pallet-zk-tree`; recompute `ct_digest` over the submitted ciphertexts and
   compare; emit the ciphertexts in an event and store them by leaf index for
   wallet sync. A padding slot never reaches the append: it is dropped when the
   public inputs are parsed, because both its commitments are zero. A zero
   commitment inside a real slot is a `ZeroCommitment` refusal of the whole
   submission, since no valid proof produces one and the all-zero digest is the
   tree's own absence sentinel. `docs/CIRCUIT.md` section 9.4 is the contract.
4. Fee: sum of the leaf fees of those same segments, split burn / block author
   as Wormhole does today.
5. A public batch is checked whole before any state changes. A segment holding a
   nullifier already settled, or one an earlier segment of the same submission
   claimed, is skipped and the rest settles; a repeat inside one segment refuses
   the submission, and a submission that settles nothing is refused.
   `docs/CIRCUIT.md` section 9.5 carries the reasoning.
6. Entry in v0: `shield(value, inner, ciphertext)`, a signed extrinsic that
   burns transparent value and appends `cm = H(CM, inner, value)`. There is no
   exit in v0: value that enters the pool moves only between notes. At v1 the
   coinbase adds a second creation path. `shield` is still the only entry and
   there is still no exit; what goes at v1 is the transparent mining reward and
   the wormhole exit (section 7.2).

Built at M4, in `chain/pallets/shielded`. Two rules the pallet owns that this
section did not spell out: a minimum fee per real leaf slot, which is the only
thing bounding how many leaves a prover can produce, and a `rho` rule for a note
created outside a spend proof, `rho = H(RHO_ENTRY, block_number, entry_index)`
under a domain tag of its own. `docs/CIRCUIT.md` section 9 is the contract as
built, including the open decisions it closed.

### 7.1 The coinbase (M6)

Value created after genesis enters circulation in exactly one place: the note a
block mints to its author. `pallet-mining-rewards` still computes the emission
and still collects transaction fees, and it no longer mints anything to an
account. It hands the credit to a sink, and the sink is the shielded pool.

Genesis is the exception, and it is a large one: `mainnet_vesting` mints 27% of
`MAX_SUPPLY` at genesis as transparent balances, a keyless vesting pot plus a
seed to each treasurer and each collective member. None of it is a note, all of
it is inside `Balances::total_issuance()`, and it reaches its holders through
`Vesting::claim`, which publishes the beneficiary and the amount. Section 7.2
is why that call is the one transparent payout v1 keeps.

```text
block author's node           inherent                 pallet-shielded
---------------------         --------                 ---------------
rho   = H(RHO_COINBASE, n)    coinbase(inner, ct)      on_finalize of block n:
r     = H(R_COINBASE, cvk, genesis, n)                   total = emission + tx fees
inner = H(NOTE, pk, rho, r)                                    + author fee share
                                                         cm    = H(CM, inner, total)
                                                         append cm, store (block,
                                                         total, ct) at its leaf
```

The value is public, and so is the block that minted it. Who it belongs to is
not. That is what the two-layer commitment is for (section 5): the chain hashes
a value it decided itself into an `inner` it cannot open, so it can price the
note without knowing whose it is. `Shielded::CoinbaseValues` is where the value
is published, keyed by leaf index, and presence in that map is what marks a
leaf a coinbase.

Nothing beside the value names the miner. The header's `PreRuntime` item, which
consensus needs and which the runtime hashes into the account it calls the
block's author, is `H(cvk, parent_hash)` and therefore changes every block: a
constant item would label every block one operator won, beside the public value
of the coinbase note in it, which is more than a Monero coinbase reveals. The
events say what was credited and never who to. `qnero_note_core::MinerKey::author_label`
is the derivation and `sc_consensus_qpow::AuthorLabel` is the seam.

Five rules the pallet holds:

1. **One per block, or the block is invalid.** The coinbase is a required inherent and a mandatory
   dispatch. A block with none mints its reward nowhere and is refused on import; a second one in
   the same block fails the dispatch and takes the block with it. The block number is the whole
   identifier `rho` is derived from, so two coinbase notes in one block would be two notes on one
   nullifier seed.
2. **The author's fee share becomes a note.** A settled fee leaves `PoolValue` whole. The
   burn share stops existing. The rest waits in `PendingCoinbaseFee` and becomes part of the same
   block's coinbase note, so no account and no issuance moves in the fee path at all.
3. **The same checks as every other creation path.** The 62-bit value cap, a whole number of pool
   quanta, and a canonical `inner`. The last is checked at the inherent, where a refusal is still
   possible, because `on_finalize` cannot refuse anything.
4. **Supply is measured across both books.** `Balances::total_issuance()` counts transparent
   balances only, and shielding burns from the shielder, so under v1 nearly every planck is invisible
   to it. `pallet-mining-rewards` adds `PoolValue + PendingCoinbaseFee` to the issuance it reads.
   Without that term the emission schedule would see supply fall as the pool filled and mint faster
   forever, and `MAX_SUPPLY` would mean nothing.
5. **The note is derived rather than encrypted.** `r = H(R_COINBASE, cvk, genesis_hash,
   block_number)`, where `cvk` is a coinbase viewing key the operator configures its node with,
   beside `pk`, as one bech32m miner key. The genesis is in the preimage because the derivation has
   no randomness in it: without it, one miner key run on a testnet and on mainnet would mint byte
   identical notes at equal heights on both. The node cannot encrypt to an ML-KEM key: the chain's own post-quantum Noise transport pins
   a semver-incompatible `ml-kem` and a binary cannot hold both. The note stays private against
   anyone holding only the miner's address, `cvk` is a viewing-tier secret for coinbase notes alone,
   and a coinbase paid to an address whose `cvk` the author does not hold still needs an encrypted
   payload, which the wallet reads (`qnero_notes::try_receive_coinbase`) and the inherent refuses
   until its bytes are priced against the author's own credit; `docs/CIRCUIT.md` section 10.3.
   `qnero_note_core::coinbase_r` carries the full argument.

### 7.2 The call filter (M6)

`BaseCallFilter` refuses every call that moves transparent value between
accounts a user chooses. One transparent payout survives it, `Vesting::claim`,
whose payee and amount are both fixed at genesis and whose pot cannot sign; the
Allowed list below carries the reasoning. This is the allowlist as a rule:
everything is allowed except the calls below, and `runtime/tests/call_filter.rs`
is the test.

It is a dispatch-time check, which has a cost worth stating plainly. A refused
call is still a valid extrinsic: it passes validation, enters a block, pays its
fee and then fails with `CallFiltered`, so its arguments stay in the block body
and in the `System::ExtrinsicFailed` event forever. One mistaken
`Balances::transfer_keep_alive` therefore publishes the sender, the recipient
and the amount that the policy exists to keep private, while nothing moves. A
wallet should refuse these calls before it signs one. Moving the refusal into a
`TransactionExtension` beside the existing ones would reject them at validation
instead, so they never reach a block; that is the open option here.

Refused:

| Call | Why |
|---|---|
| `Balances::transfer_allow_death`, `transfer_keep_alive`, `transfer_all` | the transfers themselves |
| `ReversibleTransfers::schedule_transfer`, `schedule_transfer_with_delay`, `execute_transfer`, `cancel`, `recover_funds` | transfers with a delay, and the guardian seizures of their holds |
| `ReversibleTransfers::set_high_security` | moves nothing, and is refused anyway: it is a one-way door into a feature whose every call v1 refuses, see below |
| `Vesting::create_schedule`, `end_schedule`, `retarget_schedule` | funds the pot from the treasury, and moves a schedule's unpaid remainder |
| `Utility::batch_all`, `Multisig::execute` carrying any of the above | a filter that stops a call and not the wrapper carrying it is decoration |

Allowed, and load bearing:

- `Vesting::claim`, the genesis distribution channel. Every preset endows a keyless vesting pot
  against schedules written at genesis, and `create_schedule` above means no new schedule can
  appear. A claim therefore pays a beneficiary fixed at genesis an amount fixed at genesis, and
  that beneficiary can then only shield or burn what it receives. Refusing it would strand the
  whole genesis allocation in an account with no key, permanently inside `total_issuance`, where
  the emission schedule counts it as supply and under-mints by exactly that much forever.
  `every_genesis_planck_is_reachable_under_the_call_filter` is the test, and it also holds the
  other half of the decision: no preset may endow an account that cannot sign. The dev preset used
  to endow a keyless wormhole test address, whose only spend path was the block-1 wormhole leaf v1
  removed, and that endowment is gone.
- `Shielded::shield`, the only door into the pool. It burns the caller's own balance, so it moves
  value out of the transparent layer rather than between accounts, and blocking it would lock every
  genesis balance out of the chain's own pool with no way in.
- `Shielded::submit_private_batch` and `submit_public_batch`, which are unsigned and fee free, and
  `Shielded::coinbase`, which is an inherent. A filtered inherent is a mandatory dispatch failure,
  which is a dead chain rather than a dropped reward.
- `Timestamp::set`, every `System` call, and the whole governance lane.
- `Balances::burn`, which destroys the caller's own balance and moves nothing to anyone.
- The fee path. `ChargeTransactionPayment` is a transaction extension and never reaches a `Contains`
  check, which is what lets a filtered runtime still charge for the calls it allows.

`set_high_security` is on the refused list for a reason of a different kind,
and the reason is worth writing down because it looks like an omission. The
call is one way: the pallet has nothing that clears the flag and refuses a
second enrolment. From the block it succeeds in, the account can sign only what
is on `HighSecurityConfig`'s whitelist, which is checked at validation rather
than at dispatch, and v1 refuses every value-moving call on that list at
dispatch, so the account can sign nothing at all. The whitelist stays as it is
anyway. Every call on it is delayed and reversible, which is the whole of the
guarantee the feature sells: a stolen key can only schedule, and the
owner's `cancel` or the guardian's `recover_funds` beats the delay.
`Shielded::shield` and `Balances::burn` would each break that, because both are
immediate, both are irreversible and neither is reachable by `recover_funds`,
which walks `PendingTransfersBySender` and releases holds. A `shield` whose
`inner` commits to a `pk` only a thief holds settles in the next block with the
value inside the pool and nothing left to cancel. So the whitelist stays as it
is, the enrolment is refused, and no v1-genesis chain reaches the freeze: no
non-benchmark preset seeds `HighSecurityAccounts` either.
`the_high_security_whitelist_admits_only_reversible_calls` is the test and
`chain/docs/RUNTIME_SURFACE.md` section 5 is the surface.
Two things the filter does not reach, both by design in `frame_system` and both
stated here so they are decisions rather than discoveries:

- **Root bypasses it.** `dispatch_bypass_filter` is how a privileged origin dispatches, so a tech
  referendum can still move transparent value. The calls exist and the collective can enact them;
  the filter is what keeps them out of ordinary use.
- **The scheduler is not an exemption**, which is worth stating because it reads like one. Its own
  extrinsics are disabled, and it dispatches a due task with the origin that task carries. Only
  Root is exempt from `filter_call`, so a scheduled call under a signed or non-Root custom origin
  meets this filter like any other. That is why a reversible transfer's own enactment is refused:
  the pallet executes by dispatching `Balances::transfer_*` under the account's signed origin.
  `runtime/tests/transactions/reversible_integration.rs` is the test.

`pallet-wormhole` is gone from the runtime at M6, and with it the transparent
exit and the transaction extension that scanned balance events into spendable
leaves. There are no transparent transfers left to scan. The crate stays in the
tree, and `qp-wormhole`, the primitives crate, stays in the runtime: the QPoW
author derivation lives there and the runtime's one author seam calls it.

## 8. Milestones

| # | Deliverable | Estimate |
|---|---|---|
| M1 | `qnero-notes` crate: keys, addresses, note commitment, ML-KEM note encryption, scan; KATs pinned | DONE 2026-09-11 |
| M2 | Leaf circuit fork with note fragments, tests, gate profile, prove/verify bench | DONE 2026-09-11 (319 gates at M2, 320 after the M3 padding sentinel; degree_bits 9, 26 public inputs; see `docs/CIRCUIT.md`) |
| M3 | Private and public batch aggregators on the new PI layout | DONE 2026-09-11 (private batch 5 + 21N public inputs, ZK, N = 7; public batch forwards each inner verbatim under an aggregator address and refuses a repeated inner in circuit; see `docs/CIRCUIT.md` section 8) |
| M4 | `pallet-shielded` + runtime wiring, local dev chain end to end | DONE 2026-09-12 (chain forked as a git subtree at `chain/`; `pallet-shielded` settles private and public batches, `shield` is the only v0 entry, `pallet-zk-tree` stores raw `Hash256` leaves; N = 6, n = 53; see `docs/CIRCUIT.md` section 9 and `docs/OPS-DEV.md`) |
| M5 | Wallet CLI: keygen, sync/scan, build leaf + batch, submit | DONE 2026-09-12 (`crates/qnero-wallet`, binary `qnero-wallet`: keygen, address, shield, sync, balance, send, status; hand-encoded extrinsics over JSON-RPC, storage layout and fee floor read from runtime metadata, Merkle paths rebuilt locally and the settled nullifier set paged whole so no request names a note as its own, notes in one JSON store beside the seed; memos padded to one size, at a pad chosen so the padded pair stays a fee bucket below a pair padded to `MaxCiphertextBytes`, and the payment's output slot drawn per spend, so the chain publishes neither a memo length nor which of a settlement's two leaves is the sender's change; one checkpoint-hash walk decides both whether a node is on the wallet's chain and whether it has reached everything the wallet has read, rewinding the leaf watermark to the newest checkpoint still canonical on a fork and refusing a node that is behind, with a leaf-count gate under it so the watermark never regresses outside the fork path, and spent status is derived from the settled set in both directions; see `docs/WALLET.md`, and `docs/BENCH.md` for the public batch at `n = 53`, which M4 left unmeasured); `sync --rescan` is the operator override on the node gates, runs add-only, and its known edges are docs/WALLET.md open issue 14) |
| M6 | v1 mandatory privacy: coinbase into notes, transparent transfers disabled | DONE 2026-09-12 (every unit of value created after genesis is a note, the genesis allocation staying transparent and reaching its holders through `Vesting::claim`: `pallet-shielded` mints one coinbase note per block from a required inherent, the author's share of settled fees rides in it, mining rewards to transparent accounts are off, and `BaseCallFilter` refuses every call that moves transparent value between accounts a user chooses, leaving `Vesting::claim`, a genesis-fixed payout from a keyless pot, as the one transparent payout; `pallet-wormhole` is out of the runtime with its transaction extension, the runtime identifies as `qnero` at `spec_version` 101 and `transaction_version` 7, and the wallet finds its coinbase notes from a miner key the node is configured with; see section 7, `docs/CIRCUIT.md` section 10, `docs/WALLET.md` and `docs/OPS-DEV.md`. The review pass that closed it changed five things: the header's author item became per block so no coinbase leaf carries a mining identity, `set_high_security` joined the refused list so no account can enrol into a feature whose every call v1 refuses, and the high-security whitelist stayed as it is because every call on it is delayed and a guardian can reverse it, `Vesting::claim` stays dispatchable so the genesis allocation is deliverable and no preset endows a keyless account, the coinbase inherent refuses the encrypted payload nothing builds, and a block with no emission still mints the author fee the pool already holds. A second review pass reversed one of those: `shield` and `burn` came back off the high-security whitelist, because every other call on it is delayed and a guardian can reverse it, and the freeze they were paying for is unreachable while the enrolment itself is refused. It also moved `spec_version` to 101, which is the number above, for the metadata the first pass changed without it. A third pass bound the coinbase note's `r` to the chain's genesis, so one miner key on two chains no longer mints byte-identical notes at equal heights, and corrected the claim this row itself carried: the 27% genesis allocation is transparent and reaches its holders through `Vesting::claim`) |

About 10 to 12 weeks to a private testnet. The measured risk to retire first
is wallet-side proving time and memory for a 2-in/2-out leaf plus a
6-slot private batch (see `docs/BENCH.md`).

## 9. Open questions

1. ML-KEM-1024 chosen for addresses (level-5 parity with ML-DSA-87, same as Hegemon). Encoded address is 2571 characters.
2. Proof size and verify weight for the private batch under the new PI
   layout; Wormhole's numbers are the baseline.
3. Whether to keep QPoW or bring RandomX; unrelated to privacy, defer.
4. Fee visibility: fees are public, as in Monero. **M4 decided: per-slot public
   fees, no tiering. M6 kept it, and the coinbase is why.** A block's coinbase
   note is worth the emission plus every fee the block settled, and that total
   is one public number attached to one leaf. A tier would quantize the
   per-slot fee and change nothing about it: the sum is published either way,
   the payload term of the floor is already payload dependent, and what a
   settlement's fee reveals is bounded by the floor rather than by its
   granularity. Re-deferred to a milestone that has a reason to move it.
   Original text: Each real leaf slot's fee is a 62-bit public field
   element the chain sums in `u128` (`docs/CIRCUIT.md` 9.7), and the floor
   `MinLeafFee + ceil(ciphertext_bytes / CiphertextBytesPerFeeQuantum)` is
   itself payload dependent, so a tier would have to quantize the payload term
   too. A submission carries a second floor of the same shape, over every real
   leaf slot and every ciphertext byte in the extrinsic, which is what prices
   the segments a settlement skips. Whether to quantize fees into tiers to
   reduce fingerprinting is re-deferred to M6, where the coinbase changes what
   a fee has to cover anyway.
5. Memo field size and whether it is mandatory (Zcash pads to 512 bytes).

## 10. Positioning: Qnero vs Hegemon

Hegemon (Pauli-Group/Hegemon, MIT, alpha) is the closest existing project:
shielded-only pool, PoW, ML-DSA / SLH-DSA / ML-KEM-1024, hash commitments,
STARK proofs, MASP multi-asset notes, viewing keys, proofs of disclosure.
Surveyed 2026-09-11 at b819911.

| | Hegemon | Qnero |
|---|---|---|
| Started | Nov 2025, v0.10.0 Mar 2026, still alpha | Sep 2026 |
| Team | one main author (1936 of 1979 commits), 16 stars | DigitalGuards, QRL ecosystem |
| Proof system | in-house "SmallWood" STARK backend plus an in-house lattice folding layer, both `candidate_under_review`; Plonky3 dropped | Plonky2 (Polygon lineage, years in production), unchanged |
| External review | one review pass by an LLM (Codex), verdict "claim unsupported" for the 128-bit claim; no audit firm | Eiger audit of the Wormhole circuits and Poseidon, Substrate audit of the chain, both by a firm |
| Chain stack | everything custom: consensus, p2p, sled state, sync | Substrate plus Quantus PQ p2p, already running a public network |
| Tx proof size | about 105 KB per tx, 524 KB block artifact | to measure (private batch proof; 7 tx per proof amortizes it) |
| Tx shape | 2 in, 2 out fixed | 2 in, 2 out in v0 |
| Codebase | 271k lines of Rust, docs and Lean proofs generated at machine scale, hard to review | small delta on top of audited upstream |
| Narrative | "post-quantum shielded money", governance and versioning heavy | post-quantum Monero: private by default, proof of work, CPU mining |

Where Hegemon is ahead: it runs, it has a wallet, a desktop app, a testnet
with seed nodes, multi-asset notes, diversified addresses, disclosure proofs.
None of that is in Qnero yet, and 12 weeks will not close all of it.

Where Qnero beats it, if we execute:
1. Trust. Every cryptographic component in Qnero is either standardized
   (ML-DSA, ML-KEM, SHA3) or externally audited by a firm (Plonky2 circuits,
   Poseidon, Substrate runtime). Hegemon's soundness rests on a novel proof
   backend that its own review package calls unsupported. For private money
   this is the whole argument.
2. Narrative. Monero has the largest privacy community in crypto and no
   post-quantum path. Qnero speaks Monero: spend key and view key, private by
   default, no call moving value between accounts a user chooses, every output
   a sealed note, proof of work, the anonymity set is the whole chain. Hegemon speaks protocol governance.
3. Ecosystem. Explorer, web wallet, mobile wallet, desktop wallet, connect
   SDK and dApp tooling already exist in the QRL stack and can be pointed at
   Qnero. Hegemon has one Electron app.
4. Reviewability. A reviewer can read Qnero's delta over Quantus in a day.
5. Mining story. Consider RandomX in place of QPoW so Monero miners can move
   over with the software they already run. **M6 made the swap a one-file
   change and recorded the evaluation for M7.** Everything in the runtime that
   needs to know who authored a block now reads it through one
   `FindAuthor` implementation, `configs::QpowAuthor`, and nothing else in the
   runtime touches the proof of work: the coinbase belongs to the block's
   author, the author is whatever that impl says, and the note's recipient is
   the miner key its own node holds. Swapping the engine is that impl plus the
   consensus client. `docs/OPS-DEV.md` carries the seam. **M4 kept QPoW**: the shielded
   pool's author fee reads the QPoW pre-runtime digest and credits the
   QPoW-derived account through a wormhole leaf (`docs/CIRCUIT.md` 9.7), which
   is the same seam `pallet-mining-rewards` uses, and nothing in M4 depends on
   which proof of work sits behind that digest. The RandomX evaluation is
   re-deferred to M6, which is the milestone that touches the coinbase.

Concrete "beat it" targets for the first testnet:
- proof per tx smaller than 105 KB, or clearly amortized below it per batch
- wallet proving under 5 s on a laptop, under 60 s on a phone
- audit-grade claim: no cryptographic component without a firm's review
- a running public testnet with the explorer and web wallet attached

## 11. Narrative

One line: Monero's principles, rebuilt without elliptic curves.

Pillars, in this order:
1. Private by default. No call moves value between accounts a user chooses;
   every output is a sealed note and every spend is a proof. The public edges
   are the entry, the mint, the genesis payout and the exit to nowhere:
   `shield` names its payer and amount, a coinbase publishes its value and its
   block with the recipient hidden, `Vesting::claim` pays a beneficiary fixed
   at genesis an amount fixed at genesis out of a pot that cannot sign, and
   `Balances::burn` names the account taking its own value out of circulation.
   `docs/CIRCUIT.md` section 10.7 is the full list.
2. Proof of work. No stake, no validators, no foundation keys in consensus.
3. Post-quantum from genesis. Hash-based proofs, lattice signatures and
   encapsulation, nothing for Shor to break.
4. Audited parts only. Standardized primitives and firm-audited circuits.
   No novel cryptography.
