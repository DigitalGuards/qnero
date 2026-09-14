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
| RandomX PoW | RandomX, `rx/0`, stock constants, since M7 (section 10) | `client/consensus/randomx`, `pallets/qpow` for difficulty |
| Transparent spend authorization | ML-DSA-87 only; the runtime refuses the ML-DSA-65 variant at the entry (section 7.3) | `qp-dilithium-crypto` + `runtime/src/extrinsic.rs` |
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
| ML-DSA-87 accounts, hdwallet | primitives as is, one rule added | Transparent layer. At v0 it carried miner rewards and fees; at v1 it carries fees, the shield entry and the genesis vesting payout, and no transfer between accounts a user chooses (section 7.2). The primitives are untouched, including the two-variant signature enum; what Qnero adds is the entry rule that refuses the ML-DSA-65 variant (section 7.3) |
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
a domain-separated hash of the chain's genesis, and the block number. Section 7.1 is why they are derived, and
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
block author's node            inherent              pallet-shielded
-------------------            --------              ---------------
chain = H_bytes("qnero/coinbase-chain", genesis_hash)
rho   = H(RHO_COINBASE, n)                           the mint, run from
r     = H(R_COINBASE, cvk, chain, n)                 MiningRewards' on_finalize
inner = H(NOTE, pk, rho, r)    coinbase(inner, ct)   of block n:
                                                       total = emission + tx fees
                                                             + author fee share
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
5. **The note is derived rather than encrypted.**
   `r = H(R_COINBASE, cvk, H_bytes("qnero/coinbase-chain", genesis_hash), block_number)`,
   where `cvk` is a coinbase viewing key the operator configures its node with,
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

### 7.3 One signature scheme at the entry (consensus rule)

Qnero has one signature scheme at the transparent entry, ML-DSA-87 (FIPS 204,
level 5). The rule, in full, as `chain/runtime/src/extrinsic.rs` states it:

> A signed extrinsic is valid only when its signature is the `Dilithium87`
> variant. Every other variant is refused with
> `InvalidTransaction::BadSigner`, before its signature is verified, before
> any transaction extension runs, and before its call is dispatched.

It is an allowlist, and the wording is the rule itself. A denylist over
`DilithiumSignatureScheme` is exhaustive only while that enum has the two
variants it has today, and this fork commits to leaving the enum exactly as
upstream wrote it, so a subtree merge adding a third variant would land in a
catch-all and be admitted with every guard green. Under the
allowlist it is refused at the entry by the arm that is already there. Today
the enum carries two variants and the rule refuses exactly one of them.

The rule is `chain/runtime/src/extrinsic.rs`, its runtime guard is
`chain/runtime/tests/transactions/signature_scheme.rs`, and
`crates/qnero-wallet/tests/one_signature_scheme.rs` holds this section to the
same sentence.

Three things about where it sits are load bearing.

**The enum keeps both variants.** `qp-dilithium-crypto` is upstream's, and its
`DilithiumSignatureScheme` carries two arms. Deleting one would conflict on
every subtree merge into `chain/`, and it would move the runtime's metadata,
which is where a client reads the encoded length of a signature per variant
index. The type stays; the chain admits one of its arms.

**It cannot be a transaction extension.** By the time an extension runs, the
extrinsic's `check` has already verified and dropped the signature and handed
the extension an `AccountId32`, and both variants hash to an `AccountId32` of
the same shape, so there is nothing left for an extension to look at: a
Dilithium65 account is byte-indistinguishable from a Dilithium87 one in state,
in an address and in `origin`. The refusal therefore lives in `Checkable`, one
layer below every extension, which also means it costs no change to the signed
extrinsic encoding: `transaction_version` stays where it is.

**It covers every signed call, including `shield`.** The seam is the extrinsic,
so nothing is enumerated per call. Section 7.2's call filter is a different
question answered at a different place: the filter decides what may run, and
this rule decides who may sign. A transparent transfer signed with ML-DSA-87 is
still admitted and still refused at dispatch with `CallFiltered`; the same
transfer signed with ML-DSA-65 never reaches a block at all.

The other half of one scheme is that nothing on Qnero's own paths constructs an
account under the other one. The presets derive every key-backed account from
an ML-DSA-87 pair (`every_key_derived_preset_account_is_ml_dsa_87` is the
test), the miner key is a `qnero_note_core::MinerKey` and carries no signature
key at all, the block-author label is a Poseidon digest, and `qnero-node key
qnero --scheme standard` builds an ML-DSA-87 pair. One gap is worth naming: the
Planck and mainnet accounts are SS58 literals, and both variants hash into the
same 32-byte account, so a literal carries no variant for a test to assert on.

**Pre-mainnet check for the SS58 literals.** The gap above has a permanent
consequence, so what covers it is a procedure. A level-3 account among those
literals could never sign: its vesting claim, its treasury approval and its
faucet drip would each answer `BadSigner` at the entry, and whatever genesis
vested to it would be stranded for good. Before mainnet genesis, confirm that
every beneficiary key in `genesis_config_presets/mainnet_vesting.rs` (the ten
treasurers, the ten tech collective members, and the account of every `VESTING`
row) and every literal in `genesis_config_presets/mod.rs` was minted with
`qnero-node key qnero`, which builds an ML-DSA-87 pair and has no other mode.
`account_from_ss58` carries the same instruction beside the code.

Two consequences worth writing down. The vendored `sc-cli` fork still offers
`--scheme dilithium65` on its key commands, and that tree stays as upstream
wrote it so the next subtree merge is clean; Qnero's own dispatch refuses the
flag before `sc-cli` sees it (`node/src/command.rs`), so the CLI and the entry
now say the same thing. And the rule breaks consensus. Before it, an ML-DSA-65
extrinsic passed every check and entered the block, refused only later at
dispatch by the call filter, so a block already carrying one fails to
re-execute under the rule. Qnero is devnet-only, so a devnet carrying
such a block has to be reset.

## 8. Milestones

| # | Deliverable | Estimate |
|---|---|---|
| M1 | `qnero-notes` crate: keys, addresses, note commitment, ML-KEM note encryption, scan; KATs pinned | DONE 2026-09-11 |
| M2 | Leaf circuit fork with note fragments, tests, gate profile, prove/verify bench | DONE 2026-09-11 (319 gates at M2, 320 after the M3 padding sentinel; degree_bits 9, 26 public inputs; see `docs/CIRCUIT.md`) |
| M3 | Private and public batch aggregators on the new PI layout | DONE 2026-09-11 (private batch 5 + 21N public inputs, ZK, N = 7; public batch forwards each inner verbatim under an aggregator address and refuses a repeated inner in circuit; see `docs/CIRCUIT.md` section 8) |
| M4 | `pallet-shielded` + runtime wiring, local dev chain end to end | DONE 2026-09-12 (chain forked as a git subtree at `chain/`; `pallet-shielded` settles private and public batches, `shield` is the only v0 entry, `pallet-zk-tree` stores raw `Hash256` leaves; N = 6, n = 53; see `docs/CIRCUIT.md` section 9 and `docs/OPS-DEV.md`) |
| M5 | Wallet CLI: keygen, sync/scan, build leaf + batch, submit | DONE 2026-09-12 (`crates/qnero-wallet`, binary `qnero-wallet`: keygen, address, shield, sync, balance, send, status; hand-encoded extrinsics over JSON-RPC, storage layout and fee floor read from runtime metadata, Merkle paths rebuilt locally and the settled nullifier set paged whole so no request names a note as its own, notes in one JSON store beside the seed; memos padded to one size, at a pad chosen so the padded pair stays a fee bucket below a pair padded to `MaxCiphertextBytes`, and the payment's output slot drawn per spend, so the chain publishes neither a memo length nor which of a settlement's two leaves is the sender's change; one checkpoint-hash walk decides both whether a node is on the wallet's chain and whether it has reached everything the wallet has read, rewinding the leaf watermark to the newest checkpoint still canonical on a fork and refusing a node that is behind, with a leaf-count gate under it so the watermark never regresses outside the fork path, and spent status is derived from the settled set in both directions; see `docs/WALLET.md`, and `docs/BENCH.md` for the public batch at `n = 53`, which M4 left unmeasured); `sync --rescan` is the operator override on the node gates, runs add-only, and its known edges are docs/WALLET.md open issue 14) |
| M6 | v1 mandatory privacy: coinbase into notes, transparent transfers disabled | DONE 2026-09-12 (every unit of value created after genesis is a note, the genesis allocation staying transparent and reaching its holders through `Vesting::claim`: `pallet-shielded` mints one coinbase note per block from a required inherent, the author's share of settled fees rides in it, mining rewards to transparent accounts are off, and `BaseCallFilter` refuses every call that moves transparent value between accounts a user chooses, leaving `Vesting::claim`, a genesis-fixed payout from a keyless pot, as the one transparent payout; `pallet-wormhole` is out of the runtime with its transaction extension, the runtime identifies as `qnero` at `spec_version` 101 and `transaction_version` 7, and the wallet finds its coinbase notes from a miner key the node is configured with; see section 7, `docs/CIRCUIT.md` section 10, `docs/WALLET.md` and `docs/OPS-DEV.md`. The review pass that closed it changed five things: the header's author item became per block so no coinbase leaf carries a mining identity, `set_high_security` joined the refused list so no account can enrol into a feature whose every call v1 refuses, and the high-security whitelist stayed as it is because every call on it is delayed and a guardian can reverse it, `Vesting::claim` stays dispatchable so the genesis allocation is deliverable and no preset endows a keyless account, the coinbase inherent refuses the encrypted payload nothing builds, and a block with no emission still mints the author fee the pool already holds. A second review pass reversed one of those: `shield` and `burn` came back off the high-security whitelist, because every other call on it is delayed and a guardian can reverse it, and the freeze they were paying for is unreachable while the enrolment itself is refused. It also moved `spec_version` to 101, which is the number above, for the metadata the first pass changed without it. A third pass bound the coinbase note's `r` to the chain's genesis, so one miner key on two chains no longer mints byte-identical notes at equal heights, and corrected the claim this row itself carried: the 27% genesis allocation is transparent and reaches its holders through `Vesting::claim`) |
| M7 | RandomX proof of work, so a Monero rig mines Qnero | DONE 2026-09-13 (the engine is RandomX `rx/0`, stock upstream constants, so the hash is bit-identical to what a stock xmrig computes and a Monero rig moves over with a config change; `chain/client/consensus/randomx` is the whole engine, the runtime no longer verifies a nonce because RandomX cannot run in wasm, `pallet-qpow` keeps the difficulty storage and the Homestead retarget because both are functions of block times rather than of the hash, and the node grew a stratum endpoint behind `--stratum-port` speaking the dialect xmrig speaks to a Monero pool. The M6 author seam did what it was built for: `H(cvk, parent_hash)`, `configs::QpowAuthor`, the coinbase inherent, the header shape and fork choice are untouched, and `POW_ENGINE_ID` is still `pow_`. The proof is a 4-byte nonce and a 4-byte extra nonce over a fixed 76-byte blob with the nonce at offset 39 where xmrig writes it, packed into the 64-byte seal the digest window needs with the remaining 56 bytes pinned to zero, because free seal bytes would be free block-hash grinding. The comparison is Monero's: the hash read little-endian, accepted when `hash * difficulty <= 2^256 - 1`. Seed rotation is Monero's rule with the epoch and lag as runtime constants. `spec_version` moved to 102 for the three runtime-API methods and the event that went away; `transaction_version` stayed at 7. See section 10, `docs/OPS-DEV.md` and `docs/BENCH.md`) |
| M8 | Prover budget on a phone-class device: a browser prover, measured | DONE 2026-09-14 (`crates/qnero-prover-wasm` is the browser surface, compiled to `wasm32-unknown-unknown`, single threaded, rayon-free: derive an address, decrypt a ciphertext while scanning, and prove one private batch at `N = 6`, with a headless-Chromium harness under `www/` and its Node runner. Nine samples per per-payment figure: **33.6 s per payment and 910.4 MiB peak** in single-threaded wasm, on top of 12.1 s of circuit build once per worker, against 9.82 s and the same shape natively. A desktop core under headless Chromium is the phone proxy and the stated factor is 2 to 4 with room above it, so a phone is 67 to 134 s per payment or worse: **memory fits and the single-threaded clock misses the 60 s target at every point of the range**. Seven slots were measured too: 65.8 s and 1.72 GiB, which fits this browser and does not fit a phone. The ZK leaf a delegated batcher would take is 16.6 s of proving on top of a 6.8 s circuit build, 511 MiB on its own, and 150932 bytes, 24 bytes larger than the whole six-slot batch it would be handed to. See the section below and `docs/BENCH.md`) |
| M9 | silQ Road, the Qnero explorer: what a chain reader can see, and what it cannot | DONE 2026-09-14 (`explorer/` is **silQ Road**, a static Vite and React site over `@polkadot/api`, configured by one runtime JSON so one build serves a devnet and a testnet, with no server-side indexer: home, a paged block list, a block page, a settlement page by extrinsic hash, search over heights, block hashes, extrinsic hashes, nullifiers and commitments, and a "What this chain reveals" page taken from `docs/CIRCUIT.md` section 10.7 and `docs/WALLET.md`. Two decoder seams a generic Substrate client gets silently wrong are handled and tested: the header's `zkTreeRoot` between `extrinsicsRoot` and `digest`, which polkadot-js otherwise decodes the digest out of, and the block body, which the typed `chain_getBlock` refuses because the ML-DSA-87 signature is a fixed 7219-byte array above polkadot-js's 2048-byte array limit, so the envelope is walked by hand with the signature lengths and the extension list read out of metadata. Everything else is metadata-driven and the assumed storage hashers are asserted against it at startup, because an absent key and an empty map are indistinguishable and the difference renders as "0 leaves, 0 nullifiers" with no error. The presentation rules are part of the deliverable: a slot's two outputs are an unordered pair, there is no miner table because the author label is `H(cvk, parent_hash)` and rotates every block, a refused call is named without reprinting the arguments the block body already carries, ciphertext size and anchor gap are shown where they inform and are sortable nowhere, and `zkTree_getMerkleProof` is never called, which a lint rule enforces in both the shapes the node serves it in, the method and the `ZkTreeApi_get_merkle_proof` runtime call behind `state_call` and `archive_v1_call`. Degradation is part of it too: the consensus constants are read after the connection is published so a refused `state_call` costs those fields alone, a block whose state the node no longer keeps still renders its header and body, a bounded walk that reaches the bottom of a pruned state window ends as a miss that names the boundary, and every read on the search page whose request carries the query's own 32 bytes, the nullifier lookup and the block-hash header check alike, is printed as a warning first and runs only when a reader presses its button. 99 vitest cases over the decoders, the route grammar and the three answers a page may give about a block whose state the node did not keep run against fixtures captured from a dev node, and a Playwright smoke starts its own `--dev --tmp` node at one mining thread, shields once, sends once, serves the build and asserts the five pages, counting the frames that carry a query's own 32 bytes and relaying the page's socket to answer one block's state reads the way a pruned node does, then stops the node by pidfile and waits for the port to close. See `explorer/README.md`) |
| M10 | Qloak, a Qnero wallet: keys in the page, proofs in a worker, no server | DONE 2026-09-14 (`wallet-web/` is **Qloak**, a static Vite, React 19 and TypeScript app with no server component and no account: it creates a 32-byte spend key in the page, seals it and every note's `rho`, `r`, nullifier and memo in IndexedDB under AES-256-GCM with a PBKDF2-SHA-256 key at 600,000 iterations and a fresh IV per record per write bound to its own slot, scans the chain in a worker, proves a payment in that worker and submits it, and contacts nothing but the node it is configured with. The M5 rules are ported rather than relaxed: the settled nullifier set is paged whole and spent status decided locally, leaves are read as one contiguous range and Merkle paths rebuilt locally, `zkTree_getMerkleProof` is unreachable and a lint fence keeps it that way in every spelling, the genesis binding, checkpoint-hash fork walk and leaf-count gate refuse before anything is written, the spend repeats the storage-drift, genesis and leaf gates for itself because the write-off that marks a selected note off chain rests on them, a rescan is add-only, and every number a node answers with is decoded at its declared width and bounded where it decides how long the wallet works: `Shielded::EntryCount` is one Poseidon2 hash per unit inside the worker that holds the seed, so the origin walk stops at 100,000 entries and both wallets report a pass that hit the bound, and `ZkTree::LeafCount` is read at eight bytes and refused above `4 ** max_tree_depth`, which is what a 4-ary tree the circuit can prove over holds, and the command-line wallet now reads every storage integer the same way, `LeafCount`, `Depth`, `EntryCount`, `LeafBlocks` and `CoinbaseValues` each refused by name at any other width and the count bounded by the same capacity. A per-leaf key the node answers nothing for below the count it reports at the same block refuses the pass in both wallets: `ZkTree::Leaves` and `Shielded::LeafBlocks` are required at every index, because `pallet-shielded` writes both in the call that appends the leaf and removes neither. The chain has no gaps under its own count, so such an answer is withheld rather than absent, and stepping over one hid a payment behind a watermark written above it with no error, no warning and no field in the report: no commitment and the leaf is skipped, no block and the leaf is dated by nothing. A commitment answered as the tree's own all-zero pad below that count refuses the pass as well, in both wallets and in the prover module's fold: `pallet-zk-tree::insert_commitment` refuses an append of that digest by name and reads it as an unfilled slot at every level, and `TreeFrontier` pads with the same digest, so pushing pads reaches the root a fold that stopped short reaches and a run of them at the top of the tree would carry a leaf count higher than the chain's past every root the headers published. Without that rule the fold pins a block's leaf set while the count above it stays the node's to choose, and the pass writes a watermark and a checkpoint above indices no block has filled, where the real leaves that land later are never read. **Whether a leaf owes a ciphertext or a coinbase value is not a flat rule, and a leaf's kind is derived only from data the header authenticates, never from which storage keys a node chose to answer.** Presence of `Shielded::CoinbaseValues` used to decide it, and presence is the node's to write: eight invented bytes on an incoming transfer leaf routed it onto the coinbase rebuild, which cannot open it, and an invented `Shielded::Ciphertexts` beside a withheld coinbase value hid a mined reward the other way round. What decides now is position, and position is what the headers commit to: the header chain, walked down from the head by `parentHash` to a hash the wallet already trusts and rehashed from each header's own preimage, in chunks of `HEADER_WALK_LIMIT` (1024) blocks so a chain far ahead of the checkpoint syncs in one command with one chunk of headers resident; each block's leaf range, checked by folding the leaves a node attributes to that block and comparing against the `zkTreeRoot` its header carries, which makes `Shielded::LeafBlocks` advisory; and the coinbase position, which is a block's last leaf because `pallet-mining-rewards` mints through `CoinbaseSink` in its own `on_finalize` while every shield and settled output was appended during extrinsic execution. **No rule rests on the author label.** These wallets verify no proof of work and will not in v1, because a RandomX verification needs a 256 MiB cache and has no browser build, so above the newest checkpoint a node picks every header field including `H("qnero/author-label", cvk, parent_hash)`, and a rule gated on the label is one the node switches off by publishing another. So a coinbase value below a block's last leaf is refused, a withheld one at **any** coinbase position is refused whatever the label says, a ciphertext is required at every other position, this wallet's own coinbase note is rebuilt at every coinbase position and the rebuild alone decides ownership, and the label is read afterwards as a cross-check: a label claiming this wallet's block over a rebuild that does not match refuses the pass, and a rebuild that matches under another author's label takes the reward and reports the disagreement. A checkpoint is recorded only for a head the pass authenticated, so a pass that scans no leaf walks the headers anyway. What no per-leaf rule reaches is a node that rebuilds the headers themselves, and the bound that does hold is the checkpoint fork walk: the forged head is recorded only as a checkpoint, and the first honest node disagrees with it, rewinds to the newest checkpoint both stand on and rescans, which both wallets drive end to end; a wallet that only ever talks to one node has no defence against that node beyond consistency, and `docs/WALLET.md` says so under "What a lying node can and cannot do". The fold is incremental, one Poseidon path update per leaf and one comparison per block, and the added cost is one `chain_getHeader` per block of the scanned range: see `docs/WALLET.md` under "How a leaf's kind is decided" and `docs/BENCH.md`. A scan and a payment never run at the same time: the job slot is claimed synchronously before either handler awaits anything, the Settings screen disables its rescan while a payment runs and says why, and `commitSync` reads each row inside its write transaction and keeps a `spent` or `onChain` that moved since the pass read it, so a settlement that lands mid-scan cannot be un-latched by the scan's own copy. That the node is told nothing is tested as a property of the request stream rather than asserted in prose: `tests/privacy.test.ts` drives the real read layer through a recording transport and asserts that no request carries a nullifier, that leaves are asked for as one range, that every read of a pass is pinned to one block hash and that nothing outside four public-read methods is called. Two things a generic client gets silently wrong are handled and both were found against a live node rather than in a unit test: metadata v16 publishes `extrinsic.versions` as `Bytes` rather than a `Vec` of codecs, and polkadot-js cannot construct the settlement extrinsic at all because this runtime's signature type carries a fixed `[u8; 7219]` above its 2048-byte array limit, so the bare extrinsic is hand-encoded with the pallet and call indices read off `.callIndex`. Shielding stays a command-line step, stated on the page: entry into the pool is signed with ML-DSA-87 and the wasm module exports no signing. The threaded module from M8's follow-up is loaded when the origin is cross-origin isolated, capped at four threads, with the single-threaded module as a silent fallback the settings screen names. Measured in the suite's own browser on the development workstation: 11.2 s to prove a payment on four threads against 37.6 s on one, 917.6 MiB peak threaded and 910.2 MiB on one thread, and 24.6 s from pressing Send to a settled block against 53.4 s. 280 vitest cases plus a Playwright suite that starts a `--dev --tmp` node at one mining thread on a port it chooses, has the command-line wallet fund the address the browser wallet creates, proves the payment in the browser, has the command-line wallet read it back and stops and restarts the prover, recording every JSON-RPC frame the page sends and refusing any method outside an allowlist. The passphrase floor is enforced at the key derivation rather than on the screen that asks for one, the built page declares a content policy and `wallet-web/README.md` carries the header a host should send, the socket reconnects and drives the status strip rather than being decided once at connect, and the circuits are built once per worker: they were rebuilt on every send, which added a permanent quarter gigabyte of linear memory per payment (see `docs/BENCH.md`). The look and the screen flow follow MyMonero's web wallet under BSD-3-Clause, credited in `wallet-web/NOTICE`. **Two per-leaf values are bound to a leaf by nothing on chain, and both are open in both wallets:** the bytes at `Shielded::Ciphertexts(i)`, and where a commitment sits inside its block's own leaf range. The commitment the tree authenticates carries no ciphertext and `ct_digest` binds the bytes only inside the settlement extrinsic at inclusion, which a storage-only reader never fetches, so a node with honest headers can answer a stranger's ciphertext at an incoming payment and the AEAD does not open. And `tree::hash_node` sorts a node's four children before hashing them, which is what lets a Merkle path carry siblings with no position beside them, and it mixes in neither the level nor the child slot, so a block's `zkTreeRoot` pins that block's leaf multiset and each internal node's child multiset and nothing else. Two consequences and the bound is both: sibling swaps compose at every level, so a payment moves to any position the block's range allows, across group boundaries and onto the coinbase position where no ciphertext is owed and this wallet's coinbase rebuild cannot open it; and the fold of `m` level-1 node values equals the fold of the `4m` leaves under them, so a node can answer a leaf count of 2 for a block that appended 8, serve the two node hashes as that block's leaves, pass every root check under the honest chain's own headers, and leave the watermark above every leaf the block really appended. **One part of it both wallets now catch on their own.** A move that leaves this wallet's ciphertext where the chain published it puts a payload that opens under this wallet's key, which ML-KEM decapsulation and an AEAD over this wallet's own `pk` authenticate, beside a commitment that note does not open; `try_transfer` and `decryptBatch` stop folding that into "somebody else's", the pass searches the block's own folded leaf range for the commitment the note does open, records the note there and warns with both indices, so the payment arrives with no second node needed. A commitment the block holds nowhere is warned and skipped rather than refused, because a sender who encrypts a payload opening a commitment it never published produces the same reading, `ct_digest` is unconstrained in circuit, and a refusal would be a permanent sync denial anyone could buy with one transaction. What stays hidden is a move that takes this wallet's ciphertext with it or leaves none: the leaf reads as somebody else's, the watermark is written above it, the checkpoint fork walk recovers nothing because the headers agree, and a rescan against a second node is the recovery. Both wallets carry one sentence naming both unbound values on a pass that read leaves and received nothing, on a `hint` line in the command-line wallet and on `report.hints` under the balance screen's warnings in the browser, held byte for byte identical by a test that reads the Rust literal out of the wallet's own source, and both drive every variant end to end in a test: the substituted ciphertext, the move with the ciphertext left in place, the move with it gone, the swap across two aligned groups six positions apart, the two level-1 node values served as two leaves, and the ciphertext of ours whose commitment the block holds nowhere. Closing the rest is the **next wallet milestone (M13)**, and section 9 open question 6 carries the design: read every per-leaf and per-chain storage value with a trie proof from `state_getReadProof` at the pinned block hash and verify it against that header's `stateRoot`, which the header walk already authenticates with the same hash chain as `zkTreeRoot`. That makes the count, every leaf value and every ciphertext a fact of the block, and closes the ciphertext, the index and the depth together **with no consensus change and the upstream tree untouched**; the cost is blake2-256 trie V1 verification, in `sp-trie` natively and in the same wasm module in the browser, with proofs batched per page so a window's keys share every trie node above their divergence. Section 9 open question 7 records the consensus-level alternative, domain-separating a child's slot and its level in place of sorting, which pins the position and the height in the root and costs a fork, and it is unnecessary for the wallets once question 6 lands. Two smaller answers were closed here: the browser's padding-sentinel rule compares the node's hex normalised, so the pad spelled without a `0x` prefix is refused where it used to pass, and `Chain::leaf_hashes`, the read a spend rebuilds its paths from, now takes the leaf count and refuses an absent or all-zero answer below it, which is what the browser already refused. See `wallet-web/README.md`) |

About 10 to 12 weeks to a private testnet. M8 retired the measured risk this
line used to name, wallet-side proving time and memory for a 2-in/2-out leaf
plus a 6-slot private batch, and it came back with one number good and one
number short: the memory fits a phone and the single-threaded clock does not.

### M8: what a phone can actually prove

The measurement is in `docs/BENCH.md`. The decisions it forces are here.

**Can a phone prove a full private batch locally, under the 60 s target?**
Not on one thread. A payment is 33.6 s of single-threaded wasm on a desktop
core under headless Chromium, plus 12.1 s of circuit build once per worker.
Read through the stated 2 to 4 phone factor that is 67 to 134 s per payment
and 91 to 183 s for the first payment after a cold start. The most optimistic
end of the range still misses 60 s, and the factor is a floor: its low end is a
peak single-core score ratio that excludes both the throttling a 30-second
flat-out run causes and whatever a mobile browser's wasm engine costs.

**What memory does it need?** 910.4 MiB peak, byte-identical across all nine
runs, against the 2 GiB ceiling the run pinned and the 4 GiB a 32-bit linear
memory can address. That is 44 percent of the ceiling and 22 percent of the
address space. The sticky part is the wasm part: linear memory grows and never
shrinks, so the peak stands for the life of the worker and a second prover
would add its own gigabyte. A 6 GB or 8 GB Android device has this comfortably.
A 3 GB or 4 GB device is marginal once the renderer's own footprint counts. iOS
Safari polices per-tab memory hard enough that its failure mode is a reclaimed
tab with no catchable error. Settling that one takes a device test.

**What `N = 6` bought, now measured on both sides.** `docs/CIRCUIT.md` section
9.1 argued six slots against seven as "the difference between a phone that can
prove and one that cannot" on an estimate. Seven slots measure at 65.8 s of
wasm proving and 1.72 GiB of peak linear memory, against 32.8 s and 910.4 MiB
at six: 2.01x the clock and 1.94x the memory for one more settlement per proof.
Seven fits this browser, at 86 percent of the same 2 GiB ceiling, so an earlier
claim here that it would land over that ceiling was wrong. What seven does not
fit is a phone: 132 to 263 s per payment at the stated factor, and 1.72 GiB
that never shrinks inside a renderer with its own footprint. The section 9.1
argument holds as a statement about phones, and the margin is 1.9x of memory
and half the clock.

**So the deciding change is threads.** The map written before this milestone
assumed threading was a comfort improvement that could not turn a no into a
yes. The measurement reverses that: memory has better than 2x of headroom under
the pinned ceiling and the clock is the only thing failing, so the 3.1x that M3
measured from four native threads is the size of the gap. Four threads at that
factor put a payment at about 10.8 s of wasm and 22 to 43 s on a phone, inside
the target, with enough slack that even a phone factor of 5 stays under 60 s.
Nothing is promised here: wasm threads need a nightly toolchain with
`-Z build-std` (the workspace is pinned to stable 1.93.0), `wasm-bindgen-rayon`,
a SharedArrayBuffer, and cross-origin isolation on whatever origin serves the
wallet. The harness already sets COOP and COEP, so that experiment needs no
different server. That is the next thing to measure, and it should be measured
before anything is designed around delegation.

**Is the ZK-leaf-plus-delegated-batch path worth building? No.** A phone proves
a blinded leaf, hands it to a batcher it does not run, and the batcher pays the
recursion. The measurement prices both halves of that trade and both come out
badly.

What it buys is 16.6 s against 33.6 s, a 2.0x saving, which lands a phone at 33
to 66 s per payment. That is the same order as what threads would buy for free,
and it is still over the target at the pessimistic end. A delegating wallet also
builds its own ZK leaf circuit per worker, 6.8 s of wasm, so its first payment
after a cold start is 23.4 s, which is 47 s at 2x and 94 s at 4x. It does not even save the memory
a delegating device would be delegating for: measured on its own, in a worker
that builds no private batch, a ZK-leaf prover still peaks at 511 MiB, which is
56 percent of what proving the whole batch costs.

What it costs is stated plainly. A leaf publishes 26 felts
(`crates/qnero-circuit/src/layout.rs`): the anchor block hash and number, both
input nullifiers, both output commitments, the fee, and the ciphertext digest.
Zero knowledge hides the witness and publishes all of that. So the batcher
learns the complete public record of the spend before the chain does, bound to
whoever asked: the nullifiers it is about to burn, the commitments it is about
to create, and the fee. It can sit on a leaf, drop it, order it against
another, or sell the foreknowledge, and the wallet has no way to tell a slow
batcher from a hostile one. The client's network identity rides along with it,
so a batcher also holds the IP-to-spend mapping that
`tests/node_learns_nothing.rs` exists to keep a node from building.

There is also a size argument, and it is the one that removes any doubt. A ZK
leaf is 150932 bytes. The whole six-slot private batch is 150908. Delegation
uploads 24 bytes more than proving the transaction outright, so it does not
even buy bandwidth.

The honest summary: the delegated-batch path trades a privacy property the
design spends real complexity to hold for a speedup that threads look able to
beat without it. Build threads first. If threads fail to deliver and a phone
still cannot prove, delegation comes back as a deliberate privacy tradeoff
offered to a user who is told what it costs, and it is a poor default either
way.

## 9. Open questions

1. ML-KEM-1024 chosen for addresses (level-5 parity with ML-DSA-87, same as Hegemon). Encoded address is 2571 characters.
2. Proof size and verify weight for the private batch under the new PI
   layout; Wormhole's numbers are the baseline.
3. ~~Whether to keep QPoW or bring RandomX~~ **Closed at M7: RandomX.** What
   is open is the sizing of its two seed constants, which are runtime
   constants and so a one-line change. The epoch is Monero's 2048 blocks,
   which at this chain's 12 s target rotates every 6.8 hours instead of
   Monero's 2.8 days, and every rotation costs a full-mode rig a 2 GiB dataset
   rebuild; 16384 restores the cadence. The lag is Monero's 64 blocks and
   `MaxReorgDepth` is 100, so the seed block is still inside the window a legal
   reorg can move. That cannot split the chain, because the seed is resolved
   along each candidate's own ancestry, but a deep reorg across a boundary does
   change the seed under work already started; a lag of 128 removes it. Decide
   both before a network launches, because after that they are a fork.
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
6. **A wallet still takes per-leaf storage values on a node's word, and the
   next wallet milestone (M13) is to stop: read them with `state_getReadProof`
   and verify against the header's own `stateRoot`.** Three things are open
   today and one read closes all three.

   What is open. `Shielded::Ciphertexts(i)` is tied to leaf `i` by nothing on
   chain. And `tree::hash_node` sorts a node's four children before hashing
   them and mixes in neither the level nor the child slot, so a block's
   `zkTreeRoot` pins that block's leaf multiset and each internal node's child
   multiset and nothing else: sibling swaps compose at every level, so a
   payment moves to any position the block's range allows, across group
   boundaries and onto the coinbase position where no ciphertext is owed; and
   the fold of `m` level-1 node values equals the fold of the `4m` leaves under
   them, so a node can answer a leaf count of 2 for a block that appended 8,
   serve the two node hashes as its leaves, and pass every root check under the
   honest chain's own headers. `docs/WALLET.md` carries all of it under "What
   bound A does not cover", both wallets now detect the one variant that leaves
   this wallet's ciphertext in place, and both print the rescan that recovers
   the rest.

   The closure. Every storage value the scan reads is read with a trie proof
   and verified locally: `ZkTree::LeafCount`, `ZkTree::Leaves(i)`,
   `Shielded::Ciphertexts(i)`, `Shielded::LeafBlocks(i)`,
   `Shielded::CoinbaseValues(i)`, `Shielded::EntryCount` and the
   `UsedNullifiers` pages. `state_getReadProof(keys, at)` answers the trie
   nodes on the path to each key at the pinned block hash, and the root those
   nodes reconstruct is the header's `stateRoot`, which the header walk already
   authenticates through the same hash chain that authenticates `zkTreeRoot`:
   `HeaderInputs` hashes `parent_hash`, `number`, `state_root`,
   `extrinsics_root`, `zk_tree_root` and the digest window together, and every
   header of the range is rehashed down to a hash the wallet already trusts. So
   the count becomes a fact of the block, every leaf value becomes a fact of
   the block at its own index, and every ciphertext becomes a fact of the block
   at its own index. The position bound goes, because a moved leaf is a key
   whose proof does not verify. The depth bound goes, because a leaf count and
   a leaf at an index are both proven. The ciphertext bound goes, because the
   bytes are proven at their key. **No consensus change, and the upstream tree
   is untouched**, which is what keeps section 10's trust claim.

   The cost, and what has to be measured before it is sized. Verification is
   Substrate's trie V1 under blake2-256 (`system_version: 1` in the runtime),
   which is `sp-trie`'s `verify_trie_proof` with `LayoutV1<BlakeTwo256>` in
   Rust. In the browser it belongs in the same wasm module that owns Poseidon2
   and the header hash, beside `headerBlockHashes` and `blockRoots`: a second
   implementation in TypeScript of a consensus-critical trie walk is a rule
   with two spellings, and `sp-trie` compiles to `wasm32-unknown-unknown`, so
   the price is module size and no second rule. Proofs are batched per
   page, which is what makes this affordable: the keys of one 64-leaf window
   share their map prefix, so every trie node above the point where they
   diverge appears once in the proof, and the marginal cost per key is the few
   nodes below it. A key read alone carries its whole path, on the order of one
   or two kilobytes at a state of a few million keys. Measure the proof bytes
   per key at a page of 64, the verify time per page in wasm, and the module's
   growth, and put the numbers in `docs/BENCH.md` before the milestone is
   sized. Against the M10 sketch this replaces, reading each block's body and
   recomputing `extrinsicsRoot`, it is cheaper and it covers more: no body
   fetch per block, no private-batch verify per settlement at 14.1 ms in wasm,
   and the leaf count and the fold's height are covered where a body read left
   them open.

   What stays open after it: nothing that comes out of storage. Bound B is
   unchanged, because a node above the newest checkpoint still chooses every
   header field, `stateRoot` included, and the defence there is still the
   checkpoint fork walk.
7. **Whether the tree should domain-separate a child's slot and its level in
   place of sorting, decided before a testnet genesis.** This is the
   consensus-level alternative to open question 6 and it is **unnecessary for
   the wallets once question 6 lands**, so it stays a consensus option that a
   network can take on its own merits, and no decision the wallets are waiting
   on. `tree::hash_node` sorts its four children so that a Merkle path
   can carry siblings with no position beside them, and the cost of that
   convenience is that the root commits to each node's child multiset and to no
   order, which is the position bound above; with no level tag in the hash it
   also commits to no height, which is the depth bound above. Hashing each child
   under its own slot **and under its level**, over the unsorted children in
   index order, puts all three in the root: a wallet that has checked a block's
   fold has then checked which leaf each commitment is, how many leaves the
   block appended and at what height they were folded, and a node cannot
   permute a group or present a node value as a leaf at all. The cost is a fork
   and it is not small: the pallet's node rule and its proof shape, the
   circuit's Merkle gadget, which drops the sorted-sibling adapter and gains a
   position witness per level, both wallets' local rebuilds and path checks,
   the explorer's tree views, and every KAT vector over a root or a path,
   regenerated and reviewed. It also ends this tree's status as the audited
   upstream's as-is, which is the argument `docs/DESIGN.md` section 10 rests
   the trust claim on, so the change would need its own review. If it is taken
   at all, take it before a network launches, because after that it is a hard
   fork rather than a constant.

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
5. Mining story. **M7 made it RandomX, and the swap cost the seam and nothing
   else.** The engine is `rx/0` with stock upstream constants, so the hash is
   the one Monero mines and a rig moves over by editing a pool address. The
   node speaks the stratum dialect xmrig speaks to a Monero pool
   (`--stratum-port`), and a stock `xmrig --algo rx/0` mined this chain in the
   M7 smoke run with no patched miner. Nothing in the runtime moved except
   what had to: RandomX cannot run in a wasm runtime (a 256 MiB Argon2d cache
   against a 128 MiB heap, no JIT, and a floating-point rounding mode wasm
   cannot set), so verification is client side and the runtime is the oracle
   the client asks for the difficulty and the seed schedule. M6 built for this
   exactly: everything that needs to know who authored a block reads one
   `FindAuthor` implementation, `configs::QpowAuthor`, the coinbase belongs to
   the block's author, and the note's recipient is the miner key the node
   holds. That file was not edited. Neither was the header shape, the fork
   choice, the coinbase inherent or the engine id. `docs/OPS-DEV.md` carries
   the seam and the flags. Hegemon has no CPU-mining story to compare: it runs
   its own proof of work and no existing rig speaks it.

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
2. Proof of work, and the one every CPU miner already runs. RandomX `rx/0`,
   stock constants, so a Monero rig points xmrig at a Qnero node and mines. No
   stake, no validators, no foundation keys in consensus, and no algorithm
   nobody has hardware or software for.
3. Post-quantum from genesis. Hash-based proofs, lattice signatures and
   encapsulation, nothing for Shor to break.
4. Audited parts only. Standardized primitives and firm-audited circuits.
   No novel cryptography.
