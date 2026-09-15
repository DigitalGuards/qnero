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

Genesis is the exception: `mainnet_vesting` mints 2% of `MAX_SUPPLY` at genesis
as transparent balances, a keyless vesting pot plus a seed to each treasurer and
each collective member. None of it is a note, all of it is inside
`Balances::total_issuance()`, and it reaches its holders through
`Vesting::claim`, which publishes the beneficiary and the amount. Section 7.2
is why that call is the one transparent payout v1 keeps.

**The 2% is a placeholder, decided 2026-09-14.** The table this chain forked
minted 27% across 48 vesting rows to the upstream project's own allocation
sheet, which is not an allocation this project can defend: those addresses have
no relationship with Qnero and 27% of the supply is a claim on every miner who
ever runs it. Every one of those rows is gone. What is there now is one vesting
row to one placeholder ML-DSA-87 account, 419 940 QNR on the same one-year lock
and three-year linear unlock, plus the 60 QNR of seed endowments that let the
treasurers and the tech collective pay their first deposits. The treasury holds
no schedule at all. Before mainnet genesis this is replaced with a real
allocation or deleted outright, and deleting it is a live option: a chain whose
entire supply is mined is the cleanest thing this project could launch. Section
7.3's pre-mainnet check carries the line.

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
   steps, and a canonical `inner`. The last is checked at the inherent, where a refusal is still
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

**And replace or delete the placeholder allocation.** `mainnet_vesting::VESTING`
is one row paying `mainnet_vesting::PLACEHOLDER`, an address generated with
`qnero-node key qnero` to stand in for an allocation nobody has decided on.
Shipping it would mint 2% of the supply to an account held by nothing, and
`Vesting::claim` is the only call that can move the pot, so those 419 940 QNR
would be stranded for good and would depress every block's coinbase forever,
because emission is `(MAX_SUPPLY - issued) / EmissionDivisor` over both books.
Either name a real beneficiary there or remove the row and set
`GENESIS_ALLOCATION` to the seed endowments alone. Section 7.1 is the reasoning.

Until then the preset refuses to build. `mainnet_vesting::FINALIZED` is `false`,
so `require_finalized` panics, `mainnet_config_genesis` refuses with it,
`preset_names` leaves `mainnet` off the list and `build-spec --chain mainnet`
produces no file. Flipping the bool alone does not lift the refusal either: a
compile-time assert beside `VESTING` rejects `FINALIZED == true` while any row
still names `PLACEHOLDER`, so what unblocks the build is deciding the
allocation.

Two consequences worth writing down. The vendored `sc-cli` fork still offers
`--scheme dilithium65` on its key commands, and that tree stays as upstream
wrote it so the next subtree merge is clean; Qnero's own dispatch refuses the
flag before `sc-cli` sees it (`node/src/command.rs`), so the CLI and the entry
now say the same thing. And the rule breaks consensus. Before it, an ML-DSA-65
extrinsic passed every check and entered the block, refused only later at
dispatch by the call filter, so a block already carrying one fails to
re-execute under the rule. Qnero is devnet-only, so a devnet carrying
such a block has to be reset.

### 7.4 The block interval (consensus, 2026-09-14)

**Blocks target 120 000 ms.** Monero's interval, and the decision is Monero's
reasoning applied to a chain that is not yet a network. The old target was 12 s,
inherited from the upstream chain along with everything else in `pallets/qpow`.

Four reasons, in the order they matter.

**It is Monero's cadence, and this chain's seed schedule is Monero's.** The
RandomX seed epoch is 2048 blocks with a lag of 64, copied from Monero because
the masked rule is what a stock rig already implements. At 12 s those 2048
blocks were 6.8 hours, so every full-mode rig paid a 2 GiB dataset rebuild four
times a day where Monero's rigs pay it every 2.84 days. At 120 s the block
count and the wall clock both match Monero, and the constant needed no special
value to get there. `pallets/qpow` carries the same note beside the constant.

**The retarget is calmer on a small network.** The Homestead adjustment reads
one block time and moves difficulty by at most +1/2048 or -99/2048. At a 12 s
target one slow block inside a 10 s bucket is a real signal about a network with
a handful of CPUs on it; at 120 s the same absolute timestamp noise is a tenth
of the bucket and the retarget stops chasing it. The 15 s of legal timestamp
drift a miner may claim used to push an honest block into the next bucket and
cost a single -1 step, and at a 100 s divisor it does not leave the neutral band
at all. The algorithm is unchanged: only its divisor is denominated in time, and
that scales with the target.

**A light wallet walks ten times fewer headers a day.** Both wallets
authenticate a block's leaf range by walking headers down from the head, one
`chain_getHeader` per block, and the browser wallet holds one chunk of 1024 of
them resident. A day of chain is 720 headers at 120 s where it was 7200 at 12 s,
so a wallet opened daily catches up inside one chunk instead of seven. The same
arithmetic runs through the shielded anchor window: 256 blocks is 8.5 hours of
anchor validity rather than 51 minutes, which is the difference between a phone
that starts a proof, locks its screen and finishes later and one that has to
start again.

**Nothing about the pool got slower.** Block size and weight are unchanged, so
a block still settles the same number of payments. Per second it settles a
tenth as many, and that is a real consequence rather than a free one: at 53
inner batches of up to 6 transfers the ceiling is 318 settlements a block, which
was about 26 a second and is now about 2.6. Nothing on this chain is near that
ceiling and nothing will be for a long time, so the decision is deferred rather
than answered. When it needs answering the options are Monero's own: a larger
block, or a dynamic size with a penalty above a rolling median.

**What it cost.** The emission divisor was rescaled from 50 000 000 to
5 000 000 so the supply against wall clock is what it was, ten blocks' worth of
geometric decay folded into one. To 9.0e-8 relative: the exact factor is
`1 - (1 - 1/50 000 000)^10`, a divisor of 5 000 000.45, and the rounded value
runs that fraction ahead of the 12 s curve, which is far below the 0.01 QNR
step every payout already rounds to. `configs/mod.rs` carries the
arithmetic beside the constant. Every constant derived from the target
kept its duration and changed its block count, and every constant chosen as a
block count kept its count and gained a new duration; `runtime/tests/block_time.rs`
is the list, one test for each kind. The initial difficulty moved from 100 000 to
1 000 000, because difficulty is expected hashes per block and the same network
needs ten times as much at a ten times longer target.

**One binary, two cadences.** The target is a genesis-configured storage value
in `pallets/qpow` with no setter and no extrinsic, defaulting to the runtime
constant. The `dev` preset writes 12 000 so every end-to-end suite keeps the
cadence it was sized for, and the public presets take 120 000. Setter-free is
what makes it safe for the scheduler to derive its timestamp bucket from: a
target that moved under a running chain would strand every task already queued
at an old bucket boundary. `QPoWApi::get_target_block_time` is how the client,
both wallets and the explorer read it, and none of them carries the interval as
a constant. The method moved `QPoWApi` to version 2, so a client can ask
`has_api_with` whether a node has a target to give before it asks for one.

**How far the storage target reaches.** Three readers, and the list is the whole
list: the retarget in `pallets/qpow`, `TimestampBucketSize` in the scheduler, and
`MinDelayPeriodMoment` in reversible transfers. Everything else that is
denominated in the interval reads `TARGET_BLOCK_TIME_MS`, the compile-time
constant. That means `MINUTES`, `HOURS` and `DAYS` and every window built on
them, `UndecidingTimeout`, `DefaultDelay`, `HighSecurityTxWindowBlocks`,
`MaxExpiryDuration` and the governance tracks, and it means `EmissionDivisor`.
The line is drawn at metadata. Each of those is a `#[pallet::constant]` whose
purpose is to be readable out of metadata by a client deciding what a governance
period costs or what the supply schedule is, and a value that changed with a
storage read is a value no metadata could state. The consequence is that a chain
running at another cadence keeps the public chain's block counts: on the 12 s
`dev` chain `DAYS` is 720 blocks, which is 2.4 hours, the quota window and the
default reversal delay are 2.4 hours each, and emission per second is ten times
the public schedule's. That is a property of dev chains, and a chain spec that
sets `qPoW.targetBlockTime` to a third value has to carry a runtime with a
matching `EmissionDivisor` if its supply curve is to mean anything.
`runtime/tests/block_time.rs` pins both halves, one test for the readers that
follow the chain and one for the readers that do not.

## 8. Milestones

| # | Deliverable | Estimate |
|---|---|---|
| M1 | `qnero-notes` crate: keys, addresses, note commitment, ML-KEM note encryption, scan; KATs pinned | DONE 2026-09-11 |
| M2 | Leaf circuit fork with note fragments, tests, gate profile, prove/verify bench | DONE 2026-09-11 (319 gates at M2, 320 after the M3 padding sentinel; degree_bits 9, 26 public inputs; see `docs/CIRCUIT.md`) |
| M3 | Private and public batch aggregators on the new PI layout | DONE 2026-09-11 (private batch 5 + 21N public inputs, ZK, N = 7; public batch forwards each inner verbatim under an aggregator address and refuses a repeated inner in circuit; see `docs/CIRCUIT.md` section 8) |
| M4 | `pallet-shielded` + runtime wiring, local dev chain end to end | DONE 2026-09-12 (chain forked as a git subtree at `chain/`; `pallet-shielded` settles private and public batches, `shield` is the only v0 entry, `pallet-zk-tree` stores raw `Hash256` leaves; N = 6, n = 53; see `docs/CIRCUIT.md` section 9 and `docs/OPS-DEV.md`) |
| M5 | Wallet CLI: keygen, sync/scan, build leaf + batch, submit | DONE 2026-09-12 (`crates/qnero-wallet`, binary `qnero-wallet`: keygen, address, shield, sync, balance, send, status; hand-encoded extrinsics over JSON-RPC, storage layout and fee floor read from runtime metadata, Merkle paths rebuilt locally and the settled nullifier set paged whole so no request names a note as its own, notes in one JSON store beside the seed; memos padded to one size, at a pad chosen so the padded pair stays a fee bucket below a pair padded to `MaxCiphertextBytes`, and the payment's output slot drawn per spend, so the chain publishes neither a memo length nor which of a settlement's two leaves is the sender's change; one checkpoint-hash walk decides both whether a node is on the wallet's chain and whether it has reached everything the wallet has read, rewinding the leaf watermark to the newest checkpoint still canonical on a fork and refusing a node that is behind, with a leaf-count gate under it so the watermark never regresses outside the fork path, and spent status is derived from the settled set in both directions; see `docs/WALLET.md`, and `docs/BENCH.md` for the public batch at `n = 53`, which M4 left unmeasured); `sync --rescan` is the operator override on the node gates, runs add-only, and its known edges are docs/WALLET.md open issue 14) |
| M6 | v1 mandatory privacy: coinbase into notes, transparent transfers disabled | DONE 2026-09-12 (every unit of value created after genesis is a note, the genesis allocation staying transparent and reaching its holders through `Vesting::claim`: `pallet-shielded` mints one coinbase note per block from a required inherent, the author's share of settled fees rides in it, mining rewards to transparent accounts are off, and `BaseCallFilter` refuses every call that moves transparent value between accounts a user chooses, leaving `Vesting::claim`, a genesis-fixed payout from a keyless pot, as the one transparent payout; `pallet-wormhole` is out of the runtime with its transaction extension, the runtime identifies as `qnero` at `spec_version` 101 and `transaction_version` 7, and the wallet finds its coinbase notes from a miner key the node is configured with; see section 7, `docs/CIRCUIT.md` section 10, `docs/WALLET.md` and `docs/OPS-DEV.md`. The review pass that closed it changed five things: the header's author item became per block so no coinbase leaf carries a mining identity, `set_high_security` joined the refused list so no account can enrol into a feature whose every call v1 refuses, and the high-security whitelist stayed as it is because every call on it is delayed and a guardian can reverse it, `Vesting::claim` stays dispatchable so the genesis allocation is deliverable and no preset endows a keyless account, the coinbase inherent refuses the encrypted payload nothing builds, and a block with no emission still mints the author fee the pool already holds. A second review pass reversed one of those: `shield` and `burn` came back off the high-security whitelist, because every other call on it is delayed and a guardian can reverse it, and the freeze they were paying for is unreachable while the enrolment itself is refused. It also moved `spec_version` to 101, which is the number above, for the metadata the first pass changed without it. A third pass bound the coinbase note's `r` to the chain's genesis, so one miner key on two chains no longer mints byte-identical notes at equal heights, and corrected the claim this row itself carried: the genesis allocation is transparent and reaches its holders through `Vesting::claim`) |
| M7 | RandomX proof of work, so a Monero rig mines Qnero | DONE 2026-09-13 (the engine is RandomX `rx/0`, stock upstream constants, so the hash is bit-identical to what a stock xmrig computes and a Monero rig moves over with a config change; `chain/client/consensus/randomx` is the whole engine, the runtime no longer verifies a nonce because RandomX cannot run in wasm, `pallet-qpow` keeps the difficulty storage and the Homestead retarget because both are functions of block times rather than of the hash, and the node grew a stratum endpoint behind `--stratum-port` speaking the dialect xmrig speaks to a Monero pool. The M6 author seam did what it was built for: `H(cvk, parent_hash)`, `configs::QpowAuthor`, the coinbase inherent, the header shape and fork choice are untouched, and `POW_ENGINE_ID` is still `pow_`. The proof is a 4-byte nonce and a 4-byte extra nonce over a fixed 76-byte blob with the nonce at offset 39 where xmrig writes it, packed into the 64-byte seal the digest window needs with the remaining 56 bytes pinned to zero, because free seal bytes would be free block-hash grinding. The comparison is Monero's: the hash read little-endian, accepted when `hash * difficulty <= 2^256 - 1`. Seed rotation is Monero's rule with the epoch and lag as runtime constants. `spec_version` moved to 102 for the three runtime-API methods and the event that went away; `transaction_version` stayed at 7. See section 10, `docs/OPS-DEV.md` and `docs/BENCH.md`) |
| M8 | Prover budget on a phone-class device: a browser prover, measured | DONE 2026-09-14 (`crates/qnero-prover-wasm` is the browser surface, compiled to `wasm32-unknown-unknown`, single threaded, rayon-free: derive an address, decrypt a ciphertext while scanning, and prove one private batch at `N = 6`, with a headless-Chromium harness under `www/` and its Node runner. Nine samples per per-payment figure: **33.6 s per payment and 910.4 MiB peak** in single-threaded wasm, on top of 12.1 s of circuit build once per worker, against 9.82 s and the same shape natively. A desktop core under headless Chromium is the phone proxy and the stated factor is 2 to 4 with room above it, so a phone is 67 to 134 s per payment or worse: **memory fits and the single-threaded clock misses the 60 s target at every point of the range**. Seven slots were measured too: 65.8 s and 1.72 GiB, which fits this browser and does not fit a phone. The ZK leaf a delegated batcher would take is 16.6 s of proving on top of a 6.8 s circuit build, 511 MiB on its own, and 150932 bytes, 24 bytes larger than the whole six-slot batch it would be handed to. See the section below and `docs/BENCH.md`) |
| M9 | silQ Road, the Qnero explorer: what a chain reader can see, and what it cannot | DONE 2026-09-14 (`explorer/` is **silQ Road**, a static Vite and React site over `@polkadot/api`, configured by one runtime JSON so one build serves a devnet and a testnet, with no server-side indexer: home, a paged block list, a block page, a settlement page by extrinsic hash, search over heights, block hashes, extrinsic hashes, nullifiers and commitments, and a "What this chain reveals" page taken from `docs/CIRCUIT.md` section 10.7 and `docs/WALLET.md`. Two decoder seams a generic Substrate client gets silently wrong are handled and tested: the header's `zkTreeRoot` between `extrinsicsRoot` and `digest`, which polkadot-js otherwise decodes the digest out of, and the block body, which the typed `chain_getBlock` refuses because the ML-DSA-87 signature is a fixed 7219-byte array above polkadot-js's 2048-byte array limit, so the envelope is walked by hand with the signature lengths and the extension list read out of metadata. Everything else is metadata-driven and the assumed storage hashers are asserted against it at startup, because an absent key and an empty map are indistinguishable and the difference renders as "0 leaves, 0 nullifiers" with no error. The presentation rules are part of the deliverable: a slot's two outputs are an unordered pair, there is no miner table because the author label is `H(cvk, parent_hash)` and rotates every block, a refused call is named without reprinting the arguments the block body already carries, ciphertext size and anchor gap are shown where they inform and are sortable nowhere, and `zkTree_getMerkleProof` is never called, which a lint rule enforces in both the shapes the node serves it in, the method and the `ZkTreeApi_get_merkle_proof` runtime call behind `state_call` and `archive_v1_call`. Degradation is part of it too: the consensus constants are read after the connection is published so a refused `state_call` costs those fields alone, a block whose state the node no longer keeps still renders its header and body, a bounded walk that reaches the bottom of a pruned state window ends as a miss that names the boundary, and every read on the search page whose request carries the query's own 32 bytes, the nullifier lookup and the block-hash header check alike, is printed as a warning first and runs only when a reader presses its button. 100 vitest cases over the decoders, the route grammar and the three answers a page may give about a block whose state the node did not keep run against fixtures captured from a dev node, and a Playwright smoke starts its own `--dev --tmp` node at one mining thread, shields once, sends once, serves the build and asserts the five pages, counting the frames that carry a query's own 32 bytes and relaying the page's socket to answer one block's state reads the way a pruned node does, then stops the node by pidfile and waits for the port to close. See `explorer/README.md`) |
| M10 | Qloak, a Qnero wallet: keys in the page, proofs in a worker, no server | DONE 2026-09-14 (`wallet-web/` is **Qloak**, a static Vite, React 19 and TypeScript app with no server component and no account: it creates a 32-byte spend key in the page, seals it and every note's `rho`, `r`, nullifier and memo in IndexedDB under AES-256-GCM with a PBKDF2-SHA-256 key at 600,000 iterations and a fresh IV per record per write bound to its own slot, scans the chain in a worker, proves a payment in that worker and submits it, and contacts nothing but the node it is configured with. The M5 rules are ported rather than relaxed: the settled nullifier set is paged whole and spent status decided locally, leaves are read as one contiguous range and Merkle paths rebuilt locally, `zkTree_getMerkleProof` is unreachable and a lint fence keeps it that way in every spelling, the genesis binding, checkpoint-hash fork walk and leaf-count gate refuse before anything is written, the spend repeats the storage-drift, genesis and leaf gates for itself because the write-off that marks a selected note off chain rests on them, a rescan is add-only, and every number a node answers with is decoded at its declared width and bounded where it decides how long the wallet works: `Shielded::EntryCount` is one Poseidon2 hash per unit inside the worker that holds the seed, so the origin walk stops at 100,000 entries and both wallets report a pass that hit the bound, and `ZkTree::LeafCount` is read at eight bytes and refused above `4 ** max_tree_depth`, which is what a 4-ary tree the circuit can prove over holds, and the command-line wallet now reads every storage integer the same way, `LeafCount`, `Depth`, `EntryCount`, `LeafBlocks` and `CoinbaseValues` each refused by name at any other width and the count bounded by the same capacity. A per-leaf key the node answers nothing for below the count it reports at the same block refuses the pass in both wallets: `ZkTree::Leaves` and `Shielded::LeafBlocks` are required at every index, because `pallet-shielded` writes both in the call that appends the leaf and removes neither. The chain has no gaps under its own count, so such an answer is withheld rather than absent, and stepping over one hid a payment behind a watermark written above it with no error, no warning and no field in the report: no commitment and the leaf is skipped, no block and the leaf is dated by nothing. A commitment answered as the tree's own all-zero pad below that count refuses the pass as well, in both wallets and in the prover module's fold: `pallet-zk-tree::insert_commitment` refuses an append of that digest by name and reads it as an unfilled slot at every level, and `TreeFrontier` pads with the same digest, so pushing pads reaches the root a fold that stopped short reaches and a run of them at the top of the tree would carry a leaf count higher than the chain's past every root the headers published. Without that rule the fold pins a block's leaf set while the count above it stays the node's to choose, and the pass writes a watermark and a checkpoint above indices no block has filled, where the real leaves that land later are never read. **Whether a leaf owes a ciphertext or a coinbase value is not a flat rule, and a leaf's kind is derived only from data the header authenticates, never from which storage keys a node chose to answer.** Presence of `Shielded::CoinbaseValues` used to decide it, and presence is the node's to write: eight invented bytes on an incoming transfer leaf routed it onto the coinbase rebuild, which cannot open it, and an invented `Shielded::Ciphertexts` beside a withheld coinbase value hid a mined reward the other way round. What decides now is position, and position is what the headers commit to: the header chain, authenticated from a hash the wallet already trusts up to the head with every header rehashed from its own preimage, in chunks of `HEADER_WALK_LIMIT` (1024) blocks so a chain far ahead of the checkpoint syncs in one command with one chunk of headers resident (this walk descended by `parentHash` one header at a time until it was pipelined later in this row, which changed how it asks and not what it trusts; the three local checks that stand in for following the parent links are named there); each block's leaf range, checked by folding the leaves a node attributes to that block and comparing against the `zkTreeRoot` its header carries, which makes `Shielded::LeafBlocks` advisory; and the coinbase position, which is a block's last leaf because `pallet-mining-rewards` mints through `CoinbaseSink` in its own `on_finalize` while every shield and settled output was appended during extrinsic execution. **No rule rests on the author label.** These wallets verify no proof of work and will not in v1, because a RandomX verification needs a 256 MiB cache and has no browser build, so above the newest checkpoint a node picks every header field including `H("qnero/author-label", cvk, parent_hash)`, and a rule gated on the label is one the node switches off by publishing another. So a coinbase value below a block's last leaf is refused, a withheld one at **any** coinbase position is refused whatever the label says, a ciphertext is required at every other position, this wallet's own coinbase note is rebuilt at every coinbase position and the rebuild alone decides ownership, and the label is read afterwards as a cross-check: a label claiming this wallet's block over a rebuild that does not match refuses the pass, and a rebuild that matches under another author's label takes the reward and reports the disagreement. A checkpoint is recorded only for a head the pass authenticated, so a pass that scans no leaf walks the headers anyway. What no per-leaf rule reaches is a node that rebuilds the headers themselves, and the bound that does hold is the checkpoint fork walk: the forged head is recorded only as a checkpoint, and the first honest node disagrees with it, rewinds to the newest checkpoint both stand on and rescans, which both wallets drive end to end; a wallet that only ever talks to one node has no defence against that node beyond consistency, and `docs/WALLET.md` says so under "What a lying node can and cannot do". The fold is incremental, one Poseidon path update per leaf and one comparison per block, and the added cost is one `chain_getHeader` per block of the scanned range: see `docs/WALLET.md` under "How a leaf's kind is decided" and `docs/BENCH.md`. A scan and a payment never run at the same time: the job slot is claimed synchronously before either handler awaits anything, the Settings screen disables its rescan while a payment runs and says why, and `commitSync` reads each row inside its write transaction and keeps a `spent` or `onChain` that moved since the pass read it, so a settlement that lands mid-scan cannot be un-latched by the scan's own copy. That the node is told nothing is tested as a property of the request stream rather than asserted in prose: `tests/privacy.test.ts` drives the real read layer through a recording transport and asserts that no request carries a nullifier, that leaves are asked for as one range, that every read of a pass is pinned to one block hash and that nothing outside four public-read methods is called. Two things a generic client gets silently wrong are handled and both were found against a live node rather than in a unit test: metadata v16 publishes `extrinsic.versions` as `Bytes` rather than a `Vec` of codecs, and polkadot-js cannot construct the settlement extrinsic at all because this runtime's signature type carries a fixed `[u8; 7219]` above its 2048-byte array limit, so the bare extrinsic is hand-encoded with the pallet and call indices read off `.callIndex`. Shielding stays a command-line step, stated on the page: entry into the pool is signed with ML-DSA-87 and the wasm module exports no signing. The threaded module from M8's follow-up is loaded when the origin is cross-origin isolated, capped at four threads, with the single-threaded module as a silent fallback the settings screen names. Measured in the suite's own browser on the development workstation: 11.2 s to prove a payment on four threads against 37.6 s on one, 917.6 MiB peak threaded and 910.2 MiB on one thread, and 24.6 s from pressing Send to a settled block against 53.4 s. 290 vitest cases plus a Playwright suite that starts a `--dev --tmp` node at one mining thread on a port it chooses, has the command-line wallet fund the address the browser wallet creates, proves the payment in the browser, has the command-line wallet read it back and stops and restarts the prover, recording every JSON-RPC frame the page sends and refusing any method outside an allowlist. The passphrase floor is enforced at the key derivation rather than on the screen that asks for one, the built page declares a content policy and `wallet-web/README.md` carries the header a host should send, the socket reconnects and drives the status strip rather than being decided once at connect, and the circuits are built once per worker: they were rebuilt on every send, which added a permanent quarter gigabyte of linear memory per payment (see `docs/BENCH.md`). The look and the screen flow follow MyMonero's web wallet under BSD-3-Clause, credited in `wallet-web/NOTICE`. **Two per-leaf values are bound to a leaf by nothing on chain, and both are open in both wallets:** the bytes at `Shielded::Ciphertexts(i)`, and where a commitment sits inside its block's own leaf range. The commitment the tree authenticates carries no ciphertext and `ct_digest` binds the bytes only inside the settlement extrinsic at inclusion, which a storage-only reader never fetches, so a node with honest headers can answer a stranger's ciphertext at an incoming payment and the AEAD does not open. And `tree::hash_node` sorts a node's four children before hashing them, which is what lets a Merkle path carry siblings with no position beside them, and it mixes in neither the level nor the child slot, so a block's `zkTreeRoot` pins that block's leaf multiset and each internal node's child multiset and nothing else. Two consequences and the bound is both: sibling swaps compose at every level, so a payment moves to any position the block's range allows, across group boundaries and onto the coinbase position where no ciphertext is owed and this wallet's coinbase rebuild cannot open it; and the fold of `m` level-1 node values equals the fold of the `4m` leaves under them, so a node can answer a leaf count of 2 for a block that appended 8, serve the two node hashes as that block's leaves, pass every root check under the honest chain's own headers, and leave the watermark above every leaf the block really appended. **One part of it both wallets now catch on their own.** A move that leaves this wallet's ciphertext where the chain published it puts a payload that opens under this wallet's key, which ML-KEM decapsulation and an AEAD over this wallet's own `pk` authenticate, beside a commitment that note does not open; `try_transfer` and `decryptBatch` stop folding that into "somebody else's", the pass searches the block's own folded leaf range for the commitment the note does open, records the note there and warns with both indices, so the payment arrives with no second node needed. A commitment the block holds nowhere is warned and skipped rather than refused, because a sender who encrypts a payload opening a commitment it never published produces the same reading, `ct_digest` is unconstrained in circuit, and a refusal would be a permanent sync denial anyone could buy with one transaction. What stays hidden is a move that takes this wallet's ciphertext with it or leaves none: the leaf reads as somebody else's, the watermark is written above it, the checkpoint fork walk recovers nothing because the headers agree, and a rescan against a second node is the recovery. Both wallets carry one sentence naming both unbound values on a pass that read leaves and received nothing, on a `hint` line in the command-line wallet and on `report.hints` under the balance screen's warnings in the browser, held byte for byte identical by a test that reads the Rust literal out of the wallet's own source, and both drive every variant end to end in a test: the substituted ciphertext, the move with the ciphertext left in place, the move with it gone, the swap across two aligned groups six positions apart, the two level-1 node values served as two leaves, and the ciphertext of ours whose commitment the block holds nowhere. Closing the rest is the **next wallet milestone (M13)**, and section 9 open question 6 carries the design: read every per-leaf and per-chain storage value with a trie proof from `state_getReadProof` at the pinned block hash and verify it against that header's `stateRoot`, which the header walk already authenticates with the same hash chain as `zkTreeRoot`. That makes the count, every leaf value and every ciphertext a fact of the block, and closes the ciphertext, the index and the depth together **with no consensus change and the upstream tree untouched**; the cost is blake2-256 trie V1 verification, in `sp-trie` natively and in the same wasm module in the browser, with proofs batched per page so a window's keys share every trie node above their divergence. Section 9 open question 7 records the consensus-level alternative, domain-separating a child's slot and its level in place of sorting, which pins the position and the height in the root and costs a fork, and it is unnecessary for the wallets once question 6 lands. Two smaller answers were closed here: the browser's padding-sentinel rule compares the node's hex normalised, so the pad spelled without a `0x` prefix is refused where it used to pass, and `Chain::leaf_hashes`, the read a spend rebuilds its paths from, now takes the leaf count and refuses an absent or all-zero answer below it, which is what the browser already refused. **The header walk is pipelined and a wallet records where it starts reading (2026-09-15).** The walk descended by `parentHash`, one `chain_getHeader` at a time, each header fetched by the hash its child named: one round trip per block with nothing else in flight, which against a node behind a CDN is the entire cost, and at the public chain's 120 s target a year of history is 262 000 of them in series. It is two pipelined halves now in both wallets: `chain_getBlockHash` over a **list** of numbers paged at 256, then headers by hash with many requests outstanding, 32 JSON-RPC ids on the browser's one socket and JSON-RPC batch arrays of 64 over HTTP from the command-line wallet, with a fallback to one request per call for a node that takes neither, because that is an older implementation and not a lie. **Nothing about which values are trusted moved.** The hashes are addresses and three local checks make the range a chain, which the descending walk got by construction: every header's own number is the height asked for, every header rehashes to the hash it was fetched by, and every header names as its parent the hash this node answered for the height below it, so a hash answered for a number the header chain does not carry is refused by name. Composed, they are the same equalities as before, down to a hash the wallet already trusted: hashes only, no proof of work, Bound B unchanged, `HEADER_WALK_LIMIT` chunking and per-chunk checkpoints unchanged. Measured against the live testnet through its CDN: the browser walks 325 headers in 0.45 s where it took 5.26 s, 727 headers a second against 62, and the command-line wallet's full fresh sync of the whole chain goes from refused to 0.68 s in 23 HTTP requests, because the node's front end answers `429 Too Many Requests` after about eighty HTTP requests in a window and a sequential walk over any chain longer than that cannot finish at all: it gives up 63 headers in. On loopback, where the round trip is microseconds, it is 2.5x on time and 47x on requests. A request that did not complete is read as neither of the two answers that mean "this node is older than the parameter shapes this wallet uses": a rate limit latched as "no batches" would have put the next chunk on sixty-four times the requests into the endpoint that had just refused one, so those are reported and the batching question is left open. And a wallet now records a **birthday**, the block it was created or restored at, as its first checkpoint with that block's leaf count as its first watermark: a wallet cannot have been paid into a leaf that existed before it did, so it walks no header under that block and trial-decrypts no ciphertext under that count. It is the node's claim exactly like every checkpoint, so the fork walk rewinds through it and the first sync that has leaves to scan folds the leaves under its count against that block's own `zkTreeRoot`, which refuses a count recorded too high and does not pin one that is too low (Bound A), with a pass that has nothing to scan left with the roots the chunk's own headers carry; while the watermark is still that count, both refusals it can trip name the birthday and the rescan that drops it, because a watermark that was wrong when it was written is not a node being behind and no other node satisfies it; a restore takes an optional height, one field on Qloak's restore screen taking a block number or a date and `--restore-height` on the command-line wallet's new `restore` command, which reads the spend key on stdin because a command line is world readable; every recorded birthday is rounded **down** to a 1024-block epoch, because a birthday is public, it is the bottom of the walk every node is told, and an exact one is a creation time to the block that follows the wallet across nodes; and a restore with no height is a full scan with the wait printed first at the measured rate, which both wallets quote from one constant. A restore height above the block a transfer arrived in is the one failure neither wallet can detect, a transfer never read with no warning anywhere and a rescan the only recovery, and both wallets say so where the height is asked for. See `wallet-web/README.md`) |
| M11 | Public testnet: preparation and deploy | DONE 2026-09-15 (deployed the same day: the site, Qloak, silQ Road, the faucet and the public RPC answer at their qnero.io names, the seed node mines at the 120 s target with the stratum port open, a second node joined through the published bootnode, a faucet drip landed in a fresh wallet, a rig got accepted shares, a head subscription held through the CDN across gaps of nearly four minutes, and two layers of monitoring post to the project channel; two packaging defects the launch found, a unit that hid the p2p port and an RPC host filter, are fixed in the same commit as the launch. Prepared earlier the same day: everything the chain needs, built and rehearsed on a workstation before a host exists. A `qnero-testnet` preset whose genesis is one endowed faucet account and nothing else: no vesting row, no 2% mainnet placeholder, no tech collective, no sudo, and no treasury, which widened `TreasuryGenesis.account` to `Option<AccountId>`, a state the runtime already supported. The 120 s target, and an initial difficulty of 5 000 set rather than inherited: difficulty is expected hashes per block and the retarget settles between `100 * H` and `200 * H`, so the rate the chain is certain of, its own node's 32.9 H/s light-mode thread, puts one block at 152 seconds with no retarget pressure, where the inherited 1 000 000 would be 8.4 hours to the first block and a week to converge. Low on purpose, because the Homestead retarget is linear at `H / 2048` per second upward and 57 hours per e-fold downward. The faucet account is ML-DSA-87, minted with `qnero-faucet keygen` and confirmed against the node's own derivation before genesis; the spec carries the address alone. `chain/node/chain-specs/qnero-testnet.json` is generated by `scripts/build-testnet-spec.sh` and `testnet_spec.rs` compares every one of its 1 365 586 bytes against a fresh export, with `bootNodes` the one field a deployment fills in afterwards, outside genesis. `faucet/` is an axum server around `qnero-wallet` as a library: one prover built at startup, one worker thread owning the wallet, a bounded queue in front of it, an address cooldown and a per-client window in SQLite, optional Turnstile, and `POST /drip` answering `queued` because a drip is a ten-second proof and then a block. Packaging is systemd and a copied binary rather than a container, since the 2 vCPU host cannot build the tree and shares this workstation's glibc: two units, six nginx vhosts with the wallet's COOP and COEP and every `add_header` at server level, a deploy script, a node probe, an on-box monitor and the external watchdog entries. Rehearsed: two nodes from the committed spec, B joining A through the generated multiaddr and importing every block within a second, block 1 in 199 s on one light-mode thread, xmrig sealing 52 of 54 accepted shares at about 717 H/s, the difficulty climbing 5 000 to 5 106 across 55 blocks, the faucet funding itself by shielding the endowment and dripping 10 QNR that proved in 11.18 s and settled in block 21, and a fresh wallet syncing that note from the second node. Two flags a copied runbook gets wrong, both found here: `key generate-node-key` resolves a chain before it does anything, and `--force-authoring` is what lets a new chain produce block 1 at all. `docs/TESTNET.md` is the runbook, placeholders only. The deploy phase marks this DONE) |
| M12 | Project site at `qnero.io` | DONE 2026-09-15 (`site/` is the whole of it: eight hand-written pages, one stylesheet, two scripts, one applying the stored theme before the first paint and one toggling it, a favicon and an open-graph card, with no build step, no framework, no font download, no analytics and no third-party request, which is the rule `explorer/README.md` states for itself. Home carries the one-line definition, the pre-alpha and unaudited disclosure above the fold, the four priorities with the correction attached to the fourth at the same weight, the ten-row Monero mapping, what a block publishes and the five-project comparison; then the transfer walk-through with an inline SVG of the three proving layers and the full section 10.7 disclosure table, Qloak with its threat model in plain words, mining with the stratum flags and the devnet figures labelled as devnet, silQ Road with its eight refusals, a document index and an about page carrying the audit status, the caveats, the upstream credits and this site's own BSD-3-Clause provenance notice for the MyMonero design it follows. The node download is absent because no build is released, and `wallet.qnero.io`, `explorer.qnero.io`, `faucet.qnero.io` and `wss://rpc.qnero.io` are named as the M11 targets and marked as answering nothing yet. Checked: html-validate clean on all eight pages, an internal link and fragment walk clean that also asserts every M11 subdomain reference carries its "testnet, coming online" label, a headless measurement at 320, 400 and 1280 px finding no page scrolling sideways and no inline chip wider than its box, and every text element clearing WCAG AA in both themes at 400 px and 1280 px. Token values are the two apps' own, so the site, Qloak and silQ Road read as one project, with one deliberate divergence named in the stylesheet header: the site's filled controls sit on their own ground and keep the amber in light, where the apps use the dark brown link accent) |
| M13 | Authenticated storage reads through `state_getReadProof`, in both wallets | PLANNED 2026-09-14 (every per-leaf and per-chain value a scan reads is taken with a trie proof at the pinned block hash and verified against that header's own `stateRoot`, which the header walk already authenticates, closing the ciphertext, the index inside a block and the tree's depth together with no consensus change and the upstream tree untouched: section 9 open question 6 carries the design, the key list and the cost) |

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
3. ~~Whether to keep QPoW or bring RandomX~~ **Closed at M7: RandomX.** The
   sizing of its two seed constants was open under it and the epoch closed
   itself on 2026-09-14: the target block time moved to Monero's 120 s, so
   Monero's 2048 blocks is Monero's 2.84 days here as well, and the epoch stays
   at 2048 with nothing left to tune. What remains open is the lag. It is
   Monero's 64 blocks and `MaxReorgDepth` is 100, so the seed block is still
   inside the window a legal reorg can move. That cannot split the chain,
   because the seed is resolved along each candidate's own ancestry, but a deep
   reorg across a boundary does change the seed under work already started; a
   lag of 128 removes it. Decide it before a network launches, because after
   that it is a fork.
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


## 12. Scaling and bloat: decisions (2026-09-15)

Editor's record over three proposals and two reviews. Agreed review positions are taken;
where they split, the proposal with fewer proven errors wins. Figures both reviews refuted
are excluded: the 482 KB block, 5.3 tps, 3x weight headroom, 11.5 tps at 8 MiB, the 512 KB
median floor, 175 B of public inputs.

### 12.0 Corrected baseline

| Quantity | Value |
|---|---|
| Normal block length (5 MiB x 0.75) | 3 932 160 B |
| Wire cost per transfer | 3584 B ciphertext + 747 B proof = 4331 B |
| Full public batch extrinsic (318 settlements) | 1 377 256 B |
| Length ceiling | 908 settlements/block |
| Weight of one full batch | 1.578 s (0.317 verify, 0.525 DB, 0.723 ct_digest) |
| Weight ceiling | 893 to 907 settlements/block |
| Throughput | about 7.5 transfers per second |

**Length and declared weight bind at the same point.** Two full batches are 70 percent of the
length limit and 3.16 s of the 4.5 s weight budget, so any capacity change is a two-constant
change.

### 12.1 Q1, the change output

**Decision: keep two full-length ML-KEM-1024 ciphertexts per transfer. Reject the
sender-derived short change output. Add a settlement rule that every output ciphertext is
exactly the fixed length for its `crypto_suite` id.**

| Option | Bytes/transfer | Effect |
|---|---|---|
| Two real outputs (today) | 4331 | change indistinguishable from payment |
| Sender-derived change | 2987 | lengths differ, so the change flag leaks |
| Chaff dummy of 1568 B | 4331 | zero saving |

Cost: 1568 bytes per transfer kept forever, plus a few lines beside the `ct_digest`
comparison. Leaks or forecloses nothing. The rule is only available while the bytes are in
hand, at settlement.

Dissent, resolved: a flat length rule would refuse a later ML-KEM-768 suite, so it is keyed
to the suite id. The cryptography review refutes two supporting arguments, that ML-KEM
ciphertexts are distinguishable from uniform (operator-first) and that the short variant
breaks seed-only recovery (privacy-first).

### 12.2 Q2, the note-channel KEM

**Decision: keep ML-KEM-1024. Record open question 1 as closed in this pass.**

| Axis | 1024 | 768 |
|---|---|---|
| Padded output pair | 3584 B | 2624 B |
| Bech32m address | 2571 chars | about 1950 chars |

Cost: 960 bytes per transfer. Forecloses nothing on the wire, since `crypto_suite` is already
there, though the choice is one-shot in practice: two suites publish two ciphertext lengths,
splitting the anonymity set by wallet, so a later 768 gets padded up and the saving
evaporates.

Recorded conditional: reopen at once if Q3 is ever rejected, because 768 then cuts permanent
state 27 percent. Section 9 should state the real requirement, key privacy and ciphertext
pseudorandomness under chosen-ciphertext attack.

### 12.3 Q3, where the ciphertexts live

**Decision: ciphertexts move out of the state trie into block bodies, authenticated against
the header `extrinsicsRoot`. Ship `CiphertextRetentionBlocks = 0` with a no-op prune branch
in the same bump.**

| Layout | Raw state/transfer | State at 1 tps over ten years |
|---|---|---|
| Ciphertexts in state (today) | 4.1 to 4.3 KB | about 1.7 TB, unprunable |
| Bodies; state keeps commitments and nullifiers | 600 to 750 B | about 100 GB pruned plus a 90-day body window |

About 8 to 9x. Both reviews refuted operator-first's 15x, and the disk multiplier is
unmeasured.

Cost: archive nodes carry older history, and every wallet gains a body fetch per settlement
block, a capability probe, and a named failure below the retention watermark.

Leaks: a small concentration of history on archive nodes. Authentication holds, since
`extrinsicsRoot` sits in the header preimage beside `stateRoot` and a body checked against it
is complete by construction.

`UsedNullifiers` still grows 32 bytes per spent note forever, and truncating that key to 16
bytes is refused, because padding-slot nullifiers are prover-chosen and grindable.

Dissent: ship-first would keep ciphertexts in state because M13 roughly doubles. The systems
review finds that overstated, since the extrinsic decoder already exists and the binding
adopted here removes the replay ship-first objects to.

### 12.4 Q4, block size

**Decision: keep 5 MiB and the 6 s `ref_time` at genesis. No dynamic rule before genesis.
Spend the pre-genesis effort on the two weight levers.**

| Lever | Effect on the 1.578 s batch |
|---|---|
| Stop charging `ct_digest` twice | to about 1.22 s, a 1.3x gain |
| Re-measure `POSEIDON_EVAL_REF_TIME_PS` (10 us ceiling, 3.3 us native) | multiplier on the 0.723 s term |
| Raise `RuntimeBlockLength` alone | zero, because weight co-binds |

The double charge is a soundness question first: a general-format extrinsic reaches dispatch
with no origin and no `pre_dispatch`, so `ensure_none` does not establish that validation ran,
and caching the digest needs an answer to that.

Cost of deferring: the fee floor is close to free, so a funded party can fill 7.5 tps cheaply.
Forecloses nothing, since a later penalised reward stretches emission with no supply lost.

A later dynamic rule must carry a quadratic penalty under a hard ceiling with a reward floor,
a long-term median beside the short one (the short median alone is the big-bang attack), a
median floor clearing one full batch extrinsic plus the coinbase inherent, and stated integer
rounding with a KAT per boundary case.

Dissent: privacy-first wanted 8 MiB now, operator-first wanted the median pre-genesis, and
both reviews refuted the load-bearing number under each.

### 12.5 Q5, tree depth

**Decision: raise the circuit depth constant from 16 to 20 before genesis, gated on one
build. Keep 16 if that build moves the leaf circuit off `degree_bits = 9`.**

| Item | Depth 16 | Depth 20 |
|---|---|---|
| Capacity (4-ary) | 4.29e9 leaves | 1.10e12 leaves |
| Leaf gates in 512 padded rows | 320 | 344 to 416 |
| `degree_bits` | 9 | 9, subject to measurement |
| Proof bytes, leaf / private / public | 105 500 / 150 908 / 237 544 | unchanged |
| `FINALIZE_BASE_POSEIDON_EVALS`, frontier digests | 19, 48 | 23, 60 (+384 B) |

Exhaustion is a chain halt, because `insert_commitment` refuses an append past capacity.
Raising the cap changes no existing root: depth grows lazily and the circuit selects active
levels. The constants are `qnero_circuit::chain::MAX_TREE_DEPTH` and
`pallet_zk_tree::CIRCUIT_MAX_TREE_DEPTH`; the pallet's `MAX_TREE_DEPTH` is 32 already.

Cost: regenerated verifier artifacts and KATs, shared with the bundle. Forecloses nothing.

Dissent: ship-first proposed 18, arguing every prover pays the extra levels forever. The leaf
pads to 512 rows either way, so 18 and 20 cost the same in practice.

### 12.6 Q6, wallet scanning

**Decision: a browser wallet is a full-scan wallet to about 1 tps of chain and no further.
No view tag. No detection keys. State both in `docs/WALLET.md` as designed limits.**

| Chain rate | Ciphertext bytes per day | Browser feasible |
|---|---|---|
| 1 tps | about 310 MB | yes, about 13 MB an hour |
| 10 tps | about 3.1 GB | no |
| 50 tps | about 15.5 GB | no |

A view tag is structurally unavailable: FIPS 203 decapsulation returns a pseudorandom secret
on any input and cannot fail early, so any tag checkable beforehand derives from the
recipient's public address and becomes a public label on every payment to it. Detection keys
are declined because their ambiguity degrades with observations.

Wallet work, all leak-free: the coarse public epoch birthday (an exact birthday is a
fingerprint across syncs), the checkpointed frontier, the worker-pool scan with pipelined
windows, the change-commitment match, and skipping coinbase leaves, which carry no payload.

Cost: up to about 1.9 GB of one-time rescan at a 1 048 576-leaf epoch, and both wallets must
agree that constant. Forecloses nothing, while a detection key handed to a server once is a
key that server keeps.

### 12.7 Q7, the order of work

### Step 0, measure first

1. ML-KEM-1024 decapsulation, native and wasm. Every Q6 number is parametric on it and
   `docs/BENCH.md` names it unmeasured twice.
2. The leaf circuit rebuilt at depth 20, gates and `degree_bits` read out. This gates Q5.
3. Real trie and RocksDB overhead per transfer, the multiplier under every state table, plus
   `state_getReadProof` bytes per key at a page of 64 and its wasm verify time.

### Step 1, the pre-genesis consensus bundle, one spec bump

One `spec_version` bump, one artifact regeneration, one KAT pass, one review. Each item is a
constant today and a hard fork after genesis.

1. Q5, circuit depth 16 to 20, gated on the depth-20 build.
2. Q3, ciphertexts out of state into bodies, with the settlement and weight changes.
3. `CiphertextRetentionBlocks = 0` plus the no-op prune branch, so the constant is in
   metadata at genesis and both wallets implement "absent below the retention window is
   expected" before it is ever non-zero. Taken whichever way Q3 goes.
4. Q1, the per-suite exact-length settlement rule.
5. RandomX seed lag 64 to 128 (open question 3, already flagged for decision before launch).
6. The call filter moved from dispatch to a `TransactionExtension` (section 7.2), since a
   mistaken transparent transfer today fails with `CallFiltered` and leaves sender, recipient
   and amount in the body forever. It moves `transaction_version`.
7. Q2 recorded as closed. No code.

Refused, with the refusal written into section 9 as a decision:

- **Open question 7, the positional level-tagged tree hash.** It ends the claim that the
  tree is the audited upstream's as-is, which section 10 rests on, and M13 closes the same
  three holes with no consensus change. Dissent: operator-first argues the per-sync saving is
  permanent while read proofs are paid forever, and the systems review calls that the better
  argument on the merits.
- **Any block size change and the dynamic rule** (12.4).
- **Nullifier key truncation** (12.3).

### Step 2, wallet-only, on wallet cadence

The coarse-epoch birthday constant, the checkpointed frontier, the worker-pool scan, the
change-commitment match, the retention-aware absence rule, coinbase-leaf skipping, the scan
benchmark in `docs/BENCH.md`, and the `docs/WALLET.md` statements on the view-key and 1 tps
limits.

### Step 3, how M13 changes (open question 6)

M13 today reads every per-leaf storage value with `state_getReadProof` against the header
`stateRoot`. Under Q3 it splits in two against that same header, and open question 6 is
rewritten to say ciphertexts are no longer state.

**Part one, against `stateRoot`, unchanged:** `ZkTree::LeafCount`, `ZkTree::Leaves(i)`,
`Shielded::LeafBlocks(i)`, `Shielded::CoinbaseValues(i)`, `Shielded::EntryCount` and the
`UsedNullifiers` pages, so the `sp-trie` wasm module and its size cost stay.

**Part two, against `extrinsicsRoot`, new:** fetch the body, recompute the root against the
already-authenticated header, hand-walk the extrinsic envelope (the typed decode fails on the
7219-byte ML-DSA-87 signature array), then parse the public inputs with the pallet's
parse-without-verify path. The 14.1 ms per-settlement verify open
question 6 prices against this route does not apply, because the wallet needs the public
inputs and the chain has already verified the proof.

**Binding:** decrypt an output, derive the note, compute the commitment, and require it at a
proven leaf index inside that block's folded leaf range. A moved, substituted or withheld
ciphertext fails that test, and no append-order replay is needed.

**Scope: roughly flat.** One trie proof page per ciphertext gives way to one body fetch per
settlement block a scanning wallet would make anyway. Added: the commitment search, a
capability probe, a retention-watermark failure, and an adversarial test matrix. All three
bounds M13 closes, position, depth and ciphertext binding, still close.
