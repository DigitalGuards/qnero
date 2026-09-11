# Qnero v0 spend circuit (M2)

Status: implemented and tested, 2026-09-11. Crates: `qnero-circuit`,
`qnero-prover`, `qnero-verifier`. Forked from Quantus-Network/qp-zk-circuits
(MIT); each crate carries a NOTICE and a CHANGES.md.

One leaf is one shielded transfer: up to two input notes, exactly two output
notes, a public fee, and a digest that binds the output ciphertexts. M3 wraps
leaves in a private batch, which is the layer that provides zero knowledge and
the on-chain transaction unit. M4 consumes this layout in `pallet-shielded`.

Field: Goldilocks. Hash: Poseidon2 (`qp-poseidon-core` off circuit,
`hash_n_to_hash_no_pad_p2::<Poseidon2Hash>` in circuit, the same sponge).
Proof system: Plonky2, `standard_recursion_config`, `D = 2`.

## 1. Public inputs

26 field elements, in this order. The order is positional and is registered in
one place, `SpendTargets::new`; the indices are constants in
`qnero_circuit::layout`, which is the only definition of them. `qnero-verifier`
reads proofs through those same constants, and a test asserts the built
circuit's `num_public_inputs` against `PUBLIC_INPUT_LEN`.

| index | felts | name | meaning |
|---|---|---|---|
| 0..4 | 4 | `block_hash` | Poseidon2 of the block header preimage |
| 4 | 1 | `block_number` | height of that block, 32 bits |
| 5..9 | 4 | `nf_1` | nullifier of input note 1 |
| 9..13 | 4 | `nf_2` | nullifier of input note 2 |
| 13..17 | 4 | `cm_out_1` | commitment of output note 1 |
| 17..21 | 4 | `cm_out_2` | commitment of output note 2 |
| 21 | 1 | `fee` | public fee, 62 bits |
| 22..26 | 4 | `ct_digest` | digest of the output ciphertexts, see below |

This is the layout `docs/DESIGN.md` section 6 specified, with no deviation.

What the chain does with it, at M4: check that `block_hash` is the hash of the
block at `block_number`; check that neither nullifier is in `UsedNullifiers`
and insert both; append `cm_out_1` and `cm_out_2` to the commitment tree;
recompute the digest of the ciphertexts in the extrinsic and compare it to
`ct_digest`; account the fee.

`ct_digest` is deliberately unconstrained inside the circuit. Hashing
kilobytes of ML-KEM and AEAD ciphertext in circuit would dominate the proof;
the chain recomputes the digest from the bytes it was handed and compares.

That comparison binds the ciphertexts only while the rule is unambiguous, so
the rule is fixed here and implemented once, in `qnero_notes::ct_digest`, which
both the wallet and `pallet-shielded` call:

```text
ct_digest = H_bytes("qnero/ct" || u32_le(count)
                    || u32_le(len_1) || ct_1 || ... || u32_le(len_n) || ct_n)
```

`H_bytes` is the byte-mode Poseidon2 sponge, with the ASCII prefix as the
domain separator the way `H("qnero/ask", sk)` uses one; `ct_digest` is never
recomputed in circuit, so it does not need the field-mode tag. `ct_i` is
`NoteCiphertext::to_bytes`, in output order, so `ct_1` belongs to `cm_out_1`.

The count and the per-ciphertext lengths are what make it injective. A
`NoteCiphertext` is an ML-KEM ciphertext plus two variable-length AEAD
payloads, so a bare concatenation would let two different output pairs share a
preimage; a relayer could then swap the ciphertexts attached to a settled leaf
for a colliding pair, pass the chain's comparison, and leave the recipient
unable to decrypt a note whose commitment is already in the tree.

## 2. Private witness

Per input note, twice:

- `ask` (4 felts), `nk` (4 felts): the spend credential.
- `value` (1), `rho` (4), `r` (4): the note.
- a Merkle path: 16 levels of 3 sibling digests plus a position hint per level.
- `is_dummy` (1 bit).

Per output note, twice: `pk` (4), `value` (1), `r` (4). Its `rho` is derived
in circuit, see section 3.

Plus the header preimage (`parent_hash`, `state_root`, `extrinsics_root`,
`zk_tree_root`, 28 felts of digest logs) and one `depth` shared by both paths.

`pk` is never witnessed for an input. It is derived in circuit from `ask` and
`nk`, so a wrong credential produces a commitment that is not in the tree.
Witnessing `pk` and constraining it to equal the derived value is equivalent
and costs one more equality. An output's `rho` is likewise derived, for a
different reason: see section 3.

## 3. Hash rules

All of these are `qnero-notes`, reused verbatim: the circuit imports the domain
constants from that crate so the two cannot drift, and a parity test compares
what the circuit publishes against `Note::commitment` and `Note::nullifier`
for the same witness.

```text
ak        = H(AK,       ask)
pk        = H(PK,       ak, nk)
inner     = H(NOTE,     pk, rho, r)
cm        = H(CM,       inner, value)
nf        = H(NF,       nk, rho, r)          real input slot
nf_dummy  = H(NF_DUMMY, nk, rho, r)          padding input slot
rho_out_j = H(RHO,      nf_1, nf_2, j)
```

`H(tag, parts...)` is Poseidon2 over the concatenation with the one-felt domain
tag first. `value` is a single field element over its full 62-bit range, not
the two 32-bit limbs the Wormhole leaf uses for a `u64`.

**The nullifier binds `r` as well as `(nk, rho)`.** Every output note's `rho` is
a public function of the leaf that created it, so the candidate `rho` set for
the whole chain is public data. Were the nullifier `H(NF, nk, rho)`, a holder
of `nk` alone could hash it against every published `rho` and recover exactly
which notes that wallet spent and which leaf minted each one, with no incoming
viewing key, no ML-KEM decapsulation key and no ciphertext. `r` is known only
to a note's sender and its holder, which is the role Orchard gives `psi`. So
`nk` grants spend **detection** for notes a wallet can already see, and never
pool-wide linkability or the ability to compute someone's nullifier from
public data.

**A dummy input slot's nullifier is domain separated.** A dummy proves no
membership and carries no `ask`, so whatever it publishes is unauthenticated by
construction: the circuit computes it from two free witness targets. Under the
real tag that is a burn primitive. An attacker holding a victim's `nk` and the
victim note's `(rho, r)` could put them in a dummy slot of a leaf of their own,
the chain would settle the victim's nullifier for a note nobody spent, and the
note would be permanently unspendable at the cost of one leaf. `NF_DUMMY` puts
every dummy slot's value outside the image of the real nullifier function, so
no leaf can settle a real note's nullifier without the membership proof and the
spend credential that go with it. A dummy nullifier is still a uniform 4-felt
Poseidon2 output, so which slots were real stays invisible in the public
inputs, and the chain still settles both without telling them apart.

**An output's `rho` is derived by the circuit.**
`rho_out_j = H(RHO, nf_1, nf_2, j)` over both nullifiers the leaf publishes and
the output index. A sender who could pick `rho` freely could grief a recipient:
`nf` does not depend on the note's value, and a sender picks `rho` and `r` for
a note it creates, so paying one recipient twice with one pair creates two
notes that share a nullifier, of which the recipient can spend exactly one, and
the other is stranded permanently. Constraint 5 catches that only inside a
single leaf, and the chain's used-nullifier set catches it only after the
victim has spent one of the two. Deriving `rho` removes the choice. This is the
same binding Sapling and Orchard make between an output's `rho` and a spent
nullifier.

Both nullifiers are in the preimage because either slot may hold the dummy:
constraint 9 only forbids both slots being dummies. Constraint 9 guarantees at
least one input is real, a real note's nullifier is settled exactly once over
the life of the chain because the chain must refuse a repeat to stop double
spends, so the pair `(nf_1, nf_2)` can never repeat whichever slot is real.
Deriving from slot 0 alone would rest the whole uniqueness argument on a
prover-chosen value in every leaf whose slot 0 is a dummy.

The header hash keeps the chain's preimage order:

```text
block_hash = Poseidon2(parent_hash(4) || block_number(1) || state_root(4)
                       || extrinsics_root(4) || zk_tree_root(4) || digest(28))
```

The four 32-byte fields in that preimage are not decoded the same way, and the
asymmetry is the chain's. `parent_hash` is a previous block hash and
`zk_tree_root` is a Poseidon2 node hash, so both are four canonical Goldilocks
limbs and `HeaderInputs::new` takes them as validated `Digest` values.
`state_root` and `extrinsics_root` are Blake2-256 outputs, which are not field
elements at all: roughly one header in 500 million has a limb at or above the
modulus. The chain hashes those two through the reducing 8-bytes-per-felt
decode, making `block_hash` a lossy commitment to them, so `HeaderInputs::new`
takes them as raw `[u8; 32]` and reduces them identically. Validating them
instead would leave a wallet unable to prove any spend anchored at such a
block, with an error naming a hash the chain considers perfectly valid.

## 4. Leaf hash rule (the M4 contract)

**A commitment tree leaf is the note commitment itself. `leaf_hash = cm`.**

`cm` is a Poseidon2 output: four canonical Goldilocks limbs, 32 bytes little
endian per limb, exactly the `Hash256` the 4-ary tree hashes. So the circuit
feeds its computed `cm` straight into level 0 of the path, and there is no leaf
preimage to reconstruct in circuit.

Internal nodes keep the pallet's rule unchanged:

- sort the four children by their 32 bytes, lexicographically;
- concatenate to 128 bytes, decode at 8 bytes per field element (16 felts);
- `parent = Poseidon2(those 16 felts)`, no domain tag;
- a missing child is the all-zero digest.

Sorting is what removes path indices from stored proofs. The circuit never
sorts: the prover supplies the sorted siblings plus a 2-bit position hint per
level, and a lie about the position simply yields a different root. A test
covers exactly that.

`qnero_circuit::merkle::CommitmentTree` is the off-circuit mirror of this rule
and is what the tests build paths with.

The wallet-side half of the rule is the path adapter. `generate_proof` returns
`ZkMerkleProof { leaf_index, siblings }`, where each level's three siblings are
in child-index order and no position is recorded, because the node rule sorts
its children anyway. The circuit wants the opposite: siblings already sorted,
plus the slot the running hash occupies. `MerklePath::from_unsorted(siblings,
leaf)` is that conversion, and it is what a wallet calls on a proof it fetched
from the chain. Feeding chain-ordered siblings straight into `MerklePath`
produces a path whose root is not `zk_tree_root`, and the leaf then fails to
prove with nothing to point at. `CommitmentTree::index_ordered_siblings`
reproduces the chain's shape so the adapter is covered by a test.

### What `pallet-zk-tree` must change at M4

Today `Leaves` is `StorageMap<_, Identity, u64, ZkLeaf<AccountId, AssetId,
Balance>>` and `get_leaf_hash` always recomputes `hash_leaf` from those four
typed fields. There is no slot for a raw hash. The entry points into that typed
leaf are `insert_leaf(to, transfer_count, asset_id, amount)`, the public trait
`ZkTreeRecorder::record_transfer` with the same four arguments (which is what
`pallet-wormhole` actually calls), the `Pallet::leaf` storage getter, and the
runtime API `ZkTreeApi::get_merkle_proof`, which calls `tree::hash_leaf`
directly to fill `ZkMerkleProofRpc`.

The fork is small and mechanical:

1. `Leaves` becomes `StorageMap<_, Identity, u64, Hash256>`.
2. `get_leaf_hash` becomes the identity read (missing leaf stays `empty_hash`).
3. `insert_leaf` becomes `insert_leaf(commitment: Hash256)`. It must reject
   two things. A non-canonical commitment (any limb at or above the Goldilocks
   modulus), because the 8-bytes-per-felt decode reduces mod p and a
   non-canonical alias would commit to the same tree position as a genuine
   commitment. And the all-zero digest, because that is `empty_hash()`, the
   absence sentinel the pallet returns for a missing leaf and for an empty
   subtree at every level; once `hash_leaf`'s domain separation is dropped, a
   zero leaf is indistinguishable from an unset slot. Nothing can produce a
   zero commitment today, since every `cm` is a Poseidon2 output, so this is a
   guard against a later entry point (a migration, a genesis import, a bridge
   deposit) that accepts a caller-supplied `Hash256`. Cover it with a test that
   `insert_leaf([0u8; 32])` errors.
4. `hash_leaf` and `canonicalize_account_bytes` are dropped, and with them the
   non-injective-encoding invariant they carried.
5. `tree::verify_proof` becomes
   `verify_proof(leaf_hash: Hash256, proof: &ZkMerkleProof, expected_root:
   Hash256) -> bool`, and the public wrapper `Pallet::verify_proof` follows.
   Both take a `ZkLeaf` today and call `hash_leaf` on it, so they are the one
   pair of signatures in this list that has to change.
6. `ZkTreeRecorder::record_transfer` becomes `record_transfer(commitment:
   Hash256) -> u64`, or the trait goes away entirely. `pallet-shielded` appends
   commitments itself, and the other callers (mining rewards, vesting,
   reversible transfers) go through `TransferProofRecorder`. Leaving the
   four-argument signature in place would leave a second path into the tree
   that still builds a typed leaf.
7. `Pallet::leaf` now returns `Hash256`. `ZkTreeApi::get_merkle_proof` in
   `runtime/src/apis.rs` reads that stored commitment directly and its
   `hash_leaf` call goes away, with `ZkMerkleProofRpc::leaf_data` either
   dropped or set to the commitment bytes. Missing this one is how the fork
   ships an RPC whose `leaf_hash` is no longer what the tree stores.
8. `process_pending_leaves` must clamp growth at `CIRCUIT_MAX_TREE_DEPTH`, and
   the settlement extrinsic must reject an append that would pass
   `capacity_at_depth(CIRCUIT_MAX_TREE_DEPTH)`. Today the loop is `while
   capacity_at_depth(depth) < leaf_count { depth += 1 }` with only a
   `debug_assert` against `MAX_TREE_DEPTH = 32`, so a release runtime silently
   grows to depth 17 once the pool passes 4^16 leaves. At that point every
   existing note needs a 17-level path, which both `SpendWitness::validate` and
   the in-circuit depth bound reject, and the whole pool becomes unspendable
   with no error from the chain and no migration path. The circuit is what caps
   the tree and the pallet does not know it. Cover it with a test that an
   insert past capacity errors and leaves the depth where it was.
9. `tree::hash_node`, `update_range`, `grow_tree`, `generate_proof`, the
   `Nodes` map and the `on_finalize` root publication are unchanged. They reach
   a leaf only through `get_leaf_hash`, whose body changes and whose signature
   does not.

Two properties of the pallet that the wallet must respect and that do not
change: a leaf appended in block N is only provable after that block's
`on_finalize`, so a note cannot be minted and spent in the same block; and
`CIRCUIT_MAX_TREE_DEPTH` must stay equal to the circuit's `MAX_DEPTH`, which
item 8 above is what actually enforces.

One obligation the circuit places on `pallet-shielded`: **settle both published
nullifiers of every leaf.** A dummy input slot publishes a nullifier like a
real one, by design, so the chain cannot tell them apart and must not try. Both
values are needed for double-spend safety: a note spent from slot 1 is marked
used only if slot 1's nullifier is settled. Uniqueness of the derived output
`rho` does **not** depend on this, since `rho_out_j` is derived from both
nullifiers and at least one of them belongs to a real note (section 3).

The same obligation reaches the pallet through M3, so section 8 states it as a
forwarding contract on the batch wrapper as well. A wrapper that forwards one
nullifier per leaf, which is the shape upstream's private batch has, drops
every leaf's `nf_2` before the pallet ever sees it.

### Why not pack a commitment into the existing typed leaf

The four typed fields are 4 + 2 + 1 + 1 felts, and the last four of those are
range-checked to 32 bits in circuit while `asset_id` and `amount` are narrowed
and quantized on chain. Packing a 4-limb commitment through them would lose
most of two limbs' entropy. Storing the hash directly is both simpler and
lossless.

### Leaf and node domain separation

A leaf preimage is 6 field elements beginning with the `CM` domain tag; an
internal node preimage is 16 field elements beginning with a child limb. The
lengths differ, so their sponge padding differs, and the tag is not a value a
child limb takes by accident. Passing an internal node off as a leaf would
additionally require a note whose `cm` equals that node, which is a preimage
attack on Poseidon2.

## 5. Constraints

1. `block_hash == Poseidon2(header preimage)`, and `block_number < 2^32`. The
   binding is unconditional. This is the whole security chain: public
   `block_hash` commits to the header, the header carries `zk_tree_root`, and
   each input's path reaches that root.
2. `depth <= MAX_DEPTH`. The value is decomposed into bits exactly once, by
   `split_le`, which is also what range-constrains it; the same bits carry the
   bound and derive the 16 `level < depth` flags that both paths share.

   The `MAX_DEPTH` comparison is defensive, and it rejects no witness that the
   level flags would otherwise accept. `split_le` over `DEPTH_BITS` already
   pins `depth` below 32, and the flags only ask `level < depth` for levels
   `0..MAX_DEPTH`, so every depth in `MAX_DEPTH..32` produces the same all-true
   flags as `MAX_DEPTH` itself. What bounds the tree today is the flag
   derivation. The comparison is kept so that a later change to that
   derivation, or anything that indexes by `depth`, cannot silently inherit an
   unbounded value.
3. Per input: `pk = H(PK, H(AK, ask), nk)`, `cm = H(CM, H(NOTE, pk, rho, r),
   value)`, the path from `cm` reaches `zk_tree_root`, and a nullifier over
   `(nk, rho, r)` is published. The root equality is gated:
   `(root_limb - zk_tree_root_limb) * (1 - is_dummy) == 0`. The nullifier's
   domain tag is selected in circuit by the same bit: `NF` for a real slot,
   `NF_DUMMY` for a dummy, so a slot that proves no membership can never
   publish a value in the image of the real nullifier function. See section 3
   for both properties.
4. Per input: `value * is_dummy == 0`, and `value < 2^62`.
5. `nf_1 != nf_2`. Equal nullifiers would be the same note spent twice inside
   one leaf, which a chain that inserts both nullifiers from one transaction
   without intra-transaction dedup would not catch. This is an addition over
   the Wormhole leaf, which has a single nullifier.
6. Per output: `rho = H(RHO, nf_1, nf_2, j)` derived from both published
   nullifiers and the output index, `cm_out = H(CM, H(NOTE, pk, rho, r),
   value)` bound to the public commitment, and `value < 2^62`. See section 3
   for why `rho` is derived here and why both nullifiers are in it.
7. `fee < 2^62`.
8. `v_in_1 + v_in_2 == v_out_1 + v_out_2 + fee`, as a field equation. Every
   term is below `2^62`, so the left side is below `2^63` and the right side
   below `3 * 2^62`, both below `p = 2^64 - 2^32 + 1`, and their difference is
   smaller than `p`. Equality in the field is therefore equality over the
   integers: no wraparound can fake a balance. This is why the fee is range
   checked at all, and why the two-input shape cannot be widened to four inputs
   at 62 bits without redoing the argument.
9. At least one input is real: the product of the `is_dummy` bits is zero.
   Nothing else relates the two bits. With both set, a leaf proves with no
   spend key and no note in the tree: every membership check is switched off,
   both values are forced to zero by constraint 4, so the balance holds at zero
   out and zero fee, constraint 5 is met by giving the two dummies different
   `rho`, and the header can be any real block, whose preimage is public chain
   data. That leaf would still publish two nullifiers and two output
   commitments, which the chain writes into permanent state: two entries in the
   nullifier set and two slots of a depth-16 tree sized for the life of the
   chain. Settlement extrinsics are unsigned and fee-free in the pallet this
   forks, so the leaf's own `fee` public input is the only cost, and an
   all-dummy leaf sets it to zero.

   What the constraint achieves is exactly this: every leaf must consume a note
   already in the tree, under a spend credential the prover holds, so a leaf
   cannot be produced with no key and no note at all. It is **not** a bound on
   how many leaves a prover can produce. A leaf consumes at most two notes and
   always mints two, so one real input of any value, including zero, plus a
   dummy leaves the prover with one more spendable note than they started with.
   The minimum fee per non-padding leaf in section 8 is the anti-spam
   mechanism, and it is the only one.

### Dummy inputs

`is_dummy` is a witnessed bit. The circuit does not derive it from the public
inputs the way the Wormhole leaf derives its dummy-leaf sentinel. Setting it
forces the input's value to zero, skips the membership check, and swaps the
nullifier's domain tag to `NF_DUMMY`. The nullifier is still computed from the
witnessed `(nk, rho, r)` and published, and it is still a uniform Poseidon2
output, so a dummy slot is invisible in the public inputs. Claiming `is_dummy`
for a note one does own gains nothing: the value is zeroed, so the spender only
loses the note's value from the balance.

The wallet must give every dummy a fresh `(rho, r)`, both because two dummies
with the same pair would collide under constraint 5, and because a repeated
dummy nullifier would be rejected on chain as already used.
`InputNote::dummy_random` is the constructor that draws them, and it is the one
a wallet should call; `InputNote::dummy` takes them from the caller and leaves
freshness to it.

This is a different mechanism from the Wormhole leaf's dummy, which marks a
whole leaf as padding for the batch and makes the header binding conditional on
an in-circuit sentinel. Qnero's leaf is always a real leaf.

## 6. Measured size

`cargo test -p qnero-prover --release -- --ignored --nocapture`, on the
development workstation, single threaded (plonky2's `parallel` feature is off
so a prover cannot saturate a machine unasked):

```
gates before padding : 319
degree_bits          : 9
public inputs        : 26
zero knowledge       : false
build                : 61 ms
prove, mean of 9     : 195 ms
prove, min           : 138 ms
prove, median        : 178 ms
prove, max           : 300 ms
verify               : 2.3 ms
proof bytes          : 105500
```

Proving time is a mean over nine proofs, and the spread is the measurement, so
a single warm number would be misleading. The FRI challenge carries 16 grinding
bits and the search for them is a geometric random variable seeded by the
transcript, which dominates a circuit this small: the nine samples above prove
the identical constraint system over witnesses that differ only in `ct_digest`,
a public input the circuit does not constrain, and they range from 138 ms to
300 ms. Comparing one warm number against another across a circuit change
measures grinding luck. Compare means, over the same sample count.

The gate count is dominated by the two Merkle paths: 16 levels each, evaluated
unconditionally so the cost does not leak the tree's real depth, at three
Poseidon2 permutations per level. Proof size is a property of the FRI config, so it
barely moves with this circuit's size, and it is the number the private batch
amortizes.

## 7. Zero knowledge

The leaf is non-ZK, exactly as the Wormhole leaf is. A leaf proof is an input
to the wallet's own private-batch aggregator and must never cross a trust
boundary: `standard_recursion_config` does not blind, so the proof bytes leak
witness structure. Privacy is applied one layer up.

The plumbing for a ZK leaf is kept: `qnero_leaf_zk_circuit_config()` returns
the row-blinding config, and `QneroSpendCircuit::new` accepts it. Plonky2
compiles its blinding randomness out by default, so a ZK config is rejected
with a clear error unless `qnero-circuit`'s `zk` feature is on.

## 8. What M3 and M4 still have to decide

- **Per-leaf forwarding contract for the batch wrapper.** Every non-padding
  slot's two nullifiers, two output commitments, fee and `ct_digest` must reach
  the aggregated public inputs, and the wrapper must constrain all `2N` real
  nullifiers pairwise distinct. This is the one place a mechanical fork of
  upstream's private batch goes wrong quietly. Upstream's leaf has a single
  nullifier, so its wrapper carries `nullifiers_count(N) = N` and an aggregated
  layout of one nullifier per leaf; the visibly required edits when porting are
  the leaf-side constants (`LEAF_PI_LEN` 22 to 26, `NULLIFIER_START` 4 to 5),
  and making only those drops every leaf's `nf_2` at the batch boundary. A note
  spent from input slot 1 would then never be marked used and could be spent
  again without limit. Upstream also constrains only `N` nullifiers pairwise
  distinct; at two per leaf that has to become `2N`, or one leaf proof replayed
  across slots aggregates twice against a single settled nullifier. Sizing, so
  the fork is known to fit: at `N = 7` the wrapper needs 5 shared felts
  (`block_hash` 4, `block_number` 1) plus 21 per leaf (two nullifiers, two
  commitments, fee, `ct_digest`), against the `26 * 7 + 8 = 190` that
  upstream's `pi_len()` formula yields at 26 felts per leaf.
- **Batch padding sentinel.** A private batch of N leaves needs dummy leaves
  when fewer than N real ones are available. The Wormhole wrapper recognises a
  dummy by an all-zero `block_hash` and re-masks every field it reads from a
  dummy slot, because the leaf's sentinel did not cover the exit accounts. The
  recommended Qnero shape is a fixed dummy header preimage whose `block_hash`
  is a known constant: it is derived in circuit from public inputs the wrapper
  already reads, it cannot be claimed by a leaf that also binds to a real
  block, and the wrapper must still mask the commitments, nullifiers and fee of
  a dummy slot, trusting no invariant that crosses a circuit boundary.
  Constraint 9 has to be gated on that same sentinel: a padding leaf has no
  real input, so it must stay provable, while every leaf whose `block_hash`
  binds a real block must spend something.
- **Minimum fee per non-padding leaf.** This is the anti-spam mechanism, and
  after the correction to constraint 9 it is the only one. A leaf consumes at
  most two notes and always mints two, so requiring a real input does not bound
  how many leaves a prover can produce: one note of any value, including zero,
  spent with a dummy in the other slot, yields two spendable notes and can be
  repeated every block. Each repetition writes two nullifier entries and two
  commitment slots into permanent state, and settlement extrinsics are fee-free
  in the pallet this forks, so `fee` is the only cost and nothing currently
  bounds it below. Either the circuit enforces `MIN_LEAF_FEE <= fee` next to
  constraint 9, gated on the same padding sentinel and using the comparison
  gadget already present, or `pallet-shielded` rejects a settlement extrinsic
  whose per-leaf fee is below a floor and charges the submitter for the
  commitment slots consumed. Until one of the two lands, constraint 9 only
  stops a prover who holds no notes at all.
- **Verifier artifact pinning.** `qnero-verifier` loads verifier data from
  bytes behind a size cap and a parameter floor: public-input count,
  `security_bits`, `num_challenges`, FRI query rounds, grinding bits, rate,
  cap height and the leaf's degree, all pinned to `qnero_circuit::params`,
  which the circuit crate tests against the config the prover builds with. That
  floor is what stops an artifact built over this same layout with one query
  round from verifying forged proofs; plonky2's own check on deserialized
  config rejects only a zero challenge count, a zero constant count and fewer
  than three routed wires. Provenance is a separate question. The keccak pin on
  the artifact bytes still needs a tagged circuit release to pin, and every
  circuit change after that invalidates it.
- **Pallet-side `ct_digest` recomputation.** The rule is fixed (section 1) and
  implemented once in `qnero_notes::ct_digest`. What M4 owes is the call:
  recompute the digest over the ciphertexts in the settlement extrinsic, in
  output order, and reject the leaf when it differs from the public input.
  Without that call the ciphertexts are attached to a proof that says nothing
  about them.
- **Coinbase and deposit range checks.** Every value that enters the pool
  outside a spend must be range checked to 62 bits by the pallet, or the
  balance argument in constraint 8 does not hold for notes created that way.
- **Nullifier seed uniqueness outside a spend.** Inside a spend this is
  settled: `rho_out_j = H(RHO, nf_1, nf_2, j)` is derived in circuit, so a
  sender has no choice to abuse (section 3). Every other path that creates a note still
  has to pick one. A deposit or a coinbase note has no spent nullifier to
  derive from, so M4 must give those a rule of their own, for example a
  per-block counter or the deposit's own unique identifier, and must reject a
  repeat. The recipient is the last line: a wallet should refuse a received
  note whose nullifier duplicates one it already holds or one already settled.
- **Witness zeroization.** `ask` and `nk` live in plain `Digest` values inside
  `InputNote`, protected only by redacting `Debug`, and `DerivedKeys` is
  `Copy`. Upstream wraps the equivalent material in a zeroize-on-drop
  container. Worth doing before a wallet holds real keys. `nk` is a viewing-tier
  secret: with `r` in the nullifier preimage it confers spend detection for
  notes the holder can already see, and nothing beyond that (section 3).
