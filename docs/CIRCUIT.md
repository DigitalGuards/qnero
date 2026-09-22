# Qnero v0 spend circuit (M2) and batch aggregation (M3)

Sections 1 to 8 are the circuits, section 9 is the M4 settlement contract as
built, and section 10 is the M6 coinbase record.

Status: implemented and tested, 2026-09-11. Crates: `qnero-circuit`,
`qnero-prover`, `qnero-verifier`, `qnero-aggregator`, `qnero-circuit-builder`.
Forked from Quantus-Network/qp-zk-circuits (MIT); each crate carries a NOTICE
and a CHANGES.md.

One leaf is one shielded transfer: up to two input notes, exactly two output
notes, a public fee, and a digest that binds the output ciphertexts. M3 wraps
`N` leaves in a private batch, which is the layer that provides zero knowledge
and the on-chain transaction unit, and wraps `n` private batches in a public
batch. Sections 1 to 7 are the leaf. Section 8 is the batch layers and the
rules M3 settled. M4 consumes both layouts in `pallet-shielded`.

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
the rule is fixed here and implemented once, in
`qnero_circuit::chain::ct_digest` (re-exported as `qnero_verifier::chain`),
which both the wallet and `pallet-shielded` call. It sits in the circuit
crate's layout-only surface, which compiles without the `circuit` feature, and
that is what lets a wasm runtime with no prover stack call the same function a
wallet does:

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
nf_pad    = H(NF_BATCH_PADDING, preimage)    padding slot of a private batch
```

`nf_pad` is the one rule in that list the leaf circuit never evaluates. The
private-batch wrapper emits it in place of a padding slot's leaf nullifiers,
over fresh randomness drawn per slot per proving run, so the chain settles
every published nullifier of a segment by one rule and a padding one is inert.
Section 8.4 is the rule; the tag is here because it shares the nullifier
namespace and must stay outside the image of both functions above.

The tags themselves: `AK = 0x716e_0001`, `PK = 0x716e_0002`,
`NOTE = 0x716e_0003`, `CM = 0x716e_0004`, `NF = 0x716e_0005`,
`RHO = 0x716e_0006`, `NF_DUMMY = 0x716e_0007`,
`NF_BATCH_PADDING = 0x716e_0008`. A note created outside a spend proof, a
shield at M4 and a coinbase at M6, takes the next free value: `0x716e_0009` is
`RHO_ENTRY`, section 9. Reusing `NF_BATCH_PADDING` for it would put a padding
slot's emitted nullifier and an entry note's `rho` in one image.

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

`digest(28)` is the SCALE-encoded digest **zero padded to 110 bytes**
(`DIGEST_LOGS_SIZE`, the same constant on both sides) and then encoded
injectively at 4 bytes per field element with a terminator, which is the 28
felts. The padding is not optional and it is not a detail: the chain hashes a
fixed-size window, so a wallet that feeds the encoded digest unpadded computes a
different `block_hash` and every settlement it builds is refused with
`BlockHashMismatch`. Bytes past the window are not committed at all, which is
why the import path refuses a header whose encoded digest is longer, and why
runtime code must never deposit a digest item.
`the_chain_header_hash_matches_the_circuits` in `pallet-shielded`'s tests is
the cross-crate check that `qp_header::Header::hash` and
`HeaderInputs::block_hash` agree, digest window included; nothing else holds
the two encodings together.

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

### What `pallet-zk-tree` changed at M4

Done, with three deviations from the list below, all three because the fork
keeps `pallet-wormhole` working beside the shielded pool on one tree instance.

Item 4 is partial. `hash_leaf` and `canonicalize_account_bytes` are still in
`tree.rs`, because a wormhole transfer leaf still has a typed preimage and
something has to hash it. What changed is where they sit in the flow:
`insert_leaf` hashes the typed leaf at insert time and stores the hash, so the
tree itself no longer knows the leaf type, and `get_leaf_hash` is the identity
read item 2 asks for.

Item 6 is additive. `ZkTreeRecorder::record_transfer` keeps its four arguments,
so the wormhole path is untouched, and a second trait `ZkCommitmentRecorder`
carries the shielded pool's door: `insert_commitment(Hash256) ->
Result<u64, DispatchError>`, `remaining_capacity()` and `leaf_count()`. The two
differ in more than their argument. A commitment is caller supplied and its
append is fallible in three ways (non-canonical, zero, past the depth the
circuit can prove), where a transfer leaf is built by the recorder itself and
cannot fail, and folding the fallible case into the existing signature would
have made every wormhole call site handle an error it cannot produce.

Item 3 is additive, for the same reason as item 6. `insert_leaf` keeps its four
typed arguments, because the wormhole path still builds a typed leaf and
something has to hash it, and `insert_commitment(Hash256)` is the raw-hash door
beside it. The two entry points differ by argument type and both stay, so there
is no typed path into the tree that a shielded commitment could take by
accident. The asymmetry the fork did not close is the
capacity check: `insert_commitment` refuses an append past
`capacity_at_depth(CIRCUIT_MAX_TREE_DEPTH)` and `insert_leaf` cannot, because
its caller's signature is infallible. Reaching that bound through wormhole
transfers alone needs 4^16 of them, and `process_pending_leaves` reports the
condition through `defensive!` if it ever happens.

Item 8 landed in two places, which is what the item asks for. The growth loop
clamps at `CIRCUIT_MAX_TREE_DEPTH`, and `insert_commitment` refuses an append
past `capacity_at_depth(CIRCUIT_MAX_TREE_DEPTH)` so the clamp is never reached;
`pallet-shielded` additionally checks that a whole batch fits before it writes
anything, because a settlement that ran out of capacity halfway would otherwise
depend on the dispatch layer's rollback to stay consistent.

Everything else is as listed.

**The `Leaves` type change is genesis only.** `pallet-zk-tree` now declares
storage version 1 and carries no migration. A chain holding v0 entries, which is
any Quantus chain and any Qnero devnet started before M4, cannot take this
runtime: every existing entry would fail to decode as `[u8; 32]`, and
`tree::get_leaf_hash` turns a decode failure into the absence sentinel, so the
fold would silently build a tree of empty hashes and publish a root that
disagrees with every root already in the chain's headers. Carrying v0 state
across needs a `MigrateV0ToV1` that rehashes each stored `ZkLeaf` through
`tree::hash_leaf`, or that refuses the upgrade outright.

The identity half of that problem is closed. M6 renamed the runtime: it is
`qnero` / `qnero-node` at `spec_version` 101 and `transaction_version` 7, so
the two runtimes no longer answer the same version triple, and the `spec_name`
change is itself what makes a `set_code` from an upstream `quantus-runtime` chain
impossible. For a storage layout that cannot be migrated in place that is the
intended outcome rather than a limitation.

The original list follows.

### The original list



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
nullifiers of every leaf of a non-padding batch segment.** A dummy input slot
publishes a nullifier like a real one, by design, so inside such a segment the
chain cannot tell them apart and must not try. Both values are needed for
double-spend safety: a note spent from slot 1 is marked used only if slot 1's
nullifier is settled. Section 8.6 says which segments are non-padding and why a
padding one settles nothing at all. Uniqueness of the derived output
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
9. At least one input is real, unless the leaf is batch padding: the product
   of the `is_dummy` bits times `1 - is_padding` is zero, where `is_padding` is
   `block_hash == PADDING_BLOCK_HASH` (section 8).
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

   What the constraint achieves is exactly this: every leaf that binds a real
   block must consume a note already in the tree, under a spend credential the
   prover holds, so such a leaf cannot be produced with no key and no note at
   all. The exemption is the padding leaf, which binds the one fixed padding
   header whose `zk_tree_root` is the empty tree, so it cannot be claimed by a
   leaf anchored at a real block, and section 8 covers what stops a padding
   leaf from settling anything. It is **not** a bound on
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
an in-circuit sentinel. A Qnero leaf is a real leaf unless it is the batch
padding leaf, and the header it binds is what decides which: see section 8.

## 6. Measured size

`cargo test -p qnero-prover --release -- --ignored --nocapture`, on the
development workstation, single threaded (plonky2's `parallel` feature is off
so a prover cannot saturate a machine unasked):

```
gates before padding : 320
degree_bits          : 9
public inputs        : 26
zero knowledge       : false
build                : 64 ms
prove, mean of 9     : 183 ms
prove, min           : 138 ms
prove, median        : 169 ms
prove, max           : 381 ms
verify               : 2.2 ms
proof bytes          : 105500
```

M3 added one gate: the padding sentinel is a four-limb comparison against a
constant and a single multiplication, and at 60 routed wires an arithmetic gate
packs fifteen of those operations.

Proving time is a mean over nine proofs, and the spread is the measurement, so
a single warm number would be misleading. The FRI challenge carries 16 grinding
bits and the search for them is a geometric random variable seeded by the
transcript, which dominates a circuit this small: the nine samples above prove
the identical constraint system over witnesses that differ only in `ct_digest`,
a public input the circuit does not constrain, and they range from 138 ms to
381 ms. Comparing one warm number against another across a circuit change
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
witness structure. Privacy is applied one layer up, at the private batch
(section 8), which is the only layer that blinds and the only proof that
leaves a wallet. One thing enforces that shape:
`qnero-verifier`'s leaf entry points are behind a non-default feature, so a
runtime taking the crate with default features cannot name a leaf verifier.
On the wallet side it is a convention the types do not carry:
`qnero_prover::WalletProver::prove_submission` keeps its leaf proofs inside
the call and is what a wallet should call, and `prove_leaf` is a public
advanced seam whose output must not cross a trust boundary.

The plumbing for a ZK leaf is kept: `qnero_leaf_zk_circuit_config()` returns
the row-blinding config, and `QneroSpendCircuit::new` accepts it. Plonky2
compiles its blinding randomness out by default, so a ZK config is rejected
with a clear error unless `qnero-circuit`'s `zk` feature is on. The aggregator
enables it unconditionally, because a private batch that could not blind would
be a privacy failure that compiles.

## 8. Batch aggregation (M3)

Two recursive layers sit above the leaf, both in `qnero-aggregator`:

```text
leaf proof        one shielded transfer, 26 public inputs, non-ZK
  |  N of them
private batch     zero knowledge, 5 + 21*N public inputs, the transaction a
  |               wallet submits
  |  n of them
public batch      an aggregator's bundle, 4 + n*(5 + 21*N) public inputs, non-ZK
```

Both verify their inner proofs against a verifier key baked in as circuit
**constants**. A witnessed verifier key would let a prover substitute a circuit
of their own with no constraints at all and have the wrapper accept its proof.

Chain defaults: `N = 6` leaves per private batch, `n = 53` private batches per
public batch, both overridable at artifact-build time. Six is a wallet-side
memory decision, fifty-three an aggregator-side cost one; section 9.1 carries
why six, where M3 measured at seven.

### 8.1 Private batch public inputs

`5 + 21 * N` field elements. The indices are constants in
`qnero_circuit::batch_layout`, which has no dependencies, so a verifier and the
chain read a batch proof without the prover stack.

| index | felts | name | meaning |
|---|---|---|---|
| 0..4 | 4 | `block_hash` | the block every non-padding slot is anchored at |
| 4 | 1 | `block_number` | height of that block |

then, for each slot `i` in `0..N`, at `5 + 21*i`:

| offset | felts | name |
|---|---|---|
| +0..4 | 4 | `nf_1` |
| +4..8 | 4 | `nf_2` |
| +8..12 | 4 | `cm_1` |
| +12..16 | 4 | `cm_2` |
| +16 | 1 | `fee` |
| +17..21 | 4 | `ct_digest` |

There is no trailing padding: the length is a function of `N` alone. Upstream
pads its aggregated output to a legacy size; Qnero has no legacy to preserve.

At the chain's `N = 6` that is 131 felts; M3's measurements were taken at
`N = 7`, which is 152.

**Fees are not summed in circuit.** A leaf's fee is a 62-bit field element, so
seven of them can exceed the Goldilocks modulus and the sum would wrap. Each
fee is forwarded and `pallet-shielded` sums them in native arithmetic, where
the total is a `u128`. This is the one place the Qnero wrapper does less than
upstream's, which enforces a volume fee over 32-bit amounts in circuit with a
52-bit range check that assumes 64 leaves of `u32`.

**Slot order carries no meaning.** The prover shuffles the leaf proofs
uniformly, and the circuit picks the batch's block reference by a prefix scan
over the first non-padding slot, so every position is equivalent and a batch of
several transfers publishes them in no order of the wallet's. Which slots hold
padding stays public: section 8.4 says why. Upstream
additionally permutes its emitted nullifier region through a switch network,
because its exit-slot region is grouped and stays correlated with slot order;
Qnero forwards each slot's six values as one unit, so the proof shuffle already
randomizes every emitted position and a second network would add nothing.

### 8.2 Public batch public inputs

`4 + n * (5 + 21 * N)` field elements: `aggregator_address(4)`, then each inner
private batch's public inputs forwarded **verbatim** as one contiguous segment,
in slot order. Nothing is shuffled, grouped or summed, so the chain can
attribute a settlement failure to one inner proof.

Every non-padding inner must agree on block hash and block number, which is
what lets the chain resolve one block per settlement. An aggregator therefore
buckets the proofs it pools by block.

The aggregator address is four felts of pure witness, registered as the first
four public inputs and constrained by nothing in circuit. It names who may
claim the batch's fees under a settlement rule that pays the aggregator;
**M4 pays the block author and ignores this public input entirely**, so at M4
these four felts buy an aggregator nothing on chain. Section 9.7 says
what M4 does and carries aggregator payment as an open decision. Whoever holds
the inner proofs can re-prove the same batch under another address, so an
aggregator that accepts a finished proof from elsewhere and that settles under
a rule which pays the address must compare the exposed address against its own
**off circuit**; `QneroPublicBatchProver::verify` is that check.

### 8.3 The forwarding contract

**Every non-padding slot's two nullifiers, two output commitments, fee and
`ct_digest` reach the aggregated public inputs unchanged, and all `2N`
nullifiers the batch publishes are constrained pairwise distinct.**

This is the one place a mechanical port of upstream's private batch goes wrong
quietly. Upstream's leaf has a single nullifier, so its wrapper carries
`nullifiers_count(N) = N` and an aggregated layout of one nullifier per leaf.
The visibly required edits when porting are the leaf-side constants; making
only those drops every leaf's `nf_2` at the batch boundary, and a note spent
from input slot 1 would never be marked used and could be spent again without
limit. Upstream also constrains only `N` nullifiers pairwise distinct; at two
per leaf that has to become `2N`, or one leaf proof replayed across slots
aggregates twice against a single settled nullifier.

The comparison is on the values the wrapper emits, and no slot is exempt from
it. A padding slot's emitted nullifiers are hashes of free witness targets, so
exempting padding slots would leave them unconstrained: a caller filling the
witness through plonky2's own API repeats one preimage in two padding slots and
publishes one nullifier twice inside one settleable segment. Reading the
emitted values is also what makes the rule satisfiable at all: the padding
template is one proof cloned into every empty slot, so every padding slot's
leaf-side nullifiers are identical.

The prover mirrors both rules off circuit so an impossible batch is refused in
milliseconds, ahead of the recursive proving run, and the two must be kept in
lockstep. The circuit remains the enforcer, and `qnero-aggregator`'s
own tests fill the witness directly, past the prover's checks, to prove it.

**At the public batch the rule splits in two.** A repeated inner proof is a
circuit constraint; a nullifier shared between two different inner proofs is an
admission rule and a settlement rule.

The constraint keys each inner by the first nullifier of its first slot and
requires the non-padding keys pairwise distinct. That digest is a Poseidon2
output whichever kind of slot it came from, a note's nullifier from a real slot
or a hash of the private-batch prover's randomness from a padding one, so two
distinct inner proofs share a key only on a collision while a repeated one
shares it by construction. It costs `n * (n - 1) / 2` equality checks against
`n` recursive verifiers, which is noise. The keys are compared for equality: a
lexicographic ordering would need the canonical 64-bit split
`qnero_circuit::gadgets` deliberately does not carry, and distinctness is all
an ordering would have bought. Padding inners are exempt,
because padding is one published artifact cloned into every empty slot and its
whole slot region is zeroed anyway.

What stays off circuit is the general nullifier comparison. Every inner's `2N`
nullifiers against every other's is `n * 2N` digests, 742 at the chain
defaults, and that is not affordable. So two *different* private batches that
settle the same note prove and verify here.
`QneroPublicBatchProver::prove_batch` is what stops that, by keying every
inner's `2N` nullifiers into one map before proving, and it refuses a
caller-supplied padding inner in the same pass because padding is the prover's
to append. That map binds the honest prover path alone:
`QneroPublicBatchCircuit` is public and a witness can be filled through
plonky2's own API. The chain's settled-nullifier set is the backstop, which is
why section 8.6 has the chain dedupe across every segment itself and check the
whole submission before it writes anything.

### 8.4 The padding rule

A batch has a fixed number of slots, so a wallet with fewer transfers than
slots fills the rest, and the filler must be a genuine proof of the leaf
circuit because the leaf verifier key is baked into the wrapper.

**A padding leaf is a leaf whose `block_hash` is `PADDING_BLOCK_HASH`, the
Poseidon2 hash of one fixed, publicly known header preimage.** That preimage
has a domain-separated `parent_hash`, `H_bytes("qnero/padding-header")`, which
is not a block hash any chain can produce, the empty commitment-tree root, and
zero everywhere else. The constant is pinned as limbs in
`qnero_circuit::padding`, in a module that compiles without the circuit
feature, and a test recomputes it from the preimage.

This was chosen over Wormhole's all-zero-`block_hash` sentinel, which is the
other candidate recorded at M2, for three reasons.

- **The header binding stays unconditional.** A padding leaf hashes a real
  preimage like every other leaf, so nothing in the circuit is switched off for
  padding, and no leaf can publish a `block_hash` it did not compute. Upstream
  has to make its binding conditional, because no preimage hashes to zero, and
  a conditional binding is a constraint an attacker wants switched on by the
  same bit that unlocks the padding path.
- **The sentinel cannot be claimed by a leaf that spends a note.** The padding
  preimage carries the empty `zk_tree_root`, so a real input inside a padding
  leaf would have to hash a Merkle path to the all-zero digest, which is a
  preimage attack on Poseidon2.
- **One sentinel serves all three layers.** A padding leaf, an all-padding
  private batch (whose prefix scan finds no non-padding slot and keeps the
  sentinel as its reference) and a padding inner of a public batch all carry
  the same block hash, so the chain has one rule to recognise padding by.

In the leaf, the sentinel gates constraint 9 and nothing else. Everything else
follows: with both inputs dummy their values are zero, so the balance equation
forces the fee and both output values to zero as well. A padding leaf provably
moves nothing.

**The wrapper masks every value a padding slot publishes**, trusting no
invariant that crosses a circuit boundary:

- both nullifiers become `H(NF_BATCH_PADDING, preimage)` over fresh randomness
  the prover draws per slot per proving run. They are unique, so the chain can
  settle every published nullifier by one rule, settling a padding one is
  inert, and cloning one padding template into many slots cannot collide. The
  domain tag is what keeps a prover-chosen value outside the image of both leaf
  nullifier functions, for the same reason `NF_DUMMY` exists (section 3);
- both commitments become zero, which is the absence sentinel the commitment
  tree already refuses to store, so the chain appends nothing for that slot;
- the fee and `ct_digest` become zero.

**A padding slot is identifiable, and the batch's real-transfer count is
public.** The mask zeroes a padding slot's commitment pair, and a real slot's
commitments are Poseidon2 outputs, so anyone reading the 131 published felts of
a `N = 6` batch filters the slots on `commitments == 0` and learns exactly how
many transfers the submission carries and which positions they sit in.
`BatchLeafSlot::is_padding` is that classifier, and the chain needs it to know
which commitments to append. What the padding buys is a fixed proof shape and a
fixed public-input length: every submission is one 131-felt private batch of
the same size, whatever it carries. Hiding the count would mean giving a
padding slot commitments indistinguishable from a real one's and telling the
chain by another route which to append, which is a design change; section 8.6
carries it as an open decision, together with whether a padding slot's two
nullifiers are worth their permanent state.

At the public batch, a padding inner keeps its sentinel header, so the chain
recognises the segment and skips it whole, and its slot region is zeroed. The
zeroing is load bearing there: that template is a published artifact cloned
into every empty slot, so its nullifiers would otherwise repeat across slots
and batches. Zeroed nullifiers are not settleable values, which makes the
skip an obligation; section 8.6 states it.

### 8.5 Artifacts

`qnero-circuit-builder` writes the set a pallet embeds and a wallet loads:

```text
leaf_verifier.bin                 verifier data for the spend leaf
padding_leaf_proof.bin            the canonical padding leaf proof
private_batch_verifier.bin        verifier data for the private batch
padding_private_batch_proof.bin   an all-padding private batch (optional)
public_batch_verifier.bin         verifier data for the public batch
config.json                       the dimensions the set was built for
qnero_circuit_config.rs           those dimensions as Rust constants
```

**No prover artifact, at any layer.** Prover data carries the target list that
decides which witness values become public inputs, so a poisoned one could make
a wallet publish its own spend credential, or the preimages that say which
slots were padding. Every prover rebuilds its circuit from source, which it has
to do anyway. The set is staged in a hidden sibling directory and swapped in by
rename once the last stage succeeds, so a failed run cannot leave a mixed
generation behind, and `config.json` is written last.

A verifier file is one whole `VerifierCircuitData`. A batch artifact cannot be
pinned by hash, because its bytes are a function of the dimensions, so
`qnero-verifier` holds it to a profile instead: the exact public-input count
for those dimensions, the exact `CircuitConfig`, the whole `FriParams`
recomputed from that config at the degree the artifact claims, a ceiling on
that degree, and the artifact's index structure against its own gate list.

`public_batch_verifier.bin` additionally carries a sixteen-byte header naming
the dimension pair it was built for, checked before anything is deserialized.
The profile alone is not injective in `(n, N)`: the public-input count is its
only dimension-dependent check and `4 + n * (5 + 21 * N)` collides, for example
at `n = 34, N = 1` and `n = 13, N = 3`, both 888 felts. Without the header an
artifact from a partial redeploy would load under the other pair, verify
genuine proofs, and the chain would then split them into segments at the wrong
offsets and settle one inner's block hash as another's nullifier. The private
batch needs no header: `5 + 21 * N` determines `N` from a length.

The last one is not paranoia. A gate's filter is a product over its selector
group, so a group of `0..2^40` is a verifier that never returns, and one
flipped bit in a length byte of a published artifact produces exactly that.
Nothing else catches it: the circuit digest does not cover the selector layout,
and a parameter floor never looks at it. Recomputing `FriParams` is likewise
what pins `reduction_arity_bits` and `leaf_hiding`, which live only in that
second copy. The leaf's own floor pins those two the same way, which closes
what M2 left open there; both remain unreachable from a comparison of the
first copy alone.

The wallet-side pinning is stricter, because a wallet can rebuild: the
aggregator compares an artifact's raw bytes against a canonical rebuild and
never deserializes the untrusted side, since `CommonCircuitData::from_bytes`
reserves vector capacity from length fields before they are proven consistent.
The keccak pin on a tagged release is still the thing neither has, and it still
needs a tagged circuit to pin.

### 8.6 The settlement contract, and what M4 decided

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
- **A padding segment settles nothing at all.** This is the precondition of
  the rule below, and it comes first. A private batch, or a public-batch
  segment, whose `block_hash` is `PADDING_BLOCK_HASH` is skipped whole: no
  nullifier settled, no commitment appended, no fee accounted.
  `PrivateBatchPublicInputs::is_padding` is that check, and
  `PublicBatchPublicInputs::settleable_batches` is the iterator that applies
  it, so the skip is the default path a pallet already walks. Two things force
  it. A padding inner of a public batch keeps its sentinel header
  and has its whole slot region zeroed, so it publishes `2N` all-zero
  nullifiers; a chain that settled those would insert the zero nullifier and
  then reject its own next slot as a double spend, which at 53 inner slots is
  close to every batch. And `prove_padding_batch` is a public API returning a
  proof that verifies against the published `private_batch_verifier.bin` while
  its prover holds no note, so a standalone padding submission must be refused
  outright or anyone writes nullifier entries for free into permanent state,
  settlement extrinsics being fee-free. A zero nullifier must never enter the
  nullifier set. What makes the sentinel unclaimable by a real batch is the
  section 1 obligation that `block_hash` is the hash of the block at
  `block_number`.
- **Inside a non-padding segment, settle both nullifiers of every slot, and
  skip a zero commitment.** A padding slot's two nullifiers are hashes of
  randomness drawn for that proving run, so they are unique and settling one is
  inert. Settling every published nullifier of the segment is therefore the
  safe default, and it is one rule for the whole segment. The alternative,
  skipping a padding slot's two, is the open decision below; the slot is
  identifiable either way. Commitments have no such choice: append the
  nonzero ones and skip the zero digest, which is the absence sentinel and is
  how a padding slot says it created no note.
- **A public batch is checked whole before it writes anything.** This is a
  blocking acceptance item for M4. The circuit stops the same inner segment
  appearing twice; nothing in it stops one nullifier appearing in two different
  segments (section 8.3). A settlement extrinsic must therefore walk every
  nullifier of every settleable segment and decide the whole submission before
  it mutates state. A pallet that settled segment by segment without
  transactional rollback would half-settle such a batch. What that decision is
  per segment was settled at M4 and is section 9.5: a segment holding a
  nullifier this chain already settled, or one an earlier segment of the same
  submission claimed, is skipped whole and the rest settles, because refusing
  the submission instead lets one participant destroy an aggregator's batch for
  free. A segment whose block anchor no longer resolves is skipped on the same
  argument (9.6). A repeat inside one segment still refuses the submission, and
  a submission that settles nothing is refused. A skipped segment pays no fee,
  so what it costs a block is priced by the submission floor in 9.7: the slots a
  submission settles pay `MinLeafFee` for every real slot the submission
  carries, skipped ones included, plus the byte floor for every byte it carries.
  A skipped position may be emptied to carry no bytes, and the slot behind it is
  charged all the same, because the walk and the weight it costs do not depend
  on its payload.
- **Whether a padding slot's nullifiers are worth their state, and whether the
  real-transfer count should be hidden at all.** These are one decision. A
  padding slot is identifiable today, because the wrapper zeroes its
  commitments and the chain needs that to know what to append (section 8.4), so
  a one-transfer batch at `N = 6` publishes ten unlinkable padding
  nullifiers that buy no count hiding and that a chain settling by one rule
  writes into permanent state. Either the chain skips a padding slot's
  nullifiers the way it already skips a zero commitment, which removes
  `2 * (N - 1)` entries per partly full batch and costs nothing since those
  values are inert, or the count is hidden properly: give a padding slot
  commitments a reader cannot tell from a real note's and tell the chain by
  another route which to append. The second is a circuit change and a
  settlement-format change together, and it is the only version that makes the
  shuffle buy anything.
- **Pallet-side `ct_digest` recomputation.** The rule is fixed (section 1) and
  implemented once in `qnero_circuit::chain::ct_digest`. What M4 owes is the call:
  recompute the digest over the ciphertexts in the settlement extrinsic, in
  output order, and reject the leaf when it differs from the forwarded value.
  Without that call the ciphertexts are attached to a proof that says nothing
  about them.
- **Coinbase and deposit range checks.** Every value that enters the pool
  outside a spend must be range checked to 62 bits by the pallet, or the
  balance argument in constraint 8 does not hold for notes created that way.
- **Nullifier seed uniqueness outside a spend.** Inside a spend this is
  settled: `rho_out_j = H(RHO, nf_1, nf_2, j)` is derived in circuit, so a
  sender has no choice to abuse (section 3). A deposit or a coinbase note has
  no spent nullifier to derive from, so M4 must give those a rule of their own,
  for example a per-block counter or the deposit's own unique identifier, and
  must reject a repeat. The recipient is the last line: a wallet should refuse
  a received note whose nullifier duplicates one it already holds or one
  already settled.
- **A keccak pin on a tagged release.** Both the leaf floor and the batch
  profile stand in for provenance, which they are not. The pin lands with the
  first tagged circuit, and every circuit change after that invalidates it.

## 9. The M4 settlement contract as built

`pallet-shielded` in the chain fork (`chain/pallets/shielded`) is the
implementation. This section records what section 8.6 left open, and the rules
that are the pallet's alone because no circuit enforces them. `pallet-zk-tree`'s
side of it is in section 4.

### 9.1 Chain defaults

`N = 6` leaf slots per private batch, `n = 53` private batches per public batch,
both overridable with `QNERO_NUM_LEAF_PROOFS` /
`QNERO_NUM_PRIVATE_BATCH_PROOFS`, which `chain/pallets/shielded/build.rs`
declares with `cargo:rerun-if-env-changed` so Cargo cannot reuse an `OUT_DIR`
built for other dimensions.

The numbers live in **one** place, `qnero_circuit_builder::DEFAULT_NUM_*`, and
the build script reads them from there. That matters because the builder is
also what a wallet or an aggregator runs to produce its own artifact set: a set
built at a different `N` produces proofs whose public-input length this
runtime's embedded verifier cannot read, and the rejection arrives after the
full proving cost has been paid. The pallet distinguishes that failure
(`ProofDeserializationFailed`) from a layout failure and logs the dimensions the
runtime was built for.

`N = 6`, where M3 measured seven. Blinding adds about 9000 rows at this
size, so a private batch fits `degree_bits = 15` only below about 23700 gates,
and seven recursive verifiers are 24324. Six fits; seven pays about 2x in
proving time and about 2x in peak memory, 2.1 GiB against roughly half that, for
one more slot per batch. That is the difference between a phone that can prove
and one that cannot, and it is a wallet-side cost paid by every user, where the
slot it buys back is amortized across a batch. `n = 53` is unchanged: an
aggregator's proving cost is paid on a server.

Generating the set at those dimensions takes about 53 seconds and peaks around
5.4 GiB, once per clean build of the pallet.

### 9.2 One crate boundary the pallet forced

`qnero-notes` was split at M4. `qnero-note-core` holds the digests, the domain
tags, the note commitment and nullifier rules and the spend credential;
`qnero-notes` keeps the ML-KEM viewing keys, the bech32m address and note
encryption on top, and re-exports the core so a wallet keeps one import.
`qnero-circuit` and `qnero-aggregator` take the core, and `pallet-shielded`
takes it in its test build only: the runtime graph reaches the two rules the
chain evaluates through `qnero_circuit::chain`, and the manifest lists
`qnero-note-core` under `[dev-dependencies]`.

This is a dependency boundary. A Cargo lock file resolves optional dependencies
too, so the chain's lock pulled `ml-kem 0.3.2` into its graph through
`qnero-verifier` to `qnero-circuit` to the note primitives, where it met the
`ml-kem 0.2.1` the chain's post-quantum Noise transport pins through `clatter`.
The two require incompatible versions of `kem` (`=0.3.0-pre.0` against `^0.3`),
Cargo cannot resolve two versions inside one `0.3.x` compatibility range, and
the node build failed compiling a crate neither Qnero nor the pallet uses.
Cutting the edge at the package level is what removes it, and it removes a real
surface as well: nothing between a note commitment and a verified proof needs
lattice cryptography, so a runtime linking the verifier should not have it in
its graph at all.

### 9.3 Ciphertexts on the wire

One `ShieldedOutput` per real leaf slot, in settlement order: every real slot of
every settleable segment, segments in order, slots in slot order. It carries the
two `NoteCiphertext::to_bytes` blobs of that slot, `ct_1` first, so `ct_1`
belongs to `cm_1`.

The rule is section 1's, unchanged, and it has one implementation now where it
had two: `qnero_circuit::chain::ct_digest` takes ciphertext bytes and compiles
without the circuit feature, so the chain reaches it through `qnero-verifier`'s
dependency and a wallet calls the same function. `qnero_notes::ct_digest` is
gone; there is no second copy to drift.

```text
ct_digest = H_bytes("qnero/ct" || u32_le(count)
                    || u32_le(len_1) || ct_1 || ... || u32_le(len_n) || ct_n)
```

The chain recomputes it per slot, over exactly two ciphertexts, and rejects the
slot when it differs. The count of `ShieldedOutput`s must equal the count of
real slots exactly, a segment this submission skips included (section 9.5): a
trailing extra would otherwise ride along bound by nothing, and a positional
mapping that depended on which segments were already settled would depend on
something the submitter cannot know. **Every real slot is bound, skipped
segments included.** Checking only the slots that settle would leave the skipped
positions carrying bytes nothing commits to, on an unsigned and fee-free
extrinsic the block then has to carry; at `n = 53` that is over a megabyte of
free-ridden block space. A submitter always holds the real ciphertexts, because
they arrived with the proof, so binding them costs nothing legitimate.

**The binding does not price those bytes, and it was never going to.** It fixes
*which* bytes a skipped position carries, and the attacker chose the
`ct_digest` they are bound to at proving time, so it can commit to two
ciphertexts padded to `MaxCiphertextBytes` as easily as to real ones. What
prices them is the submission floor in 9.7: the settling slots of a submission
pay one pool step per started `CiphertextBytesPerFeeQuantum` bytes the submission
carries, a skipped segment's bytes included, on top of `MinLeafFee` for every
real slot it carries. Without the byte term, one settling segment beside
fifty-two skipped ones carries up to 1.27 MB of never-pruned payload for the fee
of six leaf slots; without the slot term, emptying those positions hands the
same 318 real slots of admission walk and declared weight to every node for one
pool step.

**One shape at a skipped position is exempt: a pair of zero-length
ciphertexts.** It carries no bytes, so there is nothing there to bind and
nothing to price, and the chain evaluates no `ct_digest` for it. The position
itself stays, because the mapping from real slot to position cannot depend on
which segments someone else settled in the meantime, and the count rule is what
keeps that mapping the only reading of `outputs`. A **settling** position may
not be emptied: it is refused with `EmptyCiphertext`. A settling slot appends
two commitments and stores two ciphertexts, so an empty field there would write
an output note its recipient can never find, behind a digest nothing evaluated.
A real `NoteCiphertext` is 1792 bytes at the wallet's pad, so the refusal costs
nothing legitimate. Under the exact-length rule below, a half-emptied position
is refused one step earlier, by length, because the zero-length exemption is a
whole pair or nothing.

**Each ciphertext is capped at `MaxCiphertextBytes`, 2048 bytes in the
runtime.** A `NoteCiphertext` serializes to 1731 bytes at the chain's parameter
set with an empty memo: 19 bytes of framing (a version byte, a two-byte crypto
suite, a four-byte diversifier index, and a `u32` length before each of the
three payloads), a 1568-byte ML-KEM-1024 encapsulation, the 112-byte note
payload under a ChaCha20-Poly1305 tag, and the memo's own tag.
`an_empty_memo_ciphertext_serializes_to_1731_bytes` in `qnero-pqcrypto` pins
that total against the serializer, so a wallet sizing a memo from these parts
cannot be misled by prose that drifted. The cap leaves 317 bytes of memo.

**On the settlement path the cap is unreachable, because the length is exact.**
Every ciphertext a settlement carries is exactly the serialized length its
declared `crypto_suite` id fixes, or is one half of a fully emptied position.
One suite exists and its length is 1792 bytes, which is the 1731-byte fixed
part plus the 61-byte memo pad, so the pair a slot publishes is 3584 bytes and
that is the only payload a carried position can have. The table lives in
`qnero_circuit::chain` beside `ct_digest`, and the chain applies it by reading
three header bytes: the version byte, then the two-byte little-endian suite id
at offsets 1..3. It parses nothing else, and the version byte is deliberately
not checked, because it is an address version and the length is fixed by the
suite alone.

A blob of the exact length behind a valid header still settles whatever it
contains. The rule fixes how many bytes a settlement may publish; `ct_digest`
fixes which bytes they are. Neither authenticates a note. What the rule
forecloses is the grind: the chain used to hold no submission to a real
`NoteCiphertext` shape, so a settler could fill both fields to the cap and buy
permanent, never-parsed state for whatever fee bucket the divisor reached. A
wrong length is refused with `CiphertextLengthMismatch`, and a length behind a
suite id this release has no row for with `UnknownCryptoSuite`, which is what a
wallet one release ahead of the runtime is owed. Both are permanent and both
answer `InvalidTransaction::Call`.

The rule is enforced in one flat pass at the head of `plan_settlement`, after
the `NothingToSettle` guard and ahead of the segment walk, so it covers pool
admission, block inclusion and the dispatch body at once. It reads no storage
and hashes nothing, which is why it belongs in front of the two
`UsedNullifiers` probes per slot rather than behind them.

**The cap still binds the entry path and the encoded length.** `shield` carries
an arbitrary ciphertext up to `MaxCiphertextBytes`, zero included, and the
exact-length rule is scoped to settlement. The 317 bytes of memo slack is
therefore the figure to reason from for an entry note and no figure at all for
a settlement output. Two mechanisms still price the settlement payload: the fee
floor is linear in the payload (section 9.7), and the declared weight carries a
per-byte term, because the per-slot `ct_digest` is a byte sponge over kilobytes
and the weight is computed from the submitted vector before the length rule
refuses it. A wallet reads the bound from the pallet's metadata; a hardcoded
copy drifts. Exceeding it fails the extrinsic's SCALE decode, after the proof
that committed to those exact bytes has already been built, so a wallet checks
before it proves.

### 9.4 Padding

A padding segment settles nothing, and a submission with no other segment is
refused with `NothingToSettle`. This covers both cases section 8.6 names: a
standalone all-padding private batch, which `prove_padding_batch` produces
without holding a note, and a public batch whose inners are all padding.

Inside a settleable segment, a padding slot is dropped at the parse.
`SettlementBundle` carries only real slots, where real means the slot's
commitment pair is nonzero. **This resolves the open decision on a padding
slot's nullifiers: the chain does not settle them.** They are hashes of
randomness drawn for one proving run, so settling one is inert, and at `N = 6` a
one-transfer batch would otherwise write ten inert entries into permanent state
forever. The slot is identifiable either way, because the wrapper zeroes its
commitments and the chain needs that to know what to append, so skipping the
nullifiers costs no privacy that was not already lost.

The other half of that decision, whether the real-transfer count should be
hidden at all, stays open. It is a circuit change and a settlement-format change
together, and it is the only version that makes the batch shuffle buy anything.

### 9.5 Nullifiers

Both published nullifiers of every real slot are settled, a dummy input's
included: inside a real slot the chain cannot tell a dummy from a real one and
must not try, and a note spent from input slot 1 is marked used only if slot 1's
nullifier is settled.

Every nullifier of every settling segment goes into one set before anything is
written. The private-batch circuit already forbids a repeat inside one batch;
nothing in the public-batch circuit compares two different inners, which is why
this is a chain rule.

**A conflict skips its segment. It does not refuse the submission.** A segment
is skipped when any nullifier it publishes is already in `UsedNullifiers`, or
was claimed by an earlier segment of the same submission. A repeat inside one
segment is the one case that still refuses the submission, with
`DuplicateNullifier`; the circuit forbids it, so only a hand-built bundle or a
future circuit change reaches it. A segment whose block anchor no longer
resolves is skipped by the same rule: see 9.6.

The reason is that refusing lets one participant destroy an aggregator's batch
for free. An aggregator's public batch wraps `n` proofs that are each, on their
own, exactly what `submit_private_batch` accepts. A nullifier is a function of
the note alone, identical wherever that note is spent, so a participant can hand
an aggregator an inner, wait for the recursive run to start, and then settle a
different batch of its own that spends one of those same notes. The aggregator's
inner is now partly settled: one nullifier used, the rest fresh. Under an
all-or-nothing rule the whole public batch can never settle, the other
fifty-two participants' transfers are stranded until their anchors expire, and
the aggregator cannot defend against it because the conflict is created after
its batch is fixed. Handing an aggregator two inners that spend one common note
does the same thing for nothing at all. An honest wallet that gives up waiting
and re-proves produces the same shape, since a re-proof draws fresh dummy
nullifiers and matches no earlier segment byte for byte.

Skipping is sound because a skipped segment could not have settled anyway.
Constraint 9 makes at least one input of every real slot a real note, and one of
the segment's published nullifiers is already spent, so the segment is a double
spend by construction: refusing it and skipping it are the same outcome for that
segment, and they differ only for the segments around it. Nothing of a skipped
segment is written: no commitment appended, no nullifier marked, no fee counted,
so its own fresh nullifiers stay unspent and the notes behind them can still
settle elsewhere. Which of two conflicting segments wins is the order they
appear in the proof, which is fixed, so every node decides the same way.

A submission whose every segment is skipped settles nothing and is refused, the
same way a standalone padding batch is: admission work is not free and a no-op
settlement would spend it for nothing. The refusal names the reason. A
submission every one of whose segments conflicted is refused with
`NullifierAlreadyUsed`, which is what a replay looks like; when any segment was
skipped for its anchor, that anchor's own error is what comes back
(`BlockOutsideWindow`, `BlockNotFound` or `BlockHashMismatch`), because a
private batch has exactly one segment and a wallet whose proof named a block
this chain cannot resolve is owed the reason. The ciphertexts of a skipped
segment are still bound to its `ct_digest` (section 9.3) whenever they carry
bytes at all; only the nullifier writes, the fee and the appends are skipped.
What prices the payload those skipped positions carry is the byte term of the
submission floor in 9.7, and emptying them removes the binding and that term
together. The slots themselves stay priced either way, by the per-slot term of
the same floor.

The all-zero nullifier is refused outright. It cannot reach here through the
padding filter, and the check is what keeps that true if the filter ever moves.

### 9.6 Block anchoring

Per segment, in this order: the padding sentinel is filtered first, then the
block lookup. A padding segment carries `PADDING_BLOCK_HASH` at block number
zero and would otherwise be refused as a missing block by accident, where the
rule is what should refuse it.

A settleable segment must name a block that is already finished
(`block_number < current`), inside `BlockHashWindow` (256 blocks in the runtime,
about 8.5 hours at the public chain's 120 s target), present in
`frame_system::BlockHash`, and whose hash equals
the segment's `block_hash` public input. The public input arrives as four
canonical Goldilocks limbs and the chain's header hash is a Poseidon2 output
stored in the same 32-byte little-endian-per-limb form, so the comparison is
lossless.

**A segment that fails any of the four is skipped, and the rest of the
submission still settles.** This is the same rule as the nullifier conflict in 9.5 and it
rests on the same argument for three of the four: the window only moves forward,
a pruned hash does not come back and an orphaned one never becomes canonical
again, so a segment failing one of those cannot settle at this height or at any
later one, and refusing it and skipping it are the same outcome for it. They
differ only for the segments around it, and that difference is the whole
griefing surface the skip rule exists to close. The anchor half of it is the
half an aggregator cannot defend against by pre-validating its inners: one reorg
between the recursive proving run, about 21 seconds, and inclusion orphans an
inner's anchoring block, and a participant can force the same shape on purpose
by handing over an inner anchored near the edge of the window. Under an
`ensure!` that one inner refused the whole submission and stranded the other
fifty-two transfers. The skip is deterministic, because every node reads the
same `frame_system::BlockHash` at the height the block is executed at.

**The fourth condition, `block_number >= current`, is not permanent, and it is
a skip all the same.** An anchor at or above the height being built is a claim
about a block this chain has not finished, and that height does arrive later, so
the invariant above covers three conditions of the four. The choice is
deliberate: a refusal would hand an aggregator's participants the cheapest grief
of the lot, an inner anchored in the future being one line of a hand-built
witness, where the orphan case at least costs a reorg. What the skip promises is
narrower and is all a plan for this block needs, that the segment does not
settle here. A skipped segment writes nothing, so the same proof can settle in a
later submission if that height ever resolves to the hash it named, which takes
predicting a future header hash.

**The rule is written per segment and it decides whole submissions for the
batches the circuits produce.** Section 8.2 has the public-batch circuit
constrain every non-padding inner to one block hash and one block number, so a
public batch that verifies carries a single anchor and its segments stand or
fall together; a private batch has one segment to begin with. Per segment is
still the shape the pallet needs, because the same walk runs at pool admission
over a parsed bundle no verifier has touched, where that agreement is the
submitter's claim, and the skip is what keeps the walk total there.

So state plainly what the anchor skip buys, which is less than the nullifier
skip beside it. For a batch these circuits produce, skipping and refusing are
the same outcome: every segment fails the anchor together, the submission
settles nothing, and the error that comes back is the anchor's either way. It
earns its place at admission, and it is the shape the rule needs if 8.2's
one-block constraint is ever relaxed so an aggregator can pool proofs across
blocks. The nullifier skip in 9.5 is the one that saves an aggregator's batch
today.

`BlockHashWindow` is tighter than `BlockHashCount` on purpose. A proof built
against a much older block saw a smaller commitment tree, and settling it tells
an observer roughly how old the anonymity set its prover used was.

### 9.7 Fees

Each real slot's fee is a 62-bit field element counted in pool steps
(`POOL_STEP = 10^10` planck, 0.01 QNR, the same step `pallet-zk-tree` uses for
a wormhole leaf amount). The pallet sums them in `u128`, which is why the circuit
does not sum them: six 62-bit fees overflow Goldilocks.

Every real slot must carry at least

```text
MinLeafFee + ceil(ciphertext_bytes / CiphertextBytesPerFeeQuantum)
```

steps, where `ciphertext_bytes` is the two ciphertexts that slot publishes, and
both of them have to carry bytes: an emptied position in a segment that settles
is refused with `EmptyCiphertext` (section 9.3). The runtime sets
`MinLeafFee = 1` and `CiphertextBytesPerFeeQuantum = 512`, and the exact-length
rule leaves one reachable payload per carried position, 3584 bytes, so a
settling slot's floor is a flat eight steps: one flat, seven of payload, with
nothing left over because 3584 divides by 512. This floor and the submission
floor below it are the anti-spam mechanism, and they are the only one, for the
reason section 8.6 gives.

The payload term exists because the flat floor alone prices permanent state at
whatever a settler cares to publish: one step, 0.01 QNR, would buy 4096 bytes
of state that is never parsed, and half of every fee comes back to a settler
that is also the block author. The divisor was sized against that grind
directly: it had to sit below the slack between the real ciphertext size and
the cap, or the term priced none of that slack, and at one kilobyte 3462 and
4096 bytes both round to four steps. The exact-length rule refuses the padded
pair outright, so the separation the divisor was tuned for now prices a state
nobody can reach, and `a_pair_padded_to_the_cap_is_refused_not_priced` is where
that endpoint went. The term stays linear and the divisor keeps its value,
because it also prices a skipped position's carried bytes and because a second
suite would publish a second length. The floor is computable before proving,
because the fee is a public input
and the ciphertext sizes are known by then, so a wallet owes the arithmetic
above at witness-building time. A slot this submission skips is exempt: a
skipped segment writes no nullifier, appends no leaf and stores no ciphertext,
so there is no permanent state for a fee to price, and its own fee already left
`PoolValue` when it first settled, so counting it again would drift the pool's
books from the sum of the note values behind them. Not evaluating the floor in
the skip branch also keeps a parameter governance may have moved since from
making an already-settled segment fatal on its second appearance.

**What the skip exemption does not cover is the block space.** A skipped
segment writes nothing permanent and it still costs a block the bytes it
carries, the admission walk over its slots and a `ct_digest` sponge over both
its ciphertexts, twice for an included settlement. The per-slot floor prices the
settling slots alone, so on its own the fraction of a submission that settles is
the fraction of its work and its payload that is priced, and the submitter
chooses that fraction. The shape is reachable on chain through the circuits as
built: the public-batch circuit's only cross-inner rule compares `nf_1` of slot
0 between non-padding inners, so fifty-two inners can each re-spend a note a
fifty-third settles as long as the shared note sits anywhere but slot 0 input 0,
each one is a genuine provable private batch, and each stays conflicting and
reusable in every later submission for its anchor's whole window.

**So the settling slots pay for every slot and every byte the submission
carries.** On top of the per-slot floor, over the whole submission:

```text
sum(fee of settling slots)
    >= (settling slots + skipped slots) * MinLeafFee
       + ceil(carried bytes / CiphertextBytesPerFeeQuantum)
```

where `skipped slots` is every real leaf slot of every skipped segment,
whatever its outputs carry, and `carried bytes` is the total length of every
ciphertext in `outputs`, the positions of skipped segments included. Refused
with `PayloadUnderpaid`. There is no constant to tune: the two parameters are
the ones the per-slot floor already uses, so a slot costs `MinLeafFee` and a
byte costs one five-hundred-and-twelfth of a step wherever either is carried,
and the rounding slack over a whole submission is under one step.

**Why the rule prices slots as well as bytes.** A submission's cost to a node
has two independent terms and a submitter moves them independently. The
bytes are the `ct_digest` sponge and the block space, and the per-slot term is
everything a slot costs before its payload: the admission walk over it, two
`UsedNullifiers` probes, a position in `outputs` and the reference time the
extrinsic declares for it, all of it twice for an included settlement, all of it
unpaid on an unsigned extrinsic. Pricing the bytes alone leaves the second term
free, and emptying a skipped position is exactly how a submitter takes it: 317
skipped slots beside one settling slot, every skipped position a zero-length
pair, is 318 slots of walk and declared weight for the price of one.
`a_carried_slot_is_paid_for_even_when_its_outputs_are_emptied` is that shape.
Pricing the slots alone leaves the first free, because the payload per slot is
the submitter's to choose on each side independently and slot counts and bytes
are not proportional: three skipped slots padded to `MaxCiphertextBytes` beside
one settling slot carrying ten bytes is 12288 bytes of never-pruned payload
inside a slot ratio of four.
`a_submission_pays_for_every_byte_it_carries` is that one. Both terms are in
the floor because each closes what the other leaves open, and the earlier bound
that counted real leaf slots and allowed four carried per settled priced neither
correctly: the submitter picks the real-slot count of its own inners, up to `N`
each, so it moved both sides of that comparison.

**What an aggregator does on a race.** A segment can become skipped between
submission and inclusion, by a nullifier conflict a participant creates on
purpose or by an anchor going stale, so the rule allows both shapes at a skipped
position: it may carry its real ciphertexts, which stay bound to its `ct_digest`
and count toward the carried bytes, or it may be a pair of zero-length
ciphertexts, which binds nothing and adds nothing to the byte term (section
9.3). Whether the submission still settles is then decided by the floor: a
full public batch of six-slot inners that loses one inner settles 312 slots
whose own minimums cover 312 of the 318 the floor asks, so it passes only if
its settling fees carry six steps of slack above their own floors. Fees are
public inputs fixed by the leaf circuit at proving time, so an aggregator
cannot raise one after a grief; when the slack is not there its remedy is to
recompose a fresh public batch without the conflicted inners, which costs one
public-batch proof. A griefed segment is therefore never fatal to the notes
it carries, only to the batch that carried it, which is the property the skip
rule exists for.

What the per-slot term prices is the declared block weight and the settlement
walk a carried slot costs at `pre_dispatch` and dispatch. It cannot price the
pool-admission walk of a blob that never reaches dispatch, because
`plan_settlement` runs there over public inputs no verifier has touched; that
unpaid admission work is the pool-level open issue in section 9.10.

The far end of that scale is refused unless it is paid for, and that is the
intended outcome. A submission that settles one slot beside 317 skipped ones
owes 318 minimums where its one settling slot covers one, so the griefed
aggregator recomposes the batch for the cost of one proof. The alternative is a block handing out 318 slots of
admission walk and declared weight for one step, which is the cheapest denial
of service the settlement path has and which no aggregator needs.

Charging a skipped slot its own leaf fee stays unavailable, for the
pool-accounting reason above: a fee that already left `PoolValue` when the
segment first settled cannot be counted again. `MinLeafFee` charged to the
settling slots is a different quantity and leaves the pool once. Slot-count
asymmetry between segments still does not matter, because the floor counts
slots and bytes over the whole submission and neither term reads a segment: an
inner holding six slots and an inner holding one are each priced by what they
carry.

The sum leaves the pool, and the pool has to be holding it: a fee above
`PoolValue` refuses the settlement with `PoolUnderflow` before anything is
written. That case is unreachable while the circuit's balance equation holds and
`shield` is the only entry, which is why it fails closed. A saturating
subtraction would mint the author a share of a fee nothing backs and zero the
pallet's own books on the way past, with nothing on chain to say the two stopped
agreeing.

`FeeBurnRate` of the fee (half in the runtime, rounded up against the author) is
simply not credited back, which is what makes it a burn: the value left issuance
when it was shielded. The rest goes to the QPoW block author, taken from the
pre-runtime digest the same way `pallet-mining-rewards` takes it, and recorded
as a wormhole leaf through `TransferProofRecorder`. Without that leaf the credit
would be frozen: a QPoW-derived author account has no signing key, and a
wormhole leaf is its only spend path. With no author in the digest, or a credit
that fails below the existential deposit, the share stays uncredited and the
settlement stands.

The credit is `Unbalanced::increase_balance` plus an explicit
`set_total_issuance`. `Mutate::mint_into` deposits
`Balances::Minted`, which the runtime's `WormholeProofRecorderExtension` scans
for and turns into a wormhole leaf of its own; paired with the leaf this pallet
records itself, that would be one balance against two independent leaves and an
author able to exit twice what it was paid. `pallet-wormhole` states the same
rule for the same reason. The issuance bump is correct here and absent there:
the value left issuance at `shield`, so the unburned half is put back.

**The aggregator address is unused at M4.** A public batch registers it as its
first four public inputs (section 8.2) and the pallet ignores it: the whole fee
goes to the block author, whichever aggregator paid the proving cost. Whether an
aggregator should be paid out of the fee is an open decision, beside the M6
coinbase item.

### 9.8 Entry: the shield extrinsic, and `rho` outside a spend

`shield(value, inner, ciphertext)` is signed, and it is the only way into the
pool at v0. There is no exit.

It burns `value` from the signer, which must be a positive whole number of pool
steps, range checks `value / POOL_STEP` to 62 bits, computes
`cm = H(CM, inner, steps)` with `qnero_circuit::chain::commitment`, appends
`cm`, stores the ciphertext against its leaf index and emits it.

Burning is the simpler of the two entries the design left open, and it is the
consistent one: value inside the pool moves only through proofs, so an
account balance standing in for it would be a second book to keep in step, and
at v0 there is no exit to draw from it. `PoolValue` is the pallet's own record
of what issuance the pool stands in for, and it is what an unshield path would
have to draw from at v1.

`inner = H(NOTE, pk, rho, r)` stays opaque, which is what keeps the recipient
and the note's randomness private while its value is public.

**The `rho` rule for a note created outside a spend proof.** Inside a spend the
circuit derives `rho_out_j = H(RHO, nf_1, nf_2, j)` and a sender has no choice
to abuse. An entry has no spent nullifier to derive from, so:

```text
rho = H(RHO_ENTRY, block_number, entry_index_hi, entry_index_lo)
```

with `RHO_ENTRY = 0x716e_0009`, the next free domain tag above
`NF_BATCH_PADDING`, and `entry_index` the chain-wide `EntryCount` at the time of
the shield. `qnero_notes::entry_rho` is the implementation, beside `output_rho`
which is the in-circuit rule it stands in for, and a wallet calls it. Both
halves of the identifier are in the `Shielded` event, so a recipient recomputes
`rho` from chain data; reading it out of the ciphertext would trust the sender
to have followed the rule.

The chain does not evaluate this rule and does not link the crate that holds
it. The only note rule the chain evaluates is `cm = H(CM, inner, value)`, in
`qnero_circuit::chain`, which is what `pallet-shielded` reaches through
`qnero-verifier` without the prover stack or the note primitives.

The chain cannot check the rule, because `inner` is opaque by construction. What
it owes is the identifier, and the pair `(block_number, entry_index)` never
repeats. A shielder that ignores the rule can only strand its own note:
computing anyone else's nullifier needs their `nk`. At M6 a coinbase note takes
the same rule with the coinbase's own identifier.

**What the recipient owes.** A sender picks `rho` and `r` for the note it
creates, so a sender that repeats a pair hands over two notes sharing one
nullifier. At most one of them can ever settle, because the chain refuses a
nullifier already in `UsedNullifiers`, and which one settles is the recipient's
choice: it is whichever one the recipient spends first. So the rule is a rule
about **counting**, and a wallet holds both notes.

Two notes sharing a nullifier are a conflict set, and a wallet owes three things
for one:

- Hold every member. The note's plaintext is in the ciphertext the chain
  published, and the member a wallet discards is the one it can never recover a
  secret for.
- Count the set once, at the value a spend would use, which is its largest
  member. Summing the members reports a balance the chain will never back, and
  that is the refusal the recipient rule is actually asking for.
- Never put two members in one leaf. A private batch constrains its nullifiers
  pairwise distinct (section 8), so a selection that did would fail in circuit
  before it reached the chain.

Refusing the second member on arrival satisfies none of these. It decides by
arrival order, which the sender controls, so a sender that puts the large note
second takes the difference away from the recipient permanently, and it decides
it in a way no rescan undoes. A nullifier already settled on chain is the one
refusal left, and even that one is provisional: a reorg that orphans the
settlement makes the same output holdable, so a wallet records it with its
reason and drops the record when a later scan holds the note.
`docs/WALLET.md` has the wallet side.

### 9.9 One tree, two leaf kinds

`pallet-shielded` and `pallet-wormhole` append to the same `pallet-zk-tree`
instance, because the leaf circuit anchors at `zk_tree_root` and the block
header carries exactly one of those. A second instance would be a root no
shielded proof could reach.

The two kinds cannot be confused. A wormhole transfer leaf is a Poseidon2 hash
of an 8-felt preimage that starts with a limb of the recipient account; a
shielded leaf is a note commitment, a Poseidon2 output over a 6-felt preimage
that starts with the `CM` domain tag. The lengths differ, so the sponge padding
differs, and passing one off as the other additionally requires a note whose
`cm` equals a given transfer-leaf hash, which is a preimage attack on Poseidon2.
This is the same argument section 4 makes for leaf against internal node.

What the sharing does cost is capacity and anonymity-set composition: wormhole
traffic consumes tree slots a shielded note could have used, and a shielded
spend's anonymity set is every leaf in the tree, wormhole leaves included, which
are not notes anyone can spend. Neither is a soundness problem and both go away
at M6, when the transparent layer is removed.

### 9.10 Admission

`validate_unsigned` runs three stages, in cost order, and it runs all three.
First the parse (the size check before anything is copied, deserialization
against the embedded verifier's circuit data, the canonical-encoding round trip,
the public-input parse) and then `plan_settlement`, the cheap half of the
settlement check: a bounded walk over the segments against chain state, at most
two `UsedNullifiers` reads per slot, integer comparisons, one block-hash lookup
per segment, a count of the real slots and a sum of the `outputs` lengths for
the submission floor, and no hashing at all. Second the ZK verify, on what survives.
Third `bind_payload`, the Poseidon2 sponge over both ciphertexts of every real
slot, which is the one term linear in the submitted bytes. `pre_dispatch` runs
the parse, the verify and the whole settlement check again and is the
block-inclusion gate, because `validate_unsigned` does not run on block import.
The dispatch body verifies as well, for the reason section 9.11 gives; those two
passes are the ones block execution pays and the declared weight charges.

The cheap half comes first because a settlement proof is public by construction:
the extrinsic carrying it is gossiped and old ones sit in finalized blocks.
Anyone can take a settled proof, keep the blob byte identical, change one byte
of `outputs`, and have a transaction with a new hash that no node has seen, so
every node validates it fresh. There is no proving work and no fee behind that
and it repeats as fast as blobs can be pushed. Every segment of a settled proof
conflicts, so every one of those variants dies on `NullifierAlreadyUsed` after a
few hundred storage reads, whatever its `outputs` carry.

The payload binding comes last because at the chain's dimensions it is the
larger of it and the verify, which the earlier drafts of this section had
backwards. Read off `pallets/shielded/src/weights.rs` at `N = 6` and `n = 53`, a
full public batch is 318 real slots: one binding pass over the real 1731-byte
ciphertexts is 34,931 Poseidon2 permutations, 349 ms of declared reference time,
against 158 ms for one public-batch verify plus its parse, a ratio of 2.2, and
2.6 at the ciphertext cap. Running it ahead of the verify would make a
fabricated blob (public inputs rewritten wholesale, which the paragraphs below
explain no cheap check can catch) cost a node the walk **and** the verify where
it used to cost the verify alone. Behind the verify, a blob that cannot settle
never reaches it. The private batch is the other way round, 6.5 ms of binding
against a 30 ms verify, and the ordering is set by the case that inverts.

Upstream splits the two, verifying only at `pre_dispatch`, and M4 shipped that
split before a review took it apart. **The split does not hold, and Qnero does
not keep it.** Nothing short of the verify is cryptography: a proof carries its
public inputs as a plain vector in the serialized blob, so anyone can take a
genuine proof, rewrite its public inputs to claim any nullifiers, commitments,
fee and block anchor, re-serialize canonically, and produce a blob that passes
every remaining check. Three things follow, and all three are worse than the
cost the split was avoiding:

- the forgery is admitted and, under `propagate(true)`, re-gossiped by every
  node, each of which has already paid the whole per-slot settlement walk and
  then the payload binding on top, and the submission is unsigned and
  `Pays::No`, so none of it is charged;
- the pool tag is derived from the nullifiers, which are readable from any
  transaction sitting in a mempool, so a forged clone of a victim's settlement
  carries the victim's tag. The pool replaces on strictly higher priority and
  the priority is constant, so whichever arrived first holds the slot and the
  other is refused: censorship at no cost and with nothing on chain to show for
  it;
- the junk reaches a block author and dies at `pre_dispatch`, which is exactly
  where the verify was supposed to be cheap.

What verifying at admission buys is that a junk blob stops at the first node it
reaches, where before it cost every node on its path a settlement walk and then
reached a block author to die there. It does **not** bound the number of
verifies an attacker can force. The canonical-encoding round trip is sometimes
offered as that bound, and it is not one: it rejects other encodings of one
decoded proof, which is what stops `proof || padding` and `+ p` limbs from
multiplying one proof's transaction identities, and it says nothing about a
mutated proof object. A private-batch proof is about 157 KB, on the order of
10^5 single-bit variants that all round-trip exactly, and each costs the node
that receives it one full verify, unsigned and unpaid.

**Open issue, M5.** One unpaid cheap settlement walk plus one unpaid verify per
distinct gossiped blob, with no rate limit. The walk hashes nothing and the
payload binding sits behind the verify, so a blob that fails the verify never
pays the term linear in its bytes; what is unbounded is the number of distinct
blobs. A rejection cache keyed on `blake2_256(proof)` bounds the repeat case, so
one blob cannot be re-verified once per `outputs` variant; it does not bound
distinct blobs. The residual is recorded here and next to `WASM_VERIFY_FACTOR`
in `pallets/shielded/src/weights.rs`.

The pool tag is a Blake2 hash of the submission's nullifiers, sorted within each
segment, with the segment boundaries in the preimage. What it excludes is
byte-different rebroadcasts of one submission: they hash to one tag, hold one
pool slot, and the first seen keeps it. It is deliberately not cross-submission
double-spend exclusion, because the preimage carries the submission's
segmentation: a private batch and the public batch that wraps it as one inner
spend the same notes and hash to different tags, so both are admitted and both
can reach one block. What excludes a double spend is `UsedNullifiers` inside the
settlement check, and the segment-skip rule of section 9.5 is what lets that
pair settle once between them. Nothing may be built on the
tag as an exclusion: dropping the dispatch body's settlement check, or trading
the per-slot `UsedNullifiers` probe for pool-level exclusion, would let the same
notes settle twice.

Priority is the constant `UNSIGNED_SETTLEMENT_PRIORITY = 1`: an amount-derived
priority combined with a nullifier-derived tag would let a submission with
inflated public inputs usurp a victim's same-tag settlement, because the pool
replaces on strictly higher priority, and the public inputs a priority would
read are the prover's own claim. That the tag cannot be stolen at all rests on
admission verifying.

### 9.11 Weights

**No benchmark has produced these numbers.** They are calibrated the way
`pallet-wormhole`'s are, from verification times and from the storage operations
a settlement performs, so a runtime has a defensible ceiling to meter against.
Three things about them are worth carrying into M5:

- **Both verify figures are native measurements times a factor.** The node
  builds a `WasmExecutor` and nothing else, so the verify a block import pays is
  plonky2 FRI over Goldilocks under wasmtime, without the native build's 64-bit
  multiply and SIMD paths. `WASM_VERIFY_FACTOR = 5` is a stand-in for a number
  nobody has measured, and weight is what bounds block execution time, so an
  under-declared verify is real import work nothing accounts for. M5 owes a
  measurement taken inside the runtime.
- **The public batch has never been built or timed at `n = 53`.** Its 30 ms
  native figure is a ceiling chosen to be wrong in the safe direction.
- **The ciphertext digest is priced per byte, and everything an included
  settlement does twice is charged twice.** A slot's `ct_digest` absorbs
  kilobytes of ML-KEM and AEAD ciphertext at four bytes per field element and
  eight field elements per permutation, so a flat per-slot charge was wrong by
  more than an order of magnitude. And an included settlement runs the parse,
  the verify and the settlement check twice, once in `pre_dispatch` and once in
  the dispatch body, so all three are charged twice.
- **`shield` carries its ciphertext in `proof_size`.** It writes one ciphertext
  into the same never-pruned `Ciphertexts` map a settled slot writes two of, and
  `settlement_weight` puts that payload in its `proof_size` term, so `shield`
  does the same. The runtime sets `proof_size` to `u64::MAX` today, so nothing
  is metered against either term; the declaration is an upper bound for the day
  a concrete limit lands, which `configs/mod.rs` carries as a planned change.
- **The parse has two terms.** The blob round trip does not scale with the
  public inputs and the layout walk does: `private_batch_pi_len(6)` is 131 felts
  against `public_batch_pi_len(53, 6)` at 6947, and the parse allocates a slot
  per forwarded leaf. One flat constant for both under-declares the public
  batch. The flat constant scaled by the felt ratio over-declares it
  fiftyfold, because the blob round trip does not scale with the public
  inputs. Neither term is measured; 100 ns per felt is roughly an order of
  magnitude above what a copy and a range-reduced comparison cost natively.
- **The dispatch body verifies, and that is why the verify is charged twice.**
  `ensure_none` is satisfied by any dispatch with no origin, and sp-runtime's
  `ExtrinsicFormat::General` reaches a call with `None` as its origin without
  `ValidateUnsigned` running at all: the checked extrinsic dispatches that
  format without calling `pre_dispatch`. In this runtime that path is closed
  today by `ReversibleTransactionExtension` refusing a non-signed origin, which
  is one entry in a tuple a future runtime may reorder or relax, while
  `CheckNonce` and `ChargeTransactionPayment` both wave a `None` origin through
  free of charge. A body that only parsed would settle a bundle whose public
  inputs were rewritten wholesale: attacker-chosen commitments appended as tree
  leaves, which is unbounded pool inflation with no proof behind it. The second
  verify makes that structural, and a test in the pallet reaches the dispatch
  body directly the way that path would.
- **Admission's unpaid verify is not metered at all.** See the open issue in
  section 9.10: weight bounds block execution, and nothing bounds what a
  transaction pool absorbs before a block.

## 10. The M6 coinbase record

Value created after genesis enters circulation in one place under v1: the note a
block mints to its author. The genesis allocation is the exception and it is
transparent, the genesis allocation paid out by `Vesting::claim`
(`docs/DESIGN.md` section 7.1). This is what the chain stores for a coinbase,
what it checks, and what it deliberately does not.

### 10.1 The record

Three storage items carry one coinbase note, and two of them are the ones every
shielded leaf already uses.

| Item | Key | Value | Written by |
|---|---|---|---|
| `ZkTree::Leaves` | leaf index | `cm` | the append, like every other note |
| `Shielded::LeafBlocks` | leaf index | block number | the mint |
| `Shielded::CoinbaseValues` | leaf index | value in pool steps | the mint |
| `Shielded::Ciphertexts` | leaf index | the payload, when there is one | the mint |

`CoinbaseValues` is the only new one, and presence in it is what marks a leaf a
coinbase. A wallet reads it in the same batch as the other three, so a coinbase
costs one extra storage key per leaf on a sync and no extra round trip.

Two more items are per block rather than per leaf. `PendingCoinbase` is the
payload the inherent recorded, killed at the start of every block and taken by
the mint, so it never survives its block. `PendingCoinbaseFee` is the author's
share of the fees settled so far, which the mint folds into the note's value.

`PendingCoinbaseFee` does normally carry. A note's value is a whole number of
pool steps, so a successful mint writes `total % POOL_STEP` straight back
into it (`pallets/shielded/src/lib.rs`, `mint_coinbase`, pinned by
`sub_step_change_stays_for_the_next_coinbase`), and that sub-step remainder is
what a healthy chain shows at the start of most blocks: on the dev chain it
completes one extra step roughly every eighth block. A non-zero
value there says nothing on its own about whether the previous block minted.
The second reason it can be non-empty is the one section 10.6 lists: a block
that mints no note at all leaves the whole share sitting in it.

The event is `CoinbaseMinted { block_number, leaf_index, inner, value,
has_ciphertext }`. It publishes `inner`, which the storage does not, so a wallet
that watches events can check a note without rebuilding the commitment from the
leaf. The payload is a flag rather than the bytes: the bytes are already in
`Ciphertexts` under the leaf index, and republishing them would put every
author's payload in two places forever. Under v1 the flag is false on every
block, because the inherent refuses a non-empty payload (section 10.4).

No event and no storage item names the block's author. The header's
`PreRuntime` item, which the runtime hashes into the account it calls the
author, is `H(cvk, parent_hash)` and changes every block, so nothing groups the
coinbase leaves one miner produced.

### 10.2 The two rules the note is built from

```text
chain = H_bytes("qnero/coinbase-chain", genesis_hash)
rho   = H(RHO_COINBASE, block_number)                   0x716e_000a
r     = H(R_COINBASE, cvk, chain, block_number)         0x716e_000b
inner = H(NOTE, pk, rho, r)
cm    = H(CM, inner, value)
```

`rho` is the block number because a block mints exactly one coinbase note, so
the height names it and no two coinbase notes can share a nullifier seed. It is
not the pool's entry counter, which is what a shield takes: the node builds
`inner` while it is proposing, and how many shields the block will carry is not
known then.

`r` is derived from a coinbase viewing key rather than drawn at random, and that
is the one place v1 departs from the design that preceded it. Every other note
reaches its recipient as an ML-KEM ciphertext; a block author's node cannot
build one, because the chain's own post-quantum Noise transport pins `ml-kem`
0.2 through `clatter`, the wallet's note encryption uses `ml-kem` 0.3, and the
two share a `kem` dependency that resolves to a single version. A binary cannot
hold both. `qnero-note-core` exists for that split and its module documentation
states it. So the operator configures its node with a miner key, `pk` and `cvk`
in one bech32m string, and the node derives the note.

What that keeps: the note is private against anyone holding the miner's
address, because recovering `pk` from `inner` needs `r`, which needs `cvk`.

What it costs: `cvk` is a viewing-tier secret for coinbase notes. Whoever holds
it, with the address, can pick that miner's coinbase notes out of the tree. It
cannot spend them, which needs `ask`, and it says nothing about any other note.

What it costs, second: there is no randomness in the derivation, so one key at
one height on one chain is always one note. Two proposals at a single height,
which is what a re-proposed block or an orphan looks like, carry the same
`inner`; only the canonical one is ever in a tree, and the header's author
label `H(cvk, parent_hash)` is already identical for two candidates on one
parent, so the note adds no linkage the block did not already carry. Monero
draws a per-block random `r` and does not have even that. What determinism must
not do is cross a chain boundary, which is why the genesis is in the preimage:
one miner key configured on a testnet and on mainnet, or on any two chains with
different genesis blocks, would otherwise publish identical `inner` values at
equal heights on both, and anyone who could name that operator's coinbase notes on
the chain that matters less would name them on the other by comparing 32 bytes.
Both the node and the wallet already hold the genesis hash, so the binding
costs a scan nothing. The boundary is the genesis hash and nothing else: a
deterministic spec rebuilt from the same inputs, `--dev --tmp` being the one
every developer runs, is the same chain by this rule and does mint the same
notes.

What it does not cover: a coinbase paid to an address whose `cvk` the author
does not hold. The wallet reads an encrypted payload
(`qnero_notes::try_receive_coinbase`), nothing produces one, and the inherent
refuses one until something does and its bytes are priced (section 10.3).

### 10.3 What the chain checks

- `inner` is four canonical Goldilocks limbs. Checked at the inherent, because the mint runs in a
  hook and a hook cannot refuse anything.
- The value is a whole number of pool steps below `2^62`. The same cap every creation path carries;
  the no-wrap argument behind the balance equation (section 5, constraint 8) holds only while every
  term is below it.
- The block has an author, through the runtime's one `FindAuthor` seam.
- The block has exactly one coinbase. A second inherent fails, and a mandatory dispatch that fails
  takes the block.
- A block with no coinbase inherent at all is refused on import, because the inherent is required.
- The ciphertext field is empty. Nothing builds an encrypted coinbase payload yet, an inherent pays
  no fee, and a mandatory dispatch does not compete for block weight, so an accepted payload would
  be the one place on the chain where permanent state is free. The settlement path charges
  `MinLeafFee + ceil(bytes / CiphertextBytesPerFeeQuantum)` for the same `Ciphertexts` map, and an
  author writing `MaxCiphertextBytes` of anything on every block it won would pay nothing for bytes
  every full node keeps forever. A non-empty payload would also mark its own leaf, since a derived
  coinbase publishes none. When the third-party path lands (section 10.6), the field's bytes get
  priced against the author's own credit and the refusal is lifted.

### 10.4 What the chain does not check

The payload is the author's own. `pk` is inside an `inner` the chain cannot
open, `cvk` is not on the chain at all, and the ciphertext, when there is one,
is bytes the chain never parses. An author that malforms any of it strands its
own reward and nothing else: the value is the chain's own arithmetic, so a
malformed payload cannot mint more than the emission, and the commitment is over
that value, so it cannot be opened at another one.

There is no `ct_digest` here, unlike a settling slot. A settlement's ciphertexts
are bound to a proof; a coinbase has no proof and no second party, so there is
nothing for a digest to bind.

### 10.5 Two books, one supply

`Balances::total_issuance()` counts transparent balances. `Shielded::PoolValue`
counts what the pool holds, and shielding burns from the shielder, so a planck
that moves into the pool leaves issuance behind. Under v1 nearly every planck is
in the pool.

The emission schedule therefore measures both: `pallet-mining-rewards` adds
`PoolValue + PendingCoinbaseFee` to the issuance it reads before subtracting
from `MaxSupply`. Without that term supply appears to fall as the pool fills and
the schedule mints faster forever.

The ledger of one block, end to end:

```text
settlement       PoolValue -= fee
                 burn share: gone, from both books
                 author share: PendingCoinbaseFee += share
coinbase mint    total = emission + collected tx fees + PendingCoinbaseFee
                 PoolValue += total
                 PendingCoinbaseFee = sub-step remainder, if any
```

The emission and the collected fees are value that is in neither book when the
mint runs: emission has not been created and transaction fees were destroyed
when their imbalance dropped. Adding them to `PoolValue` is what creates them,
in the pool, as a note. Nothing is minted into an account anywhere in this path.

### 10.6 What M6 left open

- **Nothing verifies that a coinbase note is spendable by anyone.** The chain hashes an `inner` it
  cannot open, so a node with a corrupt miner key mints notes nobody holds, block after block, and
  the only symptom is a wallet whose balance does not grow. The node's own smoke path is the check:
  build a payload, and have the wallet find it. `qnero-wallet sync` reporting
  `coinbase_received` below `coinbase_leaves` on a chain you are the only miner of is the signal.
- **A coinbase for a third party has no builder.** The wallet reads an encrypted payload and
  nothing produces one, so the inherent refuses a non-empty ciphertext (section 10.3). Lifting the
  refusal means pricing the bytes the way a settling slot's are priced, against the author's own
  credit, in the same change that builds one; `docs/WALLET.md` open issue 16.
- **The author is not bound to the payload.** Any block author can put any `inner` in its own block,
  which is correct, and nothing stops a node operator from paying its reward to an address it does
  not control. That is a configuration error rather than an attack: it costs the operator its own
  reward and nobody else anything.
- **`PendingCoinbaseFee` can strand value across a chain halt.** The author's share of a settled fee
  lives there between the settlement and the block's own `on_finalize`. A chain that stops between
  the two leaves it in state, counted by `ShieldedSupply` and backed by nothing that will ever mint
  it. It is at most one block's fees.

### 10.7 What a v1 block reveals

The rest of section 10 is about what the coinbase hides. This is the other
half, in one place, because a reader deciding what Qnero is has to be able to
find it.

| Published | Where | What it ties together |
|---|---|---|
| A shield's payer, its value and the leaf it created | `Event::Shielded { who, value, commitment, leaf_index, entry_index, ciphertext }` | the account that paid, the exact amount, and the note it became |
| A coinbase note's value and its block | `Shielded::CoinbaseValues`, `Shielded::LeafBlocks` | how much was minted, and when |
| Every leaf's commitment, and the tree root in each header | `ZkTree::Leaves`, the header | the shape of the tree and its growth per block |
| Every settled nullifier | `Shielded::UsedNullifiers` | that some note was spent, never which one |
| Each settlement's slot count and fee | `Event::BatchSettled` | how many leaf slots a submission settled and what it paid |
| Each settled slot's two nullifiers, its two commitments, both leaf indices and both ciphertexts | `Event::SlotSettled` | the two notes one spend created, at consecutive leaf indices, publicly siblings and publicly tied to the two nullifiers spent alongside them |
| A vesting payout's beneficiary and amount | `Event::Claimed { schedule_id, beneficiary, amount }` | a genesis-fixed allocation, the account it went to, and when |
| A burn's account and amount | `Event::Burned { who, amount }` | value leaving circulation, and the account it left from |
| A refused call's own arguments | the block body and `System::ExtrinsicFailed` | who tried to send what to whom, though nothing moved |

The last row is the one a reader is least likely to expect. `QneroCallFilter`
is a `BaseCallFilter`, checked at dispatch, so a transparent transfer is a
valid extrinsic that enters a block, pays its fee and then fails with
`CallFiltered`. Its arguments are in the block body and its failure is in the
events, permanently, even though no value moved. One mistaken attempt therefore
publishes exactly the sender, recipient and amount triple the policy exists to
deny. A wallet should refuse these calls client-side rather than let a node
publish them; `docs/DESIGN.md` section 7.2 carries the option of moving the
refusal to validation, where a refused call never reaches a block.

`SlotSettled` is the strongest linkage a settlement publishes, and it is what
makes the nullifier row above weaker than it reads: the set alone says only
that some note was spent, while the event names which two nullifiers were
spent together and which two leaves that spend created. A payment and its
change are therefore publicly a pair. Which of the two is which is the part the
wallet hides, by drawing the payment's output slot per spend; `docs/WALLET.md`
carries that rule and the reason it is needed.

The entry is the sharp edge. `shield` is a signed extrinsic, so the payer's
account, the amount and the leaf index are all on chain together, and value
that enters the pool that way is linked to the account it came from at the
moment it enters. What is not linked is anything after: the note's spends are
proofs, and the commitment a shield publishes is the last time that value has a
name. A wallet that wants the entry itself unlinked has to receive rather than
shield, which under v1 means being paid from the pool.

A coinbase is the opposite shape. Its value and block are public, and its
recipient is inside an `inner` the chain cannot open. Nothing beside it names
the miner: the header's author item changes every block (section 10.1), the
events carry amounts and no accounts, and `pallet-mining-rewards` reads the
seam only to ask whether a block has an author at all.
