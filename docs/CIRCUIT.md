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
| 22..26 | 4 | `ct_digest` | digest of the output ciphertexts |

This is the layout `docs/DESIGN.md` section 6 specified, with no deviation.

What the chain does with it, at M4: check that `block_hash` is the hash of the
block at `block_number`; check that neither nullifier is in `UsedNullifiers`
and insert both; append `cm_out_1` and `cm_out_2` to the commitment tree;
recompute the digest of the ciphertexts in the extrinsic and compare it to
`ct_digest`; account the fee.

`ct_digest` is deliberately unconstrained inside the circuit. Hashing
kilobytes of ML-KEM and AEAD ciphertext in circuit would dominate the proof;
the chain recomputes the digest from the bytes it was handed, which binds them
to this proof just as tightly.

## 2. Private witness

Per input note, twice:

- `ask` (4 felts), `nk` (4 felts): the spend credential.
- `value` (1), `rho` (4), `r` (4): the note.
- a Merkle path: 16 levels of 3 sibling digests plus a position hint per level.
- `is_dummy` (1 bit).

Per output note, twice: `pk` (4), `value` (1), `rho` (4), `r` (4).

Plus the header preimage (`parent_hash`, `state_root`, `extrinsics_root`,
`zk_tree_root`, 28 felts of digest logs) and one `depth` shared by both paths.

`pk` is never witnessed for an input. It is derived in circuit from `ask` and
`nk`, so a wrong credential produces a commitment that is not in the tree.
Witnessing `pk` and constraining it to equal the derived value is equivalent
and costs one more equality.

## 3. Hash rules

All of these are `qnero-notes`, reused verbatim: the circuit imports the domain
constants from that crate so the two cannot drift, and a parity test compares
what the circuit publishes against `Note::commitment` and `Note::nullifier`
for the same witness.

```text
ak    = H(AK,   ask)
pk    = H(PK,   ak, nk)
inner = H(NOTE, pk, rho, r)
cm    = H(CM,   inner, value)
nf    = H(NF,   nk, rho)
```

`H(tag, parts...)` is Poseidon2 over the concatenation with the one-felt domain
tag first. `value` is a single field element over its full 62-bit range, not
the two 32-bit limbs the Wormhole leaf uses for a `u64`.

The header hash keeps the chain's preimage order:

```text
block_hash = Poseidon2(parent_hash(4) || block_number(1) || state_root(4)
                       || extrinsics_root(4) || zk_tree_root(4) || digest(28))
```

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
and is what the wallet and the tests build paths with.

### What `pallet-zk-tree` must change at M4

Today `Leaves` is `StorageMap<_, Identity, u64, ZkLeaf<AccountId, AssetId,
Balance>>` and `get_leaf_hash` always recomputes `hash_leaf` from those four
typed fields. There is no slot for a raw hash, and `insert_leaf(to,
transfer_count, asset_id, amount)` is the only entry point.

The fork is small and mechanical:

1. `Leaves` becomes `StorageMap<_, Identity, u64, Hash256>`.
2. `get_leaf_hash` becomes the identity read (missing leaf stays `empty_hash`).
3. `insert_leaf` becomes `insert_leaf(commitment: Hash256)`. It must reject a
   non-canonical commitment (every limb below the Goldilocks modulus), because
   the 8-bytes-per-felt decode reduces mod p and a non-canonical alias would
   commit to the same tree position as a genuine commitment.
4. `hash_leaf` and `canonicalize_account_bytes` are dropped, and with them the
   non-injective-encoding invariant they carried.
5. `tree::hash_node`, `update_range`, `grow_tree`, `generate_proof`,
   `verify_proof`, the `Nodes` map, depth growth and the `on_finalize` root
   publication are all unchanged.

Two properties of the pallet that the wallet must respect and that do not
change: a leaf appended in block N is only provable after that block's
`on_finalize`, so a note cannot be minted and spent in the same block; and
`CIRCUIT_MAX_TREE_DEPTH` must stay equal to the circuit's `MAX_DEPTH`.

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
2. `depth <= MAX_DEPTH`, split into bits once and shared by both paths.
3. Per input: `pk = H(PK, H(AK, ask), nk)`, `cm = H(CM, H(NOTE, pk, rho, r),
   value)`, the path from `cm` reaches `zk_tree_root`, and
   `nf = H(NF, nk, rho)` is published. The root equality is gated:
   `(root_limb - zk_tree_root_limb) * (1 - is_dummy) == 0`.
4. Per input: `value * is_dummy == 0`, and `value < 2^62`.
5. `nf_1 != nf_2`. Equal nullifiers would be the same note spent twice inside
   one leaf, which a chain that inserts both nullifiers from one transaction
   without intra-transaction dedup would not catch. This is an addition over
   the Wormhole leaf, which has a single nullifier.
6. Per output: `cm_out = H(CM, H(NOTE, pk, rho, r), value)` bound to the public
   commitment, and `value < 2^62`.
7. `fee < 2^62`.
8. `v_in_1 + v_in_2 == v_out_1 + v_out_2 + fee`, as a field equation. Every
   term is below `2^62`, so the left side is below `2^63` and the right side
   below `3 * 2^62`, both below `p = 2^64 - 2^32 + 1`, and their difference is
   smaller than `p`. Equality in the field is therefore equality over the
   integers: no wraparound can fake a balance. This is why the fee is range
   checked at all, and why the two-input shape cannot be widened to four inputs
   at 62 bits without redoing the argument.

### Dummy inputs

`is_dummy` is a witnessed bit. The circuit does not derive it from the public
inputs the way the Wormhole leaf derives its dummy-leaf sentinel. Setting it
forces the input's value to zero and skips only the membership check; the nullifier is
still computed from the witnessed `nk` and `rho` and published, so a dummy slot
is not visible in the public inputs. Claiming `is_dummy` for a note one does
own gains nothing: the value is zeroed, so the spender only loses the note's
value from the balance.

The wallet must give every dummy a fresh `rho`, both because two dummies with
the same `(nk, rho)` would collide under constraint 5, and because a repeated
dummy nullifier would be rejected on chain as already used.

This is a different mechanism from the Wormhole leaf's dummy, which marks a
whole leaf as padding for the batch and makes the header binding conditional on
an in-circuit sentinel. Qnero's leaf is always a real leaf.

## 6. Measured size

`cargo test -p qnero-prover --release -- --ignored --nocapture`, on the
development workstation, single threaded (plonky2's `parallel` feature is off
so a prover cannot saturate a machine unasked):

```
gates before padding : 316
degree_bits          : 9
public inputs        : 26
zero knowledge       : false
build                : 73 ms
prove, warm          : 302 ms
verify               : 2.5 ms
proof bytes          : 105500
```

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

- **Batch padding sentinel.** A private batch of N leaves needs dummy leaves
  when fewer than N real ones are available. The Wormhole wrapper recognises a
  dummy by an all-zero `block_hash` and re-masks every field it reads from a
  dummy slot, because the leaf's sentinel did not cover the exit accounts. The
  recommended Qnero shape is a fixed dummy header preimage whose `block_hash`
  is a known constant: it is derived in circuit from public inputs the wrapper
  already reads, it cannot be claimed by a leaf that also binds to a real
  block, and the wrapper must still mask the commitments, nullifiers and fee of
  a dummy slot, trusting no invariant that crosses a circuit boundary.
- **Verifier artifact pinning.** `qnero-verifier` loads verifier data from
  bytes behind a size cap, with no keccak pin yet: there is no tagged circuit
  release to pin. The first release adds the pin, and every circuit change
  after that invalidates it.
- **Coinbase and deposit range checks.** Every value that enters the pool
  outside a spend must be range checked to 62 bits by the pallet, or the
  balance argument in constraint 8 does not hold for notes created that way.
- **Nullifier seed uniqueness.** `nf = H(NF, nk, rho)` means two notes to the
  same recipient with the same `rho` share a nullifier and only one is ever
  spendable. The sender picks `rho`; M5's wallet must sample it fresh, and M4
  should consider whether the chain can cheaply reject a duplicate `rho` at
  deposit time.
- **Witness zeroization.** `ask` and `nk` live in plain `Digest` values inside
  `InputNote`, protected only by redacting `Debug`. Upstream wraps the
  equivalent material in a zeroize-on-drop container. Worth doing before a
  wallet holds real keys.
