# Changes from upstream

Upstream is Quantus-Network/qp-zk-circuits 4.4.0 (MIT). Qnero forks the leaf
circuit; the note fragments replace the Wormhole transfer fragments.

## Removed

- `unspendable_account`, `substrate_account` (dual exit accounts) and
  `nullifier` fragments. A Wormhole leaf carries exit accounts and a
  transfer-count nullifier; a Qnero leaf carries note commitments and note
  nullifiers.
- The `ZkLeaf` preimage (`to`, `transfer_count`, `asset_id`, `amount`). A
  Qnero tree leaf is the note commitment itself; see `docs/CIRCUIT.md`.
- `TransferProofJson` and the legacy MPT storage-proof constants.
- The 64-bit branch of `is_const_less_than` (`split_canonical_u32_halves`,
  `u32_lt`). Every comparison here is at most 62 bits, where `split_le` is
  unique, so the wraparound-alias branch is dead code. `is_const_less_than`
  now asserts `n_log <= 63`.
- `CircuitFragment`. Fragment `circuit()` functions took no `self`, so the
  trait bought nothing over free functions; the constraints are plain
  functions and witness filling is one `fill_witness` entry point.

## Changed

- One shared `depth` target for the whole leaf, since both input notes are in
  the same tree at the same block. Upstream carries one per Merkle proof.
- `depth` is split into bits once and the 16 `level < depth` flags are derived
  from those shared bits. Upstream `zk_merkle_proof.rs` calls
  `is_const_less_than` per level, and each call range-constrains `depth` again.
- Leaf hashing is the identity: the tree leaf is the note commitment, so the
  circuit feeds the computed `cm` straight into the path. There is no leaf
  preimage to hash.
- The Merkle root is read from the header's `zk_tree_root` directly. Upstream
  carries a private `root_hash` target and binds it to the header afterwards.
- Public inputs are registered in one place (`SpendTargets::new`), in the order
  given by `layout.rs`, with `PUBLIC_INPUT_LEN` asserted in a test. Upstream
  spreads registration across each fragment's `Targets::new` and depends on
  their call order.
- The block-hash binding is unconditional, at every layer, where upstream makes
  it conditional on an in-circuit dummy-leaf sentinel so a batch can be padded.
  Qnero's padding leaf binds a real header preimage instead, the fixed one in
  `padding`, so nothing has to be switched off for padding to prove. See
  "Added" below and `docs/CIRCUIT.md` section 8.

## Added

- At least one input must be real (constraint 9): the product of the `is_dummy`
  bits is zero. Upstream has a single input and no equivalent. Without it a leaf
  with both inputs dummy proves with no spend key and no note in the tree, and
  still publishes two nullifiers and two commitments the chain writes into
  permanent state, at zero fee on a fee-free extrinsic.
- `nf_1 != nf_2` (constraint 5), for the same reason: upstream's leaf has one
  nullifier, so intra-leaf double spending is not a shape it can have.
- An output note's `rho` is a derived value, `H(RHO, nf_1, nf_2, j)` over both
  nullifiers the leaf publishes and the output index. Upstream has no note
  outputs at all. A freely chosen `rho` lets a sender pay one recipient
  twice with notes that share a nullifier, of which the recipient can spend
  exactly one; the other is stranded permanently. Sapling and Orchard bind an
  output's `rho` to a spent nullifier for the same reason. Both nullifiers are
  in the preimage because either slot may hold the dummy, and constraint 9 only
  guarantees that one of the two is real; a real note's nullifier is settled
  exactly once chain-wide, so the pair never repeats. Costs four Poseidon2
  permutations.
- A dummy input slot's nullifier is domain separated, `H(NF_DUMMY, nk, rho, r)`
  against `H(NF, nk, rho, r)` for a real slot, with the tag selected in circuit
  by the same `is_dummy` bit that gates membership. Upstream's leaf has no
  per-input dummy. A dummy proves no membership and carries no `ask`, so what
  it publishes is unauthenticated: under the real tag, a holder of a victim's
  `nk` and the victim note's `(rho, r)` could have the chain settle the
  victim's nullifier for a note nobody spent and burn it permanently. Costs one
  select per input and no extra permutation.
- The nullifier preimage carries the note's `r`. Upstream's nullifier is over a
  secret and a transfer count. Every Qnero output's `rho` is a public function
  of the leaf that created it, so without `r` a holder of `nk` alone could hash
  the public candidate set against the on-chain nullifiers and link a wallet's
  spends pool-wide; `r` reaches only the note's sender and its holder, the role
  Orchard gives `psi`. The preimage grows from 9 to 13 felts, which is the same
  two permutations.
- `InputNote::dummy_random`, which draws a padding slot's `(rho, r)` from a
  CSPRNG. A repeated dummy publishes a nullifier the chain has already settled.
- A `test-support` feature exposing `fill_witness_with_public_overrides`, which
  writes a public target that disagrees with the private witness beside it.
  Without it the constraints binding a published value to its in-circuit
  recomputation are untestable: `fill_witness` writes both sides from the same
  `qnero-notes` call, so a test comparing them compares a value to itself and
  stays green when the binding is deleted.
- `SpendWitness::validate` rejects a note value or fee at or above the
  Goldilocks modulus. It is the one range the circuit cannot police, because
  the witness carries such a value as its reduction, which is below `2^32` and
  therefore inside the 62-bit range check, and it is the range a wallet reaches
  by accident through a wrapping subtraction. Everything below the modulus is
  left to the circuit.
- `HeaderInputs::new` takes `state_root` and `extrinsics_root` as raw bytes and
  reduces them mod p, while `parent_hash` and `zk_tree_root` stay validated
  digests. Upstream decodes all four with the reducing decode; Qnero's `Digest`
  is strict by construction, so the two Blake2-256 roots, which need not be
  canonical, would otherwise be rejected and no spend could be anchored at such
  a block.
- `params`, the proof-system parameters of the canonical leaf, next to
  `layout` and compiled without the circuit feature. `qnero-verifier` holds an
  artifact to them; upstream pins a keccak hash of the artifact instead, which
  Qnero cannot do until there is a tagged release.
- `padding` (M3): the fixed header preimage a padding leaf binds to, the block
  hash it produces, pinned as limbs in a dependency-free module so a verifier
  and the chain can recognise padding without the prover stack, and the
  deterministic padding witness the artifact builder proves once. Constraint 9
  is gated on that sentinel and nothing else is: a padding leaf's balance
  equation then forces its fee and both output values to zero on its own. The
  batch wrapper masks every value a padding slot publishes regardless, because
  it trusts no invariant that crosses a circuit boundary.
- `batch_layout` (M3): the public-input layouts of the private and public
  batches, beside `layout` and compiled without the circuit feature, so
  `qnero-verifier` and the chain read a batch proof without plonky2's prover.
- `qnero_private_batch_circuit_config` and `qnero_public_batch_circuit_config`,
  next to the leaf configs. The private batch is the only layer that blinds.
- `sensitive::Secret` (M3), ported from upstream's `wormhole/circuit/src/sensitive.rs`
  and narrowed to one digest: `ask` and `nk` are now held in a move-only,
  zeroize-on-drop container with no `Debug`, so duplicating the spend
  credential takes an explicitly named `expose_digest` call. `InputNote` and
  `SpendWitness` lose `Clone` as a result, which is the point.
- `MerklePath::from_unsorted`, ported from upstream's
  `ZkMerkleProofData::from_unsorted`: the chain hands out siblings in
  child-index order with no position hint, and the circuit needs them sorted
  with one. `CommitmentTree::index_ordered_siblings` reproduces the chain's
  shape so the adapter is covered by a test.

## Kept

- The 4-ary sorted-children Merkle gadget, including the position-hint select
  cascade and the `MAX_DEPTH = 16` fixed-cost loop.
- The `CircuitConfig` structural validator, called before `CircuitBuilder::new`
  in every public constructor.
- The non-ZK leaf config. Zero knowledge belongs one layer up, at the private
  batch.
