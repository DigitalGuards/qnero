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
- The block-hash binding is unconditional (upstream makes it conditional on an
  in-circuit dummy-leaf sentinel for batch padding). Qnero's per-input dummy
  flag is a different mechanism; the batch padding sentinel is an M3 decision,
  recorded in `docs/CIRCUIT.md`.

## Added

- At least one input must be real (constraint 9): the product of the `is_dummy`
  bits is zero. Upstream has a single input and no equivalent. Without it a leaf
  with both inputs dummy proves with no spend key and no note in the tree, and
  still publishes two nullifiers and two commitments the chain writes into
  permanent state, at zero fee on a fee-free extrinsic.
- `nf_1 != nf_2` (constraint 5), for the same reason: upstream's leaf has one
  nullifier, so intra-leaf double spending is not a shape it can have.
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
