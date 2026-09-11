# Changes from upstream

Upstream shape is `qp-wormhole-prover` (Quantus-Network/qp-zk-circuits, MIT).

## Kept

- One-shot lifecycle: `new` builds, `commit` consumes and fills, `prove`
  consumes and proves. The `Option<Targets>` is what makes a second `commit`
  an error; without it a second witness would silently merge into the first.
- Redacting `Debug`. After `commit` the partial witness holds the spend
  credential.
- No prover artifact is loaded or emitted, ever. Prover data carries the
  witness generators and the target list that decides which witness values
  become public inputs, so a poisoned artifact could exfiltrate a spend key
  through the victim's own proof. The leaf builds from source in about 70 ms.

## Changed

- `commit` takes a `SpendWitness`, and witness filling lives in
  `qnero-circuit`, because the batch layer will need the same entry point for
  padding leaves.
- `prove` on an uncommitted prover is an error with that wording. Upstream
  reaches plonky2 with an empty witness and fails there.
- `commit` and `prove` drop the underlying plonky2 error. An unsatisfied copy
  constraint is reported as `Partition containing Wire(..) was set twice with
  different values: <a> != <b>`, and both values are witness material: a note's
  plaintext amount, or the limbs of a Merkle node that place the note in the
  tree. A witness desync is routine for a wallet, so a logged error would write
  the spent note's amount and position next to the nullifier about to be
  published. Structural errors from `SpendWitness::validate` (depths, path
  lengths, arity) are still returned verbatim.

## Added

- `wallet::WalletProver` (M3): the API a wallet uses. It builds the leaf and
  private-batch circuits once, proves a leaf per transfer, aggregates them into
  the private batch that is the transaction, and hands back the canonical
  proof bytes. The leaf proofs never leave it, which is the point: a leaf proof
  does not blind. Upstream's prover crate stops at the leaf and leaves the
  aggregation to its caller.
- An opt-in `parallel` feature, which turns on plonky2's rayon support for this
  crate and the aggregator. Off by default so a wallet cannot saturate a
  machine unasked; the proofs are identical either way.
