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
