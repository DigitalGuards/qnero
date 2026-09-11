# pallet-shielded

The Qnero shielded pool. It settles the batch proofs produced by
`qnero-prover` and `qnero-aggregator`: it checks each segment's block
anchoring, refuses a nullifier it has already seen or one repeated inside the
submission, appends the note commitments to `pallet-zk-tree` as raw leaves,
binds the submitted ciphertexts to the proof through `ct_digest`, and accounts
the fee.

`docs/CIRCUIT.md` section 8.6 in the Qnero repository is the settlement
contract this implements, and section 4 is the leaf rule.

## Attribution

Forked from `pallet-wormhole` in Quantus-Network/chain (MIT-0), which is where
the shape of the verification pipeline comes from: the proof-size gate and the
canonical-encoding round trip ahead of any parse, the split between a cheap
`validate_unsigned` and a `pre_dispatch` that runs the ZK verify, the fixed
unsigned priority with a nullifier-derived pool tag, and the lazily loaded
verifier held to a profile. The upstream copyright notice and licence are in
`LICENSE` at the root of this repository.

What is not inherited: there are no exit accounts, no asset leg, no volume fee
in circuit and no per-segment denial. A Qnero settlement is all or nothing.
