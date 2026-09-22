# Authenticated wallet reads

Both wallets reconstruct storage values and absence from `state_getReadProof`
at a selected block hash. The shared `qnero-state-proof` crate uses the chain's
`sp-trie` 42.0.1, V1 layout, and Blake2-256 state hasher. The block header itself
is hashed with Qnero's Poseidon2 header implementation. Its recomputed hash must
match the requested block before its state root is used.

The browser runs the same Rust trie verifier in its existing verification
worker. A missing worker, unsupported proof RPC, missing proof node, wrong
block, wrong root, or unavailable historical data refuses the operation.
There is no unproven storage fallback.

## What is authenticated

The scan proves the tree count and depth, commitments at their exact storage
indices, leaf creation blocks, coinbase values, entry counter, and the complete
settled-nullifier map. Note ciphertexts are not among them: the runtime keeps
none in state, so what authenticates a payload is the header's
`extrinsics_root` over the block body that carried it. The spending path uses the same
read methods. The runtime's active protocol profile is authenticated before
building or using circuits. Header and commitment-tree consistency checks
remain additional checks.

The nullifier map needs completeness as well as membership. The wallets page
its public keys, request raw proofs for the entire returned pages, then traverse
the complete prefix locally. An omitted hashed subtree causes an incomplete
proof error. An inline entry can be recovered directly from the proof even if
the key listing omitted it. An empty listing still requires a proof of an empty
prefix. The wallets do not form these requests from private note nullifiers.

## Where the note ciphertexts are

The runtime keeps no note ciphertext in state. `CiphertextRetentionBlocks` is a
`#[pallet::constant]` pinned at 0 that nothing in the runtime reads, published
so that a wallet reading the pallet's metadata is told where the payload lives,
and protocol profile byte 76 says the same thing inside the profile a wallet
already authenticates against the header state root. A payload rides in the
extrinsic that created its note: a settlement carries every settled slot's pair
in `outputs`, a `shield` carries its own, and a coinbase note carries none
under v1.

What authenticates such a payload is the header's `extrinsics_root`, which sits
in the Poseidon header preimage beside `state_root` and which both wallets
already parse. A body checked against that root is complete by construction, so
there is no absence case to prove: a node either serves the whole body or the
recomputed root does not match.

Restoring an old wallet therefore requires a node that serves historical block
bodies rather than historical state proofs. Ordinary state pruning no longer
removes that service. Missing data stops the pass before its scan watermark or
note changes are committed.

## Resource limits

One proof or accumulated prefix proof is limited to 64 MiB of raw node bytes
and 1,000,000 nodes. Complete-prefix traversal is limited to 1,000,000 entries.
An archive ancestry cache holds at most 1,000,000 header hashes for one selected
tip; headers are fetched in ranges of at most 1024. A tip change resets that
cache. Header state-root caches hold at most 64 entries per connection.

These are explicit wallet support limits. Reaching one refuses the pass rather
than reporting an incomplete set as complete. JSON transport, hex strings, trie
database overhead, and worker messages consume additional memory beyond raw
proof bytes. Browser artifact size, peak memory, and large-state performance
still require release qualification.

## Header selection remains trusted

The wallets verify header hashes and parent links against their stored genesis,
birthday, and checkpoints. They do not verify RandomX proof of work or cumulative
chain work. A configured node therefore remains trusted for chain selection
above the latest trusted checkpoint, freshness, and data availability. Operators
should use their own verified full node or an explicitly trusted provider and
checkpoint policy. A storage proof establishes the state of the selected header;
it does not establish that this header is on the canonical greatest-work chain.

Proof verification does not authenticate a remotely fetched runtime metadata
document. The compiled profile match and authenticated active profile reject
unsupported circuit releases. Storage namespaces and map key encodings are
fixed locally, including after a browser API metadata refresh. Other metadata,
including fee constants and transaction call indices, remains node-supplied
compatibility information. A profile match does not authenticate those fields.
