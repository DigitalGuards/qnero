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
indices, leaf creation blocks, coinbase values, entry counter, ciphertext
values, and complete settled-nullifier map. The spending path uses the same
read methods. The runtime's active protocol profile is authenticated before
building or using circuits. Header and commitment-tree consistency checks
remain additional checks.

The nullifier map needs completeness as well as membership. The wallets page
its public keys, request raw proofs for the entire returned pages, then traverse
the complete prefix locally. An omitted hashed subtree causes an incomplete
proof error. An inline entry can be recovered directly from the proof even if
the key listing omitted it. An empty listing still requires a proof of an empty
prefix. The wallets do not form these requests from private note nullifiers.

## Retained ciphertexts and historical recovery

The current runtime retains ciphertexts in its state cache for a limited window.
For an older leaf, the wallet authenticates `LeafBlocks` at its scan head, links
the creation block to that selected chain through rehashed parent-linked header
ranges, and reads the ciphertext with a proof at the creation block's state
root. Historical requests are grouped by creation block. A competing branch's
historical state cannot satisfy that ancestry check.

Restoring an old wallet requires a node that serves historical state proofs.
Ordinary state pruning can remove that service even when the node still has
headers and block bodies. The current fallback uses historical state, so an
archive provider must preserve it. Missing data stops the pass before its scan
watermark or note changes are committed. Body-based recovery is separate work.

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
