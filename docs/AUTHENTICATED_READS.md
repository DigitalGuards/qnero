# Authenticated wallet reads

Both wallets reconstruct storage values and absence from `state_getReadProof`
at a selected block hash. The shared `qnero-state-proof` crate uses the chain's
`sp-trie` 42.0.1, V1 layout, and Blake2-256 state hasher. The block header itself
is hashed with Qnero's Poseidon2 header implementation. Its recomputed hash must
match the requested block before its state root is used.

Note ciphertexts are not in state at all. They ride in the block bodies that
carried the settlement or the shield, and the same crate recomputes a body's
`extrinsicsRoot` with `LayoutV0<Blake2Hasher>::ordered_trie_root`, which is the
construction `frame_system` makes while the runtime's `system_version` is 1.
A body is authenticated against the `extrinsicsRoot` of the header already
rehashed to the hash it was asked for.

The browser runs the same Rust trie verifier in its existing verification
worker. A missing worker, unsupported proof RPC, missing proof node, wrong
block, wrong root, or unavailable historical data refuses the operation.
There is no unproven storage fallback.

## What is authenticated

Against the header's state root: the tree count and depth, commitments at their
exact storage indices, leaf creation blocks, coinbase values, the entry counter,
and the complete settled-nullifier map. The spending path uses the same read
methods. The runtime's active protocol profile is authenticated before building
or using circuits. Header and commitment-tree consistency checks remain
additional checks.

Against the header's `extrinsicsRoot`: the whole block body, one block at a
time. That is a stronger shape than the per-key reads. A state read proves one
value and an absent answer has to be caught by a rule about which keys a leaf
owes; a body roots as a whole, so a node that drops one extrinsic, reorders
two, or appends one reaches a root no header carries. There is no per-payload
absence left to detect.

Which leaf a payload belongs to is decided by neither root. The wallet trial
decrypts every payload a block's body carries and requires the note that comes
out to match a commitment at some leaf index inside that block's folded leaf
range, which the block's own `zkTreeRoot` already pinned. The search reads no
index a node chose, so a payment moved to another position inside its block,
the coinbase position included, is still found.

The nullifier map needs completeness as well as membership. The wallets page
its public keys, request raw proofs for the entire returned pages, then traverse
the complete prefix locally. An omitted hashed subtree causes an incomplete
proof error. An inline entry can be recovered directly from the proof even if
the key listing omitted it. An empty listing still requires a proof of an empty
prefix. The wallets do not form these requests from private note nullifiers.

## Block bodies

`CiphertextRetentionBlocks` is 0 and the runtime writes no ciphertext to state,
so there is no retention window and no historical state to fall back to. The
wallet fetches one body per block that appended a leaf, through `chain_getBlock`
at that block's hash, and roots it against the header it has already rehashed.

Restoring an old wallet therefore needs a node that serves historical block
bodies rather than historical state proofs. A node pruning state can still
answer; a node that has dropped bodies cannot. The refusal is by name: a block
whose body a node will not serve names the block and the height, and the pass
commits no watermark and no note, so another node answers the same pass.

## Resource limits

One proof or accumulated prefix proof is limited to 64 MiB of raw node bytes
and 1,000,000 nodes. Complete-prefix traversal is limited to 1,000,000 entries.
One block body is limited to 6 MiB and 65,536 extrinsics, checked before
anything is hashed: `RuntimeBlockLength` caps a block at 5 MiB of extrinsic
data and the margin covers the compact length prefixes the RPC adds. Header
state-root caches hold at most 64 entries per connection.

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
