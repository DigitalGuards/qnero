# Protocol and verifier release identity

Qnero clients check a versioned profile before building spend circuits. The
profile commits to protocol parameters and to the exact serialized verifier
artifacts used by the runtime. Its definition and supported release pins are in
`crates/qnero-circuit/src/profile.rs`.

## Discovery and authentication

The `Shielded.ProtocolProfile` metadata constant exposes the embedded profile.
`Shielded.ActiveProtocolProfile` stores the same 192 bytes in consensus state.
Genesis initializes that value, and every runtime upgrade refreshes it from the
new runtime's embedded artifacts. Existing chains require the runtime upgrade
before upgraded wallets can send. New genesis configurations have a different
state root and retain the wallet's existing genesis binding.

Native and browser wallets compare metadata against the profile compiled into
their release, then verify the fixed storage key against the selected header's
state root before circuit construction. They check again before proving against
the selected anchor. Missing, malformed and mismatched profiles fail closed.
Both wallets also compare freshly built leaf and private-batch verifier hashes
against the release pins before proving a private witness.

The storage proof authenticates the profile relative to that header. Header
selection still follows the wallet's trusted-node and checkpoint policy. The
profile does not establish RandomX work, certify proof soundness, or replace
genesis binding. Runtime spec and transaction versions continue to describe the
outer runtime and extrinsic interfaces; profile identity describes the shielded
protocol and verifiers.

## Canonical encoding

The encoding is exactly 192 bytes, with unsigned little-endian integers and no
SCALE vector length prefix. Offsets below are zero-based, with the end excluded.

| Bytes | Meaning |
| --- | --- |
| 0..8 | ASCII `QNRPRF01` |
| 8..10 | Profile format version, currently 1 |
| 10..20 | Five u16 versions: spend protocol, note codec, ciphertext codec, verifier artifact codec, header codec |
| 20..22 | Maximum circuit tree depth |
| 22..27 | Tree arity, input count, output count, value range bits, QNR decimal places |
| 27..32 | Five suite IDs: note/tree hash, proof hash, note KEM, note AEAD, child ordering |
| 32..40 | Planck per pool step |
| 40..46 | Three u16 parameters: declared proof security bits, challenge count, FRI query rounds |
| 46..48 | FRI rate bits, cap height |
| 48..52 | FRI grinding bits |
| 52..60 | Four u16 parameters: leaf degree bits, private-batch wire count, routed wire count, extension degree |
| 60..64 | Two u16 dimensions: leaves per private batch, private batches per public batch |
| 64..76 | Three u32 public-input lengths: leaf, private batch, public batch |
| 76 | Ciphertext storage mode: 1, live cache with archive-state recovery |
| 77 | Experimental proof-system flag: 1 |
| 78..80 | Reserved, zero |
| 80..84 | Live ciphertext retention, 64 blocks |
| 84..88 | Maximum ciphertext writes per block, 2048 |
| 88..92 | Maximum ciphertext prunes per block, 4096 |
| 92..96 | Reserved, zero |
| 96..128 | Leaf verifier artifact digest |
| 128..160 | Private-batch verifier artifact digest |
| 160..192 | Public-batch verifier artifact digest |

Each suite ID is 1 in version 1: Poseidon2 over Goldilocks for notes and trees;
original `PoseidonGoldilocksConfig` for the proof transcript and commitments;
ML-KEM-1024 for note delivery; ChaCha20-Poly1305 for note encryption; sorted
quaternary children for the commitment tree. The declared proof target remains
100 bits and is separate from the security level of the note KEM.

The ciphertext mode bounds current-state payload retention. Historical wallet
recovery needs an archive node that can serve creation-block state proofs.
Node operators must preserve that history; this profile does not make pruned
payloads recoverable from an ordinary current-state node.

## Reproducible artifacts

`qnero-circuit-builder` produces `protocol_profile.bin`, a readable
`protocol_profile.json`, and the `PROTOCOL_PROFILE` Rust constant alongside each
complete public-batch artifact set. Digests use Blake2b with a 32-byte output over
the complete verifier file, including the public-batch dimension header. Padding
proofs use randomness and are excluded from release identity.

The supported profile uses six leaf slots and 53 private batches per public batch:

| Artifact | Blake2b-256 |
| --- | --- |
| `leaf_verifier.bin` | `c112dffe8f7ce4b83c7fea4bca1751f8c1de7ad4090c72faaf037fe3869368dc` |
| `private_batch_verifier.bin` | `2ffd9f4bea8079f757c48936b0cd6aba62242ee1abb2167b32bd4329ad4f9c52` |
| `public_batch_verifier.bin` | `8ea527ca522426e5d18109ba12cdf85079f2b4bbc8aaaf49d92dfed35d564ec2` |

Default artifact generation must reproduce those pins or fail before publishing
the set. Experimental dimensions still generate an accurate profile; the release
wallet refuses them. A circuit or protocol change requires an intentional profile
update, regenerated artifacts, matching wallet releases, and an explicit chain
upgrade or reset decision. Publish the generated manifest with native, runtime,
browser and aggregator releases, together with their source revision and binary
checksums.
