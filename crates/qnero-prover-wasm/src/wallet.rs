//! What a browser wallet needs besides proving, and cannot compute in JS.
//!
//! M8 shipped the proving path and nothing else, so a browser could derive an
//! address, decrypt a ciphertext and prove a request somebody else built. It
//! could not build the request: a spend names a Merkle path into a tree whose
//! root the anchor header commits to, and both the tree's node rule and the
//! header hash are Poseidon2 over Goldilocks. Neither is expressible in
//! JavaScript without a second implementation of every hash rule in
//! `docs/CIRCUIT.md` section 3, and a second implementation is a second thing
//! to keep in step with the chain.
//!
//! So these are exports rather than a TypeScript port:
//!
//! ```text
//! header_block_hash(anchor)            the anchor check: recompute what the chain says
//! tree_path(leaf_hashes, depth, index) rebuild the tree, take one path, report the root
//! path_from_unsorted(siblings, leaf)   the adapter for `zkTree_getMerkleProof`
//! note_digests(seed, v, rho, r)        commitment and nullifier for a held note
//! coinbase_note(seed, genesis, block)  the miner-key derivation a scan rebuilds from
//! entry_rho(block, entry_index)        the shield rule, for a wallet that predicts one
//! ct_digest(ct_1, ct_2)                what the leaf's public input commits to
//! miner_key(seed)                      the `qnm1...` a node is configured with
//! wallet_limits()                      the pad, the fixed ciphertext size, the depth cap
//! ```
//!
//! # The nullifier is the point of `note_digests`
//!
//! `decrypt_note` deliberately returns no nullifier: the ciphertext carries
//! `(value, rho, r)` and a nullifier needs `nk`, which never crosses the
//! boundary. A wallet still has to derive one, because spent status is decided
//! against the paged `UsedNullifiers` set and a point lookup on one nullifier
//! names it to whoever runs the node, weeks before the settlement that
//! publishes it. So the derivation happens here, from the seed, and the value
//! that comes back is as sensitive as the note: for an unspent note it has
//! appeared nowhere at all, and a leaked one lets a later reader attribute the
//! settlement with certainty. It must not reach a log, a URL or an error
//! message.
//!
//! # Why the tree rebuild takes bytes
//!
//! `tree_path` reads the whole leaf range because that is the read that
//! distinguishes nothing. Asking the node for one leaf's proof names one of
//! this wallet's leaves seconds before the settlement publishes the matching
//! nullifiers. The range is `32 * leaf_count` bytes, handed over as one
//! `Uint8Array` so the boundary crossing is one copy rather than `leaf_count`
//! of them.

use anyhow::{bail, ensure, Context, Result};
use qnero_circuit::chain::ct_digest as chain_ct_digest;
use qnero_circuit::header::DIGEST_LOGS_SIZE;
use qnero_circuit::merkle::{
    CommitmentTree, MerklePath, ARITY, MAX_DEPTH, SIBLINGS_PER_LEVEL,
};
use qnero_notes::{Address, Digest, Note};
use serde::Deserialize;
use serde_json::json;

use crate::request::{digest_from_hex, spending_key_from_hex, AnchorRequest};

/// The anchor header's own hash, recomputed from its preimage.
///
/// The chain's block hash is Poseidon2 over a felt encoding of the header, so
/// a generic Substrate client's Blake2 of the SCALE header is a different
/// number that looks exactly as plausible. A wallet compares this against
/// `chain_getBlockHash` **before** it proves: the digest re-encoding is the
/// part that goes wrong, and the alternative to checking is paying for a proof
/// and reading `BlockHashMismatch` off the pool.
pub fn header_block_hash_hex(anchor_json: &str) -> Result<String> {
    let anchor: AnchorRequest = serde_json::from_str(anchor_json)
        .context("the anchor does not parse")?;
    Ok(anchor.to_header()?.block_hash().to_hex())
}

/// `DIGEST_LOGS_SIZE`, so the caller's re-encoding is padded to the length the
/// chain hashes rather than to a number copied into TypeScript.
pub fn digest_logs_size() -> usize {
    DIGEST_LOGS_SIZE
}

/// Every leaf hash of one pass, as `32 * n` bytes.
fn leaves_from_bytes(leaf_hashes: &[u8]) -> Result<Vec<Digest>> {
    ensure!(
        leaf_hashes.len().is_multiple_of(32),
        "the leaf range is {} bytes, which is not a whole number of 32-byte digests",
        leaf_hashes.len()
    );
    leaf_hashes
        .chunks_exact(32)
        .enumerate()
        .map(|(index, chunk)| {
            let bytes: [u8; 32] = chunk.try_into().expect("chunks_exact(32)");
            Digest::from_bytes(&bytes).map_err(|_| {
                anyhow::anyhow!(
                    "leaf {index} is {} and is not four canonical Goldilocks limbs, so this \
                     wallet cannot rebuild the tree over it",
                    hex::encode(bytes)
                )
            })
        })
        .collect()
}

/// Rebuild the commitment tree at one block and take one leaf's path.
///
/// `depth` is `ZkTree::Depth` **read at the same block hash** as the leaves. A
/// rebuild at any other depth reaches a different root, and the root is what
/// makes a leaf index mean anything, so the caller compares the `root` this
/// returns against the anchor header's `zkTreeRoot` first, then the `leaf`
/// against its own note's commitment, and only then proves.
pub fn tree_path_json(leaf_hashes: &[u8], depth: usize, leaf_index: usize) -> Result<String> {
    let leaves = leaves_from_bytes(leaf_hashes)?;
    ensure!(
        leaf_index < leaves.len(),
        "leaf {leaf_index} is past the end of a {}-leaf range",
        leaves.len()
    );
    let tree = CommitmentTree::new(&leaves, depth)?;
    let path = tree.path(leaf_index)?;
    let leaf = leaves[leaf_index];
    Ok(path_json(&path, leaf, tree.root()))
}

/// The root a rebuild reaches, with no path taken.
///
/// The gate a sync runs before it trusts any leaf index: the rebuilt root has
/// to equal the header's `zkTreeRoot`, or the wallet is reading a different
/// tree from the one the anchor commits to.
pub fn tree_root_hex(leaf_hashes: &[u8], depth: usize) -> Result<String> {
    let leaves = leaves_from_bytes(leaf_hashes)?;
    Ok(CommitmentTree::new(&leaves, depth)?.root().to_hex())
}

/// The smallest depth that holds `leaf_count` leaves.
pub fn depth_for(leaf_count: usize) -> Result<usize> {
    CommitmentTree::depth_for(leaf_count)
}

/// Siblings in child-index order, the shape `zkTree_getMerkleProof` returns.
#[derive(Debug, Deserialize)]
struct UnsortedPath {
    siblings: Vec<[String; SIBLINGS_PER_LEVEL]>,
}

/// The adapter from the chain's proof shape to the circuit's.
///
/// `pallet-zk-tree` records no position, because its node rule sorts the four
/// children before hashing. The circuit does not sort, so it needs the sorted
/// siblings plus the slot the running hash occupies. Without this a path
/// fetched from a node reaches the wrong root and the leaf simply fails to
/// prove, tens of seconds in.
///
/// Only for the opt-in RPC route. Fetching a proof names the leaf being spent
/// to whoever runs the node, seconds before the settlement publishes the
/// matching nullifiers, so the default is [`tree_path_json`].
pub fn path_from_unsorted_json(unsorted_json: &str, leaf_hex: &str) -> Result<String> {
    let unsorted: UnsortedPath =
        serde_json::from_str(unsorted_json).context("the merkle proof does not parse")?;
    ensure!(
        unsorted.siblings.len() <= MAX_DEPTH,
        "the proof carries {} levels and the circuit takes at most {MAX_DEPTH}",
        unsorted.siblings.len()
    );
    let leaf = digest_from_hex("the leaf", leaf_hex)?;
    let mut levels = Vec::with_capacity(unsorted.siblings.len());
    for (level, siblings) in unsorted.siblings.iter().enumerate() {
        let mut converted = [Digest::from_bytes(&[0u8; 32]).expect("zero is canonical");
            SIBLINGS_PER_LEVEL];
        for (slot, sibling) in siblings.iter().enumerate() {
            converted[slot] =
                digest_from_hex(&format!("level {level} sibling {slot}"), sibling)?;
        }
        levels.push(converted);
    }
    let path = MerklePath::from_unsorted(&levels, leaf)?;
    let root = path.root(leaf)?;
    Ok(path_json(&path, leaf, root))
}

/// One path in the shape `TransferRequest.inputs[].path` takes, plus the root
/// it reaches and the leaf it was taken for.
fn path_json(path: &MerklePath, leaf: Digest, root: Digest) -> String {
    let siblings: Vec<Vec<String>> = path
        .siblings
        .iter()
        .map(|level| level.iter().map(Digest::to_hex).collect())
        .collect();
    json!({
        "siblings": siblings,
        "positions": path.positions,
        "root": root.to_hex(),
        "leaf": leaf.to_hex(),
        "depth": path.depth(),
    })
    .to_string()
}

/// Commitment and nullifier for a note this seed owns.
///
/// The `(value, rho, r)` a scan read out of a ciphertext, turned into the two
/// values a wallet decides with: the commitment the chain published beside the
/// leaf, and the nullifier that will settle it. See the module docs on why the
/// nullifier is derived here and why it must not be logged.
pub fn note_digests_json(seed_hex: &str, value: u64, rho_hex: &str, r_hex: &str) -> Result<String> {
    let key = spending_key_from_hex(seed_hex)?;
    let note = Note::new(
        key.pk(),
        value,
        digest_from_hex("rho", rho_hex)?,
        digest_from_hex("r", r_hex)?,
    )
    .map_err(|error| anyhow::anyhow!("this is not a valid note: {error}"))?;
    Ok(json!({
        "inner": note.inner().to_hex(),
        "commitment": note.commitment().to_hex(),
        "nullifier": note.nullifier(&key.nk()).to_hex(),
    })
    .to_string())
}

/// The coinbase note this seed's miner key mints at one height.
///
/// A coinbase leaf carries no ciphertext a recipient has to decrypt: the node
/// that builds it cannot encrypt to an ML-KEM key, so `(rho, r)` are derived
/// from the block and the coinbase viewing key instead, and the chain
/// publishes the value in `Shielded::CoinbaseValues`. The genesis hash is in
/// the `r` preimage so one miner key running on two chains does not mint
/// byte-identical notes at equal heights.
///
/// The caller compares `commitment` against the leaf. That comparison decides,
/// and the value inside any ciphertext beside it is ignored: a coinbase's
/// amount is the chain's own arithmetic.
pub fn coinbase_note_json(
    seed_hex: &str,
    genesis_hash_hex: &str,
    block_number: u32,
    value: u64,
) -> Result<String> {
    let key = spending_key_from_hex(seed_hex)?;
    let genesis = hex::decode(genesis_hash_hex.trim_start_matches("0x"))
        .context("the genesis hash is not hex")?;
    ensure!(genesis.len() == 32, "the genesis hash must be 32 bytes");
    let note = key
        .miner_key()
        .coinbase_note(&genesis, block_number, value)
        .map_err(|error| anyhow::anyhow!("the coinbase note is not valid: {error}"))?;
    Ok(json!({
        "rho": note.rho.to_hex(),
        "r": note.r.to_hex(),
        "commitment": note.commitment().to_hex(),
        "nullifier": note.nullifier(&key.nk()).to_hex(),
    })
    .to_string())
}

/// `rho = H(RHO_ENTRY, block_number, entry_index)`, the shield rule.
///
/// A shield's `rho` is a prediction: the wallet predicts `(head + 1,
/// EntryCount)`, submits, and then checks both halves. v1 signs a shield with
/// ML-DSA-87, which this module does not export, so a browser cannot send one;
/// it can still recognise one it predicted from the CLI, which is what this is
/// for.
pub fn entry_rho_hex(block_number: u32, entry_index: u64) -> String {
    qnero_notes::entry_rho(block_number, entry_index).to_hex()
}

/// The `qnm1...` a node is configured with: `pk` and `cvk`, and nothing that
/// can spend.
///
/// Secret bearing. Whoever holds it picks this wallet's coinbase notes out of
/// the tree. It is deliberately not the address, which is meant to be handed
/// out, so a UI that shows one must say which it is showing.
pub fn miner_key_hex(seed_hex: &str) -> Result<String> {
    Ok(spending_key_from_hex(seed_hex)?.miner_key().encode())
}

/// What the leaf's `ct_digest` public input commits to, over the two
/// ciphertexts in output order.
pub fn ct_digest_hex(ct_1: &[u8], ct_2: &[u8]) -> String {
    hex::encode(chain_ct_digest(&[ct_1, ct_2]))
}

/// Whether a string is an address this chain's notes can pay.
///
/// A bech32m checksum failure is the answer a typed address should get, rather
/// than a proof built against a `pk` nobody holds.
pub fn address_is_valid(address: &str) -> bool {
    Address::decode(address.trim()).is_ok()
}

/// Constants a wallet must not compile a second copy of.
///
/// The pad is the one that matters. Every memo is padded to `memo_bytes`, so
/// every ciphertext this workspace writes is one length; a wallet that padded
/// to a different number would publish its own ciphertext length, which is the
/// leak the pad exists to close. The fee floor is computed from these and from
/// the runtime's own metadata constants, never from a copy of either.
pub fn wallet_limits_json() -> String {
    json!({
        "memo_bytes": qnero_notes::MEMO_BYTES,
        "ciphertext_fixed_bytes": qnero_notes::CIPHERTEXT_FIXED_BYTES,
        "padded_ciphertext_bytes": qnero_notes::CIPHERTEXT_FIXED_BYTES + qnero_notes::MEMO_BYTES,
        "digest_logs_size": DIGEST_LOGS_SIZE,
        "max_tree_depth": MAX_DEPTH,
        "tree_arity": ARITY,
        "siblings_per_level": SIBLINGS_PER_LEVEL,
        "chain_num_leaves": crate::prove::CHAIN_NUM_LEAVES,
    })
    .to_string()
}

/// A memo's padded length, and the refusal for one that does not fit.
///
/// The pad is applied inside `encrypt_note`, so this is the check a UI runs
/// while somebody is typing rather than a second padding implementation.
pub fn memo_fits(memo: &str) -> Result<usize> {
    match qnero_notes::pad_memo(memo) {
        Ok(padded) => Ok(padded.len()),
        Err(error) => bail!("{error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qnero_circuit::merkle::hash_node;

    fn seed() -> String {
        "21".repeat(32)
    }

    fn leaf_bytes(leaves: &[Digest]) -> Vec<u8> {
        leaves.iter().flat_map(|leaf| leaf.to_bytes()).collect()
    }

    /// The whole point of the export: a path taken in wasm reaches the root
    /// the pallet computed, and the caller can check both ends of it.
    #[test]
    fn a_rebuilt_path_reaches_the_rebuilt_root() {
        let leaves: Vec<Digest> = (0..37u8)
            .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
            .collect();
        let depth = depth_for(leaves.len()).unwrap();
        let bytes = leaf_bytes(&leaves);

        let root: serde_json::Value =
            serde_json::from_str(&format!("\"{}\"", tree_root_hex(&bytes, depth).unwrap()))
                .unwrap();
        for index in [0usize, 5, 36] {
            let path: serde_json::Value =
                serde_json::from_str(&tree_path_json(&bytes, depth, index).unwrap()).unwrap();
            assert_eq!(path["root"], root);
            assert_eq!(path["leaf"], leaves[index].to_hex());
            assert_eq!(path["depth"].as_u64().unwrap() as usize, depth);
            assert_eq!(path["siblings"].as_array().unwrap().len(), depth);
        }
    }

    /// A rebuild at the wrong depth reaches a different root, which is why the
    /// depth is read at the same block hash as the leaves.
    #[test]
    fn the_depth_decides_the_root() {
        let leaves: Vec<Digest> = (0..5u8)
            .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
            .collect();
        let bytes = leaf_bytes(&leaves);
        assert_ne!(
            tree_root_hex(&bytes, 2).unwrap(),
            tree_root_hex(&bytes, 3).unwrap()
        );
    }

    /// The adapter and the local rebuild are the same path. The chain hands
    /// over the unsorted form, and a wallet that skipped the conversion would
    /// prove against a root nothing committed to.
    #[test]
    fn the_unsorted_adapter_agrees_with_the_local_rebuild() {
        let leaves: Vec<Digest> = (0..17u8)
            .map(|index| Digest::hash_bytes(&[b"leaf", &[index]]))
            .collect();
        let depth = depth_for(leaves.len()).unwrap();
        let tree = CommitmentTree::new(&leaves, depth).unwrap();
        let index = 9usize;

        let chain_order = tree.index_ordered_siblings(index).unwrap();
        let siblings: Vec<Vec<String>> = chain_order
            .iter()
            .map(|level| level.iter().map(Digest::to_hex).collect())
            .collect();
        let unsorted = json!({ "siblings": siblings }).to_string();

        let adapted = path_from_unsorted_json(&unsorted, &leaves[index].to_hex()).unwrap();
        let local = tree_path_json(&leaf_bytes(&leaves), depth, index).unwrap();
        let adapted: serde_json::Value = serde_json::from_str(&adapted).unwrap();
        let local: serde_json::Value = serde_json::from_str(&local).unwrap();
        assert_eq!(adapted["siblings"], local["siblings"]);
        assert_eq!(adapted["positions"], local["positions"]);
        assert_eq!(adapted["root"], local["root"]);
    }

    /// A leaf that is not four canonical limbs is named rather than folded
    /// into a root that would then disagree with the header for no stated
    /// reason.
    #[test]
    fn a_non_canonical_leaf_is_refused_by_index() {
        let mut bytes = vec![0u8; 64];
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        let error = tree_root_hex(&bytes, 1).unwrap_err().to_string();
        assert!(error.contains("leaf 1"), "{error}");
    }

    #[test]
    fn a_short_leaf_range_is_refused() {
        assert!(tree_root_hex(&[0u8; 31], 1).is_err());
    }

    /// The commitment a scan checks against the chain, and the nullifier it
    /// tests against the paged settled set. Neither is in the ciphertext.
    #[test]
    fn a_notes_digests_match_the_note_primitives() {
        let key = spending_key_from_hex(&seed()).unwrap();
        let rho = Digest::hash_bytes(&[b"rho"]);
        let r = Digest::hash_bytes(&[b"r"]);
        let note = Note::new(key.pk(), 1_000, rho, r).unwrap();

        let json: serde_json::Value = serde_json::from_str(
            &note_digests_json(&seed(), 1_000, &rho.to_hex(), &r.to_hex()).unwrap(),
        )
        .unwrap();
        assert_eq!(json["commitment"], note.commitment().to_hex());
        assert_eq!(json["nullifier"], note.nullifier(&key.nk()).to_hex());
        assert_eq!(json["inner"], note.inner().to_hex());
    }

    /// The coinbase rebuild is the node's own function, so a wallet finds the
    /// note the chain minted rather than one it guessed at.
    #[test]
    fn a_coinbase_note_matches_the_miner_key_derivation() {
        let key = spending_key_from_hex(&seed()).unwrap();
        let genesis = [7u8; 32];
        let expected = key.miner_key().coinbase_note(&genesis, 42, 11).unwrap();

        let json: serde_json::Value = serde_json::from_str(
            &coinbase_note_json(&seed(), &hex::encode(genesis), 42, 11).unwrap(),
        )
        .unwrap();
        assert_eq!(json["commitment"], expected.commitment().to_hex());
        assert_eq!(json["rho"], expected.rho.to_hex());

        // Another chain, same key, same height: a different note.
        let elsewhere: serde_json::Value = serde_json::from_str(
            &coinbase_note_json(&seed(), &hex::encode([8u8; 32]), 42, 11).unwrap(),
        )
        .unwrap();
        assert_ne!(json["commitment"], elsewhere["commitment"]);
    }

    /// The miner key is not the address, and a UI that showed one for the
    /// other would hand out a coinbase view.
    #[test]
    fn a_miner_key_is_its_own_string() {
        let miner = miner_key_hex(&seed()).unwrap();
        assert!(miner.starts_with("qnm1"), "{miner}");
        let account: serde_json::Value =
            serde_json::from_str(&crate::scan::derive_account_json(&seed()).unwrap()).unwrap();
        assert_ne!(account["address"].as_str().unwrap(), miner);
    }

    /// The anchor check: the hash this recomputes is the one the chain stores,
    /// and it moves when any field of the preimage does.
    #[test]
    fn a_header_hash_is_a_function_of_its_whole_preimage() {
        let anchor = json!({
            "parent_hash": Digest::hash_bytes(&[b"parent"]).to_hex(),
            "block_number": 12u32,
            "state_root": Digest::hash_bytes(&[b"state"]).to_hex(),
            "extrinsics_root": Digest::hash_bytes(&[b"extrinsics"]).to_hex(),
            "zk_tree_root": Digest::hash_bytes(&[b"tree"]).to_hex(),
            "digest_logs": hex::encode([0x7Au8; DIGEST_LOGS_SIZE]),
        });
        let first = header_block_hash_hex(&anchor.to_string()).unwrap();
        assert_eq!(first.len(), 64);

        let mut moved = anchor.clone();
        moved["block_number"] = json!(13u32);
        assert_ne!(first, header_block_hash_hex(&moved.to_string()).unwrap());

        let mut logs = anchor;
        logs["digest_logs"] = json!(hex::encode([0x7Bu8; DIGEST_LOGS_SIZE]));
        assert_ne!(first, header_block_hash_hex(&logs.to_string()).unwrap());
    }

    /// A digest blob of the wrong length is refused by name. It is the part of
    /// the re-encoding that goes wrong, and proving against it costs a whole
    /// batch before the pool says `BlockHashMismatch`.
    #[test]
    fn a_short_digest_blob_is_refused() {
        let anchor = json!({
            "parent_hash": Digest::hash_bytes(&[b"parent"]).to_hex(),
            "block_number": 1u32,
            "state_root": Digest::hash_bytes(&[b"state"]).to_hex(),
            "extrinsics_root": Digest::hash_bytes(&[b"extrinsics"]).to_hex(),
            "zk_tree_root": Digest::hash_bytes(&[b"tree"]).to_hex(),
            "digest_logs": hex::encode([0u8; 8]),
        });
        let error = header_block_hash_hex(&anchor.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("digest_logs"), "{error}");
    }

    #[test]
    fn the_ct_digest_covers_both_ciphertexts_in_order() {
        let a = vec![1u8; 16];
        let b = vec![2u8; 16];
        assert_ne!(ct_digest_hex(&a, &b), ct_digest_hex(&b, &a));
        assert_eq!(ct_digest_hex(&a, &b).len(), 64);
    }

    #[test]
    fn an_address_that_fails_its_checksum_is_not_valid() {
        let account: serde_json::Value =
            serde_json::from_str(&crate::scan::derive_account_json(&seed()).unwrap()).unwrap();
        let address = account["address"].as_str().unwrap();
        assert!(address_is_valid(address));
        assert!(!address_is_valid(&address[..address.len() - 1]));
        assert!(!address_is_valid(&miner_key_hex(&seed()).unwrap()));
    }

    /// The pad is a chain-wide agreement, so a wallet reads it rather than
    /// pinning its own copy.
    #[test]
    fn the_limits_carry_the_pad_and_the_depth_cap() {
        let limits: serde_json::Value =
            serde_json::from_str(&wallet_limits_json()).unwrap();
        assert_eq!(limits["memo_bytes"], qnero_notes::MEMO_BYTES);
        assert_eq!(
            limits["padded_ciphertext_bytes"].as_u64().unwrap() as usize,
            qnero_notes::CIPHERTEXT_FIXED_BYTES + qnero_notes::MEMO_BYTES
        );
        assert_eq!(limits["max_tree_depth"], MAX_DEPTH);
        assert_eq!(limits["digest_logs_size"], DIGEST_LOGS_SIZE);
    }

    #[test]
    fn a_memo_past_the_pad_is_refused_with_the_pad_named() {
        assert_eq!(memo_fits("hello").unwrap(), qnero_notes::MEMO_BYTES);
        assert!(memo_fits(&"x".repeat(qnero_notes::MEMO_BYTES + 1)).is_err());
    }

    /// The node rule this export mirrors is the pallet's, sorted children and
    /// all, so a single-leaf tree folds the way the chain folds one.
    #[test]
    fn one_leaf_rebuilds_the_way_the_pallet_folds_it() {
        let only = Digest::hash_bytes(&[b"only"]);
        let empty = qnero_circuit::merkle::empty_digest();
        assert_eq!(
            tree_root_hex(&only.to_bytes(), 1).unwrap(),
            hash_node(&[only, empty, empty, empty]).to_hex()
        );
    }
}
