//! The 4-ary Poseidon2 commitment tree, off circuit and in circuit.
//!
//! Forked from `qp-zk-circuits` (`common/src/zk_merkle.rs`,
//! `wormhole/circuit/src/zk_merkle_proof.rs`). The node hashing rule is the
//! one `pallets/zk-tree` implements, so a path produced here verifies against
//! that pallet's root:
//!
//! - children are sorted by their 32 canonical bytes before hashing;
//! - a parent is `Poseidon2(child_0 || child_1 || child_2 || child_3)` over
//!   the 16 field elements of the sorted children, with no domain tag;
//! - a missing child is the all-zero digest.
//!
//! Because children are sorted, a stored proof carries siblings only. The
//! circuit does not sort (too expensive); the prover supplies a position hint
//! per level and the root equality is what makes a lie useless.
//!
//! Qnero's leaf is the note commitment itself, so there is no leaf preimage to
//! hash: the circuit feeds the `cm` it computed straight into level 0.

use anyhow::{bail, ensure};
use plonky2::field::types::Field as _;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon2::Poseidon2Hash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use qnero_note_core::{Digest, Felt};

use crate::gadgets::const_less_than_bits;
use crate::{D, F};

/// Children per internal node.
pub const ARITY: usize = 4;

/// Siblings carried per level.
pub const SIBLINGS_PER_LEVEL: usize = ARITY - 1;

/// Maximum tree depth the circuit supports, under the name the circuit code
/// uses.
///
/// Defined in [`crate::chain`], which compiles without the `circuit` feature,
/// so a runtime reads the same constant without the prover stack and
/// `pallet-shielded` can const-assert it against `pallet-zk-tree`'s
/// `CIRCUIT_MAX_TREE_DEPTH`. A second definition here would be a second number
/// to keep in step.
pub use crate::chain::MAX_TREE_DEPTH as MAX_DEPTH;

/// Bits needed to hold a depth in `0..=MAX_DEPTH`.
pub const DEPTH_BITS: usize = 5;

/// The empty subtree, matching the pallet's `empty_hash()`.
pub fn empty_digest() -> Digest {
    Digest([Felt::new(0); 4])
}

/// Hash four children into their parent, sorting first.
pub fn hash_node(children: &[Digest; ARITY]) -> Digest {
    let mut sorted = *children;
    sorted.sort_by_key(|child| child.to_bytes());
    hash_node_presorted(&sorted)
}

/// Hash four already sorted children into their parent.
///
/// Every digest is four canonical limbs by construction, so concatenating the
/// limbs is the same 16 field elements the chain gets from decoding the sorted
/// 128 bytes at 8 bytes per element.
pub fn hash_node_presorted(sorted: &[Digest; ARITY]) -> Digest {
    let mut felts = [Felt::new(0); ARITY * 4];
    for (child_index, child) in sorted.iter().enumerate() {
        felts[child_index * 4..(child_index + 1) * 4].copy_from_slice(child.felts());
    }
    Digest(qp_poseidon_core::hash_to_felts(&felts))
}

/// A Merkle path in the form the circuit consumes: siblings in sorted order
/// plus the position the leaf-side hash occupies among them.
#[derive(Clone, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<[Digest; SIBLINGS_PER_LEVEL]>,
    pub positions: Vec<u8>,
}

/// Redacting `Debug`: a path identifies the note being spent by pinning its
/// exact position in the tree, which is the linkability the shielded pool
/// exists to remove.
impl core::fmt::Debug for MerklePath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MerklePath")
            .field("depth", &self.siblings.len())
            .field("siblings", &"[REDACTED]")
            .field("positions", &"[REDACTED]")
            .finish()
    }
}

impl MerklePath {
    /// A path of `depth` levels of empty siblings, for a dummy input whose
    /// membership check the circuit skips.
    pub fn dummy(depth: usize) -> Self {
        Self {
            siblings: vec![[empty_digest(); SIBLINGS_PER_LEVEL]; depth],
            positions: vec![0; depth],
        }
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Convert a chain-shaped proof into the form the circuit consumes.
    ///
    /// `pallet-zk-tree`'s `generate_proof` returns the three siblings of each
    /// level in child-index order and records no position, because the node
    /// rule sorts its children anyway. The circuit does not sort: it needs the
    /// siblings in sorted order plus the slot the running hash occupies. This
    /// is the adapter, and it is what a wallet uses on a proof it fetched from
    /// the chain. Upstream ships the same conversion as
    /// `ZkMerkleProofData::from_unsorted`.
    ///
    /// Non-canonical sibling bytes cannot reach here: a [`Digest`] is four
    /// canonical limbs by construction, so the decode that would alias two
    /// distinct byte strings onto one field element has already been rejected.
    pub fn from_unsorted(
        unsorted_siblings: &[[Digest; SIBLINGS_PER_LEVEL]],
        leaf: Digest,
    ) -> anyhow::Result<Self> {
        ensure!(
            unsorted_siblings.len() <= MAX_DEPTH,
            "merkle path depth {} exceeds MAX_DEPTH {}",
            unsorted_siblings.len(),
            MAX_DEPTH
        );

        let mut siblings = Vec::with_capacity(unsorted_siblings.len());
        let mut positions = Vec::with_capacity(unsorted_siblings.len());
        let mut current = leaf;

        for level_siblings in unsorted_siblings {
            let mut children = [
                current,
                level_siblings[0],
                level_siblings[1],
                level_siblings[2],
            ];
            children.sort_by_key(|child| child.to_bytes());
            // Duplicates are adjacent after sorting, so any index holding the
            // same value reconstructs the same array.
            let position = children
                .iter()
                .position(|child| *child == current)
                .expect("the running hash is one of the four children");

            let mut sorted_siblings = [empty_digest(); SIBLINGS_PER_LEVEL];
            let mut sibling_index = 0;
            for (slot, child) in children.iter().enumerate() {
                if slot != position {
                    sorted_siblings[sibling_index] = *child;
                    sibling_index += 1;
                }
            }

            siblings.push(sorted_siblings);
            positions.push(position as u8);
            current = hash_node_presorted(&children);
        }

        Ok(Self {
            siblings,
            positions,
        })
    }

    /// Recompute the root this path claims for `leaf`.
    pub fn root(&self, leaf: Digest) -> anyhow::Result<Digest> {
        ensure!(
            self.siblings.len() == self.positions.len(),
            "merkle path has {} sibling levels and {} positions",
            self.siblings.len(),
            self.positions.len()
        );
        ensure!(
            self.siblings.len() <= MAX_DEPTH,
            "merkle path depth {} exceeds MAX_DEPTH {}",
            self.siblings.len(),
            MAX_DEPTH
        );

        let mut current = leaf;
        for (level_siblings, position) in self.siblings.iter().zip(self.positions.iter()) {
            let mut children = [empty_digest(); ARITY];
            let position = *position as usize;
            if position >= ARITY {
                bail!("merkle path position {} is out of range", position);
            }
            let mut sibling_index = 0;
            for (slot, child) in children.iter_mut().enumerate() {
                if slot == position {
                    *child = current;
                } else {
                    *child = level_siblings[sibling_index];
                    sibling_index += 1;
                }
            }
            current = hash_node_presorted(&children);
        }
        Ok(current)
    }
}

/// An append-only 4-ary commitment tree, held in memory.
///
/// This is the wallet-side and test-side mirror of `pallets/zk-tree`: the same
/// node rule, the same empty-child padding, so `root()` equals the pallet's
/// `Root` for the same leaves at the same depth.
#[derive(Debug, Clone)]
pub struct CommitmentTree {
    depth: usize,
    /// `levels[0]` are the leaves; `levels[depth]` is the single root.
    levels: Vec<Vec<Digest>>,
}

impl CommitmentTree {
    /// Build a tree of exactly `depth` levels over `leaves`.
    pub fn new(leaves: &[Digest], depth: usize) -> anyhow::Result<Self> {
        ensure!(
            !leaves.is_empty(),
            "commitment tree needs at least one leaf"
        );
        ensure!(
            (1..=MAX_DEPTH).contains(&depth),
            "commitment tree depth {} must be in 1..={}",
            depth,
            MAX_DEPTH
        );
        let capacity = (ARITY as u128).pow(depth as u32);
        ensure!(
            leaves.len() as u128 <= capacity,
            "{} leaves do not fit in a depth-{} 4-ary tree ({} slots)",
            leaves.len(),
            depth,
            capacity
        );

        let mut levels = Vec::with_capacity(depth + 1);
        levels.push(leaves.to_vec());
        for level in 0..depth {
            let below = &levels[level];
            let mut parents = Vec::with_capacity(below.len().div_ceil(ARITY));
            for chunk in below.chunks(ARITY) {
                let mut children = [empty_digest(); ARITY];
                children[..chunk.len()].copy_from_slice(chunk);
                parents.push(hash_node(&children));
            }
            levels.push(parents);
        }
        debug_assert_eq!(levels[depth].len(), 1);

        Ok(Self { depth, levels })
    }

    /// The smallest depth that holds `leaf_count` leaves, at least 1.
    pub fn depth_for(leaf_count: usize) -> anyhow::Result<usize> {
        for depth in 1..=MAX_DEPTH {
            if (leaf_count as u128) <= (ARITY as u128).pow(depth as u32) {
                return Ok(depth);
            }
        }
        bail!(
            "{} leaves exceed the capacity of a depth-{} 4-ary tree",
            leaf_count,
            MAX_DEPTH
        )
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    pub fn root(&self) -> Digest {
        self.levels[self.depth][0]
    }

    /// The three siblings of each level in child-index order, with no position
    /// hint: the shape `pallet-zk-tree`'s `generate_proof` returns.
    ///
    /// [`MerklePath::from_unsorted`] is what turns this into a circuit path.
    pub fn index_ordered_siblings(
        &self,
        leaf_index: usize,
    ) -> anyhow::Result<Vec<[Digest; SIBLINGS_PER_LEVEL]>> {
        ensure!(
            leaf_index < self.leaf_count(),
            "leaf index {} is out of range for {} leaves",
            leaf_index,
            self.leaf_count()
        );

        let mut levels = Vec::with_capacity(self.depth);
        let mut index = leaf_index;
        for level in 0..self.depth {
            let base = (index / ARITY) * ARITY;
            let mut level_siblings = [empty_digest(); SIBLINGS_PER_LEVEL];
            let mut sibling_index = 0;
            for slot in 0..ARITY {
                if base + slot == index {
                    continue;
                }
                if let Some(value) = self.levels[level].get(base + slot) {
                    level_siblings[sibling_index] = *value;
                }
                sibling_index += 1;
            }
            levels.push(level_siblings);
            index /= ARITY;
        }

        Ok(levels)
    }

    /// The sorted-sibling path with position hints for one leaf.
    pub fn path(&self, leaf_index: usize) -> anyhow::Result<MerklePath> {
        ensure!(
            leaf_index < self.leaf_count(),
            "leaf index {} is out of range for {} leaves",
            leaf_index,
            self.leaf_count()
        );

        let mut siblings = Vec::with_capacity(self.depth);
        let mut positions = Vec::with_capacity(self.depth);
        let mut index = leaf_index;

        for level in 0..self.depth {
            let base = (index / ARITY) * ARITY;
            let mut children = [empty_digest(); ARITY];
            for (slot, child) in children.iter_mut().enumerate() {
                if let Some(value) = self.levels[level].get(base + slot) {
                    *child = *value;
                }
            }
            let current = children[index - base];

            let mut sorted = children;
            sorted.sort_by_key(|child| child.to_bytes());
            // Duplicates are adjacent after sorting, so any index holding the
            // same value reconstructs the same array.
            let position = sorted
                .iter()
                .position(|child| *child == current)
                .expect("the current hash is one of the four children");

            let mut level_siblings = [empty_digest(); SIBLINGS_PER_LEVEL];
            let mut sibling_index = 0;
            for (slot, child) in sorted.iter().enumerate() {
                if slot != position {
                    level_siblings[sibling_index] = *child;
                    sibling_index += 1;
                }
            }

            siblings.push(level_siblings);
            positions.push(position as u8);
            index /= ARITY;
        }

        Ok(MerklePath {
            siblings,
            positions,
        })
    }
}

/// The same tree, appended to one leaf at a time, keeping only the frontier.
///
/// `CommitmentTree` materialises every level, which is what a path needs.
/// A wallet that has to check the root the chain published at **every** block
/// of a range needs something else: the root after `n` leaves, for many `n`,
/// without rebuilding `n` levels each time. This keeps, per level, the
/// completed children of the node currently being filled there, which is at
/// most three digests a level, and folds them on demand.
///
/// The rule is `pallet-zk-tree`'s, unchanged: children sorted, a missing child
/// is the all-zero digest, and the depth is the smallest one that holds the
/// count. So [`TreeFrontier::root`] equals the `zkTreeRoot` the chain put in
/// the header of the block that ended on this many leaves, and
/// `a_frontier_matches_the_full_tree_at_every_prefix` pins it against
/// [`CommitmentTree`].
///
/// Cost is one Poseidon path update per leaf and one fold per root, where a
/// rebuild is one whole tree per root. That is what makes a per-block check
/// affordable.
#[derive(Debug, Clone, Default)]
pub struct TreeFrontier {
    /// `levels[l]` holds the completed level-`l` nodes that belong to the
    /// level-`l + 1` node currently being filled, so it is never four long.
    levels: Vec<Vec<Digest>>,
    count: u64,
}

impl TreeFrontier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Append one leaf, carrying completed nodes upward.
    pub fn push(&mut self, leaf: Digest) {
        let mut carry = Some(leaf);
        let mut level = 0usize;
        while let Some(node) = carry {
            if self.levels.len() == level {
                self.levels.push(Vec::with_capacity(ARITY));
            }
            self.levels[level].push(node);
            if self.levels[level].len() == ARITY {
                let mut children = [empty_digest(); ARITY];
                children.copy_from_slice(&self.levels[level]);
                self.levels[level].clear();
                carry = Some(hash_node(&children));
                level += 1;
            } else {
                carry = None;
            }
        }
        self.count = self.count.saturating_add(1);
    }

    /// The depth the chain folds this many leaves at.
    ///
    /// `pallet-zk-tree`'s growth loop is `while capacity_at_depth(depth) <
    /// leaf_count { depth += 1 }` over `capacity_at_depth(0) == 0`, started at
    /// the depth already stored and never shrunk, so it lands on the smallest
    /// depth that holds the count. An empty tree stays at depth zero and
    /// publishes the default root, which is the all-zero digest.
    pub fn depth(&self) -> anyhow::Result<usize> {
        if self.count == 0 {
            return Ok(0);
        }
        CommitmentTree::depth_for(usize::try_from(self.count).unwrap_or(usize::MAX))
    }

    /// The root the chain publishes after this many leaves.
    pub fn root(&self) -> anyhow::Result<Digest> {
        let depth = self.depth()?;
        if depth == 0 {
            // `process_pending_leaves` returns before it writes anything when
            // nothing is pending, so a chain that has appended no leaf at all
            // still carries `Root`'s default.
            return Ok(empty_digest());
        }
        let mut carry: Option<Digest> = None;
        for level in 0..depth {
            let filled = self.levels.get(level).map_or(0, Vec::len);
            if filled == 0 && carry.is_none() {
                // Nothing is under construction at this level, so the node
                // above it is already complete and sits a level higher. A
                // parent hashed over four empty children here would be a node
                // the chain never wrote.
                continue;
            }
            let mut children = [empty_digest(); ARITY];
            if let Some(nodes) = self.levels.get(level) {
                children[..filled].copy_from_slice(nodes);
            }
            if let Some(node) = carry {
                children[filled] = node;
            }
            carry = Some(hash_node(&children));
        }
        match carry {
            Some(root) => Ok(root),
            // Every level below the depth was empty, which happens exactly
            // when the count fills the tree: the root is the completed node
            // the last carry landed on.
            None => self
                .levels
                .get(depth)
                .and_then(|nodes| nodes.first())
                .copied()
                .ok_or_else(|| anyhow::anyhow!("a tree of depth {depth} folded to nothing")),
        }
    }
}

// ============================================================================
// In-circuit
// ============================================================================

/// Path targets for one input note. Always `MAX_DEPTH` levels; levels past the
/// tree's real depth are witnessed as zeros and ignored by the level flags.
#[derive(Debug, Clone)]
pub struct MerklePathTargets {
    pub siblings: Vec<[HashOutTarget; SIBLINGS_PER_LEVEL]>,
    pub positions: Vec<Target>,
}

impl MerklePathTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            siblings: (0..MAX_DEPTH)
                .map(|_| core::array::from_fn(|_| builder.add_virtual_hash()))
                .collect(),
            positions: (0..MAX_DEPTH)
                .map(|_| builder.add_virtual_target())
                .collect(),
        }
    }
}

/// `level < depth` for every level, from bits the caller already split.
///
/// Splitting is what range-constrains `depth`, so the caller owns it and can
/// reuse the same bits for the `depth <= MAX_DEPTH` bound. Upstream re-splits
/// `depth` inside every level of every path; both input notes here share one
/// tree and therefore one depth.
pub fn active_level_flags_from_bits(
    builder: &mut CircuitBuilder<F, D>,
    depth_bits: &[BoolTarget],
) -> [BoolTarget; MAX_DEPTH] {
    core::array::from_fn(|level| const_less_than_bits(builder, level, depth_bits))
}

/// [`active_level_flags_from_bits`] for a caller that has not split `depth`.
///
/// A caller that also bounds `depth` should split once itself and use
/// [`active_level_flags_from_bits`], or the value is decomposed twice.
pub fn active_level_flags(
    builder: &mut CircuitBuilder<F, D>,
    depth: Target,
) -> [BoolTarget; MAX_DEPTH] {
    let depth_bits = builder.split_le(depth, DEPTH_BITS);
    active_level_flags_from_bits(builder, &depth_bits)
}

/// Walk a path from `leaf_hash` to the root.
///
/// Every level is evaluated; `active_levels[level]` decides whether its parent
/// replaces the running hash. The cost is therefore fixed at `MAX_DEPTH`
/// levels and reveals nothing about the tree's real depth.
pub fn merkle_root_from_path(
    builder: &mut CircuitBuilder<F, D>,
    leaf_hash: HashOutTarget,
    path: &MerklePathTargets,
    active_levels: &[BoolTarget; MAX_DEPTH],
) -> HashOutTarget {
    let zero = builder.zero();
    let one = builder.one();
    let two = builder.two();
    let three = builder.constant(F::from_canonical_usize(3));

    let mut current = leaf_hash;

    for (level, is_active) in active_levels.iter().enumerate() {
        let siblings = &path.siblings[level];
        let position = path.positions[level];

        // 2 bits, so the position is one of the four slots.
        builder.range_check(position, 2);
        let at_0 = builder.is_equal(position, zero);
        let at_1 = builder.is_equal(position, one);
        let at_2 = builder.is_equal(position, two);
        let at_3 = builder.is_equal(position, three);

        // Insert `current` at `position` among the sorted siblings.
        let children: [HashOutTarget; ARITY] = core::array::from_fn(|slot| HashOutTarget {
            elements: core::array::from_fn(|limb| match slot {
                0 => builder.select(at_0, current.elements[limb], siblings[0].elements[limb]),
                1 => {
                    let sibling = builder.select(
                        at_0,
                        siblings[0].elements[limb],
                        siblings[1].elements[limb],
                    );
                    builder.select(at_1, current.elements[limb], sibling)
                }
                2 => {
                    let before_2 = builder.or(at_0, at_1);
                    let sibling = builder.select(
                        before_2,
                        siblings[1].elements[limb],
                        siblings[2].elements[limb],
                    );
                    builder.select(at_2, current.elements[limb], sibling)
                }
                3 => builder.select(at_3, current.elements[limb], siblings[2].elements[limb]),
                _ => unreachable!("ARITY is 4"),
            }),
        });

        let mut preimage = Vec::with_capacity(ARITY * 4);
        for child in &children {
            preimage.extend_from_slice(&child.elements);
        }
        let parent = builder.hash_n_to_hash_no_pad_p2::<Poseidon2Hash>(preimage);

        current = HashOutTarget {
            elements: core::array::from_fn(|limb| {
                builder.select(*is_active, parent.elements[limb], current.elements[limb])
            }),
        };
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(tag: &[u8]) -> Digest {
        Digest::hash_bytes(&[b"merkle-test", tag])
    }

    /// The frontier and the full rebuild are one tree.
    ///
    /// A wallet checks the root the chain published at every block of a range,
    /// and it does that from the frontier alone. If the two ever disagreed at
    /// one prefix, every sync would refuse an honest node at that height with
    /// a message about a node lying about a block's leaf range.
    #[test]
    fn a_frontier_matches_the_full_tree_at_every_prefix() {
        let leaves: Vec<Digest> = (0u32..70).map(|index| leaf(&index.to_le_bytes())).collect();
        let mut frontier = TreeFrontier::new();
        assert_eq!(frontier.count(), 0);
        assert_eq!(
            frontier.root().expect("an empty tree roots"),
            empty_digest(),
            "a chain that has appended no leaf publishes the default root"
        );
        for (count, next) in leaves.iter().enumerate() {
            frontier.push(*next);
            let prefix = &leaves[..count + 1];
            let depth = CommitmentTree::depth_for(prefix.len()).expect("a depth");
            let full = CommitmentTree::new(prefix, depth).expect("a tree");
            assert_eq!(frontier.count(), prefix.len() as u64);
            assert_eq!(frontier.depth().expect("a depth"), depth);
            assert_eq!(
                frontier.root().expect("a root"),
                full.root(),
                "the frontier and the rebuild disagree at {} leaves",
                prefix.len()
            );
        }
    }

    /// The node rule is `qp-poseidon-core` off circuit and plonky2's Poseidon2
    /// sponge in circuit. They must be the same function over the same 16 field
    /// elements, or a path that verifies off circuit fails in circuit.
    #[test]
    fn node_hashing_matches_the_in_circuit_sponge() {
        use plonky2::hash::poseidon2::Poseidon2Hash;
        use plonky2::plonk::config::Hasher;

        let children = [leaf(b"n0"), leaf(b"n1"), leaf(b"n2"), empty_digest()];
        let mut sorted = children;
        sorted.sort_by_key(|child| child.to_bytes());

        let mut preimage = Vec::with_capacity(16);
        for child in &sorted {
            preimage.extend(crate::convert::digest_to_felts(child));
        }
        let in_circuit_sponge = Poseidon2Hash::hash_no_pad(&preimage).elements;

        assert_eq!(
            crate::convert::digest_to_felts(&hash_node(&children)),
            in_circuit_sponge
        );
    }

    /// The node rule again, this time against the route `pallets/zk-tree`
    /// takes: sort the four 32-byte forms, concatenate to 128 bytes, decode at
    /// 8 bytes per element, hash to bytes. Qnero copies the children's limbs
    /// straight into 16 field elements instead, which is the same function
    /// only as long as the byte decode and the limb order agree.
    ///
    /// `node_hashing_matches_the_in_circuit_sponge` cannot see a divergence
    /// here: it compares this crate's off-circuit hash against plonky2's
    /// sponge, so a change in `qp-poseidon-core`'s byte handling would leave
    /// every test in this crate green while every path fetched from the chain
    /// reached a different root. The expected value is pinned as bytes for the
    /// same reason `qnero-notes` pins its note vectors: a dependency bump must
    /// not be able to move it quietly.
    #[test]
    fn node_hashing_matches_the_pallet_byte_route() {
        let children = [
            Digest::from_bytes(&[0x01; 32]).unwrap(),
            Digest::from_bytes(&[0x02; 32]).unwrap(),
            Digest::from_bytes(&[0x03; 32]).unwrap(),
            empty_digest(),
        ];

        let mut sorted: [[u8; 32]; ARITY] = core::array::from_fn(|i| children[i].to_bytes());
        sorted.sort();
        let mut concatenated = Vec::with_capacity(ARITY * 32);
        for child in &sorted {
            concatenated.extend_from_slice(child);
        }
        let felts: Vec<Felt> =
            qp_poseidon_core::serialization::bytes_to_u64s_compact(&concatenated)
                .into_iter()
                .map(Felt::from_u64)
                .collect();
        assert_eq!(felts.len(), ARITY * 4);
        let pallet_route = qp_poseidon_core::hash_to_bytes(&felts);

        let parent = hash_node(&children);
        assert_eq!(parent.to_bytes(), pallet_route);
        assert_eq!(
            parent.to_hex(),
            "af921c8f15cad25901d3789b67281a09c3fc3aa7d13a1b9b66d55593bdfc5c00"
        );
    }

    #[test]
    fn node_hashing_is_order_independent() {
        let a = leaf(b"a");
        let b = leaf(b"b");
        let c = leaf(b"c");
        let d = leaf(b"d");
        assert_eq!(hash_node(&[a, b, c, d]), hash_node(&[d, c, b, a]));
    }

    #[test]
    fn paths_reproduce_the_root() {
        let leaves: Vec<Digest> = (0..37u8).map(|i| leaf(&[i])).collect();
        let depth = CommitmentTree::depth_for(leaves.len()).unwrap();
        assert_eq!(depth, 3);
        let tree = CommitmentTree::new(&leaves, depth).unwrap();

        for (index, commitment) in leaves.iter().enumerate() {
            let path = tree.path(index).unwrap();
            assert_eq!(path.depth(), depth);
            assert_eq!(path.root(*commitment).unwrap(), tree.root());
        }
    }

    #[test]
    fn a_wrong_sibling_changes_the_root() {
        let leaves: Vec<Digest> = (0..8u8).map(|i| leaf(&[i])).collect();
        let tree = CommitmentTree::new(&leaves, 2).unwrap();
        let mut path = tree.path(3).unwrap();
        path.siblings[0][0] = leaf(b"tampered");
        assert_ne!(path.root(leaves[3]).unwrap(), tree.root());
    }

    #[test]
    fn one_leaf_tree_has_a_root() {
        let only = leaf(b"only");
        let tree = CommitmentTree::new(&[only], 1).unwrap();
        assert_eq!(
            tree.root(),
            hash_node(&[only, empty_digest(), empty_digest(), empty_digest()])
        );
        assert_eq!(tree.path(0).unwrap().root(only).unwrap(), tree.root());
    }

    /// The chain hands out index-ordered siblings with no position hint. The
    /// adapter is the wallet-side half of the leaf rule: without it a path
    /// fetched from the pallet reaches the wrong root and the leaf simply fails
    /// to prove.
    #[test]
    fn the_adapter_rebuilds_a_circuit_path_from_chain_order_siblings() {
        let leaves: Vec<Digest> = (0..37u8).map(|i| leaf(&[i])).collect();
        let depth = CommitmentTree::depth_for(leaves.len()).unwrap();
        let tree = CommitmentTree::new(&leaves, depth).unwrap();

        for (index, commitment) in leaves.iter().enumerate() {
            let chain_order = tree.index_ordered_siblings(index).unwrap();
            let path = MerklePath::from_unsorted(&chain_order, *commitment).unwrap();
            assert_eq!(path.depth(), depth);
            assert_eq!(path.root(*commitment).unwrap(), tree.root());
            assert_eq!(path, tree.path(index).unwrap());
        }
    }

    #[test]
    fn the_adapter_rejects_a_path_deeper_than_max_depth() {
        let siblings = vec![[empty_digest(); SIBLINGS_PER_LEVEL]; MAX_DEPTH + 1];
        assert!(MerklePath::from_unsorted(&siblings, leaf(b"x")).is_err());
    }

    #[test]
    fn oversized_trees_are_rejected() {
        let leaves: Vec<Digest> = (0..17u8).map(|i| leaf(&[i])).collect();
        assert!(CommitmentTree::new(&leaves, 2).is_err());
        assert!(CommitmentTree::new(&[], 2).is_err());
        assert!(CommitmentTree::new(&leaves, MAX_DEPTH + 1).is_err());
    }
}
