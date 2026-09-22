//! Seed rotation: which block's hash keys the RandomX cache.
//!
//! RandomX is keyed by a 32-byte seed that changes on a slow schedule, because
//! a full-mode rig pays a 2 GiB dataset rebuild every time it moves. Monero's
//! schedule is two constants, an epoch length and a lag, and Qnero uses the
//! same shape with the constants read from the runtime so a chain can pick its
//! own without a client release.
//!
//! The rule is Monero's, from `src/crypto/rx-slow-hash.c`:
//!
//! ```text
//! seed_height(h) = 0                                  if h <= epoch + lag
//!                  (h - lag - 1) & ~(epoch - 1)       otherwise
//! ```
//!
//! The masked form only works for a power-of-two epoch, so the implementation
//! here writes it as a truncating division, which agrees with the mask at every
//! power of two and stays well defined elsewhere. The folk version of this
//! formula, `h - (h % epoch) - lag`, is **not** the same function: at h = 2113
//! with Monero's constants it gives 1984 where the real rule gives 2048, and a
//! one-block disagreement about the seed is a chain split. Qnero keeps Monero's
//! epoch of 2048 and raises the lag to 128, which moves the same disagreement
//! to h = 2177, where the rule gives 2048 and the folk formula gives
//! 2177 - 129 - 128 = 1920.

use primitive_types::H256;

/// Default epoch length, in blocks.
///
/// Monero rotates every 2048 blocks at a 120 s target, which is 2.84 days.
/// Qnero's public target is the same 120 s, so the block count and the wall
/// clock both match Monero. The runtime constant is still what decides it, and
/// the value here is only the fallback when the runtime cannot be asked.
pub const DEFAULT_SEED_EPOCH_BLOCKS: u32 = 2048;

/// Default lag, in blocks, between the epoch boundary and the seed block.
///
/// Qnero's runtime sets 128, twice Monero's 64, which is 4.3 hours at the
/// 120 s target. The runtime constant is still what decides it, and the value
/// here is only the fallback when the runtime cannot be asked.
pub const DEFAULT_SEED_EPOCH_LAG: u32 = 128;

/// The height of the block whose hash keys the RandomX cache for `height`.
pub fn seed_height(height: u64, epoch_blocks: u64, lag: u64) -> u64 {
	let epoch = epoch_blocks.max(1);
	if height <= epoch.saturating_add(lag) {
		return 0;
	}
	// `height > epoch + lag >= lag + 1`, so this cannot underflow.
	let anchor = height - lag - 1;
	anchor - (anchor % epoch)
}

/// The height of the seed the *next* epoch will use, which is what a job's
/// `next_seed_hash` announces so a rig can build the next dataset in the
/// background instead of stalling at the boundary. Equal to [`seed_height`]
/// while the epoch is not about to turn, exactly as Monero's
/// `rx_seedheights` does it.
pub fn next_seed_height(height: u64, epoch_blocks: u64, lag: u64) -> u64 {
	seed_height(height.saturating_add(lag), epoch_blocks, lag)
}

/// The slice of the chain the seed walk needs: which block is canonical at a
/// height, and who a block's parent is.
///
/// A trait rather than a `HeaderBackend` bound so the walk can be exercised
/// against a hand-built fork in a unit test. The production implementation is
/// one adapter over the client, in `lib.rs`.
pub trait ChainView {
	/// The hash of the canonical block at `number`, if the chain has one.
	fn canonical_hash(&self, number: u64) -> Result<Option<H256>, String>;
	/// The parent of `hash`, if the block is known.
	fn parent_of(&self, hash: H256) -> Result<Option<H256>, String>;
}

/// The hash of the block at `target_height` on the branch ending at
/// `parent_hash`, which is the parent of a candidate at `height`.
///
/// Walking the branch is what makes a fork candidate hash under its own
/// ancestry's seed instead of the canonical chain's. The walk is short in
/// practice because of the second check in the loop: the moment the cursor is
/// on the canonical chain, everything below it is too, so one lookup finishes
/// the job. On the tip that is the first iteration.
pub fn resolve_on_branch<V: ChainView>(
	view: &V,
	parent_hash: H256,
	height: u64,
	target_height: u64,
	max_walk: u64,
) -> Result<Option<H256>, String> {
	if height == 0 || target_height >= height {
		return Ok(None);
	}
	let mut cursor = parent_hash;
	let mut cursor_height = height - 1;
	for _ in 0..=max_walk {
		if cursor_height == target_height {
			return Ok(Some(cursor));
		}
		if view.canonical_hash(cursor_height)? == Some(cursor) {
			return view.canonical_hash(target_height);
		}
		if cursor_height == 0 {
			return Ok(None);
		}
		match view.parent_of(cursor)? {
			Some(parent) => cursor = parent,
			None => return Ok(None),
		}
		cursor_height -= 1;
	}
	Ok(None)
}

#[cfg(test)]
mod tests {
	use super::*;

	const EPOCH: u64 = 2048;
	const LAG: u64 = 128;

	/// Monero's own reference, transcribed from `rx-slow-hash.c`, so the test
	/// compares against the C rule rather than against a restatement of the
	/// implementation.
	fn monero_rx_seedheight(height: u64) -> u64 {
		if height <= EPOCH + LAG {
			0
		} else {
			(height - LAG - 1) & !(EPOCH - 1)
		}
	}

	#[test]
	fn the_first_epoch_seeds_from_genesis() {
		for height in [0u64, 1, 2, 100, 2048, 2111, 2112, 2175, 2176] {
			assert_eq!(seed_height(height, EPOCH, LAG), 0, "height {height}");
		}
	}

	#[test]
	fn the_seed_moves_one_block_after_the_epoch_plus_lag() {
		assert_eq!(seed_height(2176, EPOCH, LAG), 0);
		assert_eq!(seed_height(2177, EPOCH, LAG), 2048);
	}

	#[test]
	fn it_agrees_with_moneros_mask_at_every_boundary() {
		for epoch_index in 0..6u64 {
			let boundary = epoch_index * EPOCH + LAG;
			for delta in 0..4u64 {
				let height = boundary.saturating_add(delta).saturating_sub(2);
				assert_eq!(
					seed_height(height, EPOCH, LAG),
					monero_rx_seedheight(height),
					"height {height}"
				);
			}
		}
		for height in (0..40_000u64).step_by(37) {
			assert_eq!(seed_height(height, EPOCH, LAG), monero_rx_seedheight(height));
		}
	}

	/// The formula people quote from memory is a different function, and the
	/// difference is a fork. Pin the disagreement so nobody "simplifies" the
	/// implementation into it.
	#[test]
	fn the_folk_formula_is_a_different_function() {
		let folk = |h: u64| h - (h % EPOCH) - LAG;
		// At this chain's lag the disagreement sits one block past
		// `EPOCH + LAG`: 2177 - (2177 % 2048) - 128 = 2177 - 129 - 128.
		assert_eq!(seed_height(2177, EPOCH, LAG), 2048);
		assert_eq!(folk(2177), 1920);
	}

	/// The reference helper above reads this module's `LAG`, so once `LAG` is
	/// Qnero's 128 nothing else in the file pins Monero's published rule at
	/// Monero's own constants. This does, and it is the test that would fail
	/// if the rule itself were rewritten into something merely self-consistent.
	#[test]
	fn it_is_moneros_rule_at_moneros_own_constants() {
		const MONERO_EPOCH: u64 = 2048;
		const MONERO_LAG: u64 = 64;

		assert_eq!(seed_height(2112, MONERO_EPOCH, MONERO_LAG), 0);
		assert_eq!(seed_height(2113, MONERO_EPOCH, MONERO_LAG), 2048);

		let masked = |height: u64| {
			if height <= MONERO_EPOCH + MONERO_LAG {
				0
			} else {
				(height - MONERO_LAG - 1) & !(MONERO_EPOCH - 1)
			}
		};
		for height in (0..40_000u64).step_by(37) {
			assert_eq!(
				seed_height(height, MONERO_EPOCH, MONERO_LAG),
				masked(height),
				"height {height}"
			);
		}
	}

	#[test]
	fn a_seed_height_is_always_an_epoch_multiple() {
		for height in (0..50_000u64).step_by(13) {
			let seed = seed_height(height, EPOCH, LAG);
			assert_eq!(seed % EPOCH, 0, "height {height} seeded from {seed}");
			assert!(seed < height || seed == 0);
		}
	}

	#[test]
	fn the_seed_never_moves_backwards_as_the_chain_grows() {
		let mut previous = 0;
		for height in 0..60_000u64 {
			let seed = seed_height(height, EPOCH, LAG);
			assert!(seed >= previous, "height {height}: {seed} < {previous}");
			previous = seed;
		}
	}

	#[test]
	fn the_next_seed_is_announced_one_lag_ahead() {
		// Inside an epoch the next seed is the current one, so a rig is told
		// nothing changes.
		assert_eq!(next_seed_height(3000, EPOCH, LAG), seed_height(3000, EPOCH, LAG));
		// A lag before the rotation it is the one that is about to be used.
		// At this chain's constants that is 2 * 2048 + 128 + 1 = 4225.
		let rotate_at = 2 * EPOCH + LAG + 1;
		assert_eq!(rotate_at, 4225);
		assert_eq!(next_seed_height(rotate_at - LAG, EPOCH, LAG), 2 * EPOCH);
		assert_eq!(seed_height(rotate_at, EPOCH, LAG), 2 * EPOCH);
	}

	#[test]
	fn a_non_power_of_two_epoch_still_partitions_the_chain() {
		let epoch = 1000;
		assert_eq!(seed_height(1128, epoch, LAG), 0);
		assert_eq!(seed_height(1129, epoch, LAG), 1000);
		assert_eq!(seed_height(2128, epoch, LAG), 1000);
		assert_eq!(seed_height(2129, epoch, LAG), 2000);
	}

	#[test]
	fn a_zero_epoch_does_not_divide_by_zero() {
		assert_eq!(seed_height(5, 0, LAG), 0);
		assert_eq!(seed_height(5_000, 0, LAG), 5_000 - LAG - 1);
	}

	/// A hand-built chain with one fork, so the walk can be checked against a
	/// branch the canonical index disagrees with.
	struct FakeChain {
		/// canonical height -> hash
		canonical: std::collections::BTreeMap<u64, H256>,
		/// hash -> parent
		parents: std::collections::HashMap<H256, H256>,
	}

	fn h(byte: u8, number: u64) -> H256 {
		let mut bytes = [0u8; 32];
		bytes[0] = byte;
		bytes[1..9].copy_from_slice(&number.to_le_bytes());
		H256(bytes)
	}

	impl FakeChain {
		/// A canonical chain of `len` blocks, plus a fork of `fork_len` blocks
		/// branching off at `fork_at`.
		fn new(len: u64, fork_at: u64, fork_len: u64) -> (Self, H256) {
			let mut chain =
				FakeChain { canonical: Default::default(), parents: Default::default() };
			for number in 0..=len {
				chain.canonical.insert(number, h(1, number));
				if number > 0 {
					chain.parents.insert(h(1, number), h(1, number - 1));
				}
			}
			let mut tip = h(1, fork_at);
			for number in (fork_at + 1)..=(fork_at + fork_len) {
				chain.parents.insert(h(2, number), tip);
				tip = h(2, number);
			}
			(chain, tip)
		}
	}

	impl ChainView for FakeChain {
		fn canonical_hash(&self, number: u64) -> Result<Option<H256>, String> {
			Ok(self.canonical.get(&number).copied())
		}

		fn parent_of(&self, hash: H256) -> Result<Option<H256>, String> {
			Ok(self.parents.get(&hash).copied())
		}
	}

	#[test]
	fn on_the_canonical_tip_the_walk_is_one_lookup() {
		let (chain, _) = FakeChain::new(5_000, 5_000, 0);
		let parent = h(1, 4_999);
		let seed = seed_height(5_000, EPOCH, LAG);
		assert_eq!(
			resolve_on_branch(&chain, parent, 5_000, seed, EPOCH + LAG).unwrap(),
			Some(h(1, seed))
		);
	}

	/// The case the walk exists for: a candidate on a fork whose seed height is
	/// inside the forked range must use the block its own branch carries at
	/// that height, whatever the canonical chain has there.
	#[test]
	fn a_fork_uses_its_own_ancestor_as_the_seed() {
		// Fork branches at 2_900 and runs 200 blocks, so heights 2_901..3_100
		// differ between the branches.
		let (chain, fork_tip) = FakeChain::new(5_000, 2_900, 200);
		// A candidate at 3_101 on the fork. Its seed height, with a small
		// epoch, lands inside the forked range.
		let epoch = 64;
		let seed = seed_height(3_101, epoch, LAG);
		assert!(seed > 2_900 && seed < 3_101, "seed {seed} must be inside the fork");
		let resolved = resolve_on_branch(&chain, fork_tip, 3_101, seed, epoch + LAG)
			.unwrap()
			.expect("the seed is an ancestor of the fork tip");
		assert_eq!(resolved, h(2, seed));
		assert_ne!(resolved, chain.canonical[&seed]);
	}

	/// Below the branch point the fork and the canonical chain are the same
	/// blocks, so the walk short-circuits onto the canonical index.
	#[test]
	fn a_fork_whose_seed_predates_the_branch_point_reads_the_canonical_block() {
		let (chain, fork_tip) = FakeChain::new(5_000, 2_900, 200);
		let seed = seed_height(3_101, EPOCH, LAG);
		assert!(seed < 2_900);
		assert_eq!(
			resolve_on_branch(&chain, fork_tip, 3_101, seed, EPOCH + LAG).unwrap(),
			Some(h(1, seed))
		);
	}

	#[test]
	fn genesis_is_the_seed_of_the_first_epoch() {
		let (chain, _) = FakeChain::new(100, 100, 0);
		assert_eq!(resolve_on_branch(&chain, h(1, 9), 10, 0, EPOCH + LAG).unwrap(), Some(h(1, 0)));
	}

	#[test]
	fn an_unknown_branch_resolves_to_nothing_rather_than_looping() {
		let (chain, _) = FakeChain::new(5_000, 5_000, 0);
		let orphan = h(9, 4_999);
		assert_eq!(resolve_on_branch(&chain, orphan, 5_000, 2_048, EPOCH + LAG).unwrap(), None);
	}

	#[test]
	fn a_seed_at_or_above_the_candidate_is_refused() {
		let (chain, _) = FakeChain::new(100, 100, 0);
		assert_eq!(resolve_on_branch(&chain, h(1, 9), 10, 10, EPOCH + LAG).unwrap(), None);
		assert_eq!(resolve_on_branch(&chain, h(1, 9), 0, 0, EPOCH + LAG).unwrap(), None);
	}
}
