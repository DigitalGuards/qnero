//! The difficulty rule, in Monero's arithmetic.
//!
//! Two comparisons live here and they are deliberately different things.
//!
//! [`meets_difficulty`] is consensus: a 32-byte RandomX hash read as a
//! **little-endian** 256-bit integer is good for a block when
//! `hash * difficulty <= 2^256 - 1`. That is Monero's `check_hash_128`
//! (`src/cryptonote_basic/difficulty.cpp`), and it is the only rule the node
//! seals or imports a block on.
//!
//! [`meets_share_target`] is the pool-side approximation every stratum miner
//! computes for itself: the last 8 bytes of the hash read as a little-endian
//! u64, compared against the 64-bit target the job carried. xmrig applies
//! exactly this before it sends a share, so the node applies it too when it
//! decides whether a share was worth counting. A share that passes it is not
//! a block; the node re-hashes every accepted share and puts it through
//! [`meets_difficulty`] before sealing.

use primitive_types::{U256, U512};

/// Read a RandomX hash as the 256-bit integer Monero reads it as.
pub fn hash_as_le_u512(hash: &[u8; 32]) -> U512 {
	let mut be = [0u8; 32];
	for (index, byte) in hash.iter().enumerate() {
		be[31 - index] = *byte;
	}
	U512::from_big_endian(&be)
}

/// The consensus rule: `hash_le * difficulty` must fit in 256 bits.
pub fn meets_difficulty(hash: &[u8; 32], difficulty: U512) -> bool {
	if difficulty.is_zero() {
		// A zero difficulty would accept every hash. Treat it as a
		// misconfiguration and accept nothing.
		return false;
	}
	let (product, overflowed) = hash_as_le_u512(hash).overflowing_mul(difficulty);
	!overflowed && product <= U512::from(U256::MAX)
}

/// The 64-bit target a stratum job carries for a given share difficulty.
///
/// Monero's pools compute `2^64 / difficulty` and miners compare the top 64
/// bits of the hash against it.
pub fn share_target_u64(share_difficulty: u64) -> u64 {
	u64::MAX / share_difficulty.max(1)
}

/// The `target` field of a stratum job: the 64-bit target, little-endian, hex.
///
/// xmrig accepts either 8 hex characters (a 32-bit target it expands) or 16
/// (a little-endian u64 it uses directly). Always send 16, because a share
/// difficulty above 2^32 cannot be expressed in the short form.
pub fn stratum_target_hex(share_difficulty: u64) -> String {
	hex::encode(share_target_u64(share_difficulty).to_le_bytes())
}

/// The share test a stratum miner applies to itself before submitting.
pub fn meets_share_target(hash: &[u8; 32], target: u64) -> bool {
	let mut top = [0u8; 8];
	top.copy_from_slice(&hash[24..32]);
	u64::from_le_bytes(top) < target
}

/// Clamp a block difficulty into the u64 a stratum target can express, for use
/// as the ceiling on a connection's share difficulty.
pub fn difficulty_as_u64(difficulty: U512) -> u64 {
	if difficulty > U512::from(u64::MAX) {
		u64::MAX
	} else {
		difficulty.low_u64()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A hash that is exactly `2^256 / difficulty` and one that is a step
	/// either side of it, so the boundary itself is pinned rather than a
	/// comfortable interior point.
	fn hash_from_le_u512(value: U512) -> [u8; 32] {
		let be = value.to_big_endian();
		let mut hash = [0u8; 32];
		for index in 0..32 {
			hash[index] = be[63 - index];
		}
		hash
	}

	#[test]
	fn a_hash_reads_little_endian() {
		let mut hash = [0u8; 32];
		hash[0] = 1;
		assert_eq!(hash_as_le_u512(&hash), U512::one());

		let mut hash = [0u8; 32];
		hash[31] = 1;
		assert_eq!(hash_as_le_u512(&hash), U512::one() << 248);
	}

	#[test]
	fn difficulty_one_accepts_every_hash() {
		assert!(meets_difficulty(&[0xffu8; 32], U512::one()));
		assert!(meets_difficulty(&[0u8; 32], U512::one()));
	}

	#[test]
	fn the_boundary_is_where_the_product_stops_fitting_in_256_bits() {
		let difficulty = U512::from(1_000_000u64);
		let ceiling = (U512::from(U256::MAX) + U512::one()) / difficulty;

		// `ceiling * difficulty` is at most 2^256 - 1 by construction, so the
		// largest accepted hash is `ceiling - 1` when the division is exact and
		// `ceiling` when it is not. Pin both sides of whichever it is.
		let accepted = hash_from_le_u512(ceiling - U512::one());
		assert!(meets_difficulty(&accepted, difficulty));

		let rejected = hash_from_le_u512(ceiling + U512::one());
		assert!(!meets_difficulty(&rejected, difficulty));
	}

	#[test]
	fn the_all_ones_hash_fails_any_difficulty_above_one() {
		assert!(!meets_difficulty(&[0xffu8; 32], U512::from(2u64)));
	}

	#[test]
	fn a_zero_difficulty_accepts_nothing() {
		assert!(!meets_difficulty(&[0u8; 32], U512::zero()));
	}

	#[test]
	fn an_oversized_difficulty_does_not_wrap_into_acceptance() {
		// Difficulty beyond 2^256 can only be met by a hash below 1, and the
		// multiply must not overflow into a small product.
		let difficulty = U512::one() << 500;
		let mut hash = [0u8; 32];
		hash[31] = 0xff;
		assert!(!meets_difficulty(&hash, difficulty));
		assert!(meets_difficulty(&[0u8; 32], difficulty));
	}

	#[test]
	fn the_stratum_target_is_a_little_endian_u64() {
		// Difficulty 1 is the whole range: 0xffff_ffff_ffff_ffff.
		assert_eq!(stratum_target_hex(1), "ffffffffffffffff");
		// Difficulty 2 halves it, and the low byte leads because it is
		// little-endian.
		assert_eq!(share_target_u64(2), 0x7fff_ffff_ffff_ffff);
		assert_eq!(stratum_target_hex(2), "ffffffffffffff7f");
		assert_eq!(stratum_target_hex(0), stratum_target_hex(1));
		assert_eq!(stratum_target_hex(1).len(), 16);
	}

	#[test]
	fn the_share_test_reads_the_last_eight_bytes() {
		let target = share_target_u64(2);
		let mut hash = [0u8; 32];
		hash[24..32].copy_from_slice(&(target - 1).to_le_bytes());
		assert!(meets_share_target(&hash, target));
		hash[24..32].copy_from_slice(&target.to_le_bytes());
		assert!(!meets_share_target(&hash, target));
	}

	/// A share that clears the block rule always clears the share rule at the
	/// same difficulty, which is what makes the two-stage check sound: the node
	/// never rejects as a share something it would have accepted as a block.
	#[test]
	fn the_block_rule_is_stricter_than_the_share_rule() {
		let difficulty = 4096u64;
		let target = share_target_u64(difficulty);
		for seed in 0..64u64 {
			let mut hash = [0u8; 32];
			hash[16..24].copy_from_slice(&seed.to_le_bytes());
			hash[24..32].copy_from_slice(&(seed % 32).to_le_bytes());
			if meets_difficulty(&hash, U512::from(difficulty)) {
				assert!(meets_share_target(&hash, target), "seed {seed}");
			}
		}
	}

	#[test]
	fn a_difficulty_above_u64_clamps_for_the_share_target() {
		assert_eq!(difficulty_as_u64(U512::from(u64::MAX)), u64::MAX);
		assert_eq!(difficulty_as_u64(U512::from(u64::MAX) + U512::one()), u64::MAX);
		assert_eq!(difficulty_as_u64(U512::from(7u64)), 7);
	}
}
