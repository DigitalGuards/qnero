//! The RandomX mining blob: what the hash is taken over.
//!
//! xmrig writes the nonce into the blob it is handed, at a fixed offset, and
//! refuses a blob shorter than 76 bytes. Monero's blob is a real block header
//! and the nonce sits at byte 39 of it. Qnero's mining input is a 32-byte
//! pre-seal header hash, so the blob here is synthetic: a fixed 76-byte layout
//! that puts the nonce exactly where a stock rig expects it and commits every
//! other byte the miner is free to choose.
//!
//! ```text
//! 0..7    domain tag, b"qnero/1"
//! 7..39   pre-seal header hash (32 bytes)
//! 39..43  nonce, little-endian u32      <- the 4 bytes xmrig writes
//! 43..51  block height, little-endian u64
//! 51..55  extra nonce, little-endian u32
//! 55..76  zero padding
//! ```
//!
//! Both miner-chosen fields, the nonce and the extra nonce, are inside the
//! hashed bytes and both are carried in the seal, so a valid proof of work
//! fixes the whole blob and the whole seal. See [`crate::seal`] for why that
//! matters.

/// Length of the mining blob. xmrig rejects anything shorter than 76 bytes.
pub const MINING_BLOB_LEN: usize = 76;

/// Byte offset of the nonce inside the blob. This is where xmrig writes for
/// the `rx/0` algorithm and it is not configurable on the miner side.
pub const NONCE_OFFSET: usize = 39;

/// Length of the nonce, in bytes.
pub const NONCE_LEN: usize = 4;

/// Domain tag, so a Qnero blob cannot be confused with a Monero one even if
/// the same rig mines both.
pub const DOMAIN_TAG: [u8; 7] = *b"qnero/1";

/// Offset of the pre-seal header hash.
pub const PRE_HASH_OFFSET: usize = 7;

/// Offset of the block height.
pub const HEIGHT_OFFSET: usize = 43;

/// Offset of the per-connection extra nonce.
pub const EXTRA_NONCE_OFFSET: usize = 51;

/// Build the blob a miner hashes.
pub fn build_blob(
	pre_hash: &[u8; 32],
	height: u64,
	extra_nonce: u32,
	nonce: u32,
) -> [u8; MINING_BLOB_LEN] {
	let mut blob = [0u8; MINING_BLOB_LEN];
	blob[..PRE_HASH_OFFSET].copy_from_slice(&DOMAIN_TAG);
	blob[PRE_HASH_OFFSET..NONCE_OFFSET].copy_from_slice(pre_hash);
	blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
	blob[HEIGHT_OFFSET..HEIGHT_OFFSET + 8].copy_from_slice(&height.to_le_bytes());
	blob[EXTRA_NONCE_OFFSET..EXTRA_NONCE_OFFSET + 4].copy_from_slice(&extra_nonce.to_le_bytes());
	blob
}

/// Overwrite the nonce of an existing blob in place, the way a miner does.
pub fn set_nonce(blob: &mut [u8; MINING_BLOB_LEN], nonce: u32) {
	blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
}

/// Read the nonce back out of a blob.
pub fn read_nonce(blob: &[u8; MINING_BLOB_LEN]) -> u32 {
	let mut bytes = [0u8; NONCE_LEN];
	bytes.copy_from_slice(&blob[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]);
	u32::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_blob_is_76_bytes_with_the_nonce_at_offset_39() {
		// Both numbers are xmrig's: `Job::setBlob` rejects a blob under 76
		// bytes and `Job::nonceOffset()` is 39 for rx/0, so the layout has to
		// satisfy the miner.
		assert_eq!(MINING_BLOB_LEN, 76);
		assert_eq!(NONCE_OFFSET, 39);
		assert_eq!(NONCE_LEN, 4);

		let blob = build_blob(&[7u8; 32], 12_345, 0xAABB_CCDD, 0x0102_0304);
		assert_eq!(blob.len(), 76);
		assert_eq!(&blob[39..43], &0x0102_0304u32.to_le_bytes());
	}

	#[test]
	fn every_field_lands_where_the_layout_says() {
		let pre_hash = [0x5au8; 32];
		let blob = build_blob(&pre_hash, 0x0011_2233_4455_6677, 9, 1);

		assert_eq!(&blob[..7], b"qnero/1");
		assert_eq!(&blob[7..39], &pre_hash[..]);
		assert_eq!(&blob[39..43], &1u32.to_le_bytes());
		assert_eq!(&blob[43..51], &0x0011_2233_4455_6677u64.to_le_bytes());
		assert_eq!(&blob[51..55], &9u32.to_le_bytes());
		assert_eq!(&blob[55..], &[0u8; 21][..]);
	}

	#[test]
	fn setting_the_nonce_in_place_matches_building_with_it() {
		let mut blob = build_blob(&[1u8; 32], 4, 5, 0);
		set_nonce(&mut blob, 0xDEAD_BEEF);
		assert_eq!(read_nonce(&blob), 0xDEAD_BEEF);
		assert_eq!(blob, build_blob(&[1u8; 32], 4, 5, 0xDEAD_BEEF));
	}

	#[test]
	fn the_nonce_and_the_extra_nonce_are_the_only_miner_controlled_bytes() {
		let base = build_blob(&[3u8; 32], 100, 0, 0);
		let other_nonce = build_blob(&[3u8; 32], 100, 0, 1);
		let other_extra = build_blob(&[3u8; 32], 100, 1, 0);

		let differs: Vec<usize> =
			(0..MINING_BLOB_LEN).filter(|&i| base[i] != other_nonce[i]).collect();
		assert_eq!(differs, vec![39]);

		let differs: Vec<usize> =
			(0..MINING_BLOB_LEN).filter(|&i| base[i] != other_extra[i]).collect();
		assert_eq!(differs, vec![51]);
	}
}
