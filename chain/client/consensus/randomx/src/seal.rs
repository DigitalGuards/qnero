//! The seal: what a won block carries in its header.
//!
//! A RandomX proof is naturally four bytes, and four bytes will not do here.
//! The header commits to a fixed 110-byte digest window
//! (`qp_header::DIGEST_LOGS_SIZE`), which a 32-byte author item and a 64-byte
//! seal fill exactly, and the same constant is a public input of the ZK header
//! circuit. So the seal stays 64 bytes and the question is what fills it.
//!
//! It may not be filler the miner chooses. The seal is not part of the pre-hash
//! but it is part of the block hash, and children reference the block hash, so
//! every free byte in the seal is a grinding handle over every descendant's
//! parent hash. One won nonce plus 56 free bytes would be 2^448 distinct valid
//! headers for the same work.
//!
//! Therefore:
//!
//! ```text
//! 0..4   nonce, little-endian u32       hashed, at blob offset 39
//! 4..8   extra nonce, little-endian u32 hashed, at blob offset 51
//! 8..64  pinned padding, all zero       not hashed, and not free either
//! ```
//!
//! Both miner-chosen fields are inside the hashed blob, and the remaining 56
//! bytes are pinned to a constant that the verifier checks before it hashes
//! anything. A seal therefore has exactly as many degrees of freedom as the
//! proof of work paid for.

use crate::blob::NONCE_LEN;

/// Length of the seal, in bytes. Fixed by the header's digest commitment
/// window; RandomX has no opinion about it.
pub const SEAL_LEN: usize = 64;

/// The bytes of a seal that carry no information and may not vary.
pub const SEAL_PADDING: [u8; SEAL_LEN - 8] = [0u8; SEAL_LEN - 8];

/// What a miner produced, and the whole of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seal {
	/// The nonce, as it sits in the blob at offset 39.
	pub nonce: u32,
	/// The per-connection extra nonce, as it sits in the blob at offset 51.
	pub extra_nonce: u32,
}

/// Why a byte string is not a seal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
	#[error("seal is {0} bytes, expected {SEAL_LEN}")]
	WrongLength(usize),
	#[error("seal padding is not the pinned constant")]
	UnpinnedPadding,
}

impl Seal {
	/// The 64 bytes that go into the header.
	pub fn encode(&self) -> [u8; SEAL_LEN] {
		let mut bytes = [0u8; SEAL_LEN];
		bytes[..NONCE_LEN].copy_from_slice(&self.nonce.to_le_bytes());
		bytes[NONCE_LEN..8].copy_from_slice(&self.extra_nonce.to_le_bytes());
		bytes[8..].copy_from_slice(&SEAL_PADDING);
		bytes
	}

	/// Read a seal, refusing anything the padding rule does not allow.
	///
	/// This runs before the block is hashed, on every path that sees a seal.
	pub fn decode(bytes: &[u8]) -> Result<Self, SealError> {
		if bytes.len() != SEAL_LEN {
			return Err(SealError::WrongLength(bytes.len()));
		}
		if bytes[8..] != SEAL_PADDING {
			return Err(SealError::UnpinnedPadding);
		}
		let mut nonce = [0u8; NONCE_LEN];
		nonce.copy_from_slice(&bytes[..NONCE_LEN]);
		let mut extra_nonce = [0u8; 4];
		extra_nonce.copy_from_slice(&bytes[NONCE_LEN..8]);
		Ok(Self { nonce: u32::from_le_bytes(nonce), extra_nonce: u32::from_le_bytes(extra_nonce) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_seal_round_trips() {
		let seal = Seal { nonce: 0x0102_0304, extra_nonce: 0xAABB_CCDD };
		assert_eq!(Seal::decode(&seal.encode()), Ok(seal));
	}

	#[test]
	fn the_seal_is_64_bytes_and_the_digest_window_is_why() {
		// PreRuntime(engine, 32) encodes to 38 bytes, Seal(engine, 64) to 71,
		// the outer vec prefix is 1: 110, which is DIGEST_LOGS_SIZE exactly.
		assert_eq!(SEAL_LEN, 64);
		assert_eq!(38 + 71 + 1, qp_header::DIGEST_LOGS_SIZE);
	}

	#[test]
	fn the_low_eight_bytes_are_little_endian_nonce_then_extra_nonce() {
		let bytes = Seal { nonce: 1, extra_nonce: 2 }.encode();
		assert_eq!(&bytes[..4], &1u32.to_le_bytes());
		assert_eq!(&bytes[4..8], &2u32.to_le_bytes());
	}

	/// The grinding gate. A seal whose padding was touched must be refused, so
	/// a miner cannot spin a won block into many distinct block hashes.
	#[test]
	fn unpinned_padding_is_refused() {
		let mut bytes = Seal { nonce: 7, extra_nonce: 9 }.encode();
		bytes[63] = 1;
		assert_eq!(Seal::decode(&bytes), Err(SealError::UnpinnedPadding));

		let mut bytes = Seal { nonce: 7, extra_nonce: 9 }.encode();
		bytes[8] = 0xff;
		assert_eq!(Seal::decode(&bytes), Err(SealError::UnpinnedPadding));
	}

	#[test]
	fn a_wrong_length_seal_is_refused() {
		assert_eq!(Seal::decode(&[0u8; 4]), Err(SealError::WrongLength(4)));
		assert_eq!(Seal::decode(&[0u8; 65]), Err(SealError::WrongLength(65)));
		assert_eq!(Seal::decode(&[]), Err(SealError::WrongLength(0)));
	}

	/// Two different proofs must give two different seals, and the same proof
	/// must give one seal and only one.
	#[test]
	fn the_seal_is_a_function_of_the_proof_alone() {
		let a = Seal { nonce: 1, extra_nonce: 0 }.encode();
		let b = Seal { nonce: 0, extra_nonce: 1 }.encode();
		assert_ne!(a, b);
		assert_eq!(a, Seal { nonce: 1, extra_nonce: 0 }.encode());
	}
}
