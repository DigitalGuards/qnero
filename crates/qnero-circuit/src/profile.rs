//! Canonical release identity, encoded independently of Rust and SCALE versions.
//!
//! A profile is 192 bytes. Integers are unsigned little endian. Bytes 0..8
//! identify the format; 8..92 describe the protocol; 92..94 carry the exact
//! serialized length of a suite-1 note ciphertext, which settlement requires;
//! 94..96 are zero; the last
//! 96 bytes are Blake2b-256 hashes of the exact serialized leaf, private-batch
//! and public-batch verifier files, including the public-batch dimension header.
//! Padding proofs are randomized and are deliberately excluded.
//!
//! Genesis and runtime code identity are separate: wallets retain genesis
//! binding and authenticate `Shielded::ActiveProtocolProfile` against the
//! selected header's state root. Matching this profile establishes release
//! compatibility. It does not certify cryptographic security or consensus work.

use crate::{batch_layout, layout, params};

pub const PROFILE_LEN: usize = 192;
pub type ProtocolProfile = [u8; PROFILE_LEN];
pub const PROFILE_VERSION: u16 = 1;
/// Proof parameters remain experimental pending independent qualification.
pub const EXPERIMENTAL_PROOF_SYSTEM: bool = true;
/// Creation-state snapshots are required after this live ciphertext window.
pub const CIPHERTEXT_RETENTION_BLOCKS: u32 = 64;
pub const MAX_CIPHERTEXTS_PER_BLOCK: u32 = 2048;
pub const MAX_CIPHERTEXT_PRUNES_PER_BLOCK: u32 = 4096;
pub const RELEASE_NUM_LEAVES: usize = 6;
pub const RELEASE_NUM_PRIVATE_BATCHES: usize = 53;
pub const LEAF_DIGEST_OFFSET: usize = 96;
pub const PRIVATE_DIGEST_OFFSET: usize = 128;
pub const PUBLIC_DIGEST_OFFSET: usize = 160;

// Release pins. The builder checks regenerated default artifacts against these
// hashes. A circuit change requires an explicit new profile and wallet release.
//
// Measured at the release dimensions, six leaf slots and 53 private batches,
// by `qnero-circuit-builder --report-pins` at `MAX_TREE_DEPTH = 20`. The
// depth-16 pins they replace were c112dffe..., 2ffd9f4b... and 8ea527ca...;
// all three moved because the deeper tree is a different leaf circuit and the
// two batch verifiers are built over it. Both verifier files kept their byte
// length, 1609 and 1749, and the public-batch verifier kept 1905.
pub const RELEASE_LEAF_DIGEST: [u8; 32] = [
    0xc6, 0xa2, 0xc9, 0x1f, 0x8b, 0xb6, 0x09, 0x0d, 0x57, 0x74, 0x5b, 0xaf, 0xb2, 0x62, 0x26, 0x02,
    0xff, 0xc2, 0xa9, 0xed, 0x50, 0xab, 0xa0, 0x84, 0x7d, 0xad, 0x53, 0xec, 0x94, 0xc4, 0xf5, 0x36,
];
pub const RELEASE_PRIVATE_DIGEST: [u8; 32] = [
    0xf0, 0xe7, 0x36, 0xd1, 0x4a, 0x20, 0x68, 0x24, 0xbf, 0xcc, 0x32, 0xb2, 0x7e, 0x67, 0x02, 0x81,
    0x4c, 0xba, 0xf2, 0x9e, 0xca, 0xc0, 0xdd, 0xda, 0xcc, 0xbc, 0x55, 0x8e, 0xdd, 0x0f, 0x77, 0x84,
];
pub const RELEASE_PUBLIC_DIGEST: [u8; 32] = [
    0xa4, 0x82, 0xc6, 0x72, 0x1f, 0x8d, 0x71, 0x3f, 0x09, 0xb2, 0x66, 0xcb, 0x18, 0xfe, 0xaf, 0xf2,
    0x67, 0x8b, 0x34, 0x4b, 0x27, 0x0a, 0x71, 0xbf, 0x64, 0xd1, 0x8b, 0x90, 0x07, 0x80, 0x25, 0x85,
];

pub const SUPPORTED_PROFILE: ProtocolProfile = protocol_profile(
    RELEASE_NUM_LEAVES,
    RELEASE_NUM_PRIVATE_BATCHES,
    RELEASE_LEAF_DIGEST,
    RELEASE_PRIVATE_DIGEST,
    RELEASE_PUBLIC_DIGEST,
);

/// Build the canonical wire representation from measured artifact hashes.
pub const fn protocol_profile(
    num_leaves: usize,
    num_private_batches: usize,
    leaf: [u8; 32],
    private: [u8; 32],
    public: [u8; 32],
) -> ProtocolProfile {
    assert!(num_leaves > 0 && num_leaves <= batch_layout::MAX_PROOF_COUNT);
    assert!(num_private_batches > 0 && num_private_batches <= batch_layout::MAX_PROOF_COUNT);
    let mut out = [0u8; PROFILE_LEN];
    out = put(out, 0, *b"QNRPRF01");
    out = put(out, 8, PROFILE_VERSION.to_le_bytes());
    // Spend protocol, note codec, ciphertext codec, verifier codec, header codec.
    out = put(out, 10, 1u16.to_le_bytes());
    out = put(out, 12, 1u16.to_le_bytes());
    out = put(out, 14, 1u16.to_le_bytes());
    out = put(out, 16, 1u16.to_le_bytes());
    out = put(out, 18, 1u16.to_le_bytes());
    out = put(out, 20, (crate::chain::MAX_TREE_DEPTH as u16).to_le_bytes());
    out[22] = 4; // Sorted quaternary commitment tree.
    out[23] = layout::NUM_INPUTS as u8;
    out[24] = layout::NUM_OUTPUTS as u8;
    out[25] = 62; // Note and fee value range.
    out[26] = 12; // Planck decimal places per QNR.
    out[27] = 1; // Note/tree digest suite: Poseidon2 over Goldilocks.
    out[28] = 1; // Proof transcript/commitments: original PoseidonGoldilocksConfig.
    out[29] = 1; // Note KEM suite: ML-KEM-1024.
    out[30] = 1; // Note AEAD suite: ChaCha20-Poly1305.
    out[31] = 1; // Sorted, position-independent child hashing.
    out = put(out, 32, 10_000_000_000u64.to_le_bytes()); // Planck per pool step.
    out = put(out, 40, (params::SECURITY_BITS as u16).to_le_bytes());
    out = put(out, 42, (params::NUM_CHALLENGES as u16).to_le_bytes());
    out = put(out, 44, (params::FRI_NUM_QUERY_ROUNDS as u16).to_le_bytes());
    out[46] = params::FRI_RATE_BITS as u8;
    out[47] = params::FRI_CAP_HEIGHT as u8;
    out = put(out, 48, params::FRI_PROOF_OF_WORK_BITS.to_le_bytes());
    out = put(out, 52, (params::LEAF_DEGREE_BITS as u16).to_le_bytes());
    out = put(
        out,
        54,
        (params::PRIVATE_BATCH_NUM_WIRES as u16).to_le_bytes(),
    );
    out = put(
        out,
        56,
        (params::PRIVATE_BATCH_NUM_ROUTED_WIRES as u16).to_le_bytes(),
    );
    out = put(out, 58, 2u16.to_le_bytes()); // Goldilocks extension degree.
    out = put(out, 60, (num_leaves as u16).to_le_bytes());
    out = put(out, 62, (num_private_batches as u16).to_le_bytes());
    out = put(out, 64, (layout::PUBLIC_INPUT_LEN as u32).to_le_bytes());
    out = put(
        out,
        68,
        (batch_layout::private_batch_pi_len(num_leaves) as u32).to_le_bytes(),
    );
    out = put(
        out,
        72,
        (batch_layout::public_batch_pi_len(num_private_batches, num_leaves) as u32).to_le_bytes(),
    );
    out[76] = 1; // Live ciphertext cache plus authenticated historical state.
    out[77] = EXPERIMENTAL_PROOF_SYSTEM as u8;
    out = put(out, 80, CIPHERTEXT_RETENTION_BLOCKS.to_le_bytes());
    out = put(out, 84, MAX_CIPHERTEXTS_PER_BLOCK.to_le_bytes());
    out = put(out, 88, MAX_CIPHERTEXT_PRUNES_PER_BLOCK.to_le_bytes());
    // The length every note ciphertext a settlement carries must have, so a
    // wallet reads the consensus rule out of the profile it already fetches and
    // authenticates instead of trusting its own compiled copy of the number.
    out = put(
        out,
        92,
        (crate::chain::SUITE_1_CIPHERTEXT_BYTES as u16).to_le_bytes(),
    );
    out = put(out, LEAF_DIGEST_OFFSET, leaf);
    out = put(out, PRIVATE_DIGEST_OFFSET, private);
    put(out, PUBLIC_DIGEST_OFFSET, public)
}

const fn put<const N: usize>(
    mut out: ProtocolProfile,
    offset: usize,
    bytes: [u8; N],
) -> ProtocolProfile {
    let mut i = 0;
    while i < N {
        out[offset + i] = bytes[i];
        i += 1;
    }
    out
}

/// Strict equality also rejects unknown versions, reserved fields and trailing bytes.
pub fn ensure_supported(bytes: &[u8], num_leaves: usize) -> Result<(), &'static str> {
    if num_leaves != RELEASE_NUM_LEAVES {
        return Err("this wallet's circuit dimensions have no supported experimental profile");
    }
    if bytes != SUPPORTED_PROFILE {
        return Err("incompatible Qnero protocol profile; update the wallet or select a compatible chain before building circuits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_profile_encodes_dimensions_and_security_parameters() {
        assert_eq!(&SUPPORTED_PROFILE[..8], b"QNRPRF01");
        // The commitment-tree depth. It is the one bundle constant the
        // profile carries that no other test names, and a wallet proving
        // against a chain at another depth builds paths the verifier refuses.
        assert_eq!(&SUPPORTED_PROFILE[20..22], &20u16.to_le_bytes());
        assert_eq!(&SUPPORTED_PROFILE[40..42], &100u16.to_le_bytes());
        assert_eq!(&SUPPORTED_PROFILE[60..64], &[6, 0, 53, 0]);
        assert!(ensure_supported(&SUPPORTED_PROFILE, RELEASE_NUM_LEAVES).is_ok());
    }

    /// Bytes 92..94 carry the settlement ciphertext length and 94..96 stay
    /// reserved. `ensure_supported` is strict equality over all 192 bytes, so a
    /// runtime that moved this number is refused at the profile check, before a
    /// wallet ever pays for a proof it could not settle.
    #[test]
    fn the_profile_carries_the_suite_1_ciphertext_length() {
        assert_eq!(
            &SUPPORTED_PROFILE[92..94],
            &(crate::chain::SUITE_1_CIPHERTEXT_BYTES as u16).to_le_bytes()
        );
        assert_eq!(&SUPPORTED_PROFILE[92..94], &1792u16.to_le_bytes());
        assert_eq!(&SUPPORTED_PROFILE[94..96], &[0, 0]);
    }

    #[test]
    fn every_profile_byte_and_compiled_dimension_is_checked() {
        for index in 0..PROFILE_LEN {
            let mut other = SUPPORTED_PROFILE;
            other[index] ^= 1;
            assert!(
                ensure_supported(&other, RELEASE_NUM_LEAVES).is_err(),
                "byte {index}"
            );
        }
        assert!(
            ensure_supported(&SUPPORTED_PROFILE[..PROFILE_LEN - 1], RELEASE_NUM_LEAVES).is_err()
        );
        assert!(ensure_supported(&SUPPORTED_PROFILE, RELEASE_NUM_LEAVES + 1).is_err());
        let mut extended = SUPPORTED_PROFILE.to_vec();
        extended.push(0);
        assert!(ensure_supported(&extended, RELEASE_NUM_LEAVES).is_err());
    }
}
