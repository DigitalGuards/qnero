//! Engine-level tests that need no chain: the header's seal shape, and the
//! proof-of-work comparison end to end against a real RandomX VM.
//!
//! The chain-shaped parts are tested where they are pure: the seed rule and the
//! ancestry walk in [`crate::seed`], the target arithmetic in
//! [`crate::target`], the blob layout in [`crate::blob`].

use super::*;
use codec::Encode;
use sp_consensus::BlockOrigin;
use sp_runtime::{traits::BlakeTwo256, OpaqueExtrinsic};

type TestHeader = qp_header::Header<u32, BlakeTwo256>;
type TestBlock = sp_runtime::generic::Block<TestHeader, OpaqueExtrinsic>;

fn sealed_header_at(number: u32, digest: Digest) -> TestHeader {
	<TestHeader as HeaderT>::new(
		number,
		Default::default(),
		Default::default(),
		Default::default(),
		digest,
	)
}

/// The canonical digest: a 32-byte author preimage plus a 64-byte seal, which
/// together encode to exactly `DIGEST_LOGS_SIZE` bytes.
fn canonical_digest() -> Digest {
	Digest {
		logs: vec![
			DigestItem::PreRuntime(POW_ENGINE_ID, vec![1u8; 32]),
			DigestItem::Seal(POW_ENGINE_ID, Seal { nonce: 7, extra_nonce: 9 }.encode().to_vec()),
		],
	}
}

fn extract(digest: Digest, number: u32) -> Result<BlockImportParams<TestBlock>, String> {
	let params = BlockImportParams::<TestBlock>::new(
		BlockOrigin::NetworkBroadcast,
		sealed_header_at(number, digest),
	);
	futures::executor::block_on(extract_pow_seal::<TestBlock>(params))
}

/// Regression test for the remotely triggerable debug panic: the verifier must
/// reject a header whose encoded digest overflows the commitment window with a
/// clean error, *without* ever hashing it (`Header::hash()` silently truncates
/// past the window, so hashing must not be relied on).
#[test]
fn an_oversized_digest_is_rejected_cleanly() {
	let mut digest = canonical_digest();
	digest.logs.insert(1, DigestItem::Other(vec![0u8; 64]));
	assert!(codec::Encode::encode(&digest).len() > qp_header::MAX_ENCODED_DIGEST_SIZE);

	let err = extract(digest, 1).err().expect("oversized digest must be rejected");
	assert!(err.contains("commitment window"), "expected the digest-window rejection, got: {err}");
}

#[test]
fn an_undersized_digest_is_rejected() {
	let digest = Digest { logs: vec![DigestItem::Seal(POW_ENGINE_ID, vec![2u8; 64])] };
	assert!(digest.encode().len() < qp_header::DIGEST_LOGS_SIZE);

	let err = extract(digest, 1).err().expect("undersized digest must be rejected");
	assert!(err.contains("commitment window"), "expected the digest-window rejection, got: {err}");
}

/// Historical blocks minted before the runtime stopped depositing
/// `RuntimeEnvironmentUpdated` on `set_code` encode to exactly one byte past
/// the committed window and must stay importable.
#[test]
fn a_historical_environment_updated_digest_still_imports() {
	let mut digest = canonical_digest();
	digest.logs.insert(1, DigestItem::RuntimeEnvironmentUpdated);
	assert_eq!(digest.encode().len(), qp_header::MAX_ENCODED_DIGEST_SIZE);

	let result = extract(digest, 1).expect("historical 111-byte sealed header must pass");
	assert_eq!(
		result.post_digests.last(),
		Some(&DigestItem::Seal(POW_ENGINE_ID, Seal { nonce: 7, extra_nonce: 9 }.encode().to_vec())),
		"seal must be moved into post_digests"
	);
}

/// The 1-byte allowance is strictly historical.
#[test]
fn an_environment_updated_digest_above_the_legacy_cutoff_is_rejected() {
	let mut digest = canonical_digest();
	digest.logs.insert(1, DigestItem::RuntimeEnvironmentUpdated);
	let number = u32::try_from(qp_header::LEGACY_DIGEST_CUTOFF + 1).expect("cutoff fits u32");

	let err = extract(digest, number)
		.err()
		.expect("111-byte digest above the cutoff must be rejected");
	assert!(err.contains("commitment window"), "expected the digest-window rejection, got: {err}");
}

#[test]
fn the_canonical_digest_passes_and_the_seal_moves_to_post_digests() {
	let digest = canonical_digest();
	assert_eq!(digest.encode().len(), qp_header::DIGEST_LOGS_SIZE);

	let result = extract(digest, 1).expect("window-sized sealed header must pass");
	assert!(
		!result.header.digest().logs.iter().any(|l| matches!(l, DigestItem::Seal(..))),
		"seal must be removed from the pre-seal header"
	);
	assert_eq!(
		Seal::decode(result.post_digests.last().map(seal_bytes).unwrap()),
		Ok(Seal { nonce: 7, extra_nonce: 9 })
	);
}

fn seal_bytes(item: &DigestItem) -> &[u8] {
	match item {
		DigestItem::Seal(_, seal) => seal,
		_ => panic!("not a seal"),
	}
}

/// A seal whose padding was ground is refused where the header is taken apart,
/// before anything about it is hashed. Without this the seal's 56 unused bytes
/// would be 2^448 distinct block hashes for one proof of work.
#[test]
fn a_seal_with_ground_padding_is_refused_by_the_verifier() {
	let mut seal = Seal { nonce: 7, extra_nonce: 9 }.encode().to_vec();
	seal[40] = 0x01;
	let digest = Digest {
		logs: vec![
			DigestItem::PreRuntime(POW_ENGINE_ID, vec![1u8; 32]),
			DigestItem::Seal(POW_ENGINE_ID, seal),
		],
	};
	let err = extract(digest, 1).err().expect("ground padding must be rejected");
	assert!(err.contains("padding"), "expected the padding rejection, got: {err}");
}

/// A seal that is not 64 bytes cannot even fill the digest window, and is
/// refused on both counts. The window check fires first; this pins that the
/// pair of checks leaves no length through.
#[test]
fn a_wrong_length_seal_is_refused() {
	let digest = Digest {
		logs: vec![
			DigestItem::PreRuntime(POW_ENGINE_ID, vec![1u8; 64]),
			DigestItem::Seal(POW_ENGINE_ID, vec![2u8; 32]),
		],
	};
	assert_eq!(digest.encode().len(), qp_header::DIGEST_LOGS_SIZE);
	let err = extract(digest, 1).err().expect("a wrong-length seal must be rejected");
	assert!(err.contains("64"), "expected the length rejection, got: {err}");
}

/// Mine at a difficulty a light-mode VM clears in a handful of hashes, then put
/// the result through the same `check_seal` the importer calls. This is the
/// whole engine in one test: blob layout, RandomX, and Monero's comparison.
#[test]
fn a_mined_seal_verifies_and_a_forged_one_does_not() {
	let engine = RandomxEngine::light(1);
	let pre_hash = H256([0x11u8; 32]);
	let height = 4_242u64;
	let seed = H256([0x22u8; 32]);
	// Difficulty 64 is about 64 hashes on average, which is a couple of
	// seconds in light mode and keeps the test honest about the comparison.
	let difficulty = U512::from(64u64);

	let lease = engine.acquire(seed.0).expect("lease");
	let mut found = None;
	for nonce in 0..4_096u32 {
		let blob = blob::build_blob(&pre_hash.0, height, 3, nonce);
		let hash = lease.hash(&blob).expect("hash");
		if target::meets_difficulty(&hash, difficulty) {
			found = Some(Seal { nonce, extra_nonce: 3 });
			break;
		}
	}
	drop(lease);
	let seal = found.expect("a nonce under difficulty 64 within 4096 tries");

	check_seal::<TestBlock>(&engine, pre_hash, height, seed, seal, difficulty)
		.expect("the mined seal verifies");

	// Every field the blob commits to is load bearing: change one and the
	// proof is gone.
	for (label, result) in [
		("height", check_seal::<TestBlock>(&engine, pre_hash, height + 1, seed, seal, difficulty)),
		(
			"pre_hash",
			check_seal::<TestBlock>(&engine, H256([0x12u8; 32]), height, seed, seal, difficulty),
		),
		(
			"seed",
			check_seal::<TestBlock>(
				&engine,
				pre_hash,
				height,
				H256([0x23u8; 32]),
				seal,
				difficulty,
			),
		),
		(
			"extra nonce",
			check_seal::<TestBlock>(
				&engine,
				pre_hash,
				height,
				seed,
				Seal { nonce: seal.nonce, extra_nonce: 4 },
				difficulty,
			),
		),
	] {
		assert!(
			matches!(result, Err(Error::InvalidSeal)),
			"changing the {label} must invalidate the proof"
		);
	}
}

/// The same nonce that clears a low difficulty must not clear a high one: the
/// comparison is what decides.
#[test]
fn the_difficulty_is_what_decides() {
	let engine = RandomxEngine::light(1);
	let pre_hash = H256([0x33u8; 32]);
	let seal = Seal { nonce: 1, extra_nonce: 0 };
	// Difficulty 1 accepts every hash.
	check_seal::<TestBlock>(&engine, pre_hash, 1, H256::zero(), seal, U512::one())
		.expect("difficulty 1 accepts anything");
	// 2^200 accepts approximately nothing.
	let result =
		check_seal::<TestBlock>(&engine, pre_hash, 1, H256::zero(), seal, U512::one() << 200);
	assert!(matches!(result, Err(Error::InvalidSeal)));
}

/// A chain the height check can be asked about: hash to header, where
/// finality sits, and nothing else.
struct FakeBackend {
	headers: std::collections::HashMap<H256, TestHeader>,
	finalized_number: u32,
	block_gap: Option<sp_blockchain::BlockGap<u32>>,
}

impl FakeBackend {
	/// One block at `number`, and its hash. Nothing is finalized.
	fn with_block(number: u32) -> (Self, H256) {
		let header = sealed_header_at(number, canonical_digest());
		let hash = header.hash();
		let mut headers = std::collections::HashMap::new();
		headers.insert(hash, header);
		(Self { headers, finalized_number: 0, block_gap: None }, hash)
	}

	/// The same, with finality at `finalized`.
	fn with_block_finalized_at(number: u32, finalized: u32) -> (Self, H256) {
		let (backend, hash) = Self::with_block(number);
		(Self { finalized_number: finalized, ..backend }, hash)
	}
}

impl HeaderBackend<TestBlock> for FakeBackend {
	fn header(&self, hash: H256) -> sp_blockchain::Result<Option<TestHeader>> {
		Ok(self.headers.get(&hash).cloned())
	}

	fn info(&self) -> sp_blockchain::Info<TestBlock> {
		let best = self.headers.values().max_by_key(|header| *header.number());
		sp_blockchain::Info {
			best_hash: best.map_or(H256::zero(), |header| header.hash()),
			best_number: best.map_or(0, |header| *header.number()),
			genesis_hash: H256::zero(),
			finalized_hash: H256::zero(),
			finalized_number: self.finalized_number,
			finalized_state: None,
			number_leaves: 0,
			block_gap: self.block_gap,
		}
	}

	fn status(&self, hash: H256) -> sp_blockchain::Result<sp_blockchain::BlockStatus> {
		Ok(if self.headers.contains_key(&hash) {
			sp_blockchain::BlockStatus::InChain
		} else {
			sp_blockchain::BlockStatus::Unknown
		})
	}

	fn number(&self, hash: H256) -> sp_blockchain::Result<Option<u32>> {
		Ok(self.headers.get(&hash).map(|header| *header.number()))
	}

	fn hash(&self, number: u32) -> sp_blockchain::Result<Option<H256>> {
		Ok(self
			.headers
			.values()
			.find(|header| *header.number() == number)
			.map(|header| header.hash()))
	}
}

/// The height in a header is attacker-supplied, and it picks the RandomX seed
/// epoch as well as going into the hashed blob. A header that claims a height
/// far past its parent must be refused before the seed walk and before the
/// hash, or a few hundred bytes of input buy an ancestry walk the length of a
/// whole epoch plus a RandomX hash.
#[test]
fn a_height_that_does_not_follow_its_parent_is_refused() {
	let (backend, parent) = FakeBackend::with_block(1_000);

	check_header_position::<TestBlock, _>(&backend, parent, 1_001, UNKNOWN_BLOCK)
		.expect("the only height that follows #1000 is #1001");

	for claimed in [1_000u64, 1_002, 4_000, 0, u64::MAX] {
		let error = check_header_position::<TestBlock, _>(&backend, parent, claimed, UNKNOWN_BLOCK)
			.expect_err("a height that does not follow its parent must be refused");
		assert!(
			matches!(error, Error::HeightMismatch { height, parent_number }
				if height == claimed && parent_number == 1_000),
			"expected a height mismatch, got: {error}",
		);
	}
}

/// And a header whose parent the node has never seen is refused on the same
/// path, before any walk begins.
#[test]
fn an_unknown_parent_is_refused_before_anything_is_walked() {
	let (backend, _parent) = FakeBackend::with_block(1_000);
	let error =
		check_header_position::<TestBlock, _>(&backend, H256([0xabu8; 32]), 1_001, UNKNOWN_BLOCK)
			.expect_err("an unknown parent must be refused");
	assert!(matches!(error, Error::UnknownParent(_)), "got: {error}");
}

/// A header at or below the finalized height is refused before the seed walk
/// and before any hash.
///
/// This is a backend consistency rule. Startup refuses legacy databases with
/// non-genesis finality; the block import seam still honors any finalized
/// boundary a backend reports. Reversible PoW keeps that boundary at genesis.
#[test]
fn a_header_at_or_below_the_finalized_height_is_refused() {
	// Finality at #1000, and a parent that is the finalized block itself.
	let (backend, parent) = FakeBackend::with_block_finalized_at(1_000, 1_000);
	check_header_position::<TestBlock, _>(&backend, parent, 1_001, UNKNOWN_BLOCK)
		.expect("the first unfinalized height is still importable");

	for finalized in [1_001u32, 1_002, 5_000] {
		let (backend, parent) = FakeBackend::with_block_finalized_at(1_000, finalized);
		let error = check_header_position::<TestBlock, _>(&backend, parent, 1_001, UNKNOWN_BLOCK)
			.expect_err("a header at or below the finalized height must be refused");
		assert!(
			matches!(error, Error::BelowFinalized { height, finalized: seen }
				if height == 1_001 && seen == u64::from(finalized)),
			"expected a finalized-height refusal, got: {error}",
		);
	}
}

/// With one exemption, and it is the one `sc-client` itself carries: the block
/// that fills the gap warp or fast sync left behind is below finality by
/// construction and is the only such block that can ever be imported.
#[test]
fn the_block_that_fills_a_sync_gap_is_exempt() {
	let (backend, parent) = FakeBackend::with_block_finalized_at(1_000, 5_000);
	let backend = FakeBackend {
		block_gap: Some(sp_blockchain::BlockGap {
			start: 1_001,
			end: 2_000,
			gap_type: sp_blockchain::BlockGapType::MissingHeaderAndBody,
		}),
		..backend
	};
	check_header_position::<TestBlock, _>(&backend, parent, 1_001, UNKNOWN_BLOCK)
		.expect("the gap block is the one below-finality block that is importable");
}

/// And a block the node already has is exempt too, because re-verifying one is
/// what `check-block` and `import-blocks` do and both are aimed at blocks that
/// are below finality by construction.
#[test]
fn a_block_the_node_already_has_is_exempt() {
	let (backend, parent) = FakeBackend::with_block_finalized_at(1_000, 5_000);
	check_header_position::<TestBlock, _>(&backend, parent, 1_001, parent)
		.expect("a block already in the chain is not a new submission");
}

/// A hash no header in the fake chain has, so neither exemption applies to it.
const UNKNOWN_BLOCK: H256 = H256([0xcdu8; 32]);

#[test]
fn reversible_pow_accepts_a_genesis_only_checkpoint() {
	let (backend, _) = FakeBackend::with_block(10_000);
	crate::ensure_pow_database::<TestBlock, _>(&backend).unwrap();
}

#[test]
fn reversible_pow_requires_replay_of_a_legacy_finalized_database() {
	let (backend, _) = FakeBackend::with_block_finalized_at(10_000, 9_900);
	let error = crate::ensure_pow_database::<TestBlock, _>(&backend).unwrap_err();
	assert!(error.to_string().contains("separate archive database"));
}

#[test]
fn a_valid_old_parent_remains_eligible_with_genesis_finality() {
	// The parent height is independent of the best height and confirmation
	// count. A fresh PoW database leaves its finalized checkpoint at genesis.
	let (mut backend, parent) = FakeBackend::with_block(1);
	let tip = sealed_header_at(10_000, canonical_digest());
	backend.headers.insert(tip.hash(), tip);
	assert_eq!(backend.info().best_number, 10_000);
	crate::ensure_pow_database::<TestBlock, _>(&backend).unwrap();
	check_header_position::<TestBlock, _>(&backend, parent, 2, UNKNOWN_BLOCK).unwrap();
}
