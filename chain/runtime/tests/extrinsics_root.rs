//! The construction behind `extrinsicsRoot`, pinned, with its known-answer
//! vector.
//!
//! The note ciphertexts live in block bodies, and the only thing that
//! authenticates a body against a header is `extrinsics_root`. Both wallets
//! recompute that root from the body a node served them, so the exact trie the
//! chain builds is consensus for a wallet in the same way the state root is.
//!
//! `frame_system::finalize` takes the construction from
//! `RuntimeVersion::system_version` by way of
//! `sp_version::RuntimeVersion::extrinsics_root_state_version`: 0 and 1 give
//! `StateVersion::V0`, anything above gives V1. V0 inlines every value into its
//! trie node; V1 replaces a value longer than 32 bytes with its hash. Every
//! extrinsic this chain carries is longer than 32 bytes, so a bump of
//! `system_version` to 2 changes every extrinsics root on the chain, with no
//! other signal anywhere, and every wallet's recomputation stops matching. That
//! is what the first assertion here exists to refuse, and
//! `runtime_identity.rs::the_extrinsics_root_construction_is_pinned` refuses
//! it a second time beside the runtime's other identity fields.
//!
//! The vector this test checks is `tests/fixtures/extrinsics_root_kat.json`:
//! the encoded extrinsics of one small body and the root over them.
//! `qnero-state-proof`'s own test reads the same file, so one body and one root
//! hold two independent implementations of the same trie together. Regenerate
//! it deliberately, with `QNERO_UPDATE_EXTRINSICS_ROOT_KAT=1`, and never to
//! make a red test green: a changed root is the chain telling a wallet it can
//! no longer read a block body.
//!
//! One thing the vector shows that a body walker has to know: the bare
//! preamble in it is `0x05`. `UncheckedExtrinsic::new_bare` takes
//! `sp_runtime`'s current `EXTRINSIC_FORMAT_VERSION`, which is 5, so every
//! inherent a node builds carries `0x05`, while the command-line wallet signs
//! and submits at the legacy version 4 and its settlements carry `0x04`
//! (`crates/qnero-wallet/src/extrinsic.rs`). `Preamble::decode` takes both, so
//! a real block body is a mixture and a walk that pins one byte reads half of
//! it as malformed.

use codec::Encode;
use frame_support::BoundedVec;
use qnero_runtime::{Block, Runtime, RuntimeCall, UncheckedExtrinsic, VERSION};
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT},
	StateVersion,
};
use sp_trie::{LayoutV0, TrieConfiguration};

/// The hasher `frame_system` builds the extrinsics trie with: the header's own,
/// named through the header rather than by hand, so a change to either is this
/// test's problem and not a wallet's.
type HeaderHashing = <<Block as BlockT>::Header as HeaderT>::Hashing;

const KAT_PATH: &str = "tests/fixtures/extrinsics_root_kat.json";

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Suite 1's serialized length. Written out rather than read from
/// `qnero_circuit::chain`: the vector is a fixed body on purpose, so a
/// constant that moves has to move the root through a deliberate regeneration
/// rather than by silently reshaping the input.
const SUITE_1_CIPHERTEXT_BYTES: usize = 1792;

/// A ciphertext of the one length settlement accepts, filled deterministically.
/// The bytes are not a real `NoteCiphertext` and nothing here dispatches: what
/// the vector needs is a body-sized leaf whose encoding is fixed.
fn suite_length_ciphertext(
	seed: u8,
) -> BoundedVec<u8, <Runtime as pallet_shielded::Config>::MaxCiphertextBytes> {
	let bytes: Vec<u8> = (0..SUITE_1_CIPHERTEXT_BYTES)
		.map(|index| seed.wrapping_add((index % 251) as u8))
		.collect();
	BoundedVec::try_from(bytes).expect("the suite length is under MaxCiphertextBytes")
}

/// One small body in the shape a real block has: the timestamp inherent, the
/// coinbase inherent, and one bare settlement carrying a full-size output pair.
fn body() -> Vec<UncheckedExtrinsic> {
	let timestamp =
		UncheckedExtrinsic::new_bare(RuntimeCall::Timestamp(pallet_timestamp::Call::set {
			now: 1_764_547_200_000,
		}));
	let coinbase =
		UncheckedExtrinsic::new_bare(RuntimeCall::Shielded(pallet_shielded::Call::coinbase {
			inner: [7u8; 32],
			ciphertext: Vec::new(),
		}));
	let settlement = UncheckedExtrinsic::new_bare(RuntimeCall::Shielded(
		pallet_shielded::Call::submit_private_batch {
			proof: (0..512u32).map(|index| (index % 256) as u8).collect(),
			outputs: vec![pallet_shielded::ShieldedOutput {
				ct_1: suite_length_ciphertext(0x11),
				ct_2: suite_length_ciphertext(0x22),
			}],
		},
	));
	vec![timestamp, coinbase, settlement]
}

/// `system_version` stays 1, the extrinsics trie stays `LayoutV0` over
/// BlakeTwo256, and the root over a fixed body stays the byte string in the
/// fixture.
#[test]
fn the_extrinsics_root_is_a_layout_v0_blake2_ordered_trie() {
	assert_eq!(VERSION.system_version, 1, "Q3 authenticates bodies against a LayoutV0 trie");
	assert_eq!(VERSION.extrinsics_root_state_version(), StateVersion::V0);

	// What the block builder hands `frame_system::note_extrinsic` is the whole
	// SCALE encoding of the extrinsic, its compact length prefix included, so
	// that is what the trie's values are.
	let encoded: Vec<Vec<u8>> = body().iter().map(Encode::encode).collect();

	// The runtime's own function, at the runtime's own version.
	let runtime_root = frame_system::extrinsics_data_root::<HeaderHashing>(
		encoded.clone(),
		VERSION.extrinsics_root_state_version(),
	);
	// The same trie, named directly, which is what a wallet builds.
	let layout_root = LayoutV0::<sp_core::Blake2Hasher>::ordered_trie_root(encoded.clone());
	assert_eq!(runtime_root.as_bytes(), layout_root.as_bytes());

	let vector = serde_json::json!({
		"description": "extrinsics root of a fixed body under system_version 1 \
			(sp_trie::LayoutV0 over BlakeTwo256). Values are whole SCALE-encoded \
			extrinsics, length prefix included, in block order.",
		"system_version": VERSION.system_version,
		"state_version": "V0",
		"extrinsics": encoded.iter().map(|xt| hex(xt)).collect::<Vec<_>>(),
		"extrinsics_root": hex(runtime_root.as_bytes()),
	});

	if std::env::var("QNERO_UPDATE_EXTRINSICS_ROOT_KAT").is_ok() {
		std::fs::write(
			KAT_PATH,
			format!("{}\n", serde_json::to_string_pretty(&vector).expect("serializable")),
		)
		.expect("the fixture directory is in the repository");
		return;
	}

	let stored: serde_json::Value = serde_json::from_str(
		&std::fs::read_to_string(KAT_PATH).expect("the known-answer vector is committed"),
	)
	.expect("the known-answer vector is JSON");
	assert_eq!(
		stored["extrinsics"], vector["extrinsics"],
		"the fixed body changed, so the vector no longer tests what it was written to test"
	);
	assert_eq!(
		stored["extrinsics_root"], vector["extrinsics_root"],
		"the extrinsics-root construction moved; every wallet's body authentication moved with it"
	);
	assert_eq!(stored["system_version"], vector["system_version"]);
}
