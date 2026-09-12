//! Test runtime for `pallet-shielded`.
//!
//! `System`, `Balances`, the real `ZkTree` and the pallet. The tree is the real
//! one on purpose: the leaf rule is `leaf_hash = cm`, so a mock tree would let
//! a test pass while the commitment the circuit proved membership against and
//! the leaf the chain stored disagreed.

use crate::{self as pallet_shielded};
use frame_support::{
	construct_runtime, parameter_types,
	traits::{ConstU32, ConstU64, Everything},
};
use frame_system::mocking::MockUncheckedExtrinsic;
use sp_core::H256;
use sp_runtime::{
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage, Permill,
};

construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		ZkTree: pallet_zk_tree,
		Shielded: pallet_shielded,
	}
);

pub type Balance = u128;
/// 1 QNR = 10^12 planck.
pub const UNIT: Balance = 1_000_000_000_000;
pub type AccountId = sp_core::crypto::AccountId32;

/// The forked header, which is what carries `zk_tree_root`. `frame_system`'s
/// `Block` bound demands it, and the whole security chain runs through it: the
/// leaf circuit's public `block_hash` commits to this header, the header
/// carries the tree root, and each input's Merkle path reaches that root.
pub type Block<T> = sp_runtime::generic::Block<
	qp_header::Header<u64, BlakeTwo256>,
	MockUncheckedExtrinsic<T, qp_dilithium_crypto::DilithiumSignatureScheme>,
>;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
}

impl frame_system::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type BaseCallFilter = Everything;
	type AuthorizeUpgradeOrigin = frame_system::EnsureRoot<Self::AccountId>;
	type BlockWeights = ();
	type BlockLength = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type RuntimeTask = ();
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block<Self>;
	type BlockHashCount = BlockHashCount;
	type DbWeight = ();
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<Balance>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type ExtensionsWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<16>;
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = ();
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
}

parameter_types! {
	pub static ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for Test {
	type RuntimeHoldReason = ();
	type RuntimeFreezeReason = ();
	type WeightInfo = ();
	type Balance = Balance;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type ReserveIdentifier = [u8; 8];
	type FreezeIdentifier = ();
	type MaxLocks = ConstU32<50>;
	type MaxReserves = ();
	type MaxFreezes = ();
	type DoneSlashHandler = ();
	type RuntimeEvent = RuntimeEvent;
}

impl pallet_zk_tree::Config for Test {
	type AssetId = u32;
	type Balance = Balance;
}

parameter_types! {
	/// Half of a settled fee is burned, half goes to the block author.
	pub const FeeBurnRate: Permill = Permill::from_percent(50);
	/// One quantum per real leaf slot, which is the runtime default.
	pub static MinLeafFee: u64 = 1;
	/// One quantum per started 512 bytes of ciphertext, the runtime default.
	pub static CiphertextBytesPerFeeQuantum: u32 = 512;
	/// The runtime's own cap, so a ciphertext the production runtime refuses at
	/// its SCALE decode cannot pass a test here.
	pub const MaxCiphertextBytes: u32 = 2048;
}

/// The mock's block-author seam, which is the runtime's: the QPoW pre-runtime
/// digest carries the miner's inner hash and the author account is the
/// wormhole address derived from it.
///
/// The pallet reads the author only through [`pallet_shielded::Config::FindAuthor`],
/// so this is the whole of what a test has to stand in for, and
/// `set_author_preimage` is what puts a digest in front of it.
pub struct QpowAuthor;

impl frame_support::traits::FindAuthor<AccountId> for QpowAuthor {
	fn find_author<'a, I>(digests: I) -> Option<AccountId>
	where
		I: 'a + IntoIterator<Item = (sp_runtime::ConsensusEngineId, &'a [u8])>,
	{
		for (engine, data) in digests {
			if engine != qp_wormhole::POW_ENGINE_ID {
				continue;
			}
			let preimage: [u8; 32] = data.try_into().ok()?;
			return qp_wormhole::derive_wormhole_address(preimage).ok().map(AccountId::new);
		}
		None
	}
}

impl pallet_shielded::Config for Test {
	type Currency = Balances;
	type ZkTree = ZkTree;
	type FindAuthor = QpowAuthor;
	type BlockHashWindow = ConstU64<64>;
	type MinLeafFee = MinLeafFee;
	type CiphertextBytesPerFeeQuantum = CiphertextBytesPerFeeQuantum;
	type FeeBurnRate = FeeBurnRate;
	type MaxCiphertextBytes = MaxCiphertextBytes;
	type WeightInfo = ();
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	let mut ext: sp_io::TestExternalities = t.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

pub fn new_test_ext_with_endowments(
	endowments: Vec<(AccountId, Balance)>,
) -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	pallet_balances::GenesisConfig::<Test> { balances: endowments, ..Default::default() }
		.assimilate_storage(&mut t)
		.unwrap();
	let mut ext: sp_io::TestExternalities = t.into();
	ext.execute_with(|| System::set_block_number(1));
	ext
}

/// Put a QPoW pre-runtime digest in place so the block-author lookup finds one.
///
/// `preimage` is the miner's inner digest; the author account is
/// `H(H(salt + secret))` of it, which is what `qp_wormhole` derives.
pub fn set_author_preimage(preimage: [u8; 32]) {
	System::deposit_log(sp_runtime::DigestItem::PreRuntime(
		qp_wormhole::POW_ENGINE_ID,
		preimage.to_vec(),
	));
}

/// The account `set_author_preimage` makes the block author.
pub fn author_of(preimage: [u8; 32]) -> AccountId {
	AccountId::new(qp_wormhole::derive_wormhole_address(preimage).expect("canonical preimage"))
}
