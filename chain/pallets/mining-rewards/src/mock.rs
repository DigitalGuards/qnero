use crate as pallet_mining_rewards;

use core::cell::RefCell;
use frame_support::{
	parameter_types,
	traits::{ConstU32, Everything, Hooks},
};
use sp_consensus_qpow::POW_ENGINE_ID;
use sp_runtime::{
	app_crypto::sp_core,
	testing::H256,
	traits::{BlakeTwo256, IdentityLookup},
	BuildStorage, DigestItem,
};

// Re-export the shared test helper from qp_wormhole
pub use qp_wormhole::TestMiner;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test {
		System: frame_system,
		Balances: pallet_balances,
		MiningRewards: pallet_mining_rewards,
	}
);

pub type Balance = u128;
pub type Block = frame_system::mocking::MockBlock<Test>;
const UNIT: u128 = 1_000_000_000_000u128;

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 189;
	pub const MaxSupply: u128 = 21_000_000 * UNIT;
	/// Matches the runtime: `remaining / 5_000_000` a block at a 120 s target,
	/// which is the 12 s schedule's `1/50_000_000` rescaled so the supply
	/// against wall clock is unchanged.
	pub const EmissionDivisor: u128 = 5_000_000;
	/// `static` so individual tests can raise it (e.g. to make a treasury mint
	/// fail below the ED) via `ExistentialDeposit::set`.
	pub static ExistentialDeposit: Balance = 1;
}

impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type AuthorizeUpgradeOrigin = frame_system::EnsureRoot<Self::AccountId>;
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type RuntimeTask = ();
	type Nonce = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sp_core::crypto::AccountId32;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Block = Block;
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
	type MaxConsumers = frame_support::traits::ConstU32<16>;
	type SingleBlockMigrations = ();
	type MultiBlockMigrator = ();
	type PreInherents = ();
	type PostInherents = ();
	type PostTransactions = ();
	type RuntimeEvent = RuntimeEvent;
}

impl pallet_balances::Config for Test {
	type RuntimeEvent = RuntimeEvent;
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
	type MaxFreezes = ConstU32<0>;
	type DoneSlashHandler = ();
}

parameter_types! {
	pub const Unit: u128 = UNIT;
	/// The value the shielded pool holds. Zero unless a test says otherwise;
	/// the emission schedule measures supply across both books.
	pub static ShieldedSupply: Balance = 0;
}

thread_local! {
	// Every coinbase credit the pallet handed to the pool, in order.
	static COINBASE_CREDITS: RefCell<Vec<u128>> = const { RefCell::new(Vec::new()) };
	// Whether the pool refuses the credit, which is what a block with no
	// coinbase inherent looks like from here.
	static COINBASE_REFUSES: RefCell<bool> = const { RefCell::new(false) };
}

/// Stands in for `pallet-shielded`: it records what it was asked to mint into
/// the block's coinbase note, and can refuse.
pub struct MockCoinbaseSink;

impl MockCoinbaseSink {
	/// Every credit taken, in order.
	pub fn credits() -> Vec<u128> {
		COINBASE_CREDITS.with(|credits| credits.borrow().clone())
	}

	/// What the pool has taken in total.
	pub fn total() -> u128 {
		COINBASE_CREDITS.with(|credits| credits.borrow().iter().sum())
	}

	pub fn clear() {
		COINBASE_CREDITS.with(|credits| credits.borrow_mut().clear());
		Self::set_refusing(false);
	}

	/// Make the next credits fail, the way a block with no coinbase inherent
	/// does.
	pub fn set_refusing(refusing: bool) {
		COINBASE_REFUSES.with(|refuses| *refuses.borrow_mut() = refusing);
	}
}

impl qp_coinbase::CoinbaseSink<u128> for MockCoinbaseSink {
	fn deposit_coinbase(amount: u128) -> Result<(), u128> {
		if COINBASE_REFUSES.with(|refuses| *refuses.borrow()) {
			return Err(amount);
		}
		COINBASE_CREDITS.with(|credits| credits.borrow_mut().push(amount));
		Ok(())
	}
}

/// The mock's block-author seam, which is the runtime's: the QPoW pre-runtime
/// digest carries the miner's inner hash and the author account is the
/// wormhole address derived from it. The pallet reads the author only through
/// `Config::FindAuthor`, so this is the whole of what a test stands in for.
pub struct QpowAuthor;

impl frame_support::traits::FindAuthor<sp_core::crypto::AccountId32> for QpowAuthor {
	fn find_author<'a, I>(digests: I) -> Option<sp_core::crypto::AccountId32>
	where
		I: 'a + IntoIterator<Item = (sp_runtime::ConsensusEngineId, &'a [u8])>,
	{
		for (engine, data) in digests {
			if engine != POW_ENGINE_ID {
				continue;
			}
			let preimage: [u8; 32] = data.try_into().ok()?;
			return qp_wormhole::derive_wormhole_address(preimage)
				.ok()
				.map(sp_core::crypto::AccountId32::new);
		}
		None
	}
}

impl pallet_mining_rewards::Config for Test {
	type Currency = Balances;
	type CoinbaseSink = MockCoinbaseSink;
	type ShieldedSupply = ShieldedSupply;
	type FindAuthor = QpowAuthor;
	type WeightInfo = ();
	type MaxSupply = MaxSupply;
	type EmissionDivisor = EmissionDivisor;
	type Unit = Unit;
}

/// Default test miners for convenience (using shared TestMiner from qp_wormhole)
pub const MINER_1: TestMiner = TestMiner(1);
pub const MINER_2: TestMiner = TestMiner(2);

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	MockCoinbaseSink::clear();
	ShieldedSupply::set(0);
	let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(MINER_1.account_id(), ExistentialDeposit::get()),
			(MINER_2.account_id(), ExistentialDeposit::get()),
		],
		dev_accounts: None,
	}
	.assimilate_storage(&mut t)
	.unwrap();

	let mut ext = sp_io::TestExternalities::new(t);
	ext.execute_with(|| System::set_block_number(1)); // Start at block 1
	ext
}

/// Helper function to create a block digest with a specific preimage.
/// Use with TestMiner: `set_miner_preimage_digest(MINER_1.preimage())`
pub fn set_miner_preimage_digest(preimage: [u8; 32]) {
	let pre_digest = DigestItem::PreRuntime(POW_ENGINE_ID, preimage.to_vec());
	System::deposit_log(pre_digest);
}

/// Helper function to create a block digest with a custom engine ID.
/// Used for testing that incorrect engine IDs are properly ignored.
pub fn set_digest_with_engine_id(engine_id: [u8; 4], data: Vec<u8>) {
	let pre_digest = DigestItem::PreRuntime(engine_id, data);
	System::deposit_log(pre_digest);
}

// Helper function to run a block
pub fn run_to_block(n: u64) {
	while System::block_number() < n {
		let block_number = System::block_number();

		// Run on_finalize for the current block
		MiningRewards::on_finalize(block_number);
		System::on_finalize(block_number);

		// Increment block number
		System::set_block_number(block_number + 1);

		// Run on_initialize for the next block
		System::on_initialize(block_number + 1);
		MiningRewards::on_initialize(block_number + 1);
	}
}
