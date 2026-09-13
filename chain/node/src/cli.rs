use sc_cli::RunCmd;

/// Default share difficulty handed to a stratum connection.
///
/// About one share every few seconds from a 4 kH/s rig, which is enough to see
/// that a miner is alive without flooding the node. It is clamped per job to
/// the block difficulty, so on an easy chain every share is a block anyway.
pub const DEFAULT_SHARE_DIFFICULTY: u64 = 5_000;

/// Default address the stratum endpoint binds: loopback, so opening the port
/// to a rig on another machine is a decision an operator makes on purpose.
pub const DEFAULT_STRATUM_HOST: std::net::IpAddr =
	std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

#[derive(Debug, clap::Parser)]
#[command(arg_required_else_help = true)]
pub struct Cli {
	#[command(subcommand)]
	pub subcommand: Option<Subcommand>,

	#[clap(flatten)]
	pub run: RunCmd,

	/// Inner hash for mining rewards (0x-prefixed, 32-byte hex from wormhole key generation)
	#[arg(long, value_name = "INNER_HASH")]
	pub rewards_inner_hash: Option<String>,

	/// The miner key this node's coinbase notes are minted for (`qnm1...`).
	///
	/// Every block this node authors mints its reward as one note that only
	/// the wallet holding this key can find, and that is the only way value
	/// enters circulation after genesis. Take it from `qnero-wallet
	/// miner-address`, which prints the wallet's address beside it.
	///
	/// **It is secret-bearing.** It carries the coinbase viewing key, so
	/// whoever holds it can pick this miner's coinbase notes out of the tree.
	/// It cannot spend them and it says nothing about any other note the
	/// wallet holds. Prefer `QNERO_MINER_KEY` to a command line, which every
	/// process listing on the machine can read.
	///
	/// An authority without one builds blocks that carry no coinbase inherent,
	/// and every node refuses those, its own import included, so startup fails
	/// instead.
	#[arg(long, value_name = "QNM_KEY", env = "QNERO_MINER_KEY")]
	pub rewards_miner_key: Option<String>,

	/// Port for the stratum endpoint rigs connect to (e.g. 3333). Off by
	/// default.
	///
	/// The dialect is the one xmrig speaks to a Monero pool, so a stock
	/// `xmrig --algo rx/0 -o <host>:<port> -u <label>` mines this chain.
	/// Requires `--validator`; startup fails otherwise.
	///
	/// Nothing is paid to the login. The block reward is a shielded note for
	/// the key in `--rewards-miner-key`, so this is a solo-mining endpoint and
	/// the login string is a worker label.
	#[arg(long, value_name = "PORT")]
	pub stratum_port: Option<u16>,

	/// Address the stratum endpoint binds. Loopback by default: a rig on
	/// another machine needs `0.0.0.0` and a firewall rule you chose on
	/// purpose.
	///
	/// Requires `--stratum-port`; startup fails otherwise, because an address
	/// with no listener behind it is a flag that silently did nothing.
	#[arg(long, value_name = "ADDRESS", default_value = "127.0.0.1")]
	pub stratum_host: std::net::IpAddr,

	/// Share difficulty handed to each stratum connection.
	///
	/// Clamped per job to the block difficulty, so it can never make a share
	/// harder to find than a block. Lower means more shares and more traffic;
	/// the block itself is always checked against the network difficulty.
	#[arg(long, value_name = "DIFFICULTY", default_value_t = DEFAULT_SHARE_DIFFICULTY)]
	pub stratum_share_difficulty: u64,

	/// Threads the node mines with in process, in RandomX light mode.
	///
	/// One by default, which is what keeps a `--dev` chain producing blocks
	/// with no rig attached. Light mode is roughly an order of magnitude slower
	/// than the full-mode dataset a real miner builds, so this is for a devnet
	/// and for keeping a node from idling, not for competing. Zero turns it
	/// off, which is what an operator with a rig on `--stratum-port` wants.
	#[arg(long, value_name = "THREADS", default_value_t = 1)]
	pub mining_threads: usize,

	/// Enable peer sharing via RPC endpoint (`peer_getNetworkInfo`).
	///
	/// The endpoint is an unsafe RPC: it is served only to local connections, or to
	/// remote ones when the node also runs with `--rpc-methods unsafe`.
	#[arg(long)]
	pub enable_peer_sharing: bool,

	/// Sync: maximum request failures before dropping a peer that is ahead.
	#[arg(long, default_value_t = 20)]
	pub sync_max_timeouts_before_drop: u32,

	/// Sync: disable request-failure tolerance for peers that are ahead.
	#[arg(long, default_value_t = false)]
	pub sync_disable_major_sync_gating: bool,

	/// Maximum tip age in seconds before authoring pauses (default: 24 hours).
	///
	/// Until the node has observed its best block to be at most this old, it
	/// refuses to mine (initial-sync guard, like Bitcoin's -maxtipage).
	/// Bypassed entirely by --force-authoring.
	#[arg(long, value_name = "SECONDS", default_value_t = crate::service::DEFAULT_MAX_TIP_AGE_SECS)]
	pub max_tip_age: u64,

	/// Sync: block request timeout in seconds (default: 30).
	#[arg(long, default_value_t = 30)]
	pub sync_block_request_timeout: u64,
}

#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommand {
	/// Key management cli utilities
	#[command(subcommand)]
	Key(QuantusKeySubcommand),

	/// Build a chain specification.
	BuildSpec(sc_cli::BuildSpecCmd),

	/// Validate blocks.
	CheckBlock(sc_cli::CheckBlockCmd),

	/// Export blocks.
	ExportBlocks(sc_cli::ExportBlocksCmd),

	/// Export the state of a given block into a chain spec.
	ExportState(sc_cli::ExportStateCmd),

	/// Import blocks.
	ImportBlocks(sc_cli::ImportBlocksCmd),

	/// Remove the whole chain.
	PurgeChain(sc_cli::PurgeChainCmd),

	/// Revert the chain to a previous state.
	Revert(sc_cli::RevertCmd),

	/// Sub-commands concerned with benchmarking.
	#[cfg(feature = "runtime-benchmarks")]
	#[command(subcommand)]
	Benchmark(frame_benchmarking_cli::BenchmarkCmd),

	/// Db meta columns information.
	ChainInfo(sc_cli::ChainInfoCmd),
}
#[derive(Debug, clap::Subcommand)]
pub enum QuantusKeySubcommand {
	/// Standard key commands from sc_cli
	#[command(flatten)]
	Sc(Box<sc_cli::KeySubcommand>),
	/// Generate a Qnero transparent (ML-DSA-87) address
	#[command(name = "qnero")]
	Quantus {
		/// Type of the key
		#[arg(long, value_name = "SCHEME", value_enum, default_value_t = QuantusAddressType::Standard, ignore_case = true)]
		scheme: QuantusAddressType,

		/// Optional: Read a 128-character hex master seed (64 bytes) from stdin.
		/// The value is intentionally not accepted as a command-line argument
		/// (argv is world-readable and recorded in shell history / audit logs):
		/// on a terminal you are prompted without echo, otherwise pipe it in
		/// (e.g. `... --seed < seed.txt`). Mutually exclusive with --words.
		#[arg(long, conflicts_with = "words")]
		seed: bool,

		/// Optional: Read a BIP39 phrase ("word1 word2 ... word24") from stdin.
		/// The value is intentionally not accepted as a command-line argument
		/// (argv is world-readable and recorded in shell history / audit logs):
		/// on a terminal you are prompted without echo, otherwise pipe it in
		/// (e.g. `... --words < mnemonic.txt`). Mutually exclusive with --seed.
		#[arg(long, conflicts_with = "seed")]
		words: bool,

		/// Optional: HD wallet derivation index (default 0). Ignored if --no-derivation is set.
		#[arg(long, value_name = "INDEX", default_value_t = 0u32)]
		wallet_index: u32,

		/// Disable HD derivation. Generates the same result as current behavior.
		#[arg(long, default_value_t = false)]
		no_derivation: bool,

		/// Additionally print the public key / address hex. Secret material (seed,
		/// secret key) is never printed; everything is re-derivable from the mnemonic.
		#[arg(long, short = 'v', default_value_t = false)]
		verbose: bool,
	},
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum QuantusAddressType {
	Wormhole,
	Standard,
}
