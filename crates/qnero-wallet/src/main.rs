//! `qnero-wallet`: the Qnero v0 command line wallet.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qnero_notes::Address;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::{create_seed, default_seed_path, store_path_for};
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::{RpcClient, DEFAULT_NODE_URL};
use qnero_wallet::store::PendingKind;
use qnero_wallet::wallet::{EntryRhoCheck, MerkleSource, Wallet, NUM_LEAF_PROOFS};
use qnero_wallet::POOL_QUANTUM;

/// Amounts are in pool quanta. One quantum is 10^10 planck, 0.01 QTC.
#[derive(Debug, Parser)]
#[command(
    name = "qnero-wallet",
    version,
    about = "Qnero v0 shielded wallet",
    long_about = "Qnero v0 shielded wallet.

Amounts are in POOL QUANTA. One quantum is 10^10 planck (0.01 QTC) and every
value inside the pool, fees included, is counted in them.

KEY HANDLING IS DEV GRADE. The seed is 32 bytes of hex in a file with mode
0600, with no passphrase, no key derivation and no encryption at rest, and the
note store beside it holds every note's rho and r in the clear. Anyone who can
read those two files can spend every note this wallet holds and can link every
spend it has made. Use it on a dev chain and nowhere else.

WHAT THE NODE LEARNS. A scan reads the whole leaf range and the whole settled
nullifier set, and a spend rebuilds the commitment tree locally, so no request
this wallet makes names a note as its own. Passing --merkle-rpc gives that up:
it asks the node for a proof of each leaf being spent, seconds before the
settlement that publishes the matching nullifiers."
)]
struct Cli {
    /// JSON-RPC endpoint of the node.
    #[arg(long, global = true, default_value = DEFAULT_NODE_URL)]
    node: String,
    /// Seed file. The note store lives beside it as `<seed>.store.json`.
    #[arg(long, global = true)]
    file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a seed and print the address it derives.
    ///
    /// The seed is written as hex with mode 0600 and is not encrypted. This is
    /// dev-grade key storage; see the top-level help.
    Keygen,
    /// Print this wallet's address.
    Address,
    /// Move transparent value from a dev account into a fresh note.
    Shield {
        /// A dev chain's endowed accounts: alice, bob or charlie.
        #[arg(long)]
        from_dev_account: String,
        /// Pool quanta to move into the pool.
        #[arg(long)]
        amount: u64,
        /// Memo carried in the note's ciphertext.
        #[arg(long, default_value = "")]
        memo: String,
    },
    /// Scan the chain for notes and settle spent status.
    Sync,
    /// Unspent total, pending total and the note list.
    Balance,
    /// Spend up to two notes into a payment and a change note.
    Send {
        /// Recipient address, `qn1...`.
        #[arg(long)]
        to: String,
        /// Pool quanta to pay.
        #[arg(long)]
        amount: u64,
        /// Fee in pool quanta. Defaults to this submission's floor, and a
        /// value below it is refused: the fee is a public input of the proof.
        #[arg(long)]
        fee: Option<u64>,
        /// Memo carried in the payment's ciphertext.
        #[arg(long, default_value = "")]
        memo: String,
        /// Skip the sync that normally runs first.
        #[arg(long)]
        no_sync: bool,
        /// Ask the node for each input's Merkle proof. The default rebuilds
        /// the tree locally; this flag tells the node which leaves are yours,
        /// seconds before the settlement that publishes their nullifiers.
        #[arg(long)]
        merkle_rpc: bool,
    },
    /// Chain head, last synced block and tree leaf count.
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let seed_path = cli.file.clone().unwrap_or_else(default_seed_path);

    match cli.command {
        Command::Keygen => {
            let key = create_seed(&seed_path)?;
            println!("seed    {}", seed_path.display());
            println!("store   {}", store_path_for(&seed_path).display());
            println!("address {}", key.address().encode());
            println!();
            println!(
                "The seed is unencrypted hex at mode 0600. Anyone who can read it can spend \
                 every note this wallet holds."
            );
        }
        Command::Address => {
            let wallet = Wallet::open(&seed_path)?;
            println!("{}", wallet.address().encode());
        }
        Command::Status => {
            let rpc = RpcClient::new(&cli.node);
            let chain = Chain::new(&rpc);
            let head = chain.head()?;
            let tree = chain.tree_state()?;
            let (spec, tx) = chain.runtime_version()?;
            println!("node              {}", rpc.url());
            println!("runtime           spec {spec}, transaction {tx}");
            println!(
                "chain head        {} ({})",
                head.number,
                hex::encode(head.hash)
            );
            println!("tree leaves       {}", tree.leaf_count);
            println!("tree depth        {}", tree.depth);
            println!("tree root         {}", hex::encode(tree.root));
            if seed_path.exists() {
                let wallet = Wallet::open(&seed_path)?;
                println!("last synced block {}", wallet.store.last_synced_block);
                println!("next leaf to scan {}", wallet.store.next_leaf);
            } else {
                println!("last synced block (no wallet at {})", seed_path.display());
            }
        }
        Command::Sync => {
            let rpc = RpcClient::new(&cli.node);
            let chain = Chain::new(&rpc);
            let metadata = ChainMetadata::fetch(&rpc)?;
            let mut wallet = Wallet::open(&seed_path)?;
            let report = wallet.sync(&chain, &metadata)?;
            println!(
                "scanned leaves {}..{} at block {}",
                report.scanned_from, report.scanned_to, report.head_block
            );
            println!(
                "received {} note(s) worth {} quanta",
                report.received, report.received_value
            );
            if report.rejected > 0 {
                println!(
                    "refused {} decryptable output(s); see `rejected` in {}",
                    report.rejected,
                    wallet.store_path.display()
                );
            }
            println!("newly spent {}", report.newly_spent);
            println!("unspent total {} quanta", wallet.store.unspent_total());
        }
        Command::Balance => {
            let wallet = Wallet::open(&seed_path)?;
            let store = &wallet.store;
            println!("address        {}", store.address);
            println!("unspent        {} quanta", store.unspent_total());
            println!("pending        {} quanta", store.pending_total());
            println!("synced through block {}", store.last_synced_block);
            println!();
            if store.notes.is_empty() {
                println!("no notes");
            } else {
                println!(
                    "{:>10}  {:>12}  {:>7}  {:>7}  memo",
                    "leaf", "quanta", "block", "state"
                );
                for note in &store.notes {
                    println!(
                        "{:>10}  {:>12}  {:>7}  {:>7}  {}",
                        note.leaf_index,
                        note.value,
                        note.block_number
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "-".into()),
                        if note.spent { "spent" } else { "unspent" },
                        note.memo
                    );
                }
            }
            for pending in &store.pending {
                println!(
                    "pending {:?} of {} quanta submitted at block {}",
                    pending.kind, pending.value, pending.submitted_at_block
                );
                if pending.kind == PendingKind::Shield {
                    println!("        commitment {}", pending.commitment);
                }
            }
            for rejected in &store.rejected {
                println!(
                    "refused leaf {} worth {} quanta: {}",
                    rejected.leaf_index, rejected.value, rejected.reason
                );
            }
        }
        Command::Shield {
            from_dev_account,
            amount,
            memo,
        } => {
            let rpc = RpcClient::new(&cli.node);
            let chain = Chain::new(&rpc);
            let metadata = ChainMetadata::fetch(&rpc)?;
            let from = TransparentKey::dev(&from_dev_account)?;
            let mut wallet = Wallet::open(&seed_path)?;
            println!(
                "shielding {amount} quanta ({} planck) from {from_dev_account}",
                u128::from(amount) * POOL_QUANTUM
            );
            let report = wallet.shield(&chain, &metadata, &from, amount, &memo)?;
            println!("commitment  {}", report.commitment);
            println!("leaf        {}", report.leaf_index);
            println!(
                "included    block {} after {:.2?}",
                report.included_at, report.inclusion
            );
            match &report.entry_check {
                EntryRhoCheck::Confirmed => {}
                EntryRhoCheck::Missed { reason } => println!(
                    "note        the entry rho prediction missed: {reason}. The note is this \
                     wallet's own and is spendable; the rule in docs/CIRCUIT.md 9.8 is what \
                     missed, and a recipient checking it strictly would refuse the note."
                ),
                EntryRhoCheck::Unproven { entries_in_block } => println!(
                    "note        {entries_in_block} shield entries settled in block {}, so which \
                     entry index the chain assigned this note is not decidable from storage \
                     alone. Only the Shielded event carries it. The note is spendable either \
                     way.",
                    report.included_at
                ),
            }
            let sync = wallet.sync(&chain, &metadata)?;
            println!(
                "synced      {} new note(s), unspent total {} quanta",
                sync.received,
                wallet.store.unspent_total()
            );
        }
        Command::Send {
            to,
            amount,
            fee,
            memo,
            no_sync,
            merkle_rpc,
        } => {
            let rpc = RpcClient::new(&cli.node);
            let chain = Chain::new(&rpc);
            let metadata = ChainMetadata::fetch(&rpc)?;
            let recipient =
                Address::decode(&to).context("the recipient address does not decode")?;
            let mut wallet = Wallet::open(&seed_path)?;
            if !no_sync {
                wallet.sync(&chain, &metadata)?;
            }
            let merkle = if merkle_rpc {
                println!(
                    "merkle      zkTree_getMerkleProof (this names the leaves being spent to the \
                     node)"
                );
                MerkleSource::Rpc
            } else {
                MerkleSource::Local
            };

            // The fee floor and the note selection are settled before any
            // circuit is built: both refuse spends that seconds of circuit
            // building and tens of seconds of proving would be spent on.
            let resolved_fee = wallet.preflight(&metadata, &recipient, amount, fee, &memo)?;
            println!("fee         {resolved_fee} quanta");

            let build_started = std::time::Instant::now();
            // One build per process. Building both circuits is seconds and
            // proving is tens of seconds; constructing a prover per
            // transaction is the mistake the API exists to prevent.
            let prover = WalletProver::new(NUM_LEAF_PROOFS)
                .context("failed to build the wallet's circuits")?;
            println!(
                "circuits    built in {:.2?} ({NUM_LEAF_PROOFS} leaf slots per batch)",
                build_started.elapsed()
            );

            let report = wallet.send(
                &chain,
                &metadata,
                &prover,
                &recipient,
                amount,
                Some(resolved_fee),
                &memo,
                merkle,
            )?;
            println!("anchor      block {}", report.anchor_block);
            println!(
                "inputs      leaves {:?} for {} quanta plus {} fee",
                report.inputs, report.amount, report.fee
            );
            println!("change      {} quanta", report.change);
            println!("proof       {} bytes", report.proof_bytes);
            println!("proving     {:.2?}", report.proving);
            println!(
                "inclusion   block {} after {:.2?}",
                report.included_at, report.inclusion
            );
            let sync = wallet.sync(&chain, &metadata)?;
            println!(
                "synced      {} new note(s), unspent total {} quanta",
                sync.received,
                wallet.store.unspent_total()
            );
        }
    }
    Ok(())
}
