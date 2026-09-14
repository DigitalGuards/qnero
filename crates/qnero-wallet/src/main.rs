//! `qnero-wallet`: the Qnero v0 command line wallet.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qnero_notes::Address;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::{create_seed, default_seed_path, store_path_for};
use qnero_wallet::memo::{memo_budget_within, render_memo_within, terminal_columns, MEMO_BYTES};
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::{RpcClient, DEFAULT_NODE_URL};
use qnero_wallet::store::{NoteRow, PendingKind, StoredNote};
use qnero_wallet::wallet::{
    ChainBinding, EntryRhoCheck, MerkleSource, SyncOptions, Wallet, NUM_LEAF_PROOFS,
};
use qnero_wallet::POOL_QUANTUM;

/// Amounts are in pool quanta. One quantum is 10^10 planck, 0.01 QNR.
#[derive(Debug, Parser)]
#[command(
    name = "qnero-wallet",
    version,
    about = "Qnero v0 shielded wallet",
    long_about = "Qnero v0 shielded wallet.

Amounts are in POOL QUANTA. One quantum is 10^10 planck (0.01 QNR) and every
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
settlement that publishes the matching nullifiers.

WHAT EVERY CHAIN READER LEARNS. Memos are padded to one size and the payment
takes either output slot at random, so a settlement's two ciphertexts do not
say which output is the sender's change or how long a memo was. A coinbase
note is the one amount this wallet holds that the chain publishes: its value
is in Shielded::CoinbaseValues and its block in Shielded::LeafBlocks, so
anyone can read a miner's income block by block and only who holds it is
hidden. The gap between a spend's anchor block and its inclusion block is
still visible and still tracks this machine's speed; see docs/WALLET.md."
)]
struct Cli {
    /// JSON-RPC endpoint of the node.
    #[arg(long, global = true, default_value = DEFAULT_NODE_URL)]
    node: String,
    /// Seed file. The note store lives beside it as `<seed>.store.json`.
    #[arg(long, global = true)]
    file: Option<PathBuf>,
    /// Archive a store built against another chain and start a fresh one.
    ///
    /// A store records the genesis of the chain it was built against, and
    /// every leaf index, block number, checkpoint hash and spent flag in it is
    /// a statement about that chain. A node serving a different genesis, which
    /// is what a restarted `--dev --tmp` node is, makes all of them wrong.
    /// This moves the old store aside rather than deleting it: it is the
    /// fastest copy of every note's rho and r, and the seed is what recovers
    /// them, because every note's plaintext is on the chain inside its
    /// ciphertext. What a lost store costs is the record of which notes are
    /// spent and the time of a full rescan.
    #[arg(long, global = true)]
    new_chain_store: bool,
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
    /// Print the miner key a block author's node is configured with.
    ///
    /// The node derives every coinbase note it mints from this, and this
    /// wallet is what finds them. It carries the coinbase viewing key, so it
    /// is secret-bearing: whoever holds it can pick this wallet's coinbase
    /// notes out of the tree. It cannot spend them and it says nothing about
    /// any other note.
    MinerAddress,
    /// Move transparent value from a dev account into a fresh note.
    Shield {
        /// A dev chain's endowed accounts: alice, bob or charlie.
        #[arg(long)]
        from_dev_account: String,
        /// Pool quanta to move into the pool.
        #[arg(long)]
        amount: u64,
        /// Memo carried in the note's ciphertext. Every memo is padded to one
        /// fixed size, so a longer one is refused.
        #[arg(long, default_value = "")]
        memo: String,
    },
    /// Scan the chain for notes and settle spent status.
    Sync {
        /// Walk the whole tree again from leaf zero, keeping every note, and
        /// go past a node gate this wallet cannot measure.
        ///
        /// The recovery for a store an older build wrote. Before conflict
        /// sets, a scan refused the second note it met that shared a nullifier
        /// with one it already held and never looked at that leaf again, so
        /// the note's rho and r were never recorded and no store upgrade can
        /// bring them back. A fresh walk reads them out of the ciphertext the
        /// chain published. Every note already held is kept, which is the
        /// difference from deleting the store.
        ///
        /// It is also the way through a sync that refuses the node: one behind
        /// this wallet, or one that diverged above its own head, which look
        /// the same from a store. The refusal is printed and bypassed, the
        /// watermark and the checkpoints go with it, and the scan then runs
        /// add only: notes and relocations are recorded, spent flags are never
        /// cleared and no note is marked off chain. Run an ordinary sync
        /// against a node at the current head afterwards to get those back.
        /// The chain check is never bypassed.
        #[arg(long)]
        rescan: bool,
    },
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
        /// Memo carried in the payment's ciphertext. Every memo is padded to
        /// one fixed size, so a longer one is refused.
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

/// Refuse a memo the padding cannot take, at the top of a command.
///
/// `memo::pad_memo` refuses it too, but only once a ciphertext is being built,
/// which for `send` is after a sync and a circuit build.
fn ensure_memo_fits(memo: &str) -> Result<()> {
    if memo.len() > MEMO_BYTES {
        anyhow::bail!(
            "the memo is {} bytes and every memo is padded to {MEMO_BYTES}. A longer one would \
             make this note's ciphertext a different length from every other note's, which is \
             the leak the padding closes.",
            memo.len()
        );
    }
    Ok(())
}

/// Say what checking the store against this node's chain found, when there is
/// anything to say.
///
/// Silent for the ordinary case, a store that already named this chain.
/// Nothing here writes the binding: a store that names no chain yet records
/// one when a sync, a shield or a send actually commits, and the `sync` report
/// below says so when it happens.
fn report_binding(binding: &ChainBinding) {
    match binding {
        ChainBinding::Bound => {}
        ChainBinding::Unrecorded => println!(
            "chain       this store names no chain yet. The first sync, shield or send that \
             commits records this node's genesis."
        ),
        ChainBinding::Archived(path) => println!(
            "chain       this store belonged to another chain. It is archived at {} and this \
             wallet starts fresh against this one.",
            path.display()
        ),
    }
}

/// The `balance` note table.
///
/// The four fields are measured before anything is printed, so the memo column
/// is budgeted against the prefix this table actually draws rather than the
/// narrowest one it could: a leaf index past 9,999,999,999 or a value past
/// 999,999,999,999 widens its own field, and a budget computed from the
/// constant would then hand the memo the columns that field took.
///
/// One row per nullifier. Two notes sharing a nullifier are
/// a conflict set: at most one of them can ever settle, so listing both would
/// print a total the chain will never back. The row carries the member a spend
/// would use and says how many notes it stands for.
fn print_notes(rows: &[NoteRow<'_>]) {
    fn state(row: &NoteRow<'_>) -> String {
        let base = if row.note.spent {
            "spent"
        } else if !row.note.on_chain {
            "orphan"
        } else {
            "unspent"
        };
        if row.is_conflict() {
            format!("{base} conflict {}", row.members)
        } else {
            base.to_string()
        }
    }
    fn block(note: &StoredNote) -> String {
        note.block_number
            .map(|number| number.to_string())
            .unwrap_or_else(|| "-".into())
    }

    /// One row, already stringified, so the widths can be measured before
    /// anything is printed.
    struct Row<'a> {
        leaf: String,
        value: String,
        block: String,
        state: String,
        memo: &'a str,
    }

    let rows: Vec<Row<'_>> = rows
        .iter()
        .map(|row| Row {
            leaf: row.note.leaf_index.to_string(),
            value: row.note.value.to_string(),
            block: block(row.note),
            state: state(row),
            memo: row.note.memo.as_str(),
        })
        .collect();
    let width = |header: usize, measure: &dyn Fn(&Row<'_>) -> usize| {
        rows.iter().map(measure).max().unwrap_or(0).max(header)
    };
    let leaf = width(10, &|row| row.leaf.len());
    let value = width(12, &|row| row.value.len());
    let block_width = width(7, &|row| row.block.len());
    let state_width = width(7, &|row| row.state.len());
    // Four fields and the two spaces after each.
    let prefix = leaf + value + block_width + state_width + 8;
    let budget = memo_budget_within(prefix);

    println!(
        "{:>leaf$}  {:>value$}  {:>block_width$}  {:>state_width$}  memo",
        "leaf", "quanta", "block", "state"
    );
    for row in &rows {
        let fields = format!(
            "{:>leaf$}  {:>value$}  {:>block_width$}  {:>state_width$}",
            row.leaf, row.value, row.block, row.state
        );
        // A memo is remote input: anyone holding this address can send a note
        // and choose its bytes. Printed raw it is an escape sequence injection
        // into this terminal. See `qnero_wallet::memo::render_memo_within`.
        // The budget is this terminal's own width less the prefix measured
        // above, so the row cannot wrap and a sender cannot draw a second one.
        match budget {
            Some(budget) => println!("{fields}  {}", render_memo_within(row.memo, budget)),
            // Too narrow to hold the table and a usable memo column both.
            // Letting it wrap is what would open a line at column 1 drawn from
            // bytes the sender chose, so the memo takes a line of its own
            // deliberately, indented and budgeted the same way.
            None => {
                println!("{fields}");
                if !row.memo.is_empty() {
                    const INDENT: usize = 4;
                    println!(
                        "{:INDENT$}{}",
                        "",
                        render_memo_within(row.memo, terminal_columns().saturating_sub(INDENT))
                    );
                }
            }
        }
    }
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
        Command::MinerAddress => {
            let wallet = Wallet::open(&seed_path)?;
            // The key alone on stdout, so `QNERO_MINER_KEY=$(qnero-wallet
            // miner-address)` is the whole of the configuration. Everything
            // else goes to stderr.
            eprintln!("address     {}", wallet.address().encode());
            eprintln!(
                "miner key   secret: it is the coinbase view of this wallet, so keep it off \
                 command lines and out of shared logs"
            );
            eprintln!("node        --rewards-miner-key <below>, or QNERO_MINER_KEY");
            println!("{}", wallet.miner_key().encode());
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
                match wallet.store.genesis_hash.as_deref() {
                    Some(genesis) if genesis == hex::encode(chain.genesis_hash()?) => {
                        println!("store chain       bound to this chain")
                    }
                    Some(genesis) => println!(
                        "store chain       {genesis}, which is NOT this node's chain: sync \
                         and send will refuse"
                    ),
                    None => {
                        println!("store chain       not recorded yet; the next sync records it")
                    }
                }
                println!("last synced block {}", wallet.store.last_synced_block);
                println!("next leaf to scan {}", wallet.store.next_leaf);
            } else {
                println!("last synced block (no wallet at {})", seed_path.display());
            }
        }
        Command::Sync { rescan } => {
            let rpc = RpcClient::new(&cli.node);
            let chain = Chain::new(&rpc);
            let metadata = ChainMetadata::fetch(&rpc)?;
            let (mut wallet, binding) =
                Wallet::open_on_chain(&seed_path, &chain, cli.new_chain_store)?;
            report_binding(&binding);
            let report = wallet.sync_with(&chain, &metadata, SyncOptions { rescan })?;
            if let Some(refusal) = &report.bypassed_refusal {
                // Loud, and quoted in full. A gate that was checked and walked
                // past in silence is a gate the operator stops knowing about,
                // and this one is the reason the scan below gives up half of
                // what a sync normally guarantees.
                println!("warning     --rescan bypassed a node gate: {refusal}");
            }
            if let Some(notice) = report.rescan_notice() {
                println!("warning     {notice}");
            }
            if report.recorded_genesis {
                println!("chain       recorded this node's genesis in the store");
            }
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
            match (
                report.rewound_from,
                report.rewound_to,
                report.forked_at_block,
            ) {
                (Some(from), Some(to), Some(block)) => println!(
                    "the chain forked below block {}: rescanned leaves from {to} where this \
                     wallet had reached {from}",
                    block + 1
                ),
                (Some(from), Some(_), None) => println!(
                    "rescanned the whole tree from leaf 0, where this wallet had reached {from}. \
                     Every note already held is kept."
                ),
                _ => {}
            }
            if report.relocated > 0 {
                println!(
                    "moved {} note(s) to the leaf the chain now carries them at",
                    report.relocated
                );
            }
            if report.vanished > 0 {
                println!(
                    "{} note(s) this wallet holds are not on the current chain: their settlement \
                     was orphaned and has not been re-included. They are out of the unspent \
                     total and no spend selects them; `balance` lists them under their own \
                     heading. A sync that finds the commitment again puts them back.",
                    report.vanished
                );
            }
            if report.rejected_cleared > 0 {
                println!(
                    "{} refused output(s) are held now: the settlement that claimed their \
                     nullifier is no longer on the chain",
                    report.rejected_cleared
                );
            }
            println!("newly spent {}", report.newly_spent);
            if report.held_spent > 0 {
                let why = if report.add_only {
                    "this sync ran add only, so a nullifier absent from this node's settled set \
                     clears nothing"
                } else {
                    "this node has not reached the block their settlement was seen at, so their \
                     nullifier being absent says nothing yet"
                };
                println!("{} spent note(s) kept spent: {why}", report.held_spent);
            }
            if report.newly_unspent > 0 {
                println!(
                    "back in the balance {}: their settlement is no longer on the chain",
                    report.newly_unspent
                );
            }
            println!("unspent total {} quanta", wallet.store.unspent_total());
        }
        Command::Balance => {
            let wallet = Wallet::open(&seed_path)?;
            let store = &wallet.store;
            println!("address        {}", store.address);
            println!("unspent        {} quanta", store.unspent_total());
            println!("pending        {} quanta", store.pending_total());
            if store.off_chain().next().is_some() {
                println!("not on chain   {} quanta", store.off_chain_total());
            }
            let conflicted = store.conflicted();
            if !conflicted.is_empty() {
                println!(
                    "in conflict    {} note(s) share a nullifier with another note this wallet \
                     holds. At most one member of each set can ever settle, so the table lists \
                     each set once, at the value a spend would use.",
                    conflicted.len()
                );
            }
            println!("synced through block {}", store.last_synced_block);
            println!();
            if store.notes.is_empty() {
                println!("no notes");
            } else {
                print_notes(&store.rows());
            }
            if store.off_chain().next().is_some() {
                println!();
                println!(
                    "not on the current chain, {} quanta. The block that settled these was \
                     orphaned and the settlement has not been re-included, so the chain does not \
                     back their value and they are out of the unspent total. A sync that finds \
                     the commitment again puts them back.",
                    store.off_chain_total()
                );
                print_notes(&store.off_chain_rows());
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
            // Refused here as well as inside the encryption, so an oversized
            // memo costs no signature and no round trip.
            ensure_memo_fits(&memo)?;
            let (mut wallet, binding) =
                Wallet::open_on_chain(&seed_path, &chain, cli.new_chain_store)?;
            report_binding(&binding);
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
            // Refused before the sync and long before the prover is built.
            ensure_memo_fits(&memo)?;
            let (mut wallet, binding) =
                Wallet::open_on_chain(&seed_path, &chain, cli.new_chain_store)?;
            report_binding(&binding);
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
