//! `qnero-wallet`: the Qnero v0 command line wallet.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qnero_notes::Address;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::keys::{create_seed, default_seed_path, import_seed, store_path_for};
use qnero_wallet::memo::{memo_budget_within, render_memo_within, terminal_columns, MEMO_BYTES};
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::{RpcClient, DEFAULT_NODE_URL};
use qnero_wallet::store;
use qnero_wallet::store::{NoteRow, PendingKind, StoredNote};
use qnero_wallet::units::{qnr, steps_from_qnr};
use qnero_wallet::wallet::{
    full_scan_estimate, ChainBinding, EntryRhoCheck, MerkleSource, SyncOptions, Wallet,
    ENTRY_WALK_LIMIT, NUM_LEAF_PROOFS,
};
use zeroize::Zeroize;

/// Amounts are in QNR, and value in the pool moves in steps of 0.01 QNR.
#[derive(Debug, Parser)]
#[command(
    name = "qnero-wallet",
    version,
    about = "Qnero v0 shielded wallet",
    long_about = "Qnero v0 shielded wallet.

AMOUNTS ARE IN QNR. --amount and --fee take a figure such as 12.34, and every
figure this wallet prints is QNR as well. Value inside the pool moves in steps
of 0.01 QNR, so an amount has at most two decimals and a third is refused.

KEY HANDLING IS DEV GRADE. The seed is 32 bytes of hex in a file with mode
0600, with no passphrase, no key derivation and no encryption at rest, and the
note store beside it holds every note's rho and r in the clear. Anyone who can
read those two files can spend every note this wallet holds and can link every
spend it has made. Use it on a dev chain and nowhere else.

WHERE A WALLET STARTS READING. keygen and restore record a birthday: the block
this wallet was created at, rounded DOWN to a multiple of 1024 blocks, with the
leaf count the chain held there. A wallet cannot have been paid into a leaf
that existed before it did, so the first sync starts there rather than at block
zero. It is recorded as the store's first checkpoint, which makes it this
node's claim like every checkpoint: an honest node that disagrees at that
height rewinds it and the scan starts lower. restore --restore-height is the
same number for a wallet that already exists, and a height ABOVE the block a
note arrived in is a note this wallet never reads, with no warning anywhere and
sync --rescan the only recovery. With no height at all the first sync reads the
whole chain, which is always correct, and restore prints what it will cost.

WHAT THE NODE LEARNS. A scan reads the whole leaf range and the whole settled
nullifier set, and a spend rebuilds the commitment tree locally, so no request
this wallet makes names a note as its own. The header walk reads block hashes
as a list and fetches headers in JSON-RPC batches, which asks for the same
public range in fewer requests and names nothing new; a recorded birthday is
the one thing a node learns that it did not before, which is why it is a coarse
epoch. Passing --merkle-rpc gives the second rule up: it asks the node for a
proof of each leaf being spent, seconds before the settlement that publishes
the matching nullifiers.

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
    /// Restore a wallet from a spend key read on stdin.
    ///
    /// The key is read from standard input rather than taken as an argument,
    /// because every process listing on the machine can read a command line.
    /// 64 hex characters, with spaces and line breaks ignored, so the grouped
    /// form the browser wallet shows goes straight back in:
    ///
    ///     qnero-wallet restore --restore-height 197000 < key.txt
    ///
    /// --restore-height is the chain height this wallet was created at. With
    /// it, the first sync starts there instead of at block zero. Without it,
    /// the first sync reads the whole chain, which is always correct and on a
    /// long chain is slow; the command prints what that will cost.
    Restore {
        /// The chain height this wallet was created at.
        ///
        /// Rounded DOWN to a multiple of 1024 blocks before it is recorded, so
        /// what every node this wallet syncs against is told is a coarse epoch
        /// rather than the moment the wallet was made. Down, so a height a
        /// little too high still starts below the first note.
        ///
        /// A height ABOVE the block a note arrived in is a note this wallet
        /// never reads and a balance quietly short. If you are not sure, leave
        /// it out or give a height you are sure is early.
        #[arg(long)]
        restore_height: Option<u32>,
    },
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
        /// QNR to move into the pool, such as 12.34.
        #[arg(long, value_parser = steps_from_qnr)]
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
        /// QNR to pay, such as 12.34.
        #[arg(long, value_parser = steps_from_qnr)]
        amount: u64,
        /// Fee in QNR. Defaults to this submission's floor. Below the floor
        /// is refused, because the fee is a public input of the proof and
        /// cannot be raised afterwards; well above it is refused too, because
        /// every settlement carries the same pool priority, so a fee over the
        /// floor buys nothing and half of it burns.
        #[arg(long, value_parser = steps_from_qnr)]
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
            value: qnr(row.note.value),
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
        "leaf", "QNR", "block", "state"
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

/// Record where a wallet starts, and say what was recorded.
///
/// `height` says which of the two paths this is: `None` for a wallet created
/// now, which starts at the node's own head, and `Some(height)` for a restore,
/// where `Some(None)` is a restore that gave no height at all.
///
/// A node that cannot be reached is reported and not an error. The seed is
/// already on disk by the time this runs, and a wallet with no birthday reads
/// the chain from block zero, which is correct and slow. Failing the command
/// here would leave a seed written and a person believing it was not.
fn report_birthday(node: &str, seed_path: &std::path::Path, height: Option<Option<u32>>) {
    let asked = height.flatten();
    if height == Some(None) {
        // A restore with no height, which is a deliberate full scan. There is
        // nothing to record and the estimate is the whole point.
        match head_of(node) {
            Ok(head) => println!("scan    {}", full_scan_estimate(head)),
            Err(_) => println!(
                "scan    this wallet records no birthday, so the first sync reads the chain \
                 from block zero"
            ),
        }
        return;
    }
    let recorded = (|| -> Result<store::SyncCheckpoint> {
        let rpc = RpcClient::new(node);
        let chain = Chain::new(&rpc);
        let mut wallet = Wallet::open(seed_path)?;
        wallet.record_birthday(&chain, asked)
    })();
    match recorded {
        Ok(checkpoint) => {
            println!(
                "birthday block {} ({} leaves), rounded down from {}",
                checkpoint.block_number,
                checkpoint.next_leaf,
                asked
                    .map(|height| height.to_string())
                    .unwrap_or_else(|| "this node's head".to_string())
            );
            println!(
                "        the first sync starts there. It is this node's claim, like every \
                 checkpoint: an honest node that disagrees at that height rewinds it."
            );
        }
        Err(error) => {
            println!("birthday not recorded: {error:#}");
            println!(
                "        the first sync reads the chain from block zero, which is correct and \
                 slow."
            );
        }
    }
}

/// The node's head height, for an estimate and nothing else.
fn head_of(node: &str) -> Result<u32> {
    let rpc = RpcClient::new(node);
    Ok(Chain::new(&rpc).head()?.number)
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
            // A wallet created now cannot have been paid before now, so the
            // store starts at the head this node is at rather than at block
            // zero. A node that cannot be reached is not an error here: the
            // seed is already written, and a wallet with no birthday reads the
            // whole chain, which is correct and slow.
            report_birthday(&cli.node, &seed_path, None);
            println!();
            println!(
                "The seed is unencrypted hex at mode 0600. Anyone who can read it can spend \
                 every note this wallet holds."
            );
        }
        Command::Restore { restore_height } => {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                .context("failed to read the spend key from stdin")?;
            let key = import_seed(&seed_path, &text)?;
            text.zeroize();
            println!("seed    {}", seed_path.display());
            println!("store   {}", store_path_for(&seed_path).display());
            println!("address {}", key.address().encode());
            report_birthday(&cli.node, &seed_path, Some(restore_height));
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
                match wallet.store.birthday.as_ref() {
                    Some(birthday) => println!(
                        "wallet birthday   block {} ({} leaves), this node's claim like every \
                         checkpoint",
                        birthday.block_number, birthday.next_leaf
                    ),
                    None => println!(
                        "wallet birthday   none: {}",
                        full_scan_estimate(head.number)
                    ),
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
            for warning in &report.warnings {
                // What the pass gave up, could not verify, or recovered from
                // an answer the chain does not back. Each one is rare, which
                // is what keeps the line worth reading: today they are the two
                // halves of the moved-leaf detector, a ciphertext of this
                // wallet's found beside a commitment it does not open.
                println!("warning     {warning}");
            }
            if report.coinbase_label_disagreed > 0 {
                // Never on a block a Qnero node built: the author label and
                // the note's own randomness come out of one coinbase viewing
                // key. The reward is taken, because only that key derives the
                // commitment the tree holds, and the disagreement is printed
                // because a header carrying this wallet's note under another
                // author's label is a header it is being handed for a block it
                // did not come from.
                println!(
                    "warning     {} mining {} this wallet rebuilt as its own sit in blocks \
                     whose author label is not this wallet's. The reward is taken, because only \
                     this wallet's coinbase viewing key derives the entry the tree holds. Sync \
                     against a second node: a branch built for this wallet alone is what the \
                     checkpoint walk finds there.",
                    report.coinbase_label_disagreed,
                    if report.coinbase_label_disagreed == 1 {
                        "reward"
                    } else {
                        "rewards"
                    }
                );
            }
            if let Some(hint) = report.ciphertext_hint() {
                // A hint rather than a warning: on most passes it is the
                // ordinary case, and every leaf on the chain that is not this
                // wallet's reads exactly like a leaf whose ciphertext was
                // swapped. Printed anyway, because the one operator who needed
                // it is the one waiting for a payment that never arrives, and
                // the recovery is a command they cannot guess.
                println!("hint        {hint}");
            }
            if let Some(entries) = report.entry_walk_truncated {
                // Beside the rescan notice, and for the same reason: a pass
                // that gave up part of what a sync normally decides says so
                // where the operator is already reading. `origin` is written
                // once at receipt, so a shield labelled `spend` here keeps
                // that label until a rescan.
                println!(
                    "warning     this chain has settled {entries} shield entries and the origin \
                     walk stops at {ENTRY_WALK_LIMIT}, so a shield received in this pass may be \
                     listed as a transfer. Origin is a label and no rule selects on it."
                );
            }
            if report.recorded_genesis {
                println!("chain       recorded this node's genesis in the store");
            }
            println!(
                "scanned leaves {}..{} at block {}",
                report.scanned_from, report.scanned_to, report.head_block
            );
            println!(
                "received {} note(s) worth {} QNR",
                report.received,
                qnr(report.received_value)
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
            println!("unspent total {} QNR", qnr(wallet.store.unspent_total()));
        }
        Command::Balance => {
            let wallet = Wallet::open(&seed_path)?;
            let store = &wallet.store;
            println!("address        {}", store.address);
            println!("unspent        {} QNR", qnr(store.unspent_total()));
            println!("pending        {} QNR", qnr(store.pending_total()));
            if store.off_chain().next().is_some() {
                println!("not on chain   {} QNR", qnr(store.off_chain_total()));
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
                    "not on the current chain, {} QNR. The block that settled these was \
                     orphaned and the settlement has not been re-included, so the chain does not \
                     back their value and they are out of the unspent total. A sync that finds \
                     the commitment again puts them back.",
                    qnr(store.off_chain_total())
                );
                print_notes(&store.off_chain_rows());
            }
            for pending in &store.pending {
                println!(
                    "pending {:?} of {} QNR submitted at block {}",
                    pending.kind,
                    qnr(pending.value),
                    pending.submitted_at_block
                );
                if pending.kind == PendingKind::Shield {
                    println!("        commitment {}", pending.commitment);
                }
            }
            for rejected in &store.rejected {
                println!(
                    "refused leaf {} worth {} QNR: {}",
                    rejected.leaf_index,
                    qnr(rejected.value),
                    rejected.reason
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
            println!("shielding {} QNR from {from_dev_account}", qnr(amount));
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
                "synced      {} new note(s), unspent total {} QNR",
                sync.received,
                qnr(wallet.store.unspent_total())
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
            let plan = wallet.preflight(&metadata, &recipient, amount, fee, &memo)?;
            let resolved_fee = plan.fee;
            // The floor is printed only when the caller asked for more than
            // it, because that is the only time the two are worth comparing
            // and a fee on its own has nothing on screen to be read against.
            if resolved_fee == plan.floor {
                println!("fee         {} QNR", qnr(resolved_fee));
            } else {
                println!(
                    "fee         {} QNR, above this submission's floor of {} QNR",
                    qnr(resolved_fee),
                    qnr(plan.floor)
                );
            }

            // What the wait is made of, said before it starts, and the same
            // composition the browser wallet quotes. The block half is read
            // from the chain: the interval is chain state, so a 120 s public
            // chain and a 12 s dev chain give different answers here and
            // neither number belongs in this binary.
            let target_block_time_ms = chain.target_block_time_ms()?;
            println!(
                "expect      tens of seconds of proving, then up to one block interval of {:.0} s",
                target_block_time_ms as f64 / 1_000.0
            );

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
                "inputs      leaves {:?} for {} QNR plus {} fee",
                report.inputs,
                qnr(report.amount),
                qnr(report.fee)
            );
            println!("change      {} QNR", qnr(report.change));
            println!("proof       {} bytes", report.proof_bytes);
            println!("proving     {:.2?}", report.proving);
            println!(
                "inclusion   block {} after {:.2?} (one block interval is {:.0} s)",
                report.included_at,
                report.inclusion,
                target_block_time_ms as f64 / 1_000.0
            );
            let sync = wallet.sync(&chain, &metadata)?;
            println!(
                "synced      {} new note(s), unspent total {} QNR",
                sync.received,
                qnr(wallet.store.unspent_total())
            );
        }
    }
    Ok(())
}
