//! The one thread that holds the spend key.
//!
//! Everything about this module follows from four properties of
//! `qnero_wallet`, none of which is negotiable from here:
//!
//! - **It is synchronous.** The RPC client is `ureq`. Nothing in the crate is async, so
//!   none of it can run on a tokio worker thread without blocking it.
//! - **`sync` and `send` take `&mut self`.** One wallet, one caller.
//! - **The note store is one JSON file with no lock** (`qnero_wallet::store`). Two writers
//!   corrupt it and lose the `rho` and `r` that open the notes it holds. Ownership is the
//!   lock here: exactly one thread ever touches the wallet, and the HTTP side reaches it
//!   only through a channel.
//! - **`WalletProver::new` is the circuit build**, 4.26 s and a few hundred megabytes held
//!   for the life of the process (`docs/BENCH.md`). It is built once, at startup, before
//!   the listener opens. Building it per request is the regression Qloak shipped.
//!
//! The consequence for the server is that a drip is a job rather than a
//! request: a private batch proves in about 9.8 s and then waits up to one
//! 120 s block to settle (`docs/BENCH.md`). So `POST /drip` records the claim,
//! hands it to this thread and answers `queued`; the page polls
//! `GET /drip/{id}`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use qnero_notes::Address;
use qnero_prover::WalletProver;
use qnero_wallet::chain::Chain;
use qnero_wallet::dev_account::TransparentKey;
use qnero_wallet::metadata::ChainMetadata;
use qnero_wallet::rpc::RpcClient;
use qnero_wallet::wallet::{MerkleSource, Wallet, NUM_LEAF_PROOFS};

use crate::config::Config;
use crate::store::{now_secs, Store};

/// The memo every drip carries. Every memo is padded to one size, so this
/// costs nothing over an empty one and tells a recipient scanning a fresh
/// wallet where the note came from.
const DRIP_MEMO: &str = "qnero testnet faucet";

/// What the HTTP side may read about the wallet without touching it.
///
/// Every field is written by the worker thread and read by request handlers.
/// None of them is authoritative for a decision the worker makes: the balance
/// here is a snapshot used to refuse a claim early, and the worker checks the
/// real one again before it proves.
#[derive(Debug, Default)]
pub struct Shared {
    /// The prover is built, the wallet is open and the node answered.
    pub ready: AtomicBool,
    /// Spendable pool quanta as of the last sync.
    pub spendable_quanta: AtomicU64,
    /// Spendable notes as of the last sync.
    pub notes: AtomicU64,
    /// The chain head at the last sync.
    pub chain_head: AtomicU32,
    /// Unix seconds of the last successful node round trip.
    pub last_seen_node: AtomicU64,
    /// The faucet's own `qn1` address, for `/status`.
    pub address: OnceLock<String>,
    /// The genesis hash the wallet is bound to, hex, no `0x`.
    pub genesis: OnceLock<String>,
}

impl Shared {
    pub fn spendable(&self) -> u64 {
        self.spendable_quanta.load(Ordering::Relaxed)
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Has the node answered inside `window` seconds.
    pub fn node_fresh(&self, window: u64, now: u64) -> bool {
        let seen = self.last_seen_node.load(Ordering::Relaxed);
        seen != 0 && now.saturating_sub(seen) <= window
    }
}

/// One drip for the worker to prove.
#[derive(Debug)]
pub struct Job {
    pub claim_id: i64,
    pub address: Address,
    pub quanta: u64,
}

/// Why a drip did not settle. Stored in the ledger and shown to the requester,
/// so every arm is a code and never the error text, which carries the node URL
/// and the store path.
fn failure_code(error: &anyhow::Error) -> &'static str {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("select") || text.contains("insufficient") || text.contains("fund") {
        "no-spendable-note"
    } else if text.contains("fee") {
        "fee-floor"
    } else if text.contains("timed out") || text.contains("timeout") {
        "not-included"
    } else {
        "send-failed"
    }
}

/// The wallet thread. Owns the wallet, the prover and the transparent key for
/// the life of the process.
pub struct Worker {
    config: Config,
    wallet: Wallet,
    transparent: TransparentKey,
    prover: WalletProver,
    rpc: RpcClient,
    metadata: ChainMetadata,
    /// The runtime version the metadata above was fetched at. A runtime
    /// upgrade moves the storage layout, and a stale layout reads as an empty
    /// map rather than as an error (`qnero_wallet::metadata`).
    metadata_version: (u32, u32),
    store: Arc<Mutex<Store>>,
    shared: Arc<Shared>,
}

impl Worker {
    /// Open everything, in the order that makes a misconfiguration cheap to
    /// diagnose: keys first, then the node, then the seconds of circuit build.
    pub fn start(config: Config, store: Arc<Mutex<Store>>, shared: Arc<Shared>) -> Result<Self> {
        let transparent = crate::keys::load_seed(&config.transparent_seed_path)?;
        let transparent_address = crate::keys::address_of(&transparent);
        if let Some(expected) = &config.expect_address {
            // Both `DilithiumSignatureScheme` variants hash to the same 32
            // bytes, so an address carries no trace of its scheme and nothing
            // here can assert one. What it can assert is that the seed on disk
            // is the seed behind the address the chain spec endowed. Without
            // this, a wrong seed file is a faucet that starts, serves, accepts
            // claims and fails every shield at the transparent entry.
            crate::ss58::decode(expected).context("QNERO_FAUCET_EXPECT_ADDRESS")?;
            if &transparent_address != expected {
                bail!(
                    "the transparent seed derives {transparent_address} and the chain spec \
                     endows {expected}. The faucet would sign for an account with no balance"
                );
            }
        }
        println!("faucet      transparent account {transparent_address}");

        let rpc = RpcClient::new(&config.node_url);
        let metadata = {
            let chain = Chain::new(&rpc);
            let _ = chain.head().context("the node did not answer")?;
            ChainMetadata::fetch(&rpc).context("the node's runtime metadata")?
        };
        let metadata_version = {
            let chain = Chain::new(&rpc);
            chain.runtime_version()?
        };

        let (wallet, binding) = {
            let chain = Chain::new(&rpc);
            Wallet::open_on_chain(&config.seed_path, &chain, false)?
        };
        println!("faucet      shielded address {}", wallet.address().encode());
        println!("faucet      store {}", wallet.store_path.display());
        let _ = shared.address.set(wallet.address().encode());
        {
            let chain = Chain::new(&rpc);
            let _ = shared.genesis.set(hex::encode(chain.genesis_hash()?));
        }
        if !matches!(binding, qnero_wallet::wallet::ChainBinding::Bound) {
            println!(
                "faucet      this store has not been bound to a chain yet; the first sync \
                 records the genesis it is pointed at"
            );
        }

        let built = std::time::Instant::now();
        let prover = WalletProver::new(NUM_LEAF_PROOFS)
            .map_err(|error| anyhow!("failed to build the wallet's circuits: {error}"))?;
        println!(
            "faucet      circuits built in {:.2?} ({NUM_LEAF_PROOFS} leaf slots per batch)",
            built.elapsed()
        );

        Ok(Self {
            config,
            wallet,
            transparent,
            prover,
            rpc,
            metadata,
            metadata_version,
            store,
            shared,
        })
    }

    /// Refresh the metadata when the runtime moved underneath it.
    fn refresh_metadata(&mut self) -> Result<()> {
        let chain = Chain::new(&self.rpc);
        let version = chain.runtime_version()?;
        if version != self.metadata_version {
            println!(
                "faucet      runtime moved from {:?} to {version:?}, re-reading the metadata",
                self.metadata_version
            );
            self.metadata = ChainMetadata::fetch(&self.rpc)?;
            self.metadata_version = version;
        }
        Ok(())
    }

    /// Scan for new notes, settle spent flags and publish the balance.
    fn sync(&mut self) -> Result<()> {
        let chain = Chain::new(&self.rpc);
        self.wallet.sync(&chain, &self.metadata)?;
        let head = chain.head()?;
        self.shared
            .spendable_quanta
            .store(self.wallet.store.unspent_total(), Ordering::Relaxed);
        self.shared.notes.store(
            self.wallet.store.spendable().len() as u64,
            Ordering::Relaxed,
        );
        self.shared.chain_head.store(head.number, Ordering::Relaxed);
        self.shared
            .last_seen_node
            .store(now_secs(), Ordering::Relaxed);
        Ok(())
    }

    /// Move transparent value from the genesis account into the faucet's own
    /// notes, until there is enough to drip from.
    ///
    /// This is the whole of "funding a faucet" under v1. There is no
    /// transparent transfer between chosen accounts, so the endowment cannot
    /// be paid to anybody directly; and `Wallet::shield` always builds the
    /// note for `self.key.pk()`, so shielding cannot pay a recipient either.
    /// Shielding moves the faucet's own balance into the faucet's own notes,
    /// and `send` is what pays. Several notes rather than one, so a drip never
    /// has to wait on the change of the one before it.
    fn ensure_funded(&mut self) -> Result<()> {
        let mut shielded = 0u32;
        while self.shared.spendable() < self.config.min_balance_quanta
            && shielded < self.config.fund_notes
        {
            let amount = self.config.fund_chunk_quanta;
            println!(
                "faucet      shielding {amount} quanta from the genesis account (note {} of {})",
                shielded + 1,
                self.config.fund_notes
            );
            let report = {
                let chain = Chain::new(&self.rpc);
                self.wallet.shield(
                    &chain,
                    &self.metadata,
                    &self.transparent,
                    amount,
                    "faucet funding",
                )
            };
            match report {
                Ok(report) => println!(
                    "faucet      funded: leaf {} in block {}",
                    report.leaf_index, report.included_at
                ),
                Err(error) => {
                    // A faucet that cannot fund itself still serves `/status`
                    // and refuses claims with `drained`, which is a far more
                    // useful state than a process that exits at boot.
                    eprintln!("faucet      funding failed: {error:#}");
                    break;
                }
            }
            shielded += 1;
            self.sync()?;
        }
        Ok(())
    }

    /// Prove and submit one drip.
    fn drip(&mut self, job: &Job) -> Result<u32> {
        self.refresh_metadata()?;
        self.sync()?;
        let fee =
            self.wallet
                .preflight(&self.metadata, &job.address, job.quanta, None, DRIP_MEMO)?;
        let chain = Chain::new(&self.rpc);
        let report = self.wallet.send(
            &chain,
            &self.metadata,
            &self.prover,
            &job.address,
            job.quanta,
            Some(fee),
            DRIP_MEMO,
            MerkleSource::Local,
        )?;
        println!(
            "faucet      drip {} quanta plus {} fee, proved in {:.2?}, block {}",
            report.amount, report.fee, report.proving, report.included_at
        );
        Ok(report.included_at)
    }

    /// The loop. Runs until the channel closes.
    pub fn run(mut self, mut jobs: tokio::sync::mpsc::Receiver<Job>) {
        if let Err(error) = self.sync() {
            eprintln!("faucet      the first sync failed: {error:#}");
        }
        if let Err(error) = self.ensure_funded() {
            eprintln!("faucet      funding: {error:#}");
        }
        self.shared.ready.store(true, Ordering::Relaxed);
        println!(
            "faucet      ready, {} quanta spendable across {} note(s)",
            self.shared.spendable(),
            self.shared.notes.load(Ordering::Relaxed)
        );

        while let Some(job) = jobs.blocking_recv() {
            let started = std::time::Instant::now();
            match self.drip(&job) {
                Ok(included_at) => {
                    if let Ok(store) = self.store.lock() {
                        let _ = store.mark_sent(job.claim_id, included_at, now_secs());
                    }
                    println!(
                        "faucet      claim {} settled in block {included_at} after {:.2?}",
                        job.claim_id,
                        started.elapsed()
                    );
                }
                Err(error) => {
                    let code = failure_code(&error);
                    // The requester is told the code. The operator is told
                    // everything, here, where the node URL and the store path
                    // are not a response body.
                    eprintln!(
                        "faucet      claim {} failed ({code}): {error:#}",
                        job.claim_id
                    );
                    if let Ok(store) = self.store.lock() {
                        let _ = store.mark_failed(job.claim_id, code, now_secs());
                    }
                }
            }
            // Publish the balance after every drip, and top up when the change
            // has taken the faucet below its floor.
            if let Err(error) = self.sync() {
                eprintln!("faucet      sync after a drip failed: {error:#}");
            }
            if self.shared.spendable() < self.config.min_balance_quanta {
                if let Err(error) = self.ensure_funded() {
                    eprintln!("faucet      top-up: {error:#}");
                }
            }
        }
        println!("faucet      the worker's queue closed, stopping");
    }
}

/// Open the wallet's seed if it exists, or create one.
///
/// A faucet with no shielded key on first start is the ordinary case, and
/// `qnero_wallet::keys::create_seed` writes it at mode 0600 beside the store.
pub fn ensure_spend_seed(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let key = qnero_wallet::keys::create_seed(path)?;
    println!(
        "faucet      created a shielded spending key at {} ({})",
        path.display(),
        key.address().encode()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every failure a drip can report has to be a code, because the ledger
    /// row is shown to the requester and the error it came from names the
    /// node URL and the wallet store.
    #[test]
    fn a_failure_is_a_code_and_never_the_error() {
        let cases = [
            anyhow!("select_notes: no combination of two notes covers 1000 quanta"),
            anyhow!("a fee of 3 quanta is below this submission's floor of 7"),
            anyhow!("the submission timed out waiting for inclusion"),
            anyhow!("http://127.0.0.1:9944 answered 500"),
        ];
        let codes: Vec<&str> = cases.iter().map(failure_code).collect();
        assert_eq!(
            codes,
            [
                "no-spendable-note",
                "fee-floor",
                "not-included",
                "send-failed"
            ]
        );
        for code in codes {
            assert!(!code.contains("127.0.0.1"), "{code} leaks the node URL");
            assert!(code.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
        }
    }
}
