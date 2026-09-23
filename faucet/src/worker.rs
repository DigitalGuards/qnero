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
//! `GET /drip/{token}`.

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
use qnero_wallet::units::qnr;
use qnero_wallet::wallet::{MerkleSource, Wallet, NUM_LEAF_PROOFS};

use crate::config::Config;
use crate::store::{now_secs, Store, INTERRUPTED};

/// How long the worker waits for a job before taking a tick of its own.
///
/// The tick is not a nicety. `last_seen_node` is written by `sync`, `/health`
/// reports the node stale after six minutes, and nothing but a claim used to
/// call `sync`: a faucet that served nobody overnight, which is the ordinary
/// state of a new testnet at four in the morning, answered 503 with
/// `nodeFresh:false` while the node was fine, and both monitoring layers paged
/// for it. The same tick is what retries a top-up that failed, because a
/// balance under the floor refuses every claim, and a claim was the only thing
/// that used to reach the funding path.
const TICK: std::time::Duration = std::time::Duration::from_secs(60);

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
    /// The spendable balance as of the last sync, as a count of pool steps.
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
        "no-spendable-funds"
    } else if text.contains("fee") {
        "fee-floor"
    } else if text.contains("timed out") || text.contains("timeout") {
        "not-included"
    } else {
        "send-failed"
    }
}

/// What a reader is told a failure was, as a sentence.
///
/// The codes above are for the operator's log and for the store, where a short
/// stable token is the right shape. The page used to interpolate one straight
/// into the sentence a requester reads after a two-minute wait: "The drip did
/// not settle (send-failed)." A hyphenated identifier in the one message a
/// reader ever sees is the thing the refusal path had already been cleaned of
/// in `limits.rs`, and this path was missed.
///
/// Every code `failure_code` can return has an arm here, plus `interrupted`,
/// which `store::INTERRUPTED` writes when the faucet restarts mid-drip. An
/// unknown code reads as the node refusing the payment, which is the truthful
/// general case and is what the reader does the same thing about.
pub fn failure_sentence(code: &str) -> &'static str {
    match code {
        "no-spendable-funds" => "The faucet could not fund the payment.",
        "fee-floor" => "The payment fee fell below the floor.",
        "not-included" => "No block took the payment in time.",
        crate::store::INTERRUPTED => "The faucet restarted during the payment.",
        _ => "The node did not take the payment.",
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
                "faucet      shielding {} QNR from the genesis account (note {} of {})",
                qnr(amount),
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
        let fee = self
            .wallet
            .preflight(&self.metadata, &job.address, job.quanta, None, DRIP_MEMO)?
            .fee;
        // The row is marked submitted BEFORE the send, because the window this
        // closes is between a drip landing in a block and `mark_sent` writing
        // that down. A process that dies in there leaves a row that is still
        // `queued` and a payment that may already have settled, and the old
        // startup path re-queued exactly that row: one crash, two payments to
        // one address, one claim in the ledger. Marking it here costs one
        // small write per drip and makes the interrupted case decidable at the
        // next start.
        if let Ok(store) = self.store.lock() {
            let _ = store.mark_submitted(job.claim_id, now_secs());
        }
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
            "faucet      drip {} QNR plus {} fee, proved in {:.2?}, block {}",
            qnr(report.amount),
            qnr(report.fee),
            report.proving,
            report.included_at
        );
        Ok(report.included_at)
    }

    /// One pass with no job to do: refresh what `/health` reports, and retry a
    /// top-up that is still needed.
    ///
    /// Both halves run after a drip as well, which is where the balance
    /// usually falls under the floor. What this adds is that neither depends
    /// on a drip: a faucet whose funding failed once is not wedged until a
    /// human restarts it, and an idle faucet does not decay into a 503.
    fn tick(&mut self) {
        if let Err(error) = self.sync() {
            eprintln!("faucet      sync failed: {error:#}");
            return;
        }
        if self.shared.spendable() < self.config.min_balance_quanta {
            if let Err(error) = self.ensure_funded() {
                eprintln!("faucet      top-up: {error:#}");
            }
        }
    }

    /// The loop. Runs until the channel closes.
    pub fn run(mut self, mut jobs: tokio::sync::mpsc::Receiver<Job>) {
        // A current-thread runtime, built here and used for one thing: waiting
        // with a deadline. This is a plain `std::thread` rather than a runtime
        // thread, `tokio::time::timeout` needs a timer driver, and putting the
        // wallet on a runtime thread is what the whole module exists to avoid.
        let waits = match tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("faucet      the worker could not build its timer: {error:#}");
                return;
            }
        };

        if let Err(error) = self.sync() {
            eprintln!("faucet      the first sync failed: {error:#}");
        }
        if let Err(error) = self.ensure_funded() {
            eprintln!("faucet      funding: {error:#}");
        }
        self.shared.ready.store(true, Ordering::Relaxed);
        println!(
            "faucet      ready, {} QNR spendable across {} note(s)",
            qnr(self.shared.spendable()),
            self.shared.notes.load(Ordering::Relaxed)
        );

        loop {
            // The `async` block is load-bearing. `timeout` builds its `Sleep`
            // at construction rather than at the first poll, so
            // `block_on(timeout(..))` builds it on this plain thread with
            // no runtime entered and panics with "there is no reactor
            // running". Constructing it inside the block puts it in the
            // runtime's context, where the timer it needs exists.
            let waited = waits.block_on(async { tokio::time::timeout(TICK, jobs.recv()).await });
            let job = match waited {
                // The deadline, which is the whole point of waiting with one.
                Err(_elapsed) => {
                    self.tick();
                    continue;
                }
                // Every sender is gone, so the server is stopping.
                Ok(None) => break,
                Ok(Some(job)) => job,
            };
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
            self.tick();
        }
        println!("faucet      the worker's queue closed, stopping");
    }
}

/// Re-queue the claims that were accepted before the last stop.
///
/// With one exception, and it is the important half: a claim the worker had
/// already started submitting is **never** re-queued. Its row was marked
/// before `Wallet::send`, so a row that still says `queued` and carries a
/// `submitted_at` is a drip that may already be in a block with nothing having
/// written that down. Proving a second one would pay that address twice for
/// one crash and record a single claim, so it is failed as `interrupted`
/// instead. That reason code still counts against the address cooldown and the
/// client's window, because the faucet cannot tell a payment that landed from
/// one that did not, and paying twice is the worse of the two mistakes.
pub fn recover_queued_claims(
    store: &Arc<Mutex<Store>>,
    jobs: &tokio::sync::mpsc::Sender<Job>,
) -> Result<()> {
    let poisoned = || anyhow::anyhow!("the claims ledger mutex is poisoned");
    let queued = store.lock().map_err(|_| poisoned())?.queued_claims()?;
    for claim in queued {
        let outcome = match Address::decode(&claim.address) {
            Err(_) => Err("bad-address"),
            Ok(_) if claim.submitted_at.is_some() => Err(INTERRUPTED),
            Ok(address) => jobs
                .try_send(Job {
                    claim_id: claim.id,
                    address,
                    quanta: claim.amount_quanta,
                })
                // More rows than the queue holds. The rest are failed rather
                // than left pending for ever, so their requesters can ask
                // again instead of watching a claim that nothing will pick up.
                .map_err(|_| "queue-full"),
        };
        match outcome {
            Ok(()) => println!("faucet      recovered queued claim {}", claim.id),
            Err(INTERRUPTED) => {
                store.lock().map_err(|_| poisoned())?.mark_failed(
                    claim.id,
                    INTERRUPTED,
                    now_secs(),
                )?;
                println!(
                    "faucet      claim {} was interrupted mid-drip and is NOT being paid again. \
                     Its payment may have settled; check {} before refunding it by hand.",
                    claim.id, claim.address
                );
            }
            Err(reason) => {
                store
                    .lock()
                    .map_err(|_| poisoned())?
                    .mark_failed(claim.id, reason, now_secs())?;
                println!("faucet      queued claim {} released as {reason}", claim.id);
            }
        }
    }
    Ok(())
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

    /// The worker waits with a deadline from a plain `std::thread`, and that
    /// is the whole subtlety: `tokio::time::timeout` builds its `Sleep` when
    /// the future is constructed rather than when it is polled, so
    /// `block_on(timeout(..))` constructs it outside the runtime and panics
    /// with "there is no reactor running". A rehearsal found that; this keeps
    /// it found. The shape asserted here is the shape `run` uses.
    #[test]
    fn a_deadline_can_be_waited_on_from_a_plain_thread() {
        let (jobs_tx, mut jobs) = tokio::sync::mpsc::channel::<Job>(1);
        let waits = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a current-thread runtime with a timer");
        let waited = waits.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), jobs.recv()).await
        });
        assert!(
            waited.is_err(),
            "nothing was sent, so the deadline is what returns"
        );
        drop(jobs_tx);
        let closed = waits.block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(50), jobs.recv()).await
        });
        assert!(
            closed
                .expect("the queue closed rather than timing out")
                .is_none(),
            "a closed queue is what ends the loop"
        );
    }

    /// Every failure a drip can report has to be a code, because the ledger
    /// row is shown to the requester and the error it came from names the
    /// node URL and the wallet store.
    #[test]
    fn a_failure_is_a_code_and_never_the_error() {
        let cases = [
            anyhow!("select_notes: no combination of two notes covers 10.00 QNR"),
            anyhow!("a fee of 0.03 QNR is below this submission's floor of 0.07"),
            anyhow!("the submission timed out waiting for inclusion"),
            anyhow!("http://127.0.0.1:9944 answered 500"),
        ];
        let codes: Vec<&str> = cases.iter().map(failure_code).collect();
        assert_eq!(
            codes,
            [
                "no-spendable-funds",
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

    /// And every code a claim can carry has a sentence, because the code is
    /// what the page used to print: "The drip did not settle (send-failed)."
    /// A reader waits two minutes for that line and it is the only account of
    /// the failure they get.
    #[test]
    fn every_failure_code_has_a_sentence_a_reader_can_read() {
        let codes = [
            "no-spendable-funds",
            "fee-floor",
            "not-included",
            "send-failed",
            crate::store::INTERRUPTED,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            let sentence = failure_sentence(code);
            assert!(
                !sentence.contains(code),
                "{code}: the sentence still carries the code"
            );
            assert!(
                !sentence.contains('-') || sentence.contains("Try again"),
                "{code}: {sentence} reads like an identifier"
            );
            let first = sentence.chars().next().expect("a sentence");
            assert!(
                first.is_ascii_uppercase(),
                "{code}: {sentence} is not sentence case"
            );
            assert!(
                sentence.ends_with('.'),
                "{code}: {sentence} does not end a sentence"
            );
            seen.insert(sentence);
        }
        // Five codes, five sentences: a reader who reports one is reporting
        // something the operator can tell apart from the other four.
        assert_eq!(seen.len(), codes.len(), "two codes read the same: {seen:?}");
        // A code this build has never emitted reads as the general case
        // rather than as an empty line or as the code itself.
        assert_eq!(
            failure_sentence("send-failed"),
            failure_sentence("something this build has never emitted")
        );
    }
}
