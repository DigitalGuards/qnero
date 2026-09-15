//! `qnero-faucet`: serve the testnet faucet, or mint the key it pays from.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qnero_faucet::config::Config;
use qnero_faucet::http::{router, AppState};
use qnero_faucet::store::{now_secs, Store};
use qnero_faucet::worker::{ensure_spend_seed, Job, Shared, Worker};
use qnero_faucet::{keys, ss58};
use qnero_notes::Address;

#[derive(Debug, Parser)]
#[command(
    name = "qnero-faucet",
    version,
    about = "Qnero testnet faucet",
    long_about = "Qnero testnet faucet.

Pays a fixed amount of pool quanta to one qn1 address as a shielded note,
rate limited per address and per client, with an optional Cloudflare Turnstile
challenge. Configuration is entirely environment variables, because two of the
values name files that spend and argv is world-readable; the deployed shape is
a systemd EnvironmentFile at mode 0600.

A drip is a zero-knowledge proof. It takes about ten seconds to prove and then
up to one block to settle, and this server proves one at a time, so POST /drip
answers `queued` and GET /drip/{id} is how a caller learns what became of it."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the faucet. Reads every `QNERO_FAUCET_*` variable.
    Serve,
    /// Mint the transparent ML-DSA-87 seed the chain spec endows.
    ///
    /// Run this once, before the genesis is cut. The address it prints goes
    /// into the `qnero-testnet` preset; the seed file it writes is the whole
    /// of the faucet's endowment and belongs nowhere but the operator's own
    /// secret store. There is no recovery: the address is in a chain spec's
    /// genesis and cannot be changed without a new chain.
    Keygen {
        /// Where to write the 32-byte seed, as 64 hex characters, mode 0600.
        #[arg(long)]
        seed_file: PathBuf,
    },
    /// Print the addresses this faucet answers to, transparent and shielded.
    Address,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { seed_file } => {
            let key = keys::create_seed(&seed_file)?;
            let address = keys::address_of(&key);
            println!("seed        {}", seed_file.display());
            println!("address     {address}");
            println!("account     0x{}", hex::encode(key.account_id()));
            println!();
            println!(
                "Put {address} in the qnero-testnet preset as the endowed faucet account, and \
                 keep {} where nothing else can read it. The chain spec carries the address and \
                 nothing else; this file is the only copy of the key behind it.",
                seed_file.display()
            );
            Ok(())
        }
        Command::Address => {
            let config = Config::from_env()?;
            let transparent = keys::load_seed(&config.transparent_seed_path)?;
            println!("transparent {}", keys::address_of(&transparent));
            if config.seed_path.exists() {
                let wallet = qnero_wallet::wallet::Wallet::open(&config.seed_path)?;
                println!("shielded    {}", wallet.address().encode());
            } else {
                println!("shielded    (no spending key yet; `serve` creates one)");
            }
            Ok(())
        }
        Command::Serve => serve(),
    }
}

fn serve() -> Result<()> {
    let config = Config::from_env()?;
    if let Some(expected) = &config.expect_address {
        ss58::decode(expected).context("QNERO_FAUCET_EXPECT_ADDRESS is not a Qnero address")?;
    }
    ensure_spend_seed(&config.seed_path)?;

    let store = Arc::new(Mutex::new(Store::open(
        &config.db_path,
        &config.ip_hash_key_path,
    )?));
    let shared = Arc::new(Shared::default());

    // The worker is built before the listener opens, so a faucet that cannot
    // reach its node or cannot open its wallet fails at startup rather than
    // answering `/health` with 200 and refusing every claim.
    let worker = Worker::start(config.clone(), Arc::clone(&store), Arc::clone(&shared))?;

    let (jobs_tx, jobs_rx) = tokio::sync::mpsc::channel(config.queue_depth);

    // Claims that were queued when the process last stopped. The row is
    // written before the proof, so a restart in between would otherwise leave
    // a claim queued for ever: visible to its requester, holding its cooldown,
    // and paid to nobody.
    recover_queued_claims(&store, &jobs_tx)?;

    let worker_thread = std::thread::Builder::new()
        .name("qnero-faucet-wallet".into())
        .spawn(move || worker.run(jobs_rx))?;

    // Two worker threads: the proof runs on a thread of its own and the
    // listener needs only enough to answer a handful of small requests. This
    // box has two cores and the node wants both of them.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;

    let bind = config.bind;
    let state = AppState {
        config: Arc::new(config),
        store,
        shared,
        jobs: jobs_tx,
    };

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .with_context(|| format!("binding {bind}"))?;
        println!("faucet      listening on {bind}");
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown())
        .await
        .context("serving")
    })?;

    // Every sender is gone once the router is dropped, which closes the queue
    // and ends the worker's loop. Joining it is what makes a stop wait for the
    // note store to be written rather than killing the thread that owns it.
    worker_thread
        .join()
        .map_err(|_| anyhow::anyhow!("the wallet worker panicked"))?;
    Ok(())
}

/// Re-queue the claims that were accepted before the last stop.
fn recover_queued_claims(
    store: &Arc<Mutex<Store>>,
    jobs: &tokio::sync::mpsc::Sender<Job>,
) -> Result<()> {
    let poisoned = || anyhow::anyhow!("the claims ledger mutex is poisoned");
    let queued = store.lock().map_err(|_| poisoned())?.queued_claims()?;
    for claim in queued {
        let outcome = match Address::decode(&claim.address) {
            Err(_) => Err("bad-address"),
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

async fn shutdown() {
    let interrupt = async {
        tokio::signal::ctrl_c().await.ok();
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
    println!("faucet      stopping");
}
