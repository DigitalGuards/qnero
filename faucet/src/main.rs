//! `qnero-faucet`: serve the testnet faucet, or mint the key it pays from.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qnero_faucet::config::Config;
use qnero_faucet::http::{router, AppState};
use qnero_faucet::store::Store;
use qnero_faucet::worker::{ensure_spend_seed, recover_queued_claims, Shared, Worker};
use qnero_faucet::{keys, ss58};

#[derive(Debug, Parser)]
#[command(
    name = "qnero-faucet",
    version,
    about = "Qnero testnet faucet",
    long_about = "Qnero testnet faucet.

Pays a fixed amount of QNR to one qn1 address as a shielded note,
rate limited per address and per client, with an optional Cloudflare Turnstile
challenge. Configuration is entirely environment variables, because two of the
values name files that spend and argv is world-readable; the deployed shape is
a systemd EnvironmentFile at mode 0600.

A drip is a zero-knowledge proof. It takes about ten seconds to prove and then
up to one block to settle, and this server proves one at a time, so POST /drip
answers `queued` and GET /drip/{token} is how a caller learns what became of it."
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
    require_captcha_decision(&config)?;
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

/// Refuse to serve with no challenge unless somebody said so out loud.
///
/// The rate limits are not a substitute for one, and the arithmetic says why.
/// A recipient address is minted locally for nothing, so the per-address
/// cooldown bounds an attacker not at all. The per-client limit counts an IPv6
/// requester by its /64, which is the right unit and still costs nothing to a
/// client holding several prefixes or a handful of cloud addresses. What is
/// left is the prover: one drip at a time, roughly half a minute end to end,
/// so a determined requester takes the endowment at about 2 880 drips a day
/// and every later claim answers `drained`.
///
/// Turnstile is the defence that actually costs an attacker something, so a
/// public faucet starts with it or says explicitly that it is not one.
fn require_captcha_decision(config: &Config) -> Result<()> {
    if config.captcha_enabled() {
        return Ok(());
    }
    let allowed = std::env::var("QNERO_FAUCET_ALLOW_NO_CAPTCHA")
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    if allowed {
        println!(
            "faucet      no captcha: QNERO_FAUCET_ALLOW_NO_CAPTCHA=1. The rate limits are all \
             that stands between this faucet and its endowment."
        );
        return Ok(());
    }
    anyhow::bail!(
        "QNERO_FAUCET_TURNSTILE_SECRET is empty, so every claim would be answered with no \
         challenge at all. The address cooldown bounds nobody, since addresses are free to \
         mint, and the per-client limit counts an IPv6 /64, which a client with several \
         prefixes simply rotates. Set the Turnstile pair, or set \
         QNERO_FAUCET_ALLOW_NO_CAPTCHA=1 to say deliberately that this faucet does not need one"
    );
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
