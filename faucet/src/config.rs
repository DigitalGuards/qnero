//! The faucet's configuration, all of it from the environment.
//!
//! The deployed shape is an `EnvironmentFile` at mode 0600 read by systemd
//! (`packaging/systemd/qnero-faucet.service`), because two of these values are
//! secret-bearing: the seed paths name files that spend, and the Turnstile
//! secret authenticates this server to Cloudflare. Nothing here is a command
//! line argument, since argv is world-readable in `ps`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// What one claim pays, in pool quanta. 1000 quanta is 10 QNR
/// (`qnero_wallet::POOL_QUANTUM`, 10^10 planck to the quantum, twelve
/// decimals to the QNR).
pub const DEFAULT_DRIP_QUANTA: u64 = 1_000;

#[derive(Debug, Clone)]
pub struct Config {
    /// The node's JSON-RPC endpoint. Loopback: nginx never proxies to this.
    pub node_url: String,
    /// The shielded spending key. Its note store sits beside it as
    /// `<seed>.store.json`, written by `qnero_wallet`.
    pub seed_path: PathBuf,
    /// The transparent ML-DSA-87 seed behind the genesis-endowed account.
    pub transparent_seed_path: PathBuf,
    /// The SS58 address the chain spec endows, checked against the seed at
    /// startup. Empty disables the check.
    pub expect_address: Option<String>,
    /// The claims ledger.
    pub db_path: PathBuf,
    /// Pool quanta per claim.
    pub drip_quanta: u64,
    /// One claim per address per this long.
    pub address_cooldown: Duration,
    /// Claims per client address per `ip_window`.
    pub ip_limit: u32,
    pub ip_window: Duration,
    /// Below this spendable balance every claim is refused, so a drip never
    /// fails inside note selection after the queue has already accepted it.
    pub min_balance_quanta: u64,
    /// At first start, and whenever the spendable balance is under
    /// `min_balance_quanta`, shield this many quanta from the transparent
    /// account, `fund_notes` times.
    pub fund_chunk_quanta: u64,
    pub fund_notes: u32,
    /// Empty disables Turnstile. `/status` reports which it is.
    pub turnstile_secret: Option<String>,
    /// The site key the page embeds. Public by design.
    pub turnstile_site_key: Option<String>,
    pub bind: SocketAddr,
    /// How many claims may wait for the one prover before the faucet answers
    /// 503 with a `Retry-After`.
    pub queue_depth: usize,
    /// The key that turns a client address into the `ip_hash` column, so the
    /// ledger is not a log of who asked. Generated on first start if absent.
    pub ip_hash_key_path: PathBuf,
}

fn var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn parse<T: std::str::FromStr>(name: &str, default: T) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    match var(name) {
        None => Ok(default),
        Some(value) => value
            .parse()
            .map_err(|error| anyhow::anyhow!("{name}={value}: {error}")),
    }
}

impl Config {
    /// Read the environment, or say which variable is missing.
    pub fn from_env() -> Result<Self> {
        let seed_path = PathBuf::from(
            var("QNERO_FAUCET_SEED")
                .context("QNERO_FAUCET_SEED names the shielded spending key and is required")?,
        );
        let transparent_seed_path = PathBuf::from(var("QNERO_FAUCET_TRANSPARENT_SEED").context(
            "QNERO_FAUCET_TRANSPARENT_SEED names the genesis account's ML-DSA-87 seed and is \
             required",
        )?);
        let db_path = PathBuf::from(
            var("QNERO_FAUCET_DB").unwrap_or_else(|| "/var/lib/qnero-faucet/claims.sqlite".into()),
        );
        let ip_hash_key_path = PathBuf::from(
            var("QNERO_FAUCET_IP_HASH_KEY")
                .unwrap_or_else(|| "/var/lib/qnero-faucet/ip-hash.key".into()),
        );
        let bind: SocketAddr = var("QNERO_FAUCET_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .context("QNERO_FAUCET_BIND is host:port")?;

        let drip_quanta = parse("QNERO_FAUCET_DRIP_QUANTA", DEFAULT_DRIP_QUANTA)?;
        if drip_quanta == 0 {
            bail!("QNERO_FAUCET_DRIP_QUANTA is zero, so every claim would pay nothing");
        }
        let cooldown_hours: f64 = parse("QNERO_FAUCET_COOLDOWN_HOURS", 24.0)?;
        if !(cooldown_hours.is_finite() && cooldown_hours > 0.0) {
            bail!("QNERO_FAUCET_COOLDOWN_HOURS must be a positive number of hours");
        }
        let ip_window_hours: f64 = parse("QNERO_FAUCET_IP_WINDOW_HOURS", 24.0)?;
        if !(ip_window_hours.is_finite() && ip_window_hours > 0.0) {
            bail!("QNERO_FAUCET_IP_WINDOW_HOURS must be a positive number of hours");
        }

        let config = Self {
            node_url: var("QNERO_FAUCET_NODE").unwrap_or_else(|| "http://127.0.0.1:9944".into()),
            seed_path,
            transparent_seed_path,
            expect_address: var("QNERO_FAUCET_EXPECT_ADDRESS"),
            db_path,
            drip_quanta,
            address_cooldown: Duration::from_secs_f64(cooldown_hours * 3600.0),
            ip_limit: parse("QNERO_FAUCET_IP_LIMIT", 3)?,
            ip_window: Duration::from_secs_f64(ip_window_hours * 3600.0),
            min_balance_quanta: parse(
                "QNERO_FAUCET_MIN_BALANCE_QUANTA",
                drip_quanta.saturating_mul(5),
            )?,
            fund_chunk_quanta: parse(
                "QNERO_FAUCET_FUND_CHUNK_QUANTA",
                drip_quanta.saturating_mul(50),
            )?,
            fund_notes: parse("QNERO_FAUCET_FUND_NOTES", 4)?,
            turnstile_secret: var("QNERO_FAUCET_TURNSTILE_SECRET"),
            turnstile_site_key: var("QNERO_FAUCET_TURNSTILE_SITE_KEY"),
            bind,
            queue_depth: parse("QNERO_FAUCET_QUEUE_DEPTH", 24)?,
            ip_hash_key_path,
        };

        // A secret with no site key is a page that cannot render the widget in
        // front of a server that demands one, which is a faucet that refuses
        // every claim and says `captcha`. Catch it here rather than there.
        if config.turnstile_secret.is_some() && config.turnstile_site_key.is_none() {
            bail!(
                "QNERO_FAUCET_TURNSTILE_SECRET is set and QNERO_FAUCET_TURNSTILE_SITE_KEY is \
                 not. The server would demand a token the page has no widget to produce, so \
                 every claim would be refused"
            );
        }
        Ok(config)
    }

    pub fn captcha_enabled(&self) -> bool {
        self.turnstile_secret.is_some()
    }

    pub fn cooldown_hours(&self) -> f64 {
        self.address_cooldown.as_secs_f64() / 3600.0
    }
}
