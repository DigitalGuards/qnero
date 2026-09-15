//! The claims ledger: what a restart has to remember.
//!
//! A rate limit held in memory is a rate limit that resets on every deploy,
//! and this process restarts on every deploy. One SQLite file in WAL mode,
//! one table, two indexed queries, and a `CREATE TABLE IF NOT EXISTS` at
//! startup. No ORM and no migration framework.
//!
//! The client address is stored as a keyed hash rather than as itself, so the
//! file records how much was paid out rather than who asked. The
//! key is generated once, kept at mode 0600 beside the database, and is what
//! makes the column unusable for a lookup by anyone who takes the file alone.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rand::TryRngCore;
use rusqlite::{params, Connection, OptionalExtension};

/// Where a claim is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStatus {
    /// Accepted, waiting for the one prover.
    Queued,
    /// The proof settled in a block.
    Sent,
    /// The drip was attempted and did not settle. The reason is stored.
    Failed,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "queued" => Self::Queued,
            "sent" => Self::Sent,
            "failed" => Self::Failed,
            other => bail!("unknown claim status {other:?} in the ledger"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Claim {
    pub id: i64,
    pub address: String,
    pub amount_quanta: u64,
    pub status: ClaimStatus,
    /// Present once the drip settled.
    pub included_at: Option<u32>,
    /// A reason code for a refusal or a failure. Never a node URL, a seed path
    /// or an extrinsic body: those are logged, and the answer carries the code
    /// alone.
    pub detail: Option<String>,
    pub requested_at: u64,
    pub settled_at: Option<u64>,
}

pub struct Store {
    connection: Connection,
    ip_key: [u8; 32],
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

/// Read the client-address hashing key, or make one on first start.
fn load_or_create_ip_key(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is mode {:o}; the client-address hashing key must not be readable beyond \
                 its owner, or the ledger's ip_hash column becomes a lookup table",
                path.display(),
                mode & 0o777
            );
        }
        let raw = fs::read_to_string(path)?;
        let bytes =
            hex::decode(raw.trim()).with_context(|| format!("{} is not hex", path.display()))?;
        if bytes.len() != 32 {
            bail!(
                "{} decodes to {} bytes and the key is 32",
                path.display(),
                bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut key)
        .context("the operating system's RNG refused")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("{}", path.display()))?;
    file.write_all(hex::encode(key).as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(key)
}

impl Store {
    pub fn open(db_path: &Path, ip_key_path: &Path) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).ok();
        }
        let connection =
            Connection::open(db_path).with_context(|| format!("{}", db_path.display()))?;
        // WAL so a reader never blocks the single writer, and a normal sync so
        // a claim row survives a crash of this process. The whole database is
        // one small table; durability costs nothing worth saving here.
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS claims (
                 id             INTEGER PRIMARY KEY AUTOINCREMENT,
                 address        TEXT    NOT NULL,
                 ip_hash        TEXT    NOT NULL,
                 amount_quanta  INTEGER NOT NULL,
                 status         TEXT    NOT NULL,
                 included_at    INTEGER,
                 detail         TEXT,
                 requested_at   INTEGER NOT NULL,
                 settled_at     INTEGER
             );
             CREATE INDEX IF NOT EXISTS claims_by_address ON claims (address, requested_at);
             CREATE INDEX IF NOT EXISTS claims_by_ip      ON claims (ip_hash, requested_at);",
        )?;
        let ip_key = load_or_create_ip_key(ip_key_path)?;
        Ok(Self { connection, ip_key })
    }

    /// An in-memory ledger, for tests.
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE claims (
                 id             INTEGER PRIMARY KEY AUTOINCREMENT,
                 address        TEXT    NOT NULL,
                 ip_hash        TEXT    NOT NULL,
                 amount_quanta  INTEGER NOT NULL,
                 status         TEXT    NOT NULL,
                 included_at    INTEGER,
                 detail         TEXT,
                 requested_at   INTEGER NOT NULL,
                 settled_at     INTEGER
             );",
        )?;
        Ok(Self {
            connection,
            ip_key: [9u8; 32],
        })
    }

    /// Keyed hash of a client address. Blake2b in keyed form, 16 bytes out,
    /// which is enough to make two clients collide only by accident and short
    /// enough that the column is not a stored identifier.
    pub fn ip_hash(&self, client: &str) -> String {
        let mut hasher = Blake2bVar::new(16).expect("16 is a valid blake2b output length");
        hasher.update(&self.ip_key);
        hasher.update(client.as_bytes());
        let mut out = [0u8; 16];
        hasher
            .finalize_variable(&mut out)
            .expect("the output length matches the one configured above");
        hex::encode(out)
    }

    /// When this address last had a claim that was queued or paid.
    ///
    /// A failed claim does not count: a drip that did not settle paid nothing,
    /// and holding the requester to a day's cooldown for the faucet's own
    /// failure is a faucet that quietly stops working.
    pub fn last_claim_for_address(&self, address: &str) -> Result<Option<u64>> {
        Ok(self
            .connection
            .query_row(
                "SELECT requested_at FROM claims
                  WHERE address = ?1 AND status IN ('queued', 'sent')
                  ORDER BY requested_at DESC LIMIT 1",
                params![address],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|seconds| seconds as u64))
    }

    /// How many claims this client address has had inside `window`.
    pub fn claims_for_client(&self, client_hash: &str, window: Duration, now: u64) -> Result<u32> {
        let since = now.saturating_sub(window.as_secs()) as i64;
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM claims
              WHERE ip_hash = ?1 AND requested_at >= ?2 AND status IN ('queued', 'sent')",
            params![client_hash, since],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Record an accepted claim, before anything is proved.
    ///
    /// The row exists first on purpose: a claim that is queued and then lost
    /// to a crash has still consumed its cooldown, which is the safe side of
    /// that trade for a faucet.
    pub fn record_queued(
        &self,
        address: &str,
        client_hash: &str,
        amount_quanta: u64,
        now: u64,
    ) -> Result<i64> {
        self.connection.execute(
            "INSERT INTO claims (address, ip_hash, amount_quanta, status, requested_at)
             VALUES (?1, ?2, ?3, 'queued', ?4)",
            params![address, client_hash, amount_quanta as i64, now as i64],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn mark_sent(&self, id: i64, included_at: u32, now: u64) -> Result<()> {
        self.connection.execute(
            "UPDATE claims SET status = 'sent', included_at = ?2, settled_at = ?3 WHERE id = ?1",
            params![id, included_at as i64, now as i64],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, id: i64, detail: &str, now: u64) -> Result<()> {
        self.connection.execute(
            "UPDATE claims SET status = 'failed', detail = ?2, settled_at = ?3 WHERE id = ?1",
            params![id, detail, now as i64],
        )?;
        Ok(())
    }

    pub fn claim(&self, id: i64) -> Result<Option<Claim>> {
        let row = self
            .connection
            .query_row(
                "SELECT id, address, amount_quanta, status, included_at, detail, requested_at,
                        settled_at
                   FROM claims WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, address, amount, status, included_at, detail, requested_at, settled_at)) =
            row
        else {
            return Ok(None);
        };
        Ok(Some(Claim {
            id,
            address,
            amount_quanta: amount as u64,
            status: ClaimStatus::parse(&status)?,
            included_at: included_at.map(|block| block as u32),
            detail,
            requested_at: requested_at as u64,
            settled_at: settled_at.map(|seconds| seconds as u64),
        }))
    }

    /// Claims still queued, oldest first. Read once at startup: a restart
    /// between the row and the proof would otherwise leave a claim queued for
    /// ever, visible to the requester and paid to nobody.
    pub fn queued_claims(&self) -> Result<Vec<Claim>> {
        let mut statement = self.connection.prepare(
            "SELECT id, address, amount_quanta, requested_at FROM claims
              WHERE status = 'queued' ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(Claim {
                id: row.get(0)?,
                address: row.get(1)?,
                amount_quanta: row.get::<_, i64>(2)? as u64,
                status: ClaimStatus::Queued,
                included_at: None,
                detail: None,
                requested_at: row.get::<_, i64>(3)? as u64,
                settled_at: None,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Total paid out, for `/status`.
    pub fn sent_total_quanta(&self) -> Result<u64> {
        let total: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(amount_quanta), 0) FROM claims WHERE status = 'sent'",
            [],
            |row| row.get(0),
        )?;
        Ok(total as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_queued_claim_holds_the_address_cooldown() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        assert_eq!(store.last_claim_for_address("qn1abc").expect("query"), None);
        let id = store
            .record_queued("qn1abc", &hash, 1000, 1_000_000)
            .expect("insert");
        assert_eq!(
            store.last_claim_for_address("qn1abc").expect("query"),
            Some(1_000_000)
        );
        store.mark_sent(id, 42, 1_000_100).expect("mark sent");
        assert_eq!(
            store.last_claim_for_address("qn1abc").expect("query"),
            Some(1_000_000)
        );
    }

    /// A drip the faucet failed to deliver must not spend the requester's
    /// cooldown. The whole point of the cooldown is one payment a day, and
    /// nobody was paid.
    #[test]
    fn a_failed_claim_does_not_hold_the_cooldown() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        let id = store
            .record_queued("qn1abc", &hash, 1000, 1_000_000)
            .expect("insert");
        store
            .mark_failed(id, "the node refused the submission", 1_000_050)
            .expect("mark failed");
        assert_eq!(store.last_claim_for_address("qn1abc").expect("query"), None);
        assert_eq!(
            store
                .claims_for_client(&hash, Duration::from_secs(86_400), 1_000_100)
                .expect("count"),
            0
        );
    }

    #[test]
    fn the_client_window_counts_only_inside_it() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        store
            .record_queued("qn1a", &hash, 1000, 10_000)
            .expect("insert");
        store
            .record_queued("qn1b", &hash, 1000, 90_000)
            .expect("insert");
        let window = Duration::from_secs(86_400);
        // At 90 000 the window opens at 3 600, so both rows are inside it.
        assert_eq!(
            store
                .claims_for_client(&hash, window, 90_000)
                .expect("count"),
            2
        );
        // Two hours later it opens at 10 100 and the first row has aged out.
        assert_eq!(
            store
                .claims_for_client(&hash, window, 96_500)
                .expect("count"),
            1
        );
    }

    /// Two client addresses must not share a bucket, and the column must not
    /// be the address itself.
    #[test]
    fn the_client_hash_separates_clients_and_hides_them() {
        let store = Store::in_memory().expect("in-memory ledger");
        let one = store.ip_hash("203.0.113.7");
        let two = store.ip_hash("203.0.113.8");
        assert_ne!(one, two);
        assert!(!one.contains("203.0.113"));
        assert_eq!(one, store.ip_hash("203.0.113.7"), "the hash is stable");
    }

    #[test]
    fn queued_claims_come_back_after_a_restart() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        let first = store
            .record_queued("qn1a", &hash, 1000, 10)
            .expect("insert");
        let second = store
            .record_queued("qn1b", &hash, 1000, 20)
            .expect("insert");
        store.mark_sent(first, 3, 30).expect("mark sent");
        let queued = store.queued_claims().expect("queued");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].id, second);
    }
}
