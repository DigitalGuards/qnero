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
use std::net::{IpAddr, Ipv6Addr};
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

/// What counts as a claim a requester has already had.
///
/// Queued and sent are the obvious two. `failed` with the reason
/// `interrupted` counts as well, and that reason code exists for exactly this:
/// the faucet stopped between submitting a drip and recording where it
/// settled, so it does not know whether that payment landed. Freeing the
/// cooldown there would pay the same address twice for one crash. Holding it
/// costs a requester who was genuinely not paid one cooldown, which the claim
/// page says in as many words.
const COUNTS_AS_CLAIMED: &str =
    "(status IN ('queued', 'sent') OR (status = 'failed' AND detail = 'interrupted'))";

/// The reason code a claim carries when the faucet stopped mid-drip.
pub const INTERRUPTED: &str = "interrupted";

/// How much randomness a claim's public handle carries, in bytes.
pub const CLAIM_TOKEN_BYTES: usize = 16;

/// A fresh claim token: 128 random bits from the operating system, hex.
///
/// The rowid is this process's own business. What a requester is handed is
/// this, because the rowid is the previous one plus one: anybody holding a
/// claim could read every other claim by counting down, and each answer named
/// the address it paid and when. A token is unguessable, so the answer reaches
/// the one requester who asked.
pub fn new_claim_token() -> Result<String> {
    let mut raw = [0u8; CLAIM_TOKEN_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut raw)
        .context("the operating system's RNG refused")?;
    Ok(hex::encode(raw))
}

/// Whether a path segment can be a claim token at all: 32 lowercase hex
/// characters and nothing else.
///
/// A rowid fails this, which is what turns the enumerable path into a 404
/// before the ledger is touched.
pub fn is_claim_token(candidate: &str) -> bool {
    candidate.len() == CLAIM_TOKEN_BYTES * 2
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// An accepted claim, as the requester and the worker each need it: the token
/// answers the poll, the rowid stays inside.
#[derive(Debug, Clone)]
pub struct NewClaim {
    pub id: i64,
    pub token: String,
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
    /// When the worker began submitting this drip, if it ever did. A row that
    /// carries one and is still `queued` at startup was interrupted mid-flight
    /// and must never be proved a second time.
    pub submitted_at: Option<u64>,
    pub settled_at: Option<u64>,
}

pub struct Store {
    connection: Connection,
    ip_key: [u8; 32],
}

/// What a client is counted as, which is deliberately coarser than its
/// address.
///
/// IPv4 is itself. **IPv6 is its /64**, because that is what a client is
/// actually handed: an ordinary residential or cloud allocation is a /64, so
/// counting whole addresses gives one requester 2^64 keys and a per-client
/// limit that bounds nothing. Rotating the low half of an address is free and
/// needs no botnet, and the recipient side is no help either, since addresses
/// are minted locally at no cost. An IPv4-mapped address is counted as the
/// IPv4 inside it, and anything that does not parse is passed through, which
/// is a test fixture or a header a proxy wrote in a shape this does not know.
///
/// `nginx` groups the same way in `packaging/nginx/00-qnero-common.conf`, and
/// the two have to agree or the outer bound and the ledger count different
/// things.
pub fn client_key(client: &str) -> String {
    match client.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let mut prefix = [0u8; 16];
            prefix[..8].copy_from_slice(&v6.octets()[..8]);
            format!("{}/64", Ipv6Addr::from(prefix))
        }
        Err(_) => client.trim().to_ascii_lowercase(),
    }
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

/// Add one column to `claims`, treating "already there" as done.
fn add_column(connection: &Connection, column: &str) -> Result<()> {
    if let Err(error) = connection.execute(&format!("ALTER TABLE claims ADD COLUMN {column}"), []) {
        let text = error.to_string();
        if !text.contains("duplicate column name") {
            return Err(error).with_context(|| format!("adding the {column} column"));
        }
    }
    Ok(())
}

/// Give every row written before tokens existed one of its own.
///
/// A ledger that survived the upgrade keeps its history, and the claims in it
/// are polled by nobody: a fresh token per row is what lets the column carry a
/// unique index and what keeps the rowid out of every lookup path.
fn backfill_tokens(connection: &Connection) -> Result<()> {
    let ids: Vec<i64> = {
        let mut statement = connection.prepare("SELECT id FROM claims WHERE token IS NULL")?;
        let rows = statement.query_map([], |row| row.get::<_, i64>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for id in ids {
        connection.execute(
            "UPDATE claims SET token = ?2 WHERE id = ?1",
            params![id, new_claim_token()?],
        )?;
    }
    Ok(())
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
                 submitted_at   INTEGER,
                 settled_at     INTEGER,
                 token          TEXT
             );
             CREATE INDEX IF NOT EXISTS claims_by_address ON claims (address, requested_at);
             CREATE INDEX IF NOT EXISTS claims_by_ip      ON claims (ip_hash, requested_at);",
        )?;
        // A ledger written before these columns existed. ALTER TABLE is the
        // whole migration story here: one table, one added column each time,
        // and an error that says "duplicate column name" means the ledger is
        // already migrated, which `add_column` treats as done.
        add_column(&connection, "submitted_at INTEGER")?;
        add_column(&connection, "token TEXT")?;
        backfill_tokens(&connection)?;
        // After the backfill, so the index is built once over a column that
        // is already filled.
        connection.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS claims_by_token ON claims (token);",
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
                 submitted_at   INTEGER,
                 settled_at     INTEGER,
                 token          TEXT
             );
             CREATE UNIQUE INDEX claims_by_token ON claims (token);",
        )?;
        Ok(Self {
            connection,
            ip_key: [9u8; 32],
        })
    }

    /// Keyed hash of a client, which is `client_key` of its address rather
    /// than the address itself, so one IPv6 /64 is one row. Blake2b in keyed
    /// form, 16 bytes out, which is enough to make two clients collide only by
    /// accident and short enough that the column is not a stored identifier.
    ///
    /// The grouping happens HERE rather than at the call sites, so a route
    /// that reaches for a client's history cannot forget it.
    pub fn ip_hash(&self, client: &str) -> String {
        let key = client_key(client);
        let mut hasher = Blake2bVar::new(16).expect("16 is a valid blake2b output length");
        hasher.update(&self.ip_key);
        hasher.update(key.as_bytes());
        let mut out = [0u8; 16];
        hasher
            .finalize_variable(&mut out)
            .expect("the output length matches the one configured above");
        hex::encode(out)
    }

    /// When this address last had a claim that was queued or paid.
    ///
    /// An ordinary failed claim does not count: a drip that did not settle
    /// paid nothing, and holding the requester to a day's cooldown for the
    /// faucet's own failure is a faucet that quietly stops working.
    pub fn last_claim_for_address(&self, address: &str) -> Result<Option<u64>> {
        Ok(self
            .connection
            .query_row(
                &format!(
                    "SELECT requested_at FROM claims
                      WHERE address = ?1 AND {COUNTS_AS_CLAIMED}
                      ORDER BY requested_at DESC LIMIT 1"
                ),
                params![address],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|seconds| seconds as u64))
    }

    /// How many claims this client has had inside `window`. The client is a
    /// `client_key`, so an IPv6 requester is counted by its /64.
    pub fn claims_for_client(&self, client_hash: &str, window: Duration, now: u64) -> Result<u32> {
        let since = now.saturating_sub(window.as_secs()) as i64;
        let count: i64 = self.connection.query_row(
            &format!(
                "SELECT COUNT(*) FROM claims
                  WHERE ip_hash = ?1 AND requested_at >= ?2 AND {COUNTS_AS_CLAIMED}"
            ),
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
    ///
    /// The token comes back with the rowid and is the only half a requester is
    /// given.
    pub fn record_queued(
        &self,
        address: &str,
        client_hash: &str,
        amount_quanta: u64,
        now: u64,
    ) -> Result<NewClaim> {
        let token = new_claim_token()?;
        self.connection.execute(
            "INSERT INTO claims (address, ip_hash, amount_quanta, status, requested_at, token)
             VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![
                address,
                client_hash,
                amount_quanta as i64,
                now as i64,
                token
            ],
        )?;
        Ok(NewClaim {
            id: self.connection.last_insert_rowid(),
            token,
        })
    }

    /// Record that the worker is about to submit this drip.
    ///
    /// Written before the proof is handed to the node and never cleared, so a
    /// row that is still `queued` at the next startup and carries this was
    /// interrupted somewhere between submission and settlement. That is the
    /// one case a restart must not re-queue: the payment may already be in a
    /// block, and proving a second one pays the same address twice for one
    /// crash. `Restart=always` makes the crash five seconds old, so this is
    /// not a rare shape; a SIGKILL after `TimeoutStopSec`, the faucet's
    /// `MemoryMax` landing on a proof that peaks near a gigabyte, or a host
    /// reset all produce it.
    pub fn mark_submitted(&self, id: i64, now: u64) -> Result<()> {
        self.connection.execute(
            "UPDATE claims SET submitted_at = ?2 WHERE id = ?1",
            params![id, now as i64],
        )?;
        Ok(())
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

    /// The claim a requester polls, found by the token it was handed.
    pub fn claim_by_token(&self, token: &str) -> Result<Option<Claim>> {
        self.claim_where("token", &token)
    }

    /// The claim the worker is carrying, found by its rowid.
    pub fn claim(&self, id: i64) -> Result<Option<Claim>> {
        self.claim_where("id", &id)
    }

    fn claim_where(&self, column: &str, key: &dyn rusqlite::ToSql) -> Result<Option<Claim>> {
        let row = self
            .connection
            .query_row(
                &format!(
                    "SELECT id, address, amount_quanta, status, included_at, detail, requested_at,
                            submitted_at, settled_at
                       FROM claims WHERE {column} = ?1"
                ),
                params![key],
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
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            id,
            address,
            amount,
            status,
            included_at,
            detail,
            requested_at,
            submitted_at,
            settled_at,
        )) = row
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
            submitted_at: submitted_at.map(|seconds| seconds as u64),
            settled_at: settled_at.map(|seconds| seconds as u64),
        }))
    }

    /// Claims still queued, oldest first. Read once at startup: a restart
    /// between the row and the proof would otherwise leave a claim queued for
    /// ever, visible to the requester and paid to nobody.
    ///
    /// `submitted_at` comes back with them because it is what separates a
    /// claim nothing was ever done about, which is safe to prove now, from one
    /// that was already handed to the node.
    pub fn queued_claims(&self) -> Result<Vec<Claim>> {
        let mut statement = self.connection.prepare(
            "SELECT id, address, amount_quanta, requested_at, submitted_at FROM claims
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
                submitted_at: row.get::<_, Option<i64>>(4)?.map(|seconds| seconds as u64),
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

    /// A directory of this test's own, removed when it ends.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("qnero-faucet-store-{tag}-{unique}"));
        fs::create_dir_all(&path).expect("a temporary directory");
        path
    }

    /// The token is what a requester polls with, and it finds the one claim it
    /// was written for.
    #[test]
    fn a_claim_is_found_by_its_token() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        let first = store
            .record_queued("qn1a", &hash, 1000, 10)
            .expect("insert");
        let second = store
            .record_queued("qn1b", &hash, 2000, 20)
            .expect("insert");

        assert_ne!(first.token, second.token, "two claims, two tokens");
        assert!(is_claim_token(&first.token), "{}", first.token);
        assert!(is_claim_token(&second.token), "{}", second.token);

        let found = store
            .claim_by_token(&first.token)
            .expect("query")
            .expect("the row the insert wrote");
        assert_eq!(found.id, first.id);
        assert_eq!(found.address, "qn1a");
        assert_eq!(
            store
                .claim_by_token(&second.token)
                .expect("query")
                .expect("the second row")
                .amount_quanta,
            2000
        );
        assert!(store
            .claim_by_token(&"0".repeat(32))
            .expect("query")
            .is_none());
    }

    /// The shape check is what keeps the rowid path out of the ledger: it is
    /// the one thing between a counted-up path and a lookup.
    #[test]
    fn only_a_token_shaped_path_is_a_token() {
        assert!(is_claim_token(&"a1b2c3d4".repeat(4)));
        assert!(!is_claim_token("1"));
        assert!(!is_claim_token("-1"));
        assert!(!is_claim_token(&"1".repeat(31)));
        assert!(!is_claim_token(&"1".repeat(33)));
        assert!(!is_claim_token(&"A1B2C3D4".repeat(4)), "hex is lowercase");
        assert!(!is_claim_token(&"g".repeat(32)), "g is not hex");
        assert!(is_claim_token(&new_claim_token().expect("the system RNG")));
    }

    /// A ledger written before tokens existed keeps its rows and is given one
    /// token per row on the next open. Without the backfill the unique index
    /// would go on a half-empty column and the old rows would be unreachable
    /// by the only route that reads them.
    #[test]
    fn an_existing_ledger_is_given_tokens_on_open() {
        let dir = scratch("migrate");
        let db = dir.join("claims.sqlite");
        let key = dir.join("ip-hash.key");

        // The oldest shape this ledger ever had: no submitted_at and no token.
        {
            let old = Connection::open(&db).expect("a ledger file");
            old.execute_batch(
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
                 );
                 INSERT INTO claims (address, ip_hash, amount_quanta, status, requested_at)
                      VALUES ('qn1old', 'hash', 1000, 'sent', 10),
                             ('qn1older', 'hash', 2000, 'queued', 20);",
            )
            .expect("the old schema");
        }

        let store = Store::open(&db, &key).expect("the migrated ledger");
        let mut tokens = Vec::new();
        for id in [1_i64, 2] {
            let claim = store
                .claim(id)
                .expect("query")
                .expect("the row survived the migration");
            let token: String = store
                .connection
                .query_row(
                    "SELECT token FROM claims WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .expect("the backfilled token");
            assert!(is_claim_token(&token), "row {id} got {token:?}");
            assert_eq!(
                store
                    .claim_by_token(&token)
                    .expect("query")
                    .expect("the row, by its new token")
                    .id,
                claim.id
            );
            tokens.push(token);
        }
        assert_ne!(tokens[0], tokens[1], "one token per row");

        // A second open changes nothing: the columns are there, every row has
        // a token, and the index already exists.
        drop(store);
        let store = Store::open(&db, &key).expect("a second open");
        assert_eq!(
            store
                .claim_by_token(&tokens[0])
                .expect("query")
                .expect("the same row")
                .address,
            "qn1old"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_queued_claim_holds_the_address_cooldown() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        assert_eq!(store.last_claim_for_address("qn1abc").expect("query"), None);
        let id = store
            .record_queued("qn1abc", &hash, 1000, 1_000_000)
            .expect("insert")
            .id;
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
            .expect("insert")
            .id;
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

    /// An interrupted drip is the one failure that DOES hold the cooldown,
    /// because it is the one the faucet cannot decide. The process stopped
    /// after the payment was submitted, so it may be in a block; re-paying
    /// that address, whether by re-queueing the row or by letting the
    /// requester ask again immediately, pays twice for one crash.
    #[test]
    fn an_interrupted_claim_holds_the_cooldown() {
        let store = Store::in_memory().expect("in-memory ledger");
        let hash = store.ip_hash("203.0.113.7");
        let id = store
            .record_queued("qn1abc", &hash, 1000, 1_000_000)
            .expect("insert")
            .id;
        store.mark_submitted(id, 1_000_010).expect("mark submitted");
        assert_eq!(
            store
                .queued_claims()
                .expect("queued")
                .first()
                .and_then(|claim| claim.submitted_at),
            Some(1_000_010),
            "the submission has to survive the restart to be decidable"
        );
        store
            .mark_failed(id, INTERRUPTED, 1_000_050)
            .expect("mark failed");
        assert_eq!(
            store.last_claim_for_address("qn1abc").expect("query"),
            Some(1_000_000)
        );
        assert_eq!(
            store
                .claims_for_client(&hash, Duration::from_secs(86_400), 1_000_100)
                .expect("count"),
            1
        );
    }

    /// One /64 is one client. An IPv6 requester is handed a /64 as a matter of
    /// course, so counting whole addresses is counting nothing.
    #[test]
    fn a_client_is_counted_by_its_prefix() {
        assert_eq!(client_key("203.0.113.7"), "203.0.113.7");
        assert_eq!(client_key("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(client_key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
        assert_eq!(client_key("2001:db8:1:2::9"), "2001:db8:1:2::/64");
        assert_eq!(client_key("2001:DB8:1:2::AAAA"), "2001:db8:1:2::/64");
        assert_ne!(client_key("2001:db8:1:3::9"), client_key("2001:db8:1:2::9"));

        let store = Store::in_memory().expect("in-memory ledger");
        let one = store.ip_hash("2001:db8:1:2:3:4:5:6");
        let two = store.ip_hash("2001:db8:1:2::ffff");
        assert_eq!(one, two, "two addresses in one /64 are one client");
        assert_ne!(
            one,
            store.ip_hash("2001:db8:1:3::1"),
            "two /64s are two clients"
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
            .expect("insert")
            .id;
        let second = store
            .record_queued("qn1b", &hash, 1000, 20)
            .expect("insert")
            .id;
        store.mark_sent(first, 3, 30).expect("mark sent");
        let queued = store.queued_claims().expect("queued");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].id, second);
    }
}
